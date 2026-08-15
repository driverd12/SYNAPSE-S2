from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import secrets
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import threading
import time
import unicodedata
import uuid
import zlib
from contextlib import ExitStack, closing, contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

import fcntl

from capture_daemon import (
    CAPTURE_ID_RE,
    CLAIM_DIR_RE,
    CaptureInboxDaemon,
    GLOBAL_CAPTURE_LOCK,
    resolve_capture_root,
)
from core_authority import CORE_AUTHORITY_LOCK_GENERATION_RE
from core_request_journal import (
    JOURNAL_APPLICATION_ID,
    JOURNAL_BINDING_SCHEMA,
    JOURNAL_SCHEMA_IDENTITY,
    JOURNAL_SCHEMA_VERSION,
    SAFE_ERROR_CODES as REQUEST_JOURNAL_SAFE_ERROR_CODES,
)
from image_capture import (
    IMAGE_ARTIFACT_ENRICHED_SCHEMA,
    IMAGE_ARTIFACT_SCHEMA,
    MAX_FEATURE_PRINT_BYTES,
    MAX_OBJECTS as MAX_MEDIA_OBJECTS,
    MAX_THUMBNAIL_BYTES,
    ImageCaptureError,
    ImageCaptureNotFound,
    MediaObjectReader,
)
from memory_store import (
    BACKUP_DIGEST_RE,
    BACKUP_CRITICAL_TABLES,
    BACKUP_SCHEMA_COMPATIBILITY_REGISTRY,
    CAPTURE_PROTOCOL_VERSION,
    SCHEMA_SQL,
    DurableMemoryStore,
    LOGICAL_SNAPSHOT_DIGEST_SCHEMA,
    RECOVERY_REQUEST_JOURNAL_BINDING_SCHEMA,
    SQLITE_USER_VERSION,
    _json_dumps,
    _matching_backup_schema_contract_versions,
    capture_request_fingerprint,
    media_references_from_connection,
)
from redaction import redact_capture_text, reject_sensitive_identifier, strip_untrusted_raw_digest_text


RECOVERY_BUNDLE_SCHEMA = "synapse-s2.recovery-bundle.v3"
PRIOR_RECOVERY_BUNDLE_SCHEMA = "synapse-s2.recovery-bundle.v2"
LEGACY_RECOVERY_BUNDLE_SCHEMA = "synapse-s2.recovery-bundle.v1"
REQUEST_JOURNAL_RESTORE_BINDING_SCHEMA = (
    "synapse-s2.request-journal-restore-binding.v1"
)
REQUEST_JOURNAL_SCHEMA_SHA256 = (
    "1325dcfa3887dc64b6de58f23d03be8393e246fcea8a72c606fcb05cc74f8e3b"
)
REQUEST_JOURNAL_ID_RE = re.compile(r"\Ajournal-[0-9a-f]{24}\Z")
STORE_IDENTITY_RE = re.compile(r"\Astore-[0-9a-f]{24}\Z")
REQUEST_JOURNAL_IDENTIFIER_RE = re.compile(
    r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z"
)
CAPTURE_ARCHIVE_MANIFEST_SCHEMA = "synapse-s2.capture-archive.v1"
MEDIA_ARCHIVE_MANIFEST_SCHEMA = "synapse-s2.media-archive.v1"
MAX_MEDIA_ARCHIVE_FILES = MAX_MEDIA_OBJECTS * 3
MAX_MEDIA_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_MEDIA_ARCHIVE_TOTAL_BYTES = 4 * 1024**3
# The decompressed tar stream may hold at most every declared member byte,
# the manifest, one 1 KiB header/padding allowance per member, and the tar
# end-of-archive marker; anything larger is a smuggled payload.
MAX_MEDIA_ARCHIVE_DECOMPRESSED_BYTES = (
    MAX_MEDIA_ARCHIVE_TOTAL_BYTES
    + MAX_MEDIA_MANIFEST_BYTES
    + (MAX_MEDIA_ARCHIVE_FILES + 2) * 1024
    + 64 * 1024
)
# gzip never inflates its input by more than a small framing overhead, so the
# compressed envelope is bounded by the decompressed ceiling plus slack.
MAX_MEDIA_ARCHIVE_ENVELOPE_BYTES = MAX_MEDIA_ARCHIVE_DECOMPRESSED_BYTES + 1024 * 1024
RUNTIME_STATE_BINDING_SCHEMA = "synapse-s2.runtime-state-binding.v1"
RUNTIME_STATE_AUTHORITY_BINDING_SCHEMA = (
    "synapse-s2.runtime-authority-binding.v1"
)
RUNTIME_STATE_AUTHORITY_LOCK_RE = CORE_AUTHORITY_LOCK_GENERATION_RE
RECOVERY_BUNDLE_RESTORE_SCHEMA = "synapse-s2.recovery-bundle-restore.v3"
PRIOR_RECOVERY_BUNDLE_RESTORE_SCHEMA = "synapse-s2.recovery-bundle-restore.v2"
LEGACY_RECOVERY_BUNDLE_RESTORE_SCHEMA = "synapse-s2.recovery-bundle-restore.v1"
RECOVERY_RETENTION_PLAN_SCHEMA = "synapse-s2.recovery-retention-plan.v1"
RECOVERY_RETIREMENT_RECEIPT_SCHEMA = "synapse-s2.recovery-retirement.v1"
RECOVERY_PUBLICATION_RECEIPT_SCHEMA = "synapse-s2.recovery-publication.v1"
GUARDED_RECOVERY_TRANSACTION_SCHEMA = (
    "synapse-s2.guarded-recovery-transaction.v1"
)
CAPTURE_LEDGER_RECONCILIATION_SCHEMA = (
    "synapse-s2.capture-ledger-reconciliation.v1"
)
CAPTURE_LEDGER_BINDING_PROOF_SCHEMA = (
    "synapse-s2.capture-ledger-binding-proof.v1"
)
LEGACY_V2_DEFAULT_FIELDS = frozenset(
    {
        "dropped_top_level_field_count",
        "min_segment_sentences",
        "surprise_threshold",
    }
)
EXPECTED_CAPTURE_AGENT_TARGETS = frozenset(
    {"mcp-clients", "codex-desktop", "local-ide-adapters"}
)
EXPECTED_CAPTURE_TARGET_RECORDS = frozenset(
    {
        ("agent", "codex-desktop"),
        ("group", "local-ide-adapters"),
        ("group", "mcp-clients"),
    }
)
LEGACY_EVENT_DERIVED_METADATA_FIELDS = frozenset(
    {
        "capture_file",
        "context_namespace",
        "context_namespace_source",
        "context_namespace_title",
        "conversation_capture",
        "detail_badges",
        "display_label",
        "display_summary",
        "embedding_provider",
        "event_segment",
        "harmonic_scaffold",
        "harmonic_scaffold_schema",
        "keywords",
        "lexical_surprise_score",
        "segment_id",
        "segment_index",
        "semantic_facets",
        "semantic_surprise_score",
        "sentence_count",
        "sequence_id",
        "source",
        "source_tag",
        "speaker",
        "surprise_mode",
        "surprise_model",
        "surprise_score",
        "temporal",
    }
)


def _require_single_bounded_gzip_stream(
    archive_path: Path,
    *,
    max_decompressed_bytes: int,
    on_payload: Callable[[bytes, int], None] | None = None,
) -> int:
    """Measure one strictly bounded gzip member and reject smuggled bytes.

    A digest-signed media envelope must be exactly one gzip stream whose
    decompressed payload stays within the supplied ceiling. Bytes after the
    gzip stream ends (appended raw or recompressed data) and streams that
    inflate past the ceiling are rejected before any tar member is trusted.
    Returns the exact decompressed byte count so callers can bind it to the
    manifest-declared member sizes. ``on_payload`` observes each decompressed
    piece with its absolute stream offset.
    """

    decompressor = zlib.decompressobj(wbits=31)
    decompressed_bytes = 0
    with archive_path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            if decompressor.eof:
                raise ValueError(
                    "media archive has trailing data after its gzip stream"
                )
            try:
                remaining = max_decompressed_bytes - decompressed_bytes
                produced = decompressor.decompress(chunk, remaining + 1)
                if on_payload is not None and produced:
                    on_payload(produced, decompressed_bytes)
                decompressed_bytes += len(produced)
                while (
                    decompressor.unconsumed_tail
                    and decompressed_bytes <= max_decompressed_bytes
                ):
                    remaining = max_decompressed_bytes - decompressed_bytes
                    produced = decompressor.decompress(
                        decompressor.unconsumed_tail, remaining + 1
                    )
                    if on_payload is not None and produced:
                        on_payload(produced, decompressed_bytes)
                    decompressed_bytes += len(produced)
            except zlib.error as exc:
                raise ValueError("media archive gzip envelope is invalid") from exc
            if decompressed_bytes > max_decompressed_bytes:
                raise ValueError(
                    "media archive decompresses past its size ceiling"
                )
    if not decompressor.eof:
        raise ValueError("media archive gzip stream is truncated")
    if decompressor.unused_data:
        raise ValueError("media archive has trailing data after its gzip stream")
    return decompressed_bytes


@contextmanager
def _immutable_read_transaction(
    connection: sqlite3.Connection,
) -> Iterator[None]:
    connection.execute("BEGIN")
    try:
        yield
    finally:
        if connection.in_transaction:
            connection.execute("ROLLBACK")


MAINTENANCE_RECEIPT_COLUMN_SIGNATURE = (
    ("operation_id", "TEXT", 0, None, 1),
    ("operation_type", "TEXT", 1, None, 0),
    ("context_id", "TEXT", 0, None, 0),
    ("before_revision", "TEXT", 1, "''", 0),
    ("after_revision", "TEXT", 1, "''", 0),
    ("payload_json", "TEXT", 1, "'{}'", 0),
    ("created_at", "REAL", 1, None, 0),
)
MAINTENANCE_RECEIPT_TABLE_SQL = """
CREATE TABLE store_maintenance_receipts (
    operation_id TEXT PRIMARY KEY,
    operation_type TEXT NOT NULL,
    context_id TEXT,
    before_revision TEXT NOT NULL DEFAULT '',
    after_revision TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL
)
"""
MAINTENANCE_RECEIPT_INDEX_SQL = """
CREATE INDEX ix_store_maintenance_receipts_type_created
ON store_maintenance_receipts(operation_type, created_at DESC)
"""
CAPTURE_TRANSPORT_DIR_KEYS = (
    "inbox_dir",
    "processing_dir",
    "processed_dir",
    "error_dir",
    "error_archive_dir",
    "error_resolution_dir",
    "receipt_dir",
)


class GuardedRecoveryPublication:
    """One-shot publication gate owned by a guarded recovery context."""

    def __init__(
        self,
        evidence: dict[str, Any],
        *,
        prepublish: Callable[[], dict[str, Any]],
    ) -> None:
        self.evidence = evidence
        self._prepublish = prepublish
        self._publication_attempted = False
        self._published = False

    @property
    def publication_attempted(self) -> bool:
        return self._publication_attempted

    @property
    def published(self) -> bool:
        return self._published

    def publish(
        self,
        callback: Callable[[dict[str, Any]], Any],
    ) -> Any:
        """Run the last fallible gate, then publish while both locks remain held."""

        if not callable(callback):
            raise TypeError("guarded recovery publication callback must be callable")
        if self._publication_attempted:
            raise RuntimeError("guarded recovery publication is one-shot")
        self._publication_attempted = True
        release_state = self._prepublish()
        self.evidence["capture_transport_at_publication"] = release_state
        self.evidence["publication_gate_completed_at"] = time.time()
        result = callback(self.evidence)
        self._published = True
        return result


class VerifiedRecoveryManager:
    """Create and prove a paired SQLite + exactly-once capture recovery point."""

    def __init__(
        self,
        store: DurableMemoryStore,
        *,
        capture_root: str | os.PathLike[str] | None = None,
        runtime_state_path: str | os.PathLike[str] | None = None,
        allow_noncanonical_capture_root: bool = False,
    ) -> None:
        self.store = store
        self.capture_root = resolve_capture_root(capture_root)
        configured_runtime_state = (
            runtime_state_path
            if runtime_state_path is not None
            else os.getenv("SYNAPSE_S2_STATE_PATH")
            or (self.store.db_path.parent / "runtime_state.json")
        )
        reject_sensitive_identifier(
            configured_runtime_state,
            field="runtime state path",
        )
        self.runtime_state_path = Path(configured_runtime_state).expanduser().absolute()
        self.allow_noncanonical_capture_root = bool(allow_noncanonical_capture_root)
        self.daemon = CaptureInboxDaemon(root=self.capture_root)
        self._repository_thread_lock = threading.RLock()
        self._repository_lock_owner: int | None = None
        self._repository_lock_depth = 0
        self._repository_lock_descriptor: int | None = None
        self._capture_maintenance_thread_lock = threading.RLock()
        self._capture_maintenance_lock_owner: int | None = None
        self._capture_maintenance_lock_token: object | None = None

    @contextmanager
    def _repository_lock(self) -> Iterable[None]:
        """Serialize bundle publication, retirement, restore proof, and future import.

        Global lock order is authority -> repository -> capture global ->
        memory-store/SQLite. Keeping that order explicit prevents recovery
        maintenance from deadlocking capture producers or the authoritative
        core service.
        """

        thread_id = threading.get_ident()
        self._repository_thread_lock.acquire()
        try:
            if self._repository_lock_depth:
                if self._repository_lock_owner != thread_id:
                    raise RuntimeError("recovery repository lock ownership is invalid")
                self._repository_lock_depth += 1
                try:
                    yield
                finally:
                    self._repository_lock_depth -= 1
                return
            lock_dir = self.store.db_path.parent / "recovery-locks"
            self.store._ensure_directory(lock_dir, owned=True)
            descriptor = self.store._acquire_file_lock(
                lock_dir / "repository.lock",
                mode=fcntl.LOCK_EX,
                timeout_seconds=30.0,
            )
            self._repository_lock_descriptor = descriptor
            self._repository_lock_owner = thread_id
            self._repository_lock_depth = 1
            try:
                self._recover_incomplete_bundle_publications_locked()
                yield
            finally:
                self._repository_lock_depth = 0
                self._repository_lock_owner = None
                self._repository_lock_descriptor = None
                self.store._release_file_lock(descriptor)
        finally:
            self._repository_thread_lock.release()

    def _require_repository_lock(self) -> None:
        if (
            self._repository_lock_owner != threading.get_ident()
            or self._repository_lock_depth <= 0
            or self._repository_lock_descriptor is None
        ):
            raise RuntimeError("recovery repository lock is not held by this thread")

    @contextmanager
    def _capture_maintenance_lock(
        self,
        *,
        existing_only: bool = False,
    ) -> Iterator[object]:
        """Own the global capture lock once, after the repository lock.

        This manager deliberately rejects same-thread re-entry instead of relying
        on platform-specific ``flock`` behavior.  Guarded recovery calls the
        capture-locked helpers directly, so no nested file-lock acquisition is
        required anywhere in the create/verify/restore transaction.
        """

        self._require_repository_lock()
        thread_id = threading.get_ident()
        self._capture_maintenance_thread_lock.acquire()
        try:
            if self._capture_maintenance_lock_owner is not None:
                raise RuntimeError("capture maintenance lock must not be reacquired")
            paths = self.daemon.paths()
            if existing_only:
                try:
                    with self._existing_private_file_lock(
                        paths["lock_dir"] / GLOBAL_CAPTURE_LOCK,
                        mode=fcntl.LOCK_EX,
                        timeout_seconds=0.0,
                    ):
                        token = object()
                        self._capture_maintenance_lock_owner = thread_id
                        self._capture_maintenance_lock_token = token
                        try:
                            yield token
                        finally:
                            self._capture_maintenance_lock_token = None
                            self._capture_maintenance_lock_owner = None
                except BlockingIOError as exc:
                    raise RuntimeError(
                        "capture maintenance lock is busy; guarded recovery "
                        "will not wait while holding core authority"
                    ) from exc
                return
            with self.daemon._exclusive_lock(
                paths["lock_dir"] / GLOBAL_CAPTURE_LOCK,
                blocking=True,
            ) as acquired:
                if not acquired:
                    raise RuntimeError("capture maintenance lock is unavailable")
                token = object()
                self._capture_maintenance_lock_owner = thread_id
                self._capture_maintenance_lock_token = token
                try:
                    yield token
                finally:
                    self._capture_maintenance_lock_token = None
                    self._capture_maintenance_lock_owner = None
        finally:
            self._capture_maintenance_thread_lock.release()

    @contextmanager
    def _held_capture_maintenance_lock(self, token: object) -> Iterator[None]:
        """Assert capture-lock ownership without acquiring another lock."""

        self._require_repository_lock()
        if (
            self._capture_maintenance_lock_owner != threading.get_ident()
            or self._capture_maintenance_lock_token is not token
        ):
            raise RuntimeError("capture maintenance lock token is not owned")
        try:
            yield
        finally:
            if (
                self._capture_maintenance_lock_owner != threading.get_ident()
                or self._capture_maintenance_lock_token is not token
            ):
                raise RuntimeError("capture maintenance lock ownership changed")

    @contextmanager
    def _existing_private_file_lock(
        self,
        path: Path,
        *,
        mode: int,
        timeout_seconds: float | None = None,
    ) -> Iterable[None]:
        """Acquire an already-established lock without creating or chmodding it."""

        observed = os.lstat(path)
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        acquired = False
        try:
            opened = os.fstat(descriptor)
            if (
                stat.S_ISLNK(observed.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.getuid()
                or int(opened.st_nlink) != 1
                or stat.S_IMODE(opened.st_mode) != 0o600
                or self.store._regular_file_identity(observed)
                != self.store._regular_file_identity(opened)
            ):
                raise PermissionError("attestation lock is not private")
            if timeout_seconds is None:
                fcntl.flock(descriptor, mode)
            else:
                deadline = time.monotonic() + max(0.0, float(timeout_seconds))
                while True:
                    try:
                        fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.02)
            acquired = True
            visible = os.lstat(path)
            held = os.fstat(descriptor)
            if (
                self.store._regular_file_identity(visible)
                != self.store._regular_file_identity(opened)
                or self.store._regular_file_identity(held)
                != self.store._regular_file_identity(opened)
            ):
                raise RuntimeError("attestation lock identity changed")
            yield
        finally:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _publication_journal_root(self) -> Path:
        root = self.store.db_path.parent / "backups" / "publication-journals"
        self.store._ensure_directory(root, owned=True)
        return root

    def _read_publication_receipt(
        self,
        path: Path,
        *,
        expected_state: str,
    ) -> dict[str, Any]:
        data, metadata = self._read_private_regular(path, max_bytes=2 * 1024**2)
        if (
            metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or int(metadata.st_nlink) != 1
        ):
            raise PermissionError("recovery publication receipt is not private")
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("recovery publication receipt is invalid JSON") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != RECOVERY_PUBLICATION_RECEIPT_SCHEMA
            or payload.get("state") != expected_state
            or not secrets.compare_digest(
                str(payload.get("receipt_digest") or ""),
                self.store._canonical_payload_digest(payload),
            )
        ):
            raise ValueError("recovery publication receipt is invalid")
        if not self.store._verify_receipt_authenticator(payload):
            raise ValueError("recovery publication signer is not trusted locally")
        return payload

    def _recover_incomplete_bundle_publications_locked(self) -> None:
        journal_root = self._publication_journal_root()
        store_root = self.store.db_path.parent.resolve()
        for prepared_path in sorted(journal_root.glob("*.prepared.receipt.json")):
            publication_id = prepared_path.name.removesuffix(
                ".prepared.receipt.json"
            )
            completed_path = journal_root / (
                f"{publication_id}.completed.receipt.json"
            )
            recovered_path = journal_root / (
                f"{publication_id}.recovered.receipt.json"
            )
            if completed_path.exists() or recovered_path.exists():
                continue
            prepared = self._read_publication_receipt(
                prepared_path,
                expected_state="prepared",
            )
            if prepared.get("publication_id") != publication_id:
                raise RuntimeError("recovery publication journal identity mismatch")
            relative_directory = Path(str(prepared.get("output_directory") or ""))
            artifact_names = prepared.get("artifact_names")
            bundle_receipt_name = str(prepared.get("bundle_receipt_name") or "")
            if (
                relative_directory.is_absolute()
                or ".." in relative_directory.parts
                or not isinstance(artifact_names, list)
                or len(artifact_names) not in {4, 5, 6, 7, 8}
                or len(set(artifact_names)) != len(artifact_names)
                or any(
                    not isinstance(name, str)
                    or not name
                    or Path(name).name != name
                    for name in artifact_names
                )
                or bundle_receipt_name not in artifact_names
            ):
                raise RuntimeError("recovery publication journal paths are invalid")
            output_directory = (store_root / relative_directory).resolve()
            try:
                output_directory.relative_to(store_root)
            except ValueError as exc:
                raise RuntimeError(
                    "recovery publication journal escapes the store root"
                ) from exc
            bundle_receipt_path = output_directory / bundle_receipt_name
            if bundle_receipt_path.is_file() and not bundle_receipt_path.is_symlink():
                try:
                    verified = self._verify_bundle_locked(bundle_receipt_path)
                except (OSError, ValueError, RuntimeError):
                    verified = None
                if verified is not None and bool(verified.get("verified")):
                    bundle_receipt, _identity_trusted = self._read_bundle_receipt(
                        bundle_receipt_path
                    )
                    completed = {
                        "schema": RECOVERY_PUBLICATION_RECEIPT_SCHEMA,
                        "state": "completed",
                        "publication_id": publication_id,
                        "prepared_receipt_digest": str(
                            prepared["receipt_digest"]
                        ),
                        "bundle_receipt_digest": str(
                            bundle_receipt["receipt_digest"]
                        ),
                        "artifact_count": len(artifact_names),
                        "verified": True,
                        "created_at": time.time(),
                    }
                    self.store._authenticate_receipt(completed)
                    self.store._write_private_json_exclusive(
                        completed_path,
                        completed,
                    )
                    continue
            quarantine_root = (
                store_root / "backups" / "incomplete-publications"
            )
            self.store._ensure_directory(quarantine_root, owned=True)
            quarantine = quarantine_root / publication_id
            if quarantine.exists():
                metadata = os.lstat(quarantine)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                ):
                    raise RuntimeError(
                        "incomplete publication quarantine is unsafe"
                    )
            else:
                os.mkdir(quarantine, mode=0o700)
                self.store._fsync_directory(quarantine_root)
            moved_count = 0
            for artifact_name in artifact_names:
                source = output_directory / artifact_name
                destination = quarantine / artifact_name
                source_exists = source.exists() or source.is_symlink()
                destination_exists = destination.exists() or destination.is_symlink()
                if source_exists and destination_exists:
                    raise RuntimeError(
                        "incomplete publication has conflicting artifact copies"
                    )
                if source_exists:
                    os.rename(source, destination)
                    moved_count += 1
                    self.store._fsync_directory(output_directory)
                    self.store._fsync_directory(quarantine)
            recovered = {
                "schema": RECOVERY_PUBLICATION_RECEIPT_SCHEMA,
                "state": "recovered",
                "publication_id": publication_id,
                "prepared_receipt_digest": str(prepared["receipt_digest"]),
                "quarantine_relative": str(quarantine.relative_to(store_root)),
                "artifact_count": len(artifact_names),
                "moved_artifact_count": moved_count,
                "recoverable": True,
                "created_at": time.time(),
            }
            self.store._authenticate_receipt(recovered)
            self.store._write_private_json_exclusive(recovered_path, recovered)

    def _validate_capture_source_root(self) -> dict[str, str]:
        if self.capture_root.is_symlink() or not self.capture_root.is_dir():
            raise ValueError("capture source root must already exist as a real directory")
        metadata = os.lstat(self.capture_root)
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise PermissionError("capture source root must be private and user-owned")
        canonical_root = self.store.db_path.parent.expanduser().absolute()
        is_canonical = self.capture_root.resolve() == canonical_root.resolve()
        if not is_canonical and not self.allow_noncanonical_capture_root:
            raise ValueError(
                "capture source root is not the memory store root; explicit noncanonical override required"
            )
        required_names = {
            "capture_inbox",
            "capture_processing",
            "capture_processed",
            "capture_errors",
            "capture_error_archive",
            "capture_error_resolutions",
            "capture_receipts",
            "capture_locks",
        }
        for name in required_names:
            candidate = self.capture_root / name
            if candidate.is_symlink() or not candidate.is_dir():
                raise ValueError("capture source root is missing initialized transport state")
        identity_seed = f"{int(metadata.st_dev)}:{int(metadata.st_ino)}"
        return {
            "capture_root_provenance": (
                "canonical-store-parent" if is_canonical else "explicit-noncanonical"
            ),
            "capture_root_identity_digest": hashlib.sha256(
                identity_seed.encode("ascii")
            ).hexdigest(),
        }

    @staticmethod
    def _capture_archive_path(database_path: Path) -> Path:
        return database_path.with_name(database_path.name + ".capture.tar.gz")

    @staticmethod
    def _media_archive_path(database_path: Path) -> Path:
        return database_path.with_name(database_path.name + ".media.tar.gz")

    def _media_root(self) -> Path:
        return self.store.db_path.parent / "media-cache"

    @staticmethod
    def _bundle_receipt_path(database_path: Path) -> Path:
        return database_path.with_name(database_path.name + ".bundle.receipt.json")

    @staticmethod
    def _request_journal_artifact_path(database_path: Path) -> Path:
        return database_path.with_name(database_path.name + ".requests.sqlite3")

    @staticmethod
    def _request_journal_binding_receipt_path(database_path: Path) -> Path:
        return database_path.with_name(
            database_path.name + ".requests.binding.receipt.json"
        )

    @staticmethod
    def _runtime_state_artifact_path(database_path: Path) -> Path:
        return database_path.with_name(database_path.name + ".runtime-state.json")

    def _store_identity(self) -> str:
        with closing(self.store._connect_read_only()) as conn:
            marker = self.store._core_authority_marker(conn)
            self.store._validate_core_authority_version_pair(conn, marker)
        if marker is not None:
            return str(marker["store_identity"])
        return self.store.store_identity_for_path(self.store.db_path)

    def _live_store_governance(self) -> dict[str, Any]:
        with closing(self.store._connect_read_only()) as conn:
            marker = self.store._core_authority_marker(conn)
            self.store._validate_core_authority_version_pair(conn, marker)
            user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if marker is None:
            if user_version != 5:
                raise RuntimeError(
                    "journal-less recovery is supported only for a pre-governed v5 store"
                )
            return {
                "governance_mode": "pre-governed-v5",
                "store_generation": "legacy-v5",
                "authority_epoch_number": None,
                "store_identity": self.store.store_identity_for_path(
                    self.store.db_path
                ),
                "request_journal_id": None,
            }
        if user_version != SQLITE_USER_VERSION:
            raise RuntimeError("governed recovery requires an authoritative v6 store")
        return {
            "governance_mode": "authoritative-v6",
            "store_generation": f"epoch-{int(marker['epoch'])}",
            "authority_epoch_number": int(marker["epoch"]),
            "store_identity": str(marker["store_identity"]),
            "request_journal_id": str(marker["request_journal_id"]),
        }

    @staticmethod
    def _bounded_capture_limits() -> tuple[int, int, int]:
        max_files = int(os.getenv("SYNAPSE_S2_RECOVERY_MAX_CAPTURE_FILES", "100000"))
        max_total_bytes = int(
            os.getenv("SYNAPSE_S2_RECOVERY_MAX_CAPTURE_BYTES", str(16 * 1024**3))
        )
        max_file_bytes = int(
            os.getenv("SYNAPSE_S2_RECOVERY_MAX_CAPTURE_FILE_BYTES", str(4 * 1024**2))
        )
        if min(max_files, max_total_bytes, max_file_bytes) <= 0:
            raise ValueError("recovery capture limits must be positive")
        return max_files, max_total_bytes, max_file_bytes

    @staticmethod
    def _read_private_regular(path: Path, *, max_bytes: int) -> tuple[bytes, os.stat_result]:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ValueError("capture recovery input must be a non-symlink regular file")
        if before.st_size > max_bytes:
            raise ValueError("capture recovery input exceeds its bounded size")
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
            ):
                raise RuntimeError("capture recovery input changed while opening")
            data = b""
            while len(data) <= max_bytes:
                chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(data)))
                if not chunk:
                    break
                data += chunk
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = os.lstat(path)
        identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity
            or (
                path_after.st_dev,
                path_after.st_ino,
                path_after.st_size,
                path_after.st_mtime_ns,
            )
            != identity
        ):
            raise RuntimeError("capture recovery input changed while reading")
        if len(data) != int(opened.st_size):
            raise RuntimeError("capture recovery input size changed while reading")
        return data, opened

    @staticmethod
    def _journal_column_signature(conn: sqlite3.Connection) -> tuple[tuple[Any, ...], ...]:
        return tuple(
            (
                str(row[1]),
                str(row[2]).upper(),
                int(row[3]),
                row[4],
                int(row[5]),
                int(row[6]),
            )
            for row in conn.execute("PRAGMA table_xinfo(request_journal)").fetchall()
        )

    def inspect_request_journal_snapshot(
        self,
        path: Path,
        *,
        maximum_authority_epoch: int,
    ) -> dict[str, Any]:
        """Inspect one sealed standalone journal without SQLite side effects.

        The caller must quiesce the writer. This verifier accepts no sidecars or
        only the normal sealed clean-close pair of a zero-byte WAL and one
        bounded 32-KiB-aligned SHM, then opens only the main database immutable.
        """

        if maximum_authority_epoch <= 0:
            raise ValueError("request-journal binding requires a governed store epoch")
        source = Path(path).expanduser().absolute()
        reject_sensitive_identifier(source, field="request journal path")
        observed = os.lstat(source)
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o600
            or int(observed.st_nlink) != 1
        ):
            raise PermissionError("request journal is not one private regular file")
        def clean_close_sidecars() -> tuple[tuple[Any, ...], ...]:
            rollback = Path(f"{source}-journal")
            wal = Path(f"{source}-wal")
            shm = Path(f"{source}-shm")
            if rollback.exists() or rollback.is_symlink():
                raise RuntimeError("request journal has rollback state")
            wal_present = wal.exists() or wal.is_symlink()
            shm_present = shm.exists() or shm.is_symlink()
            if wal_present != shm_present:
                raise RuntimeError("request journal has incomplete sidecar state")
            if not wal_present:
                return ()
            snapshots: list[tuple[Any, ...]] = []
            for sidecar in (wal, shm):
                before = os.lstat(sidecar)
                observed_size = int(before.st_size)
                size_valid = (
                    observed_size == 0
                    if sidecar == wal
                    else (
                        32_768 <= observed_size <= 8 * 1024 * 1024
                        and observed_size % 32_768 == 0
                    )
                )
                if (
                    stat.S_ISLNK(before.st_mode)
                    or not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.getuid()
                    or int(before.st_nlink) != 1
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or not size_valid
                ):
                    raise RuntimeError("request journal sidecar is unsafe")
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(sidecar, flags)
                digest = hashlib.sha256()
                try:
                    opened = os.fstat(descriptor)
                    while True:
                        chunk = os.read(descriptor, 65_536)
                        if not chunk:
                            break
                        digest.update(chunk)
                    finished = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                visible = os.lstat(sidecar)

                def identity(value: os.stat_result) -> tuple[int, ...]:
                    return (
                        int(value.st_dev),
                        int(value.st_ino),
                        int(value.st_size),
                        int(value.st_mtime_ns),
                        int(value.st_ctime_ns),
                        int(value.st_uid),
                        int(value.st_nlink),
                        stat.S_IMODE(value.st_mode),
                    )

                identities = {
                    identity(value) for value in (before, opened, finished, visible)
                }
                if len(identities) != 1:
                    raise RuntimeError("request journal sidecar changed while sealed")
                snapshots.append((*identity(before), digest.hexdigest()))
            return tuple(snapshots)

        sidecars_before = clean_close_sidecars()
        uri = source.resolve().as_uri() + "?mode=ro&immutable=1"
        with closing(
            sqlite3.connect(uri, uri=True, isolation_level=None)
        ) as conn, _immutable_read_transaction(conn):
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON")
            conn.execute("PRAGMA trusted_schema = OFF")
            quick_row = conn.execute("PRAGMA quick_check(1)").fetchone()
            integrity_row = conn.execute("PRAGMA integrity_check(1)").fetchone()
            quick_check = [] if quick_row is None else [str(quick_row[0])]
            integrity_check = (
                [] if integrity_row is None else [str(integrity_row[0])]
            )
            application_id = int(conn.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            schema = self.store._sqlite_schema_fingerprint(conn)
            logical_snapshot = self.store._canonical_logical_snapshot_digest(
                conn
            )
            expected_columns = (
                ("caller", "TEXT", 1, None, 1, 0),
                ("request_id", "TEXT", 1, None, 2, 0),
                ("operation", "TEXT", 1, None, 0, 0),
                ("request_fingerprint", "TEXT", 1, None, 0, 0),
                ("authority_epoch", "TEXT", 1, None, 0, 0),
                ("state", "TEXT", 1, None, 0, 0),
                ("result_kind", "TEXT", 0, None, 0, 0),
                ("safe_error_code", "TEXT", 0, None, 0, 0),
                ("accepted_at_unix_ms", "INTEGER", 1, None, 0, 0),
                ("finished_at_unix_ms", "INTEGER", 0, None, 0, 0),
            )
            objects = {
                (str(row[0]), str(row[1]))
                for row in conn.execute(
                    "SELECT type, name FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            if (
                quick_check != ["ok"]
                or integrity_check != ["ok"]
                or application_id != JOURNAL_APPLICATION_ID
                or user_version != JOURNAL_SCHEMA_VERSION
                or str(schema["sha256"]) != REQUEST_JOURNAL_SCHEMA_SHA256
                or self._journal_column_signature(conn) != expected_columns
                or objects
                != {
                    ("table", "request_journal"),
                    ("index", "request_journal_terminal_age"),
                    ("table", "request_journal_metadata"),
                }
            ):
                raise RuntimeError("request journal failed its exact recovery contract")
            metadata_columns = tuple(
                str(row[1])
                for row in conn.execute(
                    "PRAGMA table_info(request_journal_metadata)"
                ).fetchall()
            )
            metadata = {
                str(row[0]): str(row[1])
                for row in conn.execute(
                    "SELECT key, value FROM request_journal_metadata ORDER BY key"
                ).fetchall()
            }
            if (
                metadata_columns != ("key", "value")
                or set(metadata)
                != {"binding_schema", "journal_id", "store_identity"}
                or metadata["binding_schema"] != JOURNAL_BINDING_SCHEMA
                or REQUEST_JOURNAL_ID_RE.fullmatch(metadata["journal_id"]) is None
                or STORE_IDENTITY_RE.fullmatch(metadata["store_identity"]) is None
            ):
                raise RuntimeError(
                    "request journal has an invalid immutable store binding"
                )
            state_counts = {
                "accepted": 0,
                "completed": 0,
                "failed": 0,
                "ambiguous": 0,
            }
            current_epoch_row_count = 0
            maximum_observed_epoch = 0
            maximum_rows = int(
                os.getenv("SYNAPSE_S2_RECOVERY_MAX_JOURNAL_ROWS", "1000000")
            )
            row_count = int(
                conn.execute("SELECT COUNT(*) FROM request_journal").fetchone()[0]
            )
            if maximum_rows <= 0 or row_count > maximum_rows:
                raise RuntimeError("request journal exceeds the recovery row limit")
            result_kinds = {
                "null",
                "boolean",
                "integer",
                "number",
                "string",
                "array",
                "object",
            }
            terminal_errors = set(REQUEST_JOURNAL_SAFE_ERROR_CODES) - {
                "outcome_unknown"
            }
            cursor = conn.execute(
                "SELECT caller, request_id, operation, request_fingerprint, "
                "authority_epoch, state, result_kind, safe_error_code, "
                "accepted_at_unix_ms, finished_at_unix_ms FROM request_journal"
            )
            streamed_row_count = 0
            while True:
                batch = cursor.fetchmany(512)
                if not batch:
                    break
                streamed_row_count += len(batch)
                if streamed_row_count > row_count:
                    raise RuntimeError("request journal changed during bounded inspection")
                for row in batch:
                    caller = str(row["caller"])
                    request_id = str(row["request_id"])
                    operation = str(row["operation"])
                    fingerprint = str(row["request_fingerprint"])
                    authority_epoch = str(row["authority_epoch"])
                    state = str(row["state"])
                    result_kind = row["result_kind"]
                    safe_error_code = row["safe_error_code"]
                    accepted_at = row["accepted_at_unix_ms"]
                    finished_at = row["finished_at_unix_ms"]
                    epoch_match = re.fullmatch(
                        r"epoch-([1-9][0-9]*)", authority_epoch
                    )
                    if (
                        any(
                            REQUEST_JOURNAL_IDENTIFIER_RE.fullmatch(value) is None
                            for value in (caller, request_id, operation)
                        )
                        or BACKUP_DIGEST_RE.fullmatch(fingerprint) is None
                        or epoch_match is None
                        or state not in state_counts
                        or type(accepted_at) is not int
                        or int(accepted_at) <= 0
                    ):
                        raise RuntimeError(
                            "request journal contains an invalid durable row"
                        )
                    for field, value in (
                        ("request caller", caller),
                        ("request id", request_id),
                        ("request operation", operation),
                    ):
                        reject_sensitive_identifier(value, field=field)
                    epoch_number = int(epoch_match.group(1))
                    if epoch_number > maximum_authority_epoch:
                        raise RuntimeError(
                            "request journal belongs to a newer store authority generation"
                        )
                    maximum_observed_epoch = max(
                        maximum_observed_epoch, epoch_number
                    )
                    if epoch_number == maximum_authority_epoch:
                        current_epoch_row_count += 1
                    if state == "accepted":
                        valid_state = (
                            result_kind is None
                            and safe_error_code is None
                            and finished_at is None
                        )
                    elif state == "completed":
                        valid_state = (
                            result_kind in result_kinds
                            and safe_error_code is None
                            and type(finished_at) is int
                            and int(finished_at) >= int(accepted_at)
                        )
                    elif state == "ambiguous":
                        valid_state = (
                            result_kind is None
                            and safe_error_code == "outcome_unknown"
                            and type(finished_at) is int
                            and int(finished_at) >= int(accepted_at)
                        )
                    else:
                        valid_state = (
                            result_kind is None
                            and safe_error_code in terminal_errors
                            and type(finished_at) is int
                            and int(finished_at) >= int(accepted_at)
                        )
                    if not valid_state:
                        raise RuntimeError(
                            "request journal row state is inconsistent"
                        )
                    state_counts[state] += 1
            if streamed_row_count != row_count:
                raise RuntimeError("request journal changed during bounded inspection")
        visible = os.lstat(source)
        if (
            self.store._regular_file_identity(visible)
            != self.store._regular_file_identity(observed)
            or visible.st_uid != observed.st_uid
            or int(visible.st_nlink) != int(observed.st_nlink)
            or stat.S_IMODE(visible.st_mode) != stat.S_IMODE(observed.st_mode)
        ):
            raise RuntimeError("request journal changed during immutable inspection")
        if clean_close_sidecars() != sidecars_before:
            raise RuntimeError("request journal sidecar changed during inspection")
        return {
            "application_id": application_id,
            "schema_version": user_version,
            "schema_identity": JOURNAL_SCHEMA_IDENTITY,
            "schema_sha256": str(schema["sha256"]),
            "logical_snapshot_schema": str(logical_snapshot["schema"]),
            "logical_snapshot_sha256": str(logical_snapshot["sha256"]),
            "logical_snapshot_table_count": int(logical_snapshot["table_count"]),
            "logical_snapshot_column_count": int(logical_snapshot["column_count"]),
            "logical_snapshot_row_count": int(logical_snapshot["row_count"]),
            "logical_snapshot_value_bytes": int(logical_snapshot["value_bytes"]),
            "row_count": row_count,
            "state_counts": state_counts,
            "current_authority_epoch_row_count": current_epoch_row_count,
            "maximum_observed_authority_epoch": maximum_observed_epoch,
            "journal_id": metadata["journal_id"],
            "store_identity": metadata["store_identity"],
            "quick_check": quick_check,
            "integrity_check": integrity_check,
            "verified": True,
        }

    def recompute_request_journal_logical_digest(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        maximum_authority_epoch: int | None = None,
    ) -> dict[str, Any]:
        """Recompute the live journal's exact logical digest without mutation.

        Unlike recovery-artifact verification, this opens SQLite without
        ``immutable=1`` so committed WAL pages participate in one explicit
        read transaction.  The generic logical digest scanner supplies the
        deterministic ordering, byte/row bounds, and schema identity.
        """

        source = (
            self.store.db_path.parent / "core" / "requests.sqlite3"
            if path is None
            else Path(path).expanduser().absolute()
        )
        reject_sensitive_identifier(source, field="request journal path")
        observed = os.lstat(source)
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) & 0o077
            or int(observed.st_nlink) != 1
        ):
            raise PermissionError("live request journal is not private")
        uri = source.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON")
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("BEGIN")
            try:
                application_id = int(
                    conn.execute("PRAGMA application_id").fetchone()[0]
                )
                user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
                schema = self.store._sqlite_schema_fingerprint(conn)
                if (
                    application_id != JOURNAL_APPLICATION_ID
                    or user_version != JOURNAL_SCHEMA_VERSION
                    or str(schema["sha256"]) != REQUEST_JOURNAL_SCHEMA_SHA256
                ):
                    raise RuntimeError(
                        "live request journal failed its exact schema contract"
                    )
                maximum_rows = int(
                    os.getenv("SYNAPSE_S2_RECOVERY_MAX_JOURNAL_ROWS", "1000000")
                )
                row_count = int(
                    conn.execute("SELECT COUNT(*) FROM request_journal").fetchone()[0]
                )
                if maximum_rows <= 0 or row_count > maximum_rows:
                    raise RuntimeError("request journal exceeds the recovery row limit")
                maximum_observed_epoch = 0
                for epoch_row in conn.execute(
                    "SELECT authority_epoch FROM request_journal "
                    "GROUP BY authority_epoch"
                ):
                    match = re.fullmatch(
                        r"epoch-([1-9][0-9]*)", str(epoch_row[0])
                    )
                    if match is None:
                        raise RuntimeError(
                            "live request journal contains an invalid authority epoch"
                        )
                    maximum_observed_epoch = max(
                        maximum_observed_epoch,
                        int(match.group(1)),
                    )
                if (
                    maximum_authority_epoch is not None
                    and maximum_observed_epoch > int(maximum_authority_epoch)
                ):
                    raise RuntimeError(
                        "live request journal belongs to a newer authority generation"
                    )
                state_counts = {
                    "accepted": 0,
                    "completed": 0,
                    "failed": 0,
                    "ambiguous": 0,
                }
                for state_row in conn.execute(
                    "SELECT state, COUNT(*) FROM request_journal GROUP BY state"
                ):
                    state = str(state_row[0])
                    if state not in state_counts:
                        raise RuntimeError(
                            "live request journal contains an invalid state"
                        )
                    state_counts[state] = int(state_row[1])
                metadata = {
                    str(row[0]): str(row[1])
                    for row in conn.execute(
                        "SELECT key, value FROM request_journal_metadata ORDER BY key"
                    ).fetchall()
                }
                if (
                    set(metadata)
                    != {"binding_schema", "journal_id", "store_identity"}
                    or metadata["binding_schema"] != JOURNAL_BINDING_SCHEMA
                    or REQUEST_JOURNAL_ID_RE.fullmatch(metadata["journal_id"])
                    is None
                    or STORE_IDENTITY_RE.fullmatch(metadata["store_identity"])
                    is None
                ):
                    raise RuntimeError(
                        "live request journal has an invalid immutable binding"
                    )
                logical_snapshot = self.store._canonical_logical_snapshot_digest(
                    conn
                )
            finally:
                conn.execute("ROLLBACK")
        visible = os.lstat(source)
        if (
            int(visible.st_dev),
            int(visible.st_ino),
        ) != (
            int(observed.st_dev),
            int(observed.st_ino),
        ):
            raise RuntimeError("live request journal identity changed during attestation")
        return {
            "path": str(source),
            "application_id": application_id,
            "schema_version": user_version,
            "schema_identity": JOURNAL_SCHEMA_IDENTITY,
            "schema_sha256": str(schema["sha256"]),
            "logical_snapshot_schema": str(logical_snapshot["schema"]),
            "logical_snapshot_sha256": str(logical_snapshot["sha256"]),
            "logical_snapshot_table_count": int(logical_snapshot["table_count"]),
            "logical_snapshot_column_count": int(logical_snapshot["column_count"]),
            "logical_snapshot_row_count": int(logical_snapshot["row_count"]),
            "logical_snapshot_value_bytes": int(logical_snapshot["value_bytes"]),
            "row_count": row_count,
            "state_counts": state_counts,
            "maximum_observed_authority_epoch": maximum_observed_epoch,
            "journal_id": metadata["journal_id"],
            "store_identity": metadata["store_identity"],
            "verified": True,
        }

    def _snapshot_request_journal(
        self,
        destination: Path,
        *,
        maximum_authority_epoch: int,
    ) -> dict[str, Any]:
        source = self.store.db_path.parent / "core" / "requests.sqlite3"
        source_parent = source.parent
        parent_metadata = os.lstat(source_parent)
        source_metadata = os.lstat(source)
        maximum_bytes = int(
            os.getenv(
                "SYNAPSE_S2_RECOVERY_MAX_JOURNAL_BYTES",
                str(512 * 1024**2),
            )
        )
        if maximum_bytes <= 0 or int(source_metadata.st_size) > maximum_bytes:
            raise RuntimeError("authoritative request journal exceeds its recovery limit")
        if (
            stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.getuid()
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            or stat.S_ISLNK(source_metadata.st_mode)
            or not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_uid != os.getuid()
            or source_metadata.st_nlink != 1
            or stat.S_IMODE(source_metadata.st_mode) != 0o600
        ):
            raise PermissionError("authoritative request journal is not private")
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{source}{suffix}")
            try:
                observed = os.lstat(sidecar)
            except FileNotFoundError:
                continue
            if (
                stat.S_ISLNK(observed.st_mode)
                or not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != os.getuid()
                or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != 0o600
            ):
                raise PermissionError("authoritative request-journal sidecar is unsafe")
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("request-journal recovery artifact already exists")
        temporary = self.store._unique_private_temp_path(
            destination.parent,
            prefix=f".{destination.name}.",
        )
        published = False
        try:
            source_uri = source.resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(source_uri, uri=True)) as journal_source:
                journal_source.execute("PRAGMA query_only = ON")
                with closing(sqlite3.connect(temporary)) as journal_destination:
                    journal_source.backup(journal_destination)
                    journal_destination.commit()
            source_after = os.lstat(source)
            if self.store._regular_file_identity(source_metadata) != self.store._regular_file_identity(
                source_after
            ):
                raise RuntimeError("request journal changed identity during snapshot")
            self.store._fsync_file(temporary)
            inspection = self.inspect_request_journal_snapshot(
                temporary,
                maximum_authority_epoch=maximum_authority_epoch,
            )
            digest, size_bytes, _ = self.store._hash_stable_regular_file(temporary)
            if int(size_bytes) > maximum_bytes:
                raise RuntimeError("request-journal snapshot exceeds its recovery limit")
            os.link(temporary, destination, follow_symlinks=False)
            published = True
            os.chmod(destination, 0o600, follow_symlinks=False)
            self.store._fsync_file(destination)
            final_digest, final_size, final_metadata = self.store._hash_stable_regular_file(
                destination
            )
            if (
                not secrets.compare_digest(digest, final_digest)
                or int(size_bytes) != int(final_size)
                or int(final_metadata.st_nlink) != 2
            ):
                raise RuntimeError("request-journal publication changed after verification")
            temporary.unlink()
            self.store._fsync_directory(destination.parent)
            return {
                **inspection,
                "sha256": final_digest,
                "size_bytes": final_size,
                "artifact_path": str(destination),
            }
        except BaseException:
            temporary.unlink(missing_ok=True)
            if published:
                destination.unlink(missing_ok=True)
            self.store._fsync_directory(destination.parent)
            raise

    def _verify_request_journal_artifact(
        self,
        path: Path,
        *,
        expected_sha256: str,
        maximum_authority_epoch: int,
    ) -> dict[str, Any]:
        if BACKUP_DIGEST_RE.fullmatch(expected_sha256) is None:
            raise ValueError("request-journal digest is invalid")
        maximum_bytes = int(
            os.getenv(
                "SYNAPSE_S2_RECOVERY_MAX_JOURNAL_BYTES",
                str(512 * 1024**2),
            )
        )
        if maximum_bytes <= 0 or int(os.lstat(path).st_size) > maximum_bytes:
            raise RuntimeError("request-journal artifact exceeds its recovery limit")
        staging_dir = self.store._backup_verification_staging_dir()
        temporary = self.store._unique_private_temp_path(
            staging_dir,
            prefix=f".{path.name}.journal-verify.",
        )
        try:
            copied = self.store._copy_stable_regular_file(path, temporary)
            if not secrets.compare_digest(str(copied["sha256"]), expected_sha256):
                raise RuntimeError("request-journal artifact digest verification failed")
            inspection = self.inspect_request_journal_snapshot(
                temporary,
                maximum_authority_epoch=maximum_authority_epoch,
            )
            return {
                **inspection,
                "sha256": str(copied["sha256"]),
                "size_bytes": int(copied["size_bytes"]),
                "artifact_path": str(path),
            }
        finally:
            temporary.unlink(missing_ok=True)
            self.store._fsync_directory(staging_dir)

    @contextmanager
    def _runtime_state_lock(self, *, read_only: bool = False) -> Iterable[None]:
        lock_path = self.runtime_state_path.with_name(
            f".{self.runtime_state_path.name}.lock"
        )
        if read_only:
            observed = os.lstat(lock_path)
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(lock_path, flags)
            opened = os.fstat(descriptor)
            if (
                stat.S_ISLNK(observed.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.getuid()
                or int(opened.st_nlink) != 1
                or stat.S_IMODE(opened.st_mode) != 0o600
                or self.store._regular_file_identity(observed)
                != self.store._regular_file_identity(opened)
            ):
                os.close(descriptor)
                raise PermissionError("runtime-state lock is not private")
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            visible = os.lstat(lock_path)
            if self.store._regular_file_identity(visible) != self.store._regular_file_identity(opened):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
                raise RuntimeError("runtime-state lock identity changed")
        else:
            descriptor = self.store._acquire_file_lock(
                lock_path,
                mode=fcntl.LOCK_EX,
                timeout_seconds=30.0,
            )
        try:
            yield
        finally:
            self.store._release_file_lock(descriptor)

    def recompute_live_runtime_state_binding(
        self,
        *,
        required: bool | None = None,
    ) -> dict[str, Any]:
        """Read-only canonical runtime-state evidence under its existing lock."""

        runtime_required = (
            self._live_store_governance()["governance_mode"] == "authoritative-v6"
            if required is None
            else bool(required)
        )
        with self._runtime_state_lock(read_only=True):
            if not self.runtime_state_path.exists():
                if runtime_required:
                    raise RuntimeError("required runtime state is absent")
                return {
                    "required": False,
                    "present": False,
                    "artifact_sha256": None,
                    "canonical_sha256": None,
                    "state_schema_version": None,
                    "size_bytes": 0,
                    "verified": True,
                }
            data, metadata = self._read_private_regular(
                self.runtime_state_path,
                max_bytes=int(
                    os.getenv(
                        "SYNAPSE_S2_RECOVERY_MAX_RUNTIME_STATE_BYTES",
                        str(8 * 1024**2),
                    )
                ),
            )
            if (
                metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or int(metadata.st_nlink) != 1
            ):
                raise PermissionError("runtime state is not private")
            inspection = self._inspect_runtime_state_bytes(data)
            return {
                "required": runtime_required,
                "present": True,
                "artifact_sha256": hashlib.sha256(data).hexdigest(),
                "canonical_sha256": str(inspection["canonical_sha256"]),
                "state_schema_version": int(inspection["state_schema_version"]),
                "size_bytes": len(data),
                "global_enabled": bool(inspection["global_enabled"]),
                "context_override_count": int(
                    inspection["context_override_count"]
                ),
                "cortex_session_count": int(inspection["cortex_session_count"]),
                "verified": True,
            }

    def _inspect_runtime_state_bytes(self, data: bytes) -> dict[str, Any]:
        maximum_bytes = int(
            os.getenv("SYNAPSE_S2_RECOVERY_MAX_RUNTIME_STATE_BYTES", str(8 * 1024**2))
        )
        if maximum_bytes <= 0 or not data or len(data) > maximum_bytes:
            raise RuntimeError("runtime state exceeds its recovery limit")
        self._assert_secret_safe_text(data)
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("runtime state artifact is invalid JSON") from exc
        base_keys = {
            "version",
            "global_enabled",
            "context_overrides",
            "cortex_sessions",
            "runtime_state_repair",
            "memory_db_path",
            "updated_at",
        }
        state_version = payload.get("version") if isinstance(payload, dict) else None
        expected_keys = (
            base_keys
            if state_version == 2
            else base_keys | {"authority_binding"}
        )
        authority_binding = (
            payload.get("authority_binding") if isinstance(payload, dict) else None
        )
        authority_binding_valid = state_version == 2 or (
            state_version == 3
            and isinstance(authority_binding, dict)
            and set(authority_binding)
            == {
                "schema",
                "marker_sha256",
                "authority_epoch_number",
                "lock_generation_id",
            }
            and authority_binding.get("schema")
            == RUNTIME_STATE_AUTHORITY_BINDING_SCHEMA
            and BACKUP_DIGEST_RE.fullmatch(
                str(authority_binding.get("marker_sha256") or "")
            )
            is not None
            and type(authority_binding.get("authority_epoch_number")) is int
            and int(authority_binding["authority_epoch_number"]) > 0
            and RUNTIME_STATE_AUTHORITY_LOCK_RE.fullmatch(
                str(authority_binding.get("lock_generation_id") or "")
            )
            is not None
        )
        if (
            not isinstance(payload, dict)
            or set(payload) != expected_keys
            or state_version not in {2, 3}
            or not authority_binding_valid
            or type(payload.get("global_enabled")) is not bool
            or not isinstance(payload.get("context_overrides"), dict)
            or any(
                not isinstance(key, str) or type(value) is not bool
                for key, value in payload["context_overrides"].items()
            )
            or not isinstance(payload.get("cortex_sessions"), dict)
            or not isinstance(payload.get("runtime_state_repair"), dict)
            or not isinstance(payload.get("memory_db_path"), str)
            or not isinstance(payload.get("updated_at"), (int, float))
            or isinstance(payload.get("updated_at"), bool)
            or not math.isfinite(float(payload["updated_at"]))
        ):
            raise ValueError("runtime state artifact contract is unsupported")
        canonical_sha256 = hashlib.sha256(
            _json_dumps(payload).encode("utf-8")
        ).hexdigest()
        return {
            "binding_schema": RUNTIME_STATE_BINDING_SCHEMA,
            "state_schema_version": int(state_version),
            "canonical_sha256": canonical_sha256,
            "context_override_count": len(payload["context_overrides"]),
            "cortex_session_count": len(payload["cortex_sessions"]),
            "global_enabled": bool(payload["global_enabled"]),
        }

    def _snapshot_runtime_state(self, destination: Path) -> dict[str, Any]:
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("runtime-state recovery artifact already exists")
        source = self.runtime_state_path
        parent = os.lstat(source.parent)
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) & 0o077
        ):
            raise PermissionError("runtime state parent is not private")
        with self._runtime_state_lock():
            data, metadata = self._read_private_regular(
                source,
                max_bytes=int(
                    os.getenv(
                        "SYNAPSE_S2_RECOVERY_MAX_RUNTIME_STATE_BYTES",
                        str(8 * 1024**2),
                    )
                ),
            )
            if (
                metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or int(metadata.st_nlink) != 1
            ):
                raise PermissionError("runtime state is not private")
            inspection = self._inspect_runtime_state_bytes(data)
            temporary = self.store._unique_private_temp_path(
                destination.parent,
                prefix=f".{destination.name}.",
            )
            published = False
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY
                    | os.O_TRUNC
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    offset = 0
                    while offset < len(data):
                        offset += os.write(descriptor, data[offset:])
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                digest = hashlib.sha256(data).hexdigest()
                os.link(temporary, destination, follow_symlinks=False)
                published = True
                os.chmod(destination, 0o600, follow_symlinks=False)
                self.store._fsync_file(destination)
                final_digest, final_size, final_metadata = (
                    self.store._hash_stable_regular_file(destination)
                )
                if (
                    not secrets.compare_digest(digest, final_digest)
                    or int(final_size) != len(data)
                    or int(final_metadata.st_nlink) != 2
                ):
                    raise RuntimeError(
                        "runtime-state publication changed after verification"
                    )
                temporary.unlink()
                self.store._fsync_directory(destination.parent)
                return {
                    **inspection,
                    "sha256": final_digest,
                    "size_bytes": final_size,
                    "artifact_path": str(destination),
                }
            except BaseException:
                temporary.unlink(missing_ok=True)
                if published:
                    destination.unlink(missing_ok=True)
                self.store._fsync_directory(destination.parent)
                raise

    def _verify_runtime_state_artifact(
        self,
        path: Path,
        *,
        expected_sha256: str,
    ) -> dict[str, Any]:
        data, metadata = self._read_private_regular(
            path,
            max_bytes=int(
                os.getenv(
                    "SYNAPSE_S2_RECOVERY_MAX_RUNTIME_STATE_BYTES",
                    str(8 * 1024**2),
                )
            ),
        )
        if (
            metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or int(metadata.st_nlink) != 1
        ):
            raise PermissionError("runtime-state recovery artifact is not private")
        digest = hashlib.sha256(data).hexdigest()
        if not secrets.compare_digest(digest, expected_sha256):
            raise RuntimeError("runtime-state recovery artifact digest mismatch")
        return {
            **self._inspect_runtime_state_bytes(data),
            "sha256": digest,
            "size_bytes": len(data),
            "artifact_path": str(path),
            "verified": True,
        }

    def _restore_runtime_state_artifact(
        self,
        source: Path,
        target: Path,
        *,
        expected_source_sha256: str,
        restored_memory_path: Path,
    ) -> dict[str, Any]:
        source_data, _source_metadata = self._read_private_regular(
            source,
            max_bytes=int(
                os.getenv(
                    "SYNAPSE_S2_RECOVERY_MAX_RUNTIME_STATE_BYTES",
                    str(8 * 1024**2),
                )
            ),
        )
        source_sha256 = hashlib.sha256(source_data).hexdigest()
        if not secrets.compare_digest(source_sha256, expected_source_sha256):
            raise RuntimeError("runtime state changed before isolated restore")
        source_inspection = self._inspect_runtime_state_bytes(source_data)
        payload = json.loads(source_data.decode("utf-8"))
        payload["memory_db_path"] = str(restored_memory_path)
        if target.exists() or target.is_symlink():
            raise FileExistsError("restored runtime state target already exists")
        self.store._write_private_json_exclusive(target, payload)
        try:
            restored_data, restored_metadata = self._read_private_regular(
                target,
                max_bytes=int(
                    os.getenv(
                        "SYNAPSE_S2_RECOVERY_MAX_RUNTIME_STATE_BYTES",
                        str(8 * 1024**2),
                    )
                ),
            )
            if (
                restored_metadata.st_uid != os.getuid()
                or stat.S_IMODE(restored_metadata.st_mode) != 0o600
                or int(restored_metadata.st_nlink) != 1
            ):
                raise PermissionError("restored runtime state is not private")
            restored_inspection = self._inspect_runtime_state_bytes(restored_data)
            restored_payload = json.loads(restored_data.decode("utf-8"))
            if restored_payload.get("memory_db_path") != str(restored_memory_path):
                raise RuntimeError(
                    "restored runtime state does not identify the restored database"
                )
            return {
                **restored_inspection,
                "path": str(target),
                "sha256": hashlib.sha256(restored_data).hexdigest(),
                "size_bytes": len(restored_data),
                "memory_db_path": str(restored_memory_path),
                "source_sha256": source_sha256,
                "source_canonical_sha256": str(
                    source_inspection["canonical_sha256"]
                ),
                "verified": True,
            }
        except BaseException:
            target.unlink(missing_ok=True)
            self.store._fsync_directory(target.parent)
            raise

    def _assert_memory_snapshot_fence(
        self,
        *,
        expected_logical_snapshot_sha256: str,
        expected_store_generation: str,
    ) -> None:
        """Prove no memory mutation crossed the journal snapshot interval."""

        staging_dir = self.store._backup_verification_staging_dir()
        temporary = self.store._unique_private_temp_path(
            staging_dir,
            prefix=".request-journal-memory-fence.",
        )
        try:
            with closing(self.store._connect_read_only()) as source:
                with closing(sqlite3.connect(temporary)) as destination:
                    source.backup(destination)
                    destination.commit()
            self.store._fsync_file(temporary)
            inspection = self.store._inspect_backup_snapshot(temporary)
            if (
                not secrets.compare_digest(
                    str(inspection["logical_snapshot"]["sha256"]),
                    expected_logical_snapshot_sha256,
                )
                or str(inspection["authority_binding"]["store_generation"])
                != expected_store_generation
            ):
                raise RuntimeError(
                    "memory store changed while its request journal was being snapshotted"
                )
        finally:
            temporary.unlink(missing_ok=True)
            self.store._fsync_directory(staging_dir)

    def _restore_private_artifact(
        self,
        source: Path,
        target: Path,
        *,
        expected_sha256: str,
    ) -> dict[str, Any]:
        if target.exists() or target.is_symlink():
            raise FileExistsError("recovery artifact target already exists")
        temporary = self.store._unique_private_temp_path(
            target.parent,
            prefix=f".{target.name}.restore.",
        )
        published = False
        try:
            copied = self.store._copy_stable_regular_file(source, temporary)
            if not secrets.compare_digest(
                str(copied["sha256"]), expected_sha256
            ):
                raise RuntimeError("recovery artifact changed before restore")
            os.link(temporary, target, follow_symlinks=False)
            published = True
            os.chmod(target, 0o600, follow_symlinks=False)
            self.store._fsync_file(target)
            digest, size_bytes, metadata = self.store._hash_stable_regular_file(target)
            if (
                not secrets.compare_digest(digest, expected_sha256)
                or int(metadata.st_nlink) != 2
            ):
                raise RuntimeError("restored recovery artifact changed after publication")
            temporary.unlink()
            self.store._fsync_directory(target.parent)
            return {"path": str(target), "sha256": digest, "size_bytes": size_bytes}
        except BaseException:
            temporary.unlink(missing_ok=True)
            if published:
                target.unlink(missing_ok=True)
            self.store._fsync_directory(target.parent)
            raise

    @staticmethod
    def _request_journal_binding_expected_keys() -> set[str]:
        return {
            "schema",
            "journal_artifact_name",
            "journal_sha256",
            "journal_size_bytes",
            "journal_application_id",
            "journal_schema_version",
            "journal_schema_identity",
            "journal_schema_sha256",
            "journal_logical_snapshot_schema",
            "journal_logical_snapshot_sha256",
            "journal_logical_snapshot_table_count",
            "journal_logical_snapshot_column_count",
            "journal_logical_snapshot_row_count",
            "journal_logical_snapshot_value_bytes",
            "journal_row_count",
            "journal_state_counts",
            "journal_current_authority_epoch_row_count",
            "journal_maximum_observed_authority_epoch",
            "request_journal_id",
            "database_artifact_name",
            "database_sha256",
            "database_receipt_digest",
            "database_schema_contract_version",
            "database_snapshot_revision",
            "database_logical_snapshot_schema",
            "database_logical_snapshot_sha256",
            "store_identity",
            "store_generation",
            "authority_epoch_number",
            "created_at",
            "auth_algorithm",
            "auth_key_id",
            "signing_public_key",
            "receipt_digest",
            "receipt_signature",
        }

    def _read_request_journal_binding_receipt(
        self,
        path: Path,
    ) -> tuple[dict[str, Any], bool]:
        data, metadata = self._read_private_regular(path, max_bytes=1024 * 1024)
        if (
            metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or int(metadata.st_nlink) != 1
        ):
            raise PermissionError("request-journal binding receipt is not private")
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("request-journal binding receipt is invalid JSON") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != RECOVERY_REQUEST_JOURNAL_BINDING_SCHEMA
            or set(payload) != self._request_journal_binding_expected_keys()
        ):
            raise ValueError("request-journal binding receipt contract is unsupported")
        digest_fields = (
            "journal_sha256",
            "journal_schema_sha256",
            "journal_logical_snapshot_sha256",
            "database_sha256",
            "database_receipt_digest",
            "database_snapshot_revision",
            "database_logical_snapshot_sha256",
            "receipt_digest",
        )
        if any(
            BACKUP_DIGEST_RE.fullmatch(str(payload.get(field) or "")) is None
            for field in digest_fields
        ):
            raise ValueError("request-journal binding receipt digest is invalid")
        state_counts = payload.get("journal_state_counts")
        if (
            type(payload.get("journal_size_bytes")) is not int
            or int(payload["journal_size_bytes"]) <= 0
            or type(payload.get("journal_application_id")) is not int
            or int(payload["journal_application_id"]) != JOURNAL_APPLICATION_ID
            or type(payload.get("journal_schema_version")) is not int
            or int(payload["journal_schema_version"]) != JOURNAL_SCHEMA_VERSION
            or payload.get("journal_schema_identity") != JOURNAL_SCHEMA_IDENTITY
            or REQUEST_JOURNAL_ID_RE.fullmatch(
                str(payload.get("request_journal_id") or "")
            )
            is None
            or payload.get("journal_logical_snapshot_schema")
            != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
            or any(
                type(payload.get(field)) is not int
                or int(payload[field]) < 0
                for field in (
                    "journal_logical_snapshot_table_count",
                    "journal_logical_snapshot_column_count",
                    "journal_logical_snapshot_row_count",
                    "journal_logical_snapshot_value_bytes",
                )
            )
            or type(payload.get("journal_row_count")) is not int
            or int(payload["journal_row_count"]) < 0
            or type(payload.get("authority_epoch_number")) is not int
            or int(payload["authority_epoch_number"]) <= 0
            or type(payload.get("journal_current_authority_epoch_row_count")) is not int
            or int(payload["journal_current_authority_epoch_row_count"]) < 0
            or type(payload.get("journal_maximum_observed_authority_epoch")) is not int
            or int(payload["journal_maximum_observed_authority_epoch"]) < 0
            or payload.get("database_logical_snapshot_schema")
            != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
            or not isinstance(state_counts, dict)
            or set(state_counts) != {"accepted", "completed", "failed", "ambiguous"}
            or any(type(value) is not int or value < 0 for value in state_counts.values())
            or not isinstance(payload.get("created_at"), (int, float))
            or not math.isfinite(float(payload["created_at"]))
        ):
            raise ValueError("request-journal binding receipt fields are invalid")
        if not secrets.compare_digest(
            str(payload["receipt_digest"]),
            self.store._canonical_payload_digest(payload),
        ):
            raise ValueError("request-journal binding receipt digest validation failed")
        return payload, self.store._verify_receipt_authenticator(payload)

    @staticmethod
    def _restore_binding_expected_keys() -> set[str]:
        return {
            "schema",
            "memory_artifact_relative",
            "memory_sha256",
            "memory_size_bytes",
            "memory_schema_contract_version",
            "memory_schema_identity",
            "memory_snapshot_revision",
            "memory_logical_snapshot_schema",
            "memory_logical_snapshot_sha256",
            "memory_logical_snapshot_table_count",
            "memory_logical_snapshot_column_count",
            "memory_logical_snapshot_row_count",
            "memory_logical_snapshot_value_bytes",
            "request_journal_artifact_relative",
            "request_journal_sha256",
            "request_journal_size_bytes",
            "request_journal_application_id",
            "request_journal_schema_version",
            "request_journal_schema_identity",
            "request_journal_schema_sha256",
            "request_journal_logical_snapshot_schema",
            "request_journal_logical_snapshot_sha256",
            "request_journal_logical_snapshot_table_count",
            "request_journal_logical_snapshot_column_count",
            "request_journal_logical_snapshot_row_count",
            "request_journal_logical_snapshot_value_bytes",
            "request_journal_row_count",
            "request_journal_state_counts",
            "request_journal_current_authority_epoch_row_count",
            "request_journal_maximum_observed_authority_epoch",
            "request_journal_id",
            "runtime_state_artifact_relative",
            "runtime_state_sha256",
            "runtime_state_size_bytes",
            "runtime_state_binding_schema",
            "runtime_state_schema_version",
            "runtime_state_canonical_sha256",
            "runtime_state_memory_db_path",
            "source_runtime_state_sha256",
            "source_runtime_state_canonical_sha256",
            "store_identity",
            "store_generation",
            "authority_epoch_number",
            "source_request_journal_binding_receipt_digest",
            "source_database_receipt_digest",
            "source_bundle_receipt_digest",
            "created_at",
            "auth_algorithm",
            "auth_key_id",
            "signing_public_key",
            "receipt_digest",
            "receipt_signature",
        }

    def _read_restore_binding_receipt(
        self,
        path: Path,
        *,
        require_local_trust_anchor: bool = True,
    ) -> dict[str, Any]:
        data, metadata = self._read_private_regular(path, max_bytes=1024 * 1024)
        if (
            metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or int(metadata.st_nlink) != 1
        ):
            raise PermissionError("restored request-journal binding is not private")
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("restored request-journal binding is invalid JSON") from exc
        digest_fields = (
            "memory_sha256",
            "memory_snapshot_revision",
            "memory_logical_snapshot_sha256",
            "request_journal_sha256",
            "request_journal_schema_sha256",
            "request_journal_logical_snapshot_sha256",
            "runtime_state_sha256",
            "runtime_state_canonical_sha256",
            "source_runtime_state_sha256",
            "source_runtime_state_canonical_sha256",
            "source_request_journal_binding_receipt_digest",
            "source_database_receipt_digest",
            "source_bundle_receipt_digest",
            "receipt_digest",
        )
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != REQUEST_JOURNAL_RESTORE_BINDING_SCHEMA
            or set(payload) != self._restore_binding_expected_keys()
            or any(
                BACKUP_DIGEST_RE.fullmatch(str(payload.get(field) or "")) is None
                for field in digest_fields
            )
            or payload.get("memory_artifact_relative") != "memory.sqlite3"
            or payload.get("request_journal_artifact_relative")
            != "core/requests.sqlite3"
            or payload.get("runtime_state_artifact_relative")
            != "runtime_state.json"
            or payload.get("memory_logical_snapshot_schema")
            != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
            or payload.get("request_journal_logical_snapshot_schema")
            != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
            or payload.get("request_journal_schema_identity")
            != JOURNAL_SCHEMA_IDENTITY
            or REQUEST_JOURNAL_ID_RE.fullmatch(
                str(payload.get("request_journal_id") or "")
            )
            is None
            or payload.get("runtime_state_binding_schema")
            != RUNTIME_STATE_BINDING_SCHEMA
            or payload.get("runtime_state_schema_version") not in {2, 3}
            or not isinstance(payload.get("runtime_state_memory_db_path"), str)
            or REQUEST_JOURNAL_IDENTIFIER_RE.fullmatch(
                str(payload.get("store_identity") or "")
            )
            is None
            or REQUEST_JOURNAL_IDENTIFIER_RE.fullmatch(
                str(payload.get("store_generation") or "")
            )
            is None
            or type(payload.get("authority_epoch_number")) is not int
            or int(payload["authority_epoch_number"]) <= 0
            or not isinstance(payload.get("created_at"), (int, float))
            or isinstance(payload.get("created_at"), bool)
            or not math.isfinite(float(payload["created_at"]))
        ):
            raise ValueError("restored request-journal binding contract is invalid")
        integer_fields = (
            "memory_size_bytes",
            "memory_logical_snapshot_table_count",
            "memory_logical_snapshot_column_count",
            "memory_logical_snapshot_row_count",
            "memory_logical_snapshot_value_bytes",
            "request_journal_size_bytes",
            "request_journal_application_id",
            "request_journal_schema_version",
            "request_journal_logical_snapshot_table_count",
            "request_journal_logical_snapshot_column_count",
            "request_journal_logical_snapshot_row_count",
            "request_journal_logical_snapshot_value_bytes",
            "request_journal_row_count",
            "request_journal_current_authority_epoch_row_count",
            "request_journal_maximum_observed_authority_epoch",
            "runtime_state_size_bytes",
        )
        if any(
            type(payload.get(field)) is not int
            or int(payload[field]) < (1 if field in {"memory_size_bytes", "request_journal_size_bytes", "request_journal_schema_version", "runtime_state_size_bytes"} else 0)
            for field in integer_fields
        ):
            raise ValueError("restored request-journal binding counters are invalid")
        state_counts = payload.get("request_journal_state_counts")
        if (
            not isinstance(state_counts, dict)
            or set(state_counts) != {"accepted", "completed", "failed", "ambiguous"}
            or any(
                type(value) is not int or value < 0
                for value in state_counts.values()
            )
            or sum(int(value) for value in state_counts.values())
            != int(payload["request_journal_row_count"])
        ):
            raise ValueError("restored request-journal binding state counts are invalid")
        digest_verified = secrets.compare_digest(
            str(payload["receipt_digest"]),
            self.store._canonical_payload_digest(payload),
        )
        signer_locally_trusted = self.store._verify_receipt_authenticator(payload)
        if (
            not digest_verified
            or (require_local_trust_anchor and not signer_locally_trusted)
        ):
            raise ValueError("restored request-journal binding signer is not trusted")
        return payload

    def _inspect_live_restored_memory_binding(self) -> dict[str, Any]:
        """Inspect the active memory target through one WAL-aware read snapshot."""

        observed = self.store._assert_private_database_identity()
        with closing(self.store._connect_read_only()) as conn:
            conn.row_factory = sqlite3.Row
            data_version_before = int(
                conn.execute("PRAGMA data_version").fetchone()[0]
            )
            conn.execute("BEGIN")
            try:
                logical_snapshot = self.store._canonical_logical_snapshot_digest(
                    conn
                )
                marker = self.store._core_authority_marker(conn)
                self.store._validate_core_authority_version_pair(conn, marker)
                if marker is None:
                    raise RuntimeError(
                        "restored request-journal binding requires governed memory"
                    )
                schema = self.store._sqlite_schema_fingerprint(conn)
                migrations = sorted(
                    str(row[0])
                    for row in conn.execute(
                        "SELECT key FROM store_migrations ORDER BY key"
                    ).fetchall()
                )
                schema_contract = {
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
                matching_contract_versions = _matching_backup_schema_contract_versions(
                    schema_contract
                )
                if not matching_contract_versions:
                    raise RuntimeError(
                        "live restored memory failed its schema contract"
                    )
                tables = {
                    str(row[0])
                    for row in conn.execute(
                        "SELECT name FROM sqlite_schema WHERE type = 'table'"
                    ).fetchall()
                }
                critical_counts = {
                    table_name: int(
                        conn.execute(
                            f'SELECT COUNT(*) FROM "{table_name}"'
                        ).fetchone()[0]
                    )
                    for table_name in sorted(BACKUP_CRITICAL_TABLES & tables)
                }
                semantic = self.store._semantic_index_audit(
                    conn,
                    context_id=None,
                    sample_limit=1,
                    include_integrity_checks=False,
                )
                highwaters = {
                    "memory_event_id": int(
                        conn.execute(
                            "SELECT COALESCE(MAX(event_id), 0) FROM memory_events"
                        ).fetchone()[0]
                    ),
                    "context_event_id": int(
                        conn.execute(
                            "SELECT COALESCE(MAX(event_id), 0) "
                            "FROM agent_context_events"
                        ).fetchone()[0]
                    ),
                    "capture_committed_at_micros": int(
                        float(
                            conn.execute(
                                "SELECT COALESCE(MAX(committed_at), 0) "
                                "FROM capture_operations"
                            ).fetchone()[0]
                        )
                        * 1_000_000
                    ),
                }
                revision_seed = {
                    "schema_sha256": str(schema["sha256"]),
                    "critical_counts": critical_counts,
                    "highwaters": highwaters,
                    "semantic_source_revision": str(
                        semantic.get("source_revision") or ""
                    ),
                }
            finally:
                conn.execute("ROLLBACK")
            data_version_after = int(
                conn.execute("PRAGMA data_version").fetchone()[0]
            )
        visible = os.lstat(self.store.db_path)
        if (
            self.store._regular_file_identity(observed)
            != self.store._regular_file_identity(visible)
            or data_version_before != data_version_after
        ):
            raise RuntimeError(
                "live restored memory changed during binding verification"
            )
        return {
            "schema_contract_version": matching_contract_versions[-1],
            "authority_binding": {
                "governance_mode": "authoritative-v6",
                "store_generation": f"epoch-{int(marker['epoch'])}",
                "authority_epoch_number": int(marker["epoch"]),
                "store_identity": str(marker["store_identity"]),
                "request_journal_id": str(marker["request_journal_id"]),
                "restored_target_binding_receipt_digest": marker.get(
                    "restored_target_binding_receipt_digest"
                ),
                "schema_identity": (
                    f"sqlite-{int(schema_contract['application_id']):x}-"
                    f"v{int(schema_contract['user_version'])}"
                ),
            },
            "snapshot_revision": hashlib.sha256(
                _json_dumps(revision_seed).encode("utf-8")
            ).hexdigest(),
            "logical_snapshot": logical_snapshot,
        }

    def verify_restored_request_journal_binding(
        self,
        recovery_root: str | os.PathLike[str],
        *,
        expected_store_identity: str | None = None,
        expected_store_generation: str | None = None,
        expected_source_request_journal_binding_receipt_digest: str | None = None,
    ) -> dict[str, Any]:
        """Strictly verify the exact restored memory/journal target pair."""

        root = Path(recovery_root).expanduser().absolute()
        root_metadata = os.lstat(root)
        if (
            stat.S_ISLNK(root_metadata.st_mode)
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.getuid()
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise PermissionError("recovery root is not private")
        memory_path = root / "memory.sqlite3"
        journal_path = root / "core" / "requests.sqlite3"
        runtime_state_path = root / "runtime_state.json"
        receipt_path = root / "core" / "requests.sqlite3.binding.receipt.json"
        core_metadata = os.lstat(journal_path.parent)
        if (
            stat.S_ISLNK(core_metadata.st_mode)
            or not stat.S_ISDIR(core_metadata.st_mode)
            or core_metadata.st_uid != os.getuid()
            or stat.S_IMODE(core_metadata.st_mode) != 0o700
        ):
            raise PermissionError("restored core directory is not private")
        payload = self._read_restore_binding_receipt(receipt_path)
        if (
            expected_store_identity is not None
            and str(payload["store_identity"]) != str(expected_store_identity)
        ):
            raise RuntimeError("restored binding store identity does not match")
        if (
            expected_store_generation is not None
            and str(payload["store_generation"]) != str(expected_store_generation)
        ):
            raise RuntimeError("restored binding store generation does not match")
        if expected_source_request_journal_binding_receipt_digest is not None:
            expected_source = str(
                expected_source_request_journal_binding_receipt_digest
            )
            if (
                BACKUP_DIGEST_RE.fullmatch(expected_source) is None
                or not secrets.compare_digest(
                    str(
                        payload[
                            "source_request_journal_binding_receipt_digest"
                        ]
                    ),
                    expected_source,
                )
            ):
                raise RuntimeError("restored binding source chain does not match")
        memory_digest, memory_size, _memory_metadata = (
            self.store._hash_stable_regular_file(memory_path)
        )
        live_memory_target = (
            memory_path.expanduser().absolute()
            == self.store.db_path.expanduser().absolute()
        )
        memory = (
            self._inspect_live_restored_memory_binding()
            if live_memory_target
            else self.store._inspect_backup_snapshot(memory_path)
        )
        if live_memory_target:
            post_digest, post_size, _post_metadata = (
                self.store._hash_stable_regular_file(memory_path)
            )
            if (
                not secrets.compare_digest(memory_digest, post_digest)
                or int(memory_size) != int(post_size)
            ):
                raise RuntimeError(
                    "live restored memory changed during binding verification"
                )
        journal = self._verify_request_journal_artifact(
            journal_path,
            expected_sha256=str(payload["request_journal_sha256"]),
            maximum_authority_epoch=int(payload["authority_epoch_number"]),
        )
        runtime_state = self._verify_runtime_state_artifact(
            runtime_state_path,
            expected_sha256=str(payload["runtime_state_sha256"]),
        )
        runtime_data, _runtime_metadata = self._read_private_regular(
            runtime_state_path,
            max_bytes=int(
                os.getenv(
                    "SYNAPSE_S2_RECOVERY_MAX_RUNTIME_STATE_BYTES",
                    str(8 * 1024**2),
                )
            ),
        )
        runtime_payload = json.loads(runtime_data.decode("utf-8"))
        memory_binding = memory["authority_binding"]
        mismatches = (
            not secrets.compare_digest(memory_digest, str(payload["memory_sha256"])),
            int(memory_size) != int(payload["memory_size_bytes"]),
            str(memory["schema_contract_version"])
            != str(payload["memory_schema_contract_version"]),
            str(memory_binding["schema_identity"])
            != str(payload["memory_schema_identity"]),
            str(memory["snapshot_revision"])
            != str(payload["memory_snapshot_revision"]),
            str(memory["logical_snapshot"]["schema"])
            != str(payload["memory_logical_snapshot_schema"]),
            str(memory["logical_snapshot"]["sha256"])
            != str(payload["memory_logical_snapshot_sha256"]),
            int(memory["logical_snapshot"]["table_count"])
            != int(payload["memory_logical_snapshot_table_count"]),
            int(memory["logical_snapshot"]["column_count"])
            != int(payload["memory_logical_snapshot_column_count"]),
            int(memory["logical_snapshot"]["row_count"])
            != int(payload["memory_logical_snapshot_row_count"]),
            int(memory["logical_snapshot"]["value_bytes"])
            != int(payload["memory_logical_snapshot_value_bytes"]),
            str(memory_binding["store_generation"])
            != str(payload["store_generation"]),
            memory_binding["authority_epoch_number"]
            != int(payload["authority_epoch_number"]),
            str(memory_binding["store_identity"])
            != str(payload["store_identity"]),
            str(journal["store_identity"])
            != str(memory_binding["store_identity"]),
            str(journal["journal_id"])
            != str(memory_binding["request_journal_id"]),
            str(journal["journal_id"])
            != str(payload["request_journal_id"]),
            str(journal["schema_identity"])
            != str(payload["request_journal_schema_identity"]),
            int(journal["size_bytes"])
            != int(payload["request_journal_size_bytes"]),
            int(journal["application_id"])
            != int(payload["request_journal_application_id"]),
            int(journal["schema_version"])
            != int(payload["request_journal_schema_version"]),
            str(journal["schema_sha256"])
            != str(payload["request_journal_schema_sha256"]),
            str(journal["logical_snapshot_schema"])
            != str(payload["request_journal_logical_snapshot_schema"]),
            str(journal["logical_snapshot_sha256"])
            != str(payload["request_journal_logical_snapshot_sha256"]),
            int(journal["logical_snapshot_table_count"])
            != int(payload["request_journal_logical_snapshot_table_count"]),
            int(journal["logical_snapshot_column_count"])
            != int(payload["request_journal_logical_snapshot_column_count"]),
            int(journal["logical_snapshot_row_count"])
            != int(payload["request_journal_logical_snapshot_row_count"]),
            int(journal["logical_snapshot_value_bytes"])
            != int(payload["request_journal_logical_snapshot_value_bytes"]),
            int(journal["row_count"])
            != int(payload["request_journal_row_count"]),
            journal["state_counts"] != payload["request_journal_state_counts"],
            int(journal["current_authority_epoch_row_count"])
            != int(payload["request_journal_current_authority_epoch_row_count"]),
            int(journal["maximum_observed_authority_epoch"])
            != int(payload["request_journal_maximum_observed_authority_epoch"]),
            int(runtime_state["size_bytes"])
            != int(payload["runtime_state_size_bytes"]),
            str(runtime_state["binding_schema"])
            != str(payload["runtime_state_binding_schema"]),
            int(runtime_state["state_schema_version"])
            != int(payload["runtime_state_schema_version"]),
            str(runtime_state["canonical_sha256"])
            != str(payload["runtime_state_canonical_sha256"]),
            str(runtime_payload.get("memory_db_path") or "")
            != str(memory_path),
            str(payload["runtime_state_memory_db_path"]) != str(memory_path),
        )
        if any(mismatches):
            raise RuntimeError("restored request-journal binding does not match its targets")
        return {
            "schema": REQUEST_JOURNAL_RESTORE_BINDING_SCHEMA,
            "recovery_root": str(root),
            "memory_artifact_relative": "memory.sqlite3",
            "memory_logical_snapshot_sha256": str(
                memory["logical_snapshot"]["sha256"]
            ),
            "request_journal_artifact_relative": "core/requests.sqlite3",
            "request_journal_logical_snapshot_sha256": str(
                journal["logical_snapshot_sha256"]
            ),
            "runtime_state_artifact_relative": "runtime_state.json",
            "runtime_state_canonical_sha256": str(
                runtime_state["canonical_sha256"]
            ),
            "store_identity": str(payload["store_identity"]),
            "store_generation": str(payload["store_generation"]),
            "authority_epoch_number": int(payload["authority_epoch_number"]),
            "request_journal_id": str(payload["request_journal_id"]),
            "request_journal_schema_identity": str(
                payload["request_journal_schema_identity"]
            ),
            "source_request_journal_binding_receipt_digest": str(
                payload["source_request_journal_binding_receipt_digest"]
            ),
            "receipt_digest": str(payload["receipt_digest"]),
            "verified": True,
        }

    def verify_adopted_restored_store_identity(
        self,
        recovery_root: str | os.PathLike[str],
        *,
        expected_store_identity: str,
        expected_authority_epoch_number: int,
    ) -> dict[str, Any]:
        """Verify the persisted identity of an already-adopted restore.

        This is the post-startup identity contract used by the installer.  It
        intentionally derives the private journal identifier and immutable
        restore receipt digest from the governed database rather than from a
        path-derived identity that necessarily changes at an isolated target.
        """

        memory = self._inspect_live_restored_memory_binding()
        binding = memory["authority_binding"]
        receipt_digest = binding.get("restored_target_binding_receipt_digest")
        if not isinstance(receipt_digest, str):
            raise RuntimeError("memory store is not an adopted restored target")
        verified = self.verify_adopted_restored_request_journal_lineage(
            recovery_root,
            expected_store_identity=expected_store_identity,
            expected_request_journal_id=str(binding["request_journal_id"]),
            expected_authority_epoch_number=expected_authority_epoch_number,
            expected_restore_binding_receipt_digest=receipt_digest,
        )
        if (
            verified["store_identity"] != str(expected_store_identity)
            or int(verified["authority_epoch_number"])
            != int(expected_authority_epoch_number)
        ):
            raise RuntimeError("adopted restored service identity does not match")
        return verified

    def verify_adopted_restored_request_journal_lineage(
        self,
        recovery_root: str | os.PathLike[str],
        *,
        expected_store_identity: str,
        expected_request_journal_id: str,
        expected_authority_epoch_number: int,
        expected_restore_binding_receipt_digest: str,
    ) -> dict[str, Any]:
        """Verify immutable restore provenance after the live pair has evolved.

        The exact restore receipt binds the source database, journal, and
        runtime state at adoption time. After adoption, authority epochs,
        memory, and journal rows legitimately change, so subsequent startups
        verify the signed source receipt plus the durable marker lineage rather
        than incorrectly demanding the original byte digests forever.
        """

        root = Path(recovery_root).expanduser().absolute()
        root_metadata = os.lstat(root)
        if (
            stat.S_ISLNK(root_metadata.st_mode)
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.getuid()
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise PermissionError("recovery root is not private")
        receipt_path = root / "core" / "requests.sqlite3.binding.receipt.json"
        # Exact restore verification required the source recovery authority's
        # local trust anchor before adoption.  Afterwards the target can have a
        # different active recovery key, so continuity relies on the original
        # receipt's valid signature plus the immutable receipt digest that the
        # trusted cutover wrote into the durable v6 marker.
        payload = self._read_restore_binding_receipt(
            receipt_path,
            require_local_trust_anchor=False,
        )
        if not secrets.compare_digest(
            str(payload["receipt_digest"]),
            str(expected_restore_binding_receipt_digest),
        ):
            raise RuntimeError("restored binding receipt lineage does not match")
        memory = self._inspect_live_restored_memory_binding()
        binding = memory["authority_binding"]
        if (
            str(payload["store_identity"]) != str(expected_store_identity)
            or str(binding["store_identity"]) != str(expected_store_identity)
            or str(binding["request_journal_id"])
            != str(expected_request_journal_id)
            or int(binding["authority_epoch_number"])
            != int(expected_authority_epoch_number)
            or int(binding["authority_epoch_number"])
            <= int(payload["authority_epoch_number"])
            or not secrets.compare_digest(
                str(binding.get("restored_target_binding_receipt_digest") or ""),
                str(expected_restore_binding_receipt_digest),
            )
        ):
            raise RuntimeError("adopted restored binding lineage does not match")
        return {
            "schema": REQUEST_JOURNAL_RESTORE_BINDING_SCHEMA,
            "store_identity": str(binding["store_identity"]),
            "request_journal_id": str(binding["request_journal_id"]),
            "authority_epoch_number": int(binding["authority_epoch_number"]),
            "source_authority_epoch_number": int(payload["authority_epoch_number"]),
            "receipt_digest": str(payload["receipt_digest"]),
            "verified": True,
        }

    @staticmethod
    def _assert_secret_safe_text(data: bytes) -> None:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("capture recovery input is not UTF-8 text") from exc
        safe, _ = redact_capture_text(text)
        digest_safe, _ = strip_untrusted_raw_digest_text(safe)
        if safe != text or digest_safe != safe:
            raise RuntimeError("capture recovery input failed secret hygiene")

    @staticmethod
    def _decode_capture_records(path: Path, data: bytes) -> list[dict[str, Any]] | None:
        suffix = path.suffix.lower()
        if suffix == ".txt":
            return None
        try:
            text = data.decode("utf-8")
            if suffix == ".jsonl":
                records = [
                    json.loads(line)
                    for line in text.splitlines()
                    if line.strip()
                ]
            else:
                parsed = json.loads(text)
                records = parsed if isinstance(parsed, list) else [parsed]
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("capture payload archive is malformed") from exc
        if not records or not all(isinstance(record, dict) for record in records):
            raise ValueError("capture payload archive must contain object records")
        return records

    def _classify_capture_record(
        self,
        *,
        directory_key: str,
        path: Path,
        data: bytes,
        ledger_ids: set[str],
    ) -> dict[str, Any]:
        if directory_key == "state_path":
            try:
                state = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("capture runtime state is malformed") from exc
            if not isinstance(state, dict):
                raise ValueError("capture runtime state must be an object")
            return {
                "category": "capture-runtime-state",
                "capture_ids": [],
                "replay_disposition": "snapshot-metadata",
            }
        if directory_key == "receipt_dir":
            try:
                receipt = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("capture receipt is malformed") from exc
            expected_receipt_keys = {
                "version",
                "capture_id",
                "request_fingerprint",
                "committed_at",
                "result",
            }
            if not isinstance(receipt, dict) or set(receipt) != expected_receipt_keys:
                raise ValueError("capture receipt fields are not canonical")
            capture_id = str(receipt.get("capture_id") or "")
            if CAPTURE_ID_RE.fullmatch(capture_id) is None:
                raise ValueError("capture receipt has a noncanonical capture ID")
            request_fingerprint = str(receipt.get("request_fingerprint") or "")
            committed_at = receipt.get("committed_at")
            result = receipt.get("result")
            if (
                int(receipt.get("version") or 0) != 1
                or BACKUP_DIGEST_RE.fullmatch(request_fingerprint) is None
                or not isinstance(committed_at, (int, float))
                or not math.isfinite(float(committed_at))
                or not isinstance(result, dict)
                or set(result)
                != {
                    "capture_id",
                    "context_id",
                    "source_tag",
                    "speaker",
                    "event_count",
                    "relationship_count",
                    "agent_deployment",
                    "redaction_count",
                }
                or str(result.get("capture_id") or "") != capture_id
                or any(
                    type(result.get(field)) is not int or int(result[field]) < 0
                    for field in (
                        "event_count",
                        "relationship_count",
                        "redaction_count",
                    )
                )
                or (
                    result.get("agent_deployment") is not None
                    and not isinstance(result.get("agent_deployment"), dict)
                )
            ):
                raise ValueError("capture receipt contract is invalid")
            if capture_id not in ledger_ids:
                raise RuntimeError("capture receipt has no authoritative ledger row")
            return {
                "category": "capture-receipt",
                "capture_ids": [capture_id],
                "replay_disposition": "ledger-backed",
            }

        if directory_key in {
            "error_dir",
            "error_archive_dir",
            "error_resolution_dir",
        }:
            return {
                "category": (
                    "error-resolution-evidence"
                    if directory_key == "error_resolution_dir"
                    else "error-evidence"
                ),
                "capture_ids": [],
                "replay_disposition": "governance-evidence",
            }

        if path.name == ".capture-identity.json":
            if directory_key != "processing_dir":
                raise ValueError("capture identity metadata is outside a processing claim")
            return {
                "category": "legacy-claim-identity",
                "capture_ids": [],
                "replay_disposition": "legacy-snapshot-bound",
            }

        records = VerifiedRecoveryManager._decode_capture_records(path, data)
        if records is None:
            return {
                "category": "legacy-text-capture",
                "capture_ids": [],
                "replay_disposition": (
                    "replay-required"
                    if directory_key in {"inbox_dir", "processing_dir"}
                    else "legacy-snapshot-bound"
                ),
            }
        capture_ids: list[str] = []
        saw_v2 = False
        saw_v1 = False
        allowed_payload_keys = {
            "version",
            "capture_id",
            "created_at",
            "text",
            "context_id",
            "source_tag",
            "tag",
            "speaker",
            "surprise_threshold",
            "min_segment_sentences",
            "metadata",
            "redaction_count",
            "raw_text_stored",
            "dropped_top_level_field_count",
        }
        for record in records:
            raw_version = record.get("version", 1)
            if isinstance(raw_version, bool):
                raise ValueError("capture payload version is invalid")
            try:
                version = int(raw_version)
            except (TypeError, ValueError) as exc:
                raise ValueError("capture payload version is invalid") from exc
            if version not in {1, 2}:
                raise ValueError("capture payload version is unsupported")
            if set(record) - allowed_payload_keys:
                raise ValueError("capture payload contains unsupported top-level fields")
            validation_payload = dict(record)
            if version == 1 and not validation_payload.get("capture_id"):
                validation_payload["capture_id"] = "s2cap_" + ("0" * 32)
            self.daemon._normalize_payload_before_capture(
                path=path,
                payload=validation_payload,
                version=version,
            )
            if version == 2:
                saw_v2 = True
                capture_id = str(record.get("capture_id") or "")
                if CAPTURE_ID_RE.fullmatch(capture_id) is None:
                    raise ValueError("v2 capture payload has no canonical capture ID")
                if not isinstance(record.get("text"), str) or not str(
                    record["text"]
                ).strip():
                    raise ValueError("v2 capture payload has no text")
                if record.get("raw_text_stored") is not False:
                    raise ValueError("v2 capture payload violates raw-text privacy")
                capture_ids.append(capture_id)
            else:
                saw_v1 = True
                if record.get("capture_id") is not None:
                    capture_id = str(record.get("capture_id") or "")
                    if CAPTURE_ID_RE.fullmatch(capture_id) is None:
                        raise ValueError("v1 capture payload has a malformed capture ID")
                    capture_ids.append(capture_id)
        if saw_v1 and saw_v2:
            raise ValueError("capture payload cannot mix v1 and v2 records")
        if len(capture_ids) != len(set(capture_ids)):
            raise ValueError("capture archive contains duplicate capture IDs")
        ledger_backed = sum(capture_id in ledger_ids for capture_id in capture_ids)
        replay_required = len(capture_ids) - ledger_backed
        if directory_key in {"processed_dir"} and replay_required:
            raise RuntimeError("processed capture payload has no authoritative ledger row")
        if directory_key == "processed_dir":
            disposition = "ledger-backed" if capture_ids else "legacy-snapshot-bound"
        elif directory_key in {"inbox_dir", "processing_dir"}:
            if replay_required and ledger_backed:
                disposition = "mixed-replay-required"
            elif replay_required or not capture_ids:
                disposition = "replay-required"
            else:
                disposition = "dedupe-on-replay"
        else:
            raise ValueError("capture payload is in an unsupported transport category")
        return {
            "category": "v2-capture-payload" if saw_v2 else "v1-capture-payload",
            "capture_ids": sorted(capture_ids),
            "replay_disposition": disposition,
        }

    def _capture_inventory(
        self,
        *,
        ledger_ids: set[str],
        database_binding: dict[str, Any],
        initialize_transport: bool = True,
    ) -> dict[str, Any]:
        paths = self.daemon.paths()
        if initialize_transport:
            self.daemon._ensure_transport_dirs(paths)
        else:
            missing, unsafe = self.daemon._observe_transport_dirs(paths)
            if missing or unsafe:
                raise RuntimeError(
                    "live capture transport is not safe for read-only attestation"
                )
        max_files, max_total_bytes, max_file_bytes = self._bounded_capture_limits()
        records: list[dict[str, Any]] = []
        total_bytes = 0
        for key in CAPTURE_TRANSPORT_DIR_KEYS:
            directory = paths[key]
            root_metadata = os.lstat(directory)
            if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
                raise ValueError("capture transport directory is not a real directory")
            for current_root, dir_names, file_names in os.walk(directory, followlinks=False):
                current = Path(current_root)
                for dir_name in list(dir_names):
                    metadata = os.lstat(current / dir_name)
                    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                        raise ValueError("capture transport contains an unsafe directory")
                for file_name in sorted(file_names):
                    if file_name == ".lock":
                        continue
                    file_path = current / file_name
                    data, metadata = self._read_private_regular(
                        file_path,
                        max_bytes=max_file_bytes,
                    )
                    self._assert_secret_safe_text(data)
                    relative = file_path.relative_to(self.capture_root).as_posix()
                    if relative.startswith("/") or ".." in Path(relative).parts:
                        raise ValueError("capture transport path escaped its root")
                    total_bytes += len(data)
                    classification = self._classify_capture_record(
                        directory_key=key,
                        path=file_path,
                        data=data,
                        ledger_ids=ledger_ids,
                    )
                    records.append(
                        {
                            "relative_path": relative,
                            **classification,
                            "size_bytes": len(data),
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "mode": stat.S_IMODE(metadata.st_mode),
                        }
                    )
                    if len(records) > max_files or total_bytes > max_total_bytes:
                        raise RuntimeError("capture recovery inventory exceeded its bounds")
        state_path = paths["state_path"]
        if state_path.exists() or state_path.is_symlink():
            data, metadata = self._read_private_regular(
                state_path,
                max_bytes=max_file_bytes,
            )
            self._assert_secret_safe_text(data)
            total_bytes += len(data)
            records.append(
                {
                    "relative_path": state_path.name,
                    "category": "capture-runtime-state",
                    "capture_ids": [],
                    "replay_disposition": "snapshot-metadata",
                    "size_bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "mode": stat.S_IMODE(metadata.st_mode),
                }
            )
            if len(records) > max_files or total_bytes > max_total_bytes:
                raise RuntimeError("capture recovery inventory exceeded its bounds")
        records.sort(key=lambda value: str(value["relative_path"]))
        payload_locations: dict[str, str] = {}
        receipt_locations: dict[str, str] = {}
        for record in records:
            prefix = Path(str(record["relative_path"])).parts[0]
            registry = (
                receipt_locations
                if prefix == "capture_receipts"
                else payload_locations
                if prefix
                in {"capture_inbox", "capture_processing", "capture_processed"}
                else None
            )
            if registry is None:
                continue
            for capture_id in record["capture_ids"]:
                prior = registry.get(capture_id)
                if prior is not None:
                    raise RuntimeError(
                        "capture transport contains duplicate cross-file capture IDs"
                    )
                registry[capture_id] = str(record["relative_path"])
        replay_required_ids = {
            capture_id
            for record in records
            if record["replay_disposition"]
            in {"replay-required", "mixed-replay-required"}
            for capture_id in record["capture_ids"]
            if capture_id not in ledger_ids
        }
        reconciliation = {
            "ledger_capture_count": len(ledger_ids),
            "ledger_backed_file_count": sum(
                record["replay_disposition"]
                in {"ledger-backed", "dedupe-on-replay"}
                for record in records
            ),
            "replay_required_capture_count": len(replay_required_ids),
            "replay_required_file_count": sum(
                record["replay_disposition"]
                in {"replay-required", "mixed-replay-required"}
                for record in records
            ),
            "identifierless_replay_file_count": sum(
                record["replay_disposition"]
                in {"replay-required", "mixed-replay-required"}
                and not record["capture_ids"]
                for record in records
            ),
            "legacy_snapshot_file_count": sum(
                record["replay_disposition"] == "legacy-snapshot-bound"
                for record in records
            ),
            "governance_evidence_file_count": sum(
                record["replay_disposition"] == "governance-evidence"
                for record in records
            ),
            "unclassified_file_count": 0,
            "missing_authoritative_ledger_count": 0,
        }
        manifest_seed = {
            "schema": CAPTURE_ARCHIVE_MANIFEST_SCHEMA,
            "file_count": len(records),
            "total_bytes": total_bytes,
            "database_binding": database_binding,
            "reconciliation": reconciliation,
            "files": records,
        }
        manifest_sha256 = hashlib.sha256(
            _json_dumps(manifest_seed).encode("utf-8")
        ).hexdigest()
        return {**manifest_seed, "manifest_sha256": manifest_sha256}

    @staticmethod
    def _canonical_pending_capture_state(
        manifest: dict[str, Any],
    ) -> dict[str, Any]:
        """Summarize canonical v2 work queued in inbox or a durable claim."""

        records = manifest.get("files")
        if not isinstance(records, list):
            raise ValueError("capture manifest file inventory is missing")
        queued_records = [
            record
            for record in records
            if isinstance(record, dict)
            and (
                (
                    len(
                        Path(str(record.get("relative_path") or "")).parts
                    )
                    == 2
                    and Path(str(record["relative_path"])).parts[0]
                    == "capture_inbox"
                )
                or (
                    len(
                        Path(str(record.get("relative_path") or "")).parts
                    )
                    == 3
                    and Path(str(record["relative_path"])).parts[0]
                    == "capture_processing"
                    and CLAIM_DIR_RE.fullmatch(
                        Path(str(record["relative_path"])).parts[1]
                    )
                    is not None
                )
            )
        ]
        replay_records = [
            record
            for record in records
            if isinstance(record, dict)
            and record.get("replay_disposition")
            in {"replay-required", "mixed-replay-required"}
        ]
        receipt_capture_ids = {
            capture_id
            for record in records
            if isinstance(record, dict)
            and record.get("category") == "capture-receipt"
            for capture_id in record.get("capture_ids") or []
        }

        def canonical_queued_record(record: dict[str, Any]) -> bool:
            parts = Path(str(record.get("relative_path") or "")).parts
            disposition = record.get("replay_disposition")
            return bool(
                record.get("category") == "v2-capture-payload"
                and disposition in {"replay-required", "dedupe-on-replay"}
                and isinstance(record.get("capture_ids"), list)
                and len(record["capture_ids"]) == 1
                and (
                    (parts[0] == "capture_inbox" and disposition == "replay-required")
                    or parts[0] == "capture_processing"
                )
            )

        queued_capture_ids = {
            str(record["capture_ids"][0])
            for record in queued_records
            if isinstance(record.get("capture_ids"), list)
            and len(record["capture_ids"]) == 1
        }
        queued_receipt_count = len(queued_capture_ids & receipt_capture_ids)
        canonical = (
            all(record in queued_records for record in replay_records)
            and all(canonical_queued_record(record) for record in queued_records)
            and queued_receipt_count == 0
        )
        return {
            "pending_file_count": len(queued_records),
            "replay_required_file_count": len(replay_records),
            "replay_required_capture_count": sum(
                len(record.get("capture_ids") or []) for record in replay_records
            ),
            "receipt_backed_file_count": queued_receipt_count,
            "canonical_v2": canonical,
        }

    def recompute_live_capture_manifest(
        self,
        *,
        database_binding: dict[str, Any],
    ) -> dict[str, Any]:
        """Attest live capture bytes without creating or repairing any path."""

        expected_binding_keys = {
            "artifact_sha256",
            "receipt_digest",
            "auth_key_id",
            "schema_contract_version",
            "snapshot_revision",
            "logical_snapshot_schema",
            "logical_snapshot_sha256",
            "capture_operation_count",
            "capture_operation_highwater_micros",
            "capture_root_provenance",
            "capture_root_identity_digest",
        }
        binding = dict(database_binding) if isinstance(database_binding, dict) else {}
        if (
            set(binding) != expected_binding_keys
            or binding.get("logical_snapshot_schema")
            != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
            or any(
                BACKUP_DIGEST_RE.fullmatch(str(binding.get(field) or "")) is None
                for field in (
                    "artifact_sha256",
                    "receipt_digest",
                    "auth_key_id",
                    "snapshot_revision",
                    "logical_snapshot_sha256",
                    "capture_root_identity_digest",
                )
            )
        ):
            raise ValueError("capture attestation database binding is invalid")
        paths = self.daemon.paths()
        repository_lock = self.store.db_path.parent / "recovery-locks" / "repository.lock"
        capture_lock = paths["lock_dir"] / GLOBAL_CAPTURE_LOCK
        with self._repository_thread_lock:
            with self._existing_private_file_lock(
                repository_lock,
                mode=fcntl.LOCK_SH,
            ):
                with self._existing_private_file_lock(
                    capture_lock,
                    mode=fcntl.LOCK_EX,
                ):
                    root_provenance = self._validate_capture_source_root()
                    if (
                        root_provenance["capture_root_provenance"]
                        != binding["capture_root_provenance"]
                        or root_provenance["capture_root_identity_digest"]
                        != binding["capture_root_identity_digest"]
                    ):
                        raise RuntimeError(
                            "live capture root does not match its signed database binding"
                        )
                    with closing(self.store._connect_read_only()) as conn:
                        with self.store._transaction(conn):
                            ledger_bindings = self._snapshot_capture_ledger_bindings(
                                conn
                            )
                    capture_highwater_micros = int(
                        max(
                            (
                                float(item["committed_at"])
                                for item in ledger_bindings.values()
                            ),
                            default=0.0,
                        )
                        * 1_000_000
                    )
                    if (
                        int(binding["capture_operation_count"])
                        != len(ledger_bindings)
                        or int(binding["capture_operation_highwater_micros"])
                        != capture_highwater_micros
                    ):
                        raise RuntimeError(
                            "live capture ledger is newer than its signed database binding"
                        )
                    manifest = self._capture_inventory(
                        ledger_ids=set(ledger_bindings),
                        database_binding=binding,
                        initialize_transport=False,
                    )
        return {
            "manifest_sha256": str(manifest["manifest_sha256"]),
            "file_count": int(manifest["file_count"]),
            "total_bytes": int(manifest["total_bytes"]),
            "database_binding": dict(manifest["database_binding"]),
            "reconciliation": dict(manifest["reconciliation"]),
            "verified": True,
        }

    @staticmethod
    def _public_capture_ledger_audit(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in payload.items()
            if not str(key).startswith("_")
        }

    def _capture_ledger_schema_errors(
        self,
        conn: sqlite3.Connection,
    ) -> list[str]:
        errors = list(self.store._capture_operation_schema_errors(conn))
        table_row = conn.execute(
            "SELECT type, sql FROM sqlite_master WHERE name = ?",
            ("store_maintenance_receipts",),
        ).fetchone()
        if table_row is None or str(table_row["type"]) != "table":
            errors.append("store_maintenance_receipts:missing-table")
        else:
            actual_columns = tuple(
                (
                    str(row["name"]),
                    str(row["type"]).upper(),
                    int(row["notnull"]),
                    None
                    if row["dflt_value"] is None
                    else str(row["dflt_value"]),
                    int(row["pk"]),
                )
                for row in conn.execute(
                    'PRAGMA table_info("store_maintenance_receipts")'
                ).fetchall()
            )
            if actual_columns != MAINTENANCE_RECEIPT_COLUMN_SIGNATURE:
                errors.append("store_maintenance_receipts:column-signature")
            if self.store._normalized_schema_sql(
                str(table_row["sql"] or "")
            ) != self.store._normalized_schema_sql(
                MAINTENANCE_RECEIPT_TABLE_SQL
            ):
                errors.append("store_maintenance_receipts:table-signature")

        index_name = "ix_store_maintenance_receipts_type_created"
        index_row = conn.execute(
            "SELECT type, tbl_name, sql FROM sqlite_master WHERE name = ?",
            (index_name,),
        ).fetchone()
        index_columns = tuple(
            str(row["name"])
            for row in conn.execute(
                f'PRAGMA index_info("{index_name}")'
            ).fetchall()
        )
        if (
            index_row is None
            or str(index_row["type"]) != "index"
            or str(index_row["tbl_name"]) != "store_maintenance_receipts"
            or index_columns != ("operation_type", "created_at")
            or self.store._normalized_schema_sql(str(index_row["sql"] or ""))
            != self.store._normalized_schema_sql(MAINTENANCE_RECEIPT_INDEX_SQL)
        ):
            errors.append(f"{index_name}:index-signature")

        trigger_rows = conn.execute(
            """
            SELECT name, tbl_name FROM sqlite_master
            WHERE type = 'trigger'
              AND tbl_name IN ('capture_operations', 'store_maintenance_receipts')
            ORDER BY name
            """
        ).fetchall()
        errors.extend(
            f"{str(row['tbl_name'])}:unexpected-trigger:{str(row['name'])}"
            for row in trigger_rows
        )
        return sorted(set(errors))

    def _require_capture_ledger_schema(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        errors = self._capture_ledger_schema_errors(conn)
        if errors:
            raise RuntimeError(
                "capture ledger reconciliation schema is invalid "
                f"(errors={errors[:8]!r})"
            )

    @staticmethod
    def _legacy_capture_ledger_schema_adoption_allowed(
        errors: list[str],
    ) -> bool:
        allowed = {
            "capture_operations:missing-table",
            "store_maintenance_receipts:missing-table",
            "ix_store_maintenance_receipts_type_created:index-signature",
        }
        return bool(errors) and set(errors).issubset(allowed)

    @staticmethod
    def _legacy_capture_ledger_schema_statements() -> tuple[str, ...]:
        wanted_prefixes = (
            "CREATE TABLE IF NOT EXISTS capture_operations",
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_capture_operations_deployment_event",
            "CREATE INDEX IF NOT EXISTS ix_capture_operations_context_committed",
            "CREATE TABLE IF NOT EXISTS store_maintenance_receipts",
            "CREATE INDEX IF NOT EXISTS ix_store_maintenance_receipts_type_created",
        )
        statements: list[str] = []
        pending = ""
        for line in SCHEMA_SQL.splitlines(keepends=True):
            pending += line
            if sqlite3.complete_statement(pending):
                statement = pending.strip()
                pending = ""
                if any(statement.startswith(prefix) for prefix in wanted_prefixes):
                    statements.append(statement)
        if len(statements) != len(wanted_prefixes):
            raise RuntimeError("legacy capture ledger schema subset is incomplete")
        return tuple(statements)

    def _install_legacy_capture_ledger_schema(
        self,
        conn: sqlite3.Connection,
        *,
        expected_errors: list[str],
    ) -> list[str]:
        if not self._legacy_capture_ledger_schema_adoption_allowed(expected_errors):
            raise RuntimeError(
                "legacy capture ledger schema adoption is not allowed for this schema state"
            )
        for statement in self._legacy_capture_ledger_schema_statements():
            conn.execute(statement)
        after_errors = self._capture_ledger_schema_errors(conn)
        if after_errors:
            raise RuntimeError(
                "legacy capture ledger schema adoption failed "
                f"(errors={after_errors[:8]!r})"
            )
        return list(expected_errors)

    @staticmethod
    def _exact_json_digest(value: Any) -> str:
        try:
            canonical = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("capture reconciliation evidence is not canonical JSON") from exc
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _canonical_legacy_capture_text(value: Any) -> str:
        """Normalize renderer-only spacing while preserving word boundaries."""

        text = unicodedata.normalize("NFKC", str(value))
        rendered: list[str] = []
        index = 0

        def is_word_character(character: str) -> bool:
            return bool(character) and (
                character.isalnum() or character == "_"
            )

        while index < len(text):
            if not text[index].isspace():
                rendered.append(text[index])
                index += 1
                continue
            next_index = index
            while next_index < len(text) and text[next_index].isspace():
                next_index += 1
            previous = rendered[-1] if rendered else ""
            following = text[next_index] if next_index < len(text) else ""
            if is_word_character(previous) and is_word_character(following):
                rendered.append(" ")
            index = next_index
        return "".join(rendered)

    def _canonical_v2_capture_binding(
        self,
        *,
        path: Path,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        normalized = self.daemon._normalize_payload_before_capture(
            path=path,
            payload=dict(record),
            version=2,
        )
        changed_common_fields = {
            key
            for key in set(record) & set(normalized)
            if record[key] != normalized[key]
        }
        inferred_fields = set(normalized) - set(record)
        removed_fields = set(record) - set(normalized)
        if (
            changed_common_fields
            or removed_fields
            or not inferred_fields.issubset(LEGACY_V2_DEFAULT_FIELDS)
        ):
            raise ValueError(
                "processed v2 payload is not a supported canonical form"
            )
        request = self.daemon._canonical_capture_request(normalized)
        return {
            "capture_id": str(request["capture_id"]),
            "protocol": CAPTURE_PROTOCOL_VERSION,
            "request_fingerprint": capture_request_fingerprint(
                text=str(request["text"]),
                context_id=str(request["context_id"]),
                source_tag=str(request["source_tag"]),
                speaker=str(request["speaker"]),
                surprise_threshold=float(request["surprise_threshold"]),
                min_segment_sentences=int(request["min_segment_sentences"]),
                metadata=dict(request["metadata"]),
            ),
            "context_id": str(request["context_id"]),
            "source_tag": str(request["source_tag"]),
            "speaker": str(request["speaker"]),
            "_canonical_request": request,
        }

    def _legacy_capture_deployment_candidate(
        self,
        conn: sqlite3.Connection,
        *,
        capture_id: str,
        canonical_request: dict[str, Any],
        request_fingerprint: str,
        relative_path: str,
        file_sha256: str,
        record_index: int,
    ) -> tuple[dict[str, Any] | None, list[str]]:
        """Bind one legacy processed payload to one durable deployment event.

        The old transition cohort wrote the graph and conversation-capture
        deployment before ``capture_operations`` became authoritative.  A
        repair is allowed only when capture-tagged event memories identify one
        and only one deployment, and that deployment's complete node/edge
        receipt still matches the durable graph identities.
        """

        reasons: list[str] = []
        context_id = str(canonical_request["context_id"])
        source_tag = str(canonical_request["source_tag"])
        speaker = str(canonical_request["speaker"])
        processed_name = Path(relative_path).name
        capture_entry_rows = conn.execute(
            """
            SELECT memory_id, context_id, tag, source_text, metadata_json
            FROM memory_entries
            WHERE context_id = ?
              AND (instr(metadata_json, ?) > 0 OR instr(metadata_json, ?) > 0)
            ORDER BY memory_id
            """,
            (context_id, capture_id, processed_name),
        ).fetchall()
        event_entries: dict[str, sqlite3.Row] = {}
        event_entry_metadata: dict[str, dict[str, Any]] = {}
        entry_binding_modes: set[str] = set()
        for row in capture_entry_rows:
            try:
                metadata = json.loads(str(row["metadata_json"]))
            except (TypeError, json.JSONDecodeError):
                reasons.append("invalid-capture-entry-metadata")
                continue
            if not isinstance(metadata, dict):
                continue
            metadata_capture_id = metadata.get("capture_id")
            metadata_capture_file = metadata.get("capture_file")
            if metadata_capture_id == capture_id:
                binding_mode = "explicit-v2"
            elif (
                metadata_capture_id is None
                and metadata_capture_file == processed_name
            ):
                binding_mode = "legacy-capture-file"
            else:
                continue
            if (
                metadata.get("conversation_capture") is True
                and metadata.get("event_segment") is True
            ):
                memory_id = str(row["memory_id"])
                event_entries[memory_id] = row
                event_entry_metadata[memory_id] = metadata
                entry_binding_modes.add(binding_mode)
        if not event_entries:
            reasons.append("missing-capture-event-memory")
            return None, sorted(set(reasons))
        if len(entry_binding_modes) != 1:
            reasons.append("mixed-capture-evidence-binding")
            return None, sorted(set(reasons))
        binding_mode = next(iter(entry_binding_modes))
        if binding_mode != "legacy-capture-file":
            reasons.append("explicit-v2-ledger-loss-requires-verified-restore")
            return None, sorted(set(reasons))
        if binding_mode == "legacy-capture-file":
            if len(event_entries) != 1:
                reasons.append("legacy-capture-must-have-one-event-memory")
                return None, sorted(set(reasons))
            only_event_entry = next(iter(event_entries.values()))
            durable_text = self._canonical_legacy_capture_text(
                only_event_entry["source_text"]
            )
            processed_text = self._canonical_legacy_capture_text(
                canonical_request["text"]
            )
            if durable_text != processed_text:
                reasons.append("legacy-capture-text-mismatch")
                return None, sorted(set(reasons))
            request_metadata = dict(canonical_request["metadata"])
            inferred_capture_id = request_metadata.pop("capture_id", None)
            inferred_protocol = request_metadata.pop("capture_protocol", None)
            if (
                inferred_capture_id != capture_id
                or inferred_protocol != CAPTURE_PROTOCOL_VERSION
            ):
                reasons.append("legacy-capture-identity-mismatch")
                return None, sorted(set(reasons))
            if set(request_metadata) & LEGACY_EVENT_DERIVED_METADATA_FIELDS:
                reasons.append("legacy-capture-metadata-is-not-provable")
                return None, sorted(set(reasons))
            durable_metadata = event_entry_metadata[
                str(only_event_entry["memory_id"])
            ]
            durable_request_metadata = {
                key: value
                for key, value in durable_metadata.items()
                if key not in LEGACY_EVENT_DERIVED_METADATA_FIELDS
                and key not in {"capture_id", "capture_protocol"}
            }
            if durable_request_metadata != request_metadata:
                reasons.append("legacy-capture-metadata-mismatch")
                return None, sorted(set(reasons))

        first_event_memory_id = sorted(event_entries)[0]
        deployment_rows = conn.execute(
            """
            SELECT event_id, context_id, source_surface, event_type,
                   summary, payload_json, agent_targets_json, created_at
            FROM agent_context_events
            WHERE context_id = ?
              AND source_surface = 'conversation-capture'
              AND event_type = 'conversation-capture'
              AND instr(payload_json, ?) > 0
            ORDER BY event_id
            """,
            (context_id, first_event_memory_id),
        ).fetchall()
        matched: list[dict[str, Any]] = []
        for deployment_row in deployment_rows:
            candidate_reasons: list[str] = []
            raw_payload = str(deployment_row["payload_json"])
            try:
                payload = json.loads(raw_payload)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            payload_capture_id = payload.get("capture_id")
            payload_protocol = payload.get("protocol")
            if binding_mode == "legacy-capture-file":
                if payload_capture_id is not None or payload_protocol is not None:
                    continue
            elif (
                payload_capture_id != capture_id
                or payload_protocol != CAPTURE_PROTOCOL_VERSION
            ):
                continue
            if payload.get("source_tag") != source_tag:
                continue
            if payload.get("speaker") != speaker:
                continue
            events = payload.get("events")
            relationships = payload.get("relationships")
            namespace = payload.get("context_namespace")
            if (
                not isinstance(events, list)
                or not events
                or not all(isinstance(item, dict) for item in events)
                or not isinstance(relationships, list)
                or not all(isinstance(item, dict) for item in relationships)
                or not isinstance(namespace, dict)
            ):
                continue
            event_memory_ids = [str(item.get("memory_id") or "") for item in events]
            if (
                any(not value for value in event_memory_ids)
                or len(event_memory_ids) != len(set(event_memory_ids))
                or set(event_memory_ids) != set(event_entries)
            ):
                continue
            event_count = payload.get("event_count")
            relationship_count = payload.get("relationship_count")
            if (
                type(event_count) is not int
                or event_count != len(events)
                or type(relationship_count) is not int
                or relationship_count != len(relationships)
            ):
                continue

            for event in events:
                memory_id = str(event["memory_id"])
                live_entry = event_entries[memory_id]
                segment = event.get("segment")
                if not isinstance(segment, dict):
                    candidate_reasons.append("invalid-deployment-event-segment")
                    continue
                if (
                    event.get("tag") != str(live_entry["tag"])
                    or segment.get("text") != str(live_entry["source_text"])
                    or segment.get("context_id") != context_id
                    or segment.get("source_tag") != source_tag
                    or segment.get("sequence_id")
                    != event_entry_metadata[memory_id].get("sequence_id")
                    or segment.get("segment_id")
                    != event_entry_metadata[memory_id].get("segment_id")
                ):
                    candidate_reasons.append("deployment-event-memory-mismatch")

            nodes = namespace.get("nodes")
            namespace_relationships = namespace.get("relationships")
            if (
                namespace.get("context_id") != context_id
                or namespace.get("source_tag") != source_tag
                or namespace.get("speaker") != speaker
                or not isinstance(nodes, list)
                or not all(isinstance(item, dict) for item in nodes)
                or not isinstance(namespace_relationships, list)
                or not all(isinstance(item, dict) for item in namespace_relationships)
                or type(namespace.get("node_count")) is not int
                or namespace.get("node_count") != len(nodes)
                or type(namespace.get("source_event_count")) is not int
                or namespace.get("source_event_count") != len(events)
                or type(namespace.get("relationship_count")) is not int
                or namespace.get("relationship_count")
                != len(namespace_relationships)
            ):
                candidate_reasons.append("invalid-context-namespace-receipt")
                nodes = []
                namespace_relationships = []

            node_memory_ids = [str(item.get("memory_id") or "") for item in nodes]
            if (
                any(not value for value in node_memory_ids)
                or len(node_memory_ids) != len(set(node_memory_ids))
                or set(node_memory_ids) & set(event_memory_ids)
            ):
                candidate_reasons.append("invalid-context-namespace-node-identities")
            for node in nodes:
                memory_id = str(node.get("memory_id") or "")
                live_entry = conn.execute(
                    """
                    SELECT memory_id, context_id, tag, source_text
                    FROM memory_entries WHERE memory_id = ?
                    """,
                    (memory_id,),
                ).fetchone()
                if (
                    live_entry is None
                    or str(live_entry["context_id"]) != context_id
                    or node.get("tag") != str(live_entry["tag"])
                    or node.get("text") != str(live_entry["source_text"])
                ):
                    candidate_reasons.append("context-namespace-node-mismatch")

            all_entry_ids = set(event_memory_ids) | set(node_memory_ids)
            relationship_ids: list[str] = []
            for relationship in relationships:
                relationship_id = str(relationship.get("relationship_id") or "")
                relationship_ids.append(relationship_id)
                source_memory_id = str(relationship.get("source_memory_id") or "")
                target_memory_id = str(relationship.get("target_memory_id") or "")
                relation_type = str(relationship.get("relation_type") or "")
                if (
                    not relationship_id
                    or source_memory_id not in all_entry_ids
                    or target_memory_id not in all_entry_ids
                    or not relation_type
                    or relationship_id
                    != self.store.stable_relationship_id(
                        context_id=context_id,
                        source_memory_id=source_memory_id,
                        target_memory_id=target_memory_id,
                        relation_type=relation_type,
                    )
                ):
                    candidate_reasons.append("invalid-deployment-relationship-identity")
                    continue
                live_relationship = conn.execute(
                    """
                    SELECT context_id, source_memory_id, target_memory_id,
                           relation_type, weight
                    FROM memory_relationships WHERE relationship_id = ?
                    """,
                    (relationship_id,),
                ).fetchone()
                if (
                    live_relationship is None
                    or str(live_relationship["context_id"]) != context_id
                    or str(live_relationship["source_memory_id"])
                    != source_memory_id
                    or str(live_relationship["target_memory_id"])
                    != target_memory_id
                    or str(live_relationship["relation_type"]) != relation_type
                    or not isinstance(relationship.get("weight"), (int, float))
                    or isinstance(relationship.get("weight"), bool)
                    or not math.isclose(
                        float(live_relationship["weight"]),
                        float(relationship["weight"]),
                        rel_tol=0.0,
                        abs_tol=1e-9,
                    )
                ):
                    candidate_reasons.append("deployment-relationship-mismatch")
            if (
                any(not value for value in relationship_ids)
                or len(relationship_ids) != len(set(relationship_ids))
            ):
                candidate_reasons.append("duplicate-deployment-relationship")
            namespace_relationship_ids = {
                str(item.get("relationship_id") or "")
                for item in namespace_relationships
            }
            if not namespace_relationship_ids.issubset(set(relationship_ids)):
                candidate_reasons.append("context-namespace-relationship-mismatch")

            expected_summary = (
                f"{source_tag} captured {event_count} conversation events"
            )
            if str(deployment_row["summary"]) != expected_summary:
                candidate_reasons.append("deployment-summary-mismatch")
            try:
                agent_targets = json.loads(
                    str(deployment_row["agent_targets_json"])
                )
            except (TypeError, json.JSONDecodeError):
                agent_targets = None
            target_rows = conn.execute(
                """
                SELECT target_kind, target_id
                FROM agent_context_event_targets
                WHERE event_id = ?
                ORDER BY target_kind, target_id
                """,
                (int(deployment_row["event_id"]),),
            ).fetchall()
            target_records = {
                (str(item["target_kind"]), str(item["target_id"]))
                for item in target_rows
            }
            target_ids = {target_id for _target_kind, target_id in target_records}
            if (
                not isinstance(agent_targets, list)
                or any(not isinstance(item, str) for item in agent_targets)
                or len(agent_targets) != len(set(agent_targets))
                or set(agent_targets) != target_ids
                or (
                    binding_mode == "legacy-capture-file"
                    and (
                        target_ids != EXPECTED_CAPTURE_AGENT_TARGETS
                        or target_records != EXPECTED_CAPTURE_TARGET_RECORDS
                    )
                )
            ):
                candidate_reasons.append("deployment-target-mismatch")
            committed_at = deployment_row["created_at"]
            if (
                not isinstance(committed_at, (int, float))
                or isinstance(committed_at, bool)
                or not math.isfinite(float(committed_at))
            ):
                candidate_reasons.append("invalid-deployment-timestamp")
            try:
                canonical_payload = json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
            except (TypeError, ValueError):
                candidate_reasons.append("noncanonical-deployment-payload")
                canonical_payload = ""
            if canonical_payload != raw_payload:
                candidate_reasons.append("noncanonical-deployment-payload")
            if candidate_reasons:
                reasons.extend(candidate_reasons)
                continue

            evidence_seed = {
                "capture_id": capture_id,
                "request_fingerprint": request_fingerprint,
                "relative_path": relative_path,
                "file_sha256": file_sha256,
                "record_index": record_index,
                "binding_mode": binding_mode,
                "deployment_event_id": int(deployment_row["event_id"]),
                "deployment_payload_sha256": hashlib.sha256(
                    raw_payload.encode("utf-8")
                ).hexdigest(),
                "entry_memory_ids": sorted(all_entry_ids),
                "relationship_ids": sorted(relationship_ids),
                "committed_at": float(committed_at),
            }
            matched.append(
                {
                    **evidence_seed,
                    "evidence_revision": self._exact_json_digest(evidence_seed),
                    "context_id": context_id,
                    "source_tag": source_tag,
                    "speaker": speaker,
                    "deployment_event_type": str(deployment_row["event_type"]),
                    "deployment_source_surface": str(
                        deployment_row["source_surface"]
                    ),
                    "event_count": int(event_count),
                    "entry_count": len(all_entry_ids),
                    "relationship_count": int(relationship_count),
                }
            )

        if len(matched) != 1:
            reasons.append(
                "missing-durable-deployment"
                if not matched
                else "ambiguous-durable-deployment"
            )
            return None, sorted(set(reasons))
        return matched[0], []

    def _capture_ledger_audit_locked(
        self,
        conn: sqlite3.Connection,
        *,
        sample_limit: int,
        adopt_legacy_ledger_schema: bool = False,
    ) -> dict[str, Any]:
        root_provenance = self._validate_capture_source_root()
        schema_errors = self._capture_ledger_schema_errors(conn)
        schema_adoption_required = False
        if schema_errors:
            if not (
                adopt_legacy_ledger_schema
                and self._legacy_capture_ledger_schema_adoption_allowed(
                    schema_errors
                )
            ):
                raise RuntimeError(
                    "capture ledger reconciliation schema is invalid "
                    f"(errors={schema_errors[:8]!r})"
                )
            schema_adoption_required = True
        paths = self.daemon.paths()
        self.daemon._ensure_transport_dirs(paths)
        processed_dir = paths["processed_dir"]
        root_metadata = os.lstat(processed_dir)
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(
            root_metadata.st_mode
        ):
            raise ValueError("capture processed archive is not a real directory")
        if schema_adoption_required:
            ledger_operations = {}
        else:
            ledger_operations = {
                str(row["capture_id"]): row
                for row in conn.execute(
                    """
                    SELECT capture_id, request_fingerprint, context_id,
                           source_tag, speaker
                    FROM capture_operations
                    """
                ).fetchall()
            }
        ledger_ids = set(ledger_operations)
        max_files, max_total_bytes, max_file_bytes = self._bounded_capture_limits()
        scanned_file_count = 0
        scanned_total_bytes = 0
        findings: list[dict[str, Any]] = []
        ledger_backed_evidence: list[dict[str, Any]] = []
        seen_v2_locations: dict[str, list[dict[str, Any]]] = {}
        for current_root, dir_names, file_names in os.walk(
            processed_dir,
            followlinks=False,
        ):
            current = Path(current_root)
            for dir_name in list(dir_names):
                metadata = os.lstat(current / dir_name)
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise ValueError("capture processed archive contains an unsafe directory")
            for file_name in sorted(file_names):
                path = current / file_name
                data, _metadata = self._read_private_regular(
                    path,
                    max_bytes=max_file_bytes,
                )
                self._assert_secret_safe_text(data)
                scanned_file_count += 1
                scanned_total_bytes += len(data)
                if (
                    scanned_file_count > max_files
                    or scanned_total_bytes > max_total_bytes
                ):
                    raise RuntimeError("capture ledger audit exceeded its bounds")
                records = self._decode_capture_records(path, data)
                if records is None:
                    continue
                relative_path = path.relative_to(self.capture_root).as_posix()
                file_sha256 = hashlib.sha256(data).hexdigest()
                for record_index, record in enumerate(records):
                    raw_version = record.get("version", 1)
                    if isinstance(raw_version, bool):
                        continue
                    try:
                        version = int(raw_version)
                    except (TypeError, ValueError):
                        continue
                    if version != 2:
                        continue
                    capture_id = str(record.get("capture_id") or "")
                    if CAPTURE_ID_RE.fullmatch(capture_id) is None:
                        continue
                    finding: dict[str, Any] = {
                        "capture_id": capture_id,
                        "finding_type": (
                            "ledger-backed"
                            if capture_id in ledger_ids
                            else "missing-ledger"
                        ),
                        "relative_path": relative_path,
                        "file_sha256": file_sha256,
                        "record_index": record_index,
                        "reasons": [],
                    }
                    seen_v2_locations.setdefault(capture_id, []).append(
                        {
                            "capture_id": capture_id,
                            "relative_path": relative_path,
                            "file_sha256": file_sha256,
                            "record_index": record_index,
                        }
                    )
                    try:
                        capture_binding = self._canonical_v2_capture_binding(
                            path=path,
                            record=record,
                        )
                        canonical_request = dict(
                            capture_binding["_canonical_request"]
                        )
                        request_fingerprint = str(
                            capture_binding["request_fingerprint"]
                        )
                        ledger_operation = ledger_operations.get(capture_id)
                        if ledger_operation is not None:
                            mismatch_fields = [
                                field
                                for field, expected_value in (
                                    (
                                        "request_fingerprint",
                                        request_fingerprint,
                                    ),
                                    (
                                        "context_id",
                                        str(capture_binding["context_id"]),
                                    ),
                                    (
                                        "source_tag",
                                        str(capture_binding["source_tag"]),
                                    ),
                                    (
                                        "speaker",
                                        str(capture_binding["speaker"]),
                                    ),
                                )
                                if str(ledger_operation[field])
                                != expected_value
                            ]
                            if mismatch_fields:
                                finding["finding_type"] = "ledger-mismatch"
                                finding["reasons"] = [
                                    "ledger-request-binding-mismatch"
                                ]
                                findings.append(finding)
                            else:
                                ledger_backed_evidence.append(
                                    {
                                        "capture_id": capture_id,
                                        "relative_path": relative_path,
                                        "file_sha256": file_sha256,
                                        "record_index": record_index,
                                        "request_fingerprint": request_fingerprint,
                                    }
                                )
                            continue
                        candidate, reasons = (
                            self._legacy_capture_deployment_candidate(
                                conn,
                                capture_id=capture_id,
                                canonical_request=canonical_request,
                                request_fingerprint=request_fingerprint,
                                relative_path=relative_path,
                                file_sha256=file_sha256,
                                record_index=record_index,
                            )
                        )
                        finding["reasons"] = reasons
                        if candidate is not None:
                            finding["_candidate"] = candidate
                            finding["evidence_revision"] = candidate[
                                "evidence_revision"
                            ]
                            finding["deployment_event_id"] = candidate[
                                "deployment_event_id"
                            ]
                            finding["event_count"] = candidate["event_count"]
                            finding["entry_count"] = candidate["entry_count"]
                            finding["relationship_count"] = candidate[
                                "relationship_count"
                            ]
                    except Exception as exc:
                        finding["reasons"] = [
                            (
                                "ledger-backed-payload-invalid"
                                if capture_id in ledger_ids
                                else "unsupported-legacy-payload"
                            )
                            if isinstance(exc, ValueError)
                            else "capture-evidence-evaluation-failed"
                        ]
                        if capture_id in ledger_ids:
                            finding["finding_type"] = "ledger-mismatch"
                    findings.append(finding)

        for capture_id, locations in seen_v2_locations.items():
            if len(locations) <= 1:
                continue
            ledger_backed_evidence = [
                evidence
                for evidence in ledger_backed_evidence
                if evidence["capture_id"] != capture_id
            ]
            duplicates = [
                finding
                for finding in findings
                if finding["capture_id"] == capture_id
            ]
            if not duplicates:
                duplicates = [
                    {
                        **location,
                        "finding_type": "duplicate-processed-capture-id",
                        "reasons": [],
                    }
                    for location in locations
                ]
                findings.extend(duplicates)
            for finding in duplicates:
                finding.pop("_candidate", None)
                finding.pop("evidence_revision", None)
                finding["finding_type"] = "duplicate-processed-capture-id"
                finding["reasons"] = sorted(
                    {
                        *finding.get("reasons", []),
                        "duplicate-processed-capture-id",
                    }
                )
        findings.sort(
            key=lambda value: (
                str(value["capture_id"]),
                str(value["relative_path"]),
                int(value["record_index"]),
            )
        )
        candidates = [
            dict(finding["_candidate"])
            for finding in findings
            if isinstance(finding.get("_candidate"), dict)
        ]
        missing_capture_ids = {
            capture_id
            for capture_id in seen_v2_locations
            if capture_id not in ledger_ids
        }
        ledger_mismatches = [
            finding
            for finding in findings
            if finding["finding_type"]
            in {"ledger-mismatch", "duplicate-processed-capture-id"}
        ]
        blocked = [
            finding
            for finding in findings
            if finding["finding_type"] == "missing-ledger"
            and finding.get("reasons")
            and not finding.get("_candidate")
        ]
        revision_seed = [
            {
                "capture_id": finding["capture_id"],
                "relative_path": finding["relative_path"],
                "file_sha256": finding["file_sha256"],
                "record_index": finding["record_index"],
                "evidence_revision": finding.get("evidence_revision", ""),
                "reasons": finding.get("reasons", []),
            }
            for finding in findings
        ]
        audit_revision = self._exact_json_digest(
            {
                "schema": CAPTURE_LEDGER_RECONCILIATION_SCHEMA,
                "capture_root_provenance": root_provenance,
                "schema_adoption_required": schema_adoption_required,
                "schema_adoption_errors": schema_errors,
                "findings": revision_seed,
                "ledger_backed_evidence": sorted(
                    ledger_backed_evidence,
                    key=lambda value: (
                        str(value["capture_id"]),
                        str(value["relative_path"]),
                        int(value["record_index"]),
                    ),
                ),
            }
        )
        public_finding_keys = {
            "capture_id",
            "finding_type",
            "reasons",
            "deployment_event_id",
            "event_count",
            "entry_count",
            "relationship_count",
        }
        public_findings = [
            {
                key: value
                for key, value in finding.items()
                if key in public_finding_keys
            }
            for finding in findings[:sample_limit]
        ]
        status = (
            "ready"
            if not findings
            else "blocked"
            if blocked or ledger_mismatches
            else "degraded"
        )
        return {
            "action": "capture-ledger-audit",
            "schema": CAPTURE_LEDGER_RECONCILIATION_SCHEMA,
            "status": status,
            "capture_root_provenance": root_provenance[
                "capture_root_provenance"
            ],
            "capture_root_identity_digest": root_provenance[
                "capture_root_identity_digest"
            ],
            "audit_revision": audit_revision,
            "processed_file_count": scanned_file_count,
            "processed_total_bytes": scanned_total_bytes,
            "processed_v2_capture_count": sum(
                len(locations) for locations in seen_v2_locations.values()
            ),
            "ledger_capture_count": len(ledger_ids),
            "schema_adoption_required": schema_adoption_required,
            "schema_adoption_errors": schema_errors,
            "missing_authoritative_ledger_count": len(missing_capture_ids),
            "ledger_binding_mismatch_count": len(ledger_mismatches),
            "repairable_capture_count": len(candidates),
            "blocked_capture_count": len(blocked) + len(ledger_mismatches),
            "repairable": bool(missing_capture_ids)
            and len(candidates) == len(missing_capture_ids)
            and not blocked
            and not ledger_mismatches,
            "verification_passed": not findings,
            "finding_samples": public_findings,
            "sample_limit": sample_limit,
            "checked_at": time.time(),
            "_candidates": candidates,
        }

    def audit_capture_ledger(
        self,
        *,
        sample_limit: int = 20,
        adopt_legacy_ledger_schema: bool = False,
    ) -> dict[str, Any]:
        bounded_sample_limit = min(max(int(sample_limit), 1), 1000)
        root_provenance = self._validate_capture_source_root()
        paths = self.daemon.paths()
        self.daemon._ensure_transport_dirs(paths)
        with self.daemon._exclusive_lock(
            paths["lock_dir"] / GLOBAL_CAPTURE_LOCK,
            blocking=True,
        ) as acquired:
            if not acquired:
                raise RuntimeError("capture maintenance lock is unavailable")
            if self._validate_capture_source_root() != root_provenance:
                raise RuntimeError(
                    "capture source root changed before the maintenance lock was acquired"
                )
            with closing(self.store._connect_read_only()) as conn:
                with self.store._transaction(conn):
                    audit = self._capture_ledger_audit_locked(
                        conn,
                        sample_limit=bounded_sample_limit,
                        adopt_legacy_ledger_schema=adopt_legacy_ledger_schema,
                    )
        return self._public_capture_ledger_audit(audit)

    def _completed_capture_ledger_repair(
        self,
        conn: sqlite3.Connection,
        *,
        expected_revision: str,
    ) -> dict[str, Any] | None:
        rows = conn.execute(
            """
            SELECT operation_id, after_revision, payload_json, created_at
            FROM store_maintenance_receipts
            WHERE operation_type = 'capture-ledger-reconciliation'
              AND before_revision = ?
            ORDER BY created_at, operation_id
            """,
            (expected_revision,),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RuntimeError("capture ledger repair has ambiguous audit history")
        row = rows[0]
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("capture ledger repair receipt is invalid") from exc
        capture_ids = payload.get("capture_ids") if isinstance(payload, dict) else None
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != CAPTURE_LEDGER_RECONCILIATION_SCHEMA
            or not isinstance(capture_ids, list)
            or len(capture_ids) != len(set(capture_ids))
            or any(
                not isinstance(capture_id, str)
                or CAPTURE_ID_RE.fullmatch(capture_id) is None
                for capture_id in capture_ids
            )
        ):
            raise RuntimeError("capture ledger repair receipt contract is invalid")
        existing = {
            str(item[0])
            for capture_id in capture_ids
            for item in conn.execute(
                "SELECT capture_id FROM capture_operations WHERE capture_id = ?",
                (capture_id,),
            ).fetchall()
        }
        if existing != set(capture_ids):
            raise RuntimeError("completed capture ledger repair lost authoritative rows")
        integrity_error_count, _samples = self.store._capture_operation_integrity_audit(
            conn
        )
        if integrity_error_count:
            raise RuntimeError("completed capture ledger repair no longer verifies")
        return {
            "operation_id": str(row["operation_id"]),
            "after_revision": str(row["after_revision"]),
            "capture_ids": capture_ids,
            "repaired_capture_count": len(capture_ids),
            "created_at": float(row["created_at"]),
        }

    def _revalidate_capture_ledger_candidate_artifact(
        self,
        candidate: dict[str, Any],
    ) -> None:
        relative = Path(str(candidate.get("relative_path") or ""))
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not relative.parts
            or relative.parts[0] != "capture_processed"
        ):
            raise RuntimeError("capture ledger candidate path is invalid")
        source = self.capture_root / relative
        _max_files, _max_total_bytes, max_file_bytes = self._bounded_capture_limits()
        data, _metadata = self._read_private_regular(
            source,
            max_bytes=max_file_bytes,
        )
        if not secrets.compare_digest(
            hashlib.sha256(data).hexdigest(),
            str(candidate.get("file_sha256") or ""),
        ):
            raise RuntimeError("capture ledger candidate artifact changed after review")
        records = self._decode_capture_records(source, data)
        record_index = candidate.get("record_index")
        if (
            records is None
            or type(record_index) is not int
            or not 0 <= record_index < len(records)
        ):
            raise RuntimeError("capture ledger candidate record index is invalid")
        record = records[record_index]
        if record.get("capture_id") != candidate.get("capture_id"):
            raise RuntimeError("capture ledger candidate identity changed after review")
        normalized = self.daemon._normalize_payload_before_capture(
            path=source,
            payload=dict(record),
            version=2,
        )
        request = self.daemon._canonical_capture_request(normalized)
        fingerprint = capture_request_fingerprint(
            text=str(request["text"]),
            context_id=str(request["context_id"]),
            source_tag=str(request["source_tag"]),
            speaker=str(request["speaker"]),
            surprise_threshold=float(request["surprise_threshold"]),
            min_segment_sentences=int(request["min_segment_sentences"]),
            metadata=dict(request["metadata"]),
        )
        if (
            not secrets.compare_digest(
                fingerprint,
                str(candidate.get("request_fingerprint") or ""),
            )
            or str(request["context_id"]) != candidate.get("context_id")
            or str(request["source_tag"]) != candidate.get("source_tag")
            or str(request["speaker"]) != candidate.get("speaker")
        ):
            raise RuntimeError("capture ledger candidate request changed after review")

    def repair_capture_ledger(
        self,
        *,
        confirm: bool = False,
        expected_revision: str | None = None,
        sample_limit: int = 20,
        adopt_legacy_ledger_schema: bool = False,
        fault_hook: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        if confirm is not True:
            raise ValueError("capture ledger repair requires confirm=True")
        expected = str(expected_revision or "").strip()
        if BACKUP_DIGEST_RE.fullmatch(expected) is None:
            raise ValueError(
                "capture ledger repair requires a reviewed 64-character audit revision"
            )
        if fault_hook is not None and not callable(fault_hook):
            raise ValueError("fault_hook must be callable")
        bounded_sample_limit = min(max(int(sample_limit), 1), 1000)
        started = time.perf_counter()
        safety_backup: dict[str, Any] | None = None
        repair_committed = False
        root_provenance = self._validate_capture_source_root()
        if root_provenance["capture_root_provenance"] != "canonical-store-parent":
            raise ValueError(
                "capture ledger repair requires the canonical memory-store capture root"
            )
        paths = self.daemon.paths()
        self.daemon._ensure_transport_dirs(paths)
        try:
            with self._repository_lock():
                with self.daemon._exclusive_lock(
                    paths["lock_dir"] / GLOBAL_CAPTURE_LOCK,
                    blocking=True,
                ) as acquired:
                    if not acquired:
                        raise RuntimeError("capture maintenance lock is unavailable")
                    locked_root_provenance = self._validate_capture_source_root()
                    if locked_root_provenance != root_provenance:
                        raise RuntimeError(
                            "capture source root changed before the maintenance lock was acquired"
                        )
                    if (
                        locked_root_provenance["capture_root_provenance"]
                        != "canonical-store-parent"
                    ):
                        raise RuntimeError(
                            "capture ledger repair lost canonical root provenance"
                        )
                    with (
                        closing(self.store._connect_existing_write()) as conn,
                        ExitStack() as maintenance_scope,
                    ):
                        data_version_before = int(
                            conn.execute("PRAGMA data_version").fetchone()[0]
                        )
                        with self.store._transaction(conn):
                            before = self._capture_ledger_audit_locked(
                                conn,
                                sample_limit=bounded_sample_limit,
                                adopt_legacy_ledger_schema=adopt_legacy_ledger_schema,
                            )
                        data_version_after = int(
                            conn.execute("PRAGMA data_version").fetchone()[0]
                        )
                        if data_version_before != data_version_after:
                            raise RuntimeError(
                                "memory store changed during capture ledger audit"
                            )
                        if before["audit_revision"] != expected:
                            completed = self._completed_capture_ledger_repair(
                                conn,
                                expected_revision=expected,
                            )
                            if completed is not None and before["status"] == "ready":
                                public_before = self._public_capture_ledger_audit(
                                    before
                                )
                                return {
                                    "action": "capture-ledger-repair",
                                    "status": "ready",
                                    "state": "already-completed",
                                    "repair_confirmed": True,
                                    "expected_revision": expected,
                                    "operation_id": completed["operation_id"],
                                    "repaired_capture_count": completed[
                                        "repaired_capture_count"
                                    ],
                                    "repaired_capture_ids": completed[
                                        "capture_ids"
                                    ][:bounded_sample_limit],
                                    "safety_backup": None,
                                    "before": public_before,
                                    "after": public_before,
                                    "verification_passed": True,
                                    "elapsed_ms": round(
                                        (time.perf_counter() - started) * 1000.0,
                                        3,
                                    ),
                                }
                            raise RuntimeError(
                                "capture ledger repair plan is stale; rerun and review the audit"
                            )
                        if before["status"] == "ready":
                            public_before = self._public_capture_ledger_audit(before)
                            return {
                                "action": "capture-ledger-repair",
                                "status": "ready",
                                "state": "no-repair-needed",
                                "repair_confirmed": True,
                                "expected_revision": expected,
                                "operation_id": None,
                                "repaired_capture_count": 0,
                                "repaired_capture_ids": [],
                                "safety_backup": None,
                                "before": public_before,
                                "after": public_before,
                                "verification_passed": True,
                                "elapsed_ms": round(
                                    (time.perf_counter() - started) * 1000.0,
                                    3,
                                ),
                            }
                        if not before["repairable"]:
                            raise RuntimeError(
                                "capture ledger repair refused because durable evidence is incomplete or ambiguous"
                            )

                        maintenance_lock_fds = self.store._acquire_maintenance_lock(
                            "capture-ledger-reconciliation"
                        )
                        maintenance_scope.callback(
                            self.store._release_maintenance_lock,
                            maintenance_lock_fds,
                        )
                        safety_backup = self.store._verified_safety_backup(
                            conn,
                            label="pre-capture-ledger-reconciliation",
                        )
                        if int(conn.execute("PRAGMA data_version").fetchone()[0]) != (
                            data_version_after
                        ):
                            raise RuntimeError(
                                "memory store changed during the capture ledger safety backup"
                            )
                        with self.store._transaction(
                            conn,
                            immediate=True,
                            cooperate_with_maintenance=False,
                        ):
                            current = self._capture_ledger_audit_locked(
                                conn,
                                sample_limit=bounded_sample_limit,
                                adopt_legacy_ledger_schema=adopt_legacy_ledger_schema,
                            )
                            if current["audit_revision"] != expected:
                                raise RuntimeError(
                                    "capture ledger evidence changed after planning"
                                )
                            candidates = list(current["_candidates"])
                            adopted_schema_errors: list[str] = []
                            if current["schema_adoption_required"]:
                                if not adopt_legacy_ledger_schema:
                                    raise RuntimeError(
                                        "legacy capture ledger schema adoption was not authorized"
                                    )
                                adopted_schema_errors = (
                                    self._install_legacy_capture_ledger_schema(
                                        conn,
                                        expected_errors=list(
                                            current["schema_adoption_errors"]
                                        ),
                                    )
                                )
                            repaired_capture_ids: list[str] = []
                            evidence_revisions: list[str] = []
                            for index, candidate in enumerate(candidates):
                                self._revalidate_capture_ledger_candidate_artifact(
                                    candidate
                                )
                                capture_id = str(candidate["capture_id"])
                                existing = conn.execute(
                                    "SELECT capture_id FROM capture_operations WHERE capture_id = ?",
                                    (capture_id,),
                                ).fetchone()
                                if existing is not None:
                                    raise RuntimeError(
                                        "capture ledger candidate was committed concurrently"
                                    )
                                deployment_in_use = conn.execute(
                                    """
                                    SELECT capture_id FROM capture_operations
                                    WHERE deployment_event_id = ?
                                    """,
                                    (int(candidate["deployment_event_id"]),),
                                ).fetchone()
                                if deployment_in_use is not None:
                                    raise RuntimeError(
                                        "capture deployment event is already owned by another operation"
                                    )
                                _envelope, envelope_json = (
                                    self.store._build_private_capture_operation_receipt(
                                        capture_id=capture_id,
                                        request_fingerprint=str(
                                            candidate["request_fingerprint"]
                                        ),
                                        context_id=str(candidate["context_id"]),
                                        source_tag=str(candidate["source_tag"]),
                                        speaker=str(candidate["speaker"]),
                                        deployment_event_id=int(
                                            candidate["deployment_event_id"]
                                        ),
                                        deployment_event_type=str(
                                            candidate["deployment_event_type"]
                                        ),
                                        deployment_source_surface=str(
                                            candidate["deployment_source_surface"]
                                        ),
                                        deployment_published_at=float(
                                            candidate["committed_at"]
                                        ),
                                        event_count=int(candidate["event_count"]),
                                        entry_count=int(candidate["entry_count"]),
                                        relationship_count=int(
                                            candidate["relationship_count"]
                                        ),
                                        committed_at=float(candidate["committed_at"]),
                                    )
                                )
                                conn.execute(
                                    """
                                    INSERT INTO capture_operations (
                                        capture_id, protocol, request_fingerprint,
                                        context_id, source_tag, speaker, result_json,
                                        deployment_event_id, entry_count,
                                        relationship_count, committed_at
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                    """,
                                    (
                                        capture_id,
                                        CAPTURE_PROTOCOL_VERSION,
                                        str(candidate["request_fingerprint"]),
                                        str(candidate["context_id"]),
                                        str(candidate["source_tag"]),
                                        str(candidate["speaker"]),
                                        envelope_json,
                                        int(candidate["deployment_event_id"]),
                                        int(candidate["entry_count"]),
                                        int(candidate["relationship_count"]),
                                        float(candidate["committed_at"]),
                                    ),
                                )
                                repaired_capture_ids.append(capture_id)
                                evidence_revisions.append(
                                    str(candidate["evidence_revision"])
                                )
                                if fault_hook is not None:
                                    fault_hook(f"after_ledger_{index + 1}")

                            integrity_error_count, integrity_samples = (
                                self.store._capture_operation_integrity_audit(conn)
                            )
                            if integrity_error_count:
                                raise RuntimeError(
                                    "capture ledger verification failed after reconciliation: "
                                    f"{integrity_samples[:3]!r}"
                                )
                            after = self._capture_ledger_audit_locked(
                                conn,
                                sample_limit=bounded_sample_limit,
                                adopt_legacy_ledger_schema=False,
                            )
                            if after["status"] != "ready":
                                raise RuntimeError(
                                    "capture ledger reconciliation left missing authoritative rows"
                                )
                            operation_id = "s2maint_" + uuid.uuid4().hex
                            target_digest = hashlib.sha256(
                                "\n".join(sorted(repaired_capture_ids)).encode("ascii")
                            ).hexdigest()
                            receipt_payload = {
                                "schema": CAPTURE_LEDGER_RECONCILIATION_SCHEMA,
                                "content_free": True,
                                "legacy_schema_adopted": bool(adopted_schema_errors),
                                "legacy_schema_errors_repaired": adopted_schema_errors,
                                "capture_ids": sorted(repaired_capture_ids),
                                "capture_id_sha256": target_digest,
                                "repaired_capture_count": len(
                                    repaired_capture_ids
                                ),
                                "evidence_revision_sha256": hashlib.sha256(
                                    "\n".join(sorted(evidence_revisions)).encode(
                                        "ascii"
                                    )
                                ).hexdigest(),
                                "safety_backup_artifact": Path(
                                    str(safety_backup["backup_path"])
                                ).name,
                                "safety_backup_sha256": str(
                                    safety_backup["sha256"]
                                ),
                                "historical_commit_time_source": (
                                    "conversation-capture-deployment-event"
                                ),
                                "transport_receipts_synthesized": False,
                            }
                            if fault_hook is not None:
                                fault_hook("before_maintenance_receipt")
                            conn.execute(
                                """
                                INSERT INTO store_maintenance_receipts (
                                    operation_id, operation_type, context_id,
                                    before_revision, after_revision,
                                    payload_json, created_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    operation_id,
                                    "capture-ledger-reconciliation",
                                    "all",
                                    expected,
                                    str(after["audit_revision"]),
                                    _json_dumps(receipt_payload),
                                    time.time(),
                                ),
                            )
                        repair_committed = True
                        with self.store._transaction(conn):
                            verified_after = self._capture_ledger_audit_locked(
                                conn,
                                sample_limit=bounded_sample_limit,
                                adopt_legacy_ledger_schema=False,
                            )
                        if verified_after["status"] != "ready":
                            raise RuntimeError(
                                "capture ledger post-commit verification failed"
                            )
            return {
                "action": "capture-ledger-repair",
                "status": "ready",
                "state": "completed",
                "repair_confirmed": True,
                "expected_revision": expected,
                "operation_id": operation_id,
                "repaired_capture_count": len(repaired_capture_ids),
                "repaired_capture_ids": repaired_capture_ids[
                    :bounded_sample_limit
                ],
                "safety_backup": safety_backup,
                "before": self._public_capture_ledger_audit(before),
                "after": self._public_capture_ledger_audit(verified_after),
                "verification_passed": True,
                "elapsed_ms": round(
                    (time.perf_counter() - started) * 1000.0,
                    3,
                ),
            }
        except Exception:
            if safety_backup is not None and not repair_committed:
                self.store._discard_safety_backup(safety_backup)
            raise

    def _write_capture_archive(
        self,
        output_path: Path,
        manifest: dict[str, Any],
    ) -> dict[str, Any]:
        if output_path.exists() or output_path.is_symlink():
            raise FileExistsError("capture archive already exists; refusing overwrite")
        temporary = self.store._unique_private_temp_path(
            output_path.parent,
            prefix=f".{output_path.name}.",
        )
        published = False
        try:
            with tarfile.open(temporary, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
                manifest_bytes = (
                    json.dumps(manifest, indent=2, sort_keys=True) + "\n"
                ).encode("utf-8")
                manifest_info = tarfile.TarInfo("capture-manifest.json")
                manifest_info.size = len(manifest_bytes)
                manifest_info.mode = 0o600
                manifest_info.mtime = 0
                archive.addfile(manifest_info, io.BytesIO(manifest_bytes))
                for record in manifest["files"]:
                    relative = str(record["relative_path"])
                    source = self.capture_root / relative
                    data, _ = self._read_private_regular(
                        source,
                        max_bytes=int(record["size_bytes"]),
                    )
                    if (
                        len(data) != int(record["size_bytes"])
                        or hashlib.sha256(data).hexdigest() != str(record["sha256"])
                    ):
                        raise RuntimeError("capture input changed after manifest creation")
                    info = tarfile.TarInfo("capture/" + relative)
                    info.size = len(data)
                    info.mode = 0o600
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(data))
            self.store._fsync_file(temporary)
            temporary_digest, temporary_size, _ = self.store._hash_stable_regular_file(
                temporary
            )
            os.link(temporary, output_path, follow_symlinks=False)
            published = True
            temporary_metadata = os.lstat(temporary)
            output_metadata = os.lstat(output_path)
            if (temporary_metadata.st_dev, temporary_metadata.st_ino) != (
                output_metadata.st_dev,
                output_metadata.st_ino,
            ):
                raise RuntimeError("capture archive publication identity mismatch")
            os.chmod(output_path, 0o600, follow_symlinks=False)
            self.store._fsync_file(output_path)
            final_digest, final_size, _ = self.store._hash_stable_regular_file(output_path)
            if (
                not secrets.compare_digest(temporary_digest, final_digest)
                or temporary_size != final_size
            ):
                raise RuntimeError("capture archive changed during publication")
            temporary.unlink()
            self.store._fsync_directory(output_path.parent)
            return {"sha256": final_digest, "size_bytes": final_size}
        except BaseException:
            temporary.unlink(missing_ok=True)
            if published:
                output_path.unlink(missing_ok=True)
            self.store._fsync_directory(output_path.parent)
            raise

    def _media_inventory(
        self,
        *,
        referenced_media_ids: list[str],
        database_binding: dict[str, Any],
    ) -> dict[str, Any]:
        """Build the digest-bound media inventory for one immutable DB snapshot.

        The reference set must come from the immutable database artifact, never
        the live store. A referenced object that is missing or fails validation
        blocks publication; valid orphans are excluded from the archive and
        reported content-free.
        """

        reader = MediaObjectReader(self._media_root())
        stored_ids = reader.object_ids()
        referenced = sorted({str(media_id) for media_id in referenced_media_ids})
        if len(referenced) > MAX_MEDIA_OBJECTS:
            raise RuntimeError("media inventory reference bound exceeded")
        missing = sorted(set(referenced) - set(stored_ids))
        if missing:
            raise RuntimeError(
                "referenced media derivatives are missing from the local cache "
                f"(missing={len(missing)})"
            )
        objects: list[dict[str, Any]] = []
        total_bytes = 0
        file_count = 0
        for media_id in referenced:
            try:
                manifest, files = reader.read_object_artifacts(media_id)
            except (ImageCaptureError, ValueError, OSError) as exc:
                raise RuntimeError(
                    "referenced media derivative failed verification"
                ) from exc
            file_records = []
            for name in sorted(files):
                data = files[name]
                total_bytes += len(data)
                file_count += 1
                if (
                    file_count > MAX_MEDIA_ARCHIVE_FILES
                    or total_bytes > MAX_MEDIA_ARCHIVE_TOTAL_BYTES
                ):
                    raise RuntimeError("media inventory exceeded its bounds")
                file_records.append(
                    {
                        "name": name,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "size_bytes": len(data),
                    }
                )
            objects.append(
                {
                    "media_id": media_id,
                    "artifact_schema": str(manifest["schema"]),
                    "files": file_records,
                }
            )
        orphaned = sorted(set(stored_ids) - set(referenced))
        for media_id in orphaned:
            try:
                reader.read_object_artifacts(media_id)
            except (ImageCaptureError, ValueError, OSError) as exc:
                raise RuntimeError(
                    "orphaned media derivative failed verification; repair or "
                    "prune the cache before paired backup"
                ) from exc
        reconciliation = {
            "referenced_count": len(referenced),
            "archived_object_count": len(objects),
            "missing_count": 0,
            "missing_media_ids": [],
            "orphan_count": len(orphaned),
            "orphan_media_ids": orphaned,
        }
        manifest_seed = {
            "schema": MEDIA_ARCHIVE_MANIFEST_SCHEMA,
            "object_count": len(objects),
            "file_count": file_count,
            "total_bytes": total_bytes,
            "database_binding": database_binding,
            "reconciliation": reconciliation,
            "objects": objects,
        }
        manifest_sha256 = hashlib.sha256(
            _json_dumps(manifest_seed).encode("utf-8")
        ).hexdigest()
        return {**manifest_seed, "manifest_sha256": manifest_sha256}

    def _write_media_archive(
        self,
        output_path: Path,
        manifest: dict[str, Any],
    ) -> dict[str, Any]:
        if output_path.exists() or output_path.is_symlink():
            raise FileExistsError("media archive already exists; refusing overwrite")
        reader = MediaObjectReader(self._media_root())
        temporary = self.store._unique_private_temp_path(
            output_path.parent,
            prefix=f".{output_path.name}.",
        )
        published = False
        try:
            with tarfile.open(temporary, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
                manifest_bytes = (
                    json.dumps(manifest, indent=2, sort_keys=True) + "\n"
                ).encode("utf-8")
                if len(manifest_bytes) > MAX_MEDIA_MANIFEST_BYTES:
                    raise RuntimeError("media manifest exceeds its size bound")
                manifest_info = tarfile.TarInfo("media-manifest.json")
                manifest_info.size = len(manifest_bytes)
                manifest_info.mode = 0o600
                manifest_info.mtime = 0
                archive.addfile(manifest_info, io.BytesIO(manifest_bytes))
                for record in manifest["objects"]:
                    media_id = str(record["media_id"])
                    _manifest, files = reader.read_object_artifacts(media_id)
                    expected_files = {
                        str(item["name"]): item for item in record["files"]
                    }
                    if set(files) != set(expected_files):
                        raise RuntimeError(
                            "media object changed after inventory creation"
                        )
                    for name in sorted(files):
                        data = files[name]
                        expected = expected_files[name]
                        if (
                            len(data) != int(expected["size_bytes"])
                            or hashlib.sha256(data).hexdigest()
                            != str(expected["sha256"])
                        ):
                            raise RuntimeError(
                                "media object changed after inventory creation"
                            )
                        info = tarfile.TarInfo(f"media/objects/{media_id}/{name}")
                        info.size = len(data)
                        info.mode = 0o600
                        info.mtime = 0
                        archive.addfile(info, io.BytesIO(data))
            self.store._fsync_file(temporary)
            temporary_digest, temporary_size, _ = self.store._hash_stable_regular_file(
                temporary
            )
            os.link(temporary, output_path, follow_symlinks=False)
            published = True
            temporary_metadata = os.lstat(temporary)
            output_metadata = os.lstat(output_path)
            if (temporary_metadata.st_dev, temporary_metadata.st_ino) != (
                output_metadata.st_dev,
                output_metadata.st_ino,
            ):
                raise RuntimeError("media archive publication identity mismatch")
            os.chmod(output_path, 0o600, follow_symlinks=False)
            self.store._fsync_file(output_path)
            final_digest, final_size, _ = self.store._hash_stable_regular_file(output_path)
            if (
                not secrets.compare_digest(temporary_digest, final_digest)
                or temporary_size != final_size
            ):
                raise RuntimeError("media archive changed during publication")
            temporary.unlink()
            self.store._fsync_directory(output_path.parent)
            return {"sha256": final_digest, "size_bytes": final_size}
        except BaseException:
            temporary.unlink(missing_ok=True)
            if published:
                output_path.unlink(missing_ok=True)
            self.store._fsync_directory(output_path.parent)
            raise

    def _verify_media_archive(
        self,
        archive_path: Path,
        *,
        expected_sha256: str,
        expected_manifest_sha256: str,
        database_binding: dict[str, Any] | None = None,
        retain_verified_snapshot: bool = False,
    ) -> dict[str, Any]:
        try:
            archive_metadata = os.lstat(archive_path)
        except FileNotFoundError as exc:
            raise ValueError("media archive does not exist") from exc
        if stat.S_ISLNK(archive_metadata.st_mode) or not stat.S_ISREG(
            archive_metadata.st_mode
        ):
            raise ValueError("media archive must be a non-symlink regular file")
        staging_dir = self.store._backup_verification_staging_dir()
        staged = self.store._unique_private_temp_path(
            staging_dir,
            prefix=f".{archive_path.name}.media-verify.",
        )
        retained = False
        try:
            copied = self.store._copy_stable_regular_file(archive_path, staged)
            if not secrets.compare_digest(str(copied["sha256"]), expected_sha256):
                raise RuntimeError("media archive digest verification failed")
            verification = self._verify_media_archive_snapshot(
                staged,
                expected_sha256=expected_sha256,
                expected_manifest_sha256=expected_manifest_sha256,
                database_binding=database_binding,
            )
            if retain_verified_snapshot:
                retained = True
                verification["verified_snapshot_path"] = str(staged)
            return verification
        finally:
            if not retained:
                staged.unlink(missing_ok=True)
            self.store._fsync_directory(staging_dir)

    def _verify_media_archive_snapshot(
        self,
        archive_path: Path,
        *,
        expected_sha256: str,
        expected_manifest_sha256: str,
        database_binding: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        digest, size_bytes, _ = self.store._hash_stable_regular_file(archive_path)
        if not secrets.compare_digest(digest, expected_sha256):
            raise RuntimeError("media archive digest verification failed")
        if size_bytes > MAX_MEDIA_ARCHIVE_ENVELOPE_BYTES:
            raise ValueError("media archive envelope exceeds its size ceiling")
        decompressed_stream_bytes = _require_single_bounded_gzip_stream(
            archive_path,
            max_decompressed_bytes=MAX_MEDIA_ARCHIVE_DECOMPRESSED_BYTES,
        )
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAX_MEDIA_ARCHIVE_FILES + 1:
                raise RuntimeError("media archive contains too many members")
            if any(not member.isfile() for member in members):
                raise ValueError("media archive contains a non-file member")
            manifest_members = [
                member for member in members if member.name == "media-manifest.json"
            ]
            if len(manifest_members) != 1:
                raise ValueError("media archive manifest is missing or ambiguous")
            manifest_member = manifest_members[0]
            if manifest_member.size > MAX_MEDIA_MANIFEST_BYTES:
                raise ValueError("media archive manifest exceeds its size limit")
            extracted_manifest = archive.extractfile(manifest_member)
            if extracted_manifest is None:
                raise ValueError("media archive manifest cannot be read")
            manifest_raw = extracted_manifest.read(MAX_MEDIA_MANIFEST_BYTES + 1)
            if len(manifest_raw) > MAX_MEDIA_MANIFEST_BYTES:
                raise ValueError("media archive manifest exceeds its size limit")
            try:
                manifest = json.loads(manifest_raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("media archive manifest is invalid") from exc
            if (
                not isinstance(manifest, dict)
                or manifest.get("schema") != MEDIA_ARCHIVE_MANIFEST_SCHEMA
                or set(manifest)
                != {
                    "schema",
                    "object_count",
                    "file_count",
                    "total_bytes",
                    "database_binding",
                    "reconciliation",
                    "objects",
                    "manifest_sha256",
                }
            ):
                raise ValueError("media archive manifest schema is unsupported")
            manifest_seed = {
                key: value for key, value in manifest.items() if key != "manifest_sha256"
            }
            calculated_manifest_digest = hashlib.sha256(
                _json_dumps(manifest_seed).encode("utf-8")
            ).hexdigest()
            if (
                not secrets.compare_digest(
                    str(manifest.get("manifest_sha256") or ""),
                    calculated_manifest_digest,
                )
                or not secrets.compare_digest(
                    calculated_manifest_digest,
                    expected_manifest_sha256,
                )
            ):
                raise RuntimeError("media archive manifest digest verification failed")
            binding = manifest.get("database_binding")
            if not isinstance(binding, dict):
                raise ValueError("media archive database binding is invalid")
            if database_binding is not None and binding != database_binding:
                raise RuntimeError("media archive database binding mismatch")
            reconciliation = manifest.get("reconciliation")
            objects = manifest.get("objects")
            if (
                not isinstance(reconciliation, dict)
                or set(reconciliation)
                != {
                    "referenced_count",
                    "archived_object_count",
                    "missing_count",
                    "missing_media_ids",
                    "orphan_count",
                    "orphan_media_ids",
                }
                or reconciliation.get("missing_count") != 0
                or reconciliation.get("missing_media_ids") != []
                or not isinstance(objects, list)
                or type(reconciliation.get("referenced_count")) is not int
                or type(reconciliation.get("archived_object_count")) is not int
                or type(reconciliation.get("orphan_count")) is not int
                or not isinstance(reconciliation.get("orphan_media_ids"), list)
                or reconciliation["archived_object_count"] != len(objects)
                or reconciliation["referenced_count"] != len(objects)
                or reconciliation["orphan_count"]
                != len(reconciliation["orphan_media_ids"])
            ):
                raise ValueError("media archive reconciliation is invalid")
            expected_members: dict[str, dict[str, Any]] = {}
            object_ids: list[str] = []
            declared_files = 0
            declared_bytes = 0
            for record in objects:
                if (
                    not isinstance(record, dict)
                    or set(record) != {"media_id", "artifact_schema", "files"}
                    or record.get("artifact_schema")
                    not in (IMAGE_ARTIFACT_SCHEMA, IMAGE_ARTIFACT_ENRICHED_SCHEMA)
                    or not isinstance(record.get("files"), list)
                    or not record["files"]
                ):
                    raise ValueError("media archive object record is invalid")
                media_id = str(record["media_id"])
                if re.fullmatch(r"s2img_[0-9a-f]{32}", media_id) is None:
                    raise ValueError("media archive object identity is invalid")
                object_ids.append(media_id)
                names = sorted(str(item.get("name")) for item in record["files"])
                if names not in (
                    ["manifest.json", "thumbnail.jpg"],
                    ["feature-print.bin", "manifest.json", "thumbnail.jpg"],
                ):
                    raise ValueError("media archive object inventory is invalid")
                for item in record["files"]:
                    if (
                        not isinstance(item, dict)
                        or set(item) != {"name", "sha256", "size_bytes"}
                        or BACKUP_DIGEST_RE.fullmatch(str(item.get("sha256") or ""))
                        is None
                        or type(item.get("size_bytes")) is not int
                        or item["size_bytes"] <= 0
                    ):
                        raise ValueError("media archive file record is invalid")
                    maximum = (
                        MAX_THUMBNAIL_BYTES
                        if item["name"] == "thumbnail.jpg"
                        else MAX_FEATURE_PRINT_BYTES
                        if item["name"] == "feature-print.bin"
                        else 64 * 1024
                    )
                    if item["size_bytes"] > maximum:
                        raise ValueError("media archive file exceeds its size bound")
                    member_name = f"media/objects/{media_id}/{item['name']}"
                    if member_name in expected_members:
                        raise ValueError("media archive file record is duplicated")
                    expected_members[member_name] = dict(item)
                    declared_files += 1
                    declared_bytes += int(item["size_bytes"])
            if len(set(object_ids)) != len(object_ids):
                raise ValueError("media archive object identity is duplicated")
            if (
                int(manifest["object_count"]) != len(object_ids)
                or int(manifest["file_count"]) != declared_files
                or int(manifest["total_bytes"]) != declared_bytes
                or declared_files > MAX_MEDIA_ARCHIVE_FILES
                or declared_bytes > MAX_MEDIA_ARCHIVE_TOTAL_BYTES
            ):
                raise RuntimeError("media archive manifest totals are inconsistent")
            # Bind the measured gzip payload to the manifest-declared member
            # bytes plus bounded tar headers/padding, so a signed envelope
            # cannot smuggle data hidden after the tar end-of-archive marker.
            declared_stream_ceiling = (
                declared_bytes
                + int(manifest_member.size)
                + (declared_files + 2) * 1024
                + 64 * 1024
            )
            if decompressed_stream_bytes > declared_stream_ceiling:
                raise ValueError(
                    "media archive stream exceeds its declared payload"
                )
            member_names = [
                member.name for member in members if member.name != "media-manifest.json"
            ]
            if (
                len(member_names) != len(set(member_names))
                or set(member_names) != set(expected_members)
            ):
                raise RuntimeError("media archive members do not match the manifest")
            for member in members:
                if member.name == "media-manifest.json":
                    continue
                record = expected_members[member.name]
                if member.size != int(record["size_bytes"]):
                    raise RuntimeError("media archive member size drifted")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError("media archive member cannot be read")
                data = extracted.read(int(record["size_bytes"]) + 1)
                if (
                    len(data) != int(record["size_bytes"])
                    or hashlib.sha256(data).hexdigest() != str(record["sha256"])
                ):
                    raise RuntimeError("media archive member digest mismatch")
            # Canonical member layout: every member is one plain 512-byte
            # header followed by its data, members are contiguous from offset
            # zero, and no extended (PAX/GNU) header blocks exist. The writer
            # only emits short USTAR-representable names, so any other layout
            # is foreign structure a permissive tar parser would tolerate.
            ordered_members = sorted(members, key=lambda item: int(item.offset))
            expected_offset = 0
            zero_intervals: list[tuple[int, int]] = []
            for member in ordered_members:
                if (
                    int(member.offset) != expected_offset
                    or int(member.offset_data)
                    != int(member.offset) + tarfile.BLOCKSIZE
                ):
                    raise ValueError(
                        "media archive member layout is not canonical"
                    )
                data_end = int(member.offset_data) + int(member.size)
                padded_end = int(member.offset_data) + (
                    (int(member.size) + 511) // 512
                ) * 512
                if padded_end > data_end:
                    zero_intervals.append((data_end, padded_end))
                expected_offset = padded_end
            tar_data_end = expected_offset
        # Exact canonical tar extent: after the last member's padded data the
        # stream may hold only the two zero end-of-archive blocks and zero
        # padding up to the record boundary, and every member's data padding
        # must itself be zero. Any nonzero byte in a padding region, or any
        # stream length other than the canonical padded extent, is smuggled
        # data the tar parser would silently ignore.
        canonical_extent = (
            (tar_data_end + 1024 + tarfile.RECORDSIZE - 1)
            // tarfile.RECORDSIZE
        ) * tarfile.RECORDSIZE
        interval_index = 0

        def _require_canonical_padding(piece: bytes, start: int) -> None:
            nonlocal interval_index
            end = start + len(piece)
            while interval_index < len(zero_intervals):
                zero_start, zero_end = zero_intervals[interval_index]
                if zero_start >= end:
                    break
                low = max(zero_start - start, 0)
                high = min(zero_end - start, len(piece))
                segment = piece[low:high]
                if segment.count(0) != len(segment):
                    raise ValueError(
                        "media archive hides data inside a member's padding"
                    )
                if zero_end > end:
                    break
                interval_index += 1
            if end <= tar_data_end:
                return
            tail = piece[max(tar_data_end - start, 0):]
            if tail.count(0) != len(tail):
                raise ValueError(
                    "media archive hides data after its tar end-of-archive marker"
                )

        exact_stream_bytes = _require_single_bounded_gzip_stream(
            archive_path,
            max_decompressed_bytes=MAX_MEDIA_ARCHIVE_DECOMPRESSED_BYTES,
            on_payload=_require_canonical_padding,
        )
        if exact_stream_bytes != canonical_extent:
            raise ValueError("media archive stream extent is not canonical")
        # Restorability parity: run the exact restore-path extraction and
        # MediaObjectReader semantic validation, so a digest-consistent but
        # semantically invalid embedded object manifest, thumbnail, or
        # feature print can never verify as restorable.
        staging_dir = self.store._backup_verification_staging_dir()
        parity_target = self.store._unique_private_temp_path(
            staging_dir,
            prefix=f".{archive_path.name}.restore-parity.",
        )
        try:
            parity_target.unlink()
            self._extract_media_archive(archive_path, manifest, parity_target)
        except (ImageCaptureError, ImageCaptureNotFound) as exc:
            raise ValueError(
                "media archive failed restore-parity validation"
            ) from exc
        finally:
            shutil.rmtree(parity_target, ignore_errors=True)
            parity_target.unlink(missing_ok=True)
            self.store._fsync_directory(staging_dir)
        return {
            "sha256": digest,
            "size_bytes": size_bytes,
            "manifest_sha256": str(manifest["manifest_sha256"]),
            "object_count": int(manifest["object_count"]),
            "file_count": int(manifest["file_count"]),
            "total_bytes": int(manifest["total_bytes"]),
            "referenced_count": int(reconciliation["referenced_count"]),
            "orphan_count": int(reconciliation["orphan_count"]),
            "object_ids": sorted(object_ids),
            "manifest": manifest,
            "verified": True,
        }

    def _extract_media_archive(
        self,
        archive_path: Path,
        manifest: dict[str, Any],
        target: Path,
    ) -> None:
        """Materialize verified media derivatives beneath one private root."""

        if target.exists() or target.is_symlink():
            raise FileExistsError("media restore target already exists")
        target.mkdir(mode=0o700, parents=False)
        try:
            objects_root = target / "objects"
            objects_root.mkdir(mode=0o700, parents=False)
            records: dict[str, dict[str, Any]] = {}
            for record in manifest["objects"]:
                media_id = str(record["media_id"])
                for item in record["files"]:
                    records[f"media/objects/{media_id}/{item['name']}"] = dict(item)
            with tarfile.open(archive_path, mode="r:gz") as archive:
                members = archive.getmembers()
                if any(not member.isfile() for member in members):
                    raise ValueError("media restore archive contains a non-file member")
                media_members = [
                    member
                    for member in members
                    if member.name != "media-manifest.json"
                ]
                media_names = [member.name for member in media_members]
                if (
                    len(media_names) != len(set(media_names))
                    or set(media_names) != set(records)
                    or sum(
                        member.name == "media-manifest.json" for member in members
                    )
                    != 1
                ):
                    raise RuntimeError(
                        "media restore archive members do not match the manifest"
                    )
                for member in media_members:
                    record = records[member.name]
                    relative = Path(member.name)
                    if (
                        relative.is_absolute()
                        or ".." in relative.parts
                        or len(relative.parts) != 4
                        or relative.parts[0] != "media"
                        or relative.parts[1] != "objects"
                    ):
                        raise ValueError("media restore member path is unsafe")
                    destination = objects_root / relative.parts[2] / relative.parts[3]
                    destination.parent.mkdir(mode=0o700, parents=False, exist_ok=True)
                    if destination.exists() or destination.is_symlink():
                        raise FileExistsError("media restore member already exists")
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise ValueError("media restore member cannot be read")
                    data = extracted.read(int(record["size_bytes"]) + 1)
                    if (
                        len(data) != int(record["size_bytes"])
                        or hashlib.sha256(data).hexdigest() != str(record["sha256"])
                    ):
                        raise RuntimeError("media restore member digest mismatch")
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    descriptor = os.open(destination, flags, 0o600)
                    try:
                        offset = 0
                        while offset < len(data):
                            offset += os.write(descriptor, data[offset:])
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
            restored_reader = MediaObjectReader(target)
            restored_ids = restored_reader.object_ids()
            expected_ids = sorted(
                str(record["media_id"]) for record in manifest["objects"]
            )
            if restored_ids != expected_ids:
                raise RuntimeError("restored media objects do not match the manifest")
            for media_id in restored_ids:
                restored_reader.read_object_artifacts(media_id)
            self.store._fsync_directory(target)
        except BaseException:
            shutil.rmtree(target, ignore_errors=True)
            raise

    def _snapshot_capture_ledger_bindings(
        self,
        conn: sqlite3.Connection,
    ) -> dict[str, dict[str, Any]]:
        conn.row_factory = sqlite3.Row
        self._require_capture_ledger_schema(conn)
        integrity_error_count, integrity_samples = (
            self.store._capture_operation_integrity_audit(conn)
        )
        if integrity_error_count:
            raise RuntimeError(
                "capture ledger snapshot integrity failed "
                f"(samples={integrity_samples[:3]!r})"
            )
        rows = conn.execute(
            """
            SELECT capture_id, protocol, request_fingerprint, context_id,
                   source_tag, speaker, committed_at
            FROM capture_operations
            ORDER BY capture_id
            """
        ).fetchall()
        bindings = {
            str(row["capture_id"]): {
                "capture_id": str(row["capture_id"]),
                "protocol": str(row["protocol"]),
                "request_fingerprint": str(row["request_fingerprint"]),
                "context_id": str(row["context_id"]),
                "source_tag": str(row["source_tag"]),
                "speaker": str(row["speaker"]),
                "committed_at": float(row["committed_at"]),
            }
            for row in rows
        }
        if len(bindings) != len(rows):
            raise RuntimeError("capture ledger snapshot has duplicate identities")
        return bindings

    def _processed_v2_binding_seeds(
        self,
        *,
        path: Path,
        data: bytes,
        member_sha256: str,
        ledger_bindings: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        records = self._decode_capture_records(path, data)
        if records is None:
            return []
        seeds: list[dict[str, Any]] = []
        for record_index, record in enumerate(records):
            raw_version = record.get("version", 1)
            if isinstance(raw_version, bool):
                raise ValueError("ledger-backed capture payload version is invalid")
            try:
                version = int(raw_version)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "ledger-backed capture payload version is invalid"
                ) from exc
            if version != 2:
                continue
            binding = self._canonical_v2_capture_binding(
                path=path,
                record=record,
            )
            capture_id = str(binding["capture_id"])
            expected = ledger_bindings.get(capture_id)
            if expected is None:
                raise RuntimeError(
                    "capture payload has no authoritative ledger binding"
                )
            compared_fields = (
                "capture_id",
                "protocol",
                "request_fingerprint",
                "context_id",
                "source_tag",
                "speaker",
            )
            mismatch_fields = [
                field
                for field in compared_fields
                if not secrets.compare_digest(
                    str(binding[field]),
                    str(expected.get(field) or ""),
                )
            ]
            if mismatch_fields:
                raise RuntimeError(
                    "capture request does not match its authoritative "
                    f"ledger binding (fields={mismatch_fields!r})"
                )
            seeds.append(
                {
                    "capture_id": capture_id,
                    "member_sha256": member_sha256,
                    "record_index": record_index,
                    "request_fingerprint": str(binding["request_fingerprint"]),
                    "context_id": str(binding["context_id"]),
                    "source_tag": str(binding["source_tag"]),
                    "speaker": str(binding["speaker"]),
                }
            )
        return seeds

    def _capture_ledger_binding_proof(
        self,
        seeds: Iterable[dict[str, Any]],
    ) -> dict[str, Any]:
        ordered = sorted(
            (dict(seed) for seed in seeds),
            key=lambda seed: (
                str(seed["capture_id"]),
                str(seed["member_sha256"]),
                int(seed["record_index"]),
            ),
        )
        capture_ids = [str(seed["capture_id"]) for seed in ordered]
        if len(capture_ids) != len(set(capture_ids)):
            raise RuntimeError(
                "capture binding proof contains duplicate processed capture IDs"
            )
        revision = self._exact_json_digest(
            {
                "schema": CAPTURE_LEDGER_BINDING_PROOF_SCHEMA,
                "bindings": ordered,
            }
        )
        return {
            "schema": CAPTURE_LEDGER_BINDING_PROOF_SCHEMA,
            "verified_capture_count": len(capture_ids),
            "revision": revision,
            "verified": True,
        }

    def _verify_extracted_capture_ledger_bindings(
        self,
        processed_root: Path,
        *,
        ledger_bindings: dict[str, dict[str, Any]],
        processing_root: Path | None = None,
    ) -> dict[str, Any]:
        roots = [(processed_root, True)]
        if processing_root is not None:
            roots.append((processing_root, False))
        if not any(root.exists() or root.is_symlink() for root, _ in roots):
            return self._capture_ledger_binding_proof([])
        max_files, max_total_bytes, max_file_bytes = self._bounded_capture_limits()
        scanned_files = 0
        scanned_bytes = 0
        seeds: list[dict[str, Any]] = []
        for scan_root, require_ledger in roots:
            if not scan_root.exists() and not scan_root.is_symlink():
                continue
            if scan_root.is_symlink() or not scan_root.is_dir():
                raise ValueError(
                    "restored ledger-backed capture root is not a real directory"
                )
            for current_root, dir_names, file_names in os.walk(
                scan_root,
                followlinks=False,
            ):
                current = Path(current_root)
                for dir_name in list(dir_names):
                    metadata = os.lstat(current / dir_name)
                    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(
                        metadata.st_mode
                    ):
                        raise ValueError(
                            "restored capture archive contains an unsafe directory"
                        )
                for file_name in sorted(file_names):
                    if file_name == ".lock":
                        continue
                    path = current / file_name
                    data, _metadata = self._read_private_regular(
                        path,
                        max_bytes=max_file_bytes,
                    )
                    self._assert_secret_safe_text(data)
                    scanned_files += 1
                    scanned_bytes += len(data)
                    if scanned_files > max_files or scanned_bytes > max_total_bytes:
                        raise RuntimeError(
                            "restored capture binding verification exceeded its bounds"
                        )
                    records = self._decode_capture_records(path, data)
                    capture_ids = {
                        str(record.get("capture_id") or "")
                        for record in (records or [])
                        if int(record.get("version", 1)) == 2
                    }
                    if require_ledger or (
                        capture_ids and capture_ids.issubset(ledger_bindings)
                    ):
                        seeds.extend(
                            self._processed_v2_binding_seeds(
                                path=path,
                                data=data,
                                member_sha256=hashlib.sha256(data).hexdigest(),
                                ledger_bindings=ledger_bindings,
                            )
                        )
        return self._capture_ledger_binding_proof(seeds)

    def _verify_capture_archive(
        self,
        archive_path: Path,
        *,
        expected_sha256: str,
        expected_manifest_sha256: str,
        ledger_ids: set[str] | None = None,
        ledger_bindings: dict[str, dict[str, Any]] | None = None,
        database_binding: dict[str, Any] | None = None,
        retain_verified_snapshot: bool = False,
    ) -> dict[str, Any]:
        try:
            archive_metadata = os.lstat(archive_path)
        except FileNotFoundError as exc:
            raise ValueError("capture archive does not exist") from exc
        if stat.S_ISLNK(archive_metadata.st_mode) or not stat.S_ISREG(
            archive_metadata.st_mode
        ):
            raise ValueError("capture archive must be a non-symlink regular file")
        staging_dir = self.store._backup_verification_staging_dir()
        staged = self.store._unique_private_temp_path(
            staging_dir,
            prefix=f".{archive_path.name}.capture-verify.",
        )
        retained = False
        try:
            copied = self.store._copy_stable_regular_file(archive_path, staged)
            if not secrets.compare_digest(str(copied["sha256"]), expected_sha256):
                raise RuntimeError("capture archive digest verification failed")
            verification = self._verify_capture_archive_snapshot(
                staged,
                expected_sha256=expected_sha256,
                expected_manifest_sha256=expected_manifest_sha256,
                ledger_ids=ledger_ids,
                ledger_bindings=ledger_bindings,
                database_binding=database_binding,
            )
            if retain_verified_snapshot:
                retained = True
                verification["verified_snapshot_path"] = str(staged)
            return verification
        finally:
            if not retained:
                staged.unlink(missing_ok=True)
            self.store._fsync_directory(staging_dir)

    def _verify_capture_archive_snapshot(
        self,
        archive_path: Path,
        *,
        expected_sha256: str,
        expected_manifest_sha256: str,
        ledger_ids: set[str] | None = None,
        ledger_bindings: dict[str, dict[str, Any]] | None = None,
        database_binding: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        digest, size_bytes, _ = self.store._hash_stable_regular_file(archive_path)
        if not secrets.compare_digest(digest, expected_sha256):
            raise RuntimeError("capture archive digest verification failed")
        max_files, max_total_bytes, max_file_bytes = self._bounded_capture_limits()
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > max_files + 1:
                raise RuntimeError("capture archive contains too many members")
            if any(not member.isfile() for member in members):
                raise ValueError("capture archive contains a non-file member")
            manifest_members = [
                member for member in members if member.name == "capture-manifest.json"
            ]
            if len(manifest_members) != 1:
                raise ValueError("capture archive manifest is missing or ambiguous")
            manifest_member = manifest_members[0]
            if manifest_member.size > max_file_bytes:
                raise ValueError("capture archive manifest exceeds its size limit")
            extracted_manifest = archive.extractfile(manifest_member)
            if extracted_manifest is None:
                raise ValueError("capture archive manifest cannot be read")
            manifest_raw = extracted_manifest.read(max_file_bytes + 1)
            try:
                manifest = json.loads(manifest_raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("capture archive manifest is invalid") from exc
            if (
                not isinstance(manifest, dict)
                or manifest.get("schema") != CAPTURE_ARCHIVE_MANIFEST_SCHEMA
                or set(manifest)
                != {
                    "schema",
                    "file_count",
                    "total_bytes",
                    "database_binding",
                    "reconciliation",
                    "files",
                    "manifest_sha256",
                }
            ):
                raise ValueError("capture archive manifest schema is unsupported")
            manifest_seed = {
                key: value for key, value in manifest.items() if key != "manifest_sha256"
            }
            calculated_manifest_digest = hashlib.sha256(
                _json_dumps(manifest_seed).encode("utf-8")
            ).hexdigest()
            if (
                not secrets.compare_digest(
                    str(manifest.get("manifest_sha256") or ""),
                    calculated_manifest_digest,
                )
                or not secrets.compare_digest(
                    calculated_manifest_digest,
                    expected_manifest_sha256,
                )
            ):
                raise RuntimeError("capture archive manifest digest verification failed")
            records = manifest.get("files")
            if not isinstance(records, list):
                raise ValueError("capture archive file inventory is invalid")
            binding = manifest.get("database_binding")
            legacy_binding_keys = {
                "artifact_sha256",
                "receipt_digest",
                "auth_key_id",
                "schema_contract_version",
                "snapshot_revision",
                "capture_operation_count",
                "capture_operation_highwater_micros",
                "capture_root_provenance",
                "capture_root_identity_digest",
            }
            current_binding_keys = legacy_binding_keys | {
                "logical_snapshot_schema",
                "logical_snapshot_sha256",
            }
            if (
                not isinstance(binding, dict)
                or set(binding) not in (legacy_binding_keys, current_binding_keys)
            ):
                raise ValueError("capture archive database binding is invalid")
            if database_binding is not None and binding != database_binding:
                raise RuntimeError("capture archive database binding mismatch")
            if (
                not BACKUP_DIGEST_RE.fullmatch(str(binding["artifact_sha256"]))
                or not BACKUP_DIGEST_RE.fullmatch(str(binding["receipt_digest"]))
                or (
                    set(binding) == current_binding_keys
                    and (
                        binding["logical_snapshot_schema"]
                        != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
                        or not BACKUP_DIGEST_RE.fullmatch(
                            str(binding["logical_snapshot_sha256"])
                        )
                    )
                )
                or not BACKUP_DIGEST_RE.fullmatch(str(binding["auth_key_id"]))
                or not BACKUP_DIGEST_RE.fullmatch(
                    str(binding["capture_root_identity_digest"])
                )
                or binding["capture_root_provenance"]
                not in {"canonical-store-parent", "explicit-noncanonical"}
                or type(binding["capture_operation_count"]) is not int
                or int(binding["capture_operation_count"]) < 0
                or type(binding["capture_operation_highwater_micros"]) is not int
                or int(binding["capture_operation_highwater_micros"]) < 0
            ):
                raise ValueError("capture archive database binding values are invalid")
            expected_members: dict[str, dict[str, Any]] = {}
            relative_paths: set[str] = set()
            allowed_prefix_to_key = {
                "capture_inbox": "inbox_dir",
                "capture_processing": "processing_dir",
                "capture_processed": "processed_dir",
                "capture_errors": "error_dir",
                "capture_error_archive": "error_archive_dir",
                "capture_error_resolutions": "error_resolution_dir",
                "capture_receipts": "receipt_dir",
                "capture_daemon_state.json": "state_path",
            }
            for record in records:
                if (
                    not isinstance(record, dict)
                    or set(record)
                    != {
                        "relative_path",
                        "category",
                        "capture_ids",
                        "replay_disposition",
                        "size_bytes",
                        "sha256",
                        "mode",
                    }
                ):
                    raise ValueError("capture archive file record is invalid")
                relative = str(record.get("relative_path") or "")
                parts = Path(relative).parts
                if (
                    not relative
                    or relative.startswith("/")
                    or ".." in parts
                    or not parts
                    or parts[0] not in allowed_prefix_to_key
                    or (
                        parts[0] == "capture_daemon_state.json" and len(parts) != 1
                    )
                    or relative in relative_paths
                ):
                    raise ValueError("capture archive file path is unsafe")
                relative_paths.add(relative)
                capture_ids = record.get("capture_ids")
                if (
                    not isinstance(capture_ids, list)
                    or len(capture_ids) != len(set(capture_ids))
                    or any(
                        not isinstance(capture_id, str)
                        or CAPTURE_ID_RE.fullmatch(capture_id) is None
                        for capture_id in capture_ids
                    )
                    or type(record.get("size_bytes")) is not int
                    or int(record["size_bytes"]) < 0
                    or type(record.get("mode")) is not int
                    or int(record["mode"]) & 0o077
                    or BACKUP_DIGEST_RE.fullmatch(str(record.get("sha256") or ""))
                    is None
                ):
                    raise ValueError("capture archive file record values are invalid")
                expected_members["capture/" + relative] = record
            actual_member_names = [
                member.name for member in members if member.name != "capture-manifest.json"
            ]
            if (
                len(actual_member_names) != len(set(actual_member_names))
                or set(actual_member_names) != set(expected_members)
            ):
                raise RuntimeError("capture archive members do not match the manifest")
            total_bytes = 0
            effective_ledger_ids = set(
                ledger_bindings if ledger_bindings is not None else ledger_ids or ()
            )
            binding_seeds: list[dict[str, Any]] = []
            payload_locations: dict[str, str] = {}
            receipt_locations: dict[str, str] = {}
            for member in members:
                if member.name == "capture-manifest.json":
                    continue
                record = expected_members[member.name]
                if member.size != int(record.get("size_bytes") or -1):
                    raise RuntimeError("capture archive member size mismatch")
                if member.size > max_file_bytes:
                    raise ValueError("capture archive member exceeds its size limit")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError("capture archive member cannot be read")
                data = extracted.read(max_file_bytes + 1)
                self._assert_secret_safe_text(data)
                if hashlib.sha256(data).hexdigest() != str(record.get("sha256") or ""):
                    raise RuntimeError("capture archive member digest mismatch")
                relative = str(record["relative_path"])
                directory_key = allowed_prefix_to_key[Path(relative).parts[0]]
                classification = self._classify_capture_record(
                    directory_key=directory_key,
                    path=Path(relative),
                    data=data,
                    ledger_ids=effective_ledger_ids,
                )
                if ledger_bindings is not None and (
                    directory_key == "processed_dir"
                    or (
                        directory_key == "processing_dir"
                        and classification.get("replay_disposition")
                        == "dedupe-on-replay"
                    )
                ):
                    binding_seeds.extend(
                        self._processed_v2_binding_seeds(
                            path=Path(relative),
                            data=data,
                            member_sha256=str(record["sha256"]),
                            ledger_bindings=ledger_bindings,
                        )
                    )
                if any(
                    record[key] != classification[key]
                    for key in ("category", "capture_ids", "replay_disposition")
                ):
                    raise RuntimeError("capture archive classification mismatch")
                prefix = Path(relative).parts[0]
                registry = (
                    receipt_locations
                    if prefix == "capture_receipts"
                    else payload_locations
                    if prefix
                    in {"capture_inbox", "capture_processing", "capture_processed"}
                    else None
                )
                if registry is not None:
                    for capture_id in classification["capture_ids"]:
                        if capture_id in registry:
                            raise RuntimeError(
                                "capture archive contains duplicate cross-file capture IDs"
                            )
                        registry[capture_id] = relative
                total_bytes += len(data)
                if total_bytes > max_total_bytes:
                    raise RuntimeError("capture archive expands beyond its bound")
            if type(manifest.get("file_count")) is not int or len(records) != int(
                manifest["file_count"]
            ):
                raise RuntimeError("capture archive file count mismatch")
            if type(manifest.get("total_bytes")) is not int or total_bytes != int(
                manifest["total_bytes"]
            ):
                raise RuntimeError("capture archive total size mismatch")
            reconciliation = manifest.get("reconciliation")
            replay_required_ids = {
                capture_id
                for record in records
                if record["replay_disposition"]
                in {"replay-required", "mixed-replay-required"}
                for capture_id in record["capture_ids"]
                if capture_id not in effective_ledger_ids
            }
            expected_reconciliation = {
                "ledger_capture_count": len(effective_ledger_ids),
                "ledger_backed_file_count": sum(
                    record["replay_disposition"]
                    in {"ledger-backed", "dedupe-on-replay"}
                    for record in records
                ),
                "replay_required_capture_count": len(replay_required_ids),
                "replay_required_file_count": sum(
                    record["replay_disposition"]
                    in {"replay-required", "mixed-replay-required"}
                    for record in records
                ),
                "identifierless_replay_file_count": sum(
                    record["replay_disposition"]
                    in {"replay-required", "mixed-replay-required"}
                    and not record["capture_ids"]
                    for record in records
                ),
                "legacy_snapshot_file_count": sum(
                    record["replay_disposition"] == "legacy-snapshot-bound"
                    for record in records
                ),
                "governance_evidence_file_count": sum(
                    record["replay_disposition"] == "governance-evidence"
                    for record in records
                ),
                "unclassified_file_count": 0,
                "missing_authoritative_ledger_count": 0,
            }
            if reconciliation != expected_reconciliation:
                raise RuntimeError("capture archive reconciliation receipt mismatch")
            binding_proof = (
                self._capture_ledger_binding_proof(binding_seeds)
                if ledger_bindings is not None
                else {
                    "schema": CAPTURE_LEDGER_BINDING_PROOF_SCHEMA,
                    "verified_capture_count": 0,
                    "revision": "",
                    "verified": False,
                }
            )
        return {
            "sha256": digest,
            "size_bytes": size_bytes,
            "manifest_sha256": calculated_manifest_digest,
            "file_count": len(records),
            "total_bytes": total_bytes,
            "manifest": manifest,
            "capture_ledger_binding": binding_proof,
            "verified": True,
        }

    @staticmethod
    def _legacy_bundle_receipt_expected_keys() -> set[str]:
        return {
            "schema",
            "database_artifact_name",
            "database_receipt_name",
            "database_sha256",
            "database_size_bytes",
            "database_snapshot_revision",
            "database_receipt_digest",
            "database_auth_key_id",
            "database_schema_contract_version",
            "capture_operation_count",
            "capture_operation_highwater_micros",
            "capture_root_provenance",
            "capture_root_identity_digest",
            "capture_artifact_name",
            "capture_sha256",
            "capture_size_bytes",
            "capture_manifest_sha256",
            "capture_file_count",
            "capture_total_bytes",
            "capture_protocol_version",
            "purpose",
            "pinned",
            "created_at",
            "auth_algorithm",
            "auth_key_id",
            "signing_public_key",
            "receipt_digest",
            "receipt_signature",
        }

    @classmethod
    def _bundle_receipt_expected_keys(cls) -> set[str]:
        return cls._legacy_bundle_receipt_expected_keys() | {
            "governance_mode",
            "store_identity",
            "store_generation",
            "database_logical_snapshot_schema",
            "database_logical_snapshot_sha256",
            "database_logical_snapshot_table_count",
            "database_logical_snapshot_column_count",
            "database_logical_snapshot_row_count",
            "database_logical_snapshot_value_bytes",
            "runtime_state_required",
            "runtime_state_artifact_name",
            "runtime_state_sha256",
            "runtime_state_size_bytes",
            "runtime_state_binding_schema",
            "runtime_state_schema_version",
            "runtime_state_canonical_sha256",
            "runtime_state_global_enabled",
            "runtime_state_context_override_count",
            "runtime_state_cortex_session_count",
            "request_journal_required",
            "request_journal_artifact_name",
            "request_journal_binding_receipt_name",
            "request_journal_sha256",
            "request_journal_size_bytes",
            "request_journal_binding_receipt_digest",
            "request_journal_schema_version",
            "request_journal_schema_identity",
            "request_journal_schema_sha256",
            "request_journal_logical_snapshot_schema",
            "request_journal_logical_snapshot_sha256",
            "request_journal_logical_snapshot_table_count",
            "request_journal_logical_snapshot_column_count",
            "request_journal_logical_snapshot_row_count",
            "request_journal_logical_snapshot_value_bytes",
            "request_journal_row_count",
            "request_journal_current_authority_epoch_row_count",
            "request_journal_maximum_observed_authority_epoch",
            "request_journal_id",
            "authority_epoch_number",
        }

    @staticmethod
    def _media_receipt_expected_keys() -> set[str]:
        return {
            "media_included",
            "media_schema",
            "media_artifact_name",
            "media_sha256",
            "media_size_bytes",
            "media_manifest_sha256",
            "media_object_count",
            "media_file_count",
            "media_total_bytes",
            "media_referenced_count",
            "media_orphan_count",
        }

    def _read_bundle_receipt(self, path: Path) -> tuple[dict[str, Any], bool]:
        data, metadata = self._read_private_regular(path, max_bytes=1024 * 1024)
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise PermissionError("recovery bundle receipt must be private")
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("recovery bundle receipt is invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("recovery bundle receipt contract is unsupported")
        schema_name = payload.get("schema")
        expected_keys = (
            self._bundle_receipt_expected_keys()
            | self._media_receipt_expected_keys()
            if schema_name == RECOVERY_BUNDLE_SCHEMA
            else self._bundle_receipt_expected_keys()
            if schema_name == PRIOR_RECOVERY_BUNDLE_SCHEMA
            else self._legacy_bundle_receipt_expected_keys()
            if schema_name == LEGACY_RECOVERY_BUNDLE_SCHEMA
            else set()
        )
        if not expected_keys or set(payload) != expected_keys:
            raise ValueError("recovery bundle receipt contract is unsupported")
        if schema_name == RECOVERY_BUNDLE_SCHEMA:
            if payload.get("media_included") is True:
                if (
                    payload.get("media_schema") != MEDIA_ARCHIVE_MANIFEST_SCHEMA
                    or not isinstance(payload.get("media_artifact_name"), str)
                    or BACKUP_DIGEST_RE.fullmatch(
                        str(payload.get("media_sha256") or "")
                    )
                    is None
                    or BACKUP_DIGEST_RE.fullmatch(
                        str(payload.get("media_manifest_sha256") or "")
                    )
                    is None
                    or type(payload.get("media_size_bytes")) is not int
                    or int(payload["media_size_bytes"]) <= 0
                    or any(
                        type(payload.get(field)) is not int or int(payload[field]) < 0
                        for field in (
                            "media_object_count",
                            "media_file_count",
                            "media_total_bytes",
                            "media_referenced_count",
                            "media_orphan_count",
                        )
                    )
                    or int(payload["media_object_count"])
                    != int(payload["media_referenced_count"])
                    or int(payload["media_object_count"]) > MAX_MEDIA_OBJECTS
                    or int(payload["media_file_count"]) > MAX_MEDIA_ARCHIVE_FILES
                    or int(payload["media_total_bytes"])
                    > MAX_MEDIA_ARCHIVE_TOTAL_BYTES
                ):
                    raise ValueError("recovery bundle media binding is invalid")
            elif payload.get("media_included") is False:
                # Media-absent form for zero-reference snapshots: every media
                # binding is an explicit null and every count an explicit
                # zero, except the orphan reconciliation count which reports
                # unreferenced cache objects that were deliberately excluded.
                if (
                    any(
                        payload.get(field) is not None
                        for field in (
                            "media_schema",
                            "media_artifact_name",
                            "media_sha256",
                            "media_size_bytes",
                            "media_manifest_sha256",
                        )
                    )
                    or any(
                        type(payload.get(field)) is not int
                        or int(payload[field]) != 0
                        for field in (
                            "media_object_count",
                            "media_file_count",
                            "media_total_bytes",
                            "media_referenced_count",
                        )
                    )
                    or type(payload.get("media_orphan_count")) is not int
                    or int(payload["media_orphan_count"]) < 0
                    or int(payload["media_orphan_count"]) > MAX_MEDIA_OBJECTS
                ):
                    raise ValueError("recovery bundle media binding is invalid")
            else:
                raise ValueError("recovery bundle media binding is invalid")
        digest_fields = (
            "database_sha256",
            "database_snapshot_revision",
            "database_receipt_digest",
            "database_auth_key_id",
            "capture_sha256",
            "capture_manifest_sha256",
            "capture_root_identity_digest",
        )
        if any(
            BACKUP_DIGEST_RE.fullmatch(str(payload.get(field) or "")) is None
            for field in digest_fields
        ):
            raise ValueError("recovery bundle receipt digest field is invalid")
        positive_fields = (
            "database_size_bytes",
            "capture_size_bytes",
        )
        nonnegative_fields = (
            "capture_file_count",
            "capture_total_bytes",
            "capture_operation_count",
            "capture_operation_highwater_micros",
        )
        if (
            any(
                type(payload.get(field)) is not int or int(payload[field]) <= 0
                for field in positive_fields
            )
            or any(
                type(payload.get(field)) is not int or int(payload[field]) < 0
                for field in nonnegative_fields
            )
            or type(payload.get("pinned")) is not bool
            or payload.get("capture_protocol_version") != "capture.v2"
            or not isinstance(payload.get("purpose"), str)
            or not isinstance(payload.get("database_schema_contract_version"), str)
            or payload.get("capture_root_provenance")
            not in {"canonical-store-parent", "explicit-noncanonical"}
            or not isinstance(payload.get("created_at"), (int, float))
            or not math.isfinite(float(payload["created_at"]))
        ):
            raise ValueError("recovery bundle receipt field types are invalid")
        if schema_name in (RECOVERY_BUNDLE_SCHEMA, PRIOR_RECOVERY_BUNDLE_SCHEMA):
            governance_mode = payload.get("governance_mode")
            journal_required = payload.get("request_journal_required")
            if (
                governance_mode not in {"pre-governed-v5", "authoritative-v6"}
                or type(journal_required) is not bool
                or not isinstance(payload.get("store_identity"), str)
                or re.fullmatch(r"store-[0-9a-f]{24}", str(payload["store_identity"]))
                is None
                or not isinstance(payload.get("store_generation"), str)
                or payload.get("database_logical_snapshot_schema")
                != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
                or BACKUP_DIGEST_RE.fullmatch(
                    str(payload.get("database_logical_snapshot_sha256") or "")
                )
                is None
                or any(
                    type(payload.get(field)) is not int
                    or int(payload[field]) < 0
                    for field in (
                        "database_logical_snapshot_table_count",
                        "database_logical_snapshot_column_count",
                        "database_logical_snapshot_row_count",
                        "database_logical_snapshot_value_bytes",
                    )
                )
            ):
                raise ValueError("recovery bundle governance binding is invalid")
            journal_fields = (
                "request_journal_artifact_name",
                "request_journal_binding_receipt_name",
                "request_journal_sha256",
                "request_journal_size_bytes",
                "request_journal_binding_receipt_digest",
                "request_journal_schema_version",
                "request_journal_schema_identity",
                "request_journal_schema_sha256",
                "request_journal_logical_snapshot_schema",
                "request_journal_logical_snapshot_sha256",
                "request_journal_logical_snapshot_table_count",
                "request_journal_logical_snapshot_column_count",
                "request_journal_logical_snapshot_row_count",
                "request_journal_logical_snapshot_value_bytes",
                "request_journal_row_count",
                "request_journal_current_authority_epoch_row_count",
                "request_journal_maximum_observed_authority_epoch",
                "request_journal_id",
                "authority_epoch_number",
            )
            runtime_fields = (
                "runtime_state_artifact_name",
                "runtime_state_sha256",
                "runtime_state_size_bytes",
                "runtime_state_binding_schema",
                "runtime_state_schema_version",
                "runtime_state_canonical_sha256",
                "runtime_state_global_enabled",
                "runtime_state_context_override_count",
                "runtime_state_cortex_session_count",
            )
            runtime_required = payload.get("runtime_state_required")
            if type(runtime_required) is not bool:
                raise ValueError("recovery bundle runtime-state binding is invalid")
            if runtime_required:
                if (
                    not isinstance(payload.get("runtime_state_artifact_name"), str)
                    or BACKUP_DIGEST_RE.fullmatch(
                        str(payload.get("runtime_state_sha256") or "")
                    )
                    is None
                    or BACKUP_DIGEST_RE.fullmatch(
                        str(payload.get("runtime_state_canonical_sha256") or "")
                    )
                    is None
                    or payload.get("runtime_state_binding_schema")
                    != RUNTIME_STATE_BINDING_SCHEMA
                    or payload.get("runtime_state_schema_version") not in {2, 3}
                    or type(payload.get("runtime_state_global_enabled")) is not bool
                    or any(
                        type(payload.get(field)) is not int
                        or int(payload[field])
                        < (1 if field == "runtime_state_size_bytes" else 0)
                        for field in (
                            "runtime_state_size_bytes",
                            "runtime_state_context_override_count",
                            "runtime_state_cortex_session_count",
                        )
                    )
                ):
                    raise ValueError("recovery bundle runtime-state binding is invalid")
            elif any(payload.get(field) is not None for field in runtime_fields):
                raise ValueError("absent runtime state must use a null binding")
            if governance_mode == "pre-governed-v5":
                if (
                    journal_required
                    or payload.get("store_generation") != "legacy-v5"
                    or any(payload.get(field) is not None for field in journal_fields)
                ):
                    raise ValueError(
                        "pre-governed recovery must not claim request-journal evidence"
                    )
            else:
                digest_fields = (
                    "request_journal_sha256",
                    "request_journal_binding_receipt_digest",
                    "request_journal_schema_sha256",
                    "request_journal_logical_snapshot_sha256",
                )
                integer_fields = (
                    "request_journal_size_bytes",
                    "request_journal_schema_version",
                    "request_journal_logical_snapshot_table_count",
                    "request_journal_logical_snapshot_column_count",
                    "request_journal_logical_snapshot_row_count",
                    "request_journal_logical_snapshot_value_bytes",
                    "request_journal_row_count",
                    "request_journal_current_authority_epoch_row_count",
                    "request_journal_maximum_observed_authority_epoch",
                    "authority_epoch_number",
                )
                if (
                    not journal_required
                    or runtime_required is not True
                    or re.fullmatch(
                        r"epoch-[1-9][0-9]*", str(payload.get("store_generation") or "")
                    )
                    is None
                    or any(
                        BACKUP_DIGEST_RE.fullmatch(str(payload.get(field) or ""))
                        is None
                        for field in digest_fields
                    )
                    or any(
                        type(payload.get(field)) is not int
                        or int(payload[field]) < (1 if field in {"request_journal_size_bytes", "request_journal_schema_version", "authority_epoch_number"} else 0)
                        for field in integer_fields
                    )
                    or any(
                        not isinstance(payload.get(field), str)
                        for field in (
                            "request_journal_artifact_name",
                            "request_journal_binding_receipt_name",
                        )
                    )
                    or payload.get("request_journal_logical_snapshot_schema")
                    != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
                    or payload.get("request_journal_schema_identity")
                    != JOURNAL_SCHEMA_IDENTITY
                    or REQUEST_JOURNAL_ID_RE.fullmatch(
                        str(payload.get("request_journal_id") or "")
                    )
                    is None
                ):
                    raise ValueError(
                        "authoritative recovery request-journal binding is invalid"
                    )
        digest = str(payload.get("receipt_digest") or "").lower()
        if (
            not BACKUP_DIGEST_RE.fullmatch(digest)
            or not secrets.compare_digest(
                digest,
                self.store._canonical_payload_digest(payload),
            )
        ):
            raise ValueError("recovery bundle receipt digest verification failed")
        identity_trusted = self.store._verify_receipt_authenticator(payload)
        return payload, identity_trusted

    def _guarded_capture_state_locked(
        self,
        *,
        capture_lock_token: object,
        maximum_pending_files: int = 0,
    ) -> dict[str, Any]:
        """Return strict content-bound capture/ledger state under both locks."""

        if (
            type(maximum_pending_files) is not int
            or maximum_pending_files < 0
        ):
            raise ValueError("guarded recovery pending-file bound is invalid")
        with self._held_capture_maintenance_lock(capture_lock_token):
            root_provenance = self._validate_capture_source_root()
            status = self.daemon.status()
            blocking_count_fields = (
                "inbox_temp_file_count",
                "processing_empty_claim_count",
                "processing_malformed_claim_count",
                "error_file_count",
                "unresolved_error_count",
                "unsafe_error_artifact_count",
                "error_resolution_pending_count",
                "error_resolution_failed_count",
            )
            blocking_counts = {
                field: int(status.get(field) or 0)
                for field in blocking_count_fields
            }
            pending_file_count = status.get("pending_file_count")
            processing_file_count = status.get("processing_file_count")
            queued_file_count = (
                pending_file_count + processing_file_count
                if type(pending_file_count) is int
                and type(processing_file_count) is int
                else None
            )
            if (
                status.get("transport_ready") is not True
                or status.get("missing_transport_directories")
                or status.get("unsafe_transport_directories")
                or type(pending_file_count) is not int
                or type(processing_file_count) is not int
                or pending_file_count < 0
                or processing_file_count < 0
                or queued_file_count is None
                or queued_file_count > maximum_pending_files
                or any(blocking_counts.values())
            ):
                raise RuntimeError(
                    "capture transport is not quiescent for guarded recovery "
                    f"(pending_file_count={pending_file_count!r}, "
                    f"processing_file_count={processing_file_count!r}, "
                    f"maximum_pending_files={maximum_pending_files!r}, "
                    f"blocking_counts={blocking_counts!r})"
                )
            with closing(self.store._connect_read_only()) as conn:
                with self.store._transaction(conn):
                    ledger_audit = self._capture_ledger_audit_locked(
                        conn,
                        sample_limit=20,
                    )
                    ledger_bindings = self._snapshot_capture_ledger_bindings(conn)
            if ledger_audit["status"] != "ready":
                raise RuntimeError(
                    "capture ledger reconciliation is required before guarded recovery"
                )
            inventory = self._capture_inventory(
                ledger_ids=set(ledger_bindings),
                database_binding={"guarded_recovery_state": True},
                initialize_transport=False,
            )
            reconciliation = dict(inventory["reconciliation"])
            pending_state = self._canonical_pending_capture_state(inventory)
            expected_reconciliation = {
                "replay_required_capture_count": pending_state[
                    "replay_required_capture_count"
                ],
                "replay_required_file_count": pending_state[
                    "replay_required_file_count"
                ],
                "identifierless_replay_file_count": 0,
                "unclassified_file_count": 0,
                "missing_authoritative_ledger_count": 0,
            }
            actual_reconciliation = {
                field: reconciliation.get(field)
                for field in expected_reconciliation
            }
            if (
                actual_reconciliation != expected_reconciliation
                or pending_state
                != {
                    "pending_file_count": queued_file_count,
                    "replay_required_file_count": reconciliation.get(
                        "replay_required_file_count"
                    ),
                    "replay_required_capture_count": reconciliation.get(
                        "replay_required_capture_count"
                    ),
                    "receipt_backed_file_count": pending_state.get(
                        "receipt_backed_file_count"
                    ),
                    "canonical_v2": True,
                }
            ):
                raise RuntimeError(
                    "capture transport has unsupported replay work during guarded "
                    "recovery"
                )
            transport_revision = self._exact_json_digest(
                {
                    "capture_root": root_provenance,
                    "files": inventory["files"],
                    "reconciliation": reconciliation,
                    "ledger_audit_revision": ledger_audit["audit_revision"],
                }
            )
            return {
                "capture_root_provenance": str(
                    root_provenance["capture_root_provenance"]
                ),
                "capture_root_identity_digest": str(
                    root_provenance["capture_root_identity_digest"]
                ),
                "transport_revision": transport_revision,
                "transport_ready": True,
                "pending_file_count": queued_file_count,
                "inbox_file_count": pending_file_count,
                "processing_file_count": processing_file_count,
                "replay_required_file_count": int(
                    pending_state["replay_required_file_count"]
                ),
                "replay_required_capture_count": int(
                    pending_state["replay_required_capture_count"]
                ),
                "receipt_backed_file_count": int(
                    pending_state["receipt_backed_file_count"]
                ),
                "unresolved_error_count": 0,
                "unsafe_error_artifact_count": 0,
                "error_resolution_pending_count": 0,
                "capture_file_count": int(inventory["file_count"]),
                "capture_total_bytes": int(inventory["total_bytes"]),
                "ledger_capture_count": len(ledger_bindings),
                "ledger_audit_revision": str(ledger_audit["audit_revision"]),
                "ledger_verification_passed": bool(
                    ledger_audit["verification_passed"]
                ),
                "ledger_audit": self._public_capture_ledger_audit(ledger_audit),
                "reconciliation": reconciliation,
                "verified": True,
                "checked_at": time.time(),
            }

    def _assert_guarded_recovery_authority(self) -> None:
        """Require one active, unclaimed exclusive core lease for certification.

        Guarded recovery is an offline certification lane.  A shared local
        lease cannot fence sibling writers, while a claimed live-v6 lease may
        still serve mutations in the same process.  The narrow maintenance
        opener supplies the only accepted authority shape: an active core
        lease bound to this exact database but not yet durably claimed.
        """

        lease = getattr(self.store, "_authority_lease", None)
        if lease is None:
            raise RuntimeError(
                "guarded recovery requires an explicit exclusive core authority lease"
            )
        lease.assert_core_for(self.store.db_path)
        if lease.durable_epoch is not None:
            raise RuntimeError(
                "guarded recovery requires an offline unclaimed core authority lease"
            )
        if getattr(self.store, "_owns_authority_lease", True):
            raise RuntimeError(
                "guarded recovery requires a caller-owned core authority lease"
            )

    @staticmethod
    def _require_zero_replay_debt(
        payload: dict[str, Any],
        *,
        stage: str,
    ) -> None:
        VerifiedRecoveryManager._require_expected_replay_debt(
            payload,
            stage=stage,
            expected_pending_file_count=0,
        )

    @staticmethod
    def _require_expected_replay_debt(
        payload: dict[str, Any],
        *,
        stage: str,
        expected_pending_file_count: int,
    ) -> None:
        if (
            type(expected_pending_file_count) is not int
            or expected_pending_file_count < 0
        ):
            raise ValueError("expected guarded-recovery replay debt is invalid")
        reconciliation = payload.get("reconciliation")
        if not isinstance(reconciliation, dict):
            raise RuntimeError(f"{stage} recovery evidence lost reconciliation")
        observed = {
            field: reconciliation.get(field)
            for field in (
                "replay_required_capture_count",
                "replay_required_file_count",
                "identifierless_replay_file_count",
                "unclassified_file_count",
                "missing_authoritative_ledger_count",
            )
        }
        expected = {
            "replay_required_capture_count": expected_pending_file_count,
            "replay_required_file_count": expected_pending_file_count,
            "identifierless_replay_file_count": 0,
            "unclassified_file_count": 0,
            "missing_authoritative_ledger_count": 0,
        }
        if observed != expected:
            raise RuntimeError(
                f"{stage} recovery evidence has unexpected replay debt "
                f"(observed={observed!r}, expected={expected!r})"
            )

    def _guarded_recovery_postflight_locked(
        self,
        *,
        capture_lock_token: object,
        before: dict[str, Any],
        verification: dict[str, Any],
        maximum_pending_files: int = 0,
        expected_pending_file_count: int = 0,
        expected_replay_required_file_count: int = 0,
    ) -> dict[str, Any]:
        """Prove live memory, journal, runtime, capture, and ledger did not drift."""

        with self._held_capture_maintenance_lock(capture_lock_token):
            if verification.get("verified") is not True:
                raise RuntimeError("guarded recovery bundle verification is incomplete")
            expected_cutover_ready = expected_pending_file_count == 0
            expected_pending_state = {
                "pending_file_count": expected_pending_file_count,
                "replay_required_file_count": (
                    expected_replay_required_file_count
                ),
                "replay_required_capture_count": (
                    expected_replay_required_file_count
                ),
                "receipt_backed_file_count": 0,
                "canonical_v2": True,
            }
            if (
                verification.get("cutover_ready") is not expected_cutover_ready
                or verification.get("capture_pending_state")
                != expected_pending_state
            ):
                raise RuntimeError(
                    "guarded recovery bundle readiness does not match its "
                    "admitted capture state"
                )
            self._require_expected_replay_debt(
                verification,
                stage="verified bundle",
                expected_pending_file_count=(
                    expected_replay_required_file_count
                ),
            )
            self._assert_memory_snapshot_fence(
                expected_logical_snapshot_sha256=str(
                    verification["database"]["logical_snapshot_sha256"]
                ),
                expected_store_generation=str(verification["store_generation"]),
            )
            request_journal = verification.get("request_journal")
            if verification["governance_mode"] == "authoritative-v6":
                if not isinstance(request_journal, dict):
                    raise RuntimeError(
                        "guarded authoritative recovery lost request-journal evidence"
                    )
                live_journal = self.recompute_request_journal_logical_digest(
                    maximum_authority_epoch=int(
                        verification["database"]["authority_epoch_number"]
                    )
                )
                if (
                    not secrets.compare_digest(
                        str(live_journal["logical_snapshot_sha256"]),
                        str(request_journal["logical_snapshot_sha256"]),
                    )
                    or str(live_journal["journal_id"])
                    != str(request_journal["journal_id"])
                    or str(live_journal["store_identity"])
                    != str(verification["store_identity"])
                ):
                    raise RuntimeError(
                        "request journal changed during guarded recovery"
                    )
            runtime_state = verification.get("runtime_state")
            live_runtime = self.recompute_live_runtime_state_binding(
                required=verification["governance_mode"] == "authoritative-v6"
            )
            if runtime_state is None:
                if live_runtime.get("present") is True:
                    raise RuntimeError(
                        "runtime-state presence changed during guarded recovery"
                    )
            elif (
                live_runtime.get("present") is not True
                or not secrets.compare_digest(
                    str(live_runtime["artifact_sha256"]),
                    str(runtime_state["sha256"]),
                )
                or not secrets.compare_digest(
                    str(live_runtime["canonical_sha256"]),
                    str(runtime_state["canonical_sha256"]),
                )
            ):
                raise RuntimeError("runtime state changed during guarded recovery")

            after = self._guarded_capture_state_locked(
                capture_lock_token=capture_lock_token,
                maximum_pending_files=maximum_pending_files,
            )
            if (
                after.get("pending_file_count") != expected_pending_file_count
                or after.get("replay_required_file_count")
                != expected_replay_required_file_count
                or not secrets.compare_digest(
                    str(after["transport_revision"]),
                    str(before["transport_revision"]),
                )
                or not secrets.compare_digest(
                    str(after["ledger_audit_revision"]),
                    str(before["ledger_audit_revision"]),
                )
            ):
                raise RuntimeError(
                    "capture transport or ledger changed during guarded recovery"
                )
            with closing(self.store._connect_read_only()) as conn:
                with self.store._transaction(conn):
                    ledger_bindings = self._snapshot_capture_ledger_bindings(conn)
            live_manifest = self._capture_inventory(
                ledger_ids=set(ledger_bindings),
                database_binding=dict(verification["capture_database_binding"]),
                initialize_transport=False,
            )
            if not secrets.compare_digest(
                str(live_manifest["manifest_sha256"]),
                str(verification["capture_manifest_sha256"]),
            ):
                raise RuntimeError(
                    "live capture state does not match the verified recovery bundle"
                )
            return after

    @contextmanager
    def guarded_recovery_transaction(
        self,
        output_root: str | os.PathLike[str],
        *,
        path: str | os.PathLike[str] | None = None,
        purpose: str = "operator-certification",
        pinned: bool = True,
        replacement_pending_limit: int = 0,
    ) -> Iterator[GuardedRecoveryPublication]:
        """Create, verify, restore, and publish evidence under one lock scope.

        The yielded publication gate runs one final postflight before invoking
        its callback. Repository and global capture-maintenance locks remain
        held through that callback, and no fallible validation runs after it.
        Entry and prepublication both enforce a caller-owned, unclaimed,
        exclusive :class:`CoreAuthorityLease` for the exact memory store.
        """

        if (
            type(replacement_pending_limit) is not int
            or replacement_pending_limit < 0
        ):
            raise ValueError("replacement pending-file limit is invalid")
        if replacement_pending_limit and purpose != "replacement-admission":
            raise ValueError(
                "pending capture work is supported only for replacement admission"
            )
        self._assert_guarded_recovery_authority()
        with self._repository_lock():
            paths = self.daemon.paths()
            missing, unsafe = self.daemon._observe_transport_dirs(paths)
            if missing or unsafe:
                raise RuntimeError(
                    "guarded recovery requires an existing safe capture transport "
                    f"(missing={missing!r}, unsafe={unsafe!r})"
                )
            root_provenance = self._validate_capture_source_root()
            with self._capture_maintenance_lock(
                existing_only=True,
            ) as capture_lock_token:
                before = self._guarded_capture_state_locked(
                    capture_lock_token=capture_lock_token,
                    maximum_pending_files=replacement_pending_limit,
                )
                admitted_pending_file_count = int(before["pending_file_count"])
                admitted_replay_required_file_count = int(
                    before["replay_required_file_count"]
                )
                if (
                    replacement_pending_limit
                    and admitted_pending_file_count != replacement_pending_limit
                ):
                    raise RuntimeError(
                        "replacement pending capture count changed before guarded "
                        "recovery"
                    )
                bundle = self._create_bundle_capture_locked(
                    path,
                    purpose=purpose,
                    pinned=pinned,
                    paths=paths,
                    root_provenance=root_provenance,
                    capture_lock_token=capture_lock_token,
                )
                bundle_receipt, _identity_trusted = self._read_bundle_receipt(
                    Path(str(bundle["bundle_receipt_path"]))
                )
                expected_journal_sha256 = (
                    str(bundle_receipt["request_journal_sha256"])
                    if bundle_receipt.get("request_journal_sha256")
                    else None
                )
                expected_runtime_sha256 = (
                    str(bundle_receipt["runtime_state_sha256"])
                    if bundle_receipt.get("runtime_state_sha256")
                    else None
                )
                verification = self._verify_bundle_locked(
                    bundle["bundle_receipt_path"],
                    expected_database_sha256=str(bundle["sha256"]),
                    expected_capture_sha256=str(bundle["capture_archive_sha256"]),
                    expected_request_journal_sha256=expected_journal_sha256,
                    expected_runtime_state_sha256=expected_runtime_sha256,
                )
                restore = self._restore_bundle_isolated_locked(
                    bundle["bundle_receipt_path"],
                    output_root,
                    expected_database_sha256=str(bundle["sha256"]),
                    expected_capture_sha256=str(bundle["capture_archive_sha256"]),
                    expected_request_journal_sha256=expected_journal_sha256,
                    expected_runtime_state_sha256=expected_runtime_sha256,
                    confirm=True,
                )
                self._require_expected_replay_debt(
                    bundle,
                    stage="created bundle",
                    expected_pending_file_count=(
                        admitted_replay_required_file_count
                    ),
                )
                self._require_expected_replay_debt(
                    restore,
                    stage="isolated restore",
                    expected_pending_file_count=(
                        admitted_replay_required_file_count
                    ),
                )
                expected_cutover_ready = admitted_pending_file_count == 0
                if (
                    restore.get("verified") is not True
                    or restore.get("cutover_ready") is not expected_cutover_ready
                    or restore.get("capture_pending_state")
                    != verification.get("capture_pending_state")
                ):
                    raise RuntimeError("guarded isolated recovery proof is incomplete")
                after = self._guarded_recovery_postflight_locked(
                    capture_lock_token=capture_lock_token,
                    before=before,
                    verification=verification,
                    maximum_pending_files=replacement_pending_limit,
                    expected_pending_file_count=admitted_pending_file_count,
                    expected_replay_required_file_count=(
                        admitted_replay_required_file_count
                    ),
                )
                evidence = {
                    "schema": GUARDED_RECOVERY_TRANSACTION_SCHEMA,
                    "action": "guarded-recovery-transaction",
                    "bundle": bundle,
                    "verification": verification,
                    "restore": restore,
                    "capture_transport_before": before,
                    "capture_transport_after": after,
                    "capture_ledger_before": dict(before["ledger_audit"]),
                    "capture_ledger_after": dict(after["ledger_audit"]),
                    "lock_scope": {
                        "repository": "held-through-context-exit",
                        "capture_maintenance": "held-through-context-exit",
                    },
                    "replay_required_capture_count": (
                        admitted_replay_required_file_count
                    ),
                    "replay_required_file_count": (
                        admitted_replay_required_file_count
                    ),
                    "pending_file_count": admitted_pending_file_count,
                    "processing_file_count": int(
                        before["processing_file_count"]
                    ),
                    "receipt_backed_file_count": int(
                        before["receipt_backed_file_count"]
                    ),
                    "cutover_ready": expected_cutover_ready,
                    "replacement_stage_ready": (
                        purpose == "replacement-admission"
                    ),
                    "verified": True,
                    "completed_at": time.time(),
                }

                def prepublish() -> dict[str, Any]:
                    self._assert_guarded_recovery_authority()
                    return self._guarded_recovery_postflight_locked(
                        capture_lock_token=capture_lock_token,
                        before=before,
                        verification=verification,
                        maximum_pending_files=replacement_pending_limit,
                        expected_pending_file_count=admitted_pending_file_count,
                        expected_replay_required_file_count=(
                            admitted_replay_required_file_count
                        ),
                    )

                publication = GuardedRecoveryPublication(
                    evidence,
                    prepublish=prepublish,
                )
                try:
                    yield publication
                finally:
                    if not publication.publication_attempted:
                        release_state = prepublish()
                        evidence["capture_transport_at_release"] = release_state
                        evidence["released_at"] = time.time()

    def create_verify_restore_guarded(
        self,
        output_root: str | os.PathLike[str],
        *,
        path: str | os.PathLike[str] | None = None,
        purpose: str = "operator-certification",
        pinned: bool = True,
    ) -> dict[str, Any]:
        """Consume :meth:`guarded_recovery_transaction` without a publish body."""

        with self.guarded_recovery_transaction(
            output_root,
            path=path,
            purpose=purpose,
            pinned=pinned,
        ) as publication:
            publication.publish(lambda _evidence: None)
            return publication.evidence

    def create_bundle(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        purpose: str = "operator",
        pinned: bool = False,
    ) -> dict[str, Any]:
        with self._repository_lock():
            return self._create_bundle_locked(path, purpose=purpose, pinned=pinned)

    def _create_bundle_locked(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        purpose: str = "operator",
        pinned: bool = False,
    ) -> dict[str, Any]:
        # Bundle creation is an explicitly mutating maintenance operation and
        # may initialize a missing local capture transport.  Read-only live
        # attestations use ``recompute_live_capture_manifest`` and never take
        # this initialization path.
        paths = self.daemon.paths()
        self.daemon._ensure_transport_dirs(paths)
        root_provenance = self._validate_capture_source_root()
        with self._capture_maintenance_lock() as capture_lock_token:
            return self._create_bundle_capture_locked(
                path,
                purpose=purpose,
                pinned=pinned,
                paths=paths,
                root_provenance=root_provenance,
                capture_lock_token=capture_lock_token,
            )

    def _create_bundle_capture_locked(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        purpose: str,
        pinned: bool,
        paths: dict[str, Path],
        root_provenance: dict[str, Any],
        capture_lock_token: object,
    ) -> dict[str, Any]:
        live_governance = self._live_store_governance()
        journal_required = (
            live_governance["governance_mode"] == "authoritative-v6"
        )
        runtime_state_present = (
            self.runtime_state_path.exists() or self.runtime_state_path.is_symlink()
        )
        database_path: Path | None = None
        database_receipt_path: Path | None = None
        capture_archive_path: Path | None = None
        media_archive_path: Path | None = None
        bundle_receipt_path: Path | None = None
        request_journal_path: Path | None = None
        request_journal_binding_receipt_path: Path | None = None
        runtime_state_artifact_path: Path | None = None
        publication_id: str | None = None
        publication_completed_path: Path | None = None
        with self._held_capture_maintenance_lock(capture_lock_token):
            locked_root_provenance = self._validate_capture_source_root()
            if locked_root_provenance != root_provenance:
                raise RuntimeError(
                    "capture source root changed before the maintenance lock was acquired"
                )
            status = self.daemon.status()
            if int(status.get("unsafe_error_artifact_count") or 0):
                raise RuntimeError("capture transport has unsafe error artifacts")
            if int(status.get("error_resolution_pending_count") or 0):
                raise RuntimeError("capture transport has an incomplete error resolution")
            with closing(self.store._connect_read_only()) as preflight_conn:
                with self.store._transaction(preflight_conn):
                    ledger_preflight = self._capture_ledger_audit_locked(
                        preflight_conn,
                        sample_limit=20,
                    )
            if ledger_preflight["status"] != "ready":
                if any(
                    "duplicate-processed-capture-id"
                    in item.get("reasons", [])
                    for item in ledger_preflight.get("finding_samples", [])
                    if isinstance(item, dict)
                ):
                    raise RuntimeError(
                        "capture transport contains duplicate cross-file capture IDs"
                    )
                raise RuntimeError(
                    "capture ledger reconciliation is required before paired backup "
                    f"(missing={ledger_preflight['missing_authoritative_ledger_count']}, "
                    f"mismatch={ledger_preflight['ledger_binding_mismatch_count']})"
                )
            try:
                bundle_database_path = path
                if bundle_database_path is None:
                    verified_root = self.store.db_path.parent / "backups" / "verified"
                    self.store._ensure_directory(verified_root, owned=True)
                    stamp = time.strftime("%Y%m%d-%H%M%S")
                    bundle_database_path = verified_root / (
                        f"{self.store.db_path.stem}-recovery-{stamp}-"
                        f"{uuid.uuid4().hex[:12]}.sqlite3"
                    )
                else:
                    reject_sensitive_identifier(
                        bundle_database_path,
                        field="recovery_bundle_path",
                    )
                database_path = Path(bundle_database_path).expanduser().absolute()
                self.store._ensure_directory(database_path.parent, owned=False)
                store_root = self.store.db_path.parent.resolve()
                resolved_parent = database_path.parent.resolve()
                try:
                    relative_directory = resolved_parent.relative_to(store_root)
                except ValueError as exc:
                    raise ValueError(
                        "recovery bundle output must stay within the memory-store root"
                    ) from exc
                parent_metadata = os.lstat(resolved_parent)
                if (
                    not stat.S_ISDIR(parent_metadata.st_mode)
                    or stat.S_ISLNK(parent_metadata.st_mode)
                    or parent_metadata.st_uid != os.getuid()
                    or stat.S_IMODE(parent_metadata.st_mode) & 0o077
                ):
                    raise PermissionError(
                        "recovery bundle output directory must be private and user-owned"
                    )
                database_path = resolved_parent / database_path.name
                database_receipt_path = self.store._backup_receipt_path(database_path)
                capture_archive_path = self._capture_archive_path(database_path)
                media_archive_path = self._media_archive_path(database_path)
                bundle_receipt_path = self._bundle_receipt_path(database_path)
                base_artifact_paths = (
                    database_path,
                    database_receipt_path,
                    capture_archive_path,
                    media_archive_path,
                )
                if journal_required or runtime_state_present:
                    runtime_state_artifact_path = self._runtime_state_artifact_path(
                        database_path
                    )
                if journal_required:
                    request_journal_path = self._request_journal_artifact_path(
                        database_path
                    )
                    request_journal_binding_receipt_path = (
                        self._request_journal_binding_receipt_path(database_path)
                    )
                    artifact_paths = (
                        *base_artifact_paths,
                        request_journal_path,
                        request_journal_binding_receipt_path,
                        *((runtime_state_artifact_path,) if runtime_state_artifact_path else ()),
                        bundle_receipt_path,
                    )
                else:
                    artifact_paths = (
                        *base_artifact_paths,
                        *((runtime_state_artifact_path,) if runtime_state_artifact_path else ()),
                        bundle_receipt_path,
                    )
                if any(candidate.exists() or candidate.is_symlink() for candidate in artifact_paths):
                    raise FileExistsError(
                        "recovery bundle artifact already exists; refusing overwrite"
                    )
                publication_id = uuid.uuid4().hex
                publication_journal_root = self._publication_journal_root()
                publication_prepared_path = publication_journal_root / (
                    f"{publication_id}.prepared.receipt.json"
                )
                publication_completed_path = publication_journal_root / (
                    f"{publication_id}.completed.receipt.json"
                )
                publication_prepared = {
                    "schema": RECOVERY_PUBLICATION_RECEIPT_SCHEMA,
                    "state": "prepared",
                    "publication_id": publication_id,
                    "output_directory": str(relative_directory),
                    "artifact_names": [candidate.name for candidate in artifact_paths],
                    "bundle_receipt_name": bundle_receipt_path.name,
                    "created_at": time.time(),
                }
                self.store._authenticate_receipt(publication_prepared)
                self.store._write_private_json_exclusive(
                    publication_prepared_path,
                    publication_prepared,
                )
                database = self.store.backup(
                    database_path,
                    purpose=purpose,
                    pinned=pinned,
                    _paired_recovery=True,
                )
                if (
                    Path(str(database["backup_path"])) != database_path
                    or Path(str(database["receipt_path"])) != database_receipt_path
                ):
                    raise RuntimeError("recovery database publication path changed")
                if (
                    str(database.get("governance_mode"))
                    != str(live_governance["governance_mode"])
                    or str(database.get("store_generation"))
                    != str(live_governance["store_generation"])
                    or database.get("authority_epoch_number")
                    != live_governance["authority_epoch_number"]
                ):
                    raise RuntimeError(
                        "memory-store governance changed during recovery publication"
                    )
                database_receipt, _ = self.store._read_trusted_backup_receipt(
                    database_receipt_path,
                    artifact=database_path,
                )
                database_uri = database_path.resolve().as_uri() + "?mode=ro&immutable=1"
                with closing(sqlite3.connect(database_uri, uri=True)) as snapshot:
                    ledger_bindings = self._snapshot_capture_ledger_bindings(
                        snapshot
                    )
                ledger_ids = set(ledger_bindings)
                capture_highwater_micros = int(
                    max(
                        (
                            float(binding["committed_at"])
                            for binding in ledger_bindings.values()
                        ),
                        default=0.0,
                    )
                    * 1_000_000
                )
                database_binding = {
                    "artifact_sha256": str(database["sha256"]),
                    "receipt_digest": str(database_receipt["receipt_digest"]),
                    "auth_key_id": str(database_receipt["auth_key_id"]),
                    "schema_contract_version": str(
                        database_receipt["schema_contract_version"]
                    ),
                    "snapshot_revision": str(database["snapshot_revision"]),
                    "logical_snapshot_schema": str(
                        database["logical_snapshot_schema"]
                    ),
                    "logical_snapshot_sha256": str(
                        database["logical_snapshot_sha256"]
                    ),
                    "capture_operation_count": len(ledger_ids),
                    "capture_operation_highwater_micros": capture_highwater_micros,
                    **root_provenance,
                }
                request_journal: dict[str, Any] | None = None
                request_journal_binding_receipt: dict[str, Any] | None = None
                runtime_state: dict[str, Any] | None = None
                if journal_required:
                    if (
                        request_journal_path is None
                        or request_journal_binding_receipt_path is None
                        or runtime_state_artifact_path is None
                        or type(live_governance["authority_epoch_number"]) is not int
                    ):
                        raise RuntimeError(
                            "governed recovery request-journal paths are unavailable"
                        )
                    request_journal = self._snapshot_request_journal(
                        request_journal_path,
                        maximum_authority_epoch=int(
                            live_governance["authority_epoch_number"]
                        ),
                    )
                    if (
                        str(request_journal["journal_id"])
                        != str(live_governance["request_journal_id"])
                        or str(request_journal["store_identity"])
                        != str(live_governance["store_identity"])
                    ):
                        raise RuntimeError(
                            "request journal does not match the durable store binding"
                        )
                    self._assert_memory_snapshot_fence(
                        expected_logical_snapshot_sha256=str(
                            database["logical_snapshot_sha256"]
                        ),
                        expected_store_generation=str(
                            live_governance["store_generation"]
                        ),
                    )
                    runtime_state = self._snapshot_runtime_state(
                        runtime_state_artifact_path
                    )
                    live_journal = self.recompute_request_journal_logical_digest(
                        maximum_authority_epoch=int(
                            live_governance["authority_epoch_number"]
                        )
                    )
                    if not secrets.compare_digest(
                        str(live_journal["logical_snapshot_sha256"]),
                        str(request_journal["logical_snapshot_sha256"]),
                    ):
                        raise RuntimeError(
                            "request journal changed while runtime state was being snapshotted"
                        )
                    request_journal_binding_receipt = {
                        "schema": RECOVERY_REQUEST_JOURNAL_BINDING_SCHEMA,
                        "journal_artifact_name": request_journal_path.name,
                        "journal_sha256": str(request_journal["sha256"]),
                        "journal_size_bytes": int(request_journal["size_bytes"]),
                        "journal_application_id": int(
                            request_journal["application_id"]
                        ),
                        "journal_schema_version": int(
                            request_journal["schema_version"]
                        ),
                        "journal_schema_identity": str(
                            request_journal["schema_identity"]
                        ),
                        "journal_schema_sha256": str(
                            request_journal["schema_sha256"]
                        ),
                        "journal_logical_snapshot_schema": str(
                            request_journal["logical_snapshot_schema"]
                        ),
                        "journal_logical_snapshot_sha256": str(
                            request_journal["logical_snapshot_sha256"]
                        ),
                        "journal_logical_snapshot_table_count": int(
                            request_journal["logical_snapshot_table_count"]
                        ),
                        "journal_logical_snapshot_column_count": int(
                            request_journal["logical_snapshot_column_count"]
                        ),
                        "journal_logical_snapshot_row_count": int(
                            request_journal["logical_snapshot_row_count"]
                        ),
                        "journal_logical_snapshot_value_bytes": int(
                            request_journal["logical_snapshot_value_bytes"]
                        ),
                        "journal_row_count": int(request_journal["row_count"]),
                        "journal_state_counts": dict(
                            request_journal["state_counts"]
                        ),
                        "journal_current_authority_epoch_row_count": int(
                            request_journal[
                                "current_authority_epoch_row_count"
                            ]
                        ),
                        "journal_maximum_observed_authority_epoch": int(
                            request_journal[
                                "maximum_observed_authority_epoch"
                            ]
                        ),
                        "request_journal_id": str(request_journal["journal_id"]),
                        "database_artifact_name": database_path.name,
                        "database_sha256": str(database["sha256"]),
                        "database_receipt_digest": str(
                            database_receipt["receipt_digest"]
                        ),
                        "database_schema_contract_version": str(
                            database_receipt["schema_contract_version"]
                        ),
                        "database_snapshot_revision": str(
                            database["snapshot_revision"]
                        ),
                        "database_logical_snapshot_schema": str(
                            database["logical_snapshot_schema"]
                        ),
                        "database_logical_snapshot_sha256": str(
                            database["logical_snapshot_sha256"]
                        ),
                        "store_identity": self._store_identity(),
                        "store_generation": str(
                            live_governance["store_generation"]
                        ),
                        "authority_epoch_number": int(
                            live_governance["authority_epoch_number"]
                        ),
                        "created_at": time.time(),
                    }
                    self.store._authenticate_receipt(
                        request_journal_binding_receipt
                    )
                    self.store._write_private_json_exclusive(
                        request_journal_binding_receipt_path,
                        request_journal_binding_receipt,
                    )
                elif runtime_state_artifact_path is not None:
                    runtime_state = self._snapshot_runtime_state(
                        runtime_state_artifact_path
                    )
                    self._assert_memory_snapshot_fence(
                        expected_logical_snapshot_sha256=str(
                            database["logical_snapshot_sha256"]
                        ),
                        expected_store_generation=str(
                            live_governance["store_generation"]
                        ),
                    )
                current_runtime_presence = (
                    self.runtime_state_path.exists()
                    or self.runtime_state_path.is_symlink()
                )
                if current_runtime_presence != runtime_state_present:
                    raise RuntimeError(
                        "runtime-state presence changed during recovery publication"
                    )
                if runtime_state is not None:
                    live_runtime = self.recompute_live_runtime_state_binding(
                        required=journal_required
                    )
                    if (
                        not bool(live_runtime["present"])
                        or not secrets.compare_digest(
                            str(live_runtime["artifact_sha256"]),
                            str(runtime_state["sha256"]),
                        )
                        or not secrets.compare_digest(
                            str(live_runtime["canonical_sha256"]),
                            str(runtime_state["canonical_sha256"]),
                        )
                    ):
                        raise RuntimeError(
                            "runtime state changed during recovery publication"
                        )
                manifest = self._capture_inventory(
                    ledger_ids=ledger_ids,
                    database_binding=database_binding,
                )
                if self._validate_capture_source_root() != root_provenance:
                    raise RuntimeError("capture source root changed during inventory")
                capture = self._write_capture_archive(capture_archive_path, manifest)
                if self._validate_capture_source_root() != root_provenance:
                    raise RuntimeError("capture source root changed during archive creation")
                with closing(sqlite3.connect(database_uri, uri=True)) as snapshot:
                    media_references = media_references_from_connection(snapshot)
                if media_archive_path is None:
                    raise RuntimeError("media archive path is unavailable")
                media_manifest = self._media_inventory(
                    referenced_media_ids=media_references["media_ids"],
                    database_binding=database_binding,
                )
                # A snapshot without image references ships no media artifact:
                # the receipt states media_included=false with explicit null
                # bindings, stays fully verified, and remains compatible with
                # baseline replication peers that advertise no media
                # capability. Any referenced image memory requires the archive.
                media_included = bool(int(media_references["reference_count"]))
                if media_included:
                    media = self._write_media_archive(
                        media_archive_path, media_manifest
                    )
                else:
                    media = None
                with closing(sqlite3.connect(database_uri, uri=True)) as snapshot:
                    snapshot.row_factory = sqlite3.Row
                    ledger_postflight = self._capture_ledger_audit_locked(
                        snapshot,
                        sample_limit=20,
                    )
                if (
                    ledger_postflight["status"] != "ready"
                    or ledger_postflight["audit_revision"]
                    != ledger_preflight["audit_revision"]
                ):
                    raise RuntimeError(
                        "capture ledger binding changed during paired backup"
                    )
                created_at = time.time()
                receipt = {
                    "schema": RECOVERY_BUNDLE_SCHEMA,
                    "database_artifact_name": database_path.name,
                    "database_receipt_name": database_receipt_path.name,
                    "database_sha256": str(database["sha256"]),
                    "database_size_bytes": int(database["size_bytes"]),
                    "database_snapshot_revision": str(database["snapshot_revision"]),
                    "database_logical_snapshot_schema": str(
                        database["logical_snapshot_schema"]
                    ),
                    "database_logical_snapshot_sha256": str(
                        database["logical_snapshot_sha256"]
                    ),
                    "database_logical_snapshot_table_count": int(
                        database["logical_snapshot_table_count"]
                    ),
                    "database_logical_snapshot_column_count": int(
                        database["logical_snapshot_column_count"]
                    ),
                    "database_logical_snapshot_row_count": int(
                        database["logical_snapshot_row_count"]
                    ),
                    "database_logical_snapshot_value_bytes": int(
                        database["logical_snapshot_value_bytes"]
                    ),
                    "database_receipt_digest": str(
                        database_receipt["receipt_digest"]
                    ),
                    "database_auth_key_id": str(database_receipt["auth_key_id"]),
                    "database_schema_contract_version": str(
                        database_receipt["schema_contract_version"]
                    ),
                    "capture_operation_count": len(ledger_ids),
                    "capture_operation_highwater_micros": capture_highwater_micros,
                    **root_provenance,
                    "capture_artifact_name": capture_archive_path.name,
                    "capture_sha256": str(capture["sha256"]),
                    "capture_size_bytes": int(capture["size_bytes"]),
                    "capture_manifest_sha256": str(manifest["manifest_sha256"]),
                    "capture_file_count": int(manifest["file_count"]),
                    "capture_total_bytes": int(manifest["total_bytes"]),
                    "capture_protocol_version": "capture.v2",
                    "media_included": media_included,
                    "media_schema": (
                        MEDIA_ARCHIVE_MANIFEST_SCHEMA if media_included else None
                    ),
                    "media_artifact_name": (
                        media_archive_path.name if media_included else None
                    ),
                    "media_sha256": (
                        str(media["sha256"]) if media is not None else None
                    ),
                    "media_size_bytes": (
                        int(media["size_bytes"]) if media is not None else None
                    ),
                    "media_manifest_sha256": (
                        str(media_manifest["manifest_sha256"])
                        if media_included
                        else None
                    ),
                    "media_object_count": int(media_manifest["object_count"]),
                    "media_file_count": int(media_manifest["file_count"]),
                    "media_total_bytes": int(media_manifest["total_bytes"]),
                    "media_referenced_count": int(
                        media_manifest["reconciliation"]["referenced_count"]
                    ),
                    "media_orphan_count": int(
                        media_manifest["reconciliation"]["orphan_count"]
                    ),
                    "governance_mode": str(live_governance["governance_mode"]),
                    "store_identity": self._store_identity(),
                    "store_generation": str(live_governance["store_generation"]),
                    "runtime_state_required": runtime_state is not None,
                    "runtime_state_artifact_name": (
                        runtime_state_artifact_path.name
                        if runtime_state_artifact_path is not None
                        else None
                    ),
                    "runtime_state_sha256": (
                        str(runtime_state["sha256"])
                        if runtime_state is not None
                        else None
                    ),
                    "runtime_state_size_bytes": (
                        int(runtime_state["size_bytes"])
                        if runtime_state is not None
                        else None
                    ),
                    "runtime_state_binding_schema": (
                        str(runtime_state["binding_schema"])
                        if runtime_state is not None
                        else None
                    ),
                    "runtime_state_schema_version": (
                        int(runtime_state["state_schema_version"])
                        if runtime_state is not None
                        else None
                    ),
                    "runtime_state_canonical_sha256": (
                        str(runtime_state["canonical_sha256"])
                        if runtime_state is not None
                        else None
                    ),
                    "runtime_state_global_enabled": (
                        bool(runtime_state["global_enabled"])
                        if runtime_state is not None
                        else None
                    ),
                    "runtime_state_context_override_count": (
                        int(runtime_state["context_override_count"])
                        if runtime_state is not None
                        else None
                    ),
                    "runtime_state_cortex_session_count": (
                        int(runtime_state["cortex_session_count"])
                        if runtime_state is not None
                        else None
                    ),
                    "request_journal_required": journal_required,
                    "request_journal_artifact_name": (
                        request_journal_path.name if request_journal_path else None
                    ),
                    "request_journal_binding_receipt_name": (
                        request_journal_binding_receipt_path.name
                        if request_journal_binding_receipt_path
                        else None
                    ),
                    "request_journal_sha256": (
                        str(request_journal["sha256"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_size_bytes": (
                        int(request_journal["size_bytes"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_binding_receipt_digest": (
                        str(request_journal_binding_receipt["receipt_digest"])
                        if request_journal_binding_receipt is not None
                        else None
                    ),
                    "request_journal_schema_version": (
                        int(request_journal["schema_version"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_schema_identity": (
                        str(request_journal["schema_identity"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_schema_sha256": (
                        str(request_journal["schema_sha256"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_logical_snapshot_schema": (
                        str(request_journal["logical_snapshot_schema"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_logical_snapshot_sha256": (
                        str(request_journal["logical_snapshot_sha256"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_logical_snapshot_table_count": (
                        int(request_journal["logical_snapshot_table_count"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_logical_snapshot_column_count": (
                        int(request_journal["logical_snapshot_column_count"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_logical_snapshot_row_count": (
                        int(request_journal["logical_snapshot_row_count"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_logical_snapshot_value_bytes": (
                        int(request_journal["logical_snapshot_value_bytes"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_row_count": (
                        int(request_journal["row_count"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_current_authority_epoch_row_count": (
                        int(request_journal["current_authority_epoch_row_count"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_maximum_observed_authority_epoch": (
                        int(request_journal["maximum_observed_authority_epoch"])
                        if request_journal is not None
                        else None
                    ),
                    "request_journal_id": (
                        str(request_journal["journal_id"])
                        if request_journal is not None
                        else None
                    ),
                    "authority_epoch_number": live_governance[
                        "authority_epoch_number"
                    ],
                    "purpose": str(database["purpose"]),
                    "pinned": bool(pinned),
                    "created_at": created_at,
                }
                self.store._authenticate_receipt(receipt)
                self.store._write_private_json_exclusive(bundle_receipt_path, receipt)
                verified = self._verify_bundle_locked(bundle_receipt_path)
                publication_completed = {
                    "schema": RECOVERY_PUBLICATION_RECEIPT_SCHEMA,
                    "state": "completed",
                    "publication_id": publication_id,
                    "prepared_receipt_digest": str(
                        publication_prepared["receipt_digest"]
                    ),
                    "bundle_receipt_digest": str(receipt["receipt_digest"]),
                    "artifact_count": len(artifact_paths),
                    "verified": True,
                    "created_at": time.time(),
                }
                self.store._authenticate_receipt(publication_completed)
                self.store._write_private_json_exclusive(
                    publication_completed_path,
                    publication_completed,
                )
                return {
                    **database,
                    "action": "backup-recovery-bundle",
                    "bundle_schema": RECOVERY_BUNDLE_SCHEMA,
                    "bundle_receipt_path": str(bundle_receipt_path),
                    "capture_archive_path": str(capture_archive_path),
                    "request_journal_path": (
                        str(request_journal_path) if request_journal_path else None
                    ),
                    "request_journal_binding_receipt_path": (
                        str(request_journal_binding_receipt_path)
                        if request_journal_binding_receipt_path
                        else None
                    ),
                    "runtime_state_artifact_path": (
                        str(runtime_state_artifact_path)
                        if runtime_state_artifact_path is not None
                        else None
                    ),
                    "capture_archive_sha256": str(capture["sha256"]),
                    "capture_manifest_sha256": str(manifest["manifest_sha256"]),
                    "capture_file_count": int(manifest["file_count"]),
                    "capture_total_bytes": int(manifest["total_bytes"]),
                    "media_included": media_included,
                    "media_archive_path": (
                        str(media_archive_path) if media_included else None
                    ),
                    "media_archive_sha256": (
                        str(media["sha256"]) if media is not None else None
                    ),
                    "media_manifest_sha256": (
                        str(media_manifest["manifest_sha256"])
                        if media_included
                        else None
                    ),
                    "media_object_count": int(media_manifest["object_count"]),
                    "media_reconciliation": dict(media_manifest["reconciliation"]),
                    "reconciliation": dict(manifest["reconciliation"]),
                    "capture_ledger_binding": dict(
                        verified["capture_ledger_binding"]
                    ),
                    "cutover_ready": bool(verified["cutover_ready"]),
                    "capture_transport_health": {
                        "pending_file_count": int(status.get("pending_file_count") or 0),
                        "processing_file_count": int(
                            status.get("processing_file_count") or 0
                        ),
                        "receipt_count": int(status.get("receipt_count") or 0),
                        "unsafe_error_artifact_count": 0,
                    },
                    "bundle_verified": bool(verified["verified"]),
                    "publication_receipt_path": str(publication_completed_path),
                    "verified": True,
                }
            except BaseException:
                if publication_id is not None:
                    self._recover_incomplete_bundle_publications_locked()
                raise

    def verify_bundle(
        self,
        receipt_path: str | os.PathLike[str],
        *,
        expected_database_sha256: str | None = None,
        expected_capture_sha256: str | None = None,
        expected_request_journal_sha256: str | None = None,
        expected_runtime_state_sha256: str | None = None,
        expected_media_sha256: str | None = None,
    ) -> dict[str, Any]:
        with self._repository_lock():
            return self._verify_bundle_locked(
                receipt_path,
                expected_database_sha256=expected_database_sha256,
                expected_capture_sha256=expected_capture_sha256,
                expected_request_journal_sha256=expected_request_journal_sha256,
                expected_runtime_state_sha256=expected_runtime_state_sha256,
                expected_media_sha256=expected_media_sha256,
            )

    def _verify_bundle_locked(
        self,
        receipt_path: str | os.PathLike[str],
        *,
        expected_database_sha256: str | None = None,
        expected_capture_sha256: str | None = None,
        expected_request_journal_sha256: str | None = None,
        expected_runtime_state_sha256: str | None = None,
        expected_media_sha256: str | None = None,
    ) -> dict[str, Any]:
        reject_sensitive_identifier(receipt_path, field="recovery_bundle_receipt")
        receipt_file = Path(receipt_path).expanduser().absolute()
        receipt, identity_trusted = self._read_bundle_receipt(receipt_file)
        supplied_db = str(expected_database_sha256 or "").strip().lower()
        supplied_capture = str(expected_capture_sha256 or "").strip().lower()
        supplied_journal = str(expected_request_journal_sha256 or "").strip().lower()
        supplied_runtime = str(expected_runtime_state_sha256 or "").strip().lower()
        supplied_media = str(expected_media_sha256 or "").strip().lower()
        for supplied in (
            supplied_db,
            supplied_capture,
            supplied_journal,
            supplied_runtime,
            supplied_media,
        ):
            if supplied and not BACKUP_DIGEST_RE.fullmatch(supplied):
                raise ValueError("expected recovery digest must be lowercase SHA-256")
        journal_required = bool(receipt.get("request_journal_required"))
        runtime_state_required = bool(receipt.get("runtime_state_required"))
        media_included = bool(receipt.get("media_included"))
        if supplied_media and not media_included:
            raise ValueError("recovery bundle does not contain a media artifact")
        required_reviewed_digests = bool(
            supplied_db
            and supplied_capture
            and (supplied_journal if journal_required else True)
            and (supplied_runtime if runtime_state_required else True)
            and (supplied_media if media_included else True)
        )
        if not identity_trusted and not required_reviewed_digests:
            raise ValueError(
                "recovery signer is not trusted locally; provide every reviewed artifact SHA-256"
            )
        database_path = receipt_file.parent / self.store._validate_backup_artifact_name(
            receipt["database_artifact_name"], field="database artifact name"
        )
        database_receipt_path = receipt_file.parent / self.store._validate_backup_artifact_name(
            receipt["database_receipt_name"], field="database receipt name"
        )
        capture_path = receipt_file.parent / self.store._validate_backup_artifact_name(
            receipt["capture_artifact_name"], field="capture artifact name"
        )
        database_expected = str(receipt["database_sha256"])
        capture_expected = str(receipt["capture_sha256"])
        if supplied_db and not secrets.compare_digest(supplied_db, database_expected):
            raise ValueError("reviewed database digest does not match the bundle receipt")
        if supplied_capture and not secrets.compare_digest(
            supplied_capture, capture_expected
        ):
            raise ValueError("reviewed capture digest does not match the bundle receipt")
        if journal_required and supplied_journal and not secrets.compare_digest(
            supplied_journal,
            str(receipt["request_journal_sha256"]),
        ):
            raise ValueError(
                "reviewed request-journal digest does not match the bundle receipt"
            )
        if media_included and supplied_media and not secrets.compare_digest(
            supplied_media,
            str(receipt["media_sha256"]),
        ):
            raise ValueError(
                "reviewed media digest does not match the bundle receipt"
            )
        if supplied_runtime and not runtime_state_required:
            raise ValueError("recovery bundle does not contain a runtime-state artifact")
        if runtime_state_required and supplied_runtime and not secrets.compare_digest(
            supplied_runtime,
            str(receipt["runtime_state_sha256"]),
        ):
            raise ValueError(
                "reviewed runtime-state digest does not match the bundle receipt"
            )
        database = self.store.verify_backup(
            database_path,
            expected_sha256=database_expected if supplied_db else None,
            receipt_path=database_receipt_path,
        )
        if not secrets.compare_digest(str(database["sha256"]), database_expected):
            raise RuntimeError("recovery database digest does not match the bundle receipt")
        database_receipt, _ = self.store._read_trusted_backup_receipt(
            database_receipt_path,
            artifact=database_path,
        )
        bundle_schema = str(receipt["schema"])
        governance_mode = str(database["governance_mode"])
        store_generation = str(database["store_generation"])
        authority_epoch_number = database["authority_epoch_number"]
        request_journal: dict[str, Any] | None = None
        request_journal_binding: dict[str, Any] | None = None
        request_journal_binding_path: Path | None = None
        runtime_state: dict[str, Any] | None = None
        runtime_state_path: Path | None = None
        if (
            bundle_schema in (RECOVERY_BUNDLE_SCHEMA, PRIOR_RECOVERY_BUNDLE_SCHEMA)
            and bool(receipt.get("runtime_state_required"))
        ):
            runtime_state_path = receipt_file.parent / self.store._validate_backup_artifact_name(
                receipt["runtime_state_artifact_name"],
                field="runtime state artifact name",
            )
            runtime_state = self._verify_runtime_state_artifact(
                runtime_state_path,
                expected_sha256=str(receipt["runtime_state_sha256"]),
            )
            runtime_state_mismatches = (
                int(receipt["runtime_state_size_bytes"])
                != int(runtime_state["size_bytes"]),
                str(receipt["runtime_state_binding_schema"])
                != str(runtime_state["binding_schema"]),
                int(receipt["runtime_state_schema_version"])
                != int(runtime_state["state_schema_version"]),
                str(receipt["runtime_state_canonical_sha256"])
                != str(runtime_state["canonical_sha256"]),
                bool(receipt["runtime_state_global_enabled"])
                != bool(runtime_state["global_enabled"]),
                int(receipt["runtime_state_context_override_count"])
                != int(runtime_state["context_override_count"]),
                int(receipt["runtime_state_cortex_session_count"])
                != int(runtime_state["cortex_session_count"]),
            )
            if any(runtime_state_mismatches):
                raise RuntimeError(
                    "runtime state does not match its signed bundle binding"
                )
        if bundle_schema == LEGACY_RECOVERY_BUNDLE_SCHEMA:
            if governance_mode != "pre-governed-v5":
                raise RuntimeError(
                    "legacy journal-less bundles are valid only for pre-governed v5"
                )
        else:
            if (
                str(receipt["governance_mode"]) != governance_mode
                or str(receipt["store_generation"]) != store_generation
                or receipt["authority_epoch_number"] != authority_epoch_number
            ):
                raise RuntimeError(
                    "recovery bundle store generation does not match its database"
                )
            if governance_mode == "authoritative-v6":
                if not journal_required or type(authority_epoch_number) is not int:
                    raise RuntimeError(
                        "governed v6 recovery is missing request-journal evidence"
                    )
                request_journal_path = receipt_file.parent / self.store._validate_backup_artifact_name(
                    receipt["request_journal_artifact_name"],
                    field="request journal artifact name",
                )
                request_journal_binding_path = receipt_file.parent / self.store._validate_backup_artifact_name(
                    receipt["request_journal_binding_receipt_name"],
                    field="request journal binding receipt name",
                )
                request_journal_binding, binding_identity_trusted = (
                    self._read_request_journal_binding_receipt(
                        request_journal_binding_path
                    )
                )
                if identity_trusted and not binding_identity_trusted:
                    raise RuntimeError(
                        "request-journal binding signer is not trusted locally"
                    )
                request_journal = self._verify_request_journal_artifact(
                    request_journal_path,
                    expected_sha256=str(receipt["request_journal_sha256"]),
                    maximum_authority_epoch=int(authority_epoch_number),
                )
                if (
                    str(request_journal["store_identity"])
                    != str(database["store_identity"])
                    or str(request_journal["journal_id"])
                    != str(database["request_journal_id"])
                ):
                    raise RuntimeError(
                        "request journal does not match the restored database binding"
                    )
                binding_mismatches = (
                    str(request_journal_binding["journal_artifact_name"])
                    != request_journal_path.name,
                    str(request_journal_binding["journal_sha256"])
                    != str(request_journal["sha256"]),
                    int(request_journal_binding["journal_size_bytes"])
                    != int(request_journal["size_bytes"]),
                    int(request_journal_binding["journal_application_id"])
                    != int(request_journal["application_id"]),
                    int(request_journal_binding["journal_schema_version"])
                    != int(request_journal["schema_version"]),
                    str(request_journal_binding["journal_schema_identity"])
                    != str(request_journal["schema_identity"]),
                    str(request_journal_binding["request_journal_id"])
                    != str(request_journal["journal_id"]),
                    str(request_journal_binding["journal_schema_sha256"])
                    != str(request_journal["schema_sha256"]),
                    str(
                        request_journal_binding[
                            "journal_logical_snapshot_schema"
                        ]
                    )
                    != str(request_journal["logical_snapshot_schema"]),
                    str(
                        request_journal_binding[
                            "journal_logical_snapshot_sha256"
                        ]
                    )
                    != str(request_journal["logical_snapshot_sha256"]),
                    int(
                        request_journal_binding[
                            "journal_logical_snapshot_table_count"
                        ]
                    )
                    != int(request_journal["logical_snapshot_table_count"]),
                    int(
                        request_journal_binding[
                            "journal_logical_snapshot_column_count"
                        ]
                    )
                    != int(request_journal["logical_snapshot_column_count"]),
                    int(
                        request_journal_binding[
                            "journal_logical_snapshot_row_count"
                        ]
                    )
                    != int(request_journal["logical_snapshot_row_count"]),
                    int(
                        request_journal_binding[
                            "journal_logical_snapshot_value_bytes"
                        ]
                    )
                    != int(request_journal["logical_snapshot_value_bytes"]),
                    int(request_journal_binding["journal_row_count"])
                    != int(request_journal["row_count"]),
                    request_journal_binding["journal_state_counts"]
                    != request_journal["state_counts"],
                    int(
                        request_journal_binding[
                            "journal_current_authority_epoch_row_count"
                        ]
                    )
                    != int(request_journal["current_authority_epoch_row_count"]),
                    int(
                        request_journal_binding[
                            "journal_maximum_observed_authority_epoch"
                        ]
                    )
                    != int(request_journal["maximum_observed_authority_epoch"]),
                    str(request_journal_binding["database_artifact_name"])
                    != database_path.name,
                    str(request_journal_binding["database_sha256"])
                    != str(database["sha256"]),
                    str(request_journal_binding["database_receipt_digest"])
                    != str(database_receipt["receipt_digest"]),
                    str(
                        request_journal_binding[
                            "database_schema_contract_version"
                        ]
                    )
                    != str(database_receipt["schema_contract_version"]),
                    str(request_journal_binding["database_snapshot_revision"])
                    != str(database["snapshot_revision"]),
                    str(
                        request_journal_binding[
                            "database_logical_snapshot_schema"
                        ]
                    )
                    != str(database["logical_snapshot_schema"]),
                    str(
                        request_journal_binding[
                            "database_logical_snapshot_sha256"
                        ]
                    )
                    != str(database["logical_snapshot_sha256"]),
                    str(request_journal_binding["store_identity"])
                    != str(receipt["store_identity"]),
                    str(request_journal_binding["store_generation"])
                    != store_generation,
                    int(request_journal_binding["authority_epoch_number"])
                    != int(authority_epoch_number),
                    str(request_journal_binding["auth_key_id"])
                    != str(receipt["auth_key_id"]),
                    str(request_journal_binding["auth_key_id"])
                    != str(database_receipt["auth_key_id"]),
                    str(request_journal_binding["receipt_digest"])
                    != str(receipt["request_journal_binding_receipt_digest"]),
                    int(receipt["request_journal_size_bytes"])
                    != int(request_journal["size_bytes"]),
                    int(receipt["request_journal_schema_version"])
                    != int(request_journal["schema_version"]),
                    str(receipt["request_journal_schema_identity"])
                    != str(request_journal["schema_identity"]),
                    str(receipt["request_journal_id"])
                    != str(request_journal["journal_id"]),
                    str(receipt["request_journal_schema_sha256"])
                    != str(request_journal["schema_sha256"]),
                    str(receipt["request_journal_logical_snapshot_schema"])
                    != str(request_journal["logical_snapshot_schema"]),
                    str(receipt["request_journal_logical_snapshot_sha256"])
                    != str(request_journal["logical_snapshot_sha256"]),
                    int(receipt["request_journal_logical_snapshot_table_count"])
                    != int(request_journal["logical_snapshot_table_count"]),
                    int(receipt["request_journal_logical_snapshot_column_count"])
                    != int(request_journal["logical_snapshot_column_count"]),
                    int(receipt["request_journal_logical_snapshot_row_count"])
                    != int(request_journal["logical_snapshot_row_count"]),
                    int(receipt["request_journal_logical_snapshot_value_bytes"])
                    != int(request_journal["logical_snapshot_value_bytes"]),
                    int(receipt["request_journal_row_count"])
                    != int(request_journal["row_count"]),
                    int(
                        receipt[
                            "request_journal_current_authority_epoch_row_count"
                        ]
                    )
                    != int(request_journal["current_authority_epoch_row_count"]),
                    int(
                        receipt[
                            "request_journal_maximum_observed_authority_epoch"
                        ]
                    )
                    != int(request_journal["maximum_observed_authority_epoch"]),
                )
                if any(binding_mismatches):
                    raise RuntimeError(
                        "request journal does not match its memory-store binding"
                    )
                runtime_state_mismatches = (
                    int(receipt["runtime_state_size_bytes"])
                    != int(runtime_state["size_bytes"]),
                    str(receipt["runtime_state_binding_schema"])
                    != str(runtime_state["binding_schema"]),
                    int(receipt["runtime_state_schema_version"])
                    != int(runtime_state["state_schema_version"]),
                    str(receipt["runtime_state_canonical_sha256"])
                    != str(runtime_state["canonical_sha256"]),
                    bool(receipt["runtime_state_global_enabled"])
                    != bool(runtime_state["global_enabled"]),
                    int(receipt["runtime_state_context_override_count"])
                    != int(runtime_state["context_override_count"]),
                    int(receipt["runtime_state_cortex_session_count"])
                    != int(runtime_state["cortex_session_count"]),
                )
                if any(runtime_state_mismatches):
                    raise RuntimeError(
                        "runtime state does not match its signed bundle binding"
                    )
            elif journal_required:
                raise RuntimeError(
                    "pre-governed v5 recovery must not include a request journal"
                )
        database_uri = database_path.resolve().as_uri() + "?mode=ro&immutable=1"
        with closing(sqlite3.connect(database_uri, uri=True)) as snapshot:
            ledger_bindings = self._snapshot_capture_ledger_bindings(snapshot)
        ledger_ids = set(ledger_bindings)
        capture_highwater_micros = int(
            max(
                (
                    float(binding["committed_at"])
                    for binding in ledger_bindings.values()
                ),
                default=0.0,
            )
            * 1_000_000
        )
        database_binding = {
            "artifact_sha256": database_expected,
            "receipt_digest": str(database_receipt["receipt_digest"]),
            "auth_key_id": str(database_receipt["auth_key_id"]),
            "schema_contract_version": str(
                database_receipt["schema_contract_version"]
            ),
            "snapshot_revision": str(database["snapshot_revision"]),
            "logical_snapshot_schema": str(database["logical_snapshot_schema"]),
            "logical_snapshot_sha256": str(database["logical_snapshot_sha256"]),
            "capture_operation_count": len(ledger_ids),
            "capture_operation_highwater_micros": capture_highwater_micros,
            "capture_root_provenance": str(receipt["capture_root_provenance"]),
            "capture_root_identity_digest": str(
                receipt["capture_root_identity_digest"]
            ),
        }
        archive_database_binding: dict[str, Any] | None = database_binding
        if bundle_schema == LEGACY_RECOVERY_BUNDLE_SCHEMA:
            # A v1 outer receipt may refer either to a genuinely old archive or
            # to an archive produced just before a receipt-only downgrade test.
            # Verify the signed archive first, then accept only the exact
            # current binding or its historical projection.
            archive_database_binding = None
        capture = self._verify_capture_archive(
            capture_path,
            expected_sha256=capture_expected,
            expected_manifest_sha256=str(receipt["capture_manifest_sha256"]),
            ledger_ids=ledger_ids,
            ledger_bindings=ledger_bindings,
            database_binding=archive_database_binding,
        )
        if bundle_schema == LEGACY_RECOVERY_BUNDLE_SCHEMA:
            legacy_database_binding = dict(database_binding)
            legacy_database_binding.pop("logical_snapshot_schema")
            legacy_database_binding.pop("logical_snapshot_sha256")
            archived_database_binding = dict(
                capture["manifest"]["database_binding"]
            )
            if archived_database_binding not in (
                database_binding,
                legacy_database_binding,
            ):
                raise RuntimeError("capture archive database binding mismatch")
        with closing(sqlite3.connect(database_uri, uri=True)) as snapshot:
            media_references = media_references_from_connection(snapshot)
        if (
            bundle_schema == RECOVERY_BUNDLE_SCHEMA
            and not media_included
            and int(media_references["reference_count"])
        ):
            # A current-schema receipt may state media_included=false only for
            # a snapshot without image references; anything else is a
            # dishonest bundle, not a legacy compatibility case.
            raise RuntimeError(
                "recovery bundle omits its media archive while the database "
                "references image memories"
            )
        media: dict[str, Any] | None = None
        media_archive_file: Path | None = None
        if media_included:
            media_archive_file = receipt_file.parent / self.store._validate_backup_artifact_name(
                receipt["media_artifact_name"],
                field="media artifact name",
            )
            media = self._verify_media_archive(
                media_archive_file,
                expected_sha256=str(receipt["media_sha256"]),
                expected_manifest_sha256=str(receipt["media_manifest_sha256"]),
                database_binding=database_binding,
            )
            media_mismatches = (
                int(receipt["media_size_bytes"]) != int(media["size_bytes"]),
                int(receipt["media_object_count"]) != int(media["object_count"]),
                int(receipt["media_file_count"]) != int(media["file_count"]),
                int(receipt["media_total_bytes"]) != int(media["total_bytes"]),
                int(receipt["media_referenced_count"])
                != int(media["referenced_count"]),
                int(receipt["media_orphan_count"]) != int(media["orphan_count"]),
                sorted(media_references["media_ids"]) != list(media["object_ids"]),
            )
            if any(media_mismatches):
                raise RuntimeError(
                    "media archive does not match its signed bundle binding"
                )
        media_recovery_complete = bool(
            media_included or media_references["reference_count"] == 0
        )
        reconciliation = dict(capture["manifest"]["reconciliation"])
        capture_ledger_binding = dict(capture["capture_ledger_binding"])
        pending_state = self._canonical_pending_capture_state(
            capture["manifest"]
        )
        cutover_ready = (
            bool(capture_ledger_binding["verified"])
            and not bool(reconciliation["replay_required_file_count"])
            and pending_state.get("pending_file_count") == 0
            # A bundle whose database still references image memories that no
            # archived media artifact can restore stays inspectable but must
            # never be promoted to an authoritative cutover candidate.
            and media_recovery_complete
            and (
                governance_mode == "pre-governed-v5"
                or (
                    request_journal is not None
                    and request_journal_binding is not None
                    and runtime_state is not None
                )
            )
        )
        if (
            int(receipt["database_size_bytes"]) != int(database["size_bytes"])
            or int(receipt["capture_size_bytes"]) != int(capture["size_bytes"])
            or str(receipt["database_snapshot_revision"])
            != str(database["snapshot_revision"])
            or (
                bundle_schema
                in (RECOVERY_BUNDLE_SCHEMA, PRIOR_RECOVERY_BUNDLE_SCHEMA)
                and (
                    str(receipt["database_logical_snapshot_schema"])
                    != str(database["logical_snapshot_schema"])
                    or not secrets.compare_digest(
                        str(receipt["database_logical_snapshot_sha256"]),
                        str(database["logical_snapshot_sha256"]),
                    )
                    or int(receipt["database_logical_snapshot_table_count"])
                    != int(database["logical_snapshot_table_count"])
                    or int(receipt["database_logical_snapshot_column_count"])
                    != int(database["logical_snapshot_column_count"])
                    or int(receipt["database_logical_snapshot_row_count"])
                    != int(database["logical_snapshot_row_count"])
                    or int(receipt["database_logical_snapshot_value_bytes"])
                    != int(database["logical_snapshot_value_bytes"])
                )
            )
            or int(receipt["capture_file_count"]) != int(capture["file_count"])
            or int(receipt["capture_total_bytes"]) != int(capture["total_bytes"])
            or str(receipt["database_receipt_digest"])
            != str(database_receipt["receipt_digest"])
            or str(receipt["database_auth_key_id"])
            != str(database_receipt["auth_key_id"])
            or str(receipt["database_schema_contract_version"])
            != str(database_receipt["schema_contract_version"])
            or int(receipt["capture_operation_count"]) != len(ledger_ids)
            or int(receipt["capture_operation_highwater_micros"])
            != capture_highwater_micros
            or str(receipt["capture_root_identity_digest"])
            != str(
                capture["manifest"]["database_binding"][
                    "capture_root_identity_digest"
                ]
            )
            or str(receipt["capture_root_provenance"])
            != str(
                capture["manifest"]["database_binding"]["capture_root_provenance"]
            )
        ):
            raise RuntimeError("recovery bundle receipt does not match its artifacts")
        return {
            "action": "verify-recovery-bundle",
            "bundle_receipt_path": str(receipt_file),
            "bundle_receipt_digest": str(receipt["receipt_digest"]),
            "database": database,
            "capture": {
                key: value for key, value in capture.items() if key != "manifest"
            },
            "capture_manifest_sha256": str(capture["manifest_sha256"]),
            "capture_database_binding": dict(
                capture["manifest"]["database_binding"]
            ),
            "capture_pending_state": pending_state,
            "reconciliation": reconciliation,
            "capture_ledger_binding": capture_ledger_binding,
            "governance_mode": governance_mode,
            "store_identity": (
                str(receipt["store_identity"])
                if bundle_schema
                in (RECOVERY_BUNDLE_SCHEMA, PRIOR_RECOVERY_BUNDLE_SCHEMA)
                else self._store_identity()
            ),
            "store_generation": store_generation,
            "logical_snapshot_schema": str(database["logical_snapshot_schema"]),
            "logical_snapshot_sha256": str(database["logical_snapshot_sha256"]),
            "request_journal": request_journal,
            "request_journal_binding": (
                None
                if request_journal_binding is None
                else {
                    "receipt_path": str(request_journal_binding_path),
                    "receipt_digest": str(
                        request_journal_binding["receipt_digest"]
                    ),
                    "store_identity": str(
                        request_journal_binding["store_identity"]
                    ),
                    "store_generation": str(
                        request_journal_binding["store_generation"]
                    ),
                    "request_journal_id": str(
                        request_journal_binding["request_journal_id"]
                    ),
                    "journal_schema_identity": str(
                        request_journal_binding["journal_schema_identity"]
                    ),
                    "verified": True,
                }
            ),
            "runtime_state": (
                None
                if runtime_state is None
                else {
                    "artifact_path": str(runtime_state_path),
                    "sha256": str(runtime_state["sha256"]),
                    "canonical_sha256": str(runtime_state["canonical_sha256"]),
                    "state_schema_version": int(
                        runtime_state["state_schema_version"]
                    ),
                    "verified": True,
                }
            ),
            "media_included": media_included,
            "media_recovery_complete": media_recovery_complete,
            "media_reference_count": int(media_references["reference_count"]),
            "media": (
                {
                    "artifact_path": str(media_archive_file),
                    "sha256": str(media["sha256"]),
                    "size_bytes": int(media["size_bytes"]),
                    "manifest_sha256": str(media["manifest_sha256"]),
                    "object_count": int(media["object_count"]),
                    "file_count": int(media["file_count"]),
                    "total_bytes": int(media["total_bytes"]),
                    "referenced_count": int(media["referenced_count"]),
                    "orphan_count": int(media["orphan_count"]),
                    "verified": True,
                }
                if media is not None
                else None
            ),
            "media_recovery": (
                "media-archive-verified"
                if media_included
                else "media-not-required-zero-references"
                if bundle_schema == RECOVERY_BUNDLE_SCHEMA
                else "legacy-media-not-present"
            ),
            "cutover_ready": cutover_ready,
            "receipt_identity_trusted": identity_trusted,
            "reviewed_digests_verified": required_reviewed_digests,
            "verified": True,
            "verified_at": time.time(),
        }

    def _extract_capture_archive(
        self,
        archive_path: Path,
        manifest: dict[str, Any],
        target: Path,
    ) -> None:
        if target.exists() or target.is_symlink():
            raise FileExistsError("capture restore target already exists")
        target.mkdir(mode=0o700, parents=False)
        try:
            records = {
                "capture/" + str(record["relative_path"]): record
                for record in manifest["files"]
            }
            with tarfile.open(archive_path, mode="r:gz") as archive:
                members = archive.getmembers()
                if any(not member.isfile() for member in members):
                    raise ValueError("capture restore archive contains a non-file member")
                capture_members = [
                    member for member in members
                    if member.name != "capture-manifest.json"
                ]
                capture_names = [member.name for member in capture_members]
                if (
                    len(capture_names) != len(set(capture_names))
                    or set(capture_names) != set(records)
                    or sum(
                        member.name == "capture-manifest.json"
                        for member in members
                    )
                    != 1
                ):
                    raise RuntimeError(
                        "capture restore archive members do not match the manifest"
                    )
                for member in capture_members:
                    if member.name == "capture-manifest.json":
                        continue
                    record = records[member.name]
                    relative = Path(str(record["relative_path"]))
                    destination = target / relative
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    if destination.exists() or destination.is_symlink():
                        raise FileExistsError("capture restore member already exists")
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise ValueError("capture restore member cannot be read")
                    data = extracted.read(int(record["size_bytes"]) + 1)
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    descriptor = os.open(destination, flags, 0o600)
                    try:
                        offset = 0
                        while offset < len(data):
                            offset += os.write(descriptor, data[offset:])
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    if hashlib.sha256(data).hexdigest() != str(record["sha256"]):
                        raise RuntimeError("capture restore member digest mismatch")
            self.store._fsync_directory(target)
        except BaseException:
            shutil.rmtree(target, ignore_errors=True)
            raise

    @staticmethod
    def _capture_ids_from_payload(value: Any) -> set[str]:
        capture_ids: set[str] = set()
        if isinstance(value, dict):
            capture_id = value.get("capture_id")
            if isinstance(capture_id, str) and capture_id.startswith("s2cap_"):
                capture_ids.add(capture_id)
            records = value.get("records")
            if isinstance(records, list):
                for record in records:
                    capture_ids.update(VerifiedRecoveryManager._capture_ids_from_payload(record))
        return capture_ids

    def restore_bundle_isolated(
        self,
        receipt_path: str | os.PathLike[str],
        output_root: str | os.PathLike[str],
        *,
        expected_database_sha256: str | None = None,
        expected_capture_sha256: str | None = None,
        expected_request_journal_sha256: str | None = None,
        expected_runtime_state_sha256: str | None = None,
        expected_media_sha256: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        with self._repository_lock():
            return self._restore_bundle_isolated_locked(
                receipt_path,
                output_root,
                expected_database_sha256=expected_database_sha256,
                expected_capture_sha256=expected_capture_sha256,
                expected_request_journal_sha256=expected_request_journal_sha256,
                expected_runtime_state_sha256=expected_runtime_state_sha256,
                expected_media_sha256=expected_media_sha256,
                confirm=confirm,
            )

    def _restore_bundle_isolated_locked(
        self,
        receipt_path: str | os.PathLike[str],
        output_root: str | os.PathLike[str],
        *,
        expected_database_sha256: str | None = None,
        expected_capture_sha256: str | None = None,
        expected_request_journal_sha256: str | None = None,
        expected_runtime_state_sha256: str | None = None,
        expected_media_sha256: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        if not confirm:
            raise ValueError("confirm=true is required to materialize recovery proof")
        reject_sensitive_identifier(output_root, field="recovery_output_root")
        target_root = Path(output_root).expanduser().absolute()
        if target_root.exists() or target_root.is_symlink():
            raise FileExistsError("recovery output root already exists")
        verified = self._verify_bundle_locked(
            receipt_path,
            expected_database_sha256=expected_database_sha256,
            expected_capture_sha256=expected_capture_sha256,
            expected_request_journal_sha256=expected_request_journal_sha256,
            expected_runtime_state_sha256=expected_runtime_state_sha256,
            expected_media_sha256=expected_media_sha256,
        )
        receipt_file = Path(str(verified["bundle_receipt_path"]))
        receipt, _ = self._read_bundle_receipt(receipt_file)
        if not secrets.compare_digest(
            str(receipt["receipt_digest"]),
            str(verified["bundle_receipt_digest"]),
        ):
            raise RuntimeError("recovery bundle receipt changed after verification")
        database_path = receipt_file.parent / str(receipt["database_artifact_name"])
        database_receipt = receipt_file.parent / str(receipt["database_receipt_name"])
        capture_path = receipt_file.parent / str(receipt["capture_artifact_name"])
        request_journal_path: Path | None = None
        request_journal_binding_source: Path | None = None
        request_journal_binding_payload: dict[str, Any] | None = None
        runtime_state_source: Path | None = None
        if verified["governance_mode"] == "authoritative-v6":
            request_journal_path = receipt_file.parent / str(
                receipt["request_journal_artifact_name"]
            )
            request_journal_binding_source = receipt_file.parent / str(
                receipt["request_journal_binding_receipt_name"]
            )
            request_journal_binding_payload, _binding_trusted = (
                self._read_request_journal_binding_receipt(
                    request_journal_binding_source
                )
            )
            if not secrets.compare_digest(
                str(request_journal_binding_payload["receipt_digest"]),
                str(receipt["request_journal_binding_receipt_digest"]),
            ):
                raise RuntimeError(
                    "request-journal binding changed after bundle verification"
                )
        if bool(receipt.get("runtime_state_required")):
            runtime_state_source = receipt_file.parent / str(
                receipt["runtime_state_artifact_name"]
            )
        database_receipt_payload, _ = self.store._read_trusted_backup_receipt(
            database_receipt,
            artifact=database_path,
        )
        if not secrets.compare_digest(
            str(database_receipt_payload["receipt_digest"]),
            str(receipt["database_receipt_digest"]),
        ):
            raise RuntimeError("database receipt changed after bundle verification")
        database_uri = database_path.resolve().as_uri() + "?mode=ro&immutable=1"
        with closing(sqlite3.connect(database_uri, uri=True)) as snapshot:
            ledger_bindings = self._snapshot_capture_ledger_bindings(snapshot)
        ledger_ids = set(ledger_bindings)
        database_binding = {
            "artifact_sha256": str(receipt["database_sha256"]),
            "receipt_digest": str(database_receipt_payload["receipt_digest"]),
            "auth_key_id": str(database_receipt_payload["auth_key_id"]),
            "schema_contract_version": str(
                database_receipt_payload["schema_contract_version"]
            ),
            "snapshot_revision": str(receipt["database_snapshot_revision"]),
            "logical_snapshot_schema": str(
                verified["database"]["logical_snapshot_schema"]
            ),
            "logical_snapshot_sha256": str(
                verified["database"]["logical_snapshot_sha256"]
            ),
            "capture_operation_count": len(ledger_ids),
            "capture_operation_highwater_micros": int(
                max(
                    (
                        float(binding["committed_at"])
                        for binding in ledger_bindings.values()
                    ),
                    default=0.0,
                )
                * 1_000_000
            ),
            "capture_root_provenance": str(receipt["capture_root_provenance"]),
            "capture_root_identity_digest": str(
                receipt["capture_root_identity_digest"]
            ),
        }
        archive_database_binding: dict[str, Any] | None = database_binding
        if receipt.get("schema") == LEGACY_RECOVERY_BUNDLE_SCHEMA:
            archive_database_binding = None
        capture_verification = self._verify_capture_archive(
            capture_path,
            expected_sha256=str(receipt["capture_sha256"]),
            expected_manifest_sha256=str(receipt["capture_manifest_sha256"]),
            ledger_ids=ledger_ids,
            ledger_bindings=ledger_bindings,
            database_binding=archive_database_binding,
            retain_verified_snapshot=True,
        )
        if receipt.get("schema") == LEGACY_RECOVERY_BUNDLE_SCHEMA:
            legacy_database_binding = dict(database_binding)
            legacy_database_binding.pop("logical_snapshot_schema")
            legacy_database_binding.pop("logical_snapshot_sha256")
            archived_database_binding = dict(
                capture_verification["manifest"]["database_binding"]
            )
            if archived_database_binding not in (
                database_binding,
                legacy_database_binding,
            ):
                raise RuntimeError("capture archive database binding mismatch")
        verified_capture_snapshot = Path(
            str(capture_verification.pop("verified_snapshot_path"))
        )
        media_included = bool(receipt.get("media_included"))
        media_verification: dict[str, Any] | None = None
        verified_media_snapshot: Path | None = None
        try:
            if media_included:
                media_archive_source = receipt_file.parent / str(
                    receipt["media_artifact_name"]
                )
                media_verification = self._verify_media_archive(
                    media_archive_source,
                    expected_sha256=str(receipt["media_sha256"]),
                    expected_manifest_sha256=str(receipt["media_manifest_sha256"]),
                    database_binding=database_binding,
                    retain_verified_snapshot=True,
                )
                verified_media_snapshot = Path(
                    str(media_verification.pop("verified_snapshot_path"))
                )
            target_root.mkdir(mode=0o700, parents=False)
            database_target = target_root / "memory.sqlite3"
            database_restore = self.store.restore_backup(
                database_path,
                database_target,
                expected_sha256=str(receipt["database_sha256"]),
                receipt_path=database_receipt,
                confirm=True,
                _paired_request_journal_binding=(
                    request_journal_binding_payload
                    if verified["governance_mode"] == "authoritative-v6"
                    else None
                ),
                _paired_request_journal_expected_sha256=(
                    expected_request_journal_sha256
                    if verified["governance_mode"] == "authoritative-v6"
                    else None
                ),
            )
            request_journal_restore: dict[str, Any] | None = None
            request_journal_binding_restore: dict[str, Any] | None = None
            request_journal_restore_binding: dict[str, Any] | None = None
            runtime_state_restore: dict[str, Any] | None = None
            if verified["governance_mode"] == "authoritative-v6":
                if (
                    request_journal_path is None
                    or request_journal_binding_source is None
                    or request_journal_binding_payload is None
                    or runtime_state_source is None
                    or type(receipt["authority_epoch_number"]) is not int
                ):
                    raise RuntimeError(
                        "governed restore lost its request-journal binding"
                    )
                core_target = target_root / "core"
                os.mkdir(core_target, mode=0o700)
                request_journal_target = core_target / "requests.sqlite3"
                request_journal_restore = self._restore_private_artifact(
                    request_journal_path,
                    request_journal_target,
                    expected_sha256=str(receipt["request_journal_sha256"]),
                )
                restored_journal_verification = (
                    self._verify_request_journal_artifact(
                        request_journal_target,
                        expected_sha256=str(receipt["request_journal_sha256"]),
                        maximum_authority_epoch=int(
                            receipt["authority_epoch_number"]
                        ),
                    )
                )
                if (
                    int(restored_journal_verification["row_count"])
                    != int(receipt["request_journal_row_count"])
                    or str(restored_journal_verification["schema_sha256"])
                    != str(receipt["request_journal_schema_sha256"])
                    or not secrets.compare_digest(
                        str(
                            restored_journal_verification[
                                "logical_snapshot_sha256"
                            ]
                        ),
                        str(
                            receipt[
                                "request_journal_logical_snapshot_sha256"
                            ]
                        ),
                    )
                ):
                    raise RuntimeError(
                        "restored request journal does not match its signed binding"
                    )
                request_journal_binding_target = (
                    core_target / "requests.sqlite3.binding.receipt.json"
                )
                runtime_state_target = target_root / "runtime_state.json"
                runtime_state_restore = self._restore_runtime_state_artifact(
                    runtime_state_source,
                    runtime_state_target,
                    expected_source_sha256=str(receipt["runtime_state_sha256"]),
                    restored_memory_path=database_target,
                )
                restore_binding_payload = {
                    "schema": REQUEST_JOURNAL_RESTORE_BINDING_SCHEMA,
                    "memory_artifact_relative": "memory.sqlite3",
                    "memory_sha256": str(database_restore["sha256"]),
                    "memory_size_bytes": int(database_restore["size_bytes"]),
                    "memory_schema_contract_version": str(verified["database"]["schema_contract_version"]),
                    "memory_schema_identity": str(verified["database"]["schema_identity"]),
                    "memory_snapshot_revision": str(database_restore["snapshot_revision"]),
                    "memory_logical_snapshot_schema": str(database_restore["logical_snapshot_schema"]),
                    "memory_logical_snapshot_sha256": str(database_restore["logical_snapshot_sha256"]),
                    "memory_logical_snapshot_table_count": int(verified["database"]["logical_snapshot_table_count"]),
                    "memory_logical_snapshot_column_count": int(verified["database"]["logical_snapshot_column_count"]),
                    "memory_logical_snapshot_row_count": int(verified["database"]["logical_snapshot_row_count"]),
                    "memory_logical_snapshot_value_bytes": int(verified["database"]["logical_snapshot_value_bytes"]),
                    "request_journal_artifact_relative": "core/requests.sqlite3",
                    "request_journal_sha256": str(request_journal_restore["sha256"]),
                    "request_journal_size_bytes": int(request_journal_restore["size_bytes"]),
                    "request_journal_application_id": int(restored_journal_verification["application_id"]),
                    "request_journal_schema_version": int(restored_journal_verification["schema_version"]),
                    "request_journal_schema_identity": str(restored_journal_verification["schema_identity"]),
                    "request_journal_schema_sha256": str(restored_journal_verification["schema_sha256"]),
                    "request_journal_logical_snapshot_schema": str(restored_journal_verification["logical_snapshot_schema"]),
                    "request_journal_logical_snapshot_sha256": str(restored_journal_verification["logical_snapshot_sha256"]),
                    "request_journal_logical_snapshot_table_count": int(restored_journal_verification["logical_snapshot_table_count"]),
                    "request_journal_logical_snapshot_column_count": int(restored_journal_verification["logical_snapshot_column_count"]),
                    "request_journal_logical_snapshot_row_count": int(restored_journal_verification["logical_snapshot_row_count"]),
                    "request_journal_logical_snapshot_value_bytes": int(restored_journal_verification["logical_snapshot_value_bytes"]),
                    "request_journal_row_count": int(restored_journal_verification["row_count"]),
                    "request_journal_state_counts": dict(restored_journal_verification["state_counts"]),
                    "request_journal_current_authority_epoch_row_count": int(restored_journal_verification["current_authority_epoch_row_count"]),
                    "request_journal_maximum_observed_authority_epoch": int(restored_journal_verification["maximum_observed_authority_epoch"]),
                    "request_journal_id": str(restored_journal_verification["journal_id"]),
                    "runtime_state_artifact_relative": "runtime_state.json",
                    "runtime_state_sha256": str(runtime_state_restore["sha256"]),
                    "runtime_state_size_bytes": int(runtime_state_restore["size_bytes"]),
                    "runtime_state_binding_schema": str(runtime_state_restore["binding_schema"]),
                    "runtime_state_schema_version": int(runtime_state_restore["state_schema_version"]),
                    "runtime_state_canonical_sha256": str(runtime_state_restore["canonical_sha256"]),
                    "runtime_state_memory_db_path": str(database_target),
                    "source_runtime_state_sha256": str(runtime_state_restore["source_sha256"]),
                    "source_runtime_state_canonical_sha256": str(runtime_state_restore["source_canonical_sha256"]),
                    "store_identity": str(verified["store_identity"]),
                    "store_generation": str(verified["store_generation"]),
                    "authority_epoch_number": int(receipt["authority_epoch_number"]),
                    "source_request_journal_binding_receipt_digest": str(request_journal_binding_payload["receipt_digest"]),
                    "source_database_receipt_digest": str(database_receipt_payload["receipt_digest"]),
                    "source_bundle_receipt_digest": str(receipt["receipt_digest"]),
                    "created_at": time.time(),
                }
                self.store._authenticate_receipt(restore_binding_payload)
                self.store._write_private_json_exclusive(
                    request_journal_binding_target,
                    restore_binding_payload,
                )
                binding_digest, binding_size, _binding_metadata = self.store._hash_stable_regular_file(
                    request_journal_binding_target
                )
                request_journal_binding_restore = {
                    "path": str(request_journal_binding_target),
                    "sha256": binding_digest,
                    "size_bytes": binding_size,
                }
                request_journal_restore_binding = self.verify_restored_request_journal_binding(
                    target_root,
                    expected_store_identity=str(verified["store_identity"]),
                    expected_store_generation=str(verified["store_generation"]),
                    expected_source_request_journal_binding_receipt_digest=str(
                        request_journal_binding_payload["receipt_digest"]
                    ),
                )
            elif runtime_state_source is not None:
                runtime_state_restore = self._restore_runtime_state_artifact(
                    runtime_state_source,
                    target_root / "runtime_state.json",
                    expected_source_sha256=str(receipt["runtime_state_sha256"]),
                    restored_memory_path=database_target,
                )
            capture_target = target_root / "capture-root"
            self._extract_capture_archive(
                verified_capture_snapshot,
                capture_verification["manifest"],
                capture_target,
            )
            restored_database_uri = (
                database_target.resolve().as_uri() + "?mode=ro&immutable=1"
            )
            with closing(
                sqlite3.connect(restored_database_uri, uri=True)
            ) as conn:
                restored_ledger_bindings = (
                    self._snapshot_capture_ledger_bindings(conn)
                )
            ledger_ids = set(restored_ledger_bindings)
            restored_binding_proof = (
                self._verify_extracted_capture_ledger_bindings(
                    capture_target / "capture_processed",
                    ledger_bindings=restored_ledger_bindings,
                    processing_root=capture_target / "capture_processing",
                )
            )
            archive_binding_proof = dict(
                capture_verification["capture_ledger_binding"]
            )
            if (
                not bool(archive_binding_proof.get("verified"))
                or restored_binding_proof != archive_binding_proof
            ):
                raise RuntimeError(
                    "restored capture ledger binding proof does not match the "
                    "verified recovery archive"
                )
            receipt_ids: set[str] = set()
            processed_ids: set[str] = set()
            for relative_dir, target_set in (
                ("capture_receipts", receipt_ids),
                ("capture_processed", processed_ids),
            ):
                directory = capture_target / relative_dir
                if not directory.exists():
                    continue
                for candidate in directory.rglob("*"):
                    if not candidate.is_file() or candidate.is_symlink():
                        continue
                    data, _ = self._read_private_regular(candidate, max_bytes=4 * 1024**2)
                    try:
                        parsed = json.loads(data.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    target_set.update(self._capture_ids_from_payload(parsed))
            missing_receipt_ledgers = receipt_ids - ledger_ids
            missing_processed_ledgers = processed_ids - ledger_ids
            if missing_receipt_ledgers or missing_processed_ledgers:
                raise RuntimeError(
                    "paired recovery proof found capture transport without authoritative ledger rows"
                )
            with closing(
                sqlite3.connect(restored_database_uri, uri=True)
            ) as conn:
                restored_media_references = media_references_from_connection(conn)
            media_target: Path | None = None
            if media_included:
                if (
                    media_verification is None
                    or verified_media_snapshot is None
                ):
                    raise RuntimeError("media restore lost its verified archive")
                media_target = target_root / "media-cache"
                self._extract_media_archive(
                    verified_media_snapshot,
                    media_verification["manifest"],
                    media_target,
                )
                if (
                    sorted(restored_media_references["media_ids"])
                    != list(media_verification["object_ids"])
                ):
                    raise RuntimeError(
                        "restored media references do not match the verified "
                        "media archive"
                    )
            if (
                receipt.get("schema") == RECOVERY_BUNDLE_SCHEMA
                and not media_included
                and int(restored_media_references["reference_count"])
            ):
                raise RuntimeError(
                    "recovery bundle omits its media archive while the "
                    "database references image memories"
                )
            media_recovery_complete = bool(
                media_included
                or restored_media_references["reference_count"] == 0
            )
            media_absent_verified = bool(
                receipt.get("schema") == RECOVERY_BUNDLE_SCHEMA
                and not media_included
            )
            proof_schema = (
                RECOVERY_BUNDLE_RESTORE_SCHEMA
                if receipt.get("schema") == RECOVERY_BUNDLE_SCHEMA
                else PRIOR_RECOVERY_BUNDLE_RESTORE_SCHEMA
                if receipt.get("schema") == PRIOR_RECOVERY_BUNDLE_SCHEMA
                else LEGACY_RECOVERY_BUNDLE_RESTORE_SCHEMA
            )
            restored_pending_state = self._canonical_pending_capture_state(
                capture_verification["manifest"]
            )
            proof = {
                "schema": proof_schema,
                "bundle_receipt_name": receipt_file.name,
                "database_sha256": str(database_restore["sha256"]),
                "database_logical_snapshot_schema": str(
                    database_restore["logical_snapshot_schema"]
                ),
                "database_logical_snapshot_sha256": str(
                    database_restore["logical_snapshot_sha256"]
                ),
                "capture_sha256": str(capture_verification["sha256"]),
                "capture_manifest_sha256": str(
                    capture_verification["manifest_sha256"]
                ),
                "capture_file_count": int(capture_verification["file_count"]),
                "ledger_capture_count": len(ledger_ids),
                "transport_receipt_capture_count": len(receipt_ids),
                "processed_capture_count": len(processed_ids),
                "missing_transport_ledger_count": 0,
                "capture_ledger_binding": restored_binding_proof,
                "capture_pending_state": restored_pending_state,
                "reconciliation": dict(
                    capture_verification["manifest"]["reconciliation"]
                ),
                "cutover_ready": bool(restored_binding_proof["verified"])
                and restored_pending_state.get("pending_file_count") == 0
                and not bool(
                    capture_verification["manifest"]["reconciliation"][
                        "replay_required_file_count"
                    ]
                )
                # Restored proofs mirror verification: incomplete media
                # recovery keeps the proof inspectable but never cutover-ready.
                and media_recovery_complete
                and (
                    verified["governance_mode"] == "pre-governed-v5"
                    or (
                        request_journal_restore is not None
                        and request_journal_binding_restore is not None
                        and request_journal_restore_binding is not None
                        and runtime_state_restore is not None
                    )
                ),
                "governance_mode": str(verified["governance_mode"]),
                "store_identity": str(verified["store_identity"]),
                "store_generation": str(verified["store_generation"]),
                "authority_epoch_number": verified["database"][
                    "authority_epoch_number"
                ],
                "request_journal_id": (
                    None
                    if request_journal_restore is None
                    else str(verified["request_journal"]["journal_id"])
                ),
                "request_journal_schema_identity": (
                    None
                    if request_journal_restore is None
                    else str(verified["request_journal"]["schema_identity"])
                ),
                "request_journal_sha256": (
                    None
                    if request_journal_restore is None
                    else str(request_journal_restore["sha256"])
                ),
                "request_journal_binding_receipt_digest": (
                    None
                    if request_journal_restore_binding is None
                    else str(request_journal_restore_binding["receipt_digest"])
                ),
                "source_request_journal_binding_receipt_digest": (
                    None
                    if request_journal_binding_payload is None
                    else str(request_journal_binding_payload["receipt_digest"])
                ),
                "request_journal_logical_snapshot_schema": (
                    None
                    if request_journal_restore is None
                    else str(
                        verified["request_journal"]["logical_snapshot_schema"]
                    )
                ),
                "request_journal_logical_snapshot_sha256": (
                    None
                    if request_journal_restore is None
                    else str(
                        verified["request_journal"]["logical_snapshot_sha256"]
                    )
                ),
                "request_journal_artifact_relative": (
                    "core/requests.sqlite3"
                    if request_journal_restore is not None
                    else None
                ),
                "request_journal_binding_receipt_relative": (
                    "core/requests.sqlite3.binding.receipt.json"
                    if request_journal_binding_restore is not None
                    else None
                ),
                "request_journal_binding_verified": bool(
                    request_journal_restore is not None
                    and request_journal_binding_restore is not None
                    and request_journal_binding_payload is not None
                    and request_journal_restore_binding is not None
                ),
                "media_included": media_included,
                "media_recovery_complete": media_recovery_complete,
                "media_recovery": (
                    "media-archive-restored"
                    if media_included
                    else "media-not-required-zero-references"
                    if media_absent_verified
                    else "legacy-media-not-present"
                ),
                "media_reference_count": int(
                    restored_media_references["reference_count"]
                ),
                "media_artifact_relative": (
                    "media-cache" if media_included else None
                ),
                "media_sha256": (
                    str(media_verification["sha256"])
                    if media_verification is not None
                    else None
                ),
                "media_manifest_sha256": (
                    str(media_verification["manifest_sha256"])
                    if media_verification is not None
                    else None
                ),
                "media_object_count": (
                    int(media_verification["object_count"])
                    if media_verification is not None
                    else 0
                    if media_absent_verified
                    else None
                ),
                "media_file_count": (
                    int(media_verification["file_count"])
                    if media_verification is not None
                    else 0
                    if media_absent_verified
                    else None
                ),
                "media_orphan_count": (
                    int(media_verification["orphan_count"])
                    if media_verification is not None
                    else int(receipt["media_orphan_count"])
                    if media_absent_verified
                    else None
                ),
                "runtime_state_required": bool(
                    receipt.get("runtime_state_required")
                ),
                "runtime_state_present": runtime_state_restore is not None,
                "runtime_state_artifact_relative": (
                    "runtime_state.json"
                    if runtime_state_restore is not None
                    else None
                ),
                "runtime_state_sha256": (
                    None
                    if runtime_state_restore is None
                    else str(runtime_state_restore["sha256"])
                ),
                "runtime_state_canonical_sha256": (
                    None
                    if runtime_state_restore is None
                    else str(runtime_state_restore["canonical_sha256"])
                ),
                "runtime_state_memory_db_path": (
                    None
                    if runtime_state_restore is None
                    else str(database_target)
                ),
                "source_runtime_state_sha256": (
                    None
                    if runtime_state_restore is None
                    else str(runtime_state_restore["source_sha256"])
                ),
                "source_runtime_state_canonical_sha256": (
                    None
                    if runtime_state_restore is None
                    else str(runtime_state_restore["source_canonical_sha256"])
                ),
                "mode": "isolated-recovery-proof",
                "verified": True,
                "created_at": time.time(),
            }
            self.store._authenticate_receipt(proof)
            proof_path = target_root / "recovery-proof.receipt.json"
            self.store._write_private_json_exclusive(proof_path, proof)
            self.store._fsync_directory(target_root)
            return {
                "action": "restore-recovery-bundle",
                "mode": "isolated-recovery-proof",
                "restore_root": str(target_root),
                "database_restore": database_restore,
                "capture_restore_path": str(capture_target),
                "media_included": media_included,
                "media_recovery_complete": media_recovery_complete,
                "media_restore_path": (
                    str(media_target) if media_target is not None else None
                ),
                "media_object_count": (
                    int(media_verification["object_count"])
                    if media_verification is not None
                    else 0
                    if media_absent_verified
                    else None
                ),
                "media_reference_count": int(
                    restored_media_references["reference_count"]
                ),
                "request_journal_restore_path": (
                    None
                    if request_journal_restore is None
                    else str(request_journal_restore["path"])
                ),
                "request_journal_binding_receipt_path": (
                    None
                    if request_journal_binding_restore is None
                    else str(request_journal_binding_restore["path"])
                ),
                "request_journal_binding": (
                    None
                    if request_journal_restore_binding is None
                    else {
                        "store_identity": str(request_journal_restore_binding["store_identity"]),
                        "store_generation": str(request_journal_restore_binding["store_generation"]),
                        "request_journal_id": str(
                            request_journal_restore_binding["request_journal_id"]
                        ),
                        "request_journal_schema_identity": str(
                            request_journal_restore_binding[
                                "request_journal_schema_identity"
                            ]
                        ),
                        "receipt_digest": str(request_journal_restore_binding["receipt_digest"]),
                        "source_receipt_digest": str(
                            request_journal_restore_binding[
                                "source_request_journal_binding_receipt_digest"
                            ]
                        ),
                        "verified": True,
                    }
                ),
                "runtime_state_restore_path": (
                    None
                    if runtime_state_restore is None
                    else str(runtime_state_restore["path"])
                ),
                "recovery_proof_path": str(proof_path),
                "capture_file_count": int(capture_verification["file_count"]),
                "missing_transport_ledger_count": 0,
                "capture_ledger_binding": restored_binding_proof,
                "capture_pending_state": dict(
                    proof["capture_pending_state"]
                ),
                "reconciliation": dict(
                    capture_verification["manifest"]["reconciliation"]
                ),
                "cutover_ready": bool(proof["cutover_ready"]),
                "verified": True,
            }
        except BaseException:
            shutil.rmtree(target_root, ignore_errors=True)
            raise
        finally:
            verified_capture_snapshot.unlink(missing_ok=True)
            if verified_media_snapshot is not None:
                verified_media_snapshot.unlink(missing_ok=True)
            self.store._fsync_directory(verified_capture_snapshot.parent)

    def _retention_directory(
        self,
        directory: str | os.PathLike[str] | None,
    ) -> Path:
        store_root = self.store.db_path.parent.expanduser().resolve()
        if directory is None:
            target = store_root / "backups" / "verified"
            self.store._ensure_directory(target, owned=True)
        else:
            reject_sensitive_identifier(directory, field="recovery retention directory")
            target = Path(directory).expanduser().absolute()
        resolved = target.resolve()
        try:
            resolved.relative_to(store_root)
        except ValueError as exc:
            raise ValueError(
                "recovery retention directory must stay within the memory-store root"
            ) from exc
        metadata = os.lstat(resolved)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise PermissionError(
                "recovery retention directory must be private, user-owned, and non-symlinked"
            )
        return resolved

    @staticmethod
    def _validate_retention_policy(
        *,
        keep_latest: int,
        max_age_days: float,
    ) -> tuple[int, float]:
        if isinstance(keep_latest, bool) or int(keep_latest) != keep_latest:
            raise ValueError("keep_latest must be an integer")
        bounded_keep = int(keep_latest)
        bounded_age = float(max_age_days)
        if (
            bounded_keep < 1
            or bounded_keep > 10_000
            or not math.isfinite(bounded_age)
            or bounded_age < 0
            or bounded_age > 36_500
        ):
            raise ValueError("recovery retention policy is outside its safe bounds")
        return bounded_keep, bounded_age

    def _retention_bundle_record(
        self,
        receipt_path: Path,
    ) -> dict[str, Any]:
        receipt, _identity_trusted = self._read_bundle_receipt(receipt_path)
        verified = self.verify_bundle(receipt_path)
        artifact_names_list = [
            str(receipt["database_artifact_name"]),
            str(receipt["database_receipt_name"]),
            str(receipt["capture_artifact_name"]),
        ]
        if bool(receipt.get("media_included")):
            artifact_names_list.append(str(receipt["media_artifact_name"]))
        if bool(receipt.get("request_journal_required")):
            artifact_names_list.extend(
                (
                    str(receipt["request_journal_artifact_name"]),
                    str(receipt["request_journal_binding_receipt_name"]),
                )
            )
        if bool(receipt.get("runtime_state_required")):
            artifact_names_list.append(str(receipt["runtime_state_artifact_name"]))
        artifact_names_list.append(receipt_path.name)
        artifact_names = tuple(artifact_names_list)
        if len(set(artifact_names)) != len(artifact_names):
            raise RuntimeError("recovery bundle contains overlapping artifact names")
        artifacts: list[dict[str, Any]] = []
        for name in artifact_names:
            safe_name = self.store._validate_backup_artifact_name(
                name,
                field="retention artifact name",
            )
            artifact_path = receipt_path.parent / safe_name
            digest, size_bytes, metadata = self.store._hash_stable_regular_file(
                artifact_path
            )
            if (
                metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or int(metadata.st_nlink) != 1
            ):
                raise PermissionError("recovery retention artifact is not private")
            artifacts.append(
                {
                    "name": safe_name,
                    "sha256": digest,
                    "size_bytes": size_bytes,
                    "device": int(metadata.st_dev),
                    "inode": int(metadata.st_ino),
                    "uid": int(metadata.st_uid),
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "link_count": int(metadata.st_nlink),
                    "mtime_ns": int(metadata.st_mtime_ns),
                    "ctime_ns": int(metadata.st_ctime_ns),
                }
            )
        return {
            "bundle_id": str(receipt["receipt_digest"]),
            "auth_key_id": str(receipt["auth_key_id"]),
            "bundle_receipt_name": receipt_path.name,
            "created_at": float(receipt["created_at"]),
            "pinned": bool(receipt["pinned"]),
            "cutover_ready": bool(verified["cutover_ready"]),
            "replay_required_file_count": int(
                verified["reconciliation"]["replay_required_file_count"]
            ),
            "artifacts": artifacts,
        }

    def _build_retention_plan(
        self,
        *,
        directory: Path,
        keep_latest: int,
        max_age_days: float,
        evaluation_time: float,
    ) -> dict[str, Any]:
        cutoff_created_at = evaluation_time - (max_age_days * 86_400.0)
        bundles: list[dict[str, Any]] = []
        blocked_receipts: list[dict[str, str]] = []
        for receipt_path in sorted(directory.glob("*.bundle.receipt.json")):
            try:
                bundles.append(self._retention_bundle_record(receipt_path))
            except (OSError, ValueError, RuntimeError, PermissionError) as exc:
                blocked_receipts.append(
                    {
                        "name": receipt_path.name,
                        "error_type": type(exc).__name__,
                    }
                )
        bundles.sort(
            key=lambda item: (
                -float(item["created_at"]),
                str(item["bundle_id"]),
                str(item["bundle_receipt_name"]).encode("utf-8"),
            )
        )
        claimed_names: set[str] = set()
        overlapping_names: set[str] = set()
        claimed_inodes: set[tuple[int, int]] = set()
        overlapping_inodes: set[str] = set()
        normalized_names: dict[str, str] = {}
        colliding_names: set[str] = set()
        for bundle in bundles:
            for artifact in bundle["artifacts"]:
                name = str(artifact["name"])
                if name in claimed_names:
                    overlapping_names.add(name)
                claimed_names.add(name)
                inode_key = (int(artifact["device"]), int(artifact["inode"]))
                if inode_key in claimed_inodes:
                    overlapping_inodes.add(name)
                claimed_inodes.add(inode_key)
                normalized = unicodedata.normalize("NFC", name).casefold()
                prior_name = normalized_names.get(normalized)
                if prior_name is not None and prior_name != name:
                    colliding_names.update({prior_name, name})
                normalized_names[normalized] = name
        recognized_candidates = [
            candidate
            for candidate in directory.iterdir()
            if (
                candidate.name.endswith(".sqlite3")
                or candidate.name.endswith(".sqlite3.receipt.json")
                or candidate.name.endswith(".sqlite3.capture.tar.gz")
                or candidate.name.endswith(".sqlite3.media.tar.gz")
                or candidate.name.endswith(".sqlite3.requests.sqlite3")
                or candidate.name.endswith(
                    ".sqlite3.requests.binding.receipt.json"
                )
                or candidate.name.endswith(".sqlite3.runtime-state.json")
                or candidate.name.endswith(".sqlite3.bundle.receipt.json")
            )
        ]
        recognized_names = {candidate.name for candidate in recognized_candidates}
        ambiguous_names = sorted(
            candidate.name
            for candidate in recognized_candidates
            if candidate.is_symlink()
            or not stat.S_ISREG(os.lstat(candidate).st_mode)
            or int(os.lstat(candidate).st_nlink) != 1
        )
        orphan_names = sorted(recognized_names - claimed_names)
        planned_bundles: list[dict[str, Any]] = []
        newest_cutover_ready_id = next(
            (
                str(bundle["bundle_id"])
                for bundle in bundles
                if bool(bundle["cutover_ready"])
            ),
            "",
        )
        for index, bundle in enumerate(bundles):
            reasons: list[str] = []
            if index == 0:
                reasons.append("latest-verified")
            if index < keep_latest:
                reasons.append("within-keep-latest")
            if bool(bundle["pinned"]):
                reasons.append("pinned")
            if str(bundle["bundle_id"]) == newest_cutover_ready_id:
                reasons.append("newest-cutover-ready")
            if float(bundle["created_at"]) > cutoff_created_at:
                reasons.append("within-max-age")
            disposition = "protect" if reasons else "retire"
            planned_bundles.append(
                {
                    **bundle,
                    "disposition": disposition,
                    "protection_reasons": sorted(set(reasons)),
                }
            )
        repository_metadata = os.lstat(directory)
        ttl_seconds = int(
            os.getenv("SYNAPSE_S2_RETENTION_PLAN_TTL_SECONDS", "3600")
        )
        if ttl_seconds < 60 or ttl_seconds > 86_400:
            raise ValueError(
                "SYNAPSE_S2_RETENTION_PLAN_TTL_SECONDS must be between 60 and 86400"
            )
        plan_seed = {
            "schema": RECOVERY_RETENTION_PLAN_SCHEMA,
            "directory": str(directory.relative_to(self.store.db_path.parent.resolve())),
            "repository_identity": {
                "device": int(repository_metadata.st_dev),
                "inode": int(repository_metadata.st_ino),
                "uid": int(repository_metadata.st_uid),
                "mode": stat.S_IMODE(repository_metadata.st_mode),
            },
            "keep_latest": keep_latest,
            "max_age_days": max_age_days,
            "cutoff_created_at": cutoff_created_at,
            "evaluation_time": evaluation_time,
            "expires_at": evaluation_time + ttl_seconds,
            "bundles": planned_bundles,
            "blocked_receipts": blocked_receipts,
            "orphan_artifact_names": orphan_names,
            "overlapping_artifact_names": sorted(overlapping_names),
            "overlapping_inode_artifact_names": sorted(overlapping_inodes),
            "colliding_artifact_names": sorted(colliding_names),
            "ambiguous_artifact_names": ambiguous_names,
        }
        decision_digest = hashlib.sha256(
            _json_dumps(plan_seed).encode("utf-8")
        ).hexdigest()
        return {
            **plan_seed,
            "decision_digest": decision_digest,
            "verified_bundle_count": len(planned_bundles),
            "protected_bundle_count": sum(
                bundle["disposition"] == "protect" for bundle in planned_bundles
            ),
            "retire_bundle_count": sum(
                bundle["disposition"] == "retire" for bundle in planned_bundles
            ),
            "blocked_receipt_count": len(blocked_receipts),
            "orphan_artifact_count": len(orphan_names),
            "apply_permitted": not bool(
                blocked_receipts
                or orphan_names
                or overlapping_names
                or overlapping_inodes
                or colliding_names
                or ambiguous_names
            ),
            "generated_at": evaluation_time,
        }

    def _retention_plan_root(self) -> Path:
        root = self.store.db_path.parent / "backups" / "retention-plans"
        self.store._ensure_directory(root, owned=True)
        return root

    def _retirement_journal_root(self) -> Path:
        root = self.store.db_path.parent / "backups" / "retirement-journals"
        self.store._ensure_directory(root, owned=True)
        return root

    def _read_retention_plan(self, plan_token: str) -> dict[str, Any]:
        path = self._retention_plan_root() / f"{plan_token}.receipt.json"
        data, metadata = self._read_private_regular(path, max_bytes=16 * 1024**2)
        if (
            metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or int(metadata.st_nlink) != 1
        ):
            raise PermissionError("recovery retention plan receipt is not private")
        try:
            plan = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("recovery retention plan receipt is invalid JSON") from exc
        expected_keys = {
            "action",
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
            "decision_digest",
            "verified_bundle_count",
            "protected_bundle_count",
            "retire_bundle_count",
            "blocked_receipt_count",
            "orphan_artifact_count",
            "apply_permitted",
            "generated_at",
            "auth_algorithm",
            "auth_key_id",
            "signing_public_key",
            "receipt_digest",
            "receipt_signature",
        }
        if (
            not isinstance(plan, dict)
            or set(plan) != expected_keys
            or plan.get("schema") != RECOVERY_RETENTION_PLAN_SCHEMA
            or plan.get("action") != "plan-recovery-retention"
            or not secrets.compare_digest(
                str(plan.get("receipt_digest") or ""), plan_token
            )
            or not secrets.compare_digest(
                str(plan.get("receipt_digest") or ""),
                self.store._canonical_payload_digest(plan),
            )
        ):
            raise ValueError("recovery retention plan receipt is invalid")
        if not self.store._verify_receipt_authenticator(plan):
            raise ValueError("recovery retention plan signer is not trusted locally")
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
        decision = hashlib.sha256(
            _json_dumps({key: plan[key] for key in seed_keys}).encode("utf-8")
        ).hexdigest()
        if not secrets.compare_digest(decision, str(plan["decision_digest"])):
            raise ValueError("recovery retention decision digest is invalid")
        plan["plan_receipt_path"] = str(path)
        plan["plan_token"] = plan_token
        return plan

    def _read_retirement_receipt(
        self,
        path: Path,
        *,
        expected_state: str,
    ) -> dict[str, Any]:
        data, metadata = self._read_private_regular(path, max_bytes=32 * 1024**2)
        if (
            metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or int(metadata.st_nlink) != 1
        ):
            raise PermissionError("recovery retirement receipt is not private")
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("recovery retirement receipt is invalid JSON") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != RECOVERY_RETIREMENT_RECEIPT_SCHEMA
            or payload.get("state") != expected_state
            or not secrets.compare_digest(
                str(payload.get("receipt_digest") or ""),
                self.store._canonical_payload_digest(payload),
            )
        ):
            raise ValueError("recovery retirement receipt is invalid")
        if not self.store._verify_receipt_authenticator(payload):
            raise ValueError("recovery retirement signer is not trusted locally")
        return payload

    def _artifact_matches_retention_record(
        self,
        path: Path,
        record: dict[str, Any],
        *,
        require_planned_identity: bool,
    ) -> None:
        digest, size_bytes, metadata = self.store._hash_stable_regular_file(path)
        if (
            not secrets.compare_digest(digest, str(record["sha256"]))
            or size_bytes != int(record["size_bytes"])
            or metadata.st_uid != int(record["uid"])
            or stat.S_IMODE(metadata.st_mode) != int(record["mode"])
            or int(metadata.st_nlink) != 1
            or (
                require_planned_identity
                and (
                    int(metadata.st_dev) != int(record["device"])
                    or int(metadata.st_ino) != int(record["inode"])
                    or int(metadata.st_mtime_ns) != int(record["mtime_ns"])
                    or int(metadata.st_ctime_ns) != int(record["ctime_ns"])
                )
            )
        ):
            raise RuntimeError("recovery retention artifact identity changed")

    def _verify_retirement_artifacts_locked(
        self,
        completed: dict[str, Any],
        *,
        location: str,
    ) -> None:
        if location not in {"source", "destination"}:
            raise ValueError("recovery retirement verification location is invalid")
        moves = completed.get("moves")
        if not isinstance(moves, list):
            raise RuntimeError("recovery retirement receipt has invalid moves")
        if not moves:
            return
        store_root = self.store.db_path.parent.resolve()
        bundle_receipts: dict[str, Path] = {}
        for move in moves:
            if not isinstance(move, dict) or not isinstance(move.get("artifact"), dict):
                raise RuntimeError("recovery retirement move is invalid")
            path = store_root / str(move[f"{location}_relative"])
            self._artifact_matches_retention_record(
                path,
                move["artifact"],
                require_planned_identity=False,
            )
            bundle_id = str(move.get("bundle_id") or "")
            receipt_name = str(move.get("bundle_receipt_name") or "")
            if not bundle_id or not receipt_name:
                raise RuntimeError("recovery retirement bundle identity is invalid")
            if str(move["artifact"].get("name")) == receipt_name:
                bundle_receipts[bundle_id] = path
        expected_bundle_count = int(completed.get("retired_bundle_count") or 0)
        if len(bundle_receipts) != expected_bundle_count:
            raise RuntimeError("recovery retirement bundle receipt set is incomplete")
        for receipt_path in bundle_receipts.values():
            self._verify_bundle_locked(receipt_path)

    def _recover_incomplete_retirements_locked(self) -> None:
        journal_root = self._retirement_journal_root()
        store_root = self.store.db_path.parent.resolve()
        for prepared_path in sorted(journal_root.glob("*.prepared.receipt.json")):
            token = prepared_path.name.removesuffix(".prepared.receipt.json")
            completed_path = journal_root / f"{token}.completed.receipt.json"
            restored_path = journal_root / f"{token}.restored.receipt.json"
            recovered_path = journal_root / f"{token}.recovered.receipt.json"
            if completed_path.exists() or restored_path.exists() or recovered_path.exists():
                continue
            prepared = self._read_retirement_receipt(
                prepared_path,
                expected_state="prepared",
            )
            moves = prepared.get("moves")
            if not isinstance(moves, list):
                raise RuntimeError("incomplete recovery retirement journal is malformed")
            for move in reversed(moves):
                source = store_root / str(move["source_relative"])
                destination = store_root / str(move["destination_relative"])
                source_exists = source.exists() or source.is_symlink()
                destination_exists = destination.exists() or destination.is_symlink()
                if source_exists and destination_exists:
                    raise RuntimeError(
                        "incomplete recovery retirement has conflicting source and destination"
                    )
                if not source_exists and not destination_exists:
                    raise RuntimeError(
                        "incomplete recovery retirement is missing both artifact copies"
                    )
                if destination_exists:
                    self._artifact_matches_retention_record(
                        destination,
                        move["artifact"],
                        require_planned_identity=False,
                    )
                    os.rename(destination, source)
                    self.store._fsync_directory(destination.parent)
                    self.store._fsync_directory(source.parent)
                else:
                    self._artifact_matches_retention_record(
                        source,
                        move["artifact"],
                        require_planned_identity=False,
                    )
            quarantine_relative = prepared.get("quarantine_relative")
            if isinstance(quarantine_relative, str) and quarantine_relative:
                quarantine = store_root / quarantine_relative
                if quarantine.is_dir() and not quarantine.is_symlink():
                    bundle_directories = {
                        quarantine / str(move["bundle_id"])
                        for move in moves
                        if isinstance(move, dict) and move.get("bundle_id")
                    }
                    for bundle_directory in bundle_directories:
                        if (
                            bundle_directory.is_dir()
                            and not bundle_directory.is_symlink()
                            and not any(bundle_directory.iterdir())
                        ):
                            os.rmdir(bundle_directory)
                    if not any(quarantine.iterdir()):
                        os.rmdir(quarantine)
                        self.store._fsync_directory(quarantine.parent)
            recovered = {
                "schema": RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
                "state": "recovered",
                "plan_token": token,
                "prepared_receipt_digest": str(prepared["receipt_digest"]),
                "move_count": len(moves),
                "recoverable": True,
                "created_at": time.time(),
            }
            self.store._authenticate_receipt(recovered)
            self.store._write_private_json_exclusive(recovered_path, recovered)

        for prepared_path in sorted(
            journal_root.glob("*.restore-prepared.receipt.json")
        ):
            token = prepared_path.name.removesuffix(
                ".restore-prepared.receipt.json"
            )
            restored_path = journal_root / f"{token}.restored.receipt.json"
            recovered_path = journal_root / (
                f"{token}.restore-recovered.receipt.json"
            )
            if restored_path.exists() or recovered_path.exists():
                continue
            prepared = self._read_retirement_receipt(
                prepared_path,
                expected_state="restore-prepared",
            )
            moves = prepared.get("moves")
            if not isinstance(moves, list) or not moves:
                raise RuntimeError("incomplete recovery restore journal is malformed")
            for move in reversed(moves):
                source = store_root / str(move["source_relative"])
                destination = store_root / str(move["destination_relative"])
                source_exists = source.exists() or source.is_symlink()
                destination_exists = destination.exists() or destination.is_symlink()
                if source_exists and destination_exists:
                    raise RuntimeError(
                        "incomplete recovery restore has conflicting source and destination"
                    )
                if not source_exists and not destination_exists:
                    raise RuntimeError(
                        "incomplete recovery restore is missing both artifact copies"
                    )
                if source_exists:
                    self._artifact_matches_retention_record(
                        source,
                        move["artifact"],
                        require_planned_identity=False,
                    )
                    os.rename(source, destination)
                    self.store._fsync_directory(source.parent)
                    self.store._fsync_directory(destination.parent)
                else:
                    self._artifact_matches_retention_record(
                        destination,
                        move["artifact"],
                        require_planned_identity=False,
                    )
            recovered = {
                "schema": RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
                "state": "restore-recovered",
                "plan_token": token,
                "restore_prepared_receipt_digest": str(
                    prepared["receipt_digest"]
                ),
                "move_count": len(moves),
                "recoverable": True,
                "created_at": time.time(),
            }
            self.store._authenticate_receipt(recovered)
            self.store._write_private_json_exclusive(recovered_path, recovered)

    def plan_retention(
        self,
        directory: str | os.PathLike[str] | None = None,
        *,
        keep_latest: int = 7,
        max_age_days: float = 30.0,
        evaluation_time: float | None = None,
    ) -> dict[str, Any]:
        with self._repository_lock():
            return self._plan_retention_locked(
                directory,
                keep_latest=keep_latest,
                max_age_days=max_age_days,
                evaluation_time=evaluation_time,
            )

    def _plan_retention_locked(
        self,
        directory: str | os.PathLike[str] | None = None,
        *,
        keep_latest: int = 7,
        max_age_days: float = 30.0,
        evaluation_time: float | None = None,
    ) -> dict[str, Any]:
        bounded_keep, bounded_age = self._validate_retention_policy(
            keep_latest=keep_latest,
            max_age_days=max_age_days,
        )
        now = time.time() if evaluation_time is None else float(evaluation_time)
        if not math.isfinite(now) or now <= 0:
            raise ValueError("retention evaluation time must be a finite timestamp")
        self._recover_incomplete_retirements_locked()
        target = self._retention_directory(directory)
        plan = self._build_retention_plan(
            directory=target,
            keep_latest=bounded_keep,
            max_age_days=bounded_age,
            evaluation_time=now,
        )
        plan = {"action": "plan-recovery-retention", **plan}
        self.store._authenticate_receipt(plan)
        plan_token = str(plan["receipt_digest"])
        plan_path = self._retention_plan_root() / f"{plan_token}.receipt.json"
        if plan_path.exists() or plan_path.is_symlink():
            existing = self._read_retention_plan(plan_token)
            return existing
        self.store._write_private_json_exclusive(plan_path, plan)
        return {
            **plan,
            "plan_token": plan_token,
            "plan_receipt_path": str(plan_path),
        }

    def apply_retention(
        self,
        *,
        plan_token: str,
        cutoff_created_at: float,
        directory: str | os.PathLike[str] | None = None,
        keep_latest: int = 7,
        max_age_days: float = 30.0,
        confirm: bool = False,
    ) -> dict[str, Any]:
        with self._repository_lock():
            return self._apply_retention_locked(
                plan_token=plan_token,
                cutoff_created_at=cutoff_created_at,
                directory=directory,
                keep_latest=keep_latest,
                max_age_days=max_age_days,
                confirm=confirm,
            )

    def _apply_retention_locked(
        self,
        *,
        plan_token: str,
        cutoff_created_at: float,
        directory: str | os.PathLike[str] | None = None,
        keep_latest: int = 7,
        max_age_days: float = 30.0,
        confirm: bool = False,
    ) -> dict[str, Any]:
        if not confirm:
            raise ValueError("confirm=true is required to retire recovery bundles")
        token = str(plan_token or "").strip().lower()
        if BACKUP_DIGEST_RE.fullmatch(token) is None:
            raise ValueError("recovery retention plan token is invalid")
        self._recover_incomplete_retirements_locked()
        journal_root = self._retirement_journal_root()
        completion_path = journal_root / f"{token}.completed.receipt.json"
        restored_path = journal_root / f"{token}.restored.receipt.json"
        recovered_path = journal_root / f"{token}.recovered.receipt.json"
        if restored_path.exists():
            restored = self._read_retirement_receipt(
                restored_path,
                expected_state="restored",
            )
            completed = self._read_retirement_receipt(
                completion_path,
                expected_state="completed",
            )
            self._verify_retirement_artifacts_locked(
                completed,
                location="source",
            )
            return {
                "action": "apply-recovery-retention",
                "plan_token": token,
                "state": "already-restored",
                "retired_bundle_count": 0,
                "retired_artifact_count": 0,
                "restoration_receipt_path": str(restored_path),
                "recoverable": True,
                "verified": True,
                "created_at": float(restored["created_at"]),
            }
        if completion_path.exists():
            completed = self._read_retirement_receipt(
                completion_path,
                expected_state="completed",
            )
            self._verify_retirement_artifacts_locked(
                completed,
                location="destination",
            )
            quarantine_relative = completed.get("quarantine_relative")
            quarantine_path = (
                str(
                    self.store.db_path.parent.resolve()
                    / str(quarantine_relative)
                )
                if quarantine_relative is not None
                else None
            )
            return {
                "action": "apply-recovery-retention",
                "plan_token": token,
                "state": "already-completed",
                "retired_bundle_count": int(completed["retired_bundle_count"]),
                "retired_artifact_count": int(completed["retired_artifact_count"]),
                "quarantine_path": quarantine_path,
                "completion_receipt_path": str(completion_path),
                "recoverable": True,
                "verified": True,
                "created_at": float(completed["created_at"]),
            }
        if recovered_path.exists():
            raise RuntimeError(
                "recovery retention plan was rolled back; create a fresh signed plan"
            )
        signed_plan = self._read_retention_plan(token)
        bounded_keep, bounded_age = self._validate_retention_policy(
            keep_latest=keep_latest,
            max_age_days=max_age_days,
        )
        cutoff = float(cutoff_created_at)
        if not math.isfinite(cutoff) or cutoff <= 0:
            raise ValueError("retention cutoff must be a finite timestamp")
        target = self._retention_directory(directory)
        expected_directory = str(
            target.relative_to(self.store.db_path.parent.resolve())
        )
        if (
            int(signed_plan["keep_latest"]) != bounded_keep
            or float(signed_plan["max_age_days"]) != bounded_age
            or float(signed_plan["cutoff_created_at"]) != cutoff
            or str(signed_plan["directory"]) != expected_directory
        ):
            raise ValueError("recovery retention apply policy does not match its signed plan")
        if time.time() > float(signed_plan["expires_at"]):
            raise RuntimeError("recovery retention plan expired; create a fresh plan")
        current = self._build_retention_plan(
            directory=target,
            keep_latest=bounded_keep,
            max_age_days=bounded_age,
            evaluation_time=float(signed_plan["evaluation_time"]),
        )
        if not secrets.compare_digest(
            str(signed_plan["decision_digest"]),
            str(current["decision_digest"]),
        ):
            raise RuntimeError("recovery retention inventory changed after planning")
        if not current["apply_permitted"]:
            raise RuntimeError(
                "recovery retention is blocked by invalid, orphaned, or overlapping artifacts"
            )
        candidates = [
            bundle
            for bundle in current["bundles"]
            if bundle["disposition"] == "retire"
        ]
        if not candidates:
            completed = {
                "schema": RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
                "state": "completed",
                "plan_token": token,
                "decision_digest": str(current["decision_digest"]),
                "prepared_receipt_digest": None,
                "source_directory": expected_directory,
                "quarantine_relative": None,
                "retired_bundle_count": 0,
                "retired_artifact_count": 0,
                "moves": [],
                "recoverable": True,
                "created_at": time.time(),
            }
            self.store._authenticate_receipt(completed)
            self.store._write_private_json_exclusive(completion_path, completed)
            return {
                "action": "apply-recovery-retention",
                "plan_token": token,
                "state": "completed",
                "retired_bundle_count": 0,
                "retired_artifact_count": 0,
                "quarantine_path": None,
                "completion_receipt_path": str(completion_path),
                "recoverable": True,
                "verified": True,
                "created_at": float(completed["created_at"]),
            }
        store_root = self.store.db_path.parent.resolve()
        retirement_root = store_root / "backups" / "retired"
        self.store._ensure_directory(retirement_root, owned=True)
        if os.lstat(retirement_root).st_dev != os.lstat(target).st_dev:
            raise RuntimeError("recovery retirement quarantine must be on the same filesystem")
        quarantine = retirement_root / token
        if quarantine.exists() or quarantine.is_symlink():
            quarantine_metadata = os.lstat(quarantine)
            if (
                stat.S_ISDIR(quarantine_metadata.st_mode)
                and not stat.S_ISLNK(quarantine_metadata.st_mode)
                and quarantine_metadata.st_uid == os.getuid()
                and not (stat.S_IMODE(quarantine_metadata.st_mode) & 0o077)
                and not any(quarantine.iterdir())
                and not (journal_root / f"{token}.prepared.receipt.json").exists()
            ):
                os.rmdir(quarantine)
                self.store._fsync_directory(retirement_root)
            else:
                raise FileExistsError(
                    "recovery retirement quarantine already exists"
                )
        moves: list[dict[str, Any]] = []
        for bundle in candidates:
            bundle_directory = quarantine / str(bundle["bundle_id"])
            ordered_artifacts = sorted(
                bundle["artifacts"],
                key=lambda artifact: (
                    str(artifact["name"]) == str(bundle["bundle_receipt_name"]),
                    str(artifact["name"]).encode("utf-8"),
                ),
            )
            for artifact in ordered_artifacts:
                moves.append(
                    {
                        "bundle_id": str(bundle["bundle_id"]),
                        "bundle_receipt_name": str(bundle["bundle_receipt_name"]),
                        "source_relative": str(
                            (target / str(artifact["name"])).relative_to(store_root)
                        ),
                        "destination_relative": str(
                            (bundle_directory / str(artifact["name"])).relative_to(
                                store_root
                            )
                        ),
                        "artifact": artifact,
                    }
                )
        moved: list[tuple[Path, Path, dict[str, Any]]] = []
        prepared_path = journal_root / f"{token}.prepared.receipt.json"
        try:
            prepared = {
                "schema": RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
                "state": "prepared",
                "plan_token": token,
                "decision_digest": str(current["decision_digest"]),
                "source_directory": expected_directory,
                "quarantine_relative": str(quarantine.relative_to(store_root)),
                "bundle_count": len(candidates),
                "artifact_count": len(moves),
                "moves": moves,
                "created_at": time.time(),
            }
            self.store._authenticate_receipt(prepared)
            self.store._write_private_json_exclusive(
                prepared_path,
                prepared,
            )
            os.mkdir(quarantine, mode=0o700)
            self.store._fsync_directory(retirement_root)
            for bundle in candidates:
                os.mkdir(
                    quarantine / str(bundle["bundle_id"]),
                    mode=0o700,
                )
            self.store._fsync_directory(quarantine)
            for move in moves:
                source = store_root / str(move["source_relative"])
                destination = store_root / str(move["destination_relative"])
                if destination.exists() or destination.is_symlink():
                    raise FileExistsError(
                        "recovery retirement quarantine artifact already exists"
                    )
                self._artifact_matches_retention_record(
                    source,
                    move["artifact"],
                    require_planned_identity=True,
                )
                os.rename(source, destination)
                moved.append((source, destination, move["artifact"]))
                self.store._fsync_directory(source.parent)
                self.store._fsync_directory(destination.parent)
            for bundle in candidates:
                bundle_directory = quarantine / str(bundle["bundle_id"])
                self.verify_bundle(
                    bundle_directory / str(bundle["bundle_receipt_name"])
                )
            completed = {
                "schema": RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
                "state": "completed",
                "plan_token": token,
                "decision_digest": str(current["decision_digest"]),
                "prepared_receipt_digest": str(prepared["receipt_digest"]),
                "source_directory": expected_directory,
                "quarantine_relative": str(quarantine.relative_to(store_root)),
                "retired_bundle_count": len(candidates),
                "retired_artifact_count": len(moved),
                "moves": moves,
                "recoverable": True,
                "created_at": time.time(),
            }
            self.store._authenticate_receipt(completed)
            self.store._write_private_json_exclusive(completion_path, completed)
            return {
                "action": "apply-recovery-retention",
                "plan_token": token,
                "state": "completed",
                "retired_bundle_count": len(candidates),
                "retired_artifact_count": len(moved),
                "quarantine_path": str(quarantine),
                "completion_receipt_path": str(completion_path),
                "recoverable": True,
                "verified": True,
                "created_at": time.time(),
            }
        except BaseException:
            rollback_failed = False
            for source, destination, _artifact in reversed(moved):
                try:
                    if source.exists() or source.is_symlink():
                        rollback_failed = True
                        continue
                    if destination.exists() and not destination.is_symlink():
                        self._artifact_matches_retention_record(
                            destination,
                            _artifact,
                            require_planned_identity=False,
                        )
                        os.rename(destination, source)
                        self.store._fsync_directory(destination.parent)
                        self.store._fsync_directory(source.parent)
                    else:
                        rollback_failed = True
                except (OSError, ValueError, RuntimeError):
                    rollback_failed = True
            self.store._fsync_directory(target)
            if quarantine.is_dir() and not quarantine.is_symlink():
                self.store._fsync_directory(quarantine)
            if rollback_failed:
                raise RuntimeError(
                    "recovery retirement failed and rollback is incomplete; inspect quarantine"
                )
            if quarantine.is_dir() and not quarantine.is_symlink():
                for bundle in candidates:
                    bundle_directory = quarantine / str(bundle["bundle_id"])
                    if bundle_directory.is_dir() and not any(bundle_directory.iterdir()):
                        os.rmdir(bundle_directory)
                if not any(quarantine.iterdir()):
                    os.rmdir(quarantine)
                    self.store._fsync_directory(retirement_root)
            recovered = {
                "schema": RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
                "state": "recovered",
                "plan_token": token,
                "prepared_receipt_digest": str(prepared["receipt_digest"]),
                "move_count": len(moved),
                "recoverable": True,
                "created_at": time.time(),
            }
            self.store._authenticate_receipt(recovered)
            if not recovered_path.exists():
                self.store._write_private_json_exclusive(recovered_path, recovered)
            raise

    def restore_retired(
        self,
        *,
        plan_token: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        with self._repository_lock():
            return self._restore_retired_locked(
                plan_token=plan_token,
                confirm=confirm,
            )

    def _restore_retired_locked(
        self,
        *,
        plan_token: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        if not confirm:
            raise ValueError("confirm=true is required to restore retired recovery bundles")
        token = str(plan_token or "").strip().lower()
        if BACKUP_DIGEST_RE.fullmatch(token) is None:
            raise ValueError("recovery retirement plan token is invalid")
        self._recover_incomplete_retirements_locked()
        journal_root = self._retirement_journal_root()
        completion_path = journal_root / f"{token}.completed.receipt.json"
        restored_path = journal_root / f"{token}.restored.receipt.json"
        restore_prepared_path = journal_root / (
            f"{token}.restore-prepared.receipt.json"
        )
        if restored_path.exists():
            restored = self._read_retirement_receipt(
                restored_path,
                expected_state="restored",
            )
            completed = self._read_retirement_receipt(
                completion_path,
                expected_state="completed",
            )
            self._verify_retirement_artifacts_locked(
                completed,
                location="source",
            )
            return {
                "action": "restore-retired-recovery",
                "plan_token": token,
                "state": "already-restored",
                "restored_bundle_count": int(restored["restored_bundle_count"]),
                "restored_artifact_count": int(restored["restored_artifact_count"]),
                "restoration_receipt_path": str(restored_path),
                "verified": True,
                "created_at": float(restored["created_at"]),
            }
        completed = self._read_retirement_receipt(
            completion_path,
            expected_state="completed",
        )
        moves = completed.get("moves")
        if not isinstance(moves, list) or not moves:
            raise RuntimeError("retirement receipt contains no recoverable bundle moves")
        store_root = self.store.db_path.parent.resolve()
        for move in moves:
            source = store_root / str(move["source_relative"])
            destination = store_root / str(move["destination_relative"])
            if source.exists() or source.is_symlink():
                raise FileExistsError(
                    "recovery retirement restore would overwrite a source artifact"
                )
            self._artifact_matches_retention_record(
                destination,
                move["artifact"],
                require_planned_identity=False,
            )
        restore_prepared = {
            "schema": RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
            "state": "restore-prepared",
            "plan_token": token,
            "completion_receipt_digest": str(completed["receipt_digest"]),
            "move_count": len(moves),
            "moves": moves,
            "created_at": time.time(),
        }
        if restore_prepared_path.exists():
            persisted_restore_prepared = self._read_retirement_receipt(
                restore_prepared_path,
                expected_state="restore-prepared",
            )
            restore_recovered_path = journal_root / (
                f"{token}.restore-recovered.receipt.json"
            )
            restore_recovered = self._read_retirement_receipt(
                restore_recovered_path,
                expected_state="restore-recovered",
            )
            if (
                not secrets.compare_digest(
                    str(persisted_restore_prepared.get("completion_receipt_digest")),
                    str(completed["receipt_digest"]),
                )
                or persisted_restore_prepared.get("moves") != moves
                or not secrets.compare_digest(
                    str(restore_recovered.get("restore_prepared_receipt_digest")),
                    str(persisted_restore_prepared["receipt_digest"]),
                )
            ):
                raise RuntimeError(
                    "recovered restore journal does not match the retirement receipt"
                )
            restore_prepared = persisted_restore_prepared
        else:
            self.store._authenticate_receipt(restore_prepared)
            self.store._write_private_json_exclusive(
                restore_prepared_path,
                restore_prepared,
            )
        restored_moves: list[tuple[Path, Path, dict[str, Any]]] = []
        try:
            for move in moves:
                source = store_root / str(move["source_relative"])
                destination = store_root / str(move["destination_relative"])
                if source.exists() or source.is_symlink():
                    raise FileExistsError(
                        "recovery retirement restore source changed after preflight"
                    )
                self._artifact_matches_retention_record(
                    destination,
                    move["artifact"],
                    require_planned_identity=False,
                )
                os.rename(destination, source)
                restored_moves.append((source, destination, move["artifact"]))
                self.store._fsync_directory(destination.parent)
                self.store._fsync_directory(source.parent)
            bundle_receipts = {
                str(move["bundle_id"]): str(move["bundle_receipt_name"])
                for move in moves
            }
            source_directory = store_root / str(completed["source_directory"])
            for receipt_name in bundle_receipts.values():
                self.verify_bundle(source_directory / receipt_name)
            restored = {
                "schema": RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
                "state": "restored",
                "plan_token": token,
                "completion_receipt_digest": str(completed["receipt_digest"]),
                "restore_prepared_receipt_digest": str(
                    restore_prepared["receipt_digest"]
                ),
                "restored_bundle_count": len(bundle_receipts),
                "restored_artifact_count": len(restored_moves),
                "moves": moves,
                "recoverable": True,
                "created_at": time.time(),
            }
            self.store._authenticate_receipt(restored)
            self.store._write_private_json_exclusive(restored_path, restored)
            return {
                "action": "restore-retired-recovery",
                "plan_token": token,
                "state": "restored",
                "restored_bundle_count": len(bundle_receipts),
                "restored_artifact_count": len(restored_moves),
                "restoration_receipt_path": str(restored_path),
                "verified": True,
                "created_at": float(restored["created_at"]),
            }
        except BaseException:
            rollback_failed = False
            for source, destination, artifact in reversed(restored_moves):
                try:
                    if destination.exists() or destination.is_symlink():
                        rollback_failed = True
                        continue
                    self._artifact_matches_retention_record(
                        source,
                        artifact,
                        require_planned_identity=False,
                    )
                    os.rename(source, destination)
                    self.store._fsync_directory(source.parent)
                    self.store._fsync_directory(destination.parent)
                except (OSError, ValueError, RuntimeError):
                    rollback_failed = True
            if rollback_failed:
                raise RuntimeError(
                    "retired recovery restore failed and rollback is incomplete"
                )
            raise

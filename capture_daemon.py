from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import logging
import math
import os
import re
import secrets
import shutil
import stat
import sys
import time
from pathlib import Path
from typing import Any, Iterator

import mlx_backend
from redaction import (
    SECRET_SAFE_LOG_FORMAT,
    SecretRedactingFormatter,
    SecretSafeArgumentParser,
    is_sensitive_key,
    redact_capture_text,
    redact_sensitive_value,
    reject_sensitive_identifier,
    safe_public_error,
    strip_untrusted_raw_digest_fields,
    strip_untrusted_raw_digest_text,
)


LOGGER = logging.getLogger("synapse_s2.capture_daemon")
if not LOGGER.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(SecretRedactingFormatter(SECRET_SAFE_LOG_FORMAT))
    LOGGER.addHandler(_handler)
LOGGER.setLevel(os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper())
LOGGER.propagate = False

CAPTURE_SUFFIXES = {".json", ".jsonl", ".txt"}
MAX_CAPTURE_BYTES = 256_000
STALE_EMPTY_CLAIM_SECONDS = 60.0
STALE_INBOX_TEMP_SECONDS = 300.0
CAPTURE_PROTOCOL_VERSION = 2
CAPTURE_ID_RE = re.compile(r"^s2cap_[0-9a-f]{32}$")
CLAIM_DIR_RE = re.compile(r"^s2claim_[0-9a-f]{32}$")
DETACHED_DISCARD_RE = re.compile(r"^\.s2-discard-([0-9a-f]{32})\.tmp$")
DETACHED_TREE_DISCARD_RE = re.compile(
    r"^\.s2-discard-tree-([0-9a-f]{32})\.tmp$"
)
LEGACY_INBOX_TEMP_RE = re.compile(r"^.+\.(?:json|jsonl|txt)\.tmp$", re.IGNORECASE)
ATOMIC_INBOX_TEMP_RE = re.compile(
    r"^\..+\.(?:json|jsonl|txt)\.[0-9a-f]{32}\.tmp$",
    re.IGNORECASE,
)
LEGACY_TEXT_IDENTITY_FILE = ".capture-identity.json"
PROCESSED_ARCHIVE_SCRUB_SCHEMA = "capture-processed-scrub.v1"
GLOBAL_CAPTURE_LOCK = ".capture-maintenance.lock"
ERROR_RESOLUTION_SCHEMA = "capture-error-resolution.v1"
ERROR_RESOLUTION_ARCHIVE_RE = re.compile(r"^resolved-[0-9a-f]{32}\.json$")
ERROR_RESOLUTION_MANIFEST_RE = re.compile(r"^resolution-[0-9a-f]{32}\.json$")
TERMINAL_ERROR_DISPOSITIONS = frozenset(
    {
        "discarded-without-content-inspection",
        "legacy-raw-quarantine-discarded",
        "recovered-discard-complete",
    }
)
RECOVERABLE_DISCARD_ARTIFACT_TYPES = frozenset(
    {
        "stale-capture-inbox-temp",
        "legacy-raw-stale-temp-quarantine",
        "detached-capture-discard-recovery",
        "malformed-capture-claim",
        "rejected-raw-capture-payload",
    }
)
SENSITIVE_METADATA_KEYS = {
    "api_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "token",
    "secret",
    "password",
    "authorization",
    "private_key",
}


class CaptureDeferred(RuntimeError):
    """A capture is owned by another worker and should be retried later."""


class CaptureCleanupPending(RuntimeError):
    """The backend committed, but transport cleanup must be retried."""


def resolve_capture_root(root: str | os.PathLike[str] | None = None) -> Path:
    if root is not None:
        reject_sensitive_identifier(root, field="capture_root")
        return Path(root).expanduser().resolve()
    configured = os.getenv("SYNAPSE_S2_CAPTURE_ROOT")
    if configured:
        reject_sensitive_identifier(configured, field="capture_root")
        return Path(configured).expanduser().resolve()
    return (Path.cwd() / ".synapse_s2").resolve()


def _json_safe(value: Any, fallback: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return fallback


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ensure_private_dir(path: Path, *, tighten_existing: bool = False) -> None:
    created = False
    try:
        path.mkdir(parents=True, exist_ok=False, mode=0o700)
        created = True
    except FileExistsError:
        pass
    try:
        path_stat = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError("private capture directory is unavailable") from exc
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISDIR(path_stat.st_mode):
        raise ValueError("private capture path must be a real directory")

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fd = os.open(path, flags)
    try:
        opened_stat = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(opened_stat.st_mode)
            or (int(opened_stat.st_dev), int(opened_stat.st_ino))
            != (int(path_stat.st_dev), int(path_stat.st_ino))
        ):
            raise ValueError("private capture directory changed during validation")
        if created or tighten_existing:
            try:
                os.fchmod(directory_fd, 0o700)
            except PermissionError:
                LOGGER.warning("could not chmod private capture directory %s", path)
    finally:
        os.close(directory_fd)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_write_private_text(path: Path, text: str) -> None:
    _ensure_private_dir(path.parent)
    temp_path = path.parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(temp_path, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        os.replace(temp_path, path)
        try:
            path.chmod(0o600)
        except PermissionError:
            LOGGER.warning("could not chmod private capture file %s", path)
        _fsync_directory(path.parent)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _read_regular_file_at(
    directory_fd: int,
    filename: str,
    *,
    max_bytes: int,
) -> tuple[bytes, os.stat_result]:
    """Read one unchanged regular file relative to an already-open directory."""

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(filename, flags, dir_fd=directory_fd)
    try:
        opened_stat = os.fstat(fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise ValueError("processed capture archive must be a regular file")
        if int(opened_stat.st_size) > int(max_bytes):
            raise ValueError("processed capture archive exceeds the size limit")
        chunks: list[bytes] = []
        remaining = int(opened_stat.st_size)
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != int(opened_stat.st_size):
            raise ValueError("processed capture archive changed while reading")
        current_stat = os.stat(
            filename,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(current_stat.st_mode)
            or stat.S_ISLNK(current_stat.st_mode)
            or _stat_identity(current_stat) != _stat_identity(opened_stat)
        ):
            raise ValueError("processed capture archive changed while reading")
        return raw, opened_stat
    finally:
        os.close(fd)


def _atomic_rewrite_private_text_at(
    directory_fd: int,
    filename: str,
    text: str,
    *,
    expected_stat: os.stat_result,
) -> None:
    """Conditionally replace one verified regular file with private bytes."""

    temp_name = f".{filename}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            temp_name,
            flags,
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, 0o600)
        encoded = text.encode("utf-8")
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("private archive rewrite made no write progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1

        current_stat = os.stat(
            filename,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(current_stat.st_mode)
            or stat.S_ISLNK(current_stat.st_mode)
            or _stat_identity(current_stat) != _stat_identity(expected_stat)
        ):
            raise ValueError("processed capture archive changed before replacement")
        os.replace(
            temp_name,
            filename,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temp_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _ensure_private_regular_mode_at(
    directory_fd: int,
    filename: str,
    *,
    expected_stat: os.stat_result,
) -> None:
    """Tighten one already-verified archive through a no-follow descriptor."""

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(filename, flags, dir_fd=directory_fd)
    try:
        opened_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_stat.st_mode)
            or _stat_identity(opened_stat) != _stat_identity(expected_stat)
        ):
            raise ValueError("processed capture archive changed before mode repair")
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)


def _remove_tree_without_following_links(
    path: Path,
    *,
    parent_dir: Path,
) -> None:
    """Remove one private transport tree without following symlinks."""

    if path.parent != parent_dir or path.name in {"", ".", ".."}:
        raise ValueError("capture cleanup target escaped its owned directory")
    if not bool(getattr(shutil.rmtree, "avoids_symlink_attacks", False)):
        raise RuntimeError("platform lacks symlink-safe recursive removal")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_fd = os.open(parent_dir, flags)
    try:
        try:
            path_stat = os.stat(
                path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISDIR(path_stat.st_mode):
            raise ValueError("capture cleanup target must be a real directory")
        shutil.rmtree(path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def _staged_file_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    """Identity fields stable across an atomic rename on macOS and Linux."""

    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
    )


def _stage_regular_file_for_discard(
    *,
    path: Path,
    staging_dir: Path,
    expected_stat: os.stat_result,
) -> Path | None:
    """Atomically detach one verified regular file before destructive cleanup."""

    staged = staging_dir / f".s2-discard-{secrets.token_hex(16)}.tmp"
    try:
        os.replace(path, staged)
    except FileNotFoundError:
        return None
    try:
        staged_stat = staged.lstat()
    except FileNotFoundError:
        return None
    if (
        _staged_file_identity(staged_stat) != _staged_file_identity(expected_stat)
        or not stat.S_ISREG(staged_stat.st_mode)
        or stat.S_ISLNK(staged_stat.st_mode)
    ):
        try:
            if not path.exists():
                os.replace(staged, path)
        except OSError:
            LOGGER.warning("failed to restore changed discard candidate %s", path)
        return None
    _fsync_directory(path.parent)
    if staging_dir != path.parent:
        _fsync_directory(staging_dir)
    return staged


def _stage_tree_for_discard(
    *,
    path: Path,
    staging_dir: Path,
    expected_stat: os.stat_result,
) -> Path | None:
    """Atomically detach one verified owned directory before tree cleanup."""

    staged = staging_dir / f".s2-discard-tree-{secrets.token_hex(16)}.tmp"
    try:
        os.replace(path, staged)
    except FileNotFoundError:
        return None
    try:
        staged_stat = staged.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISDIR(staged_stat.st_mode)
        or stat.S_ISLNK(staged_stat.st_mode)
        or (int(staged_stat.st_dev), int(staged_stat.st_ino))
        != (int(expected_stat.st_dev), int(expected_stat.st_ino))
    ):
        try:
            if not path.exists():
                os.replace(staged, path)
        except OSError:
            LOGGER.warning("failed to restore changed discard tree %s", path)
        return None
    _fsync_directory(path.parent)
    if staging_dir != path.parent:
        _fsync_directory(staging_dir)
    return staged


def _discard_operation_id(staged: Path) -> str:
    for pattern in (DETACHED_DISCARD_RE, DETACHED_TREE_DISCARD_RE):
        match = pattern.fullmatch(staged.name)
        if match is not None:
            return match.group(1)
    return ""


def _canonical_capture_id(value: Any) -> str:
    capture_id = str(value or "").strip()
    if CAPTURE_ID_RE.fullmatch(capture_id) is None:
        raise ValueError(
            "capture_id must use canonical s2cap_<32 lowercase hex> format"
        )
    return capture_id


def new_capture_id() -> str:
    """Return a cryptographically random canonical capture transport identity."""

    return f"s2cap_{secrets.token_hex(16)}"


def write_capture_drop(
    *,
    root: str | os.PathLike[str] | None = None,
    context_id: str = "default",
    source_tag: str = "codex-session",
    speaker: str = "operator",
    text: str,
    metadata: dict[str, Any] | None = None,
    capture_id: str | None = None,
) -> Path:
    clean_text = str(text or "").strip()
    if not clean_text:
        raise ValueError("capture drop text must not be empty")
    capture_root = resolve_capture_root(root)
    inbox_dir = capture_root / "capture_inbox"
    # The configured root may be an existing caller-owned directory. Preserve
    # its mode, while enforcing privacy on the dedicated transport subdir.
    _ensure_private_dir(capture_root)
    _ensure_private_dir(inbox_dir, tighten_existing=True)
    context = mlx_backend.sanitize_context_id(context_id)
    tag = mlx_backend.sanitize_tag(source_tag).replace(" ", "-")
    redacted_text, redaction_count = redact_capture_text(clean_text)
    safe_metadata, metadata_redactions = redact_sensitive_value(metadata or {})
    safe_metadata, raw_digest_removals = strip_untrusted_raw_digest_fields(
        safe_metadata
    )
    canonical_capture_id = (
        _canonical_capture_id(capture_id)
        if capture_id is not None
        else new_capture_id()
    )
    payload = {
        "version": CAPTURE_PROTOCOL_VERSION,
        "capture_id": canonical_capture_id,
        "created_at": time.time(),
        "context_id": context,
        "source_tag": tag,
        "speaker": mlx_backend.sanitize_agent_id(speaker),
        "text": redacted_text,
        "metadata": _json_safe(safe_metadata, {}),
        "redaction_count": int(
            redaction_count + metadata_redactions + raw_digest_removals
        ),
        "raw_text_stored": False,
    }
    filename = (
        f"{time.strftime('%Y%m%d-%H%M%S')}-{tag[:80]}-"
        f"{canonical_capture_id}-{secrets.token_hex(6)}.json"
    )
    output_path = inbox_dir / filename
    lock_dir = capture_root / "capture_locks"
    _ensure_private_dir(lock_dir, tighten_existing=True)
    # Recovery bundles take the same exclusive gate as the daemon.  Producers
    # must join that gate too, otherwise an inbox payload can appear between
    # the database snapshot and capture-transport manifest.
    daemon = CaptureInboxDaemon(root=capture_root)
    with daemon._exclusive_lock(
        lock_dir / GLOBAL_CAPTURE_LOCK,
        blocking=True,
    ) as acquired:
        if not acquired:
            raise RuntimeError("capture maintenance lock is unavailable")
        _atomic_write_private_text(
            output_path,
            json.dumps(payload, indent=2, sort_keys=True),
        )
    return output_path


class CaptureInboxDaemon:
    """Process opt-in session capture payloads dropped into a local inbox."""

    def __init__(
        self,
        *,
        root: str | os.PathLike[str] | None = None,
        backend: mlx_backend.SpikingAttentionBackend | None = None,
    ) -> None:
        self.root = resolve_capture_root(root)
        self._backend = backend
        self._processed_archive_scrub_verified = False

    @property
    def backend(self) -> mlx_backend.SpikingAttentionBackend:
        """Construct the expensive MLX backend only on the ingestion path."""

        if self._backend is None:
            self._backend = mlx_backend.get_backend()
        return self._backend

    def paths(self) -> dict[str, Path]:
        return {
            "root": self.root,
            "inbox_dir": self.root / "capture_inbox",
            "processing_dir": self.root / "capture_processing",
            "processed_dir": self.root / "capture_processed",
            "error_dir": self.root / "capture_errors",
            "error_archive_dir": self.root / "capture_error_archive",
            "error_resolution_dir": self.root / "capture_error_resolutions",
            "receipt_dir": self.root / "capture_receipts",
            "lock_dir": self.root / "capture_locks",
            "state_path": self.root / "capture_daemon_state.json",
        }

    def _ensure_transport_dirs(self, paths: dict[str, Path]) -> None:
        root = paths["root"]
        _ensure_private_dir(root)
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
            if paths[key].parent != root:
                raise ValueError("capture transport directory escaped its root")
            _ensure_private_dir(paths[key], tighten_existing=True)

    def _observe_transport_dirs(
        self,
        paths: dict[str, Path],
    ) -> tuple[list[str], list[str]]:
        """Validate transport directories without creating or chmodding them."""

        keys = (
            "root",
            "inbox_dir",
            "processing_dir",
            "processed_dir",
            "error_dir",
            "error_archive_dir",
            "error_resolution_dir",
            "receipt_dir",
            "lock_dir",
        )
        missing: list[str] = []
        unsafe: list[str] = []
        for key in keys:
            path = paths[key]
            try:
                observed = path.lstat()
            except FileNotFoundError:
                missing.append(key)
                continue
            if (
                stat.S_ISLNK(observed.st_mode)
                or not stat.S_ISDIR(observed.st_mode)
                or observed.st_uid != os.getuid()
                or stat.S_IMODE(observed.st_mode) != 0o700
            ):
                unsafe.append(key)
        return missing, unsafe

    def status(self) -> dict[str, Any]:
        paths = self.paths()
        missing_dirs, unsafe_dirs = self._observe_transport_dirs(paths)
        transport_ready = not missing_dirs and not unsafe_dirs
        base = {
            "root": str(paths["root"]),
            "inbox_dir": str(paths["inbox_dir"]),
            "processing_dir": str(paths["processing_dir"]),
            "processed_dir": str(paths["processed_dir"]),
            "error_dir": str(paths["error_dir"]),
            "error_archive_dir": str(paths["error_archive_dir"]),
            "receipt_dir": str(paths["receipt_dir"]),
            "transport_ready": transport_ready,
            "missing_transport_directories": missing_dirs,
            "unsafe_transport_directories": unsafe_dirs,
            "enabled": transport_ready,
            "mode": "capture-inbox",
        }
        if unsafe_dirs:
            return {
                **base,
                "pending_file_count": 0,
                "inbox_temp_file_count": 0,
                "fresh_inbox_temp_file_count": 0,
                "stale_inbox_temp_file_count": 0,
                "ignored_inbox_temp_file_count": 0,
                "inbox_temp_stale_after_seconds": STALE_INBOX_TEMP_SECONDS,
                "processing_file_count": 0,
                "processing_empty_claim_count": 0,
                "processing_malformed_claim_count": 0,
                "processed_file_count": 0,
                "error_file_count": 0,
                "unresolved_error_count": 0,
                "terminal_error_evidence_count": 0,
                "historical_error_evidence_count": 0,
                "unsafe_error_artifact_count": 0,
                "resolved_error_count": 0,
                "error_resolution_pending_count": 0,
                "error_resolution_failed_count": 0,
                "receipt_count": 0,
                "pending_files": [],
                "processing_files": [],
                "last_result": {},
            }
        pending = self._capture_files(paths["inbox_dir"])
        temp_diagnostics = self._inbox_temp_diagnostics(paths["inbox_dir"])
        processing = self._processing_claims(paths["processing_dir"])
        processing_diagnostics = self._processing_diagnostics(paths["processing_dir"])
        processed = self._capture_files(paths["processed_dir"])
        error_diagnostics = (
            self._error_artifact_diagnostics(paths)
            if paths["error_dir"].is_dir()
            else {
                "unresolved_error_count": 0,
                "terminal_evidence_count": 0,
                "historical_evidence_count": 0,
                "unsafe_error_count": 0,
            }
        )
        resolution_diagnostics = self._error_resolution_diagnostics(paths)
        resolved_errors = self._capture_files(paths["error_archive_dir"])
        receipts = self._receipt_files(paths["receipt_dir"])
        last_result = self._read_state(paths["state_path"])
        return {
            **base,
            "pending_file_count": len(pending),
            "inbox_temp_file_count": temp_diagnostics["total"],
            "fresh_inbox_temp_file_count": temp_diagnostics["fresh"],
            "stale_inbox_temp_file_count": temp_diagnostics["stale"],
            "ignored_inbox_temp_file_count": temp_diagnostics["ignored"],
            "inbox_temp_stale_after_seconds": STALE_INBOX_TEMP_SECONDS,
            "processing_file_count": len(processing),
            "processing_empty_claim_count": processing_diagnostics["empty"],
            "processing_malformed_claim_count": processing_diagnostics["malformed"],
            "processed_file_count": len(processed),
            # Compatibility alias: completed terminal evidence is history, not
            # an active failure. Unsafe and manual-review artifacts remain
            # actionable until an explicit governed resolution succeeds.
            "error_file_count": int(error_diagnostics["unresolved_error_count"]),
            "unresolved_error_count": int(
                error_diagnostics["unresolved_error_count"]
            ),
            "terminal_error_evidence_count": int(
                error_diagnostics["terminal_evidence_count"]
            ),
            "historical_error_evidence_count": int(
                error_diagnostics["historical_evidence_count"]
            ),
            "unsafe_error_artifact_count": int(
                error_diagnostics["unsafe_error_count"]
            ),
            "resolved_error_count": len(resolved_errors),
            "error_resolution_pending_count": int(
                resolution_diagnostics["pending_count"]
            ),
            "error_resolution_failed_count": int(
                resolution_diagnostics["failed_count"]
            ),
            "receipt_count": len(receipts),
            "pending_files": [
                safe_public_error(path.name, fallback="capture payload")
                for path in pending[:20]
            ],
            "processing_files": [
                safe_public_error(path.name, fallback="capture payload")
                for _, path in processing[:20]
            ],
            "last_result": last_result,
        }

    def prepare_transport(self) -> dict[str, Any]:
        """Create/tighten capture transport directories as an explicit mutation."""

        paths = self.paths()
        self._ensure_transport_dirs(paths)
        return self.status()

    def error_resolution_preflight(
        self,
        *,
        reason: str,
        include_historical: bool = False,
    ) -> dict[str, Any]:
        """Describe a filename-free, no-content error archival transaction."""

        paths = self.paths()
        self._ensure_transport_dirs(paths)
        clean_reason, _ = redact_capture_text(" ".join(str(reason or "").split()))
        if not clean_reason:
            raise ValueError("a non-empty resolution reason is required")
        diagnostics = self._error_artifact_diagnostics(paths)
        return self._error_resolution_preflight_payload(
            diagnostics=diagnostics,
            reason=clean_reason,
            include_historical=bool(include_historical),
        )

    def resolve_error_artifacts(
        self,
        *,
        preflight_token: str,
        reason: str,
        include_historical: bool = False,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Move classified historical evidence into a durable private archive.

        The operation never auto-resolves unsafe, raw-retained, malformed, or
        special-file artifacts. A preflight token is fenced to the exact inode
        snapshot, requested scope, and redacted operator reason.
        """

        if not confirm:
            raise ValueError("confirm=true is required to resolve capture errors")
        clean_reason, _ = redact_capture_text(" ".join(str(reason or "").split()))
        if not clean_reason:
            raise ValueError("a non-empty resolution reason is required")
        token = reject_sensitive_identifier(
            preflight_token,
            field="error resolution preflight token",
        ).strip()
        if re.fullmatch(r"[0-9a-f]{64}", token) is None:
            raise ValueError("invalid error resolution preflight token")

        paths = self.paths()
        self._ensure_transport_dirs(paths)
        with self._exclusive_lock(
            paths["lock_dir"] / GLOBAL_CAPTURE_LOCK,
            blocking=True,
        ) as acquired:
            if not acquired:
                raise RuntimeError("capture maintenance lock is unavailable")
            recovery = self._reconcile_error_resolutions(paths)
            if recovery["failed_count"]:
                raise RuntimeError(
                    "an incomplete capture-error resolution requires manual repair"
                )
            diagnostics = self._error_artifact_diagnostics(paths)
            preflight = self._error_resolution_preflight_payload(
                diagnostics=diagnostics,
                reason=clean_reason,
                include_historical=bool(include_historical),
            )
            if not secrets.compare_digest(token, preflight["preflight_token"]):
                raise ValueError(
                    "capture error set changed after preflight; review and retry"
                )
            if diagnostics["unsafe_error_count"]:
                raise ValueError(
                    "unsafe capture error artifacts require manual repair and cannot be archived"
                )
            selected = [
                record
                for record in diagnostics["records"]
                if record["category"] == "terminal"
                or (
                    bool(include_historical)
                    and record["category"] == "historical"
                )
            ]
            if not selected:
                return {
                    "action": "capture-error-resolve",
                    "status": "ready",
                    "resolved_count": 0,
                    "resolution_id": "",
                    "reason": clean_reason,
                    "recovery": recovery,
                }

            resolution_id = secrets.token_hex(16)
            manifest_path = paths["error_resolution_dir"] / (
                f"resolution-{resolution_id}.json"
            )
            items: list[dict[str, Any]] = []
            for record in selected:
                source_stat = record["stat"]
                items.append(
                    {
                        "item_id": secrets.token_hex(16),
                        "source_identity": record["token"],
                        "source_suffix": ".json",
                        "category": record["category"],
                        "archive_name": f"resolved-{secrets.token_hex(16)}.json",
                        "expected": self._error_resolution_expected_stat(source_stat),
                        "moved": False,
                    }
                )
            manifest: dict[str, Any] = {
                "schema": ERROR_RESOLUTION_SCHEMA,
                "resolution_id": resolution_id,
                "state": "prepared",
                "reason": clean_reason,
                "include_historical": bool(include_historical),
                "preflight_fence": token,
                "confirmation_recorded": True,
                "raw_content_stored": False,
                "source_filenames_stored": False,
                "raw_equality_oracle_stored": False,
                "created_at": time.time(),
                "items": items,
            }
            self._write_error_resolution_manifest(manifest_path, manifest)

            records_by_token = {
                str(record["token"]): record
                for record in diagnostics["records"]
            }
            for item in items:
                record = records_by_token.get(str(item["source_identity"]))
                if record is None:
                    raise RuntimeError(
                        "capture error source disappeared during resolution"
                    )
                self._move_error_resolution_item(
                    paths=paths,
                    record=record,
                    item=item,
                )
                item["moved"] = True
                item["resolved_at"] = time.time()
                self._write_error_resolution_manifest(manifest_path, manifest)

            manifest["state"] = "complete"
            manifest["completed_at"] = time.time()
            self._write_error_resolution_manifest(manifest_path, manifest)
            return {
                "action": "capture-error-resolve",
                "status": "ready",
                "resolved_count": len(items),
                "terminal_resolved_count": sum(
                    1 for item in items if item["category"] == "terminal"
                ),
                "historical_resolved_count": sum(
                    1 for item in items if item["category"] == "historical"
                ),
                "resolution_id": resolution_id,
                "reason": clean_reason,
                "recovery": recovery,
            }

    def _error_artifact_diagnostics(
        self,
        paths: dict[str, Path],
    ) -> dict[str, Any]:
        error_dir = paths["error_dir"]
        records: list[dict[str, Any]] = []
        unsafe_count = 0
        try:
            entries = list(error_dir.iterdir())
        except FileNotFoundError:
            entries = []
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        directory_fd = os.open(error_dir, flags)
        try:
            for path in entries:
                try:
                    path_stat = path.lstat()
                except FileNotFoundError:
                    continue
                category = "unsafe"
                parsed: dict[str, Any] | None = None
                if (
                    stat.S_ISREG(path_stat.st_mode)
                    and not stat.S_ISLNK(path_stat.st_mode)
                    and path.suffix.lower() == ".json"
                    and not path.name.startswith(".")
                    and int(path_stat.st_size) <= MAX_CAPTURE_BYTES
                ):
                    try:
                        raw, opened_stat = _read_regular_file_at(
                            directory_fd,
                            path.name,
                            max_bytes=MAX_CAPTURE_BYTES,
                        )
                        candidate = json.loads(raw.decode("utf-8"))
                        redacted, redactions = redact_sensitive_value(candidate)
                        sanitized, digest_removals = strip_untrusted_raw_digest_fields(
                            redacted
                        )
                        if (
                            isinstance(candidate, dict)
                            and candidate == sanitized
                            and not redactions
                            and not digest_removals
                            and candidate.get("raw_payload_retained") is not True
                        ):
                            parsed = candidate
                            path_stat = opened_stat
                            if (
                                candidate.get("artifact_type")
                                in RECOVERABLE_DISCARD_ARTIFACT_TYPES
                                and candidate.get("raw_payload_retained") is False
                                and str(candidate.get("disposition") or "")
                                in TERMINAL_ERROR_DISPOSITIONS
                            ):
                                category = "terminal"
                            else:
                                category = "historical"
                    except (
                        OSError,
                        UnicodeError,
                        ValueError,
                        TypeError,
                        json.JSONDecodeError,
                    ):
                        category = "unsafe"
                token = self._preflight_transport_token(
                    path=path,
                    stat_result=path_stat,
                )
                if category == "unsafe":
                    unsafe_count += 1
                records.append(
                    {
                        "path": path,
                        "stat": path_stat,
                        "token": token,
                        "category": category,
                        # Parsed content is deliberately not returned or logged.
                        "classified": parsed is not None,
                    }
                )
        finally:
            os.close(directory_fd)
        terminal_count = sum(1 for item in records if item["category"] == "terminal")
        historical_count = sum(
            1 for item in records if item["category"] == "historical"
        )
        return {
            "records": records,
            "terminal_evidence_count": terminal_count,
            "historical_evidence_count": historical_count,
            "unsafe_error_count": unsafe_count,
            "unresolved_error_count": historical_count + unsafe_count,
        }

    def _error_resolution_preflight_payload(
        self,
        *,
        diagnostics: dict[str, Any],
        reason: str,
        include_historical: bool,
    ) -> dict[str, Any]:
        selected_tokens = sorted(
            str(record["token"])
            for record in diagnostics["records"]
            if record["category"] == "terminal"
            or (include_historical and record["category"] == "historical")
        )
        token_payload = {
            "schema": ERROR_RESOLUTION_SCHEMA,
            "reason": reason,
            "include_historical": bool(include_historical),
            "selected_source_tokens": selected_tokens,
            "unsafe_error_count": int(diagnostics["unsafe_error_count"]),
        }
        preflight_token = _sha256_text(
            json.dumps(token_payload, sort_keys=True, separators=(",", ":"))
        )
        return {
            "action": "capture-error-resolution-preflight",
            "preflight_token": preflight_token,
            "terminal_evidence_count": int(
                diagnostics["terminal_evidence_count"]
            ),
            "historical_evidence_count": int(
                diagnostics["historical_evidence_count"]
            ),
            "unsafe_error_count": int(diagnostics["unsafe_error_count"]),
            "selected_count": len(selected_tokens),
            "include_historical": bool(include_historical),
            "reason": reason,
            "ready_to_resolve": bool(
                selected_tokens and not diagnostics["unsafe_error_count"]
            ),
            "source_filenames_returned": False,
            "content_returned": False,
            "content_digests_returned": False,
        }

    def _move_error_resolution_item(
        self,
        *,
        paths: dict[str, Path],
        record: dict[str, Any],
        item: dict[str, Any],
    ) -> None:
        source = record["path"]
        source_stat = source.lstat()
        if _stat_identity(source_stat) != _stat_identity(record["stat"]):
            raise ValueError("capture error artifact changed during resolution")
        archive_name = str(item["archive_name"])
        if ERROR_RESOLUTION_ARCHIVE_RE.fullmatch(archive_name) is None:
            raise ValueError("invalid capture error archive identity")
        destination = paths["error_archive_dir"] / archive_name
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("capture error archive target already exists")
        os.replace(source, destination)
        try:
            destination.chmod(0o600)
        except PermissionError:
            LOGGER.warning("could not chmod resolved capture error archive")
        _fsync_directory(paths["error_dir"])
        _fsync_directory(paths["error_archive_dir"])

    @staticmethod
    def _error_resolution_expected_stat(value: os.stat_result) -> dict[str, int]:
        return {
            "device": int(value.st_dev),
            "inode": int(value.st_ino),
            "bytes": int(value.st_size),
            "modified_ns": int(value.st_mtime_ns),
            "changed_ns": int(value.st_ctime_ns),
        }

    def _classify_resolved_error_archive(
        self,
        *,
        archive_dir: Path,
        archive_name: str,
    ) -> tuple[str, os.stat_result]:
        """Revalidate an already-moved archive without trusting its manifest."""

        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(archive_dir, directory_flags)
        try:
            raw, opened_stat = _read_regular_file_at(
                directory_fd,
                archive_name,
                max_bytes=MAX_CAPTURE_BYTES,
            )
        finally:
            os.close(directory_fd)
        candidate = json.loads(raw.decode("utf-8"))
        redacted, redactions = redact_sensitive_value(candidate)
        sanitized, digest_removals = strip_untrusted_raw_digest_fields(redacted)
        if (
            not isinstance(candidate, dict)
            or candidate != sanitized
            or redactions
            or digest_removals
            or candidate.get("raw_payload_retained") is True
        ):
            raise ValueError("resolved capture error archive is unsafe")
        if (
            candidate.get("artifact_type") in RECOVERABLE_DISCARD_ARTIFACT_TYPES
            and candidate.get("raw_payload_retained") is False
            and str(candidate.get("disposition") or "")
            in TERMINAL_ERROR_DISPOSITIONS
        ):
            return "terminal", opened_stat
        return "historical", opened_stat

    def _validate_prepared_error_resolution(
        self,
        *,
        manifest_path: Path,
        manifest: dict[str, Any],
        diagnostics: dict[str, Any],
        paths: dict[str, Path],
    ) -> list[tuple[dict[str, Any], dict[str, Any] | None, Path]]:
        """Validate recovery state independently of the file that described it."""

        resolution_id = str(manifest.get("resolution_id") or "")
        if re.fullmatch(r"[0-9a-f]{32}", resolution_id) is None:
            raise ValueError("invalid capture error resolution id")
        if manifest_path.name != f"resolution-{resolution_id}.json":
            raise ValueError("capture error resolution id does not match its manifest")
        include_historical = manifest.get("include_historical")
        if type(include_historical) is not bool:
            raise ValueError("invalid capture error resolution scope")
        reason = str(manifest.get("reason") or "")
        clean_reason, redactions = redact_capture_text(" ".join(reason.split()))
        if not clean_reason or redactions or clean_reason != reason:
            raise ValueError("invalid capture error resolution reason")
        if (
            manifest.get("raw_content_stored") is not False
            or manifest.get("source_filenames_stored") is not False
            or manifest.get("raw_equality_oracle_stored") is not False
            or manifest.get("confirmation_recorded") is not True
        ):
            raise ValueError("capture error resolution attestations are invalid")
        if int(diagnostics.get("unsafe_error_count") or 0):
            raise ValueError(
                "unsafe capture error artifacts block automatic resolution recovery"
            )
        items = manifest.get("items")
        if not isinstance(items, list) or not items:
            raise ValueError("invalid capture error resolution items")
        source_identities: list[str] = []
        item_ids: set[str] = set()
        archive_names: set[str] = set()
        validated: list[tuple[dict[str, Any], dict[str, Any] | None, Path]] = []
        records_by_token = {
            str(record["token"]): record for record in diagnostics["records"]
        }
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("invalid capture error resolution item")
            item_id = str(item.get("item_id") or "")
            source_identity = str(item.get("source_identity") or "")
            archive_name = str(item.get("archive_name") or "")
            category = str(item.get("category") or "")
            expected = item.get("expected")
            if re.fullmatch(r"[0-9a-f]{32}", item_id) is None or item_id in item_ids:
                raise ValueError("invalid or duplicate capture error resolution item id")
            if re.fullmatch(r"[0-9a-f]{64}", source_identity) is None:
                raise ValueError("invalid capture error source identity")
            if source_identity in source_identities:
                raise ValueError("duplicate capture error source identity")
            if (
                ERROR_RESOLUTION_ARCHIVE_RE.fullmatch(archive_name) is None
                or archive_name in archive_names
            ):
                raise ValueError("invalid or duplicate capture error archive identity")
            if category not in {"terminal", "historical"}:
                raise ValueError("unsafe capture error category cannot be recovered")
            if category == "historical" and not include_historical:
                raise ValueError("historical capture error is outside resolution scope")
            if not isinstance(expected, dict) or set(expected) != {
                "device",
                "inode",
                "bytes",
                "modified_ns",
                "changed_ns",
            }:
                raise ValueError("invalid capture error expected-stat fence")
            if any(type(expected[key]) is not int or expected[key] < 0 for key in expected):
                raise ValueError("invalid capture error expected-stat value")
            item_ids.add(item_id)
            source_identities.append(source_identity)
            archive_names.add(archive_name)
            record = records_by_token.get(source_identity)
            destination = paths["error_archive_dir"] / archive_name
            destination_exists = destination.exists() and not destination.is_symlink()
            if record is not None and destination_exists:
                raise ValueError("capture error exists in both source and archive")
            if record is not None:
                if record.get("category") != category or not record.get("classified"):
                    raise ValueError("capture error category changed during recovery")
                if expected != self._error_resolution_expected_stat(record["stat"]):
                    raise ValueError("capture error stat fence changed during recovery")
            elif destination_exists:
                archive_category, archive_stat = self._classify_resolved_error_archive(
                    archive_dir=paths["error_archive_dir"],
                    archive_name=archive_name,
                )
                if archive_category != category:
                    raise ValueError("resolved capture error category does not match")
                stable_expected = (
                    expected["device"],
                    expected["inode"],
                    expected["bytes"],
                    expected["modified_ns"],
                )
                if stable_expected != _staged_file_identity(archive_stat):
                    raise ValueError("resolved capture error stat fence does not match")
            else:
                raise RuntimeError(
                    "capture error resolution lost both source and archive"
                )
            validated.append((item, record, destination))

        preflight_payload = {
            "schema": ERROR_RESOLUTION_SCHEMA,
            "reason": reason,
            "include_historical": include_historical,
            "selected_source_tokens": sorted(source_identities),
            "unsafe_error_count": 0,
        }
        expected_preflight = _sha256_text(
            json.dumps(preflight_payload, sort_keys=True, separators=(",", ":"))
        )
        preflight_token = str(manifest.get("preflight_fence") or "")
        if not secrets.compare_digest(preflight_token, expected_preflight):
            raise ValueError("capture error resolution preflight proof is invalid")
        return validated

    def _write_error_resolution_manifest(
        self,
        path: Path,
        manifest: dict[str, Any],
    ) -> None:
        if ERROR_RESOLUTION_MANIFEST_RE.fullmatch(path.name) is None:
            raise ValueError("invalid capture error resolution manifest identity")
        safe_manifest, redactions = redact_sensitive_value(manifest)
        safe_manifest, digest_removals = strip_untrusted_raw_digest_fields(
            safe_manifest
        )
        if redactions or digest_removals or safe_manifest != manifest:
            raise ValueError("capture error resolution manifest is not secret-safe")
        _atomic_write_private_text(
            path,
            json.dumps(manifest, indent=2, sort_keys=True),
        )

    def _error_resolution_diagnostics(
        self,
        paths: dict[str, Path],
    ) -> dict[str, int]:
        pending = 0
        failed = 0
        complete = 0
        for path in self._capture_files(paths["error_resolution_dir"]):
            if ERROR_RESOLUTION_MANIFEST_RE.fullmatch(path.name) is None:
                failed += 1
                continue
            try:
                parsed = json.loads(self._read_capture_text(path))
            except Exception:
                failed += 1
                continue
            if not isinstance(parsed, dict) or parsed.get("schema") != ERROR_RESOLUTION_SCHEMA:
                failed += 1
            elif parsed.get("state") == "complete":
                complete += 1
            elif parsed.get("state") == "prepared":
                pending += 1
            else:
                failed += 1
        return {
            "pending_count": pending,
            "failed_count": failed,
            "complete_count": complete,
        }

    def _reconcile_error_resolutions(
        self,
        paths: dict[str, Path],
    ) -> dict[str, int]:
        result = {"completed_count": 0, "moved_count": 0, "failed_count": 0}
        diagnostics = self._error_artifact_diagnostics(paths)
        for manifest_path in self._capture_files(paths["error_resolution_dir"]):
            if ERROR_RESOLUTION_MANIFEST_RE.fullmatch(manifest_path.name) is None:
                result["failed_count"] += 1
                continue
            try:
                manifest = json.loads(self._read_capture_text(manifest_path))
                if (
                    not isinstance(manifest, dict)
                    or manifest.get("schema") != ERROR_RESOLUTION_SCHEMA
                ):
                    raise ValueError("invalid capture error resolution manifest")
                if manifest.get("state") == "complete":
                    continue
                if manifest.get("state") != "prepared":
                    raise ValueError("unknown capture error resolution state")
                validated = self._validate_prepared_error_resolution(
                    manifest_path=manifest_path,
                    manifest=manifest,
                    diagnostics=diagnostics,
                    paths=paths,
                )
                for item, record, _destination in validated:
                    if record is not None:
                        self._move_error_resolution_item(
                            paths=paths,
                            record=record,
                            item=item,
                        )
                        result["moved_count"] += 1
                    item["moved"] = True
                    item.setdefault("resolved_at", time.time())
                    self._write_error_resolution_manifest(manifest_path, manifest)
                manifest["state"] = "complete"
                manifest["completed_at"] = time.time()
                manifest["recovered_after_interruption"] = True
                self._write_error_resolution_manifest(manifest_path, manifest)
                result["completed_count"] += 1
            except Exception:
                result["failed_count"] += 1
                LOGGER.exception("failed to reconcile capture error resolution")
        return result

    def preflight(self, *, max_files: int = 50) -> dict[str, Any]:
        paths = self.paths()
        self._ensure_transport_dirs(paths)
        bounded_max = min(max(int(max_files), 1), 250)
        pending = self._capture_files(paths["inbox_dir"])
        selected = pending[:bounded_max]
        selected_files: list[dict[str, Any]] = []
        selected_total_bytes = 0
        for path in selected:
            try:
                stat_result = path.lstat()
                size = int(stat_result.st_size)
                modified_at = float(stat_result.st_mtime)
            except FileNotFoundError:
                continue
            transport_token = self._preflight_transport_token(
                path=path,
                stat_result=stat_result,
            )
            try:
                request_fingerprint = self._preflight_request_fingerprint(path)
                fingerprint_mode = "post-redaction-request"
            except Exception:
                # Malformed drops still need an operator-confirmable transport
                # identity so processing can quarantine them. The token below
                # contains only file-system metadata, never content bytes.
                request_fingerprint = ""
                fingerprint_mode = "transport-metadata-only"
            selected_total_bytes += size
            safe_suffix = path.suffix.lower()
            if safe_suffix not in CAPTURE_SUFFIXES:
                safe_suffix = ".payload"
            selected_files.append(
                {
                    "file": f"capture-{transport_token[:16]}{safe_suffix}",
                    "bytes": size,
                    "modified_at": modified_at,
                    "transport_token": transport_token,
                    "request_fingerprint": request_fingerprint,
                    "fingerprint_mode": fingerprint_mode,
                }
            )
        return {
            "action": "capture-inbox-preflight",
            "root": str(self.root),
            "inbox_dir": str(paths["inbox_dir"]),
            "pending_file_count": len(pending),
            "selected_file_count": len(selected_files),
            "selected_total_bytes": selected_total_bytes,
            "selected_files": selected_files,
            "max_files": bounded_max,
            "mode": "manual-confirmation-preflight",
        }

    def _preflight_transport_token(
        self,
        *,
        path: Path,
        stat_result: os.stat_result,
    ) -> str:
        metadata = {
            "protocol": "capture-transport.v3",
            "device": int(stat_result.st_dev),
            "inode": int(stat_result.st_ino),
            "mode": int(stat.S_IMODE(stat_result.st_mode)),
            "bytes": int(stat_result.st_size),
            "modified_ns": int(stat_result.st_mtime_ns),
            "changed_ns": int(stat_result.st_ctime_ns),
        }
        return _sha256_text(
            json.dumps(metadata, sort_keys=True, separators=(",", ":"))
        )

    def _preflight_request_fingerprint(self, path: Path) -> str:
        document_kind, raw_payloads = self._load_payload_document(path)
        requests: list[dict[str, Any]] = []
        for ordinal, raw_payload in enumerate(raw_payloads):
            payload = dict(raw_payload)
            raw_version = payload.get("version", 1)
            if isinstance(raw_version, bool):
                raise ValueError("capture payload version must be 1 or 2")
            version = int(raw_version)
            if version not in (1, CAPTURE_PROTOCOL_VERSION):
                raise ValueError(f"unsupported capture payload version: {version}")
            payload["version"] = version
            if version == CAPTURE_PROTOCOL_VERSION:
                capture_id = _canonical_capture_id(payload.get("capture_id"))
            elif payload.get("capture_id"):
                capture_id = _canonical_capture_id(payload.get("capture_id"))
            else:
                # Preflight must not allocate durable identity. A stable local
                # placeholder lets equivalent legacy requests compare safely;
                # the claimed file receives a random persisted ID before apply.
                capture_id = f"s2cap_{ordinal:032x}"
            payload["capture_id"] = capture_id
            normalized = self._normalize_payload_before_capture(
                path=path,
                payload=payload,
                version=version,
            )
            requests.append(self._canonical_capture_request(normalized))
        safe_contract = {
            "protocol": "capture-preflight.v2",
            "document_kind": document_kind,
            "requests": requests,
        }
        return self._request_fingerprint(safe_contract)

    def _inbox_temp_kind(self, name: str) -> str:
        if ATOMIC_INBOX_TEMP_RE.fullmatch(name) is not None:
            return "atomic-write-temp"
        if LEGACY_INBOX_TEMP_RE.fullmatch(name) is not None:
            return "legacy-write-temp"
        return ""

    def _inbox_temp_artifacts(self, inbox_dir: Path) -> list[dict[str, Any]]:
        try:
            entries = list(inbox_dir.iterdir())
        except FileNotFoundError:
            return []
        now = time.time()
        artifacts: list[dict[str, Any]] = []
        for path in entries:
            temp_kind = self._inbox_temp_kind(path.name)
            if not temp_kind:
                continue
            try:
                path_stat = path.lstat()
            except FileNotFoundError:
                continue
            regular = bool(
                stat.S_ISREG(path_stat.st_mode)
                and not stat.S_ISLNK(path_stat.st_mode)
            )
            newest_change = max(
                float(path_stat.st_mtime),
                float(path_stat.st_ctime),
            )
            age_seconds = max(0.0, now - newest_change)
            state = (
                "ignored"
                if not regular
                else "stale"
                if age_seconds >= STALE_INBOX_TEMP_SECONDS
                else "fresh"
            )
            artifacts.append(
                {
                    "path": path,
                    "kind": temp_kind,
                    "state": state,
                    "age_seconds": age_seconds,
                    "stat": path_stat,
                }
            )
        return sorted(
            artifacts,
            key=lambda item: (float(item["stat"].st_mtime), item["path"].name),
        )

    def _inbox_temp_diagnostics(self, inbox_dir: Path) -> dict[str, int]:
        artifacts = self._inbox_temp_artifacts(inbox_dir)
        return {
            "total": len(artifacts),
            "fresh": sum(1 for item in artifacts if item["state"] == "fresh"),
            "stale": sum(1 for item in artifacts if item["state"] == "stale"),
            "ignored": sum(1 for item in artifacts if item["state"] == "ignored"),
        }

    def _repair_inbox_temp_artifacts(
        self,
        paths: dict[str, Path],
    ) -> dict[str, int]:
        repaired = {
            "discarded": 0,
            "evidence_errors": 0,
        }
        inbox_dir = paths["inbox_dir"]
        for artifact in self._inbox_temp_artifacts(inbox_dir):
            if artifact["state"] != "stale":
                continue
            path = artifact["path"]
            observed_stat = artifact["stat"]
            observed_identity = _stat_identity(observed_stat)
            try:
                current_stat = path.lstat()
            except FileNotFoundError:
                continue
            current_identity = _stat_identity(current_stat)
            if (
                current_identity != observed_identity
                or not stat.S_ISREG(current_stat.st_mode)
                or stat.S_ISLNK(current_stat.st_mode)
            ):
                continue
            current_age = max(
                0.0,
                time.time()
                - max(float(current_stat.st_mtime), float(current_stat.st_ctime)),
            )
            if current_age < STALE_INBOX_TEMP_SECONDS:
                continue
            staged = _stage_regular_file_for_discard(
                path=path,
                staging_dir=paths["error_dir"],
                expected_stat=current_stat,
            )
            if staged is None:
                continue
            discarded_at = time.time()
            evidence = {
                "artifact_type": "stale-capture-inbox-temp",
                "discard_operation_id": _discard_operation_id(staged),
                "original_file": safe_public_error(
                    path.name,
                    fallback="capture temp",
                ),
                "temp_kind": artifact["kind"],
                "observed_bytes": int(current_stat.st_size),
                "observed_modified_at": float(current_stat.st_mtime),
                "observed_changed_at": float(current_stat.st_ctime),
                "observed_age_seconds": round(current_age, 3),
                "content_inspected": False,
                "content_digest_recorded": False,
                "raw_payload_retained": True,
                "disposition": "detached-pending-discard",
                "discarded_at": discarded_at,
                "reason": (
                    "stale capture inbox temp was never eligible for ingestion"
                ),
            }
            evidence_path = self._unique_destination(
                paths["error_dir"],
                f"temp-discard-evidence-{secrets.token_hex(16)}.json",
            )
            try:
                _atomic_write_private_text(
                    evidence_path,
                    json.dumps(evidence, indent=2, sort_keys=True),
                )
            except Exception:
                repaired["evidence_errors"] += 1
                LOGGER.exception(
                    "failed to persist stale inbox temp evidence %s",
                    evidence_path,
                )
                try:
                    os.replace(staged, path)
                    _fsync_directory(inbox_dir)
                except OSError:
                    LOGGER.exception("failed to restore capture temp after evidence error")
                continue
            try:
                staged.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                repaired["evidence_errors"] += 1
                LOGGER.exception("failed to discard detached capture temp")
                continue
            _fsync_directory(paths["error_dir"])
            evidence["raw_payload_retained"] = False
            evidence["disposition"] = "discarded-without-content-inspection"
            try:
                _atomic_write_private_text(
                    evidence_path,
                    json.dumps(evidence, indent=2, sort_keys=True),
                )
            except Exception:
                repaired["evidence_errors"] += 1
                LOGGER.exception("failed to finalize capture temp discard evidence")
            repaired["discarded"] += 1
        return repaired

    def _discard_legacy_raw_error_artifacts(
        self,
        paths: dict[str, Path],
    ) -> dict[str, int]:
        """Remove raw stale-temp quarantine bytes left by pre-v2 daemons."""

        result = {"discarded": 0, "evidence_errors": 0}
        error_dir = paths["error_dir"]
        try:
            entries = list(error_dir.iterdir())
        except FileNotFoundError:
            return result
        for path in entries:
            if not path.name.startswith("stale-temp-") or path.name.endswith(
                ".evidence.json"
            ):
                continue
            try:
                path_stat = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(path_stat.st_mode) or stat.S_ISLNK(path_stat.st_mode):
                continue
            staged = _stage_regular_file_for_discard(
                path=path,
                staging_dir=error_dir,
                expected_stat=path_stat,
            )
            if staged is None:
                continue
            evidence = {
                "artifact_type": "legacy-raw-stale-temp-quarantine",
                "discard_operation_id": _discard_operation_id(staged),
                "original_file": safe_public_error(
                    path.name,
                    fallback="legacy capture temp",
                ),
                "observed_bytes": int(path_stat.st_size),
                "observed_modified_at": float(path_stat.st_mtime),
                "content_inspected": False,
                "content_digest_recorded": False,
                "raw_payload_retained": True,
                "disposition": "legacy-raw-quarantine-detached",
                "discarded_at": time.time(),
                "reason": "legacy daemon retained rejected raw transport bytes",
            }
            evidence_path = self._unique_destination(
                error_dir,
                f"legacy-raw-discard-{int(time.time())}-{secrets.token_hex(8)}.evidence.json",
            )
            try:
                _atomic_write_private_text(
                    evidence_path,
                    json.dumps(evidence, indent=2, sort_keys=True),
                )
            except Exception:
                result["evidence_errors"] += 1
                LOGGER.exception(
                    "failed to persist legacy raw quarantine evidence %s",
                    evidence_path,
                )
                try:
                    os.replace(staged, path)
                    _fsync_directory(error_dir)
                except OSError:
                    LOGGER.exception("failed to restore legacy temp after evidence error")
                continue
            try:
                staged.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                result["evidence_errors"] += 1
                LOGGER.exception("failed to discard detached legacy capture temp")
                continue
            _fsync_directory(error_dir)
            evidence["raw_payload_retained"] = False
            evidence["disposition"] = "legacy-raw-quarantine-discarded"
            try:
                _atomic_write_private_text(
                    evidence_path,
                    json.dumps(evidence, indent=2, sort_keys=True),
                )
            except Exception:
                result["evidence_errors"] += 1
                LOGGER.exception("failed to finalize legacy discard evidence")
            result["discarded"] += 1
        return result

    def _recover_detached_discard_artifacts(
        self,
        paths: dict[str, Path],
    ) -> dict[str, int]:
        """Finish interrupted raw-byte discards and reconcile their evidence."""

        result = {"discarded": 0, "evidence_updates": 0, "errors": 0}
        error_dir = paths["error_dir"]
        completed_ids: set[str] = set()
        try:
            staged_paths = list(error_dir.iterdir())
        except FileNotFoundError:
            return result
        for staged in staged_paths:
            discard_id = _discard_operation_id(staged)
            if not discard_id:
                continue
            try:
                staged_stat = staged.lstat()
            except FileNotFoundError:
                continue
            try:
                if DETACHED_DISCARD_RE.fullmatch(staged.name):
                    if not stat.S_ISREG(staged_stat.st_mode) or stat.S_ISLNK(
                        staged_stat.st_mode
                    ):
                        raise ValueError(
                            "detached capture discard must remain a regular file"
                        )
                    staged.unlink()
                    _fsync_directory(error_dir)
                else:
                    if not stat.S_ISDIR(staged_stat.st_mode) or stat.S_ISLNK(
                        staged_stat.st_mode
                    ):
                        raise ValueError(
                            "detached capture discard tree must remain a real directory"
                        )
                    _remove_tree_without_following_links(
                        staged,
                        parent_dir=error_dir,
                    )
            except (OSError, RuntimeError, ValueError):
                result["errors"] += 1
                LOGGER.exception("failed to resume detached capture discard")
                continue
            result["discarded"] += 1
            completed_ids.add(discard_id)

        evidence_ids: set[str] = set()
        pending_evidence: list[tuple[Path, dict[str, Any], str]] = []
        for evidence_path in list(error_dir.glob("*.json")):
            try:
                evidence_stat = evidence_path.lstat()
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(evidence_stat.st_mode)
                or stat.S_ISLNK(evidence_stat.st_mode)
                or int(evidence_stat.st_size) > MAX_CAPTURE_BYTES
            ):
                continue
            try:
                evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(evidence, dict):
                continue
            discard_id = str(evidence.get("discard_operation_id") or "")
            if re.fullmatch(r"[0-9a-f]{32}", discard_id) is None:
                continue
            if evidence.get("artifact_type") not in RECOVERABLE_DISCARD_ARTIFACT_TYPES:
                continue
            evidence_ids.add(discard_id)
            if evidence.get("raw_payload_retained") is True:
                pending_evidence.append((evidence_path, evidence, discard_id))

        for evidence_path, evidence, discard_id in pending_evidence:
            staged_names = (
                f".s2-discard-{discard_id}.tmp",
                f".s2-discard-tree-{discard_id}.tmp",
            )
            retained_artifact_exists = False
            for staged_name in staged_names:
                try:
                    (error_dir / staged_name).lstat()
                except FileNotFoundError:
                    continue
                except OSError:
                    retained_artifact_exists = True
                    break
                else:
                    retained_artifact_exists = True
                    break
            if retained_artifact_exists:
                continue
            evidence["raw_payload_retained"] = False
            evidence["disposition"] = "recovered-discard-complete"
            evidence["recovered_at"] = time.time()
            try:
                _atomic_write_private_text(
                    evidence_path,
                    json.dumps(evidence, indent=2, sort_keys=True),
                )
            except Exception:
                result["errors"] += 1
                LOGGER.exception("failed to reconcile recovered discard evidence")
            else:
                result["evidence_updates"] += 1

        for discard_id in completed_ids - evidence_ids:
            recovery_evidence = {
                "version": 2,
                "artifact_type": "detached-capture-discard-recovery",
                "discard_operation_id": discard_id,
                "content_inspected": False,
                "content_digest_recorded": False,
                "raw_payload_retained": False,
                "disposition": "recovered-discard-complete",
                "recovered_at": time.time(),
            }
            try:
                _atomic_write_private_text(
                    self._unique_destination(
                        error_dir,
                        f"temp-discard-evidence-{secrets.token_hex(16)}.evidence.json",
                    ),
                    json.dumps(recovery_evidence, indent=2, sort_keys=True),
                )
                result["evidence_updates"] += 1
            except Exception:
                result["errors"] += 1
                LOGGER.exception("failed to persist discard recovery evidence")
        return result

    def _scrub_legacy_temp_evidence_artifacts(
        self,
        paths: dict[str, Path],
    ) -> dict[str, int]:
        """Canonicalize old discard evidence without retaining raw names/tokens."""

        result = {"scrubbed": 0, "errors": 0}
        error_dir = paths["error_dir"]
        allowed_artifact_types = set(RECOVERABLE_DISCARD_ARTIFACT_TYPES)
        allowed_keys = {
            "artifact_type",
            "discard_operation_id",
            "temp_kind",
            "observed_bytes",
            "observed_modified_at",
            "observed_changed_at",
            "observed_age_seconds",
            "content_inspected",
            "content_digest_recorded",
            "raw_payload_retained",
            "disposition",
            "discarded_at",
            "recovered_at",
            "reason",
            "cleanup_kind",
            "claim",
            "children",
            "file",
            "error",
            "failed_at",
            "payload_disposition",
            "redacted_payload_retained",
        }
        try:
            entries = list(error_dir.iterdir())
        except FileNotFoundError:
            return result
        for path in entries:
            try:
                path_stat = path.lstat()
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(path_stat.st_mode)
                or stat.S_ISLNK(path_stat.st_mode)
                or path.suffix.lower() != ".json"
                or int(path_stat.st_size) > MAX_CAPTURE_BYTES
            ):
                continue
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if (
                not isinstance(parsed, dict)
                or parsed.get("artifact_type") not in allowed_artifact_types
            ):
                continue
            canonical = {
                "version": 2,
                **{key: parsed[key] for key in allowed_keys if key in parsed},
                "original_filename_stored": False,
                "transport_token_stored": False,
                "content_digest_recorded": False,
            }
            canonical, _ = redact_sensitive_value(canonical)
            canonical, _ = strip_untrusted_raw_digest_fields(canonical)
            safe_name = bool(
                re.fullmatch(
                    r"(?:temp-discard-evidence|legacy-raw-discard)-[0-9a-f-]+(?:\.evidence)?\.json",
                    path.name,
                )
            )
            if canonical == parsed and safe_name:
                continue
            destination = self._unique_destination(
                error_dir,
                f"temp-discard-evidence-{secrets.token_hex(16)}.evidence.json",
            )
            try:
                _atomic_write_private_text(
                    destination,
                    json.dumps(canonical, indent=2, sort_keys=True),
                )
                path.unlink()
                _fsync_directory(error_dir)
            except Exception:
                result["errors"] += 1
                LOGGER.exception("failed to canonicalize legacy discard evidence")
                try:
                    destination.unlink()
                except FileNotFoundError:
                    pass
                continue
            result["scrubbed"] += 1
        return result

    @staticmethod
    def _decode_processed_archive(
        *,
        suffix: str,
        raw: bytes,
    ) -> tuple[str, Any]:
        text = raw.decode("utf-8")
        if suffix == ".txt":
            return "text", text
        if suffix == ".jsonl":
            records: list[dict[str, Any]] = []
            for line in text.splitlines():
                if not line.strip():
                    continue
                parsed = json.loads(line)
                if not isinstance(parsed, dict):
                    raise ValueError("processed JSONL records must be objects")
                records.append(parsed)
            if not records:
                raise ValueError("processed JSONL archive must not be empty")
            return "jsonl", records
        parsed = json.loads(text)
        if isinstance(parsed, list):
            if not parsed or not all(isinstance(item, dict) for item in parsed):
                raise ValueError("processed JSON list must contain objects")
            return "json-list", parsed
        if not isinstance(parsed, dict):
            raise ValueError("processed JSON archive must be an object or list")
        return "json-object", parsed

    @staticmethod
    def _processed_archive_capture_ids(document: Any) -> tuple[Any, ...]:
        records = document if isinstance(document, list) else [document]
        if not all(isinstance(record, dict) for record in records):
            raise ValueError("processed capture archive records must be objects")
        return tuple(record.get("capture_id") for record in records)

    @classmethod
    def _sanitize_processed_archive(
        cls,
        document: Any,
    ) -> tuple[Any, int, int]:
        if isinstance(document, str):
            redacted, redaction_count = redact_capture_text(document)
            sanitized, digest_removals = strip_untrusted_raw_digest_text(redacted)
            stable, _ = redact_capture_text(sanitized)
            stable, remaining_digests = strip_untrusted_raw_digest_text(stable)
            if stable != sanitized or remaining_digests:
                raise ValueError("processed text archive sanitization is not idempotent")
            return sanitized, int(redaction_count), int(digest_removals)
        capture_ids = cls._processed_archive_capture_ids(document)
        redacted, redaction_count = redact_sensitive_value(document)
        sanitized, digest_removals = strip_untrusted_raw_digest_fields(redacted)
        if cls._processed_archive_capture_ids(sanitized) != capture_ids:
            raise ValueError("processed capture archive identity is not rewritable")
        stable, _ = redact_sensitive_value(sanitized)
        stable, remaining_digests = strip_untrusted_raw_digest_fields(stable)
        if stable != sanitized or remaining_digests:
            raise ValueError("processed capture archive sanitization is not idempotent")
        return sanitized, int(redaction_count), int(digest_removals)

    @staticmethod
    def _encode_processed_archive(*, document_kind: str, document: Any) -> str:
        if document_kind == "text":
            if not isinstance(document, str):
                raise ValueError("processed text archive must remain text")
            return document
        if document_kind == "jsonl":
            return "\n".join(
                json.dumps(
                    record,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
                for record in document
            ) + "\n"
        return json.dumps(
            document,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )

    def _scrub_legacy_processed_artifacts(
        self,
        paths: dict[str, Path],
    ) -> dict[str, Any]:
        """Canonicalize private processed archives without changing identity."""

        result: dict[str, Any] = {
            "schema": PROCESSED_ARCHIVE_SCRUB_SCHEMA,
            "scanned": 0,
            "scrubbed": 0,
            "clean": 0,
            "skipped": 0,
            "symlink_refusals": 0,
            "errors": 0,
            "redactions": 0,
            "raw_digest_fields_removed": 0,
            "post_pass_unsafe": 0,
            "post_pass_unverified": 0,
        }
        if self._processed_archive_scrub_verified:
            return result
        processed_dir = paths["processed_dir"]
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            directory_fd = os.open(processed_dir, flags)
        except OSError:
            result["errors"] += 1
            result["post_pass_unverified"] += 1
            LOGGER.warning("processed capture archive scrub could not open its private directory")
            return result
        try:
            try:
                filenames = sorted(os.listdir(directory_fd))
            except OSError:
                result["errors"] += 1
                result["post_pass_unverified"] += 1
                return result
            for filename in filenames:
                suffix = Path(filename).suffix.lower()
                if suffix not in {".json", ".jsonl", ".txt"}:
                    result["skipped"] += 1
                    continue
                result["scanned"] += 1
                unsafe = False
                try:
                    candidate_stat = os.stat(
                        filename,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if stat.S_ISLNK(candidate_stat.st_mode):
                        result["symlink_refusals"] += 1
                        result["errors"] += 1
                        result["post_pass_unverified"] += 1
                        continue
                    if not stat.S_ISREG(candidate_stat.st_mode):
                        result["skipped"] += 1
                        continue
                    raw, opened_stat = _read_regular_file_at(
                        directory_fd,
                        filename,
                        max_bytes=MAX_CAPTURE_BYTES,
                    )
                    document_kind, document = self._decode_processed_archive(
                        suffix=suffix,
                        raw=raw,
                    )
                    sanitized, redactions, digest_removals = (
                        self._sanitize_processed_archive(document)
                    )
                    unsafe = sanitized != document
                    if not unsafe:
                        _ensure_private_regular_mode_at(
                            directory_fd,
                            filename,
                            expected_stat=opened_stat,
                        )
                        result["clean"] += 1
                        continue
                    encoded = self._encode_processed_archive(
                        document_kind=document_kind,
                        document=sanitized,
                    )
                    _atomic_rewrite_private_text_at(
                        directory_fd,
                        filename,
                        encoded,
                        expected_stat=opened_stat,
                    )
                    verify_raw, verify_stat = _read_regular_file_at(
                        directory_fd,
                        filename,
                        max_bytes=MAX_CAPTURE_BYTES,
                    )
                    _, verify_document = self._decode_processed_archive(
                        suffix=suffix,
                        raw=verify_raw,
                    )
                    verify_sanitized, _, verify_digest_removals = (
                        self._sanitize_processed_archive(verify_document)
                    )
                    if (
                        verify_sanitized != verify_document
                        or verify_digest_removals
                    ):
                        raise ValueError(
                            "processed capture archive failed its post-write invariant"
                        )
                    _ensure_private_regular_mode_at(
                        directory_fd,
                        filename,
                        expected_stat=verify_stat,
                    )
                    result["scrubbed"] += 1
                    result["redactions"] += int(redactions)
                    result["raw_digest_fields_removed"] += int(digest_removals)
                except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
                    result["errors"] += 1
                    if unsafe:
                        result["post_pass_unsafe"] += 1
                    else:
                        result["post_pass_unverified"] += 1
        finally:
            os.close(directory_fd)
        if result["errors"]:
            LOGGER.warning(
                "processed capture archive scrub completed with %d count-only error(s)",
                result["errors"],
            )
        elif not result["post_pass_unsafe"] and not result["post_pass_unverified"]:
            # A long-running daemon processes only canonical archives after
            # this pass. Avoid reparsing the entire immutable archive every
            # poll interval; a fresh daemon process verifies it again.
            self._processed_archive_scrub_verified = True
        return result

    def process_once(self, *, max_files: int = 50) -> dict[str, Any]:
        paths = self.paths()
        self._ensure_transport_dirs(paths)
        while True:
            initialize_backend = False
            with self._exclusive_lock(
                paths["lock_dir"] / GLOBAL_CAPTURE_LOCK,
                blocking=True,
            ) as acquired:
                if not acquired:
                    raise RuntimeError("capture maintenance lock is unavailable")
                # Never lazily acquire a backend/authority route while holding
                # the global capture lock. If work appeared since the previous
                # observation, release capture, initialize authority, and then
                # reacquire capture in the canonical order.
                if self._backend is None and any(
                    any(directory.iterdir())
                    for directory in (
                        paths["inbox_dir"],
                        paths["processing_dir"],
                    )
                ):
                    initialize_backend = True
                else:
                    self._repair_legacy_state(paths["state_path"])
                    return self._process_once_locked(
                        paths=paths,
                        max_files=max_files,
                    )
            if initialize_backend:
                self.backend

    def _process_once_locked(
        self,
        *,
        paths: dict[str, Path],
        max_files: int,
    ) -> dict[str, Any]:
        bounded_max = min(max(int(max_files), 1), 250)
        error_resolution_repair = self._reconcile_error_resolutions(paths)
        processed_archive_scrub = self._scrub_legacy_processed_artifacts(paths)
        detached_discard_repair = self._recover_detached_discard_artifacts(paths)
        legacy_error_repair = self._discard_legacy_raw_error_artifacts(paths)
        legacy_evidence_repair = self._scrub_legacy_temp_evidence_artifacts(paths)
        temp_repair = self._repair_inbox_temp_artifacts(paths)
        repair = self._repair_processing_claims(paths)
        claims = self._processing_claims(paths["processing_dir"])[:bounded_max]
        remaining = bounded_max - len(claims)
        if remaining > 0:
            for inbox_path in self._capture_files(paths["inbox_dir"])[:remaining]:
                claimed = self._claim_inbox_file(
                    inbox_path=inbox_path,
                    inbox_dir=paths["inbox_dir"],
                    processing_dir=paths["processing_dir"],
                )
                if claimed is not None:
                    claims.append(claimed)

        captures: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        processed_file_count = 0
        error_file_count = 0
        deferred_file_count = 0
        idempotent_capture_count = 0

        for claim_dir, path in claims:
            outcome = self._process_claim(
                claim_dir=claim_dir,
                path=path,
                paths=paths,
            )
            if outcome is None:
                deferred_file_count += 1
                continue
            captures.extend(outcome["captures"])
            errors.extend(outcome["errors"])
            processed_file_count += int(outcome["processed_file_count"])
            error_file_count += int(outcome["error_file_count"])
            idempotent_capture_count += int(outcome["idempotent_capture_count"])

        captured_event_count = sum(int(item.get("event_count") or 0) for item in captures)
        captured_relationship_count = sum(
            int(item.get("relationship_count") or 0) for item in captures
        )
        temp_diagnostics = self._inbox_temp_diagnostics(paths["inbox_dir"])
        result = {
            "processed_at": time.time(),
            "root": str(self.root),
            "processed_archive_scrub_schema": processed_archive_scrub["schema"],
            "processed_archive_scanned_count": processed_archive_scrub["scanned"],
            "processed_archive_scrubbed_count": processed_archive_scrub["scrubbed"],
            "processed_archive_clean_count": processed_archive_scrub["clean"],
            "processed_archive_skipped_count": processed_archive_scrub["skipped"],
            "processed_archive_symlink_refusal_count": processed_archive_scrub[
                "symlink_refusals"
            ],
            "processed_archive_scrub_error_count": processed_archive_scrub["errors"],
            "processed_archive_redaction_count": processed_archive_scrub["redactions"],
            "processed_archive_raw_digest_removed_count": processed_archive_scrub[
                "raw_digest_fields_removed"
            ],
            "processed_archive_post_pass_unsafe_count": processed_archive_scrub[
                "post_pass_unsafe"
            ],
            "processed_archive_post_pass_unverified_count": processed_archive_scrub[
                "post_pass_unverified"
            ],
            "error_resolution_completed_count": error_resolution_repair[
                "completed_count"
            ],
            "error_resolution_moved_count": error_resolution_repair["moved_count"],
            "error_resolution_failed_count": error_resolution_repair["failed_count"],
            "processed_file_count": processed_file_count,
            "error_file_count": error_file_count,
            "deferred_file_count": deferred_file_count,
            "repaired_empty_claim_count": repair["empty_removed"],
            "quarantined_claim_count": repair["malformed_quarantined"],
            # Compatibility count: quarantine now retains metadata evidence
            # only; the untrusted payload bytes are discarded.
            "quarantined_stale_temp_count": temp_repair["discarded"],
            "discarded_stale_temp_count": temp_repair["discarded"],
            "discarded_legacy_raw_error_count": legacy_error_repair["discarded"],
            "recovered_detached_discard_count": detached_discard_repair[
                "discarded"
            ],
            "scrubbed_legacy_evidence_count": legacy_evidence_repair["scrubbed"],
            "temp_quarantine_evidence_error_count": (
                temp_repair["evidence_errors"]
                + legacy_error_repair["evidence_errors"]
                + legacy_evidence_repair["errors"]
                + detached_discard_repair["errors"]
            ),
            "inbox_temp_file_count": temp_diagnostics["total"],
            "fresh_inbox_temp_file_count": temp_diagnostics["fresh"],
            "stale_inbox_temp_file_count": temp_diagnostics["stale"],
            "ignored_inbox_temp_file_count": temp_diagnostics["ignored"],
            "inbox_temp_stale_after_seconds": STALE_INBOX_TEMP_SECONDS,
            "captured_payload_count": len(captures),
            "idempotent_capture_count": idempotent_capture_count,
            "captured_event_count": captured_event_count,
            "captured_relationship_count": captured_relationship_count,
            "captures": captures,
            "errors": errors,
        }
        if (
            claims
            or temp_repair["discarded"]
            or legacy_error_repair["discarded"]
            or legacy_evidence_repair["scrubbed"]
            or detached_discard_repair["discarded"]
            or processed_archive_scrub["scrubbed"]
            or processed_archive_scrub["errors"]
            or error_resolution_repair["completed_count"]
            or error_resolution_repair["failed_count"]
        ):
            _atomic_write_private_text(
                paths["state_path"],
                json.dumps(
                    self._compact_process_result(result),
                    indent=2,
                    sort_keys=True,
                    default=str,
                ),
            )
        return result

    def _read_state(self, state_path: Path) -> dict[str, Any]:
        if not state_path.exists():
            return {}
        try:
            parsed = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception:
            LOGGER.warning("failed to read capture daemon state", exc_info=True)
            return {}
        if not isinstance(parsed, dict):
            return {}
        return self._compact_process_result(parsed)

    def _repair_legacy_state(self, state_path: Path) -> bool:
        """Canonicalize old daemon state only on an explicit process mutation."""

        if not state_path.exists():
            return False
        try:
            parsed = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception:
            LOGGER.warning("failed to read capture daemon state", exc_info=True)
            return False
        if not isinstance(parsed, dict):
            return False
        compact = self._compact_process_result(parsed)
        if compact == parsed:
            return False
        _atomic_write_private_text(
            state_path,
            json.dumps(compact, indent=2, sort_keys=True, default=str),
        )
        return True

    def _compact_process_result(self, result: dict[str, Any]) -> dict[str, Any]:
        """Return the content-free durable/status form of one daemon receipt."""

        scalar_keys = (
            "processed_at",
            "processed_file_count",
            "error_file_count",
            "deferred_file_count",
            "repaired_empty_claim_count",
            "quarantined_claim_count",
            "quarantined_stale_temp_count",
            "discarded_stale_temp_count",
            "discarded_legacy_raw_error_count",
            "recovered_detached_discard_count",
            "scrubbed_legacy_evidence_count",
            "temp_quarantine_evidence_error_count",
            "inbox_temp_file_count",
            "fresh_inbox_temp_file_count",
            "stale_inbox_temp_file_count",
            "ignored_inbox_temp_file_count",
            "inbox_temp_stale_after_seconds",
            "captured_payload_count",
            "idempotent_capture_count",
            "captured_event_count",
            "captured_relationship_count",
            "processed_archive_scrub_schema",
            "processed_archive_scanned_count",
            "processed_archive_scrubbed_count",
            "processed_archive_clean_count",
            "processed_archive_skipped_count",
            "processed_archive_symlink_refusal_count",
            "processed_archive_scrub_error_count",
            "processed_archive_redaction_count",
            "processed_archive_raw_digest_removed_count",
            "processed_archive_post_pass_unsafe_count",
            "processed_archive_post_pass_unverified_count",
            "error_resolution_completed_count",
            "error_resolution_moved_count",
            "error_resolution_failed_count",
        )
        compact: dict[str, Any] = {
            "protocol": "capture-daemon-state.v2",
            "content_free": True,
            "root": str(self.root),
        }
        for key in scalar_keys:
            if key in result:
                compact[key] = result[key]

        capture_keys = (
            "capture_id",
            "context_id",
            "source_tag",
            "speaker",
            "event_count",
            "relationship_count",
            "redaction_count",
            "idempotent_replay",
            "receipt_replay",
            "receipt_compact",
            "protocol",
            "capture_protocol",
        )
        compact["captures"] = [
            {key: item[key] for key in capture_keys if key in item}
            for item in result.get("captures", [])
            if isinstance(item, dict)
        ]

        error_keys = (
            "file",
            "failed_at",
            "batch_atomicity",
            "batch_record_count",
            "failed_record_index",
            "failed_capture_id",
            "committed_capture_count",
            "committed_capture_ids",
            "committed_event_count",
            "committed_relationship_count",
            "idempotent_replay_count",
            "receipt_replay_count",
            "committed_captures",
        )
        compact_errors: list[dict[str, Any]] = []
        for item in result.get("errors", []):
            if not isinstance(item, dict):
                continue
            safe_item = {key: item[key] for key in error_keys if key in item}
            if "file" in safe_item:
                safe_item["file"] = safe_public_error(
                    str(safe_item["file"]),
                    fallback="capture payload",
                )
            if item.get("error"):
                safe_item["error"] = safe_public_error(
                    str(item["error"]),
                    fallback="capture processing failed",
                )
            compact_errors.append(safe_item)
        compact["errors"] = compact_errors
        return compact

    def _capture_files(self, directory: Path) -> list[Path]:
        if not directory.exists():
            return []
        files: list[Path] = []
        try:
            entries = list(directory.iterdir())
        except FileNotFoundError:
            return []
        for path in entries:
            try:
                path_stat = path.lstat()
            except FileNotFoundError:
                continue
            if (
                stat.S_ISREG(path_stat.st_mode)
                and not path.is_symlink()
                and path.suffix.lower() in CAPTURE_SUFFIXES
                and not path.name.startswith(".")
                and not path.name.endswith(".tmp")
            ):
                files.append(path)
        return sorted(files, key=self._path_sort_key)

    def _path_sort_key(self, path: Path) -> tuple[float, str]:
        try:
            modified_at = float(path.lstat().st_mtime)
        except FileNotFoundError:
            modified_at = float("inf")
        return (modified_at, path.name)

    def _receipt_files(self, receipt_dir: Path) -> list[Path]:
        if not receipt_dir.exists():
            return []
        receipts: list[Path] = []
        for path in receipt_dir.iterdir():
            try:
                path_stat = path.lstat()
            except FileNotFoundError:
                continue
            if (
                stat.S_ISREG(path_stat.st_mode)
                and not path.is_symlink()
                and path.suffix == ".json"
                and CAPTURE_ID_RE.fullmatch(path.stem) is not None
            ):
                receipts.append(path)
        return sorted(receipts, key=self._path_sort_key)

    def _processing_claims(self, processing_dir: Path) -> list[tuple[Path, Path]]:
        if not processing_dir.exists():
            return []
        claims: list[tuple[Path, Path]] = []
        for claim_dir in processing_dir.iterdir():
            try:
                claim_stat = claim_dir.lstat()
            except FileNotFoundError:
                continue
            if (
                claim_dir.is_symlink()
                or not stat.S_ISDIR(claim_stat.st_mode)
                or CLAIM_DIR_RE.fullmatch(claim_dir.name) is None
                or claim_stat.st_uid != os.getuid()
                or stat.S_IMODE(claim_stat.st_mode) != 0o700
            ):
                continue
            payload_files = self._capture_files(claim_dir)
            if len(payload_files) == 1:
                claims.append((claim_dir, payload_files[0]))
        return sorted(claims, key=lambda item: self._path_sort_key(item[1]))

    def _processing_diagnostics(self, processing_dir: Path) -> dict[str, int]:
        diagnostics = {"empty": 0, "malformed": 0}
        if not processing_dir.exists():
            return diagnostics
        for claim_dir in processing_dir.iterdir():
            try:
                claim_stat = claim_dir.lstat()
            except FileNotFoundError:
                continue
            if (
                claim_dir.is_symlink()
                or not stat.S_ISDIR(claim_stat.st_mode)
                or CLAIM_DIR_RE.fullmatch(claim_dir.name) is None
                or claim_stat.st_uid != os.getuid()
                or stat.S_IMODE(claim_stat.st_mode) != 0o700
            ):
                diagnostics["malformed"] += 1
                continue
            state = self._claim_state(claim_dir)
            if state["missing"]:
                continue
            if state["malformed"]:
                diagnostics["malformed"] += 1
            elif not state["payloads"]:
                diagnostics["empty"] += 1
        return diagnostics

    def _claim_state(self, claim_dir: Path) -> dict[str, Any]:
        payloads = self._capture_files(claim_dir)
        child_names: list[str] = []
        unknown_names: list[str] = []
        try:
            children = list(claim_dir.iterdir())
        except FileNotFoundError:
            return {
                "payloads": [],
                "child_names": [],
                "unknown_names": [],
                "malformed": False,
                "missing": True,
            }
        for child in children:
            child_names.append(child.name)
            try:
                child_stat = child.lstat()
            except FileNotFoundError:
                continue
            safe_private_file = bool(
                stat.S_ISREG(child_stat.st_mode)
                and not stat.S_ISLNK(child_stat.st_mode)
                and child_stat.st_uid == os.getuid()
                and child_stat.st_nlink == 1
                and stat.S_IMODE(child_stat.st_mode) == 0o600
            )
            if child.name in {".lock", LEGACY_TEXT_IDENTITY_FILE}:
                if safe_private_file:
                    continue
            elif child in payloads and safe_private_file:
                continue
            unknown_names.append(child.name)
        identity_allowed = bool(
            not (claim_dir / LEGACY_TEXT_IDENTITY_FILE).exists()
            or (len(payloads) == 1 and payloads[0].suffix.lower() == ".txt")
            or not payloads
        )
        return {
            "payloads": payloads,
            "child_names": sorted(child_names),
            "unknown_names": sorted(unknown_names),
            "malformed": bool(
                len(payloads) > 1 or unknown_names or not identity_allowed
            ),
            "missing": False,
        }

    def _repair_processing_claims(self, paths: dict[str, Path]) -> dict[str, int]:
        repaired = {"empty_removed": 0, "malformed_quarantined": 0}
        processing_dir = paths["processing_dir"]
        now = time.time()
        for claim_dir in list(processing_dir.iterdir()):
            try:
                claim_stat = claim_dir.lstat()
            except FileNotFoundError:
                continue
            if (
                claim_dir.is_symlink()
                or not stat.S_ISDIR(claim_stat.st_mode)
                or CLAIM_DIR_RE.fullmatch(claim_dir.name) is None
            ):
                continue
            initial_state = self._claim_state(claim_dir)
            if initial_state["missing"]:
                continue
            if initial_state["malformed"]:
                quarantine = False
                with self._exclusive_lock(claim_dir / ".lock") as acquired:
                    if not acquired:
                        continue
                    state = self._claim_state(claim_dir)
                    if state["missing"] or not state["malformed"]:
                        continue
                    staged = _stage_tree_for_discard(
                        path=claim_dir,
                        staging_dir=paths["error_dir"],
                        expected_stat=claim_stat,
                    )
                    if staged is None:
                        continue
                    error_payload = {
                        "artifact_type": "malformed-capture-claim",
                        "discard_operation_id": _discard_operation_id(staged),
                        "cleanup_kind": "tree",
                        "claim": claim_dir.name,
                        "error": "malformed capture claim discarded before effect",
                        "children": [
                            safe_public_error(name, fallback="claim artifact")
                            for name in state["child_names"]
                        ],
                        "failed_at": time.time(),
                        "raw_payload_retained": True,
                        "disposition": "raw-claim-detached-pending-discard",
                        "payload_disposition": "raw-claim-detached-pending-discard",
                    }
                    evidence_path = self._unique_destination(
                        paths["error_dir"],
                        f"{claim_dir.name}.error.json",
                    )
                    try:
                        _atomic_write_private_text(
                            evidence_path,
                            json.dumps(error_payload, indent=2, sort_keys=True),
                        )
                    except Exception:
                        LOGGER.exception(
                            "failed to persist malformed claim discard evidence"
                        )
                        try:
                            os.replace(staged, claim_dir)
                            _fsync_directory(processing_dir)
                            _fsync_directory(paths["error_dir"])
                        except OSError:
                            quarantine = True
                            LOGGER.exception(
                                "failed to restore detached malformed claim"
                            )
                        continue
                    quarantine = True
                    try:
                        _remove_tree_without_following_links(
                            staged,
                            parent_dir=paths["error_dir"],
                        )
                    except (OSError, RuntimeError, ValueError):
                        LOGGER.exception(
                            "failed to discard detached malformed claim tree"
                        )
                        continue
                    error_payload["raw_payload_retained"] = False
                    error_payload["disposition"] = "raw-claim-discarded"
                    error_payload["payload_disposition"] = "raw-claim-discarded"
                    try:
                        _atomic_write_private_text(
                            evidence_path,
                            json.dumps(error_payload, indent=2, sort_keys=True),
                        )
                    except Exception:
                        LOGGER.exception(
                            "failed to finalize malformed claim discard evidence"
                        )
                if quarantine:
                    repaired["malformed_quarantined"] += 1
                continue
            if initial_state["payloads"]:
                continue
            newest_mtime = float(claim_stat.st_mtime)
            for child_name in initial_state["child_names"]:
                try:
                    newest_mtime = max(
                        newest_mtime,
                        float((claim_dir / child_name).lstat().st_mtime),
                    )
                except FileNotFoundError:
                    continue
            if now - newest_mtime < STALE_EMPTY_CLAIM_SECONDS:
                continue
            remove_empty = False
            with self._exclusive_lock(claim_dir / ".lock") as acquired:
                if not acquired:
                    continue
                state = self._claim_state(claim_dir)
                remove_empty = bool(
                    not state["missing"]
                    and not state["payloads"]
                    and not state["malformed"]
                )
            if remove_empty:
                self._cleanup_empty_claim(claim_dir)
                if not claim_dir.exists():
                    repaired["empty_removed"] += 1
        return repaired

    def _claim_inbox_file(
        self,
        *,
        inbox_path: Path,
        inbox_dir: Path,
        processing_dir: Path,
    ) -> tuple[Path, Path] | None:
        claim_dir = processing_dir / f"s2claim_{secrets.token_hex(16)}"
        _ensure_private_dir(claim_dir)
        safe_suffix = inbox_path.suffix.lower()
        if safe_suffix not in CAPTURE_SUFFIXES:
            safe_suffix = ".payload"
        claimed_path = claim_dir / f"payload-{secrets.token_hex(16)}{safe_suffix}"
        try:
            os.replace(inbox_path, claimed_path)
        except FileNotFoundError:
            self._cleanup_empty_claim(claim_dir)
            return None
        except Exception:
            self._cleanup_empty_claim(claim_dir)
            raise
        try:
            claimed_path.chmod(0o600)
        except PermissionError:
            LOGGER.warning("could not chmod claimed capture file %s", claimed_path)
        _fsync_directory(inbox_dir)
        _fsync_directory(claim_dir)
        _fsync_directory(processing_dir)
        return claim_dir, claimed_path

    @contextlib.contextmanager
    def _exclusive_lock(
        self,
        lock_path: Path,
        *,
        blocking: bool = False,
    ) -> Iterator[bool]:
        flags = os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        created = False
        try:
            fd = os.open(
                lock_path,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            created = True
        except FileExistsError:
            fd = os.open(lock_path, flags)
        except FileNotFoundError:
            yield False
            return
        acquired = False
        try:
            opened = os.fstat(fd)
            if created:
                os.fchmod(fd, 0o600)
                opened = os.fstat(fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.getuid()
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o600
            ):
                raise RuntimeError("capture lock identity is unsafe")
            visible = lock_path.lstat()
            if (
                stat.S_ISLNK(visible.st_mode)
                or visible.st_dev != opened.st_dev
                or visible.st_ino != opened.st_ino
                or visible.st_uid != opened.st_uid
                or visible.st_nlink != 1
                or stat.S_IMODE(visible.st_mode) != 0o600
            ):
                raise RuntimeError("capture lock path changed during open")
            try:
                operation = fcntl.LOCK_EX
                if not blocking:
                    operation |= fcntl.LOCK_NB
                fcntl.flock(fd, operation)
                acquired = True
            except BlockingIOError:
                acquired = False
            if acquired:
                held = os.fstat(fd)
                visible = lock_path.lstat()
                if (
                    held.st_dev != opened.st_dev
                    or held.st_ino != opened.st_ino
                    or visible.st_dev != opened.st_dev
                    or visible.st_ino != opened.st_ino
                    or visible.st_uid != opened.st_uid
                    or visible.st_nlink != 1
                    or stat.S_IMODE(visible.st_mode) != 0o600
                ):
                    raise RuntimeError("capture lock identity changed after acquisition")
            yield acquired
        finally:
            if acquired:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _process_claim(
        self,
        *,
        claim_dir: Path,
        path: Path,
        paths: dict[str, Path],
    ) -> dict[str, Any] | None:
        moved = False
        outcome: dict[str, Any] | None = None
        with self._exclusive_lock(claim_dir / ".lock") as acquired:
            if not acquired:
                return None
            captures: list[dict[str, Any]] = []
            payloads: list[dict[str, Any]] = []
            payload_document_prepared = False
            current_payload: dict[str, Any] | None = None
            current_record_index: int | None = None
            try:
                document_kind, payloads = self._prepare_payload_document(path)
                payload_document_prepared = True
                del document_kind
                for record_index, payload in enumerate(payloads):
                    current_payload = payload
                    current_record_index = record_index
                    captures.append(
                        self._capture_payload_exactly_once(path=path, payload=payload)
                    )
                try:
                    self._move_file(path, paths["processed_dir"])
                except Exception as exc:
                    raise CaptureCleanupPending(
                        f"capture committed but archive cleanup failed for {path.name}"
                    ) from exc
                moved = True
                outcome = {
                    "processed_file_count": 1,
                    "error_file_count": 0,
                    "idempotent_capture_count": sum(
                        1 for item in captures if item.get("idempotent_replay")
                    ),
                    "captures": captures,
                    "errors": [],
                }
            except CaptureCleanupPending:
                LOGGER.warning(
                    "capture commit is durable; cleanup remains pending for %s",
                    path,
                    exc_info=True,
                )
                return None
            except CaptureDeferred:
                return None
            except Exception as exc:
                LOGGER.exception("failed to process capture payload %s", path)
                error_payload = {
                    "file": safe_public_error(
                        path.name,
                        fallback="capture payload",
                    ),
                    "error": safe_public_error(
                        exc,
                        fallback="capture processing failed",
                    ),
                    "failed_at": time.time(),
                    "batch_atomicity": "per-record",
                    "batch_record_count": len(payloads),
                    "failed_record_index": current_record_index,
                    "failed_capture_id": (
                        str(current_payload.get("capture_id") or "")
                        if isinstance(current_payload, dict)
                        else ""
                    ),
                    "raw_payload_retained": not payload_document_prepared,
                    "redacted_payload_retained": bool(payload_document_prepared),
                    "payload_disposition": (
                        "redacted-payload-quarantined"
                        if payload_document_prepared
                        else "raw-payload-pending-discard"
                    ),
                    **self._committed_capture_audit(captures),
                }
                staged_raw: Path | None = None
                if not payload_document_prepared:
                    try:
                        path_stat = path.lstat()
                    except FileNotFoundError:
                        path_stat = None
                    if path_stat is None:
                        return None
                    staged_raw = _stage_regular_file_for_discard(
                        path=path,
                        staging_dir=paths["error_dir"],
                        expected_stat=path_stat,
                    )
                    if staged_raw is None:
                        return None
                    error_payload.update(
                        {
                            "artifact_type": "rejected-raw-capture-payload",
                            "discard_operation_id": _discard_operation_id(staged_raw),
                            "cleanup_kind": "file",
                            "disposition": "raw-payload-detached-pending-discard",
                        }
                    )
                sidecar = self._unique_destination(
                    paths["error_dir"],
                    f"capture-error-{int(time.time())}-{secrets.token_hex(8)}.json",
                )
                try:
                    _atomic_write_private_text(
                        sidecar,
                        json.dumps(error_payload, indent=2, sort_keys=True),
                    )
                except Exception:
                    if staged_raw is not None:
                        try:
                            os.replace(staged_raw, path)
                            _fsync_directory(claim_dir)
                            _fsync_directory(paths["error_dir"])
                        except OSError:
                            LOGGER.exception(
                                "failed to restore detached rejected capture payload"
                            )
                    raise
                if payload_document_prepared:
                    try:
                        path.lstat()
                    except FileNotFoundError:
                        pass
                    else:
                        self._move_file(path, paths["error_dir"])
                elif staged_raw is not None:
                    moved = True
                    try:
                        staged_raw.unlink()
                        _fsync_directory(paths["error_dir"])
                    except FileNotFoundError:
                        _fsync_directory(paths["error_dir"])
                    except OSError:
                        LOGGER.exception(
                            "failed to discard rejected raw capture payload"
                        )
                    else:
                        error_payload["raw_payload_retained"] = False
                        error_payload["disposition"] = "raw-payload-discarded"
                        error_payload["payload_disposition"] = (
                            "raw-payload-discarded"
                        )
                        try:
                            _atomic_write_private_text(
                                sidecar,
                                json.dumps(error_payload, indent=2, sort_keys=True),
                            )
                        except Exception:
                            LOGGER.exception(
                                "failed to finalize rejected payload discard evidence"
                            )
                moved = True
                outcome = {
                    "processed_file_count": 0,
                    "error_file_count": 1,
                    "idempotent_capture_count": sum(
                        1 for item in captures if item.get("idempotent_replay")
                    ),
                    "captures": captures,
                    "errors": [error_payload],
                }
        if moved:
            self._cleanup_empty_claim(claim_dir)
        return outcome

    def _committed_capture_audit(
        self,
        captures: list[dict[str, Any]],
    ) -> dict[str, Any]:
        committed: list[dict[str, Any]] = []
        for capture in captures:
            capture_id = _canonical_capture_id(capture.get("capture_id"))
            committed.append(
                {
                    "capture_id": capture_id,
                    "context_id": str(capture.get("context_id") or "default"),
                    "source_tag": str(capture.get("source_tag") or ""),
                    "event_count": int(capture.get("event_count") or 0),
                    "relationship_count": int(
                        capture.get("relationship_count") or 0
                    ),
                    "idempotent_replay": bool(
                        capture.get("idempotent_replay")
                    ),
                    "receipt_replay": bool(capture.get("receipt_replay")),
                }
            )
        return {
            "committed_capture_count": len(committed),
            "committed_capture_ids": [
                item["capture_id"] for item in committed
            ],
            "committed_event_count": sum(
                int(item["event_count"]) for item in committed
            ),
            "committed_relationship_count": sum(
                int(item["relationship_count"]) for item in committed
            ),
            "idempotent_replay_count": sum(
                1 for item in committed if item["idempotent_replay"]
            ),
            "receipt_replay_count": sum(
                1 for item in committed if item["receipt_replay"]
            ),
            "committed_captures": committed,
        }

    def _load_payload_document(self, path: Path) -> tuple[str, list[dict[str, Any]]]:
        raw = self._read_capture_text(path)
        suffix = path.suffix.lower()
        if suffix == ".txt":
            payload: dict[str, Any] = {
                "version": 1,
                # An inbox filename is untrusted transport metadata, not a
                # semantic source label. Never let it enter request identity.
                "source_tag": "legacy-text-capture",
                "text": raw,
            }
            identity_path = path.parent / LEGACY_TEXT_IDENTITY_FILE
            if (
                CLAIM_DIR_RE.fullmatch(path.parent.name) is not None
                and identity_path.exists()
            ):
                try:
                    identity = json.loads(self._read_capture_text(identity_path))
                except Exception as exc:
                    raise ValueError("legacy text capture identity is invalid") from exc
                if not isinstance(identity, dict):
                    raise ValueError("legacy text capture identity must be an object")
                payload.update(identity)
                payload["text"] = raw
            return "txt", [payload]
        if suffix == ".jsonl":
            payloads: list[dict[str, Any]] = []
            for line_number, line in enumerate(raw.splitlines(), start=1):
                if not line.strip():
                    continue
                parsed = json.loads(line)
                if not isinstance(parsed, dict):
                    raise ValueError(f"jsonl line {line_number} must be an object")
                payloads.append(parsed)
            if not payloads:
                raise ValueError("capture JSONL must contain at least one object")
            return "jsonl", payloads
        parsed = json.loads(raw or "{}")
        if isinstance(parsed, list):
            if not all(isinstance(item, dict) for item in parsed):
                raise ValueError("capture JSON list items must be objects")
            if not parsed:
                raise ValueError("capture JSON list must not be empty")
            return "json-list", parsed
        if not isinstance(parsed, dict):
            raise ValueError("capture JSON must be an object or list of objects")
        return "json-object", [parsed]

    def _prepare_payload_document(
        self,
        path: Path,
    ) -> tuple[str, list[dict[str, Any]]]:
        document_kind, raw_payloads = self._load_payload_document(path)
        payloads: list[dict[str, Any]] = []
        changed = False
        capture_ids: set[str] = set()
        for ordinal, raw_payload in enumerate(raw_payloads):
            payload = dict(raw_payload)
            raw_version = payload.get("version", 1)
            if isinstance(raw_version, bool):
                raise ValueError("capture payload version must be 1 or 2")
            try:
                version = int(raw_version)
            except (TypeError, ValueError) as exc:
                raise ValueError("capture payload version must be 1 or 2") from exc
            if version not in (1, CAPTURE_PROTOCOL_VERSION):
                raise ValueError(f"unsupported capture payload version: {version}")
            payload["version"] = version
            if version == CAPTURE_PROTOCOL_VERSION:
                capture_id = _canonical_capture_id(payload.get("capture_id"))
            elif payload.get("capture_id"):
                capture_id = _canonical_capture_id(payload.get("capture_id"))
            else:
                capture_id = new_capture_id()
            payload["capture_id"] = capture_id
            payload.pop("input_sha256", None)
            payload = self._normalize_payload_before_capture(
                path=path,
                payload=payload,
                version=version,
            )
            if capture_id in capture_ids:
                raise ValueError(
                    f"duplicate capture_id within one batch: {capture_id}"
                )
            capture_ids.add(capture_id)
            payloads.append(payload)
            changed = changed or payload != raw_payload

        if document_kind == "txt":
            self._persist_legacy_text_payload(path=path, payload=payloads[0])
        elif changed:
            self._persist_payload_document(
                path=path,
                document_kind=document_kind,
                payloads=payloads,
            )
        return document_kind, payloads

    def _normalize_payload_before_capture(
        self,
        *,
        path: Path,
        payload: dict[str, Any],
        version: int,
    ) -> dict[str, Any]:
        text = str(payload.get("text") or "").strip()
        if not text:
            raise ValueError(f"{path.name} capture payload text must not be empty")
        redacted_text, text_redactions = redact_capture_text(text)
        try:
            inherited_redactions = max(
                0,
                min(int(payload.get("redaction_count", 0) or 0), 1_000_000),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("redaction_count must be an integer") from exc
        raw_metadata = payload.get("metadata", {})
        safe_metadata, metadata_redactions = self._safe_capture_metadata(
            raw_metadata if isinstance(raw_metadata, dict) else {}
        )
        source_default = "capture-daemon" if version == 2 else path.stem
        source_tag = mlx_backend.sanitize_tag(
            str(
                payload.get("source_tag")
                or payload.get("tag")
                or source_default
            )
        ).replace(" ", "-")
        context_id = mlx_backend.sanitize_context_id(
            str(payload.get("context_id") or "default")
        )
        speaker = mlx_backend.sanitize_agent_id(
            str(payload.get("speaker") or "capture-daemon")
        )
        try:
            surprise_threshold = float(payload.get("surprise_threshold", 0.5))
        except (TypeError, ValueError) as exc:
            raise ValueError("surprise_threshold must be a finite number") from exc
        if not math.isfinite(surprise_threshold):
            raise ValueError("surprise_threshold must be a finite number")
        surprise_threshold = min(max(surprise_threshold, 0.0), 1.0)
        raw_min_sentences = payload.get("min_segment_sentences", 1)
        if isinstance(raw_min_sentences, bool):
            raise ValueError("min_segment_sentences must be an integer")
        try:
            min_segment_sentences = max(1, int(raw_min_sentences))
        except (TypeError, ValueError) as exc:
            raise ValueError("min_segment_sentences must be an integer") from exc
        canonical_input_keys = {
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
        unknown_fields = {
            str(key): value
            for key, value in payload.items()
            if str(key) not in canonical_input_keys
        }
        _, unknown_redactions = redact_sensitive_value(unknown_fields)
        try:
            prior_dropped_fields = max(
                0,
                min(
                    int(payload.get("dropped_top_level_field_count", 0) or 0),
                    1_000_000,
                ),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "dropped_top_level_field_count must be an integer"
            ) from exc
        normalized: dict[str, Any] = {
            "version": int(version),
            "capture_id": _canonical_capture_id(payload.get("capture_id")),
            "text": redacted_text,
            "context_id": context_id,
            "source_tag": source_tag,
            "speaker": speaker,
            "surprise_threshold": surprise_threshold,
            "min_segment_sentences": min_segment_sentences,
            "metadata": safe_metadata,
            "redaction_count": int(
                inherited_redactions
                + text_redactions
                + metadata_redactions
                + unknown_redactions
            ),
            "raw_text_stored": False,
            "dropped_top_level_field_count": (
                prior_dropped_fields + len(unknown_fields)
            ),
        }
        if payload.get("created_at") is not None:
            try:
                created_at = float(payload["created_at"])
            except (TypeError, ValueError) as exc:
                raise ValueError("created_at must be a finite timestamp") from exc
            if not math.isfinite(created_at):
                raise ValueError("created_at must be a finite timestamp")
            normalized["created_at"] = created_at
        return normalized

    def _safe_capture_metadata(
        self,
        metadata: dict[str, Any],
    ) -> tuple[dict[str, Any], int]:
        redacted_value, value_redactions = redact_sensitive_value(metadata)
        redacted_value, _removed_digest_count = strip_untrusted_raw_digest_fields(
            redacted_value
        )

        def strip_sensitive_fields(value: Any) -> Any:
            if isinstance(value, dict):
                clean: dict[str, Any] = {}
                for raw_key, item in value.items():
                    key = str(raw_key)
                    folded = key.strip().casefold().replace("-", "_")
                    compact_key = folded.replace("_", "")
                    if (
                        folded in SENSITIVE_METADATA_KEYS
                        or is_sensitive_key(key)
                        or compact_key
                        in {
                            "apikey",
                            "accesstoken",
                            "refreshtoken",
                            "clientsecret",
                            "privatekey",
                        }
                    ):
                        continue
                    clean[key] = strip_sensitive_fields(item)
                return clean
            if isinstance(value, list):
                return [strip_sensitive_fields(item) for item in value]
            return value

        stripped = strip_sensitive_fields(redacted_value)
        try:
            serialized = json.dumps(
                stripped,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("capture metadata must be finite JSON-safe data") from exc
        safe = json.loads(serialized)
        return (
            safe if isinstance(safe, dict) else {},
            int(value_redactions),
        )

    def _persist_legacy_text_payload(
        self,
        *,
        path: Path,
        payload: dict[str, Any],
    ) -> None:
        _atomic_write_private_text(path, str(payload["text"]))
        identity = {key: value for key, value in payload.items() if key != "text"}
        _atomic_write_private_text(
            path.parent / LEGACY_TEXT_IDENTITY_FILE,
            json.dumps(identity, indent=2, sort_keys=True),
        )

    def _persist_payload_document(
        self,
        *,
        path: Path,
        document_kind: str,
        payloads: list[dict[str, Any]],
    ) -> None:
        if document_kind == "json-object":
            text = json.dumps(payloads[0], indent=2, sort_keys=True)
        elif document_kind == "json-list":
            text = json.dumps(payloads, indent=2, sort_keys=True)
        elif document_kind == "jsonl":
            text = "\n".join(
                json.dumps(payload, sort_keys=True, separators=(",", ":"))
                for payload in payloads
            ) + "\n"
        else:
            return
        _atomic_write_private_text(path, text)

    def _read_capture_text(self, path: Path) -> str:
        return self._read_capture_bytes(path).decode("utf-8", errors="replace")

    def _read_capture_bytes(self, path: Path) -> bytes:
        if path.is_symlink():
            raise ValueError("capture inbox refuses symlink payloads")
        try:
            path_stat = path.lstat()
        except FileNotFoundError as exc:
            raise ValueError(f"capture file disappeared before processing: {path.name}") from exc
        if not stat.S_ISREG(path_stat.st_mode):
            raise ValueError("capture inbox payload must be a regular file")
        if path_stat.st_size > MAX_CAPTURE_BYTES:
            raise ValueError(f"capture file exceeds {MAX_CAPTURE_BYTES} bytes")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            opened_stat = os.fstat(fd)
            if not stat.S_ISREG(opened_stat.st_mode):
                raise ValueError("capture inbox payload must be a regular file")
            if opened_stat.st_size > MAX_CAPTURE_BYTES:
                raise ValueError(f"capture file exceeds {MAX_CAPTURE_BYTES} bytes")
            chunks: list[bytes] = []
            remaining = opened_stat.st_size
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw_bytes = b"".join(chunks)
        finally:
            os.close(fd)
        return raw_bytes

    def _canonical_capture_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        capture_id = _canonical_capture_id(payload.get("capture_id"))
        text, text_redactions = redact_capture_text(str(payload.get("text") or "").strip())
        if not text:
            raise ValueError("capture payload text must not be empty")
        raw_metadata = payload.get("metadata", {})
        safe_metadata, metadata_redactions = self._safe_capture_metadata(
            raw_metadata if isinstance(raw_metadata, dict) else {}
        )
        inherited_redactions = int(payload.get("redaction_count", 0) or 0)
        redaction_count = int(
            inherited_redactions + text_redactions + metadata_redactions
        )
        return {
            "capture_id": capture_id,
            "text": text,
            "context_id": mlx_backend.sanitize_context_id(
                str(payload.get("context_id") or "default")
            ),
            "source_tag": mlx_backend.sanitize_tag(
                str(payload.get("source_tag") or "capture-daemon")
            ).replace(" ", "-"),
            "speaker": mlx_backend.sanitize_agent_id(
                str(payload.get("speaker") or "capture-daemon")
            ),
            "surprise_threshold": float(payload.get("surprise_threshold", 0.5)),
            "min_segment_sentences": int(payload.get("min_segment_sentences", 1)),
            "metadata": {
                **safe_metadata,
                "capture_daemon": True,
                "capture_id": capture_id,
                "capture_protocol": "capture.v2",
                "redaction_count": redaction_count,
                "raw_text_stored": False,
            },
        }

    def _request_fingerprint(self, request: dict[str, Any]) -> str:
        canonical = json.dumps(
            _json_safe(request, {}),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return _sha256_text(canonical)

    def _capture_payload_exactly_once(
        self,
        *,
        path: Path,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        capture_id = _canonical_capture_id(payload.get("capture_id"))
        request = self._canonical_capture_request(payload)
        request_fingerprint = self._request_fingerprint(request)
        paths = self.paths()
        lock_path = paths["lock_dir"] / f"{capture_id}.lock"
        with self._exclusive_lock(lock_path) as acquired:
            if not acquired:
                raise CaptureDeferred(f"capture {capture_id} is owned by another worker")
            receipt_path = paths["receipt_dir"] / f"{capture_id}.json"
            receipt_replay = False
            if receipt_path.exists():
                try:
                    receipt = self._read_receipt(receipt_path)
                    receipt_replay = bool(
                        receipt["capture_id"] == capture_id
                        and receipt["request_fingerprint"] == request_fingerprint
                    )
                    if not receipt_replay:
                        self._quarantine_transport_receipt(receipt_path)
                except Exception:
                    LOGGER.warning(
                        "quarantining invalid transport receipt %s",
                        receipt_path,
                        exc_info=True,
                    )
                    self._quarantine_transport_receipt(receipt_path)

            # The SQLite capture_operations ledger is authoritative. Even a
            # matching transport receipt must replay through the backend so a
            # restored database cannot silently lose a capture.
            result = self._capture_payload(
                path=path,
                payload=payload,
                request=request,
            )
            try:
                compact_result = self._compact_capture_result(result)
                receipt_payload = {
                    "version": 1,
                    "capture_id": capture_id,
                    "request_fingerprint": request_fingerprint,
                    "committed_at": time.time(),
                    "result": compact_result,
                }
                _atomic_write_private_text(
                    receipt_path,
                    json.dumps(receipt_payload, indent=2, sort_keys=True),
                )
            except Exception as exc:
                raise CaptureCleanupPending(
                    f"capture {capture_id} committed but receipt persistence failed"
                ) from exc
            compact_result["idempotent_replay"] = bool(
                result.get("idempotent_replay")
            )
            compact_result["receipt_replay"] = receipt_replay
            return compact_result

    def _quarantine_transport_receipt(self, receipt_path: Path) -> None:
        if not receipt_path.exists():
            return
        destination = receipt_path.parent / (
            f"stale-{receipt_path.stem}-{int(time.time() * 1000)}-"
            f"{secrets.token_hex(8)}.json"
        )
        try:
            os.replace(receipt_path, destination)
            _fsync_directory(receipt_path.parent)
        except FileNotFoundError:
            return
        except OSError:
            LOGGER.warning(
                "could not quarantine stale transport receipt %s; it will be replaced after ledger verification",
                receipt_path,
                exc_info=True,
            )

    def _read_receipt(self, receipt_path: Path) -> dict[str, Any]:
        try:
            parsed = json.loads(self._read_capture_text(receipt_path))
        except Exception as exc:
            raise ValueError(f"invalid capture receipt {receipt_path.name}") from exc
        if not isinstance(parsed, dict):
            raise ValueError(f"invalid capture receipt {receipt_path.name}")
        capture_id = _canonical_capture_id(parsed.get("capture_id"))
        request_fingerprint = str(parsed.get("request_fingerprint") or "")
        if re.fullmatch(r"[0-9a-f]{64}", request_fingerprint) is None:
            raise ValueError(f"invalid capture receipt digest for {capture_id}")
        result = parsed.get("result")
        if not isinstance(result, dict):
            raise ValueError(f"invalid capture receipt result for {capture_id}")
        return {
            **parsed,
            "capture_id": capture_id,
            "request_fingerprint": request_fingerprint,
            "result": result,
        }

    def _capture_payload(
        self,
        *,
        path: Path,
        payload: dict[str, Any],
        request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        canonical_request = request or self._canonical_capture_request(payload)
        capture_id = _canonical_capture_id(canonical_request.get("capture_id"))
        capture = self.backend.capture_conversation(**canonical_request)
        return {
            "capture_id": capture_id,
            "context_id": capture.get("context_id") or "default",
            "source_tag": capture.get("source_tag") or canonical_request["source_tag"],
            "speaker": capture.get("speaker"),
            "event_count": int(capture.get("event_count") or 0),
            "relationship_count": int(capture.get("relationship_count") or 0),
            "agent_deployment": capture.get("agent_deployment"),
            "redaction_count": int(
                canonical_request["metadata"].get("redaction_count") or 0
            ),
            "idempotent_replay": bool(capture.get("idempotent_replay")),
        }

    def _compact_capture_result(self, result: dict[str, Any]) -> dict[str, Any]:
        deployment = result.get("agent_deployment")
        compact_deployment: dict[str, Any] | None = None
        if isinstance(deployment, dict):
            compact_deployment = {
                key: _json_safe(deployment[key], None)
                for key in (
                    "action",
                    "context_id",
                    "event_id",
                    "event_type",
                    "published_at",
                )
                if key in deployment
            }
        return {
            "capture_id": _canonical_capture_id(result.get("capture_id")),
            "context_id": str(result.get("context_id") or "default"),
            "source_tag": str(result.get("source_tag") or "capture-daemon"),
            "speaker": result.get("speaker"),
            "event_count": int(result.get("event_count") or 0),
            "relationship_count": int(result.get("relationship_count") or 0),
            "agent_deployment": compact_deployment,
            "redaction_count": int(result.get("redaction_count") or 0),
        }

    def _unique_destination(self, destination_dir: Path, name: str) -> Path:
        _ensure_private_dir(destination_dir)
        destination = destination_dir / name
        if not destination.exists():
            return destination
        candidate = Path(name)
        return destination_dir / (
            f"{candidate.stem}-{int(time.time() * 1000)}-"
            f"{secrets.token_hex(8)}{candidate.suffix}"
        )

    def _move_file(self, path: Path, destination_dir: Path) -> Path:
        _ensure_private_dir(destination_dir, tighten_existing=True)
        source_stat = path.lstat()
        if not stat.S_ISREG(source_stat.st_mode) or stat.S_ISLNK(
            source_stat.st_mode
        ):
            raise ValueError("capture archive source must be a regular file")

        # Recover a crash after the no-replace link but before source unlink.
        for existing in destination_dir.iterdir():
            try:
                existing_stat = existing.lstat()
            except FileNotFoundError:
                continue
            if (
                stat.S_ISREG(existing_stat.st_mode)
                and not stat.S_ISLNK(existing_stat.st_mode)
                and (int(existing_stat.st_dev), int(existing_stat.st_ino))
                == (int(source_stat.st_dev), int(source_stat.st_ino))
            ):
                path.unlink()
                _fsync_directory(path.parent)
                _fsync_directory(destination_dir)
                return existing

        candidate = Path(path.name)
        destination: Path | None = None
        for attempt in range(128):
            if attempt == 0:
                proposed = destination_dir / candidate.name
            else:
                proposed = destination_dir / (
                    f"{candidate.stem}-{int(time.time() * 1000)}-"
                    f"{secrets.token_hex(8)}{candidate.suffix}"
                )
            try:
                # link(2) is an atomic no-overwrite reservation and transfer
                # within this single-filesystem transport root. Unlike
                # check-then-replace, a colliding archive is never clobbered.
                os.link(path, proposed, follow_symlinks=False)
            except FileExistsError:
                continue
            destination = proposed
            break
        if destination is None:
            raise FileExistsError("could not reserve a unique capture archive path")

        descriptor = -1
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(destination, flags)
            linked_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(linked_stat.st_mode)
                or (int(linked_stat.st_dev), int(linked_stat.st_ino))
                != (int(source_stat.st_dev), int(source_stat.st_ino))
            ):
                raise ValueError("capture archive reservation changed unexpectedly")
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        except Exception:
            try:
                destination.unlink()
                _fsync_directory(destination_dir)
            except OSError:
                LOGGER.exception("failed to roll back capture archive reservation")
            raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)

        _fsync_directory(destination_dir)
        try:
            path.unlink()
        except Exception:
            # Keep both hard links. A retry recognizes the shared inode and
            # completes the source unlink without duplicating the archive.
            _fsync_directory(path.parent)
            raise
        _fsync_directory(path.parent)
        return destination

    def _cleanup_empty_claim(self, claim_dir: Path) -> None:
        processing_dir = self.paths()["processing_dir"]
        if (
            claim_dir.parent != processing_dir
            or CLAIM_DIR_RE.fullmatch(claim_dir.name) is None
        ):
            raise ValueError("capture claim cleanup escaped its processing directory")
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            parent_fd = os.open(processing_dir, flags)
        except FileNotFoundError:
            return
        claim_fd = -1
        try:
            try:
                claim_stat = os.stat(
                    claim_dir.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return
            if stat.S_ISLNK(claim_stat.st_mode) or not stat.S_ISDIR(
                claim_stat.st_mode
            ):
                raise ValueError("capture claim cleanup target must be a real directory")
            claim_fd = os.open(claim_dir.name, flags, dir_fd=parent_fd)
            for private_name in (".lock", LEGACY_TEXT_IDENTITY_FILE):
                try:
                    os.unlink(private_name, dir_fd=claim_fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    return
            try:
                os.rmdir(claim_dir.name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError:
                return
            os.fsync(parent_fd)
        finally:
            if claim_fd >= 0:
                os.close(claim_fd)
            os.close(parent_fd)


def build_parser() -> argparse.ArgumentParser:
    parser = SecretSafeArgumentParser(description="Run the SYNAPSE-S2 capture inbox daemon.")
    parser.add_argument("--capture-root", default=None)
    parser.add_argument("--state", default=None)
    parser.add_argument("--memory-db", default=None)
    parser.add_argument("--dimension", type=int, default=1024)
    parser.add_argument("--neurons", type=int, default=5400)
    parser.add_argument("--top-k", type=int, default=256)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--max-files", type=int, default=50)
    parser.add_argument("--poll-transcript-sources", action="store_true")
    parser.add_argument("--max-transcript-bytes", type=int, default=256_000)
    return parser


def backend_from_args(args: argparse.Namespace) -> Any:
    from backend_router import core_client_if_required

    client = core_client_if_required(
        memory_path=args.memory_db,
        state_path=args.state,
        capture_root=args.capture_root,
        local_config={
            "dimension": args.dimension,
            "num_neurons": args.neurons,
            "default_top_k": args.top_k,
        },
        local_defaults={
            "dimension": 1024,
            "num_neurons": 5400,
            "default_top_k": 256,
        },
    )
    if client is not None:
        return client
    return mlx_backend.SpikingAttentionBackend(
        dimension=args.dimension,
        num_neurons=args.neurons,
        default_top_k=args.top_k,
        compile_graph=False,
        state_path=args.state,
        memory_path=args.memory_db,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    daemon = CaptureInboxDaemon(root=args.capture_root, backend=backend_from_args(args))
    if args.once:
        result = daemon.process_once(max_files=args.max_files)
        if args.poll_transcript_sources:
            result["transcript_sources"] = _poll_transcript_sources(
                root=args.capture_root,
                backend=daemon.backend,
                max_bytes=args.max_transcript_bytes,
            )
        print(json.dumps(result, sort_keys=True, default=str))
        return 0
    LOGGER.info("starting SYNAPSE-S2 capture inbox daemon root=%s", daemon.root)
    while True:
        daemon.process_once(max_files=args.max_files)
        if args.poll_transcript_sources:
            _poll_transcript_sources(
                root=args.capture_root,
                backend=daemon.backend,
                max_bytes=args.max_transcript_bytes,
            )
        time.sleep(max(0.25, float(args.poll_interval)))


def _poll_transcript_sources(
    *,
    root: str | os.PathLike[str] | None,
    backend: Any,
    max_bytes: int,
) -> dict[str, Any]:
    try:
        import transcript_capture

        return transcript_capture.TranscriptCaptureManager(
            root=root,
            backend=backend,
        ).poll_sources(max_bytes=max_bytes)
    except Exception as exc:
        LOGGER.exception("transcript source polling failed")
        return {
            "error": safe_public_error(
                exc,
                fallback="transcript source polling failed",
            )
        }


if __name__ == "__main__":
    raise SystemExit(main())

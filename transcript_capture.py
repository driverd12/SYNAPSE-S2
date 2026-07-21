from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import logging
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Iterator

import mlx_backend
from redaction import (
    SECRET_SAFE_LOG_FORMAT,
    SecretRedactingFormatter,
    SecretSafeArgumentParser,
    redact_capture_text,
    redact_sensitive_value,
    reject_sensitive_identifier,
    safe_public_error,
    strip_untrusted_raw_digest_fields,
)


LOGGER = logging.getLogger("synapse_s2.transcript_capture")
if not LOGGER.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(SecretRedactingFormatter(SECRET_SAFE_LOG_FORMAT))
    LOGGER.addHandler(_handler)
LOGGER.setLevel(os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper())
LOGGER.propagate = False

MAX_TRANSCRIPT_DELTA_BYTES = 256_000
MAX_TRANSCRIPT_STATE_BYTES = 8_000_000
SOURCE_STATE_VERSION = 3
APP_STATE_VERSION = 1
SOURCE_INSTANCE_ID_RE = re.compile(r"s2src_[0-9a-f]{32}")
APP_DETECT_SYSTEM_EVENTS_TIMEOUT_SECONDS = float(
    os.getenv("SYNAPSE_S2_APP_DETECT_TIMEOUT_SECONDS", "12.0")
)
APP_DETECT_PS_TIMEOUT_SECONDS = 2.0
APP_SNAPSHOT_ACCESSIBILITY_TIMEOUT_SECONDS = float(
    os.getenv("SYNAPSE_S2_APP_SNAPSHOT_TIMEOUT_SECONDS", "8.0")
)
CLIPBOARD_READ_TIMEOUT_SECONDS = 5.0
ALLOWED_TRANSCRIPT_SUFFIXES = {
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".txt",
}
SENSITIVE_PATH_FRAGMENTS = {
    ".aws",
    ".gnupg",
    ".ssh",
    ".env",
    "1password",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "keychain",
    "private_key",
    "secret",
    "secrets",
}
SENSITIVE_CREDENTIAL_STORE_PARTS = {
    ".aws",
    ".azure",
    ".docker",
    ".kube",
    "gcloud",
    "google-cloud-sdk",
}
SENSITIVE_CREDENTIAL_FILENAMES = {
    ".dockercfg",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "accesstokens.json",
    "application_default_credentials.json",
    "azureprofile.json",
}


def resolve_capture_root(root: str | os.PathLike[str] | None = None) -> Path:
    if root is not None:
        reject_sensitive_identifier(root, field="capture_root")
        return Path(root).expanduser().resolve()
    configured = os.getenv("SYNAPSE_S2_CAPTURE_ROOT")
    if configured:
        reject_sensitive_identifier(configured, field="capture_root")
        return Path(configured).expanduser().resolve()
    return (Path.cwd() / ".synapse_s2").resolve()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8")).hexdigest()


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(str(path).encode("utf-8")).hexdigest()


def _capture_id_for_file_delta(
    *,
    source_instance_id: str,
    stream_generation: int,
    cursor_start: int,
    cursor_end: int,
) -> str:
    """Return the logical operation id for one durable file-tail delta.

    The random source instance is minted at explicit registration and persisted
    independently from the mutable cursor cache. Path, capture root, inode,
    mtime, and content hashes are deliberately excluded. They may help detect a
    rotation, but they never define capture identity.
    """

    payload = "\x1f".join(
        (
            "file-tail.v3",
            str(source_instance_id),
            str(int(stream_generation)),
            str(int(cursor_start)),
            str(int(cursor_end)),
        )
    ).encode("utf-8")
    return "s2cap_" + hashlib.sha256(payload).hexdigest()[:32]


@contextmanager
def _exclusive_file_lock(
    path: Path,
    *,
    blocking: bool,
) -> Iterator[bool]:
    """Hold a private advisory lock for the complete protected operation."""

    _ensure_private_lock_directory(path.parent)

    flags = os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    created = False
    try:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        descriptor = os.open(path, flags)
    acquired = False
    try:
        opened = os.fstat(descriptor)
        if created:
            os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise RuntimeError("transcript lock identity is unsafe")
        visible = path.lstat()
        if (
            stat.S_ISLNK(visible.st_mode)
            or visible.st_dev != opened.st_dev
            or visible.st_ino != opened.st_ino
            or visible.st_uid != opened.st_uid
            or visible.st_nlink != 1
            or stat.S_IMODE(visible.st_mode) != 0o600
        ):
            raise RuntimeError("transcript lock path changed during open")
        lock_flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(descriptor, lock_flags)
            acquired = True
        except BlockingIOError:
            yield False
            return
        held = os.fstat(descriptor)
        visible = path.lstat()
        if (
            held.st_dev != opened.st_dev
            or held.st_ino != opened.st_ino
            or visible.st_dev != opened.st_dev
            or visible.st_ino != opened.st_ino
            or visible.st_uid != opened.st_uid
            or visible.st_nlink != 1
            or stat.S_IMODE(visible.st_mode) != 0o600
        ):
            raise RuntimeError("transcript lock identity changed after acquisition")
        yield True
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _ensure_private_lock_directory(path: Path) -> None:
    """Validate an existing lock parent or create exactly one private leaf."""

    try:
        parent = path.parent.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            "transcript lock directory parent must already exist"
        ) from exc
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise RuntimeError("transcript lock parent ancestor is unsafe")
    try:
        current = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700, parents=False)
        current = path.lstat()
        parent_after = path.parent.lstat()
        if (
            parent_after.st_dev != parent.st_dev
            or parent_after.st_ino != parent.st_ino
        ):
            raise RuntimeError("transcript lock parent changed during creation")
        if stat.S_IMODE(current.st_mode) != 0o700:
            raise RuntimeError("new transcript lock parent must have mode 0700")
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or current.st_uid != os.getuid()
        or stat.S_IMODE(current.st_mode) & 0o022
    ):
        raise RuntimeError("transcript lock parent is unsafe")


def _source_stat_snapshot(stat_result: os.stat_result) -> tuple[int, ...]:
    return (
        int(stat_result.st_dev),
        int(stat_result.st_ino),
        int(stat_result.st_size),
        int(stat_result.st_mtime_ns),
        int(stat_result.st_ctime_ns),
    )


@contextmanager
def _open_stable_transcript_source(
    path: Path,
) -> Iterator[tuple[int, os.stat_result, list[dict[str, int]]]]:
    """Open a source by descriptor-relative no-follow traversal."""

    if not path.is_absolute():
        raise ValueError("transcript source path must be absolute")

    common_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        common_flags |= os.O_CLOEXEC
    directory_flags = common_flags
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    root_fd = os.open(path.anchor or os.sep, directory_flags)
    parent_fd = root_fd
    parent_chain: list[dict[str, int]] = []
    root_stat = os.fstat(root_fd)
    parent_chain.append(
        {"device": int(root_stat.st_dev), "inode": int(root_stat.st_ino)}
    )
    descriptor = -1
    try:
        for component in path.parent.parts[1:]:
            next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            opened_parent = os.fstat(next_fd)
            if not stat.S_ISDIR(opened_parent.st_mode):
                os.close(next_fd)
                raise ValueError("transcript source ancestor must remain a directory")
            if parent_fd != root_fd:
                os.close(parent_fd)
            parent_fd = next_fd
            parent_chain.append(
                {
                    "device": int(opened_parent.st_dev),
                    "inode": int(opened_parent.st_ino),
                }
            )

        observed = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
            raise ValueError("transcript source must remain a regular non-symlink file")

        file_flags = common_flags
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            file_flags |= os.O_NONBLOCK
        descriptor = os.open(path.name, file_flags, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("transcript source must remain a regular file")
        if _source_stat_snapshot(opened) != _source_stat_snapshot(observed):
            raise ValueError("transcript source changed between validation and open")
        yield descriptor, opened, parent_chain
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd != root_fd:
            os.close(parent_fd)
        os.close(root_fd)


def _read_descriptor_range(descriptor: int, *, start: int, length: int) -> bytes:
    os.lseek(descriptor, max(0, int(start)), os.SEEK_SET)
    remaining = max(0, int(length))
    chunks: list[bytes] = []
    while remaining:
        try:
            chunk = os.read(descriptor, remaining)
        except InterruptedError:
            continue
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _json_safe(value: Any, fallback: Any) -> Any:
    safe_value, _ = redact_sensitive_value(value)
    safe_value, _ = strip_untrusted_raw_digest_fields(safe_value)
    try:
        return json.loads(json.dumps(safe_value, allow_nan=False))
    except (TypeError, ValueError):
        return fallback


def _identifier_is_safe(value: Any, *, field: str) -> bool:
    try:
        reject_sensitive_identifier(str(value or ""), field=field)
    except ValueError:
        return False
    return True


def _read_private_regular_bytes(
    path: Path,
    *,
    label: str,
) -> tuple[bytes | None, os.stat_result | None]:
    """Read a bounded private file without following its final path component."""

    try:
        observed = os.lstat(path)
    except FileNotFoundError:
        return None, None
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
        raise RuntimeError(f"{label} must be a regular non-symlink file")
    if int(observed.st_size) > MAX_TRANSCRIPT_STATE_BYTES:
        raise RuntimeError(f"{label} exceeds the supported size limit")

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise RuntimeError(f"{label} must remain a regular file")
        if (int(opened.st_dev), int(opened.st_ino)) != (
            int(observed.st_dev),
            int(observed.st_ino),
        ):
            raise RuntimeError(f"{label} changed between validation and open")
        if int(opened.st_size) > MAX_TRANSCRIPT_STATE_BYTES:
            raise RuntimeError(f"{label} exceeds the supported size limit")
        chunks: list[bytes] = []
        remaining = int(opened.st_size)
        while remaining:
            try:
                chunk = os.read(descriptor, min(remaining, 1_048_576))
            except InterruptedError:
                continue
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if _source_stat_snapshot(after) != _source_stat_snapshot(opened):
            raise RuntimeError(f"{label} changed while being read")
        if len(raw) != int(opened.st_size):
            raise RuntimeError(f"{label} changed while being read")
        return raw, opened
    finally:
        os.close(descriptor)


def _read_private_json_document(
    path: Path,
    *,
    default: dict[str, Any],
    label: str,
) -> tuple[dict[str, Any], bytes | None, os.stat_result | None]:
    raw, opened = _read_private_regular_bytes(path, label=label)
    if raw is None:
        return dict(default), None, None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{label} must contain a JSON object")
    return parsed, raw, opened


def _assert_private_replace_target(path: Path) -> None:
    try:
        observed = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
        raise RuntimeError("private state target must be a regular non-symlink file")


def _atomic_write_private_bytes(path: Path, payload: bytes) -> None:
    """Durably replace a private regular file without retaining a backup."""

    _assert_private_replace_target(path)

    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not parent_existed:
        os.chmod(path.parent, 0o700)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temp_path = Path(temp_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _assert_private_replace_target(path)
        os.replace(temp_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Durably replace a private JSON cache without shared temporary names."""

    serialized = (
        json.dumps(
            _json_safe(payload, {}),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    _atomic_write_private_bytes(path, serialized)


class TranscriptCaptureManager:
    """Hardened transcript and local app capture adapters.

    The manager keeps all connectors local and auditable: registered file
    deltas, explicit selected text, and confirmed running-app snapshots.
    """

    def __init__(
        self,
        *,
        root: str | os.PathLike[str] | None = None,
        backend: mlx_backend.SpikingAttentionBackend | None = None,
        running_app_provider: Callable[[], list[dict[str, Any]]] | None = None,
        app_snapshot_provider: Callable[[dict[str, Any]], str] | None = None,
    ) -> None:
        self.root = resolve_capture_root(root)
        self.backend = backend or mlx_backend.get_backend()
        self.running_app_provider = running_app_provider or self._detect_running_apps_macos
        self.app_snapshot_provider = app_snapshot_provider or self._snapshot_app_accessibility

    def paths(self) -> dict[str, Path]:
        return {
            "root": self.root,
            "source_state_path": self.root / "transcript_sources.json",
            "source_state_lock_path": self.root / ".transcript_sources.lock",
            "source_lock_dir": self.root / "transcript_source_locks",
            "source_lineage_dir": self.root / "transcript_source_lineages",
            "app_state_path": self.root / "app_connections.json",
            "app_state_lock_path": self.root / ".app_connections.lock",
        }

    def _source_lock_path(self, source_id: str) -> Path:
        _ensure_private_lock_directory(self.root)
        digest = hashlib.sha256(str(source_id).encode("utf-8")).hexdigest()[:32]
        return self.paths()["source_lock_dir"] / f"{digest}.lock"

    def _source_lineage_path(self, source_id: str) -> Path:
        digest = hashlib.sha256(str(source_id).encode("utf-8")).hexdigest()[:32]
        return self.paths()["source_lineage_dir"] / f"{digest}.json"

    def _migration_source_lock_path(self, source_id: str) -> Path:
        _ensure_private_lock_directory(self.root)
        if not _identifier_is_safe(source_id, field="source_id"):
            # Do not create a durable equality oracle by hashing a credential-
            # shaped legacy identifier into a new lock filename.
            return self.paths()["source_lock_dir"] / ".unsafe-legacy-source.lock"
        return self._source_lock_path(source_id)

    def _canonicalize_source_state(
        self,
        parsed: dict[str, Any],
    ) -> tuple[dict[str, Any], set[str]]:
        raw_sources = parsed.get("sources")
        clean_sources: dict[str, dict[str, Any]] = {}
        lineage_delete_ids: set[str] = set()
        if isinstance(raw_sources, dict):
            for raw_key, raw_source in raw_sources.items():
                source_id = str(raw_key or "")
                if not source_id:
                    continue
                if not isinstance(raw_source, dict):
                    lineage_delete_ids.add(source_id)
                    continue
                identity_values = (
                    (source_id, "source_id"),
                    (raw_source.get("source_id"), "source_id"),
                    (raw_source.get("path"), "transcript source path"),
                    (raw_source.get("context_id"), "context_id"),
                    (raw_source.get("source_tag"), "source_tag"),
                    (raw_source.get("speaker"), "speaker"),
                )
                if any(
                    not _identifier_is_safe(value, field=field)
                    for value, field in identity_values
                ):
                    lineage_delete_ids.add(source_id)
                    continue
                if str(raw_source.get("source_id") or "") != source_id:
                    lineage_delete_ids.add(source_id)
                    continue
                safe_source = _json_safe(raw_source, {})
                if isinstance(safe_source, dict):
                    clean_sources[source_id] = safe_source
        return {
            "version": SOURCE_STATE_VERSION,
            "sources": clean_sources,
        }, lineage_delete_ids

    def _canonicalize_app_state(self, parsed: dict[str, Any]) -> dict[str, Any]:
        raw_connections = parsed.get("connections")
        clean_connections: dict[str, dict[str, Any]] = {}
        if isinstance(raw_connections, dict):
            for raw_key, raw_connection in raw_connections.items():
                connection_id = str(raw_key or "")
                if not isinstance(raw_connection, dict) or not connection_id:
                    continue
                identity_values = (
                    (connection_id, "connection_id"),
                    (raw_connection.get("connection_id"), "connection_id"),
                    (raw_connection.get("app_name"), "app_name"),
                    (raw_connection.get("bundle_id"), "bundle_id"),
                    (raw_connection.get("context_id"), "context_id"),
                    (raw_connection.get("source_tag"), "source_tag"),
                    (raw_connection.get("speaker"), "speaker"),
                )
                if any(
                    not _identifier_is_safe(value, field=field)
                    for value, field in identity_values
                    if value not in (None, "")
                ):
                    continue
                if str(raw_connection.get("connection_id") or "") != connection_id:
                    continue
                safe_connection = _json_safe(raw_connection, {})
                if isinstance(safe_connection, dict):
                    clean_connections[connection_id] = safe_connection
        return {
            "version": APP_STATE_VERSION,
            "connections": clean_connections,
        }

    def _read_source_state_document(
        self,
    ) -> tuple[dict[str, Any], bytes | None, os.stat_result | None]:
        return _read_private_json_document(
            self.paths()["source_state_path"],
            default={"version": SOURCE_STATE_VERSION, "sources": {}},
            label="transcript source state",
        )

    def _read_app_state_document(
        self,
    ) -> tuple[dict[str, Any], bytes | None, os.stat_result | None]:
        return _read_private_json_document(
            self.paths()["app_state_path"],
            default={"version": APP_STATE_VERSION, "connections": {}},
            label="app connection state",
        )

    @staticmethod
    def _requires_private_rewrite(
        parsed: dict[str, Any],
        canonical: dict[str, Any],
        opened: os.stat_result | None,
    ) -> bool:
        return bool(
            parsed != canonical
            or (opened is not None and stat.S_IMODE(opened.st_mode) != 0o600)
        )

    def _rollback_state_bytes(self, path: Path, original: bytes | None) -> None:
        if original is None:
            try:
                path.unlink()
            except FileNotFoundError:
                return
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return
        _atomic_write_private_bytes(path, original)

    def _replace_migrated_state(
        self,
        *,
        path: Path,
        canonical: dict[str, Any],
        original: bytes | None,
        label: str,
    ) -> None:
        """Replace and verify migrated state with an in-memory rollback image."""

        try:
            _atomic_write_json(path, canonical)
            verified, _, verified_stat = _read_private_json_document(
                path,
                default={},
                label=label,
            )
            if verified != canonical or verified_stat is None:
                raise RuntimeError(f"{label} migration verification failed")
            if stat.S_IMODE(verified_stat.st_mode) != 0o600:
                raise RuntimeError(f"{label} migration is not private")
        except BaseException:
            try:
                self._rollback_state_bytes(path, original)
            except BaseException as rollback_exc:
                raise RuntimeError(f"{label} migration rollback failed") from rollback_exc
            raise

    def _read_lineage_rollback_image(self, path: Path) -> bytes | None:
        try:
            observed = os.lstat(path)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(observed.st_mode):
            # Never follow or recreate an attacker-controlled lineage symlink.
            return None
        if not stat.S_ISREG(observed.st_mode):
            raise RuntimeError("transcript source lineage must be a regular file")
        raw, _ = _read_private_regular_bytes(
            path,
            label="transcript source lineage",
        )
        return raw

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        try:
            descriptor = os.open(path, os.O_RDONLY)
        except FileNotFoundError:
            return
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _migrate_legacy_source_state(self) -> None:
        """Idempotently canonicalize source state under source-to-state locks."""

        for _attempt in range(8):
            observed, _, _ = self._read_source_state_document()
            _, candidates = self._canonicalize_source_state(observed)
            with ExitStack() as locks:
                source_lock_paths = sorted(
                    {
                        self._migration_source_lock_path(source_id)
                        for source_id in candidates
                    },
                    key=str,
                )
                for source_lock_path in source_lock_paths:
                    acquired = locks.enter_context(
                        _exclusive_file_lock(
                            source_lock_path,
                            blocking=True,
                        )
                    )
                    if not acquired:  # pragma: no cover - blocking lock acquires
                        raise RuntimeError("failed to acquire transcript source lock")
                state_acquired = locks.enter_context(
                    _exclusive_file_lock(
                        self.paths()["source_state_lock_path"],
                        blocking=True,
                    )
                )
                if not state_acquired:  # pragma: no cover - blocking lock acquires
                    raise RuntimeError("failed to acquire transcript state lock")

                parsed, original, opened = self._read_source_state_document()
                canonical, current_candidates = self._canonicalize_source_state(parsed)
                if not current_candidates.issubset(candidates):
                    continue
                needs_rewrite = self._requires_private_rewrite(
                    parsed,
                    canonical,
                    opened,
                )
                if not needs_rewrite and not current_candidates:
                    return

                lineage_images: dict[Path, bytes | None] = {}
                deleted_paths: list[Path] = []
                try:
                    # Remove unusable lineage first. If the process stops before
                    # the aggregate write, the next initialization rechecks and
                    # finishes the same idempotent repair.
                    for source_id in sorted(current_candidates):
                        lineage_path = self._source_lineage_path(source_id)
                        try:
                            os.lstat(lineage_path)
                        except FileNotFoundError:
                            continue
                        lineage_images[lineage_path] = self._read_lineage_rollback_image(
                            lineage_path
                        )
                        lineage_path.unlink()
                        deleted_paths.append(lineage_path)
                    if deleted_paths:
                        self._fsync_directory(self.paths()["source_lineage_dir"])
                    if needs_rewrite:
                        self._replace_migrated_state(
                            path=self.paths()["source_state_path"],
                            canonical=canonical,
                            original=original,
                            label="transcript source state",
                        )
                except BaseException:
                    for lineage_path in deleted_paths:
                        rollback_image = lineage_images.get(lineage_path)
                        if rollback_image is not None:
                            _atomic_write_private_bytes(lineage_path, rollback_image)
                    if deleted_paths:
                        self._fsync_directory(self.paths()["source_lineage_dir"])
                    raise
                return
        raise RuntimeError("transcript source migration could not stabilize state")

    def _migrate_legacy_app_state(self) -> None:
        with _exclusive_file_lock(
            self.paths()["app_state_lock_path"],
            blocking=True,
        ) as acquired:
            if not acquired:  # pragma: no cover - blocking lock acquires
                raise RuntimeError("failed to acquire app connection state lock")
            parsed, original, opened = self._read_app_state_document()
            canonical = self._canonicalize_app_state(parsed)
            if not self._requires_private_rewrite(parsed, canonical, opened):
                return
            self._replace_migrated_state(
                path=self.paths()["app_state_path"],
                canonical=canonical,
                original=original,
                label="app connection state",
            )

    def _migrate_legacy_state(self) -> None:
        self._migrate_legacy_source_state()
        self._reconcile_source_lineages()
        self._migrate_legacy_app_state()

    def repair_legacy_state(self) -> dict[str, Any]:
        """Run state migration only through an explicit mutation surface."""

        self._migrate_legacy_state()
        return {
            "action": "repair-transcript-capture-state",
            "status": "ready",
            "root": str(self.root),
        }

    def _new_source_instance_id(self) -> str:
        return f"s2src_{secrets.token_hex(16)}"

    def _validate_source_instance_id(self, value: Any) -> str:
        if type(value) is not str or SOURCE_INSTANCE_ID_RE.fullmatch(value) is None:
            raise ValueError(
                "source_instance_id must be canonical s2src_<32 lowercase hex>"
            )
        return value

    def _read_source_lineage(self, source_id: str) -> dict[str, Any] | None:
        reject_sensitive_identifier(source_id, field="source_id")
        path = self._source_lineage_path(source_id)
        try:
            raw, opened = _read_private_regular_bytes(
                path,
                label="transcript source lineage",
            )
        except Exception as exc:
            raise RuntimeError(
                f"transcript source lineage is unreadable for {source_id}"
            ) from exc
        if raw is None:
            return None
        try:
            lineage = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(
                f"transcript source lineage is unreadable for {source_id}"
            ) from exc
        if not isinstance(lineage, dict) or lineage.get("source_id") != source_id:
            raise RuntimeError(
                f"transcript source lineage does not match {source_id}"
            )
        safe_lineage = _json_safe(lineage, {})
        if not isinstance(safe_lineage, dict):  # pragma: no cover - dict input stays dict
            raise RuntimeError(
                f"transcript source lineage is invalid for {source_id}"
            )
        try:
            source_instance_id = self._validate_source_instance_id(
                safe_lineage.get("source_instance_id")
            )
            registration_generation = int(
                safe_lineage.get("registration_generation", 0)
            )
            stream_generation = int(safe_lineage.get("stream_generation", 0))
            cursor = int(safe_lineage.get("cursor", 0))
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"transcript source lineage is invalid for {source_id}"
            ) from exc
        if registration_generation < 0 or stream_generation < 0 or cursor < 0:
            raise RuntimeError(
                f"transcript source lineage has negative counters for {source_id}"
            )
        return {
            **safe_lineage,
            "_requires_private_rewrite": bool(
                safe_lineage != lineage
                or (opened is not None and stat.S_IMODE(opened.st_mode) != 0o600)
            ),
            "version": 1,
            "source_id": source_id,
            "source_instance_id": source_instance_id,
            "registration_generation": registration_generation,
            "stream_generation": stream_generation,
            "cursor": cursor,
        }

    def _source_lineage_record(self, source: dict[str, Any]) -> dict[str, Any]:
        source_id = str(source.get("source_id") or "")
        reject_sensitive_identifier(source_id, field="source_id")
        source_instance_id = self._validate_source_instance_id(
            source.get("source_instance_id")
        )
        return {
            "version": 1,
            "source_id": source_id,
            "source_instance_id": source_instance_id,
            "registration_generation": max(
                0,
                int(source.get("registration_generation") or 0),
            ),
            "stream_generation": max(0, int(source.get("stream_generation") or 0)),
            "cursor": max(0, int(source.get("cursor") or 0)),
            "file_device": int(source.get("file_device") or 0),
            "file_inode": int(source.get("file_inode") or 0),
            "path_sha256": str(source.get("path_sha256") or ""),
            "file_size": max(0, int(source.get("file_size") or 0)),
            "file_mtime_ns": max(0, int(source.get("file_mtime_ns") or 0)),
            "file_ctime_ns": max(0, int(source.get("file_ctime_ns") or 0)),
            "parent_identity_chain": _json_safe(
                source.get("parent_identity_chain") or [],
                [],
            ),
            "created_at": float(
                source.get("source_instance_created_at")
                or source.get("created_at")
                or time.time()
            ),
            "updated_at": time.time(),
        }

    def _persist_source_lineage(self, source: dict[str, Any]) -> None:
        lineage = self._source_lineage_record(source)
        _atomic_write_json(
            self._source_lineage_path(str(lineage["source_id"])),
            lineage,
        )

    @staticmethod
    def _source_progress(record: dict[str, Any]) -> tuple[int, int, int]:
        return (
            max(0, int(record.get("registration_generation") or 0)),
            max(0, int(record.get("stream_generation") or 0)),
            max(0, int(record.get("cursor") or 0)),
        )

    def _lineage_matches_source(
        self,
        source: dict[str, Any],
        lineage: dict[str, Any],
    ) -> bool:
        if bool(lineage.get("_requires_private_rewrite")):
            return False
        expected = self._source_lineage_record(source)
        for field in (
            "source_id",
            "source_instance_id",
            "registration_generation",
            "stream_generation",
            "cursor",
            "file_device",
            "file_inode",
            "path_sha256",
            "file_size",
            "file_mtime_ns",
            "file_ctime_ns",
            "parent_identity_chain",
            "created_at",
        ):
            if lineage.get(field) != expected.get(field):
                return False
        return True

    @staticmethod
    def _promote_lineage_into_source(
        source: dict[str, Any],
        lineage: dict[str, Any],
    ) -> dict[str, Any]:
        promoted = dict(source)
        promoted["source_instance_id"] = str(lineage["source_instance_id"])
        promoted["registration_generation"] = max(
            0,
            int(lineage.get("registration_generation") or 0),
        )
        promoted["source_instance_created_at"] = float(
            lineage.get("created_at")
            or source.get("source_instance_created_at")
            or source.get("created_at")
            or time.time()
        )
        for field in (
            "stream_generation",
            "cursor",
            "file_device",
            "file_inode",
            "file_size",
            "file_mtime_ns",
            "file_ctime_ns",
        ):
            promoted[field] = max(0, int(lineage.get(field) or 0))
        if lineage.get("path_sha256"):
            promoted["path_sha256"] = str(lineage["path_sha256"])
        if lineage.get("parent_identity_chain"):
            promoted["parent_identity_chain"] = _json_safe(
                lineage["parent_identity_chain"],
                [],
            )
        promoted["updated_at"] = time.time()
        return promoted

    @staticmethod
    def _enrich_source_from_matching_lineage(
        source: dict[str, Any],
        lineage: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        enriched = dict(source)
        changed = False
        if not enriched.get("source_instance_created_at") and lineage.get(
            "created_at"
        ):
            enriched["source_instance_created_at"] = float(lineage["created_at"])
            changed = True
        for field in (
            "file_device",
            "file_inode",
            "file_size",
            "file_mtime_ns",
            "file_ctime_ns",
        ):
            if not enriched.get(field) and lineage.get(field):
                enriched[field] = max(0, int(lineage[field]))
                changed = True
        if not enriched.get("path_sha256") and lineage.get("path_sha256"):
            enriched["path_sha256"] = str(lineage["path_sha256"])
            changed = True
        if not enriched.get("parent_identity_chain") and lineage.get(
            "parent_identity_chain"
        ):
            enriched["parent_identity_chain"] = _json_safe(
                lineage["parent_identity_chain"],
                [],
            )
            changed = True
        if changed:
            enriched["updated_at"] = time.time()
        return enriched, changed

    def _reconcile_source_record(
        self,
        source: dict[str, Any],
        persisted: dict[str, Any] | None,
    ) -> tuple[dict[str, Any], bool, bool]:
        """Return source, aggregate-changed, lineage-changed monotonically."""

        raw_instance_id = source.get("source_instance_id")
        source_instance_id = ""
        if raw_instance_id:
            source_instance_id = self._validate_source_instance_id(raw_instance_id)
        if not source_instance_id:
            if persisted is not None:
                return (
                    self._promote_lineage_into_source(source, persisted),
                    True,
                    bool(persisted.get("_requires_private_rewrite")),
                )
            repaired = dict(source)
            repaired["source_instance_id"] = self._new_source_instance_id()
            repaired["registration_generation"] = max(
                0,
                int(repaired.get("registration_generation") or 0),
            )
            repaired["source_instance_created_at"] = float(
                repaired.get("source_instance_created_at")
                or repaired.get("created_at")
                or time.time()
            )
            repaired["updated_at"] = time.time()
            return repaired, True, True

        if persisted is None:
            return source, False, True

        persisted_instance_id = str(persisted["source_instance_id"])
        source_progress = self._source_progress(source)
        lineage_progress = self._source_progress(persisted)
        if source_instance_id != persisted_instance_id:
            if source_progress[0] == lineage_progress[0]:
                raise RuntimeError(
                    "transcript source lineage has an ambiguous registration conflict"
                )
            if lineage_progress[0] > source_progress[0]:
                return (
                    self._promote_lineage_into_source(source, persisted),
                    True,
                    bool(persisted.get("_requires_private_rewrite")),
                )
            return source, False, True

        if lineage_progress > source_progress:
            return (
                self._promote_lineage_into_source(source, persisted),
                True,
                bool(persisted.get("_requires_private_rewrite")),
            )
        if lineage_progress == source_progress:
            enriched, aggregate_changed = self._enrich_source_from_matching_lineage(
                source,
                persisted,
            )
            if aggregate_changed:
                return (
                    enriched,
                    True,
                    bool(persisted.get("_requires_private_rewrite")),
                )
        if source_progress > lineage_progress or not self._lineage_matches_source(
            source,
            persisted,
        ):
            return source, False, True
        return source, False, False

    def _reconcile_source_lineages(self) -> None:
        """Repair interrupted aggregate/lineage commits without regression."""

        snapshot = self._read_state()
        source_ids = sorted(
            str(source_id)
            for source_id, source in snapshot.get("sources", {}).items()
            if isinstance(source, dict)
        )
        for source_id in source_ids:
            with _exclusive_file_lock(
                self._source_lock_path(source_id),
                blocking=True,
            ) as source_acquired:
                if not source_acquired:  # pragma: no cover - blocking lock acquires
                    raise RuntimeError("failed to acquire transcript source lock")
                with _exclusive_file_lock(
                    self.paths()["source_state_lock_path"],
                    blocking=True,
                ) as state_acquired:
                    if not state_acquired:  # pragma: no cover - blocking lock acquires
                        raise RuntimeError("failed to acquire transcript state lock")
                    latest = self._read_state()
                    current = latest.get("sources", {}).get(source_id)
                    if not isinstance(current, dict):
                        continue
                    source = dict(current)
                    persisted = self._read_source_lineage(source_id)
                    repaired, aggregate_changed, lineage_changed = (
                        self._reconcile_source_record(source, persisted)
                    )
                    if aggregate_changed:
                        latest.setdefault("sources", {})[source_id] = repaired
                        self._write_state(latest)
                    if lineage_changed:
                        self._persist_source_lineage(repaired)

    def _ensure_source_lineage(self, source: dict[str, Any]) -> dict[str, Any]:
        source_id = str(source.get("source_id") or "")
        if not source_id:
            raise ValueError("transcript source is missing source_id")
        persisted = self._read_source_lineage(source_id)
        repaired, _aggregate_changed, lineage_changed = self._reconcile_source_record(
            source,
            persisted,
        )
        if repaired is not source:
            source.clear()
            source.update(repaired)
        if lineage_changed:
            self._persist_source_lineage(source)
        return source

    def _assert_safe_source_re_registration(self, source: dict[str, Any]) -> None:
        old_path = Path(
            os.path.abspath(
                os.path.expanduser(str(source.get("path") or ""))
            )
        )
        try:
            reject_sensitive_identifier(
                str(old_path),
                field="transcript source path",
            )
            self._validate_source_path(old_path)
            with _open_stable_transcript_source(old_path) as (
                _descriptor,
                stat,
                parent_identity_chain,
            ):
                expected_chain = _json_safe(
                    source.get("parent_identity_chain") or [],
                    [],
                )
                if expected_chain and expected_chain != parent_identity_chain:
                    raise ValueError("transcript source ancestor identity changed")
        except Exception as exc:
            raise ValueError(
                "cannot re-register transcript source until its prior file is readable"
            ) from exc
        cursor = max(0, int(source.get("cursor") or 0))
        prior_device = int(source.get("file_device") or 0)
        prior_inode = int(source.get("file_inode") or 0)
        same_stream = bool(
            prior_device == int(stat.st_dev) and prior_inode == int(stat.st_ino)
        )
        if not same_stream or int(stat.st_size) != cursor:
            raise ValueError(
                "cannot re-register transcript source while unread bytes remain; poll it first"
            )
        prior_mtime_ns = int(source.get("file_mtime_ns") or 0)
        prior_ctime_ns = int(source.get("file_ctime_ns") or 0)
        if (
            (prior_mtime_ns and prior_mtime_ns != int(stat.st_mtime_ns))
            or (prior_ctime_ns and prior_ctime_ns != int(stat.st_ctime_ns))
        ):
            raise ValueError(
                "cannot re-register transcript source after an unprocessed rewrite; poll it first"
            )

    def _commit_source_record(
        self,
        source: dict[str, Any],
        *,
        allow_instance_replacement: bool,
    ) -> None:
        source_id = str(source.get("source_id") or "")
        with _exclusive_file_lock(
            self.paths()["source_state_lock_path"],
            blocking=True,
        ) as acquired:
            if not acquired:  # pragma: no cover - blocking lock always acquires
                raise RuntimeError("failed to acquire transcript state lock")
            latest = self._read_state()
            sources = latest.setdefault("sources", {})
            existing = sources.get(source_id)
            if isinstance(existing, dict):
                existing_instance = str(existing.get("source_instance_id") or "")
                candidate_instance = str(source.get("source_instance_id") or "")
                existing_registration = max(
                    0,
                    int(existing.get("registration_generation") or 0),
                )
                candidate_registration = max(
                    0,
                    int(source.get("registration_generation") or 0),
                )
                if existing_instance and existing_instance != candidate_instance:
                    if not allow_instance_replacement:
                        raise RuntimeError(
                            f"transcript source instance changed while polling {source_id}"
                        )
                    if candidate_registration <= existing_registration:
                        raise RuntimeError(
                            f"transcript source registration changed while committing {source_id}"
                        )
                elif candidate_registration < existing_registration:
                    raise RuntimeError(
                        f"transcript source registration regressed while committing {source_id}"
                    )
                elif candidate_registration == existing_registration:
                    existing_stream = max(
                        0,
                        int(existing.get("stream_generation") or 0),
                    )
                    candidate_stream = max(
                        0,
                        int(source.get("stream_generation") or 0),
                    )
                    if candidate_stream < existing_stream or (
                        candidate_stream == existing_stream
                        and max(0, int(source.get("cursor") or 0))
                        < max(0, int(existing.get("cursor") or 0))
                    ):
                        raise RuntimeError(
                            f"transcript source cursor regressed while committing {source_id}"
                        )
            sources[source_id] = source
            self._write_state(latest)
            # Aggregate state is authoritative while present; lineage is its
            # monotonic recovery projection. Initialization reconciles this
            # exact boundary if the process stops after the aggregate replace.
            self._persist_source_lineage(source)

    def status(self) -> dict[str, Any]:
        sources = self.list_sources()["sources"]
        enabled = [source for source in sources if source.get("enabled")]
        return {
            "root": str(self.root),
            "source_state_path": str(self.paths()["source_state_path"]),
            "source_count": len(sources),
            "enabled_source_count": len(enabled),
            "sources": sources,
            "app_connections": self.list_app_connections()["connections"],
            "mode": "hardened-app-connect",
            "connector_model": {
                "remote_control_plane": False,
                "background_clipboard_monitoring": False,
                "requires_explicit_source_registration": True,
                "redaction_before_ingest": True,
            },
        }

    def detect_running_apps(self) -> dict[str, Any]:
        started = time.perf_counter()
        apps: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        provider_warning = ""
        try:
            raw_apps = list(self.running_app_provider() or [])
        except Exception as exc:
            provider_warning = str(exc.__class__.__name__)
            LOGGER.debug(
                "running app provider failed; falling back to ps: %s",
                safe_public_error(
                    exc,
                    fallback="running app provider failed",
                ),
                exc_info=True,
            )
            raw_apps = self._detect_running_apps_ps()
        for raw_app in raw_apps:
            try:
                app = self._public_app(raw_app)
            except ValueError:
                # Provider-supplied process labels are untrusted identifiers.
                # Skip unsafe rows instead of hashing, echoing, or persisting
                # credential-shaped material.
                continue
            if not app["app_name"]:
                continue
            if app.get("detection") == "ps" and not self._looks_like_attachable_app(app):
                continue
            key = (
                str(app.get("app_name") or "").strip().lower(),
                str(app.get("bundle_id") or "").strip().lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            apps.append(app)
        apps.sort(key=lambda item: (item["app_name"].lower(), int(item.get("pid") or 0)))
        return {
            "action": "detect-running-apps",
            "app_count": len(apps),
            "apps": apps,
            "mode": "local-process-detection",
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "warning": provider_warning,
        }

    def connect_running_app(
        self,
        *,
        app_name: str,
        context_id: str = "default",
        source_tag: str = "app-connect",
        speaker: str = "operator",
        bundle_id: str = "",
        pid: int = 0,
        metadata: dict[str, Any] | None = None,
        confirmed: bool = False,
        allow_manual: bool = False,
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("explicit --confirm is required to connect a local app")
        requested_name = " ".join(str(app_name or "").split())
        if not requested_name:
            raise ValueError("app_name must not be empty")
        requested_bundle = " ".join(str(bundle_id or "").split())
        reject_sensitive_identifier(requested_name, field="app_name")
        if requested_bundle:
            reject_sensitive_identifier(requested_bundle, field="bundle_id")
        detected = self._match_running_app(
            app_name=requested_name,
            bundle_id=requested_bundle,
            pid=int(pid or 0),
        )
        if detected is None:
            if not allow_manual:
                raise ValueError("app is not currently detected; pass allow_manual only for a verified local app")
            detected = {
                "app_name": requested_name,
                "bundle_id": requested_bundle,
                "pid": int(pid or 0),
                "detection": "manual-operator-entry",
            }
        detected = self._public_app(detected)
        connection_id = self._connection_id(detected)
        with _exclusive_file_lock(
            self.paths()["app_state_lock_path"],
            blocking=True,
        ) as acquired:
            if not acquired:  # pragma: no cover - blocking lock acquires
                raise RuntimeError("failed to acquire app connection state lock")
            # Read again only after acquiring the global app-state lock. This
            # makes the commit a lost-update-safe read-modify-write operation.
            state = self._read_app_state()
            connections = state.setdefault("connections", {})
            now = time.time()
            record = {
                "connection_id": connection_id,
                "app_name": str(detected.get("app_name") or requested_name),
                "bundle_id": str(detected.get("bundle_id") or requested_bundle),
                "pid": int(detected.get("pid") or pid or 0),
                "context_id": mlx_backend.sanitize_context_id(context_id),
                "source_tag": mlx_backend.sanitize_tag(source_tag).replace(" ", "-"),
                "speaker": mlx_backend.sanitize_agent_id(speaker),
                "enabled": True,
                "adapter_kinds": [
                    "frontmost-selection",
                    "clipboard-once",
                    "app-accessibility-snapshot",
                    "app-selected-text",
                ],
                "created_at": float(
                    connections.get(connection_id, {}).get("created_at") or now
                ),
                "updated_at": now,
                "metadata": _json_safe(metadata or {}, {}),
                "consent": {
                    "operator_confirmed": True,
                    "mode": "local-app-connect",
                    "attached_at": now,
                },
            }
            connections[connection_id] = record
            self._write_app_state(state)
        return self._public_connection(record)

    def list_app_connections(self) -> dict[str, Any]:
        state = self._read_app_state()
        connections = [
            self._public_connection(connection)
            for connection in state.get("connections", {}).values()
            if isinstance(connection, dict)
        ]
        connections.sort(key=lambda item: (item["app_name"].lower(), item["connection_id"]))
        return {
            "root": str(self.root),
            "app_state_path": str(self.paths()["app_state_path"]),
            "connection_count": len(connections),
            "connections": connections,
        }

    def preview_app_snapshot(
        self,
        *,
        connection_id: str,
    ) -> dict[str, Any]:
        connection = self._get_connection(connection_id)
        try:
            snapshot_text = self._clean_accessibility_snapshot_text(
                str(self.app_snapshot_provider(connection) or "")
            )
        except Exception as exc:
            return self._blocked_app_snapshot_preview(
                connection=connection,
                reason="app snapshot failed; grant Accessibility permission or use selected-text capture",
                error_type=exc.__class__.__name__,
            )
        if not snapshot_text:
            return self._blocked_app_snapshot_preview(
                connection=connection,
                reason="app snapshot did not return text; use selected-text capture",
                error_type="empty-snapshot",
            )
        if len(snapshot_text.encode("utf-8")) > MAX_TRANSCRIPT_DELTA_BYTES:
            snapshot_text = snapshot_text.encode("utf-8")[:MAX_TRANSCRIPT_DELTA_BYTES].decode(
                "utf-8",
                errors="replace",
            )
        redacted_text, redaction_count = redact_capture_text(snapshot_text)
        quality = self._snapshot_quality(snapshot_text)
        badge = self._snapshot_quality_badge(quality)
        preview_text = self._preview_text(redacted_text, limit=1200)
        return {
            "action": "preview-app-snapshot",
            "adapter_kind": "app-accessibility-snapshot",
            "connection_id": connection["connection_id"],
            "app_name": connection["app_name"],
            "bundle_id": connection.get("bundle_id", ""),
            "pid": int(connection.get("pid") or 0),
            "context_id": str(connection.get("context_id") or "default"),
            "source_tag": str(connection.get("source_tag") or "app-connect"),
            "speaker": str(connection.get("speaker") or "operator"),
            "preview_text": preview_text,
            "preview_line_count": len([line for line in preview_text.splitlines() if line.strip()]),
            "redaction_count": int(redaction_count),
            "snapshot_quality": quality,
            "quality_badge": badge,
            "capability_badge": self._app_capability_badge(connection, quality=quality),
            "capture_guidance": self._app_capture_guidance(
                connection=connection,
                quality=quality,
                badge=badge,
            ),
            "writes_memory": False,
        }

    def _blocked_app_snapshot_preview(
        self,
        *,
        connection: dict[str, Any],
        reason: str,
        error_type: str,
    ) -> dict[str, Any]:
        quality = {
            "line_count": 0,
            "unique_line_count": 0,
            "signal_chars": 0,
            "low_signal": True,
            "repetitive": False,
            "quality": "blocked",
            "blocked_reason": str(reason or "app snapshot unavailable"),
        }
        badge = self._snapshot_quality_badge(quality)
        return {
            "action": "preview-app-snapshot",
            "adapter_kind": "app-accessibility-snapshot",
            "connection_id": connection["connection_id"],
            "app_name": connection["app_name"],
            "bundle_id": connection.get("bundle_id", ""),
            "pid": int(connection.get("pid") or 0),
            "context_id": str(connection.get("context_id") or "default"),
            "source_tag": str(connection.get("source_tag") or "app-connect"),
            "speaker": str(connection.get("speaker") or "operator"),
            "preview_text": "",
            "preview_line_count": 0,
            "redaction_count": 0,
            "snapshot_quality": quality,
            "quality_badge": badge,
            "capability_badge": self._app_capability_badge(connection, quality=quality),
            "capture_guidance": self._app_capture_guidance(
                connection=connection,
                quality=quality,
                badge=badge,
            ),
            "writes_memory": False,
            "error_type": str(error_type or "snapshot-unavailable"),
            "error": quality["blocked_reason"],
        }

    def _replay_dynamic_capture(
        self,
        *,
        capture_id: str,
        context_id: str,
        source_tag: str,
        speaker: str,
    ) -> dict[str, Any] | None:
        return self.backend.replay_capture_operation(
            capture_id,
            context_id=context_id,
            source_tag=source_tag,
            speaker=speaker,
        )

    def _render_app_snapshot_capture(
        self,
        *,
        connection: dict[str, Any],
        capture: dict[str, Any],
        snapshot_quality: dict[str, Any],
        redaction_count: int,
        replay_without_live_read: bool = False,
    ) -> dict[str, Any]:
        quality_badge = self._snapshot_quality_badge(snapshot_quality)
        protocol = capture.get("protocol") or capture.get("capture_protocol")
        return {
            "action": "capture-app-snapshot",
            "adapter_kind": "app-accessibility-snapshot",
            "connection_id": connection["connection_id"],
            "app_name": connection["app_name"],
            "context_id": capture["context_id"],
            "source_tag": capture["source_tag"],
            "speaker": capture.get("speaker"),
            "event_count": capture["event_count"],
            "relationship_count": capture["relationship_count"],
            "agent_deployment": capture.get("agent_deployment"),
            "capture_id": capture.get("capture_id"),
            "protocol": protocol,
            "capture_protocol": capture.get("capture_protocol") or protocol,
            "idempotent_replay": bool(capture.get("idempotent_replay", False)),
            "receipt_compact": bool(capture.get("receipt_compact", False)),
            "replay_without_live_read": bool(replay_without_live_read),
            "redaction_count": int(redaction_count),
            "redaction_count_known": not replay_without_live_read,
            "snapshot_quality": snapshot_quality,
            "quality_badge": quality_badge,
            "capability_badge": self._app_capability_badge(
                connection,
                quality=snapshot_quality,
            ),
            "capture_guidance": self._app_capture_guidance(
                connection=connection,
                quality=snapshot_quality,
                badge=quality_badge,
            ),
            "receipt": {
                "action": "capture-app-snapshot",
                "status": quality_badge["status"],
                "title": f"{connection['app_name']} snapshot captured",
                "summary": (
                    f"{capture['event_count']} events, "
                    f"{capture['relationship_count']} relationships, "
                    + (
                        "signal stats unavailable on compact replay"
                        if replay_without_live_read
                        else f"{snapshot_quality['signal_chars']} signal chars"
                    )
                ),
                "context_id": capture["context_id"],
                "source_tag": capture["source_tag"],
                "event_count": capture["event_count"],
                "relationship_count": capture["relationship_count"],
                "quality": quality_badge["label"],
                "next_action": quality_badge["next_action"],
            },
        }

    def capture_app_snapshot(
        self,
        *,
        connection_id: str,
        confirmed: bool = False,
        metadata: dict[str, Any] | None = None,
        capture_id: str | None = None,
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("explicit confirmation is required to capture an app snapshot")
        connection = self._get_connection(connection_id)
        context_id = str(connection.get("context_id") or "default")
        source_tag = str(connection.get("source_tag") or "app-connect")
        speaker = str(connection.get("speaker") or "operator")
        if capture_id is not None:
            replay = self._replay_dynamic_capture(
                capture_id=capture_id,
                context_id=context_id,
                source_tag=source_tag,
                speaker=speaker,
            )
            if replay is not None:
                snapshot_quality = {
                    "line_count": 0,
                    "unique_line_count": 0,
                    "signal_chars": 0,
                    "signal_stats_known": False,
                    "low_signal": False,
                    "repetitive": False,
                    "quality": "replayed",
                    "replay_without_live_read": True,
                }
                return self._render_app_snapshot_capture(
                    connection=connection,
                    capture=replay,
                    snapshot_quality=snapshot_quality,
                    redaction_count=0,
                    replay_without_live_read=True,
                )
        snapshot_text = self._clean_accessibility_snapshot_text(
            str(self.app_snapshot_provider(connection) or "")
        )
        if not snapshot_text:
            raise ValueError("app snapshot did not return text")
        if len(snapshot_text.encode("utf-8")) > MAX_TRANSCRIPT_DELTA_BYTES:
            snapshot_text = snapshot_text.encode("utf-8")[:MAX_TRANSCRIPT_DELTA_BYTES].decode(
                "utf-8",
                errors="replace",
            )
        snapshot_quality = self._snapshot_quality(snapshot_text)
        redacted_text, redaction_count = redact_capture_text(snapshot_text)
        capture = self.backend.capture_conversation(
            text=redacted_text,
            context_id=context_id,
            source_tag=source_tag,
            speaker=speaker,
            surprise_threshold=0.5,
            min_segment_sentences=1,
            capture_id=capture_id,
            metadata={
                **_json_safe(connection.get("metadata") or {}, {}),
                **_json_safe(metadata or {}, {}),
                "transcript_adapter": True,
                "adapter_kind": "app-accessibility-snapshot",
                "capture_mode": "confirmed-local-app-snapshot",
                "connection_id": connection["connection_id"],
                "app_name": connection["app_name"],
                "bundle_id": connection.get("bundle_id", ""),
                "pid": connection.get("pid", 0),
                "redaction_count": int(redaction_count),
                "remote_control_plane": False,
                "snapshot_quality": snapshot_quality,
            },
        )
        return self._render_app_snapshot_capture(
            connection=connection,
            capture=capture,
            snapshot_quality=snapshot_quality,
            redaction_count=redaction_count,
        )

    def _render_app_selected_text_capture(
        self,
        *,
        connection: dict[str, Any],
        capture: dict[str, Any],
        redaction_count: int,
        replay_without_live_read: bool = False,
    ) -> dict[str, Any]:
        protocol = capture.get("protocol") or capture.get("capture_protocol")
        return {
            "action": "capture-app-selected-text",
            "adapter_kind": "app-selected-text",
            "connection_id": connection["connection_id"],
            "app_name": connection["app_name"],
            "context_id": capture["context_id"],
            "source_tag": capture["source_tag"],
            "speaker": capture.get("speaker"),
            "event_count": capture["event_count"],
            "relationship_count": capture["relationship_count"],
            "agent_deployment": capture.get("agent_deployment"),
            "capture_id": capture.get("capture_id"),
            "protocol": protocol,
            "capture_protocol": capture.get("capture_protocol") or protocol,
            "idempotent_replay": bool(capture.get("idempotent_replay", False)),
            "receipt_compact": bool(capture.get("receipt_compact", False)),
            "replay_without_live_read": bool(replay_without_live_read),
            "redaction_count": int(redaction_count),
            "redaction_count_known": not replay_without_live_read,
        }

    def capture_app_selected_text(
        self,
        *,
        connection_id: str,
        text: str | None = None,
        confirmed: bool = False,
        metadata: dict[str, Any] | None = None,
        capture_id: str | None = None,
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("explicit confirmation is required to capture app selected text")
        connection = self._get_connection(connection_id)
        context_id = str(connection.get("context_id") or "default")
        source_tag = str(connection.get("source_tag") or "app-connect")
        speaker = str(connection.get("speaker") or "operator")
        if text is None and capture_id is not None:
            replay = self._replay_dynamic_capture(
                capture_id=capture_id,
                context_id=context_id,
                source_tag=source_tag,
                speaker=speaker,
            )
            if replay is not None:
                return self._render_app_selected_text_capture(
                    connection=connection,
                    capture=replay,
                    redaction_count=0,
                    replay_without_live_read=True,
                )
        raw_text = self._read_clipboard() if text is None else str(text or "")
        clean_text = raw_text.strip()
        if not clean_text:
            raise ValueError("selected app text must not be empty")
        if len(clean_text.encode("utf-8")) > MAX_TRANSCRIPT_DELTA_BYTES:
            clean_text = clean_text.encode("utf-8")[:MAX_TRANSCRIPT_DELTA_BYTES].decode(
                "utf-8",
                errors="replace",
            )
        redacted_text, redaction_count = redact_capture_text(clean_text)
        capture = self.backend.capture_conversation(
            text=redacted_text,
            context_id=context_id,
            source_tag=source_tag,
            speaker=speaker,
            surprise_threshold=0.5,
            min_segment_sentences=1,
            capture_id=capture_id,
            metadata={
                **_json_safe(connection.get("metadata") or {}, {}),
                **_json_safe(metadata or {}, {}),
                "transcript_adapter": True,
                "adapter_kind": "app-selected-text",
                "capture_mode": "confirmed-selected-text-fallback",
                "connection_id": connection["connection_id"],
                "app_name": connection["app_name"],
                "bundle_id": connection.get("bundle_id", ""),
                "pid": connection.get("pid", 0),
                "redaction_count": int(redaction_count),
                "remote_control_plane": False,
            },
        )
        return self._render_app_selected_text_capture(
            connection=connection,
            capture=capture,
            redaction_count=redaction_count,
        )

    def register_file_source(
        self,
        *,
        source_id: str,
        path: str | os.PathLike[str],
        context_id: str = "default",
        source_tag: str = "transcript-source",
        speaker: str = "operator",
        metadata: dict[str, Any] | None = None,
        confirmed: bool = False,
        start_at_end: bool = True,
        enabled: bool = True,
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("explicit --confirm is required to register a transcript source")
        reject_sensitive_identifier(str(source_id or ""), field="source_id")
        source = mlx_backend.sanitize_tag(source_id).replace(" ", "-")
        if not source:
            raise ValueError("source_id must not be empty")
        expanded = Path(path).expanduser()
        absolute_input = Path(os.path.abspath(str(expanded)))
        reject_sensitive_identifier(
            str(absolute_input),
            field="transcript source path",
        )
        # Canonicalize platform aliases such as macOS /var -> /private/var once
        # at registration. The stored canonical path is subsequently opened by
        # descriptor-relative no-follow traversal, so later ancestor swaps fail
        # closed rather than being followed.
        resolved = Path(os.path.realpath(str(absolute_input)))
        reject_sensitive_identifier(str(resolved), field="transcript source path")
        self._validate_source_path(resolved)
        with _open_stable_transcript_source(resolved) as (
            _descriptor,
            registered_stat,
            parent_identity_chain,
        ):
            stat_snapshot = registered_stat
        with _exclusive_file_lock(self._source_lock_path(source), blocking=False) as acquired:
            if not acquired:
                raise RuntimeError(
                    f"transcript source is busy and cannot be re-registered: {source}"
                )
            stat = stat_snapshot
            state = self._read_state()
            existing = state.setdefault("sources", {}).get(source)
            lineage = self._read_source_lineage(source)
            now = time.time()

            if isinstance(existing, dict):
                existing = dict(existing)
                self._ensure_source_lineage(existing)
                self._assert_safe_source_re_registration(existing)
                source_instance_id = self._new_source_instance_id()
                registration_generation = (
                    max(0, int(existing.get("registration_generation") or 0)) + 1
                )
                source_instance_created_at = now
                stream_generation = 0
                cursor = int(stat.st_size) if start_at_end else 0
                created_at = float(existing.get("created_at") or now)
            elif lineage is not None:
                # A lineage sidecar outlives the mutable aggregate state file.
                # Recover the immutable source identity and its latest cursor
                # instead of silently minting a colliding/replayed producer.
                source_instance_id = str(lineage["source_instance_id"])
                registration_generation = int(
                    lineage.get("registration_generation", 0)
                )
                source_instance_created_at = float(
                    lineage.get("created_at") or now
                )
                created_at = source_instance_created_at
                recovered_cursor = max(0, int(lineage.get("cursor") or 0))
                same_stream = bool(
                    int(lineage.get("file_device") or 0) == int(stat.st_dev)
                    and int(lineage.get("file_inode") or 0) == int(stat.st_ino)
                )
                same_size_rewrite = bool(
                    same_stream
                    and int(stat.st_size) == recovered_cursor
                    and (
                        (
                            int(lineage.get("file_mtime_ns") or 0)
                            and int(lineage.get("file_mtime_ns") or 0)
                            != int(stat.st_mtime_ns)
                        )
                        or (
                            int(lineage.get("file_ctime_ns") or 0)
                            and int(lineage.get("file_ctime_ns") or 0)
                            != int(stat.st_ctime_ns)
                        )
                    )
                )
                if same_stream and int(stat.st_size) >= recovered_cursor and not same_size_rewrite:
                    cursor = recovered_cursor
                    stream_generation = max(
                        0,
                        int(lineage.get("stream_generation") or 0),
                    )
                else:
                    # This is recovery, not a deliberate registration reset:
                    # read the replacement from its beginning so no bytes are
                    # skipped merely because start_at_end defaults to true.
                    cursor = 0
                    stream_generation = (
                        max(0, int(lineage.get("stream_generation") or 0)) + 1
                    )
            else:
                source_instance_id = self._new_source_instance_id()
                registration_generation = 0
                source_instance_created_at = now
                stream_generation = 0
                cursor = int(stat.st_size) if start_at_end else 0
                created_at = now

            record = {
                "source_id": source,
                "source_instance_id": source_instance_id,
                "registration_generation": registration_generation,
                "source_instance_created_at": source_instance_created_at,
                "kind": "file-tail",
                "path": str(resolved),
                "path_sha256": _sha256_path(resolved),
                "parent_identity_chain": parent_identity_chain,
                "context_id": mlx_backend.sanitize_context_id(context_id),
                "source_tag": mlx_backend.sanitize_tag(source_tag).replace(" ", "-"),
                "speaker": mlx_backend.sanitize_agent_id(speaker),
                "enabled": bool(enabled),
                "cursor": cursor,
                "stream_generation": stream_generation,
                "file_device": int(stat.st_dev),
                "file_inode": int(stat.st_ino),
                "file_size": int(stat.st_size),
                "file_mtime_ns": int(stat.st_mtime_ns),
                "file_ctime_ns": int(stat.st_ctime_ns),
                "format": resolved.suffix.lower().lstrip(".") or "text",
                "created_at": created_at,
                "updated_at": now,
                "metadata": _json_safe(metadata or {}, {}),
                "consent": {
                    "operator_confirmed": True,
                    "mode": "explicit-registration",
                    "registered_at": now,
                },
            }
            self._commit_source_record(record, allow_instance_replacement=True)
            return self._public_source(record)

    def list_sources(self) -> dict[str, Any]:
        state = self._read_state()
        sources = [
            self._public_source(source)
            for source in state.get("sources", {}).values()
            if isinstance(source, dict)
        ]
        sources.sort(key=lambda item: item["source_id"])
        return {
            "root": str(self.root),
            "source_state_path": str(self.paths()["source_state_path"]),
            "source_count": len(sources),
            "sources": sources,
        }

    def poll_sources(
        self,
        *,
        source_id: str = "",
        max_bytes: int = MAX_TRANSCRIPT_DELTA_BYTES,
    ) -> dict[str, Any]:
        state = self._read_state()
        sources = state.get("sources", {})
        bounded_max = max(1, min(int(max_bytes), MAX_TRANSCRIPT_DELTA_BYTES))
        requested = mlx_backend.sanitize_tag(source_id).replace(" ", "-") if source_id else ""
        selected_ids: list[str] = []
        if requested:
            source = sources.get(requested)
            if isinstance(source, dict):
                selected_ids.append(requested)
            else:
                raise ValueError(f"transcript source not found: {requested}")
        else:
            selected_ids = [
                str(source_key)
                for source_key, source in sources.items()
                if isinstance(source, dict) and bool(source.get("enabled", True))
            ]

        captures: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        deferred_sources: list[dict[str, Any]] = []
        for selected_id in selected_ids:
            with _exclusive_file_lock(
                self._source_lock_path(selected_id),
                blocking=False,
            ) as acquired:
                if not acquired:
                    deferred_sources.append(
                        {
                            "source_id": selected_id,
                            "reason": "source-busy",
                        }
                    )
                    continue

                # Never use the state snapshot taken before waiting for the
                # source lock. Another process may have advanced the cursor.
                locked_state = self._read_state()
                source = locked_state.get("sources", {}).get(selected_id)
                if not isinstance(source, dict):
                    errors.append(
                        {
                            "source_id": selected_id,
                            "error": "transcript source disappeared while polling",
                        }
                    )
                    continue
                source = dict(source)
                if not bool(source.get("enabled", True)):
                    continue
                try:
                    self._ensure_source_lineage(source)
                    capture = self._poll_file_source(source, max_bytes=bounded_max)
                except Exception as exc:
                    LOGGER.exception(
                        "failed to poll transcript source %s",
                        source.get("source_id"),
                    )
                    errors.append(
                        {
                            "source_id": str(source.get("source_id") or ""),
                            "error": safe_public_error(
                                exc,
                                fallback="transcript source poll failed",
                            ),
                        }
                    )
                    continue

                # Keep state commit failures visible to the caller. The
                # backend receipt is already durable, so a retry will use the
                # same source lineage/range operation id without duplicating
                # database effects.
                self._commit_source_record(
                    source,
                    allow_instance_replacement=False,
                )
                if capture is not None:
                    captures.append(capture)
        return {
            "action": "poll-transcript-sources",
            "root": str(self.root),
            "source_count": len(selected_ids),
            "captured_source_count": len(captures),
            "deferred_source_count": len(deferred_sources),
            "captured_event_count": sum(int(item.get("event_count") or 0) for item in captures),
            "captured_relationship_count": sum(
                int(item.get("relationship_count") or 0) for item in captures
            ),
            "captures": captures,
            "deferred_sources": deferred_sources,
            "errors": errors,
        }

    def capture_clipboard_once(
        self,
        *,
        text: str | None = None,
        context_id: str = "default",
        source_tag: str = "frontmost-selection",
        speaker: str = "operator",
        metadata: dict[str, Any] | None = None,
        capture_id: str | None = None,
    ) -> dict[str, Any]:
        canonical_context_id = mlx_backend.sanitize_context_id(context_id)
        canonical_source_tag = mlx_backend.sanitize_tag(source_tag).replace(" ", "-")
        canonical_speaker = mlx_backend.sanitize_agent_id(speaker)
        if text is None and capture_id is not None:
            replay = self._replay_dynamic_capture(
                capture_id=capture_id,
                context_id=canonical_context_id,
                source_tag=canonical_source_tag,
                speaker=canonical_speaker,
            )
            if replay is not None:
                return self._render_clipboard_capture(
                    capture=replay,
                    redaction_count=0,
                    replay_without_live_read=True,
                )
        raw_text = self._read_clipboard() if text is None else str(text or "")
        clean_text = raw_text.strip()
        if not clean_text:
            raise ValueError("clipboard capture text must not be empty")
        redacted_text, redaction_count = redact_capture_text(clean_text)
        capture = self.backend.capture_conversation(
            text=redacted_text,
            context_id=canonical_context_id,
            source_tag=canonical_source_tag,
            speaker=canonical_speaker,
            surprise_threshold=0.5,
            min_segment_sentences=1,
            capture_id=capture_id,
            metadata={
                **_json_safe(metadata or {}, {}),
                "transcript_adapter": True,
                "adapter_kind": "clipboard-once",
                "capture_mode": "explicit-one-shot",
                "redaction_count": int(redaction_count),
                "remote_control_plane": False,
            },
        )
        return self._render_clipboard_capture(
            capture=capture,
            redaction_count=redaction_count,
        )

    def _render_clipboard_capture(
        self,
        *,
        capture: dict[str, Any],
        redaction_count: int,
        replay_without_live_read: bool = False,
    ) -> dict[str, Any]:
        protocol = capture.get("protocol") or capture.get("capture_protocol")
        return {
            "action": "capture-clipboard-once",
            "adapter_kind": "clipboard-once",
            "context_id": capture["context_id"],
            "source_tag": capture["source_tag"],
            "speaker": capture.get("speaker"),
            "event_count": capture["event_count"],
            "relationship_count": capture["relationship_count"],
            "agent_deployment": capture.get("agent_deployment"),
            "capture_id": capture.get("capture_id"),
            "protocol": protocol,
            "capture_protocol": capture.get("capture_protocol") or protocol,
            "idempotent_replay": bool(capture.get("idempotent_replay", False)),
            "receipt_compact": bool(capture.get("receipt_compact", False)),
            "replay_without_live_read": bool(replay_without_live_read),
            "redaction_count": int(redaction_count),
            "redaction_count_known": not replay_without_live_read,
        }

    def _poll_file_source(
        self,
        source: dict[str, Any],
        *,
        max_bytes: int,
    ) -> dict[str, Any] | None:
        path = Path(
            os.path.abspath(
                os.path.expanduser(str(source.get("path") or ""))
            )
        )
        reject_sensitive_identifier(
            str(path),
            field="transcript source path",
        )
        self._validate_source_path(path)
        expected_parent_chain = _json_safe(
            source.get("parent_identity_chain") or [],
            [],
        )
        if not expected_parent_chain:
            raise ValueError(
                "transcript source requires explicit re-registration after path hardening"
            )
        with _open_stable_transcript_source(path) as (
            descriptor,
            source_stat,
            parent_identity_chain,
        ):
            if parent_identity_chain != expected_parent_chain:
                raise ValueError("transcript source ancestor identity changed")
            size = int(source_stat.st_size)
            cursor = max(0, int(source.get("cursor") or 0))
            stream_generation = max(0, int(source.get("stream_generation") or 0))
            source_instance_id = self._validate_source_instance_id(
                source.get("source_instance_id")
            )
            previous_device = int(source.get("file_device") or 0)
            previous_inode = int(source.get("file_inode") or 0)
            previous_size = max(0, int(source.get("file_size") or 0))
            previous_mtime_ns = max(0, int(source.get("file_mtime_ns") or 0))
            previous_ctime_ns = max(0, int(source.get("file_ctime_ns") or 0))
            same_file_identity = bool(
                previous_device == int(source_stat.st_dev)
                and previous_inode == int(source_stat.st_ino)
            )
            same_size_rewrite = bool(
                same_file_identity
                and size == cursor
                and (
                    (
                        previous_mtime_ns
                        and previous_mtime_ns != int(source_stat.st_mtime_ns)
                    )
                    or (
                        previous_ctime_ns
                        and previous_ctime_ns != int(source_stat.st_ctime_ns)
                    )
                )
            )
            rotated = bool(
                (previous_device and previous_device != int(source_stat.st_dev))
                or (previous_inode and previous_inode != int(source_stat.st_ino))
                or size < cursor
                or (previous_size and size < previous_size)
                or same_size_rewrite
            )
            # This adapter is intentionally append-only. Timestamp changes with
            # unchanged committed size detect same-inode rewrites without storing a
            # raw-content digest. A producer that rewrites old bytes *and* grows the
            # file in one operation cannot be distinguished from a normal append;
            # such producers must rotate/rename the file instead.
            if rotated:
                stream_generation += 1
                cursor = 0

            def update_source_file_state(committed_cursor: int) -> None:
                source["cursor"] = max(0, int(committed_cursor))
                source["stream_generation"] = stream_generation
                source["file_device"] = int(source_stat.st_dev)
                source["file_inode"] = int(source_stat.st_ino)
                source["file_size"] = size
                source["file_mtime_ns"] = int(source_stat.st_mtime_ns)
                source["file_ctime_ns"] = int(source_stat.st_ctime_ns)
                source["parent_identity_chain"] = parent_identity_chain
                source["updated_at"] = time.time()

            if size <= cursor:
                update_source_file_state(size)
                return None
            end = min(size, cursor + max_bytes)
            raw = _read_descriptor_range(
                descriptor,
                start=cursor,
                length=end - cursor,
            )
            if len(raw) != end - cursor:
                raise ValueError("transcript source changed while being read")
            after_read = os.fstat(descriptor)
            if _source_stat_snapshot(after_read) != _source_stat_snapshot(source_stat):
                raise ValueError("transcript source changed while being read")
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            update_source_file_state(end)
            return None
        redacted_text, redaction_count = redact_capture_text(text)
        source_id = str(source.get("source_id") or "")
        capture_id = _capture_id_for_file_delta(
            source_instance_id=source_instance_id,
            stream_generation=stream_generation,
            cursor_start=cursor,
            cursor_end=end,
        )
        capture = self.backend.capture_conversation(
            text=redacted_text,
            context_id=str(source.get("context_id") or "default"),
            source_tag=str(source.get("source_tag") or source_id or "transcript-source"),
            speaker=str(source.get("speaker") or "operator"),
            surprise_threshold=0.5,
            min_segment_sentences=1,
            capture_id=capture_id,
            metadata={
                **_json_safe(source.get("metadata") or {}, {}),
                "transcript_adapter": True,
                "adapter_kind": "file-tail",
                "capture_mode": "registered-file-delta",
                "source_id": source_id,
                "source_instance_id": source_instance_id,
                "registration_generation": max(
                    0,
                    int(source.get("registration_generation") or 0),
                ),
                "path_sha256": source.get("path_sha256") or _sha256_path(path),
                "path_name": path.name,
                "cursor_start": cursor,
                "cursor_end": end,
                "stream_generation": stream_generation,
                "truncated": end < size,
                "redaction_count": int(redaction_count),
                "remote_control_plane": False,
            },
        )
        # The cursor is only advanced after the capture ledger has committed (or
        # returned the cached result for this exact operation id).  If the state
        # file write is lost, the next poll recomputes the same id and cannot
        # duplicate the database effects.
        update_source_file_state(end)
        return {
            "source_id": source_id,
            "source_instance_id": source_instance_id,
            "registration_generation": max(
                0,
                int(source.get("registration_generation") or 0),
            ),
            "adapter_kind": "file-tail",
            "context_id": capture["context_id"],
            "source_tag": capture["source_tag"],
            "speaker": capture.get("speaker"),
            "cursor_start": cursor,
            "cursor_end": end,
            "stream_generation": stream_generation,
            "bytes_captured": len(raw),
            "truncated": end < size,
            "event_count": capture["event_count"],
            "relationship_count": capture["relationship_count"],
            "redaction_count": int(redaction_count),
            "agent_deployment": capture.get("agent_deployment"),
            "capture_id": capture.get("capture_id", capture_id),
            "protocol": capture.get("protocol") or capture.get("capture_protocol"),
            "capture_protocol": (
                capture.get("capture_protocol") or capture.get("protocol")
            ),
            "idempotent_replay": bool(capture.get("idempotent_replay", False)),
        }

    def _read_state(self) -> dict[str, Any]:
        parsed, _, _ = self._read_source_state_document()
        canonical, _ = self._canonicalize_source_state(parsed)
        return canonical

    def _write_state(self, state: dict[str, Any]) -> None:
        path = self.paths()["source_state_path"]
        payload = dict(state)
        payload["version"] = SOURCE_STATE_VERSION
        _atomic_write_json(
            path,
            _json_safe(
                payload,
                {"version": SOURCE_STATE_VERSION, "sources": {}},
            ),
        )

    def _read_app_state(self) -> dict[str, Any]:
        parsed, _, _ = self._read_app_state_document()
        return self._canonicalize_app_state(parsed)

    def _write_app_state(self, state: dict[str, Any]) -> None:
        path = self.paths()["app_state_path"]
        payload = dict(state)
        payload["version"] = APP_STATE_VERSION
        _atomic_write_json(
            path,
            _json_safe(
                payload,
                {"version": APP_STATE_VERSION, "connections": {}},
            ),
        )

    def _match_running_app(
        self,
        *,
        app_name: str,
        bundle_id: str = "",
        pid: int = 0,
    ) -> dict[str, Any] | None:
        requested_name = " ".join(str(app_name or "").split()).lower()
        requested_bundle = str(bundle_id or "").strip().lower()
        requested_pid = int(pid or 0)
        candidates: list[dict[str, Any]] = []
        for raw_app in self.running_app_provider():
            try:
                candidates.append(self._public_app(raw_app))
            except ValueError:
                continue
        if requested_pid > 0:
            for app in candidates:
                candidate_name = str(app.get("app_name") or "").strip().lower()
                candidate_bundle = str(app.get("bundle_id") or "").strip().lower()
                if (
                    int(app.get("pid") or 0) == requested_pid
                    and (not requested_name or candidate_name == requested_name)
                    and (not requested_bundle or candidate_bundle == requested_bundle)
                ):
                    return app
            # An explicit PID is an identity constraint, not a hint. Falling
            # back to a same-name or same-bundle process after PID mismatch
            # could attach a different app after process exit or reuse.
            return None
        if requested_bundle:
            for app in candidates:
                if (
                    str(app.get("bundle_id") or "").strip().lower()
                    == requested_bundle
                    and (
                        not requested_name
                        or str(app.get("app_name") or "").strip().lower()
                        == requested_name
                    )
                ):
                    return app
            return None
        if requested_name:
            for app in candidates:
                if str(app.get("app_name") or "").strip().lower() == requested_name:
                    return app
        return None

    def _connection_id(self, app: dict[str, Any]) -> str:
        app_name = " ".join(str(app.get("app_name") or "").split())
        bundle_id = " ".join(str(app.get("bundle_id") or "").split())
        reject_sensitive_identifier(app_name, field="app_name")
        if bundle_id:
            reject_sensitive_identifier(bundle_id, field="bundle_id")
        pid = int(app.get("pid") or 0)
        fingerprint = f"{bundle_id}|{app_name}|{pid}"
        return "app_" + _sha256_text(fingerprint)[:16]

    def _get_connection(self, connection_id: str) -> dict[str, Any]:
        requested = str(connection_id or "").strip()
        if not requested:
            raise ValueError("connection_id must not be empty")
        reject_sensitive_identifier(requested, field="connection_id")
        connection = self._read_app_state().get("connections", {}).get(requested)
        if not isinstance(connection, dict):
            raise ValueError(f"app connection not found: {requested}")
        if not bool(connection.get("enabled", True)):
            raise ValueError(f"app connection is disabled: {requested}")
        return connection

    def _validate_source_path(self, path: Path) -> None:
        if not path.exists():
            raise ValueError(f"transcript source path does not exist: {path}")
        if not path.is_file():
            raise ValueError(f"transcript source must be a file: {path}")
        if path.suffix.lower() not in ALLOWED_TRANSCRIPT_SUFFIXES:
            allowed = ", ".join(sorted(ALLOWED_TRANSCRIPT_SUFFIXES))
            raise ValueError(f"transcript source suffix must be one of: {allowed}")
        lowered_parts = {part.lower() for part in path.parts}
        lowered_name = path.name.lower()
        if (
            lowered_parts & SENSITIVE_PATH_FRAGMENTS
            or lowered_parts & SENSITIVE_CREDENTIAL_STORE_PARTS
            or lowered_name in SENSITIVE_CREDENTIAL_FILENAMES
            or any(
                fragment in lowered_name for fragment in SENSITIVE_PATH_FRAGMENTS
            )
        ):
            raise ValueError("refusing to register sensitive-looking path as transcript source")

    def _read_clipboard(self) -> str:
        try:
            result = subprocess.run(
                ["pbpaste"],
                text=True,
                capture_output=True,
                check=True,
                timeout=CLIPBOARD_READ_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            raise ValueError(
                "could not read macOS clipboard; pass explicit text or run from a user session"
            ) from exc
        return result.stdout

    def _detect_visible_application_processes(self) -> list[dict[str, Any]]:
        script = """
        tell application "System Events"
          set appRows to {}
          repeat with proc in (application processes whose visible is true)
            set appName to ""
            set appPid to 0
            set appBundle to ""
            try
              set appName to name of proc as text
            end try
            try
              set appPid to unix id of proc as integer
            end try
            try
              set appBundle to bundle identifier of proc as text
            end try
            if appName is not "" then
              set end of appRows to appName & tab & appPid & tab & appBundle
            end if
          end repeat
          set AppleScript's text item delimiters to linefeed
          return appRows as text
        end tell
        """
        result = subprocess.run(
            ["osascript", "-e", script],
            text=True,
            capture_output=True,
            check=True,
            timeout=APP_DETECT_SYSTEM_EVENTS_TIMEOUT_SECONDS,
        )
        apps: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if not parts or not parts[0].strip():
                continue
            try:
                pid = int(parts[1]) if len(parts) > 1 and parts[1].strip() else 0
            except ValueError:
                pid = 0
            bundle_id = parts[2].strip() if len(parts) > 2 else ""
            apps.append(
                {
                    "app_name": parts[0].strip(),
                    "pid": pid,
                    "bundle_id": "" if bundle_id == "missing value" else bundle_id,
                    "detection": "system-events",
                }
            )
        return apps

    def _detect_running_apps_macos(self) -> list[dict[str, Any]]:
        try:
            return self._detect_visible_application_processes()
        except Exception as exc:
            detail = str(getattr(exc, "stderr", "") or exc.__class__.__name__).strip()
            LOGGER.debug(
                "macOS System Events app detection failed; falling back to ps: %s",
                detail[:240],
            )
            LOGGER.debug("System Events detection failure detail", exc_info=True)
            return self._detect_running_apps_ps()

    def _detect_running_apps_ps(self) -> list[dict[str, Any]]:
        try:
            result = subprocess.run(
                ["ps", "-axo", "pid=,comm="],
                text=True,
                capture_output=True,
                check=True,
                timeout=APP_DETECT_PS_TIMEOUT_SECONDS,
            )
        except Exception:
            LOGGER.warning("ps app detection failed", exc_info=True)
            return []
        apps: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            row = line.strip()
            if not row:
                continue
            pid_text, _, command = row.partition(" ")
            try:
                pid = int(pid_text)
            except ValueError:
                continue
            app_name = Path(command.strip()).name if command.strip() else ""
            if not app_name:
                continue
            apps.append(
                {
                    "app_name": app_name,
                    "pid": pid,
                    "bundle_id": "",
                    "detection": "ps",
                }
            )
        return apps

    def _looks_like_attachable_app(self, app: dict[str, Any]) -> bool:
        name = str(app.get("app_name") or "").strip()
        if not name:
            return False
        lowered = name.lower()
        preferred_exact = {
            "alacritty",
            "chatgpt",
            "chrome",
            "claude",
            "codex",
            "cursor",
            "notes",
            "safari",
            "script editor",
            "slack",
            "terminal",
            "wireshark",
            "windows app",
        }
        if lowered in preferred_exact or (
            lowered.startswith("google chrome")
            and "helper" not in lowered
            and "renderer" not in lowered
        ):
            return True
        noisy_fragments = {
            "agent",
            "assistant",
            "background",
            "browsersupport",
            "center",
            "crashpad",
            "daemon",
            "driver",
            "extension",
            "extractor",
            "helper",
            "notification",
            "launcher",
            "plugin",
            "renderer",
            "registrar",
            "service",
            "spotlight",
            "support",
            "sync",
            "widget",
            "xpc",
            " for chrome",
        }
        if any(fragment in lowered for fragment in noisy_fragments):
            return False
        if lowered in {"sh", "zsh", "-zsh", "bash", "python", "node", "ps", "osascript"}:
            return False
        return " " in name and bool(name[0].isupper())

    def _resolve_accessibility_app_identity(self, app: dict[str, Any]) -> dict[str, Any]:
        app_name = " ".join(str(app.get("app_name") or "").split())
        if not app_name:
            raise ValueError("app_name must not be empty")
        requested_name = app_name.lower()
        requested_bundle = str(app.get("bundle_id") or "").strip().lower()
        try:
            requested_pid = int(app.get("pid") or 0)
        except (TypeError, ValueError):
            requested_pid = 0
        if requested_pid <= 0:
            raise ValueError(
                "app identity is incomplete; reconnect the running app before snapshot"
            )
        try:
            candidates = [
                self._public_app(candidate)
                for candidate in self._detect_visible_application_processes()
            ]
        except Exception as exc:
            raise ValueError(
                "app identity could not be revalidated; reconnect or use selected-text capture"
            ) from exc
        matches = [
            candidate
            for candidate in candidates
            if int(candidate.get("pid") or 0) == requested_pid
            and str(candidate.get("app_name") or "").strip().lower() == requested_name
            and str(candidate.get("bundle_id") or "").strip().lower()
            == requested_bundle
        ]
        if len(matches) != 1:
            raise ValueError(
                "app identity changed; reconnect the running app before snapshot"
            )
        return matches[0]

    def _clean_accessibility_snapshot_text(self, text: str) -> str:
        lines: list[str] = []
        seen: set[str] = set()
        for raw_line in str(text or "").splitlines():
            line = " ".join(raw_line.split())
            if not line or line.lower() == "missing value":
                continue
            key = line.lower()
            if key in seen:
                continue
            seen.add(key)
            lines.append(line)
        return "\n".join(lines).strip()

    def _snapshot_quality(self, text: str) -> dict[str, Any]:
        lines = [line for line in str(text or "").splitlines() if line.strip()]
        signal_chars = sum(len(line) for line in lines)
        unique_count = len(set(line.lower() for line in lines))
        low_signal = signal_chars < 160 or len(lines) < 4
        repetitive = bool(lines) and unique_count / max(len(lines), 1) < 0.55
        if not lines:
            quality = "blocked"
        elif low_signal:
            quality = "low"
        elif repetitive:
            quality = "degraded"
        else:
            quality = "high"
        return {
            "line_count": len(lines),
            "unique_line_count": unique_count,
            "signal_chars": signal_chars,
            "low_signal": low_signal,
            "repetitive": repetitive,
            "quality": quality,
        }

    def _snapshot_quality_badge(self, quality: dict[str, Any]) -> dict[str, Any]:
        quality_id = str(quality.get("quality") or "low")
        if quality_id == "replayed":
            return {
                "status": "ready",
                "label": "Durable replay",
                "detail": (
                    "The committed compact receipt was returned without observing "
                    "the live app again."
                ),
                "next_action": "No recapture is needed for this capture ID.",
            }
        if quality_id == "high":
            return {
                "status": "ready",
                "label": "High signal",
                "detail": "Accessibility returned enough distinct UI text for memory capture.",
                "next_action": "Capture snapshot to memory if this preview matches the intended work.",
            }
        if quality_id == "degraded":
            return {
                "status": "degraded",
                "label": "Repetitive",
                "detail": "The snapshot has enough text, but repeated UI labels may dilute recall value.",
                "next_action": "Prefer selected-text capture for exact content if this preview is mostly chrome.",
            }
        if quality_id == "blocked":
            return {
                "status": "blocked",
                "label": "No text",
                "detail": "The app did not expose readable Accessibility text.",
                "next_action": "Select relevant text in the app and use the selected-text fallback.",
            }
        return {
            "status": "degraded",
            "label": "Low signal",
            "detail": "The snapshot returned only a small amount of app text.",
            "next_action": "Open the relevant app view or use selected-text capture before writing memory.",
        }

    def _app_capture_guidance(
        self,
        *,
        connection: dict[str, Any],
        quality: dict[str, Any],
        badge: dict[str, Any],
    ) -> list[str]:
        app_name = str(connection.get("app_name") or "the app")
        if bool(quality.get("replay_without_live_read")):
            return [
                f"Returned the durable compact receipt for {app_name}.",
                "The live app was not observed again and no recapture is needed.",
            ]
        guidance = [
            f"Preview shows locally exposed Accessibility text from {app_name}.",
            str(badge.get("next_action") or "Capture only if the preview matches the intended content."),
        ]
        if bool(quality.get("low_signal")):
            guidance.append("Use selected-text capture for exact content when the preview is short.")
        if int(quality.get("line_count") or 0) <= 2:
            guidance.append("Bring the target window forward and expand the relevant panel before retrying.")
        return guidance

    def _preview_text(self, text: str, *, limit: int) -> str:
        clean = str(text or "").strip()
        if len(clean) <= limit:
            return clean
        return clean[: max(0, limit - 14)].rstrip() + "\n[truncated]"

    def _snapshot_app_accessibility(self, app: dict[str, Any]) -> str:
        identity = self._resolve_accessibility_app_identity(app)
        app_name = str(identity["app_name"])
        app_pid = int(identity["pid"])
        app_bundle = str(identity.get("bundle_id") or "")
        script = """
        on appendClean(rawValue)
          try
            set textValue to rawValue as text
          on error
            return ""
          end try
          if textValue is "" or textValue is "missing value" then return ""
          return textValue & linefeed
        end appendClean

        on run argv
          set appName to item 1 of argv
          set appPid to item 2 of argv as integer
          set appBundle to item 3 of argv
          set outputText to "Application: " & appName & linefeed
          tell application "System Events"
            set matchingProcesses to application processes whose unix id is appPid
            if (count matchingProcesses) is not 1 then error "process identity unavailable"
            set targetProcess to item 1 of matchingProcesses
            if (name of targetProcess as text) is not appName then error "process name changed"
            if appBundle is not "" then
              set liveBundle to ""
              try
                set liveBundle to bundle identifier of targetProcess as text
              end try
              if liveBundle is not appBundle then error "process bundle changed"
            end if
            tell targetProcess
              try
                set frontmost to true
              end try
              set winIndex to 0
              repeat with win in windows
                set winIndex to winIndex + 1
                try
                  set outputText to outputText & "Window " & winIndex & ": " & (name of win as text) & linefeed
                on error
                  set outputText to outputText & "Window " & winIndex & linefeed
                end try
                try
                  set uiItems to entire contents of win
                  repeat with itemRef in uiItems
                    try
                      set outputText to outputText & my appendClean(name of itemRef)
                    end try
                    try
                      set outputText to outputText & my appendClean(title of itemRef)
                    end try
                    try
                      set outputText to outputText & my appendClean(description of itemRef)
                    end try
                    try
                      set outputText to outputText & my appendClean(value of itemRef)
                    end try
                  end repeat
                end try
              end repeat
            end tell
          end tell
          return outputText
        end run
        """
        try:
            result = subprocess.run(
                ["osascript", "-e", script, app_name, str(app_pid), app_bundle],
                text=True,
                capture_output=True,
                check=True,
                timeout=APP_SNAPSHOT_ACCESSIBILITY_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            raise ValueError(
                "app snapshot failed; grant Accessibility permission or use selected-text capture"
            ) from exc
        return self._clean_accessibility_snapshot_text(result.stdout)

    def _public_app(self, app: dict[str, Any]) -> dict[str, Any]:
        try:
            pid = int(app.get("pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        app_name = " ".join(
            str(app.get("app_name") or app.get("name") or "").split()
        )
        bundle_id = " ".join(str(app.get("bundle_id") or "").split())
        if app_name:
            reject_sensitive_identifier(app_name, field="app_name")
        if bundle_id:
            reject_sensitive_identifier(bundle_id, field="bundle_id")
        return {
            "app_name": app_name,
            "bundle_id": bundle_id,
            "pid": pid,
            "detection": str(app.get("detection") or "provider"),
        }

    def _public_source(self, source: dict[str, Any]) -> dict[str, Any]:
        path = Path(str(source.get("path") or ""))
        return {
            "source_id": str(source.get("source_id") or ""),
            "source_instance_id": str(source.get("source_instance_id") or ""),
            "registration_generation": max(
                0,
                int(source.get("registration_generation") or 0),
            ),
            "kind": str(source.get("kind") or "file-tail"),
            "path": str(source.get("path") or ""),
            "path_name": path.name,
            "path_sha256": str(source.get("path_sha256") or ""),
            "context_id": str(source.get("context_id") or "default"),
            "source_tag": str(source.get("source_tag") or ""),
            "speaker": str(source.get("speaker") or "operator"),
            "enabled": bool(source.get("enabled", True)),
            "cursor": int(source.get("cursor") or 0),
            "stream_generation": max(0, int(source.get("stream_generation") or 0)),
            "format": str(source.get("format") or ""),
            "created_at": float(source.get("created_at") or 0.0),
            "updated_at": float(source.get("updated_at") or 0.0),
            "consent": _json_safe(source.get("consent") or {}, {}),
        }

    def _public_connection(self, connection: dict[str, Any]) -> dict[str, Any]:
        return {
            "connection_id": str(connection.get("connection_id") or ""),
            "app_name": str(connection.get("app_name") or ""),
            "bundle_id": str(connection.get("bundle_id") or ""),
            "pid": int(connection.get("pid") or 0),
            "context_id": str(connection.get("context_id") or "default"),
            "source_tag": str(connection.get("source_tag") or "app-connect"),
            "speaker": str(connection.get("speaker") or "operator"),
            "enabled": bool(connection.get("enabled", True)),
            "adapter_kinds": list(connection.get("adapter_kinds") or []),
            "capability_badge": self._app_capability_badge(connection),
            "created_at": float(connection.get("created_at") or 0.0),
            "updated_at": float(connection.get("updated_at") or 0.0),
            "metadata": _json_safe(connection.get("metadata") or {}, {}),
            "consent": _json_safe(connection.get("consent") or {}, {}),
        }

    def _app_capability_badge(
        self,
        connection: dict[str, Any],
        *,
        quality: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        app_name = str(connection.get("app_name") or "").lower()
        bundle_id = str(connection.get("bundle_id") or "").lower()
        quality_id = str((quality or {}).get("quality") or "")
        if quality_id == "blocked":
            return {
                "level": "accessibility_blocked",
                "label": "Accessibility blocked",
                "detail": "The app did not expose readable UI text to the local snapshot adapter.",
                "recommended_capture": "Select the relevant text in the app and use Capture selected text.",
            }
        if quality_id == "high":
            return {
                "level": "rich_text_available",
                "label": "Rich text available",
                "detail": "Accessibility returned enough distinct text for a useful memory snapshot.",
                "recommended_capture": "Preview, confirm the text is useful, then snapshot to memory.",
            }
        if quality_id in {"low", "degraded"}:
            return {
                "level": "selection_capture_recommended",
                "label": "Selection capture recommended",
                "detail": "The app exposed limited or repetitive text; exact selected text will be more trustworthy.",
                "recommended_capture": "Select the important text in the app and use Capture selected text.",
            }
        if "chrome" in app_name or "chrome" in bundle_id:
            return {
                "level": "selection_capture_recommended",
                "label": "Chrome selected text best",
                "detail": "Chrome reliably provides tab title and URL, but page internals vary by site.",
                "recommended_capture": "Capture active tab metadata plus selected page text.",
            }
        if "cursor" in app_name or "cursor" in bundle_id:
            return {
                "level": "selection_capture_recommended",
                "label": "Cursor selection best",
                "detail": "Editor and terminal internals are often low-signal through Accessibility snapshots.",
                "recommended_capture": "Select editor or terminal text before capture.",
            }
        if "terminal" in app_name or "iterm" in app_name:
            return {
                "level": "selection_capture_recommended",
                "label": "Terminal selection best",
                "detail": "Terminal snapshots can include chrome or stale scrollback.",
                "recommended_capture": "Select the command output you want remembered.",
            }
        if "codex" in app_name or "openai" in bundle_id:
            return {
                "level": "selection_capture_recommended",
                "label": "Codex selected text best",
                "detail": "Thread chrome is visible, but exact conversation or terminal content should be selected.",
                "recommended_capture": "Select the relevant Codex text or terminal output before capture.",
            }
        return {
            "level": "window_metadata_only",
            "label": "Window metadata only",
            "detail": "This app has no specialized adapter yet; snapshot quality depends on Accessibility output.",
            "recommended_capture": "Preview first, then use selected-text capture if the preview is low signal.",
        }


def build_parser() -> argparse.ArgumentParser:
    parser = SecretSafeArgumentParser(description="Operate SYNAPSE-S2 transcript capture adapters.")
    parser.add_argument("--capture-root", default=None)
    parser.add_argument("--state", default=None)
    parser.add_argument("--memory-db", default=None)
    parser.add_argument("--dimension", type=int, default=1024)
    parser.add_argument("--neurons", type=int, default=5400)
    parser.add_argument("--top-k", type=int, default=256)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--max-bytes", type=int, default=MAX_TRANSCRIPT_DELTA_BYTES)
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
    manager = TranscriptCaptureManager(
        root=args.capture_root,
        backend=backend_from_args(args),
    )
    if args.once:
        print(
            json.dumps(
                manager.poll_sources(max_bytes=args.max_bytes),
                sort_keys=True,
                default=str,
            )
        )
        return 0
    LOGGER.info("starting SYNAPSE-S2 transcript capture poller root=%s", manager.root)
    while True:
        manager.poll_sources(max_bytes=args.max_bytes)
        time.sleep(max(0.25, float(args.poll_interval)))


if __name__ == "__main__":
    raise SystemExit(main())

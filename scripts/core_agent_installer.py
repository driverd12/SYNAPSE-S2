#!/usr/bin/env python3
"""Install and operate the macOS authoritative-core LaunchAgent safely."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import plistlib
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core_protocol import (  # noqa: E402
    PROTOCOL_VERSION,
    contains_secret_shape,
    decode_canonical_json,
)
from core_authority import CoreAuthorityError, CoreAuthorityLease  # noqa: E402
from core_request_journal import (  # noqa: E402
    CoreRequestJournalError,
    repair_empty_preclaim_journal_residue,
)
from core_runtime_paths import (  # noqa: E402
    CoreRuntimePathError,
    canonical_core_socket_path,
    validate_core_socket_path,
)
from core_client_binding import (  # noqa: E402
    binding_for_config,
    default_binding_path,
    load_bound_core_config,
    load_core_client_binding,
    write_core_client_binding,
)
from core_service import (  # noqa: E402
    CoreConfig,
    CoreServiceError,
    REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX,
    STORE_GENERATION_ID_RE,
    STORE_GENERATION_SCHEMA,
    _manifest_build_id,
    _store_identity,
    config_from_wire,
    load_core_config,
    write_core_config,
)
from scripts.core_cutover_preflight import (  # noqa: E402
    CUTOVER_ATTESTATION_NAME,
    REPLACEMENT_ADMISSION_DEFAULT_TTL_SECONDS,
    REPLACEMENT_ADMISSION_MAX_TTL_SECONDS,
    CutoverAttestationRequest,
    CutoverPreflightError,
    ReplacementAdmissionRequest,
    _normal_absolute,
    launchctl_service_snapshot,
    publish_replacement_admission,
    run_preflight,
)
from redaction import SecretSafeArgumentParser  # noqa: E402


DEFAULT_LABEL = "aero.boom.synapse-s2.core"
DEFAULT_CAPTURE_LABEL = "aero.boom.synapse-s2.capture-daemon"
DEFAULT_DASHBOARD_LABEL = "aero.boom.synapse-s2.dashboard"
DEFAULT_PRODUCTION_EMBEDDING_PROVIDER = "mlx-neural"
DEFAULT_PRODUCTION_NEURAL_MODEL = (
    "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ"
)
DEFAULT_PRODUCTION_NEURAL_REVISION = "6c3ae70858513f1a78e9cdca3cae330d9075cd2a"
DEFAULT_PRODUCTION_MLX_DEVICE = "gpu"
REPLACEMENT_CERTIFICATION_MIN_REMAINING_SECONDS = 300.0
REPLACEMENT_ACTIVATION_HEADROOM_SECONDS = 300.0
CAPTURE_TRANSPORT_ZERO_DEBT_FIELDS = (
    "inbox_temp_file_count",
    "processing_empty_claim_count",
    "processing_malformed_claim_count",
    "error_file_count",
    "unresolved_error_count",
    "terminal_error_evidence_count",
    "historical_error_evidence_count",
    "unsafe_error_artifact_count",
    "error_resolution_pending_count",
    "error_resolution_failed_count",
)
LABEL_RE = re.compile(r"^[A-Za-z0-9._-]{1,160}$")
LAYOUT_MANIFEST_SCHEMA = "synapse-s2.noncanonical-core-layout.v1"
EXPECTED_SCHEMA_IDENTITY = "sqlite-53324442-v6"
EPOCH_RE = re.compile(r"^epoch-[1-9][0-9]*$")
MAX_LAYOUT_MANIFEST_BYTES = 64 * 1024


class CoreInstallerError(RuntimeError):
    """A bounded installer failure that is safe to show to an operator."""


@dataclass(frozen=True)
class InstallPaths:
    home: Path
    root: Path
    data_root: Path
    core_root: Path
    config: Path
    socket: Path
    state: Path
    memory_db: Path
    capture_root: Path
    log: Path
    plist: Path
    python: Path
    service_program: Path


def _env_path(name: str, default: Path) -> Path:
    raw = os.getenv(name)
    return _normal_absolute(raw if raw is not None else default, name=name.lower())


def _canonical_layout(data_root: Path, *, home: Path) -> dict[str, Path]:
    core_root = data_root / "core"
    return {
        "data_root": data_root,
        "core_root": core_root,
        "config": core_root / "service.json",
        # Keep the AF_UNIX endpoint short even when the reviewed repository is
        # nested below a long macOS Documents path. Durable generation,
        # journal, repair, and attestation evidence remains under core_root.
        "socket": canonical_core_socket_path(data_root, home=home),
        "state": data_root / "runtime_state.json",
        "memory_db": data_root / "memory.sqlite3",
        "capture_root": data_root,
        # launchd opens stdout/stderr before Python starts. On current macOS,
        # a newly-created log below Documents can be denied by protected-folder
        # admission even though the interactive operator can write it. Keep the
        # durable store in its reviewed layout and put only process output in
        # the user's canonical Logs directory.
        "log": home / "Library" / "Logs" / "SYNAPSE-S2" / "core-service.log",
    }


def _read_noncanonical_layout_manifest(path: Path) -> dict[str, Any]:
    _assert_no_symlink_components(path)
    if contains_secret_shape(str(path)):
        raise CoreInstallerError(
            "noncanonical layout manifest path contains credential material"
        )
    try:
        observed = path.lstat()
    except FileNotFoundError as exc:
        raise CoreInstallerError("noncanonical layout manifest is missing") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) & 0o077
        or observed.st_size > MAX_LAYOUT_MANIFEST_BYTES
    ):
        raise CoreInstallerError("noncanonical layout manifest is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, MAX_LAYOUT_MANIFEST_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_LAYOUT_MANIFEST_BYTES:
                raise CoreInstallerError("noncanonical layout manifest is too large")
        payload = b"".join(chunks)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    visible = path.lstat()
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        for item in (observed, opened, finished, visible)
    }
    if len(identities) != 1 or len(payload) != observed.st_size:
        raise CoreInstallerError("noncanonical layout manifest changed while being read")
    try:
        manifest = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CoreInstallerError("noncanonical layout manifest is invalid") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != LAYOUT_MANIFEST_SCHEMA
        or manifest.get("reviewed") is not True
        or not isinstance(manifest.get("reviewed_by"), str)
        or not manifest["reviewed_by"].strip()
        or contains_secret_shape(manifest["reviewed_by"])
        or not isinstance(manifest.get("paths"), dict)
    ):
        raise CoreInstallerError("noncanonical layout manifest is not explicitly reviewed")
    return manifest


def resolve_paths(
    *,
    label: str,
    noncanonical_layout_manifest: Path | None = None,
) -> InstallPaths:
    if LABEL_RE.fullmatch(label) is None or contains_secret_shape(label):
        raise CoreInstallerError("authoritative-core label is invalid")
    home = _env_path("HOME", Path.home())
    data_root = _env_path("SYNAPSE_S2_CORE_DATA_ROOT", ROOT / ".synapse_s2")
    core_root = _env_path("SYNAPSE_S2_CORE_RUNTIME_ROOT", data_root / "core")
    canonical_socket = canonical_core_socket_path(data_root, home=home)
    values = InstallPaths(
        home=home,
        root=ROOT,
        data_root=data_root,
        core_root=core_root,
        config=_env_path("SYNAPSE_S2_CORE_CONFIG", core_root / "service.json"),
        socket=_env_path("SYNAPSE_S2_CORE_SOCKET", canonical_socket),
        state=_env_path("SYNAPSE_S2_CORE_STATE", data_root / "runtime_state.json"),
        memory_db=_env_path("SYNAPSE_S2_MEMORY_DB", data_root / "memory.sqlite3"),
        capture_root=_env_path("SYNAPSE_S2_CAPTURE_ROOT", data_root),
        log=_env_path(
            "SYNAPSE_S2_CORE_LOG",
            home / "Library" / "Logs" / "SYNAPSE-S2" / "core-service.log",
        ),
        plist=home / "Library" / "LaunchAgents" / f"{label}.plist",
        python=_env_path("SYNAPSE_S2_CORE_PYTHON", ROOT / ".venv" / "bin" / "python"),
        service_program=ROOT / "core_service.py",
    )
    for field, path in values.__dict__.items():
        if isinstance(path, Path) and contains_secret_shape(str(path)):
            raise CoreInstallerError(f"{field} contains a credential-shaped value")
    expected = _canonical_layout(values.data_root, home=values.home)
    for field, expected_path in expected.items():
        if getattr(values, field) != expected_path:
            raise CoreInstallerError(
                "core data paths must use one internally canonical layout"
            )
    canonical = _canonical_layout(ROOT / ".synapse_s2", home=values.home)
    observed_layout = {field: getattr(values, field) for field in canonical}
    if observed_layout != canonical:
        manifest_path = noncanonical_layout_manifest
        if manifest_path is None:
            configured = os.getenv("SYNAPSE_S2_NONCANONICAL_LAYOUT_MANIFEST")
            if configured:
                manifest_path = _normal_absolute(
                    configured,
                    name="noncanonical layout manifest",
                )
        if manifest_path is None:
            raise CoreInstallerError(
                "noncanonical core layout requires an explicit reviewed manifest"
            )
        manifest = _read_noncanonical_layout_manifest(manifest_path)
        manifest_paths = manifest["paths"]
        if set(manifest_paths) != set(canonical) or any(
            not isinstance(manifest_paths.get(field), str)
            or _normal_absolute(
                manifest_paths[field],
                name=f"noncanonical layout {field}",
            )
            != observed_layout[field]
            for field in canonical
        ):
            raise CoreInstallerError(
                "noncanonical layout does not match its reviewed manifest"
            )
    try:
        validate_core_socket_path(values.socket)
    except CoreRuntimePathError as exc:
        raise CoreInstallerError(
            "core socket path exceeds the safe transport bound"
        ) from exc
    if values.socket != canonical_socket:
        raise CoreInstallerError(
            "core socket must use the canonical private transport path"
        )
    if values.state.parent != values.data_root:
        raise CoreInstallerError(
            "runtime state must remain directly under data_root for adapter compatibility"
        )
    return values


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _assert_no_symlink_components(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise CoreInstallerError("managed path is not a normal absolute path")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        observed = _lstat(current)
        if observed is None:
            continue
        if stat.S_ISLNK(observed.st_mode):
            if current == Path("/var") and os.readlink(current) == "private/var":
                continue
            raise CoreInstallerError("managed path contains a symlink component")
        if current != path and not stat.S_ISDIR(observed.st_mode):
            raise CoreInstallerError("managed path contains a non-directory component")


def _assert_layout(paths: InstallPaths) -> None:
    expected = _canonical_layout(paths.data_root, home=paths.home)
    if any(getattr(paths, field) != value for field, value in expected.items()):
        raise CoreInstallerError("authoritative-core paths do not share one canonical layout")
    broad = {
        Path("/"),
        paths.home,
        paths.root,
        *paths.home.parents,
        *paths.root.parents,
    }
    if paths.data_root in broad or paths.core_root in broad:
        raise CoreInstallerError("authoritative-core managed path is too broad")
    if paths.plist.parent != paths.home / "Library" / "LaunchAgents":
        raise CoreInstallerError("LaunchAgent plist escaped the user LaunchAgents directory")
    for path in (
        paths.data_root,
        paths.core_root,
        paths.config,
        paths.socket,
        paths.state,
        paths.memory_db,
        paths.log,
        paths.plist,
        paths.service_program,
    ):
        _assert_no_symlink_components(path)


def _assert_owner_controlled(
    path: Path,
    *,
    kind: str,
    require_mode: int | None = None,
) -> os.stat_result:
    _assert_no_symlink_components(path)
    observed = _lstat(path)
    if observed is None:
        raise CoreInstallerError(f"{kind} is missing")
    expected = stat.S_ISDIR if kind.endswith("directory") else stat.S_ISREG
    if (
        stat.S_ISLNK(observed.st_mode)
        or not expected(observed.st_mode)
        or observed.st_uid != os.getuid()
        or (not kind.endswith("directory") and observed.st_nlink != 1)
    ):
        raise CoreInstallerError(f"{kind} must be owner-controlled and non-symlinked")
    if require_mode is not None and stat.S_IMODE(observed.st_mode) != require_mode:
        raise CoreInstallerError(f"{kind} has an unsafe permission mode")
    return observed


def ensure_private_directory(path: Path, *, require_private: bool = True) -> None:
    _assert_no_symlink_components(path)
    observed = _lstat(path)
    if observed is None:
        missing: list[Path] = []
        cursor = path
        while _lstat(cursor) is None:
            missing.append(cursor)
            if cursor.parent == cursor:
                raise CoreInstallerError("private directory parent is invalid")
            cursor = cursor.parent
        parent_stat = cursor.lstat()
        if (
            stat.S_ISLNK(parent_stat.st_mode)
            or not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.getuid()
            or stat.S_IMODE(parent_stat.st_mode) & 0o022
        ):
            raise CoreInstallerError("private directory parent is not owner-controlled")
        for candidate in reversed(missing):
            try:
                candidate.mkdir(mode=0o700, parents=False)
            except FileExistsError:
                pass
            created = candidate.lstat()
            if (
                stat.S_ISLNK(created.st_mode)
                or not stat.S_ISDIR(created.st_mode)
                or created.st_uid != os.getuid()
                or stat.S_IMODE(created.st_mode) != 0o700
            ):
                raise CoreInstallerError("private directory creation raced with an unsafe target")
        observed = path.lstat()
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.getuid()
    ):
        raise CoreInstallerError("private directory must be owner-controlled and non-symlinked")
    mode = stat.S_IMODE(observed.st_mode)
    if (require_private and mode != 0o700) or (not require_private and mode & 0o022):
        raise CoreInstallerError("private directory has an unsafe permission mode")


def prepare_private_regular(path: Path) -> None:
    ensure_private_directory(path.parent)
    observed = _lstat(path)
    if observed is not None and (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) != 0o600
    ):
        raise CoreInstallerError("private file target is unsafe")
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    if observed is None:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        visible = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            != (
                visible.st_dev,
                visible.st_ino,
                visible.st_size,
                visible.st_mtime_ns,
                visible.st_ctime_ns,
            )
            or (
                observed is not None
                and (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    opened.st_mtime_ns,
                    opened.st_ctime_ns,
                )
                != (
                    observed.st_dev,
                    observed.st_ino,
                    observed.st_size,
                    observed.st_mtime_ns,
                    observed.st_ctime_ns,
                )
            )
        ):
            raise CoreInstallerError("private file target is unsafe")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.getuid():
            raise CoreInstallerError("publication directory is not owner-controlled")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_private_bytes(path: Path, payload: bytes) -> None:
    ensure_private_directory(path.parent, require_private=False)
    existing = _lstat(path)
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_uid != os.getuid()
        or existing.st_nlink != 1
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        raise CoreInstallerError("refusing to replace an unsafe LaunchAgent plist")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(6)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        current = _lstat(path)
        if existing is None:
            if current is not None:
                raise CoreInstallerError("LaunchAgent plist appeared during publication")
        elif current is None or (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
            current.st_uid,
            current.st_nlink,
            stat.S_IMODE(current.st_mode),
        ) != (
            existing.st_dev,
            existing.st_ino,
            existing.st_size,
            existing.st_mtime_ns,
            existing.st_ctime_ns,
            existing.st_uid,
            existing.st_nlink,
            stat.S_IMODE(existing.st_mode),
        ):
            raise CoreInstallerError("LaunchAgent plist changed during publication")
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _read_stable_private_regular(
    path: Path,
    *,
    kind: str,
    maximum_bytes: int,
) -> bytes:
    """Read one exact owner-only file without following or repairing it."""

    if maximum_bytes < 1:
        raise CoreInstallerError(f"{kind} size bound is invalid")
    _assert_no_symlink_components(path)
    before = _assert_owner_controlled(
        path,
        kind=kind,
        require_mode=0o600,
    )
    if before.st_size <= 0 or before.st_size > maximum_bytes:
        raise CoreInstallerError(f"{kind} has an unsafe size")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CoreInstallerError(f"{kind} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(65_536, maximum_bytes + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise CoreInstallerError(f"{kind} has an unsafe size")
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    visible = path.lstat()

    def identity(item: os.stat_result) -> tuple[int, ...]:
        return (
            int(item.st_dev),
            int(item.st_ino),
            int(item.st_size),
            int(item.st_mtime_ns),
            int(item.st_ctime_ns),
            int(item.st_uid),
            int(item.st_nlink),
            stat.S_IMODE(item.st_mode),
        )

    if (
        len({identity(item) for item in (before, opened, finished, visible)}) != 1
        or total != int(before.st_size)
    ):
        raise CoreInstallerError(f"{kind} changed while being read")
    return b"".join(chunks)


@contextmanager
def _exclusive_existing_private_lock(path: Path, *, kind: str) -> Iterator[None]:
    """Hold an existing 0600 lock without creating or normalizing it."""

    _assert_no_symlink_components(path)
    before = _assert_owner_controlled(
        path,
        kind=kind,
        require_mode=0o600,
    )
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CoreInstallerError(f"{kind} could not be opened safely") from exc
    acquired = False
    try:
        opened = os.fstat(descriptor)
        visible = path.lstat()
        expected = (
            int(before.st_dev),
            int(before.st_ino),
            int(before.st_uid),
            int(before.st_nlink),
            stat.S_IMODE(before.st_mode),
        )
        if any(
            (
                int(item.st_dev),
                int(item.st_ino),
                int(item.st_uid),
                int(item.st_nlink),
                stat.S_IMODE(item.st_mode),
            )
            != expected
            for item in (opened, visible)
        ):
            raise CoreInstallerError(f"{kind} changed while being opened")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError as exc:
            raise CoreInstallerError(f"{kind} is held by another process") from exc
        yield
        held_after = os.fstat(descriptor)
        visible_after = path.lstat()
        if any(
            (
                int(item.st_dev),
                int(item.st_ino),
                int(item.st_uid),
                int(item.st_nlink),
                stat.S_IMODE(item.st_mode),
            )
            != expected
            for item in (held_after, visible_after)
        ):
            raise CoreInstallerError(f"{kind} changed while it was held")
    finally:
        if acquired:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(descriptor)


def build_config(paths: InstallPaths) -> CoreConfig:
    try:
        embedding_provider = os.getenv(
            "SYNAPSE_S2_EMBEDDING_PROVIDER",
            DEFAULT_PRODUCTION_EMBEDDING_PROVIDER,
        )
        neural_selected = embedding_provider.strip().lower() in {
            "mlx-neural",
            "mlx-neural-v1",
        }
        neural_normalize = os.getenv("SYNAPSE_S2_NEURAL_NORMALIZE", "true")
        neural_local_only = os.getenv(
            "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY", "true"
        )

        def strict_environment_bool(raw: str, *, name: str) -> bool:
            normalized = raw.strip().lower()
            if normalized in {"1", "true", "yes"}:
                return True
            if normalized in {"0", "false", "no"}:
                return False
            raise CoreInstallerError(f"{name} must be an explicit boolean")

        require_native = strict_environment_bool(
            os.getenv("SYNAPSE_S2_CORE_REQUIRE_NATIVE", "true"),
            name="SYNAPSE_S2_CORE_REQUIRE_NATIVE",
        )
        poll_transcripts = strict_environment_bool(
            os.getenv("SYNAPSE_S2_TRANSCRIPT_POLL", "true"),
            name="SYNAPSE_S2_TRANSCRIPT_POLL",
        )
        canonical_neural_model = os.getenv("SYNAPSE_S2_NEURAL_MODEL")
        legacy_neural_model = os.getenv("SYNAPSE_S2_NEURAL_MODEL_ID")
        if (
            canonical_neural_model is not None
            and legacy_neural_model is not None
            and canonical_neural_model != legacy_neural_model
        ):
            raise CoreInstallerError(
                "SYNAPSE_S2_NEURAL_MODEL conflicts with deprecated "
                "SYNAPSE_S2_NEURAL_MODEL_ID"
            )
        if canonical_neural_model is not None:
            neural_model = canonical_neural_model
        elif legacy_neural_model is not None:
            neural_model = legacy_neural_model
        else:
            neural_model = DEFAULT_PRODUCTION_NEURAL_MODEL
        raw_neural_revision = os.getenv("SYNAPSE_S2_NEURAL_REVISION")
        neural_revision = (
            DEFAULT_PRODUCTION_NEURAL_REVISION
            if (
                raw_neural_revision is None
                and neural_model == DEFAULT_PRODUCTION_NEURAL_MODEL
            )
            else raw_neural_revision
        )
        raw_neural_cache_dir = os.getenv("SYNAPSE_S2_NEURAL_CACHE_DIR")
        neural_cache_dir = (
            paths.data_root / "models"
            if raw_neural_cache_dir is None
            else Path(raw_neural_cache_dir).expanduser()
        )

        config = CoreConfig(
            socket_path=paths.socket,
            state_path=paths.state,
            memory_path=paths.memory_db,
            capture_root=paths.capture_root,
            dimension=int(os.getenv("SYNAPSE_S2_DIMENSION", "1024")),
            num_neurons=int(os.getenv("SYNAPSE_S2_NEURONS", "8192")),
            default_top_k=int(os.getenv("SYNAPSE_S2_TOP_K", "256")),
            recall_count=int(os.getenv("SYNAPSE_S2_RECALL_COUNT", "10")),
            quick_pruning_interval_seconds=float(
                os.getenv("SYNAPSE_S2_QUICK_PRUNING_INTERVAL_SECONDS", "300")
            ),
            idle_deep_sleep_seconds=float(
                os.getenv("SYNAPSE_S2_IDLE_DEEP_SLEEP_SECONDS", "1800")
            ),
            embedding_provider_name=embedding_provider,
            embedding_neural_model_id=(
                neural_model
                if neural_selected
                else None
            ),
            embedding_neural_revision=(
                neural_revision
                if neural_selected
                else None
            ),
            embedding_neural_cache_dir=(
                neural_cache_dir
                if neural_selected
                else None
            ),
            embedding_neural_pooling=(
                os.getenv("SYNAPSE_S2_NEURAL_POOLING", "mean")
                if neural_selected
                else None
            ),
            embedding_neural_max_tokens=(
                int(os.getenv("SYNAPSE_S2_NEURAL_MAX_TOKENS", "512"))
                if neural_selected
                else None
            ),
            embedding_neural_normalize=(
                strict_environment_bool(
                    neural_normalize,
                    name="SYNAPSE_S2_NEURAL_NORMALIZE",
                )
                if neural_selected
                else None
            ),
            embedding_neural_local_files_only=(
                strict_environment_bool(
                    neural_local_only,
                    name="SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY",
                )
                if neural_selected
                else None
            ),
            mlx_device=os.getenv(
                "MLX_DEVICE",
                DEFAULT_PRODUCTION_MLX_DEVICE,
            ),
            require_native=require_native,
            capture_poll_seconds=float(
                os.getenv("SYNAPSE_S2_CAPTURE_POLL_INTERVAL", "2")
            ),
            capture_max_files=int(os.getenv("SYNAPSE_S2_CAPTURE_MAX_FILES", "50")),
            poll_transcript_sources=poll_transcripts,
            max_transcript_bytes=int(
                os.getenv("SYNAPSE_S2_MAX_TRANSCRIPT_BYTES", "256000")
            ),
        )
        # Close every field through the production codec before it can be
        # published as the reviewed client configuration.
        return config_from_wire(config.to_wire())
    except (TypeError, ValueError, RuntimeError) as exc:
        raise CoreInstallerError("authoritative-core configuration is invalid") from exc


def publish_client_binding(
    *,
    paths: InstallPaths,
    label: str,
    config: CoreConfig,
    authority_mode: str,
) -> dict[str, Any]:
    try:
        closed_config = config_from_wire(config.to_wire())
        # The config is the first half of a fail-closed two-file publication.
        # If binding publication is interrupted, the prior binding disagrees
        # with this config and every new client refuses to start.
        write_core_config(paths.config, closed_config)
        _assert_owner_controlled(
            paths.config,
            kind="core service config",
            require_mode=0o600,
        )
        verified_config = load_core_config(paths.config)
    except Exception as exc:
        raise CoreInstallerError("core client config publication failed") from exc
    if (
        verified_config != closed_config
        or verified_config.fingerprint != closed_config.fingerprint
        or verified_config.embedding_space_identity
        != closed_config.embedding_space_identity
    ):
        raise CoreInstallerError("core client config publication was not stable")
    binding = binding_for_config(
        repo_root=paths.root,
        data_root=paths.data_root,
        config=verified_config,
        core_label=label,
        authority_mode=authority_mode,
    )
    binding_path = default_binding_path(paths.home)
    try:
        write_core_client_binding(binding_path, binding)
        verified = load_core_client_binding(binding_path)
        bound_config = load_bound_core_config(verified)
    except Exception as exc:
        raise CoreInstallerError("core client binding publication failed") from exc
    if verified != binding or bound_config != verified_config:
        raise CoreInstallerError("core client binding publication was not stable")
    return {
        "path": str(binding_path),
        "digest": binding.digest,
        "config_path": str(binding.config_path),
        "config_digest": binding.config_digest,
        "authority_mode": binding.authority_mode,
        "config_fingerprint": binding.config_fingerprint,
        "embedding_space_identity": binding.embedding_space_identity,
    }


def plist_payload(
    *,
    label: str,
    paths: InstallPaths,
    config: CoreConfig,
    keep_alive: bool = True,
    replacement_admission: bool = False,
) -> bytes:
    try:
        closed_config = config_from_wire(config.to_wire())
    except Exception as exc:
        raise CoreInstallerError("LaunchAgent configuration is invalid") from exc
    if (
        closed_config.socket_path != paths.socket
        or closed_config.state_path != paths.state
        or closed_config.memory_path != paths.memory_db
        or closed_config.capture_root != paths.capture_root
    ):
        raise CoreInstallerError(
            "LaunchAgent configuration does not match the reviewed layout"
        )
    if type(keep_alive) is not bool or type(replacement_admission) is not bool:
        raise CoreInstallerError("LaunchAgent staging policy is invalid")
    if replacement_admission and keep_alive:
        raise CoreInstallerError(
            "replacement admission must use a non-persistent LaunchAgent"
        )
    environment = {
        # Pin the exact source manifest used by the installer. Do not let
        # an inherited shell override make health compare unlike builds.
        "SYNAPSE_S2_BUILD_ID": _manifest_build_id(paths.root),
        # MLX selects its device from process environment.  Publish the
        # exact closed CoreConfig value so launchd cannot silently fall
        # back to "default" for a reviewed cpu/gpu configuration.
        "MLX_DEVICE": closed_config.mlx_device,
    }
    if replacement_admission:
        # This narrowly selects the signed, short-lived successor-admission
        # verifier.  It is never present in the persistent production plist.
        environment["SYNAPSE_S2_REPLACEMENT_ADMISSION"] = "1"
    payload = {
        "Label": label,
        "ProgramArguments": [
            str(paths.python),
            str(paths.service_program),
            "serve",
            "--config",
            str(paths.config),
        ],
        "RunAtLoad": True,
        "KeepAlive": keep_alive,
        "ProcessType": "Interactive",
        "Umask": 0o077,
        "EnvironmentVariables": environment,
        "StandardOutPath": str(paths.log),
        "StandardErrorPath": str(paths.log),
        "WorkingDirectory": str(paths.root),
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True)


class LaunchCtl:
    def __init__(self, executable: str | os.PathLike[str], *, uid: int, label: str) -> None:
        self.executable = str(executable)
        self.uid = int(uid)
        self.label = label
        self.domain = f"gui/{self.uid}"
        self.target = f"{self.domain}/{self.label}"

    def _run(self, *arguments: str, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [self.executable, *arguments],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CoreInstallerError("launchctl operation failed") from exc

    def snapshot(self) -> dict[str, Any]:
        try:
            snapshot = launchctl_service_snapshot(
                launchctl_bin=self.executable,
                uid=self.uid,
                label=self.label,
            )
        except CutoverPreflightError as exc:
            raise CoreInstallerError(str(exc)) from exc
        return {
            **snapshot,
            "running": snapshot.get("state") == "running",
        }

    def enable(self) -> None:
        if self._run("enable", self.target).returncode != 0:
            raise CoreInstallerError("could not enable authoritative-core LaunchAgent")

    def disable(self) -> None:
        if self._run("disable", self.target).returncode != 0:
            raise CoreInstallerError("could not disable authoritative-core LaunchAgent")

    def disabled(self) -> bool:
        completed = self._run("print-disabled", self.domain)
        output = completed.stdout or ""
        diagnostic = completed.stderr or ""
        if (
            completed.returncode != 0
            or len(output.encode("utf-8")) > 1024 * 1024
            or len(diagnostic.encode("utf-8")) > 1024 * 1024
            or "\x00" in output
        ):
            raise CoreInstallerError(
                "could not verify authoritative-core disabled policy"
            )
        exact = re.compile(
            rf'^\s*"{re.escape(self.label)}"\s*=>\s*'
            r'(enabled|disabled|true|false)\s*$'
        )
        values = [
            match.group(1) in {"disabled", "true"}
            for line in output.splitlines()
            if (match := exact.fullmatch(line)) is not None
        ]
        if len(values) != 1:
            raise CoreInstallerError(
                "authoritative-core disabled policy is ambiguous"
            )
        return values[0]

    def bootstrap(self, plist: Path) -> None:
        if self._run("bootstrap", self.domain, str(plist)).returncode != 0:
            raise CoreInstallerError("could not bootstrap authoritative-core LaunchAgent")

    def kickstart(self) -> None:
        if self._run("kickstart", self.target).returncode != 0:
            raise CoreInstallerError("could not kickstart authoritative-core LaunchAgent")

    def bootout(self, *, wait_seconds: float) -> None:
        if not self.snapshot()["loaded"]:
            return
        completed = self._run("bootout", self.target)
        if completed.returncode != 0 and self.snapshot()["loaded"]:
            raise CoreInstallerError("could not boot out authoritative-core LaunchAgent")
        deadline = time.monotonic() + wait_seconds
        while self.snapshot()["loaded"]:
            if time.monotonic() >= deadline:
                raise CoreInstallerError("authoritative-core LaunchAgent did not unload")
            time.sleep(0.1)


def _private_socket(path: Path) -> None:
    observed = _lstat(path)
    if observed is None:
        raise CoreInstallerError("authoritative-core socket is missing")
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISSOCK(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) != 0o600
    ):
        raise CoreInstallerError("authoritative-core socket is not private")
    _assert_owner_controlled(path.parent, kind="socket directory", require_mode=0o700)


def _private_token(path: Path) -> None:
    _assert_owner_controlled(path, kind="authentication token", require_mode=0o600)


def _verify_restored_health_identity(
    config: CoreConfig,
    *,
    store_identity: str,
    authority_epoch_number: int,
) -> dict[str, Any]:
    """Verify a restored target's persisted identity against its lineage."""

    from memory_store import DurableMemoryStore
    from recovery_manager import VerifiedRecoveryManager

    store = DurableMemoryStore.open_existing_for_audit(config.memory_path)
    try:
        manager = VerifiedRecoveryManager(
            store,
            capture_root=config.capture_root or config.memory_path.parent,
            runtime_state_path=config.state_path,
        )
        return manager.verify_adopted_restored_store_identity(
            config.memory_path.parent,
            expected_store_identity=store_identity,
            expected_authority_epoch_number=authority_epoch_number,
        )
    finally:
        store.close()


def probe_health(
    config: CoreConfig,
    *,
    restored_target: bool = False,
    expected_deployment_mode: str = "authoritative",
    require_capture_ready: bool = True,
) -> dict[str, Any]:
    from core_client import CoreClient

    client = CoreClient(
        socket_path=config.socket_path,
        state_path=config.state_path,
        expected_config_fingerprint=config.fingerprint,
    )
    result = client.health(timeout_seconds=2.0)
    identity = client.authority_identity
    if not isinstance(identity, dict):
        raise CoreInstallerError("authoritative-core identity is missing")
    required_identity = {
        "authority_id",
        "neural_epoch",
        "config_fingerprint",
        "build_id",
        "store_identity",
        "schema_identity",
    }
    if not required_identity.issubset(identity) or any(
        not isinstance(identity[key], str) or not identity[key] or len(identity[key]) > 256
        for key in required_identity
    ):
        raise CoreInstallerError("authoritative-core identity is incomplete")
    capture = result.get("capture") if isinstance(result, dict) else None
    capture_ready = bool(
        isinstance(capture, dict)
        and capture.get("ready") is True
        and type(capture.get("iteration_count")) is int
        and int(capture["iteration_count"]) >= 1
    )
    if (
        not isinstance(result, dict)
        or result.get("ready") is not True
        or result.get("protocol_version") != PROTOCOL_VERSION
        or result.get("deployment_mode") != expected_deployment_mode
        or not isinstance(capture, dict)
        or capture.get("enabled") is not True
        or type(capture.get("ready")) is not bool
        or type(capture.get("iteration_count")) is not int
        or int(capture["iteration_count"]) < 0
        or type(capture.get("error_count")) is not int
        or int(capture["error_count"]) < 0
        or (not capture_ready and capture.get("last_error_code") is not None)
        or (require_capture_ready and not capture_ready)
    ):
        raise CoreInstallerError("authoritative-core or embedded capture is not ready")
    expected = {
        "config_fingerprint": config.fingerprint,
        "build_id": _manifest_build_id(ROOT),
    }
    if any(identity.get(key) != value for key, value in expected.items()):
        raise CoreInstallerError("authoritative-core identity does not match this install")
    if identity["schema_identity"] != EXPECTED_SCHEMA_IDENTITY:
        raise CoreInstallerError("authoritative-core schema identity is not exact v6")
    if EPOCH_RE.fullmatch(identity["neural_epoch"]) is None:
        raise CoreInstallerError("authoritative-core neural epoch has an invalid format")
    authority_epoch_number = int(identity["neural_epoch"].split("-", 1)[1])
    path_store_identity = _store_identity(config.memory_path)
    persisted_store_identity = str(identity["store_identity"])
    if restored_target or persisted_store_identity != path_store_identity:
        try:
            lineage = _verify_restored_health_identity(
                config,
                store_identity=persisted_store_identity,
                authority_epoch_number=authority_epoch_number,
            )
        except Exception as exc:
            raise CoreInstallerError(
                "authoritative-core restored identity is not verified"
            ) from exc
        if (
            lineage.get("verified") is not True
            or lineage.get("store_identity") != persisted_store_identity
            or type(lineage.get("authority_epoch_number")) is not int
            or int(lineage["authority_epoch_number"])
            != authority_epoch_number
        ):
            raise CoreInstallerError(
                "authoritative-core restored identity is not verified"
            )
    _private_socket(config.socket_path)
    _private_token(config.socket_path.with_name(config.socket_path.name + ".token"))
    return {
        "ready": True,
        "capture_ready": capture_ready,
        "authority_id": identity["authority_id"],
        "neural_epoch": identity["neural_epoch"],
        "build_id": identity["build_id"],
        "schema_identity": identity["schema_identity"],
        "deployment_mode": result["deployment_mode"],
        "config_identity_verified": True,
        "store_identity_verified": True,
    }


def wait_for_health(
    *,
    launchctl: LaunchCtl,
    config: CoreConfig,
    prior_pid: int | None,
    wait_seconds: float,
    restored_target: bool = False,
    expected_deployment_mode: str = "authoritative",
    require_capture_ready: bool = True,
) -> dict[str, Any]:
    deadline = time.monotonic() + wait_seconds
    last_pid = None
    consecutive = 0
    while time.monotonic() < deadline:
        snapshot = launchctl.snapshot()
        observed_pid = snapshot.get("pid")
        if snapshot.get("running") and isinstance(observed_pid, int) and observed_pid != prior_pid:
            try:
                health = probe_health(
                    config,
                    restored_target=restored_target,
                    expected_deployment_mode=expected_deployment_mode,
                    require_capture_ready=require_capture_ready,
                )
            except Exception:
                health = None
            if health is not None:
                if last_pid == observed_pid:
                    consecutive += 1
                else:
                    last_pid = observed_pid
                    consecutive = 1
                if consecutive >= 2:
                    return {**health, "pid": observed_pid}
            else:
                consecutive = 0
        else:
            consecutive = 0
        time.sleep(0.25)
    raise CoreInstallerError("authoritative-core did not pass its stabilized health gate")


def replacement_certification_seconds_remaining(
    admission: Mapping[str, Any] | None,
) -> int:
    """Require enough signed life for a full live certification attempt."""

    expires_at = (
        None if not isinstance(admission, Mapping) else admission.get("expires_at_unix_ms")
    )
    if type(expires_at) is not int:
        raise CoreInstallerError("replacement admission expiry is invalid")
    remaining_milliseconds = int(expires_at) - int(time.time() * 1000)
    if remaining_milliseconds < int(
        REPLACEMENT_CERTIFICATION_MIN_REMAINING_SECONDS * 1000
    ):
        raise CoreInstallerError(
            "replacement candidate has too little signed time remaining for certification"
        )
    return remaining_milliseconds // 1000


def replacement_admission_ttl_seconds(wait_seconds: float) -> float:
    """Budget both activation waits, certification reserve, and publication work."""

    if (
        not isinstance(wait_seconds, (int, float))
        or isinstance(wait_seconds, bool)
        or not math.isfinite(float(wait_seconds))
        or float(wait_seconds) <= 0.0
    ):
        raise CoreInstallerError("replacement activation wait is invalid")
    ttl_seconds = max(
        REPLACEMENT_ADMISSION_DEFAULT_TTL_SECONDS,
        (2.0 * float(wait_seconds))
        + REPLACEMENT_CERTIFICATION_MIN_REMAINING_SECONDS
        + REPLACEMENT_ACTIVATION_HEADROOM_SECONDS,
    )
    if ttl_seconds > REPLACEMENT_ADMISSION_MAX_TTL_SECONDS:
        raise CoreInstallerError(
            "replacement activation cannot fit inside the signed admission bound"
        )
    return ttl_seconds


def replacement_activation_seconds_remaining(
    admission: Mapping[str, Any] | None,
    *,
    wait_seconds: float,
) -> int:
    """Fail before launch unless both bounded waits and certification still fit."""

    replacement_admission_ttl_seconds(wait_seconds)
    expires_at = (
        None if not isinstance(admission, Mapping) else admission.get("expires_at_unix_ms")
    )
    if type(expires_at) is not int:
        raise CoreInstallerError("replacement admission expiry is invalid")
    remaining_milliseconds = int(expires_at) - int(time.time() * 1000)
    required_seconds = (
        (2.0 * float(wait_seconds))
        + REPLACEMENT_CERTIFICATION_MIN_REMAINING_SECONDS
    )
    if remaining_milliseconds < int(required_seconds * 1000):
        raise CoreInstallerError(
            "replacement admission has too little signed time remaining for activation"
        )
    return remaining_milliseconds // 1000


def validate_replacement_capture_transport(
    status: Mapping[str, Any] | None,
    *,
    maximum_pending_files: int,
) -> int:
    """Admit bounded canonical queued debt, but no ambiguous transport state."""

    if type(maximum_pending_files) is not int or maximum_pending_files < 0:
        raise CoreInstallerError("replacement capture pending bound is invalid")
    pending = (
        None
        if not isinstance(status, Mapping)
        else status.get("pending_file_count")
    )
    processing = (
        None
        if not isinstance(status, Mapping)
        else status.get("processing_file_count")
    )
    if (
        not isinstance(status, Mapping)
        or status.get("transport_ready") is not True
        or type(pending) is not int
        or type(processing) is not int
        or int(pending) < 0
        or int(processing) < 0
        or int(pending) + int(processing) > maximum_pending_files
        or any(
            type(status.get(field)) is not int or int(status[field]) != 0
            for field in CAPTURE_TRANSPORT_ZERO_DEBT_FIELDS
        )
    ):
        raise CoreInstallerError(
            "replacement staging requires bounded, unambiguous capture transport"
        )
    return int(pending) + int(processing)


def capture_transport_status(
    capture_root: Path,
    *,
    blocking: bool = True,
) -> dict[str, Any] | None:
    """Take one capture-transport snapshot behind the producer/daemon gate."""

    from capture_daemon import CaptureInboxDaemon, GLOBAL_CAPTURE_LOCK

    daemon = CaptureInboxDaemon(root=capture_root)
    paths = daemon.paths()
    with daemon._exclusive_lock(
        paths["lock_dir"] / GLOBAL_CAPTURE_LOCK,
        blocking=blocking,
    ) as acquired:
        if not acquired:
            if not blocking:
                return None
            raise CoreInstallerError(
                "capture maintenance lock is unavailable during replacement drain"
            )
        return dict(daemon.status())


def wait_for_replacement_capture_drain(
    *,
    capture_root: Path,
    admitted_status: Mapping[str, Any],
    admitted_pending_file_count: int,
    admitted_receipt_backed_file_count: int = 0,
    wait_seconds: float,
) -> dict[str, Any]:
    """Wait for only the admitted inbox set to become durable and archived."""

    if (
        type(admitted_pending_file_count) is not int
        or admitted_pending_file_count < 0
        or type(admitted_receipt_backed_file_count) is not int
        or admitted_receipt_backed_file_count < 0
        or admitted_receipt_backed_file_count > admitted_pending_file_count
        or not isinstance(admitted_status, Mapping)
        or type(admitted_status.get("processed_file_count")) is not int
        or type(admitted_status.get("receipt_count")) is not int
        or not isinstance(wait_seconds, (int, float))
        or isinstance(wait_seconds, bool)
        or not math.isfinite(float(wait_seconds))
        or float(wait_seconds) <= 0
    ):
        raise CoreInstallerError("replacement capture drain request is invalid")
    expected_processed = (
        int(admitted_status["processed_file_count"])
        + admitted_pending_file_count
    )
    expected_receipts = (
        int(admitted_status["receipt_count"])
        + admitted_pending_file_count
        - admitted_receipt_backed_file_count
    )
    deadline = time.monotonic() + float(wait_seconds)
    fatal_fields = tuple(
        field
        for field in CAPTURE_TRANSPORT_ZERO_DEBT_FIELDS
        if field != "processing_file_count"
    )
    while True:
        status = capture_transport_status(capture_root, blocking=False)
        if status is None:
            if time.monotonic() >= deadline:
                raise CoreInstallerError(
                    "replacement capture drain did not complete before its deadline"
                )
            time.sleep(0.1)
            continue
        pending = status.get("pending_file_count")
        processing = status.get("processing_file_count")
        if (
            status.get("transport_ready") is not True
            or status.get("missing_transport_directories")
            or status.get("unsafe_transport_directories")
            or type(pending) is not int
            or type(processing) is not int
            or pending < 0
            or processing < 0
            or pending + processing > admitted_pending_file_count
            or any(
                type(status.get(field)) is not int
                or int(status[field]) != 0
                for field in fatal_fields
            )
        ):
            raise CoreInstallerError(
                "replacement capture drain entered an ambiguous or failed state"
            )
        if pending == 0 and processing == 0:
            validate_replacement_capture_transport(
                status,
                maximum_pending_files=0,
            )
            if (
                status.get("processed_file_count") != expected_processed
                or status.get("receipt_count") != expected_receipts
            ):
                raise CoreInstallerError(
                    "replacement capture drain did not produce exact durable "
                    "archive and receipt counts"
                )
            return dict(status)
        if time.monotonic() >= deadline:
            raise CoreInstallerError(
                "replacement capture drain did not complete before its deadline"
            )
        time.sleep(0.1)


def verified_exact_label_cleanup(
    *,
    launchctl: "LaunchCtl",
    wait_seconds: float,
) -> list[str]:
    """Best-effort cleanup with explicit readback of both launchd states."""

    cleanup_errors: list[str] = []
    try:
        launchctl.bootout(wait_seconds=wait_seconds)
    except Exception:
        cleanup_errors.append("bootout")
    try:
        launchctl.disable()
    except Exception:
        cleanup_errors.append("disable")
    try:
        cleanup_snapshot = launchctl.snapshot()
        if cleanup_snapshot.get("loaded") or cleanup_snapshot.get("running"):
            cleanup_errors.append("launch-state")
    except Exception:
        cleanup_errors.append("launch-state")
    try:
        if not launchctl.disabled():
            cleanup_errors.append("disabled-policy")
    except Exception:
        cleanup_errors.append("disabled-policy")
    return cleanup_errors


@contextmanager
def install_lock(paths: InstallPaths, *, label: str) -> Iterator[None]:
    ensure_private_directory(paths.plist.parent, require_private=False)
    lock_path = paths.plist.parent / f".{label}.install.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise CoreInstallerError("authoritative-core install lock is unsafe") from exc
    try:
        opened = os.fstat(descriptor)
        visible = lock_path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino)
        ):
            raise CoreInstallerError("authoritative-core install lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CoreInstallerError("another authoritative-core operation is in progress") from exc
        yield
    finally:
        os.close(descriptor)


def _validate_install_sources(paths: InstallPaths) -> None:
    _assert_layout(paths)
    if not paths.python.is_file() or not os.access(paths.python, os.X_OK):
        raise CoreInstallerError("authoritative-core Python runtime is missing")
    _assert_owner_controlled(paths.service_program, kind="core service program")
    _assert_owner_controlled(
        paths.memory_db,
        kind="live memory database",
        require_mode=0o600,
    )
    for path, kind, expected_type in (
        (paths.state, "runtime state", "regular"),
        (paths.socket, "service socket", "socket"),
        (
            paths.socket.with_name(paths.socket.name + ".token"),
            "authentication token",
            "regular",
        ),
    ):
        observed = _lstat(path)
        if observed is None:
            continue
        valid_type = (
            stat.S_ISSOCK(observed.st_mode)
            if expected_type == "socket"
            else stat.S_ISREG(observed.st_mode)
        )
        if (
            stat.S_ISLNK(observed.st_mode)
            or not valid_type
            or observed.st_uid != os.getuid()
            or observed.st_nlink != 1
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            raise CoreInstallerError(f"existing {kind} is unsafe")


def _safe_result(action: str, **values: Any) -> dict[str, Any]:
    return {"schema": "synapse-s2.core-agent-install.v1", "action": action, **values}


def _binding_result(path: Path, binding: Any) -> dict[str, Any]:
    return {
        "path": str(path),
        "digest": binding.digest,
        "config_path": str(binding.config_path),
        "config_digest": binding.config_digest,
        "authority_mode": binding.authority_mode,
        "config_fingerprint": binding.config_fingerprint,
        "embedding_space_identity": binding.embedding_space_identity,
    }


def _verify_recovery_static_install(
    *,
    paths: InstallPaths,
    label: str,
) -> tuple[CoreConfig, Any]:
    """Prove the exact installed config, plist, and existing client binding."""

    _validate_install_sources(paths)
    _assert_owner_controlled(
        paths.config,
        kind="core service config",
        require_mode=0o600,
    )
    try:
        config = load_core_config(paths.config)
    except Exception as exc:
        raise CoreInstallerError("existing core service config is invalid") from exc
    if (
        config.socket_path != paths.socket
        or config.state_path != paths.state
        or config.memory_path != paths.memory_db
        or config.capture_root != paths.capture_root
    ):
        raise CoreInstallerError(
            "existing core service config does not match the reviewed layout"
        )
    token = _read_stable_private_regular(
        paths.socket.with_name(paths.socket.name + ".token"),
        kind="authentication token",
        maximum_bytes=256,
    )
    if re.fullmatch(rb"[0-9a-f]{64}", token) is None:
        raise CoreInstallerError("existing authentication token is invalid")
    expected_plist = plist_payload(label=label, paths=paths, config=config)
    observed_plist = _read_stable_private_regular(
        paths.plist,
        kind="LaunchAgent plist",
        maximum_bytes=256 * 1024,
    )
    if not secrets.compare_digest(observed_plist, expected_plist):
        raise CoreInstallerError(
            "existing LaunchAgent plist does not match this config and build"
        )

    binding_path = default_binding_path(paths.home)
    try:
        observed_binding = load_core_client_binding(binding_path)
        bound_config = load_bound_core_config(observed_binding)
        candidate_binding = binding_for_config(
            repo_root=paths.root,
            data_root=paths.data_root,
            config=config,
            core_label=label,
            authority_mode="candidate-local-v5",
        )
        authoritative_binding = binding_for_config(
            repo_root=paths.root,
            data_root=paths.data_root,
            config=config,
            core_label=label,
            authority_mode="authoritative-core-v6",
        )
    except Exception as exc:
        raise CoreInstallerError(
            "existing core client binding is invalid"
        ) from exc
    if (
        observed_binding not in {candidate_binding, authoritative_binding}
        or bound_config != config
    ):
        raise CoreInstallerError(
            "existing core client binding does not identify this installation"
        )
    return config, observed_binding


def _load_recovery_root_generation(
    paths: InstallPaths,
    *,
    expected_store_identity: str,
) -> str:
    path = paths.core_root / "store-generation.json"
    raw = _read_stable_private_regular(
        path,
        kind="root-generation sentinel",
        maximum_bytes=64 * 1024,
    )
    try:
        payload = decode_canonical_json(raw)
    except Exception as exc:
        raise CoreInstallerError("root-generation sentinel is invalid") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema", "root_generation_id", "store_identity"}
        or payload.get("schema") != STORE_GENERATION_SCHEMA
        or STORE_GENERATION_ID_RE.fullmatch(
            str(payload.get("root_generation_id") or "")
        )
        is None
        or not secrets.compare_digest(
            str(payload.get("store_identity") or ""),
            expected_store_identity,
        )
    ):
        raise CoreInstallerError("root-generation sentinel is invalid")
    return str(payload["root_generation_id"])


def _stable_recovery_sidecar_snapshot(
    path: Path,
    *,
    kind: str,
    minimum_size: int,
    maximum_size: int,
    size_multiple: int,
) -> tuple[Any, ...]:
    _assert_no_symlink_components(path)
    before = _assert_owner_controlled(
        path,
        kind=kind,
        require_mode=0o600,
    )
    observed_size = int(before.st_size)
    if (
        observed_size < minimum_size
        or observed_size > maximum_size
        or size_multiple <= 0
        or observed_size % size_multiple != 0
    ):
        raise CoreInstallerError(f"{kind} has an unsafe size")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CoreInstallerError(f"{kind} could not be opened safely") from exc
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
    visible = path.lstat()

    def identity(item: os.stat_result) -> tuple[int, ...]:
        return (
            int(item.st_dev),
            int(item.st_ino),
            int(item.st_size),
            int(item.st_mtime_ns),
            int(item.st_ctime_ns),
            int(item.st_uid),
            int(item.st_nlink),
            stat.S_IMODE(item.st_mode),
        )

    identities = {identity(item) for item in (before, opened, finished, visible)}
    if len(identities) != 1:
        raise CoreInstallerError(f"{kind} changed while being sealed")
    return (*identity(before), digest.hexdigest())


def _validate_sqlite_transients(
    sqlite_path: Path,
    *,
    kind: str,
) -> tuple[tuple[Any, ...], tuple[Any, ...]] | None:
    """Seal the only safe clean-close residue without opening SQLite."""

    rollback = Path(f"{sqlite_path}-journal")
    if rollback.exists() or rollback.is_symlink():
        raise CoreInstallerError(f"{kind} has unresolved SQLite sidecar state")
    wal = Path(f"{sqlite_path}-wal")
    shm = Path(f"{sqlite_path}-shm")
    wal_present = wal.exists() or wal.is_symlink()
    shm_present = shm.exists() or shm.is_symlink()
    if wal_present != shm_present:
        raise CoreInstallerError(f"{kind} has incomplete SQLite sidecar state")
    if not wal_present:
        return None
    return (
        _stable_recovery_sidecar_snapshot(
            wal,
            kind=f"{kind} WAL",
            minimum_size=0,
            maximum_size=0,
            size_multiple=1,
        ),
        _stable_recovery_sidecar_snapshot(
            shm,
            kind=f"{kind} SHM",
            minimum_size=32_768,
            maximum_size=8 * 1024 * 1024,
            size_multiple=32_768,
        ),
    )


def _validate_request_journal_transients(
    journal_path: Path,
) -> tuple[tuple[Any, ...], tuple[Any, ...]] | None:
    return _validate_sqlite_transients(journal_path, kind="request journal")


def _validate_recovery_runtime_state(
    *,
    paths: InstallPaths,
    store: Any,
    expected_binding: dict[str, Any] | None,
    allow_absent: bool,
) -> str | None:
    """Apply the core's pure canonical runtime validator without repairing."""

    from mlx_backend import SpikingAttentionBackend

    try:
        paths.state.lstat()
    except FileNotFoundError:
        if allow_absent:
            return None
        raise CoreInstallerError("governed runtime state is unavailable") from None

    raw = _read_stable_private_regular(
        paths.state,
        kind="governed runtime state",
        maximum_bytes=8 * 1024 * 1024,
    )
    try:
        payload = json.loads(raw.decode("utf-8"))
        canonical = (
            json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoreInstallerError("governed runtime state is invalid") from exc
    validator = SpikingAttentionBackend.__new__(SpikingAttentionBackend)
    validator.memory_store = store
    try:
        validator._apply_canonical_runtime_state(payload)
    except Exception as exc:
        raise CoreInstallerError("governed runtime state is invalid") from exc
    if not secrets.compare_digest(raw, canonical) or (
        expected_binding is not None
        and payload.get("authority_binding") != expected_binding
    ):
        raise CoreInstallerError(
            "governed runtime state does not match the durable marker"
        )
    return hashlib.sha256(raw).hexdigest()


def _verify_recovery_admission(
    *,
    paths: InstallPaths,
    config: CoreConfig,
) -> dict[str, Any]:
    """Read-only proof for one exact same-installation v6 restart."""

    from memory_store import DurableMemoryStore
    from recovery_manager import VerifiedRecoveryManager

    authority_lock = paths.core_root / "authority.lock"
    _assert_owner_controlled(
        authority_lock,
        kind="authoritative core lock",
        require_mode=0o600,
    )
    journal_path = paths.core_root / "requests.sqlite3"
    journal_lock = paths.core_root / "requests.sqlite3.lock"
    _assert_owner_controlled(
        journal_path,
        kind="request journal",
        require_mode=0o600,
    )
    _assert_owner_controlled(
        journal_lock,
        kind="request-journal lock",
        require_mode=0o600,
    )
    restored_binding = paths.core_root / "requests.sqlite3.binding.receipt.json"
    if restored_binding.exists() or restored_binding.is_symlink():
        raise CoreInstallerError(
            "recover-existing does not adopt a restored authoritative target"
        )
    memory_sidecars = _validate_sqlite_transients(
        paths.memory_db,
        kind="live memory database",
    )
    journal_sidecars = _validate_request_journal_transients(journal_path)

    try:
        lease = CoreAuthorityLease.acquire_core(
            paths.memory_db,
            timeout_seconds=0.0,
            instance_id="core-installer-recover-existing",
        )
    except Exception as exc:
        raise CoreInstallerError(
            "recover-existing requires exclusive authoritative-core quiescence"
        ) from exc
    store: Any = None
    try:
        # Attach the held exact core lease to the audit view without running
        # ordinary initialization, migrations, chmod, or repair code.  The
        # immutable verifier below rejects data-bearing or unsafe SQLite
        # sidecars and never opens the live path through SQLite's ordinary
        # read-only lane.
        store = DurableMemoryStore.open_existing_for_audit(paths.memory_db)
        store._authority_lease = lease
        if _validate_sqlite_transients(
            paths.memory_db,
            kind="live memory database",
        ) != memory_sidecars:
            raise CoreInstallerError(
                "live memory database sidecars changed during admission"
            )
        inspection = store.inspect_core_authority_preclaim_immutable()
        if _validate_sqlite_transients(
            paths.memory_db,
            kind="live memory database",
        ) != memory_sidecars:
            raise CoreInstallerError(
                "live memory database sidecars changed during inspection"
            )
        marker = inspection.get("marker")
        path_store_identity = _store_identity(paths.memory_db)
        current_build_id = _manifest_build_id(paths.root)
        if (
            inspection.get("governance_mode") != "authoritative-v6"
            or inspection.get("schema_identity") != EXPECTED_SCHEMA_IDENTITY
            or not isinstance(marker, dict)
            or marker.get("service_required") is not True
            or marker.get("config_fingerprint") != config.fingerprint
            or marker.get("build_id") != current_build_id
            or marker.get("protocol_version") != PROTOCOL_VERSION
            or marker.get("embedding_space_identity")
            != config.embedding_space_identity
            or marker.get("store_identity") != path_store_identity
            or inspection.get("store_identity") != path_store_identity
            or marker.get("lock_generation_id") != lease.lock_generation_id
            or marker.get("restored_target_binding_receipt_digest") is not None
        ):
            raise CoreInstallerError(
                "durable v6 marker does not identify this exact installation"
            )
        root_generation = _load_recovery_root_generation(
            paths,
            expected_store_identity=path_store_identity,
        )
        if marker.get("root_generation_id") != root_generation:
            raise CoreInstallerError(
                "durable v6 marker does not match the core root generation"
            )

        with _exclusive_existing_private_lock(
            journal_lock,
            kind="request-journal lock",
        ):
            if _validate_request_journal_transients(journal_path) != journal_sidecars:
                raise CoreInstallerError(
                    "request journal sidecars changed during admission"
                )
            manager = VerifiedRecoveryManager(
                store,
                capture_root=paths.capture_root,
                runtime_state_path=paths.state,
            )
            journal = manager.inspect_request_journal_snapshot(
                journal_path,
                maximum_authority_epoch=int(marker["epoch"]),
            )
            if _validate_request_journal_transients(journal_path) != journal_sidecars:
                raise CoreInstallerError(
                    "request journal sidecars changed during inspection"
                )
        if (
            journal.get("verified") is not True
            or journal.get("journal_id") != marker.get("request_journal_id")
            or journal.get("store_identity") != path_store_identity
            or journal.get("schema_version")
            != marker.get("request_journal_schema_version")
        ):
            raise CoreInstallerError(
                "request journal does not match the durable v6 marker"
            )

        publication = inspection.get("runtime_publication")
        if not isinstance(publication, dict):
            raise CoreInstallerError(
                "durable runtime publication receipt is unavailable"
            )
        runtime_status = publication.get("status")
        if publication.get("runtime_state_path_sha256") != (
            DurableMemoryStore.runtime_state_path_sha256(paths.state)
        ):
            raise CoreInstallerError(
                "durable runtime publication receipt targets another path"
            )
        runtime_sha256: str | None
        if runtime_status == "complete":
            runtime_sha256 = _validate_recovery_runtime_state(
                paths=paths,
                store=store,
                expected_binding=(
                    DurableMemoryStore.runtime_state_authority_binding_for_marker(
                        marker
                    )
                ),
                allow_absent=False,
            )
        elif runtime_status == "pending":
            DurableMemoryStore.validate_interrupted_runtime_publication_binding(
                marker=marker,
                publication=publication,
                runtime_state_path=paths.state,
                expected_lock_generation_id=lease.lock_generation_id,
                expected_config_fingerprint=config.fingerprint,
                expected_build_id=current_build_id,
                expected_protocol_version=PROTOCOL_VERSION,
                expected_root_generation_id=root_generation,
                expected_embedding_space_identity=config.embedding_space_identity,
            )
            runtime_sha256 = _validate_recovery_runtime_state(
                paths=paths,
                store=store,
                expected_binding=None,
                allow_absent=True,
            )
        else:
            raise CoreInstallerError(
                "durable runtime publication receipt is invalid"
            )
        marker_sha256 = DurableMemoryStore._core_authority_marker_sha256(marker)
        if _validate_sqlite_transients(
            paths.memory_db,
            kind="live memory database",
        ) != memory_sidecars:
            raise CoreInstallerError(
                "live memory database sidecars changed during admission"
            )
        if _validate_request_journal_transients(journal_path) != journal_sidecars:
            raise CoreInstallerError(
                "request journal sidecars changed during admission"
            )
        lease.assert_active_for(paths.memory_db)
        return {
            "verified": True,
            "authority_epoch_number": int(marker["epoch"]),
            "marker_sha256": marker_sha256,
            "memory_logical_snapshot_sha256": str(
                inspection["logical_snapshot"]["sha256"]
            ),
            "request_journal_logical_snapshot_sha256": str(
                journal["logical_snapshot_sha256"]
            ),
            "runtime_publication_status": runtime_status,
            "runtime_state_sha256": runtime_sha256,
        }
    except CoreInstallerError:
        raise
    except Exception as exc:
        raise CoreInstallerError(
            "recover-existing admission proof failed"
        ) from exc
    finally:
        if store is not None:
            store.close()
        lease.close()


def _publish_recovered_client_binding(
    *,
    paths: InstallPaths,
    label: str,
    config: CoreConfig,
    observed_binding: Any,
) -> dict[str, Any]:
    """Publish only the active binding; never rewrite the proven config."""

    expected = binding_for_config(
        repo_root=paths.root,
        data_root=paths.data_root,
        config=config,
        core_label=label,
        authority_mode="authoritative-core-v6",
    )
    path = default_binding_path(paths.home)
    if observed_binding != expected:
        try:
            write_core_client_binding(path, expected)
        except Exception as exc:
            raise CoreInstallerError(
                "authoritative core binding publication failed"
            ) from exc
    try:
        verified = load_core_client_binding(path)
        bound_config = load_bound_core_config(verified)
    except Exception as exc:
        raise CoreInstallerError(
            "authoritative core binding verification failed"
        ) from exc
    if verified != expected or bound_config != config:
        raise CoreInstallerError(
            "authoritative core binding publication was not stable"
        )
    return _binding_result(path, verified)


def recover_existing(
    *,
    paths: InstallPaths,
    label: str,
    launchctl: LaunchCtl,
    wait_seconds: float,
) -> dict[str, Any]:
    """Restart only the exact already-claimed v6 installation."""

    config, observed_binding = _verify_recovery_static_install(
        paths=paths,
        label=label,
    )
    snapshot = launchctl.snapshot()
    if snapshot.get("loaded"):
        if not snapshot.get("running"):
            raise CoreInstallerError(
                "recover-existing requires the exact core label to be unloaded"
            )
        health = wait_for_health(
            launchctl=launchctl,
            config=config,
            prior_pid=-1,
            wait_seconds=wait_seconds,
        )
        stable_config, stable_binding = _verify_recovery_static_install(
            paths=paths,
            label=label,
        )
        if stable_config != config:
            raise CoreInstallerError(
                "core service config changed during recovery verification"
            )
        binding = _publish_recovered_client_binding(
            paths=paths,
            label=label,
            config=config,
            observed_binding=stable_binding,
        )
        return _safe_result(
            "recover-existing",
            status="already-healthy",
            client_binding=binding,
            **health,
        )

    admission = _verify_recovery_admission(paths=paths, config=config)
    stable_config, stable_binding = _verify_recovery_static_install(
        paths=paths,
        label=label,
    )
    if stable_config != config or stable_binding != observed_binding:
        raise CoreInstallerError(
            "installation identity changed during recovery admission"
        )
    second_snapshot = launchctl.snapshot()
    if second_snapshot.get("loaded") or second_snapshot.get("running"):
        raise CoreInstallerError(
            "core launch state changed during recovery admission"
        )

    launch_mutation_attempted = False
    try:
        launch_mutation_attempted = True
        launchctl.enable()
        launchctl.bootstrap(paths.plist)
        launchctl.kickstart()
        health = wait_for_health(
            launchctl=launchctl,
            config=config,
            prior_pid=None,
            wait_seconds=wait_seconds,
        )
        stable_config, stable_binding = _verify_recovery_static_install(
            paths=paths,
            label=label,
        )
        if stable_config != config:
            raise CoreInstallerError(
                "installation identity changed during recovery activation"
            )
        binding = _publish_recovered_client_binding(
            paths=paths,
            label=label,
            config=config,
            observed_binding=stable_binding,
        )
    except BaseException as exc:
        cleanup_errors: list[str] = []
        if launch_mutation_attempted:
            cleanup_errors = verified_exact_label_cleanup(
                launchctl=launchctl,
                wait_seconds=wait_seconds,
            )
        if cleanup_errors:
            raise CoreInstallerError(
                "recover-existing activation failed; exact-label cleanup "
                "could not be verified; all installation evidence was preserved"
            ) from exc
        if isinstance(exc, CoreInstallerError):
            raise CoreInstallerError(
                "recover-existing activation failed; exact-label cleanup was "
                "verified unloaded and disabled; all installation evidence was preserved"
            ) from exc
        raise
    return _safe_result(
        "recover-existing",
        status="healthy",
        recovery_admission=admission,
        client_binding=binding,
        **health,
    )


def _existing_install_is_current(
    *,
    launchctl: LaunchCtl,
    config: CoreConfig,
    config_path: Path,
    plist: Path,
    expected_plist: bytes,
    restored_target: bool = False,
) -> dict[str, Any] | None:
    snapshot = launchctl.snapshot()
    if not snapshot.get("running"):
        return None
    try:
        _assert_owner_controlled(plist, kind="LaunchAgent plist", require_mode=0o600)
        observed_plist = plist.read_bytes()
        loaded_config = load_core_config(config_path)
        if observed_plist != expected_plist or loaded_config.fingerprint != config.fingerprint:
            return None
        health = probe_health(config, restored_target=restored_target)
    except Exception:
        return None
    return {**health, "pid": snapshot.get("pid")}


def repair_preclaim_residue(
    *,
    paths: InstallPaths,
    launchctl: LaunchCtl,
    confirm: bool,
    _allow_authoritative_v6_noop: bool = False,
) -> dict[str, Any]:
    """Guardedly archive one exact empty v5 preclaim journal.

    This explicit lane exists so a failed first-adoption journal can be
    reconciled before a fresh paired bundle and operator certification are
    created. It never starts a service, replays a request, or changes the
    memory database.
    """

    if confirm is not True:
        raise CoreInstallerError("preclaim residue repair requires --confirm")
    snapshot = launchctl.snapshot()
    if (
        snapshot.get("loaded")
        or snapshot.get("running")
        or not launchctl.disabled()
    ):
        raise CoreInstallerError(
            "preclaim residue repair requires the exact core LaunchAgent "
            "to be disabled and unloaded"
        )
    _assert_owner_controlled(
        paths.core_root,
        kind="core directory",
        require_mode=0o700,
    )
    _assert_owner_controlled(
        paths.memory_db,
        kind="live memory database",
        require_mode=0o600,
    )
    lease = CoreAuthorityLease.acquire_core(
        paths.memory_db,
        timeout_seconds=0.0,
        instance_id="core-installer-preclaim-repair",
    )
    store = None
    try:
        from memory_store import DurableMemoryStore

        store = DurableMemoryStore(
            paths.memory_db,
            authority_lease=lease,
        )
        inspection = store.inspect_core_authority_preclaim()
        governance_mode = inspection.get("governance_mode")
        if (
            governance_mode == "authoritative-v6"
            and _allow_authoritative_v6_noop
        ):
            return _safe_result(
                "repair-preclaim-residue",
                status="not-applicable-authoritative-v6",
                repaired=False,
                request_row_count=0,
                logical_snapshot_sha256=(
                    dict(inspection.get("logical_snapshot") or {}).get(
                        "sha256"
                    )
                ),
            )
        if governance_mode != "pre-governed-v5":
            raise CoreInstallerError(
                "preclaim residue repair requires an exact unclaimed v5 store"
            )
        logical_before = dict(inspection.get("logical_snapshot") or {})
        result = repair_empty_preclaim_journal_residue(
            paths.core_root / "requests.sqlite3",
            expected_store_identity=str(inspection["store_identity"]),
            memory_db_path=paths.memory_db,
            authority_lease=lease,
        )
        reinspected = store.inspect_core_authority_preclaim()
        if dict(reinspected) != dict(inspection):
            raise CoreAuthorityError(
                "memory store changed during preclaim journal repair"
            )
        if result is None:
            return _safe_result(
                "repair-preclaim-residue",
                status="no-residue",
                repaired=False,
                request_row_count=0,
                logical_snapshot_sha256=logical_before.get("sha256"),
            )
        return _safe_result(
            "repair-preclaim-residue",
            status="complete",
            repaired=True,
            repair_id=result.get("repair_id"),
            receipt_name=(
                "requests.sqlite3.preclaim-repair-"
                f"{result.get('repair_id')}.json"
            ),
            request_row_count=int(result.get("request_row_count") or 0),
            logical_snapshot_sha256=logical_before.get("sha256"),
        )
    finally:
        if store is not None:
            store.close()
        lease.close()


def _preflight(
    *,
    paths: InstallPaths,
    evidence_manifest: Path,
    maximum_evidence_age_seconds: float,
    launchctl_bin: str,
    ps_bin: str,
    label: str,
    config: CoreConfig,
    restored_target: bool = False,
) -> dict[str, Any]:
    try:
        # A failed first cutover can leave the newly-created, still-empty
        # request journal behind while SQLite remains v5.  Repair only that
        # exact residue under the same authority lock used by the read-only
        # proof.  v6 lineage is never routed through this path.
        if paths.core_root.exists() or paths.core_root.is_symlink():
            repair_preclaim_residue(
                paths=paths,
                launchctl=LaunchCtl(
                    launchctl_bin,
                    uid=os.getuid(),
                    label=label,
                ),
                confirm=True,
                _allow_authoritative_v6_noop=True,
            )
        return run_preflight(
            root=paths.root,
            memory_db=paths.memory_db,
            capture_root=paths.capture_root,
            evidence_manifest=evidence_manifest,
            maximum_evidence_age_seconds=maximum_evidence_age_seconds,
            require_quiescent=True,
            inventory_only=False,
            launchctl_bin=launchctl_bin,
            ps_bin=ps_bin,
            labels={
                "capture": os.getenv("SYNAPSE_S2_CAPTURE_LABEL", DEFAULT_CAPTURE_LABEL),
                "dashboard": os.getenv("SYNAPSE_S2_DASHBOARD_LABEL", DEFAULT_DASHBOARD_LABEL),
                "core": label,
            },
            attestation_request=CutoverAttestationRequest(
                path=paths.core_root / CUTOVER_ATTESTATION_NAME,
                build_id=_manifest_build_id(paths.root),
                config_fingerprint=config.fingerprint,
                restored_target=restored_target,
            ),
        )
    except CoreInstallerError:
        raise
    except (
        CutoverPreflightError,
        CoreAuthorityError,
        CoreRequestJournalError,
    ) as exc:
        raise CoreInstallerError(str(exc)) from exc
    except Exception as exc:
        raise CoreInstallerError("authoritative core preflight failed") from exc


def install(
    *,
    paths: InstallPaths,
    label: str,
    launchctl: LaunchCtl,
    launchctl_bin: str,
    ps_bin: str,
    evidence_manifest: Path | None,
    maximum_evidence_age_seconds: float,
    wait_seconds: float,
    force_restart: bool,
    restored_target: bool = False,
) -> dict[str, Any]:
    _validate_install_sources(paths)
    config = build_config(paths)
    expected_plist = plist_payload(label=label, paths=paths, config=config)
    if not force_restart:
        current = _existing_install_is_current(
            launchctl=launchctl,
            config=config,
            config_path=paths.config,
            plist=paths.plist,
            expected_plist=expected_plist,
            restored_target=restored_target,
        )
        if current is not None:
            binding = publish_client_binding(
                paths=paths,
                label=label,
                config=config,
                authority_mode="authoritative-core-v6",
            )
            return _safe_result(
                "install",
                status="already-healthy",
                client_binding=binding,
                **current,
            )
    if evidence_manifest is None:
        raise CoreInstallerError("install requires --evidence-manifest")

    prior = launchctl.snapshot()
    prior_pid = prior.get("pid") if isinstance(prior.get("pid"), int) else None
    if prior.get("loaded"):
        launchctl.bootout(wait_seconds=wait_seconds)
    # A failed proof or replacement must stay stopped across login as well as
    # for the remainder of this invocation.
    launchctl.disable()
    # A replacement is never started until the old authority is fully gone and
    # the signed backup is proven equal to the now-quiescent live database.
    preflight_result = _preflight(
        paths=paths,
        evidence_manifest=evidence_manifest,
        maximum_evidence_age_seconds=maximum_evidence_age_seconds,
        launchctl_bin=launchctl_bin,
        ps_bin=ps_bin,
        label=label,
        config=config,
        restored_target=restored_target,
    )

    for directory in {
        paths.data_root,
        paths.core_root,
        paths.capture_root,
        paths.config.parent,
        paths.socket.parent,
        paths.state.parent,
        paths.log.parent,
    }:
        ensure_private_directory(directory)
    prepare_private_regular(paths.log)
    write_core_config(paths.config, config)
    _assert_owner_controlled(paths.config, kind="core service config", require_mode=0o600)
    _atomic_private_bytes(paths.plist, expected_plist)
    _assert_owner_controlled(paths.plist, kind="LaunchAgent plist", require_mode=0o600)

    activated = False
    try:
        launchctl.enable()
        launchctl.bootstrap(paths.plist)
        launchctl.kickstart()
        activated = True
        health = wait_for_health(
            launchctl=launchctl,
            config=config,
            prior_pid=prior_pid,
            wait_seconds=wait_seconds,
            restored_target=restored_target,
        )
        binding = publish_client_binding(
            paths=paths,
            label=label,
            config=config,
            authority_mode="authoritative-core-v6",
        )
    except BaseException as exc:
        cleanup_errors = verified_exact_label_cleanup(
            launchctl=launchctl,
            wait_seconds=wait_seconds,
        )
        if cleanup_errors:
            raise CoreInstallerError(
                "authoritative-core activation failed; exact-label cleanup "
                "could not be verified; state and recovery evidence were "
                "preserved and the system must be treated as fail-closed"
            ) from exc
        if isinstance(exc, CoreInstallerError):
            raise CoreInstallerError(
                "authoritative-core activation failed; it is verified unloaded and "
                "disabled; state, config, plist, token, logs, database, and captures "
                "were preserved; if schema v6 was claimed the system remains fail-closed"
            ) from exc
        raise
    if not activated:
        raise CoreInstallerError("authoritative-core activation did not begin")
    return _safe_result(
        "install",
        status="healthy",
        cutover_attestation=preflight_result.get("cutover_attestation"),
        client_binding=binding,
        **health,
    )


def stop(*, launchctl: LaunchCtl, wait_seconds: float) -> dict[str, Any]:
    launchctl.disable()
    launchctl.bootout(wait_seconds=wait_seconds)
    return _safe_result("stop", status="stopped", loaded=False)


def context_delivery_integrity(
    *,
    paths: InstallPaths,
    launchctl: LaunchCtl,
    wait_seconds: float,
    repair: bool,
    confirm: bool,
    expected_revision: str | None,
) -> dict[str, Any]:
    """Audit or narrowly repair derived delivery-publication state offline.

    This is intentionally an installer-only maintenance lane.  It requires the
    exact LaunchAgent to have already been disabled and unloaded, then takes an
    exclusive unclaimed core lease before opening the existing v6 store.  It
    never starts, stops, enables, installs, or rewrites core configuration.
    """

    snapshot = launchctl.snapshot()
    disabled = launchctl.disabled()
    if snapshot.get("loaded") or snapshot.get("running") or not disabled:
        raise CoreInstallerError(
            "context delivery integrity requires the exact core LaunchAgent "
            "to be disabled and unloaded"
        )
    if repair:
        if confirm is not True:
            raise CoreInstallerError(
                "context delivery integrity repair requires --confirm"
            )
        if re.fullmatch(r"[0-9a-f]{64}", str(expected_revision or "")) is None:
            raise CoreInstallerError(
                "context delivery integrity repair requires one exact reviewed revision"
            )
    elif confirm or expected_revision:
        raise CoreInstallerError(
            "repair confirmation and revision are valid only with --repair"
        )

    _validate_install_sources(paths)
    from memory_store import DurableMemoryStore

    lease: CoreAuthorityLease | None = None
    store: DurableMemoryStore | None = None
    try:
        lease = CoreAuthorityLease.acquire_core(
            paths.memory_db,
            timeout_seconds=min(float(wait_seconds), 30.0),
            instance_id="core-installer-context-delivery-integrity",
        )
        store = DurableMemoryStore.open_existing_for_core_maintenance(
            paths.memory_db,
            authority_lease=lease,
        )
        inspection = store.inspect_core_authority_preclaim()
        marker = inspection.get("marker")
        if (
            inspection.get("governance_mode") != "authoritative-v6"
            or inspection.get("schema_identity") != EXPECTED_SCHEMA_IDENTITY
            or not isinstance(marker, dict)
            or marker.get("service_required") is not True
        ):
            raise CoreInstallerError(
                "context delivery integrity requires an authoritative v6 store"
            )
        audit = store.audit_context_delivery_publication_repair()
        result: dict[str, Any] | None = None
        if repair:
            result = store.repair_context_delivery_publication(
                expected_revision=str(expected_revision),
                confirm=True,
            )
            lease.assert_core_for(paths.memory_db)
        final_snapshot = launchctl.snapshot()
        final_disabled = launchctl.disabled()
        if (
            final_snapshot.get("loaded")
            or final_snapshot.get("running")
            or not final_disabled
        ):
            raise CoreInstallerError(
                "exact core LaunchAgent changed during context delivery integrity"
            )
        lease.assert_core_for(paths.memory_db)
        replacement_required = str(marker.get("build_id") or "") != (
            _manifest_build_id(paths.root)
        )
        return _safe_result(
            "context-delivery-integrity",
            status=(result["status"] if result is not None else audit["status"]),
            service_state={
                "loaded": False,
                "running": False,
                "disabled": final_disabled,
            },
            replacement_required=replacement_required,
            audit=audit,
            repair=result,
        )
    except CoreInstallerError:
        raise
    except Exception as exc:
        raise CoreInstallerError(
            "context delivery publication integrity operation failed"
        ) from exc
    finally:
        try:
            if store is not None:
                store.close()
        finally:
            if lease is not None:
                lease.close()


def replacement_capture_freeze_ttl_seconds(wait_seconds: float) -> float:
    """Keep producers out of the signed inbox across proof and activation."""

    if (
        not isinstance(wait_seconds, (int, float))
        or isinstance(wait_seconds, bool)
        or not math.isfinite(float(wait_seconds))
        or float(wait_seconds) <= 0.0
    ):
        raise CoreInstallerError("replacement activation wait is invalid")
    return min(
        7_200.0,
        max(
            3_600.0,
            (3.0 * float(wait_seconds)) + 1_800.0,
        ),
    )


def stage_replacement(
    *,
    paths: InstallPaths,
    label: str,
    launchctl: LaunchCtl,
    wait_seconds: float,
    maximum_evidence_age_seconds: float,
    confirm: bool,
    expected_revision: str | None,
) -> dict[str, Any]:
    """Freeze late producers around the exact signed replacement lane."""

    if confirm is not True:
        raise CoreInstallerError("replacement staging requires --confirm")
    reviewed_revision = str(expected_revision or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", reviewed_revision) is None:
        raise CoreInstallerError(
            "replacement staging requires one exact reviewed delivery revision"
        )
    initial_service = launchctl.snapshot()
    initial_disabled = launchctl.disabled()
    if (
        initial_service.get("loaded")
        or initial_service.get("running")
        or not initial_disabled
    ):
        raise CoreInstallerError(
            "replacement staging requires the exact core LaunchAgent to be "
            "disabled and unloaded"
        )

    from capture_daemon import (
        begin_capture_replacement_freeze,
        release_capture_replacement_freeze,
    )

    freeze = begin_capture_replacement_freeze(
        root=paths.capture_root,
        ttl_seconds=replacement_capture_freeze_ttl_seconds(wait_seconds),
    )
    freeze_released = False
    try:
        result = _stage_replacement_frozen(
            paths=paths,
            label=label,
            launchctl=launchctl,
            wait_seconds=wait_seconds,
            maximum_evidence_age_seconds=maximum_evidence_age_seconds,
            confirm=confirm,
            expected_revision=expected_revision,
        )
        thaw = release_capture_replacement_freeze(
            root=paths.capture_root,
            freeze_id=str(freeze["freeze_id"]),
            require_main_queue_empty=True,
        )
        freeze_released = True
        late_file_count = int(thaw["deferred_file_count"])
        updated = {
            **result,
            "recovered_preexisting_deferred_file_count": int(
                freeze.get("recovered_deferred_count") or 0
            ),
            "drained_late_arrival_file_count": late_file_count,
        }
        if late_file_count:
            baseline = thaw.get("baseline_status")
            if not isinstance(baseline, Mapping):
                raise CoreInstallerError(
                    "replacement late-arrival baseline is invalid"
                )
            config = load_core_config(paths.config)
            wait_for_replacement_capture_drain(
                capture_root=paths.capture_root,
                admitted_status=baseline,
                admitted_pending_file_count=late_file_count,
                admitted_receipt_backed_file_count=0,
                wait_seconds=wait_seconds,
            )
            health = wait_for_health(
                launchctl=launchctl,
                config=config,
                prior_pid=None,
                wait_seconds=min(
                    wait_seconds,
                    REPLACEMENT_ACTIVATION_HEADROOM_SECONDS,
                ),
                expected_deployment_mode="replacement-certification",
                require_capture_ready=True,
            )
            admission = result.get("admission")
            certification_seconds_remaining = (
                replacement_certification_seconds_remaining(
                    admission if isinstance(admission, Mapping) else None
                )
            )
            updated.update(health)
            updated["certification_seconds_remaining"] = (
                certification_seconds_remaining
            )
            updated["drained_pending_file_count"] = int(
                result.get("drained_pending_file_count") or 0
            ) + late_file_count
        return updated
    except BaseException as exc:
        if not freeze_released:
            try:
                release_capture_replacement_freeze(
                    root=paths.capture_root,
                    freeze_id=str(freeze["freeze_id"]),
                    require_main_queue_empty=False,
                )
                freeze_released = True
            except Exception as release_error:
                raise CoreInstallerError(
                    "replacement capture freeze could not be safely released"
                ) from release_error
        snapshot = launchctl.snapshot()
        if snapshot.get("loaded") or snapshot.get("running"):
            cleanup_errors = verified_exact_label_cleanup(
                launchctl=launchctl,
                wait_seconds=wait_seconds,
            )
            if cleanup_errors:
                raise CoreInstallerError(
                    "replacement late-arrival handling failed and exact-label "
                    "cleanup could not be verified"
                ) from exc
        raise


def _stage_replacement_frozen(
    *,
    paths: InstallPaths,
    label: str,
    launchctl: LaunchCtl,
    wait_seconds: float,
    maximum_evidence_age_seconds: float,
    confirm: bool,
    expected_revision: str | None,
) -> dict[str, Any]:
    """Admit one exact current build long enough to certify it live.

    This lane is intentionally narrower than installation.  It requires an
    already-disabled and unloaded incumbent, proves a fresh paired recovery
    point under exclusive authority, publishes one short-lived signed
    build-only successor admission, and launches a non-KeepAlive service.  It
    never publishes a production client binding or persistent LaunchAgent.
    """

    if confirm is not True:
        raise CoreInstallerError("replacement staging requires --confirm")
    reviewed_revision = str(expected_revision or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", reviewed_revision) is None:
        raise CoreInstallerError(
            "replacement staging requires one exact reviewed delivery revision"
        )
    initial_service = launchctl.snapshot()
    initial_disabled = launchctl.disabled()
    if (
        initial_service.get("loaded")
        or initial_service.get("running")
        or not initial_disabled
    ):
        raise CoreInstallerError(
            "replacement staging requires the exact core LaunchAgent to be "
            "disabled and unloaded"
        )

    _validate_install_sources(paths)
    config = build_config(paths)
    candidate_build_id = _manifest_build_id(paths.root)
    staged_plist = paths.core_root / f"{label}.replacement-stage.plist"
    expected_plist = plist_payload(
        label=label,
        paths=paths,
        config=config,
        keep_alive=False,
        replacement_admission=True,
    )
    for directory in {
        paths.data_root,
        paths.core_root,
        paths.capture_root,
        paths.config.parent,
        paths.socket.parent,
        paths.state.parent,
        paths.log.parent,
        paths.data_root / "recovery",
    }:
        ensure_private_directory(directory)

    from memory_store import DurableMemoryStore
    from recovery_manager import VerifiedRecoveryManager

    admission: dict[str, Any] | None = None
    guarded_evidence: dict[str, Any] | None = None
    with tempfile.TemporaryDirectory(
        prefix="replacement-admission-",
        dir=paths.data_root / "recovery",
    ) as temporary:
        lease: CoreAuthorityLease | None = None
        store: DurableMemoryStore | None = None
        try:
            lease = CoreAuthorityLease.acquire_core(
                paths.memory_db,
                timeout_seconds=min(float(wait_seconds), 30.0),
                instance_id="core-installer-replacement-admission",
            )
            store = DurableMemoryStore.open_existing_for_core_maintenance(
                paths.memory_db,
                authority_lease=lease,
            )
            inspection = store.inspect_core_authority_preclaim()
            marker = inspection.get("marker")
            if (
                inspection.get("governance_mode") != "authoritative-v6"
                or inspection.get("schema_identity") != EXPECTED_SCHEMA_IDENTITY
                or not isinstance(marker, dict)
                or marker.get("service_required") is not True
                or marker.get("lock_generation_id")
                != lease.lock_generation_id
                or marker.get("config_fingerprint") != config.fingerprint
                or (
                    marker.get("build_id") == candidate_build_id
                    and not str(marker.get("instance_id") or "").startswith(
                        REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX
                    )
                )
                or marker.get("root_generation_id")
                != _load_recovery_root_generation(
                    paths,
                    expected_store_identity=str(inspection["store_identity"]),
                )
            ):
                raise CoreInstallerError(
                    "replacement staging requires one exact build-only v6 successor"
                )
            audit = store.audit_context_delivery_publication_repair()
            if (
                audit.get("status") != "ready"
                or audit.get("repair_required") is not False
                or audit.get("audit_revision") != reviewed_revision
            ):
                raise CoreInstallerError(
                    "replacement staging delivery audit changed or is not ready"
                )
            manager = VerifiedRecoveryManager(
                store,
                capture_root=paths.capture_root,
                runtime_state_path=paths.state,
            )
            capture = manager.daemon.status()
            admitted_pending_file_count = validate_replacement_capture_transport(
                capture,
                maximum_pending_files=config.capture_max_files,
            )
            restore_root = Path(temporary) / "isolated-restore"
            with manager.guarded_recovery_transaction(
                restore_root,
                purpose="replacement-admission",
                pinned=True,
                replacement_pending_limit=admitted_pending_file_count,
            ) as publication:

                def publish(
                    evidence: dict[str, Any],
                ) -> dict[str, Any]:
                    nonlocal guarded_evidence
                    guarded_evidence = evidence
                    live_inspection = store.inspect_core_authority_preclaim()
                    live_audit = store.audit_context_delivery_publication_repair()
                    if (
                        dict(live_inspection) != dict(inspection)
                        or dict(live_audit) != dict(audit)
                        or live_audit.get("audit_revision") != reviewed_revision
                    ):
                        raise CoreInstallerError(
                            "replacement predecessor changed before signed publication"
                        )
                    bundle = evidence.get("bundle")
                    restore = evidence.get("restore")
                    if not isinstance(bundle, dict) or not isinstance(restore, dict):
                        raise CoreInstallerError(
                            "replacement recovery evidence is incomplete"
                        )
                    if (
                        evidence.get("replacement_stage_ready") is not True
                        or evidence.get("pending_file_count")
                        != admitted_pending_file_count
                        or type(evidence.get("replay_required_file_count"))
                        is not int
                        or evidence.get("replay_required_capture_count")
                        != evidence.get("replay_required_file_count")
                        or int(evidence["replay_required_file_count"]) < 0
                        or int(evidence["replay_required_file_count"])
                        > admitted_pending_file_count
                        or evidence.get("receipt_backed_file_count") != 0
                    ):
                        raise CoreInstallerError(
                            "replacement recovery evidence changed its admitted "
                            "capture set"
                        )
                    return publish_replacement_admission(
                        request=ReplacementAdmissionRequest(
                            path=paths.core_root / "replacement-admission.json",
                            build_id=candidate_build_id,
                            config_fingerprint=config.fingerprint,
                            ttl_seconds=replacement_admission_ttl_seconds(
                                wait_seconds
                            ),
                            expected_pending_file_count=(
                                admitted_pending_file_count
                            ),
                            expected_replay_required_file_count=int(
                                evidence["replay_required_file_count"]
                            ),
                        ),
                        root=paths.root,
                        memory_db=paths.memory_db,
                        capture_root=paths.capture_root,
                        recovery_bundle_receipt=Path(
                            str(bundle.get("bundle_receipt_path") or "")
                        ),
                        recovery_restore_proof=Path(
                            str(restore.get("recovery_proof_path") or "")
                        ),
                        inspection=live_inspection,
                        delivery_audit=live_audit,
                        maximum_evidence_age_seconds=(
                            maximum_evidence_age_seconds
                        ),
                    )

                admission = publication.publish(publish)
            lease.assert_core_for(paths.memory_db)
        except CoreInstallerError:
            raise
        except Exception as exc:
            raise CoreInstallerError(
                "replacement admission proof or publication failed"
            ) from exc
        finally:
            try:
                if store is not None:
                    store.close()
            finally:
                if lease is not None:
                    lease.close()

        before_activation = launchctl.snapshot()
        if (
            before_activation.get("loaded")
            or before_activation.get("running")
            or not launchctl.disabled()
        ):
            raise CoreInstallerError(
                "exact core LaunchAgent changed before replacement activation"
            )
        prepare_private_regular(paths.log)
        write_core_config(paths.config, config)
        _assert_owner_controlled(
            paths.config,
            kind="core service config",
            require_mode=0o600,
        )
        _atomic_private_bytes(staged_plist, expected_plist)
        _assert_owner_controlled(
            staged_plist,
            kind="replacement staging LaunchAgent plist",
            require_mode=0o600,
        )
        replacement_activation_seconds_remaining(
            admission,
            wait_seconds=wait_seconds,
        )
        activated = False
        certification_seconds_remaining: int | None = None
        try:
            launchctl.enable()
            launchctl.bootstrap(staged_plist)
            launchctl.kickstart()
            activated = True
            health = wait_for_health(
                launchctl=launchctl,
                config=config,
                prior_pid=None,
                wait_seconds=wait_seconds,
                expected_deployment_mode="replacement-certification",
                require_capture_ready=False,
            )
            wait_for_replacement_capture_drain(
                capture_root=paths.capture_root,
                admitted_status=capture,
                admitted_pending_file_count=admitted_pending_file_count,
                admitted_receipt_backed_file_count=int(
                    guarded_evidence.get("receipt_backed_file_count") or 0
                ),
                wait_seconds=wait_seconds,
            )
            health = wait_for_health(
                launchctl=launchctl,
                config=config,
                prior_pid=None,
                wait_seconds=min(
                    wait_seconds,
                    REPLACEMENT_ACTIVATION_HEADROOM_SECONDS,
                ),
                expected_deployment_mode="replacement-certification",
                require_capture_ready=True,
            )
            certification_seconds_remaining = (
                replacement_certification_seconds_remaining(admission)
            )
        except BaseException as exc:
            cleanup_errors = verified_exact_label_cleanup(
                launchctl=launchctl,
                wait_seconds=wait_seconds,
            )
            if cleanup_errors:
                raise CoreInstallerError(
                    "replacement candidate activation failed; exact-label "
                    "cleanup could not be verified; the signed admission will "
                    "self-expire and live cutover must not continue"
                ) from exc
            if isinstance(exc, CoreInstallerError):
                raise CoreInstallerError(
                    "replacement candidate activation failed; the exact label "
                    "was verified disabled and unloaded"
                ) from exc
            raise
        if not activated or admission is None or guarded_evidence is None:
            raise CoreInstallerError("replacement candidate activation did not begin")
        if certification_seconds_remaining is None:
            raise CoreInstallerError(
                "replacement certification time budget was not established"
            )
        bundle = guarded_evidence.get("bundle")
        restore = guarded_evidence.get("restore")
        return _safe_result(
            "stage-replacement",
            status="staged-healthy",
            provisional=True,
            persistent=False,
            drained_pending_file_count=admitted_pending_file_count,
            certification_seconds_remaining=certification_seconds_remaining,
            staged_plist=str(staged_plist),
            admission={
                "receipt_digest": admission.get("receipt_digest"),
                "expires_at_unix_ms": admission.get("expires_at_unix_ms"),
                "candidate_build_id": admission.get("candidate_build_id"),
                "candidate_config_fingerprint": admission.get(
                    "candidate_config_fingerprint"
                ),
                "delivery_audit_revision": admission.get(
                    "delivery_audit_revision"
                ),
            },
            recovery={
                "verified": guarded_evidence.get("verified"),
                "cutover_ready": guarded_evidence.get("cutover_ready"),
                "isolated_restore_verified": (
                    restore.get("verified")
                    if isinstance(restore, dict)
                    else False
                ),
                "bundle_receipt_path": (
                    bundle.get("bundle_receipt_path")
                    if isinstance(bundle, dict)
                    else None
                ),
            },
            **health,
        )


def _unlink_exact_private(path: Path) -> bool:
    observed = _lstat(path)
    if observed is None:
        return False
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
    ):
        raise CoreInstallerError("refusing to unlink an unsafe LaunchAgent plist")
    path.unlink()
    _fsync_directory(path.parent)
    return True


def uninstall(*, paths: InstallPaths, launchctl: LaunchCtl, wait_seconds: float) -> dict[str, Any]:
    launchctl.disable()
    launchctl.bootout(wait_seconds=wait_seconds)
    removed = _unlink_exact_private(paths.plist)
    return _safe_result(
        "uninstall",
        status="uninstalled",
        plist_removed=removed,
        data_preserved=True,
        config_preserved=True,
        token_preserved=True,
        logs_preserved=True,
        client_binding_preserved=True,
    )


def status(*, paths: InstallPaths, launchctl: LaunchCtl) -> dict[str, Any]:
    snapshot = launchctl.snapshot()
    healthy = False
    runtime_healthy = False
    capture_ready = False
    deployment_mode: str | None = None
    provisional = False
    binding_path = default_binding_path(paths.home)
    binding_ready = False
    binding_digest = None
    if snapshot.get("running") and paths.config.exists() and not paths.config.is_symlink():
        try:
            health = probe_health(load_core_config(paths.config))
            healthy = bool(health.get("ready"))
            runtime_healthy = healthy
            capture_ready = bool(health.get("capture_ready"))
            deployment_mode = str(health.get("deployment_mode") or "") or None
        except Exception:
            try:
                health = probe_health(
                    load_core_config(paths.config),
                    expected_deployment_mode="replacement-certification",
                )
                runtime_healthy = bool(health.get("ready"))
                capture_ready = bool(health.get("capture_ready"))
                deployment_mode = str(
                    health.get("deployment_mode") or ""
                ) or None
                provisional = runtime_healthy
            except Exception:
                pass
    if paths.config.exists() and not paths.config.is_symlink():
        try:
            config = load_core_config(paths.config)
            expected_binding = binding_for_config(
                repo_root=paths.root,
                data_root=paths.data_root,
                config=config,
                core_label=launchctl.label,
                authority_mode="authoritative-core-v6",
            )
            observed_binding = load_core_client_binding(binding_path)
            binding_ready = observed_binding == expected_binding
            binding_digest = observed_binding.digest
        except Exception:
            pass
    return _safe_result(
        "status",
        loaded=bool(snapshot.get("loaded")),
        running=bool(snapshot.get("running")),
        pid=snapshot.get("pid"),
        healthy=healthy,
        runtime_healthy=runtime_healthy,
        production_ready=bool(healthy and binding_ready),
        deployment_mode=deployment_mode,
        provisional=provisional,
        capture_ready=capture_ready,
        plist_present=paths.plist.is_file() and not paths.plist.is_symlink(),
        config_present=paths.config.is_file() and not paths.config.is_symlink(),
        client_binding={
            "path": str(binding_path),
            "ready": binding_ready,
            "digest": binding_digest,
        },
    )


def build_parser() -> argparse.ArgumentParser:
    parser = SecretSafeArgumentParser(
        description="Operate the SYNAPSE-S2 core LaunchAgent"
    )
    parser.add_argument(
        "action",
        nargs="?",
        choices=(
            "install",
            "stage-replacement",
            "recover-existing",
            "repair-preclaim-residue",
            "context-delivery-integrity",
            "publish-binding",
            "status",
            "stop",
            "uninstall",
        ),
        default="install",
    )
    parser.add_argument("--label", default=os.getenv("SYNAPSE_S2_CORE_LABEL", DEFAULT_LABEL))
    parser.add_argument("--evidence-manifest")
    parser.add_argument("--maximum-evidence-age-seconds", type=float, default=7200.0)
    parser.add_argument("--wait-seconds", type=float, default=180.0)
    parser.add_argument("--force-restart", action="store_true")
    parser.add_argument(
        "--repair",
        action="store_true",
        help="apply only the reviewed derived delivery-publication repair",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="explicitly confirm the reviewed repair or replacement staging action",
    )
    parser.add_argument(
        "--expected-revision",
        default="",
        help="exact 64-hex delivery audit revision reviewed immediately before action",
    )
    parser.add_argument(
        "--restored-target",
        action="store_true",
        help=(
            "require and attest the exact restored memory/journal/runtime binding; "
            "valid only for an authoritative-v6 install"
        ),
    )
    parser.add_argument(
        "--noncanonical-layout-manifest",
        help="private reviewed manifest authorizing a noncanonical data root",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if not 2.0 <= args.wait_seconds <= 600.0:
            raise CoreInstallerError("wait-seconds must be between 2 and 600")
        if not 60.0 <= args.maximum_evidence_age_seconds <= 86_400.0:
            raise CoreInstallerError("maximum evidence age must be between 60 and 86400 seconds")
        if args.restored_target and args.action != "install":
            raise CoreInstallerError("restored-target is valid only for install")
        delivery_integrity_flags = bool(args.repair or args.confirm or args.expected_revision)
        if delivery_integrity_flags and args.action not in {
            "context-delivery-integrity",
            "stage-replacement",
            "repair-preclaim-residue",
        }:
            raise CoreInstallerError(
                "reviewed delivery flags are valid only for delivery integrity "
                "or replacement staging"
            )
        if args.action == "stage-replacement" and args.repair:
            raise CoreInstallerError(
                "replacement staging never repairs delivery publication"
            )
        if args.action == "repair-preclaim-residue" and (
            args.repair
            or args.expected_revision
            or args.evidence_manifest
            or args.force_restart
            or args.restored_target
        ):
            raise CoreInstallerError(
                "repair-preclaim-residue accepts only its explicit --confirm"
            )
        if args.action == "context-delivery-integrity" and (
            args.evidence_manifest or args.force_restart
        ):
            raise CoreInstallerError(
                "context-delivery-integrity does not accept cutover evidence "
                "or restart flags"
            )
        if args.action == "stage-replacement" and (
            args.evidence_manifest or args.force_restart
        ):
            raise CoreInstallerError(
                "replacement staging does not accept cutover evidence or restart flags"
            )
        if args.action == "recover-existing" and args.evidence_manifest:
            raise CoreInstallerError(
                "recover-existing does not accept or reuse cutover evidence"
            )
        if args.action == "recover-existing" and args.force_restart:
            raise CoreInstallerError(
                "force-restart is not valid for recover-existing"
            )
        layout_manifest = (
            _normal_absolute(
                args.noncanonical_layout_manifest,
                name="noncanonical layout manifest",
            )
            if args.noncanonical_layout_manifest
            else None
        )
        paths = resolve_paths(
            label=args.label,
            noncanonical_layout_manifest=layout_manifest,
        )
        launchctl_bin = os.getenv("SYNAPSE_S2_LAUNCHCTL", "/bin/launchctl")
        ps_bin = os.getenv("SYNAPSE_S2_PS_BIN", "/bin/ps")
        launchctl = LaunchCtl(launchctl_bin, uid=os.getuid(), label=args.label)
        evidence = (
            _normal_absolute(args.evidence_manifest, name="evidence manifest")
            if args.evidence_manifest
            else None
        )
        if args.action == "status":
            result = status(paths=paths, launchctl=launchctl)
        else:
            with install_lock(paths, label=args.label):
                if args.action == "install":
                    result = install(
                        paths=paths,
                        label=args.label,
                        launchctl=launchctl,
                        launchctl_bin=launchctl_bin,
                        ps_bin=ps_bin,
                        evidence_manifest=evidence,
                        maximum_evidence_age_seconds=args.maximum_evidence_age_seconds,
                        wait_seconds=args.wait_seconds,
                        force_restart=args.force_restart,
                        restored_target=args.restored_target,
                    )
                elif args.action == "stage-replacement":
                    result = stage_replacement(
                        paths=paths,
                        label=args.label,
                        launchctl=launchctl,
                        wait_seconds=args.wait_seconds,
                        maximum_evidence_age_seconds=(
                            args.maximum_evidence_age_seconds
                        ),
                        confirm=bool(args.confirm),
                        expected_revision=(
                            str(args.expected_revision).strip().lower()
                            if args.expected_revision
                            else None
                        ),
                    )
                elif args.action == "recover-existing":
                    result = recover_existing(
                        paths=paths,
                        label=args.label,
                        launchctl=launchctl,
                        wait_seconds=args.wait_seconds,
                    )
                elif args.action == "repair-preclaim-residue":
                    result = repair_preclaim_residue(
                        paths=paths,
                        launchctl=launchctl,
                        confirm=bool(args.confirm),
                    )
                elif args.action == "publish-binding":
                    from backend_router import database_requires_core

                    _validate_install_sources(paths)
                    config = build_config(paths)
                    if database_requires_core(paths.memory_db):
                        raise CoreInstallerError(
                            "candidate binding cannot replace an adopted core binding"
                        )
                    result = _safe_result(
                        "publish-binding",
                        status="candidate-ready",
                        client_binding=publish_client_binding(
                            paths=paths,
                            label=args.label,
                            config=config,
                            authority_mode="candidate-local-v5",
                        ),
                    )
                elif args.action == "context-delivery-integrity":
                    result = context_delivery_integrity(
                        paths=paths,
                        launchctl=launchctl,
                        wait_seconds=args.wait_seconds,
                        repair=bool(args.repair),
                        confirm=bool(args.confirm),
                        expected_revision=(
                            str(args.expected_revision).strip().lower()
                            if args.expected_revision
                            else None
                        ),
                    )
                elif args.action == "stop":
                    result = stop(launchctl=launchctl, wait_seconds=args.wait_seconds)
                else:
                    result = uninstall(
                        paths=paths,
                        launchctl=launchctl,
                        wait_seconds=args.wait_seconds,
                    )
    except (CoreInstallerError, CoreServiceError, CutoverPreflightError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

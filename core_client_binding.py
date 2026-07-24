from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from core_runtime_paths import (
    CoreRuntimePathError,
    supported_core_socket_path,
)


BINDING_SCHEMA = "synapse-s2.core-client-binding.v3"
BINDING_ENV = "SYNAPSE_S2_CORE_BINDING"
EXPECTED_CONFIG_ENV = "SYNAPSE_S2_EXPECTED_CORE_CONFIG_FINGERPRINT"
MAX_BINDING_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LABEL = re.compile(r"^[A-Za-z0-9._-]{1,160}$")
_LAYOUTS = frozenset({"canonical", "reviewed-noncanonical"})
_AUTHORITY_MODES = frozenset({"candidate-local-v5", "authoritative-core-v6"})
_CANDIDATE_RUNTIME_ENV = frozenset(
    {
        "MLX_DEVICE",
        "SYNAPSE_S2_DIMENSION",
        "SYNAPSE_S2_EMBEDDING_PROVIDER",
        "SYNAPSE_S2_IDLE_DEEP_SLEEP_SECONDS",
        "SYNAPSE_S2_NEURAL_CACHE_DIR",
        "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY",
        "SYNAPSE_S2_NEURAL_MODEL",
        # Deprecated installer-only spelling. It is accepted while publishing
        # a config, but never exported into a bound client process.
        "SYNAPSE_S2_NEURAL_MODEL_ID",
        "SYNAPSE_S2_NEURAL_REVISION",
        "SYNAPSE_S2_NEURAL_POOLING",
        "SYNAPSE_S2_NEURAL_MAX_TOKENS",
        "SYNAPSE_S2_NEURAL_NORMALIZE",
        "SYNAPSE_S2_NEURONS",
        "SYNAPSE_S2_QUICK_PRUNING_INTERVAL_SECONDS",
        "SYNAPSE_S2_RECALL_COUNT",
        "SYNAPSE_S2_REQUIRE_NATIVE",
        "SYNAPSE_S2_TOP_K",
        "SYNAPSE_S2_CAPTURE_POLL_INTERVAL",
        "SYNAPSE_S2_CAPTURE_MAX_FILES",
        "SYNAPSE_S2_TRANSCRIPT_POLL",
        "SYNAPSE_S2_MAX_TRANSCRIPT_BYTES",
    }
)
_PATH_FIELDS = (
    "repo_root",
    "data_root",
    "config_path",
    "socket_path",
    "state_path",
    "memory_path",
    "capture_root",
    "export_root",
    "backup_root",
    "recovery_root",
    "replication_inbox_root",
)
_FIELDS = frozenset(
    {
        "schema",
        "core_label",
        "config_digest",
        "config_fingerprint",
        "embedding_space_identity",
        "layout",
        "authority_mode",
        *_PATH_FIELDS,
    }
)


class CoreClientBindingError(RuntimeError):
    """A content-free failure at the owner-controlled client binding boundary."""

    def __init__(self) -> None:
        super().__init__("core_binding_invalid")


def _deny() -> None:
    raise CoreClientBindingError()


def default_binding_path(home: Path | None = None) -> Path:
    root = Path.home() if home is None else Path(home)
    return root.expanduser().absolute() / ".config" / "synapse-s2" / "core-binding.json"


def _normal_absolute(value: Any) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        _deny()
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        _deny()
    path = Path(value).expanduser()
    if not path.is_absolute() or ".." in path.parts:
        _deny()
    normalized = Path(os.path.normpath(str(path)))
    if normalized != path or normalized == Path(normalized.anchor):
        _deny()
    return normalized


def _assert_no_symlink_components(path: Path, *, final_may_be_missing: bool) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            observed = current.lstat()
        except FileNotFoundError:
            if final_may_be_missing:
                continue
            _deny()
        except OSError:
            _deny()
        if stat.S_ISLNK(observed.st_mode):
            # macOS exposes /var as a platform-owned compatibility symlink.
            if current == Path("/var") and os.readlink(current) == "private/var":
                continue
            _deny()


@dataclass(frozen=True)
class CoreClientBinding:
    repo_root: Path
    data_root: Path
    config_path: Path
    socket_path: Path
    state_path: Path
    memory_path: Path
    capture_root: Path
    export_root: Path
    backup_root: Path
    recovery_root: Path
    replication_inbox_root: Path
    core_label: str
    config_digest: str
    config_fingerprint: str
    embedding_space_identity: str
    layout: str
    authority_mode: str

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": BINDING_SCHEMA,
            "repo_root": str(self.repo_root),
            "data_root": str(self.data_root),
            "config_path": str(self.config_path),
            "socket_path": str(self.socket_path),
            "state_path": str(self.state_path),
            "memory_path": str(self.memory_path),
            "capture_root": str(self.capture_root),
            "export_root": str(self.export_root),
            "backup_root": str(self.backup_root),
            "recovery_root": str(self.recovery_root),
            "replication_inbox_root": str(self.replication_inbox_root),
            "core_label": self.core_label,
            "config_digest": self.config_digest,
            "config_fingerprint": self.config_fingerprint,
            "embedding_space_identity": self.embedding_space_identity,
            "layout": self.layout,
            "authority_mode": self.authority_mode,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical_bytes(self.to_wire())).hexdigest()


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            dict(value),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError) as exc:
        raise CoreClientBindingError() from exc


def validate_core_client_binding(value: Any) -> CoreClientBinding:
    if not isinstance(value, dict) or frozenset(value) != _FIELDS:
        _deny()
    if value.get("schema") != BINDING_SCHEMA:
        _deny()
    paths = {field: _normal_absolute(value.get(field)) for field in _PATH_FIELDS}
    label = value.get("core_label")
    config_digest = value.get("config_digest")
    config_fingerprint = value.get("config_fingerprint")
    embedding_identity = value.get("embedding_space_identity")
    layout = value.get("layout")
    authority_mode = value.get("authority_mode")
    if (
        not isinstance(label, str)
        or _LABEL.fullmatch(label) is None
        or not isinstance(config_digest, str)
        or _SHA256.fullmatch(config_digest) is None
        or not isinstance(config_fingerprint, str)
        or _SHA256.fullmatch(config_fingerprint) is None
        or not isinstance(embedding_identity, str)
        or _SHA256.fullmatch(embedding_identity) is None
        or layout not in _LAYOUTS
        or authority_mode not in _AUTHORITY_MODES
    ):
        _deny()
    data = paths["data_root"]
    core = data / "core"
    expected = {
        "config_path": core / "service.json",
        "state_path": data / "runtime_state.json",
        "memory_path": data / "memory.sqlite3",
        "capture_root": data,
        "export_root": data / "exports",
        "backup_root": data / "backups",
        "recovery_root": data / "recovery",
        "replication_inbox_root": data / "replication" / "inbox",
    }
    if any(paths[field] != path for field, path in expected.items()):
        _deny()
    try:
        socket_path = supported_core_socket_path(
            paths["socket_path"],
            memory_path=paths["memory_path"],
        )
    except CoreRuntimePathError:
        _deny()
    if socket_path != paths["socket_path"]:
        _deny()
    canonical_data = paths["repo_root"] / ".synapse_s2"
    if (layout == "canonical") != (data == canonical_data):
        _deny()
    for path in paths.values():
        _assert_no_symlink_components(path, final_may_be_missing=True)
    return CoreClientBinding(
        **paths,
        core_label=label,
        config_digest=config_digest,
        config_fingerprint=config_fingerprint,
        embedding_space_identity=embedding_identity,
        layout=layout,
        authority_mode=authority_mode,
    )


def binding_for_config(
    *,
    repo_root: Path,
    data_root: Path,
    config: Any,
    core_label: str,
    authority_mode: str,
) -> CoreClientBinding:
    try:
        from core_service import config_from_wire

        config = config_from_wire(config.to_wire())
        config_wire = config.to_wire()
    except Exception as exc:
        raise CoreClientBindingError() from exc
    config_digest = hashlib.sha256(_canonical_bytes(config_wire)).hexdigest()
    payload = {
        "schema": BINDING_SCHEMA,
        "repo_root": str(Path(repo_root).absolute()),
        "data_root": str(Path(data_root).absolute()),
        "config_path": str(Path(data_root) / "core" / "service.json"),
        "socket_path": str(config.socket_path),
        "state_path": str(config.state_path),
        "memory_path": str(config.memory_path),
        "capture_root": str(config.capture_root),
        "export_root": str(Path(data_root) / "exports"),
        "backup_root": str(Path(data_root) / "backups"),
        "recovery_root": str(Path(data_root) / "recovery"),
        "replication_inbox_root": str(
            Path(data_root) / "replication" / "inbox"
        ),
        "core_label": str(core_label),
        "config_digest": config_digest,
        "config_fingerprint": str(config.fingerprint),
        "embedding_space_identity": str(config.embedding_space_identity),
        "layout": (
            "canonical"
            if Path(data_root).absolute()
            == Path(repo_root).absolute() / ".synapse_s2"
            else "reviewed-noncanonical"
        ),
        "authority_mode": str(authority_mode),
    }
    return validate_core_client_binding(payload)


def load_bound_core_config(binding: CoreClientBinding) -> Any:
    """Load and verify the exact private CoreConfig named by a binding.

    Importing the config codec is deliberately lazy: persistent clients call
    this boundary before importing or constructing a backend, so a missing,
    malformed, swapped, or drifted reviewed config fails closed first.
    """

    canonical = validate_core_client_binding(binding.to_wire())
    try:
        from core_service import load_core_config

        config = load_core_config(canonical.config_path)
        config_wire = config.to_wire()
        config_digest = hashlib.sha256(_canonical_bytes(config_wire)).hexdigest()
        fingerprint = str(config.fingerprint)
        embedding_identity = str(config.embedding_space_identity)
    except Exception as exc:
        raise CoreClientBindingError() from exc
    expected_paths = {
        "socket_path": canonical.socket_path,
        "state_path": canonical.state_path,
        "memory_path": canonical.memory_path,
        "capture_root": canonical.capture_root,
    }
    if any(getattr(config, field) != path for field, path in expected_paths.items()):
        _deny()
    if not secrets.compare_digest(config_digest, canonical.config_digest):
        _deny()
    if not secrets.compare_digest(fingerprint, canonical.config_fingerprint):
        _deny()
    if not secrets.compare_digest(
        embedding_identity,
        canonical.embedding_space_identity,
    ):
        _deny()
    return config


def _private_parent(path: Path) -> None:
    missing: list[Path] = []
    cursor = path
    while True:
        try:
            observed = cursor.lstat()
            break
        except FileNotFoundError:
            missing.append(cursor)
            if cursor.parent == cursor:
                _deny()
            cursor = cursor.parent
        except OSError:
            _deny()
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
        _deny()
    if observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) & 0o022:
        _deny()
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        created = directory.lstat()
        if (
            stat.S_ISLNK(created.st_mode)
            or not stat.S_ISDIR(created.st_mode)
            or created.st_uid != os.getuid()
            or stat.S_IMODE(created.st_mode) != 0o700
        ):
            _deny()
    final = path.lstat()
    if (
        stat.S_ISLNK(final.st_mode)
        or not stat.S_ISDIR(final.st_mode)
        or final.st_uid != os.getuid()
        or stat.S_IMODE(final.st_mode) != 0o700
    ):
        _deny()


def write_core_client_binding(path: Path, binding: CoreClientBinding) -> None:
    target = _normal_absolute(str(path))
    canonical = validate_core_client_binding(binding.to_wire())
    payload = _canonical_bytes(canonical.to_wire()) + b"\n"
    _assert_no_symlink_components(target, final_may_be_missing=True)
    _private_parent(target.parent)
    existing = None
    try:
        existing = target.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        _deny()
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_uid != os.getuid()
        or existing.st_nlink != 1
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        _deny()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=f".{secrets.token_hex(6)}.tmp",
        dir=str(target.parent),
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        current = None
        try:
            current = target.lstat()
        except FileNotFoundError:
            pass
        if (existing is None) != (current is None):
            _deny()
        if existing is not None and current is not None and (
            existing.st_dev,
            existing.st_ino,
            existing.st_size,
            existing.st_mtime_ns,
        ) != (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
        ):
            _deny()
        os.replace(temporary, target)
        directory_fd = os.open(
            target.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_core_client_binding(path: Path) -> CoreClientBinding:
    target = _normal_absolute(str(path))
    _assert_no_symlink_components(target, final_may_be_missing=False)
    try:
        before = target.lstat()
    except OSError:
        _deny()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size <= 0
        or before.st_size > MAX_BINDING_BYTES
    ):
        _deny()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags)
    try:
        opened = os.fstat(descriptor)
        payload = b""
        while len(payload) <= MAX_BINDING_BYTES:
            chunk = os.read(descriptor, min(65_536, MAX_BINDING_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload += chunk
        finished = os.fstat(descriptor)
    except OSError:
        _deny()
    finally:
        os.close(descriptor)
    try:
        visible = target.lstat()
    except OSError:
        _deny()
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        for item in (before, opened, finished, visible)
    }
    if len(identities) != 1 or len(payload) != before.st_size:
        _deny()
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        _deny()
    binding = validate_core_client_binding(value)
    if not secrets.compare_digest(
        payload,
        _canonical_bytes(binding.to_wire()) + b"\n",
    ):
        _deny()
    return binding


def binding_from_environment(
    env: Mapping[str, str] | None = None,
) -> CoreClientBinding | None:
    values = os.environ if env is None else env
    raw = str(values.get(BINDING_ENV, "") or "").strip()
    if not raw:
        return None
    return load_core_client_binding(_normal_absolute(raw))


def _bool_environment(value: bool) -> str:
    return "true" if value else "false"


def _candidate_config_environment(config: Any) -> dict[str, str]:
    expected = {
        "MLX_DEVICE": str(config.mlx_device),
        "SYNAPSE_S2_DIMENSION": str(config.dimension),
        "SYNAPSE_S2_NEURONS": str(config.num_neurons),
        "SYNAPSE_S2_TOP_K": str(config.default_top_k),
        "SYNAPSE_S2_RECALL_COUNT": str(config.recall_count),
        "SYNAPSE_S2_QUICK_PRUNING_INTERVAL_SECONDS": str(
            config.quick_pruning_interval_seconds
        ),
        "SYNAPSE_S2_IDLE_DEEP_SLEEP_SECONDS": str(
            config.idle_deep_sleep_seconds
        ),
        "SYNAPSE_S2_EMBEDDING_PROVIDER": str(config.embedding_provider_name),
        "SYNAPSE_S2_REQUIRE_NATIVE": _bool_environment(config.require_native),
        "SYNAPSE_S2_CAPTURE_POLL_INTERVAL": str(config.capture_poll_seconds),
        "SYNAPSE_S2_CAPTURE_MAX_FILES": str(config.capture_max_files),
        "SYNAPSE_S2_TRANSCRIPT_POLL": _bool_environment(
            config.poll_transcript_sources
        ),
        "SYNAPSE_S2_MAX_TRANSCRIPT_BYTES": str(config.max_transcript_bytes),
    }
    provider = str(config.embedding_provider_name).strip().lower()
    if provider in {"mlx-neural", "mlx-neural-v1"}:
        neural_values = {
            "SYNAPSE_S2_NEURAL_MODEL": config.embedding_neural_model_id,
            "SYNAPSE_S2_NEURAL_REVISION": config.embedding_neural_revision,
            "SYNAPSE_S2_NEURAL_CACHE_DIR": config.embedding_neural_cache_dir,
            "SYNAPSE_S2_NEURAL_POOLING": config.embedding_neural_pooling,
            "SYNAPSE_S2_NEURAL_MAX_TOKENS": config.embedding_neural_max_tokens,
            "SYNAPSE_S2_NEURAL_NORMALIZE": (
                None
                if config.embedding_neural_normalize is None
                else _bool_environment(config.embedding_neural_normalize)
            ),
            "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY": (
                None
                if config.embedding_neural_local_files_only is None
                else _bool_environment(config.embedding_neural_local_files_only)
            ),
        }
        if any(value is None for value in neural_values.values()):
            _deny()
        expected.update({key: str(value) for key, value in neural_values.items()})
    return expected


def apply_binding_environment(
    env: dict[str, str] | None = None,
) -> CoreClientBinding | None:
    values = os.environ if env is None else env
    binding = binding_from_environment(values)
    if binding is None:
        return None
    config = load_bound_core_config(binding)
    # A reviewed binding is the sole authority selector.  Reject stale fields
    # from the opposite mode instead of letting a candidate binding inherit a
    # service socket (or an authoritative binding inherit local store paths).
    disallowed = (
        ("SYNAPSE_S2_MEMORY_DB", "SYNAPSE_S2_STATE_PATH")
        if binding.authority_mode == "authoritative-core-v6"
        else ("SYNAPSE_S2_CORE_SOCKET", EXPECTED_CONFIG_ENV)
    )
    if any(key in values for key in disallowed):
        _deny()
    expected = {
        "SYNAPSE_S2_EXPORT_DIR": str(binding.export_root),
        "SYNAPSE_S2_CAPTURE_ROOT": str(binding.capture_root),
        "SYNAPSE_S2_REPLICATION_INBOX_ROOT": str(
            binding.replication_inbox_root
        ),
    }
    if binding.authority_mode == "authoritative-core-v6":
        expected.update(
            {
                "SYNAPSE_S2_CORE_SOCKET": str(binding.socket_path),
                EXPECTED_CONFIG_ENV: binding.config_fingerprint,
            }
        )
    else:
        candidate_config = _candidate_config_environment(config)
        for key in _CANDIDATE_RUNTIME_ENV:
            if key not in values:
                continue
            if key not in candidate_config or str(values[key]) != candidate_config[key]:
                _deny()
        expected.update(
            {
                "SYNAPSE_S2_MEMORY_DB": str(binding.memory_path),
                "SYNAPSE_S2_STATE_PATH": str(binding.state_path),
                **candidate_config,
            }
        )
    for key, value in expected.items():
        existing = str(values.get(key, "") or "")
        if existing and existing != value:
            _deny()
        values[key] = value
    return binding

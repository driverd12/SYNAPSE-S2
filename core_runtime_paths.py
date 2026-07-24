from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


# Darwin's sockaddr_un.sun_path has 104 bytes including the terminating NUL.
# Keep this explicit and platform-independent so an invalid production path is
# rejected before request-journal or database startup can mutate durable state.
MAX_UNIX_SOCKET_PATH_BYTES = 103
CORE_TRANSPORT_DIRECTORY_NAME = "run"
CORE_TRANSPORT_ID_HEX_LENGTH = 24


class CoreRuntimePathError(ValueError):
    """A content-free runtime path validation failure."""


def _normal_absolute(path: str | os.PathLike[str]) -> Path:
    value = Path(path).expanduser()
    if (
        not value.is_absolute()
        or ".." in value.parts
        or "\x00" in str(value)
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in str(value)
        )
    ):
        raise CoreRuntimePathError("core_runtime_path_invalid")
    lexical = Path(os.path.normpath(str(value)))
    if lexical != value or lexical == Path(lexical.anchor):
        raise CoreRuntimePathError("core_runtime_path_invalid")
    return lexical


def _identity_absolute(path: str | os.PathLike[str]) -> Path:
    lexical = _normal_absolute(path)
    try:
        resolved = lexical.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise CoreRuntimePathError("core_runtime_path_invalid") from exc
    if resolved == Path(resolved.anchor):
        raise CoreRuntimePathError("core_runtime_path_invalid")
    return resolved


def validate_core_socket_path(path: str | os.PathLike[str]) -> Path:
    """Validate one absolute Unix socket endpoint without exposing its value."""

    normalized = _normal_absolute(path)
    try:
        encoded = os.fsencode(str(normalized))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CoreRuntimePathError("core_runtime_path_invalid") from exc
    if not encoded or len(encoded) > MAX_UNIX_SOCKET_PATH_BYTES:
        raise CoreRuntimePathError("core_runtime_path_invalid")
    return normalized


def durable_core_root(memory_path: str | os.PathLike[str]) -> Path:
    """Return the durable control/evidence root adjacent to the memory store."""

    memory = _normal_absolute(memory_path)
    return memory.parent / "core"


def legacy_core_socket_path(memory_path: str | os.PathLike[str]) -> Path:
    """Return the pre-transport-split socket location for bounded compatibility."""

    return durable_core_root(memory_path) / "service.sock"


def canonical_core_socket_path(
    data_root: str | os.PathLike[str],
    *,
    home: str | os.PathLike[str] | None = None,
) -> Path:
    """Return a deterministic, owner-private, short transport endpoint.

    Durable journals, repair receipts, attestations, and generation metadata
    remain below ``data_root/core``. Only the Unix socket and its authentication
    token use this bounded transport directory.
    """

    data = _normal_absolute(data_root)
    data_identity = _identity_absolute(data)
    legacy = data_identity / "core" / "service.sock"
    try:
        # Preserve the established endpoint (and therefore config identity)
        # whenever it is already representable by Darwin sockaddr_un.
        return validate_core_socket_path(legacy)
    except CoreRuntimePathError:
        pass
    owner_home = _normal_absolute(Path.home() if home is None else home)
    transport_id = hashlib.sha256(os.fsencode(str(data_identity))).hexdigest()[
        :CORE_TRANSPORT_ID_HEX_LENGTH
    ]
    return validate_core_socket_path(
        owner_home
        / ".config"
        / "synapse-s2"
        / CORE_TRANSPORT_DIRECTORY_NAME
        / transport_id
        / "service.sock"
    )


def supported_core_socket_path(
    socket_path: str | os.PathLike[str],
    *,
    memory_path: str | os.PathLike[str],
    home: str | os.PathLike[str] | None = None,
) -> Path:
    """Accept the canonical endpoint or one still-safe legacy endpoint."""

    socket = validate_core_socket_path(socket_path)
    legacy = legacy_core_socket_path(memory_path)
    data = _identity_absolute(Path(memory_path).expanduser().parent)
    transport_id = hashlib.sha256(os.fsencode(str(data))).hexdigest()[
        :CORE_TRANSPORT_ID_HEX_LENGTH
    ]
    canonical_tail = (
        ".config",
        "synapse-s2",
        CORE_TRANSPORT_DIRECTORY_NAME,
        transport_id,
        "service.sock",
    )
    if socket == legacy:
        return socket
    if socket.parts[-5:] != canonical_tail:
        raise CoreRuntimePathError("core_runtime_path_invalid")
    # The selected transport home is explicit in the reviewed endpoint.  It
    # must itself be an owner-controlled, non-symlink directory; accepting a
    # matching suffix beneath an arbitrary ancestor would weaken the binding.
    try:
        selected_home = socket.parents[4]
        observed_home = selected_home.lstat()
    except (IndexError, OSError) as exc:
        raise CoreRuntimePathError("core_runtime_path_invalid") from exc
    if (
        not stat.S_ISDIR(observed_home.st_mode)
        or stat.S_ISLNK(observed_home.st_mode)
        or observed_home.st_uid != os.getuid()
        or stat.S_IMODE(observed_home.st_mode) & 0o022
    ):
        raise CoreRuntimePathError("core_runtime_path_invalid")
    if home is not None and selected_home != _normal_absolute(home):
        raise CoreRuntimePathError("core_runtime_path_invalid")
    if canonical_core_socket_path(data, home=selected_home) != socket:
        raise CoreRuntimePathError("core_runtime_path_invalid")
    return socket

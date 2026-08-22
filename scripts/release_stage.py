#!/usr/bin/env python3
"""Fail-closed, incumbent-run, inactive SYNAPSE-S2 source staging.

This slice copies only the trusted whole-product inventory into an immutable
*identity-named* release directory beneath an explicit private install root.
It never executes candidate code, builds an environment, creates a
``current``/``latest`` selector, activates a release, opens or traverses a
data root, or touches runtime, capture, recovery, client, launcher, binding,
or launchd state.  Data/environment leaf metadata is identity-guarded solely
to reject aliases, while contents remain unread.  The expected product and
inventory-policy identifiers are authority inputs supplied by the already-
authenticated orchestration layer.

Candidate and staged source are independently checked by the trusted
incumbent ``release_update_plan`` library.  Inventory bytes are read through
that library's held-descriptor, no-follow, stable-read implementation and are
written into a unique private operation directory with exact file modes.
Publication is a Darwin ``renameatx_np(RENAME_EXCL)``: atomic and incapable of
replacing an existing release.  A private hash-chained journal records the
published identity.  If publication succeeded but journaling did not, the
next invocation re-verifies the visible release and reconciles the journal.

CLI output is one bounded deterministic redacted JSON line.  It never
contains paths, file bytes, exception text, command output, or secrets.
Before any non-builtin import, cwd/PYTHONPATH entries are removed.  Use
``python -I scripts/release_stage.py`` so isolated mode also closes Python's
pre-script startup/sitecustomize window.
"""

from __future__ import annotations

import sys

# Harden imports before the first non-builtin module can be resolved.  Preserve
# the exact caller state so API import is side-effect-neutral; direct CLI use
# intentionally retains the hardened path and no-bytecode policy for life.
_ORIGINAL_SYS_PATH = list(sys.path)
_ORIGINAL_DONT_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True


def _sanitize_sys_path() -> None:
    """Admit only interpreter-owned stdlib locations.

    ``os`` is loaded by the interpreter before this script body.  Looking it
    up in ``sys.modules`` therefore cannot execute a cwd/PYTHONPATH shadow.
    Hardened operator invocation remains ``python -I release_stage.py``:
    isolated mode also closes the startup/sitecustomize window that necessarily
    precedes this code.
    """

    def _clean(entry: object) -> bool:
        return (
            isinstance(entry, str)
            and entry.startswith("/")
            and "\x00" not in entry
            and not any(part in ("", ".", "..") for part in entry.split("/")[1:])
        )

    os_file = getattr(sys.modules.get("os"), "__file__", None)
    if not isinstance(os_file, str) or not _clean(os_file) or "/" not in os_file[1:]:
        raise ImportError("untrusted standard library location")
    stdlib_dir = os_file.rsplit("/", 1)[0]
    stdlib_parent = stdlib_dir.rsplit("/", 1)[0]
    versioned_zip = (
        stdlib_parent
        + "/python"
        + str(sys.version_info.major)
        + str(sys.version_info.minor)
        + ".zip"
    )
    sanitized: list[str] = []
    for entry in (
        versioned_zip,
        stdlib_dir,
        stdlib_dir + "/lib-dynload",
    ):
        if _clean(entry) and entry not in sanitized:
            sanitized.append(entry)
    if len(sanitized) != 3:
        raise ImportError("untrusted standard library location")
    sys.path[:] = sanitized


_sanitize_sys_path()

import argparse
import ctypes
import errno
import fcntl
import hashlib
import inspect
import json
import os
import posixpath
import re
import stat
from pathlib import Path
from types import ModuleType
from typing import Callable


if __name__ != "__main__":
    sys.path[:] = _ORIGINAL_SYS_PATH
    sys.dont_write_bytecode = _ORIGINAL_DONT_WRITE_BYTECODE


RESULT_SCHEMA = "synapse-s2.release-stage-result.v1"
RESULT_MODE = "incumbent-inactive-source-stage"
JOURNAL_SCHEMA = "synapse-s2.release-stage-journal-entry.v1"
HELP_SCHEMA = "synapse-s2.release-stage-help.v1"

# This reviewed digest is the trust bridge from this incumbent stager to the
# only planner source it is permitted to execute.  Filesystem ownership and
# held-descriptor continuity cannot distinguish an attacker-controlled
# same-UID replacement made before the loader starts; the embedded byte pin
# does.  A deliberate planner update therefore requires a reviewed stager
# update in the same release.
TRUSTED_PLANNER_SHA256 = (
    "2ad36ef1ff0c302d89592c563a95a0f98f8144f73f205af4bde1eeafc01b83b6"
)

STATUS_STAGED = "staged"
STATUS_ALREADY_STAGED = "already-staged"
STATUS_UNSUPPORTED = "unsupported"
STATUS_OUTCOME_UNKNOWN = "outcome_unknown"

MAX_RESULT_BYTES = 4096
MAX_JOURNAL_BYTES = 4 * 1024 * 1024
MAX_JOURNAL_ENTRIES = 4096
MAX_PATH_BYTES = 4096
MAX_WRITE_CHUNK_BYTES = 1024 * 1024

_PRODUCT_ID_RE = re.compile(r"product-[0-9a-f]{64}")
_POLICY_ID_RE = re.compile(r"inventory-policy-[0-9a-f]{64}")
_OPERATION_RE = re.compile(r"stage-[0-9a-f]{32}")
_JOURNAL_HASH_RE = re.compile(r"[0-9a-f]{64}")
_JOURNAL_HASH_DOMAIN = b"SYNAPSE-S2\x00RELEASE-STAGE-JOURNAL\x00v1\x00"
_FORBIDDEN_ACTIVE_COMPONENTS = frozenset(
    (".synapse_s2", "recovery", "launchagents", "launchdaemons")
)

_O_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", None)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", None)

_DIR_OPEN_FLAGS = (
    os.O_RDONLY | (_O_DIRECTORY or 0) | (_O_NOFOLLOW or 0) | (_O_CLOEXEC or 0)
)
_READ_FLAGS = (
    os.O_RDONLY | (_O_NOFOLLOW or 0) | (_O_CLOEXEC or 0) | (_O_NONBLOCK or 0)
)
_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | (_O_NOFOLLOW or 0)
    | (_O_CLOEXEC or 0)
    | (_O_NONBLOCK or 0)
)

_RENAME_EXCL = 0x00000004

NONCLAIMS = (
    "no-activation",
    "no-current-or-latest-selector",
    "no-environment-build",
    "no-data-root-access",
    "no-live-state-access",
    "no-migration",
    "no-provenance-authentication-inside-stager",
    "no-post-stage-immutability-claim",
    "no-orphan-operation-reclamation",
)


class _Blocked(Exception):
    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


class _OutcomeUnknown(Exception):
    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


class _CliArgumentError(Exception):
    pass


def _close_fd_quietly(descriptor: int) -> None:
    """Best-effort cleanup that never masks the exception being unwound."""
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except BaseException:
        pass


def _identity(observed: os.stat_result) -> tuple[int, int, int]:
    return (observed.st_dev, observed.st_ino, stat.S_IFMT(observed.st_mode))


def _fingerprint(
    observed: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_uid,
        observed.st_nlink,
        observed.st_mode,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
    )


def _is_private_directory(observed: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(observed.st_mode)
        and observed.st_uid == os.geteuid()
        and stat.S_IMODE(observed.st_mode) == 0o700
    )


def _is_private_regular(observed: os.stat_result) -> bool:
    return (
        stat.S_ISREG(observed.st_mode)
        and observed.st_uid == os.geteuid()
        and observed.st_nlink == 1
        and stat.S_IMODE(observed.st_mode) == 0o600
    )


def _canonical_absolute_path(value: object) -> str:
    if isinstance(value, Path):
        raw = str(value)
    elif isinstance(value, str):
        raw = value
    else:
        raise _Blocked("invalid-arguments")
    if (
        not raw
        or "\x00" in raw
        or not raw.startswith("/")
        or raw.startswith("//")
        or len(os.fsencode(raw)) > MAX_PATH_BYTES
        or posixpath.normpath(raw) != raw
        or raw == "/"
    ):
        raise _Blocked("invalid-arguments")
    parts = raw.split("/")[1:]
    if any(part in ("", ".", "..") for part in parts):
        raise _Blocked("invalid-arguments")
    return raw


def _is_within(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/")


def _validate_separation(paths: tuple[str, ...]) -> None:
    # Pure lexical validation by design: data/environment roots are authority
    # labels only and must never be traversed merely to prove separation.
    folded: set[str] = set()
    for path in paths:
        key = path.casefold()
        if key in folded:
            raise _Blocked("root-overlap")
        folded.add(key)
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            if _is_within(left, right) or _is_within(right, left):
                raise _Blocked("root-overlap")


def _reject_active_state_path(path: str) -> None:
    if any(
        component.casefold() in _FORBIDDEN_ACTIVE_COMPONENTS
        for component in path.split("/")[1:]
    ):
        raise _Blocked("active-state-path-forbidden")


class _UntouchedRootGuard:
    """Prove a root spelling has no symlinked component without opening leaf.

    This is used for *all* authority roots before any write.  For the data and
    environment roots the leaf is only lstat'ed: it is never opened, listed,
    read, or descended into.  Held no-follow ancestor descriptors plus an
    identity-only leaf recheck permit live contents to change while detecting
    a rename/symlink swap and Darwin aliases such as ``/tmp``.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._fds: list[int] = []
        self._chain: list[tuple[int, int, int]] = []
        self._components = tuple(path.split("/")[1:])
        self._leaf_parent_fd = -1
        self._leaf_name = ""
        self.leaf_identity: tuple[int, int, int] | None = None

    def open(self) -> None:
        try:
            anchor = os.open("/", _DIR_OPEN_FLAGS)
            # Register ownership before the first interruptible operation.
            self._fds.append(anchor)
            anchor_observed = os.fstat(anchor)
        except OSError:
            raise _Blocked("root-unsafe") from None
        self._chain.append(_identity(anchor_observed))
        parent = anchor
        for index, name in enumerate(self._components):
            try:
                observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except OSError:
                raise _Blocked("root-unsafe") from None
            if not stat.S_ISDIR(observed.st_mode):
                # A symlink alias is rejected, never resolved.
                raise _Blocked("root-alias-unsafe")
            identity = _identity(observed)
            self._chain.append(identity)
            if index == len(self._components) - 1:
                self._leaf_parent_fd = parent
                self._leaf_name = name
                self.leaf_identity = identity
                return
            try:
                child = os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent)
                # The guard owns the descriptor as soon as open returns.
                self._fds.append(child)
                held = os.fstat(child)
            except OSError:
                raise _Blocked("root-unsafe") from None
            if _identity(held) != identity:
                raise _Blocked("validation-race")
            parent = child
        raise _Blocked("root-unsafe")

    @property
    def chain(self) -> tuple[tuple[int, int, int], ...]:
        return tuple(self._chain)

    def recheck(self) -> None:
        if self.leaf_identity is None:
            raise _Blocked("validation-race")
        try:
            for index, descriptor in enumerate(self._fds):
                if _identity(os.fstat(descriptor)) != self._chain[index]:
                    raise _Blocked("validation-race")
                if index == 0:
                    continue
                parent = self._fds[index - 1]
                visible = os.stat(
                    self._components[index - 1],
                    dir_fd=parent,
                    follow_symlinks=False,
                )
                if _identity(visible) != self._chain[index]:
                    raise _Blocked("validation-race")
            leaf = os.stat(
                self._leaf_name,
                dir_fd=self._leaf_parent_fd,
                follow_symlinks=False,
            )
        except _Blocked:
            raise
        except OSError:
            raise _Blocked("validation-race") from None
        if (
            not stat.S_ISDIR(leaf.st_mode)
            or _identity(leaf) != self.leaf_identity
        ):
            raise _Blocked("validation-race")

    def close(self) -> None:
        while self._fds:
            _close_fd_quietly(self._fds.pop())


def _validate_physical_separation(guards: list[_UntouchedRootGuard]) -> None:
    for index, left in enumerate(guards):
        if left.leaf_identity is None:
            raise _Blocked("root-unsafe")
        for right in guards[index + 1 :]:
            if right.leaf_identity is None:
                raise _Blocked("root-unsafe")
            # Exact aliases and containment reached through a mount alias are
            # both caught: either root leaf appears in the other's held chain.
            if (
                left.leaf_identity in right.chain
                or right.leaf_identity in left.chain
            ):
                raise _Blocked("root-overlap")


class _HeldPrivateRoot:
    """A no-follow held descriptor chain for an explicit private root.

    Ancestors need not be private (``/private/tmp`` legitimately is shared),
    but none may be a symlink and the leaf must be exact owner-only 0700.
    Root mtime/ctime may change through this operation; identity, type,
    ownership, and mode may not.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = -1
        self._fds: list[int] = []
        self._anchor_identity: tuple[int, int, int] | None = None
        self._ancestors: list[tuple[int, str, int, tuple[int, int, int]]] = []
        self._parent_fd = -1
        self._name = ""
        self._identity: tuple[int, int, int] | None = None

    def open(self) -> None:
        try:
            anchor = os.open("/", _DIR_OPEN_FLAGS)
        except OSError:
            raise _Blocked("root-unsafe") from None
        self._fds.append(anchor)
        self._anchor_identity = _identity(os.fstat(anchor))
        parent = anchor
        components = self.path.split("/")[1:]
        for index, name in enumerate(components):
            try:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode):
                    raise _Blocked("root-unsafe")
                child = os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent)
                self._fds.append(child)
                held = os.fstat(child)
            except _Blocked:
                raise
            except OSError:
                raise _Blocked("root-unsafe") from None
            if _identity(before) != _identity(held):
                raise _Blocked("validation-race")
            if index == len(components) - 1:
                if not _is_private_directory(held):
                    raise _Blocked("root-not-private")
                self.fd = child
                self._parent_fd = parent
                self._name = name
                self._identity = _identity(held)
            else:
                self._ancestors.append(
                    (parent, name, child, _identity(held))
                )
            parent = child

    def recheck(self) -> None:
        try:
            if _identity(os.fstat(self._fds[0])) != self._anchor_identity:
                raise _Blocked("validation-race")
            for parent, name, held_fd, expected in self._ancestors:
                held = os.fstat(held_fd)
                visible = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if _identity(held) != expected or _identity(visible) != expected:
                    raise _Blocked("validation-race")
            held_root = os.fstat(self.fd)
            visible_root = os.stat(
                self._name, dir_fd=self._parent_fd, follow_symlinks=False
            )
        except _Blocked:
            raise
        except OSError:
            raise _Blocked("validation-race") from None
        if (
            _identity(held_root) != self._identity
            or _identity(visible_root) != self._identity
            or not _is_private_directory(held_root)
            or not _is_private_directory(visible_root)
        ):
            raise _Blocked("validation-race")

    def close(self) -> None:
        while self._fds:
            _close_fd_quietly(self._fds.pop())
        self.fd = -1


def _ensure_private_child(parent_fd: int, name: str) -> int:
    if not name or "/" in name or "\x00" in name:
        raise _Blocked("internal-layout-invalid")
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            # mkdir is umask-filtered and returns no descriptor.  Repair the
            # exact mode without following a substituted symlink, then bind
            # the name to a held descriptor and compare identities below.
            os.chmod(
                name,
                0o700,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            os.fsync(parent_fd)
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            raise _Blocked("stage-write-failed") from None
    except OSError:
        raise _Blocked("stage-write-failed") from None
    if not _is_private_directory(before):
        raise _Blocked("stage-root-unsafe")
    child = -1
    try:
        child = os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
        held = os.fstat(child)
        if (
            _fingerprint(held) != _fingerprint(before)
            or not _is_private_directory(held)
        ):
            raise _Blocked("validation-race")
        result = child
        child = -1
        return result
    except _Blocked:
        raise
    except OSError:
        raise _Blocked("stage-write-failed") from None
    finally:
        _close_fd_quietly(child)


def _open_private_child(parent_fd: int, name: str) -> int:
    child = -1
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not _is_private_directory(before):
            raise _Blocked("stage-root-unsafe")
        child = os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
        held = os.fstat(child)
        if _fingerprint(held) != _fingerprint(before):
            raise _Blocked("validation-race")
        result = child
        child = -1
        return result
    except _Blocked:
        raise
    except OSError:
        raise _Blocked("stage-write-failed") from None
    finally:
        _close_fd_quietly(child)


def _open_private_regular(
    parent_fd: int, name: str, *, create: bool, append: bool = False
) -> int:
    flags = os.O_RDWR | (_O_NOFOLLOW or 0) | (_O_CLOEXEC or 0)
    if append:
        flags |= os.O_APPEND
    created = False
    descriptor = -1
    try:
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            if not create:
                raise _Blocked("journal-unsafe") from None
            descriptor = os.open(
                name,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            created = True
            # Correct even under an adversarial umask.
            os.fchmod(descriptor, 0o600)
            os.fsync(parent_fd)
        else:
            if not _is_private_regular(before):
                raise _Blocked("journal-unsafe")
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        held = os.fstat(descriptor)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not _is_private_regular(held)
            or _fingerprint(held) != _fingerprint(visible)
            or (created and stat.S_IMODE(held.st_mode) != 0o600)
        ):
            raise _Blocked("journal-unsafe")
        result = descriptor
        descriptor = -1
        return result
    except _Blocked:
        raise
    except OSError:
        raise _Blocked("journal-unsafe") from None
    finally:
        _close_fd_quietly(descriptor)


class _HeldIncumbentCodeDirectory:
    """Held, no-follow trust anchor for this script and its planner sibling."""

    def __init__(self) -> None:
        self.script_path = _canonical_absolute_path(__file__)
        if self.script_path.rsplit("/", 1)[-1] != "release_stage.py":
            raise _Blocked("trusted-planner-unsafe")
        self.directory_path = self.script_path.rsplit("/", 1)[0]
        self.planner_path = self.directory_path + "/release_update_plan.py"
        self._fds: list[int] = []
        self.directory_fd = -1
        self.stage_fd = -1
        self.planner_fd = -1
        self._anchor_identity: tuple | None = None
        self._ancestors: list[tuple[int, str, int, tuple]] = []
        self._directory_parent_fd = -1
        self._directory_name = ""
        self._directory_fingerprint: tuple | None = None
        self._stage_fingerprint: tuple | None = None
        self._planner_fingerprint: tuple | None = None

    def _open_regular(self, name: str, maximum_bytes: int) -> tuple[int, tuple]:
        descriptor = -1
        try:
            before = os.stat(
                name, dir_fd=self.directory_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or before.st_mode & 0o022
                or before.st_size > maximum_bytes
            ):
                raise _Blocked("trusted-planner-unsafe")
            descriptor = os.open(name, _READ_FLAGS, dir_fd=self.directory_fd)
            held = os.fstat(descriptor)
            if _fingerprint(held) != _fingerprint(before):
                raise _Blocked("trusted-planner-raced")
            fingerprint = _fingerprint(held)
            self._fds.append(descriptor)
            descriptor = -1
            return self._fds[-1], fingerprint
        except _Blocked:
            raise
        except OSError:
            raise _Blocked("trusted-planner-unsafe") from None
        finally:
            _close_fd_quietly(descriptor)

    def open(self) -> None:
        components = tuple(self.directory_path.split("/")[1:])
        if not components:
            raise _Blocked("trusted-planner-unsafe")
        try:
            anchor = os.open("/", _DIR_OPEN_FLAGS)
        except OSError:
            raise _Blocked("trusted-planner-unsafe") from None
        self._fds.append(anchor)
        self._anchor_identity = _identity(os.fstat(anchor))
        parent = anchor
        for index, name in enumerate(components):
            try:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode):
                    raise _Blocked("trusted-planner-unsafe")
                child = os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent)
                self._fds.append(child)
                held = os.fstat(child)
            except _Blocked:
                raise
            except OSError:
                raise _Blocked("trusted-planner-unsafe") from None
            if _identity(held) != _identity(before):
                raise _Blocked("trusted-planner-raced")
            if index == len(components) - 1:
                if (
                    held.st_uid != os.geteuid()
                    or held.st_mode & 0o022
                ):
                    raise _Blocked("trusted-planner-unsafe")
                self.directory_fd = child
                self._directory_parent_fd = parent
                self._directory_name = name
                self._directory_fingerprint = _fingerprint(held)
            else:
                self._ancestors.append(
                    (parent, name, child, _identity(held))
                )
            parent = child
        self.stage_fd, self._stage_fingerprint = self._open_regular(
            "release_stage.py", 4 * 1024 * 1024
        )
        self.planner_fd, self._planner_fingerprint = self._open_regular(
            "release_update_plan.py", 4 * 1024 * 1024
        )

    def read_planner(self) -> bytes:
        try:
            observed = os.fstat(self.planner_fd)
            remaining = observed.st_size
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(
                    self.planner_fd, min(remaining, 1024 * 1024)
                )
                if not chunk:
                    raise _Blocked("trusted-planner-raced")
                chunks.append(chunk)
                remaining -= len(chunk)
        except _Blocked:
            raise
        except OSError:
            raise _Blocked("trusted-planner-raced") from None
        if _fingerprint(os.fstat(self.planner_fd)) != self._planner_fingerprint:
            raise _Blocked("trusted-planner-raced")
        return b"".join(chunks)

    def recheck(self) -> None:
        try:
            if _identity(os.fstat(self._fds[0])) != self._anchor_identity:
                raise _Blocked("trusted-planner-raced")
            for parent, name, held_fd, expected in self._ancestors:
                held = os.fstat(held_fd)
                visible = os.stat(
                    name, dir_fd=parent, follow_symlinks=False
                )
                if _identity(held) != expected or _identity(visible) != expected:
                    raise _Blocked("trusted-planner-raced")
            held_directory = os.fstat(self.directory_fd)
            visible_directory = os.stat(
                self._directory_name,
                dir_fd=self._directory_parent_fd,
                follow_symlinks=False,
            )
            held_stage = os.fstat(self.stage_fd)
            visible_stage = os.stat(
                "release_stage.py",
                dir_fd=self.directory_fd,
                follow_symlinks=False,
            )
            held_planner = os.fstat(self.planner_fd)
            visible_planner = os.stat(
                "release_update_plan.py",
                dir_fd=self.directory_fd,
                follow_symlinks=False,
            )
        except _Blocked:
            raise
        except OSError:
            raise _Blocked("trusted-planner-raced") from None
        if (
            _fingerprint(held_directory) != self._directory_fingerprint
            or _fingerprint(visible_directory) != self._directory_fingerprint
            or _fingerprint(held_stage) != self._stage_fingerprint
            or _fingerprint(visible_stage) != self._stage_fingerprint
            or _fingerprint(held_planner) != self._planner_fingerprint
            or _fingerprint(visible_planner) != self._planner_fingerprint
        ):
            raise _Blocked("trusted-planner-raced")

    def close(self) -> None:
        while self._fds:
            _close_fd_quietly(self._fds.pop())


def _load_incumbent_planner() -> ModuleType:
    """Execute exact held bytes from the incumbent sibling planner only."""
    anchor: _HeldIncumbentCodeDirectory | None = None
    original_dont_write_bytecode = sys.dont_write_bytecode
    original_sys_path = list(sys.path)
    try:
        anchor = _HeldIncumbentCodeDirectory()
        anchor.open()
        source = anchor.read_planner()
        anchor.recheck()
        if hashlib.sha256(source).hexdigest() != TRUSTED_PLANNER_SHA256:
            raise _Blocked("trusted-planner-identity-mismatch")
        code = compile(
            source,
            anchor.planner_path,
            "exec",
            dont_inherit=True,
            optimize=0,
        )
        # Compilation is deliberately separated from execution by another
        # full visible/held identity check.  Even trusted pinned bytes must
        # not begin executing after their incumbent directory was swapped.
        anchor.recheck()
        module = ModuleType("_synapse_s2_incumbent_release_update_plan")
        module.__file__ = anchor.planner_path
        module.__package__ = None
        sys.dont_write_bytecode = True
        exec(code, module.__dict__)
        anchor.recheck()
    except _Blocked:
        raise
    except Exception:
        raise _Blocked("trusted-planner-unavailable") from None
    finally:
        sys.path[:] = original_sys_path
        sys.dont_write_bytecode = original_dont_write_bytecode
        if anchor is not None:
            anchor.close()
    return module


def _validate_planner(planner: ModuleType) -> None:
    try:
        if planner.PRODUCT_SCHEMA != "synapse-s2.product-release-plan.v1":
            raise ValueError
        inventory = planner.PRODUCT_INVENTORY
        if not isinstance(inventory, tuple) or not inventory:
            raise ValueError
        integer_bounds = {
            "MAX_PRODUCT_TOTAL_BYTES": (1, 1024 * 1024 * 1024),
            "MAX_PRODUCT_SCANNED_NAME_BYTES": (1, 64 * 1024 * 1024),
            "MAX_PRODUCT_DIRECTORY_ENTRIES": (1, 65536),
            "MAX_PRODUCT_NAME_BYTES": (1, 65536),
        }
        for name, (minimum, maximum) in integer_bounds.items():
            value = getattr(planner, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError
        callables = (
            "plan_product_release",
            "_inventory_policy_id",
            "_validate_product_inventory",
            "_product_directory_map",
            "_product_identity",
        )
        if any(not callable(getattr(planner, name)) for name in callables):
            raise ValueError
        inspect.signature(planner.plan_product_release).bind(
            Path("/__synapse_s2_current_probe__"),
            Path("/__synapse_s2_candidate_probe__"),
            expected_candidate_product_id=None,
        )
        inspect.signature(planner._inventory_policy_id).bind()
        inspect.signature(planner._validate_product_inventory).bind()
        inspect.signature(planner._product_directory_map).bind()
        inspect.signature(planner._product_identity).bind([])
        snapshot = planner._RootSnapshot
        if not isinstance(snapshot, type):
            raise ValueError
        inspect.signature(snapshot).bind(
            Path("/__synapse_s2_snapshot_probe__")
        )
        method_arguments = {
            "open_root": (),
            "read_file_with_stat": ("probe", {"remaining": 1}),
            "recheck": (),
            "close": (),
            "_directory_fd": ((),),
        }
        for name, arguments in method_arguments.items():
            method = getattr(snapshot, name)
            if not callable(method):
                raise ValueError
            inspect.signature(method).bind(None, *arguments)
        planner._validate_product_inventory()
        directory_map = planner._product_directory_map()
        if not isinstance(directory_map, dict) or not directory_map:
            raise ValueError
        for key, value in directory_map.items():
            if (
                not isinstance(key, tuple)
                or not all(isinstance(part, str) for part in key)
                or not isinstance(value, tuple)
                or len(value) != 2
                or not all(isinstance(item, frozenset) for item in value)
            ):
                raise ValueError
        policy_id = planner._inventory_policy_id()
        if (
            not isinstance(policy_id, str)
            or _POLICY_ID_RE.fullmatch(policy_id) is None
        ):
            raise ValueError
        empty_identity = planner._product_identity([])
        if (
            not isinstance(empty_identity, dict)
            or _PRODUCT_ID_RE.fullmatch(
                str(empty_identity.get("product_id"))
            )
            is None
            or not isinstance(empty_identity.get("component_ids"), dict)
        ):
            raise ValueError
    except Exception:
        raise _Blocked("trusted-planner-incompatible") from None


def _validate_product_plan(
    plan: object, expected_product_id: str, expected_policy_id: str
) -> None:
    if not isinstance(plan, dict):
        raise _Blocked("candidate-verification-failed")
    candidate = plan.get("candidate")
    if (
        plan.get("schema") != "synapse-s2.product-release-plan.v1"
        or plan.get("mode") != "read-only-product-inventory"
        or plan.get("status") not in ("no-update", "update-available")
        or plan.get("apply_supported") is not False
        or plan.get("apply_performed") is not False
        or plan.get("inventory_policy_id") != expected_policy_id
        or not isinstance(candidate, dict)
        or candidate.get("product_id") != expected_product_id
    ):
        raise _Blocked("candidate-verification-failed")


def _verify_candidate(
    planner: ModuleType,
    current_root: str,
    candidate_root: str,
    expected_product_id: str,
    expected_policy_id: str,
) -> dict:
    try:
        plan = planner.plan_product_release(
            Path(current_root),
            Path(candidate_root),
            expected_candidate_product_id=expected_product_id,
        )
    except Exception:
        raise _Blocked("candidate-verification-failed") from None
    _validate_product_plan(plan, expected_product_id, expected_policy_id)
    return plan


def _verify_staged(
    planner: ModuleType,
    candidate_root: str,
    staged_root: str,
    expected_product_id: str,
    expected_policy_id: str,
) -> None:
    try:
        plan = planner.plan_product_release(
            Path(candidate_root),
            Path(staged_root),
            expected_candidate_product_id=expected_product_id,
        )
    except Exception:
        raise _Blocked("staged-verification-failed") from None
    _validate_product_plan(plan, expected_product_id, expected_policy_id)
    current = plan.get("current")
    candidate = plan.get("candidate")
    if (
        plan.get("status") != "no-update"
        or not isinstance(current, dict)
        or not isinstance(candidate, dict)
        or current.get("product_id") != expected_product_id
        or candidate.get("product_id") != expected_product_id
        or plan.get("changed_path_count") != 0
    ):
        raise _Blocked("staged-verification-failed")


def _verify_exact_staged_tree(
    planner: ModuleType, staged_root: str, expected_product_id: str
) -> None:
    """Reverify the published object with *no* planner root exemptions.

    Product planning intentionally tolerates top-level ``.git`` metadata in
    pre-extracted inputs.  An installed release object does not: it is the
    exact inventory and nothing else.  This held-descriptor scan therefore
    closes that final gap for both newly built and previously visible stages.
    """
    snapshot = None
    try:
        planner._validate_product_inventory()
        snapshot = planner._RootSnapshot(Path(staged_root))
        snapshot.open_root()
        budget = {"remaining": int(planner.MAX_PRODUCT_TOTAL_BYTES)}
        records: list[tuple] = []
        for component, role, path in planner.PRODUCT_INVENTORY:
            payload, observed = snapshot.read_file_with_stat(path, budget)
            records.append(
                (
                    component,
                    role,
                    path,
                    format(stat.S_IMODE(observed.st_mode), "04o"),
                    observed.st_size,
                    hashlib.sha256(payload).hexdigest(),
                )
            )
        name_budget = int(planner.MAX_PRODUCT_SCANNED_NAME_BYTES)
        for key, expected in sorted(planner._product_directory_map().items()):
            expected_files, expected_directories = expected
            descriptor = snapshot._directory_fd(key)
            names: list[str] = []
            folded: set[str] = set()
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if len(names) >= int(planner.MAX_PRODUCT_DIRECTORY_ENTRIES):
                        raise _Blocked("staged-tree-oversize")
                    name = entry.name
                    if (
                        not isinstance(name, str)
                        or not name
                        or not name.isascii()
                        or "\x00" in name
                        or len(name.encode("ascii"))
                        > int(planner.MAX_PRODUCT_NAME_BYTES)
                    ):
                        raise _Blocked("staged-tree-unsafe")
                    name_budget -= len(name.encode("ascii"))
                    if name_budget < 0:
                        raise _Blocked("staged-tree-oversize")
                    folded_name = name.casefold()
                    if folded_name in folded:
                        raise _Blocked("staged-tree-unsafe")
                    folded.add(folded_name)
                    names.append(name)
            if frozenset(names) != expected_files | expected_directories:
                raise _Blocked("staged-tree-not-exact")
        snapshot.recheck()
        identity = planner._product_identity(records)
        if (
            not isinstance(identity, dict)
            or identity.get("product_id") != expected_product_id
        ):
            raise _Blocked("staged-verification-failed")
    except _Blocked:
        raise
    except Exception:
        raise _Blocked("staged-verification-failed") from None
    finally:
        if snapshot is not None:
            try:
                snapshot.close()
            except Exception:
                pass


class _DestinationTree:
    def __init__(self, root_fd: int) -> None:
        self.root_fd = root_fd
        self._directories: dict[tuple[str, ...], int] = {(): root_fd}
        self._opened: list[int] = []

    def _directory(self, parts: tuple[str, ...]) -> int:
        parent = self.root_fd
        for depth, name in enumerate(parts):
            key = parts[: depth + 1]
            known = self._directories.get(key)
            if known is not None:
                parent = known
                continue
            child = -1
            try:
                try:
                    os.mkdir(name, 0o700, dir_fd=parent)
                    os.chmod(
                        name,
                        0o700,
                        dir_fd=parent,
                        follow_symlinks=False,
                    )
                    os.fsync(parent)
                    child = os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent)
                    os.fchmod(child, 0o700)
                    observed = os.fstat(child)
                    visible = os.stat(
                        name, dir_fd=parent, follow_symlinks=False
                    )
                except OSError:
                    raise _Blocked("stage-write-failed") from None
                if (
                    not _is_private_directory(observed)
                    or _fingerprint(observed) != _fingerprint(visible)
                ):
                    raise _Blocked("validation-race")
                self._opened.append(child)
                self._directories[key] = child
            except BaseException:
                # Roll back either a local acquisition or a partially
                # completed ownership transfer before propagating.
                self._directories.pop(key, None)
                if self._opened and self._opened[-1] == child:
                    self._opened.pop()
                _close_fd_quietly(child)
                raise
            parent = child
        return parent

    def write_file(self, relative_path: str, payload: bytes, mode: int) -> None:
        parts = tuple(relative_path.split("/"))
        if (
            not parts
            or any(part in ("", ".", "..") for part in parts)
            or not all(part.isascii() for part in parts)
        ):
            raise _Blocked("trusted-inventory-invalid")
        parent = self._directory(parts[:-1])
        leaf = parts[-1]
        descriptor = -1
        try:
            descriptor = os.open(
                leaf, _WRITE_FLAGS, 0o600, dir_fd=parent
            )
            os.fchmod(descriptor, mode)
            offset = 0
            while offset < len(payload):
                written = os.write(
                    descriptor,
                    payload[offset : offset + MAX_WRITE_CHUNK_BYTES],
                )
                if written <= 0:
                    raise OSError(errno.EIO, "short write")
                offset += written
            os.fsync(descriptor)
            held = os.fstat(descriptor)
            visible = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except OSError:
            raise _Blocked("stage-write-failed") from None
        finally:
            _close_fd_quietly(descriptor)
        if (
            not stat.S_ISREG(held.st_mode)
            or held.st_uid != os.geteuid()
            or held.st_nlink != 1
            or stat.S_IMODE(held.st_mode) != mode
            or held.st_size != len(payload)
            or _fingerprint(held) != _fingerprint(visible)
        ):
            raise _Blocked("stage-write-failed")

    def sync(self) -> None:
        try:
            for key in sorted(self._directories, key=len, reverse=True):
                os.fsync(self._directories[key])
        except OSError:
            raise _Blocked("stage-write-failed") from None

    def close(self) -> None:
        while self._opened:
            _close_fd_quietly(self._opened.pop())


def _copy_inventory(
    planner: ModuleType, candidate_root: str, operation_fd: int
) -> None:
    snapshot = None
    destination = _DestinationTree(operation_fd)
    try:
        planner._validate_product_inventory()
        snapshot = planner._RootSnapshot(Path(candidate_root))
        snapshot.open_root()
        budget = {"remaining": int(planner.MAX_PRODUCT_TOTAL_BYTES)}
        for entry in planner.PRODUCT_INVENTORY:
            if (
                not isinstance(entry, tuple)
                or len(entry) != 3
                or not isinstance(entry[2], str)
            ):
                raise _Blocked("trusted-inventory-invalid")
            path = entry[2]
            payload, observed = snapshot.read_file_with_stat(path, budget)
            destination.write_file(
                path, payload, stat.S_IMODE(observed.st_mode)
            )
        snapshot.recheck()
        destination.sync()
    except _Blocked:
        raise
    except Exception:
        raise _Blocked("source-copy-failed") from None
    finally:
        destination.close()
        if snapshot is not None:
            try:
                snapshot.close()
            except Exception:
                pass


def _exclusive_rename_darwin(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx = getattr(libc, "renameatx_np", None)
    if renameatx is None:
        raise _Blocked("exclusive-publish-unavailable")
    renameatx.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameatx.restype = ctypes.c_int
    result = renameatx(
        source_parent_fd,
        os.fsencode(source_name),
        destination_parent_fd,
        os.fsencode(destination_name),
        _RENAME_EXCL,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, "exclusive rename failed")


def _existing_release_fd(releases_fd: int, product_id: str) -> int | None:
    try:
        before = os.stat(product_id, dir_fd=releases_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise _Blocked("release-state-unsafe") from None
    if not _is_private_directory(before):
        raise _Blocked("release-state-unsafe")
    descriptor = -1
    try:
        descriptor = os.open(product_id, _DIR_OPEN_FLAGS, dir_fd=releases_fd)
        held = os.fstat(descriptor)
        if _fingerprint(held) != _fingerprint(before):
            raise _Blocked("validation-race")
        result = descriptor
        descriptor = -1
        return result
    except _Blocked:
        raise
    except OSError:
        raise _Blocked("release-state-unsafe") from None
    finally:
        _close_fd_quietly(descriptor)


def _recheck_visible_release(
    releases_fd: int, product_id: str, held_fd: int
) -> None:
    try:
        held = os.fstat(held_fd)
        visible = os.stat(
            product_id, dir_fd=releases_fd, follow_symlinks=False
        )
    except OSError:
        raise _OutcomeUnknown("published-release-raced") from None
    if (
        _fingerprint(held) != _fingerprint(visible)
        or not _is_private_directory(held)
    ):
        raise _OutcomeUnknown("published-release-raced")


def _operation_still_visible(
    operations_fd: int, operation_name: str, held_fd: int
) -> bool:
    try:
        visible = os.stat(
            operation_name, dir_fd=operations_fd, follow_symlinks=False
        )
        held = os.fstat(held_fd)
    except FileNotFoundError:
        return False
    except OSError:
        raise _OutcomeUnknown("publish-state-ambiguous") from None
    if not _is_private_directory(visible):
        raise _OutcomeUnknown("publish-state-ambiguous")
    return _fingerprint(visible) == _fingerprint(held)


def _journal_unsigned(entry: dict) -> bytes:
    return json.dumps(
        entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _journal_hash(entry: dict) -> str:
    return hashlib.sha256(_JOURNAL_HASH_DOMAIN + _journal_unsigned(entry)).hexdigest()


def _parse_journal(payload: bytes) -> list[dict]:
    if len(payload) > MAX_JOURNAL_BYTES:
        raise _Blocked("journal-oversize")
    if not payload:
        return []
    if not payload.endswith(b"\n"):
        raise _Blocked("journal-malformed")
    lines = payload[:-1].split(b"\n")
    if len(lines) > MAX_JOURNAL_ENTRIES:
        raise _Blocked("journal-oversize")
    entries: list[dict] = []
    previous = "0" * 64
    for index, line in enumerate(lines, 1):
        try:
            decoded = line.decode("ascii")
            entry = json.loads(decoded)
        except Exception:
            raise _Blocked("journal-malformed") from None
        if not isinstance(entry, dict) or set(entry) != {
            "schema",
            "sequence",
            "previous_hash",
            "product_id",
            "inventory_policy_id",
            "release_state",
            "entry_hash",
        }:
            raise _Blocked("journal-malformed")
        unsigned = dict(entry)
        entry_hash = unsigned.pop("entry_hash")
        if (
            entry.get("schema") != JOURNAL_SCHEMA
            or entry.get("sequence") != index
            or isinstance(entry.get("sequence"), bool)
            or entry.get("previous_hash") != previous
            or _PRODUCT_ID_RE.fullmatch(str(entry.get("product_id"))) is None
            or _POLICY_ID_RE.fullmatch(
                str(entry.get("inventory_policy_id"))
            )
            is None
            or entry.get("release_state") not in ("staged", "reconciled")
            or _JOURNAL_HASH_RE.fullmatch(str(entry_hash)) is None
            or _journal_hash(unsigned) != entry_hash
            or _journal_unsigned(entry) != line
        ):
            raise _Blocked("journal-malformed")
        previous = entry_hash
        entries.append(entry)
    return entries


def _read_all_bounded(descriptor: int, bound: int) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, bound + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > bound:
                raise _Blocked("journal-oversize")
    except _Blocked:
        raise
    except OSError:
        raise _Blocked("journal-read-failed") from None


class _Journal:
    def __init__(self, root_fd: int) -> None:
        self.root_fd = root_fd
        self.lock_fd = -1
        self.data_fd = -1
        self.entries: list[dict] = []
        self._payload = b""
        self._lock_fingerprint: tuple | None = None
        self._data_fingerprint: tuple | None = None

    def _recheck_lock(self) -> None:
        try:
            held = os.fstat(self.lock_fd)
            visible = os.stat(
                "release-stage.lock",
                dir_fd=self.root_fd,
                follow_symlinks=False,
            )
        except OSError:
            raise _OutcomeUnknown("journal-lock-raced") from None
        if (
            self._lock_fingerprint is None
            or _fingerprint(held) != self._lock_fingerprint
            or _fingerprint(visible) != self._lock_fingerprint
        ):
            raise _OutcomeUnknown("journal-lock-raced")

    def _recheck_data(self) -> None:
        try:
            held = os.fstat(self.data_fd)
            visible = os.stat(
                "release-stage.jsonl",
                dir_fd=self.root_fd,
                follow_symlinks=False,
            )
        except OSError:
            raise _OutcomeUnknown("journal-file-raced") from None
        if (
            self._data_fingerprint is None
            or _fingerprint(held) != self._data_fingerprint
            or _fingerprint(visible) != self._data_fingerprint
        ):
            raise _OutcomeUnknown("journal-file-raced")

    def open(self) -> None:
        self.lock_fd = _open_private_regular(
            self.root_fd, "release-stage.lock", create=True
        )
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
        except OSError:
            raise _Blocked("journal-lock-failed") from None
        # Lock the stable visible inode, not an unlinked/replaced predecessor.
        try:
            visible = os.stat(
                "release-stage.lock",
                dir_fd=self.root_fd,
                follow_symlinks=False,
            )
            held = os.fstat(self.lock_fd)
        except OSError:
            raise _Blocked("journal-lock-failed") from None
        if _fingerprint(visible) != _fingerprint(held):
            raise _Blocked("journal-lock-raced")
        self._lock_fingerprint = _fingerprint(held)
        self.data_fd = _open_private_regular(
            self.root_fd,
            "release-stage.jsonl",
            create=True,
            append=True,
        )
        self._data_fingerprint = _fingerprint(os.fstat(self.data_fd))
        self._recheck_lock()
        try:
            payload = _read_all_bounded(self.data_fd, MAX_JOURNAL_BYTES)
            self._recheck_data()
            self.entries = _parse_journal(payload)
            self._payload = payload
        except _OutcomeUnknown:
            raise
        except _Blocked as blocked:
            if blocked.token in (
                "journal-malformed",
                "journal-read-failed",
                "journal-oversize",
            ):
                raise _OutcomeUnknown(blocked.token) from None
            raise

    def has_release(self, product_id: str, policy_id: str) -> bool:
        return any(
            entry["product_id"] == product_id
            and entry["inventory_policy_id"] == policy_id
            for entry in self.entries
        )

    def append(
        self, product_id: str, policy_id: str, release_state: str
    ) -> None:
        if len(self.entries) >= MAX_JOURNAL_ENTRIES:
            raise _Blocked("journal-oversize")
        self._recheck_lock()
        self._recheck_data()
        # Bind this append to the exact byte preimage parsed under the lock,
        # not merely to inode metadata.  An uncooperative same-UID writer can
        # ignore flock; it must never be silently incorporated into our chain.
        if _read_all_bounded(self.data_fd, MAX_JOURNAL_BYTES) != self._payload:
            raise _OutcomeUnknown("journal-cas-mismatch")
        self._recheck_data()
        previous = (
            self.entries[-1]["entry_hash"] if self.entries else "0" * 64
        )
        unsigned = {
            "schema": JOURNAL_SCHEMA,
            "sequence": len(self.entries) + 1,
            "previous_hash": previous,
            "product_id": product_id,
            "inventory_policy_id": policy_id,
            "release_state": release_state,
        }
        entry = dict(unsigned)
        entry["entry_hash"] = _journal_hash(unsigned)
        line = _journal_unsigned(entry) + b"\n"
        expected_payload = self._payload + line
        try:
            end = os.lseek(self.data_fd, 0, os.SEEK_END)
            if end != len(self._payload):
                raise _OutcomeUnknown("journal-cas-mismatch")
            if len(expected_payload) > MAX_JOURNAL_BYTES:
                raise _Blocked("journal-oversize")
            offset = 0
            while offset < len(line):
                written = os.write(self.data_fd, line[offset:])
                if written <= 0:
                    raise OSError(errno.EIO, "short write")
                offset += written
            os.fsync(self.data_fd)
            os.fsync(self.root_fd)
            visible = os.stat(
                "release-stage.jsonl",
                dir_fd=self.root_fd,
                follow_symlinks=False,
            )
            committed_fingerprint = _fingerprint(os.fstat(self.data_fd))
            if _fingerprint(visible) != committed_fingerprint:
                raise OSError(errno.EIO, "journal identity changed")
            observed_payload = _read_all_bounded(
                self.data_fd, MAX_JOURNAL_BYTES
            )
            after_read = _fingerprint(os.fstat(self.data_fd))
            visible_after_read = _fingerprint(
                os.stat(
                    "release-stage.jsonl",
                    dir_fd=self.root_fd,
                    follow_symlinks=False,
                )
            )
            if (
                after_read != committed_fingerprint
                or visible_after_read != committed_fingerprint
            ):
                raise _OutcomeUnknown("journal-cas-mismatch")
            if observed_payload != expected_payload:
                raise _OutcomeUnknown("journal-cas-mismatch")
            parsed = _parse_journal(observed_payload)
            if parsed != self.entries + [entry]:
                raise _OutcomeUnknown("journal-cas-mismatch")
        except _Blocked:
            raise
        except _OutcomeUnknown:
            raise
        except OSError:
            # At least one byte may be durable.  Never report an ordinary
            # failure that could invite a blind retry over ambiguous state.
            raise _OutcomeUnknown("journal-commit-ambiguous") from None
        self._data_fingerprint = committed_fingerprint
        self._recheck_lock()
        self._recheck_data()
        self._payload = expected_payload
        self.entries.append(entry)

    def close(self) -> None:
        for descriptor in (self.data_fd, self.lock_fd):
            _close_fd_quietly(descriptor)
        self.data_fd = -1
        self.lock_fd = -1


def _result(
    status: str,
    reason: str,
    product_id: str | None,
    policy_id: str | None,
    *,
    source_staged: bool = False,
    resumed: bool = False,
    reconciled: bool = False,
    journal_committed: bool = False,
) -> dict:
    return {
        "schema": RESULT_SCHEMA,
        "mode": RESULT_MODE,
        "status": status,
        "reason": reason,
        "product_id": product_id,
        "inventory_policy_id": policy_id,
        "source_staged": source_staged,
        "identity_pin_verified": source_staged,
        "journal_committed": journal_committed,
        "resumed": resumed,
        "reconciled": reconciled,
        "environment_stage_supported": False,
        "environment_built": False,
        "activation_supported": False,
        "activation_performed": False,
        "live_state_modified": False,
        "nonclaims": list(NONCLAIMS),
    }


def _unsupported(token: str) -> dict:
    return _result(STATUS_UNSUPPORTED, "unsupported:" + token, None, None)


def _unknown(
    token: str, product_id: str | None, policy_id: str | None
) -> dict:
    return _result(
        STATUS_OUTCOME_UNKNOWN,
        "outcome_unknown:" + token,
        product_id,
        policy_id,
    )


def stage_release(
    *,
    current_source_root: str | Path,
    candidate_source_root: str | Path,
    install_root: str | Path,
    environment_root: str | Path,
    data_root: str | Path,
    journal_root: str | Path,
    expected_product_id: str,
    expected_inventory_policy_id: str,
    platform_system: str | None = None,
    platform_machine: str | None = None,
    exclusive_rename: Callable[[int, str, int, str], None] | None = None,
) -> dict:
    """Verify and publish one inactive source release.

    ``environment_root`` and ``data_root`` are validated lexically and by
    no-follow leaf identity for separation.  Their leaf directories are never
    opened, listed, resolved through symlinks, descended into, or written.
    They reserve distinct authority domains for later slices.
    """
    install: _HeldPrivateRoot | None = None
    journal_root_handle: _HeldPrivateRoot | None = None
    journal: _Journal | None = None
    operations_fd = -1
    releases_fd = -1
    operation_fd = -1
    published_fd = -1
    product_id: str | None = None
    policy_id: str | None = None
    publication_visible = False
    root_guards: list[_UntouchedRootGuard] = []
    try:
        current = _canonical_absolute_path(current_source_root)
        candidate = _canonical_absolute_path(candidate_source_root)
        install_path = _canonical_absolute_path(install_root)
        environment_path = _canonical_absolute_path(environment_root)
        data_path = _canonical_absolute_path(data_root)
        journal_path = _canonical_absolute_path(journal_root)
        _validate_separation(
            (
                current,
                candidate,
                install_path,
                environment_path,
                data_path,
                journal_path,
            )
        )
        for touched_path in (current, candidate, install_path, journal_path):
            _reject_active_state_path(touched_path)
        if (
            not isinstance(expected_product_id, str)
            or _PRODUCT_ID_RE.fullmatch(expected_product_id) is None
            or not isinstance(expected_inventory_policy_id, str)
            or _POLICY_ID_RE.fullmatch(expected_inventory_policy_id) is None
        ):
            raise _Blocked("invalid-arguments")
        product_id = expected_product_id
        policy_id = expected_inventory_policy_id

        if platform_system is None or platform_machine is None:
            uname = os.uname()
            platform_system = uname.sysname
            platform_machine = uname.machine
        if platform_system != "Darwin" or platform_machine != "arm64":
            raise _Blocked("platform-unsupported")
        if None in (_O_DIRECTORY, _O_NOFOLLOW, _O_CLOEXEC, _O_NONBLOCK):
            raise _Blocked("platform-unsupported")

        for path in (
            current,
            candidate,
            install_path,
            environment_path,
            data_path,
            journal_path,
        ):
            guard = _UntouchedRootGuard(path)
            try:
                guard.open()
            except BaseException:
                # ``open`` intentionally retains ancestor descriptors for
                # later identity rechecks.  If it fails part way through,
                # the guard has not yet been registered with the outer
                # cleanup path, so close that partial chain here.
                guard.close()
                raise
            root_guards.append(guard)
        _validate_physical_separation(root_guards)

        trusted_planner = _load_incumbent_planner()
        _validate_planner(trusted_planner)
        try:
            embedded_policy = trusted_planner._inventory_policy_id()
        except Exception:
            raise _Blocked("trusted-planner-incompatible") from None
        if embedded_policy != policy_id:
            raise _Blocked("inventory-policy-mismatch")
        _verify_candidate(
            trusted_planner, current, candidate, product_id, policy_id
        )

        install = _HeldPrivateRoot(install_path)
        install.open()
        journal_root_handle = _HeldPrivateRoot(journal_path)
        journal_root_handle.open()
        if _identity(os.fstat(install.fd)) == _identity(
            os.fstat(journal_root_handle.fd)
        ):
            raise _Blocked("root-overlap")
        operations_fd = _ensure_private_child(install.fd, "operations")
        releases_fd = _ensure_private_child(install.fd, "releases")

        journal = _Journal(journal_root_handle.fd)
        journal.open()

        existing_fd = _existing_release_fd(releases_fd, product_id)
        if existing_fd is not None:
            published_fd = existing_fd
            publication_visible = True
            _verify_staged(
                trusted_planner,
                candidate,
                install_path + "/releases/" + product_id,
                product_id,
                policy_id,
            )
            _verify_exact_staged_tree(
                trusted_planner,
                install_path + "/releases/" + product_id,
                product_id,
            )
            _recheck_visible_release(releases_fd, product_id, published_fd)
            reconciled = not journal.has_release(product_id, policy_id)
            if reconciled:
                journal.append(product_id, policy_id, "reconciled")
            install.recheck()
            journal_root_handle.recheck()
            for guard in root_guards:
                guard.recheck()
            # The journal commit and authority-root checks are not a release
            # visibility lock.  Rebind the success claim to the held release,
            # then prove exact inventory closure, then rebind once more so a
            # post-journal name or content substitution cannot be reported as
            # already staged.
            _recheck_visible_release(releases_fd, product_id, published_fd)
            try:
                _verify_exact_staged_tree(
                    trusted_planner,
                    install_path + "/releases/" + product_id,
                    product_id,
                )
            except _Blocked:
                raise _OutcomeUnknown(
                    "post-journal-release-invalid"
                ) from None
            _recheck_visible_release(releases_fd, product_id, published_fd)
            return _result(
                STATUS_ALREADY_STAGED,
                "identity-already-staged",
                product_id,
                policy_id,
                source_staged=True,
                resumed=True,
                reconciled=reconciled,
                journal_committed=True,
            )

        if journal.has_release(product_id, policy_id):
            raise _OutcomeUnknown("journal-release-missing")

        operation_name = ""
        for _ in range(16):
            operation_name = "stage-" + os.urandom(16).hex()
            if _OPERATION_RE.fullmatch(operation_name) is None:
                raise _Blocked("operation-id-failed")
            try:
                os.mkdir(operation_name, 0o700, dir_fd=operations_fd)
                os.chmod(
                    operation_name,
                    0o700,
                    dir_fd=operations_fd,
                    follow_symlinks=False,
                )
                os.fsync(operations_fd)
                break
            except FileExistsError:
                continue
            except OSError:
                raise _Blocked("stage-write-failed") from None
        else:
            raise _Blocked("operation-id-collision")
        operation_fd = _open_private_child(operations_fd, operation_name)

        _copy_inventory(trusted_planner, candidate, operation_fd)
        _verify_staged(
            trusted_planner,
            candidate,
            install_path + "/operations/" + operation_name,
            product_id,
            policy_id,
        )
        _verify_exact_staged_tree(
            trusted_planner,
            install_path + "/operations/" + operation_name,
            product_id,
        )

        rename = exclusive_rename or _exclusive_rename_darwin
        publish_reconciled = False
        try:
            rename(operations_fd, operation_name, releases_fd, product_id)
            publication_visible = True
        except BaseException as exc:
            # Entering the callback is the publication uncertainty boundary:
            # every exceptional return, including a non-OSError or a trusted
            # control exception, must reconcile both names before any result
            # can claim that publication did not happen.
            try:
                existing_fd = _existing_release_fd(releases_fd, product_id)
            except BaseException:
                raise _OutcomeUnknown("publish-state-ambiguous") from None
            if existing_fd is not None:
                published_fd = existing_fd
                publication_visible = True
                if isinstance(exc, OSError) and exc.errno == errno.EEXIST:
                    # RENAME_EXCL's expected collision result is safe to
                    # reverify and reconcile as an already-visible identity.
                    publish_reconciled = True
                else:
                    try:
                        destination_is_operation = _identity(
                            os.fstat(existing_fd)
                        ) == _identity(os.fstat(operation_fd))
                    except BaseException:
                        raise _OutcomeUnknown(
                            "publish-state-ambiguous"
                        ) from None
                    # The destination is visible, but an arbitrary callback
                    # exception cannot be converted into a success claim.
                    # A later invocation will reverify it and durably append
                    # the missing journal entry.
                    token = (
                        "publish-callback-failed"
                        if destination_is_operation
                        else "publish-state-ambiguous"
                    )
                    raise _OutcomeUnknown(token) from None
            else:
                try:
                    source_intact = _operation_still_visible(
                        operations_fd, operation_name, operation_fd
                    )
                except BaseException:
                    raise _OutcomeUnknown("publish-state-ambiguous") from None
                if source_intact:
                    # Exact source name/inode still exists and destination is
                    # positively absent: publication did not occur.
                    raise _Blocked("exclusive-publish-failed") from None
                raise _OutcomeUnknown("publish-state-ambiguous") from None
        try:
            os.fsync(operations_fd)
            os.fsync(releases_fd)
            os.fsync(install.fd)
        except OSError:
            raise _OutcomeUnknown("publish-durability-ambiguous") from None

        if published_fd < 0:
            # The operation descriptor remains valid across rename and proves
            # the visible product name refers to the exact directory built.
            published_fd = operation_fd
        _recheck_visible_release(releases_fd, product_id, published_fd)
        try:
            _verify_staged(
                trusted_planner,
                candidate,
                install_path + "/releases/" + product_id,
                product_id,
                policy_id,
            )
            _verify_exact_staged_tree(
                trusted_planner,
                install_path + "/releases/" + product_id,
                product_id,
            )
        except _Blocked:
            raise _OutcomeUnknown("published-reverification-failed") from None
        _recheck_visible_release(releases_fd, product_id, published_fd)

        reconciled = False
        if not journal.has_release(product_id, policy_id):
            journal.append(product_id, policy_id, "staged")
        install.recheck()
        journal_root_handle.recheck()
        for guard in root_guards:
            guard.recheck()
        # Success is authorized only by a final post-journal proof of both the
        # visible name-to-held-object binding and exact whole-product closure.
        _recheck_visible_release(releases_fd, product_id, published_fd)
        try:
            _verify_exact_staged_tree(
                trusted_planner,
                install_path + "/releases/" + product_id,
                product_id,
            )
        except _Blocked:
            raise _OutcomeUnknown("post-journal-release-invalid") from None
        _recheck_visible_release(releases_fd, product_id, published_fd)
        return _result(
            STATUS_STAGED,
            "source-staged-inactive",
            product_id,
            policy_id,
            source_staged=True,
            reconciled=reconciled or publish_reconciled,
            journal_committed=True,
        )
    except _OutcomeUnknown as blocked:
        return _unknown(blocked.token, product_id, policy_id)
    except _Blocked as blocked:
        if publication_visible:
            return _unknown(blocked.token, product_id, policy_id)
        return _unsupported(blocked.token)
    except Exception:
        if publication_visible:
            return _unknown("internal-error", product_id, policy_id)
        return _unsupported("internal-error")
    finally:
        if journal is not None:
            journal.close()
        closed: set[int] = set()
        for descriptor in (
            published_fd,
            operation_fd,
            releases_fd,
            operations_fd,
        ):
            if descriptor >= 0 and descriptor not in closed:
                closed.add(descriptor)
                _close_fd_quietly(descriptor)
        if journal_root_handle is not None:
            journal_root_handle.close()
        if install is not None:
            install.close()
        for guard in root_guards:
            guard.close()


def render_result(result: dict) -> str:
    line = json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    if "\n" in line or len(line.encode("ascii")) > MAX_RESULT_BYTES:
        fallback = _unsupported("result-oversize")
        line = json.dumps(
            fallback,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    return line


def result_exit_code(result: object) -> int:
    if not isinstance(result, dict):
        return 2
    status = result.get("status")
    if status in (STATUS_STAGED, STATUS_ALREADY_STAGED):
        return 0
    if status == STATUS_OUTCOME_UNKNOWN:
        return 4
    return 2


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise _CliArgumentError()


_REQUIRED_CLI_OPTIONS = (
    "--current-source-root",
    "--candidate-source-root",
    "--install-root",
    "--environment-root",
    "--data-root",
    "--journal-root",
    "--expected-product-id",
    "--expected-inventory-policy-id",
)


def _help_result() -> dict:
    return {
        "activation_performed": False,
        "activation_supported": False,
        "environment_built": False,
        "environment_stage_supported": False,
        "live_state_modified": False,
        "mode": RESULT_MODE,
        "required_options": list(_REQUIRED_CLI_OPTIONS),
        "schema": HELP_SCHEMA,
        "status": "help",
    }


def main(argv: list[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    if any(item in ("-h", "--help") for item in raw_arguments):
        result = _help_result()
        sys.stdout.write(render_result(result) + "\n")
        return 0

    parser = _Parser(add_help=False)
    parser.add_argument("--current-source-root", required=True)
    parser.add_argument("--candidate-source-root", required=True)
    parser.add_argument("--install-root", required=True)
    parser.add_argument("--environment-root", required=True)
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--journal-root", required=True)
    parser.add_argument("--expected-product-id", required=True)
    parser.add_argument("--expected-inventory-policy-id", required=True)
    try:
        arguments = parser.parse_args(raw_arguments)
        result = stage_release(
            current_source_root=arguments.current_source_root,
            candidate_source_root=arguments.candidate_source_root,
            install_root=arguments.install_root,
            environment_root=arguments.environment_root,
            data_root=arguments.data_root,
            journal_root=arguments.journal_root,
            expected_product_id=arguments.expected_product_id,
            expected_inventory_policy_id=(
                arguments.expected_inventory_policy_id
            ),
        )
    except _CliArgumentError:
        result = _unsupported("invalid-arguments")
    sys.stdout.write(render_result(result) + "\n")
    return result_exit_code(result)


if __name__ == "__main__":
    raise SystemExit(main())

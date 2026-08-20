#!/usr/bin/env python3
"""Strictly read-only local source release-update planner.

This slice only *plans*: it compares the trusted-manifest source bytes of a
current root against a candidate root and classifies the delta.  It never
applies anything, never imports or executes candidate code, never opens a
socket, database, or subprocess.  This module itself performs no filesystem
writes of any kind; bytecode caching is disabled below before any import this
module performs.  During direct CLI execution the hardened import path and
no-bytecode setting remain active for the process lifetime.  When imported as
an API, the caller's exact ``sys.path`` and ``sys.dont_write_bytecode`` values
are restored immediately after trusted imports complete.  Python's import
loader may cache this module itself before its body (and therefore the
no-bytecode setting) runs; that is outside planner control.  Changed source is
always blocked ("changed-unclassified");
later slices classify contracts before any apply path exists.

Roots are captured through held directory descriptors anchored at the
filesystem root: ``/`` is opened once per snapshot and every component of the
absolute root path — ancestors included — is traversed dir_fd-relative with a
no-follow stat plus O_DIRECTORY|O_NOFOLLOW open, so no pathname above or below
the root is ever re-resolved after validation.  Every ancestor, manifest
directory, and file identity is rechecked from its held parent after the full
snapshot.  Any swap, replacement, or in-place rewrite observed across the
stat/open/read window — including a same-size rewrite with a restored mtime,
caught by st_ctime_ns, or a parent directory swapped to a symlink — fails
unsupported.  Manifest files must be single-link regular files and are opened
O_NONBLOCK so a swap to a FIFO cannot block.  Nothing is ever read outside the
held root, and the aggregate byte budget is enforced before each open.
Directory/file screening covers POSIX owner, mode, type, link count, and
time-bounded identity only.  It deliberately does not claim to authenticate
macOS ACLs, extended attributes, source provenance, or post-plan immutability;
therefore ``no-op`` means manifest-byte equality at capture time, not an
exclusive-writability or authenticity decision.  A later signed-package gate
must establish those properties before any apply path exists.

The manifest of files that define a build is an embedded, reviewed copy of
``core_service.BUILD_SOURCE_MANIFEST``; repository tests require exact parity
with the runtime tuple.  The planner imports no repository code, so invoking a
byte-identical copy through a symlink cannot redirect executable imports.
Both roots must carry exactly one top-level literal ``BUILD_SOURCE_MANIFEST``
tuple, byte-for-byte identical to the embedded tuple, established by bounded
*static analysis* only: source byte and token ceilings are enforced before
parsing, candidate code is never imported, and
obvious rebinding, mutation, deletion, wildcard-import, dynamic-namespace
(exec/eval/globals/locals/vars/__import__/setattr/delattr), and manifest
string-reference patterns are rejected.  This is honest static screening, not
a proof against arbitrary obfuscated Python runtime semantics — which is why
changed source always remains blocked and provenance is never claimed.

Emitted JSON is deterministic (one line, sorted keys, compact separators) and
redacted: it carries classification tokens and source build ids only — never
filesystem paths, file contents, configuration, secrets, or exception text.

Import hardening: before any non-builtin import, ``sys.path`` is rebuilt
using builtins only — PYTHONPATH, cwd, and other untrusted entries are
dropped, and only interpreter-owned entries are retained for stdlib loading.
The planner has no project imports; after its stdlib imports complete, an API
import restores the caller's exact path and bytecode settings.  Non-claim:
Python *startup* (``site``, ``sitecustomize``, path hooks) runs before this
script body and may itself import startup modules from a hostile environment;
that is outside planner control.  The hardened operator invocation is therefore
``.venv/bin/python -I scripts/release_update_plan.py ...`` — isolated mode
ignores PYTHONPATH and user site entirely, closing the startup window too.
"""

import sys

# The import bootstrap temporarily hardens process-global state.  Preserve it
# exactly so importing this planner as an API cannot perturb a long-lived
# orchestrator after trusted modules have been loaded and origin-checked.
_ORIGINAL_SYS_PATH = list(sys.path)
_ORIGINAL_DONT_WRITE_BYTECODE = sys.dont_write_bytecode

# Disable bytecode caching before every subsequent import this module
# performs (stdlib and project alike).  Only interpreter startup, which runs
# before this line, may cache.
sys.dont_write_bytecode = True


def _sanitize_sys_path() -> None:
    """Rebuild sys.path using builtins only, before any non-builtin import:
    an attacker-controlled PYTHONPATH or cwd entry could otherwise shadow a
    stdlib module such as ``ast`` and execute on its first import here.  The
    new path contains only the exact startup-loaded stdlib directory, its
    ``lib-dynload`` directory, and its versioned stdlib zip location — never
    arbitrary descendants of an interpreter prefix, site-packages, cwd, or a
    script directory.  No repository path is admitted; this planner is
    deliberately self-contained."""

    def _clean(entry: object) -> bool:
        return (
            isinstance(entry, str)
            and entry.startswith("/")
            and "\x00" not in entry
            and not any(
                part in ("", ".", "..") for part in entry.split("/")[1:]
            )
        )

    # This is a sys.modules lookup of a module the interpreter loaded before
    # this script ran — no new import, so nothing attacker-shadowable executes
    # here.  Hardened CLI use requires ``-I`` because Python startup itself is
    # necessarily outside this module's control.
    os_file = getattr(sys.modules.get("os"), "__file__", None)
    if not (
        isinstance(os_file, str)
        and _clean(os_file)
        and "/" in os_file[1:]
    ):
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
        if not _clean(entry):
            continue
        if entry not in sanitized:
            sanitized.append(entry)
    if len(sanitized) != 3:
        raise ImportError("untrusted standard library location")
    sys.path[:] = sanitized


_sanitize_sys_path()

import ast
import argparse
import errno
import hashlib
import io
import json
import os
import re
import stat
import tokenize
from pathlib import Path

# CLI execution keeps its hardened import/no-bytecode policy for the full
# process lifetime.  API imports restore the caller's exact process-global
# state once every stdlib import is complete; planner calls below require no
# further dynamic imports.
if __name__ != "__main__":
    sys.path[:] = _ORIGINAL_SYS_PATH
    sys.dont_write_bytecode = _ORIGINAL_DONT_WRITE_BYTECODE

PLAN_SCHEMA = "synapse-s2.release-update-plan.v1"
PLAN_MODE = "read-only-plan"

CLASSIFICATION_NO_OP = "no-op"
CLASSIFICATION_CHANGED = "changed-unclassified"
CLASSIFICATION_UNSUPPORTED = "unsupported"

EXIT_CODES = {
    CLASSIFICATION_NO_OP: 0,
    CLASSIFICATION_CHANGED: 3,
    CLASSIFICATION_UNSUPPORTED: 2,
}

MAX_MANIFEST_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_MANIFEST_BYTES = 64 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024

_BUILD_ID_RE = re.compile(r"source-[0-9a-f]{24}")
_GROUP_OR_WORLD_WRITE = 0o022
_MANIFEST_NAME = "BUILD_SOURCE_MANIFEST"

# Bounds on candidate core_service.py analysis, with generous headroom over
# the trusted source (~231 KB / ~35,238 tokens at the pinned revision).
MAX_MANIFEST_SOURCE_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_SOURCE_TOKENS = 160_000

_DYNAMIC_NAMESPACE_BUILTINS = frozenset(
    (
        "exec",
        "eval",
        "globals",
        "locals",
        "vars",
        "__import__",
        "setattr",
        "delattr",
    )
)

# Flag lookups use getattr so importing this module can never fail on a
# platform that lacks one; the deterministic gate below refuses to plan
# instead.
_O_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", None)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", None)

_DIR_OPEN_FLAGS = (
    os.O_RDONLY | (_O_DIRECTORY or 0) | (_O_NOFOLLOW or 0) | (_O_CLOEXEC or 0)
)
# O_NONBLOCK guarantees that a manifest entry swapped to a FIFO between the
# no-follow stat and the open cannot block the planner; for regular files it
# is a no-op.
_FILE_OPEN_FLAGS = (
    os.O_RDONLY
    | (_O_NOFOLLOW or 0)
    | (_O_CLOEXEC or 0)
    | (_O_NONBLOCK or 0)
)

_PLATFORM_SUPPORTED = (
    None not in (_O_DIRECTORY, _O_NOFOLLOW, _O_CLOEXEC, _O_NONBLOCK)
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
)

# Reviewed copy of core_service.BUILD_SOURCE_MANIFEST.  The repository test
# suite requires exact tuple parity, so runtime-manifest evolution fails closed
# until this planner is deliberately updated as part of the same release.
TRUSTED_MANIFEST = (
    "apple_vision_enrichment.py",
    "backend_router.py",
    "bridge_governance.py",
    "capture_daemon.py",
    "core_authority.py",
    "core_client_binding.py",
    "core_client.py",
    "core_path_policy.py",
    "core_protocol.py",
    "core_request_journal.py",
    "core_runtime_paths.py",
    "core_service.py",
    "embedding_providers.py",
    "event_segmenter.py",
    "harmonic_memory.py",
    "image_capture.py",
    "media_similarity.py",
    "memora_governance.py",
    "memora_shadow.py",
    "memory_store.py",
    "mlx_backend.py",
    "native/apple_vision_enrich.swift",
    "recovery_manager.py",
    "redaction.py",
    "replication_manager.py",
    "replication_protocol.py",
    "replication_store.py",
    "replacement_policy.py",
    "scripts/core_cutover_preflight.py",
    "transcript_capture.py",
    "pyproject.toml",
    "uv.lock",
)


class _Unsupported(Exception):
    """Internal control flow only.  Carries a fixed public token and nothing
    else: no paths, no source, no wrapped exception text ever leaves this
    module."""

    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


class _CliArgumentError(Exception):
    """Internal signal that argparse rejected the command line."""


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


def _identity(observed: os.stat_result) -> tuple[int, int, int]:
    # Shared ancestors (e.g. /, /Users, /tmp) legitimately change mtime as
    # unrelated processes work inside them; their swap detection needs only
    # device, inode, and file type.
    return (observed.st_dev, observed.st_ino, stat.S_IFMT(observed.st_mode))


def _validate_trusted_manifest() -> None:
    if (
        not isinstance(TRUSTED_MANIFEST, tuple)
        or not TRUSTED_MANIFEST
        or len(set(TRUSTED_MANIFEST)) != len(TRUSTED_MANIFEST)
        or "core_service.py" not in TRUSTED_MANIFEST
    ):
        raise _Unsupported("trusted-manifest-invalid")
    for name in TRUSTED_MANIFEST:
        if (
            not isinstance(name, str)
            or not name
            or "\\" in name
            or "\x00" in name
        ):
            raise _Unsupported("trusted-manifest-invalid")
        components = name.split("/")
        if any(part in ("", ".", "..") for part in components):
            raise _Unsupported("trusted-manifest-invalid")


def _validate_directory_stat(observed: os.stat_result, token: str) -> None:
    if (
        not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.geteuid()
        or observed.st_mode & _GROUP_OR_WORLD_WRITE
    ):
        raise _Unsupported(token)


class _RootSnapshot:
    """Holds descriptors for the complete absolute chain of a root — from the
    filesystem anchor ``/`` through every ancestor — plus every traversed
    manifest directory, so all reads and rechecks happen against captured
    identities, never re-resolved pathnames."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._descriptors: list[int] = []
        self._anchor_fd = -1
        self._anchor_identity: tuple | None = None
        # (held parent fd, component name, held fd, identity fingerprint)
        self._ancestors: list[tuple[int, str, int, tuple]] = []
        self._root_parent_fd = -1
        self._root_name = ""
        self._root_fd = -1
        self._root_fingerprint: tuple | None = None
        self._directories: dict[tuple[str, ...], tuple[int, tuple]] = {}
        self._files: list[tuple[tuple[str, ...], str, tuple]] = []

    def open_root(self) -> None:
        components = self.root.parts[1:]
        if not components:
            raise _Unsupported("root-unsafe")
        try:
            anchor = os.open("/", _DIR_OPEN_FLAGS)
        except OSError:
            raise _Unsupported("root-unsafe") from None
        self._descriptors.append(anchor)
        self._anchor_fd = anchor
        self._anchor_identity = _identity(os.fstat(anchor))
        parent = anchor
        last_index = len(components) - 1
        for index, name in enumerate(components):
            try:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except OSError:
                raise _Unsupported("root-unsafe") from None
            # A symlink (or anything but a directory) anywhere in the chain,
            # ancestors included, is rejected outright.
            if not stat.S_ISDIR(before.st_mode):
                raise _Unsupported("root-unsafe")
            try:
                held = os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent)
            except OSError:
                raise _Unsupported("root-unsafe") from None
            self._descriptors.append(held)
            observed = os.fstat(held)
            if index == last_index:
                if _fingerprint(observed) != _fingerprint(before):
                    raise _Unsupported("validation-race")
                _validate_directory_stat(observed, "root-unsafe")
                self._root_parent_fd = parent
                self._root_name = name
                self._root_fd = held
                self._root_fingerprint = _fingerprint(observed)
            else:
                if _identity(observed) != _identity(before):
                    raise _Unsupported("validation-race")
                self._ancestors.append((parent, name, held, _identity(observed)))
            parent = held

    def _directory_fd(self, key: tuple[str, ...]) -> int:
        descriptor = self._root_fd
        for depth in range(len(key)):
            prefix = key[: depth + 1]
            entry = self._directories.get(prefix)
            if entry is None:
                name = key[depth]
                try:
                    before = os.stat(
                        name, dir_fd=descriptor, follow_symlinks=False
                    )
                except OSError:
                    raise _Unsupported("root-unsafe") from None
                _validate_directory_stat(before, "root-unsafe")
                try:
                    child = os.open(name, _DIR_OPEN_FLAGS, dir_fd=descriptor)
                except OSError:
                    raise _Unsupported("root-unsafe") from None
                self._descriptors.append(child)
                held = os.fstat(child)
                if _fingerprint(held) != _fingerprint(before):
                    raise _Unsupported("validation-race")
                _validate_directory_stat(held, "root-unsafe")
                entry = (child, _fingerprint(held))
                self._directories[prefix] = entry
            descriptor = entry[0]
        return descriptor

    def read_file(self, name: str, budget: dict[str, int]) -> bytes:
        components = tuple(name.split("/"))
        directory_key = components[:-1]
        leaf = components[-1]
        parent = self._directory_fd(directory_key)
        try:
            before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except OSError as exc:
            token = "file-missing" if exc.errno == errno.ENOENT else "file-unsafe"
            raise _Unsupported(token) from None
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_mode & _GROUP_OR_WORLD_WRITE
        ):
            raise _Unsupported("file-unsafe")
        if before.st_size > MAX_MANIFEST_FILE_BYTES:
            raise _Unsupported("file-oversize")
        # The aggregate budget is enforced before the open so no byte beyond
        # the invocation limit is ever read.
        if before.st_size > budget["remaining"]:
            raise _Unsupported("total-oversize")
        try:
            descriptor = os.open(leaf, _FILE_OPEN_FLAGS, dir_fd=parent)
        except OSError as exc:
            token = "file-missing" if exc.errno == errno.ENOENT else "file-unsafe"
            raise _Unsupported(token) from None
        try:
            opened = os.fstat(descriptor)
            if _fingerprint(opened) != _fingerprint(before):
                raise _Unsupported("validation-race")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining > 0:
                chunk = os.read(descriptor, min(remaining, _READ_CHUNK_BYTES))
                if not chunk:
                    raise _Unsupported("validation-race")
                chunks.append(chunk)
                remaining -= len(chunk)
            # No trailing EOF probe: it could return bytes appended after the
            # budget check, pushing aggregate reads past the cap.  Growth or
            # any other mutation is caught by the immediate post-read fstat
            # below and by the full held-vs-visible recheck.
            after = os.fstat(descriptor)
            if _fingerprint(after) != _fingerprint(before):
                raise _Unsupported("validation-race")
        finally:
            os.close(descriptor)
        payload = b"".join(chunks)
        budget["remaining"] -= len(payload)
        self._files.append((directory_key, leaf, _fingerprint(before)))
        return payload

    def recheck(self) -> None:
        try:
            if _identity(os.fstat(self._anchor_fd)) != self._anchor_identity:
                raise _Unsupported("validation-race")
            for parent, name, held, identity in self._ancestors:
                if _identity(os.fstat(held)) != identity:
                    raise _Unsupported("validation-race")
                visible = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(visible.st_mode)
                    or _identity(visible) != identity
                ):
                    raise _Unsupported("validation-race")
            held_root = os.fstat(self._root_fd)
            visible_root = os.stat(
                self._root_name,
                dir_fd=self._root_parent_fd,
                follow_symlinks=False,
            )
        except OSError:
            raise _Unsupported("validation-race") from None
        if (
            _fingerprint(held_root) != self._root_fingerprint
            or _fingerprint(visible_root) != self._root_fingerprint
        ):
            raise _Unsupported("validation-race")
        for key, (descriptor, fingerprint) in self._directories.items():
            parent = (
                self._root_fd
                if len(key) == 1
                else self._directories[key[:-1]][0]
            )
            try:
                held = os.fstat(descriptor)
                visible = os.stat(
                    key[-1], dir_fd=parent, follow_symlinks=False
                )
            except OSError:
                raise _Unsupported("validation-race") from None
            if (
                _fingerprint(held) != fingerprint
                or _fingerprint(visible) != fingerprint
            ):
                raise _Unsupported("validation-race")
        for directory_key, leaf, fingerprint in self._files:
            parent = (
                self._root_fd
                if not directory_key
                else self._directories[directory_key][0]
            )
            try:
                visible = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            except OSError:
                raise _Unsupported("validation-race") from None
            if _fingerprint(visible) != fingerprint:
                raise _Unsupported("validation-race")

    def close(self) -> None:
        while self._descriptors:
            descriptor = self._descriptors.pop()
            try:
                os.close(descriptor)
            except OSError:
                pass


def _validate_root_argument(root: object) -> Path:
    if (
        not isinstance(root, Path)
        or not root.is_absolute()
        # POSIX permits an implementation-defined "//" double root; only the
        # single canonical anchor is plannable.
        or root.anchor != "/"
        or "\x00" in str(root)
        or any(part in (".", "..") for part in root.parts[1:])
    ):
        raise _Unsupported("invalid-arguments")
    return root


def _extract_manifest(source: bytes) -> tuple[str, tuple[str, ...] | None]:
    """Return ("ok", tuple) only when the source binds BUILD_SOURCE_MANIFEST
    exactly once, at top level, to a literal tuple of strings.  Any further
    store, delete, rebind, mutation, aliasing import, or shadowing binding —
    nested scopes included — is ambiguous."""
    # Bound work before parsing: a hostile candidate could otherwise submit
    # pathological source engineered against the parser.  The token ceiling
    # streams via tokenize and aborts early, so no huge AST is ever built.
    if len(source) > MAX_MANIFEST_SOURCE_BYTES:
        return ("complexity", None)
    token_count = 0
    try:
        for _ in tokenize.tokenize(io.BytesIO(source).readline):
            token_count += 1
            if token_count > MAX_MANIFEST_SOURCE_TOKENS:
                return ("complexity", None)
    except (
        tokenize.TokenError,
        IndentationError,
        SyntaxError,
        ValueError,
        UnicodeDecodeError,
    ):
        return ("missing", None)
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (SyntaxError, ValueError, UnicodeDecodeError):
        return ("missing", None)
    def _touches_manifest(node: ast.AST) -> bool:
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            if (
                isinstance(node, ast.Attribute)
                and node.attr == _MANIFEST_NAME
            ):
                return True
            node = node.value
        return isinstance(node, ast.Name) and node.id == _MANIFEST_NAME

    type_parameter_nodes = tuple(
        node_type
        for node_type in (
            getattr(ast, "TypeVar", None),
            getattr(ast, "ParamSpec", None),
            getattr(ast, "TypeVarTuple", None),
        )
        if isinstance(node_type, type)
    )
    bindings = 0
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id == _MANIFEST_NAME
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            bindings += 1
        elif isinstance(node, ast.alias) and _MANIFEST_NAME in (
            node.name.split(".")[0],
            node.asname,
        ):
            return ("ambiguous", None)
        elif (
            isinstance(node, (ast.Global, ast.Nonlocal))
            and _MANIFEST_NAME in node.names
        ):
            return ("ambiguous", None)
        elif isinstance(node, ast.ExceptHandler) and node.name == _MANIFEST_NAME:
            return ("ambiguous", None)
        elif isinstance(node, ast.arg) and node.arg == _MANIFEST_NAME:
            return ("ambiguous", None)
        elif (
            isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
            and node.name == _MANIFEST_NAME
        ):
            return ("ambiguous", None)
        elif (
            isinstance(node, (ast.MatchAs, ast.MatchStar))
            and node.name == _MANIFEST_NAME
        ):
            return ("ambiguous", None)
        elif isinstance(node, ast.MatchMapping) and node.rest == _MANIFEST_NAME:
            return ("ambiguous", None)
        elif isinstance(node, ast.ImportFrom) and any(
            alias.name == "*" for alias in node.names
        ):
            return ("ambiguous", None)
        elif (
            isinstance(node, (ast.Attribute, ast.Subscript))
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and _touches_manifest(node)
        ):
            return ("ambiguous", None)
        elif (
            type_parameter_nodes
            and isinstance(node, type_parameter_nodes)
            and node.name == _MANIFEST_NAME
        ):
            return ("ambiguous", None)
        elif (
            isinstance(node, ast.Name)
            and node.id in _DYNAMIC_NAMESPACE_BUILTINS
        ):
            return ("ambiguous", None)
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and _MANIFEST_NAME in node.value
        ):
            # Any string mention of the manifest name outside its literal
            # binding (e.g. a globals()/setattr key) is ambiguous.
            return ("ambiguous", None)
    if bindings == 0:
        return ("missing", None)
    if bindings > 1:
        return ("ambiguous", None)
    assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == _MANIFEST_NAME
    ]
    if len(assignments) != 1:
        # The single binding is not a plain top-level assignment (AnnAssign,
        # AugAssign, walrus, loop target, tuple unpack, nested scope, ...).
        return ("ambiguous", None)
    value = assignments[0].value
    if not isinstance(value, ast.Tuple):
        return ("missing", None)
    entries: list[str] = []
    for element in value.elts:
        if not isinstance(element, ast.Constant) or not isinstance(
            element.value, str
        ):
            return ("missing", None)
        entries.append(element.value)
    return ("ok", tuple(entries))


def _capture_root_state(
    snapshot: _RootSnapshot, budget: dict[str, int]
) -> tuple[str, dict[str, str]]:
    snapshot.open_root()
    build_digest = hashlib.sha256()
    file_digests: dict[str, str] = {}
    core_service_source: bytes | None = None
    for name in TRUSTED_MANIFEST:
        payload = snapshot.read_file(name, budget)
        encoded_name = name.encode("utf-8")
        build_digest.update(len(encoded_name).to_bytes(4, "big"))
        build_digest.update(encoded_name)
        build_digest.update(len(payload).to_bytes(8, "big"))
        build_digest.update(payload)
        file_digests[name] = hashlib.sha256(payload).hexdigest()
        if name == "core_service.py":
            core_service_source = payload
    status, literal = (
        ("missing", None)
        if core_service_source is None
        else _extract_manifest(core_service_source)
    )
    if status == "complexity":
        raise _Unsupported("manifest-complexity")
    if status == "missing":
        raise _Unsupported("manifest-missing")
    if status == "ambiguous" or literal != TRUSTED_MANIFEST:
        raise _Unsupported("manifest-drift")
    return f"source-{build_digest.hexdigest()[:24]}", file_digests


def _build_plan(
    classification: str,
    status: str,
    current_build_id: str | None,
    candidate_build_id: str | None,
    changes: list[str],
) -> dict:
    if classification == CLASSIFICATION_NO_OP:
        requirements: list[str] = []
    elif classification == CLASSIFICATION_CHANGED:
        requirements = ["contract-classification", "operator-review"]
    else:
        requirements = ["operator-review"]
    return {
        "schema": PLAN_SCHEMA,
        "mode": PLAN_MODE,
        "classification": classification,
        "status": status,
        "apply_supported": False,
        "apply_performed": False,
        "provenance_verified": False,
        "current": {"source_build_id": current_build_id},
        "candidate": {"source_build_id": candidate_build_id},
        "changes": list(changes),
        "requirements": requirements,
    }


def plan_release_update(
    current_root: Path,
    candidate_root: Path,
    expected_candidate_build_id: str | None = None,
) -> dict:
    current_build_id: str | None = None
    candidate_build_id: str | None = None
    snapshots: list[_RootSnapshot] = []
    try:
        try:
            if expected_candidate_build_id is not None and (
                not isinstance(expected_candidate_build_id, str)
                or _BUILD_ID_RE.fullmatch(expected_candidate_build_id) is None
            ):
                raise _Unsupported("invalid-arguments")
            if not _PLATFORM_SUPPORTED:
                raise _Unsupported("platform-unsupported")
            _validate_trusted_manifest()
            current_root = _validate_root_argument(current_root)
            candidate_root = _validate_root_argument(candidate_root)
            budget = {"remaining": MAX_TOTAL_MANIFEST_BYTES}
            current_snapshot = _RootSnapshot(current_root)
            snapshots.append(current_snapshot)
            current_build_id, current_digests = _capture_root_state(
                current_snapshot, budget
            )
            candidate_snapshot = _RootSnapshot(candidate_root)
            snapshots.append(candidate_snapshot)
            candidate_build_id, candidate_digests = _capture_root_state(
                candidate_snapshot, budget
            )
            # Both chains stay held across the full snapshot; only now compare
            # each held identity against what its held parent currently shows.
            current_snapshot.recheck()
            candidate_snapshot.recheck()
            if (
                expected_candidate_build_id is not None
                and candidate_build_id != expected_candidate_build_id
            ):
                raise _Unsupported("expected-build-id-mismatch")
            changes = sorted(
                name
                for name in TRUSTED_MANIFEST
                if current_digests[name] != candidate_digests[name]
            )
            if not changes and current_build_id == candidate_build_id:
                return _build_plan(
                    CLASSIFICATION_NO_OP,
                    "no-op",
                    current_build_id,
                    candidate_build_id,
                    [],
                )
            return _build_plan(
                CLASSIFICATION_CHANGED,
                "blocked-changed-unclassified",
                current_build_id,
                candidate_build_id,
                changes,
            )
        finally:
            for snapshot in snapshots:
                snapshot.close()
    except _Unsupported as blocked:
        return _build_plan(
            CLASSIFICATION_UNSUPPORTED,
            f"unsupported:{blocked.token}",
            current_build_id,
            candidate_build_id,
            [],
        )
    except Exception:
        # Unknown failure: emit nothing observed under the unknown state.
        return _build_plan(
            CLASSIFICATION_UNSUPPORTED,
            "unsupported:internal-error",
            None,
            None,
            [],
        )


def plan_exit_code(plan: dict) -> int:
    return EXIT_CODES.get(str(plan.get("classification")), 2)


def render_plan(plan: dict) -> str:
    return json.dumps(plan, sort_keys=True, separators=(",", ":"))


class _PlanArgumentParser(argparse.ArgumentParser):
    """Rejected command lines must yield the deterministic unsupported JSON
    contract on stdout, never argparse usage text on stderr.  Help output is
    untouched."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise _CliArgumentError()


def _emit(plan: dict) -> int:
    sys.stdout.write(render_plan(plan) + "\n")
    return plan_exit_code(plan)


def main(argv: list[str] | None = None) -> int:
    parser = _PlanArgumentParser(
        prog="release_update_plan",
        description=(
            "Read-only release update planner: classifies the trusted-manifest "
            "source delta between two local roots without applying anything."
        ),
    )
    parser.add_argument(
        "--current-root",
        required=True,
        help="Absolute path of the currently deployed source root.",
    )
    parser.add_argument(
        "--candidate-root",
        required=True,
        help="Absolute path of the candidate source root.",
    )
    parser.add_argument(
        "--expected-candidate-build-id",
        default=None,
        help="Optional expected candidate build id (source-<24 hex>).",
    )
    try:
        args = parser.parse_args(argv)
    except _CliArgumentError:
        return _emit(
            _build_plan(
                CLASSIFICATION_UNSUPPORTED,
                "unsupported:invalid-arguments",
                None,
                None,
                [],
            )
        )
    try:
        plan = plan_release_update(
            Path(args.current_root),
            Path(args.candidate_root),
            args.expected_candidate_build_id,
        )
    except Exception:
        plan = _build_plan(
            CLASSIFICATION_UNSUPPORTED,
            "unsupported:internal-error",
            None,
            None,
            [],
        )
    return _emit(plan)


if __name__ == "__main__":
    raise SystemExit(main())

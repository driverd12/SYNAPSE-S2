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

A second, equally read-only *preservation gate* mode (``--preservation-gate``)
compares the canonical AST of an explicit, versioned selection of semantic
durable-contract nodes — schema identifiers and migrations, request-journal
DDL, authority/runtime identity, recovery schemas, replication field sets,
and readiness/quiescence policies — between the same two roots.  Selected-node
AST equality is the accepted preservation relation: implementation changes
outside the selected nodes can pass the gate while the source planner above
still blocks the very same delta as changed-unclassified.  The gate is the
same honest bounded static screening as the manifest check — it never
imports, executes, or proves runtime equivalence of candidate code — so
missing, duplicated, rebound, dynamically mutated, syntactically ambiguous,
over-budget, unsafe, or raced contract sources all fail closed to
``unsupported`` and provenance is still never claimed or verified.

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
    "client_config.py",
    "core_authority.py",
    "core_client_binding.py",
    "core_client.py",
    "core_path_policy.py",
    "core_protocol.py",
    "core_request_journal.py",
    "core_runtime_paths.py",
    "core_service.py",
    "cortex_contract.py",
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
    "operator_readiness_contract.py",
    "recovery_manager.py",
    "redaction.py",
    "replication_manager.py",
    "replication_protocol.py",
    "replication_store.py",
    "replacement_policy.py",
    "retrieval_cursor.py",
    "scripts/core_cutover_preflight.py",
    "transcript_capture.py",
    "pyproject.toml",
    "uv.lock",
)

GATE_SCHEMA = "synapse-s2.release-preservation-gate.v1"
GATE_MODE = "read-only-preservation-gate"
# The accepted preservation relation: canonical (attribute-free) ast.dump
# equality of exactly the selected top-level nodes, nothing more.  Changes
# outside selected nodes are invisible to this relation by design; the v1
# source planner above still blocks them as changed-unclassified.
GATE_RELATION = "selected-node-ast-equality.v1"

GATE_STATUS_PROVEN_EQUAL = "proven-equal"
GATE_STATUS_BLOCKED = "blocked-contract-change"

GATE_EXIT_CODES = {
    GATE_STATUS_PROVEN_EQUAL: 0,
    GATE_STATUS_BLOCKED: 3,
}

# Bounds on per-file contract-source analysis, with generous headroom over the
# largest trusted contract source (memory_store.py: ~844 KiB / ~107,404 tokens
# at the pinned revision).  Enforced before ast.parse, like the manifest scan.
MAX_CONTRACT_SOURCE_BYTES = 4 * 1024 * 1024
MAX_CONTRACT_SOURCE_TOKENS = 640_000

# Builtins whose mere mention makes a contract source unverifiable: each one
# can rebind or shadow a module-level name without a static Store node.
# ``locals`` is deliberately absent here — trusted contract modules use it
# inside method bodies, where it cannot rebind module-level contract nodes —
# and is instead rejected only in import-time (module/class scope) code.
_GATE_DYNAMIC_NAMESPACE_BUILTINS = frozenset(
    (
        "exec",
        "eval",
        "globals",
        "vars",
        "__import__",
        "setattr",
        "delattr",
        "__builtins__",
    )
)

# Import forms that would smuggle a dynamic-namespace builtin back in under a
# new name.  Any imported binding whose source name or local alias collides
# with a denied builtin is rejected, and ``locals`` is denied here even though
# bare function-body ``locals()`` calls are tolerated: an imported alias
# escapes the module/class-scope screen that constrains the builtin.  The same
# names are banned as attribute accesses (``x.globals``) for symmetry.
_GATE_DYNAMIC_IMPORT_DENYLIST = _GATE_DYNAMIC_NAMESPACE_BUILTINS | frozenset(
    ("locals",)
)

# Modules whose import (whole, dotted, re-exported, or aliased) hands back the
# builtin namespace or a dynamic import primitive.  Trusted contract sources
# import neither.
_GATE_DENIED_IMPORT_MODULES = frozenset(("builtins", "importlib"))

# Reviewed, versioned semantic contract surfaces.  Each item names one exact
# top-level constant, function, class-qualified method, or class whose
# canonical AST is contract-critical for durability.  The surface id is the
# public token emitted in gate results; the (file, name) selection is the
# entire meaning of that id at this version.
SEMANTIC_SURFACES = (
    (
        "durable-store-schema.v1",
        (
            ("memory_store.py", "SQLITE_APPLICATION_ID"),
            ("memory_store.py", "SQLITE_USER_VERSION"),
            ("memory_store.py", "BACKUP_SCHEMA_CONTRACT_VERSION"),
            ("memory_store.py", "BACKUP_RECOVERY_RUNTIME_ID"),
            ("memory_store.py", "BACKUP_SCHEMA_COMPATIBILITY_REGISTRY"),
            ("memory_store.py", "_matching_backup_schema_contract_versions"),
            ("memory_store.py", "SCHEMA_SQL"),
            ("memory_store.py", "BACKUP_CRITICAL_TABLES"),
            ("memory_store.py", "BACKUP_RECEIPT_SCHEMA"),
            ("memory_store.py", "LEGACY_BACKUP_RECEIPT_SCHEMA"),
            ("memory_store.py", "BACKUP_RESTORE_RECEIPT_SCHEMA"),
            ("memory_store.py", "BACKUP_RESTORE_PLAN_SCHEMA"),
            ("memory_store.py", "DurableMemoryStore._run_migrations"),
            (
                "memory_store.py",
                "DurableMemoryStore._ensure_schema_transactionally",
            ),
            ("memory_store.py", "DurableMemoryStore._schema_statements"),
            (
                "memory_store.py",
                "DurableMemoryStore._assert_exact_schema_contract",
            ),
            ("memory_store.py", "DurableMemoryStore._schema_contract_key"),
            ("core_service.py", "CORE_STORE_SCHEMA_IDENTITY"),
            (
                "scripts/core_agent_installer.py",
                "EXPECTED_SCHEMA_IDENTITY",
            ),
        ),
    ),
    (
        "request-journal.v1",
        (
            ("core_request_journal.py", "JOURNAL_APPLICATION_ID"),
            ("core_request_journal.py", "JOURNAL_SCHEMA_VERSION"),
            ("core_request_journal.py", "JOURNAL_SCHEMA_IDENTITY"),
            ("core_request_journal.py", "JOURNAL_BINDING_SCHEMA"),
            ("core_request_journal.py", "_JOURNAL_ID_RE"),
            ("core_request_journal.py", "_REQUEST_JOURNAL_TABLE_SQL"),
            ("core_request_journal.py", "_REQUEST_JOURNAL_METADATA_TABLE_SQL"),
            ("core_request_journal.py", "_REQUEST_JOURNAL_INDEX_SQL"),
            ("core_request_journal.py", "_normalized_schema_sql"),
            ("core_request_journal.py", "_assert_exact_current_schema"),
        ),
    ),
    (
        "authority-runtime-identity.v1",
        (
            ("core_authority.py", "CORE_AUTHORITY_METADATA_KEY"),
            ("core_authority.py", "CORE_AUTHORITY_SCHEMA_VERSION"),
            ("core_authority.py", "CORE_AUTHORITY_INSTANCE_RE"),
            ("core_authority.py", "CORE_AUTHORITY_LOCK_GENERATION_RE"),
            ("core_authority.py", "CORE_AUTHORITY_LOCK_TRANSITION_SCHEMA"),
            ("core_authority.py", "_parse_lock_generation_id"),
            ("core_authority.py", "_lock_generation_id"),
            ("memory_store.py", "CORE_AUTHORITY_MARKER_FIELDS"),
            ("memory_store.py", "RUNTIME_STATE_AUTHORITY_BINDING_SCHEMA"),
            ("memory_store.py", "CORE_STORE_IDENTITY_RE"),
            ("memory_store.py", "CORE_REQUEST_JOURNAL_ID_RE"),
            ("memory_store.py", "CORE_ROOT_GENERATION_ID_RE"),
            ("memory_store.py", "CORE_ADOPTION_ATTESTATION_SCHEMA"),
            ("memory_store.py", "CORE_RUNTIME_PUBLICATION_SCHEMA"),
            ("core_service.py", "STORE_GENERATION_SCHEMA"),
            ("core_service.py", "STORE_GENERATION_ID_RE"),
        ),
    ),
    (
        "recovery.v1",
        (
            ("recovery_manager.py", "RECOVERY_BUNDLE_SCHEMA"),
            ("recovery_manager.py", "PRIOR_RECOVERY_BUNDLE_SCHEMA"),
            ("recovery_manager.py", "LEGACY_RECOVERY_BUNDLE_SCHEMA"),
            ("recovery_manager.py", "RECOVERY_BUNDLE_RESTORE_SCHEMA"),
            ("recovery_manager.py", "PRIOR_RECOVERY_BUNDLE_RESTORE_SCHEMA"),
            ("recovery_manager.py", "LEGACY_RECOVERY_BUNDLE_RESTORE_SCHEMA"),
            ("recovery_manager.py", "REQUEST_JOURNAL_RESTORE_BINDING_SCHEMA"),
            ("recovery_manager.py", "REQUEST_JOURNAL_SCHEMA_SHA256"),
            ("recovery_manager.py", "RUNTIME_STATE_BINDING_SCHEMA"),
            ("recovery_manager.py", "RUNTIME_STATE_AUTHORITY_BINDING_SCHEMA"),
            ("recovery_manager.py", "LEGACY_V2_DEFAULT_FIELDS"),
            ("memory_store.py", "RECOVERY_REQUEST_JOURNAL_BINDING_SCHEMA"),
            ("recovery_manager.py", "CAPTURE_TRANSPORT_DIR_KEYS"),
        ),
    ),
    (
        "replication-protocol.v1",
        (
            ("replication_protocol.py", "REPLICATION_PROTOCOL_VERSION"),
            ("replication_protocol.py", "NODE_DESCRIPTOR_SCHEMA"),
            ("replication_protocol.py", "CHECKPOINT_SCHEMA"),
            ("replication_protocol.py", "DESCRIPTOR_TRANSITION_SCHEMA"),
            ("replication_protocol.py", "NODE_DESCRIPTOR_TRANSITION_SCHEMA"),
            ("replication_protocol.py", "ACK_SCHEMA"),
            ("replication_protocol.py", "LEDGER_ANCHOR_SCHEMA"),
            ("replication_protocol.py", "MEDIA_ARTIFACT_CAPABILITY"),
            ("replication_protocol.py", "BASE_NODE_CAPABILITIES"),
            ("replication_protocol.py", "NODE_CAPABILITIES"),
            ("replication_protocol.py", "AUTH_FIELDS"),
            ("replication_protocol.py", "NODE_DESCRIPTOR_FIELDS"),
            ("replication_protocol.py", "DESCRIPTOR_TRANSITION_FIELDS"),
            ("replication_protocol.py", "NODE_DESCRIPTOR_TRANSITION_FIELDS"),
            ("replication_protocol.py", "CHECKPOINT_FIELDS"),
            ("replication_protocol.py", "ACK_FIELDS"),
            ("replication_protocol.py", "ARTIFACT_FIELDS"),
            ("replication_protocol.py", "LEDGER_ANCHOR_FIELDS"),
            ("replication_protocol.py", "ALLOWED_ARTIFACT_KINDS"),
            ("replication_protocol.py", "REQUIRED_ARTIFACT_KINDS"),
        ),
    ),
    (
        "readiness-quiescence.v1",
        (
            (
                "operator_readiness_contract.py",
                "OPERATOR_READINESS_PROOF_CONTRACT_SCHEMA",
            ),
            (
                "operator_readiness_contract.py",
                "OPERATOR_READINESS_PROOF_CONTRACT_VERSION",
            ),
            (
                "operator_readiness_contract.py",
                "OPERATOR_READINESS_REQUIRED_PROOF_IDS",
            ),
            ("operator_readiness_contract.py", "ready_operator_proof_contract"),
            ("operator_readiness_contract.py", "QUIESCENCE_POLICY_SCHEMA"),
            ("operator_readiness_contract.py", "QUIESCENCE_POLICY_VERSION"),
            ("operator_readiness_contract.py", "QUIESCENCE_LAUNCH_AGENT_RULES"),
            ("operator_readiness_contract.py", "quiescence_launch_agent_rules"),
            ("operator_readiness_contract.py", "quiescence_policy_contract"),
            ("operator_readiness_contract.py", "quiescence_policy_digest"),
            ("operator_readiness_contract.py", "REPLAY_DEBT_COUNTERS"),
        ),
    ),
    (
        "capture-protocol.v1",
        (
            ("memory_store.py", "CAPTURE_PROTOCOL_VERSION"),
            ("memory_store.py", "CAPTURE_ID_RE"),
            ("memory_store.py", "CAPTURE_REQUEST_FINGERPRINT_RE"),
            ("memory_store.py", "CAPTURE_OPERATION_RESULT_JSON_MAX_BYTES"),
            ("memory_store.py", "CAPTURE_OPERATION_COUNTER_MAX"),
            ("memory_store.py", "CAPTURE_OPERATION_ENVELOPE_KEYS"),
            ("memory_store.py", "CAPTURE_OPERATION_DEPLOYMENT_HEADER_KEYS"),
            ("memory_store.py", "CAPTURE_OPERATION_LEGACY_DEPLOYMENT_KEYS"),
            ("memory_store.py", "CAPTURE_OPERATION_RESULT_KEYS"),
            ("capture_daemon.py", "CAPTURE_SUFFIXES"),
            ("capture_daemon.py", "MAX_CAPTURE_BYTES"),
            ("capture_daemon.py", "CAPTURE_PROTOCOL_VERSION"),
            ("capture_daemon.py", "CAPTURE_ID_RE"),
            ("capture_daemon.py", "GLOBAL_CAPTURE_LOCK"),
            ("capture_daemon.py", "CAPTURE_REPLACEMENT_FREEZE_SCHEMA"),
            ("capture_daemon.py", "CAPTURE_REPLACEMENT_FREEZE_NAME"),
            ("capture_daemon.py", "CAPTURE_REPLACEMENT_FREEZE_ID_RE"),
            (
                "capture_daemon.py",
                "CAPTURE_REPLACEMENT_FREEZE_MAX_SECONDS",
            ),
            ("capture_daemon.py", "CAPTURE_DEFERRED_DIR_NAME"),
        ),
    ),
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


# Marker for a contract source file that is absent from a root: its selected
# items are *missing*, unlike screening failures, which are *unverifiable*.
_CONTRACT_SOURCE_ABSENT = object()


def _required_surface_ids() -> list[str]:
    identifiers = set()
    for entry in SEMANTIC_SURFACES:
        if (
            isinstance(entry, tuple)
            and len(entry) == 2
            and isinstance(entry[0], str)
        ):
            identifiers.add(entry[0])
    return sorted(identifiers)


def _validate_semantic_surfaces() -> None:
    if not isinstance(SEMANTIC_SURFACES, tuple) or not SEMANTIC_SURFACES:
        raise _Unsupported("surface-spec-invalid")
    seen_surfaces: set[str] = set()
    for entry in SEMANTIC_SURFACES:
        if not (isinstance(entry, tuple) and len(entry) == 2):
            raise _Unsupported("surface-spec-invalid")
        surface_id, items = entry
        if (
            not isinstance(surface_id, str)
            or not surface_id
            or surface_id in seen_surfaces
            or not isinstance(items, tuple)
            or not items
        ):
            raise _Unsupported("surface-spec-invalid")
        seen_surfaces.add(surface_id)
        seen_items: set[tuple[str, str]] = set()
        for item in items:
            if not (isinstance(item, tuple) and len(item) == 2):
                raise _Unsupported("surface-spec-invalid")
            filename, name = item
            if (
                not isinstance(filename, str)
                or not filename
                or "\\" in filename
                or "\x00" in filename
                or any(
                    part in ("", ".", "..") for part in filename.split("/")
                )
                or not isinstance(name, str)
                or name.count(".") > 1
                or not all(part.isidentifier() for part in name.split("."))
                or (filename, name) in seen_items
            ):
                raise _Unsupported("surface-spec-invalid")
            seen_items.add((filename, name))


def _surface_file_items() -> dict[str, frozenset[str]]:
    grouped: dict[str, set[str]] = {}
    for _, items in SEMANTIC_SURFACES:
        for filename, name in items:
            grouped.setdefault(filename, set()).add(name)
    return {
        filename: frozenset(names) for filename, names in grouped.items()
    }


def _module_scope_uses_locals(tree: ast.Module) -> bool:
    """``locals()`` reached from import-time code (module or class scope,
    decorators, defaults, annotations) can observe and feed mutation of the
    namespace holding contract nodes; only function *bodies* — where it cannot
    rebind module-level names — are exempt."""
    pending: list[ast.AST] = list(ast.iter_child_nodes(tree))
    while pending:
        node = pending.pop()
        if isinstance(node, ast.Name) and node.id == "locals":
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            pending.extend(node.decorator_list)
            pending.append(node.args)
            if node.returns is not None:
                pending.append(node.returns)
            continue
        if isinstance(node, ast.Lambda):
            pending.append(node.args)
            continue
        pending.extend(ast.iter_child_nodes(node))
    return False


def _analyze_contract_source(
    source: bytes, names: frozenset[str]
) -> dict[str, str] | None:
    """Resolve each selected name to the canonical ``ast.dump`` of its unique
    top-level binder (or unique direct class-body method for qualified names).

    Returns ``None`` when the file is unverifiable — over budget, unparsable,
    or any selected name is rebound, duplicated, aliased, shadowed, or
    reachable by dynamic-namespace mutation.  Selected names that are simply
    absent are omitted from the returned mapping (missing, not unverifiable).
    """
    if len(source) > MAX_CONTRACT_SOURCE_BYTES:
        return None
    token_count = 0
    try:
        for _ in tokenize.tokenize(io.BytesIO(source).readline):
            token_count += 1
            if token_count > MAX_CONTRACT_SOURCE_TOKENS:
                return None
    except (
        tokenize.TokenError,
        IndentationError,
        SyntaxError,
        ValueError,
        UnicodeDecodeError,
    ):
        return None
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (SyntaxError, ValueError, UnicodeDecodeError):
        return None

    simple = frozenset(name for name in names if "." not in name)
    qualified = frozenset(name for name in names if "." in name)
    class_names = frozenset(name.split(".", 1)[0] for name in qualified)
    method_names = frozenset(name.split(".", 1)[1] for name in qualified)
    guarded = simple | class_names
    watched = guarded | method_names

    type_parameter_nodes = tuple(
        node_type
        for node_type in (
            getattr(ast, "TypeVar", None),
            getattr(ast, "ParamSpec", None),
            getattr(ast, "TypeVarTuple", None),
        )
        if isinstance(node_type, type)
    )

    def _touches_watched(node: ast.AST) -> bool:
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            if isinstance(node, ast.Attribute) and node.attr in watched:
                return True
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, str)
                and node.slice.value in watched
            ):
                return True
            node = node.value
        return isinstance(node, ast.Name) and node.id in guarded

    if _module_scope_uses_locals(tree):
        return None
    # The single sanctioned ``__dict__`` shape: ``X.__dict__.items()`` read
    # and called in place.  A read-only items() iteration cannot rebind any
    # module or class member; every other reachable form (aliasing the dict,
    # subscripting it, storing through it, ``__globals__``) still fails
    # closed below.
    sanctioned_dict_reads: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "items"
            and isinstance(node.func.ctx, ast.Load)
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "__dict__"
            and isinstance(node.func.value.ctx, ast.Load)
        ):
            sanctioned_dict_reads.add(id(node.func.value))
    store_counts: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if node.id in _GATE_DYNAMIC_NAMESPACE_BUILTINS:
                return None
            if node.id in guarded and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                store_counts[node.id] = store_counts.get(node.id, 0) + 1
        elif isinstance(node, (ast.Attribute, ast.Subscript)):
            if isinstance(node, ast.Attribute):
                if node.attr == "__globals__" or (
                    node.attr == "__dict__"
                    and id(node) not in sanctioned_dict_reads
                ):
                    # Namespace-object handles reach every module and class
                    # member without naming it through a static binding node.
                    return None
                if node.attr in _GATE_DYNAMIC_IMPORT_DENYLIST:
                    # Attribute-form access to a dynamic-namespace primitive
                    # (``x.globals``, ``b.__import__``) is the same power as
                    # the bare name, reached through any smuggled binding.
                    return None
            if isinstance(node.ctx, (ast.Store, ast.Del)) and _touches_watched(
                node
            ):
                return None
        elif isinstance(node, ast.alias):
            if (
                node.name.split(".")[0] in guarded
                or node.asname in guarded
            ):
                return None
            if (
                node.name.split(".")[0] in _GATE_DENIED_IMPORT_MODULES
                or node.asname in _GATE_DENIED_IMPORT_MODULES
                or node.name in _GATE_DYNAMIC_IMPORT_DENYLIST
                or node.asname in _GATE_DYNAMIC_IMPORT_DENYLIST
            ):
                # Imported or aliased dynamic builtins (``from builtins
                # import globals as _g``, ``import builtins as b``, ``from m
                # import vars``) rebind namespaces without tripping the bare
                # Name ban.
                return None
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            if guarded & set(node.names):
                return None
        elif isinstance(node, ast.ExceptHandler):
            if node.name in guarded:
                return None
        elif isinstance(node, ast.arg):
            if node.arg in guarded:
                return None
        elif isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                return None
            if (
                node.module is not None
                and node.module.split(".")[0] in _GATE_DENIED_IMPORT_MODULES
            ):
                # Even innocuously-named members of ``builtins`` or
                # ``importlib`` are refused wholesale: the module itself is
                # the capability.
                return None
        elif isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            if node.name in guarded:
                store_counts[node.name] = store_counts.get(node.name, 0) + 1
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            if node.name in guarded:
                return None
        elif isinstance(node, ast.MatchMapping):
            if node.rest in guarded:
                return None
        elif type_parameter_nodes and isinstance(node, type_parameter_nodes):
            if node.name in guarded:
                return None
    if any(count != 1 for count in store_counts.values()):
        return None

    binders: dict[str, ast.stmt] = {}
    for statement in tree.body:
        bound_name: str | None = None
        if isinstance(statement, ast.Assign):
            if (
                len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id in guarded
            ):
                bound_name = statement.targets[0].id
        elif isinstance(statement, ast.AnnAssign):
            if (
                isinstance(statement.target, ast.Name)
                and statement.target.id in guarded
                and statement.value is not None
            ):
                bound_name = statement.target.id
        elif isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            if statement.name in guarded:
                bound_name = statement.name
        if bound_name is not None:
            if bound_name in binders:
                return None
            binders[bound_name] = statement

    resolved: dict[str, str] = {}
    for name in guarded:
        if name not in binders and store_counts.get(name, 0) != 0:
            # Bound somewhere (nested scope, unpacking, augmented target,
            # loop variable, type alias, ...) but not by exactly one plain
            # top-level statement: ambiguous, never merely missing.
            return None
    for name in simple:
        binder = binders.get(name)
        if binder is not None:
            resolved[name] = ast.dump(binder)
    for qualified_name in qualified:
        cls_name, _, method_name = qualified_name.partition(".")
        binder = binders.get(cls_name)
        if binder is None:
            continue
        if not isinstance(binder, ast.ClassDef):
            continue
        direct = [
            member
            for member in binder.body
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
            and member.name == method_name
        ]
        subtree_defs = [
            node
            for node in ast.walk(binder)
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
            and node.name == method_name
        ]
        method_stores = [
            node
            for node in ast.walk(binder)
            if isinstance(node, ast.Name)
            and node.id == method_name
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ]
        if len(direct) > 1 or len(subtree_defs) != len(direct) or method_stores:
            return None
        if not direct:
            continue
        resolved[qualified_name] = ast.dump(direct[0])
    return resolved


def _capture_contract_state(
    snapshot: _RootSnapshot,
    file_items: dict[str, frozenset[str]],
    budget: dict[str, int],
) -> dict[str, object]:
    snapshot.open_root()
    analyses: dict[str, object] = {}
    for name in sorted(file_items):
        try:
            payload = snapshot.read_file(name, budget)
        except _Unsupported as blocked:
            # A wholly absent contract source is a *missing* contract, which
            # the comparison reports per surface; every other snapshot
            # failure (unsafe, oversize, raced) aborts the gate entirely.
            if blocked.token == "file-missing":
                analyses[name] = _CONTRACT_SOURCE_ABSENT
                continue
            raise
        analyses[name] = _analyze_contract_source(payload, file_items[name])
    return analyses


def _contract_item_state(
    analyses: dict[str, object], filename: str, name: str
) -> tuple[str, str | None]:
    entry = analyses[filename]
    if entry is _CONTRACT_SOURCE_ABSENT:
        return ("missing", None)
    if entry is None:
        return ("unknown", None)
    dump = entry.get(name)
    if dump is None:
        return ("missing", None)
    return ("resolved", dump)


def _contract_digest(records: list[tuple[str, str, str, str]]) -> str:
    payload = json.dumps(
        sorted(records), sort_keys=True, separators=(",", ":")
    )
    return "contract-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _build_gate_result(
    status: str,
    current_digest: str | None,
    candidate_digest: str | None,
    changed: list[str],
    missing: list[str],
    unknown: list[str],
) -> dict:
    if status == GATE_STATUS_PROVEN_EQUAL:
        # Preservation of the selected nodes never authorizes an apply: the
        # overall source delta stays governed by the v1 source plan and the
        # operator.
        requirements = ["operator-review", "source-delta-review"]
    elif status == GATE_STATUS_BLOCKED:
        requirements = ["contract-review", "operator-review"]
    else:
        requirements = ["operator-review"]
    return {
        "schema": GATE_SCHEMA,
        "mode": GATE_MODE,
        "status": status,
        "relation": GATE_RELATION,
        "apply_supported": False,
        "apply_performed": False,
        "provenance_verified": False,
        "current": {"contract_digest": current_digest},
        "candidate": {"contract_digest": candidate_digest},
        "required_surfaces": _required_surface_ids(),
        "changed_surfaces": sorted(changed),
        "missing_surfaces": sorted(missing),
        "unknown_surfaces": sorted(unknown),
        "requirements": requirements,
    }


def _compare_contract_states(
    current_analyses: dict[str, object],
    candidate_analyses: dict[str, object],
) -> dict:
    changed: list[str] = []
    missing: list[str] = []
    unknown: list[str] = []
    current_records: list[tuple[str, str, str, str]] = []
    candidate_records: list[tuple[str, str, str, str]] = []
    current_complete = True
    candidate_complete = True
    for surface_id, items in SEMANTIC_SURFACES:
        surface_unknown = False
        surface_missing = False
        surface_changed = False
        for filename, name in items:
            current_state, current_dump = _contract_item_state(
                current_analyses, filename, name
            )
            candidate_state, candidate_dump = _contract_item_state(
                candidate_analyses, filename, name
            )
            if current_state == "resolved":
                current_records.append(
                    (surface_id, filename, name, current_dump)
                )
            else:
                current_complete = False
            if candidate_state == "resolved":
                candidate_records.append(
                    (surface_id, filename, name, candidate_dump)
                )
            else:
                candidate_complete = False
            if "unknown" in (current_state, candidate_state):
                surface_unknown = True
            elif "missing" in (current_state, candidate_state):
                surface_missing = True
            elif current_dump != candidate_dump:
                surface_changed = True
        if surface_unknown:
            unknown.append(surface_id)
        elif surface_missing:
            missing.append(surface_id)
        elif surface_changed:
            changed.append(surface_id)
    # A contract digest is only meaningful for a root whose every selected
    # node resolved; partial digests could alias distinct contract states.
    current_digest = (
        _contract_digest(current_records) if current_complete else None
    )
    candidate_digest = (
        _contract_digest(candidate_records) if candidate_complete else None
    )
    if unknown:
        status = "unsupported:contract-unverifiable"
    elif missing:
        status = "unsupported:contract-missing"
    elif changed:
        status = GATE_STATUS_BLOCKED
    else:
        status = GATE_STATUS_PROVEN_EQUAL
    return _build_gate_result(
        status, current_digest, candidate_digest, changed, missing, unknown
    )


def run_preservation_gate(current_root: Path, candidate_root: Path) -> dict:
    snapshots: list[_RootSnapshot] = []
    try:
        try:
            if not _PLATFORM_SUPPORTED:
                raise _Unsupported("platform-unsupported")
            _validate_semantic_surfaces()
            current_root = _validate_root_argument(current_root)
            candidate_root = _validate_root_argument(candidate_root)
            file_items = _surface_file_items()
            budget = {"remaining": MAX_TOTAL_MANIFEST_BYTES}
            current_snapshot = _RootSnapshot(current_root)
            snapshots.append(current_snapshot)
            current_analyses = _capture_contract_state(
                current_snapshot, file_items, budget
            )
            candidate_snapshot = _RootSnapshot(candidate_root)
            snapshots.append(candidate_snapshot)
            candidate_analyses = _capture_contract_state(
                candidate_snapshot, file_items, budget
            )
            # Same discipline as the source plan: both chains stay held
            # across the full capture and are verified against what their
            # held parents currently show before any verdict is produced.
            current_snapshot.recheck()
            candidate_snapshot.recheck()
            return _compare_contract_states(
                current_analyses, candidate_analyses
            )
        finally:
            for snapshot in snapshots:
                snapshot.close()
    except _Unsupported as blocked:
        return _build_gate_result(
            f"unsupported:{blocked.token}",
            None,
            None,
            [],
            [],
            _required_surface_ids(),
        )
    except Exception:
        return _build_gate_result(
            "unsupported:internal-error",
            None,
            None,
            [],
            [],
            _required_surface_ids(),
        )


def preservation_exit_code(result: dict) -> int:
    return GATE_EXIT_CODES.get(str(result.get("status")), 2)


class _PlanArgumentParser(argparse.ArgumentParser):
    """Rejected command lines must yield the deterministic unsupported JSON
    contract on stdout, never argparse usage text on stderr.  Help output is
    untouched."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise _CliArgumentError()


def _emit(plan: dict) -> int:
    sys.stdout.write(render_plan(plan) + "\n")
    return plan_exit_code(plan)


def _emit_gate(result: dict) -> int:
    sys.stdout.write(render_plan(result) + "\n")
    return preservation_exit_code(result)


def main(argv: list[str] | None = None) -> int:
    # Argparse rejections happen before flags are parsed, so the output shape
    # for an invalid command line is chosen by a literal scan for the gate
    # flag: gate invocations always get gate-shaped JSON, plan invocations
    # keep their exact v1 bytes.
    raw_argv = list(sys.argv[1:]) if argv is None else list(argv)
    gate_requested = "--preservation-gate" in raw_argv
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
    parser.add_argument(
        "--preservation-gate",
        action="store_true",
        help=(
            "Run the read-only semantic-contract preservation gate instead "
            "of the source-delta plan."
        ),
    )
    try:
        args = parser.parse_args(argv)
    except _CliArgumentError:
        if gate_requested:
            return _emit_gate(
                _build_gate_result(
                    "unsupported:invalid-arguments",
                    None,
                    None,
                    [],
                    [],
                    _required_surface_ids(),
                )
            )
        return _emit(
            _build_plan(
                CLASSIFICATION_UNSUPPORTED,
                "unsupported:invalid-arguments",
                None,
                None,
                [],
            )
        )
    if args.preservation_gate:
        # The expected-build-id contract belongs to the source plan; mixing
        # the two modes is rejected rather than silently ignored.
        if args.expected_candidate_build_id is not None:
            return _emit_gate(
                _build_gate_result(
                    "unsupported:invalid-arguments",
                    None,
                    None,
                    [],
                    [],
                    _required_surface_ids(),
                )
            )
        try:
            result = run_preservation_gate(
                Path(args.current_root), Path(args.candidate_root)
            )
        except Exception:
            result = _build_gate_result(
                "unsupported:internal-error",
                None,
                None,
                [],
                [],
                _required_surface_ids(),
            )
        return _emit_gate(result)
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

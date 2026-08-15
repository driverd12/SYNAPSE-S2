#!/usr/bin/env python3
"""Run the pinned official LongMemEval-V2 harness with the synapse_s2 memory.

Two-phase wrapper.  The OUTER phase (default) never imports any official
module: it creates a fresh, unique, owner-0700 disposable run root under
``/private/tmp`` plus a fresh private bytecode-cache directory inside it,
then re-executes this script in a NEW interpreter so ``PYTHONPYCACHEPREFIX``
is effective for every import the official harness performs.  The adoption
token is passed privately through the child environment, never on the
command line.  The outer phase alone removes the root it created and proves
absence, success or failure.

The INNER phase (``--inner``) adopts the creator's run root with its token,
verifies+bootstraps the pinned official checkout (registering
``memory_type=synapse_s2``), and then either:

* ``--verify-only``: proves the unmodified official ``build_memory``
  resolves ``synapse_s2`` and prints a content-free summary, or
* invokes the pristine pinned ``evaluation.harness`` through a wrapper-only
  lifecycle shim.  The generated ``synapse_s2`` config lets each adapter
  instance allocate a unique workspace inside the run root and carries the
  exact ``trajectories_root_dir``.  ``run_eval`` is never used: it hardcodes
  method choices that do not include synapse_s2.

Harness output is staged inside the run root and relocated to the requested
``--output-dir`` by the outer phase after a successful run.  Public
summaries printed by this wrapper are content-free (no raw absolute paths),
and nothing here computes or claims an official score.

Usage:
    run_longmem_v2_official.py --verify-only [--official-root PATH]
    run_longmem_v2_official.py --domain web --questions-path Q
        --haystack-path H --trajectories-path T --output-dir OUT
        [--memory-config-path CFG] [--save-memory] [--skip-evaluation]
        [--load-memory-dir DIR
         --expected-artifact-manifest-sha256 SHA256]
        [--official-root PATH]
        [-- <extra official harness args...>]
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import importlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from official_longmem import bootstrap as _bootstrap  # noqa: E402

_STAGED_OUTPUT_NAME = "results"
_COPY_CHUNK_BYTES = 1024 * 1024
_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_QUESTIONS_BYTES = 64 * 1024 * 1024
_MAX_HAYSTACK_BYTES = 512 * 1024 * 1024
_MAX_TRAJECTORIES_BYTES = 16 * 1024 * 1024 * 1024
_MAX_API_KEY_BYTES = 64 * 1024
_MAX_TRAJECTORY_TREE_ENTRIES = 2_000_000
_TRAJECTORY_TREE_DEADLINE_SECONDS = 300.0
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
_EXPECTED_ARTIFACT_SHA_KEY = "expected_artifact_manifest_sha256"
_RELEASE_AFTER_QUERY_KEY = "release_after_query"

_EXTRA_VALUE_FLAGS = frozenset(
    {
        "--model",
        "--base-url",
        "--api-key-env",
        "--api-key-file",
        "--max-completion-tokens",
        "--memory-context-max-tokens",
        "--prompt-build-max-workers",
        "--shuffle-questions-seed",
        "--reader-max-concurrent-requests",
        "--timeout-seconds",
        "--reasoning-effort",
        "--temperature",
        "--top-p",
        "--presence-penalty",
        "--top-k",
        "--repetition-penalty",
        "--evaluator-model",
        "--evaluator-base-url",
        "--evaluator-api-key-env",
        "--evaluator-api-key-file",
        "--evaluator-reasoning-effort",
        "--evaluator-max-completion-tokens",
        "--evaluator-timeout-seconds",
    }
)
_EXTRA_SWITCH_FLAGS = frozenset(
    {"--reader-enable-thinking", "--reader-disable-thinking"}
)
_API_KEY_FILE_FLAGS = frozenset(
    {"--api-key-file", "--evaluator-api-key-file"}
)
_API_KEY_ENV_FLAGS = frozenset({"--api-key-env", "--evaluator-api-key-env"})
_SCREENSHOT_COPY_GUIDANCE = (
    "the trajectories tree contains symlinks (the standard symlink-prepared "
    "screenshot layout); this wrapper refuses symlinked media until it can "
    "stage them safely. Re-run the official preparation in copy mode "
    '(data.public_data.prepare_screenshots(mode="copy")) so every entry '
    "under the trajectories root is a regular file or directory"
)


class RunnerError(_bootstrap.BootstrapError):
    """A deliberately content-free validation error safe to print publicly."""


def _fail(message: str) -> None:
    raise RunnerError(message)


def _safe_absolute_path(raw: str | os.PathLike[str], *, owner: str) -> Path:
    """Return a canonical absolute path after content-free path checks."""

    try:
        candidate = _canonical_path(str(raw))
        return _bootstrap.require_no_symlink_components(candidate, owner=owner)
    except (OSError, ValueError, _bootstrap.BootstrapError):
        _fail(f"{owner} failed path safety validation")


def _open_directory_nofollow(
    raw: str | os.PathLike[str], *, owner: str
) -> tuple[int, Path, os.stat_result]:
    """Open an absolute directory one component at a time without symlinks.

    Keeping each parent descriptor open while opening its child prevents a
    rename/symlink swap from redirecting the traversal after validation.
    """

    path = _safe_absolute_path(raw, owner=owner)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if getattr(os, "O_NOFOLLOW", 0) == 0 or getattr(os, "O_DIRECTORY", 0) == 0:
        _fail(f"{owner} cannot be opened safely on this platform")
    try:
        descriptor = os.open(os.sep, directory_flags)
    except OSError:
        _fail(f"{owner} could not be opened safely")
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(component, directory_flags, dir_fd=descriptor)
            except OSError:
                _fail(f"{owner} is unavailable or unsafe")
            os.close(descriptor)
            descriptor = child
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode):
            _fail(f"{owner} is not a directory")
        return descriptor, path, opened
    except BaseException:
        os.close(descriptor)
        raise


def _open_bounded_regular(
    raw: str | os.PathLike[str], *, owner: str, maximum_bytes: int
) -> tuple[int, Path, os.stat_result]:
    """Open one regular file without following its final or parent symlinks."""

    path = _safe_absolute_path(raw, owner=owner)
    if path.name in ("", os.sep):
        _fail(f"{owner} is not a bounded regular file")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        _fail(f"{owner} cannot be opened safely on this platform")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    parent_fd, _parent, _parent_stat = _open_directory_nofollow(
        path.parent, owner=f"{owner} parent"
    )
    try:
        fd = os.open(path.name, flags, dir_fd=parent_fd)
    except OSError:
        os.close(parent_fd)
        _fail(f"{owner} is unavailable or unsafe")
    try:
        opened = os.fstat(fd)
        current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or opened.st_size <= 0
            or opened.st_size > maximum_bytes
        ):
            _fail(f"{owner} is not a bounded regular file")
        return fd, path, opened
    except BaseException:
        os.close(fd)
        raise
    finally:
        os.close(parent_fd)


def _require_unchanged_file(fd: int, before: os.stat_result, *, owner: str) -> None:
    after = os.fstat(fd)
    if (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ):
        _fail(f"{owner} changed while it was being staged")


def _read_bounded_regular(
    raw: str | os.PathLike[str], *, owner: str, maximum_bytes: int
) -> bytes:
    fd, _path, before = _open_bounded_regular(
        raw, owner=owner, maximum_bytes=maximum_bytes
    )
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(_COPY_CHUNK_BYTES, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                _fail(f"{owner} exceeds its byte limit")
        _require_unchanged_file(fd, before, owner=owner)
        if total != before.st_size:
            _fail(f"{owner} changed while it was being read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_private_exclusive(path: Path, payload: bytes, *, owner: str) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(path, flags, 0o600)
    except OSError:
        _fail(f"{owner} could not be created safely")
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                _fail(f"{owner} could not be written completely")
            view = view[written:]
        os.fsync(fd)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)


def _copy_bounded_regular(
    source: str | os.PathLike[str],
    destination: Path,
    *,
    owner: str,
    maximum_bytes: int,
) -> None:
    source_fd, _source_path, before = _open_bounded_regular(
        source, owner=owner, maximum_bytes=maximum_bytes
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        destination_fd = os.open(destination, flags, 0o600)
    except OSError:
        os.close(source_fd)
        _fail(f"staged {owner} could not be created safely")
    total = 0
    try:
        while True:
            chunk = os.read(source_fd, _COPY_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                _fail(f"{owner} exceeds its byte limit")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    _fail(f"staged {owner} could not be written completely")
                view = view[written:]
        _require_unchanged_file(source_fd, before, owner=owner)
        if total != before.st_size:
            _fail(f"{owner} changed while it was being staged")
        os.fsync(destination_fd)
    except BaseException:
        try:
            os.unlink(destination)
        except OSError:
            pass
        raise
    finally:
        os.close(source_fd)
        os.close(destination_fd)


def _canonical_path(raw: str) -> Path:
    """Canonicalize a caller-supplied path without following symlinks.

    expanduser + cwd-join + verified /tmp alias rewrite + LEXICAL normpath.
    The result is what gets used everywhere afterwards, and the strict
    no-symlink-component gates still run against it downstream, so lexical
    dot-dot collapse can never smuggle a path through a symlink.
    """

    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = _bootstrap.normalize_tmp_alias(path)
    return Path(os.path.normpath(path))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_longmem_v2_official",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--official-root",
        default=None,
        help=(
            "path to the pinned official LongMemEval-V2 checkout (defaults "
            f"to the {_bootstrap.OFFICIAL_ROOT_ENV} environment variable)"
        ),
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help=(
            "verify the pinned checkout, registry wiring, and official "
            "build_memory resolution, print the summary, and exit"
        ),
    )
    parser.add_argument("--domain", choices=("web", "enterprise"), default=None)
    parser.add_argument("--questions-path", default=None)
    parser.add_argument("--haystack-path", default=None)
    parser.add_argument("--trajectories-path", default=None)
    parser.add_argument(
        "--output-dir",
        default=None,
        help="final destination for the official harness output directory",
    )
    parser.add_argument(
        "--memory-config-path",
        default=None,
        help=(
            "optional synapse_s2 memory config to use as the base; "
            "memory_type must be synapse_s2 (no other method is supported)"
        ),
    )
    parser.add_argument("--save-memory", action="store_true")
    parser.add_argument("--skip-evaluation", action="store_true")
    parser.add_argument("--load-memory-dir", default=None)
    parser.add_argument(
        "--expected-artifact-manifest-sha256",
        default=None,
        help=(
            "out-of-band SHA-256 of artifact_manifest.json; required with "
            "--load-memory-dir and never read from or persisted into the artifact"
        ),
    )
    parser.add_argument(
        "harness_args",
        nargs=argparse.REMAINDER,
        help="extra arguments passed verbatim to the official harness after --",
    )
    return parser


def _extra_harness_args(args: argparse.Namespace) -> list[str]:
    """Return only explicitly supported reader/evaluator harness options.

    Wrapper-owned arguments are intentionally not forwarded.  This closes
    argparse's last-value-wins behavior, which otherwise lets a second
    ``--memory-config-path`` or ``--output-dir`` replace the governed value.
    """

    extra = list(args.harness_args)
    if extra and extra[0] == "--":
        extra = extra[1:]
    validated: list[str] = []
    seen: set[str] = set()
    index = 0
    while index < len(extra):
        token = extra[index]
        if not isinstance(token, str) or not token.startswith("--"):
            _fail("extra harness arguments contain an unexpected positional value")
        option, separator, inline_value = token.partition("=")
        if option in _EXTRA_SWITCH_FLAGS:
            if separator:
                _fail("an extra harness switch was given an unexpected value")
            logical_option = "--reader-thinking"
            if logical_option in seen:
                _fail("an extra harness option was provided more than once")
            seen.add(logical_option)
            validated.append(option)
            index += 1
            continue
        if option not in _EXTRA_VALUE_FLAGS:
            _fail("extra harness arguments contain an unsupported option")
        if option in seen:
            _fail("an extra harness option was provided more than once")
        seen.add(option)
        if separator:
            if not inline_value:
                _fail("an extra harness option is missing its value")
            value = inline_value
        else:
            index += 1
            if index >= len(extra) or extra[index].startswith("--"):
                _fail("an extra harness option is missing its value")
            value = extra[index]
        if option in _API_KEY_ENV_FLAGS and not _ENV_NAME_RE.fullmatch(value):
            _fail("an API-key environment option has an invalid variable name")
        validated.extend((option, value))
        index += 1
    return validated


def _stage_extra_harness_args(
    args: argparse.Namespace, run_root: "_bootstrap.DisposableRunRoot"
) -> list[str]:
    """Copy accepted key files into the private run root and rewrite paths."""

    validated = _extra_harness_args(args)
    staged: list[str] = []
    index = 0
    key_index = 0
    while index < len(validated):
        option = validated[index]
        staged.append(option)
        if option in _EXTRA_SWITCH_FLAGS:
            index += 1
            continue
        value = validated[index + 1]
        if option in _API_KEY_FILE_FLAGS:
            destination = run_root.trace_parent / f"api-key-{key_index}.txt"
            _copy_bounded_regular(
                value,
                destination,
                owner="API key file",
                maximum_bytes=_MAX_API_KEY_BYTES,
            )
            value = str(destination)
            key_index += 1
        staged.append(value)
        index += 2
    return staged


def _validate_output_destination(path: Path) -> tuple[Path, tuple[int, int]]:
    """Validate a never-existing final destination and bind its parent inode."""

    destination = _safe_absolute_path(path, owner="final output directory")
    try:
        destination = _bootstrap.require_outside_live_store(
            destination, owner="final output directory"
        )
    except _bootstrap.BootstrapError:
        _fail("final output directory failed path safety validation")
    if destination.name in ("", os.sep):
        _fail("final output directory is not a valid child path")
    parent_fd, _parent, parent_stat = _open_directory_nofollow(
        destination.parent, owner="final output parent"
    )
    try:
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError:
            _fail("final output destination could not be inspected safely")
        else:
            _fail("final output destination already exists")
    finally:
        os.close(parent_fd)
    return destination, (parent_stat.st_dev, parent_stat.st_ino)


def _validate_run_request(args: argparse.Namespace) -> dict[str, object]:
    """Fail fast (before any run root exists) on an unusable full-run request."""

    missing = [
        flag
        for flag, value in (
            ("--domain", args.domain),
            ("--questions-path", args.questions_path),
            ("--haystack-path", args.haystack_path),
            ("--trajectories-path", args.trajectories_path),
            ("--output-dir", args.output_dir),
        )
        if value is None
    ]
    if missing:
        _fail(
            f"a full official run requires {', '.join(missing)} "
            "(or pass --verify-only)"
        )
    expected_artifact_sha = args.expected_artifact_manifest_sha256
    if args.load_memory_dir is not None:
        if not isinstance(expected_artifact_sha, str) or not _SHA256_RE.fullmatch(
            expected_artifact_sha
        ):
            _fail(
                "--load-memory-dir requires an explicit 64-hex "
                "--expected-artifact-manifest-sha256"
            )
    elif expected_artifact_sha is not None:
        _fail(
            "--expected-artifact-manifest-sha256 is only valid with "
            "--load-memory-dir"
        )
    # Validate the entire remainder before any disposable state is created.
    _extra_harness_args(args)
    paths: dict[str, object] = {
        "questions": _canonical_path(args.questions_path),
        "haystack": _canonical_path(args.haystack_path),
        "trajectories": _canonical_path(args.trajectories_path),
        "output": _canonical_path(args.output_dir),
    }
    for label, limit in (
        ("questions", _MAX_QUESTIONS_BYTES),
        ("haystack", _MAX_HAYSTACK_BYTES),
        ("trajectories", _MAX_TRAJECTORIES_BYTES),
    ):
        fd, canonical, _opened = _open_bounded_regular(
            paths[label], owner=f"official {label} input", maximum_bytes=limit
        )
        os.close(fd)
        paths[label] = canonical
    destination, parent_identity = _validate_output_destination(
        paths["output"]  # type: ignore[arg-type]
    )
    paths["output"] = destination
    paths["output_parent_identity"] = parent_identity
    if args.load_memory_dir is not None:
        load_fd, load_path, _load_stat = _open_directory_nofollow(
            args.load_memory_dir, owner="load-memory directory"
        )
        os.close(load_fd)
        try:
            paths["load_memory"] = _bootstrap.require_outside_live_store(
                load_path, owner="load-memory directory"
            )
        except _bootstrap.BootstrapError:
            _fail("load-memory directory failed path safety validation")
    return paths


def _reject_symlinks_under(root: Path) -> None:
    """Descriptor-relative, entry/deadline-bounded tree safety scan."""

    root_fd, _root, _root_stat = _open_directory_nofollow(
        root, owner="trajectories tree"
    )
    stack = [root_fd]
    entries = 0
    deadline = time.monotonic() + _TRAJECTORY_TREE_DEADLINE_SECONDS
    try:
        while stack:
            if time.monotonic() > deadline:
                _fail("trajectories tree safety scan exceeded its time limit")
            directory_fd = stack.pop()
            try:
                with os.scandir(directory_fd) as iterator:
                    for entry in iterator:
                        entries += 1
                        if entries > _MAX_TRAJECTORY_TREE_ENTRIES:
                            _fail("trajectories tree exceeds its entry limit")
                        try:
                            node_stat = entry.stat(follow_symlinks=False)
                        except OSError:
                            _fail("trajectories tree contains an unreadable entry")
                        if stat.S_ISLNK(node_stat.st_mode):
                            _fail(_SCREENSHOT_COPY_GUIDANCE)
                        if stat.S_ISDIR(node_stat.st_mode):
                            try:
                                child_fd = os.open(
                                    entry.name,
                                    os.O_RDONLY
                                    | os.O_DIRECTORY
                                    | os.O_NOFOLLOW
                                    | getattr(os, "O_CLOEXEC", 0),
                                    dir_fd=directory_fd,
                                )
                            except OSError:
                                _fail(
                                    "trajectories tree changed during its safety scan"
                                )
                            stack.append(child_fd)
                        elif not stat.S_ISREG(node_stat.st_mode):
                            _fail("trajectories tree contains an unsafe entry type")
            finally:
                os.close(directory_fd)
    except BaseException:
        for descriptor in stack:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _stage_official_inputs(
    run_root: "_bootstrap.DisposableRunRoot", paths: dict[str, object]
) -> dict[str, Path]:
    """Stream official JSON inputs into private immutable-by-name copies."""

    staged: dict[str, Path] = {}
    for label, limit in (
        ("questions", _MAX_QUESTIONS_BYTES),
        ("haystack", _MAX_HAYSTACK_BYTES),
        ("trajectories", _MAX_TRAJECTORIES_BYTES),
    ):
        source = paths[label]
        assert isinstance(source, Path)
        suffix = ".jsonl" if source.suffix.lower() == ".jsonl" else ".json"
        destination = run_root.trace_parent / f"input-{label}{suffix}"
        _copy_bounded_regular(
            source,
            destination,
            owner=f"official {label} input",
            maximum_bytes=limit,
        )
        staged[label] = destination
    return staged


def _generate_memory_config(
    args: argparse.Namespace,
    run_root: "_bootstrap.DisposableRunRoot",
    trajectories_path: Path,
) -> Path:
    if args.memory_config_path is not None:
        raw = _read_bounded_regular(
            args.memory_config_path,
            owner="memory config",
            maximum_bytes=_MAX_CONFIG_BYTES,
        )
        try:
            config = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("memory config is not valid UTF-8 JSON")
        if not isinstance(config, dict) or config.get("memory_type") != "synapse_s2":
            _fail(
                "this wrapper only runs memory_type synapse_s2; run_eval "
                "method choices are not supported"
            )
    else:
        config = {"memory_type": "synapse_s2", "memory_params": {}}
    params = config.get("memory_params")
    if not isinstance(params, dict):
        _fail("memory_params must be a JSON object")
    params = dict(params)
    # The adapter allocates a unique per-instance workspace beneath the active
    # run root when workspace_dir is absent.  A fixed wrapper workspace would
    # make per-question official-harness instances collide.
    params.pop("workspace_dir", None)
    # Never trust a digest embedded in a reusable config.  For an imported
    # artifact the caller must supply the expected manifest digest separately;
    # adapter reconciliation treats it as runtime-only and save serialization
    # excludes it.
    params.pop(_EXPECTED_ARTIFACT_SHA_KEY, None)
    params.pop(_RELEASE_AFTER_QUERY_KEY, None)
    if getattr(args, "load_memory_dir", None) is not None:
        expected = getattr(args, "expected_artifact_manifest_sha256", None)
        assert isinstance(expected, str) and _SHA256_RE.fullmatch(expected)
        params[_EXPECTED_ARTIFACT_SHA_KEY] = expected.lower()
    params["trajectories_root_dir"] = str(trajectories_path.parent)
    config = {**config, "memory_params": params}
    config_path = run_root.trace_parent / "memory_config.json"
    _write_private_exclusive(
        config_path,
        (json.dumps(config, indent=2, ensure_ascii=True) + "\n").encode("utf-8"),
        owner="generated memory config",
    )
    return config_path


def _wire_harness_lifecycle(harness_module: object):
    """Add deterministic SYNAPSE instance release around pinned harness calls.

    The pinned per-question helper constructs a memory but never closes it.
    This wrapper leaves the official source untouched: it marks per-question
    configs for adapter post-query release and also tracks instances in a
    thread-local finally guard so exceptions cannot leak a runtime/workspace.
    Shared instances remain live for all questions and are closed after the
    harness returns.
    """

    marker = "_synapse_s2_lifecycle_wired"
    if getattr(harness_module, marker, False):
        closer = getattr(harness_module, "_synapse_s2_close_remaining", None)
        if not callable(closer):
            _fail("official harness lifecycle marker is malformed")
        return closer

    original_inject = getattr(harness_module, "inject_runtime_memory_params", None)
    original_build = getattr(harness_module, "build_memory", None)
    original_load = getattr(harness_module, "load_memory", None)
    original_per_question = getattr(
        harness_module, "build_prompt_row_with_per_question_memory", None
    )
    if not all(
        callable(item)
        for item in (
            original_inject,
            original_build,
            original_load,
            original_per_question,
        )
    ):
        _fail("the pinned official harness lifecycle surface is incomplete")

    local = threading.local()
    live: dict[int, object] = {}
    live_lock = threading.Lock()

    def register(memory: object) -> object:
        if getattr(memory, "memory_type", None) == "synapse_s2":
            with live_lock:
                live[id(memory)] = memory
            bucket = getattr(local, "per_question", None)
            if isinstance(bucket, list):
                bucket.append(memory)
        return memory

    def close_one(memory: object) -> None:
        try:
            close = getattr(memory, "close", None)
            if callable(close):
                close()
        finally:
            with live_lock:
                live.pop(id(memory), None)

    def wrapped_build(memory_config):
        return register(original_build(memory_config))

    def wrapped_load(input_dir, requested_config=None):
        return register(original_load(input_dir, requested_config=requested_config))

    def wrapped_inject(memory_config, **kwargs):
        runtime_config = original_inject(memory_config, **kwargs)
        if (
            isinstance(runtime_config, dict)
            and runtime_config.get("memory_type") == "synapse_s2"
            and isinstance(runtime_config.get("memory_params"), dict)
        ):
            runtime_config = {
                "memory_type": "synapse_s2",
                "memory_params": dict(runtime_config["memory_params"]),
            }
            workspace = kwargs.get("workspace_dir")
            runtime_config["memory_params"][_RELEASE_AFTER_QUERY_KEY] = not (
                isinstance(workspace, Path) and workspace.name == "shared"
            )
        return runtime_config

    def wrapped_per_question(*args, **kwargs):
        if getattr(local, "per_question", None) is not None:
            _fail("nested per-question harness memory construction is unsupported")
        local.per_question = []
        try:
            return original_per_question(*args, **kwargs)
        finally:
            memories = list(reversed(local.per_question))
            del local.per_question
            for memory in memories:
                close_one(memory)

    def close_remaining() -> None:
        while True:
            with live_lock:
                remaining = list(live.values())
            if not remaining:
                return
            for memory in remaining:
                close_one(memory)

    setattr(harness_module, "inject_runtime_memory_params", wrapped_inject)
    setattr(harness_module, "build_memory", wrapped_build)
    setattr(harness_module, "load_memory", wrapped_load)
    setattr(
        harness_module,
        "build_prompt_row_with_per_question_memory",
        wrapped_per_question,
    )
    setattr(harness_module, "_synapse_s2_close_remaining", close_remaining)
    setattr(harness_module, marker, True)
    return close_remaining


def _run_inner(args: argparse.Namespace) -> int:
    if sys.flags.isolated != 1:
        _fail("inner wrapper requires a fresh isolated Python interpreter")
    base = os.environ.get(_bootstrap.RUN_ROOT_ENV)
    token = os.environ.get(_bootstrap.RUN_TOKEN_ENV)
    if not base or not token:
        _fail(
            "inner wrapper mode requires the creating wrapper's run root and "
            f"token in {_bootstrap.RUN_ROOT_ENV}/{_bootstrap.RUN_TOKEN_ENV}; "
            "invoke scripts/run_longmem_v2_official.py without --inner"
        )
    run_root = _bootstrap.activate_run_root(adopt=_canonical_path(base), token=token)
    try:
        # The child is dedicated to one disposable run.  Keep every official
        # harness output owner-private even before the publication hardening
        # pass below.
        os.umask(0o077)
        official_root = (
            str(_canonical_path(args.official_root))
            if args.official_root is not None
            else None
        )
        summary = _bootstrap.bootstrap_official(official_root)
        print(json.dumps(summary, indent=2, sort_keys=True), file=sys.stderr)

        official = importlib.import_module("memory_modules.memory")
        adapter_module = importlib.import_module(
            "official_longmem.synapse_s2_memory"
        )
        if args.verify_only:
            memory = official.build_memory(
                {"memory_type": adapter_module.MEMORY_TYPE, "memory_params": {}}
            )
            try:
                report = dict(summary)
                report["build_memory_resolved"] = type(memory).__name__
                report["memory_config_public_keys"] = sorted(
                    memory.memory_config["memory_params"]
                )
                print(json.dumps(report, indent=2, sort_keys=True))
            finally:
                close = getattr(memory, "close", None)
                if callable(close):
                    close()
            return 0

        paths = _validate_run_request(args)
        trajectories_path = paths["trajectories"]
        assert isinstance(trajectories_path, Path)
        _reject_symlinks_under(trajectories_path.parent)
        staged_inputs = _stage_official_inputs(run_root, paths)
        config_path = _generate_memory_config(args, run_root, trajectories_path)
        staging = run_root.output_parent / _STAGED_OUTPUT_NAME

        harness_argv = [
            "harness.py",
            "--domain",
            str(args.domain),
            "--questions-path",
            str(staged_inputs["questions"]),
            "--haystack-path",
            str(staged_inputs["haystack"]),
            "--trajectories-path",
            str(staged_inputs["trajectories"]),
            "--memory-config-path",
            str(config_path),
            "--output-dir",
            str(staging),
        ]
        if args.save_memory:
            harness_argv.append("--save-memory")
        if args.skip_evaluation:
            harness_argv.append("--skip-evaluation")
        if "load_memory" in paths:
            harness_argv += ["--load-memory-dir", str(paths["load_memory"])]
        harness_argv += _stage_extra_harness_args(args, run_root)

        harness_module = importlib.import_module("evaluation.harness")
        close_remaining = _wire_harness_lifecycle(harness_module)
        harness_main = getattr(harness_module, "main", None)
        if not callable(harness_main):
            _fail("the official evaluation.harness module has no main()")
        saved_argv = sys.argv
        try:
            sys.argv = harness_argv
            try:
                result = harness_main()
            except SystemExit as exc:
                code = exc.code
                result = code if isinstance(code, int) else (0 if code is None else 1)
            except Exception as exc:
                raise RunnerError("the official harness execution failed") from exc
        finally:
            try:
                close_remaining()
            finally:
                sys.argv = saved_argv
        return int(result) if isinstance(result, int) else 0
    finally:
        # Adopted root: deactivation never removes it; the creator does.
        _bootstrap.deactivate_run_root()


def _harden_staged_output_tree(root_fd: int) -> None:
    """Reject unsafe output nodes and enforce 0700 directories/0600 files."""

    os.fchmod(root_fd, 0o700)
    stack = [os.dup(root_fd)]
    entries = 0
    deadline = time.monotonic() + _TRAJECTORY_TREE_DEADLINE_SECONDS
    try:
        while stack:
            if time.monotonic() > deadline:
                _fail("staged output validation exceeded its time limit")
            directory_fd = stack.pop()
            try:
                with os.scandir(directory_fd) as iterator:
                    for entry in iterator:
                        entries += 1
                        if entries > _MAX_TRAJECTORY_TREE_ENTRIES:
                            _fail("staged output exceeds its entry limit")
                        try:
                            before = entry.stat(follow_symlinks=False)
                        except OSError:
                            _fail("staged output contains an unreadable entry")
                        if stat.S_ISDIR(before.st_mode):
                            try:
                                child_fd = os.open(
                                    entry.name,
                                    os.O_RDONLY
                                    | os.O_DIRECTORY
                                    | os.O_NOFOLLOW
                                    | getattr(os, "O_CLOEXEC", 0),
                                    dir_fd=directory_fd,
                                )
                            except OSError:
                                _fail("staged output changed during validation")
                            opened = os.fstat(child_fd)
                            if (opened.st_dev, opened.st_ino) != (
                                before.st_dev,
                                before.st_ino,
                            ):
                                os.close(child_fd)
                                _fail("staged output changed during validation")
                            os.fchmod(child_fd, 0o700)
                            stack.append(child_fd)
                        elif stat.S_ISREG(before.st_mode):
                            try:
                                file_fd = os.open(
                                    entry.name,
                                    os.O_RDONLY
                                    | os.O_NOFOLLOW
                                    | getattr(os, "O_CLOEXEC", 0),
                                    dir_fd=directory_fd,
                                )
                            except OSError:
                                _fail("staged output changed during validation")
                            try:
                                opened = os.fstat(file_fd)
                                if (
                                    (opened.st_dev, opened.st_ino)
                                    != (before.st_dev, before.st_ino)
                                    or opened.st_nlink != 1
                                ):
                                    _fail("staged output contains an unsafe file")
                                os.fchmod(file_fd, 0o600)
                            finally:
                                os.close(file_fd)
                        else:
                            _fail("staged output contains an unsafe entry type")
            finally:
                os.close(directory_fd)
    except BaseException:
        for descriptor in stack:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _relocate_staged_output(
    run_root: "_bootstrap.DisposableRunRoot",
    destination: Path,
    expected_parent_identity: tuple[int, int],
) -> bool:
    """Atomically publish staged output without following or replacing names."""

    staging = run_root.output_parent / _STAGED_OUTPUT_NAME
    if not os.path.lexists(staging):
        _fail("the official harness produced no staged output directory")
    source_fd, _source_parent, source_parent_stat = _open_directory_nofollow(
        run_root.output_parent, owner="staged output parent"
    )
    destination_fd, _destination_parent, destination_parent_stat = (
        _open_directory_nofollow(
            destination.parent, owner="final output parent"
        )
    )
    try:
        if (
            destination_parent_stat.st_dev,
            destination_parent_stat.st_ino,
        ) != expected_parent_identity:
            _fail("final output parent changed after validation")
        if source_parent_stat.st_dev != destination_parent_stat.st_dev:
            _fail("final output parent must be on the staging filesystem")
        try:
            staged_stat = os.stat(
                _STAGED_OUTPUT_NAME,
                dir_fd=source_fd,
                follow_symlinks=False,
            )
        except OSError:
            _fail("staged output disappeared before publication")
        if not stat.S_ISDIR(staged_stat.st_mode):
            _fail("staged output is not a directory")
        try:
            staging_fd = os.open(
                _STAGED_OUTPUT_NAME,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=source_fd,
            )
        except OSError:
            _fail("staged output changed during validation")
        try:
            opened_staging = os.fstat(staging_fd)
            if (opened_staging.st_dev, opened_staging.st_ino) != (
                staged_stat.st_dev,
                staged_stat.st_ino,
            ):
                _fail("staged output changed during validation")
            _harden_staged_output_tree(staging_fd)
        finally:
            os.close(staging_fd)

        source_name = os.fsencode(_STAGED_OUTPUT_NAME)
        destination_name = os.fsencode(destination.name)
        libc = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
            rename = libc.renameatx_np
            rename.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            rename.restype = ctypes.c_int
            result = rename(
                source_fd,
                source_name,
                destination_fd,
                destination_name,
                0x00000004,  # RENAME_EXCL from <sys/stdio.h>
            )
        elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
            rename = libc.renameat2
            rename.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            rename.restype = ctypes.c_int
            result = rename(
                source_fd,
                source_name,
                destination_fd,
                destination_name,
                0x00000001,  # RENAME_NOREPLACE
            )
        else:
            _fail("atomic no-clobber output publication is unavailable")
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number in (errno.EEXIST, errno.ENOTEMPTY):
                _fail("final output destination already exists")
            _fail("atomic output publication failed")
        try:
            published = os.stat(
                destination.name,
                dir_fd=destination_fd,
                follow_symlinks=False,
            )
        except OSError:
            _fail("published output could not be verified")
        if not stat.S_ISDIR(published.st_mode):
            _fail("published output is not a directory")
    finally:
        os.close(source_fd)
        os.close(destination_fd)
    return True


def _run_outer(args: argparse.Namespace, argv: list[str]) -> int:
    destination: Path | None = None
    destination_parent_identity: tuple[int, int] | None = None
    if not args.verify_only:
        validated = _validate_run_request(args)
        destination = validated["output"]  # type: ignore[assignment]
        destination_parent_identity = validated[
            "output_parent_identity"
        ]  # type: ignore[assignment]

    run_root = _bootstrap.DisposableRunRoot()
    relocated = False
    try:
        pycache_dir = Path(
            tempfile.mkdtemp(prefix="cache-", dir=run_root.pycache_parent)
        )
        os.chmod(pycache_dir, 0o700)

        child_env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("PYTHON", "DYLD_", "LD_", "GIT_"))
            and key != "__PYVENV_LAUNCHER__"
        }
        child_env[_bootstrap.RUN_ROOT_ENV] = str(run_root.base)
        # The adoption token travels only in the child environment, never on
        # the command line.
        child_env[_bootstrap.RUN_TOKEN_ENV] = run_root.token
        if args.official_root is not None:
            child_env[_bootstrap.OFFICIAL_ROOT_ENV] = str(
                _canonical_path(args.official_root)
            )

        child = subprocess.run(
            [
                sys.executable,
                "-I",
                "-X",
                f"pycache_prefix={pycache_dir}",
                str(Path(__file__).resolve()),
                "--inner",
                *argv,
            ],
            env=child_env,
            check=False,
        )
        returncode = child.returncode
        if returncode == 0 and destination is not None:
            assert destination_parent_identity is not None
            relocated = _relocate_staged_output(
                run_root, destination, destination_parent_identity
            )
        return returncode
    finally:
        run_root.close()  # verified removal; fails loudly on residue
        completion = {
            "run_root_removed": not os.path.lexists(run_root.base),
            "private_pycache_removed": not os.path.lexists(run_root.pycache_parent),
            "output_relocated": relocated,
            "official_score_claimed": False,
        }
        print(json.dumps(completion, sort_keys=True), file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    try:
        args = _build_parser().parse_args(argv)
        if args.inner:
            inner_argv = [entry for entry in argv if entry != "--inner"]
            return _run_inner(_build_parser().parse_args(inner_argv))
        return _run_outer(args, argv)
    except RunnerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except _bootstrap.BootstrapError:
        print(
            "error: official LongMemEval bootstrap validation failed",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

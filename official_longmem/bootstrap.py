"""Bootstrap for running the pinned official LongMemEval-V2 harness.

This module is the only supported way to make the ``synapse_s2`` memory type
available to the official harness.  It never edits any file inside the
official checkout, never installs anything, and never persists environment
state:

* ``verify_official_checkout`` fails closed unless the provided checkout path
  is absolute with no dot-dot and no symlink components (checked BEFORE any
  resolution -- the single deterministic exception is the verified macOS
  ``/tmp`` -> ``/private/tmp`` alias, which is rewritten, never followed), is
  at the exact pinned commit, has zero modified tracked files, zero untracked
  files, and no code-shaped ignored files (``.py``/``.pyc``/``.pyo``/
  ``.so``/``.dylib``, ``sitecustomize``/``usercustomize``) in importable
  official directories.  All git enumerations are bounded, streamed with a
  hard deadline, and pathspec-restricted so huge dataset/run trees are never
  enumerated and a hung or flooding git child is killed instead of blocking.
* ``official_dependency_preflight`` enforces the interpreter floor and
  reports exact versions plus content-free origin labels for every official
  third-party dependency (torch/torchvision included); it never installs
  anything and the wrapper never adds pip or network behavior.
* ``bootstrap_official`` rejects preloaded official modules (and, on
  repeated bootstraps, re-verifies that every loaded official module still
  resolves from inside the pinned checkout), wires ``sys.path`` for this
  process only (official checkout index 0, this repository index 1, an
  optional explicit test-only dependency directory last), imports the pinned
  ``memory_modules.memory`` contract, proves it resolved from inside the
  pinned checkout, and registers ``synapse_s2`` with the pinned registry so
  the unmodified official ``build_memory``/``load_memory`` resolve it.  The
  returned summary is content-free: no raw absolute paths.
* ``DisposableRunRoot`` provides a short, private, freshly created
  ``/private/tmp`` root with separate workspace/runtime/trace/pycache
  parents and a random adoption token, so runtime sockets never depend on
  long or space-containing artifact paths and only the wrapper's own child
  process can adopt the root it created.  Every disposable write path must
  be contained in the active run root, and all cleanup is verified: removal
  helpers validate containment first and fail loudly on residue.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import os
import platform
import secrets
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath

from official_longmem import OFFICIAL_COMMIT_PIN

OFFICIAL_COMMIT = OFFICIAL_COMMIT_PIN
OFFICIAL_ROOT_ENV = "LONGMEM_V2_OFFICIAL_ROOT"
OFFICIAL_DEPS_ENV = "LONGMEM_V2_OFFICIAL_DEPS"
RUN_ROOT_ENV = "LONGMEM_V2_RUN_ROOT"
RUN_TOKEN_ENV = "LONGMEM_V2_RUN_TOKEN"
REPO_ROOT = Path(__file__).resolve().parents[1]
RUN_ROOT_PARENT = Path("/private/tmp")
RUN_ROOT_PREFIX = "s2lm-"
RUN_TOKEN_NAME = "run.token"
LIVE_STORE_DIR_NAME = ".synapse_s2"
GIT_EXECUTABLE = Path("/usr/bin/git")

_REQUIRED_OFFICIAL_FILES = (
    "memory_modules/memory.py",
    "evaluation/harness.py",
    "evaluation/run_eval.py",
    "data/public_data.py",
)

# Third-party modules the pinned official harness imports at module load.
# The preflight only reports absences; nothing here ever installs.
OFFICIAL_THIRD_PARTY_MODULES = (
    "agents",
    "openai",
    "PIL",
    "numpy",
    "tqdm",
    "transformers",
    "huggingface_hub",
)

# Optional GPU extras pinned by the checkout's requirements-torch.txt.  They
# are reported always and, when importable, enforced against the exact pins.
OFFICIAL_OPTIONAL_TORCH_MODULES = ("torch", "torchvision")

_MODULE_TO_DISTRIBUTION = {
    "agents": "openai-agents",
    "PIL": "pillow",
}

# Official top-level packages that must never be imported before the pinned
# checkout is wired at sys.path index 0.
OFFICIAL_TOP_LEVEL_PACKAGES = ("memory_modules", "evaluation", "data")

# Ignored paths under these prefixes are dataset/run outputs, never imported.
_ALLOWED_IGNORED_PREFIXES = (
    "data/longmemeval-v2/",
    "runs/",
    "leaderboard/submissions/",
)
_CODE_SUFFIXES = (".py", ".pyc", ".pyo", ".so", ".dylib")

# Hard cap on entries any bounded git enumeration may yield, and the hard
# wall-clock deadline after which a git child is killed.
_GIT_ENTRY_CAP = 10000
_GIT_DEADLINE_SECONDS = 120.0

# Top-level entries a bytecode-cache prefix may contain: mirror directories
# only, and never more than this many path-root components.
_PYCACHE_TOP_LEVEL_CAP = 32


class BootstrapError(RuntimeError):
    """The pinned harness or a disposable root cannot establish its invariants."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BootstrapError(message)


def normalize_tmp_alias(path: str | os.PathLike[str]) -> Path:
    """Rewrite the single known macOS ``/tmp`` -> ``/private/tmp`` alias.

    The rewrite happens only when ``/tmp`` is verified (via ``readlink``) to
    be exactly the platform alias, so this never follows an arbitrary
    symlink; every other symlink component is still rejected by the strict
    pre-resolution gate.
    """

    candidate = Path(path)
    if not candidate.is_absolute():
        return candidate
    parts = candidate.parts
    if len(parts) < 2 or parts[0] != os.sep or parts[1] != "tmp":
        return candidate
    try:
        link_stat = os.lstat("/tmp")
    except OSError:
        return candidate
    if not stat.S_ISLNK(link_stat.st_mode):
        return candidate
    if os.readlink("/tmp") not in ("private/tmp", "/private/tmp"):
        return candidate
    return Path("/private/tmp", *parts[2:])


def require_no_symlink_components(path: str | os.PathLike[str], *, owner: str) -> Path:
    """Reject dot-dot/dot components and any symlink component along ``path``.

    Rejection happens BEFORE any resolution, so a crafted path can never be
    canonicalized into (or out of) a guarded root behind this gate.  Returns
    the alias-normalized path; callers must use the return value.
    """

    candidate = normalize_tmp_alias(path)
    _require(candidate.is_absolute(), f"{owner} must be an absolute path: {candidate}")
    _require(
        ".." not in candidate.parts and "." not in candidate.parts,
        f"{owner} must not contain dot-dot or dot components: {candidate}",
    )
    for node in (candidate, *candidate.parents):
        try:
            node_stat = os.lstat(node)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise BootstrapError(f"{owner} component could not be inspected: {node}") from exc
        _require(
            not stat.S_ISLNK(node_stat.st_mode),
            f"{owner} contains a symlink component: {node}",
        )
    return candidate


def live_store_roots() -> tuple[Path, ...]:
    """Candidate live SYNAPSE-S2 store roots that must never be touched."""

    candidates = {
        REPO_ROOT / LIVE_STORE_DIR_NAME,
        Path.cwd() / LIVE_STORE_DIR_NAME,
        Path.home() / LIVE_STORE_DIR_NAME,
    }
    env_root = os.environ.get("SYNAPSE_S2_DATA_ROOT")
    if env_root and env_root.strip():
        candidates.add(Path(env_root).expanduser())
    return tuple(sorted(candidates, key=str))


def require_outside_live_store(path: str | os.PathLike[str], *, owner: str) -> Path:
    """Reject any overlap (either direction) with a live SYNAPSE-S2 store."""

    candidate = normalize_tmp_alias(path)
    _require(candidate.is_absolute(), f"{owner} must be an absolute path: {candidate}")
    _require(
        ".." not in candidate.parts and "." not in candidate.parts,
        f"{owner} must not contain dot-dot or dot components: {candidate}",
    )
    _require(
        LIVE_STORE_DIR_NAME not in candidate.parts,
        f"{owner} must not contain a {LIVE_STORE_DIR_NAME} component: {candidate}",
    )
    for store in live_store_roots():
        overlap = candidate.is_relative_to(store) or store.is_relative_to(candidate)
        _require(
            not overlap,
            f"{owner} overlaps the live SYNAPSE-S2 store {store}: {candidate}",
        )
    return candidate


def require_disposable_root(path: str | os.PathLike[str], *, owner: str) -> Path:
    """Full disposable-root gate: no symlink components, no live-store overlap."""

    candidate = require_no_symlink_components(path, owner=owner)
    return require_outside_live_store(candidate, owner=owner)


def require_within_active_run_root(
    path: str | os.PathLike[str], *, owner: str
) -> Path:
    """Require full gates plus containment in the active disposable run root.

    Every disposable write path (workspace, runtime root, artifact staging)
    must live inside the wrapper-created run root; lexical non-overlap with
    live paths alone is not sufficient.
    """

    candidate = require_disposable_root(path, owner=owner)
    run_root = active_run_root()
    _require(
        run_root is not None,
        f"{owner} requires an active disposable run root "
        "(invoke scripts/run_longmem_v2_official.py or activate one first)",
    )
    assert run_root is not None
    _require(
        candidate.is_relative_to(run_root.base),
        f"{owner} must be contained in the active disposable run root "
        f"{run_root.base}: {candidate}",
    )
    return candidate


def remove_tree_checked(
    path: str | os.PathLike[str],
    *,
    owner: str,
    safe_root: str | os.PathLike[str],
) -> None:
    """Remove a tree only inside a validated disposable safe root.

    The target must be contained in ``safe_root`` and ``safe_root`` itself
    must be a run-root-shaped directory directly under ``/private/tmp``
    (``s2lm-*``), so an arbitrary caller path can never be recursively
    deleted.  Fails loudly if any residue remains afterwards.
    """

    safe = require_no_symlink_components(safe_root, owner=f"{owner} cleanup safe root")
    safe = require_outside_live_store(safe, owner=f"{owner} cleanup safe root")
    _require(
        safe.parent == RUN_ROOT_PARENT and safe.name.startswith(RUN_ROOT_PREFIX),
        f"{owner} cleanup safe root must be a disposable {RUN_ROOT_PREFIX}* "
        f"directory directly under {RUN_ROOT_PARENT}: {safe}",
    )
    target = normalize_tmp_alias(path)
    _require(target.is_absolute(), f"{owner} cleanup target must be absolute: {target}")
    _require(
        ".." not in target.parts and "." not in target.parts,
        f"{owner} cleanup target must not contain dot-dot or dot components: {target}",
    )
    _require(
        target == safe or target.is_relative_to(safe),
        f"{owner} cleanup target escapes its safe root {safe}: {target}",
    )
    require_outside_live_store(target, owner=f"{owner} cleanup target")
    if not os.path.lexists(target):
        return
    _require(
        not stat.S_ISLNK(os.lstat(target).st_mode),
        f"{owner} cleanup target must not be a symlink: {target}",
    )
    shutil.rmtree(target, ignore_errors=True)
    _require(
        not os.path.lexists(target),
        f"{owner} cleanup left residue at {target}; remove it manually and "
        "investigate what held it open",
    )


def _require_private_dir(path: Path, *, owner: str) -> None:
    try:
        node_stat = os.lstat(path)
    except OSError as exc:
        raise BootstrapError(f"{owner} could not be inspected: {path}") from exc
    _require(stat.S_ISDIR(node_stat.st_mode), f"{owner} is not a directory: {path}")
    _require(
        node_stat.st_uid == os.getuid(),
        f"{owner} is not owned by the current user: {path}",
    )
    _require(
        stat.S_IMODE(node_stat.st_mode) == 0o700,
        f"{owner} must have exactly mode 0700: {path}",
    )


class DisposableRunRoot:
    """Short private /private/tmp root with workspace/runtime/trace/pycache parents."""

    _CHILD_NAMES = ("ws", "rt", "tr", "pyc", "out")

    def __init__(self) -> None:
        _require(
            RUN_ROOT_PARENT.is_dir(),
            f"{RUN_ROOT_PARENT} must exist to host disposable run roots",
        )
        base = Path(tempfile.mkdtemp(prefix=RUN_ROOT_PREFIX, dir=RUN_ROOT_PARENT))
        try:
            os.chmod(base, 0o700)
            require_disposable_root(base, owner="disposable run root")
            for name in self._CHILD_NAMES:
                (base / name).mkdir(mode=0o700)
            token = secrets.token_hex(16)
            token_path = base / RUN_TOKEN_NAME
            fd = os.open(
                token_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                os.write(fd, token.encode("ascii"))
            finally:
                os.close(fd)
        except BaseException as exc:
            try:
                remove_tree_checked(base, owner="disposable run root", safe_root=base)
            except BootstrapError as cleanup_exc:
                raise cleanup_exc from exc
            raise
        self._wire(base, token, owned=True)

    def _wire(self, base: Path, token: str, *, owned: bool) -> None:
        self.base = base
        self.token = token
        self.workspace_parent = base / "ws"
        self.runtime_parent = base / "rt"
        self.trace_parent = base / "tr"
        self.pycache_parent = base / "pyc"
        self.output_parent = base / "out"
        self._owned = owned
        self._closed = False

    @classmethod
    def adopt(cls, base: str | os.PathLike[str], *, token: str) -> "DisposableRunRoot":
        """Adopt the run root this wrapper invocation created in its parent.

        Adoption requires the random per-run token written by the creating
        process, so an arbitrary or stale ``s2lm-*`` directory can never be
        adopted; every structural invariant of a freshly created root is
        re-verified as well.
        """

        _require(
            isinstance(token, str) and len(token) == 32,
            "adopted run root requires the creating wrapper's run token",
        )
        path = require_disposable_root(base, owner="adopted run root")
        _require(
            path.parent == RUN_ROOT_PARENT,
            f"adopted run root must live directly under {RUN_ROOT_PARENT}: {path}",
        )
        _require(
            path.name.startswith(RUN_ROOT_PREFIX),
            f"adopted run root must be named {RUN_ROOT_PREFIX}*: {path}",
        )
        _require_private_dir(path, owner="adopted run root")
        for name in cls._CHILD_NAMES:
            _require_private_dir(path / name, owner=f"adopted run root child {name}")
        token_path = path / RUN_TOKEN_NAME
        token_stat = os.lstat(token_path)
        _require(
            stat.S_ISREG(token_stat.st_mode)
            and stat.S_IMODE(token_stat.st_mode) == 0o600
            and token_stat.st_uid == os.getuid()
            and token_stat.st_size == 32,
            "adopted run root token file is malformed",
        )
        stored = token_path.read_bytes().decode("ascii", errors="replace")
        _require(
            secrets.compare_digest(stored, token),
            "adopted run root token does not match this wrapper invocation",
        )
        instance = cls.__new__(cls)
        instance._wire(path, token, owned=False)
        return instance

    def close(self) -> None:
        """Remove the root (creator only): adopted roots are removed by their creator."""

        if not self._closed:
            if self._owned:
                remove_tree_checked(
                    self.base, owner="disposable run root", safe_root=self.base
                )
            self._closed = True


_RUN_ROOT_LOCK = threading.Lock()
_ACTIVE_RUN_ROOT: DisposableRunRoot | None = None
_VERIFIED_OFFICIAL_ROOT: Path | None = None


def activate_run_root(
    adopt: str | os.PathLike[str] | None = None,
    *,
    token: str | None = None,
) -> DisposableRunRoot:
    """Create (or adopt with its token) the process-wide disposable run root."""

    global _ACTIVE_RUN_ROOT
    with _RUN_ROOT_LOCK:
        _require(_ACTIVE_RUN_ROOT is None, "a disposable run root is already active")
        if adopt is None:
            _ACTIVE_RUN_ROOT = DisposableRunRoot()
        else:
            _require(token is not None, "adopting a run root requires its token")
            assert token is not None
            _ACTIVE_RUN_ROOT = DisposableRunRoot.adopt(adopt, token=token)
        return _ACTIVE_RUN_ROOT


def deactivate_run_root() -> None:
    """Close and clear the active disposable run root (idempotent, verified)."""

    global _ACTIVE_RUN_ROOT
    with _RUN_ROOT_LOCK:
        if _ACTIVE_RUN_ROOT is not None:
            active = _ACTIVE_RUN_ROOT
            _ACTIVE_RUN_ROOT = None
            active.close()


def active_run_root() -> DisposableRunRoot | None:
    with _RUN_ROOT_LOCK:
        return _ACTIVE_RUN_ROOT


def verified_official_root() -> Path:
    """The checkout verified by ``bootstrap_official`` in this process."""

    _require(
        _VERIFIED_OFFICIAL_ROOT is not None,
        "bootstrap_official has not verified an official checkout yet",
    )
    assert _VERIFIED_OFFICIAL_ROOT is not None
    return _VERIFIED_OFFICIAL_ROOT


def _trusted_git_command(root: Path, *args: str) -> list[str]:
    _require(
        GIT_EXECUTABLE.is_file() and not GIT_EXECUTABLE.is_symlink(),
        "trusted system git executable is unavailable",
    )
    return [
        str(GIT_EXECUTABLE),
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-C",
        str(root),
        *args,
    ]


def _trusted_git_env() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    env.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return env


def _git_output(root: Path, *args: str) -> str:
    completed = subprocess.run(
        _trusted_git_command(root, *args),
        env=_trusted_git_env(),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    _require(
        completed.returncode == 0,
        f"git {' '.join(args)} failed for {root}: {completed.stderr.strip()[:400]}",
    )
    return completed.stdout


def _git_paths_bounded(
    root: Path,
    args: list[str],
    *,
    owner: str,
    limit: int = _GIT_ENTRY_CAP,
    deadline_seconds: float = _GIT_DEADLINE_SECONDS,
) -> list[str]:
    """Collect NUL-delimited git output entries with hard caps and a deadline.

    stdout is consumed incrementally through a selector with a wall-clock
    deadline so a hung or flooding git child is killed instead of blocking
    forever; stderr goes to an anonymous temporary file so it can never
    deadlock the pipe.  Crossing ``limit`` kills git and fails closed.
    """

    entries: list[str] = []
    failure: str | None = None
    deadline = time.monotonic() + deadline_seconds
    with tempfile.TemporaryFile() as stderr_file:
        proc = subprocess.Popen(
            _trusted_git_command(root, *args),
            env=_trusted_git_env(),
            stdout=subprocess.PIPE,
            stderr=stderr_file,
        )
        assert proc.stdout is not None
        try:
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ)
            try:
                buffer = b""
                open_stream = True
                while open_stream and failure is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        failure = f"{owner}: git did not finish within the deadline"
                        break
                    ready = selector.select(timeout=min(remaining, 1.0))
                    if not ready:
                        continue
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    if not chunk:
                        open_stream = False
                        break
                    buffer += chunk
                    parts = buffer.split(b"\x00")
                    buffer = parts.pop()
                    for part in parts:
                        if not part:
                            continue
                        entries.append(part.decode("utf-8", errors="replace"))
                        if len(entries) > limit:
                            failure = (
                                f"{owner}: git produced more than {limit} entries; "
                                "refusing to enumerate further against a tree "
                                "this far from pristine"
                            )
                            break
            finally:
                selector.close()
            if failure is not None:
                raise BootstrapError(failure)
            try:
                returncode = proc.wait(timeout=max(deadline - time.monotonic(), 1.0))
            except subprocess.TimeoutExpired:
                raise BootstrapError(f"{owner}: git did not exit within the deadline")
            stderr_file.seek(0)
            stderr_tail = stderr_file.read(4096)
            _require(
                returncode == 0,
                f"{owner}: git {' '.join(args)} failed for {root}: "
                f"{stderr_tail.decode('utf-8', errors='replace').strip()[:400]}",
            )
            _require(not buffer, f"{owner}: truncated NUL-delimited git output")
            return entries
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=60)
            proc.stdout.close()


def _validate_existing_pycache_mirror(root: Path) -> None:
    """Bound an already-created mirror on a repeated in-process bootstrap."""

    entry_count = 0
    deadline = time.monotonic() + 30.0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        _require(
            time.monotonic() <= deadline,
            "bytecode cache mirror validation exceeded its deadline",
        )
        for name in (*dirnames, *filenames):
            entry_count += 1
            _require(
                entry_count <= _GIT_ENTRY_CAP,
                "bytecode cache mirror exceeds its entry limit",
            )
            path = Path(dirpath) / name
            try:
                node_stat = os.lstat(path)
            except OSError as exc:
                raise BootstrapError(
                    "bytecode cache mirror changed during validation"
                ) from exc
            _require(
                not stat.S_ISLNK(node_stat.st_mode),
                "bytecode cache mirror contains a symlink",
            )
            if name in dirnames:
                _require(
                    stat.S_ISDIR(node_stat.st_mode),
                    "bytecode cache mirror contains an unsafe directory entry",
                )
            else:
                _require(
                    stat.S_ISREG(node_stat.st_mode)
                    and path.suffix.lower() == ".pyc"
                    and node_stat.st_nlink == 1,
                    "bytecode cache mirror contains an unsafe file entry",
                )


def require_private_pycache(
    checkout: Path, *, allow_existing_official_mirror: bool = False
) -> Path:
    """Require the current run's fresh private owner-0700 bytecode-cache prefix.

    With ``sys.pycache_prefix`` set, CPython neither reads nor writes in-tree
    ``__pycache__`` directories for source-backed imports, which is what makes
    the checkout's ignored bytecode inert.  Only the prefix created for THIS
    wrapper invocation is accepted: it must live strictly inside the active
    disposable run root's ``pyc`` parent, be an owner-0700 directory, contain
    nothing but mirror directories, and carry no pre-existing bytecode mirror
    for the official checkout (stale prefixes are rejected).
    """

    prefix = sys.pycache_prefix
    _require(
        isinstance(prefix, str) and bool(prefix.strip()),
        "a private PYTHONPYCACHEPREFIX is required to run the pinned official "
        "harness; invoke scripts/run_longmem_v2_official.py (which re-executes "
        "itself with one) or set PYTHONPYCACHEPREFIX to a fresh directory "
        "under the active run root",
    )
    assert isinstance(prefix, str)
    prefix_path = require_disposable_root(Path(prefix), owner="bytecode cache prefix")
    run_root = active_run_root()
    _require(
        run_root is not None,
        "bytecode cache prefix validation requires an active disposable run root",
    )
    assert run_root is not None
    _require(
        prefix_path != run_root.pycache_parent
        and prefix_path.is_relative_to(run_root.pycache_parent),
        "bytecode cache prefix must live strictly inside the active run "
        f"root's pycache parent {run_root.pycache_parent}: {prefix_path}",
    )
    _require(
        not prefix_path.is_relative_to(checkout) and not checkout.is_relative_to(prefix_path),
        f"bytecode cache prefix must be outside the official checkout: {prefix_path}",
    )
    _require(
        not prefix_path.is_relative_to(REPO_ROOT) and not REPO_ROOT.is_relative_to(prefix_path),
        f"bytecode cache prefix must be outside this repository: {prefix_path}",
    )
    _require_private_dir(prefix_path, owner="bytecode cache prefix")
    entry_count = 0
    with os.scandir(prefix_path) as children:
        for child in children:
            entry_count += 1
            _require(
                entry_count <= _PYCACHE_TOP_LEVEL_CAP,
                f"bytecode cache prefix has too many top-level entries: {prefix_path}",
            )
            child_stat = os.lstat(child.path)
            _require(
                stat.S_ISDIR(child_stat.st_mode),
                "bytecode cache prefix may contain only bytecode mirror "
                f"directories: {prefix_path}",
            )
    checkout_mirror = Path(prefix_path, *checkout.parts[1:])
    if os.path.lexists(checkout_mirror):
        _require(
            allow_existing_official_mirror,
            "bytecode cache prefix already contains a bytecode mirror for the "
            f"official checkout (stale prefix): {prefix_path}; use a fresh one",
        )
        try:
            mirror_stat = os.lstat(checkout_mirror)
        except OSError as exc:
            raise BootstrapError(
                "bytecode cache mirror could not be inspected"
            ) from exc
        _require(
            stat.S_ISDIR(mirror_stat.st_mode),
            "bytecode cache mirror is not a directory",
        )
        _validate_existing_pycache_mirror(checkout_mirror)
    return prefix_path


def reject_preloaded_official_modules(
    modules: dict[str, object] | None = None,
) -> None:
    """Fail if any official top-level package is already imported.

    Imports that happen before the pinned checkout is wired at sys.path
    index 0 could have resolved anywhere; the wrapper guarantees freshness by
    re-executing in a new subprocess, and this check proves it.
    """

    loaded = sys.modules if modules is None else modules
    dotted = tuple(f"{name}." for name in OFFICIAL_TOP_LEVEL_PACKAGES)
    offenders = sorted(
        name
        for name in loaded
        if name in OFFICIAL_TOP_LEVEL_PACKAGES or name.startswith(dotted)
    )
    _require(
        not offenders,
        "official top-level modules are already imported in this process; "
        f"run inside a fresh subprocess: {offenders[:5]}",
    )


def require_official_modules_from(
    checkout: Path,
    modules: dict[str, object] | None = None,
) -> None:
    """Require every loaded official module to resolve inside ``checkout``.

    Used on repeated bootstraps in one process: the first bootstrap demands
    no official modules at all; later ones must prove no polluted
    ``memory_modules``/``evaluation``/``data`` module has appeared since.
    """

    loaded = sys.modules if modules is None else modules
    dotted = tuple(f"{name}." for name in OFFICIAL_TOP_LEVEL_PACKAGES)
    for name in sorted(loaded):
        if not (name in OFFICIAL_TOP_LEVEL_PACKAGES or name.startswith(dotted)):
            continue
        module = loaded[name]
        origin = getattr(module, "__file__", None)
        if origin is None:
            search_paths = [Path(p) for p in list(getattr(module, "__path__", []) or [])]
            _require(
                bool(search_paths)
                and all(path.resolve().is_relative_to(checkout) for path in search_paths),
                f"official module {name} is loaded from outside the pinned checkout",
            )
            continue
        _require(
            Path(str(origin)).resolve().is_relative_to(checkout),
            f"official module {name} is loaded from outside the pinned checkout",
        )


def _code_shaped(relative: str) -> bool:
    parts = PurePosixPath(relative)
    name = parts.name.lower()
    return parts.suffix.lower() in _CODE_SUFFIXES or name in (
        "sitecustomize.py",
        "usercustomize.py",
    )


def _reject_untrusted_code_artifacts(root: Path) -> None:
    """Reject code-shaped untracked or ignored files in importable directories.

    All enumerations are bounded, streamed, and deadline-limited.  Untracked
    listing uses ``--directory`` so a fully-untracked tree yields one entry
    instead of a walk; the ignored listing is restricted by pathspec to
    code-shaped suffixes with the dataset/run-output trees excluded, so huge
    ``data/longmemeval-v2``/``runs`` trees are never enumerated.
    ``__pycache__`` bytecode is allowed only because
    ``require_private_pycache`` has already made it unreadable to imports.
    """

    untracked = _git_paths_bounded(
        root,
        [
            "ls-files",
            "--others",
            "--exclude-standard",
            "--directory",
            "--no-empty-directory",
            "-z",
        ],
        owner="official checkout untracked scan",
    )
    _require(
        not untracked,
        "official checkout has untracked files; refusing to run against a "
        f"non-pristine harness: {untracked[:5]}",
    )
    ignored_pathspecs = [f":(glob)**/*{suffix}" for suffix in _CODE_SUFFIXES]
    ignored_pathspecs += [
        f":(exclude,glob){prefix}**" for prefix in _ALLOWED_IGNORED_PREFIXES
    ]
    ignored = _git_paths_bounded(
        root,
        [
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
            "--",
            *ignored_pathspecs,
        ],
        owner="official checkout ignored-code scan",
    )
    for relative in ignored:
        clean = relative.strip()
        if not clean or clean.startswith(_ALLOWED_IGNORED_PREFIXES):
            continue
        if not _code_shaped(clean):
            continue
        parts = PurePosixPath(clean)
        if parts.suffix.lower() in (".pyc", ".pyo") and "__pycache__" in parts.parts:
            continue  # inert: a private pycache prefix is enforced
        raise BootstrapError(
            "official checkout contains a code-shaped ignored file in an "
            f"importable directory: {clean}; remove it or re-clone the pinned "
            "checkout before running"
        )


def verify_official_checkout(root: str | os.PathLike[str] | None = None) -> Path:
    """Fail closed unless the checkout is exactly the pinned pristine commit.

    The provided path itself is trusted input: it must be absolute and free
    of dot-dot and symlink components BEFORE any resolution (the verified
    macOS ``/tmp`` alias is deterministically rewritten, never followed), so
    a crafted alias can never redirect verification to a different tree than
    the one that gets imported.
    """

    raw = root if root is not None else os.environ.get(OFFICIAL_ROOT_ENV)
    _require(
        raw is not None and str(raw).strip() != "",
        "official checkout root not provided (argument or "
        f"{OFFICIAL_ROOT_ENV} environment variable)",
    )
    path = Path(str(raw)).expanduser()
    _require(path.is_absolute(), f"official checkout root must be absolute: {path}")
    path = require_no_symlink_components(path, owner="official checkout root")
    _require(path.is_dir(), f"official checkout root is not a directory: {path}")
    for relative in _REQUIRED_OFFICIAL_FILES:
        _require(
            (path / relative).is_file(),
            f"official checkout is missing {relative}: {path}",
        )
    head = _git_output(path, "rev-parse", "HEAD").strip()
    _require(
        head == OFFICIAL_COMMIT,
        f"official checkout HEAD {head} does not match pinned commit {OFFICIAL_COMMIT}",
    )
    modified = _git_paths_bounded(
        path,
        ["status", "--porcelain", "--untracked-files=no", "-z"],
        owner="official checkout tracked-status scan",
    )
    _require(
        not modified,
        "official checkout has local modifications to tracked files; "
        "refusing to run against a non-pristine harness",
    )
    _reject_untrusted_code_artifacts(path)
    return path


def _torch_pins(checkout: Path) -> dict[str, str]:
    """Exact optional torch pins declared by the checkout, if any."""

    pins: dict[str, str] = {}
    requirements = checkout / "requirements-torch.txt"
    if not requirements.is_file():
        return pins
    for raw_line in requirements.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if "==" not in line:
            continue
        name, _, version = line.partition("==")
        pins[name.strip().lower()] = version.strip()
    return pins


def _origin_label(origin: str, deps_dir: Path | None) -> str:
    """Content-free classification of an import origin (no raw paths)."""

    path = Path(origin)
    if deps_dir is not None and path.is_relative_to(deps_dir):
        return "staged-deps-dir"
    if path.is_relative_to(REPO_ROOT):
        return "repo"
    if "site-packages" in path.parts:
        return "site-packages"
    if path.is_relative_to(Path(sys.prefix)):
        return "interpreter-env"
    return "external"


def official_dependency_preflight(
    checkout: Path | None = None,
    *,
    deps_dir: Path | None = None,
) -> dict[str, object]:
    """Enforce/report exact interpreter and dependency versions + origins.

    Never installs anything.  Required modules missing -> fail closed with a
    test-only staging instruction.  Optional torch/torchvision are reported
    always and, when importable and the checkout pins them, enforced to the
    exact pinned versions.  Origins are reported as content-free labels, not
    raw absolute paths.
    """

    _require(
        sys.version_info >= (3, 11),
        "the pinned official harness requires Python >= 3.11; this "
        f"interpreter is {platform.python_version()}",
    )
    dependencies: dict[str, dict[str, object]] = {}
    missing: list[str] = []
    for name in (*OFFICIAL_THIRD_PARTY_MODULES, *OFFICIAL_OPTIONAL_TORCH_MODULES):
        optional = name in OFFICIAL_OPTIONAL_TORCH_MODULES
        try:
            spec = importlib.util.find_spec(name)
        except (ImportError, ValueError):
            spec = None
        if spec is None:
            if not optional:
                missing.append(name)
            dependencies[name] = {"present": False, "optional": optional}
            continue
        origin = spec.origin
        if origin is None and spec.submodule_search_locations:
            locations = list(spec.submodule_search_locations)
            origin = locations[0] if locations else None
        distribution = _MODULE_TO_DISTRIBUTION.get(name, name)
        try:
            version = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            version = None
        dependencies[name] = {
            "present": True,
            "optional": optional,
            "distribution": distribution,
            "version": version,
            "origin_label": (
                _origin_label(str(origin), deps_dir) if origin is not None else None
            ),
        }
    _require(
        not missing,
        "the pinned official harness needs third-party modules that are not "
        f"importable: {missing}. Install them yourself (this tooling never "
        "installs anything). For compatibility testing only, stage them into "
        "an isolated directory, e.g. `python3 -m pip install --target <dir> "
        "openai openai-agents pillow`, export "
        f"{OFFICIAL_DEPS_ENV}=<dir>, and remove <dir> afterwards",
    )
    if checkout is not None:
        pins = _torch_pins(checkout)
        for name in OFFICIAL_OPTIONAL_TORCH_MODULES:
            info = dependencies[name]
            pin = pins.get(name)
            if pin is not None:
                info["pinned_version"] = pin
                if info.get("present"):
                    _require(
                        info.get("version") == pin,
                        f"{name} version {info.get('version')} does not match "
                        f"the exact pin {pin} from requirements-torch.txt",
                    )
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "dependencies": dependencies,
        "installed_by_preflight": False,
    }


def _wire_dependency_dir(deps_dir: str | os.PathLike[str] | None) -> Path | None:
    raw = deps_dir if deps_dir is not None else os.environ.get(OFFICIAL_DEPS_ENV)
    if raw is None or not str(raw).strip():
        return None
    path = Path(str(raw)).expanduser()
    path = require_no_symlink_components(path, owner="official dependency directory")
    path = require_outside_live_store(path, owner="official dependency directory")
    _require(path.is_dir(), f"official dependency directory does not exist: {path}")
    entry = str(path)
    if entry not in sys.path:
        sys.path.append(entry)  # lowest precedence: it can never shadow code
    return path


def bootstrap_official(
    root: str | os.PathLike[str] | None = None,
    *,
    deps_dir: str | os.PathLike[str] | None = None,
) -> dict[str, object]:
    """Verify the pinned checkout, wire sys.path, register ``synapse_s2``.

    Returns a content-free public summary (no raw absolute paths).  The
    official registry must resolve ``synapse_s2`` to this repository's
    adapter class afterwards, so the unmodified official
    ``build_memory``/``load_memory`` paths work.
    """

    global _VERIFIED_OFFICIAL_ROOT

    checkout = verify_official_checkout(root)
    if _VERIFIED_OFFICIAL_ROOT is None:
        # First bootstrap in this process: nothing official may be loaded yet.
        reject_preloaded_official_modules()
    else:
        _require(
            checkout == _VERIFIED_OFFICIAL_ROOT,
            "this process already bootstrapped a different official checkout",
        )
        # Repeated bootstrap: re-verify no polluted official module appeared.
        require_official_modules_from(checkout)
    require_private_pycache(
        checkout,
        allow_existing_official_mirror=_VERIFIED_OFFICIAL_ROOT is not None,
    )
    wired_deps = _wire_dependency_dir(deps_dir)

    checkout_entry = str(checkout)
    repo_entry = str(REPO_ROOT)
    for entry in (checkout_entry, repo_entry):
        while entry in sys.path:
            sys.path.remove(entry)
    sys.path.insert(0, checkout_entry)
    sys.path.insert(1, repo_entry)

    dependency_report = official_dependency_preflight(checkout, deps_dir=wired_deps)

    official = importlib.import_module("memory_modules.memory")
    module_path = Path(official.__file__).resolve()
    _require(
        module_path == checkout / "memory_modules" / "memory.py",
        "memory_modules.memory resolved outside the pinned checkout",
    )
    require_official_modules_from(checkout)
    adapter_module = importlib.import_module("official_longmem.synapse_s2_memory")
    registered = official.MEMORY_TYPES.get(adapter_module.MEMORY_TYPE)
    _require(
        registered is adapter_module.SynapseS2Memory,
        "synapse_s2 is not registered with the pinned official registry",
    )
    _VERIFIED_OFFICIAL_ROOT = checkout
    return {
        "official_commit": OFFICIAL_COMMIT,
        "official_root_verified": True,
        "registered_memory_type": adapter_module.MEMORY_TYPE,
        "registry_size": len(official.MEMORY_TYPES),
        "memory_contract_verified": True,
        "private_pycache_verified": True,
        "dependency_dir_wired": wired_deps is not None,
        "dependency_report": dependency_report,
        "interpreter_isolated": bool(sys.flags.isolated),
        "pythonpath_persisted": False,
        "official_score_claimed": False,
    }

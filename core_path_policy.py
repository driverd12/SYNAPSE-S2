from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Mapping, NoReturn, Self


ROOT_NAMES = frozenset({"export", "backup", "recovery", "capture"})
PathKind = Literal["file", "directory", "any"]
MAX_POLICY_PATH_BYTES = 4_096
_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class CorePathPolicyError(RuntimeError):
    """Content-free rejection at the authoritative core filesystem boundary."""

    code = "path_not_authorized"

    def __init__(self) -> None:
        super().__init__(self.code)


def _deny() -> NoReturn:
    raise CorePathPolicyError()


def _require_descriptor_primitives() -> None:
    if (
        not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        _deny()


def _coerce_absolute_path(value: str | os.PathLike[str]) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError:
        _deny()
    if (
        not isinstance(raw, str)
        or not raw
        or "\x00" in raw
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
    ):
        _deny()
    try:
        if len(raw.encode("utf-8")) > MAX_POLICY_PATH_BYTES:
            _deny()
    except UnicodeError:
        _deny()
    candidate = Path(raw)
    if not candidate.is_absolute() or ".." in candidate.parts:
        _deny()
    normalized = Path(os.path.normpath(raw))
    if not normalized.is_absolute() or ".." in normalized.parts:
        _deny()
    return normalized


def _safe_lstat(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except (OSError, ValueError):
        _deny()


@dataclass(frozen=True)
class _PathBinding:
    path: Path
    device: int
    inode: int
    mode: int
    uid: int
    # Directory link counts legitimately change as child directories are
    # created or retired. They are therefore not part of path identity; regular
    # file hardlink count is checked explicitly by the private-file validator
    # and by ``assert_current`` below.
    link_count: int = field(compare=False)

    @classmethod
    def capture(cls, path: Path, observed: os.stat_result) -> "_PathBinding":
        if stat.S_ISLNK(observed.st_mode):
            _deny()
        return cls(
            path=path,
            device=int(observed.st_dev),
            inode=int(observed.st_ino),
            mode=int(observed.st_mode),
            uid=int(observed.st_uid),
            link_count=int(observed.st_nlink),
        )

    def assert_current(self) -> None:
        observed = _PathBinding.capture(self.path, _safe_lstat(self.path))
        if observed != self or (
            stat.S_ISREG(self.mode) and observed.link_count != self.link_count
        ):
            _deny()

    def assert_stat(self, observed: os.stat_result) -> None:
        if (
            int(observed.st_dev) != self.device
            or int(observed.st_ino) != self.inode
            or int(observed.st_mode) != self.mode
            or int(observed.st_uid) != self.uid
            or (
                stat.S_ISREG(self.mode)
                and int(observed.st_nlink) != self.link_count
            )
        ):
            _deny()


def _validate_private_directory(binding: _PathBinding) -> None:
    if (
        not stat.S_ISDIR(binding.mode)
        or binding.uid != os.getuid()
        or stat.S_IMODE(binding.mode) != 0o700
    ):
        _deny()


def _validate_private_file(binding: _PathBinding) -> None:
    if (
        not stat.S_ISREG(binding.mode)
        or binding.uid != os.getuid()
        or binding.link_count != 1
        or stat.S_IMODE(binding.mode) != 0o600
    ):
        _deny()


def _validate_final_binding(binding: _PathBinding, kind: PathKind) -> None:
    if kind == "file":
        _validate_private_file(binding)
    elif kind == "directory":
        _validate_private_directory(binding)
    elif kind == "any":
        if stat.S_ISDIR(binding.mode):
            _validate_private_directory(binding)
        elif stat.S_ISREG(binding.mode):
            _validate_private_file(binding)
        else:
            _deny()
    else:
        _deny()


def _absolute_component_paths(path: Path) -> tuple[Path, ...]:
    if path.anchor != os.path.sep:
        _deny()
    current = Path(path.anchor)
    components = [current]
    for part in path.parts[1:]:
        if part in {"", ".", ".."}:
            _deny()
        current = current / part
        components.append(current)
    return tuple(components)


def _scan_canonical_root(root: Path) -> tuple[_PathBinding, ...]:
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        _deny()
    if resolved != root:
        _deny()
    bindings = tuple(
        _PathBinding.capture(component, _safe_lstat(component))
        for component in _absolute_component_paths(root)
    )
    _validate_private_directory(bindings[-1])
    return bindings


def _relative_parts(candidate: Path, root: Path) -> tuple[str, ...]:
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        _deny()
    parts = tuple(relative.parts)
    if any(part in {"", ".", ".."} for part in parts):
        _deny()
    return parts


def _close_fd(descriptor: int | None) -> None:
    if descriptor is None or descriptor < 0:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _duplicate_fd(descriptor: int) -> int:
    try:
        duplicate = os.dup(descriptor)
        os.set_inheritable(duplicate, False)
        return duplicate
    except OSError:
        _deny()


def _open_directory_component(
    name: str,
    *,
    directory_fd: int | None,
    expected: _PathBinding,
) -> int:
    try:
        descriptor = os.open(
            name,
            _DIRECTORY_OPEN_FLAGS,
            dir_fd=directory_fd,
        )
    except (OSError, TypeError, ValueError):
        _deny()
    try:
        expected.assert_stat(os.fstat(descriptor))
        _validate_private_directory(expected)
        os.set_inheritable(descriptor, False)
        return descriptor
    except BaseException:
        _close_fd(descriptor)
        raise


def _open_anchored_root(bindings: tuple[_PathBinding, ...]) -> int:
    """Open a canonical root one component at a time without following links."""

    if not bindings or bindings[0].path != Path(os.path.sep):
        _deny()
    current: int | None = None
    try:
        # The filesystem root need not be owner-private, so it is checked for
        # exact identity and directory type without applying the 0700 policy.
        current = os.open(os.path.sep, _DIRECTORY_OPEN_FLAGS)
        bindings[0].assert_stat(os.fstat(current))
        if not stat.S_ISDIR(bindings[0].mode):
            _deny()
        os.set_inheritable(current, False)
        for binding in bindings[1:]:
            next_descriptor = os.open(
                binding.path.name,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=current,
            )
            try:
                binding.assert_stat(os.fstat(next_descriptor))
                if binding is bindings[-1]:
                    _validate_private_directory(binding)
                os.set_inheritable(next_descriptor, False)
            except BaseException:
                _close_fd(next_descriptor)
                raise
            _close_fd(current)
            current = next_descriptor
        if current is None:
            _deny()
        return current
    except (OSError, TypeError, ValueError):
        _close_fd(current)
        _deny()
    except BaseException:
        _close_fd(current)
        raise


def _open_anchored_directory_beneath(
    *,
    root_fd: int,
    root: Path,
    parts: tuple[str, ...],
    bindings: Mapping[Path, _PathBinding],
) -> int:
    current = _duplicate_fd(root_fd)
    current_path = root
    try:
        for part in parts:
            current_path = current_path / part
            expected = bindings.get(current_path)
            if expected is None:
                _deny()
            next_descriptor = _open_directory_component(
                part,
                directory_fd=current,
                expected=expected,
            )
            _close_fd(current)
            current = next_descriptor
        return current
    except BaseException:
        _close_fd(current)
        raise


def _open_anchored_target(
    *,
    parent_fd: int,
    leaf_name: str,
    expected: _PathBinding,
    kind: PathKind,
) -> int:
    flags = (
        _DIRECTORY_OPEN_FLAGS
        if kind == "directory" or (kind == "any" and stat.S_ISDIR(expected.mode))
        else _FILE_OPEN_FLAGS
    )
    try:
        descriptor = os.open(leaf_name, flags, dir_fd=parent_fd)
    except (OSError, TypeError, ValueError):
        _deny()
    try:
        expected.assert_stat(os.fstat(descriptor))
        _validate_final_binding(expected, kind)
        os.set_inheritable(descriptor, False)
        return descriptor
    except BaseException:
        _close_fd(descriptor)
        raise


def _assert_missing_at(parent_fd: int, leaf_name: str) -> None:
    try:
        os.stat(leaf_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except (OSError, TypeError, ValueError):
        _deny()
    _deny()


@dataclass(eq=False, repr=False)
class AuthorizedPath:
    """An openat-anchored filesystem capability.

    ``path`` is retained for result rendering and compatibility only. Security
    sensitive I/O must use ``duplicate_parent_fd``/``leaf_name`` (or the
    retained target descriptor) instead of resolving that pathname again.
    The descriptors pin the authorized vnodes even if another same-user
    process renames or replaces a component after authorization.
    """

    root_name: str
    path: Path
    root: Path
    target_exists: bool
    replacement_allowed: bool
    existing_ancestor: Path
    _bindings: tuple[_PathBinding, ...]
    _missing_paths: tuple[Path, ...]
    _root_fd: int = field(repr=False)
    _parent_fd: int = field(repr=False)
    _target_fd: int | None = field(repr=False)
    _root_binding: _PathBinding = field(repr=False)
    _parent_binding: _PathBinding = field(repr=False)
    _target_binding: _PathBinding | None = field(repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __fspath__(self) -> str:
        return str(self.path)

    def __repr__(self) -> str:
        return (
            "AuthorizedPath("
            f"root_name={self.root_name!r}, "
            f"target_exists={self.target_exists!r}, "
            f"replacement_allowed={self.replacement_allowed!r}"
            ")"
        )

    @property
    def leaf_name(self) -> str:
        """The single name to use with a duplicate of the anchored parent."""

        if self.path == self.root:
            _deny()
        return self.path.name

    @property
    def closed(self) -> bool:
        return self._closed

    def __enter__(self) -> Self:
        self._assert_descriptors()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        descriptors = {self._root_fd, self._parent_fd}
        if self._target_fd is not None:
            descriptors.add(self._target_fd)
        for descriptor in descriptors:
            _close_fd(descriptor)
        self._root_fd = -1
        self._parent_fd = -1
        self._target_fd = None

    def _assert_descriptors(self) -> None:
        if self._closed:
            _deny()
        try:
            self._root_binding.assert_stat(os.fstat(self._root_fd))
            self._parent_binding.assert_stat(os.fstat(self._parent_fd))
            if self._target_binding is None:
                if self._target_fd is not None:
                    _deny()
            else:
                if self._target_fd is None:
                    _deny()
                self._target_binding.assert_stat(os.fstat(self._target_fd))
        except OSError:
            _deny()

    def duplicate_parent_fd(self) -> int:
        """Return a caller-owned descriptor anchoring ``leaf_name``'s parent."""

        self._assert_descriptors()
        return _duplicate_fd(self._parent_fd)

    def duplicate_target_fd(self) -> int:
        """Return a caller-owned descriptor for an authorized existing target."""

        self._assert_descriptors()
        if self._target_fd is None:
            _deny()
        return _duplicate_fd(self._target_fd)

    def assert_stable(self) -> None:
        self._assert_descriptors()
        for binding in self._bindings:
            binding.assert_current()
        for path in self._missing_paths:
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                _deny()
            _deny()


@dataclass(frozen=True)
class _FutureSnapshot:
    bindings: tuple[_PathBinding, ...]
    missing_paths: tuple[Path, ...]
    target_exists: bool
    existing_ancestor: Path


class CorePathPolicy:
    """Authorize filesystem arguments before dispatching authoritative RPCs.

    The policy is observation-only: it never creates, chmods, replaces, or
    removes paths. Configured roots and every existing component beneath them
    must be owner-controlled and symlink-free.
    """

    def __init__(
        self,
        *,
        export_root: str | os.PathLike[str],
        backup_root: str | os.PathLike[str],
        recovery_root: str | os.PathLike[str],
        capture_root: str | os.PathLike[str],
    ) -> None:
        _require_descriptor_primitives()
        requested = {
            "export": _coerce_absolute_path(export_root),
            "backup": _coerce_absolute_path(backup_root),
            "recovery": _coerce_absolute_path(recovery_root),
            "capture": _coerce_absolute_path(capture_root),
        }
        roots: dict[str, Path] = {}
        root_bindings: dict[str, tuple[_PathBinding, ...]] = {}
        for name, root in requested.items():
            first = _scan_canonical_root(root)
            second = _scan_canonical_root(root)
            if first != second:
                _deny()
            roots[name] = root
            root_bindings[name] = first
        self._roots: Mapping[str, Path] = MappingProxyType(roots)
        self._root_bindings: Mapping[
            str, tuple[_PathBinding, ...]
        ] = MappingProxyType(root_bindings)

    def _root_snapshot(self, root_name: str) -> tuple[Path, tuple[_PathBinding, ...]]:
        if root_name not in ROOT_NAMES:
            _deny()
        root = self._roots[root_name]
        current = _scan_canonical_root(root)
        if current != self._root_bindings[root_name]:
            _deny()
        return root, current

    def configured_root(self, root_name: str) -> Path:
        root, _bindings = self._root_snapshot(root_name)
        return root

    def authorize_existing_input(
        self,
        root_name: str,
        value: str | os.PathLike[str],
        *,
        kind: PathKind = "file",
    ) -> AuthorizedPath:
        root, root_bindings = self._root_snapshot(root_name)
        candidate = _coerce_absolute_path(value)
        parts = _relative_parts(candidate, root)
        try:
            if candidate.resolve(strict=True) != candidate:
                _deny()
        except (OSError, RuntimeError, ValueError):
            _deny()

        def scan() -> tuple[_PathBinding, ...]:
            current = root
            bindings = list(root_bindings)
            if not parts:
                _validate_final_binding(bindings[-1], kind)
                return tuple(bindings)
            for index, part in enumerate(parts):
                current = current / part
                binding = _PathBinding.capture(current, _safe_lstat(current))
                if index == len(parts) - 1:
                    _validate_final_binding(binding, kind)
                else:
                    _validate_private_directory(binding)
                bindings.append(binding)
            return tuple(bindings)

        first = scan()
        second = scan()
        if first != second:
            _deny()
        binding_by_path = {binding.path: binding for binding in second}
        root_fd: int | None = None
        parent_fd: int | None = None
        target_fd: int | None = None
        try:
            root_fd = _open_anchored_root(root_bindings)
            if not parts:
                parent_fd = _duplicate_fd(root_fd)
                target_fd = _duplicate_fd(root_fd)
                parent_binding = root_bindings[-1]
                target_binding = root_bindings[-1]
            else:
                parent_fd = _open_anchored_directory_beneath(
                    root_fd=root_fd,
                    root=root,
                    parts=parts[:-1],
                    bindings=binding_by_path,
                )
                parent_binding = binding_by_path.get(candidate.parent)
                target_binding = binding_by_path.get(candidate)
                if parent_binding is None or target_binding is None:
                    _deny()
                target_fd = _open_anchored_target(
                    parent_fd=parent_fd,
                    leaf_name=parts[-1],
                    expected=target_binding,
                    kind=kind,
                )
            return AuthorizedPath(
                root_name=root_name,
                path=candidate,
                root=root,
                target_exists=True,
                replacement_allowed=False,
                existing_ancestor=candidate,
                _bindings=second,
                _missing_paths=(),
                _root_fd=root_fd,
                _parent_fd=parent_fd,
                _target_fd=target_fd,
                _root_binding=root_bindings[-1],
                _parent_binding=parent_binding,
                _target_binding=target_binding,
            )
        except BaseException:
            _close_fd(target_fd)
            _close_fd(parent_fd)
            _close_fd(root_fd)
            raise

    def _future_snapshot(
        self,
        *,
        root: Path,
        root_bindings: tuple[_PathBinding, ...],
        parts: tuple[str, ...],
        allow_replacement: bool,
    ) -> _FutureSnapshot:
        if not parts:
            _deny()
        current = root
        bindings = list(root_bindings)
        missing_paths: list[Path] = []
        missing_seen = False
        target_exists = False
        existing_ancestor = root
        for index, part in enumerate(parts):
            current = current / part
            try:
                observed = current.lstat()
            except FileNotFoundError:
                if index != len(parts) - 1:
                    # Outputs must be a single not-yet-existing leaf beneath
                    # an already existing, descriptor-bindable directory.
                    _deny()
                missing_seen = True
                missing_paths.append(current)
                continue
            except (OSError, ValueError):
                _deny()
            if missing_seen:
                # A descendant cannot exist beneath a missing parent without a
                # concurrent namespace change. Fail closed instead of guessing.
                _deny()
            binding = _PathBinding.capture(current, observed)
            bindings.append(binding)
            existing_ancestor = current
            if index == len(parts) - 1:
                target_exists = True
                if not allow_replacement:
                    _deny()
                _validate_private_file(binding)
            else:
                _validate_private_directory(binding)
        return _FutureSnapshot(
            bindings=tuple(bindings),
            missing_paths=tuple(missing_paths),
            target_exists=target_exists,
            existing_ancestor=existing_ancestor,
        )

    def authorize_future_output(
        self,
        root_name: str,
        value: str | os.PathLike[str],
        *,
        allow_replacement: bool = False,
    ) -> AuthorizedPath:
        if type(allow_replacement) is not bool:
            _deny()
        root, root_bindings = self._root_snapshot(root_name)
        candidate = _coerce_absolute_path(value)
        parts = _relative_parts(candidate, root)
        first = self._future_snapshot(
            root=root,
            root_bindings=root_bindings,
            parts=parts,
            allow_replacement=allow_replacement,
        )
        second = self._future_snapshot(
            root=root,
            root_bindings=root_bindings,
            parts=parts,
            allow_replacement=allow_replacement,
        )
        if first != second:
            _deny()
        binding_by_path = {binding.path: binding for binding in second.bindings}
        root_fd: int | None = None
        parent_fd: int | None = None
        target_fd: int | None = None
        try:
            root_fd = _open_anchored_root(root_bindings)
            parent_fd = _open_anchored_directory_beneath(
                root_fd=root_fd,
                root=root,
                parts=parts[:-1],
                bindings=binding_by_path,
            )
            parent_binding = binding_by_path.get(candidate.parent)
            if parent_binding is None:
                _deny()
            target_binding = binding_by_path.get(candidate)
            if second.target_exists:
                if target_binding is None:
                    _deny()
                target_fd = _open_anchored_target(
                    parent_fd=parent_fd,
                    leaf_name=parts[-1],
                    expected=target_binding,
                    kind="file",
                )
            else:
                if target_binding is not None:
                    _deny()
                _assert_missing_at(parent_fd, parts[-1])
            return AuthorizedPath(
                root_name=root_name,
                path=candidate,
                root=root,
                target_exists=second.target_exists,
                replacement_allowed=allow_replacement,
                existing_ancestor=second.existing_ancestor,
                _bindings=second.bindings,
                _missing_paths=second.missing_paths,
                _root_fd=root_fd,
                _parent_fd=parent_fd,
                _target_fd=target_fd,
                _root_binding=root_bindings[-1],
                _parent_binding=parent_binding,
                _target_binding=target_binding,
            )
        except BaseException:
            _close_fd(target_fd)
            _close_fd(parent_fd)
            _close_fd(root_fd)
            raise

    def authorize_export_output(
        self,
        value: str | os.PathLike[str],
        *,
        allow_replacement: bool = False,
    ) -> AuthorizedPath:
        return self.authorize_future_output(
            "export",
            value,
            allow_replacement=allow_replacement,
        )

    def authorize_backup_output(
        self,
        value: str | os.PathLike[str],
        *,
        allow_replacement: bool = False,
    ) -> AuthorizedPath:
        return self.authorize_future_output(
            "backup",
            value,
            allow_replacement=allow_replacement,
        )

    def authorize_backup_input(
        self,
        value: str | os.PathLike[str],
        *,
        kind: PathKind = "file",
    ) -> AuthorizedPath:
        return self.authorize_existing_input("backup", value, kind=kind)

    def authorize_recovery_input(
        self,
        value: str | os.PathLike[str],
        *,
        kind: PathKind = "file",
    ) -> AuthorizedPath:
        return self.authorize_existing_input("recovery", value, kind=kind)

    def authorize_recovery_output(
        self,
        value: str | os.PathLike[str],
        *,
        allow_replacement: bool = False,
    ) -> AuthorizedPath:
        return self.authorize_future_output(
            "recovery",
            value,
            allow_replacement=allow_replacement,
        )

    def authorize_capture_root(
        self,
        client_override: str | os.PathLike[str] | None = None,
    ) -> AuthorizedPath:
        if client_override is not None:
            _deny()
        return self.authorize_existing_input(
            "capture",
            self._roots["capture"],
            kind="directory",
        )

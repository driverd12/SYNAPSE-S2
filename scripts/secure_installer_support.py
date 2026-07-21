#!/usr/bin/env python3
"""Shared no-follow filesystem and flock primitives for LaunchAgent installers."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redaction import SecretSafeArgumentParser, reject_sensitive_identifier  # noqa: E402


class SecureInstallError(RuntimeError):
    pass


def _normal(path: str) -> Path:
    raw = reject_sensitive_identifier(path, field="installer_path")
    value = Path(raw).expanduser()
    if not value.is_absolute() or ".." in value.parts or "\x00" in str(value):
        raise SecureInstallError("installer path must be a normal absolute path")
    return value


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _no_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        observed = _lstat(current)
        if observed is None:
            continue
        if stat.S_ISLNK(observed.st_mode):
            if current == Path("/var") and os.readlink(current) == "private/var":
                continue
            raise SecureInstallError("installer path contains a symlink component")
        if current != path and not stat.S_ISDIR(observed.st_mode):
            raise SecureInstallError("installer path contains a non-directory component")


def ensure_directory(path: Path, *, private: bool) -> None:
    _no_symlink_components(path)
    missing: list[Path] = []
    cursor = path
    while _lstat(cursor) is None:
        missing.append(cursor)
        if cursor.parent == cursor:
            raise SecureInstallError("installer directory has no safe parent")
        cursor = cursor.parent
    parent = cursor.lstat()
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise SecureInstallError("installer directory parent is unsafe")
    for candidate in reversed(missing):
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            pass
        created = candidate.lstat()
        if (
            stat.S_ISLNK(created.st_mode)
            or not stat.S_ISDIR(created.st_mode)
            or created.st_uid != os.getuid()
            or stat.S_IMODE(created.st_mode) != 0o700
        ):
            raise SecureInstallError("installer directory creation raced")
    observed = path.lstat()
    mode = stat.S_IMODE(observed.st_mode)
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.getuid()
        or (mode != 0o700 if private else bool(mode & 0o022))
    ):
        raise SecureInstallError("installer directory is unsafe")


def validate_regular(path: Path, *, allow_missing: bool, mode: int = 0o600) -> bool:
    _no_symlink_components(path)
    observed = _lstat(path)
    if observed is None:
        if allow_missing:
            return False
        raise SecureInstallError("installer file is missing")
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) != mode
    ):
        raise SecureInstallError("installer file is unsafe")
    return True


def prepare_log(path: Path) -> None:
    ensure_directory(path.parent, private=True)
    existed = validate_regular(path, allow_missing=True)
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    if not existed:
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
            or (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino)
        ):
            raise SecureInstallError("installer log identity is unsafe")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(path.parent)


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stable_digest(path: Path) -> str:
    before = path.lstat()
    validate_regular(path, allow_missing=False)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    visible = path.lstat()
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        for item in (before, opened, finished, visible)
    }
    if len(identities) != 1:
        raise SecureInstallError("installer file changed while being read")
    return digest.hexdigest()


def replace_regular(
    source: Path,
    target: Path,
    *,
    expected_current: Path | None = None,
    expect_absent: bool = False,
) -> None:
    validate_regular(source, allow_missing=False)
    target_exists = validate_regular(target, allow_missing=True)
    if source.parent != target.parent:
        raise SecureInstallError("installer replacement must stay in one directory")
    if expect_absent and target_exists:
        raise SecureInstallError("installer replacement target appeared")
    if expected_current is not None:
        if not target_exists or _stable_digest(target) != _stable_digest(expected_current):
            raise SecureInstallError("installer replacement target changed")
    os.replace(source, target)
    validate_regular(target, allow_missing=False)
    fsync_directory(target.parent)


def backup_regular(source: Path, target: Path) -> None:
    source_stat = source.lstat()
    validate_regular(source, allow_missing=False)
    validate_regular(target, allow_missing=False)
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    source_flags |= getattr(os, "O_NOFOLLOW", 0)
    target_flags = os.O_WRONLY | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0)
    target_flags |= getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(source, source_flags)
    target_fd = os.open(target, target_flags)
    try:
        opened_source = os.fstat(source_fd)
        opened_target = os.fstat(target_fd)
        if (
            (opened_source.st_dev, opened_source.st_ino)
            != (source_stat.st_dev, source_stat.st_ino)
            or opened_source.st_nlink != 1
            or opened_target.st_nlink != 1
        ):
            raise SecureInstallError("installer backup identity changed")
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(target_fd, view)
                if written <= 0:
                    raise OSError("installer backup write made no progress")
                view = view[written:]
        os.fsync(target_fd)
        finished_source = os.fstat(source_fd)
        visible_source = source.lstat()
        identities = {
            (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
            for item in (source_stat, opened_source, finished_source, visible_source)
        }
        if len(identities) != 1:
            raise SecureInstallError("installer source changed during backup")
    finally:
        os.close(target_fd)
        os.close(source_fd)
    validate_regular(target, allow_missing=False)
    fsync_directory(target.parent)


def run_locked(lock_path: Path, marker: str, command: Sequence[str]) -> int:
    ensure_directory(lock_path.parent, private=False)
    validate_regular(lock_path, allow_missing=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
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
            raise SecureInstallError("installer lock identity is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SecureInstallError("another LaunchAgent install is already in progress") from exc
        environment = os.environ.copy()
        environment["SYNAPSE_S2_INSTALL_LOCK_HELD"] = marker
        completed = subprocess.run(list(command), check=False, env=environment)
        return int(completed.returncode)
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def build_parser() -> argparse.ArgumentParser:
    parser = SecretSafeArgumentParser(add_help=True)
    subparsers = parser.add_subparsers(dest="action", required=True)
    locked = subparsers.add_parser("run-locked")
    locked.add_argument("--lock", required=True)
    locked.add_argument("--marker", required=True)
    locked.add_argument("command", nargs=argparse.REMAINDER)
    directory = subparsers.add_parser("ensure-directory")
    directory.add_argument("--path", required=True)
    directory.add_argument("--shared", action="store_true")
    log = subparsers.add_parser("prepare-log")
    log.add_argument("--path", required=True)
    regular = subparsers.add_parser("validate-regular")
    regular.add_argument("--path", required=True)
    regular.add_argument("--allow-missing", action="store_true")
    replace = subparsers.add_parser("replace-regular")
    replace.add_argument("--source", required=True)
    replace.add_argument("--target", required=True)
    replace.add_argument("--expected-current")
    replace.add_argument("--expect-absent", action="store_true")
    backup = subparsers.add_parser("backup-regular")
    backup.add_argument("--source", required=True)
    backup.add_argument("--target", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.action == "run-locked":
            command = list(args.command)
            if command and command[0] == "--":
                command = command[1:]
            if not command:
                raise SecureInstallError("locked installer command is missing")
            return run_locked(_normal(args.lock), args.marker, command)
        if args.action == "ensure-directory":
            ensure_directory(_normal(args.path), private=not args.shared)
        elif args.action == "prepare-log":
            prepare_log(_normal(args.path))
        elif args.action == "validate-regular":
            validate_regular(_normal(args.path), allow_missing=args.allow_missing)
        elif args.action == "replace-regular":
            if args.expected_current and args.expect_absent:
                raise SecureInstallError("replacement expectations conflict")
            replace_regular(
                _normal(args.source),
                _normal(args.target),
                expected_current=(
                    _normal(args.expected_current) if args.expected_current else None
                ),
                expect_absent=args.expect_absent,
            )
        else:
            backup_regular(_normal(args.source), _normal(args.target))
    except (OSError, SecureInstallError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

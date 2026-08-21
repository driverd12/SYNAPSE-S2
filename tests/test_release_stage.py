"""Adversarial tests for inactive, memory-preserving release staging."""

from __future__ import annotations

import builtins
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


planner = _load("test_release_stage_planner", ROOT / "scripts/release_update_plan.py")
stage = _load("test_release_stage_module", ROOT / "scripts/release_stage.py")


def _snapshot(path: Path) -> tuple:
    observed = path.stat()
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_mode,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
        path.read_bytes(),
    )


class ReleaseStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="synapse-s2-release-stage-", dir="/private/tmp"
        )
        self.base = Path(self.temp.name)
        self.current = self.base / "current-source"
        self.candidate = self.base / "candidate-source"
        self.install = self.base / "install-state"
        self.environment = self.base / "environment-state"
        self.data = self.base / "durable-data"
        self.journal = self.base / "stage-journal"
        self.live = self.base / "live-runtime"
        for root in (
            self.current,
            self.candidate,
            self.install,
            self.environment,
            self.data,
            self.journal,
            self.live,
        ):
            root.mkdir(mode=0o700)
            root.chmod(0o700)
        self._build_product_root(self.current)
        self._build_product_root(self.candidate)
        self.data_sentinel = self.data / "memory.sqlite3"
        self.environment_sentinel = self.environment / "never-built.txt"
        self.live_sentinel = self.live / "running.state"
        self.data_sentinel.write_bytes(b"durable-memory-sentinel")
        self.environment_sentinel.write_bytes(b"environment-sentinel")
        self.live_sentinel.write_bytes(b"runtime-sentinel")
        for path in (
            self.data_sentinel,
            self.environment_sentinel,
            self.live_sentinel,
        ):
            path.chmod(0o600)
        plan = planner.plan_product_release(self.current, self.candidate)
        self.assertEqual(plan["status"], "no-update")
        self.product_id = plan["candidate"]["product_id"]
        self.policy_id = plan["inventory_policy_id"]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _build_product_root(self, root: Path) -> None:
        for _component, _role, relative in planner.PRODUCT_INVENTORY:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.parent.chmod(0o700)
            path.write_bytes(("fixture:" + relative).encode("ascii"))
            # Exercise exact executable and non-executable mode preservation.
            mode = 0o700 if relative.endswith((".sh", ".py")) else 0o600
            path.chmod(mode)

    def _exclusive_rename(
        self, source_fd: int, source: str, destination_fd: int, destination: str
    ) -> None:
        try:
            os.stat(destination, dir_fd=destination_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(
                source,
                destination,
                src_dir_fd=source_fd,
                dst_dir_fd=destination_fd,
            )
            return
        raise OSError(errno.EEXIST, "destination exists")

    def _incumbent_code_fixture(self, name: str) -> Path:
        scripts = self.base / name / "scripts"
        scripts.mkdir(parents=True, mode=0o700)
        scripts.chmod(0o700)
        for filename in ("release_stage.py", "release_update_plan.py"):
            destination = scripts / filename
            shutil.copy2(ROOT / "scripts" / filename, destination)
            destination.chmod(0o600)
        return scripts

    def _arguments(self) -> dict:
        return {
            "current_source_root": self.current,
            "candidate_source_root": self.candidate,
            "install_root": self.install,
            "environment_root": self.environment,
            "data_root": self.data,
            "journal_root": self.journal,
            "expected_product_id": self.product_id,
            "expected_inventory_policy_id": self.policy_id,
            "platform_system": "Darwin",
            "platform_machine": "arm64",
            "exclusive_rename": self._exclusive_rename,
        }

    def _open_descriptors(self) -> set[int]:
        descriptors: set[int] = set()
        for descriptor in range(512):
            try:
                fcntl.fcntl(descriptor, fcntl.F_GETFD)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                descriptors.add(descriptor)
        return descriptors

    def _sentinels(self) -> dict[Path, tuple]:
        return {
            path: _snapshot(path)
            for path in (
                self.data_sentinel,
                self.environment_sentinel,
                self.live_sentinel,
            )
        }

    def _assert_sentinels(self, before: dict[Path, tuple]) -> None:
        self.assertEqual(
            before,
            {path: _snapshot(path) for path in before},
        )

    def _assert_release_exact(self) -> None:
        release = self.install / "releases" / self.product_id
        expected_paths = {entry[2] for entry in planner.PRODUCT_INVENTORY}
        actual_paths = {
            str(path.relative_to(release))
            for path in release.rglob("*")
            if path.is_file()
        }
        self.assertEqual(actual_paths, expected_paths)
        for _component, _role, relative in planner.PRODUCT_INVENTORY:
            source = self.candidate / relative
            target = release / relative
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertEqual(
                stat.S_IMODE(target.stat().st_mode),
                stat.S_IMODE(source.stat().st_mode),
            )

    def test_success_is_inactive_exact_and_memory_preserving(self) -> None:
        sentinels = self._sentinels()
        result = stage.stage_release(**self._arguments())
        self.assertEqual(result["status"], "staged")
        self.assertTrue(result["source_staged"])
        self.assertTrue(result["identity_pin_verified"])
        self.assertTrue(result["journal_committed"])
        self.assertFalse(result["environment_stage_supported"])
        self.assertFalse(result["environment_built"])
        self.assertFalse(result["activation_supported"])
        self.assertFalse(result["activation_performed"])
        self.assertFalse(result["live_state_modified"])
        self._assert_release_exact()
        self.assertFalse((self.install / "current").exists())
        self.assertFalse((self.install / "latest").exists())
        self.assertFalse((self.install / "releases" / "current").exists())
        self.assertFalse((self.install / "releases" / "latest").exists())
        self._assert_sentinels(sentinels)

        lines = (self.journal / "release-stage.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["product_id"], self.product_id)
        self.assertEqual(entry["previous_hash"], "0" * 64)
        unsigned = dict(entry)
        entry_hash = unsigned.pop("entry_hash")
        self.assertEqual(entry_hash, stage._journal_hash(unsigned))

    def test_default_darwin_exclusive_publish_path(self) -> None:
        arguments = self._arguments()
        arguments.pop("exclusive_rename")
        result = stage.stage_release(**arguments)
        self.assertEqual(result["status"], "staged", result)
        self._assert_release_exact()

    def test_incumbent_planner_loader_restores_process_and_writes_no_pyc(self) -> None:
        arguments = self._arguments()
        cache = ROOT / "scripts/__pycache__"
        cache_before = (
            {
                path.name: (path.stat().st_size, path.stat().st_mtime_ns)
                for path in cache.iterdir()
            }
            if cache.is_dir()
            else {}
        )
        path_before = list(os.sys.path)
        bytecode_before = os.sys.dont_write_bytecode
        result = stage.stage_release(**arguments)
        cache_after = (
            {
                path.name: (path.stat().st_size, path.stat().st_mtime_ns)
                for path in cache.iterdir()
            }
            if cache.is_dir()
            else {}
        )
        self.assertEqual(result["status"], "staged", result)
        self.assertEqual(os.sys.path, path_before)
        self.assertIs(os.sys.dont_write_bytecode, bytecode_before)
        self.assertEqual(cache_after, cache_before)

    def test_api_import_restores_sys_path_and_bytecode_state(self) -> None:
        path_before = list(os.sys.path)
        bytecode_before = os.sys.dont_write_bytecode
        loaded = _load(
            "test_release_stage_import_state",
            ROOT / "scripts/release_stage.py",
        )
        self.assertEqual(loaded.RESULT_SCHEMA, stage.RESULT_SCHEMA)
        self.assertEqual(os.sys.path, path_before)
        self.assertIs(os.sys.dont_write_bytecode, bytecode_before)

    def test_hostile_pythonpath_and_stdlib_shadow_never_import(self) -> None:
        hostile = self.base / "hostile-import"
        hostile.mkdir(mode=0o700)
        copied_stage = hostile / "release_stage.py"
        shutil.copy2(ROOT / "scripts/release_stage.py", copied_stage)
        copied_stage.chmod(0o700)
        marker = hostile / "shadow-imported"
        (hostile / "json.py").write_text(
            "open("
            + repr(str(marker))
            + ", 'wb').write(b'imported')\n"
            + "raise RuntimeError('stdlib shadow executed')\n",
            encoding="utf-8",
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(hostile)
        for isolated in (False, True):
            with self.subTest(isolated=isolated):
                command = [os.sys.executable]
                if isolated:
                    command.append("-I")
                command.extend((str(copied_stage), "--invalid"))
                completed = subprocess.run(
                    command,
                    cwd=hostile,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertEqual(len(completed.stdout.splitlines()), 1)
                self.assertEqual(
                    json.loads(completed.stdout)["reason"],
                    "unsupported:invalid-arguments",
                )
                self.assertFalse(marker.exists())

    def test_planner_loader_rejects_symlinked_ancestor_and_leaf(self) -> None:
        scripts = self._incumbent_code_fixture("trusted-symlink")
        original_file = stage.__file__
        try:
            alias = self.base / "trusted-alias"
            alias.symlink_to(scripts.parent, target_is_directory=True)
            stage.__file__ = str(alias / "scripts/release_stage.py")
            with self.assertRaises(stage._Blocked) as caught:
                stage._load_incumbent_planner()
            self.assertEqual(caught.exception.token, "trusted-planner-unsafe")

            stage.__file__ = str(scripts / "release_stage.py")
            planner_path = scripts / "release_update_plan.py"
            planner_path.unlink()
            planner_path.symlink_to(ROOT / "scripts/release_update_plan.py")
            with self.assertRaises(stage._Blocked) as caught:
                stage._load_incumbent_planner()
            self.assertEqual(caught.exception.token, "trusted-planner-unsafe")
        finally:
            stage.__file__ = original_file

    def test_planner_loader_rejects_ancestor_swap_without_execution(self) -> None:
        scripts = self._incumbent_code_fixture("trusted-swap")
        original_file = stage.__file__
        original_compile = builtins.compile
        marker = self.base / "replacement-planner-executed"
        swapped = False

        def swapping_compile(source, filename, mode, **kwargs):
            nonlocal swapped
            if not swapped and filename.endswith("/release_update_plan.py"):
                swapped = True
                held = scripts.parent / "scripts-held"
                scripts.rename(held)
                scripts.mkdir(mode=0o700)
                scripts.chmod(0o700)
                (scripts / "release_stage.py").write_bytes(b"# replacement\n")
                (scripts / "release_stage.py").chmod(0o600)
                (scripts / "release_update_plan.py").write_text(
                    "open("
                    + repr(str(marker))
                    + ", 'wb').write(b'executed')\n",
                    encoding="utf-8",
                )
                (scripts / "release_update_plan.py").chmod(0o600)
            return original_compile(source, filename, mode, **kwargs)

        try:
            stage.__file__ = str(scripts / "release_stage.py")
            with mock.patch("builtins.compile", side_effect=swapping_compile):
                with self.assertRaises(stage._Blocked) as caught:
                    stage._load_incumbent_planner()
            self.assertTrue(swapped)
            self.assertEqual(caught.exception.token, "trusted-planner-raced")
            self.assertFalse(marker.exists())
        finally:
            stage.__file__ = original_file

    def test_planner_loader_rejects_visible_leaf_swap_before_exec(self) -> None:
        scripts = self._incumbent_code_fixture("trusted-leaf-swap")
        original_file = stage.__file__
        original_read = os.read
        swapped = False
        marker = self.base / "leaf-planner-executed"

        def swapping_read(descriptor, amount):
            nonlocal swapped
            path = os.fsdecode(
                fcntl.fcntl(
                    descriptor, fcntl.F_GETPATH, b"\x00" * 1024
                )
            ).split("\x00", 1)[0]
            payload = original_read(descriptor, amount)
            if path.endswith("/release_update_plan.py") and not swapped:
                swapped = True
                visible = scripts / "release_update_plan.py"
                visible.rename(scripts / "release_update_plan.py.held")
                visible.write_text(
                    "open("
                    + repr(str(marker))
                    + ", 'wb').write(b'executed')\n",
                    encoding="utf-8",
                )
                visible.chmod(0o600)
            return payload

        try:
            stage.__file__ = str(scripts / "release_stage.py")
            with mock.patch.object(os, "read", side_effect=swapping_read):
                with self.assertRaises(stage._Blocked) as caught:
                    stage._load_incumbent_planner()
            self.assertTrue(swapped)
            self.assertEqual(caught.exception.token, "trusted-planner-raced")
            self.assertFalse(marker.exists())
        finally:
            stage.__file__ = original_file

    def test_planner_loader_rejects_prepinned_replacement_without_execution(
        self,
    ) -> None:
        scripts = self._incumbent_code_fixture("trusted-preload-replacement")
        copied_stage = _load(
            "test_release_stage_pinned_copy", scripts / "release_stage.py"
        )
        marker = self.base / "prepinned-replacement-executed"
        replacement = scripts / "release_update_plan.py"
        replacement.write_text(
            "open("
            + repr(str(marker))
            + ", 'wb').write(b'executed')\n",
            encoding="utf-8",
        )
        replacement.chmod(0o600)

        with self.assertRaises(copied_stage._Blocked) as caught:
            copied_stage._load_incumbent_planner()
        self.assertEqual(
            caught.exception.token, "trusted-planner-identity-mismatch"
        )
        self.assertFalse(marker.exists())

    def test_embedded_planner_byte_pin_matches_reviewed_sibling(self) -> None:
        self.assertEqual(
            hashlib.sha256(
                (ROOT / "scripts/release_update_plan.py").read_bytes()
            ).hexdigest(),
            stage.TRUSTED_PLANNER_SHA256,
        )

    def test_planner_compatibility_preflight_covers_every_consumed_api(self) -> None:
        required = (
            "PRODUCT_SCHEMA",
            "PRODUCT_INVENTORY",
            "MAX_PRODUCT_TOTAL_BYTES",
            "MAX_PRODUCT_SCANNED_NAME_BYTES",
            "MAX_PRODUCT_DIRECTORY_ENTRIES",
            "MAX_PRODUCT_NAME_BYTES",
            "plan_product_release",
            "_inventory_policy_id",
            "_validate_product_inventory",
            "_product_directory_map",
            "_product_identity",
            "_RootSnapshot",
        )
        for missing in required:
            with self.subTest(missing=missing):
                fake = ModuleType("incompatible_planner")
                fake.__dict__.update(planner.__dict__)
                delattr(fake, missing)
                with mock.patch.object(
                    stage, "_load_incumbent_planner", return_value=fake
                ):
                    result = stage.stage_release(**self._arguments())
                self.assertEqual(
                    result["reason"],
                    "unsupported:trusted-planner-incompatible",
                )
                self.assertFalse((self.install / "operations").exists())
                self.assertFalse((self.install / "releases").exists())

        broken = ModuleType("incompatible_snapshot_planner")
        broken.__dict__.update(planner.__dict__)
        broken._RootSnapshot = object
        with mock.patch.object(
            stage, "_load_incumbent_planner", return_value=broken
        ):
            result = stage.stage_release(**self._arguments())
        self.assertEqual(
            result["reason"], "unsupported:trusted-planner-incompatible"
        )
        self.assertFalse((self.install / "operations").exists())

        wrong_signature = ModuleType("wrong_signature_planner")
        wrong_signature.__dict__.update(planner.__dict__)
        wrong_signature._product_identity = lambda: {}
        with mock.patch.object(
            stage, "_load_incumbent_planner", return_value=wrong_signature
        ):
            result = stage.stage_release(**self._arguments())
        self.assertEqual(
            result["reason"], "unsupported:trusted-planner-incompatible"
        )
        self.assertFalse((self.install / "operations").exists())

    def test_created_modes_are_exact_under_hostile_umask(self) -> None:
        previous = os.umask(0o777)
        try:
            result = stage.stage_release(**self._arguments())
        finally:
            os.umask(previous)
        self.assertEqual(result["status"], "staged", result)
        self.assertEqual(
            stat.S_IMODE((self.install / "releases").stat().st_mode), 0o700
        )
        self.assertEqual(
            stat.S_IMODE(
                (self.install / "releases" / self.product_id).stat().st_mode
            ),
            0o700,
        )
        self.assertEqual(
            stat.S_IMODE(
                (self.journal / "release-stage.jsonl").stat().st_mode
            ),
            0o600,
        )

    def test_repeat_is_idempotent_and_does_not_extend_journal(self) -> None:
        first = stage.stage_release(**self._arguments())
        self.assertEqual(first["status"], "staged")
        before = (self.journal / "release-stage.jsonl").read_bytes()
        second = stage.stage_release(**self._arguments())
        self.assertEqual(second["status"], "already-staged")
        self.assertTrue(second["resumed"])
        self.assertFalse(second["reconciled"])
        self.assertEqual(
            (self.journal / "release-stage.jsonl").read_bytes(), before
        )

    def test_visible_release_without_journal_is_reconciled(self) -> None:
        self.assertEqual(
            stage.stage_release(**self._arguments())["status"], "staged"
        )
        journal_file = self.journal / "release-stage.jsonl"
        journal_file.unlink()
        result = stage.stage_release(**self._arguments())
        self.assertEqual(result["status"], "already-staged")
        self.assertTrue(result["resumed"])
        self.assertTrue(result["reconciled"])
        entry = json.loads(journal_file.read_text().strip())
        self.assertEqual(entry["release_state"], "reconciled")

    def test_journal_claim_without_release_is_outcome_unknown(self) -> None:
        self.assertEqual(
            stage.stage_release(**self._arguments())["status"], "staged"
        )
        release = self.install / "releases" / self.product_id
        shutil.rmtree(release)
        result = stage.stage_release(**self._arguments())
        self.assertEqual(result["status"], "outcome_unknown")
        self.assertEqual(
            result["reason"], "outcome_unknown:journal-release-missing"
        )

    def test_corrupt_journal_is_outcome_unknown_and_never_replayed(self) -> None:
        self.assertEqual(
            stage.stage_release(**self._arguments())["status"], "staged"
        )
        journal_file = self.journal / "release-stage.jsonl"
        payload = bytearray(journal_file.read_bytes())
        payload[len(payload) // 2] ^= 1
        journal_file.write_bytes(payload)
        journal_file.chmod(0o600)
        release_before = {
            path.relative_to(self.install).as_posix(): _snapshot(path)
            for path in (self.install / "releases" / self.product_id).rglob("*")
            if path.is_file()
        }
        result = stage.stage_release(**self._arguments())
        self.assertEqual(result["status"], "outcome_unknown")
        self.assertEqual(result["reason"], "outcome_unknown:journal-malformed")
        release_after = {
            path.relative_to(self.install).as_posix(): _snapshot(path)
            for path in (self.install / "releases" / self.product_id).rglob("*")
            if path.is_file()
        }
        self.assertEqual(release_after, release_before)

    def test_uncooperative_concurrent_journal_writer_is_detected(self) -> None:
        real_write = os.write
        real_open = os.open
        injected = False

        def racing_write(descriptor, payload):
            nonlocal injected
            try:
                path = os.fsdecode(
                    fcntl.fcntl(
                        descriptor, fcntl.F_GETPATH, b"\x00" * 1024
                    )
                ).split("\x00", 1)[0]
            except OSError:
                path = ""
            if path.endswith("/release-stage.jsonl") and not injected:
                injected = True
                attacker = real_open(path, os.O_WRONLY | os.O_APPEND)
                try:
                    real_write(attacker, b"X\n")
                    os.fsync(attacker)
                finally:
                    os.close(attacker)
            return real_write(descriptor, payload)

        with mock.patch.object(os, "write", side_effect=racing_write):
            result = stage.stage_release(**self._arguments())
        self.assertTrue(injected)
        self.assertEqual(result["status"], "outcome_unknown")
        self.assertEqual(result["reason"], "outcome_unknown:journal-cas-mismatch")
        self.assertFalse(result["journal_committed"])
        retry = stage.stage_release(**self._arguments())
        self.assertEqual(retry["status"], "outcome_unknown")
        self.assertEqual(retry["reason"], "outcome_unknown:journal-malformed")

    def test_partial_journal_write_is_outcome_unknown_not_replayed(self) -> None:
        real_write = os.write
        partial_started = False
        fail_next = False

        def partial_write(descriptor, payload):
            nonlocal partial_started, fail_next
            try:
                path = os.fsdecode(
                    fcntl.fcntl(
                        descriptor, fcntl.F_GETPATH, b"\x00" * 1024
                    )
                ).split("\x00", 1)[0]
            except OSError:
                path = ""
            if path.endswith("/release-stage.jsonl"):
                if fail_next:
                    raise OSError(errno.EIO, "injected partial write")
                if not partial_started:
                    partial_started = True
                    fail_next = True
                    return real_write(descriptor, payload[:1])
            return real_write(descriptor, payload)

        with mock.patch.object(os, "write", side_effect=partial_write):
            result = stage.stage_release(**self._arguments())
        self.assertTrue(partial_started)
        self.assertEqual(result["status"], "outcome_unknown")
        self.assertEqual(
            result["reason"], "outcome_unknown:journal-commit-ambiguous"
        )
        retry = stage.stage_release(**self._arguments())
        self.assertEqual(retry["status"], "outcome_unknown")
        self.assertEqual(retry["reason"], "outcome_unknown:journal-malformed")

    def test_fresh_stage_post_journal_swap_cannot_false_success(self) -> None:
        sentinels = self._sentinels()
        release = self.install / "releases" / self.product_id
        detached = self.base / "fresh-detached-valid-release"
        attacker = self.base / "fresh-attacker-release"
        shutil.copytree(self.candidate, attacker)
        attacker.chmod(0o700)
        poisoned = attacker / "pyproject.toml"
        poisoned.write_bytes(b"attacker bytes\n")
        poisoned.chmod(0o600)
        original_append = stage._Journal.append
        append_called = False

        def append_then_swap(journal, product_id, policy_id, release_state):
            nonlocal append_called
            original_append(journal, product_id, policy_id, release_state)
            append_called = True
            release.rename(detached)
            attacker.rename(release)

        with mock.patch.object(
            stage._Journal, "append", new=append_then_swap
        ):
            result = stage.stage_release(**self._arguments())

        self.assertTrue(append_called)
        self.assertEqual(result["status"], "outcome_unknown", result)
        self.assertEqual(
            result["reason"], "outcome_unknown:published-release-raced"
        )
        self.assertFalse(result["journal_committed"])
        self.assertEqual(
            (release / "pyproject.toml").read_bytes(), b"attacker bytes\n"
        )
        self.assertEqual(
            (detached / "pyproject.toml").read_bytes(),
            (self.candidate / "pyproject.toml").read_bytes(),
        )
        lines = (self.journal / "release-stage.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["product_id"], self.product_id)
        self.assertEqual(entry["release_state"], "staged")
        unsigned = dict(entry)
        entry_hash = unsigned.pop("entry_hash")
        self.assertEqual(entry_hash, stage._journal_hash(unsigned))
        self._assert_sentinels(sentinels)

    def test_reconcile_post_journal_swap_cannot_false_success(self) -> None:
        def renamed_then_failed(source_fd, source, destination_fd, destination):
            os.rename(
                source,
                destination,
                src_dir_fd=source_fd,
                dst_dir_fd=destination_fd,
            )
            raise RuntimeError("leave visible release without journal")

        initial_arguments = self._arguments()
        initial_arguments["exclusive_rename"] = renamed_then_failed
        initial = stage.stage_release(**initial_arguments)
        self.assertEqual(initial["status"], "outcome_unknown", initial)
        self.assertEqual(
            (self.journal / "release-stage.jsonl").read_bytes(), b""
        )

        sentinels = self._sentinels()
        release = self.install / "releases" / self.product_id
        detached = self.base / "reconcile-detached-valid-release"
        attacker = self.base / "reconcile-attacker-release"
        shutil.copytree(self.candidate, attacker)
        attacker.chmod(0o700)
        poisoned = attacker / "pyproject.toml"
        poisoned.write_bytes(b"attacker bytes\n")
        poisoned.chmod(0o600)
        original_append = stage._Journal.append
        append_called = False

        def append_then_swap(journal, product_id, policy_id, release_state):
            nonlocal append_called
            original_append(journal, product_id, policy_id, release_state)
            append_called = True
            release.rename(detached)
            attacker.rename(release)

        with mock.patch.object(
            stage._Journal, "append", new=append_then_swap
        ):
            result = stage.stage_release(**self._arguments())

        self.assertTrue(append_called)
        self.assertEqual(result["status"], "outcome_unknown", result)
        self.assertEqual(
            result["reason"], "outcome_unknown:published-release-raced"
        )
        self.assertFalse(result["journal_committed"])
        self.assertEqual(
            (release / "pyproject.toml").read_bytes(), b"attacker bytes\n"
        )
        self.assertEqual(
            (detached / "pyproject.toml").read_bytes(),
            (self.candidate / "pyproject.toml").read_bytes(),
        )
        lines = (self.journal / "release-stage.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["product_id"], self.product_id)
        self.assertEqual(entry["release_state"], "reconciled")
        unsigned = dict(entry)
        entry_hash = unsigned.pop("entry_hash")
        self.assertEqual(entry_hash, stage._journal_hash(unsigned))
        self._assert_sentinels(sentinels)

    def test_rename_then_oserror_is_unknown_then_resumed(self) -> None:
        def renamed_then_failed(source_fd, source, destination_fd, destination):
            os.rename(
                source,
                destination,
                src_dir_fd=source_fd,
                dst_dir_fd=destination_fd,
            )
            raise OSError(errno.EIO, "ambiguous injected rename result")

        arguments = self._arguments()
        arguments["exclusive_rename"] = renamed_then_failed
        result = stage.stage_release(**arguments)
        self.assertEqual(result["status"], "outcome_unknown", result)
        self.assertEqual(
            result["reason"], "outcome_unknown:publish-callback-failed"
        )
        self.assertFalse(result["journal_committed"])
        self._assert_release_exact()
        retry = stage.stage_release(**self._arguments())
        self.assertEqual(retry["status"], "already-staged", retry)
        self.assertTrue(retry["reconciled"])
        self.assertTrue(retry["journal_committed"])

    def test_rename_then_runtime_error_is_unknown_then_resumed(self) -> None:
        def renamed_then_failed(source_fd, source, destination_fd, destination):
            os.rename(
                source,
                destination,
                src_dir_fd=source_fd,
                dst_dir_fd=destination_fd,
            )
            raise RuntimeError("ambiguous injected callback result")

        arguments = self._arguments()
        arguments["exclusive_rename"] = renamed_then_failed
        result = stage.stage_release(**arguments)
        self.assertEqual(result["status"], "outcome_unknown", result)
        self.assertEqual(
            result["reason"], "outcome_unknown:publish-callback-failed"
        )
        self.assertFalse(result["journal_committed"])
        self._assert_release_exact()
        retry = stage.stage_release(**self._arguments())
        self.assertEqual(retry["status"], "already-staged", retry)
        self.assertTrue(retry["reconciled"])
        self.assertTrue(retry["journal_committed"])

    def test_rename_then_blocked_is_unknown_then_resumed(self) -> None:
        def renamed_then_failed(source_fd, source, destination_fd, destination):
            os.rename(
                source,
                destination,
                src_dir_fd=source_fd,
                dst_dir_fd=destination_fd,
            )
            raise stage._Blocked("injected-callback-control-error")

        arguments = self._arguments()
        arguments["exclusive_rename"] = renamed_then_failed
        result = stage.stage_release(**arguments)
        self.assertEqual(result["status"], "outcome_unknown", result)
        self.assertEqual(
            result["reason"], "outcome_unknown:publish-callback-failed"
        )
        self.assertFalse(result["journal_committed"])
        self._assert_release_exact()
        retry = stage.stage_release(**self._arguments())
        self.assertEqual(retry["status"], "already-staged", retry)
        self.assertTrue(retry["reconciled"])
        self.assertTrue(retry["journal_committed"])

    def test_rename_then_keyboard_interrupt_is_unknown_then_resumed(self) -> None:
        def renamed_then_interrupted(
            source_fd, source, destination_fd, destination
        ):
            os.rename(
                source,
                destination,
                src_dir_fd=source_fd,
                dst_dir_fd=destination_fd,
            )
            raise KeyboardInterrupt

        arguments = self._arguments()
        arguments["exclusive_rename"] = renamed_then_interrupted
        result = stage.stage_release(**arguments)
        self.assertEqual(result["status"], "outcome_unknown", result)
        self.assertEqual(
            result["reason"], "outcome_unknown:publish-callback-failed"
        )
        self.assertFalse(result["journal_committed"])
        self._assert_release_exact()
        retry = stage.stage_release(**self._arguments())
        self.assertEqual(retry["status"], "already-staged", retry)
        self.assertTrue(retry["reconciled"])
        self.assertTrue(retry["journal_committed"])

    def test_rename_error_with_intact_source_is_ordinary_refusal(self) -> None:
        def failed_without_rename(source_fd, source, destination_fd, destination):
            raise OSError(errno.EIO, "injected no-op rename failure")

        arguments = self._arguments()
        arguments["exclusive_rename"] = failed_without_rename
        result = stage.stage_release(**arguments)
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["reason"], "unsupported:exclusive-publish-failed")
        self.assertFalse((self.install / "releases" / self.product_id).exists())

    def test_product_identity_and_policy_are_both_pinned(self) -> None:
        arguments = self._arguments()
        arguments["expected_product_id"] = "product-" + "0" * 64
        result = stage.stage_release(**arguments)
        self.assertEqual(result["status"], "unsupported")
        self.assertFalse((self.install / "releases").exists())

        arguments = self._arguments()
        arguments["expected_inventory_policy_id"] = (
            "inventory-policy-" + "0" * 64
        )
        result = stage.stage_release(**arguments)
        self.assertEqual(result["reason"], "unsupported:inventory-policy-mismatch")
        self.assertFalse((self.install / "releases").exists())

    def test_all_root_overlaps_fail_before_writes(self) -> None:
        root_fields = (
            "current_source_root",
            "candidate_source_root",
            "install_root",
            "environment_root",
            "data_root",
            "journal_root",
        )
        for field in root_fields:
            with self.subTest(field=field):
                arguments = self._arguments()
                overlap_parent = (
                    self.data if field != "data_root" else self.install
                )
                arguments[field] = overlap_parent / "nested"
                result = stage.stage_release(**arguments)
                self.assertEqual(result["reason"], "unsupported:root-overlap")
        self.assertFalse((self.install / "releases").exists())

    def test_active_state_path_components_are_casefold_rejected(self) -> None:
        for field in (
            "current_source_root",
            "candidate_source_root",
            "install_root",
            "journal_root",
        ):
            with self.subTest(field=field):
                arguments = self._arguments()
                arguments[field] = self.base / ".SYNAPSE_S2" / field
                result = stage.stage_release(**arguments)
                self.assertEqual(
                    result["reason"],
                    "unsupported:active-state-path-forbidden",
                )

    def test_darwin_tmp_alias_is_rejected_for_every_authority_root(self) -> None:
        self.assertTrue(str(self.base).startswith("/private/tmp/"))
        for field in (
            "current_source_root",
            "candidate_source_root",
            "install_root",
            "environment_root",
            "data_root",
            "journal_root",
        ):
            with self.subTest(field=field):
                arguments = self._arguments()
                original = str(arguments[field])
                arguments[field] = "/tmp/" + original.removeprefix(
                    "/private/tmp/"
                )
                self.assertTrue(
                    os.path.samefile(arguments[field], original)
                )
                result = stage.stage_release(**arguments)
                self.assertEqual(
                    result["reason"], "unsupported:root-alias-unsafe"
                )
        self.assertFalse((self.install / "releases").exists())

    def test_repeated_alias_refusals_close_partial_guard_descriptors(self) -> None:
        arguments = self._arguments()
        arguments["data_root"] = "/tmp/" + str(self.data).removeprefix(
            "/private/tmp/"
        )
        before = self._open_descriptors()
        for _ in range(24):
            result = stage.stage_release(**arguments)
            self.assertEqual(
                result["reason"], "unsupported:root-alias-unsafe"
            )
        self.assertEqual(self._open_descriptors(), before)

    def test_all_descriptor_acquisitions_close_on_base_exception(self) -> None:
        def assert_balanced(label, action) -> None:
            with self.subTest(site=label):
                before = self._open_descriptors()
                with self.assertRaises(KeyboardInterrupt):
                    action()
                after = self._open_descriptors()
                leaked = after - before
                for descriptor in leaked:
                    os.close(descriptor)
                self.assertEqual(after, before)

        def untouched_anchor_fstat() -> None:
            guard = stage._UntouchedRootGuard(str(self.base))
            try:
                with mock.patch.object(
                    stage.os, "fstat", side_effect=KeyboardInterrupt
                ):
                    guard.open()
            finally:
                guard.close()

        assert_balanced("untouched-anchor-fstat", untouched_anchor_fstat)

        def held_private_child_fstat() -> None:
            held = stage._HeldPrivateRoot(str(self.base))
            real_fstat = stage.os.fstat
            calls = 0

            def fail_second(descriptor):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise KeyboardInterrupt
                return real_fstat(descriptor)

            try:
                with mock.patch.object(
                    stage.os, "fstat", side_effect=fail_second
                ):
                    held.open()
            finally:
                held.close()

        assert_balanced("held-private-child-fstat", held_private_child_fstat)

        child = self.base / "fd-existing-child"
        child.mkdir(mode=0o700)
        child.chmod(0o700)

        def call_with_parent(callback) -> None:
            parent = os.open(self.base, stage._DIR_OPEN_FLAGS)
            try:
                callback(parent)
            finally:
                os.close(parent)

        def ensure_private_child_fstat() -> None:
            def invoke(parent) -> None:
                with mock.patch.object(
                    stage.os, "fstat", side_effect=KeyboardInterrupt
                ):
                    stage._ensure_private_child(parent, child.name)

            call_with_parent(invoke)

        assert_balanced("ensure-private-child-fstat", ensure_private_child_fstat)

        def open_private_child_fstat() -> None:
            def invoke(parent) -> None:
                with mock.patch.object(
                    stage.os, "fstat", side_effect=KeyboardInterrupt
                ):
                    stage._open_private_child(parent, child.name)

            call_with_parent(invoke)

        assert_balanced("open-private-child-fstat", open_private_child_fstat)

        def private_regular_fchmod() -> None:
            def invoke(parent) -> None:
                with mock.patch.object(
                    stage.os, "fchmod", side_effect=KeyboardInterrupt
                ):
                    stage._open_private_regular(
                        parent, "fd-fault.lock", create=True
                    )

            call_with_parent(invoke)

        assert_balanced("private-regular-fchmod", private_regular_fchmod)

        existing_regular = self.base / "fd-existing.lock"
        existing_regular.write_bytes(b"")
        existing_regular.chmod(0o600)

        def private_regular_fstat() -> None:
            def invoke(parent) -> None:
                with mock.patch.object(
                    stage.os, "fstat", side_effect=KeyboardInterrupt
                ):
                    stage._open_private_regular(
                        parent, existing_regular.name, create=True
                    )

            call_with_parent(invoke)

        assert_balanced("private-regular-fstat", private_regular_fstat)

        release = self.base / ("product-" + "0" * 64)
        release.mkdir(mode=0o700)
        release.chmod(0o700)

        def existing_release_fstat() -> None:
            def invoke(parent) -> None:
                with mock.patch.object(
                    stage.os, "fstat", side_effect=KeyboardInterrupt
                ):
                    stage._existing_release_fd(parent, release.name)

            call_with_parent(invoke)

        assert_balanced("existing-release-fstat", existing_release_fstat)

        incumbent = self.base / "fd-incumbent"
        incumbent.mkdir(mode=0o700)
        incumbent.chmod(0o700)
        incumbent_planner = incumbent / "release_update_plan.py"
        incumbent_planner.write_bytes(b"# pinned fixture\n")
        incumbent_planner.chmod(0o600)

        def incumbent_regular_fstat() -> None:
            anchor = stage._HeldIncumbentCodeDirectory()
            anchor.directory_fd = os.open(incumbent, stage._DIR_OPEN_FLAGS)
            anchor._fds.append(anchor.directory_fd)
            try:
                with mock.patch.object(
                    stage.os, "fstat", side_effect=KeyboardInterrupt
                ):
                    anchor._open_regular(incumbent_planner.name, 1024)
            finally:
                anchor.close()

        assert_balanced("incumbent-regular-fstat", incumbent_regular_fstat)

        def incumbent_child_fstat() -> None:
            anchor = stage._HeldIncumbentCodeDirectory()
            real_fstat = stage.os.fstat
            calls = 0

            def fail_second(descriptor):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise KeyboardInterrupt
                return real_fstat(descriptor)

            try:
                with mock.patch.object(
                    stage.os, "fstat", side_effect=fail_second
                ):
                    anchor.open()
            finally:
                anchor.close()

        assert_balanced("incumbent-child-fstat", incumbent_child_fstat)

        def destination_directory_fchmod() -> None:
            root = self.base / "fd-destination-directory"
            root.mkdir(mode=0o700)
            root.chmod(0o700)
            root_fd = os.open(root, stage._DIR_OPEN_FLAGS)
            destination = stage._DestinationTree(root_fd)
            try:
                with mock.patch.object(
                    stage.os, "fchmod", side_effect=KeyboardInterrupt
                ):
                    destination._directory(("child",))
            finally:
                destination.close()
                os.close(root_fd)

        assert_balanced(
            "destination-directory-fchmod", destination_directory_fchmod
        )

        def destination_file_fchmod() -> None:
            root = self.base / "fd-destination-file"
            root.mkdir(mode=0o700)
            root.chmod(0o700)
            root_fd = os.open(root, stage._DIR_OPEN_FLAGS)
            destination = stage._DestinationTree(root_fd)
            try:
                with mock.patch.object(
                    stage.os, "fchmod", side_effect=KeyboardInterrupt
                ):
                    destination.write_file("fault.bin", b"x", 0o600)
            finally:
                destination.close()
                os.close(root_fd)

        assert_balanced("destination-file-fchmod", destination_file_fchmod)

    def test_symlink_hardlink_and_fifo_candidates_fail_closed(self) -> None:
        paths = [entry[2] for entry in planner.PRODUCT_INVENTORY[:3]]
        for kind, relative in zip(("symlink", "hardlink", "fifo"), paths):
            with self.subTest(kind=kind):
                root = self.base / ("candidate-" + kind)
                root.mkdir(mode=0o700)
                root.chmod(0o700)
                self._build_product_root(root)
                target = root / relative
                target.unlink()
                if kind == "symlink":
                    outside = self.base / "outside-target"
                    outside.write_bytes(b"outside")
                    target.symlink_to(outside)
                elif kind == "hardlink":
                    source = root / planner.PRODUCT_INVENTORY[5][2]
                    os.link(source, target)
                else:
                    os.mkfifo(target, 0o600)
                arguments = self._arguments()
                arguments["candidate_source_root"] = root
                result = stage.stage_release(**arguments)
                self.assertEqual(result["status"], "unsupported")
                self.assertFalse((self.install / "releases").exists())

    def test_candidate_python_is_never_executed(self) -> None:
        marker = self.base / "candidate-executed"
        payload = (
            "from pathlib import Path\n"
            + "Path("
            + repr(str(marker))
            + ").write_text('executed')\n"
        ).encode("utf-8")
        candidate_code = self.candidate / "synapse_cli.py"
        candidate_code.write_bytes(payload)
        candidate_code.chmod(0o700)
        plan = planner.plan_product_release(self.current, self.candidate)
        self.assertEqual(plan["status"], "update-available")
        arguments = self._arguments()
        arguments["expected_product_id"] = plan["candidate"]["product_id"]
        result = stage.stage_release(**arguments)
        self.assertEqual(result["status"], "staged", result)
        self.assertFalse(marker.exists())
        self.assertEqual(
            (
                self.install
                / "releases"
                / plan["candidate"]["product_id"]
                / "synapse_cli.py"
            ).read_bytes(),
            payload,
        )

    def test_candidate_planner_is_data_only_and_never_loaded(self) -> None:
        marker = self.base / "candidate-planner-executed"
        payload = (
            "open("
            + repr(str(marker))
            + ", 'wb').write(b'executed')\n"
        ).encode("utf-8")
        candidate_planner = self.candidate / "scripts/release_update_plan.py"
        candidate_planner.write_bytes(payload)
        candidate_planner.chmod(0o700)
        plan = planner.plan_product_release(self.current, self.candidate)
        self.assertEqual(plan["status"], "update-available")
        arguments = self._arguments()
        arguments["expected_product_id"] = plan["candidate"]["product_id"]
        result = stage.stage_release(**arguments)
        self.assertEqual(result["status"], "staged", result)
        self.assertFalse(marker.exists())
        staged = (
            self.install
            / "releases"
            / plan["candidate"]["product_id"]
            / "scripts/release_update_plan.py"
        )
        self.assertEqual(staged.read_bytes(), payload)

    def test_candidate_git_metadata_is_never_copied(self) -> None:
        metadata = self.candidate / ".git"
        metadata.mkdir(mode=0o700)
        metadata.chmod(0o700)
        result = stage.stage_release(**self._arguments())
        self.assertEqual(result["status"], "staged", result)
        release = self.install / "releases" / self.product_id
        self.assertFalse((release / ".git").exists())

    def test_existing_release_with_extra_entry_is_outcome_unknown(self) -> None:
        self.assertEqual(
            stage.stage_release(**self._arguments())["status"], "staged"
        )
        extra = self.install / "releases" / self.product_id / ".git"
        extra.mkdir(mode=0o700)
        extra.chmod(0o700)
        result = stage.stage_release(**self._arguments())
        self.assertEqual(result["status"], "outcome_unknown")
        self.assertIn(
            result["reason"],
            (
                "outcome_unknown:staged-tree-not-exact",
                "outcome_unknown:staged-verification-failed",
            ),
        )

    def test_data_and_environment_roots_are_not_traversed(self) -> None:
        sentinels = self._sentinels()
        self.data.chmod(0o000)
        self.environment.chmod(0o000)
        try:
            result = stage.stage_release(**self._arguments())
        finally:
            self.data.chmod(0o700)
            self.environment.chmod(0o700)
        self.assertEqual(result["status"], "staged", result)
        self._assert_sentinels(sentinels)

    def test_candidate_drift_during_capture_fails_closed(self) -> None:
        sentinels = self._sentinels()
        original = planner._RootSnapshot.read_file_with_stat
        changed = False

        def drifting(snapshot, name, budget):
            nonlocal changed
            result = original(snapshot, name, budget)
            if str(snapshot.root) == str(self.candidate) and not changed:
                changed = True
                path = self.candidate / name
                payload = path.read_bytes()
                path.write_bytes(payload)
                path.chmod(stat.S_IMODE(result[1].st_mode))
            return result

        with mock.patch.object(
            planner._RootSnapshot,
            "read_file_with_stat",
            new=drifting,
        ), mock.patch.object(
            stage, "_load_incumbent_planner", return_value=planner
        ):
            result = stage.stage_release(**self._arguments())
        self.assertTrue(changed)
        self.assertEqual(result["status"], "unsupported")
        self.assertFalse((self.install / "releases").exists())
        self._assert_sentinels(sentinels)

    def test_private_root_and_journal_tampering_fail_closed(self) -> None:
        self.install.chmod(0o755)
        result = stage.stage_release(**self._arguments())
        self.assertEqual(result["reason"], "unsupported:root-not-private")
        self.install.chmod(0o700)

        unsafe = self.journal / "release-stage.lock"
        unsafe.write_bytes(b"")
        unsafe.chmod(0o644)
        before = unsafe.stat().st_mode
        result = stage.stage_release(**self._arguments())
        self.assertEqual(result["reason"], "unsupported:journal-unsafe")
        self.assertEqual(unsafe.stat().st_mode, before)

    def test_no_external_execution_database_socket_or_outside_writes(self) -> None:
        sentinels = self._sentinels()
        real_open = os.open
        real_mkdir = os.mkdir
        real_write = os.write
        real_chmod = os.chmod
        real_fchmod = os.fchmod
        real_rename = os.rename
        allowed = (str(self.install), str(self.journal))

        def descriptor_path(descriptor: int) -> str:
            return os.fsdecode(
                fcntl.fcntl(descriptor, fcntl.F_GETPATH, b"\x00" * 1024)
            ).split("\x00", 1)[0]

        def assert_allowed(path: object, dir_fd: int | None = None) -> None:
            raw = os.fsdecode(path)
            if not raw.startswith("/"):
                if dir_fd is None:
                    return
                raw = descriptor_path(dir_fd) + "/" + raw
            normalized = os.path.normpath(raw)
            if not any(
                normalized == root or normalized.startswith(root + "/")
                for root in allowed
            ):
                raise AssertionError("write outside explicit stage roots")

        def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
                assert_allowed(path, dir_fd)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        def guarded_mkdir(path, mode=0o777, *, dir_fd=None):
            assert_allowed(path, dir_fd)
            return real_mkdir(path, mode, dir_fd=dir_fd)

        def guarded_write(descriptor, payload):
            assert_allowed(descriptor_path(descriptor))
            return real_write(descriptor, payload)

        def guarded_chmod(
            path, mode, *, dir_fd=None, follow_symlinks=True
        ):
            assert_allowed(path, dir_fd)
            return real_chmod(
                path,
                mode,
                dir_fd=dir_fd,
                follow_symlinks=follow_symlinks,
            )

        def guarded_fchmod(descriptor, mode):
            assert_allowed(descriptor_path(descriptor))
            return real_fchmod(descriptor, mode)

        def guarded_rename(
            source,
            destination,
            *,
            src_dir_fd=None,
            dst_dir_fd=None,
        ):
            assert_allowed(source, src_dir_fd)
            assert_allowed(destination, dst_dir_fd)
            return real_rename(
                source,
                destination,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )

        blocked = AssertionError("forbidden side effect")
        with (
            mock.patch.object(os, "open", side_effect=guarded_open),
            mock.patch.object(os, "mkdir", side_effect=guarded_mkdir),
            mock.patch.object(os, "write", side_effect=guarded_write),
            mock.patch.object(os, "chmod", side_effect=guarded_chmod),
            mock.patch.object(os, "fchmod", side_effect=guarded_fchmod),
            mock.patch.object(os, "rename", side_effect=guarded_rename),
            mock.patch.object(subprocess, "Popen", side_effect=blocked),
            mock.patch.object(subprocess, "run", side_effect=blocked),
            mock.patch.object(subprocess, "call", side_effect=blocked),
            mock.patch.object(subprocess, "check_call", side_effect=blocked),
            mock.patch.object(subprocess, "check_output", side_effect=blocked),
            mock.patch.object(socket, "socket", side_effect=blocked),
            mock.patch.object(socket, "create_connection", side_effect=blocked),
            mock.patch.object(sqlite3, "connect", side_effect=blocked),
            mock.patch.object(os, "system", side_effect=blocked),
            mock.patch.object(
                stage, "_load_incumbent_planner", return_value=planner
            ),
        ):
            result = stage.stage_release(**self._arguments())
        self.assertEqual(result["status"], "staged", result)
        self._assert_sentinels(sentinels)

    def test_platform_gate_is_injectable_and_precedes_filesystem_access(self) -> None:
        arguments = self._arguments()
        arguments["platform_system"] = "Linux"
        arguments["platform_machine"] = "x86_64"
        with mock.patch.object(stage, "_load_incumbent_planner") as load:
            result = stage.stage_release(**arguments)
        self.assertEqual(result["reason"], "unsupported:platform-unsupported")
        load.assert_not_called()

    def test_cli_and_renderer_are_one_line_bounded_and_redacted(self) -> None:
        result = stage._unsupported("internal-error")
        line = stage.render_result(result)
        self.assertNotIn("\n", line)
        self.assertLessEqual(len(line.encode("ascii")), stage.MAX_RESULT_BYTES)
        self.assertNotIn(str(self.base), line)
        self.assertEqual(stage.result_exit_code(result), 2)
        self.assertEqual(stage.main([]), 2)

    def test_cli_help_is_one_deterministic_json_line(self) -> None:
        completed = subprocess.run(
            [os.sys.executable, "-I", str(ROOT / "scripts/release_stage.py"), "--help"],
            cwd="/private/tmp",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["schema"], stage.HELP_SCHEMA)
        self.assertEqual(payload["status"], "help")
        self.assertEqual(
            payload["required_options"], list(stage._REQUIRED_CLI_OPTIONS)
        )
        self.assertFalse(payload["activation_supported"])
        self.assertFalse(payload["activation_performed"])
        self.assertFalse(payload["live_state_modified"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import ast
import codecs
import contextlib
import hashlib
import io
import json
import os
import pathlib
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import tokenize
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core_service import BUILD_SOURCE_MANIFEST, _manifest_build_id
from scripts import release_update_plan as planner

# Build id of the trusted manifest at the pinned working-tree revision.  This
# test suite deliberately certifies the real repository root.
REAL_ROOT_BUILD_ID = "source-5cd8917c28e911d7100cde16"

PLAN_KEYS = {
    "schema",
    "mode",
    "classification",
    "status",
    "apply_supported",
    "apply_performed",
    "provenance_verified",
    "current",
    "candidate",
    "changes",
    "requirements",
}

INVALID_ARGUMENTS_LINE = (
    planner.render_plan(
        planner._build_plan(
            "unsupported", "unsupported:invalid-arguments", None, None, []
        )
    )
    + "\n"
)


class ReleaseUpdatePlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.class_temporary = tempfile.TemporaryDirectory(
            prefix="s2rup-", dir="/tmp"
        )
        # macOS exposes /var and /tmp as symlinks; the planner requires
        # physical paths, so fixtures use the resolved base.
        cls.class_base = Path(cls.class_temporary.name).resolve()
        cls.template = cls.class_base / "template"
        for name in BUILD_SOURCE_MANIFEST:
            destination = cls.template / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / name).read_bytes())
        for directory, _, files in os.walk(cls.template):
            os.chmod(directory, 0o755)
            for filename in files:
                os.chmod(Path(directory) / filename, 0o644)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.class_temporary.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="s2rup-", dir="/tmp")
        self.base = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)

    def make_root(self, name: str) -> Path:
        destination = self.base / name
        shutil.copytree(self.template, destination)
        return destination

    def firing_os_open(self, trigger_leaf: str, action):
        """Wrap os.open so ``action`` runs exactly once, immediately before
        the first dir_fd-relative open of ``trigger_leaf`` — i.e. after the
        planner's before-stat and inside its stat/open/read window."""
        real_open = os.open
        state = {"fired": False}

        def wrapper(path, flags, *args, **kwargs):
            if not state["fired"] and str(path) == trigger_leaf:
                state["fired"] = True
                action()
            return real_open(path, flags, *args, **kwargs)

        return wrapper, state

    def assert_plan_shape(self, plan: dict) -> None:
        self.assertEqual(set(plan), PLAN_KEYS)
        self.assertEqual(plan["schema"], "synapse-s2.release-update-plan.v1")
        self.assertEqual(plan["mode"], "read-only-plan")
        self.assertIs(plan["apply_supported"], False)
        self.assertIs(plan["apply_performed"], False)
        self.assertIs(plan["provenance_verified"], False)
        self.assertEqual(set(plan["current"]), {"source_build_id"})
        self.assertEqual(set(plan["candidate"]), {"source_build_id"})
        self.assertIsInstance(plan["changes"], list)
        self.assertIsInstance(plan["requirements"], list)

    def assert_unsupported(self, plan: dict, token: str) -> None:
        self.assert_plan_shape(plan)
        self.assertEqual(plan["classification"], "unsupported")
        self.assertEqual(plan["status"], f"unsupported:{token}")
        self.assertEqual(plan["changes"], [])
        self.assertEqual(planner.plan_exit_code(plan), 2)

    def test_real_root_no_op_with_expected_build_id(self) -> None:
        plan = planner.plan_release_update(ROOT, ROOT, REAL_ROOT_BUILD_ID)
        self.assert_plan_shape(plan)
        self.assertEqual(plan["classification"], "no-op")
        self.assertEqual(plan["status"], "no-op")
        self.assertEqual(plan["current"]["source_build_id"], REAL_ROOT_BUILD_ID)
        self.assertEqual(plan["candidate"]["source_build_id"], REAL_ROOT_BUILD_ID)
        self.assertEqual(plan["changes"], [])
        self.assertEqual(plan["requirements"], [])
        self.assertEqual(planner.plan_exit_code(plan), 0)

    def test_build_id_byte_compatible_with_manifest_build_id(self) -> None:
        plan = planner.plan_release_update(ROOT, ROOT)
        self.assertEqual(
            plan["current"]["source_build_id"], _manifest_build_id(ROOT)
        )

    def test_manifest_python_imports_transitively_closed(self) -> None:
        # Every repo-local top-level module reachable by import from a
        # manifested Python file must itself be manifested, or the build id
        # silently excludes code that ships with the release.
        manifested = set(BUILD_SOURCE_MANIFEST)
        pending = sorted(
            name for name in manifested if name.endswith(".py")
        )
        visited: set[str] = set(pending)
        unmanifested: set[str] = set()
        while pending:
            filename = pending.pop()
            tree = ast.parse((ROOT / filename).read_text())
            roots: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        roots.add(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module is not None:
                        roots.add(node.module.split(".")[0])
            for root_name in roots:
                local = f"{root_name}.py"
                if not (ROOT / local).is_file():
                    continue
                if local not in manifested:
                    unmanifested.add(local)
                if local not in visited:
                    visited.add(local)
                    pending.append(local)
        self.assertEqual(sorted(unmanifested), [])

    def test_identical_copied_roots_are_no_op(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        plan = planner.plan_release_update(current, candidate)
        self.assert_plan_shape(plan)
        self.assertEqual(plan["classification"], "no-op")
        self.assertEqual(plan["status"], "no-op")
        self.assertEqual(
            plan["current"]["source_build_id"],
            plan["candidate"]["source_build_id"],
        )
        self.assertEqual(planner.plan_exit_code(plan), 0)

    def test_harmless_candidate_change_is_blocked_not_compatible(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        victim = candidate / "redaction.py"
        victim.write_bytes(victim.read_bytes() + b"\n# harmless comment\n")
        plan = planner.plan_release_update(current, candidate)
        self.assert_plan_shape(plan)
        self.assertEqual(plan["classification"], "changed-unclassified")
        self.assertEqual(plan["status"], "blocked-changed-unclassified")
        self.assertEqual(plan["changes"], ["redaction.py"])
        self.assertIn("contract-classification", plan["requirements"])
        self.assertNotEqual(
            plan["current"]["source_build_id"],
            plan["candidate"]["source_build_id"],
        )
        self.assertEqual(planner.plan_exit_code(plan), 3)

    def test_expected_build_id_mismatch_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        plan = planner.plan_release_update(
            current, candidate, "source-" + "0" * 24
        )
        self.assert_unsupported(plan, "expected-build-id-mismatch")

    def test_malformed_expected_build_id_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        for malformed in ("SOURCE-" + "0" * 24, "source-" + "0" * 23, "abc"):
            plan = planner.plan_release_update(current, candidate, malformed)
            self.assert_unsupported(plan, "invalid-arguments")

    def test_candidate_manifest_drift_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        source_path = candidate / "core_service.py"
        text = source_path.read_text()
        drifted = text.replace(
            '"apple_vision_enrichment.py",',
            '"apple_vision_enrichment_drift.py",',
            1,
        )
        self.assertNotEqual(text, drifted)
        source_path.write_text(drifted)
        plan = planner.plan_release_update(current, candidate)
        self.assert_unsupported(plan, "manifest-drift")

    def test_candidate_manifest_rebind_or_mutation_is_drift(self) -> None:
        current = self.make_root("current")
        suffixes = [
            b'\nBUILD_SOURCE_MANIFEST += ("extra_source.py",)\n',
            b"\nBUILD_SOURCE_MANIFEST = BUILD_SOURCE_MANIFEST\n",
            b"\ndef _shadow():\n    BUILD_SOURCE_MANIFEST = None\n",
            b"\ndel BUILD_SOURCE_MANIFEST\n",
            b"\ndef BUILD_SOURCE_MANIFEST():\n    pass\n",
            b"\nasync def BUILD_SOURCE_MANIFEST():\n    pass\n",
            b"\nclass BUILD_SOURCE_MANIFEST:\n    pass\n",
            b"\nmatch (1,):\n    case BUILD_SOURCE_MANIFEST:\n        pass\n",
            b"\nmatch (1,):\n    case [*BUILD_SOURCE_MANIFEST]:\n        pass\n",
            b"\nmatch {}:\n    case {**BUILD_SOURCE_MANIFEST}:\n        pass\n",
            b"\nfrom attacker import *\n",
            b'\nexec("BUILD_SOURCE_MANIFEST = ()")\n',
            b'\nglobals().update({"BUILD_SOURCE_MANIFEST": ()})\n',
            b'\nglobals()["BUILD_SOURCE_MANIFEST"] = ()\n',
            b"\nimport core_service as _m\n_m.BUILD_SOURCE_MANIFEST = ()\n",
            b'\n_d = {}\n_d["BUILD_SOURCE_MANIFEST"] = ()\n',
            b'\nBUILD_SOURCE_MANIFEST[0] = "changed"\n',
            b"\ndel BUILD_SOURCE_MANIFEST[0]\n",
            b"\nBUILD_SOURCE_MANIFEST.attribute = ()\n",
            b'\nimport source as _source\n_source.BUILD_SOURCE_MANIFEST[0] = "changed"\n',
            b"\nimport source as _source\ndel _source.BUILD_SOURCE_MANIFEST[0]\n",
        ]
        if sys.version_info >= (3, 12):
            suffixes.extend(
                (
                    b"\ndef _generic[BUILD_SOURCE_MANIFEST]():\n    pass\n",
                    b"\nclass _Generic[BUILD_SOURCE_MANIFEST]:\n    pass\n",
                    b"\ntype _Alias[BUILD_SOURCE_MANIFEST] = int\n",
                    b"\ndef _variadic[*BUILD_SOURCE_MANIFEST]():\n    pass\n",
                    b"\ndef _paramspec[**BUILD_SOURCE_MANIFEST]():\n    pass\n",
                )
            )
        for index, suffix in enumerate(suffixes):
            candidate = self.make_root(f"candidate-rebind-{index}")
            source_path = candidate / "core_service.py"
            source_path.write_bytes(source_path.read_bytes() + suffix)
            plan = planner.plan_release_update(current, candidate)
            self.assert_unsupported(plan, "manifest-drift")

    def test_candidate_manifest_missing_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        (candidate / "core_service.py").write_bytes(b"VALUE = 1\n")
        plan = planner.plan_release_update(current, candidate)
        self.assert_unsupported(plan, "manifest-missing")

    def test_missing_manifest_file_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        (candidate / "mlx_backend.py").unlink()
        plan = planner.plan_release_update(current, candidate)
        self.assert_unsupported(plan, "file-missing")

    def test_symlinked_manifest_file_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        victim = candidate / "redaction.py"
        victim.unlink()
        victim.symlink_to(candidate / "core_protocol.py")
        plan = planner.plan_release_update(current, candidate)
        self.assert_unsupported(plan, "file-unsafe")

    def test_hardlinked_manifest_file_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        # A second link outside the root means the file content can be
        # rewritten through a path the planner never validates.
        os.link(candidate / "memory_store.py", self.base / "outside-hardlink")
        plan = planner.plan_release_update(current, candidate)
        self.assert_unsupported(plan, "file-unsafe")

    def test_world_writable_manifest_file_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        os.chmod(candidate / "memory_store.py", 0o666)
        plan = planner.plan_release_update(current, candidate)
        self.assert_unsupported(plan, "file-unsafe")

    def test_oversize_manifest_file_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        with open(candidate / "uv.lock", "r+b") as handle:
            handle.truncate(planner.MAX_MANIFEST_FILE_BYTES + 1)
        plan = planner.plan_release_update(current, candidate)
        self.assert_unsupported(plan, "file-oversize")

    def test_aggregate_total_budget_is_enforced_before_read(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        # Four files at exactly the per-file cap each pass individually but
        # push the invocation past the aggregate 64 MiB budget.
        for name in BUILD_SOURCE_MANIFEST[:4]:
            with open(candidate / name, "r+b") as handle:
                handle.truncate(planner.MAX_MANIFEST_FILE_BYTES)
        real_read = os.read
        total = {"bytes": 0}

        def counting_read(descriptor, size):
            chunk = real_read(descriptor, size)
            total["bytes"] += len(chunk)
            return chunk

        with mock.patch.object(planner.os, "read", new=counting_read):
            plan = planner.plan_release_update(current, candidate)
        self.assert_unsupported(plan, "total-oversize")
        # The budget is enforced before each open, so the run never reads a
        # single byte beyond the aggregate limit.
        self.assertLessEqual(total["bytes"], planner.MAX_TOTAL_MANIFEST_BYTES)
        self.assertGreater(total["bytes"], 0)

    def test_append_race_during_read_never_exceeds_budget(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        # Cap the aggregate budget at exactly the byte total of both roots so
        # even a single byte read beyond the accounted sizes overshoots.
        cap = sum(
            os.stat(root / name).st_size
            for root in (current, candidate)
            for name in BUILD_SOURCE_MANIFEST
        )
        victim = candidate / "uv.lock"
        real_open = os.open
        real_read = os.read
        tracker = {"opens": 0, "victim_fd": None, "total": 0, "fired": False}

        def tracking_open(path, flags, *args, **kwargs):
            descriptor = real_open(path, flags, *args, **kwargs)
            if str(path) == "uv.lock":
                tracker["opens"] += 1
                if tracker["opens"] == 2:
                    # The candidate's uv.lock: the last manifest file read.
                    tracker["victim_fd"] = descriptor
            return descriptor

        def racing_read(descriptor, size):
            if descriptor == tracker["victim_fd"] and not tracker["fired"]:
                # Append inside the open/fstat-to-read window, after the
                # budget was debited from the pre-open size.
                tracker["fired"] = True
                with open(victim, "ab") as handle:
                    handle.write(b"#")
            chunk = real_read(descriptor, size)
            tracker["total"] += len(chunk)
            return chunk

        with (
            mock.patch.object(planner, "MAX_TOTAL_MANIFEST_BYTES", cap),
            mock.patch.object(planner.os, "open", new=tracking_open),
            mock.patch.object(planner.os, "read", new=racing_read),
        ):
            plan = planner.plan_release_update(current, candidate)
        self.assertTrue(tracker["fired"])
        # Fails closed and never returns a byte past the configured cap.
        self.assert_unsupported(plan, "validation-race")
        self.assertLessEqual(tracker["total"], cap)

    def test_concurrent_mutation_race_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        victim = current / "apple_vision_enrichment.py"

        def append_to_victim() -> None:
            with open(victim, "ab") as handle:
                handle.write(b"#")

        wrapper, state = self.firing_os_open(
            "apple_vision_enrichment.py", append_to_victim
        )
        with mock.patch.object(planner.os, "open", new=wrapper):
            plan = planner.plan_release_update(current, candidate)
        self.assertTrue(state["fired"])
        self.assert_unsupported(plan, "validation-race")

    def test_same_size_rewrite_with_restored_mtime_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        victim = current / "apple_vision_enrichment.py"
        original_stat = os.lstat(victim)

        def rewrite_in_place() -> None:
            data = victim.read_bytes()
            mutated = bytes([data[0] ^ 0x01]) + data[1:]
            with open(victim, "r+b") as handle:
                handle.write(mutated)
            os.utime(
                victim,
                ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
            )

        wrapper, state = self.firing_os_open(
            "apple_vision_enrichment.py", rewrite_in_place
        )
        with mock.patch.object(planner.os, "open", new=wrapper):
            plan = planner.plan_release_update(current, candidate)
        self.assertTrue(state["fired"])
        # The rewrite is invisible to every field except st_ctime_ns: same
        # inode, same size, mtime restored.
        mutated_stat = os.lstat(victim)
        self.assertEqual(mutated_stat.st_ino, original_stat.st_ino)
        self.assertEqual(mutated_stat.st_size, original_stat.st_size)
        self.assertEqual(mutated_stat.st_mtime_ns, original_stat.st_mtime_ns)
        self.assertNotEqual(mutated_stat.st_ctime_ns, original_stat.st_ctime_ns)
        self.assert_unsupported(plan, "validation-race")

    def test_fifo_swap_is_timeout_safe_and_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        victim = current / "apple_vision_enrichment.py"

        def swap_to_fifo() -> None:
            os.unlink(victim)
            os.mkfifo(victim)

        wrapper, state = self.firing_os_open(
            "apple_vision_enrichment.py", swap_to_fifo
        )
        result: dict[str, dict] = {}

        def run_plan() -> None:
            result["plan"] = planner.plan_release_update(current, candidate)

        # Without O_NONBLOCK a read-only open of a writer-less FIFO blocks
        # forever; run the plan on a daemon thread so a regression fails the
        # test instead of hanging the suite.
        with mock.patch.object(planner.os, "open", new=wrapper):
            worker = threading.Thread(target=run_plan, daemon=True)
            worker.start()
            worker.join(timeout=60)
            self.assertFalse(worker.is_alive(), "planner blocked on FIFO open")
        self.assertTrue(state["fired"])
        self.assert_unsupported(result["plan"], "validation-race")

    def test_root_swap_during_snapshot_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        decoy = self.base / "decoy"
        decoy.mkdir()
        os.chmod(decoy, 0o755)

        def swap_current_root() -> None:
            os.rename(current, self.base / "displaced-current")
            os.rename(decoy, current)

        # uv.lock is the last manifest entry, so the swap lands after the
        # current root's files are captured but before the held-vs-visible
        # recheck.
        wrapper, state = self.firing_os_open("uv.lock", swap_current_root)
        with mock.patch.object(planner.os, "open", new=wrapper):
            plan = planner.plan_release_update(current, candidate)
        self.assertTrue(state["fired"])
        self.assert_unsupported(plan, "validation-race")

    def test_nested_native_directory_swap_is_unsupported(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        decoy = self.base / "decoy-native"
        decoy.mkdir()
        os.chmod(decoy, 0o755)

        def swap_native_directory() -> None:
            os.rename(current / "native", self.base / "displaced-native")
            os.rename(decoy, current / "native")

        # recovery_manager.py follows native/apple_vision_enrich.swift in the
        # manifest, so the held native descriptor is already captured.
        wrapper, state = self.firing_os_open(
            "recovery_manager.py", swap_native_directory
        )
        with mock.patch.object(planner.os, "open", new=wrapper):
            plan = planner.plan_release_update(current, candidate)
        self.assertTrue(state["fired"])
        self.assert_unsupported(plan, "validation-race")

    def test_parent_symlink_swap_race_reproduces_poc(self) -> None:
        # Exact PoC shape from scan occ_03926b4f3c1b27d33032e33d: the original
        # current differs from the candidate, the decoy equals the candidate,
        # and an intermediate parent directory is swapped to a symlink during
        # the plan.  The old absolute-path planner returned no-op; the held
        # ancestor chain must surface a validation race.
        lane = self.base / "lane"
        lane.mkdir()
        os.chmod(lane, 0o755)
        current = lane / "current"
        shutil.copytree(self.template, current)
        divergent = current / "redaction.py"
        divergent.write_bytes(divergent.read_bytes() + b"\n# divergent\n")
        candidate = self.make_root("candidate")
        decoy_lane = self.base / "decoy-lane"
        decoy_lane.mkdir()
        os.chmod(decoy_lane, 0o755)
        shutil.copytree(self.template, decoy_lane / "current")

        def swap_parent_to_symlink() -> None:
            os.rename(lane, self.base / "displaced-lane")
            os.symlink(decoy_lane, lane)

        wrapper, state = self.firing_os_open("uv.lock", swap_parent_to_symlink)
        with mock.patch.object(planner.os, "open", new=wrapper):
            plan = planner.plan_release_update(current, candidate)
        self.assertTrue(state["fired"])
        self.assertNotEqual(plan["classification"], "no-op")
        self.assert_unsupported(plan, "validation-race")

    def test_preexisting_symlink_parent_is_root_unsafe(self) -> None:
        real_lane = self.base / "real-lane"
        real_lane.mkdir()
        os.chmod(real_lane, 0o755)
        shutil.copytree(self.template, real_lane / "current")
        link_lane = self.base / "lane-link"
        os.symlink(real_lane, link_lane)
        candidate = self.make_root("candidate")
        plan = planner.plan_release_update(link_lane / "current", candidate)
        self.assert_unsupported(plan, "root-unsafe")
        plan = planner.plan_release_update(candidate, link_lane / "current")
        self.assert_unsupported(plan, "root-unsafe")

    def test_nonabsolute_roots_are_unsupported(self) -> None:
        candidate = self.make_root("candidate")
        plan = planner.plan_release_update(Path("relative"), candidate)
        self.assert_unsupported(plan, "invalid-arguments")
        plan = planner.plan_release_update(candidate, Path("relative"))
        self.assert_unsupported(plan, "invalid-arguments")

    def test_double_slash_anchor_roots_are_unsupported(self) -> None:
        candidate = self.make_root("candidate")
        double_root = Path("//" + str(candidate).lstrip("/"))
        self.assertTrue(double_root.is_absolute())
        self.assertEqual(double_root.anchor, "//")
        plan = planner.plan_release_update(double_root, candidate)
        self.assert_unsupported(plan, "invalid-arguments")
        plan = planner.plan_release_update(candidate, double_root)
        self.assert_unsupported(plan, "invalid-arguments")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = planner.main(
                [
                    "--current-root",
                    str(double_root),
                    "--candidate-root",
                    str(candidate),
                ]
            )
        self.assertEqual(code, 2)
        self.assert_unsupported(json.loads(stdout.getvalue()), "invalid-arguments")

    def test_dotdot_root_components_are_unsupported(self) -> None:
        candidate = self.make_root("candidate")
        traversal = self.base / "candidate" / ".." / "candidate"
        plan = planner.plan_release_update(traversal, candidate)
        self.assert_unsupported(plan, "invalid-arguments")

    def test_platform_gate_is_deterministic(self) -> None:
        self.assertTrue(planner._PLATFORM_SUPPORTED)
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        with mock.patch.object(planner, "_PLATFORM_SUPPORTED", False):
            plan = planner.plan_release_update(current, candidate)
        self.assert_unsupported(plan, "platform-unsupported")

    def test_cli_requires_absolute_roots(self) -> None:
        candidate = self.make_root("candidate")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = planner.main(
                ["--current-root", "relative", "--candidate-root", str(candidate)]
            )
        self.assertEqual(code, 2)
        plan = json.loads(stdout.getvalue())
        self.assert_unsupported(plan, "invalid-arguments")

    def test_cli_argument_errors_emit_deterministic_json(self) -> None:
        candidate = self.make_root("candidate")
        argv_cases = [
            [],
            ["--current-root", str(candidate)],
            ["--current-root"],
            [
                "--current-root",
                str(candidate),
                "--candidate-root",
                str(candidate),
                "--bogus-flag",
            ],
            ["--unknown"],
        ]
        for argv in argv_cases:
            for _ in range(2):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    code = planner.main(argv)
                self.assertEqual(code, 2)
                self.assertEqual(stderr.getvalue(), "")
                self.assertEqual(stdout.getvalue(), INVALID_ARGUMENTS_LINE)

    def test_cli_help_is_preserved(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            with self.assertRaises(SystemExit) as caught:
                planner.main(["-h"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("usage", stdout.getvalue())
        self.assertIn("--current-root", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_malicious_candidate_top_level_code_never_executes(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        sentinel = self.base / "sentinel-executed"
        source_path = candidate / "core_service.py"
        source_path.write_bytes(
            source_path.read_bytes()
            + (
                "\nimport pathlib\n"
                f"pathlib.Path({str(sentinel)!r}).write_text(\"executed\")\n"
                "raise SystemExit(99)\n"
            ).encode("utf-8")
        )
        plan = planner.plan_release_update(current, candidate)
        self.assertFalse(sentinel.exists())
        self.assert_plan_shape(plan)
        self.assertEqual(plan["classification"], "changed-unclassified")
        self.assertEqual(plan["status"], "blocked-changed-unclassified")
        self.assertEqual(plan["changes"], ["core_service.py"])
        self.assertEqual(planner.plan_exit_code(plan), 3)

    def test_embedded_manifest_matches_trusted_runtime(self) -> None:
        self.assertEqual(planner.TRUSTED_MANIFEST, BUILD_SOURCE_MANIFEST)

    def test_api_import_restores_process_global_import_state(self) -> None:
        sentinel = self.base / "caller-import-path"
        probe = "\n".join(
            (
                "import json, sys",
                f"root = {str(ROOT)!r}",
                f"sentinel = {str(sentinel)!r}",
                "sys.path.insert(0, root)",
                "sys.path.insert(1, sentinel)",
                "expected_path = list(sys.path)",
                "sys.dont_write_bytecode = False",
                "from scripts import release_update_plan as planner",
                "print(json.dumps({",
                "  'path_restored': sys.path == expected_path,",
                "  'bytecode_restored': sys.dont_write_bytecode is False,",
                "  'manifest_size': len(planner.TRUSTED_MANIFEST),",
                "  'classification': planner.plan_release_update(planner.Path(root), planner.Path(root))['classification'],",
                "}, sort_keys=True))",
            )
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-c", probe],
            capture_output=True,
            text=True,
            cwd=str(self.base),
            timeout=300,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        result = json.loads(completed.stdout)
        self.assertIs(result["path_restored"], True)
        self.assertIs(result["bytecode_restored"], True)
        self.assertEqual(result["manifest_size"], len(BUILD_SOURCE_MANIFEST))
        self.assertEqual(result["classification"], "no-op")

    def test_pythonpath_candidate_shadow_never_executes(self) -> None:
        shadow = self.base / "shadow"
        shadow.mkdir()
        sentinel = self.base / "shadow-executed"
        payload = (
            "import pathlib\n"
            f"pathlib.Path({str(sentinel)!r}).write_text(\"executed\")\n"
            "BUILD_SOURCE_MANIFEST = ()\n"
            "class SecretSafeArgumentParser:\n"
            "    pass\n"
        )
        (shadow / "core_service.py").write_text(payload)
        (shadow / "redaction.py").write_text(payload)
        environment = dict(os.environ)
        environment["PYTHONPATH"] = f"{shadow}{os.pathsep}{ROOT}"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "release_update_plan.py"),
                "--help",
            ],
            capture_output=True,
            text=True,
            env=environment,
            cwd=str(self.base),
            timeout=300,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertIn("usage", completed.stdout)
        # The shadow modules on PYTHONPATH must never be imported or executed:
        # the planner sanitizes sys.path before any non-builtin import.
        self.assertFalse(sentinel.exists())

    def make_shadow_modules(self, names: tuple[str, ...]) -> tuple[Path, dict]:
        shadow = self.base / "shadow-modules"
        shadow.mkdir(exist_ok=True)
        sentinels = {}
        for name in names:
            sentinel = self.base / f"shadow-{name}-executed"
            sentinels[name] = sentinel
            (shadow / f"{name}.py").write_text(
                "import pathlib\n"
                f"pathlib.Path({str(sentinel)!r}).write_text(\"executed\")\n"
                "BUILD_SOURCE_MANIFEST = ()\n"
                "class SecretSafeArgumentParser:\n"
                "    pass\n"
            )
        return shadow, sentinels

    def test_pythonpath_stdlib_shadow_never_executes(self) -> None:
        # ast and hashlib are the planner's first attacker-reachable stdlib
        # imports (Python startup itself does not import them); a hostile
        # PYTHONPATH shadowing them must never execute.
        shadow, sentinels = self.make_shadow_modules(
            ("ast", "hashlib", "core_service", "redaction")
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(shadow)
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "release_update_plan.py"),
                "--help",
            ],
            capture_output=True,
            text=True,
            env=environment,
            cwd=str(self.base),
            timeout=300,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertIn("usage", completed.stdout)
        for name, sentinel in sentinels.items():
            self.assertFalse(sentinel.exists(), f"shadow {name} executed")

    def test_isolated_mode_defeats_startup_shadowing(self) -> None:
        # Python startup (site/sitecustomize) runs before the script body and
        # imports modules like os, which the planner cannot protect.  The
        # documented hardened invocation uses -I, which makes the interpreter
        # ignore PYTHONPATH entirely — startup shadows included.
        shadow, sentinels = self.make_shadow_modules(
            ("os", "ast", "core_service", "redaction")
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(shadow)
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(ROOT / "scripts" / "release_update_plan.py"),
                "--help",
            ],
            capture_output=True,
            text=True,
            env=environment,
            cwd=str(self.base),
            timeout=300,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertIn("usage", completed.stdout)
        for name, sentinel in sentinels.items():
            self.assertFalse(sentinel.exists(), f"shadow {name} executed")

    def test_interpreter_path_shadow_never_executes(self) -> None:
        # Model an interpreter-owned site-packages entry entirely under this
        # disposable fixture.  The bootstrap inserts it and temporarily makes
        # its parent the interpreter prefix before running the planner.  This
        # exercises retained-path ordering without writing into the real venv.
        synthetic_prefix = self.base / "synthetic-prefix"
        purelib = synthetic_prefix / "lib" / "python" / "site-packages"
        purelib.mkdir(parents=True)
        sentinels = {}
        for name in ("ast", "argparse", "hashlib"):
            target = purelib / f"{name}.py"
            sentinel = self.base / f"site-shadow-{name}-executed"
            sentinels[name] = sentinel
            target.write_text(
                "import pathlib\n"
                f"pathlib.Path({str(sentinel)!r}).write_text(\"executed\")\n"
                "BUILD_SOURCE_MANIFEST = ()\n"
            )
        planner_path = ROOT / "scripts" / "release_update_plan.py"
        bootstrap = "\n".join(
            (
                "import runpy, sys",
                f"sys.prefix = {str(synthetic_prefix)!r}",
                f"sys.path.insert(0, {str(purelib)!r})",
                f"sys.argv = [{str(planner_path)!r}, '--help']",
                f"runpy.run_path({str(planner_path)!r}, run_name='__main__')",
            )
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                bootstrap,
            ],
            capture_output=True,
            text=True,
            cwd=str(self.base),
            timeout=300,
        )
        # rc 0 with usage proves the verified repo modules loaded: had a
        # shadow been imported instead, the origin check raises ImportError.
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertIn("usage", completed.stdout)
        for name, sentinel in sentinels.items():
            self.assertFalse(
                sentinel.exists(), f"site-packages shadow {name} executed"
            )

    def test_symlink_invocation_parent_never_supplies_project_imports(self) -> None:
        malicious_root = self.base / "malicious-root"
        scripts = malicious_root / "scripts"
        scripts.mkdir(parents=True)
        planner_link = scripts / "release_update_plan.py"
        planner_link.symlink_to(ROOT / "scripts" / "release_update_plan.py")
        sentinels = {}
        for name in ("core_service", "redaction"):
            sentinel = self.base / f"symlink-parent-{name}-executed"
            sentinels[name] = sentinel
            (malicious_root / f"{name}.py").write_text(
                "import pathlib\n"
                f"pathlib.Path({str(sentinel)!r}).write_text(\"executed\")\n"
                "BUILD_SOURCE_MANIFEST = ()\n"
                "class SecretSafeArgumentParser:\n"
                "    pass\n"
            )
        completed = subprocess.run(
            [sys.executable, "-I", str(planner_link), "--help"],
            capture_output=True,
            text=True,
            cwd=str(self.base),
            timeout=300,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertIn("usage", completed.stdout)
        for name, sentinel in sentinels.items():
            self.assertFalse(sentinel.exists(), f"symlink parent {name} executed")

    def test_manifest_complexity_bounded_before_parse(self) -> None:
        trusted = (ROOT / "core_service.py").read_bytes()
        self.assertLessEqual(
            len(trusted), planner.MAX_MANIFEST_SOURCE_BYTES // 4
        )
        trusted_tokens = sum(
            1 for _ in tokenize.tokenize(io.BytesIO(trusted).readline)
        )
        self.assertLessEqual(
            trusted_tokens, planner.MAX_MANIFEST_SOURCE_TOKENS // 4
        )
        dense = b"a=1;" * (planner.MAX_MANIFEST_SOURCE_TOKENS // 4 + 64) + b"\n"
        oversize = b"#" + b"x" * planner.MAX_MANIFEST_SOURCE_BYTES
        real_parse = planner.ast.parse

        def guarded_parse(source, *args, **kwargs):
            text = (
                source.decode("utf-8", "replace")
                if isinstance(source, (bytes, bytearray))
                else source
            )
            if text.startswith(("a=1;", "#x")):
                raise AssertionError("ast.parse reached for complexity payload")
            return real_parse(source, *args, **kwargs)

        current = self.make_root("current")
        for index, payload in enumerate((dense, oversize)):
            candidate = self.make_root(f"candidate-{index}")
            (candidate / "core_service.py").write_bytes(payload)
            with mock.patch.object(planner.ast, "parse", new=guarded_parse):
                plan = planner.plan_release_update(current, candidate)
            self.assert_unsupported(plan, "manifest-complexity")

    def test_descriptors_closed_after_success_and_failure(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        bad_candidate = self.make_root("bad-candidate")
        (bad_candidate / "mlx_backend.py").unlink()
        real_open, real_close = os.open, os.close
        opened: set = set()

        def tracking_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.add(fd)
            return fd

        def tracking_close(fd):
            real_close(fd)
            opened.discard(fd)

        with mock.patch.object(os, "open", new=tracking_open), mock.patch.object(
            os, "close", new=tracking_close
        ):
            for _ in range(3):
                plan = planner.plan_release_update(current, candidate)
                self.assertEqual(plan["classification"], "no-op")
                self.assertEqual(opened, set(), "descriptor leaked on success")
            for _ in range(3):
                plan = planner.plan_release_update(current, bad_candidate)
                self.assert_unsupported(plan, "file-missing")
                self.assertEqual(opened, set(), "descriptor leaked on failure")

    def test_cli_output_is_deterministic_single_line_and_redacted(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        victim = candidate / "redaction.py"
        victim.write_bytes(victim.read_bytes() + b"\n# harmless comment\n")
        argv = [
            "--current-root",
            str(current),
            "--candidate-root",
            str(candidate),
        ]
        outputs = []
        codes = []
        for _ in range(2):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                codes.append(planner.main(argv))
            outputs.append(stdout.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(codes, [3, 3])
        line = outputs[0]
        self.assertTrue(line.endswith("\n"))
        self.assertEqual(line.count("\n"), 1)
        body = line[:-1]
        self.assertNotIn(str(self.base), body)
        self.assertNotIn(str(ROOT), body)
        self.assertNotIn("Traceback", body)
        plan = json.loads(body)
        self.assert_plan_shape(plan)
        self.assertEqual(
            body, json.dumps(plan, sort_keys=True, separators=(",", ":"))
        )

    def test_cli_subprocess_run_writes_no_bytecode_or_files(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        baseline_scratch = self.base / "pycache-baseline"
        baseline_scratch.mkdir()
        planner_scratch = self.base / "pycache-planner"
        planner_scratch.mkdir()

        def entries(root: Path) -> list[tuple[str, int, int]]:
            listed = []
            for path in sorted(root.rglob("*")):
                observed = os.lstat(path)
                listed.append(
                    (str(path), observed.st_size, observed.st_mtime_ns)
                )
            return listed

        def cached(prefix: Path) -> set[Path]:
            return {
                path.relative_to(prefix)
                for path in prefix.rglob("*")
                if path.is_file()
            }

        before_current = entries(current)
        before_candidate = entries(candidate)
        environment = dict(os.environ)
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        # Differential baseline: everything a bare interpreter caches during
        # startup, with an identical environment.
        environment["PYTHONPYCACHEPREFIX"] = str(baseline_scratch)
        baseline = subprocess.run(
            [sys.executable, "-c", "pass"],
            capture_output=True,
            text=True,
            env=environment,
            cwd=str(self.base),
            timeout=300,
        )
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        environment["PYTHONPYCACHEPREFIX"] = str(planner_scratch)
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "release_update_plan.py"),
                "--current-root",
                str(current),
                "--candidate-root",
                str(candidate),
            ],
            capture_output=True,
            text=True,
            env=environment,
            cwd=str(self.base),
            timeout=300,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(completed.stdout.count("\n"), 1)
        plan = json.loads(completed.stdout)
        self.assertEqual(plan["classification"], "no-op")
        self.assertEqual(entries(current), before_current)
        self.assertEqual(entries(candidate), before_candidate)
        # Every import the planner performs happens after
        # sys.dont_write_bytecode is set, so the planner run must cache
        # nothing beyond the interpreter's own startup baseline: zero
        # planner-caused bytecode.
        planner_caused = cached(planner_scratch) - cached(baseline_scratch)
        self.assertEqual(planner_caused, set())
        # PYTHONPYCACHEPREFIX mirrors absolute paths, so any bytecode written
        # for repository modules would land under the ROOT mirror; the .venv
        # subtree is interpreter machinery, not repo modules.
        mirror = planner_scratch / Path(*ROOT.parts[1:])
        offending = (
            [
                str(path)
                for path in mirror.rglob("*")
                if path.is_file() and ".venv" not in path.parts
            ]
            if mirror.exists()
            else []
        )
        self.assertEqual(offending, [])

    def test_dont_write_bytecode_set_before_local_imports(self) -> None:
        source = (ROOT / "scripts" / "release_update_plan.py").read_text()
        tree = ast.parse(source)
        sys_import_index = None
        flag_index = None
        first_other_import_index = None
        for index, node in enumerate(tree.body):
            is_sys_import = isinstance(node, ast.Import) and [
                alias.name for alias in node.names
            ] == ["sys"]
            if is_sys_import:
                if sys_import_index is None:
                    sys_import_index = index
                continue
            if (
                first_other_import_index is None
                and isinstance(node, (ast.Import, ast.ImportFrom))
            ):
                first_other_import_index = index
            if (
                flag_index is None
                and isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Attribute)
                and node.targets[0].attr == "dont_write_bytecode"
                and isinstance(node.targets[0].value, ast.Name)
                and node.targets[0].value.id == "sys"
                and isinstance(node.value, ast.Constant)
                and node.value.value is True
            ):
                flag_index = index
        self.assertIsNotNone(sys_import_index)
        self.assertIsNotNone(flag_index)
        self.assertIsNotNone(first_other_import_index)
        # Only ``import sys`` may precede the flag; every other import —
        # __future__, stdlib, and project — must follow it.
        self.assertLess(sys_import_index, flag_index)
        self.assertLess(flag_index, first_other_import_index)
        self.assertFalse(
            any(
                isinstance(node, ast.ImportFrom)
                and node.module == "__future__"
                for node in ast.walk(tree)
            )
        )

    def test_tripwires_no_mutation_spawn_network_or_sqlite(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        real_os_open = os.open

        def read_only_os_open(path, flags, *args, **kwargs):
            forbidden = (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            )
            if flags & forbidden:
                raise AssertionError("planner attempted a writable os.open")
            return real_os_open(path, flags, *args, **kwargs)

        tripwire = AssertionError("forbidden side channel invoked")
        mutation_targets = [
            (os, "rename"),
            (os, "replace"),
            (os, "unlink"),
            (os, "remove"),
            (os, "rmdir"),
            (os, "removedirs"),
            (os, "mkdir"),
            (os, "makedirs"),
            (os, "chmod"),
            (os, "chown"),
            (os, "link"),
            (os, "symlink"),
            (os, "utime"),
            (os, "truncate"),
        ]
        spawn_targets = [
            (os, "system"),
            (os, "posix_spawn"),
            (os, "posix_spawnp"),
            (subprocess, "Popen"),
            (subprocess, "run"),
        ]
        network_targets = [
            (socket, "socket"),
            (socket, "create_connection"),
            (sqlite3, "connect"),
        ]
        with contextlib.ExitStack() as stack:
            for target, attribute in (
                mutation_targets + spawn_targets + network_targets
            ):
                stack.enter_context(
                    mock.patch.object(target, attribute, side_effect=tripwire)
                )
            stack.enter_context(mock.patch("builtins.open", side_effect=tripwire))
            stack.enter_context(
                mock.patch.object(io, "open", side_effect=tripwire)
            )
            # Direct pathlib mutation/write entry points; the planner only
            # uses Path for path arithmetic, never pathlib I/O.
            for attribute in (
                "write_text",
                "write_bytes",
                "touch",
                "mkdir",
                "rmdir",
                "unlink",
                "rename",
                "replace",
                "symlink_to",
                "hardlink_to",
                "chmod",
                "open",
            ):
                stack.enter_context(
                    mock.patch.object(
                        pathlib.Path, attribute, side_effect=tripwire
                    )
                )
            stack.enter_context(
                mock.patch.object(planner.os, "open", new=read_only_os_open)
            )
            plan = planner.plan_release_update(current, candidate)
        self.assert_plan_shape(plan)
        self.assertEqual(plan["classification"], "no-op")

    def test_planner_source_imports_are_allowlisted(self) -> None:
        source = (ROOT / "scripts" / "release_update_plan.py").read_text()
        modules = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        allowed = {
            "argparse",
            "ast",
            "errno",
            "hashlib",
            "io",
            "json",
            "tokenize",
            "os",
            "re",
            "stat",
            "sys",
            "pathlib",
        }
        self.assertLessEqual(modules, allowed)
        self.assertNotIn("__future__", modules)
        forbidden = {
            "subprocess",
            "socket",
            "sqlite3",
            "http",
            "urllib",
            "shutil",
            "ctypes",
            "importlib",
        }
        self.assertFalse(modules & forbidden)


class AnalyzerCodecIsolationTests(unittest.TestCase):
    def test_encoding_cookies_and_bom_fail_without_codec_lookup(self) -> None:
        manifest = (
            "BUILD_SOURCE_MANIFEST = " + repr(planner.TRUSTED_MANIFEST) + "\n"
        ).encode("utf-8")
        contract = b"SELECTED = 1\n"
        codec_lookups = []

        def codec_hook(name):
            codec_lookups.append(name)
            return None

        prefixes = (
            b"# coding: s2_planner_attacker_codec\n",
            b"#!/usr/bin/env python\n# coding=s2_planner_attacker_codec\n",
            b"\xef\xbb\xbf# coding: s2_planner_attacker_codec\n",
            b"\xef\xbb\xbf",
        )
        codecs.register(codec_hook)
        try:
            for prefix in prefixes:
                self.assertEqual(
                    planner._extract_manifest(prefix + manifest),
                    ("missing", None),
                )
                self.assertIsNone(
                    planner._analyze_contract_source(
                        prefix + contract, frozenset(("SELECTED",))
                    )
                )
        finally:
            codecs.unregister(codec_hook)
        self.assertEqual(codec_lookups, [])

    def test_string_tokenizer_preserves_encoding_inclusive_limits(self) -> None:
        manifest = (
            "BUILD_SOURCE_MANIFEST = " + repr(planner.TRUSTED_MANIFEST) + "\n"
        ).encode("utf-8")
        manifest_tokens = sum(
            1 for _ in tokenize.tokenize(io.BytesIO(manifest).readline)
        )
        with mock.patch.object(
            planner, "MAX_MANIFEST_SOURCE_TOKENS", manifest_tokens - 1
        ):
            self.assertEqual(
                planner._extract_manifest(manifest), ("complexity", None)
            )
        with mock.patch.object(
            planner, "MAX_MANIFEST_SOURCE_TOKENS", manifest_tokens
        ):
            self.assertEqual(
                planner._extract_manifest(manifest),
                ("ok", planner.TRUSTED_MANIFEST),
            )

        contract = b"SELECTED = 1\n"
        contract_tokens = sum(
            1 for _ in tokenize.tokenize(io.BytesIO(contract).readline)
        )
        names = frozenset(("SELECTED",))
        with mock.patch.object(
            planner, "MAX_CONTRACT_SOURCE_TOKENS", contract_tokens - 1
        ):
            self.assertIsNone(planner._analyze_contract_source(contract, names))
        with mock.patch.object(
            planner, "MAX_CONTRACT_SOURCE_TOKENS", contract_tokens
        ):
            self.assertIn(
                "SELECTED", planner._analyze_contract_source(contract, names)
            )


GATE_KEYS = {
    "schema",
    "mode",
    "status",
    "relation",
    "apply_supported",
    "apply_performed",
    "provenance_verified",
    "current",
    "candidate",
    "required_surfaces",
    "changed_surfaces",
    "missing_surfaces",
    "unknown_surfaces",
    "requirements",
}

EXPECTED_SURFACE_IDS = [
    "authority-runtime-identity.v1",
    "capture-protocol.v1",
    "durable-store-schema.v1",
    "readiness-quiescence.v1",
    "recovery.v1",
    "replication-protocol.v1",
    "request-journal.v1",
]

CONTRACT_SOURCE_FILES = {
    "capture_daemon.py",
    "core_authority.py",
    "core_request_journal.py",
    "core_service.py",
    "memory_store.py",
    "operator_readiness_contract.py",
    "recovery_manager.py",
    "replication_protocol.py",
    "scripts/core_agent_installer.py",
}

CONTRACT_DIGEST_PATTERN = r"\Acontract-[0-9a-f]{64}\Z"

GATE_INVALID_ARGUMENTS_LINE = (
    planner.render_plan(
        planner._build_gate_result(
            "unsupported:invalid-arguments",
            None,
            None,
            [],
            [],
            planner._required_surface_ids(),
        )
    )
    + "\n"
)


class ReleasePreservationGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.class_temporary = tempfile.TemporaryDirectory(
            prefix="s2rpg-", dir="/tmp"
        )
        cls.class_base = Path(cls.class_temporary.name).resolve()
        cls.template = cls.class_base / "template"
        # The gate's contract sources are the manifest plus the installer
        # script, which is deliberately outside the build manifest.
        for name in tuple(BUILD_SOURCE_MANIFEST) + (
            "scripts/core_agent_installer.py",
        ):
            destination = cls.template / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / name).read_bytes())
        for directory, _, files in os.walk(cls.template):
            os.chmod(directory, 0o755)
            for filename in files:
                os.chmod(Path(directory) / filename, 0o644)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.class_temporary.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="s2rpg-", dir="/tmp")
        self.base = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)

    def make_root(self, name: str) -> Path:
        destination = self.base / name
        shutil.copytree(self.template, destination)
        return destination

    def firing_os_open(self, trigger_leaf: str, action):
        real_open = os.open
        state = {"fired": False}

        def wrapper(path, flags, *args, **kwargs):
            if not state["fired"] and str(path) == trigger_leaf:
                state["fired"] = True
                action()
            return real_open(path, flags, *args, **kwargs)

        return wrapper, state

    def rewrite(self, root: Path, filename: str, old: str, new: str) -> None:
        path = root / filename
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1))

    def append_bytes(self, root: Path, filename: str, suffix: bytes) -> None:
        path = root / filename
        path.write_bytes(path.read_bytes() + suffix)

    def assert_gate_shape(self, result: dict) -> None:
        self.assertEqual(set(result), GATE_KEYS)
        self.assertEqual(
            result["schema"], "synapse-s2.release-preservation-gate.v1"
        )
        self.assertEqual(result["mode"], "read-only-preservation-gate")
        self.assertEqual(result["relation"], "selected-node-ast-equality.v1")
        self.assertIs(result["apply_supported"], False)
        self.assertIs(result["apply_performed"], False)
        self.assertIs(result["provenance_verified"], False)
        self.assertEqual(set(result["current"]), {"contract_digest"})
        self.assertEqual(set(result["candidate"]), {"contract_digest"})
        self.assertEqual(result["required_surfaces"], EXPECTED_SURFACE_IDS)
        for key in ("changed_surfaces", "missing_surfaces", "unknown_surfaces"):
            self.assertIsInstance(result[key], list)
        self.assertIsInstance(result["requirements"], list)

    def assert_proven_equal(self, result: dict) -> None:
        self.assert_gate_shape(result)
        self.assertEqual(result["status"], "proven-equal")
        self.assertEqual(result["changed_surfaces"], [])
        self.assertEqual(result["missing_surfaces"], [])
        self.assertEqual(result["unknown_surfaces"], [])
        self.assertRegex(
            result["current"]["contract_digest"], CONTRACT_DIGEST_PATTERN
        )
        self.assertEqual(
            result["current"]["contract_digest"],
            result["candidate"]["contract_digest"],
        )
        self.assertEqual(planner.preservation_exit_code(result), 0)

    def assert_gate_unsupported(self, result: dict, token: str) -> None:
        self.assert_gate_shape(result)
        self.assertEqual(result["status"], f"unsupported:{token}")
        self.assertEqual(planner.preservation_exit_code(result), 2)

    def test_surface_spec_is_stable_and_valid(self) -> None:
        planner._validate_semantic_surfaces()
        self.assertEqual(
            sorted(entry[0] for entry in planner.SEMANTIC_SURFACES),
            EXPECTED_SURFACE_IDS,
        )
        self.assertEqual(
            set(planner._surface_file_items()), CONTRACT_SOURCE_FILES
        )
        selected = {
            (filename, name)
            for _, items in planner.SEMANTIC_SURFACES
            for filename, name in items
        }
        for required_item in (
            ("memory_store.py", "SQLITE_APPLICATION_ID"),
            ("memory_store.py", "SQLITE_USER_VERSION"),
            ("memory_store.py", "BACKUP_SCHEMA_COMPATIBILITY_REGISTRY"),
            ("memory_store.py", "SCHEMA_SQL"),
            ("memory_store.py", "BACKUP_CRITICAL_TABLES"),
            ("memory_store.py", "DurableMemoryStore._run_migrations"),
            ("core_request_journal.py", "JOURNAL_SCHEMA_IDENTITY"),
            ("core_request_journal.py", "_REQUEST_JOURNAL_TABLE_SQL"),
            ("core_request_journal.py", "_assert_exact_current_schema"),
            ("core_authority.py", "CORE_AUTHORITY_SCHEMA_VERSION"),
            ("memory_store.py", "CORE_AUTHORITY_MARKER_FIELDS"),
            ("recovery_manager.py", "RECOVERY_BUNDLE_SCHEMA"),
            ("recovery_manager.py", "LEGACY_RECOVERY_BUNDLE_SCHEMA"),
            ("recovery_manager.py", "REQUEST_JOURNAL_RESTORE_BINDING_SCHEMA"),
            ("replication_protocol.py", "REPLICATION_PROTOCOL_VERSION"),
            ("replication_protocol.py", "NODE_DESCRIPTOR_FIELDS"),
            ("replication_protocol.py", "ALLOWED_ARTIFACT_KINDS"),
            (
                "operator_readiness_contract.py",
                "OPERATOR_READINESS_REQUIRED_PROOF_IDS",
            ),
            ("operator_readiness_contract.py", "QUIESCENCE_LAUNCH_AGENT_RULES"),
            ("operator_readiness_contract.py", "REPLAY_DEBT_COUNTERS"),
            ("core_service.py", "CORE_STORE_SCHEMA_IDENTITY"),
            ("core_service.py", "STORE_GENERATION_SCHEMA"),
            ("core_service.py", "STORE_GENERATION_ID_RE"),
            ("scripts/core_agent_installer.py", "EXPECTED_SCHEMA_IDENTITY"),
            ("recovery_manager.py", "CAPTURE_TRANSPORT_DIR_KEYS"),
            ("memory_store.py", "CAPTURE_PROTOCOL_VERSION"),
            ("memory_store.py", "CAPTURE_OPERATION_RESULT_KEYS"),
            ("capture_daemon.py", "CAPTURE_SUFFIXES"),
            ("capture_daemon.py", "CAPTURE_REPLACEMENT_FREEZE_MAX_SECONDS"),
            ("capture_daemon.py", "CAPTURE_DEFERRED_DIR_NAME"),
        ):
            self.assertIn(required_item, selected)

    def test_real_root_self_gate_is_proven_equal(self) -> None:
        result = planner.run_preservation_gate(ROOT, ROOT)
        self.assert_proven_equal(result)

    def test_copied_roots_gate_is_proven_equal(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        result = planner.run_preservation_gate(current, candidate)
        self.assert_proven_equal(result)
        self.assertEqual(
            result["requirements"], ["operator-review", "source-delta-review"]
        )

    def test_non_contract_change_passes_gate_but_source_plan_blocks(
        self,
    ) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        self.append_bytes(
            candidate,
            "memory_store.py",
            b'\n_PRESERVATION_TUNING_HINT = "non-contract"\n',
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assert_proven_equal(result)
        plan = planner.plan_release_update(current, candidate)
        self.assertEqual(plan["classification"], "changed-unclassified")
        self.assertEqual(plan["status"], "blocked-changed-unclassified")
        self.assertEqual(plan["changes"], ["memory_store.py"])
        self.assertEqual(planner.plan_exit_code(plan), 3)

    def test_gate_never_executes_candidate_top_level_code(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        sentinel = self.base / "gate-sentinel-executed"
        self.append_bytes(
            candidate,
            "operator_readiness_contract.py",
            (
                "\nimport pathlib as _gate_probe\n"
                f"_gate_probe.Path({str(sentinel)!r}).write_text(\"executed\")\n"
            ).encode("utf-8"),
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assertFalse(sentinel.exists())
        # The malicious statements are outside every selected node, so the
        # accepted relation deliberately still holds; the v1 source plan is
        # what blocks the byte delta (for manifest files) plus provenance
        # remains unclaimed either way.
        self.assert_proven_equal(result)

    def test_selected_constant_change_blocks(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        self.rewrite(
            candidate,
            "memory_store.py",
            "SQLITE_USER_VERSION = 6",
            "SQLITE_USER_VERSION = 7",
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assert_gate_shape(result)
        self.assertEqual(result["status"], "blocked-contract-change")
        self.assertEqual(result["changed_surfaces"], ["durable-store-schema.v1"])
        self.assertEqual(result["missing_surfaces"], [])
        self.assertEqual(result["unknown_surfaces"], [])
        self.assertRegex(
            result["current"]["contract_digest"], CONTRACT_DIGEST_PATTERN
        )
        self.assertRegex(
            result["candidate"]["contract_digest"], CONTRACT_DIGEST_PATTERN
        )
        self.assertNotEqual(
            result["current"]["contract_digest"],
            result["candidate"]["contract_digest"],
        )
        self.assertIn("contract-review", result["requirements"])
        self.assertEqual(planner.preservation_exit_code(result), 3)

    def test_selected_function_change_blocks(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        self.rewrite(
            candidate,
            "operator_readiness_contract.py",
            "ensure_ascii=True",
            "ensure_ascii=False",
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assertEqual(result["status"], "blocked-contract-change")
        self.assertEqual(
            result["changed_surfaces"], ["readiness-quiescence.v1"]
        )
        self.assertEqual(planner.preservation_exit_code(result), 3)

    def test_journal_ddl_change_blocks(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        # First occurrence of this fragment is inside the selected
        # _REQUEST_JOURNAL_TABLE_SQL literal.
        self.rewrite(
            candidate,
            "core_request_journal.py",
            "length(caller) BETWEEN 1 AND 128",
            "length(caller) BETWEEN 1 AND 256",
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assertEqual(result["status"], "blocked-contract-change")
        self.assertEqual(result["changed_surfaces"], ["request-journal.v1"])
        self.assertEqual(planner.preservation_exit_code(result), 3)

    def test_migration_method_change_blocks(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        # Unique statement inside DurableMemoryStore._run_migrations.
        self.rewrite(
            candidate,
            "memory_store.py",
            "core_migration_required = bool(",
            "core_migration_required = not bool(",
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assertEqual(result["status"], "blocked-contract-change")
        self.assertEqual(result["changed_surfaces"], ["durable-store-schema.v1"])
        self.assertEqual(planner.preservation_exit_code(result), 3)

    def test_store_generation_schema_change_blocks(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        self.rewrite(
            candidate,
            "core_service.py",
            '"synapse-s2.root-generation.v1"',
            '"synapse-s2.root-generation.v2"',
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assertEqual(result["status"], "blocked-contract-change")
        self.assertEqual(
            result["changed_surfaces"], ["authority-runtime-identity.v1"]
        )
        self.assertEqual(planner.preservation_exit_code(result), 3)

    def test_installer_schema_identity_change_blocks(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        self.rewrite(
            candidate,
            "scripts/core_agent_installer.py",
            '"sqlite-53324442-v6"',
            '"sqlite-53324442-v7"',
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assertEqual(result["status"], "blocked-contract-change")
        self.assertEqual(result["changed_surfaces"], ["durable-store-schema.v1"])
        self.assertEqual(planner.preservation_exit_code(result), 3)

    def test_capture_transport_dir_keys_change_blocks(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        self.rewrite(
            candidate,
            "recovery_manager.py",
            'CAPTURE_TRANSPORT_DIR_KEYS = (\n    "inbox_dir",',
            'CAPTURE_TRANSPORT_DIR_KEYS = (\n    "inbox_dir_v2",',
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assertEqual(result["status"], "blocked-contract-change")
        self.assertEqual(result["changed_surfaces"], ["recovery.v1"])
        self.assertEqual(planner.preservation_exit_code(result), 3)

    def test_capture_operation_result_limit_change_blocks(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        self.rewrite(
            candidate,
            "memory_store.py",
            "CAPTURE_OPERATION_RESULT_JSON_MAX_BYTES = 2048",
            "CAPTURE_OPERATION_RESULT_JSON_MAX_BYTES = 4096",
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assertEqual(result["status"], "blocked-contract-change")
        self.assertEqual(result["changed_surfaces"], ["capture-protocol.v1"])
        self.assertEqual(planner.preservation_exit_code(result), 3)

    def test_capture_daemon_freeze_window_change_blocks(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        self.rewrite(
            candidate,
            "capture_daemon.py",
            "CAPTURE_REPLACEMENT_FREEZE_MAX_SECONDS = 7_200.0",
            "CAPTURE_REPLACEMENT_FREEZE_MAX_SECONDS = 9_600.0",
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assertEqual(result["status"], "blocked-contract-change")
        self.assertEqual(result["changed_surfaces"], ["capture-protocol.v1"])
        self.assertEqual(planner.preservation_exit_code(result), 3)

    def test_missing_selected_names_fail_closed(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        (candidate / "operator_readiness_contract.py").write_bytes(
            b"VALUE = 1\n"
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assert_gate_unsupported(result, "contract-missing")
        self.assertEqual(result["missing_surfaces"], ["readiness-quiescence.v1"])
        self.assertEqual(result["changed_surfaces"], [])
        self.assertEqual(result["unknown_surfaces"], [])
        self.assertRegex(
            result["current"]["contract_digest"], CONTRACT_DIGEST_PATTERN
        )
        self.assertIsNone(result["candidate"]["contract_digest"])

    def test_absent_contract_source_file_fails_closed(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        (candidate / "operator_readiness_contract.py").unlink()
        result = planner.run_preservation_gate(current, candidate)
        self.assert_gate_unsupported(result, "contract-missing")
        self.assertEqual(result["missing_surfaces"], ["readiness-quiescence.v1"])
        self.assertIsNone(result["candidate"]["contract_digest"])

    def test_duplicate_selected_binding_fails_closed(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        self.append_bytes(
            candidate,
            "operator_readiness_contract.py",
            b'\ndef quiescence_policy_digest():\n    return ""\n',
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assert_gate_unsupported(result, "contract-unverifiable")
        self.assertEqual(result["unknown_surfaces"], ["readiness-quiescence.v1"])
        self.assertIsNone(result["candidate"]["contract_digest"])

    def test_unparsable_contract_source_fails_closed(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        (candidate / "operator_readiness_contract.py").write_bytes(
            b"def broken(:\n    pass\n"
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assert_gate_unsupported(result, "contract-unverifiable")
        self.assertEqual(result["unknown_surfaces"], ["readiness-quiescence.v1"])
        self.assertIsNone(result["candidate"]["contract_digest"])

    def test_rebound_selected_binding_fails_closed(self) -> None:
        current = self.make_root("current")
        suffixes = (
            b"\nQUIESCENCE_POLICY_VERSION = QUIESCENCE_POLICY_VERSION\n",
            b"\ndel REPLAY_DEBT_COUNTERS\n",
            b"\nREPLAY_DEBT_COUNTERS += ()\n",
            b"\ndef _shadow():\n    QUIESCENCE_POLICY_SCHEMA = None\n",
            b"\nclass REPLAY_DEBT_COUNTERS:\n    pass\n",
            b"\nfrom attacker import *\n",
        )
        for index, suffix in enumerate(suffixes):
            candidate = self.make_root(f"candidate-rebind-{index}")
            self.append_bytes(
                candidate, "operator_readiness_contract.py", suffix
            )
            result = planner.run_preservation_gate(current, candidate)
            self.assert_gate_unsupported(result, "contract-unverifiable")
            self.assertEqual(
                result["unknown_surfaces"], ["readiness-quiescence.v1"]
            )

    def test_dynamic_namespace_mutation_fails_closed(self) -> None:
        current = self.make_root("current")
        cases = (
            (
                "operator_readiness_contract.py",
                b'\nglobals()["REPLAY_DEBT_COUNTERS"] = ()\n',
            ),
            (
                "operator_readiness_contract.py",
                b'\nvars()["QUIESCENCE_POLICY_VERSION"] = 2\n',
            ),
            (
                "operator_readiness_contract.py",
                b'\nsetattr(object(), "unrelated", 1)\n',
            ),
            (
                "operator_readiness_contract.py",
                b'\nlocals()["REPLAY_DEBT_COUNTERS"] = ()\n',
            ),
            (
                "operator_readiness_contract.py",
                b"\nclass _Probe:\n    _namespace = locals()\n",
            ),
            (
                "operator_readiness_contract.py",
                b'\n_d = {}\n_d["REPLAY_DEBT_COUNTERS"] = ()\n',
            ),
            (
                "operator_readiness_contract.py",
                b"\nimport sys as _sys\n_ns = _sys.modules[__name__].__dict__\n",
            ),
            (
                "memory_store.py",
                b"\nDurableMemoryStore._run_migrations = None\n",
            ),
        )
        for index, (filename, suffix) in enumerate(cases):
            candidate = self.make_root(f"candidate-dynamic-{index}")
            self.append_bytes(candidate, filename, suffix)
            result = planner.run_preservation_gate(current, candidate)
            self.assert_gate_unsupported(result, "contract-unverifiable")
            if filename == "operator_readiness_contract.py":
                self.assertEqual(
                    result["unknown_surfaces"], ["readiness-quiescence.v1"]
                )
            else:
                self.assertIn(
                    "durable-store-schema.v1", result["unknown_surfaces"]
                )
            self.assertIsNone(result["candidate"]["contract_digest"])

    def test_imported_alias_dynamic_builtin_poc_fails_closed(self) -> None:
        current = self.make_root("current")
        # The exact evasion this remediation closes: a builtins re-import
        # binds ``globals`` under a fresh name, and a non-constant subscript
        # key (the BinOp form) defeats the watched-name Store screen.  The
        # constant-key variant stays here as a defense-in-depth regression.
        payloads = (
            b"\nfrom builtins import globals as _ns\n"
            b'_ns()["QUIESCENCE_POLICY_" + "VERSION"] = 999\n',
            b"\nfrom builtins import globals as _ns\n"
            b'_ns()["QUIESCENCE_POLICY_VERSION"] = 999\n',
        )
        for index, payload in enumerate(payloads):
            candidate = self.make_root(f"candidate-poc-{index}")
            self.append_bytes(
                candidate, "operator_readiness_contract.py", payload
            )
            result = planner.run_preservation_gate(current, candidate)
            self.assert_gate_unsupported(result, "contract-unverifiable")
            self.assertEqual(
                result["unknown_surfaces"], ["readiness-quiescence.v1"]
            )
            self.assertIsNone(result["candidate"]["contract_digest"])

    def test_dynamic_builtin_import_denylist_matrix_unverifiable(self) -> None:
        base = "SELECTED = 1\n"
        names = frozenset({"SELECTED"})
        denied = (
            "exec",
            "eval",
            "globals",
            "vars",
            "setattr",
            "delattr",
            "__import__",
            "locals",
        )
        payloads = []
        for name in denied:
            payloads.append(f"from builtins import {name}\n")
            payloads.append(f"from builtins import {name} as _borrowed\n")
            payloads.append(f"from json import {name}\n")
            payloads.append(f"from json import dumps as {name}\n")
            payloads.append(f"import json as {name}\n")
            payloads.append(f"_probe = _module.{name}\n")
        payloads.extend(
            (
                "import builtins\n",
                "import builtins as _b\n",
                "import importlib\n",
                "import importlib.util\n",
                "from importlib import import_module\n",
                "from json import dumps as builtins\n",
                "import json as builtins\n",
                "_b = __builtins__\n",
                "_alias = _module.__dict__\n",
                "_view = _module.__dict__.keys()\n",
            )
        )
        for payload in payloads:
            source = (base + payload).encode("utf-8")
            self.assertIsNone(
                planner._analyze_contract_source(source, names), payload
            )
        # Negative controls: function-body ``locals()`` and read-only
        # ``__dict__.items()`` iteration stay verifiable.
        legit = (
            base
            + "def _probe(obj):\n"
            + "    _snapshot = locals()\n"
            + "    return sorted(obj.__dict__.items()) + sorted(_snapshot)\n"
        ).encode("utf-8")
        analysis = planner._analyze_contract_source(legit, names)
        self.assertIsNotNone(analysis)
        self.assertEqual(set(analysis), {"SELECTED"})

    def test_function_body_locals_and_dict_items_stay_proven_equal(
        self,
    ) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        self.append_bytes(
            candidate,
            "operator_readiness_contract.py",
            b"\ndef _legit_probe(obj):\n"
            b"    _snapshot = locals()\n"
            b"    return sorted(obj.__dict__.items()) + sorted(_snapshot)\n",
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assert_proven_equal(result)

    def test_unverifiable_takes_precedence_over_missing(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        (candidate / "operator_readiness_contract.py").write_bytes(
            b"VALUE = 1\n"
        )
        self.append_bytes(
            candidate, "core_authority.py", b'\nglobals()["x"] = 1\n'
        )
        result = planner.run_preservation_gate(current, candidate)
        self.assert_gate_unsupported(result, "contract-unverifiable")
        self.assertEqual(
            result["unknown_surfaces"], ["authority-runtime-identity.v1"]
        )
        self.assertEqual(result["missing_surfaces"], ["readiness-quiescence.v1"])

    def test_contract_complexity_bounded_before_parse(self) -> None:
        # Headroom: the largest trusted contract source stays well inside a
        # quarter of both analysis ceilings.
        trusted = (ROOT / "memory_store.py").read_bytes()
        self.assertLessEqual(
            len(trusted), planner.MAX_CONTRACT_SOURCE_BYTES // 4
        )
        trusted_tokens = sum(
            1 for _ in tokenize.tokenize(io.BytesIO(trusted).readline)
        )
        self.assertLessEqual(
            trusted_tokens, planner.MAX_CONTRACT_SOURCE_TOKENS // 4
        )
        dense = b"a=1;" * (planner.MAX_CONTRACT_SOURCE_TOKENS // 4 + 64) + b"\n"
        oversize = b"#" + b"x" * planner.MAX_CONTRACT_SOURCE_BYTES
        real_parse = planner.ast.parse

        def guarded_parse(source, *args, **kwargs):
            text = (
                source.decode("utf-8", "replace")
                if isinstance(source, (bytes, bytearray))
                else source
            )
            if text.startswith(("a=1;", "#x")):
                raise AssertionError("ast.parse reached for complexity payload")
            return real_parse(source, *args, **kwargs)

        current = self.make_root("current")
        for index, payload in enumerate((dense, oversize)):
            candidate = self.make_root(f"candidate-{index}")
            (candidate / "operator_readiness_contract.py").write_bytes(payload)
            with mock.patch.object(planner.ast, "parse", new=guarded_parse):
                result = planner.run_preservation_gate(current, candidate)
            self.assert_gate_unsupported(result, "contract-unverifiable")
            self.assertEqual(
                result["unknown_surfaces"], ["readiness-quiescence.v1"]
            )

    def test_contract_read_race_fails_closed(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        victim = current / "core_authority.py"

        def append_to_victim() -> None:
            with open(victim, "ab") as handle:
                handle.write(b"#")

        wrapper, state = self.firing_os_open(
            "core_authority.py", append_to_victim
        )
        with mock.patch.object(planner.os, "open", new=wrapper):
            result = planner.run_preservation_gate(current, candidate)
        self.assertTrue(state["fired"])
        self.assert_gate_unsupported(result, "validation-race")
        self.assertEqual(result["unknown_surfaces"], EXPECTED_SURFACE_IDS)
        self.assertIsNone(result["current"]["contract_digest"])
        self.assertIsNone(result["candidate"]["contract_digest"])

    def test_symlink_hardlink_and_fifo_contract_sources_fail_closed(
        self,
    ) -> None:
        current = self.make_root("current")
        symlinked = self.make_root("candidate-symlink")
        victim = symlinked / "operator_readiness_contract.py"
        victim.unlink()
        victim.symlink_to(symlinked / "replication_protocol.py")
        result = planner.run_preservation_gate(current, symlinked)
        self.assert_gate_unsupported(result, "file-unsafe")
        self.assertEqual(result["unknown_surfaces"], EXPECTED_SURFACE_IDS)

        hardlinked = self.make_root("candidate-hardlink")
        os.link(
            hardlinked / "operator_readiness_contract.py",
            self.base / "outside-hardlink",
        )
        result = planner.run_preservation_gate(current, hardlinked)
        self.assert_gate_unsupported(result, "file-unsafe")

        fifo_root = self.make_root("candidate-fifo")
        fifo_victim = fifo_root / "operator_readiness_contract.py"
        fifo_victim.unlink()
        os.mkfifo(fifo_victim)
        result_holder: dict[str, dict] = {}

        def run_gate() -> None:
            result_holder["result"] = planner.run_preservation_gate(
                current, fifo_root
            )

        worker = threading.Thread(target=run_gate, daemon=True)
        worker.start()
        worker.join(timeout=60)
        self.assertFalse(worker.is_alive(), "gate blocked on FIFO")
        self.assert_gate_unsupported(result_holder["result"], "file-unsafe")

    def test_gate_descriptors_closed_after_success_and_failure(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        missing_candidate = self.make_root("missing-candidate")
        (missing_candidate / "operator_readiness_contract.py").unlink()
        unsafe_candidate = self.make_root("unsafe-candidate")
        unsafe_victim = unsafe_candidate / "core_authority.py"
        unsafe_victim.unlink()
        unsafe_victim.symlink_to(unsafe_candidate / "memory_store.py")
        real_open, real_close = os.open, os.close
        opened: set = set()

        def tracking_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.add(fd)
            return fd

        def tracking_close(fd):
            real_close(fd)
            opened.discard(fd)

        with mock.patch.object(os, "open", new=tracking_open), mock.patch.object(
            os, "close", new=tracking_close
        ):
            result = planner.run_preservation_gate(current, candidate)
            self.assertEqual(result["status"], "proven-equal")
            self.assertEqual(opened, set(), "descriptor leaked on success")
            result = planner.run_preservation_gate(current, missing_candidate)
            self.assert_gate_unsupported(result, "contract-missing")
            self.assertEqual(opened, set(), "descriptor leaked on missing")
            result = planner.run_preservation_gate(current, unsafe_candidate)
            self.assert_gate_unsupported(result, "file-unsafe")
            self.assertEqual(opened, set(), "descriptor leaked on abort")

    def test_gate_tripwires_no_mutation_spawn_network_or_sqlite(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        real_os_open = os.open

        def read_only_os_open(path, flags, *args, **kwargs):
            forbidden = (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            )
            if flags & forbidden:
                raise AssertionError("gate attempted a writable os.open")
            return real_os_open(path, flags, *args, **kwargs)

        tripwire = AssertionError("forbidden side channel invoked")
        targets = [
            (os, "rename"),
            (os, "replace"),
            (os, "unlink"),
            (os, "remove"),
            (os, "rmdir"),
            (os, "mkdir"),
            (os, "chmod"),
            (os, "link"),
            (os, "symlink"),
            (os, "utime"),
            (os, "truncate"),
            (os, "system"),
            (os, "posix_spawn"),
            (os, "posix_spawnp"),
            (subprocess, "Popen"),
            (subprocess, "run"),
            (socket, "socket"),
            (socket, "create_connection"),
            (sqlite3, "connect"),
        ]
        with contextlib.ExitStack() as stack:
            for target, attribute in targets:
                stack.enter_context(
                    mock.patch.object(target, attribute, side_effect=tripwire)
                )
            stack.enter_context(mock.patch("builtins.open", side_effect=tripwire))
            stack.enter_context(
                mock.patch.object(io, "open", side_effect=tripwire)
            )
            for attribute in (
                "write_text",
                "write_bytes",
                "touch",
                "mkdir",
                "rmdir",
                "unlink",
                "rename",
                "replace",
                "symlink_to",
                "hardlink_to",
                "chmod",
                "open",
            ):
                stack.enter_context(
                    mock.patch.object(
                        pathlib.Path, attribute, side_effect=tripwire
                    )
                )
            stack.enter_context(
                mock.patch.object(planner.os, "open", new=read_only_os_open)
            )
            result = planner.run_preservation_gate(current, candidate)
        self.assert_proven_equal(result)

    def test_gate_cli_output_is_deterministic_single_line_and_redacted(
        self,
    ) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        self.rewrite(
            candidate,
            "memory_store.py",
            "SQLITE_USER_VERSION = 6",
            "SQLITE_USER_VERSION = 7",
        )
        argv = [
            "--preservation-gate",
            "--current-root",
            str(current),
            "--candidate-root",
            str(candidate),
        ]
        outputs = []
        codes = []
        for _ in range(2):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                codes.append(planner.main(argv))
            outputs.append(stdout.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(codes, [3, 3])
        line = outputs[0]
        self.assertTrue(line.endswith("\n"))
        self.assertEqual(line.count("\n"), 1)
        body = line[:-1]
        self.assertNotIn(str(self.base), body)
        self.assertNotIn(str(ROOT), body)
        self.assertNotIn("Traceback", body)
        result = json.loads(body)
        self.assert_gate_shape(result)
        self.assertEqual(result["status"], "blocked-contract-change")
        self.assertEqual(
            body, json.dumps(result, sort_keys=True, separators=(",", ":"))
        )

    def test_gate_cli_rejects_expected_build_id_combination(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = planner.main(
                [
                    "--preservation-gate",
                    "--current-root",
                    str(current),
                    "--candidate-root",
                    str(candidate),
                    "--expected-candidate-build-id",
                    "source-" + "0" * 24,
                ]
            )
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), GATE_INVALID_ARGUMENTS_LINE)

    def test_gate_cli_argument_errors_emit_gate_shaped_json(self) -> None:
        current = self.make_root("current")
        argv_cases = [
            ["--preservation-gate"],
            ["--preservation-gate", "--current-root", str(current)],
            ["--preservation-gate", "--unknown"],
        ]
        for argv in argv_cases:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                code = planner.main(argv)
            self.assertEqual(code, 2)
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(stdout.getvalue(), GATE_INVALID_ARGUMENTS_LINE)

    def test_gate_cli_subprocess_isolated_mode_proven_equal(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(ROOT / "scripts" / "release_update_plan.py"),
                "--preservation-gate",
                "--current-root",
                str(ROOT),
                "--candidate-root",
                str(ROOT),
            ],
            capture_output=True,
            text=True,
            cwd=str(self.base),
            timeout=300,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(completed.stdout.count("\n"), 1)
        result = json.loads(completed.stdout)
        self.assert_proven_equal(result)


PRODUCT_KEYS = {
    "schema",
    "mode",
    "status",
    "apply_supported",
    "apply_performed",
    "provenance_verified",
    "signature_verified",
    "inventory_policy_id",
    "current",
    "candidate",
    "components",
    "changed_paths",
    "changed_path_count",
    "changed_paths_truncated",
    "changed_components",
    "requirements",
    "nonclaims",
}

PRODUCT_INVALID_ARGUMENTS_LINE = (
    planner.render_plan(
        planner._build_product_result(
            "unsupported:invalid-arguments", None, None, [], []
        )
    )
    + "\n"
)

GOVERNED_UNSUPPORTED_LINE = (
    planner.render_governed_plan(
        planner._build_governed_result(
            planner.GOVERNED_STATUS_UNSUPPORTED, None, None
        )
    )
    + "\n"
)

# Local git trees for the required historical regression, pinned by full
# commit SHA.  The tracked path sets at these two commits are identical and
# exactly three inventoried paths differ: both dashboard web assets and one
# dashboard test.  The whole-product inventory binds the tests component
# too, so the honest changed set has three entries, not two.
HISTORY_OLD_COMMIT = "1eb49708591cf7c357ef5b3146e0eb8dee95a30a"
HISTORY_NEW_COMMIT = "f739c89be2561f8d6fc900add786e41707dc18bb"
HISTORY_CHANGED_PATHS = [
    "tests/test_dashboard_server.py",
    "web/app.js",
    "web/index.html",
]
# The identical release-foundation overlay applied to both historical
# templates: the closed 199-entry inventory binds these files, so both
# trees carry the same current copies and the factual delta between the
# templates stays exactly HISTORY_CHANGED_PATHS.  Product identities can
# no longer be pinned as hex constants here: this very file is part of
# the overlay, so any pinned digest would feed its own input.
HISTORY_FOUNDATION_OVERLAY = (
    "pyproject.toml",
    "scripts/installed_layout.py",
    "scripts/release_compatibility.py",
    "scripts/release_provenance.py",
    "scripts/release_stage.py",
    "scripts/release_update_plan.py",
    "scripts/sign_release_provenance.py",
    "tests/test_installed_layout.py",
    "tests/test_release_compatibility.py",
    "tests/test_release_provenance.py",
    "tests/test_release_stage.py",
    "tests/test_release_update_plan.py",
    "uv.lock",
)

# Inventory paths introduced on top of the tracked HISTORY_NEW_COMMIT tree.
FOUNDATION_NEW_PATHS = (
    "scripts/installed_layout.py",
    "scripts/release_compatibility.py",
    "scripts/release_provenance.py",
    "scripts/release_stage.py",
    "scripts/sign_release_provenance.py",
    "tests/test_installed_layout.py",
    "tests/test_release_compatibility.py",
    "tests/test_release_provenance.py",
    "tests/test_release_stage.py",
)

PRODUCT_ID_PATTERN = r"\Aproduct-[0-9a-f]{64}\Z"
COMPONENT_ID_PATTERN = r"\Acomponent-[0-9a-f]{64}\Z"
INVENTORY_POLICY_ID_PATTERN = r"\Ainventory-policy-[0-9a-f]{64}\Z"


class ProductReleasePlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.class_temporary = tempfile.TemporaryDirectory(
            prefix="s2prp-", dir="/tmp"
        )
        # macOS exposes /var and /tmp as symlinks; the planner requires
        # physical paths, so fixtures use the resolved base.  Templates are
        # exact extractions of the two pinned commits (tar.umask=0022 keeps
        # the extracted 0644/0755 modes independent of the process umask);
        # tests must never mutate them.
        cls.class_base = Path(cls.class_temporary.name).resolve()
        cls.template = cls.class_base / "template-new"
        cls.template_old = cls.class_base / "template-old"
        for commit, destination in (
            (HISTORY_NEW_COMMIT, cls.template),
            (HISTORY_OLD_COMMIT, cls.template_old),
        ):
            destination.mkdir()
            archive = subprocess.run(
                [
                    "git",
                    "-C",
                    str(ROOT),
                    "-c",
                    "tar.umask=0022",
                    "archive",
                    commit,
                ],
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ["tar", "-xpf", "-", "-C", str(destination)],
                input=archive.stdout,
                check=True,
            )
        # Identical release-foundation overlay into both trees: byte-for-byte
        # copies of the current files with a fixed 0644 mode, so neither
        # template can differ from the other on any overlaid path.
        for relative in HISTORY_FOUNDATION_OVERLAY:
            source = ROOT / relative
            for destination in (cls.template, cls.template_old):
                target = destination / relative
                shutil.copyfile(source, target)
                os.chmod(target, 0o644)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.class_temporary.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="s2prp-", dir="/tmp")
        self.base = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)

    def make_root(self, name: str) -> Path:
        destination = self.base / name
        shutil.copytree(self.template, destination)
        return destination

    def firing_os_open(self, trigger_leaf: str, action, occurrence: int = 1):
        """Wrap os.open so ``action`` runs exactly once, immediately before
        the ``occurrence``-th dir_fd-relative open of ``trigger_leaf``."""
        real_open = os.open
        state = {"fired": False, "seen": 0}

        def wrapper(path, flags, *args, **kwargs):
            if not state["fired"] and str(path) == trigger_leaf:
                state["seen"] += 1
                if state["seen"] == occurrence:
                    state["fired"] = True
                    action()
            return real_open(path, flags, *args, **kwargs)

        return wrapper, state

    def recording_os_open(self):
        real_open = os.open
        opened_names: list[str] = []

        def recording(path, flags, *args, **kwargs):
            opened_names.append(str(path))
            return real_open(path, flags, *args, **kwargs)

        return recording, opened_names

    def assert_product_shape(self, result: dict) -> None:
        self.assertEqual(set(result), PRODUCT_KEYS)
        self.assertEqual(
            result["schema"], "synapse-s2.product-release-plan.v1"
        )
        self.assertEqual(result["mode"], "read-only-product-inventory")
        self.assertIs(result["apply_supported"], False)
        self.assertIs(result["apply_performed"], False)
        self.assertIs(result["provenance_verified"], False)
        self.assertIs(result["signature_verified"], False)
        # Every result -- unsupported refusals included -- names the exact
        # inventory policy its identities were computed under; only an
        # invalid embedded inventory yields no policy identifier at all.
        if result["status"] == "unsupported:product-inventory-invalid":
            self.assertIsNone(result["inventory_policy_id"])
        else:
            self.assertRegex(
                result["inventory_policy_id"], INVENTORY_POLICY_ID_PATTERN
            )
        self.assertEqual(
            set(result["current"]), {"component_ids", "product_id"}
        )
        self.assertEqual(
            set(result["candidate"]), {"component_ids", "product_id"}
        )
        self.assertEqual(result["components"], planner._product_components())
        self.assertIsInstance(result["changed_paths"], list)
        self.assertIsInstance(result["changed_path_count"], int)
        self.assertIsInstance(result["changed_paths_truncated"], bool)
        self.assertIsInstance(result["changed_components"], list)
        self.assertIsInstance(result["requirements"], list)
        self.assertEqual(
            result["nonclaims"], list(planner.PRODUCT_NONCLAIMS)
        )
        self.assertIn("stable-inventory-only", result["nonclaims"])
        self.assertIn("no-inventory-policy-transition", result["nonclaims"])

    def assert_product_unsupported(self, result: dict, token: str) -> None:
        self.assert_product_shape(result)
        self.assertEqual(result["status"], f"unsupported:{token}")
        self.assertEqual(result["changed_paths"], [])
        self.assertEqual(result["changed_path_count"], 0)
        self.assertIs(result["changed_paths_truncated"], False)
        self.assertEqual(result["changed_components"], [])
        self.assertEqual(result["requirements"], ["operator-review"])
        self.assertEqual(planner.product_exit_code(result), 2)

    def assert_no_update(self, result: dict) -> None:
        self.assert_product_shape(result)
        self.assertEqual(result["status"], "no-update")
        self.assertEqual(result["changed_paths"], [])
        self.assertEqual(result["changed_path_count"], 0)
        self.assertIs(result["changed_paths_truncated"], False)
        self.assertEqual(result["changed_components"], [])
        self.assertEqual(result["requirements"], [])
        self.assertEqual(planner.product_exit_code(result), 0)

    def test_product_inventory_binds_every_tracked_path_exactly(self) -> None:
        planner._validate_product_inventory()
        inventory_paths = sorted(
            path for _, _, path in planner.PRODUCT_INVENTORY
        )
        self.assertEqual(len(inventory_paths), 199)
        tracked = sorted(
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(ROOT),
                    "ls-tree",
                    "-r",
                    "--name-only",
                    HISTORY_NEW_COMMIT,
                ],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.splitlines()
        )
        # Exact parity with the tracked tree at the release base plus the
        # nine release-foundation additions: no path is derived at runtime,
        # nothing tracked is uninventoried, and nothing inventoried is
        # neither tracked nor a declared addition.
        self.assertEqual(len(tracked), 190)
        for path in FOUNDATION_NEW_PATHS:
            self.assertNotIn(path, tracked)
            self.assertTrue((ROOT / path).is_file(), path)
            self.assertEqual(
                stat.S_IMODE((ROOT / path).stat().st_mode), 0o644, path
            )
        self.assertEqual(
            inventory_paths, sorted(tracked + list(FOUNDATION_NEW_PATHS))
        )
        # Every trusted-manifest source file must also be product-inventoried.
        for name in planner.TRUSTED_MANIFEST:
            self.assertIn(name, inventory_paths)

    def test_product_inventory_disk_mode_census_is_closed(self) -> None:
        # The working tree the closed 199-entry inventory binds carries an
        # equally closed permission census: exactly 187 regular 0644 files
        # and exactly 12 executable 0755 operator entry points.  Any new
        # executable (or a lost executable bit) must be reviewed here.
        census: dict[int, int] = {}
        executables = []
        for _, _, path in planner.PRODUCT_INVENTORY:
            observed = (ROOT / path).lstat()
            self.assertTrue(stat.S_ISREG(observed.st_mode), path)
            mode = stat.S_IMODE(observed.st_mode)
            census[mode] = census.get(mode, 0) + 1
            if mode == 0o755:
                executables.append(path)
        self.assertEqual(census, {0o644: 187, 0o755: 12})
        self.assertEqual(
            sorted(executables),
            [
                "scripts/capture_frontmost_selection.sh",
                "scripts/core_agent_installer.py",
                "scripts/core_cutover_preflight.py",
                "scripts/core_cutover_preflight.sh",
                "scripts/install_capture_daemon.sh",
                "scripts/install_client_configs.py",
                "scripts/install_core_agent.sh",
                "scripts/install_dashboard_agent.sh",
                "scripts/install_local_launcher.sh",
                "scripts/open_dashboard.py",
                "scripts/prep_tomorrow.sh",
                "scripts/purge_namespaces.py",
            ],
        )

    def test_inventory_policy_id_binds_the_closed_policy(self) -> None:
        # Independent recomputation from the documented construction: the
        # domain-separated SHA-256 of the canonical JSON policy document.
        payload = json.dumps(
            {
                "schema": "synapse-s2.product-inventory-policy.v1",
                "product_schema": "synapse-s2.product-release-plan.v1",
                "record_fields": [
                    "component",
                    "role",
                    "path",
                    "mode",
                    "size",
                    "sha256",
                ],
                "candidate_layout": "closed-exact-v1",
                "entries": [
                    list(entry)
                    for entry in sorted(planner.PRODUCT_INVENTORY)
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        expected = "inventory-policy-" + hashlib.sha256(
            b"SYNAPSE-S2\x00PRODUCT-INVENTORY-POLICY\x00v1\x00"
            + payload.encode("ascii")
        ).hexdigest()
        self.assertRegex(expected, INVENTORY_POLICY_ID_PATTERN)
        self.assertEqual(planner._inventory_policy_id(), expected)
        # A verified result and an unsupported refusal both carry the exact
        # policy identifier while the embedded inventory is valid.
        verified = planner.plan_product_release(self.template, self.template)
        self.assert_no_update(verified)
        self.assertEqual(verified["inventory_policy_id"], expected)
        refused = planner.plan_product_release(
            self.template, self.template, "totally-bogus"
        )
        self.assert_product_unsupported(refused, "invalid-arguments")
        self.assertEqual(refused["inventory_policy_id"], expected)
        # An invalid embedded inventory yields no policy identifier at all.
        with mock.patch.object(planner, "PRODUCT_INVENTORY", ()):
            broken = planner.plan_product_release(
                self.template, self.template
            )
        self.assertEqual(set(broken), PRODUCT_KEYS)
        self.assertEqual(
            broken["status"], "unsupported:product-inventory-invalid"
        )
        self.assertIsNone(broken["inventory_policy_id"])

    def test_product_vocabulary_is_fixed_and_fully_used(self) -> None:
        self.assertEqual(
            planner.PRODUCT_COMPONENTS,
            frozenset(
                (
                    "cli",
                    "config-template",
                    "core",
                    "dashboard",
                    "dependencies",
                    "mcp",
                    "native",
                    "official-longmem",
                    "operator-docs",
                    "operator-manual",
                    "operator-scripts",
                    "repo-config",
                    "support-tools",
                    "tests",
                )
            ),
        )
        self.assertEqual(
            planner.PRODUCT_ROLES,
            frozenset(
                (
                    "agent-doc",
                    "code",
                    "config-template",
                    "dependency-lock",
                    "doc",
                    "eval-adapter",
                    "evidence",
                    "fixture",
                    "manual-asset",
                    "native-source",
                    "operator-script",
                    "packaging",
                    "policy-doc",
                    "support-tool",
                    "test",
                    "vcs-config",
                    "web-asset",
                )
            ),
        )
        used_components = {c for c, _, _ in planner.PRODUCT_INVENTORY}
        used_roles = {r for _, r, _ in planner.PRODUCT_INVENTORY}
        self.assertEqual(used_components, planner.PRODUCT_COMPONENTS)
        self.assertEqual(used_roles, planner.PRODUCT_ROLES)
        self.assertEqual(
            planner._product_components(),
            sorted(planner.PRODUCT_COMPONENTS),
        )
        for binding in (
            ("dashboard", "web-asset", "web/app.js"),
            ("core", "code", "core_service.py"),
            ("cli", "code", "synapse_cli.py"),
            ("mcp", "code", "mcp_server.py"),
            ("native", "native-source", "native/apple_vision_enrich.swift"),
            ("official-longmem", "eval-adapter", "official_longmem/bootstrap.py"),
            (
                "tests",
                "fixture",
                "tests/fixtures/longmem_v2/benchmark_v1.json",
            ),
            ("tests", "test", "tests/test_dashboard_server.py"),
            ("repo-config", "agent-doc", "AGENTS.md"),
            ("operator-docs", "policy-doc", "README.md"),
            ("operator-docs", "evidence",
             "docs/evidence/phase9-replication-acceptance.json"),
            ("operator-manual", "manual-asset",
             "output/pdf/SYNAPSE-S2_Visual_User_Manual.pdf"),
            ("operator-scripts", "operator-script",
             "scripts/installed_layout.py"),
            ("operator-scripts", "operator-script",
             "scripts/release_compatibility.py"),
            ("operator-scripts", "operator-script",
             "scripts/release_stage.py"),
            ("operator-scripts", "operator-script",
             "scripts/release_update_plan.py"),
            ("tests", "test", "tests/test_installed_layout.py"),
            ("tests", "test", "tests/test_release_compatibility.py"),
            ("tests", "test", "tests/test_release_stage.py"),
            ("support-tools", "support-tool", "scripts/measure_retrieval_v2.py"),
            ("dependencies", "dependency-lock", "uv.lock"),
            ("config-template", "config-template", ".mcp.json.example"),
        ):
            self.assertIn(binding, planner.PRODUCT_INVENTORY)

    def test_product_inventory_validation_fails_closed(self) -> None:
        bad_appended = [
            # Duplicate path.
            (("core", "code", "README.md"),),
            # Component outside the fixed vocabulary.
            (("bogus", "code", "zz_extra.py"),),
            # Role outside the fixed vocabulary.
            (("core", "bogus", "zz_extra.py"),),
            # Paths under exempted or VCS names can never be inventoried.
            (("core", "code", ".venv/zz_extra.py"),),
            (("core", "code", ".git/config"),),
            # Neither can exempted host artifacts or cache directories.
            (("core", "code", ".mcp.json"),),
            (("core", "code", ".mcp.json.bak-20260719-211716"),),
            (("tests", "test", "tests/__pycache__/zz_extra.py"),),
            (("tests", "test", "tests/.pytest_cache/zz_extra.py"),),
            # Traversal and empty components.
            (("core", "code", "docs/../zz_extra.py"),),
            (("core", "code", "docs//zz_extra.py"),),
        ]
        for extra in bad_appended:
            with self.subTest(extra=extra):
                with mock.patch.object(
                    planner,
                    "PRODUCT_INVENTORY",
                    planner.PRODUCT_INVENTORY + extra,
                ):
                    with self.assertRaises(planner._Unsupported) as caught:
                        planner._validate_product_inventory()
                    self.assertEqual(
                        caught.exception.token, "product-inventory-invalid"
                    )
        # Dropping a component breaks the fixed-vocabulary closure.
        pruned = tuple(
            entry for entry in planner.PRODUCT_INVENTORY
            if entry[0] != "tests"
        )
        with mock.patch.object(planner, "PRODUCT_INVENTORY", pruned):
            with self.assertRaises(planner._Unsupported) as caught:
                planner._validate_product_inventory()
            self.assertEqual(
                caught.exception.token, "product-inventory-invalid"
            )
        # Inventory count bound, exercised at the exact edge.
        with mock.patch.object(planner, "MAX_PRODUCT_INVENTORY_ENTRIES", 199):
            planner._validate_product_inventory()
        with mock.patch.object(planner, "MAX_PRODUCT_INVENTORY_ENTRIES", 198):
            result = planner.plan_product_release(
                self.template, self.template
            )
        self.assert_product_unsupported(result, "product-inventory-invalid")

    def test_identical_trees_no_update_with_full_sha256_ids(self) -> None:
        result = planner.plan_product_release(self.template, self.template)
        self.assert_no_update(result)
        product_id = result["current"]["product_id"]
        self.assertRegex(product_id, PRODUCT_ID_PATTERN)
        self.assertEqual(result["candidate"]["product_id"], product_id)
        self.assertEqual(
            sorted(result["current"]["component_ids"]),
            result["components"],
        )
        for component_id in result["current"]["component_ids"].values():
            self.assertRegex(component_id, COMPONENT_ID_PATTERN)
        self.assertEqual(
            result["current"]["component_ids"],
            result["candidate"]["component_ids"],
        )
        again = planner.plan_product_release(self.template, self.template)
        self.assertEqual(
            planner.render_plan(again), planner.render_plan(result)
        )
        # A faithful copy is identity-equal to its source tree.
        copied = self.make_root("copied")
        self.assert_no_update(
            planner.plan_product_release(copied, self.template)
        )
        # Identity digests are domain-separated: identical records can never
        # produce interchangeable product and component identifiers.
        records = [("core", "code", "a.py", "0644", 1, "00" * 32)]
        self.assertNotEqual(
            planner._product_digest(planner._PRODUCT_ID_DOMAIN, records),
            planner._product_digest(
                planner._PRODUCT_COMPONENT_ID_DOMAIN, records
            ),
        )

    def test_changed_web_asset_is_update_available_never_apply(self) -> None:
        candidate = self.make_root("candidate")
        victim = candidate / "web" / "app.js"
        victim.write_bytes(victim.read_bytes() + b"\n// injected\n")
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_shape(result)
        self.assertEqual(result["status"], "update-available")
        self.assertEqual(result["changed_paths"], ["web/app.js"])
        self.assertEqual(result["changed_path_count"], 1)
        self.assertIs(result["changed_paths_truncated"], False)
        self.assertEqual(result["changed_components"], ["dashboard"])
        self.assertNotEqual(
            result["current"]["product_id"],
            result["candidate"]["product_id"],
        )
        self.assertNotEqual(
            result["current"]["component_ids"]["dashboard"],
            result["candidate"]["component_ids"]["dashboard"],
        )
        self.assertEqual(
            result["current"]["component_ids"]["core"],
            result["candidate"]["component_ids"]["core"],
        )
        self.assertEqual(
            result["requirements"],
            list(planner.PRODUCT_REVIEW_REQUIREMENTS),
        )
        self.assertIs(result["apply_supported"], False)
        self.assertIs(result["apply_performed"], False)
        self.assertIs(result["provenance_verified"], False)
        self.assertIs(result["signature_verified"], False)
        self.assertEqual(planner.product_exit_code(result), 3)

    def test_permission_mode_changes_are_update_available(self) -> None:
        # 0644 -> 0600: content-identical, but the bound stat.S_IMODE moved.
        candidate = self.make_root("candidate-0600")
        os.chmod(candidate / "README.md", 0o600)
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_shape(result)
        self.assertEqual(result["status"], "update-available")
        self.assertEqual(result["changed_paths"], ["README.md"])
        self.assertEqual(result["changed_components"], ["operator-docs"])
        self.assertEqual(planner.product_exit_code(result), 3)

        # 0644 -> 0754: a quietly added group-execute bit is a change too.
        candidate = self.make_root("candidate-0754")
        os.chmod(candidate / "synapse_cli.py", 0o754)
        result = planner.plan_product_release(self.template, candidate)
        self.assertEqual(result["status"], "update-available")
        self.assertEqual(result["changed_paths"], ["synapse_cli.py"])
        self.assertEqual(result["changed_components"], ["cli"])

        # 0644 -> 0755 on a web asset.
        candidate = self.make_root("candidate-0755")
        os.chmod(candidate / "web" / "styles.css", 0o755)
        result = planner.plan_product_release(self.template, candidate)
        self.assertEqual(result["status"], "update-available")
        self.assertEqual(result["changed_paths"], ["web/styles.css"])
        self.assertEqual(result["changed_components"], ["dashboard"])

    def test_official_adapter_and_fixture_are_fully_bound(self) -> None:
        adapter = "official_longmem/bootstrap.py"
        fixture = "tests/fixtures/longmem_v2/benchmark_v1.json"

        candidate = self.make_root("candidate-adapter-change")
        target = candidate / adapter
        target.write_bytes(target.read_bytes() + b"\n# tampered\n")
        result = planner.plan_product_release(self.template, candidate)
        self.assertEqual(result["status"], "update-available")
        self.assertEqual(result["changed_paths"], [adapter])
        self.assertEqual(result["changed_components"], ["official-longmem"])

        candidate = self.make_root("candidate-fixture-change")
        target = candidate / fixture
        target.write_bytes(target.read_bytes() + b"\n")
        result = planner.plan_product_release(self.template, candidate)
        self.assertEqual(result["status"], "update-available")
        self.assertEqual(result["changed_paths"], [fixture])
        self.assertEqual(result["changed_components"], ["tests"])

        for name in (adapter, fixture, "official_longmem/synapse_s2_memory.py"):
            with self.subTest(removed=name):
                candidate = self.make_root(
                    f"candidate-missing-{name.replace('/', '-')}"
                )
                (candidate / name).unlink()
                result = planner.plan_product_release(self.template, candidate)
                self.assert_product_unsupported(result, "file-missing")

        candidate = self.make_root("candidate-adapter-symlink")
        target = candidate / adapter
        target.unlink()
        target.symlink_to(candidate / "official_longmem" / "__init__.py")
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "file-unsafe")

        candidate = self.make_root("candidate-adapter-extra")
        (candidate / "official_longmem" / "evil.py").write_bytes(
            b"import os\n"
        )
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "unexpected-entry")

    def test_missing_product_files_are_unsupported(self) -> None:
        for name in ("synapse_cli.py", "docs/BRIDGE_GOVERNANCE.md"):
            with self.subTest(name=name):
                candidate = self.make_root(
                    f"candidate-{name.replace('/', '-')}"
                )
                (candidate / name).unlink()
                result = planner.plan_product_release(self.template, candidate)
                self.assert_product_unsupported(result, "file-missing")

    def test_root_package_and_pth_droppers_are_rejected(self) -> None:
        candidate = self.make_root("candidate")

        # Stdlib-shadowing package at the root: classic import hijack.
        package = candidate / "argparse"
        package.mkdir()
        (package / "__init__.py").write_bytes(b"raise SystemExit(99)\n")
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "unexpected-entry")
        shutil.rmtree(package)

        dropper = candidate / "unexpected.pth"
        dropper.write_bytes(b"import os\n")
        os.chmod(dropper, 0o644)
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "unexpected-entry")
        dropper.unlink()

        (candidate / "sitecustomize.py").write_bytes(b"raise SystemExit(99)\n")
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "unexpected-entry")

    def test_candidate_bytecode_caches_are_rejected(self) -> None:
        candidate = self.make_root("candidate")

        # PoC: a __pycache__ .pyc shadowing a shipped module must never be
        # deliverable through a "clean" product plan.
        cache = candidate / "scripts" / "__pycache__"
        cache.mkdir()
        (cache / "release_update_plan.cpython-314.pyc").write_bytes(b"\x00")
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "unexpected-entry")
        shutil.rmtree(cache)

        cache = candidate / "__pycache__"
        cache.mkdir()
        (cache / "core_service.cpython-314.pyc").write_bytes(b"\x00")
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "unexpected-entry")
        shutil.rmtree(cache)

        (candidate / "core_service.pyc").write_bytes(b"\x00")
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "unexpected-entry")

    def test_every_unknown_entry_is_rejected_any_suffix_any_dir(self) -> None:
        cases = [
            "web/readme.txt",
            "NOTES.md",
            "docs/extra_guide.pdf",
            "docs/superpowers/plans/zz-extra-plan.md",
            "output/manual/plates/manual-99.png",
            "tests/test_zz_extra.py",
            "state.db",
        ]
        for name in cases:
            with self.subTest(name=name, root="candidate"):
                candidate = self.make_root(
                    f"candidate-{name.replace('/', '-')}"
                )
                extra = candidate / name
                extra.write_bytes(b"extra\n")
                os.chmod(extra, 0o644)
                result = planner.plan_product_release(self.template, candidate)
                self.assert_product_unsupported(result, "unexpected-entry")
        for name in ("web/vendor", "scripts/vendor", "docs/archive"):
            with self.subTest(name=name, kind="directory"):
                candidate = self.make_root(
                    f"candidate-dir-{name.replace('/', '-')}"
                )
                (candidate / name).mkdir()
                result = planner.plan_product_release(self.template, candidate)
                self.assert_product_unsupported(result, "unexpected-entry")
        # The current root gets no nested exemptions either.
        current = self.make_root("current-web-extra")
        (current / "web" / "readme.txt").write_bytes(b"extra\n")
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "unexpected-entry")

    def test_current_root_local_state_dirs_are_ignored_never_read(
        self,
    ) -> None:
        current = self.make_root("current")
        state = current / ".synapse_s2"
        state.mkdir()
        (state / "synapse.db").write_bytes(b"SQLite format 3\x00")
        (state / "synapse.db-wal").write_bytes(b"wal")
        for name in (".venv", ".claude", "__pycache__", ".pytest_cache"):
            nested = current / name
            nested.mkdir()
            (nested / "payload.py").write_bytes(b"import os\n")
        recording, opened_names = self.recording_os_open()
        with mock.patch.object(planner.os, "open", new=recording):
            result = planner.plan_product_release(current, self.template)
        self.assert_no_update(result)
        never_opened = {
            ".synapse_s2",
            "synapse.db",
            "synapse.db-wal",
            ".venv",
            ".claude",
            "__pycache__",
            ".pytest_cache",
            "payload.py",
        }
        self.assertFalse(never_opened & set(opened_names), opened_names)

    def test_candidate_gets_no_state_dir_exemption(self) -> None:
        for name in (".venv", ".synapse_s2", ".claude", "__pycache__"):
            with self.subTest(name=name):
                candidate = self.make_root(f"candidate-{name}")
                (candidate / name).mkdir()
                result = planner.plan_product_release(self.template, candidate)
                self.assert_product_unsupported(result, "unexpected-entry")

    def test_state_dir_exemption_is_root_local_dirs_only(self) -> None:
        # Nested occurrences of root-state basenames are never exempt; only
        # the separate exact cache-directory names may appear nested.
        current = self.make_root("current-nested-venv")
        (current / "tests" / ".venv").mkdir()
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "unexpected-entry")

        current = self.make_root("current-nested-claude")
        state = current / "tests" / ".claude"
        state.mkdir()
        (state / "junk.json").write_bytes(b"{}")
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "unexpected-entry")

        # The exemption requires a real directory after no-follow screening.
        current = self.make_root("current-venv-file")
        (current / ".venv").write_bytes(b"not a dir\n")
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "unexpected-entry")

        current = self.make_root("current-venv-symlink")
        (current / ".venv").symlink_to(current / "docs")
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "special-file")

    def test_current_root_host_artifacts_are_ignored_never_read(self) -> None:
        current = self.make_root("current")
        host_files = [
            ".mcp.json",
            "..mcp.json.synapse-config.lock",
            ".DS_Store",
            ".mcp.json.bak-20260719-211716",
            ".mcp.json.bak-20260720-035745-5227afc8d913",
        ]
        for name in host_files:
            target = current / name
            target.write_bytes(b"host artifact\n")
            os.chmod(target, 0o600)
        for cache in (
            current / "official_longmem" / "__pycache__",
            current / "scripts" / "__pycache__",
            current / "tests" / "__pycache__",
            current / ".pytest_cache",
        ):
            cache.mkdir()
            (cache / "cache-payload.pyc").write_bytes(b"\x00")
        recording, opened_names = self.recording_os_open()
        with mock.patch.object(planner.os, "open", new=recording):
            result = planner.plan_product_release(current, self.template)
        self.assert_no_update(result)
        never_opened = set(host_files) | {
            "__pycache__",
            ".pytest_cache",
            "cache-payload.pyc",
        }
        self.assertFalse(never_opened & set(opened_names), opened_names)

    def test_candidate_rejects_every_host_artifact(self) -> None:
        candidate = self.make_root("candidate")
        for name in (
            ".mcp.json",
            "..mcp.json.synapse-config.lock",
            ".DS_Store",
            ".mcp.json.bak-20260719-211716",
            ".mcp.json.bak-20260720-035745-5227afc8d913",
        ):
            with self.subTest(name=name):
                target = candidate / name
                target.write_bytes(b"host artifact\n")
                os.chmod(target, 0o600)
                result = planner.plan_product_release(self.template, candidate)
                self.assert_product_unsupported(result, "unexpected-entry")
                target.unlink()
        for cache in (
            "official_longmem/__pycache__",
            "tests/__pycache__",
            "tests/.pytest_cache",
        ):
            with self.subTest(cache=cache):
                target = candidate / cache
                target.mkdir()
                result = planner.plan_product_release(self.template, candidate)
                self.assert_product_unsupported(result, "unexpected-entry")
                target.rmdir()

    def test_host_artifact_exemptions_are_strict(self) -> None:
        # Near misses of the exempted names stay rejected in the current
        # root, and unknown entries still fail closed.
        current = self.make_root("current")
        near_misses = [
            ".mcp.json.bak-",
            ".mcp.json.bak-2026",
            ".mcp.json.bak-20260719_211716",
            ".mcp.json.bak-20260719-2117160",
            ".mcp.json.bak-20260719-211716-XYZABCQQ",
            ".mcp.json.bak-20260719-211716-abcdef1",
            ".mcp.json.bak-20260719-211716-" + "a" * 33,
            ".mcp.json.backup",
            "mcp.json",
            ".ds_store",
            "unknown.lock",
            "state.db",
        ]
        for name in near_misses:
            with self.subTest(name=name):
                target = current / name
                target.write_bytes(b"x\n")
                os.chmod(target, 0o600)
                result = planner.plan_product_release(current, self.template)
                self.assert_product_unsupported(result, "unexpected-entry")
                target.unlink()
        # Host-file exemptions are root-only.
        for nested in ("docs/.mcp.json", "web/.DS_Store"):
            with self.subTest(nested=nested):
                target = current / nested
                target.write_bytes(b"x\n")
                result = planner.plan_product_release(current, self.template)
                self.assert_product_unsupported(result, "unexpected-entry")
                target.unlink()
        # Cache-directory exemptions cover the exact basenames only.
        (current / "tests" / ".tox").mkdir()
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "unexpected-entry")

    def test_unsafe_or_mistyped_host_artifacts_fail_closed(self) -> None:
        current = self.make_root("current-symlink")
        (current / ".mcp.json").symlink_to(current / ".mcp.json.example")
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "special-file")

        current = self.make_root("current-fifo")
        os.mkfifo(current / ".mcp.json.bak-20260719-211716")
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "special-file")

        current = self.make_root("current-mode")
        target = current / ".DS_Store"
        target.write_bytes(b"x\n")
        os.chmod(target, 0o666)
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "file-unsafe")

        current = self.make_root("current-hardlink")
        target = current / ".mcp.json"
        target.write_bytes(b"x\n")
        os.chmod(target, 0o600)
        os.link(target, self.base / "mcp-alias")
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "file-unsafe")

        current = self.make_root("current-dir")
        (current / ".DS_Store").mkdir()
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "unexpected-entry")

        current = self.make_root("current-cache-symlink")
        (current / "tests" / "__pycache__").symlink_to(current / "docs")
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "special-file")

        current = self.make_root("current-cache-file")
        (current / "tests" / "__pycache__").write_bytes(b"x\n")
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "unexpected-entry")

        current = self.make_root("current-cache-mode")
        cache = current / "tests" / "__pycache__"
        cache.mkdir()
        os.chmod(cache, 0o775)
        self.addCleanup(os.chmod, cache, 0o755)
        result = planner.plan_product_release(current, self.template)
        self.assert_product_unsupported(result, "root-unsafe")

    def test_nested_cache_exemption_is_exact_paths_only(self) -> None:
        self.assertEqual(
            planner.PRODUCT_CURRENT_CACHE_DIR_PATHS,
            frozenset(
                (
                    "official_longmem/__pycache__",
                    "scripts/__pycache__",
                    "tests/__pycache__",
                )
            ),
        )
        current = self.make_root("current")
        # A malicious or stray cache anywhere off the allowlist rejects,
        # docs/__pycache__ included.
        for nested in (
            "docs/__pycache__",
            "docs/superpowers/__pycache__",
            "web/__pycache__",
            "output/__pycache__",
            "tests/fixtures/__pycache__",
            "official_longmem/.pytest_cache",
            "tests/.pytest_cache",
            "scripts/.mypy_cache",
        ):
            with self.subTest(nested=nested):
                target = current / nested
                target.mkdir()
                result = planner.plan_product_release(current, self.template)
                self.assert_product_unsupported(result, "unexpected-entry")
                target.rmdir()

    def test_unsafe_root_state_and_vcs_dirs_fail_closed(self) -> None:
        for name, mode in ((".venv", 0o775), (".synapse_s2", 0o777)):
            with self.subTest(name=name):
                current = self.make_root(f"current-{name}")
                state = current / name
                state.mkdir()
                os.chmod(state, mode)
                self.addCleanup(os.chmod, state, 0o755)
                result = planner.plan_product_release(current, self.template)
                self.assert_product_unsupported(result, "root-unsafe")
        # VCS metadata is safety-screened in both roots.
        for role in ("current", "candidate"):
            with self.subTest(role=role):
                tainted = self.make_root(f"{role}-git")
                meta = tainted / ".git"
                meta.mkdir()
                os.chmod(meta, 0o775)
                self.addCleanup(os.chmod, meta, 0o755)
                if role == "current":
                    pair = (tainted, self.template)
                else:
                    pair = (self.template, tainted)
                result = planner.plan_product_release(*pair)
                self.assert_product_unsupported(result, "root-unsafe")

    def test_ignored_entries_are_final_rechecked(self) -> None:
        def build_current(name: str) -> Path:
            current = self.make_root(name)
            config = current / ".mcp.json"
            config.write_bytes(b"{}\n")
            os.chmod(config, 0o600)
            (current / ".venv").mkdir()
            (current / ".claude").mkdir()
            (current / "tests" / "__pycache__").mkdir()
            state = current / ".synapse_s2"
            state.mkdir()
            os.chmod(state, 0o700)
            return current

        # Every mutation below fires deterministically on the candidate's
        # read of synapse_cli.py — strictly after the current root's files
        # were read and its directories scanned and registered.
        current = build_current("current-file-chmod")
        wrapper, state = self.firing_os_open(
            "synapse_cli.py",
            lambda: os.chmod(current / ".mcp.json", 0o666),
            occurrence=2,
        )
        with mock.patch.object(planner.os, "open", new=wrapper):
            result = planner.plan_product_release(current, self.template)
        self.assertTrue(state["fired"])
        self.assert_product_unsupported(result, "validation-race")

        current = build_current("current-file-swap")

        def swap_config() -> None:
            target = current / ".mcp.json"
            target.unlink()
            target.write_bytes(b"{}\n")
            os.chmod(target, 0o600)

        wrapper, state = self.firing_os_open(
            "synapse_cli.py", swap_config, occurrence=2
        )
        with mock.patch.object(planner.os, "open", new=wrapper):
            result = planner.plan_product_release(current, self.template)
        self.assertTrue(state["fired"])
        self.assert_product_unsupported(result, "validation-race")

        current = build_current("current-dir-chmod")
        victim = current / ".venv"
        wrapper, state = self.firing_os_open(
            "synapse_cli.py", lambda: os.chmod(victim, 0o775), occurrence=2
        )
        self.addCleanup(os.chmod, victim, 0o755)
        with mock.patch.object(planner.os, "open", new=wrapper):
            result = planner.plan_product_release(current, self.template)
        self.assertTrue(state["fired"])
        self.assert_product_unsupported(result, "root-unsafe")

        current = build_current("current-dir-swap")

        def swap_state_dir() -> None:
            (current / ".claude").rmdir()
            (current / ".claude").mkdir()

        wrapper, state = self.firing_os_open(
            "synapse_cli.py", swap_state_dir, occurrence=2
        )
        with mock.patch.object(planner.os, "open", new=wrapper):
            result = planner.plan_product_release(current, self.template)
        self.assertTrue(state["fired"])
        self.assert_product_unsupported(result, "validation-race")

        current = build_current("current-cache-chmod")
        cache = current / "tests" / "__pycache__"
        wrapper, state = self.firing_os_open(
            "synapse_cli.py", lambda: os.chmod(cache, 0o775), occurrence=2
        )
        self.addCleanup(os.chmod, cache, 0o755)
        with mock.patch.object(planner.os, "open", new=wrapper):
            result = planner.plan_product_release(current, self.template)
        self.assertTrue(state["fired"])
        self.assert_product_unsupported(result, "root-unsafe")

        # Live-state *content* drift inside an ignored directory stays
        # tolerated: same inode, same type, still safe.
        current = build_current("current-benign-drift")
        wrapper, state = self.firing_os_open(
            "synapse_cli.py",
            lambda: (current / ".synapse_s2" / "synapse.db-wal").write_bytes(
                b"wal"
            ),
            occurrence=2,
        )
        with mock.patch.object(planner.os, "open", new=wrapper):
            result = planner.plan_product_release(current, self.template)
        self.assertTrue(state["fired"])
        self.assert_no_update(result)

    def test_real_incumbent_root_matches_clean_archive(self) -> None:
        # The actual deployed checkout, with its live host artifacts, must
        # plan no-update against a clean archive of the same commit.
        git_common = subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        real_root = Path(git_common).parent
        if not (real_root / "core_service.py").is_file():
            self.skipTest("primary checkout not found")
        head = subprocess.run(
            ["git", "-C", str(real_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if head != HISTORY_NEW_COMMIT:
            self.skipTest("primary checkout moved past the pinned base")
        dirty = subprocess.run(
            ["git", "-C", str(real_root), "status", "--porcelain", "-uno"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        if dirty.strip():
            self.skipTest("primary checkout has modified tracked files")
        # The templates carry the release-foundation overlay, so the live
        # checkout only matches once the identical overlay is deployed
        # there too; anything else is a skip, not a weakened assertion.
        for relative in HISTORY_FOUNDATION_OVERLAY:
            deployed = real_root / relative
            if (
                not deployed.is_file()
                or deployed.read_bytes() != (ROOT / relative).read_bytes()
            ):
                self.skipTest(
                    "primary checkout predates the release foundation"
                )
        recording, opened_names = self.recording_os_open()
        with mock.patch.object(planner.os, "open", new=recording):
            result = planner.plan_product_release(real_root, self.template)
        self.assert_no_update(result)
        self.assertEqual(
            result["current"]["product_id"],
            result["candidate"]["product_id"],
        )
        self.assertFalse(
            {
                ".synapse_s2",
                "synapse.db",
                ".venv",
                ".claude",
                ".mcp.json",
                ".DS_Store",
                "..mcp.json.synapse-config.lock",
                "__pycache__",
                ".pytest_cache",
            }
            & set(opened_names),
            sorted(set(opened_names)),
        )

    def test_git_metadata_is_screened_then_ignored_never_read(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        for root in (current, candidate):
            meta = root / ".git"
            meta.mkdir()
            (meta / "HEAD").write_bytes(b"ref: refs/heads/main\n")
            (meta / "hooks.db").write_bytes(b"\x00")
        recording, opened_names = self.recording_os_open()
        with mock.patch.object(planner.os, "open", new=recording):
            result = planner.plan_product_release(current, candidate)
        self.assert_no_update(result)
        self.assertFalse(
            {".git", "HEAD", "hooks.db"} & set(opened_names), opened_names
        )

        # Linked-worktree layout: .git is a regular file.
        shutil.rmtree(candidate / ".git")
        (candidate / ".git").write_bytes(b"gitdir: /elsewhere\n")
        result = planner.plan_product_release(current, candidate)
        self.assert_no_update(result)

        # Anything else under the .git name fails closed.
        (candidate / ".git").unlink()
        (candidate / ".git").symlink_to(candidate / "docs")
        result = planner.plan_product_release(current, candidate)
        self.assert_product_unsupported(result, "special-file")

    def test_symlink_hardlink_and_special_files_fail_closed(self) -> None:
        candidate = self.make_root("candidate-symlink")
        victim = candidate / "web" / "index.html"
        victim.unlink()
        victim.symlink_to(candidate / "web" / "styles.css")
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "file-unsafe")

        candidate = self.make_root("candidate-hardlink")
        os.link(candidate / "synapse_cli.py", self.base / "cli-alias")
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "file-unsafe")

        candidate = self.make_root("candidate-extralink")
        (candidate / "web" / "evil").symlink_to("/etc/passwd")
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "special-file")

        candidate = self.make_root("candidate-fifo")
        os.mkfifo(candidate / "scripts" / "pipe")
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "special-file")

    def test_fifo_swap_of_product_file_is_timeout_safe(self) -> None:
        current = self.make_root("current")
        victim = current / "synapse_cli.py"

        def swap_to_fifo() -> None:
            os.unlink(victim)
            os.mkfifo(victim)

        wrapper, state = self.firing_os_open("synapse_cli.py", swap_to_fifo)
        result: dict[str, dict] = {}

        def run_plan() -> None:
            result["plan"] = planner.plan_product_release(
                current, self.template
            )

        # Without O_NONBLOCK a read-only open of a writer-less FIFO blocks
        # forever; run the plan on a daemon thread so a regression fails the
        # test instead of hanging the suite.
        wrapped = mock.patch.object(planner.os, "open", new=wrapper)
        with wrapped:
            worker = threading.Thread(target=run_plan, daemon=True)
            worker.start()
            worker.join(timeout=60)
            self.assertFalse(worker.is_alive(), "planner blocked on FIFO open")
        self.assertTrue(state["fired"])
        self.assert_product_unsupported(result["plan"], "validation-race")

    def test_unsafe_mode_fails_closed(self) -> None:
        candidate = self.make_root("candidate-file")
        os.chmod(candidate / "web" / "app.js", 0o666)
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "file-unsafe")

        candidate = self.make_root("candidate-dir")
        os.chmod(candidate / "web", 0o775)
        self.addCleanup(os.chmod, candidate / "web", 0o755)
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "root-unsafe")

    def test_scan_name_screening_rejects_collisions_and_non_ascii(
        self,
    ) -> None:
        snapshot = planner._RootSnapshot(self.template)
        snapshot.open_root()
        self.addCleanup(snapshot.close)

        class _FakeEntry:
            def __init__(self, name: str) -> None:
                self.name = name

        def fake_scandir_factory(names):
            @contextlib.contextmanager
            def fake_scandir(descriptor):
                yield iter([_FakeEntry(name) for name in names])

            return fake_scandir

        for names, token in (
            (["App.js", "app.js"], "name-collision"),
            (["INDEX.HTML", "index.html"], "name-collision"),
            (["café.js"], "name-unsafe"),
        ):
            with self.subTest(names=names):
                budget = {
                    "remaining": planner.MAX_PRODUCT_SCANNED_NAME_BYTES
                }
                with mock.patch.object(
                    planner.os, "scandir", new=fake_scandir_factory(names)
                ):
                    with self.assertRaises(planner._Unsupported) as caught:
                        planner._scan_product_directory(
                            snapshot,
                            ("web",),
                            frozenset(),
                            frozenset(),
                            False,
                            budget,
                            [],
                        )
                self.assertEqual(caught.exception.token, token)

    def test_incremental_scan_bounds_are_exact(self) -> None:
        directory_map = planner._product_directory_map()
        listings = {
            key: os.listdir(self.template.joinpath(*key))
            for key in directory_map
        }
        max_entries = max(len(names) for names in listings.values())
        per_root_name_bytes = sum(
            len(name.encode("ascii"))
            for names in listings.values()
            for name in names
        )
        total_name_bytes = 2 * per_root_name_bytes

        with mock.patch.object(
            planner, "MAX_PRODUCT_DIRECTORY_ENTRIES", max_entries
        ):
            result = planner.plan_product_release(
                self.template, self.template
            )
        self.assert_no_update(result)
        with mock.patch.object(
            planner, "MAX_PRODUCT_DIRECTORY_ENTRIES", max_entries - 1
        ):
            result = planner.plan_product_release(
                self.template, self.template
            )
        self.assert_product_unsupported(result, "directory-oversize")

        with mock.patch.object(
            planner, "MAX_PRODUCT_SCANNED_NAME_BYTES", total_name_bytes
        ):
            result = planner.plan_product_release(
                self.template, self.template
            )
        self.assert_no_update(result)
        with mock.patch.object(
            planner, "MAX_PRODUCT_SCANNED_NAME_BYTES", total_name_bytes - 1
        ):
            result = planner.plan_product_release(
                self.template, self.template
            )
        self.assert_product_unsupported(result, "scan-oversize")

    def test_name_and_path_byte_bounds_are_exact(self) -> None:
        longest_part = max(
            len(part.encode("ascii"))
            for _, _, path in planner.PRODUCT_INVENTORY
            for part in path.split("/")
        )
        longest_path = max(
            len(path.encode("ascii"))
            for _, _, path in planner.PRODUCT_INVENTORY
        )

        with mock.patch.object(
            planner, "MAX_PRODUCT_NAME_BYTES", longest_part
        ):
            result = planner.plan_product_release(
                self.template, self.template
            )
        self.assert_no_update(result)
        with mock.patch.object(
            planner, "MAX_PRODUCT_NAME_BYTES", longest_part - 1
        ):
            result = planner.plan_product_release(
                self.template, self.template
            )
        self.assert_product_unsupported(result, "product-inventory-invalid")

        with mock.patch.object(
            planner, "MAX_PRODUCT_PATH_BYTES", longest_path
        ):
            result = planner.plan_product_release(
                self.template, self.template
            )
        self.assert_no_update(result)
        with mock.patch.object(
            planner, "MAX_PRODUCT_PATH_BYTES", longest_path - 1
        ):
            result = planner.plan_product_release(
                self.template, self.template
            )
        self.assert_product_unsupported(result, "product-inventory-invalid")

        # Scan-side name bound: an extra entry one byte over a patched cap is
        # name-oversize; at the cap it survives screening and is rejected as
        # the unknown entry it is.
        cap = longest_part + 8
        candidate = self.make_root("candidate-longname")
        over = candidate / ("z" * (cap + 1))
        over.write_bytes(b"x\n")
        with mock.patch.object(planner, "MAX_PRODUCT_NAME_BYTES", cap):
            result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "name-oversize")
        exact = candidate / ("z" * cap)
        over.rename(exact)
        with mock.patch.object(planner, "MAX_PRODUCT_NAME_BYTES", cap):
            result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "unexpected-entry")

    def test_changed_paths_cap_reports_count_and_truncation(self) -> None:
        candidate = self.make_root("candidate")
        victims = sorted(
            (
                "cortex_contract.py",
                "event_segmenter.py",
                "harmonic_memory.py",
                "redaction.py",
                "replacement_policy.py",
            )
        )
        for name in victims:
            target = candidate / name
            target.write_bytes(target.read_bytes() + b"\n# delta\n")

        with mock.patch.object(planner, "MAX_PRODUCT_CHANGED_PATHS", 5):
            result = planner.plan_product_release(self.template, candidate)
        self.assert_product_shape(result)
        self.assertEqual(result["status"], "update-available")
        self.assertEqual(result["changed_paths"], victims)
        self.assertEqual(result["changed_path_count"], 5)
        self.assertIs(result["changed_paths_truncated"], False)

        with mock.patch.object(planner, "MAX_PRODUCT_CHANGED_PATHS", 4):
            result = planner.plan_product_release(self.template, candidate)
        self.assert_product_shape(result)
        self.assertEqual(result["status"], "update-available")
        self.assertEqual(result["changed_paths"], victims[:4])
        self.assertEqual(result["changed_path_count"], 5)
        self.assertIs(result["changed_paths_truncated"], True)
        self.assertEqual(result["changed_components"], ["core"])
        self.assertEqual(planner.product_exit_code(result), 3)

    def test_rendered_output_cap_collapses_to_fixed_refusal(self) -> None:
        argv = [
            "--product-release-plan",
            "--current-root",
            str(self.template),
            "--candidate-root",
            str(self.template),
        ]
        expected = (
            planner.render_plan(
                planner._build_product_result(
                    "unsupported:output-oversize", None, None, [], []
                )
            )
            + "\n"
        )
        with mock.patch.object(planner, "MAX_PRODUCT_RESULT_BYTES", 64):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = planner.main(argv)
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), expected)
        self.assertEqual(stdout.getvalue().count("\n"), 1)

    def test_oversize_and_total_budget_bounds_fail_closed(self) -> None:
        candidate = self.make_root("candidate")
        oversize = candidate / "web" / "app.js"
        with open(oversize, "r+b") as handle:
            handle.truncate(planner.MAX_MANIFEST_FILE_BYTES + 1)
        result = planner.plan_product_release(self.template, candidate)
        self.assert_product_unsupported(result, "file-oversize")

        with mock.patch.object(planner, "MAX_PRODUCT_TOTAL_BYTES", 1024):
            result = planner.plan_product_release(
                self.template, self.template
            )
        self.assert_product_unsupported(result, "total-oversize")

        # The configured budget stays generous: the tracked tree is roughly
        # 16.3MB per root, far below the shared cap.
        self.assertEqual(
            planner.MAX_PRODUCT_TOTAL_BYTES,
            2 * planner.MAX_TOTAL_MANIFEST_BYTES,
        )
        self.assertGreaterEqual(
            planner.MAX_PRODUCT_TOTAL_BYTES, 100 * 1024 * 1024
        )

    def test_expected_product_id_pin(self) -> None:
        baseline = planner.plan_product_release(self.template, self.template)
        self.assert_no_update(baseline)
        pin = baseline["candidate"]["product_id"]
        self.assertRegex(pin, PRODUCT_ID_PATTERN)
        self.assertEqual(pin, baseline["current"]["product_id"])
        pinned = planner.plan_product_release(self.template, self.template, pin)
        self.assert_no_update(pinned)
        mismatch = planner.plan_product_release(
            self.template, self.template, "product-" + "0" * 64
        )
        self.assert_product_unsupported(
            mismatch, "expected-product-id-mismatch"
        )
        # Identities were fully captured before the pin check, so honest ids
        # (never paths) are still reported.
        self.assertEqual(mismatch["candidate"]["product_id"], pin)
        for malformed in ("totally-bogus", "product-" + "0" * 24):
            with self.subTest(malformed=malformed):
                result = planner.plan_product_release(
                    self.template, self.template, malformed
                )
                self.assert_product_unsupported(result, "invalid-arguments")

    def test_product_concurrent_mutation_race_is_unsupported(self) -> None:
        current = self.make_root("current")
        victim = current / "synapse_cli.py"

        def append_to_victim() -> None:
            with open(victim, "ab") as handle:
                handle.write(b"#")

        wrapper, state = self.firing_os_open("synapse_cli.py", append_to_victim)
        with mock.patch.object(planner.os, "open", new=wrapper):
            result = planner.plan_product_release(current, self.template)
        self.assertTrue(state["fired"])
        self.assert_product_unsupported(result, "validation-race")

    def test_post_scan_directory_mutation_is_unsupported(self) -> None:
        current = self.make_root("current")

        def add_extra_after_current_scan() -> None:
            # Fires on the candidate's read of synapse_cli.py, i.e. after the
            # current root's reads *and* directory scans completed; the late
            # addition must still fail the held-vs-visible recheck.
            (current / "web" / "zz_note.txt").write_bytes(b"late\n")

        wrapper, state = self.firing_os_open(
            "synapse_cli.py", add_extra_after_current_scan, occurrence=2
        )
        with mock.patch.object(planner.os, "open", new=wrapper):
            result = planner.plan_product_release(current, self.template)
        self.assertTrue(state["fired"])
        self.assert_product_unsupported(result, "validation-race")

    def test_product_descriptors_closed_after_success_and_failure(
        self,
    ) -> None:
        bad_candidate = self.make_root("bad-candidate")
        (bad_candidate / "mcp_server.py").unlink()
        real_open, real_close = os.open, os.close
        opened: set = set()

        def tracking_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.add(fd)
            return fd

        def tracking_close(fd):
            real_close(fd)
            opened.discard(fd)

        with mock.patch.object(os, "open", new=tracking_open), mock.patch.object(
            os, "close", new=tracking_close
        ):
            for _ in range(3):
                result = planner.plan_product_release(
                    self.template, self.template
                )
                self.assert_no_update(result)
                self.assertEqual(opened, set(), "descriptor leaked on success")
            for _ in range(3):
                result = planner.plan_product_release(
                    self.template, bad_candidate
                )
                self.assert_product_unsupported(result, "file-missing")
                self.assertEqual(opened, set(), "descriptor leaked on failure")

    def test_product_tripwires_no_mutation_spawn_network_or_sqlite(
        self,
    ) -> None:
        real_os_open = os.open

        def read_only_os_open(path, flags, *args, **kwargs):
            forbidden = (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            )
            if flags & forbidden:
                raise AssertionError("planner attempted a writable os.open")
            return real_os_open(path, flags, *args, **kwargs)

        tripwire = AssertionError("forbidden side channel invoked")
        mutation_targets = [
            (os, "rename"),
            (os, "replace"),
            (os, "unlink"),
            (os, "remove"),
            (os, "rmdir"),
            (os, "removedirs"),
            (os, "mkdir"),
            (os, "makedirs"),
            (os, "chmod"),
            (os, "chown"),
            (os, "link"),
            (os, "symlink"),
            (os, "utime"),
            (os, "truncate"),
        ]
        spawn_targets = [
            (os, "system"),
            (os, "posix_spawn"),
            (os, "posix_spawnp"),
            (subprocess, "Popen"),
            (subprocess, "run"),
        ]
        network_targets = [
            (socket, "socket"),
            (socket, "create_connection"),
            (sqlite3, "connect"),
        ]
        with contextlib.ExitStack() as stack:
            for target, attribute in (
                mutation_targets + spawn_targets + network_targets
            ):
                stack.enter_context(
                    mock.patch.object(target, attribute, side_effect=tripwire)
                )
            stack.enter_context(mock.patch("builtins.open", side_effect=tripwire))
            stack.enter_context(
                mock.patch.object(io, "open", side_effect=tripwire)
            )
            # Direct pathlib mutation/write entry points; the planner only
            # uses Path for path arithmetic, never pathlib I/O.
            for attribute in (
                "write_text",
                "write_bytes",
                "touch",
                "mkdir",
                "rmdir",
                "unlink",
                "rename",
                "replace",
                "symlink_to",
                "hardlink_to",
                "chmod",
                "open",
            ):
                stack.enter_context(
                    mock.patch.object(
                        pathlib.Path, attribute, side_effect=tripwire
                    )
                )
            stack.enter_context(
                mock.patch.object(planner.os, "open", new=read_only_os_open)
            )
            result = planner.plan_product_release(self.template, self.template)
        self.assert_no_update(result)

    def test_product_plan_never_executes_candidate_code(self) -> None:
        candidate = self.make_root("candidate")
        sentinel = self.base / "sentinel-executed"
        payload = (
            "\nimport pathlib\n"
            f"pathlib.Path({str(sentinel)!r}).write_text(\"executed\")\n"
            "raise SystemExit(99)\n"
        ).encode("utf-8")
        for name in ("core_service.py", "mcp_server.py"):
            source_path = candidate / name
            source_path.write_bytes(source_path.read_bytes() + payload)
        web_victim = candidate / "web" / "app.js"
        web_victim.write_bytes(web_victim.read_bytes() + b"\n// injected\n")
        result = planner.plan_product_release(self.template, candidate)
        self.assertFalse(sentinel.exists())
        self.assert_product_shape(result)
        self.assertEqual(result["status"], "update-available")
        self.assertEqual(
            result["changed_paths"],
            ["core_service.py", "mcp_server.py", "web/app.js"],
        )
        self.assertEqual(result["changed_path_count"], 3)
        self.assertEqual(
            result["changed_components"], ["core", "dashboard", "mcp"]
        )
        self.assertEqual(planner.product_exit_code(result), 3)

    def test_product_cli_output_is_deterministic_single_line_and_redacted(
        self,
    ) -> None:
        candidate = self.make_root("candidate")
        victim = candidate / "web" / "index.html"
        victim.write_bytes(victim.read_bytes() + b"\n<!-- note -->\n")
        argv = [
            "--product-release-plan",
            "--current-root",
            str(self.template),
            "--candidate-root",
            str(candidate),
        ]
        outputs = []
        codes = []
        for _ in range(2):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                codes.append(planner.main(argv))
            outputs.append(stdout.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(codes, [3, 3])
        line = outputs[0]
        self.assertTrue(line.endswith("\n"))
        self.assertEqual(line.count("\n"), 1)
        body = line[:-1]
        self.assertNotIn(str(self.base), body)
        self.assertNotIn(str(self.class_base), body)
        self.assertNotIn(str(ROOT), body)
        self.assertNotIn("Traceback", body)
        result = json.loads(body)
        self.assert_product_shape(result)
        self.assertEqual(result["changed_paths"], ["web/index.html"])
        self.assertEqual(result["changed_path_count"], 1)
        self.assertEqual(
            body, json.dumps(result, sort_keys=True, separators=(",", ":"))
        )

    def test_product_cli_argument_errors_emit_product_shaped_json(
        self,
    ) -> None:
        argv_cases = [
            ["--product-release-plan"],
            ["--product-release-plan", "--current-root", str(self.template)],
            ["--product-release-plan", "--unknown"],
            # allow_abbrev=False: prefixes are never accepted as flags.
            [
                "--product-release-plan",
                "--current-root",
                str(self.template),
                "--candidate",
                str(self.template),
            ],
        ]
        for argv in argv_cases:
            with self.subTest(argv=argv):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    code = planner.main(argv)
                self.assertEqual(code, 2)
                self.assertEqual(stderr.getvalue(), "")
                self.assertEqual(stdout.getvalue(), PRODUCT_INVALID_ARGUMENTS_LINE)
        # An abbreviated mode flag is not the mode flag: the rejection keeps
        # the plan shape because no exact product flag is present.
        for argv in (
            [
                "--current-root",
                str(self.template),
                "--candidate-root",
                str(self.template),
                "--product",
            ],
            [
                "--current-root",
                str(self.template),
                "--candidate-root",
                str(self.template),
                "--product-release",
            ],
        ):
            with self.subTest(argv=argv):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    code = planner.main(argv)
                self.assertEqual(code, 2)
                self.assertEqual(stdout.getvalue(), INVALID_ARGUMENTS_LINE)

    def test_product_cli_rejects_mode_and_pin_combinations(self) -> None:
        roots = [
            "--current-root",
            str(self.template),
            "--candidate-root",
            str(self.template),
        ]
        cases = [
            # Mode precedence stays governed > gate > product > plan, so the
            # rejection shape follows the highest-precedence flag present.
            (
                ["--product-release-plan", "--governed-update-plan", *roots],
                GOVERNED_UNSUPPORTED_LINE,
            ),
            (
                ["--product-release-plan", "--preservation-gate", *roots],
                GATE_INVALID_ARGUMENTS_LINE,
            ),
            (
                [
                    "--product-release-plan",
                    *roots,
                    "--expected-candidate-build-id",
                    "source-" + "0" * 24,
                ],
                PRODUCT_INVALID_ARGUMENTS_LINE,
            ),
            (
                [
                    *roots,
                    "--expected-candidate-product-id",
                    "product-" + "0" * 64,
                ],
                INVALID_ARGUMENTS_LINE,
            ),
            (
                [
                    "--preservation-gate",
                    *roots,
                    "--expected-candidate-product-id",
                    "product-" + "0" * 64,
                ],
                GATE_INVALID_ARGUMENTS_LINE,
            ),
            (
                [
                    "--governed-update-plan",
                    *roots,
                    "--expected-candidate-product-id",
                    "product-" + "0" * 64,
                ],
                GOVERNED_UNSUPPORTED_LINE,
            ),
        ]
        for argv, expected_line in cases:
            with self.subTest(argv=argv):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    code = planner.main(argv)
                self.assertEqual(code, 2)
                self.assertEqual(stdout.getvalue(), expected_line)

    def test_product_plan_on_read_only_roots(self) -> None:
        current = self.make_root("current")
        candidate = self.make_root("candidate")
        locked: list = []
        for root in (current, candidate):
            for directory, _, _ in os.walk(root):
                locked.append(directory)
        for directory in locked:
            os.chmod(directory, 0o555)
        self.addCleanup(
            lambda: [os.chmod(directory, 0o755) for directory in locked]
        )
        result = planner.plan_product_release(current, candidate)
        self.assert_no_update(result)

    def test_product_cli_subprocess_isolated_mode_no_update(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(ROOT / "scripts" / "release_update_plan.py"),
                "--product-release-plan",
                "--current-root",
                str(self.template),
                "--candidate-root",
                str(self.template),
            ],
            capture_output=True,
            text=True,
            cwd=str(self.base),
            timeout=300,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(completed.stdout.count("\n"), 1)
        result = json.loads(completed.stdout)
        self.assert_no_update(result)
        self.assertRegex(
            result["current"]["product_id"], PRODUCT_ID_PATTERN
        )
        self.assertEqual(
            result["current"]["product_id"],
            result["candidate"]["product_id"],
        )

    def independent_product_id(self, root: Path) -> str:
        """Recompute the product identity straight from the documented
        domain construction, sharing no digest code with the planner."""
        records = []
        for component, role, path in planner.PRODUCT_INVENTORY:
            target = root / path
            observed = os.lstat(target)
            self.assertTrue(stat.S_ISREG(observed.st_mode), path)
            data = target.read_bytes()
            records.append(
                (
                    component,
                    role,
                    path,
                    format(stat.S_IMODE(observed.st_mode), "04o"),
                    len(data),
                    hashlib.sha256(data).hexdigest(),
                )
            )
        hasher = hashlib.sha256()
        hasher.update(
            "\x00".join(
                (
                    "synapse-s2.product-identity.v1",
                    "synapse-s2.product-release-plan.v1",
                    str(len(records)),
                )
            ).encode("ascii")
            + b"\n"
        )
        for component, role, path, mode, size, digest in sorted(records):
            hasher.update(
                "\x00".join(
                    (component, role, path, mode, str(size), digest)
                ).encode("ascii")
                + b"\n"
            )
        return "product-" + hasher.hexdigest()

    def test_historical_release_trees_product_acceptance(self) -> None:
        # Trusted incumbent verifier: the currently deployed planner compares
        # the two extracted trees without importing anything from either.
        result = planner.plan_product_release(self.template_old, self.template)
        self.assert_product_shape(result)
        self.assertEqual(result["status"], "update-available")
        self.assertEqual(result["changed_paths"], HISTORY_CHANGED_PATHS)
        self.assertEqual(result["changed_path_count"], 3)
        self.assertIs(result["changed_paths_truncated"], False)
        self.assertEqual(
            result["changed_components"], ["dashboard", "tests"]
        )
        # The overlaid trees cannot carry pinned digests (this file is part
        # of the overlay), so the identities are recomputed independently
        # from the documented domain construction instead.
        self.assertRegex(
            result["current"]["product_id"], PRODUCT_ID_PATTERN
        )
        self.assertRegex(
            result["candidate"]["product_id"], PRODUCT_ID_PATTERN
        )
        self.assertNotEqual(
            result["current"]["product_id"],
            result["candidate"]["product_id"],
        )
        self.assertEqual(
            result["current"]["product_id"],
            self.independent_product_id(self.template_old),
        )
        self.assertEqual(
            result["candidate"]["product_id"],
            self.independent_product_id(self.template),
        )
        for component, component_id in result["current"][
            "component_ids"
        ].items():
            if component in ("dashboard", "tests"):
                self.assertNotEqual(
                    component_id,
                    result["candidate"]["component_ids"][component],
                    component,
                )
            else:
                self.assertEqual(
                    component_id,
                    result["candidate"]["component_ids"][component],
                    component,
                )
        self.assertEqual(planner.product_exit_code(result), 3)

        # Self-comparison of each extracted tree distinguishes extraction
        # problems from comparison problems.
        self.assert_no_update(
            planner.plan_product_release(self.template_old, self.template_old)
        )
        self.assert_no_update(
            planner.plan_product_release(self.template, self.template)
        )

        # The legacy trusted-manifest source plan stays a byte-exact no-op
        # across the same pair: the dashboard and test deltas are invisible
        # to it.
        legacy = planner.plan_release_update(self.template_old, self.template)
        self.assertEqual(legacy["classification"], "no-op")
        self.assertEqual(legacy["status"], "no-op")
        self.assertEqual(legacy["changes"], [])
        self.assertEqual(planner.plan_exit_code(legacy), 0)




if __name__ == "__main__":
    unittest.main()

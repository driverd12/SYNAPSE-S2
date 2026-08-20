from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import pathlib
import shutil
import socket
import sqlite3
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
REAL_ROOT_BUILD_ID = "source-4a48c7cff2e3c240c227351a"

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


if __name__ == "__main__":
    unittest.main()

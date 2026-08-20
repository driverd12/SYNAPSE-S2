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
REAL_ROOT_BUILD_ID = "source-a1a182919c89d7d4fd06d713"

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


if __name__ == "__main__":
    unittest.main()

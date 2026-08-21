"""Tests for the deterministic plan-only governed update plan.

The governed plan composes the read-only v1 source planner and the read-only
preservation gate.  These tests prove every status/exit rule, byte
determinism, the fixed workflow/stop-condition/nonclaim sections, malformed
CLI handling, path/content nonleakage, candidate nonexecution, and the
read-only tripwires.
"""

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
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core_service import BUILD_SOURCE_MANIFEST  # noqa: E402
from scripts import release_update_plan as planner  # noqa: E402

# Governed mode deliberately lives in the already-hardened, self-contained
# planner.  Keeping the alias makes the contract assertions below readable
# while proving no second executable wrapper is required.
orchestrator = planner

BUILD_ID_PATTERN = r"\Asource-[0-9a-f]{24}\Z"
CONTRACT_DIGEST_PATTERN = r"\Acontract-[0-9a-f]{64}\Z"

GOVERNED_KEYS = {
    "schema",
    "mode",
    "status",
    "apply_supported",
    "apply_performed",
    "provenance_verified",
    "current",
    "candidate",
    "source_plan",
    "preservation_gate",
    "blockers",
    "requirements",
    "workflow",
    "stop_conditions",
    "nonclaims",
}

EXPECTED_WORKFLOW = [
    {"step": "source-review", "execution_supported": False},
    {"step": "delivery-audit", "execution_supported": False},
    {"step": "writer-quiescence", "execution_supported": False},
    {"step": "replacement-stage", "execution_supported": False},
    {"step": "readiness-certification", "execution_supported": False},
    {"step": "cutover-preflight", "execution_supported": False},
    {"step": "explicit-install", "execution_supported": False},
    {"step": "post-update-memory-equivalence", "execution_supported": False},
    {"step": "client-config-convergence", "execution_supported": False},
]

EXPECTED_STOP_CONDITIONS = [
    "stale",
    "drifted",
    "expired",
    "unsigned",
    "mismatched",
    "outcome_unknown",
    "nonquiescent",
    "memory-equivalence-failure",
]

EXPECTED_NONCLAIMS = [
    "no-evidence-validation",
    "no-staging",
    "no-cutover",
    "no-rollback",
    "no-memory-equivalence-verification",
    "no-live-store-safety",
    "no-provenance-proof",
]

EXPECTED_BLOCKERS = {
    "no-update": [],
    "review-required": ["source-delta-unclassified"],
    "blocked-contract-change": ["contract-change"],
    "unsupported": ["unsupported-input-or-result"],
}

EXPECTED_REQUIREMENTS = {
    "no-update": [],
    "review-required": [
        "contract-classification",
        "operator-review",
        "source-delta-review",
    ],
    "blocked-contract-change": [
        "contract-review",
        "operator-review",
        "source-delta-review",
    ],
    "unsupported": ["operator-review"],
}

EXPECTED_EXIT_CODES = {
    "no-update": 0,
    "review-required": 3,
    "blocked-contract-change": 3,
    "unsupported": 2,
}

# The gate's contract sources are the manifest plus the installer script,
# which is deliberately outside the build manifest.
TEMPLATE_FILES = tuple(BUILD_SOURCE_MANIFEST) + (
    "scripts/core_agent_installer.py",
)

MALFORMED_CLI_VARIANTS = (
    [],
    ["--current-root", "/somewhere"],
    ["--candidate-root", "/somewhere"],
    ["--current-root"],
    ["--current-root", "/a", "--candidate-root", "/b", "--unknown-flag"],
    ["positional", "--current-root", "/a", "--candidate-root", "/b"],
)


class GovernedUpdatePlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.class_temporary = tempfile.TemporaryDirectory(
            prefix="s2guo-", dir="/tmp"
        )
        cls.class_base = Path(cls.class_temporary.name).resolve()
        cls.template = cls.class_base / "template"
        for name in TEMPLATE_FILES:
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
        self.temporary = tempfile.TemporaryDirectory(prefix="s2guo-", dir="/tmp")
        self.base = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)

    def make_root(self, name: str) -> Path:
        destination = self.base / name
        shutil.copytree(self.template, destination)
        return destination

    def make_pair(self) -> tuple[Path, Path]:
        return self.make_root("current"), self.make_root("candidate")

    def rewrite(self, root: Path, filename: str, old: str, new: str) -> None:
        path = root / filename
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1))

    def append_bytes(self, root: Path, filename: str, suffix: bytes) -> None:
        path = root / filename
        path.write_bytes(path.read_bytes() + suffix)

    def run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
            stderr
        ):
            code = orchestrator.main(["--governed-update-plan", *argv])
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_governed_shape(self, result: dict, status: str) -> None:
        self.assertEqual(set(result), GOVERNED_KEYS)
        self.assertEqual(
            result["schema"], "synapse-s2.governed-update-plan.v1"
        )
        self.assertEqual(result["mode"], "plan-only")
        self.assertEqual(result["status"], status)
        self.assertIs(result["apply_supported"], False)
        self.assertIs(result["apply_performed"], False)
        self.assertIs(result["provenance_verified"], False)
        self.assertEqual(set(result["current"]), {"source_build_id"})
        self.assertEqual(set(result["candidate"]), {"source_build_id"})
        self.assertEqual(result["blockers"], EXPECTED_BLOCKERS[status])
        self.assertEqual(result["blockers"], sorted(result["blockers"]))
        self.assertEqual(result["requirements"], EXPECTED_REQUIREMENTS[status])
        self.assertEqual(
            result["requirements"], sorted(result["requirements"])
        )
        self.assertEqual(result["workflow"], EXPECTED_WORKFLOW)
        for step in result["workflow"]:
            self.assertIs(step["execution_supported"], False)
        self.assertEqual(result["stop_conditions"], EXPECTED_STOP_CONDITIONS)
        self.assertEqual(result["nonclaims"], EXPECTED_NONCLAIMS)
        self.assertEqual(
            orchestrator.governed_exit_code(result),
            EXPECTED_EXIT_CODES[status],
        )

    def test_identical_roots_no_update_exit_zero(self) -> None:
        current, candidate = self.make_pair()
        result = orchestrator.plan_governed_update(current, candidate)
        self.assert_governed_shape(result, "no-update")
        self.assertRegex(result["current"]["source_build_id"], BUILD_ID_PATTERN)
        self.assertEqual(
            result["current"]["source_build_id"],
            result["candidate"]["source_build_id"],
        )
        plan = result["source_plan"]
        self.assertEqual(plan["classification"], "no-op")
        self.assertEqual(plan["status"], "no-op")
        self.assertEqual(plan["changes"], [])
        gate = result["preservation_gate"]
        self.assertEqual(gate["status"], "proven-equal")
        self.assertRegex(
            gate["current"]["contract_digest"], CONTRACT_DIGEST_PATTERN
        )
        self.assertEqual(
            gate["current"]["contract_digest"],
            gate["candidate"]["contract_digest"],
        )

    def test_real_root_against_itself_is_no_update(self) -> None:
        result = orchestrator.plan_governed_update(ROOT, ROOT)
        self.assert_governed_shape(result, "no-update")

    def test_non_contract_delta_review_required_exit_three(self) -> None:
        current, candidate = self.make_pair()
        self.append_bytes(
            candidate, "redaction.py", b"\n# governed-plan review fixture\n"
        )
        result = orchestrator.plan_governed_update(current, candidate)
        self.assert_governed_shape(result, "review-required")
        plan = result["source_plan"]
        self.assertEqual(plan["classification"], "changed-unclassified")
        self.assertEqual(plan["status"], "blocked-changed-unclassified")
        self.assertEqual(plan["changes"], ["redaction.py"])
        self.assertEqual(result["preservation_gate"]["status"], "proven-equal")
        self.assertNotEqual(
            result["current"]["source_build_id"],
            result["candidate"]["source_build_id"],
        )

    def test_contract_change_blocked_exit_three(self) -> None:
        current, candidate = self.make_pair()
        self.rewrite(
            candidate,
            "core_request_journal.py",
            "JOURNAL_SCHEMA_VERSION = 3",
            "JOURNAL_SCHEMA_VERSION = 4",
        )
        result = orchestrator.plan_governed_update(current, candidate)
        self.assert_governed_shape(result, "blocked-contract-change")
        gate = result["preservation_gate"]
        self.assertEqual(gate["status"], "blocked-contract-change")
        self.assertEqual(gate["changed_surfaces"], ["request-journal.v1"])
        self.assertNotEqual(
            gate["current"]["contract_digest"],
            gate["candidate"]["contract_digest"],
        )
        self.assertEqual(
            result["source_plan"]["classification"], "changed-unclassified"
        )
        self.assertIn(
            "core_request_journal.py", result["source_plan"]["changes"]
        )

    def test_missing_manifest_file_unsupported_exit_two(self) -> None:
        current, candidate = self.make_pair()
        (candidate / "mlx_backend.py").unlink()
        result = orchestrator.plan_governed_update(current, candidate)
        self.assert_governed_shape(result, "unsupported")
        self.assertEqual(
            result["source_plan"]["status"], "unsupported:file-missing"
        )

    def test_gate_unsupported_dominates_no_op_plan(self) -> None:
        current, candidate = self.make_pair()
        (candidate / "scripts" / "core_agent_installer.py").unlink()
        result = orchestrator.plan_governed_update(current, candidate)
        self.assert_governed_shape(result, "unsupported")
        # The installer is outside the build manifest, so the source plan is
        # a genuine no-op; the missing contract source alone must fail the
        # composition closed.
        self.assertEqual(result["source_plan"]["classification"], "no-op")
        self.assertEqual(
            result["preservation_gate"]["status"],
            "unsupported:contract-missing",
        )

    def test_relative_root_unsupported_exit_two(self) -> None:
        candidate = self.make_root("candidate")
        result = orchestrator.plan_governed_update(
            Path("relative/root"), candidate
        )
        self.assert_governed_shape(result, "unsupported")
        self.assertEqual(
            result["source_plan"]["status"], "unsupported:invalid-arguments"
        )
        self.assertEqual(
            result["preservation_gate"]["status"],
            "unsupported:invalid-arguments",
        )

    def test_expected_build_id_match_mismatch_and_malformed(self) -> None:
        current, candidate = self.make_pair()
        baseline = orchestrator.plan_governed_update(current, candidate)
        expected = baseline["candidate"]["source_build_id"]
        self.assertRegex(expected, BUILD_ID_PATTERN)

        matched = orchestrator.plan_governed_update(
            current, candidate, expected
        )
        self.assert_governed_shape(matched, "no-update")

        mismatched = orchestrator.plan_governed_update(
            current, candidate, "source-" + "0" * 24
        )
        self.assert_governed_shape(mismatched, "unsupported")
        self.assertEqual(
            mismatched["source_plan"]["status"],
            "unsupported:expected-build-id-mismatch",
        )

        malformed = orchestrator.plan_governed_update(
            current, candidate, "not-a-build-id"
        )
        self.assert_governed_shape(malformed, "unsupported")
        self.assertEqual(
            malformed["source_plan"]["status"],
            "unsupported:invalid-arguments",
        )

    def test_rendered_output_is_byte_deterministic(self) -> None:
        current, candidate = self.make_pair()
        first = orchestrator.render_governed_plan(
            orchestrator.plan_governed_update(current, candidate)
        )
        second = orchestrator.render_governed_plan(
            orchestrator.plan_governed_update(current, candidate)
        )
        self.assertEqual(first, second)
        self.assertNotIn("\n", first)
        self.assertNotIn(" ", first.split('"schema"')[0])
        decoded = json.loads(first)
        self.assertEqual(
            json.dumps(decoded, sort_keys=True, separators=(",", ":")), first
        )

    def test_fixed_sections_identical_across_all_statuses(self) -> None:
        current, candidate = self.make_pair()
        results = [orchestrator.plan_governed_update(current, candidate)]

        review_candidate = self.make_root("review-candidate")
        self.append_bytes(review_candidate, "redaction.py", b"\n# delta\n")
        results.append(
            orchestrator.plan_governed_update(current, review_candidate)
        )

        blocked_candidate = self.make_root("blocked-candidate")
        self.rewrite(
            blocked_candidate,
            "core_request_journal.py",
            "JOURNAL_SCHEMA_VERSION = 3",
            "JOURNAL_SCHEMA_VERSION = 4",
        )
        results.append(
            orchestrator.plan_governed_update(current, blocked_candidate)
        )

        results.append(
            orchestrator.plan_governed_update(Path("relative"), candidate)
        )

        self.assertEqual(
            [result["status"] for result in results],
            [
                "no-update",
                "review-required",
                "blocked-contract-change",
                "unsupported",
            ],
        )
        for result in results:
            self.assertEqual(result["workflow"], EXPECTED_WORKFLOW)
            self.assertEqual(
                result["stop_conditions"], EXPECTED_STOP_CONDITIONS
            )
            self.assertEqual(result["nonclaims"], EXPECTED_NONCLAIMS)

    def test_no_path_content_or_error_leakage(self) -> None:
        current, candidate = self.make_pair()
        marker = "LEAK-MARKER-9f3a17"
        self.append_bytes(
            candidate, "redaction.py", f"\n# {marker}\n".encode("utf-8")
        )
        broken = self.make_root("broken")
        (broken / "mlx_backend.py").unlink()
        rendered = [
            orchestrator.render_governed_plan(
                orchestrator.plan_governed_update(current, candidate)
            ),
            orchestrator.render_governed_plan(
                orchestrator.plan_governed_update(current, broken)
            ),
            orchestrator.render_governed_plan(
                orchestrator.plan_governed_update(Path("relative"), candidate)
            ),
        ]
        for text in rendered:
            self.assertNotIn(str(self.base), text)
            self.assertNotIn(str(ROOT), text)
            self.assertNotIn("/tmp", text)
            self.assertNotIn("/private", text)
            self.assertNotIn(marker, text)
            self.assertNotIn("Traceback", text)
            self.assertNotIn("Errno", text)

    def test_candidate_code_is_never_imported_or_executed(self) -> None:
        current, candidate = self.make_pair()
        sentinel = self.base / "executed-sentinel"
        payload = (
            "\nimport pathlib as _p\n"
            f"_p.Path({str(sentinel)!r}).write_text('candidate-ran')\n"
        )
        self.append_bytes(
            candidate, "core_service.py", payload.encode("utf-8")
        )
        result = orchestrator.plan_governed_update(current, candidate)
        self.assertFalse(sentinel.exists())
        self.assert_governed_shape(result, "review-required")
        self.assertIn("core_service.py", result["source_plan"]["changes"])
        rendered = orchestrator.render_governed_plan(result)
        self.assertNotIn("executed-sentinel", rendered)
        self.assertNotIn("candidate-ran", rendered)

    def test_atomic_capture_rejects_mutation_between_analyses(self) -> None:
        current, candidate = self.make_pair()
        original = planner._capture_contract_state
        mutated = False

        def mutate_before_contract(snapshot, *args, **kwargs):
            nonlocal mutated
            if snapshot.root == candidate and not mutated:
                mutated = True
                self.append_bytes(
                    candidate,
                    "redaction.py",
                    b"\n# concurrent governed-capture mutation\n",
                )
            return original(snapshot, *args, **kwargs)

        with mock.patch.object(
            planner,
            "_capture_contract_state",
            side_effect=mutate_before_contract,
        ):
            result = orchestrator.plan_governed_update(current, candidate)

        self.assertTrue(mutated)
        self.assert_governed_shape(result, "unsupported")
        self.assertEqual(
            result["source_plan"]["status"],
            "unsupported:validation-race",
        )
        self.assertNotEqual(result["status"], "no-update")

    def test_cli_malformed_arguments_emit_fixed_json_no_stderr(self) -> None:
        outputs = []
        for argv in MALFORMED_CLI_VARIANTS:
            code, stdout, stderr = self.run_cli(list(argv))
            self.assertEqual(code, 2)
            self.assertEqual(stderr, "")
            self.assertTrue(stdout.endswith("\n"))
            lines = stdout.splitlines()
            self.assertEqual(len(lines), 1)
            decoded = json.loads(lines[0])
            self.assert_governed_shape(decoded, "unsupported")
            self.assertIsNone(decoded["source_plan"])
            self.assertIsNone(decoded["preservation_gate"])
            self.assertIsNone(decoded["current"]["source_build_id"])
            self.assertIsNone(decoded["candidate"]["source_build_id"])
            outputs.append(stdout)
        self.assertEqual(len(set(outputs)), 1)

    def test_cli_happy_path_and_mismatch(self) -> None:
        current, candidate = self.make_pair()
        code, stdout, stderr = self.run_cli(
            [
                "--current-root",
                str(current),
                "--candidate-root",
                str(candidate),
            ]
        )
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(
            stdout,
            orchestrator.render_governed_plan(
                orchestrator.plan_governed_update(current, candidate)
            )
            + "\n",
        )
        self.assertEqual(json.loads(stdout)["status"], "no-update")

        code, stdout, stderr = self.run_cli(
            [
                "--current-root",
                str(current),
                "--candidate-root",
                str(candidate),
                "--expected-candidate-build-id",
                "source-" + "f" * 24,
            ]
        )
        self.assertEqual(code, 2)
        self.assertEqual(stderr, "")
        self.assertEqual(json.loads(stdout)["status"], "unsupported")

    def test_tripwires_no_mutation_spawn_network_or_database(self) -> None:
        current, candidate = self.make_pair()
        real_os_open = os.open

        def read_only_os_open(path, flags, *args, **kwargs):
            forbidden = (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            )
            if flags & forbidden:
                raise AssertionError("orchestrator attempted a writable open")
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
            stack.enter_context(
                mock.patch("builtins.open", side_effect=tripwire)
            )
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
            result = orchestrator.plan_governed_update(current, candidate)
        self.assert_governed_shape(result, "no-update")

    def test_governed_mode_has_no_project_import_wrapper(self) -> None:
        self.assertFalse(
            (ROOT / "scripts" / "release_update_orchestrator.py").exists()
        )
        source = (ROOT / "scripts" / "release_update_plan.py").read_text()
        modules = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                modules.update(
                    alias.name.split(".")[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        allowed = {
            "argparse",
            "ast",
            "errno",
            "hashlib",
            "io",
            "json",
            "os",
            "pathlib",
            "re",
            "stat",
            "sys",
            "tokenize",
        }
        self.assertLessEqual(modules, allowed)
        self.assertNotIn("scripts", modules)

    def test_exit_code_mapping_is_total_and_fail_closed(self) -> None:
        for status, code in EXPECTED_EXIT_CODES.items():
            self.assertEqual(
                orchestrator.governed_exit_code({"status": status}), code
            )
            self.assertEqual(orchestrator.GOVERNED_EXIT_CODES[status], code)
        self.assertEqual(
            orchestrator.governed_exit_code({"status": "bogus"}), 2
        )
        self.assertEqual(orchestrator.governed_exit_code({}), 2)
        self.assertEqual(orchestrator.governed_exit_code(None), 2)


if __name__ == "__main__":
    unittest.main()

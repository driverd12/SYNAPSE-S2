"""Focused security and lifecycle regressions for the official runner."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = REPO_ROOT / "scripts" / "run_longmem_v2_official.py"
SPEC = importlib.util.spec_from_file_location("stage1a_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)

OFFICIAL_ROOT = Path(
    os.environ.get(
        "LONGMEM_V2_OFFICIAL_ROOT",
        "/private/tmp/s2-frontier-review.CqgTZr/longmemeval-v2",
    )
)
OFFICIAL_DEPS = Path(
    os.environ.get("LONGMEM_V2_OFFICIAL_DEPS", "/private/tmp/s2lm-official-deps")
)


class OfficialRunnerStage1ATests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp(prefix="s2lm-runner-test-", dir="/private/tmp"))
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)

    def _inputs(self) -> tuple[Path, Path, Path]:
        questions = self.base / "questions.json"
        haystack = self.base / "haystack.json"
        trajectories = self.base / "trajectories.json"
        questions.write_text("[]\n", encoding="utf-8")
        haystack.write_text("{}\n", encoding="utf-8")
        trajectories.write_text("[]\n", encoding="utf-8")
        return questions, haystack, trajectories

    def _full_args(self, *, extra: list[str] | None = None) -> argparse.Namespace:
        questions, haystack, trajectories = self._inputs()
        argv = [
            "--domain",
            "web",
            "--questions-path",
            str(questions),
            "--haystack-path",
            str(haystack),
            "--trajectories-path",
            str(trajectories),
            "--output-dir",
            str(self.base / "output"),
        ]
        if extra:
            argv += ["--", *extra]
        return RUNNER._build_parser().parse_args(argv)

    def _run_root_with_staging(self):
        run_root = RUNNER._bootstrap.DisposableRunRoot()
        staging = run_root.output_parent / RUNNER._STAGED_OUTPUT_NAME
        staging.mkdir()
        (staging / "result.json").write_text("{}\n", encoding="utf-8")
        return run_root

    def test_reserved_and_duplicate_extra_flags_are_rejected(self) -> None:
        marker = "SENSITIVE-PATH-MARKER"
        rejected = (
            ["--output-dir", f"/private/tmp/{marker}"],
            [f"--memory-config-path=/private/tmp/{marker}"],
            ["--questions-path", f"/private/tmp/{marker}"],
            ["--inner"],
            ["--model", "first", "--model=second"],
            ["--reader-enable-thinking", "--reader-disable-thinking"],
        )
        for extra in rejected:
            with self.subTest(extra=extra):
                args = argparse.Namespace(harness_args=["--", *extra])
                with self.assertRaises(RUNNER._bootstrap.BootstrapError) as caught:
                    RUNNER._extra_harness_args(args)
                self.assertNotIn(marker, str(caught.exception))

    def test_reader_and_evaluator_allowlist_is_preserved(self) -> None:
        args = argparse.Namespace(
            harness_args=[
                "--",
                "--model",
                "reader-model",
                "--reader-disable-thinking",
                "--evaluator-model=evaluator-model",
                "--api-key-env",
                "READER_API_KEY",
            ]
        )
        self.assertEqual(
            RUNNER._extra_harness_args(args),
            [
                "--model",
                "reader-model",
                "--reader-disable-thinking",
                "--evaluator-model",
                "evaluator-model",
                "--api-key-env",
                "READER_API_KEY",
            ],
        )

    def test_config_read_is_nofollow_bounded_and_nonreflective(self) -> None:
        _questions, _haystack, trajectories = self._inputs()
        marker = "CONFIG-SECRET-MARKER"
        target = self.base / f"{marker}.json"
        target.write_text(
            json.dumps({"memory_type": "synapse_s2", "memory_params": {}}),
            encoding="utf-8",
        )
        link = self.base / "config-link.json"
        link.symlink_to(target)
        run_root = RUNNER._bootstrap.DisposableRunRoot()
        self.addCleanup(run_root.close)
        with self.assertRaises(RUNNER._bootstrap.BootstrapError) as caught:
            RUNNER._generate_memory_config(
                argparse.Namespace(memory_config_path=str(link)),
                run_root,
                trajectories,
            )
        self.assertNotIn(marker, str(caught.exception))

        oversized = self.base / f"oversized-{marker}.json"
        oversized.write_bytes(b"x" * 17)
        with mock.patch.object(RUNNER, "_MAX_CONFIG_BYTES", 16):
            with self.assertRaises(RUNNER._bootstrap.BootstrapError) as caught:
                RUNNER._generate_memory_config(
                    argparse.Namespace(memory_config_path=str(oversized)),
                    run_root,
                    trajectories,
                )
        self.assertNotIn(marker, str(caught.exception))

    def test_generated_config_removes_fixed_workspace_and_is_private(self) -> None:
        _questions, _haystack, trajectories = self._inputs()
        source = self.base / "config.json"
        source.write_text(
            json.dumps(
                {
                    "memory_type": "synapse_s2",
                    "memory_params": {"workspace_dir": "/private/tmp/collision"},
                }
            ),
            encoding="utf-8",
        )
        run_root = RUNNER._bootstrap.DisposableRunRoot()
        self.addCleanup(run_root.close)
        generated = RUNNER._generate_memory_config(
            argparse.Namespace(memory_config_path=str(source)),
            run_root,
            trajectories,
        )
        payload = json.loads(generated.read_text(encoding="utf-8"))
        self.assertNotIn("workspace_dir", payload["memory_params"])
        self.assertEqual(
            payload["memory_params"]["trajectories_root_dir"],
            str(trajectories.parent),
        )
        self.assertEqual(stat.S_IMODE(generated.stat().st_mode), 0o600)

    def test_load_requires_out_of_band_manifest_sha_and_injects_runtime_key(self) -> None:
        args = self._full_args()
        load_dir = self.base / "artifact"
        load_dir.mkdir()
        args.load_memory_dir = str(load_dir)
        args.expected_artifact_manifest_sha256 = None
        with self.assertRaisesRegex(
            RUNNER._bootstrap.BootstrapError, "requires an explicit 64-hex"
        ):
            RUNNER._validate_run_request(args)

        expected = "A" * 64
        args.expected_artifact_manifest_sha256 = expected
        paths = RUNNER._validate_run_request(args)
        self.assertEqual(paths["load_memory"], load_dir)

        _questions, _haystack, trajectories = self._inputs()
        source = self.base / "load-config.json"
        source.write_text(
            json.dumps(
                {
                    "memory_type": "synapse_s2",
                    "memory_params": {
                        "expected_artifact_manifest_sha256": "0" * 64
                    },
                }
            ),
            encoding="utf-8",
        )
        run_root = RUNNER._bootstrap.DisposableRunRoot()
        self.addCleanup(run_root.close)
        args.memory_config_path = str(source)
        generated = RUNNER._generate_memory_config(args, run_root, trajectories)
        payload = json.loads(generated.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["memory_params"]["expected_artifact_manifest_sha256"],
            expected.lower(),
        )

    def test_manifest_sha_is_rejected_without_load(self) -> None:
        args = self._full_args()
        args.expected_artifact_manifest_sha256 = "a" * 64
        with self.assertRaisesRegex(
            RUNNER._bootstrap.BootstrapError, "only valid"
        ):
            RUNNER._validate_run_request(args)

    def test_official_inputs_reject_symlinks_and_byte_overflow(self) -> None:
        args = self._full_args()
        questions = Path(args.questions_path)
        real_questions = questions.with_name("real-questions.json")
        questions.rename(real_questions)
        questions.symlink_to(real_questions)
        with self.assertRaises(RUNNER._bootstrap.BootstrapError):
            RUNNER._validate_run_request(args)

        questions.unlink()
        questions.write_bytes(b"12345")
        with mock.patch.object(RUNNER, "_MAX_QUESTIONS_BYTES", 4):
            with self.assertRaises(RUNNER._bootstrap.BootstrapError):
                RUNNER._validate_run_request(args)

    def test_all_caller_file_lanes_reject_fifo_fast_without_residue(self) -> None:
        marker = "FIFO-PRIVATE-MARKER"
        roots_before = {path.name for path in Path("/private/tmp").glob("s2lm-*")}
        for label, attribute in (
            ("questions", "questions_path"),
            ("haystack", "haystack_path"),
            ("trajectories", "trajectories_path"),
        ):
            with self.subTest(lane=label):
                fifo = self.base / f"{marker}-{label}.fifo"
                os.mkfifo(fifo, 0o600)
                args = self._full_args()
                setattr(args, attribute, str(fifo))
                started = time.monotonic()
                with self.assertRaises(RUNNER._bootstrap.BootstrapError) as caught:
                    RUNNER._validate_run_request(args)
                self.assertLess(time.monotonic() - started, 1.0)
                self.assertNotIn(marker, str(caught.exception))
                self.assertFalse(Path(args.output_dir).exists())

        config_fifo = self.base / f"{marker}-config.fifo"
        os.mkfifo(config_fifo, 0o600)
        _questions, _haystack, trajectories = self._inputs()
        config_root = RUNNER._bootstrap.DisposableRunRoot()
        config_root_path = config_root.base
        try:
            started = time.monotonic()
            with self.assertRaises(RUNNER._bootstrap.BootstrapError) as caught:
                RUNNER._generate_memory_config(
                    argparse.Namespace(memory_config_path=str(config_fifo)),
                    config_root,
                    trajectories,
                )
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertNotIn(marker, str(caught.exception))
            self.assertFalse(
                (config_root.trace_parent / "memory_config.json").exists()
            )
        finally:
            config_root.close()
        self.assertFalse(config_root_path.exists())

        key_fifo = self.base / f"{marker}-api-key.fifo"
        os.mkfifo(key_fifo, 0o600)
        key_root = RUNNER._bootstrap.DisposableRunRoot()
        key_root_path = key_root.base
        try:
            started = time.monotonic()
            with self.assertRaises(RUNNER._bootstrap.BootstrapError) as caught:
                RUNNER._stage_extra_harness_args(
                    argparse.Namespace(
                        harness_args=["--", "--api-key-file", str(key_fifo)]
                    ),
                    key_root,
                )
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertNotIn(marker, str(caught.exception))
            self.assertEqual(list(key_root.trace_parent.glob("api-key-*")), [])
        finally:
            key_root.close()
        self.assertFalse(key_root_path.exists())
        roots_after = {path.name for path in Path("/private/tmp").glob("s2lm-*")}
        self.assertEqual(roots_after, roots_before)

    def test_official_inputs_are_staged_as_private_regular_files(self) -> None:
        args = self._full_args()
        paths = RUNNER._validate_run_request(args)
        run_root = RUNNER._bootstrap.DisposableRunRoot()
        self.addCleanup(run_root.close)
        staged = RUNNER._stage_official_inputs(run_root, paths)
        for label in ("questions", "haystack", "trajectories"):
            source = paths[label]
            self.assertIsInstance(source, Path)
            self.assertEqual(staged[label].read_bytes(), source.read_bytes())
            self.assertTrue(staged[label].is_relative_to(run_root.trace_parent))
            self.assertEqual(stat.S_IMODE(staged[label].stat().st_mode), 0o600)

    def test_trajectory_scan_rejects_nested_symlink(self) -> None:
        tree = self.base / "tree"
        tree.mkdir()
        (tree / "regular.png").write_bytes(b"png")
        (tree / "escape.png").symlink_to(self.base / "outside.png")
        with self.assertRaisesRegex(
            RUNNER._bootstrap.BootstrapError, "copy mode"
        ):
            RUNNER._reject_symlinks_under(tree)

    def test_output_relocation_detects_parent_inode_swap(self) -> None:
        parent = self.base / "parent"
        parent.mkdir()
        destination = parent / "published"
        destination, identity = RUNNER._validate_output_destination(destination)
        original = self.base / "original-parent"
        parent.rename(original)
        parent.mkdir()
        run_root = self._run_root_with_staging()
        self.addCleanup(run_root.close)
        with self.assertRaisesRegex(
            RUNNER._bootstrap.BootstrapError, "parent changed"
        ):
            RUNNER._relocate_staged_output(run_root, destination, identity)
        self.assertFalse((parent / "published").exists())
        self.assertTrue((run_root.output_parent / RUNNER._STAGED_OUTPUT_NAME).exists())

    def test_output_relocation_rejects_symlink_swap_and_no_clobbers(self) -> None:
        parent = self.base / "parent"
        alternate = self.base / "alternate"
        parent.mkdir()
        alternate.mkdir()
        destination = parent / "published"
        destination, identity = RUNNER._validate_output_destination(destination)
        original = self.base / "original-parent"
        parent.rename(original)
        parent.symlink_to(alternate, target_is_directory=True)
        run_root = self._run_root_with_staging()
        self.addCleanup(run_root.close)
        with self.assertRaises(RUNNER._bootstrap.BootstrapError):
            RUNNER._relocate_staged_output(run_root, destination, identity)
        self.assertFalse((alternate / "published").exists())

        parent.unlink()
        original.rename(parent)
        destination, identity = RUNNER._validate_output_destination(destination)
        destination.mkdir()
        with self.assertRaisesRegex(
            RUNNER._bootstrap.BootstrapError, "already exists"
        ):
            RUNNER._relocate_staged_output(run_root, destination, identity)
        self.assertTrue(destination.is_dir())
        self.assertTrue((run_root.output_parent / RUNNER._STAGED_OUTPUT_NAME).exists())

    def test_output_relocation_atomically_publishes_once(self) -> None:
        parent = self.base / "parent"
        parent.mkdir()
        destination, identity = RUNNER._validate_output_destination(
            parent / "published"
        )
        run_root = self._run_root_with_staging()
        self.addCleanup(run_root.close)
        self.assertTrue(
            RUNNER._relocate_staged_output(run_root, destination, identity)
        )
        self.assertEqual((destination / "result.json").read_text(), "{}\n")
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE((destination / "result.json").stat().st_mode), 0o600
        )
        self.assertFalse((run_root.output_parent / RUNNER._STAGED_OUTPUT_NAME).exists())

    def test_output_relocation_rejects_symlink_and_hardlink_entries(self) -> None:
        parent = self.base / "parent"
        parent.mkdir()
        destination, identity = RUNNER._validate_output_destination(
            parent / "published"
        )
        run_root = self._run_root_with_staging()
        self.addCleanup(run_root.close)
        staging = run_root.output_parent / RUNNER._STAGED_OUTPUT_NAME
        (staging / "unsafe-link").symlink_to(self.base / "outside")
        with self.assertRaisesRegex(
            RUNNER._bootstrap.BootstrapError, "unsafe entry type"
        ):
            RUNNER._relocate_staged_output(run_root, destination, identity)
        (staging / "unsafe-link").unlink()

        external = self.base / "external"
        external.write_text("private", encoding="utf-8")
        os.link(external, staging / "unsafe-hardlink")
        with self.assertRaisesRegex(
            RUNNER._bootstrap.BootstrapError, "unsafe file"
        ):
            RUNNER._relocate_staged_output(run_root, destination, identity)
        self.assertFalse(destination.exists())

    def test_adopted_root_rejects_wrong_token(self) -> None:
        run_root = RUNNER._bootstrap.DisposableRunRoot()
        self.addCleanup(run_root.close)
        with self.assertRaisesRegex(
            RUNNER._bootstrap.BootstrapError, "token does not match"
        ):
            RUNNER._bootstrap.DisposableRunRoot.adopt(
                run_root.base, token="0" * 32
            )

    def test_cli_bootstrap_failure_does_not_reflect_supplied_path(self) -> None:
        marker = "OFFICIAL-ROOT-SECRET-MARKER"
        completed = subprocess.run(
            [
                sys.executable,
                str(RUNNER_PATH),
                "--verify-only",
                "--official-root",
                str(self.base / marker),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn(marker, completed.stdout)
        self.assertNotIn(marker, completed.stderr)
        self.assertIn("bootstrap validation failed", completed.stderr)

    def test_harness_lifecycle_marks_and_closes_per_question_instances(self) -> None:
        built = []

        class FakeMemory:
            memory_type = "synapse_s2"

            def __init__(self, config):
                self.config = config
                self.close_count = 0
                self.image_path = None
                self.hook_saw_image = False
                self.image_consumed = False

            def post_query_hook(self):
                self.hook_saw_image = bool(
                    self.image_path is not None and self.image_path.is_file()
                )
                return {"release_state": "deferred-for-image-consumption"}

            def close(self):
                self.close_count += 1
                if self.image_path is not None:
                    self.image_path.unlink(missing_ok=True)

        module = types.SimpleNamespace()

        def inject(config, **_kwargs):
            return {
                "memory_type": config["memory_type"],
                "memory_params": dict(config["memory_params"]),
            }

        def build(config):
            memory = FakeMemory(config)
            built.append(memory)
            return memory

        def load(_input, requested_config=None):
            return build(requested_config)

        def per_question(*_args, **kwargs):
            config = module.inject_runtime_memory_params(
                {"memory_type": "synapse_s2", "memory_params": {}},
                workspace_dir=kwargs["workspace_dir"],
            )
            memory = module.build_memory(config)
            if kwargs.get("fail"):
                raise RuntimeError("synthetic query failure")
            image_path = kwargs.get("image_path")
            if isinstance(image_path, Path):
                image_path.write_bytes(b"bounded-thumbnail")
                memory.image_path = image_path
                memory.post_query_hook()
                memory.image_consumed = image_path.read_bytes() == b"bounded-thumbnail"
            return memory

        module.inject_runtime_memory_params = inject
        module.build_memory = build
        module.load_memory = load
        module.build_prompt_row_with_per_question_memory = per_question
        close_remaining = RUNNER._wire_harness_lifecycle(module)

        returned = module.build_prompt_row_with_per_question_memory(
            workspace_dir=self.base / "per-question"
        )
        self.assertTrue(
            returned.config["memory_params"]["release_after_query"]
        )
        self.assertEqual(returned.close_count, 1)

        image_path = self.base / "returned-thumbnail.jpg"
        image_returned = module.build_prompt_row_with_per_question_memory(
            workspace_dir=self.base / "image-question",
            image_path=image_path,
        )
        self.assertTrue(image_returned.hook_saw_image)
        self.assertTrue(image_returned.image_consumed)
        self.assertEqual(image_returned.close_count, 1)
        self.assertFalse(image_path.exists())

        with self.assertRaisesRegex(RuntimeError, "synthetic query failure"):
            module.build_prompt_row_with_per_question_memory(
                workspace_dir=self.base / "failing-question", fail=True
            )
        self.assertEqual(built[-1].close_count, 1)

        shared_config = module.inject_runtime_memory_params(
            {"memory_type": "synapse_s2", "memory_params": {}},
            workspace_dir=self.base / "shared",
        )
        shared = module.build_memory(shared_config)
        self.assertFalse(shared.config["memory_params"]["release_after_query"])
        self.assertEqual(shared.close_count, 0)
        close_remaining()
        self.assertEqual(shared.close_count, 1)
        self.assertIs(RUNNER._wire_harness_lifecycle(module), close_remaining)

    @unittest.skipUnless(
        OFFICIAL_ROOT.is_dir() and OFFICIAL_DEPS.is_dir(),
        "pinned official checkout and staged dependency fixture are required",
    )
    def test_repeated_bootstrap_accepts_own_cache_then_rejects_pollution(self) -> None:
        run_root = RUNNER._bootstrap.DisposableRunRoot()
        pycache = Path(tempfile.mkdtemp(prefix="cache-", dir=run_root.pycache_parent))
        os.chmod(pycache, 0o700)
        code = """
import sys, types
from official_longmem import bootstrap as b
b.activate_run_root(adopt=sys.argv[1], token=sys.argv[2])
try:
    b.bootstrap_official(sys.argv[3], deps_dir=sys.argv[4])
    b.bootstrap_official(sys.argv[3], deps_dir=sys.argv[4])
    poisoned = types.ModuleType('evaluation.poisoned')
    poisoned.__file__ = '/private/tmp/outside-poison.py'
    sys.modules['evaluation.poisoned'] = poisoned
    try:
        b.bootstrap_official(sys.argv[3], deps_dir=sys.argv[4])
    except b.BootstrapError:
        print('TWICE_OK_POLLUTION_REJECTED')
    else:
        raise SystemExit('polluted repeated bootstrap was accepted')
finally:
    b.deactivate_run_root()
"""
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        env["PYTHONPYCACHEPREFIX"] = str(pycache)
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                code,
                str(run_root.base),
                run_root.token,
                str(OFFICIAL_ROOT),
                str(OFFICIAL_DEPS),
            ],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        run_root.close()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("TWICE_OK_POLLUTION_REJECTED", completed.stdout)
        self.assertFalse(run_root.base.exists())

    @unittest.skipUnless(
        OFFICIAL_ROOT.is_dir() and OFFICIAL_DEPS.is_dir(),
        "pinned official checkout and staged dependency fixture are required",
    )
    def test_real_verify_only_has_no_run_root_or_pycache_residue(self) -> None:
        before = {path.name for path in Path("/private/tmp").glob("s2lm-*")}
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        env["LONGMEM_V2_OFFICIAL_ROOT"] = str(OFFICIAL_ROOT)
        env["LONGMEM_V2_OFFICIAL_DEPS"] = str(OFFICIAL_DEPS)
        completed = subprocess.run(
            [sys.executable, str(RUNNER_PATH), "--verify-only"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        after = {path.name for path in Path("/private/tmp").glob("s2lm-*")}
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn('"build_memory_resolved": "SynapseS2Memory"', completed.stdout)
        self.assertIn('"interpreter_isolated": true', completed.stdout)
        self.assertIn('"private_pycache_removed": true', completed.stderr)
        self.assertIn('"run_root_removed": true', completed.stderr)
        self.assertEqual(after - before, set())

    @unittest.skipUnless(
        OFFICIAL_ROOT.is_dir() and OFFICIAL_DEPS.is_dir(),
        "pinned official checkout and staged dependency fixture are required",
    )
    def test_real_skip_evaluation_run_publishes_native_output(self) -> None:
        questions = self.base / "official-questions.json"
        haystack = self.base / "official-haystack.json"
        trajectories = self.base / "official-trajectories.json"
        config = self.base / "synapse-config.json"
        output = self.base / "native-output"
        questions.write_text(
            json.dumps(
                [
                    {
                        "id": "q-1",
                        "question_type": "static-environment",
                        "eval_function": "norm_phrase_set_match",
                        "question": "Where is the red stapler?",
                        "answer": "desk",
                    }
                ]
            ),
            encoding="utf-8",
        )
        haystack.write_text(json.dumps({"q-1": ["trajectory-1"]}), encoding="utf-8")
        trajectories.write_text(
            json.dumps(
                [
                    {
                        "id": "trajectory-1",
                        "goal": "find office supplies",
                        "states": [
                            {
                                "url": "https://example.test/office",
                                "action": "inspect desk",
                                "thought": "look for the stapler",
                                "accessibility_tree": "The red stapler is on the desk.",
                            }
                        ],
                    }
                ]
            ),
            encoding="utf-8",
        )
        config.write_text(
            json.dumps(
                {
                    "memory_type": "synapse_s2",
                    "memory_params": {
                        "backend": {
                            "dimension": 32,
                            "num_neurons": 64,
                            "default_top_k": 8,
                            "recall_count": 16,
                            "embedding_provider": "semantic-hash",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        before = {path.name for path in Path("/private/tmp").glob("s2lm-*")}
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        env["LONGMEM_V2_OFFICIAL_ROOT"] = str(OFFICIAL_ROOT)
        env["LONGMEM_V2_OFFICIAL_DEPS"] = str(OFFICIAL_DEPS)
        completed = subprocess.run(
            [
                sys.executable,
                str(RUNNER_PATH),
                "--domain",
                "web",
                "--questions-path",
                str(questions),
                "--haystack-path",
                str(haystack),
                "--trajectories-path",
                str(trajectories),
                "--output-dir",
                str(output),
                "--memory-config-path",
                str(config),
                "--save-memory",
                "--skip-evaluation",
            ],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        after = {path.name for path in Path("/private/tmp").glob("s2lm-*")}
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue((output / "run_args.json").is_file())
        self.assertTrue((output / "memory_state").is_dir())
        self.assertIn('"output_relocated": true', completed.stderr)
        self.assertEqual(after - before, set())


if __name__ == "__main__":
    unittest.main()

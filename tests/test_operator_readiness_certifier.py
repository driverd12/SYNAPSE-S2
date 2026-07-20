import argparse
import json
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest import mock
import zipfile


from scripts.operator_readiness_certify import (
    CheckResult,
    OperatorReadinessCertifier,
    app_preview_status,
    choose_app,
    classify_overall,
    json_safe,
    render_runbook_markdown,
    render_summary_markdown,
    sanitize_evidence_text,
    write_private_text,
)


class OperatorReadinessCertifierTests(unittest.TestCase):
    @staticmethod
    def _args(default_output_dir: Path, **overrides):
        values = {
            "context": "default",
            "agent_id": "codex-desktop",
            "run_id": "operator-readiness-unit-test",
            "output_dir": str(default_output_dir),
            "launcher": str(default_output_dir / "synapse-s2-mcp"),
            "embedding_provider": "semantic-hash",
            "dimension": 1024,
            "neurons": 8192,
            "top_k": 256,
            "neural_model": "safe-local-model",
            "neural_cache_dir": str(default_output_dir / "models"),
            "neural_local_files_only": True,
            "app_name": "",
            "zip": False,
            "json": True,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_cli_commands_are_bound_to_certified_topology(self):
        with TemporaryDirectory() as tmp:
            certifier = OperatorReadinessCertifier(
                self._args(
                    Path(tmp),
                    dimension=768,
                    neurons=6800,
                    top_k=192,
                )
            )

            command = certifier._cli_command("doctor", "--context", "default")
            env = certifier._base_env()

        self.assertEqual(command[command.index("--dimension") + 1], "768")
        self.assertEqual(command[command.index("--neurons") + 1], "6800")
        self.assertEqual(command[command.index("--top-k") + 1], "192")
        self.assertEqual(env["SYNAPSE_S2_DIMENSION"], "768")
        self.assertEqual(env["SYNAPSE_S2_NEURONS"], "6800")
        self.assertEqual(env["SYNAPSE_S2_TOP_K"], "192")

    def test_private_evidence_writer_preserves_existing_parent_mode(self):
        with TemporaryDirectory() as tmp:
            parent = Path(tmp) / "caller-owned"
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            target = parent / "evidence.json"

            write_private_text(target, '{"safe": true}\n')

            self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_private_evidence_writer_preserves_original_on_replace_failure(self):
        with TemporaryDirectory() as tmp:
            parent = Path(tmp)
            target = parent / "evidence.json"
            target.write_text("original\n", encoding="utf-8")

            with (
                mock.patch(
                    "scripts.operator_readiness_certify.os.replace",
                    side_effect=OSError("synthetic replace failure"),
                ),
                self.assertRaisesRegex(OSError, "synthetic replace failure"),
            ):
                write_private_text(target, "replacement\n")

            self.assertEqual(target.read_text(encoding="utf-8"), "original\n")
            self.assertEqual(list(parent.glob(".evidence.json.*.tmp")), [])

    def test_certifier_rejects_secret_and_traversing_identifiers_before_write(self):
        marker = "SYNTHETIC_ONLY_READINESS_SECRET_42"
        with TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "evidence"
            for run_id in ("../escape", "nested/run", "/tmp/escape", ".", ".."):
                with self.subTest(run_id=run_id), self.assertRaisesRegex(
                    ValueError,
                    "one safe basename component",
                ):
                    OperatorReadinessCertifier(
                        self._args(output_root, run_id=run_id)
                    )

            sensitive_overrides = (
                {"run_id": f"password={marker}"},
                {"output_dir": str(Path(tmp) / f"api_key={marker}")},
                {"launcher": str(Path(tmp) / f"token={marker}")},
                {"embedding_provider": f"password={marker}"},
                {"neural_model": f"api_key={marker}"},
                {"neural_cache_dir": str(Path(tmp) / f"token={marker}")},
            )
            for overrides in sensitive_overrides:
                with self.subTest(overrides=tuple(overrides)), self.assertRaisesRegex(
                    ValueError,
                    "must not contain credential material",
                ):
                    OperatorReadinessCertifier(
                        self._args(output_root, **overrides)
                    )

            sensitive_target = Path(tmp) / f"password={marker}"
            sensitive_target.mkdir()
            safe_alias = Path(tmp) / "safe-output-alias"
            safe_alias.symlink_to(sensitive_target, target_is_directory=True)
            with self.assertRaisesRegex(
                ValueError,
                "must not contain credential material",
            ):
                OperatorReadinessCertifier(
                    self._args(output_root, output_dir=str(safe_alias))
                )

            self.assertFalse(output_root.exists())

    def test_json_safe_redacts_secrets_and_removes_raw_digest_oracles(self):
        marker = "sk-synthetic-evidence-secret-1234567890"
        raw_digest = "a" * 64

        rendered = json_safe(
            {
                "safe": True,
                "nested": {
                    "input_sha256": raw_digest,
                    "message": f"api_key={marker}",
                    "note": f"input_sha256={raw_digest}",
                },
                "items": [{"payload_sha256": raw_digest, "count": 3}],
            }
        )
        serialized = json.dumps(rendered, sort_keys=True)

        self.assertNotIn(marker, serialized)
        self.assertNotIn(raw_digest, serialized)
        self.assertNotIn("input_sha256", serialized)
        self.assertNotIn("payload_sha256", serialized)
        self.assertIn("[REMOVED_RAW_DIGEST_FIELD]", serialized)
        self.assertIn("[REDACTED_SECRET]", serialized)
        fallback = sanitize_evidence_text(
            f"diagnostic input_sha256={raw_digest} api_key={marker}"
        )
        self.assertNotIn(raw_digest, fallback)
        self.assertNotIn("input_sha256", fallback)
        self.assertNotIn(marker, fallback)

    def test_command_json_is_sanitized_before_artifact_persistence(self):
        marker = "sk-synthetic-command-secret-1234567890"
        raw_digest = "b" * 64
        with TemporaryDirectory() as tmp:
            certifier = OperatorReadinessCertifier(self._args(Path(tmp)))
            certifier.pack_dir.mkdir(mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            completed = __import__("subprocess").CompletedProcess(
                ["synthetic"],
                0,
                stdout=json.dumps(
                    {
                        "ready": True,
                        "input_sha256": raw_digest,
                        "nested": {"api_key": marker},
                    }
                ),
                stderr="",
            )

            with mock.patch(
                "scripts.operator_readiness_certify.subprocess.run",
                return_value=completed,
            ):
                result = certifier._run_command(
                    "synthetic",
                    label="Synthetic command",
                    command=["synthetic"],
                    required=True,
                    timeout=1,
                    evaluator=lambda *_: ("ready", "safe", "", {}),
                )

            artifact_text = "\n".join(
                Path(path).read_text(encoding="utf-8")
                for path in result.artifact_paths.values()
            )
            self.assertNotIn(marker, artifact_text)
            self.assertNotIn(raw_digest, artifact_text)
            self.assertNotIn("input_sha256", artifact_text)
            self.assertIn("[REDACTED_SECRET]", artifact_text)
            self.assertNotIn("input_sha256", result.parsed)

    def test_json_artifacts_and_zip_remain_parseable_after_string_sanitization(self):
        raw_digest = "d" * 64
        with TemporaryDirectory() as tmp:
            certifier = OperatorReadinessCertifier(
                self._args(Path(tmp), zip=True)
            )
            certifier.pack_dir.mkdir(mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            certifier.metadata = {
                "run_id": certifier.run_id,
                "context_id": certifier.context,
                "agent_id": certifier.agent_id,
                "embedding_provider": "semantic-hash",
                "nested": {"note": f"input_sha256={raw_digest}"},
            }

            result = certifier._finalize()
            manifest_text = Path(result["manifest_path"]).read_text(
                encoding="utf-8"
            )
            manifest = json.loads(manifest_text)
            self.assertIn("[REMOVED_RAW_DIGEST_FIELD]", manifest["nested"]["note"])
            self.assertNotIn(raw_digest, manifest_text)

            with zipfile.ZipFile(result["archive_path"]) as archive:
                for name in archive.namelist():
                    if name.endswith(".json"):
                        archived = archive.read(name).decode("utf-8")
                        json.loads(archived)
                        self.assertNotIn(raw_digest, archived)

    def test_final_zip_contains_only_private_sanitized_run_artifacts(self):
        marker = "sk-synthetic-zip-secret-1234567890"
        raw_digest = "c" * 64
        with TemporaryDirectory() as tmp:
            certifier = OperatorReadinessCertifier(
                self._args(Path(tmp), zip=True)
            )
            certifier.output_root.chmod(0o755)
            certifier.pack_dir.mkdir(mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            certifier.metadata = {
                "run_id": certifier.run_id,
                "context_id": certifier.context,
                "agent_id": certifier.agent_id,
                "git": {"head": "abc123"},
                "embedding_provider": "semantic-hash",
                "input_sha256": raw_digest,
            }
            certifier.results = [
                CheckResult(
                    check_id="memory_write",
                    label="Memory write",
                    status="ready",
                    required=True,
                    detail=f"api_key={marker}",
                    metrics={"payload_sha256": raw_digest, "safe": True},
                )
            ]
            rogue = certifier.pack_dir / "untracked.txt"
            rogue.write_text(f"api_key={marker}", encoding="utf-8")

            result = certifier._finalize()
            archive_path = Path(result["archive_path"])

            self.assertEqual(stat.S_IMODE(archive_path.stat().st_mode), 0o600)
            with zipfile.ZipFile(archive_path) as archive:
                self.assertNotIn("untracked.txt", archive.namelist())
                payload = b"\n".join(
                    archive.read(name) for name in archive.namelist()
                ).decode("utf-8")
                for info in archive.infolist():
                    self.assertEqual((info.external_attr >> 16) & 0o777, 0o600)
            self.assertNotIn(marker, payload)
            self.assertNotIn(raw_digest, payload)
            self.assertNotIn("input_sha256", payload)
            self.assertNotIn("payload_sha256", payload)
            for evidence_path in certifier._evidence_files:
                self.assertEqual(
                    stat.S_IMODE(evidence_path.stat().st_mode),
                    0o600,
                )

    def test_choose_app_prefers_requested_then_high_signal_defaults(self):
        apps = [
            {"app_name": "Slack", "pid": 1},
            {"app_name": "Google Chrome", "pid": 2},
            {"app_name": "Terminal", "pid": 3},
        ]

        self.assertEqual(choose_app(apps, preferred="Terminal")["app_name"], "Terminal")
        self.assertEqual(choose_app(apps)["app_name"], "Google Chrome")
        self.assertIsNone(choose_app([]))

    def test_app_preview_status_accepts_honest_blocked_preview_without_memory_write(self):
        parsed = {
            "action": "preview-app-snapshot",
            "app_name": "Codex",
            "writes_memory": False,
            "snapshot_quality": {
                "signal_chars": 0,
                "quality": "blocked",
                "blocked_reason": "Accessibility blocked this app",
            },
            "quality_badge": {
                "status": "blocked",
                "label": "Accessibility blocked",
                "next_action": "Use selected-text capture.",
            },
            "capability_badge": {
                "level": "selection_capture_recommended",
                "label": "Selection capture recommended",
            },
            "capture_guidance": [
                "Select the useful text in Codex, then run selected-text capture.",
            ],
        }

        status, detail, repair, metrics = app_preview_status(parsed)

        self.assertEqual(status, "ready")
        self.assertIn("writes_memory=false", detail)
        self.assertIn("selected-text", repair)
        self.assertEqual(metrics["quality_status"], "blocked")
        self.assertFalse(metrics["writes_memory"])

    def test_app_preview_status_blocks_silent_or_mutating_preview(self):
        status, detail, _, _ = app_preview_status(
            {
                "action": "preview-app-snapshot",
                "writes_memory": True,
                "quality_badge": {"status": "ready"},
                "capability_badge": {"level": "rich_text_available"},
            }
        )

        self.assertEqual(status, "blocked")
        self.assertIn("wrote memory", detail)

    def test_summary_and_runbook_make_required_failures_visible(self):
        results = [
            CheckResult(
                check_id="memory_write",
                label="Memory write",
                status="ready",
                required=True,
                detail="Wrote trace readiness as s2_123.",
            ),
            CheckResult(
                check_id="dashboard",
                label="Dashboard render smoke",
                status="blocked",
                required=True,
                detail="Dashboard warning tokens found.",
                repair="Fix dashboard warnings.",
            ),
        ]
        manifest = {
            "run_id": "operator-readiness-test",
            "context_id": "demo",
            "agent_id": "codex-desktop",
            "overall_status": classify_overall(results),
            "operator_trustworthy": False,
            "required_ready": 1,
            "required_total": 2,
            "git": {"head": "abc123"},
            "embedding_provider": "mlx-neural",
        }

        summary = render_summary_markdown(manifest, results)
        runbook = render_runbook_markdown(manifest)

        self.assertEqual(manifest["overall_status"], "blocked")
        self.assertIn("Operator trustworthy: `false`", summary)
        self.assertIn("Fix dashboard warnings.", summary)
        self.assertIn("scripts/operator_readiness_certify.py", runbook)
        self.assertIn("--embedding-provider mlx-neural", runbook)

    def test_pack_summary_is_json_serializable_shape(self):
        result = CheckResult(
            check_id="recall",
            label="Recall proof",
            status="ready",
            required=True,
            detail="Recall returned the readiness write.",
            metrics={"matched_evidence": ["s2_123"]},
        )

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps({"checks": [result.to_manifest()]}), encoding="utf-8")
            loaded = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(loaded["checks"][0]["check_id"], "recall")
        self.assertEqual(loaded["checks"][0]["metrics"]["matched_evidence"], ["s2_123"])


if __name__ == "__main__":
    unittest.main()

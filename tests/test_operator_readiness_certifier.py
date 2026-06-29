import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


from scripts.operator_readiness_certify import (
    CheckResult,
    app_preview_status,
    choose_app,
    classify_overall,
    render_runbook_markdown,
    render_summary_markdown,
)


class OperatorReadinessCertifierTests(unittest.TestCase):
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

import unittest

from scripts.synapse_status_report import render_status_markdown, sorted_context_rows


class SynapseStatusReportTests(unittest.TestCase):
    def test_sorted_context_rows_keeps_default_first(self):
        rows = sorted_context_rows({"servus": 3, "default": 10, "james": 2})

        self.assertEqual(rows[0], ("default", 10))
        self.assertEqual(rows[1:], [("james", 2), ("servus", 3)])

    def test_status_report_renders_current_features_stack_and_non_claims(self):
        markdown = render_status_markdown(
            {
                "generated_at": "2026-07-01T08:55:00-06:00",
                "context_id": "default",
                "agent_id": "codex-desktop",
                "status": {
                    "runtime": "ready",
                    "effective_enabled": True,
                    "num_neurons": 8192,
                    "default_top_k": 256,
                    "dimension": 1024,
                    "memory_context_entry_count": 1507,
                    "memory_context_relationship_count": 2480,
                    "context_bus_latest_event_id": 2280,
                    "memory_contexts": {
                        "servus-hydrated-handoff-20260630": 252,
                        "default": 1507,
                    },
                    "embedding_provider": {
                        "provider": "mlx-neural-v1",
                        "provider_type": "mlx-neural",
                        "model_id": "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ",
                        "native_mlx": True,
                        "semantic": True,
                    },
                },
                "profile": {
                    "estimated_total_mb": 288.09375,
                    "target_envelope_mb": {"min": 96.0, "max": 384.0},
                    "within_target_envelope": True,
                    "quick_pruning": {
                        "within_60ms_budget": True,
                        "elapsed_ms": 46.785,
                        "budget_ms": 60.0,
                    },
                },
                "doctor": {"overall_status": "ready", "repair_plan": []},
                "context_health": {"status": "ready", "score": 96},
                "memory_hygiene": {
                    "memory_quality_score": 78,
                    "backlog_count": 64,
                    "queue_summary": {"duplicate_candidate": 63},
                },
                "cortex_state": {"active_session_count": 0, "goal_count": 1},
                "git": {
                    "branch": "main",
                    "head": "abc1234",
                    "dirty": True,
                    "remotes": ["origin", "github-kolonelpanik"],
                },
            }
        )

        self.assertIn("# SYNAPSE-S2 Current Status", markdown)
        self.assertIn("mlx-neural-v1", markdown)
        self.assertIn("8,192", markdown)
        self.assertIn("288.1 MB", markdown)
        self.assertIn("| default | 1,507 |", markdown)
        self.assertIn("Saved namespace menu", markdown)
        self.assertIn("Start Work", markdown)
        self.assertIn("Cross-process Cortex closure", markdown)
        self.assertIn("App Connect preview", markdown)
        self.assertIn("Known Non-Claims", markdown)
        self.assertIn("App Connect is not guaranteed internal app scraping", markdown)
        self.assertIn("Memory hygiene backlog", markdown)
        self.assertIn("Source checkout at generation", markdown)
        self.assertIn("final commit position", markdown)


if __name__ == "__main__":
    unittest.main()

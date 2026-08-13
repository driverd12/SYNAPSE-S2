from __future__ import annotations

import json
import math
import multiprocessing
import os
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import impact_metrics
from impact_metrics import ImpactMetricsError, ImpactMetricsStore


def _concurrent_recorder(data_root: str, count: int, worker_index: int) -> None:
    store = ImpactMetricsStore(data_root)
    for index in range(count):
        store.record_dashboard_recall(
            succeeded=True,
            latency_ms=float((worker_index * count) + index + 1),
            result_count=1,
            bridge_eligible=False,
            connected_assist=False,
            graph_assist=False,
            response_bytes=8,
        )


class ImpactMetricsTests(unittest.TestCase):
    def make_store(self, temporary: str) -> ImpactMetricsStore:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        return ImpactMetricsStore(root)

    def test_empty_projection_is_truthful_and_cost_is_disabled(self) -> None:
        with TemporaryDirectory() as temporary:
            store = self.make_store(temporary)
            projected = store.project()

        self.assertEqual(projected["schema"], impact_metrics.PROJECTION_SCHEMA)
        self.assertEqual(projected["coverage"]["scope"], "dashboard-recall-only")
        self.assertTrue(projected["coverage"]["content_free"])
        self.assertEqual(projected["recall"]["attempt_count"], 0)
        self.assertIsNone(projected["recall"]["error_rate"])
        self.assertIsNone(projected["recall"]["result_yield"]["ratio"])
        self.assertIsNone(
            projected["assistance"]["connected_assist_rate"]["ratio"]
        )
        self.assertIsNone(projected["performance"]["latency_ms"]["p50"])
        self.assertIsNone(projected["performance"]["latency_ms"]["p95"])
        self.assertFalse(projected["cost"]["enabled"])
        self.assertIsNone(
            projected["cost"]["estimated_model_input_equivalent_cost_usd"]
        )
        self.assertFalse(projected["cost"]["savings_available"])
        self.assertIsNone(projected["cost"]["estimated_input_cost_avoided_usd"])
        caveats = " ".join(projected["caveats"]).lower()
        self.assertIn("does not measure correctness", caveats)
        self.assertIn("no measured no-synapse counterfactual", caveats)
        self.assertIn("response ceiling is not actual savings", caveats)
        self.assertIn("dashboard responses may never enter a model context", caveats)

    def test_records_recall_outcomes_and_projects_exact_formulas(self) -> None:
        with TemporaryDirectory() as temporary:
            store = self.make_store(temporary)
            store.record_dashboard_recall(
                succeeded=True,
                latency_ms=10,
                result_count=2,
                bridge_eligible=True,
                connected_assist=True,
                response_bytes=101,
                recorded_at=0,
            )
            store.record_dashboard_recall(
                succeeded=True,
                latency_ms=30,
                result_count=0,
                bridge_eligible=True,
                response_bytes=40,
                estimated_tokens=10,
                recorded_at=200,
            )
            store.record_dashboard_recall(
                succeeded=False,
                latency_ms=50,
                response_bytes=20,
                recorded_at=300,
            )
            store.record_dashboard_recall(
                succeeded=True,
                latency_ms=20,
                result_count=1,
                graph_assist=True,
                response_bytes=4,
                recorded_at=50,
            )

            aggregate = store.load()
            projected = store.project(input_price_per_million_tokens=5.0)
            store_mode = stat.S_IMODE(store.path.lstat().st_mode)
            directory_mode = stat.S_IMODE(store.store_directory.lstat().st_mode)
            lock_mode = stat.S_IMODE(store.lock_path.lstat().st_mode)

        recall = aggregate["dashboard_recall"]
        self.assertEqual(recall["attempt_count"], 4)
        self.assertEqual(recall["completed_count"], 3)
        self.assertEqual(recall["error_count"], 1)
        self.assertEqual(recall["nonempty_result_count"], 2)
        self.assertEqual(recall["result_count_total"], 3)
        self.assertEqual(recall["bridge_eligible_count"], 2)
        self.assertEqual(recall["connected_assist_count"], 1)
        self.assertEqual(recall["graph_assist_count"], 1)
        self.assertEqual(recall["response_bytes_total"], 165)
        self.assertEqual(recall["estimated_tokens_total"], 42)
        self.assertEqual(aggregate["coverage"]["first_recorded_at"], 0.0)
        self.assertEqual(aggregate["coverage"]["updated_at"], 300.0)

        self.assertEqual(projected["recall"]["error_rate"], 0.25)
        self.assertEqual(projected["recall"]["result_yield"]["ratio"], 0.666667)
        self.assertEqual(
            projected["recall"]["mean_results_per_completed_recall"],
            1.0,
        )
        self.assertEqual(
            projected["assistance"]["connected_assist_rate"]["ratio"],
            0.5,
        )
        self.assertEqual(
            projected["assistance"]["graph_assist_rate"]["ratio"],
            0.333333,
        )
        latency = projected["performance"]["latency_ms"]
        self.assertEqual(latency["sample_count"], 4)
        self.assertEqual(latency["p50"], 20.0)
        self.assertEqual(latency["p95"], 50.0)
        self.assertEqual(latency["mean"], 27.5)
        self.assertEqual(latency["minimum"], 10.0)
        self.assertEqual(latency["maximum"], 50.0)
        self.assertTrue(projected["cost"]["enabled"])
        self.assertEqual(
            projected["cost"]["estimated_model_input_equivalent_cost_usd"],
            0.00021,
        )
        self.assertIn("not an observed bill", projected["cost"]["basis"])
        self.assertFalse(projected["cost"]["savings_available"])
        self.assertEqual(store_mode, 0o600)
        self.assertEqual(directory_mode, 0o700)
        self.assertEqual(lock_mode, 0o600)

    def test_latency_history_is_a_bounded_recent_ring(self) -> None:
        with TemporaryDirectory() as temporary:
            store = self.make_store(temporary)
            for value in range(impact_metrics.LATENCY_SAMPLE_LIMIT + 3):
                store.record_dashboard_recall(
                    succeeded=True,
                    latency_ms=float(value),
                    result_count=0,
                    response_bytes=0,
                )
            aggregate = store.load()
            projected = store.project()

        samples = aggregate["dashboard_recall"]["latency_samples_ms"]
        self.assertEqual(len(samples), impact_metrics.LATENCY_SAMPLE_LIMIT)
        self.assertEqual(samples[0], 3.0)
        self.assertEqual(samples[-1], 130.0)
        latency = projected["performance"]["latency_ms"]
        self.assertTrue(latency["bounded_recent_window"])
        self.assertEqual(latency["sample_count"], impact_metrics.LATENCY_SAMPLE_LIMIT)
        self.assertEqual(latency["p50"], 66.0)
        self.assertEqual(latency["p95"], 124.0)

    def test_concurrent_recorders_do_not_lose_updates(self) -> None:
        with TemporaryDirectory() as temporary:
            store = self.make_store(temporary)
            worker_count = 4
            records_per_worker = 12
            context = multiprocessing.get_context("fork")
            workers = [
                context.Process(
                    target=_concurrent_recorder,
                    args=(str(store.data_root), records_per_worker, worker_index),
                )
                for worker_index in range(worker_count)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=20)
            exit_codes = [worker.exitcode for worker in workers]
            aggregate = store.load()

        self.assertEqual(exit_codes, [0] * worker_count)
        expected = worker_count * records_per_worker
        recall = aggregate["dashboard_recall"]
        self.assertEqual(recall["attempt_count"], expected)
        self.assertEqual(recall["completed_count"], expected)
        self.assertEqual(recall["error_count"], 0)
        self.assertEqual(recall["result_count_total"], expected)
        self.assertEqual(recall["response_bytes_total"], expected * 8)
        self.assertEqual(recall["estimated_tokens_total"], expected * 2)
        self.assertEqual(len(recall["latency_samples_ms"]), expected)

    def test_malformed_outcomes_fail_without_mutating_aggregate(self) -> None:
        invalid_outcomes = (
            {"succeeded": 1, "latency_ms": 1},
            {"succeeded": True, "latency_ms": -1},
            {"succeeded": True, "latency_ms": math.nan},
            {"succeeded": True, "latency_ms": 1, "result_count": True},
            {"succeeded": True, "latency_ms": 1, "result_count": -1},
            {"succeeded": True, "latency_ms": 1, "response_bytes": -1},
            {
                "succeeded": True,
                "latency_ms": 1,
                "response_bytes": 8,
                "estimated_tokens": 3,
            },
            {
                "succeeded": True,
                "latency_ms": 1,
                "connected_assist": True,
                "result_count": 1,
            },
            {
                "succeeded": True,
                "latency_ms": 1,
                "bridge_eligible": True,
                "connected_assist": True,
                "result_count": 0,
            },
            {
                "succeeded": True,
                "latency_ms": 1,
                "graph_assist": True,
                "result_count": 0,
            },
            {"succeeded": False, "latency_ms": 1, "result_count": 1},
            {"succeeded": False, "latency_ms": 1, "bridge_eligible": True},
        )
        with TemporaryDirectory() as temporary:
            store = self.make_store(temporary)
            for outcome in invalid_outcomes:
                with self.subTest(outcome=outcome):
                    with self.assertRaises(ImpactMetricsError):
                        store.record_dashboard_recall(**outcome)
            aggregate = store.load()

        self.assertEqual(aggregate["dashboard_recall"]["attempt_count"], 0)

    def test_invalid_prices_are_rejected_and_zero_rate_is_explicitly_enabled(self) -> None:
        with TemporaryDirectory() as temporary:
            store = self.make_store(temporary)
            for price in (-1, math.nan, math.inf, True, "5"):
                with self.subTest(price=price):
                    with self.assertRaises(ImpactMetricsError):
                        store.project(input_price_per_million_tokens=price)
            zero = store.project(input_price_per_million_tokens=0.0)

        self.assertTrue(zero["cost"]["enabled"])
        self.assertEqual(
            zero["cost"]["estimated_model_input_equivalent_cost_usd"],
            0.0,
        )
        self.assertFalse(zero["cost"]["savings_available"])

    def test_malformed_or_content_bearing_store_is_not_overwritten(self) -> None:
        with TemporaryDirectory() as temporary:
            store = self.make_store(temporary)
            malformed = b'{"prompt":"must-not-be-accepted"}\n'
            store.path.write_bytes(malformed)
            store.path.chmod(0o600)

            with self.assertRaises(ImpactMetricsError):
                store.load()
            with self.assertRaises(ImpactMetricsError):
                store.record_dashboard_recall(
                    succeeded=True,
                    latency_ms=1,
                    response_bytes=0,
                )
            after = store.path.read_bytes()

        self.assertEqual(after, malformed)

    def test_store_payload_has_only_fixed_content_free_fields(self) -> None:
        with TemporaryDirectory() as temporary:
            store = self.make_store(temporary)
            store.record_dashboard_recall(
                succeeded=True,
                latency_ms=12.5,
                result_count=2,
                bridge_eligible=True,
                connected_assist=True,
                graph_assist=True,
                response_bytes=64,
            )
            payload = json.loads(store.path.read_text(encoding="utf-8"))
            serialized = json.dumps(payload, sort_keys=True)

        self.assertEqual(
            set(payload),
            {"schema", "version", "coverage", "dashboard_recall"},
        )
        self.assertNotIn("prompt", serialized)
        self.assertNotIn("context_id", serialized)
        self.assertNotIn("memory_id", serialized)
        self.assertNotIn("excerpt", serialized)

    def test_root_and_store_permissions_fail_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o755)
            with self.assertRaises(ImpactMetricsError):
                ImpactMetricsStore(root)
            root.chmod(0o700)
            store = ImpactMetricsStore(root)
            store.record_dashboard_recall(
                succeeded=True,
                latency_ms=1,
                response_bytes=0,
            )
            store.path.chmod(0o644)
            with self.assertRaises(ImpactMetricsError):
                store.load()

        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            link = root.parent / f"{root.name}-impact-link"
            try:
                link.symlink_to(root, target_is_directory=True)
                with self.assertRaises(ImpactMetricsError):
                    ImpactMetricsStore(link)
            finally:
                link.unlink(missing_ok=True)

        with self.assertRaises(ImpactMetricsError):
            ImpactMetricsStore(Path("relative-data-root"))


if __name__ == "__main__":
    unittest.main()

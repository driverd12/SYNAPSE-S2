from __future__ import annotations

import contextlib
import copy
import io
import json
import math
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import measure_retrieval_v2 as measurement


class _StepTimer:
    def __init__(self, step_ns: int = 1_000_000) -> None:
        self.current = 0
        self.step_ns = step_ns

    def __call__(self) -> int:
        self.current += self.step_ns
        return self.current


class RetrievalV2MeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = measurement.run_acceptance_benchmark(
            code_commit="deadbeef",
            source_snapshot="fixture-snapshot-v1",
            latency_samples=2,
            timer=_StepTimer(),
        )
        cls.fixture = measurement.load_fixture()

    def test_report_passes_with_complete_methodology_and_metrics(self) -> None:
        report = self.report
        self.assertEqual(report["schema"], measurement.REPORT_SCHEMA)
        self.assertEqual(report["version"], measurement.REPORT_VERSION)
        self.assertEqual(report["status"], "pass")
        self.assertTrue(report["acceptance"]["accepted"])
        self.assertEqual(report["aggregate"]["verdict"], "pass")
        self.assertIn("does not prove retrieval quality", report["synthetic_benchmark_notice"])
        self.assertIn(report["synthetic_benchmark_notice"], report["limitations"])
        self.assertTrue(report["run_identity"]["offline"])
        self.assertTrue(report["run_identity"]["temporary_store"])
        self.assertEqual(report["run_identity"]["embedding_provider"], "semantic-hash")
        self.assertEqual(report["run_identity"]["code_commit"], "deadbeef")
        self.assertEqual(report["run_identity"]["source_snapshot"], "fixture-snapshot-v1")

        population = report["population"]
        self.assertGreaterEqual(population["namespaces"], 3)
        self.assertTrue(
            measurement.REQUIRED_CATEGORIES.issubset(population["category_counts"])
        )
        self.assertEqual(population["queries"], len(report["per_query"]))
        for name in (
            "recall_at_k",
            "ndcg_at_k",
            "mrr",
            "namespace_leakage_rate",
            "duplicate_rate",
            "result_bytes",
            "result_set_bytes",
            "component_signal_coverage",
            "p50_p95_latency_ms",
        ):
            self.assertIn(name, report["metric_definitions"])

        aggregate = report["aggregate"]
        self.assertGreaterEqual(aggregate["metrics"]["macro_recall_at_k"], 0.8)
        self.assertGreaterEqual(aggregate["metrics"]["macro_ndcg_at_k"], 0.75)
        self.assertGreaterEqual(aggregate["metrics"]["macro_mrr"], 0.75)
        self.assertEqual(aggregate["metrics"]["namespace_leakage_count"], 0)
        self.assertEqual(aggregate["metrics"]["duplicate_memory_id_count"], 0)
        self.assertEqual(aggregate["metrics"]["duplicate_rate"], 0.0)
        self.assertGreater(aggregate["metrics"]["source_content_deduplications"], 0)
        self.assertEqual(aggregate["metrics"]["confidence_violation_count"], 0)
        self.assertEqual(aggregate["metrics"]["score_contract_violation_count"], 0)
        self.assertEqual(aggregate["metrics"]["scope_provenance_violation_count"], 0)
        self.assertTrue(
            all(value > 0 for value in aggregate["component_signal_coverage"].values())
        )
        self.assertEqual(
            aggregate["latency_ms"]["samples"],
            2 * population["queries"],
        )
        self.assertEqual(aggregate["latency_ms"]["p50"], 1.0)
        self.assertEqual(aggregate["latency_ms"]["p95"], 1.0)
        self.assertTrue(aggregate["latency_ms"]["informational_only"])
        self.assertTrue(aggregate["latency_ms"]["excluded_from_acceptance"])
        self.assertGreater(aggregate["result_sizes_bytes"]["result"]["min"], 0)
        self.assertGreater(aggregate["result_sizes_bytes"]["result_set"]["min"], 0)

        for query in report["per_query"]:
            self.assertGreater(query["bytes"]["result"], query["bytes"]["result_set"])
            self.assertEqual(query["bytes"]["serializer"], "canonical-json-utf8")
            self.assertEqual(query["metrics"]["namespace_leakage_count"], 0)
            self.assertFalse(query["confidence_violations"])
            self.assertFalse(query["score_contract_violations"])
            self.assertFalse(query["scope_provenance_violations"])
            for item in query["retrieved"]:
                self.assertIs(item["confidence"]["calibrated"], False)
                self.assertIsNone(item["confidence"]["probability"])

    def test_fixture_connected_scope_uses_governed_bridge_projection(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            backend = measurement._make_backend(root, self.fixture)
            try:
                measurement.populate_fixture(backend, self.fixture)
                resolved = backend.resolve_recall_contexts(
                    context_id="control-room",
                    recall_scope="connected",
                )
                self.assertIn(
                    "ptz-camera",
                    {str(item["context_id"]) for item in resolved},
                )
                self.assertEqual(
                    backend.bridge_governance.audit_integrity()["status"],
                    "ready",
                )
                result = measurement._query_call(
                    backend,
                    self.fixture["queries"][0],
                )
                self.assertTrue(
                    any(
                        float(
                            item["score_breakdown"]["signals"][
                                "same_context_graph"
                            ]
                        )
                        > 0.0
                        for item in result["items"]
                    )
                )
            finally:
                backend.memory_store.close()

    def test_determinism_matrix_purity_and_over_cap_ties_are_proven(self) -> None:
        determinism = self.report["aggregate"]["determinism"]
        self.assertTrue(determinism["canonical_digest_all_equal"])
        self.assertTrue(determinism["fresh_backend_raw_equal"])
        self.assertTrue(determinism["randomized_insertion_raw_equal"])
        self.assertTrue(determinism["repeated_same_backend_raw_equal"])
        self.assertEqual(
            len(
                {
                    determinism["baseline_digest"],
                    determinism["fresh_backend_digest"],
                    determinism["randomized_insertion_digest"],
                }
            ),
            1,
        )

        purity = self.report["aggregate"]["purity"]
        self.assertTrue(purity["all_runs_unchanged"])
        for run in purity["runs"].values():
            self.assertTrue(run["unchanged"])
            self.assertEqual(run["before"], run["after"])
            self.assertIn("database_logical_sha256", run["before"])

        tie_documents = [
            document
            for document in self.fixture["documents"]
            if document.get("tie_group") == "over-source-limit-tie"
        ]
        tie_query_fixture = next(
            query
            for query in self.fixture["queries"]
            if query["query_id"] == "deterministic-tie-order"
        )
        source_limit = max(
            tie_query_fixture["result_limit"],
            (tie_query_fixture["candidate_limit"] + 1) // 2,
        )
        self.assertGreater(len(tie_documents), source_limit)
        tie_evidence = next(
            query
            for query in self.report["per_query"]
            if query["query_id"] == "deterministic-tie-order"
        )
        returned_ids = [item["memory_id"] for item in tie_evidence["retrieved"]]
        self.assertEqual(returned_ids, sorted(returned_ids))
        self.assertEqual(tie_evidence["metrics"]["recall_at_k"], 1.0)
        self.assertFalse(tie_evidence["tie_ordering_violations"])

    def test_every_required_failure_condition_closes_the_gate(self) -> None:
        mutations = {
            "namespace-scope-no-leakage": lambda value: value["metrics"].update(
                namespace_leakage_count=1,
                namespace_leakage_rate=0.1,
            ),
            "retrieval-is-pure": lambda value: value["purity"].update(
                all_runs_unchanged=False
            ),
            "canonical-output-deterministic": lambda value: value["determinism"].update(
                canonical_digest_all_equal=False
            ),
            "duplicate-memory-ids-absent": lambda value: value["metrics"].update(
                duplicate_memory_id_count=1
            ),
            "duplicate-content-rate": lambda value: value["metrics"].update(
                duplicate_rate=0.1
            ),
            "confidence-remains-uncalibrated": lambda value: value["metrics"].update(
                confidence_violation_count=1
            ),
            "score-breakdown-contract-valid": lambda value: value["metrics"].update(
                score_contract_violation_count=1
            ),
            "fixture-recall-at-k": lambda value: value["metrics"].update(
                macro_recall_at_k=0.0
            ),
        }
        for expected_failure, mutate in mutations.items():
            with self.subTest(expected_failure=expected_failure):
                aggregate = copy.deepcopy(self.report["aggregate"])
                mutate(aggregate)
                verdict = measurement.acceptance_verdict(
                    aggregate,
                    self.report["thresholds"],
                )
                self.assertFalse(verdict["accepted"])
                self.assertEqual(verdict["verdict"], "fail")
                self.assertIn(expected_failure, verdict["failure_codes"])

    def test_fixture_validation_and_metric_helpers_fail_closed(self) -> None:
        self.assertAlmostEqual(
            measurement._dcg([3, 2]),
            7.0 + 3.0 / math.log2(3),
        )
        self.assertEqual(measurement._nearest_rank_percentile([1, 2, 3, 4], 0.5), 2.0)
        self.assertEqual(measurement._nearest_rank_percentile([1, 2, 3, 4], 0.95), 4.0)
        self.assertIsNone(measurement._nearest_rank_percentile([], 0.95))
        with self.assertRaises(measurement.MeasurementError):
            measurement.run_acceptance_benchmark(latency_samples=0)
        with self.assertRaises(measurement.MeasurementError):
            measurement.run_acceptance_benchmark(code_commit="unsafe identity with spaces")

        invalid = copy.deepcopy(self.fixture)
        for document in invalid["documents"]:
            document["categories"] = [
                category
                for category in document["categories"]
                if category != "near-duplicate"
            ]
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid-fixture.json"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(
                measurement.MeasurementError,
                "lacks required categories",
            ):
                measurement.load_fixture(path)

    def test_output_is_canonical_private_and_failure_artifacts_are_written(self) -> None:
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "retrieval-v2.json"
            written = measurement.write_report(self.report, output)
            expected = measurement.canonical_json_bytes(self.report) + b"\n"
            self.assertEqual(written, output.absolute())
            self.assertEqual(output.read_bytes(), expected)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            measurement.write_report(self.report, output)
            self.assertEqual(output.read_bytes(), expected)

            failed = copy.deepcopy(self.report)
            failed["status"] = "fail"
            failed["aggregate"]["verdict"] = "fail"
            failed["acceptance"] = {
                "accepted": False,
                "verdict": "fail",
                "checks": [],
                "failure_codes": ["injected-test-failure"],
            }
            failed_output = Path(temporary) / "failed.json"
            captured = io.StringIO()
            with (
                mock.patch.object(
                    measurement,
                    "run_acceptance_benchmark",
                    return_value=failed,
                ) as runner,
                contextlib.redirect_stdout(captured),
            ):
                exit_code = measurement.main(
                    [
                        "--output",
                        str(failed_output),
                        "--code-commit",
                        "abc123",
                        "--snapshot",
                        "snapshot-v2",
                        "--latency-samples",
                        "3",
                    ]
                )
            self.assertEqual(exit_code, 1)
            self.assertEqual(
                failed_output.read_bytes(),
                measurement.canonical_json_bytes(failed) + b"\n",
            )
            self.assertEqual(
                json.loads(captured.getvalue()),
                failed,
            )
            runner.assert_called_once_with(
                code_commit="abc123",
                source_snapshot="snapshot-v2",
                latency_samples=3,
            )


if __name__ == "__main__":
    unittest.main()

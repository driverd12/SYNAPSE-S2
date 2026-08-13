from __future__ import annotations

import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts import measure_memory_confidence as measurement


class _StepTimer:
    def __init__(self, step_ns: int = 1_000_000) -> None:
        self.current = 0
        self.step_ns = step_ns

    def __call__(self) -> int:
        self.current += self.step_ns
        return self.current


class MemoryConfidenceMeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = measurement.load_fixture()
        cls.report = measurement.run_confidence_benchmark(
            latency_samples=2,
            timer=_StepTimer(),
            code_commit="deadbeef",
        )

    def test_report_passes_every_required_dimension_offline(self) -> None:
        report = self.report
        self.assertEqual(report["schema"], measurement.REPORT_SCHEMA)
        self.assertEqual(report["version"], measurement.REPORT_VERSION)
        self.assertEqual(report["status"], "pass")
        self.assertTrue(report["acceptance"]["accepted"])
        self.assertEqual(report["acceptance"]["failure_codes"], [])
        self.assertEqual(set(report["dimensions"]), measurement.REQUIRED_DIMENSIONS)
        self.assertTrue(all(item["passed"] for item in report["dimensions"].values()))
        self.assertEqual(report["acceptance"]["dimension_pass_rate"], 1.0)

        identity = report["run_identity"]
        self.assertTrue(identity["offline"])
        self.assertTrue(identity["temporary_store"])
        self.assertFalse(identity["live_database_opened"])
        self.assertFalse(identity["network_used"])
        self.assertFalse(identity["llm_used"])
        self.assertEqual(identity["embedding_provider"], "semantic-hash")
        self.assertEqual(identity["code_commit"], "deadbeef")
        self.assertIn("not either full benchmark", report["synthetic_benchmark_notice"])
        self.assertIn(report["synthetic_benchmark_notice"], report["limitations"])

        latency = report["latency_ms"]
        self.assertEqual(latency["samples"], 2 * 13)
        self.assertEqual(latency["p50"], 1.0)
        self.assertEqual(latency["p95"], 1.0)
        self.assertTrue(latency["informational_only"])
        self.assertTrue(latency["excluded_from_acceptance"])

    def test_behavior_evidence_proves_update_scope_image_and_deletion_contracts(self) -> None:
        dimensions = self.report["dimensions"]

        update = dimensions["updates_supersession"]["evidence"]
        self.assertTrue(update["stable_memory_id"])
        self.assertEqual(update["stored_revision"], 2)
        self.assertEqual(update["retired_marker_hits"], [])
        self.assertEqual(len(update["current_marker_hits"]), 1)
        self.assertEqual(dimensions["dynamic_tracking"]["evidence"], update)

        temporal = dimensions["temporal_order"]["evidence"]
        self.assertEqual(len(temporal["ordered_memory_ids"]), 2)
        self.assertIn(temporal["ordered_memory_ids"][0], temporal["memory_ids"])
        self.assertIn(temporal["ordered_memory_ids"][1], temporal["memory_ids"])

        premise = dimensions["premise_awareness"]["evidence"]
        abstention = dimensions["abstention"]["evidence"]
        self.assertEqual(premise["qualified_evidence_count"], 0)
        self.assertEqual(abstention["qualified_evidence_count"], 0)
        self.assertGreaterEqual(premise["returned"], 0)
        self.assertEqual(
            premise["qualification"],
            "exact required marker in returned evidence",
        )

        bridge = dimensions["bridge_isolation"]["evidence"]
        self.assertNotIn(bridge["approved_memory_id"], bridge["local_memory_ids"])
        self.assertIn(bridge["approved_memory_id"], bridge["connected_memory_ids"])
        self.assertNotIn(bridge["isolated_memory_id"], bridge["connected_memory_ids"])
        self.assertEqual(bridge["namespace_leakage_count"], 0)

        image = dimensions["image_description_recall"]["evidence"]
        self.assertIn(image["image_memory_id"], image["memory_ids"])
        self.assertFalse(image["raw_original_stored"])

        deletion = dimensions["deletion_residue"]["evidence"]
        self.assertTrue(deletion["deleted"])
        self.assertEqual(deletion["post_delete_marker_hits"], [])
        self.assertEqual(deletion["logical_residue_count"], 0)
        self.assertTrue(all(value == 0 for value in deletion["logical_application_tables"].values()))
        self.assertEqual(deletion["orphan_observed_before_governed_cache_prune"], 1)
        self.assertEqual(deletion["media_residue_count"], 0)
        self.assertTrue(deletion["final_cache_audit"]["healthy"])
        self.assertIn("not forensic", deletion["scope"])

    def test_fixture_and_threshold_tampering_fail_closed(self) -> None:
        mutations = []

        weakened = copy.deepcopy(self.fixture)
        weakened["thresholds"]["minimum_dimension_pass_rate"] = 0.5
        mutations.append((weakened, "thresholds"))

        missing_dimension = copy.deepcopy(self.fixture)
        missing_dimension["required_dimensions"].remove("deletion_residue")
        mutations.append((missing_dimension, "required confidence dimension"))

        unknown_document = copy.deepcopy(self.fixture)
        unknown_document["queries"]["factual"]["expected_document_id"] = "missing"
        mutations.append((unknown_document, "query factual"))

        answer_leak = copy.deepcopy(self.fixture)
        answer_leak["documents"][0]["text"] += " NEVER-SEEN-PREMISE-1907"
        mutations.append((answer_leak, "marker is not absent"))

        with TemporaryDirectory() as temporary:
            for index, (payload, expected) in enumerate(mutations):
                with self.subTest(expected=expected):
                    path = Path(temporary) / f"tampered-{index}.json"
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(measurement.ConfidenceMeasurementError, expected):
                        measurement.load_fixture(path)

    def test_acceptance_detects_behavior_residue_and_scope_regressions(self) -> None:
        report = copy.deepcopy(self.report)
        report["latency_ms"] = {
            "samples": 1,
            "p50": 999999.0,
            "p95": 999999.0,
            "informational_only": True,
            "excluded_from_acceptance": True,
        }
        self.assertTrue(
            measurement.acceptance_verdict(report, self.fixture["thresholds"])["accepted"]
        )

        mutations = {
            "all-dimensions-pass": lambda value: value["dimensions"]["factual_recall"].update(passed=False),
            "bridge-has-zero-leakage": lambda value: value["dimensions"]["bridge_isolation"]["evidence"].update(namespace_leakage_count=1),
            "logical-deletion-has-zero-residue": lambda value: value["dimensions"]["deletion_residue"]["evidence"].update(logical_residue_count=1),
            "media-deletion-has-zero-residue": lambda value: value["dimensions"]["deletion_residue"]["evidence"].update(media_residue_count=1),
            "offline-disposable-execution": lambda value: value["run_identity"].update(live_database_opened=True),
        }
        for expected, mutate in mutations.items():
            with self.subTest(expected=expected):
                candidate = copy.deepcopy(self.report)
                mutate(candidate)
                verdict = measurement.acceptance_verdict(candidate, self.fixture["thresholds"])
                self.assertFalse(verdict["accepted"])
                self.assertIn(expected, verdict["failure_codes"])

        weakened = dict(self.fixture["thresholds"])
        weakened["minimum_dimension_pass_rate"] = 0.5
        verdict = measurement.acceptance_verdict(self.report, weakened)
        self.assertFalse(verdict["accepted"])
        self.assertEqual(verdict["failure_codes"], ["acceptance-thresholds-weakened"])

    def test_repeated_runs_are_semantically_identical(self) -> None:
        repeated = measurement.run_confidence_benchmark(
            latency_samples=2,
            timer=_StepTimer(),
            code_commit="deadbeef",
        )
        self.assertEqual(
            measurement._canonical_bytes(self.report),
            measurement._canonical_bytes(repeated),
        )

    def test_invalid_measurement_bounds_fail_before_execution(self) -> None:
        with self.assertRaises(measurement.ConfidenceMeasurementError):
            measurement.run_confidence_benchmark(latency_samples=0)
        with self.assertRaises(measurement.ConfidenceMeasurementError):
            measurement.run_confidence_benchmark(
                latency_samples=measurement.MAX_LATENCY_SAMPLES + 1
            )
        with self.assertRaises(measurement.ConfidenceMeasurementError):
            measurement.run_confidence_benchmark(latency_samples=1, code_commit="unsafe identity")


if __name__ == "__main__":
    unittest.main()

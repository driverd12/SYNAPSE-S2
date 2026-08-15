from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import longmem_eval as evaluation
from scripts import measure_longmem_v2 as measurement


class _StepTimer:
    def __init__(self, step_ns: int = 1_000_000) -> None:
        self.current = 0
        self.step_ns = step_ns

    def __call__(self) -> int:
        self.current += self.step_ns
        return self.current


class _AblationAdapter(evaluation.LongMemInsertQueryAdapter):
    label = "ablation-shadow-candidate"


def _prepared_payload() -> dict:
    payload = measurement.load_fixture()
    prepared = copy.deepcopy(payload)
    prepared["schema"] = evaluation.PREPARED_DATASET_SCHEMA
    prepared["dataset_label"] = "longmem-v2-prepared-sample.v1"
    prepared["dataset_version"] = "prepared-sample.v1"
    prepared["preparation"] = {
        "prepared_by": "operator",
        "source_note": "local prepared dataset derived from the fixture for contract tests",
        "official_reader_parity": False,
    }
    return prepared


class LongMemV2MeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = measurement.run_measurement(
            code_commit="deadbeef",
            latency_samples=2,
            timer=_StepTimer(),
        )
        cls.fixture = measurement.load_fixture()

    def test_report_shape_and_honest_claims(self) -> None:
        report = self.report
        self.assertEqual(report["schema"], measurement.REPORT_SCHEMA)
        self.assertEqual(report["version"], measurement.REPORT_VERSION)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["mode"], "synapse-derived")
        self.assertTrue(report["acceptance"]["accepted"])
        self.assertIs(report["official_score_claimed"], False)
        self.assertIn("not an official LongMemEval-V2 score", report["claim_notice"])
        self.assertIn(report["claim_notice"], report["limitations"])
        contract = report["official_contract"]
        self.assertEqual(contract["trajectory_tiers"], [100, 500])
        self.assertEqual(contract["question_count"], 451)
        self.assertIn("never run", contract["reader"])
        identity = report["run_identity"]
        self.assertTrue(identity["offline"])
        self.assertTrue(identity["temporary_store"])
        self.assertIs(identity["live_database_opened"], False)
        self.assertIs(identity["network_used"], False)
        self.assertIs(identity["llm_used"], False)
        self.assertIsNone(identity["reader"])
        self.assertIsNone(identity["judge"])
        self.assertEqual(identity["embedding_provider"], "semantic-hash")
        self.assertEqual(identity["code_commit"], "deadbeef")
        self.assertIsNone(identity["dataset_pins"])
        self.assertIn("attested", identity["execution_provenance"])
        adapter = identity["adapter"]
        self.assertEqual(adapter["label"], "synapse-durable-store-baseline")
        self.assertEqual(adapter["protocol"], evaluation.ADAPTER_PROTOCOL)
        self.assertTrue(adapter["builtin"])
        self.assertEqual(
            adapter["identity"], "longmem_eval.LongMemInsertQueryAdapter"
        )
        self.assertEqual(adapter["source_sha256"], measurement.adapter_source_sha256())
        self.assertFalse(adapter["injected_ablation_adapter"])
        execution = self.report["aggregate"]["execution"]
        self.assertTrue(execution["adapter_audited"])
        self.assertIs(execution["offline"], True)
        self.assertIs(execution["network_used"], False)
        self.assertEqual(report["thresholds"], evaluation.SAFE_THRESHOLDS)
        measurement.canonical_json_bytes(report)

    def test_population_and_coverage_are_complete(self) -> None:
        population = self.report["population"]
        self.assertGreaterEqual(population["namespaces"], 3)
        self.assertEqual(population["questions"], len(self.report["per_question"]))
        self.assertGreaterEqual(population["deletions"], 1)
        self.assertFalse(population["official_tier_match"])
        aggregate = self.report["aggregate"]
        self.assertEqual(set(aggregate["by_ability"]), evaluation.ABILITIES)
        self.assertEqual(set(aggregate["by_horizon"]), evaluation.HORIZONS)
        for slot in aggregate["by_ability"].values():
            self.assertGreaterEqual(slot["questions"], 1)
            self.assertEqual(slot["violation_count"], 0)

    def test_metrics_meet_every_fixed_gate(self) -> None:
        metrics = self.report["aggregate"]["metrics"]
        self.assertGreaterEqual(metrics["graded_macro_recall_at_k"], 0.75)
        self.assertGreaterEqual(metrics["graded_macro_ndcg_at_k"], 0.7)
        self.assertGreaterEqual(metrics["graded_macro_mrr"], 0.7)
        for name in (
            "namespace_leakage_count",
            "scope_provenance_violation_count",
            "false_premise_qualified_support_count",
            "abstention_violation_count",
            "current_over_retired_violation_count",
            "temporal_evidence_violation_count",
            "result_contract_violation_count",
            "answer_decision_violation_count",
            "deleted_evidence_count",
            "duplicate_memory_id_count",
            "duplicate_content_count",
            "provenance_violation_count",
            "confidence_violation_count",
            "tie_ordering_violation_count",
        ):
            self.assertEqual(metrics[name], 0, name)
        self.assertGreater(metrics["source_content_deduplications"], 0)
        self.assertGreaterEqual(metrics["near_duplicate_collision_count"], 1)
        self.assertEqual(metrics["image_evidence_hits"], metrics["image_questions"])
        self.assertGreaterEqual(metrics["image_evidence_hits"], 1)
        minimums = self.report["aggregate"]["per_question_minimums"]
        self.assertGreaterEqual(minimums["graded_recall_at_k"], 0.5)
        latency = self.report["aggregate"]["latency_ms"]
        self.assertEqual(latency["samples"], 2 * self.report["population"]["questions"])
        self.assertEqual(latency["p50"], 1.0)
        self.assertTrue(latency["informational_only"])
        memory = self.report["aggregate"]["memory"]
        self.assertGreater(memory["peak_tracemalloc_bytes"], 0)
        self.assertTrue(memory["informational_only"])
        sizes = self.report["aggregate"]["result_sizes_bytes"]
        self.assertGreater(sizes["result"]["min"], 0)
        tokens = self.report["aggregate"]["estimated_tokens"]
        self.assertGreater(tokens["result_total"], 0)
        self.assertIn("heuristic", tokens["estimator"])

    def test_determinism_matrix_and_purity(self) -> None:
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
        self.assertNotEqual(
            determinism["trajectory_order_baseline"],
            determinism["trajectory_order_randomized"],
        )
        self.assertEqual(
            sorted(determinism["trajectory_order_baseline"]),
            sorted(determinism["trajectory_order_randomized"]),
        )
        purity = self.report["aggregate"]["purity"]
        self.assertTrue(purity["all_runs_unchanged"])
        self.assertEqual(
            set(purity["runs"]), {"baseline", "fresh_backend", "randomized"}
        )
        for run in purity["runs"].values():
            self.assertTrue(run["unchanged"])
            self.assertEqual(run["before"], run["after"])
            self.assertIn("database_logical_sha256", run["before"])

    def test_deletion_leaves_no_residue_anywhere_probed(self) -> None:
        residue = self.report["aggregate"]["residue"]
        self.assertEqual(residue["logical_total"], 0)
        self.assertEqual(residue["surface_total"], 0)
        self.assertEqual(len(residue["deleted"]), 1)
        deleted = residue["deleted"][0]
        self.assertEqual(deleted["turn_id"], "t-041")
        self.assertEqual(deleted["logical_total"], 0)
        self.assertEqual(deleted["surface_count"], 0)
        media = residue["media"]
        self.assertEqual(media["media_residue_count"], 0)
        self.assertEqual(media["pre_prune_audit"]["orphan_count"], 1)
        self.assertEqual(media["final_audit"]["orphan_count"], 0)
        self.assertEqual(
            media["final_audit"]["stored_count"], media["expected_stored_count"]
        )
        for probe_name in ("recovery", "replication"):
            probe = residue[probe_name]
            self.assertTrue(probe["probed"])
            self.assertEqual(probe["residue_count"], 0)
            self.assertEqual(probe["exercised"], probe["root_exists"])
            self.assertEqual(probe["informational_only"], not probe["root_exists"])
            self.assertIn("net-new read-only filesystem probe", probe["scope"])
            self.assertIn("unexercised and informational", probe["scope"])
            self.assertIn("not a", probe["scope"])

    def test_question_level_behaviours(self) -> None:
        by_id = {item["question_id"]: item for item in self.report["per_question"]}

        tie = by_id["q-tie-drill"]
        tie_ids = [item["memory_id"] for item in tie["retrieved"]]
        self.assertEqual(tie_ids, sorted(tie_ids))
        self.assertEqual(len({item["score"] for item in tie["retrieved"]}), 1)
        self.assertEqual(tie["metrics"]["recall_at_k"], 1.0)
        self.assertFalse(tie["tie_ordering_violations"])

        duplicate = by_id["q-duplicate-badge"]
        self.assertEqual(duplicate["metrics"]["duplicate_content_count"], 0)
        self.assertGreater(duplicate["metrics"]["source_content_deduplications"], 0)
        self.assertEqual(duplicate["metrics"]["recall_at_k"], 0.5)

        dynamic = by_id["q-dynamic-fuel"]
        self.assertFalse(dynamic["current_over_retired_violations"])
        self.assertTrue(dynamic["marker_evidence"]["stable_memory_id"])
        self.assertEqual(dynamic["marker_evidence"]["stored_revision"], 2)
        self.assertEqual(dynamic["marker_evidence"]["stored_status"], "current")
        self.assertFalse(dynamic["marker_evidence"]["retired_marker_hits"])

        temporal = by_id["q-temporal-tunnel"]
        self.assertFalse(temporal["temporal_violations"])
        self.assertLess(
            temporal["temporal_evidence"]["before_event_time"],
            temporal["temporal_evidence"]["after_event_time"],
        )

        premise = by_id["q-premise-bluejay"]
        self.assertFalse(premise["graded"])
        self.assertFalse(premise["false_premise_qualified_support"])
        self.assertEqual(premise["answer_decision"]["kind"], "false-premise")
        self.assertEqual(premise["answer_decision"]["decision"], "abstain")
        self.assertEqual(premise["answer_decision"]["expected_decision"], "abstain")
        self.assertEqual(premise["answer_decision"]["support_memory_ids"], [])
        self.assertFalse(premise["answer_decision_violations"])
        abstain = by_id["q-abstain-cryopump"]
        self.assertFalse(abstain["abstention_violations"])
        self.assertEqual(abstain["answer_decision"]["kind"], "absent-topic")
        self.assertEqual(abstain["answer_decision"]["decision"], "abstain")
        self.assertFalse(abstain["answer_decision_violations"])

        connected = by_id["q-connected-chase"]
        self.assertEqual(connected["retrieved"][0]["context_id"], "flight-test")
        self.assertEqual(connected["metrics"]["namespace_leakage_count"], 0)
        isolation = by_id["q-local-chase-isolation"]
        self.assertTrue(
            all(
                item["context_id"] == "mission-ops"
                for item in isolation["retrieved"]
            )
        )

        image = by_id["q-image-livery"]
        self.assertIs(image["image_hit"], True)
        self.assertIs(image["image_evidence"]["raw_original_stored"], False)
        deleted = by_id["q-deleted-falcon"]
        self.assertFalse(deleted["deleted_evidence"])

        for question in self.report["per_question"]:
            self.assertFalse(question["scope_leakage"])
            self.assertFalse(question["provenance_violations"])
            self.assertFalse(question["confidence_violations"])
            self.assertFalse(question["result_contract_violations"])
            self.assertFalse(question["answer_decision_violations"])
            self.assertLessEqual(len(question["retrieved"]), question["k"])
            self.assertEqual(
                [item["rank"] for item in question["retrieved"]],
                list(range(1, len(question["retrieved"]) + 1)),
            )
            if question["graded"]:
                self.assertEqual(
                    question["answer_decision"]["kind"], "graded-evidence"
                )
                self.assertEqual(question["answer_decision"]["decision"], "qualified")
                self.assertTrue(question["answer_decision"]["support_memory_ids"])
            self.assertGreater(question["bytes"]["result"], 0)
            self.assertTrue(question["latency_ms"]["informational_only"])
            for item in question["retrieved"]:
                self.assertIs(item["confidence"]["calibrated"], False)
                self.assertIsNone(item["confidence"]["probability"])
                self.assertTrue(item["within_result_limit"])

    def test_every_failure_condition_closes_the_gate(self) -> None:
        mutations = {
            "graded-recall-at-k": lambda a: a["metrics"].update(graded_macro_recall_at_k=0.0),
            "graded-ndcg-at-k": lambda a: a["metrics"].update(graded_macro_ndcg_at_k=0.0),
            "graded-mrr": lambda a: a["metrics"].update(graded_macro_mrr=0.0),
            "per-question-recall-floor": lambda a: a["per_question_minimums"].update(
                graded_recall_at_k=0.0
            ),
            "ability-coverage-complete": lambda a: a["by_ability"].pop("workflow"),
            "namespace-scope-no-leakage": lambda a: a["metrics"].update(
                namespace_leakage_count=1
            ),
            "scope-provenance-authorized": lambda a: a["metrics"].update(
                scope_provenance_violation_count=1
            ),
            "false-premise-no-marker-support": lambda a: a["metrics"].update(
                false_premise_qualified_support_count=1
            ),
            "absent-topic-no-marker-support": lambda a: a["metrics"].update(
                abstention_violation_count=1
            ),
            "answer-decision-consistent": lambda a: a["metrics"].update(
                answer_decision_violation_count=1
            ),
            "query-result-contract": lambda a: a["metrics"].update(
                result_contract_violation_count=1
            ),
            "current-state-over-retired": lambda a: a["metrics"].update(
                current_over_retired_violation_count=1
            ),
            "temporal-evidence-retrieved": lambda a: a["metrics"].update(
                temporal_evidence_violation_count=1
            ),
            "image-evidence-grounded": lambda a: a["metrics"].update(image_evidence_hits=0),
            "deleted-evidence-never-returned": lambda a: a["metrics"].update(
                deleted_evidence_count=1
            ),
            "duplicate-memory-ids-absent": lambda a: a["metrics"].update(
                duplicate_memory_id_count=1
            ),
            "duplicate-content-rate": lambda a: a["metrics"].update(
                source_content_deduplications=0
            ),
            "provenance-complete": lambda a: a["metrics"].update(
                provenance_violation_count=1
            ),
            "confidence-remains-uncalibrated": lambda a: a["metrics"].update(
                confidence_violation_count=1
            ),
            "stable-memory-id-tie-break": lambda a: a["metrics"].update(
                tie_ordering_violation_count=1
            ),
            "retrieval-is-pure": lambda a: a["purity"].update(all_runs_unchanged=False),
            "canonical-output-deterministic": lambda a: a["determinism"].update(
                canonical_digest_all_equal=False
            ),
            "zero-logical-deletion-residue": lambda a: a["residue"].update(logical_total=1),
            "zero-surface-deletion-residue": lambda a: a["residue"].update(surface_total=1),
            "zero-media-residue": lambda a: a["residue"]["media"].update(
                media_residue_count=1
            ),
            "recovery-residue-probe": lambda a: a["residue"]["recovery"].update(
                exercised=True, residue_count=1
            ),
            "replication-residue-probe": lambda a: a["residue"]["replication"].update(
                exercised=True, residue_count=1
            ),
            "offline-disposable-execution": lambda a: a["execution"].update(
                network_used=True
            ),
            "official-claim-honest": lambda a: a["claims"].update(
                official_score_claimed=True
            ),
            "scope-disclosed": lambda a: a["claims"].update(scope_disclosure=""),
        }
        for expected_failure, mutate in mutations.items():
            with self.subTest(expected_failure=expected_failure):
                aggregate = copy.deepcopy(self.report["aggregate"])
                mutate(aggregate)
                verdict = measurement.acceptance_verdict(
                    aggregate, self.report["thresholds"]
                )
                self.assertFalse(verdict["accepted"])
                self.assertIn(expected_failure, verdict["failure_codes"])

    def test_thresholds_cannot_be_weakened_at_verdict_or_load(self) -> None:
        weakened = copy.deepcopy(self.report["thresholds"])
        weakened["maximum_namespace_leakage_count"] = 10
        verdict = measurement.acceptance_verdict(
            copy.deepcopy(self.report["aggregate"]), weakened
        )
        self.assertFalse(verdict["accepted"])
        self.assertEqual(verdict["failure_codes"], ["acceptance-thresholds-weakened"])

        with TemporaryDirectory() as temporary:
            tampered = Path(temporary) / "tampered.json"
            payload = copy.deepcopy(self.fixture)
            payload["thresholds"]["maximum_deleted_evidence_count"] = 99
            tampered.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                measurement.MeasurementError, "missing or weakened"
            ):
                measurement.load_fixture(tampered)
            broken = Path(temporary) / "broken.json"
            broken.write_text("{not json", encoding="utf-8")
            with self.assertRaisesRegex(
                measurement.MeasurementError, "could not be parsed"
            ):
                measurement.load_fixture(broken)
            with self.assertRaisesRegex(
                measurement.MeasurementError, "existing local regular file"
            ):
                measurement.load_fixture(Path(temporary) / "missing.json")

    def test_mode_and_pin_validation_fail_closed(self) -> None:
        with self.assertRaisesRegex(measurement.MeasurementError, "mode must be one of"):
            measurement.run_measurement(mode="official")
        with self.assertRaisesRegex(measurement.MeasurementError, "latency_samples"):
            measurement.run_measurement(latency_samples=0)
        with self.assertRaisesRegex(
            measurement.MeasurementError, "only valid in prepared-corpus mode"
        ):
            measurement.run_measurement(dataset_sha256="a" * 64)
        with self.assertRaisesRegex(measurement.MeasurementError, "requires dataset-path"):
            measurement.run_measurement(mode="prepared-corpus")
        with self.assertRaisesRegex(
            measurement.MeasurementError,
            "renamed to 'prepared-corpus'.*never .*official-harness-compatible",
        ):
            measurement.run_measurement(mode="official-adapter")
        with self.assertRaisesRegex(
            measurement.MeasurementError, "does not accept --fixture"
        ):
            measurement.run_measurement(
                mode="prepared-corpus",
                fixture_path=measurement.FIXTURE_PATH,
                dataset_path=measurement.FIXTURE_PATH,
                dataset_sha256="a" * 64,
                dataset_version="v1",
                adapter_sha256="b" * 64,
            )
        with TemporaryDirectory() as temporary:
            dataset = Path(temporary) / "prepared.json"
            payload = _prepared_payload()
            dataset.write_bytes(measurement.canonical_json_bytes(payload))
            digest = hashlib.sha256(dataset.read_bytes()).hexdigest()
            with self.assertRaisesRegex(
                measurement.MeasurementError, "64-character lowercase SHA-256"
            ):
                measurement.load_prepared_dataset(
                    dataset_path=dataset,
                    dataset_sha256="not-a-sha",
                    dataset_version="v1",
                    adapter_sha256=measurement.adapter_source_sha256(),
                )
            with self.assertRaisesRegex(
                measurement.MeasurementError, "does not match the dataset bytes"
            ):
                measurement.load_prepared_dataset(
                    dataset_path=dataset,
                    dataset_sha256="0" * 64,
                    dataset_version="v1",
                    adapter_sha256=measurement.adapter_source_sha256(),
                )
            with self.assertRaisesRegex(
                measurement.MeasurementError, "does not match longmem_eval.py"
            ):
                measurement.load_prepared_dataset(
                    dataset_path=dataset,
                    dataset_sha256=digest,
                    dataset_version="v1",
                    adapter_sha256="0" * 64,
                )
            with self.assertRaisesRegex(
                measurement.MeasurementError,
                "does not match the prepared dataset metadata",
            ):
                measurement.load_prepared_dataset(
                    dataset_path=dataset,
                    dataset_sha256=digest,
                    dataset_version="some-other-version.v9",
                    adapter_sha256=measurement.adapter_source_sha256(),
                )
            loaded = measurement.load_prepared_dataset(
                dataset_path=dataset,
                dataset_sha256=digest,
                dataset_version="prepared-sample.v1",
                adapter_sha256=measurement.adapter_source_sha256(),
            )
            self.assertEqual(loaded["dataset_label"], "longmem-v2-prepared-sample.v1")
            self.assertEqual(loaded["dataset_version"], "prepared-sample.v1")

    def test_dataset_file_byte_bound_fails_closed(self) -> None:
        bound = evaluation.RESOURCE_BOUNDS["max_dataset_file_bytes"]
        with TemporaryDirectory() as temporary:
            oversized = Path(temporary) / "oversized.json"
            oversized.write_bytes(b"x" * (bound + 1))
            with self.assertRaisesRegex(
                measurement.MeasurementError, "dataset file byte bound"
            ):
                measurement.load_fixture(oversized)
            with self.assertRaisesRegex(
                measurement.MeasurementError, "dataset file byte bound"
            ):
                measurement.load_prepared_dataset(
                    dataset_path=oversized,
                    dataset_sha256=hashlib.sha256(b"irrelevant").hexdigest(),
                    dataset_version="v1",
                    adapter_sha256=measurement.adapter_source_sha256(),
                )

    def test_dataset_version_metadata_must_be_bounded_and_present(self) -> None:
        with TemporaryDirectory() as temporary:
            dataset = Path(temporary) / "prepared.json"
            payload = _prepared_payload()
            del payload["dataset_version"]
            dataset.write_bytes(measurement.canonical_json_bytes(payload))
            digest = hashlib.sha256(dataset.read_bytes()).hexdigest()
            with self.assertRaisesRegex(
                measurement.MeasurementError, "bounded dataset_version"
            ):
                measurement.load_prepared_dataset(
                    dataset_path=dataset,
                    dataset_sha256=digest,
                    dataset_version="prepared-sample.v1",
                    adapter_sha256=measurement.adapter_source_sha256(),
                )

    def test_new_gate_thresholds_cannot_be_dropped_or_weakened(self) -> None:
        for key in (
            "maximum_result_contract_violation_count",
            "maximum_answer_decision_violation_count",
            "maximum_temporal_evidence_violation_count",
        ):
            self.assertEqual(evaluation.SAFE_THRESHOLDS[key], 0)
            self.assertEqual(self.report["thresholds"][key], 0)
            weakened = copy.deepcopy(self.report["thresholds"])
            weakened[key] = 1
            verdict = measurement.acceptance_verdict(
                copy.deepcopy(self.report["aggregate"]), weakened
            )
            self.assertFalse(verdict["accepted"])
            self.assertEqual(
                verdict["failure_codes"], ["acceptance-thresholds-weakened"]
            )
            with TemporaryDirectory() as temporary:
                tampered = Path(temporary) / "tampered.json"
                payload = copy.deepcopy(self.fixture)
                del payload["thresholds"][key]
                tampered.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaisesRegex(
                    measurement.MeasurementError, "missing or weakened"
                ):
                    measurement.load_fixture(tampered)

    def test_prepared_corpus_mode_rejects_injected_adapters(self) -> None:
        with TemporaryDirectory() as temporary:
            dataset = Path(temporary) / "prepared.json"
            dataset.write_bytes(measurement.canonical_json_bytes(_prepared_payload()))
            digest = hashlib.sha256(dataset.read_bytes()).hexdigest()
            with self.assertRaisesRegex(
                measurement.MeasurementError, "built-in audited adapter"
            ):
                measurement.run_measurement(
                    mode="prepared-corpus",
                    dataset_path=dataset,
                    dataset_sha256=digest,
                    dataset_version="prepared-sample.v1",
                    adapter_sha256=measurement.adapter_source_sha256(),
                    adapter_factory=lambda backend: _AblationAdapter(backend),
                )

    def test_adapter_identity_binding_fails_closed(self) -> None:
        class _WrongProtocolAdapter(evaluation.LongMemInsertQueryAdapter):
            protocol = "some-other-protocol"

        class _UnboundedLabelAdapter(evaluation.LongMemInsertQueryAdapter):
            label = "unsafe label with spaces"

        with self.assertRaisesRegex(
            measurement.MeasurementError, "longmem-insert-query-v1 protocol"
        ):
            measurement.run_measurement(
                latency_samples=1,
                timer=_StepTimer(),
                adapter_factory=lambda backend: _WrongProtocolAdapter(backend),
            )
        with self.assertRaisesRegex(
            measurement.MeasurementError, "bounded public identifier"
        ):
            measurement.run_measurement(
                latency_samples=1,
                timer=_StepTimer(),
                adapter_factory=lambda backend: _UnboundedLabelAdapter(backend),
            )

    def test_unexercised_probe_roots_are_informational_not_passes(self) -> None:
        with TemporaryDirectory() as temporary:
            missing_root = Path(temporary) / "never-created"
            probe = measurement._filesystem_residue_probe(
                missing_root, ["marker"], scope=measurement.RECOVERY_PROBE_SCOPE
            )
            self.assertTrue(probe["probed"])
            self.assertFalse(probe["root_exists"])
            self.assertFalse(probe["exercised"])
            self.assertTrue(probe["informational_only"])
            self.assertEqual(probe["files_scanned"], 0)

            exercised_root = Path(temporary) / "exists"
            exercised_root.mkdir()
            (exercised_root / "residue.txt").write_text("marker", encoding="utf-8")
            dirty = measurement._filesystem_residue_probe(
                exercised_root, ["marker"], scope=measurement.RECOVERY_PROBE_SCOPE
            )
            self.assertTrue(dirty["exercised"])
            self.assertEqual(dirty["residue_count"], 1)

        # An unexercised probe must not fail the gate even with a nonzero
        # count, while an exercised probe with residue must fail it.
        aggregate = copy.deepcopy(self.report["aggregate"])
        aggregate["residue"]["recovery"].update(exercised=False, residue_count=5)
        verdict = measurement.acceptance_verdict(aggregate, self.report["thresholds"])
        self.assertNotIn("recovery-residue-probe", verdict["failure_codes"])
        aggregate["residue"]["recovery"].update(exercised=True)
        verdict = measurement.acceptance_verdict(aggregate, self.report["thresholds"])
        self.assertIn("recovery-residue-probe", verdict["failure_codes"])

    def test_prepared_corpus_mode_uses_builtin_audited_adapter(self) -> None:
        with TemporaryDirectory() as temporary:
            dataset = Path(temporary) / "prepared.json"
            dataset.write_bytes(measurement.canonical_json_bytes(_prepared_payload()))
            digest = hashlib.sha256(dataset.read_bytes()).hexdigest()
            report = measurement.run_measurement(
                mode="prepared-corpus",
                dataset_path=dataset,
                dataset_sha256=digest,
                dataset_version="prepared-sample.v1",
                adapter_sha256=measurement.adapter_source_sha256(),
                latency_samples=1,
                timer=_StepTimer(),
            )
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["mode"], "prepared-corpus")
        self.assertIs(report["official_score_claimed"], False)
        self.assertIn("not an official LongMemEval-V2 score", report["claim_notice"])
        identity = report["run_identity"]
        self.assertEqual(identity["source_kind"], "operator-prepared-local-dataset")
        adapter = identity["adapter"]
        self.assertEqual(adapter["label"], "synapse-durable-store-baseline")
        self.assertTrue(adapter["builtin"])
        self.assertFalse(adapter["injected_ablation_adapter"])
        self.assertEqual(adapter["source_sha256"], measurement.adapter_source_sha256())
        self.assertIs(identity["offline"], True)
        self.assertIs(identity["network_used"], False)
        pins = identity["dataset_pins"]
        self.assertEqual(pins["dataset_sha256"], digest)
        self.assertEqual(pins["dataset_version"], "prepared-sample.v1")
        self.assertEqual(pins["dataset_label"], "longmem-v2-prepared-sample.v1")
        self.assertIs(pins["preparation"]["official_reader_parity"], False)

    def test_injected_ablation_adapter_never_claims_execution_provenance(self) -> None:
        report = measurement.run_measurement(
            latency_samples=1,
            timer=_StepTimer(),
            adapter_factory=lambda backend: _AblationAdapter(backend),
        )
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["mode"], "synapse-derived")
        self.assertIs(report["official_score_claimed"], False)
        identity = report["run_identity"]
        adapter = identity["adapter"]
        self.assertEqual(adapter["label"], "ablation-shadow-candidate")
        self.assertFalse(adapter["builtin"])
        self.assertTrue(adapter["injected_ablation_adapter"])
        self.assertIsNone(adapter["source_sha256"])
        self.assertTrue(adapter["identity"].endswith("_AblationAdapter"))
        # No offline/live/network/LLM provenance is claimed for injected code.
        for field in (
            "offline",
            "temporary_store",
            "live_database_opened",
            "network_used",
            "llm_used",
        ):
            self.assertIsNone(identity[field], field)
        self.assertIn("unverified", identity["execution_provenance"])
        execution = report["aggregate"]["execution"]
        self.assertIs(execution["adapter_audited"], False)
        for field in (
            "offline",
            "temporary_store",
            "live_database_opened",
            "network_used",
            "llm_used",
        ):
            self.assertIsNone(execution[field], field)

    def test_main_prints_canonical_json_and_never_writes_files(self) -> None:
        failed = {
            "schema": measurement.REPORT_SCHEMA,
            "version": measurement.REPORT_VERSION,
            "status": "fail",
            "official_score_claimed": False,
        }
        captured = io.StringIO()
        with (
            mock.patch.object(
                measurement, "run_measurement", return_value=failed
            ) as runner,
            contextlib.redirect_stdout(captured),
        ):
            exit_code = measurement.main(
                ["--code-commit", "abc123", "--latency-samples", "4"]
            )
        self.assertEqual(exit_code, 1)
        self.assertEqual(
            captured.getvalue().encode("utf-8"),
            measurement.canonical_json_bytes(failed) + b"\n",
        )
        runner.assert_called_once_with(
            mode="synapse-derived",
            fixture_path=None,
            dataset_path=None,
            dataset_sha256=None,
            dataset_version=None,
            adapter_sha256=None,
            code_commit="abc123",
            latency_samples=4,
        )

        captured = io.StringIO()
        with (
            mock.patch.object(
                measurement,
                "run_measurement",
                side_effect=measurement.MeasurementError("boom"),
            ),
            contextlib.redirect_stdout(captured),
        ):
            exit_code = measurement.main([])
        self.assertEqual(exit_code, 2)
        error_payload = json.loads(captured.getvalue())
        self.assertEqual(error_payload["status"], "error")
        self.assertIs(error_payload["official_score_claimed"], False)
        self.assertEqual(error_payload["error"], "boom")

        stderr = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(stderr):
            measurement.main(["--output", "/tmp/should-never-exist.json"])
        self.assertIn("--output", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

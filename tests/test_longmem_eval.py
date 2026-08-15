from __future__ import annotations

import copy
import json
import math
import unittest
from pathlib import Path

import longmem_eval as evaluation

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "longmem_v2"
    / "benchmark_v1.json"
)


def _fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _turn(corpus: dict, turn_id: str) -> dict:
    for trajectory in corpus["trajectories"]:
        for session in trajectory["sessions"]:
            for turn in session["turns"]:
                if turn["turn_id"] == turn_id:
                    return turn
    raise AssertionError(f"turn {turn_id} not in fixture")


class _FakeAdapter:
    """Protocol-compatible in-memory adapter for population unit tests."""

    label = "fake-adapter"
    protocol = evaluation.ADAPTER_PROTOCOL

    def __init__(self) -> None:
        self.inserts: list[dict] = []
        self.links: list[dict] = []
        self.relationships: list[dict] = []
        self.deletions: list[dict] = []

    def insert_turn(self, **kwargs):
        self.inserts.append(kwargs)
        return f"mem-{kwargs['context_id']}-{kwargs['tag']}"

    def approve_context_link(self, link, *, request_id, timestamp):
        self.links.append({"link": link, "request_id": request_id, "timestamp": timestamp})

    def add_relationship(self, **kwargs):
        self.relationships.append(kwargs)
        return {
            "relationship_id": f"rel-{len(self.relationships)}",
            "source_memory_id": kwargs["source_memory_id"],
            "target_memory_id": kwargs["target_memory_id"],
        }

    def delete_memory(self, **kwargs):
        self.deletions.append(kwargs)
        return True

    def get_entry(self, memory_id):
        return None

    def query(self, **kwargs):
        return {"items": []}


class _EntryStubAdapter:
    """Read-side stub for evaluate_question unit tests."""

    def get_entry(self, memory_id):
        return {
            "metadata": {
                "embedding_provider": "semantic-hash",
                "memory_type": "text",
            }
        }


def _fake_capturer(turn: dict) -> dict:
    return {
        "media_id": turn["media_id"],
        "raw_original_stored": False,
        "artifact": {"media_id": turn["media_id"], "width": 16, "height": 16},
    }


class LongMemEvalLibraryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = evaluation.validate_fixture(_fixture())
        cls.corpus = cls.payload["corpus"]
        cls.index = evaluation.validate_corpus(cls.corpus)

    def test_fixture_is_valid_and_indexed(self) -> None:
        index = self.index
        self.assertIn("t-012", index["turns"])
        self.assertEqual(index["turns"]["t-012"]["revision"], 2)
        self.assertEqual(index["turns"]["t-010"]["superseded_by"], "t-012")
        self.assertIsNone(index["turns"]["t-012"]["superseded_by"])
        self.assertEqual(index["deleted_turn_ids"], {"t-041"})
        self.assertGreaterEqual(len(index["contexts"]), 3)
        self.assertEqual(
            len(index["groups"]["tie_group"]["drill-tie"]),
            4,
        )
        summary = evaluation.population_summary(self.corpus, index)
        self.assertEqual(summary["trajectories"], 6)
        self.assertEqual(summary["image_turns"], 2)
        self.assertFalse(summary["official_tier_match"])

    def test_helper_math_is_exact(self) -> None:
        self.assertAlmostEqual(evaluation._dcg([3, 2]), 7.0 + 3.0 / math.log2(3))
        self.assertEqual(evaluation.nearest_rank_percentile([1, 2, 3, 4], 0.5), 2.0)
        self.assertEqual(evaluation.nearest_rank_percentile([1, 2, 3, 4], 0.95), 4.0)
        self.assertIsNone(evaluation.nearest_rank_percentile([], 0.95))
        self.assertEqual(evaluation.estimate_tokens(0), 0)
        self.assertEqual(evaluation.estimate_tokens(1), 1)
        self.assertEqual(evaluation.estimate_tokens(9), 3)
        self.assertEqual(
            evaluation.canonical_json_bytes({"b": 1, "a": 2}), b'{"a":2,"b":1}'
        )
        with self.assertRaises(evaluation.EvalError):
            evaluation.canonical_json_bytes({"bad": float("nan")})
        with self.assertRaises(evaluation.EvalError):
            evaluation.bounded_identity("unsafe identity with spaces", field="commit")
        self.assertIsNone(evaluation.bounded_identity("  ", field="commit"))
        hits = evaluation.marker_hits(
            [{"memory_id": "m1", "excerpt": "the Falcon Mural wall"}], "falcon mural"
        )
        self.assertEqual(hits, ["m1"])

    def test_validators_fail_closed(self) -> None:
        cases = {
            "duplicate turn ids": (
                lambda corpus: _turn(corpus, "t-002").update(turn_id="t-001"),
                "must be unique",
            ),
            "global namespace": (
                lambda corpus: corpus["trajectories"][0].update(context_id="global"),
                "global context",
            ),
            "tag reuse without supersession": (
                lambda corpus: _turn(corpus, "t-012").pop("supersedes_turn_ref"),
                "without superseding",
            ),
            "invalid media id": (
                lambda corpus: _turn(corpus, "t-040").update(media_id="s2img_SHORT"),
                "media_id is invalid",
            ),
            "judging a deleted turn": (
                lambda corpus: corpus["questions"][0].update(judgments={"t-041": 3}),
                "judges a deleted turn",
            ),
            "judging a retired revision": (
                lambda corpus: corpus["questions"][0].update(judgments={"t-010": 3}),
                "retired state revision",
            ),
            "grade out of range": (
                lambda corpus: corpus["questions"][0].update(judgments={"t-001": 4}),
                "integers from 1 to 3",
            ),
            "unsupported ability": (
                lambda corpus: corpus["questions"][0].update(ability="vibes"),
                "ability is unsupported",
            ),
            "judgment outside allowed scope": (
                lambda corpus: corpus["questions"][0].update(judgments={"t-020": 3}),
                "outside allowed scope",
            ),
            "premise marker present in corpus": (
                lambda corpus: _turn(corpus, "t-001").update(
                    text=_turn(corpus, "t-001")["text"] + " Bluejay-9 backup."
                ),
                "premise marker is not absent",
            ),
            "abstention marker present in corpus": (
                lambda corpus: _turn(corpus, "t-004").update(
                    text=_turn(corpus, "t-004")["text"] + " cryogenic pump nearby."
                ),
                "abstention marker is not absent",
            ),
            "deleting a superseded turn": (
                lambda corpus: corpus["deletions"].append(
                    {"turn_ref": "t-012", "reason": "invalid: part of a state chain"}
                ),
                "standalone state turns",
            ),
            "relationship to deleted turn": (
                lambda corpus: corpus["relationships"].append(
                    {
                        "context_id": "mission-ops",
                        "source_turn_ref": "t-041",
                        "target_turn_ref": "t-011",
                        "relation_type": "temporal_next",
                        "weight": 1.0,
                    }
                ),
                "references a deleted turn",
            ),
            "unsupported context link direction": (
                lambda corpus: corpus["context_links"][0].update(
                    direction="sideways"
                ),
                "direction must be directed or bidirectional",
            ),
            "non-finite context link confidence": (
                lambda corpus: corpus["context_links"][0].update(
                    confidence=float("nan")
                ),
                "confidence must be a finite number",
            ),
            "out-of-range context link confidence": (
                lambda corpus: corpus["context_links"][0].update(confidence=1.1),
                "confidence must be between 0 and 1",
            ),
            "non-finite relationship weight": (
                lambda corpus: corpus["relationships"][0].update(
                    weight=float("inf")
                ),
                "weight must be a finite number",
            ),
            "out-of-range relationship weight": (
                lambda corpus: corpus["relationships"][0].update(weight=-0.1),
                "weight must be between 0 and 1",
            ),
            "non-finite event time": (
                lambda corpus: _turn(corpus, "t-001").update(
                    event_time=float("nan")
                ),
                "event_time must be a finite number",
            ),
            "temporal expectation without relationship": (
                lambda corpus: next(
                    question
                    for question in corpus["questions"]
                    if question["question_id"] == "q-temporal-tunnel"
                )["temporal_expectation"].update(before_turn_ref="t-011", after_turn_ref="t-013"),
                "lacks a corpus relationship",
            ),
            "missing ability coverage": (
                lambda corpus: corpus.update(
                    questions=[
                        question
                        for question in corpus["questions"]
                        if question["ability"] != "premise_awareness"
                    ]
                ),
                "must cover every LongMemEval-V2 ability",
            ),
            "missing image deletion": (
                lambda corpus: (
                    corpus.update(
                        deletions=[{"turn_ref": "t-004", "reason": "text-only deletion"}],
                        questions=[
                            question
                            for question in corpus["questions"]
                            if question["question_id"]
                            not in {"q-event-rig", "q-deleted-falcon"}
                        ],
                    )
                ),
                "deleted image turn",
            ),
        }
        for name, (mutate, message) in cases.items():
            with self.subTest(case=name):
                corpus = copy.deepcopy(self.corpus)
                mutate(corpus)
                with self.assertRaisesRegex(evaluation.EvalError, message):
                    evaluation.validate_corpus(corpus)

    def test_fixture_thresholds_cannot_be_weakened(self) -> None:
        payload = copy.deepcopy(_fixture())
        payload["thresholds"]["maximum_namespace_leakage_count"] = 5
        with self.assertRaisesRegex(evaluation.EvalError, "missing or weakened"):
            evaluation.validate_fixture(payload)
        payload = copy.deepcopy(_fixture())
        del payload["thresholds"]["maximum_deleted_evidence_count"]
        with self.assertRaisesRegex(evaluation.EvalError, "missing or weakened"):
            evaluation.validate_fixture(payload)
        payload = copy.deepcopy(_fixture())
        payload["backend"]["embedding_provider"] = "mlx-neural-v1"
        with self.assertRaisesRegex(evaluation.EvalError, "semantic-hash"):
            evaluation.validate_fixture(payload)

    def test_prepared_dataset_contract_is_honest(self) -> None:
        prepared = copy.deepcopy(_fixture())
        prepared["schema"] = evaluation.PREPARED_DATASET_SCHEMA
        prepared["dataset_label"] = "longmem-v2-prepared-sample.v1"
        prepared["dataset_version"] = "prepared-sample.v1"
        prepared["preparation"] = {
            "prepared_by": "operator",
            "source_note": "sample prepared dataset for contract tests",
            "official_reader_parity": False,
        }
        self.assertEqual(
            evaluation.validate_prepared_dataset(copy.deepcopy(prepared))["dataset_label"],
            "longmem-v2-prepared-sample.v1",
        )
        parity = copy.deepcopy(prepared)
        parity["preparation"]["official_reader_parity"] = True
        with self.assertRaisesRegex(evaluation.EvalError, "reader/judge parity"):
            evaluation.validate_prepared_dataset(parity)
        unlabeled = copy.deepcopy(prepared)
        del unlabeled["dataset_label"]
        with self.assertRaisesRegex(evaluation.EvalError, "dataset_label"):
            evaluation.validate_prepared_dataset(unlabeled)
        unversioned = copy.deepcopy(prepared)
        del unversioned["dataset_version"]
        with self.assertRaisesRegex(evaluation.EvalError, "dataset_version"):
            evaluation.validate_prepared_dataset(unversioned)
        unprepared = copy.deepcopy(prepared)
        del unprepared["preparation"]
        with self.assertRaisesRegex(evaluation.EvalError, "preparation provenance"):
            evaluation.validate_prepared_dataset(unprepared)
        wrong_schema = copy.deepcopy(prepared)
        wrong_schema["schema"] = evaluation.FIXTURE_SCHEMA
        with self.assertRaisesRegex(evaluation.EvalError, "schema or version"):
            evaluation.validate_prepared_dataset(wrong_schema)

    def test_populate_corpus_contract(self) -> None:
        adapter = _FakeAdapter()
        record = evaluation.populate_corpus(
            adapter,
            self.corpus,
            fixed_epoch=float(self.payload["fixed_epoch"]),
            image_capturer=_fake_capturer,
        )
        self.assertEqual(len(record["insertion_order"]), len(self.index["turns"]))
        self.assertEqual(record["memory_ids"]["t-010"], record["memory_ids"]["t-012"])
        self.assertEqual(len(record["deleted"]), 1)
        self.assertEqual(record["deleted"][0]["media_id"], _turn(self.corpus, "t-041")["media_id"])
        self.assertEqual(len(record["live_media"]), 1)
        self.assertEqual(len(adapter.links), 1)
        self.assertEqual(len(adapter.relationships), 1)
        timestamps = {
            insert["metadata"]["benchmark_turn_id"]: insert["timestamp"]
            for insert in adapter.inserts
        }
        tie_times = {timestamps[f"t-05{i}"] for i in range(4)}
        self.assertEqual(len(tie_times), 1)
        self.assertLess(timestamps["t-001"], timestamps["t-013"])
        retired = next(
            insert
            for insert in adapter.inserts
            if insert["metadata"]["benchmark_turn_id"] == "t-010"
        )
        current = next(
            insert
            for insert in adapter.inserts
            if insert["metadata"]["benchmark_turn_id"] == "t-012"
        )
        self.assertEqual(retired["metadata"]["status"], "retired")
        self.assertEqual(current["metadata"]["status"], "current")
        self.assertEqual(current["metadata"]["revision"], 2)

        shuffled = evaluation.populate_corpus(
            _FakeAdapter(),
            self.corpus,
            fixed_epoch=float(self.payload["fixed_epoch"]),
            trajectory_order=list(reversed(self.index["trajectory_ids"])),
            image_capturer=_fake_capturer,
        )
        self.assertEqual(shuffled["memory_ids"], record["memory_ids"])

        class _UnstableRevisionAdapter(_FakeAdapter):
            def insert_turn(self, **kwargs):
                self.inserts.append(kwargs)
                return f"mem-{len(self.inserts)}"

        with self.assertRaisesRegex(
            evaluation.EvalError, "stable memory identity changed across revisions"
        ):
            evaluation.populate_corpus(
                _UnstableRevisionAdapter(),
                self.corpus,
                fixed_epoch=float(self.payload["fixed_epoch"]),
                image_capturer=_fake_capturer,
            )

        with self.assertRaisesRegex(evaluation.EvalError, "every trajectory exactly once"):
            evaluation.populate_corpus(
                _FakeAdapter(),
                self.corpus,
                fixed_epoch=float(self.payload["fixed_epoch"]),
                trajectory_order=["traj-drills"],
                image_capturer=_fake_capturer,
            )
        with self.assertRaisesRegex(evaluation.EvalError, "raw original"):
            evaluation.populate_corpus(
                _FakeAdapter(),
                self.corpus,
                fixed_epoch=float(self.payload["fixed_epoch"]),
                image_capturer=lambda turn: {
                    "media_id": turn["media_id"],
                    "raw_original_stored": True,
                    "artifact": {},
                },
            )
        with self.assertRaisesRegex(evaluation.EvalError, "no image_capturer"):
            evaluation.populate_corpus(
                _FakeAdapter(),
                self.corpus,
                fixed_epoch=float(self.payload["fixed_epoch"]),
                image_capturer=None,
            )

    def test_aggregate_requires_graded_questions(self) -> None:
        with self.assertRaisesRegex(evaluation.EvalError, "graded question"):
            evaluation.aggregate_questions([])

    def _question(self, question_id: str) -> dict:
        return next(
            question
            for question in self.corpus["questions"]
            if question["question_id"] == question_id
        )

    def _populate_record(self) -> dict:
        return evaluation.populate_corpus(
            _FakeAdapter(),
            self.corpus,
            fixed_epoch=float(self.payload["fixed_epoch"]),
            image_capturer=_fake_capturer,
        )

    @staticmethod
    def _result_item(rank: int, memory_id: str, context_id: str, origin: str) -> dict:
        return {
            "rank": rank,
            "memory_id": memory_id,
            "context_id": context_id,
            "tag": "stub-tag",
            "label": "stub label",
            "summary": "stub summary",
            "excerpt": "stub excerpt",
            "score": 0.5,
            "confidence": {"calibrated": False, "probability": None, "signal": 0.5},
            "scope_provenance": {
                "origin_context_id": origin,
                "resolved_context_id": context_id,
                "context_link": None,
            },
            "source_provenance": {"source": "unit-test"},
        }

    def _evaluate(self, question: dict, items: list[dict], record: dict) -> dict:
        result = {
            "items": items,
            "ranker": {"confidence_semantics": {"calibrated": False}},
        }
        return evaluation.evaluate_question(
            question, result, self.index, record, _EntryStubAdapter(), [1.0]
        )

    def test_over_return_cannot_inflate_graded_metrics(self) -> None:
        record = self._populate_record()
        question = self._question("q-static-relay")
        memory_ids = record["memory_ids"]
        irrelevant = ["t-002", "t-003", "t-004", "t-011"]
        items = [
            self._result_item(rank, memory_ids[turn_id], "mission-ops", "mission-ops")
            for rank, turn_id in enumerate(irrelevant, start=1)
        ]
        # The only relevant memory arrives beyond result_limit; over-return
        # must not let it count toward recall/nDCG/MRR.
        items.append(
            self._result_item(5, memory_ids["t-001"], "mission-ops", "mission-ops")
        )
        evidence = self._evaluate(question, items, record)
        self.assertEqual(evidence["metrics"]["recall_at_k"], 0.0)
        self.assertEqual(evidence["metrics"]["ndcg_at_k"], 0.0)
        self.assertEqual(evidence["metrics"]["mrr"], 0.0)
        reasons = {v["reason"] for v in evidence["result_contract_violations"]}
        self.assertIn("returned-more-than-result-limit", reasons)
        self.assertFalse(evidence["retrieved"][4]["within_result_limit"])
        self.assertEqual(len(evidence["answer_decision_violations"]), 1)
        self.assertEqual(evidence["answer_decision"]["decision"], "abstain")
        self.assertEqual(evidence["answer_decision"]["expected_decision"], "qualified")

        compliant = self._evaluate(
            question,
            [self._result_item(1, memory_ids["t-001"], "mission-ops", "mission-ops")],
            record,
        )
        self.assertEqual(compliant["metrics"]["recall_at_k"], 1.0)
        self.assertFalse(compliant["result_contract_violations"])
        self.assertEqual(compliant["answer_decision"]["decision"], "qualified")
        self.assertEqual(
            compliant["answer_decision"]["support_memory_ids"],
            [memory_ids["t-001"]],
        )
        self.assertFalse(compliant["answer_decision_violations"])

    def test_ranks_must_be_unique_ordered_and_one_based(self) -> None:
        record = self._populate_record()
        question = self._question("q-static-relay")
        memory_ids = record["memory_ids"]
        cases = {
            "gap": [1, 3],
            "duplicate": [1, 1],
            "zero-based": [0, 1],
            "non-integer": [1, "2"],
        }
        for name, ranks in cases.items():
            with self.subTest(case=name):
                items = [
                    self._result_item(1, memory_ids["t-001"], "mission-ops", "mission-ops"),
                    self._result_item(2, memory_ids["t-002"], "mission-ops", "mission-ops"),
                ]
                for item, rank in zip(items, ranks):
                    item["rank"] = rank
                evidence = self._evaluate(question, items, record)
                reasons = {v["reason"] for v in evidence["result_contract_violations"]}
                self.assertIn("ranks-not-unique-ordered-one-based", reasons)

    def test_answer_decision_grades_premise_and_abstention_probes(self) -> None:
        record = self._populate_record()
        memory_ids = record["memory_ids"]
        premise = self._question("q-premise-bluejay")
        clean = self._evaluate(
            premise,
            [self._result_item(1, memory_ids["t-001"], "mission-ops", "mission-ops")],
            record,
        )
        self.assertEqual(clean["answer_decision"]["kind"], "false-premise")
        self.assertEqual(clean["answer_decision"]["decision"], "abstain")
        self.assertEqual(clean["answer_decision"]["support_memory_ids"], [])
        self.assertFalse(clean["answer_decision_violations"])
        self.assertFalse(clean["false_premise_qualified_support"])

        tainted_item = self._result_item(
            1, memory_ids["t-001"], "mission-ops", "mission-ops"
        )
        tainted_item["excerpt"] = "rerouted through groundstation Bluejay-9 backup"
        tainted = self._evaluate(premise, [tainted_item], record)
        self.assertEqual(tainted["answer_decision"]["decision"], "qualified")
        self.assertEqual(len(tainted["answer_decision_violations"]), 1)
        self.assertEqual(
            tainted["answer_decision"]["support_memory_ids"], [memory_ids["t-001"]]
        )
        self.assertTrue(tainted["false_premise_qualified_support"])

        abstain = self._question("q-abstain-cryopump")
        leak_item = self._result_item(
            1, memory_ids["t-004"], "mission-ops", "mission-ops"
        )
        leak_item["summary"] = "maintenance of the cryogenic pump on stand nine"
        leaked = self._evaluate(abstain, [leak_item], record)
        self.assertEqual(leaked["answer_decision"]["kind"], "absent-topic")
        self.assertEqual(leaked["answer_decision"]["decision"], "qualified")
        self.assertEqual(len(leaked["answer_decision_violations"]), 1)
        self.assertTrue(leaked["abstention_violations"])

    def test_aggregate_counts_new_violation_classes(self) -> None:
        record = self._populate_record()
        question = self._question("q-static-relay")
        memory_ids = record["memory_ids"]
        items = [
            self._result_item(rank, memory_ids[turn_id], "mission-ops", "mission-ops")
            for rank, turn_id in enumerate(
                ["t-002", "t-003", "t-004", "t-011"], start=1
            )
        ]
        items.append(
            self._result_item(6, memory_ids["t-001"], "mission-ops", "mission-ops")
        )
        bad = self._evaluate(question, items, record)
        aggregate = evaluation.aggregate_questions([bad])
        metrics = aggregate["metrics"]
        # Over-return plus the rank gap plus the failed qualified decision.
        self.assertEqual(metrics["result_contract_violation_count"], 2)
        self.assertEqual(metrics["answer_decision_violation_count"], 1)
        slot = aggregate["by_ability"]["static_state"]
        self.assertGreaterEqual(slot["violation_count"], 3)

    def test_resource_bounds_fail_closed(self) -> None:
        oversized_backend = copy.deepcopy(_fixture())
        oversized_backend["backend"]["dimension"] = (
            evaluation.RESOURCE_BOUNDS["max_backend_dimension"] + 1
        )
        with self.assertRaisesRegex(evaluation.EvalError, "resource bound"):
            evaluation.validate_fixture(oversized_backend)

        oversized_limit = copy.deepcopy(self.corpus)
        oversized_limit["questions"][0]["result_limit"] = (
            evaluation.RESOURCE_BOUNDS["max_result_limit"] + 1
        )
        with self.assertRaisesRegex(evaluation.EvalError, "resource bound"):
            evaluation.validate_corpus(oversized_limit)

        oversized_candidates = copy.deepcopy(self.corpus)
        oversized_candidates["questions"][0]["candidate_limit"] = (
            evaluation.RESOURCE_BOUNDS["max_candidate_limit"] + 1
        )
        with self.assertRaisesRegex(evaluation.EvalError, "resource bound"):
            evaluation.validate_corpus(oversized_candidates)

        oversized_text = copy.deepcopy(self.corpus)
        _turn(oversized_text, "t-001")["text"] = "x" * (
            evaluation.RESOURCE_BOUNDS["max_turn_text_bytes"] + 1
        )
        with self.assertRaisesRegex(evaluation.EvalError, "byte bound"):
            evaluation.validate_corpus(oversized_text)

        oversized_topology = copy.deepcopy(_fixture())
        oversized_topology["backend"].update(dimension=8192, num_neurons=8192)
        with self.assertRaisesRegex(evaluation.EvalError, "384 MiB"):
            evaluation.validate_fixture(oversized_topology)

        non_finite_epoch = copy.deepcopy(_fixture())
        non_finite_epoch["fixed_epoch"] = float("inf")
        with self.assertRaisesRegex(evaluation.EvalError, "finite number"):
            evaluation.validate_fixture(non_finite_epoch)


if __name__ == "__main__":
    unittest.main()

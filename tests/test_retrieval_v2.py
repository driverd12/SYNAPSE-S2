from __future__ import annotations

import hashlib
import json
import math
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import mlx_backend
from mlx_backend import SpikingAttentionBackend


class RetrievalV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.backends: list[SpikingAttentionBackend] = []

    def tearDown(self) -> None:
        for backend in reversed(self.backends):
            try:
                backend.memory_store.close()
            except Exception:
                pass

    def _backend(
        self,
        name: str = "primary",
        *,
        state_path: Path | None = None,
    ) -> SpikingAttentionBackend:
        path = state_path or (
            Path(self.temporary_directory.name) / name / "runtime_state.json"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=path,
            embedding_provider_name="semantic-hash",
        )
        self.backends.append(backend)
        return backend

    def _close_backend(self, backend: SpikingAttentionBackend) -> None:
        backend.memory_store.close()
        if backend in self.backends:
            self.backends.remove(backend)

    def _register_with_query_embedding(
        self,
        backend: SpikingAttentionBackend,
        *,
        prompt: str,
        context_id: str,
        tag: str,
        text: str,
        label: str | None = None,
    ) -> dict:
        embedding = backend.embed_text(prompt)
        return backend.register_trace(
            tag=tag,
            embedding=embedding,
            context_id=context_id,
            source_text=text,
            metadata={
                "display_label": label or tag,
                "display_summary": text,
                "source": "retrieval-v2-test",
            },
        )

    @staticmethod
    def _id_scores(payload: dict) -> list[tuple[str, float, int]]:
        return [
            (item["memory_id"], item["score"], item["rank"])
            for item in payload["items"]
        ]

    @staticmethod
    def _state_digest(backend: SpikingAttentionBackend) -> str:
        def array_value(value):
            return None if value is None else value.tolist()

        state_bytes = (
            backend.state_path.read_bytes() if backend.state_path.exists() else b""
        )
        database_bytes = backend.memory_store.db_path.read_bytes()
        payload = {
            "dimension": backend.dimension,
            "w_syn": array_value(backend.W_syn),
            "w_lateral": array_value(backend.W_lateral),
            "mem": array_value(backend.state["mem"]),
            "spk": array_value(backend.state["spk"]),
            "active_traces": array_value(backend.active_traces),
            "global_enabled": backend.global_enabled,
            "context_overrides": backend.context_overrides,
            "registered_traces": backend.registered_traces,
            "surface_cache": backend._surface_recall_cache,
            "last_pruning_monotonic": backend.last_pruning_monotonic,
            "last_activity_monotonic": backend.last_activity_monotonic,
            "quick_pruning_count": backend.quick_pruning_count,
            "deep_sleep_count": backend.deep_sleep_count,
            "last_maintenance": backend.last_maintenance,
            "state_sha256": hashlib.sha256(state_bytes).hexdigest(),
            "database_sha256": hashlib.sha256(database_bytes).hexdigest(),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, allow_nan=False).encode("utf-8")
        ).hexdigest()

    def _assert_finite_json(self, value) -> None:
        if isinstance(value, float):
            self.assertTrue(math.isfinite(value), value)
        elif isinstance(value, dict):
            for nested in value.values():
                self._assert_finite_json(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                self._assert_finite_json(nested)

    def test_repeated_and_fresh_backend_are_byte_deterministic(self) -> None:
        backend = self._backend()
        prompt = "deterministic camera control room retrieval"
        for suffix in ("alpha", "bravo", "charlie"):
            self._register_with_query_embedding(
                backend,
                prompt=prompt,
                context_id="ops",
                tag=f"deterministic-{suffix}",
                text=f"Deterministic camera control room retrieval evidence {suffix}.",
                label=f"Control room {suffix}",
            )

        first = backend.retrieve_text_v2(
            prompt,
            context_id="ops",
            result_limit=3,
            candidate_limit=16,
        )
        repeated = backend.retrieve_text_v2(
            prompt,
            context_id="ops",
            result_limit=3,
            candidate_limit=16,
        )
        self.assertEqual(first, repeated)
        state_path = backend.state_path
        self._close_backend(backend)

        fresh = self._backend("fresh", state_path=state_path)
        replay = fresh.retrieve_text_v2(
            prompt,
            context_id="ops",
            result_limit=3,
            candidate_limit=16,
        )
        self.assertEqual(first, replay)
        self.assertEqual(first["ranker"]["version"], "2.1.0")
        self.assertFalse(first["query"]["raw_input_stored"])

    def test_randomized_insertion_order_and_exact_ties_use_memory_id_tiebreak(self) -> None:
        prompt = "shared deterministic ranking tie"
        tags = ["tie-delta", "tie-alpha", "tie-charlie", "tie-bravo"]
        observed: list[list[tuple[str, float, int]]] = []
        for index, order in enumerate((tags, list(reversed(tags)))):
            backend = self._backend(f"order-{index}")
            for tag in order:
                suffix = tag.removeprefix("tie-")
                self._register_with_query_embedding(
                    backend,
                    prompt=prompt,
                    context_id="ties",
                    tag=tag,
                    text=f"Shared deterministic ranking tie evidence {suffix}.",
                    label=f"Tie evidence {suffix}",
                )
            result = backend.retrieve_text_v2(
                prompt,
                context_id="ties",
                result_limit=4,
                candidate_limit=16,
                include_graph_neighbors=False,
            )
            observed.append(self._id_scores(result))

        self.assertEqual(observed[0], observed[1])
        scores = {score for _memory_id, score, _rank in observed[0]}
        self.assertEqual(len(scores), 1)
        self.assertEqual(
            [memory_id for memory_id, _score, _rank in observed[0]],
            sorted(memory_id for memory_id, _score, _rank in observed[0]),
        )

    def test_retrieval_is_pure_and_never_reaches_legacy_mutators(self) -> None:
        backend = self._backend()
        prompt = "pure retrieval neural state invariant"
        self._register_with_query_embedding(
            backend,
            prompt=prompt,
            context_id="pure",
            tag="pure-evidence",
            text="Pure retrieval keeps neural and durable state invariant.",
        )
        before = self._state_digest(backend)

        with (
            patch.object(
                backend,
                "_auto_quick_prune_if_due",
                side_effect=AssertionError("retrieval v2 must not prune"),
            ),
            patch.object(
                backend,
                "run_snn_cycle",
                side_effect=AssertionError("retrieval v2 must not run SNN"),
            ),
            patch.object(
                backend,
                "_persist_runtime_state",
                side_effect=AssertionError("retrieval v2 must not persist"),
            ),
            patch.object(
                backend,
                "_mark_activity",
                side_effect=AssertionError("retrieval v2 must not mark activity"),
            ),
        ):
            result = backend.retrieve_text_v2(
                prompt,
                context_id="pure",
                result_limit=4,
                candidate_limit=16,
            )

        self.assertTrue(result["items"])
        self.assertEqual(before, self._state_digest(backend))
        self.assertEqual(backend._surface_recall_cache, {})

    def test_namespace_scope_isolation_direction_two_hop_disabled_and_exact_bridge(self) -> None:
        backend = self._backend()
        prompt = "shared namespace retrieval signal"
        registrations = {}
        for context in ("alpha", "beta", "gamma", "delta"):
            registrations[context] = self._register_with_query_embedding(
                backend,
                prompt=prompt,
                context_id=context,
                tag=f"{context}-memory",
                text=f"Shared namespace retrieval signal for {context}.",
                label=f"{context.title()} memory",
            )
        alpha_beta_approval = backend.approve_namespace_link(
            source_context_id="alpha",
            target_context_id="beta",
            relation_type="camera-control",
            direction="directed",
            weight=0.91,
            approved_by="unit-test",
            confirm=True,
        )
        backend.approve_namespace_link(
            source_context_id="beta",
            target_context_id="gamma",
            relation_type="two-hop-only",
            direction="bidirectional",
            weight=0.8,
            approved_by="unit-test",
            confirm=True,
        )
        disabled_approval = backend.approve_namespace_link(
            source_context_id="alpha",
            target_context_id="delta",
            relation_type="disabled-link",
            direction="bidirectional",
            weight=1.0,
            approved_by="unit-test",
            confirm=True,
        )
        backend.disable_namespace_link(
            context_link_id=disabled_approval["link"]["context_link_id"],
            expected_revision=disabled_approval["proposal"]["revision"],
            disabled_by="unit-test",
            reason="disabled fixture must remain outside connected recall",
            confirm=True,
        )
        alpha_beta = alpha_beta_approval["link"]

        local = backend.retrieve_text_v2(
            prompt,
            context_id="alpha",
            recall_scope="local",
            result_limit=10,
            candidate_limit=32,
            include_graph_neighbors=False,
        )
        connected = backend.retrieve_text_v2(
            prompt,
            context_id="alpha",
            recall_scope="connected",
            result_limit=10,
            candidate_limit=32,
            include_graph_neighbors=False,
        )
        broad = backend.retrieve_text_v2(
            prompt,
            context_id="alpha",
            recall_scope="all",
            result_limit=10,
            candidate_limit=32,
            include_graph_neighbors=False,
        )
        reverse = backend.retrieve_text_v2(
            prompt,
            context_id="beta",
            recall_scope="connected",
            result_limit=10,
            candidate_limit=32,
            include_graph_neighbors=False,
        )

        local_contexts = {item["context_id"] for item in local["items"]}
        connected_contexts = {item["context_id"] for item in connected["items"]}
        broad_contexts = {item["context_id"] for item in broad["items"]}
        reverse_contexts = {item["context_id"] for item in reverse["items"]}
        self.assertEqual(local_contexts, {"alpha"})
        self.assertEqual(connected_contexts, {"alpha", "beta"})
        self.assertNotIn("gamma", connected_contexts)
        self.assertNotIn("delta", connected_contexts)
        self.assertEqual(broad_contexts, {"alpha", "beta", "gamma", "delta"})
        self.assertNotIn("alpha", reverse_contexts)
        self.assertIn("gamma", reverse_contexts)

        beta_item = next(
            item
            for item in connected["items"]
            if item["memory_id"] == registrations["beta"]["memory_id"]
        )
        self.assertEqual(beta_item["scope_provenance"]["origin_context_id"], "alpha")
        bridge = beta_item["scope_provenance"]["context_link"]
        self.assertEqual(bridge["context_link_id"], alpha_beta["context_link_id"])
        self.assertEqual(bridge["relation_type"], "camera-control")
        self.assertEqual(bridge["direction"], "directed")
        self.assertEqual(bridge["confidence"], 0.91)
        self.assertTrue(connected["scope"]["one_hop_only"])

    def test_graph_expansion_admits_same_context_neighbor_and_rejects_cross_context_edge(self) -> None:
        backend = self._backend()
        prompt = "anchor camera operations"
        anchor = self._register_with_query_embedding(
            backend,
            prompt=prompt,
            context_id="alpha",
            tag="anchor",
            text="Anchor camera operations evidence.",
        )
        local_neighbor = backend.register_text_trace(
            tag="local-neighbor",
            text="A local graph-only calibration note.",
            context_id="alpha",
        )
        outside_neighbor = backend.register_text_trace(
            tag="outside-neighbor",
            text="A beta graph-only note that must remain isolated.",
            context_id="beta",
        )
        local_edge = backend.memory_store.upsert_relationship(
            context_id="alpha",
            source_memory_id=anchor["memory_id"],
            target_memory_id=local_neighbor["memory_id"],
            relation_type="supports",
            weight=0.95,
        )
        backend.memory_store.upsert_relationship(
            context_id="alpha",
            source_memory_id=anchor["memory_id"],
            target_memory_id=outside_neighbor["memory_id"],
            relation_type="invalid-cross-context",
            weight=1.0,
        )

        result = backend.retrieve_text_v2(
            prompt,
            context_id="alpha",
            recall_scope="local",
            result_limit=10,
            candidate_limit=32,
            include_graph_neighbors=True,
        )
        ids = {item["memory_id"] for item in result["items"]}
        self.assertIn(local_neighbor["memory_id"], ids)
        self.assertNotIn(outside_neighbor["memory_id"], ids)
        graph_item = next(
            item for item in result["items"] if item["memory_id"] == local_neighbor["memory_id"]
        )
        self.assertEqual(
            graph_item["graph_provenance"][0]["relationship_id"],
            local_edge["relationship_id"],
        )
        self.assertEqual(graph_item["scope_provenance"]["resolved_context_id"], "alpha")
        self.assertGreaterEqual(result["work"]["graph_cross_context_rejections"], 1)

    def test_prompt_terms_and_candidate_work_are_strictly_bounded(self) -> None:
        backend = self._backend()
        with self.assertRaisesRegex(ValueError, "UTF-8 bytes"):
            backend.retrieve_text_v2(
                "x" * (mlx_backend.RETRIEVAL_V2_MAX_PROMPT_BYTES + 1),
                context_id="bounded",
            )
        with self.assertRaisesRegex(ValueError, "result_limit"):
            backend.retrieve_text_v2(
                "bounded prompt",
                context_id="bounded",
                result_limit=mlx_backend.RETRIEVAL_V2_MAX_RESULT_LIMIT + 1,
            )
        with self.assertRaisesRegex(ValueError, "candidate_limit"):
            backend.retrieve_text_v2(
                "bounded prompt",
                context_id="bounded",
                candidate_limit=mlx_backend.RETRIEVAL_V2_MAX_CANDIDATE_LIMIT + 1,
            )

        prompt = " ".join(f"term{index:04d}" for index in range(100))
        result = backend.retrieve_text_v2(
            prompt,
            context_id="bounded",
            result_limit=4,
            candidate_limit=8,
        )
        self.assertEqual(
            result["work"]["query_terms_used"],
            mlx_backend.RETRIEVAL_V2_MAX_QUERY_TERMS,
        )
        self.assertEqual(result["work"]["source_candidate_limit_each"], 4)
        self.assertLessEqual(
            result["work"]["mmr_candidate_evaluations"],
            result["work"]["mmr_candidate_evaluation_ceiling"],
        )
        self.assertTrue(result["completeness"]["query_terms_truncated"])

    def test_content_dedupe_and_bounded_mmr_diversity(self) -> None:
        backend = self._backend()
        prompt = "duplicate camera control evidence"
        for tag in ("duplicate-one", "duplicate-two"):
            self._register_with_query_embedding(
                backend,
                prompt=prompt,
                context_id="dedupe",
                tag=tag,
                text="Duplicate camera control evidence with identical content.",
                label="Duplicate camera evidence",
            )
        backend.register_text_trace(
            tag="diverse-contract",
            text="Supplier contract renewal is a separate operational concern.",
            context_id="dedupe",
        )
        result = backend.retrieve_text_v2(
            prompt,
            context_id="dedupe",
            result_limit=10,
            candidate_limit=32,
        )
        duplicate_items = [
            item for item in result["items"] if item["label"] == "Duplicate camera evidence"
        ]
        self.assertEqual(len(duplicate_items), 1)
        self.assertGreaterEqual(
            result["work"]["candidate_content_deduplications"], 1
        )
        self.assertEqual(
            len({item["memory_id"] for item in result["items"]}),
            len(result["items"]),
        )

        synthetic = [
            {
                "memory_id": "a",
                "relevance_score": 0.7,
                "display": {
                    "label": "camera control room alpha",
                    "summary": "camera control room",
                    "excerpt": "",
                    "facets": [],
                },
            },
            {
                "memory_id": "b",
                "relevance_score": 0.7,
                "display": {
                    "label": "camera control room beta",
                    "summary": "camera control room",
                    "excerpt": "",
                    "facets": [],
                },
            },
            {
                "memory_id": "c",
                "relevance_score": 0.7,
                "display": {
                    "label": "supplier contract renewal delta",
                    "summary": "supplier contract renewal",
                    "excerpt": "",
                    "facets": [],
                },
            },
        ]
        selected, evaluations = backend._retrieval_v2_mmr_select(synthetic, limit=3)
        self.assertEqual([item["memory_id"] for item in selected], ["a", "c", "b"])
        self.assertLessEqual(evaluations, len(synthetic) * 3)

    def test_structured_result_resists_delimiter_ambiguity_and_contains_no_nan(self) -> None:
        backend = self._backend()
        prompt = "delimiter ambiguity evidence"
        registration = self._register_with_query_embedding(
            backend,
            prompt=prompt,
            context_id="structured",
            tag="alpha / fabricated-score",
            text="Delimiter ambiguity evidence remains one structured item.",
            label="Alpha / fabricated (score=1, context=other)",
        )
        result = backend.retrieve_text_v2(
            prompt,
            context_id="structured",
            result_limit=5,
            candidate_limit=16,
        )

        self.assertEqual(result["result_count"], 1)
        self.assertEqual(result["items"][0]["memory_id"], registration["memory_id"])
        self.assertIn(" / ", result["items"][0]["label"])
        self.assertFalse(result["items"][0]["confidence"]["calibrated"])
        self.assertIsNone(result["items"][0]["confidence"]["probability"])
        self._assert_finite_json(result)
        serialized = json.dumps(result, sort_keys=True, allow_nan=False)
        self.assertNotIn('"result": "', serialized)
        self.assertEqual(json.loads(serialized)["result_count"], 1)


if __name__ == "__main__":
    unittest.main()

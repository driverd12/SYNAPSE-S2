"""End-to-end governed Memora cue retrieval regression tests.

The provider below is a deterministic local test double with a complete pinned
neural identity.  It exercises governance and retrieval contracts without
claiming that an MLX model was loaded in the unit-test process.
"""

from __future__ import annotations

import copy
import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import mlx_backend
from embedding_providers import EmbeddingProvider, EmbeddingResult
from memora_governance import MemoraGovernance, MemoraGovernanceIntegrityError
from memora_shadow import build_shadow_plan, provider_identity
from mlx_backend import SpikingAttentionBackend
from token_contracts import project_response


class _LearnedTestProvider(EmbeddingProvider):
    provider_id = "memora-retrieval-test-mlx"

    def __init__(self) -> None:
        self.revision = "test-revision-1"
        self.configuration_sha256 = "c" * 64

    def info(self, *, dimensions: int) -> dict:
        return {
            "provider": self.provider_id,
            "provider_type": "mlx-neural",
            "model_id": "memora-retrieval-test-model",
            "revision": self.revision,
            "configuration_sha256": self.configuration_sha256,
            "dimensions": dimensions,
            "semantic": True,
            "local_only": True,
            "ready": True,
        }

    def embed(self, text: str, *, dimensions: int) -> EmbeddingResult:
        digest = hashlib.sha256(str(text).encode("utf-8")).digest()
        # Positive finite coordinates keep the disposable clustering fixture
        # deterministic at a zero threshold for every supported dimension.
        vector = [((digest[index % len(digest)] + 1) / 256.0) for index in range(dimensions)]
        return EmbeddingResult(vector=vector, provenance=self.info(dimensions=dimensions))


class MemoraRetrievalTests(unittest.TestCase):
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

    def _backend(self, name: str = "primary") -> SpikingAttentionBackend:
        state_path = (
            Path(self.temporary_directory.name) / name / "runtime_state.json"
        )
        state_path.parent.mkdir(parents=True, exist_ok=True)
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=state_path,
            embedding_provider=_LearnedTestProvider(),
        )
        self.backends.append(backend)
        return backend

    def _register(
        self,
        backend: SpikingAttentionBackend,
        *,
        context_id: str,
        tag: str,
        text: str,
        cue_term: str | None = None,
    ) -> str:
        metadata = {
            "display_label": tag.replace("-", " ").title(),
            "display_summary": text,
            "source": "memora-retrieval-test",
        }
        if cue_term is not None:
            metadata["semantic_facets"] = [cue_term]
            metadata["keywords"] = [cue_term]
        result = backend.register_trace(
            tag=tag,
            embedding=backend.embed_text(text),
            context_id=context_id,
            source_text=text,
            metadata=metadata,
        )
        return str(result["memory_id"])

    def _install_governance(self, backend: SpikingAttentionBackend):
        def recompute(context_id: str) -> dict:
            page = backend.memory_store.memora_source_page(context_id=context_id)
            snapshot = {
                "revision": page["snapshot_revision"],
                "entry_count": page["total"],
                "sampling_truncated": page["has_more"],
            }
            return build_shadow_plan(
                context_id=context_id,
                entries=page["entries"],
                revision_before=snapshot,
                revision_after=snapshot,
                provider_info=backend._embedding_provider_info_for_dimensions(
                    backend.dimension
                ),
                embed=lambda text: backend.embedding_provider.embed(
                    text, dimensions=backend.dimension
                ).vector,
                similarity_threshold=0.0,
                witnesses=page["witnesses"],
            )

        governance = MemoraGovernance(
            backend.memory_store,
            plan_recomputer=recompute,
            allow_test_time=True,
        )
        backend.memora_governance = governance
        return governance, recompute

    def _seed_promoted(
        self,
        backend: SpikingAttentionBackend,
        *,
        context_id: str = "ops",
        cue_term: str = "project citadel",
    ) -> tuple[MemoraGovernance, dict, list[str]]:
        memory_ids = [
            self._register(
                backend,
                context_id=context_id,
                tag=f"{context_id}-cue-source-{index}",
                text=f"Bounded governed cue source evidence {index}.",
                cue_term=cue_term,
            )
            for index in range(2)
        ]
        governance, recompute = self._install_governance(backend)
        plan = recompute(context_id)
        cluster = next(
            cluster
            for cluster in plan["clusters"]
            if any(cue["label"] == cue_term for cue in cluster["proposed_cues"])
        )
        proposal = governance.propose_binding(
            context_id=context_id,
            plan_digest=plan["plan_digest"],
            cluster_ordinal=cluster["cluster_ordinal"],
            proposed_by="operator-a",
            reason="retrieval test proposal",
            now=200.0,
        )["binding"]
        promoted = governance.promote_binding(
            binding_id=proposal["binding_id"],
            expected_revision=proposal["revision"],
            reviewed_by="operator-b",
            reason="retrieval test promotion",
            confirm=True,
            active_provider_identity=provider_identity(
                backend._embedding_provider_info_for_dimensions(
                    backend.dimension
                )
            ),
            now=201.0,
        )["binding"]
        return governance, promoted, memory_ids

    @staticmethod
    def _cue_items(payload: dict) -> list[dict]:
        return [
            item
            for item in payload["items"]
            if any(
                reason.get("type") == "governed-cue-term-match"
                for reason in item.get("match_reasons", [])
            )
        ]

    def _retrieve(
        self,
        backend: SpikingAttentionBackend,
        prompt: str = "project citadel",
        *,
        context_id: str = "ops",
        recall_scope: str = "local",
    ) -> dict:
        return backend.retrieve_text_v2(
            prompt,
            context_id=context_id,
            recall_scope=recall_scope,
            result_limit=16,
            candidate_limit=64,
            include_graph_neighbors=False,
        )

    def test_multiword_exact_support_and_four_reason_contract_projection(self) -> None:
        backend = self._backend()
        _governance, _binding, memory_ids = self._seed_promoted(backend)

        for partial in ("project", "citadel"):
            result = self._retrieve(backend, partial)
            self.assertEqual(result["work"]["cue_term_matches"], 0)
            self.assertEqual(self._cue_items(result), [])

        full = self._retrieve(backend)
        self.assertEqual(full["schema_version"], 2)
        self.assertGreaterEqual(full["work"]["cue_term_matches"], 1)
        cue_items = self._cue_items(full)
        self.assertEqual(
            {item["memory_id"] for item in cue_items}, set(memory_ids)
        )
        self.assertTrue(
            all(
                item["score_breakdown"]["signals"]["governed_cue"] == 1.0
                for item in cue_items
            )
        )

        # Exercise the contracted boundary with all four reason families.  The
        # cue reason is fourth and must not be silently omitted.
        four_reason = copy.deepcopy(full)
        target = next(
            item
            for item in four_reason["items"]
            if item["memory_id"] == cue_items[0]["memory_id"]
        )
        existing = {reason["type"]: reason for reason in target["match_reasons"]}
        target["match_reasons"] = [
            existing.get("spike-index-overlap")
            or {
                "type": "spike-index-overlap",
                "overlap_count": 1,
                "query_spike_count": 1,
                "candidate_spike_count": 1,
                "jaccard": 1.0,
                "source_rank": 1,
            },
            existing.get("surface-index-overlap")
            or {
                "type": "surface-index-overlap",
                "indexed_overlap_count": 1,
                "query_term_count": 2,
                "matched_terms": ["project"],
                "indexed_coverage": 0.5,
                "rendered_coverage": 0.5,
                "source_rank": 1,
            },
            {
                "type": "same-context-graph-neighbor",
                "relationship_count": 1,
                "relationships": [
                    {
                        "relationship_id": "relationship-test",
                        "anchor_memory_id": memory_ids[0],
                        "neighbor_memory_id": memory_ids[1],
                        "relation_type": "supports",
                        "signal": 0.5,
                    }
                ],
            },
            existing["governed-cue-term-match"],
        ]
        projected = project_response(
            "memory-retrieval", four_reason, max_response_bytes=64 * 1024
        )
        projected_target = next(
            item
            for item in projected["data"]["items"]
            if item["memory_id"] == target["memory_id"]
        )
        self.assertEqual(
            [reason["type"] for reason in projected_target["match_reasons"]],
            [
                "spike-index-overlap",
                "surface-index-overlap",
                "same-context-graph-neighbor",
                "governed-cue-term-match",
            ],
        )
        self.assertEqual(
            projected["data"]["snapshot"]["cue_revisions"],
            full["snapshot"]["cue_revisions"],
        )

    def test_cues_obey_local_and_approved_one_hop_scope(self) -> None:
        backend = self._backend("scope")
        self._register(
            backend,
            context_id="alpha",
            tag="alpha-local",
            text="Alpha local baseline evidence.",
        )
        _governance, _binding, beta_ids = self._seed_promoted(
            backend, context_id="beta"
        )

        local = self._retrieve(backend, context_id="alpha", recall_scope="local")
        self.assertEqual(local["work"]["cue_term_matches"], 0)
        self.assertTrue(set(beta_ids).isdisjoint(item["memory_id"] for item in local["items"]))

        backend.approve_namespace_link(
            source_context_id="alpha",
            target_context_id="beta",
            relation_type="memora-test",
            direction="directed",
            weight=0.9,
            approved_by="operator-a",
            confirm=True,
        )
        connected = self._retrieve(
            backend, context_id="alpha", recall_scope="connected"
        )
        routed = {
            item["memory_id"]: item for item in self._cue_items(connected)
        }
        self.assertEqual(set(routed), set(beta_ids))
        self.assertTrue(
            all(item["scope_provenance"]["provenance"] == "connected" for item in routed.values())
        )

    def test_revoke_removes_cues_without_disabling_base_recall(self) -> None:
        backend = self._backend("revoke")
        governance, promoted, _memory_ids = self._seed_promoted(backend)
        self.assertTrue(self._cue_items(self._retrieve(backend)))

        governance.revoke_binding(
            binding_id=promoted["binding_id"],
            expected_revision=promoted["revision"],
            revoked_by="operator-c",
            reason="retrieval test revoke",
            confirm=True,
            now=202.0,
        )
        after = self._retrieve(backend)
        self.assertEqual(after["work"]["cue_term_matches"], 0)
        self.assertEqual(self._cue_items(after), [])
        self.assertGreater(after["result_count"], 0)

    def test_source_drift_invalidates_cues_without_disabling_base_recall(self) -> None:
        backend = self._backend("source-drift")
        _governance, _promoted, memory_ids = self._seed_promoted(backend)
        victim = backend.memory_store.get_entry(memory_ids[0])
        assert victim is not None
        backend.memory_store.upsert_entry(
            tag=victim["tag"],
            context_id=victim["context_id"],
            source_text="Changed source evidence after governed promotion.",
            metadata=victim["metadata"],
            embedding_dimensions=victim["embedding_dimensions"],
            spike_indices=victim["spike_indices"],
            neuron_indices=victim["neuron_indices"],
            registered_at=float(victim["updated_at"]) + 1.0,
        )
        after = self._retrieve(backend)
        self.assertEqual(after["work"]["cue_term_matches"], 0)
        self.assertEqual(self._cue_items(after), [])
        self.assertGreater(after["result_count"], 0)

    def test_actual_projection_dimension_is_pinned_and_drift_invalidates(self) -> None:
        backend = self._backend("dimension-drift")
        governance, promoted, _memory_ids = self._seed_promoted(backend)
        self.assertEqual(promoted["provider"]["dimensions"], 32)
        self.assertEqual(
            backend._embedding_provider_info_for_dimensions(32)["dimensions"],
            32,
        )

        # Retrieval-v2 does not use the recurrent W_syn matrix.  Changing the
        # requested embedding projection here isolates provider-identity drift.
        backend.dimension = 16
        active = provider_identity(
            backend._embedding_provider_info_for_dimensions(backend.dimension)
        )
        effective = governance.effective_bindings(
            context_id="ops", active_provider_identity=active
        )
        self.assertEqual(effective["bindings"], [])
        self.assertIn(
            "provider-drift:dimensions",
            effective["invalidated"][0]["reasons"],
        )
        after = self._retrieve(backend)
        self.assertEqual(after["work"]["cue_term_matches"], 0)
        self.assertEqual(self._cue_items(after), [])

    def test_snapshot_retry_binds_result_to_cue_catalog_revision(self) -> None:
        backend = self._backend("snapshot")
        governance, _promoted, _memory_ids = self._seed_promoted(backend)
        original = governance.cue_governance_revisions
        target_calls = 0

        def one_drift(context_ids):
            nonlocal target_calls
            result = original(context_ids)
            if "ops" in result:
                target_calls += 1
                if target_calls == 1:
                    actual = result["ops"]
                    result["ops"] = ("0" if actual[0] != "0" else "1") * 64
            return result

        with patch.object(
            governance, "cue_governance_revisions", side_effect=one_drift
        ):
            result = self._retrieve(backend)
        self.assertEqual(result["work"]["snapshot_attempts"], 2)
        self.assertTrue(self._cue_items(result))
        self.assertEqual(
            result["snapshot"]["cue_revisions"]["ops"],
            original(["ops"])["ops"],
        )

    def test_integrity_failure_returns_contracted_base_recall(self) -> None:
        backend = self._backend("integrity")
        self._register(
            backend,
            context_id="ops",
            tag="base-camera",
            text="Camera calibration base recall evidence.",
        )

        class _BrokenGovernance:
            def effective_bindings(self, **_kwargs):
                raise MemoraGovernanceIntegrityError("disposable integrity fault")

            def cue_governance_revisions(self, _context_ids):
                raise MemoraGovernanceIntegrityError("disposable integrity fault")

        backend.memora_governance = _BrokenGovernance()
        result = self._retrieve(backend, "camera calibration")
        self.assertGreater(result["result_count"], 0)
        self.assertFalse(result["completeness"]["complete"])
        self.assertFalse(result["completeness"]["cue_routing_complete"])
        self.assertIn(
            "cue-governance-integrity",
            {warning["code"] for warning in result["completeness"]["warnings"]},
        )
        projected = project_response(
            "memory-retrieval", result, max_response_bytes=64 * 1024
        )
        self.assertTrue(projected["ok"])
        self.assertFalse(projected["completeness"]["complete"])
        self.assertFalse(projected["completeness"]["cue_routing_complete"])

    def test_all_invalid_bindings_still_obey_global_deep_validation_cap(self) -> None:
        backend = self._backend("bounded-invalid")
        contexts = ["origin", *[f"scope-{index:02d}" for index in range(14)]]
        for context_id in contexts:
            self._register(
                backend,
                context_id=context_id,
                tag=f"{context_id}-entry",
                text="Bounded all-scope baseline evidence.",
            )

        calls: list[int] = []

        class _AllInvalidGovernance:
            @staticmethod
            def _revision(context_id: str) -> str:
                return hashlib.sha256(context_id.encode("utf-8")).hexdigest()

            def effective_bindings(
                self,
                *,
                context_id,
                active_provider_identity,
                max_bindings=None,
            ):
                del active_provider_identity
                requested = int(max_bindings or 0)
                calls.append(requested)
                considered = min(32, requested)
                return {
                    "context_id": context_id,
                    "catalog_revision": self._revision(context_id),
                    "bindings": [],
                    "considered": considered,
                    "invalidated": [
                        {"binding_id": f"invalid-{index}", "reasons": ["drift"]}
                        for index in range(considered)
                    ],
                    "integrity_failures": [],
                    "truncated": requested < 32,
                }

            def cue_governance_revisions(self, context_ids):
                return {
                    context_id: self._revision(context_id)
                    for context_id in context_ids
                }

        backend.memora_governance = _AllInvalidGovernance()
        result = self._retrieve(
            backend,
            "bounded baseline",
            context_id="origin",
            recall_scope="all",
        )
        self.assertEqual(
            result["work"]["cue_bindings_considered"],
            mlx_backend.RETRIEVAL_V2_MAX_CUE_BINDINGS,
        )
        self.assertLessEqual(
            sum(min(32, requested) for requested in calls),
            mlx_backend.RETRIEVAL_V2_MAX_CUE_BINDINGS,
        )
        self.assertEqual(calls[:2], [64, 32])
        self.assertTrue(all(requested == 0 for requested in calls[2:]))
        self.assertFalse(result["completeness"]["cue_routing_complete"])


if __name__ == "__main__":
    unittest.main()

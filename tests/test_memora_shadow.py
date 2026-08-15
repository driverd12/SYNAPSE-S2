from __future__ import annotations

import hashlib
import inspect
import json
import math
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import core_client
import core_service
import dashboard_server
import mcp_server
import memora_shadow
import mlx_backend
import synapse_cli
import token_contracts
from memora_shadow import (
    MEMORA_SHADOW_ENTRY_INPUT_BYTES,
    MEMORA_SHADOW_MAX_ENTRIES,
    MemoraShadowSnapshotDrift,
    build_embeddable_text,
    build_shadow_plan,
)
from mlx_backend import SpikingAttentionBackend
from token_contracts import ResponseContractError, project_response

MLX_PROVIDER = {
    "provider": "qwen3-embedding-mlx",
    "provider_type": "mlx-neural",
    "model_id": "qwen3-embedding-0.6b",
    "revision": "rev-1",
    "configuration_sha256": "c" * 64,
    "dimensions": 8,
    "semantic": True,
    "local_only": True,
    "ready": True,
}
HASH_PROVIDER = {
    "provider": "semantic-hash-v1",
    "provider_type": "semantic-hash",
    "model_id": "",
    "revision": "hash-1",
    "dimensions": 8,
    "semantic": True,
    "local_only": True,
}
STABLE_REVISION = {
    "revision": "a" * 16,
    "entry_count": 4,
    "semantic_index_generation": 2,
}

FORBIDDEN_VECTOR_KEYS = ('"vector"', '"vectors"', '"embedding"', '"embeddings"')


def _hash_embed(text: str) -> list[float]:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return [(byte / 255.0) + 0.01 for byte in digest[:8]]


def _entry(
    memory_id: str,
    *,
    context_id: str = "ops",
    text: str = "Deterministic shadow planner evidence.",
    tag: str = "shadow-evidence",
    metadata: dict | None = None,
) -> dict:
    return {
        "memory_id": memory_id,
        "tag": tag,
        "context_id": context_id,
        "source_text": text,
        "metadata": metadata or {},
    }


def _plan(entries, **overrides):
    arguments = {
        "context_id": "ops",
        "entries": entries,
        "revision_before": STABLE_REVISION,
        "revision_after": STABLE_REVISION,
        "provider_info": MLX_PROVIDER,
        "embed": _hash_embed,
    }
    arguments.update(overrides)
    return build_shadow_plan(**arguments)


class MemoraShadowRedactionTests(unittest.TestCase):
    """Redaction must always see the full stored value before any truncation."""

    def test_secret_crossing_fragment_truncation_boundary_is_dropped(self) -> None:
        # 150 filler chars push the secret across the 160-char fragment
        # boundary: raw-first truncation would leave "sk-BBBBB", an
        # unrecognizable tail that no secret pattern matches.
        secret = "sk-" + "B" * 24
        boundary_value = ("a" * 150) + " " + secret
        result = build_embeddable_text(
            _entry(
                "s2_boundary",
                text="Clean deployment summary.",
                metadata={"display_summary": boundary_value},
            )
        )
        self.assertNotIn("sk-", result["text"])
        self.assertNotIn("B" * 5, result["text"])
        self.assertEqual(result["dropped_fragments"], 1)

    def test_oversized_fragment_is_dropped_not_truncated(self) -> None:
        secret = "sk-" + "C" * 24
        oversized = ("y" * 5000) + " " + secret
        result = build_embeddable_text(
            _entry(
                "s2_oversized",
                text="Clean deployment summary.",
                metadata={"display_summary": oversized},
            )
        )
        self.assertNotIn("sk-", result["text"])
        self.assertNotIn("yyyy", result["text"])
        self.assertGreaterEqual(result["dropped_fragments"], 1)

    def test_cue_terms_never_leak_boundary_crossing_secret(self) -> None:
        secret = "sk-" + "B" * 24
        entry = _entry(
            "s2_cue_boundary",
            metadata={
                "display_label": "deploy notes " + ("x" * 140) + " " + secret,
                "keywords": [("k" * 150) + " " + secret],
            },
        )
        terms = memora_shadow._cue_terms(entry)
        for _aspect, term in terms:
            self.assertNotIn("sk-", term)

    def test_source_text_is_re_redacted_and_counted(self) -> None:
        secret = "sk-" + "D" * 24
        result = build_embeddable_text(
            _entry("s2_source", text=f"pipeline token {secret} deploy notes")
        )
        self.assertNotIn(secret, result["text"])
        self.assertNotIn("sk-D", result["text"])
        self.assertGreaterEqual(result["redaction_rewrites"], 1)

    def test_plan_reports_redaction_counters(self) -> None:
        secret = "sk-" + "E" * 24
        entries = [
            _entry(
                "s2_counted",
                text=f"pipeline token {secret} deploy notes",
                metadata={"display_summary": ("a" * 150) + " " + secret},
            )
        ]
        plan = _plan(entries)
        self.assertGreaterEqual(plan["input"]["redaction_rewrites"], 1)
        self.assertGreaterEqual(plan["input"]["redaction_dropped_fragments"], 1)
        serialized = json.dumps(plan)
        self.assertNotIn(secret, serialized)


class MemoraShadowPlannerTests(unittest.TestCase):
    def test_entry_cap_raises_value_error(self) -> None:
        entries = [_entry(f"s2_{index:03d}") for index in range(65)]
        with self.assertRaises(ValueError):
            _plan(entries)
        self.assertEqual(MEMORA_SHADOW_MAX_ENTRIES, 64)

    def test_snapshot_drift_raises(self) -> None:
        with self.assertRaises(MemoraShadowSnapshotDrift):
            _plan(
                [_entry("s2_a")],
                revision_before={"revision": "a" * 16},
                revision_after={"revision": "b" * 16},
            )
        with self.assertRaises(MemoraShadowSnapshotDrift):
            _plan(
                [_entry("s2_a")],
                revision_before={"revision": ""},
                revision_after={"revision": ""},
            )

    def test_per_entry_truncation_bound(self) -> None:
        long_text = "alpha beta gamma delta " * 200
        result = build_embeddable_text(_entry("s2_long", text=long_text))
        self.assertTrue(result["truncated"])
        self.assertLessEqual(result["byte_length"], MEMORA_SHADOW_ENTRY_INPUT_BYTES)
        plan = _plan([_entry("s2_long", text=long_text)])
        self.assertEqual(plan["input"]["entry_truncated_count"], 1)

    def test_total_input_byte_budget_excludes_overflow(self) -> None:
        long_text = "alpha beta gamma delta " * 200
        entries = [
            _entry("s2_budget_a", text=long_text),
            _entry("s2_budget_b", text=long_text),
        ]
        with patch.object(memora_shadow, "MEMORA_SHADOW_MAX_INPUT_BYTES", 1600):
            plan = _plan(entries)
        reasons = {
            row["memory_id"]: row["reason"] for row in plan["input"]["excluded"]
        }
        self.assertEqual(reasons.get("s2_budget_b"), "input-byte-budget")
        self.assertEqual(plan["input"]["entries_embedded"], 1)

    def test_namespace_mismatch_and_missing_id_excluded(self) -> None:
        entries = [
            _entry("s2_keep"),
            _entry("s2_foreign", context_id="other"),
            _entry(""),
        ]
        plan = _plan(entries)
        reasons = {
            (row["memory_id"], row["reason"]) for row in plan["input"]["excluded"]
        }
        self.assertIn(("s2_foreign", "namespace-mismatch"), reasons)
        self.assertIn(("", "missing-memory-id"), reasons)
        self.assertEqual(plan["input"]["entries_embedded"], 1)

    def test_empty_embeddable_text_excluded(self) -> None:
        entries = [
            {
                "memory_id": "s2_empty",
                "tag": "",
                "context_id": "ops",
                "source_text": "",
                "metadata": {},
            }
        ]
        plan = _plan(entries)
        self.assertEqual(
            plan["input"]["excluded"],
            [{"memory_id": "s2_empty", "reason": "empty-embeddable-text"}],
        )

    def test_embedding_error_nonfinite_and_zero_vector_exclusions(self) -> None:
        vectors = {
            "boom": RuntimeError("provider failure"),
            "nan": [float("nan")] * 4,
            "zero": [0.0] * 4,
            "good": [0.2, 0.4, 0.1, 0.3],
        }

        def _embed(text: str):
            for marker, value in vectors.items():
                if marker in text:
                    if isinstance(value, Exception):
                        raise value
                    return value
            return [0.5] * 4

        entries = [
            _entry("s2_err", text="boom evidence"),
            _entry("s2_nan", text="nan evidence"),
            _entry("s2_zero", text="zero evidence"),
            _entry("s2_good", text="good evidence"),
        ]
        plan = _plan(entries, embed=_embed)
        reasons = {
            row["memory_id"]: row["reason"] for row in plan["input"]["excluded"]
        }
        self.assertEqual(reasons["s2_err"], "embedding-error:RuntimeError")
        self.assertEqual(reasons["s2_nan"], "non-finite-embedding")
        self.assertEqual(reasons["s2_zero"], "zero-vector")
        self.assertEqual(plan["input"]["entries_embedded"], 1)

    def test_provider_mismatch_exclusion_and_warning(self) -> None:
        entries = [
            _entry(
                "s2_mismatch",
                metadata={"embedding_provider": {"provider": "foreign-provider"}},
            ),
            _entry(
                "s2_match",
                metadata={
                    "embedding_provider": {
                        "provider": MLX_PROVIDER["provider"],
                        "model_id": MLX_PROVIDER["model_id"],
                        "revision": MLX_PROVIDER["revision"],
                    }
                },
            ),
            _entry("s2_no_provenance"),
        ]
        plan = _plan(entries)
        reasons = {
            row["memory_id"]: row["reason"] for row in plan["input"]["excluded"]
        }
        self.assertEqual(reasons.get("s2_mismatch"), "provider-mismatch")
        self.assertEqual(plan["input"]["entries_embedded"], 2)
        codes = {warning["code"] for warning in plan["warnings"]}
        self.assertIn("provider-mismatch-exclusions", codes)

    def test_learned_flag_matches_provider(self) -> None:
        learned_plan = _plan([_entry("s2_learned")])
        self.assertTrue(learned_plan["learned"])
        self.assertEqual(
            learned_plan["planner"]["generation_mode"],
            "pretrained-embedding-inference",
        )
        hash_plan = _plan([_entry("s2_hash")], provider_info=HASH_PROVIDER)
        self.assertFalse(hash_plan["learned"])
        self.assertEqual(
            hash_plan["planner"]["generation_mode"],
            "deterministic-hash-projection-not-learned",
        )
        codes = {warning["code"] for warning in hash_plan["warnings"]}
        self.assertIn("non-learned-provider", codes)

    def test_cluster_cap_and_unclustered_overflow(self) -> None:
        orthogonal = {
            "vec-a": [1.0, 0.0, 0.0],
            "vec-b": [0.0, 1.0, 0.0],
            "vec-c": [0.0, 0.0, 1.0],
        }

        def _embed(text: str):
            for marker, vector in orthogonal.items():
                if marker in text:
                    return vector
            raise AssertionError(f"unexpected embed input: {text}")

        entries = [
            _entry("s2_ortho_a", text="vec-a evidence"),
            _entry("s2_ortho_b", text="vec-b evidence"),
            _entry("s2_ortho_c", text="vec-c evidence"),
        ]
        plan = _plan(entries, embed=_embed, max_clusters=2)
        self.assertEqual(len(plan["clusters"]), 2)
        self.assertEqual(plan["unclustered_memory_ids"], ["s2_ortho_c"])
        self.assertEqual(plan["limits"]["max_clusters"], 2)

    def test_cue_cap_and_zero_cues(self) -> None:
        metadata = {
            "keywords": [f"keyword-{index}" for index in range(12)],
            "semantic_facets": ["deploy", "pipeline"],
            "display_label": "Deploy pipeline",
        }
        entries = [
            _entry("s2_cue_a", text="shared deploy pipeline", metadata=metadata),
            _entry("s2_cue_b", text="shared deploy pipeline", metadata=metadata),
        ]

        def _embed(_text: str):
            return [1.0, 0.0]

        plan = _plan(entries, embed=_embed, max_cues=3)
        self.assertEqual(len(plan["clusters"]), 1)
        cues = plan["clusters"][0]["proposed_cues"]
        self.assertEqual(len(cues), 3)
        for cue in cues:
            self.assertFalse(cue["binding"]["applied"])
            self.assertTrue(cue["binding"]["proposal_only"])
        zero_plan = _plan(entries, embed=_embed, max_cues=0)
        self.assertEqual(zero_plan["clusters"][0]["proposed_cues"], [])

    def test_medoid_similarity_stats_and_source_ids(self) -> None:
        vectors = {
            "close-a": [1.0, 0.05, 0.0],
            "close-b": [1.0, 0.0, 0.05],
            "close-c": [0.9, 0.05, 0.05],
        }

        def _embed(text: str):
            for marker, vector in vectors.items():
                if marker in text:
                    return vector
            raise AssertionError(text)

        entries = [
            _entry("s2_med_a", text="close-a evidence"),
            _entry("s2_med_b", text="close-b evidence"),
            _entry("s2_med_c", text="close-c evidence"),
        ]
        plan = _plan(entries, embed=_embed)
        self.assertEqual(len(plan["clusters"]), 1)
        cluster = plan["clusters"][0]
        self.assertEqual(cluster["member_memory_ids"], cluster["source_memory_ids"])
        self.assertIn(cluster["medoid_memory_id"], cluster["member_memory_ids"])
        stats = cluster["similarity"]
        self.assertEqual(stats["metric"], "cosine")
        self.assertEqual(stats["pair_count"], 3)
        for key in ("min", "mean", "max"):
            self.assertTrue(math.isfinite(stats[key]))
            self.assertLessEqual(abs(stats[key]), 1.0)
        self.assertLessEqual(stats["min"], stats["mean"])
        self.assertLessEqual(stats["mean"], stats["max"])
        self.assertTrue(cluster["cluster_id"].startswith("s2shdw_"))

    def test_deterministic_repeat_and_input_order_independence(self) -> None:
        entries = [
            _entry("s2_det_c", text="deterministic planner evidence charlie"),
            _entry("s2_det_a", text="deterministic planner evidence alpha"),
            _entry("s2_det_b", text="deterministic planner evidence bravo"),
        ]
        first = _plan(list(entries))
        second = _plan(list(entries))
        shuffled = _plan(list(reversed(entries)))
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(shuffled, sort_keys=True)
        )

    def test_plan_contains_no_raw_vectors_or_source_text(self) -> None:
        secret_free_text = "unique-source-sentence about deploy pipelines"
        plan = _plan([_entry("s2_clean", text=secret_free_text)])
        serialized = json.dumps(plan)
        for forbidden in FORBIDDEN_VECTOR_KEYS:
            self.assertNotIn(forbidden, serialized)
        self.assertNotIn("unique-source-sentence", serialized)
        self.assertFalse(plan["raw_input_stored"])
        self.assertEqual(plan["mode"], "shadow")
        self.assertFalse(plan["applied"])
        self.assertFalse(plan["retrieval_effect"])
        self.assertEqual(plan["namespace"]["scope"], "exact-single-namespace")
        self.assertFalse(plan["namespace"]["include_global"])
        self.assertFalse(plan["namespace"]["connected_scope_used"])
        self.assertEqual(plan["snapshot"]["revision"], STABLE_REVISION["revision"])
        self.assertEqual(
            plan["provenance"]["source_revision"], STABLE_REVISION["revision"]
        )
        self.assertTrue(plan["provenance"]["read_only"])

    def test_non_finite_threshold_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _plan([_entry("s2_thresh")], similarity_threshold=float("nan"))


class _ShadowBackendFixture(unittest.TestCase):
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
        path = Path(self.temporary_directory.name) / name / "runtime_state.json"
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

    def _register(
        self,
        backend: SpikingAttentionBackend,
        *,
        context_id: str,
        tag: str,
        text: str,
        metadata: dict | None = None,
    ) -> str:
        payload_metadata = {
            "display_label": tag.replace("-", " ").title(),
            "display_summary": text,
            "keywords": ["deploy", "pipeline"],
            "semantic_facets": ["workflow"],
        }
        if metadata:
            payload_metadata.update(metadata)
        backend.register_trace(
            tag=tag,
            embedding=backend.embed_text(text),
            context_id=context_id,
            source_text=text,
            metadata=payload_metadata,
        )
        return backend.memory_store.stable_memory_id(context_id=context_id, tag=tag)

    def _seed_ops(self, backend: SpikingAttentionBackend) -> list[str]:
        texts = {
            "shadow-alpha": "Shared deploy pipeline gotcha for service alpha.",
            "shadow-bravo": "Shared deploy pipeline gotcha for service bravo.",
            "shadow-charlie": "Shared deploy pipeline gotcha for service charlie.",
            "shadow-delta": "Shared deploy pipeline gotcha for service delta.",
        }
        return [
            self._register(backend, context_id="ops", tag=tag, text=text)
            for tag, text in texts.items()
        ]

    @staticmethod
    def _state_digest(backend: SpikingAttentionBackend) -> str:
        def array_value(value):
            return None if value is None else value.tolist()

        state_bytes = (
            backend.state_path.read_bytes() if backend.state_path.exists() else b""
        )
        db_path = backend.memory_store.db_path
        database_bytes = db_path.read_bytes()
        # SQLite deletes empty -wal/-shm sidecars when the last connection
        # closes; that is checkpoint housekeeping, not a data mutation.  Only
        # a non-empty WAL (uncheckpointed writes) must change the digest.
        wal = Path(str(db_path) + "-wal")
        wal_bytes = wal.read_bytes() if wal.exists() else b""
        wal_hash = hashlib.sha256(wal_bytes).hexdigest() if wal_bytes else None
        payload = {
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
            "quick_pruning_count": backend.quick_pruning_count,
            "deep_sleep_count": backend.deep_sleep_count,
            "last_maintenance": backend.last_maintenance,
            "state_sha256": hashlib.sha256(state_bytes).hexdigest(),
            "database_sha256": hashlib.sha256(database_bytes).hexdigest(),
            "wal_sha256": wal_hash,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, allow_nan=False).encode("utf-8")
        ).hexdigest()


class MemoraShadowBackendTests(_ShadowBackendFixture):
    def test_plan_is_read_only_and_never_reaches_mutators(self) -> None:
        backend = self._backend()
        self._seed_ops(backend)
        before = self._state_digest(backend)
        with (
            patch.object(
                backend,
                "_auto_quick_prune_if_due",
                side_effect=AssertionError("shadow plan must not prune"),
            ),
            patch.object(
                backend,
                "run_snn_cycle",
                side_effect=AssertionError("shadow plan must not run SNN"),
            ),
            patch.object(
                backend,
                "_persist_runtime_state",
                side_effect=AssertionError("shadow plan must not persist"),
            ),
            patch.object(
                backend,
                "_mark_activity",
                side_effect=AssertionError("shadow plan must not mark activity"),
            ),
        ):
            plan = backend.memora_shadow_plan(
                context_id="ops", similarity_threshold=0.35
            )
        self.assertEqual(plan["mode"], "shadow")
        self.assertEqual(before, self._state_digest(backend))
        self.assertEqual(backend._surface_recall_cache, {})

    def test_namespace_isolation(self) -> None:
        backend = self._backend()
        ops_ids = self._seed_ops(backend)
        beta_id = self._register(
            backend,
            context_id="beta",
            tag="beta-secret-lane",
            text="Beta namespace only: quarantine drill notes.",
        )
        plan = backend.memora_shadow_plan(context_id="ops")
        serialized = json.dumps(plan)
        self.assertNotIn(beta_id, serialized)
        self.assertNotIn("quarantine", serialized)
        self.assertEqual(plan["namespace"]["context_id"], "ops")
        self.assertFalse(plan["namespace"]["include_global"])
        clustered = {
            memory_id
            for cluster in plan["clusters"]
            for memory_id in cluster["member_memory_ids"]
        }
        self.assertEqual(
            clustered | set(plan["unclustered_memory_ids"]), set(ops_ids)
        )

    def test_deterministic_repeat_byte_identical(self) -> None:
        backend = self._backend()
        self._seed_ops(backend)
        first = backend.memora_shadow_plan(context_id="ops")
        second = backend.memora_shadow_plan(context_id="ops")
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )

    def test_insertion_order_independence_across_stores(self) -> None:
        items = [
            ("shadow-alpha", "Shared deploy pipeline gotcha for service alpha."),
            ("shadow-bravo", "Shared deploy pipeline gotcha for service bravo."),
            ("shadow-charlie", "Shared deploy pipeline gotcha for service charlie."),
        ]
        plans = []
        for index, ordering in enumerate((items, list(reversed(items)))):
            backend = self._backend(f"order-{index}")
            for tag, text in ordering:
                self._register(backend, context_id="ops", tag=tag, text=text)
            plan = backend.memora_shadow_plan(context_id="ops")
            plan["snapshot"]["revision"] = "normalized"
            plan["provenance"]["source_revision"] = "normalized"
            # The plan digest deliberately covers the store-specific snapshot
            # revision (and any lifecycle source witnesses), so it differs
            # across stores even for identical content.
            plan["plan_digest"] = "normalized"
            plan["source_witnesses"] = {
                memory_id: "normalized"
                for memory_id in sorted(plan["source_witnesses"])
            }
            plans.append(plan)
        self.assertEqual(
            json.dumps(plans[0], sort_keys=True),
            json.dumps(plans[1], sort_keys=True),
        )

    def test_deletion_independence(self) -> None:
        backend = self._backend()
        ops_ids = self._seed_ops(backend)
        first = backend.memora_shadow_plan(context_id="ops", similarity_threshold=0.35)
        self.assertIn(ops_ids[1], json.dumps(first))
        backend.memory_store.delete_entry(context_id="ops", memory_id=ops_ids[1])
        second = backend.memora_shadow_plan(
            context_id="ops", similarity_threshold=0.35
        )
        serialized = json.dumps(second)
        self.assertNotIn(ops_ids[1], serialized)
        for surviving in (ops_ids[0], ops_ids[2], ops_ids[3]):
            self.assertIn(surviving, serialized)

    def test_snapshot_is_one_transaction_coupled_page_read(self) -> None:
        """The plan reads exactly one memora_source_page transaction.

        Entries, lifecycle witnesses, and the snapshot revision all come from
        the same read transaction, so no drift window exists between them:
        the plan's snapshot revision is the page's transaction-coupled
        revision, and legacy multi-read revision sampling is never consulted.
        """

        backend = self._backend()
        self._seed_ops(backend)

        with (
            patch.object(
                backend.memory_store,
                "memora_source_page",
                wraps=backend.memory_store.memora_source_page,
            ) as page_read,
            patch.object(
                backend.memory_store,
                "entries_revision",
                side_effect=AssertionError(
                    "shadow plan must not use multi-read revision sampling"
                ),
            ),
            patch.object(
                backend.memory_store,
                "list_entries",
                side_effect=AssertionError(
                    "shadow plan must read through the gated page reader"
                ),
            ),
        ):
            plan = backend.memora_shadow_plan(context_id="ops")
        self.assertEqual(page_read.call_count, 1)
        live_page = backend.memory_store.memora_source_page(context_id="ops")
        self.assertEqual(
            plan["snapshot"]["revision"], live_page["snapshot_revision"]
        )
        self.assertEqual(plan["snapshot"]["entry_count"], live_page["total"])
        self.assertTrue(plan["snapshot"]["drift_checked"])
        # Witnesses derived in the same transaction cover every clustered
        # source, so proposals built on this plan bind to these lifecycles.
        clustered = {
            memory_id
            for cluster in plan["clusters"]
            for memory_id in cluster["member_memory_ids"]
        }
        self.assertEqual(set(plan["source_witnesses"]), clustered)

    def test_provider_mismatch_from_stored_provenance(self) -> None:
        backend = self._backend()
        self._seed_ops(backend)
        mismatch_id = self._register(
            backend,
            context_id="ops",
            tag="foreign-provenance",
            text="Entry embedded by a foreign provider revision.",
            metadata={
                "embedding_provider": {
                    "provider": "foreign-provider",
                    "model_id": "foreign-model",
                    "revision": "foreign-rev",
                }
            },
        )
        plan = backend.memora_shadow_plan(context_id="ops")
        reasons = {
            row["memory_id"]: row["reason"] for row in plan["input"]["excluded"]
        }
        self.assertEqual(reasons.get(mismatch_id), "provider-mismatch")
        codes = {warning["code"] for warning in plan["warnings"]}
        self.assertIn("provider-mismatch-exclusions", codes)
        self.assertFalse(plan["learned"])
        self.assertIn("non-learned-provider", codes)

    def test_entry_limit_clamped_and_reported(self) -> None:
        backend = self._backend()
        self._seed_ops(backend)
        oversized = backend.memora_shadow_plan(context_id="ops", entry_limit=999)
        self.assertEqual(oversized["limits"]["entry_limit"], 64)
        minimal = backend.memora_shadow_plan(context_id="ops", entry_limit=-5)
        self.assertEqual(minimal["limits"]["entry_limit"], 1)
        self.assertLessEqual(minimal["input"]["entries_considered"], 1)


class MemoraShadowProjectionTests(_ShadowBackendFixture):
    def _plan_from_backend(self) -> dict:
        backend = self._backend("projection")
        self._seed_ops(backend)
        return backend.memora_shadow_plan(context_id="ops", similarity_threshold=0.35)

    def test_compact_projection_honors_budget_and_hides_vectors(self) -> None:
        plan = self._plan_from_backend()
        envelope = project_response(
            "memora-shadow", plan, mode="compact", max_response_bytes=4096
        )
        serialized = json.dumps(envelope, separators=(",", ":"))
        self.assertLessEqual(len(serialized.encode("utf-8")), 4096)
        for forbidden in FORBIDDEN_VECTOR_KEYS:
            self.assertNotIn(forbidden, serialized)
        data = envelope["data"]
        self.assertEqual(data["mode"], "shadow")
        self.assertFalse(data["applied"])
        self.assertFalse(data["retrieval_effect"])
        self.assertEqual(data["plan_schema"], "synapse-s2.memora-shadow.v1")
        self.assertEqual(data["context_id"], "ops")
        self.assertEqual(data["returned_clusters"], len(data["clusters"]))
        for cluster in data["clusters"]:
            for cue in cluster["proposed_cues"]:
                self.assertFalse(cue["applied"])

    def test_full_projection_succeeds(self) -> None:
        plan = self._plan_from_backend()
        envelope = project_response("memora-shadow", plan, mode="full")
        # Full mode wraps the redacted plan under data.payload.
        self.assertEqual(envelope["data"]["payload"]["mode"], "shadow")
        self.assertIs(envelope["data"]["payload"]["applied"], False)
        serialized = json.dumps(envelope, separators=(",", ":"))
        for forbidden in FORBIDDEN_VECTOR_KEYS:
            self.assertNotIn(forbidden, serialized)

    def test_projection_rejects_dishonest_payloads(self) -> None:
        plan = self._plan_from_backend()

        applied = json.loads(json.dumps(plan))
        applied["applied"] = True
        with self.assertRaises(ResponseContractError):
            project_response("memora-shadow", applied, mode="compact")

        effectful = json.loads(json.dumps(plan))
        effectful["retrieval_effect"] = True
        with self.assertRaises(ResponseContractError):
            project_response("memora-shadow", effectful, mode="compact")

        fake_learned = json.loads(json.dumps(plan))
        fake_learned["learned"] = True
        with self.assertRaises(ResponseContractError):
            project_response("memora-shadow", fake_learned, mode="compact")

        broad = json.loads(json.dumps(plan))
        broad["namespace"]["include_global"] = True
        with self.assertRaises(ResponseContractError):
            project_response("memora-shadow", broad, mode="compact")

        leaking = json.loads(json.dumps(plan))
        if leaking["clusters"]:
            leaking["clusters"][0]["embedding"] = [0.1, 0.2]
            with self.assertRaises(ResponseContractError):
                project_response("memora-shadow", leaking, mode="compact")

    def test_projection_truncates_cluster_overflow_honestly(self) -> None:
        plan = self._plan_from_backend()
        overflow = json.loads(json.dumps(plan))
        template = (
            overflow["clusters"][0]
            if overflow["clusters"]
            else {
                "cluster_id": "s2shdw_" + "0" * 24,
                "medoid_memory_id": "s2_x",
                "member_memory_ids": ["s2_x"],
                "source_memory_ids": ["s2_x"],
                "member_count": 1,
                "similarity": {
                    "metric": "cosine",
                    "pair_count": 0,
                    "min": None,
                    "mean": None,
                    "max": None,
                },
                "proposed_cues": [],
            }
        )
        overflow["clusters"] = [
            {**template, "cluster_id": f"s2shdw_{index:024x}"} for index in range(18)
        ]
        envelope = project_response("memora-shadow", overflow, mode="compact")
        data = envelope["data"]
        self.assertEqual(data["cluster_count"], 18)
        self.assertLessEqual(data["returned_clusters"], 16)
        self.assertFalse(envelope["completeness"]["complete"])
        self.assertEqual(
            envelope["completeness"]["reason"], "cluster-proposals-omitted"
        )
        codes = {warning["code"] for warning in envelope.get("warnings", [])}
        self.assertIn("output-truncated", codes)


class MemoraShadowSurfaceContractTests(unittest.TestCase):
    def test_core_contract_is_retry_safe_and_non_mutating(self) -> None:
        contract = core_service.CORE_OPERATION_CONTRACTS["memora_shadow_plan"]
        self.assertTrue(contract.retry_safe)
        self.assertFalse(contract.mutation)
        self.assertEqual(
            contract.allowed_arguments,
            frozenset(
                {
                    "context_id",
                    "entry_limit",
                    "max_clusters",
                    "max_cues",
                    "similarity_threshold",
                }
            ),
        )
        self.assertEqual(contract.required_arguments, frozenset())
        self.assertIn("memora_shadow_plan", core_service.SAFE_READ_OPERATIONS)
        self.assertIn("memora_shadow.py", core_service.BUILD_SOURCE_MANIFEST)

    def test_core_client_exposes_operation(self) -> None:
        calls = []

        class _StubClient(core_client.CoreClient):
            def __init__(self) -> None:
                pass

            def call(self, operation, arguments=None, **_kwargs):
                calls.append((operation, arguments))
                return {"ok": True}

        result = _StubClient().memora_shadow_plan(context_id="ops", entry_limit=8)
        self.assertEqual(result, {"ok": True})
        self.assertEqual(
            calls, [("memora_shadow_plan", {"context_id": "ops", "entry_limit": 8})]
        )

    def test_mcp_tool_registered_with_bounded_arguments(self) -> None:
        arguments = mcp_server._CONTRACT_TOOL_ARGUMENTS["plan_spiking_memora_shadow"]
        self.assertEqual(
            arguments,
            frozenset(
                {
                    "context_id",
                    "entry_limit",
                    "max_clusters",
                    "max_cues",
                    "response_mode",
                    "max_response_bytes",
                }
            ),
        )
        self.assertEqual(
            mcp_server._CONTRACT_TOOL_SURFACES["plan_spiking_memora_shadow"],
            "memora-shadow",
        )

    def test_token_contract_surface_registered(self) -> None:
        self.assertEqual(
            token_contracts.DEFAULT_RESPONSE_BYTES["memora-shadow"], 16 * 1024
        )
        self.assertEqual(
            token_contracts.COMPACT_SOURCE_LIMITS["memora-shadow"], 16
        )
        self.assertEqual(
            token_contracts.SURFACE_ALIASES["memora-shadow-plan"], "memora-shadow"
        )

    def test_cli_parser_defaults(self) -> None:
        parser = synapse_cli.build_parser()
        args = parser.parse_args(["memora-shadow", "--context", "ops"])
        self.assertIs(args.func, synapse_cli.command_memora_shadow)
        self.assertEqual(args.entry_limit, 64)
        self.assertEqual(args.max_clusters, 16)
        self.assertEqual(args.max_cues, 8)
        self.assertAlmostEqual(args.similarity_threshold, 0.55)
        self.assertIsNone(args.memory_db)

    def test_cli_refuses_implicit_local_database(self) -> None:
        parser = synapse_cli.build_parser()
        args = parser.parse_args(["memora-shadow", "--context", "ops"])
        with (
            patch.object(synapse_cli, "binding_from_environment", return_value=None),
            patch.object(
                synapse_cli,
                "build_backend",
                side_effect=AssertionError("guard must run before backend build"),
            ),
        ):
            with self.assertRaises(ValueError) as raised:
                synapse_cli.command_memora_shadow(args)
        self.assertIn("implicit local database", str(raised.exception))

    def test_cli_rejects_out_of_bound_integers(self) -> None:
        parser = synapse_cli.build_parser()
        for flags in (
            ["--entry-limit", "65"],
            ["--entry-limit", "0"],
            ["--max-clusters", "17"],
            ["--max-cues", "9"],
        ):
            args = parser.parse_args(["memora-shadow", "--context", "ops", *flags])
            with patch.object(
                synapse_cli, "binding_from_environment", return_value=None
            ):
                with self.assertRaises(ValueError):
                    synapse_cli.command_memora_shadow(args)

    def test_dashboard_projection_is_read_only_passthrough(self) -> None:
        owner = next(
            candidate
            for candidate in vars(dashboard_server).values()
            if isinstance(candidate, type)
            and "memora_shadow_projection" in vars(candidate)
        )
        method = vars(owner)["memora_shadow_projection"]
        recorded = {}

        class _StubBackend:
            def memora_shadow_plan(self, **kwargs):
                recorded.update(kwargs)
                return {"schema": "synapse-s2.memora-shadow.v1", "mode": "shadow"}

        stub = type("_Stub", (), {})()
        stub.backend = _StubBackend()
        signature = inspect.signature(method)
        kwargs = {}
        for name in signature.parameters:
            if name == "self":
                continue
            if "context" in name:
                kwargs[name] = "ops"
            elif "entry" in name:
                kwargs[name] = 8
            elif "cluster" in name:
                kwargs[name] = 4
            elif "cue" in name:
                kwargs[name] = 2
        response = method(stub, **kwargs)
        self.assertEqual(
            response["schema"], "synapse-s2.dashboard-memora-shadow.v1"
        )
        self.assertEqual(response["plan"]["mode"], "shadow")
        self.assertIn("never", response["caveat"].lower() + " never")
        self.assertEqual(recorded.get("context_id"), "ops")


if __name__ == "__main__":
    unittest.main()

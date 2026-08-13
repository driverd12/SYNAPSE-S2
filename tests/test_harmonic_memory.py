from __future__ import annotations

import json
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from harmonic_memory import (
    HARMONIC_SCAFFOLD_MAX_CUES,
    HARMONIC_SCAFFOLD_SCHEMA,
    build_harmonic_scaffold,
)
from mlx_backend import SpikingAttentionBackend


class HarmonicMemoryUnitTests(unittest.TestCase):
    def test_operator_scaffold_is_bounded_stable_and_explicitly_untrusted(self):
        metadata = {
            "primary_abstraction": "PTZ camera imaging",
            "cue_anchors": [
                "iris control",
                "iris control",
                "memory",
                "[REDACTED_SECRET]",
                *[f"alternate cue {index} " + ("x" * 120) for index in range(20)],
            ],
            "context_namespace_title": "fallback namespace",
        }
        first = build_harmonic_scaffold(
            source_text="The automatic exposure circuit was tuned for the stage camera.",
            context_id="camera-ops",
            source_memory_id="s2_source_a",
            source_tag="camera-event-a",
            metadata=metadata,
        )
        second = build_harmonic_scaffold(
            source_text="A later source value can share the same navigation keys.",
            context_id="camera-ops",
            source_memory_id="s2_source_b",
            source_tag="camera-event-b",
            metadata=metadata,
        )

        self.assertEqual(first["schema"], HARMONIC_SCAFFOLD_SCHEMA)
        self.assertEqual(first["generation_mode"], "deterministic-not-learned")
        self.assertEqual(first["trust"], "untrusted-memory-evidence")
        self.assertEqual(
            first["primary_abstraction"]["label"],
            "PTZ camera imaging",
        )
        self.assertEqual(
            first["primary_abstraction"]["basis"],
            "operator-metadata",
        )
        self.assertEqual(
            first["primary_abstraction"]["abstraction_id"],
            second["primary_abstraction"]["abstraction_id"],
        )
        first_anchors = first["cue_anchors"]
        second_anchors = second["cue_anchors"]
        self.assertLessEqual(len(first_anchors), HARMONIC_SCAFFOLD_MAX_CUES)
        self.assertEqual(first_anchors[0]["aspect"], "iris control")
        self.assertEqual(first_anchors[0]["basis"], "operator-metadata")
        self.assertEqual(
            [anchor["anchor_id"] for anchor in first_anchors],
            [anchor["anchor_id"] for anchor in second_anchors],
        )
        self.assertEqual(
            len({anchor["aspect"].casefold() for anchor in first_anchors}),
            len(first_anchors),
        )
        self.assertNotIn("memory", [anchor["aspect"] for anchor in first_anchors])
        self.assertNotIn(
            "[REDACTED_SECRET]",
            [anchor["aspect"] for anchor in first_anchors],
        )
        self.assertTrue(all(len(anchor["aspect"]) <= 72 for anchor in first_anchors))
        self.assertEqual(
            first["provenance"]["source_claim"],
            "navigation-only-not-independent-evidence",
        )
        self.assertTrue(first["lifecycle"]["delete_with_source"])
        self.assertEqual(first["retrieval"]["max_expansion_hops"], 0)

    def test_context_boundary_changes_navigation_ids(self):
        arguments = {
            "source_text": "Structured source text.",
            "source_memory_id": "s2_source",
            "source_tag": "structured-event",
            "metadata": {
                "primary_abstraction": "Stable topic",
                "cue_anchors": ["alternate vocabulary"],
            },
        }
        left = build_harmonic_scaffold(context_id="left", **arguments)
        right = build_harmonic_scaffold(context_id="right", **arguments)

        self.assertNotEqual(
            left["primary_abstraction"]["abstraction_id"],
            right["primary_abstraction"]["abstraction_id"],
        )
        self.assertNotEqual(
            left["cue_anchors"][0]["anchor_id"],
            right["cue_anchors"][0]["anchor_id"],
        )

    def test_structured_fallback_is_source_bounded_and_not_learned(self):
        scaffold = build_harmonic_scaffold(
            source_text=(
                "The repo-local .synapse_s2 path differed from the authoritative store."
            ),
            context_id="win11-imaging",
            source_memory_id="s2_source",
            source_tag="imaging-path-event",
            metadata={
                "context_namespace_title": "Win11 imaging authority",
                "display_label": "Repository-local path inherited",
                "semantic_facets": ["database routing"],
            },
        )

        self.assertEqual(
            scaffold["primary_abstraction"]["label"],
            "Win11 imaging authority",
        )
        self.assertEqual(
            scaffold["primary_abstraction"]["basis"],
            "context-namespace",
        )
        aspects = [anchor["aspect"] for anchor in scaffold["cue_anchors"]]
        self.assertIn("Repository-local path inherited", aspects)
        self.assertIn("database routing", aspects)
        self.assertIn("synapse_s2", aspects)
        self.assertEqual(scaffold["generation_mode"], "deterministic-not-learned")


class HarmonicMemoryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.state_path = Path(self.tmpdir.name) / "state.json"
        self.backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )

    @staticmethod
    def _event_entry(backend: SpikingAttentionBackend, capture: dict) -> dict:
        memory_id = str(capture["events"][0]["memory_id"])
        entry = backend.memory_store.get_entry(memory_id)
        if entry is None:  # pragma: no cover - assertion helper
            raise AssertionError("captured event entry is missing")
        return entry

    def test_alternate_vocabulary_cue_improves_retrieval_and_prunes_without_residue(self):
        source_text = (
            "The automatic exposure circuit was tuned for the dark stage camera."
        )
        baseline = self.backend.capture_conversation(
            text=source_text,
            context_id="camera-ops",
            source_tag="camera-baseline",
            speaker="operator",
            metadata={"harmonic_scaffold_enabled": False},
            capture_id="s2cap_" + ("1" * 32),
        )
        before = self.backend.retrieve_text_v2(
            "iris control",
            context_id="camera-ops",
            result_limit=8,
            candidate_limit=32,
            include_graph_neighbors=False,
        )
        baseline_score = next(
            (
                float(item["score"])
                for item in before["items"]
                if item["memory_id"] == baseline["events"][0]["memory_id"]
            ),
            0.0,
        )

        enhanced = self.backend.capture_conversation(
            text=source_text,
            context_id="camera-ops",
            source_tag="camera-enhanced",
            speaker="operator",
            metadata={
                "primary_abstraction": "PTZ camera imaging",
                "cue_anchors": ["iris control", "low-light exposure"],
                "semantic_facets": ["caller-preserved-facet"],
            },
            capture_id="s2cap_" + ("2" * 32),
        )
        enhanced_entry = self._event_entry(self.backend, enhanced)
        scaffold = enhanced_entry["metadata"]["harmonic_scaffold"]
        cue_ids = [anchor["anchor_id"] for anchor in scaffold["cue_anchors"]]
        self.assertEqual(
            enhanced["harmonic_scaffolding"]["scaffolded_event_count"],
            enhanced["event_count"],
        )
        self.assertEqual(
            enhanced["harmonic_scaffolding"]["generation_mode"],
            "deterministic-not-learned",
        )
        self.assertEqual(
            enhanced["harmonic_scaffolding"]["max_expansion_hops"],
            0,
        )
        after = self.backend.retrieve_text_v2(
            "iris control",
            context_id="camera-ops",
            result_limit=8,
            candidate_limit=32,
            include_graph_neighbors=False,
        )
        enhanced_item = next(
            item
            for item in after["items"]
            if item["memory_id"] == enhanced_entry["memory_id"]
        )

        self.assertGreater(float(enhanced_item["score"]), baseline_score)
        self.assertGreater(
            float(enhanced_item["score_breakdown"]["signals"]["surface_index"]),
            0.0,
        )
        self.assertIn("iris control", enhanced_item["facets"])
        self.assertIn(
            "caller-preserved-facet",
            enhanced_entry["metadata"]["semantic_facets"],
        )
        with sqlite3.connect(self.backend.memory_store.db_path) as connection:
            indexed_cues = {
                row[0]
                for row in connection.execute(
                    "SELECT term FROM memory_surface_terms WHERE memory_id = ?",
                    (enhanced_entry["memory_id"],),
                )
            }
        self.assertTrue(set(cue_ids).issubset(indexed_cues))

        export_path = Path(self.tmpdir.name) / "export.json"
        self.backend.memory_store.export_json(
            export_path,
            context_id="camera-ops",
        )
        exported = json.loads(export_path.read_text(encoding="utf-8"))
        exported_entry = next(
            entry
            for entry in exported["entries"]
            if entry["memory_id"] == enhanced_entry["memory_id"]
        )
        self.assertEqual(
            exported_entry["metadata"]["harmonic_scaffold"]["schema"],
            HARMONIC_SCAFFOLD_SCHEMA,
        )

        self.backend.memory_store.delete_entry(
            context_id="camera-ops",
            memory_id=enhanced_entry["memory_id"],
        )
        with sqlite3.connect(self.backend.memory_store.db_path) as connection:
            remaining = connection.execute(
                "SELECT COUNT(*) FROM memory_surface_terms WHERE memory_id = ?",
                (enhanced_entry["memory_id"],),
            ).fetchone()[0]
            cue_residue = connection.execute(
                "SELECT COUNT(*) FROM memory_surface_terms "
                f"WHERE term IN ({','.join('?' for _ in cue_ids)})",
                cue_ids,
            ).fetchone()[0]
        self.assertEqual(remaining, 0)
        self.assertEqual(cue_residue, 0)


if __name__ == "__main__":
    unittest.main()

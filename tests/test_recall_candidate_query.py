"""Behavioral parity for narrowing spike matches before loading entry payloads."""

import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from memory_store import DurableMemoryStore


class RecallCandidateQueryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = DurableMemoryStore(Path(temporary.name) / "memory.sqlite3")
        self.addCleanup(self.store.close)

    def entry(self, tag, context="alpha", spikes=(1, 2, 3), neurons=(0,), at=100.0):
        with patch("memory_store.time.time", return_value=at):
            return self.store.upsert_entry(
                tag=tag,
                context_id=context,
                source_text=f"Complete payload for {tag}. " + "retained text " * 100,
                metadata={"fixture": tag, "nested": {"retained": True}},
                embedding_dimensions=32,
                spike_indices=list(spikes),
                neuron_indices=list(neurons),
            )

    def legacy_candidates(self, *, query_spikes, firing_values, limit, records):
        """Frozen pre-optimization SQL and scoring oracle, using only this temp DB."""
        if not query_spikes or not records:
            return []
        scope = {str(record["context_id"]): dict(record) for record in records}
        spikes = sorted({int(value) for value in query_spikes})
        contexts_sql = ",".join("?" for _ in scope)
        spikes_sql = ",".join("?" for _ in spikes)
        bounded_limit = min(max(int(limit), 1), 10_000)
        source_limit = min(max(bounded_limit * 16, 128), 10_000)
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"""
                SELECT e.*, COUNT(*) AS overlap_count
                FROM memory_spikes AS s
                JOIN memory_entries AS e ON e.memory_id = s.memory_id
                WHERE s.context_id IN ({contexts_sql})
                  AND s.spike_index IN ({spikes_sql})
                GROUP BY e.memory_id
                ORDER BY overlap_count DESC, e.updated_at DESC, e.memory_id ASC
                LIMIT ?
                """,
                (*scope, *spikes, source_limit),
            ).fetchall()
        candidates = []
        for row in rows:
            entry = self.store._row_to_entry(row)
            trace = {int(index) for index in entry["spike_indices"]}
            if not trace:
                continue
            jaccard = int(row["overlap_count"]) / max(1, len(set(spikes) | trace))
            if jaccard <= 0.0:
                continue
            activity = sum(
                float(firing_values[int(index)])
                for index in entry["neuron_indices"]
                if 0 <= int(index) < len(firing_values)
            )
            bonus = min(activity / max(1, len(entry["neuron_indices"])), 1.0)
            entry["score"] = round(float(jaccard + 0.05 * bonus), 6)
            entry.update(scope.get(str(entry["context_id"]), {}))
            candidates.append(entry)
        candidates.sort(
            key=lambda item: (-item["score"], -item["updated_at"], item["memory_id"])
        )
        return candidates[:bounded_limit]

    def test_scopes_ties_and_activity_match_legacy_query(self):
        self.entry("alpha-tie-a")
        self.entry("alpha-tie-b")
        self.entry("alpha-active", neurons=(1,), at=50.0)
        self.entry("alpha-newer", at=150.0)
        self.entry("alpha-dense", spikes=(1, 2, 3, 4, 5), at=200.0)
        self.entry("global-shared", context="global", spikes=(1, 2))
        self.entry("beta-connected", context="beta", spikes=(1, 3))
        self.entry("gamma-two-hops", context="gamma", spikes=(2, 3))
        self.entry("delta-disconnected", context="delta")
        self.entry("alpha-empty", spikes=())
        self.store.upsert_context_link(
            source_context_id="alpha", target_context_id="beta",
            relation_type="shares_fixture", confidence=0.9, approved_by="unit-test",
        )
        self.store.upsert_context_link(
            source_context_id="beta", target_context_id="gamma",
            relation_type="shares_fixture", confidence=0.9, approved_by="unit-test",
        )
        for scope in ("local", "connected", "all"):
            records = self.store.resolve_recall_contexts(context_id="alpha", scope=scope)
            for limit in (0, 1, 3, 50):
                arguments = dict(query_spikes={1, 2, 3}, firing_values=[0.0, 2.0], limit=limit)
                expected = self.legacy_candidates(**arguments, records=records)
                for explicit in (False, True):
                    with self.subTest(scope=scope, limit=limit, explicit=explicit):
                        actual = self.store.recall_candidates(
                            **arguments, context_id="alpha", recall_scope=scope,
                            recall_contexts=records if explicit else None,
                        )
                        self.assertEqual(actual, expected)
            contexts = {item["context_id"] for item in expected}
            self.assertIn("global", contexts)
            if scope == "local":
                self.assertEqual(contexts, {"alpha", "global"})
            elif scope == "connected":
                self.assertEqual(contexts, {"alpha", "beta", "global"})
            else:
                self.assertEqual(contexts, {"alpha", "beta", "gamma", "delta", "global"})

        local = self.store.recall_candidates(
            context_id="alpha", query_spikes={1, 2, 3}, firing_values=[0.0, 2.0], limit=50,
        )
        self.assertEqual(local[0]["tag"], "alpha-active")
        self.assertEqual(local[0]["score"], 1.05)
        self.assertEqual(local[1]["tag"], "alpha-newer")
        ties = [item for item in local if item["tag"].startswith("alpha-tie-")]
        self.assertEqual(len(ties), 2)
        self.assertEqual([item["memory_id"] for item in ties], sorted(item["memory_id"] for item in ties))
        self.assertTrue(all(item["score"] == 1.0 for item in ties))

    def test_explicit_contexts_and_empty_inputs_remain_authoritative(self):
        self.entry("local")
        selected = self.entry("selected", context="delta")
        self.entry("global", context="global")
        records = [{"context_id": "delta", "recall_provenance": "explicit-fixture"}]
        arguments = dict(query_spikes={1, 2, 3}, firing_values=[0.0], limit=10)
        actual = self.store.recall_candidates(
            **arguments, context_id="alpha", recall_scope="all", recall_contexts=records,
        )
        self.assertEqual(actual, self.legacy_candidates(**arguments, records=records))
        self.assertEqual([item["memory_id"] for item in actual], [selected["memory_id"]])
        self.assertEqual(actual[0]["recall_provenance"], "explicit-fixture")
        self.assertEqual(self.store.recall_candidates(
            **arguments, context_id="alpha", recall_contexts=[],
        ), [])
        self.assertEqual(self.store.recall_candidates(
            context_id="alpha", query_spikes=set(), firing_values=[0.0], limit=10,
        ), [])

    def test_source_floor_and_cutoff_precede_final_activity_ranking(self):
        for index in range(127):
            self.entry(
                f"recent-weak-{index:03d}", spikes=(1, 2, *range(10, 30)),
                at=1_000.0 + index,
            )
        boundary_tags = sorted(
            ("source-boundary-a", "source-boundary-b"),
            key=lambda tag: self.store.stable_memory_id(context_id="alpha", tag=tag),
        )
        # Equal overlap and timestamp put the memory-ID tie exactly at the cap.
        winner = self.entry(boundary_tags[0], spikes=(1, 2), at=100.0)
        excluded = self.entry(boundary_tags[1], spikes=(1, 2), neurons=(1,), at=100.0)
        arguments = dict(query_spikes={1, 2, 3}, firing_values=[0.0, 1.0], limit=1)
        records = self.store.resolve_recall_contexts(context_id="alpha", scope="local")
        with patch.object(self.store, "_row_to_entry", wraps=self.store._row_to_entry) as decode:
            actual = self.store.recall_candidates(**arguments, context_id="alpha")
        self.assertEqual(decode.call_count, 128)
        self.assertEqual(actual, self.legacy_candidates(**arguments, records=records))
        self.assertEqual([item["memory_id"] for item in actual], [winner["memory_id"]])
        # A larger source window admits the stronger activity candidate.
        wider = self.store.recall_candidates(
            **{**arguments, "limit": 9}, context_id="alpha",
        )
        self.assertEqual(wider[0]["memory_id"], excluded["memory_id"])

    def test_orphan_spikes_do_not_consume_source_slots(self):
        valid = self.entry("valid", spikes=(1, 2))
        # Simulate damaged derived index rows only inside the isolated fixture.
        # Every orphan outranks the real row by overlap, so limiting before
        # the entry join would lose the real result completely.
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.executemany(
                "INSERT INTO memory_spikes (memory_id, context_id, spike_index) VALUES (?, ?, ?)",
                [(f"orphan-{index:03d}", "alpha", spike) for index in range(128) for spike in (1, 2, 3)],
            )
            conn.commit()
        arguments = dict(query_spikes={1, 2, 3}, firing_values=[0.0], limit=1)
        records = self.store.resolve_recall_contexts(context_id="alpha", scope="local")
        actual = self.store.recall_candidates(**arguments, context_id="alpha")
        self.assertEqual(actual, self.legacy_candidates(**arguments, records=records))
        self.assertEqual([item["memory_id"] for item in actual], [valid["memory_id"]])

    def test_executed_candidate_query_uses_spike_index(self):
        self.entry("indexed")
        statements = []
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            conn.set_trace_callback(statements.append)
            self.store.recall_candidates(
                context_id="alpha", query_spikes={1, 2}, firing_values=[0.0], limit=1,
                recall_contexts=[{"context_id": "alpha"}], _conn=conn,
            )
            candidate_statements = [sql for sql in statements if "memory_spikes" in sql]
            self.assertEqual(len(candidate_statements), 1)
            plan = conn.execute("EXPLAIN QUERY PLAN " + candidate_statements[0]).fetchall()
        spike_lookups = [str(row[3]) for row in plan if "SEARCH s USING" in str(row[3])]
        # SQLite may prefer context_memory to avoid a GROUP BY sort on a small
        # single-context fixture; both existing indexes bound the spike lookup.
        self.assertTrue(any(
            index in detail
            for detail in spike_lookups
            for index in ("ix_memory_spikes_context_spike", "ix_memory_spikes_context_memory")
        ), [tuple(row) for row in plan])


if __name__ == "__main__":
    unittest.main()

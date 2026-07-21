import random
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from memory_store import (
    DurableMemoryStore,
    RetrievalSnapshotStaleError,
)


class RetrievalPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.db_path = Path(self.temporary.name) / "memory.sqlite3"
        self.store = DurableMemoryStore(self.db_path)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _entry(
        self,
        tag: str,
        *,
        context_id: str = "alpha",
        metadata: dict | None = None,
    ) -> dict:
        return self.store.upsert_entry(
            tag=tag,
            context_id=context_id,
            source_text=f"Retrieval fixture {context_id}/{tag}.",
            metadata=metadata or {},
            embedding_dimensions=8,
            spike_indices=[1, 3],
            neuron_indices=[2, 4],
        )

    def _relationship(
        self,
        source: dict,
        target: dict,
        *,
        context_id: str,
        relation_type: str,
    ) -> dict:
        return self.store.upsert_relationship(
            context_id=context_id,
            source_memory_id=source["memory_id"],
            target_memory_id=target["memory_id"],
            relation_type=relation_type,
            weight=0.8,
            evidence={"source": "retrieval-page-test"},
        )

    def _force_timestamp_ties(self, timestamp: float = 1_700_000_000.25) -> None:
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE memory_entries SET created_at = ?, updated_at = ?",
                    (timestamp, timestamp),
                )
                conn.execute(
                    "UPDATE memory_relationships SET created_at = ?, updated_at = ?",
                    (timestamp, timestamp),
                )

    def _database_rows(self) -> tuple[list[tuple], list[tuple]]:
        uri = self.db_path.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            entries = conn.execute(
                """
                SELECT memory_id, context_id, tag, metadata_json, created_at, updated_at
                FROM memory_entries
                ORDER BY memory_id
                """
            ).fetchall()
            relationships = conn.execute(
                """
                SELECT relationship_id, context_id, source_memory_id,
                       target_memory_id, created_at, updated_at
                FROM memory_relationships
                ORDER BY relationship_id
                """
            ).fetchall()
        return entries, relationships

    def test_memory_pages_are_deterministic_across_ties_and_random_insertion(self) -> None:
        specs = [
            (f"entry-{index:02d}", "alpha" if index % 2 else "beta")
            for index in range(13)
        ]
        random.Random(90210).shuffle(specs)
        inserted = [
            self._entry(tag, context_id=context_id)
            for tag, context_id in specs
        ]
        self._entry("excluded", context_id="other")
        self._force_timestamp_ties()

        def collect() -> tuple[list[str], str]:
            ids: list[str] = []
            position = None
            revision = None
            while True:
                page = self.store.retrieval_memory_page(
                    context_ids=["beta", "alpha"],
                    limit=3,
                    position=position,
                    expected_revision=revision,
                )
                revision = page["snapshot_revision"]
                self.assertEqual(page["context_ids"], ["alpha", "beta"])
                self.assertEqual(page["total"], len(inserted))
                ids.extend(entry["memory_id"] for entry in page["entries"])
                if not page["has_more"]:
                    self.assertIsNone(page["next_position"])
                    break
                position = page["next_position"]
                self.assertEqual(set(position), {"updated_at", "memory_id"})
            return ids, revision

        first_ids, first_revision = collect()
        second_ids, second_revision = collect()
        expected_ids = sorted(
            (entry["memory_id"] for entry in inserted),
            reverse=True,
        )
        self.assertEqual(first_ids, expected_ids)
        self.assertEqual(second_ids, expected_ids)
        self.assertEqual(len(first_ids), len(set(first_ids)))
        self.assertEqual(first_revision, second_revision)

    def test_memory_snapshot_rejects_selected_insert_update_and_delete(self) -> None:
        original = self._entry("original")
        first = self.store.retrieval_memory_page(context_ids=["alpha"], limit=1)

        inserted = self._entry("inserted")
        with self.assertRaises(RetrievalSnapshotStaleError) as inserted_error:
            self.store.retrieval_memory_page(
                context_ids=["alpha"],
                limit=1,
                expected_revision=first["snapshot_revision"],
            )
        self.assertEqual(
            inserted_error.exception.expected_revision,
            first["snapshot_revision"],
        )
        self.assertNotEqual(
            inserted_error.exception.actual_revision,
            first["snapshot_revision"],
        )

        second = self.store.retrieval_memory_page(context_ids=["alpha"], limit=1)
        self._entry("original", metadata={"updated": True})
        with self.assertRaises(RetrievalSnapshotStaleError):
            self.store.retrieval_memory_page(
                context_ids=["alpha"],
                limit=1,
                expected_revision=second["snapshot_revision"],
            )

        third = self.store.retrieval_memory_page(context_ids=["alpha"], limit=1)
        self.store.delete_entry(
            context_id="alpha",
            memory_id=inserted["memory_id"],
        )
        with self.assertRaises(RetrievalSnapshotStaleError):
            self.store.retrieval_memory_page(
                context_ids=["alpha"],
                limit=1,
                expected_revision=third["snapshot_revision"],
            )
        self.assertIsNotNone(self.store.get_entry(original["memory_id"]))

    def test_unselected_namespace_does_not_invalidate_memory_snapshot(self) -> None:
        self._entry("selected", context_id="alpha")
        first = self.store.retrieval_memory_page(context_ids=["alpha"], limit=10)
        self._entry("unselected", context_id="beta")

        replay = self.store.retrieval_memory_page(
            context_ids=["alpha"],
            limit=10,
            expected_revision=first["snapshot_revision"],
        )
        self.assertEqual(replay["snapshot_revision"], first["snapshot_revision"])
        self.assertEqual(replay["total"], 1)
        self.assertEqual(
            {entry["context_id"] for entry in replay["entries"]},
            {"alpha"},
        )

    def test_snapshot_revisions_bind_content_without_timestamp_changes(self) -> None:
        first = self._entry(
            "first",
            metadata={"cortex_governor": True, "version": 1},
        )
        second = self._entry("second")
        relationship = self._relationship(
            first,
            second,
            context_id="alpha",
            relation_type="related",
        )
        memory_page = self.store.retrieval_memory_page(
            context_ids=["alpha"],
            limit=10,
        )
        cortex_page = self.store.retrieval_cortex_page(
            context_id="alpha",
            limit=10,
        )
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    """
                    UPDATE memory_entries
                    SET source_text = ?, metadata_json = ?
                    WHERE memory_id = ?
                    """,
                    (
                        "Changed without a timestamp bump.",
                        '{"cortex_governor":true,"version":2}',
                        first["memory_id"],
                    ),
                )

        with self.assertRaises(RetrievalSnapshotStaleError):
            self.store.retrieval_memory_page(
                context_ids=["alpha"],
                limit=10,
                expected_revision=memory_page["snapshot_revision"],
            )
        with self.assertRaises(RetrievalSnapshotStaleError):
            self.store.retrieval_cortex_page(
                context_id="alpha",
                limit=10,
                expected_revision=cortex_page["snapshot_revision"],
            )

        graph_page = self.store.retrieval_graph_page(
            context_id="alpha",
            entry_limit=10,
            relationship_limit=10,
        )
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    """
                    UPDATE memory_relationships
                    SET weight = ?, evidence_json = ?
                    WHERE relationship_id = ?
                    """,
                    (
                        0.45,
                        '{"source":"changed-without-timestamp"}',
                        relationship["relationship_id"],
                    ),
                )
        with self.assertRaises(RetrievalSnapshotStaleError):
            self.store.retrieval_graph_page(
                context_id="alpha",
                entry_limit=10,
                relationship_limit=10,
                expected_revision=graph_page["snapshot_revision"],
            )

    def test_existing_write_connection_cannot_bypass_snapshot_generation(self) -> None:
        entry = self._entry("maintenance-update")
        page = self.store.retrieval_memory_page(
            context_ids=["alpha"],
            limit=10,
        )

        with closing(self.store._connect_existing_write()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    """
                    UPDATE memory_entries
                    SET source_text = ?
                    WHERE memory_id = ?
                    """,
                    (
                        "Changed through the governed maintenance write lane.",
                        entry["memory_id"],
                    ),
                )

        with self.assertRaises(RetrievalSnapshotStaleError):
            self.store.retrieval_memory_page(
                context_ids=["alpha"],
                limit=10,
                expected_revision=page["snapshot_revision"],
            )

    def test_derived_index_mutations_rotate_snapshot_generation(self) -> None:
        entry = self._entry("derived-index-update")
        spike_page = self.store.retrieval_memory_page(
            context_ids=["alpha"],
            limit=10,
        )

        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    """
                    UPDATE memory_spikes
                    SET spike_index = ?
                    WHERE memory_id = ? AND spike_index = ?
                    """,
                    (99, entry["memory_id"], 1),
                )

        with self.assertRaises(RetrievalSnapshotStaleError):
            self.store.retrieval_memory_page(
                context_ids=["alpha"],
                limit=10,
                expected_revision=spike_page["snapshot_revision"],
            )

        surface_page = self.store.retrieval_memory_page(
            context_ids=["alpha"],
            limit=10,
        )
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                surface = conn.execute(
                    """
                    SELECT term, weight
                    FROM memory_surface_terms
                    WHERE memory_id = ?
                    ORDER BY term ASC
                    LIMIT 1
                    """,
                    (entry["memory_id"],),
                ).fetchone()
                self.assertIsNotNone(surface)
                conn.execute(
                    """
                    UPDATE memory_surface_terms
                    SET weight = ?
                    WHERE memory_id = ? AND term = ?
                    """,
                    (
                        float(surface["weight"]) + 0.125,
                        entry["memory_id"],
                        str(surface["term"]),
                    ),
                )

        with self.assertRaises(RetrievalSnapshotStaleError):
            self.store.retrieval_memory_page(
                context_ids=["alpha"],
                limit=10,
                expected_revision=surface_page["snapshot_revision"],
            )

    def test_revision_and_rows_share_one_transaction_during_concurrent_commit(self) -> None:
        original = self._entry("original")
        original_revision_method = (
            DurableMemoryStore._retrieval_generation_snapshot_revision
        )
        injected = False

        def revision_then_commit(**kwargs):
            nonlocal injected
            result = original_revision_method(**kwargs)
            if not injected:
                injected = True
                self._entry("committed-after-revision")
            return result

        with patch.object(
            DurableMemoryStore,
            "_retrieval_generation_snapshot_revision",
            side_effect=revision_then_commit,
        ):
            page = self.store.retrieval_memory_page(
                context_ids=["alpha"],
                limit=10,
            )

        self.assertEqual(page["total"], 1)
        self.assertEqual(
            [entry["memory_id"] for entry in page["entries"]],
            [original["memory_id"]],
        )
        with self.assertRaises(RetrievalSnapshotStaleError):
            self.store.retrieval_memory_page(
                context_ids=["alpha"],
                limit=10,
                expected_revision=page["snapshot_revision"],
            )

    def test_graph_pages_are_independent_complete_and_endpoint_safe(self) -> None:
        alpha_entries = [self._entry(f"a-{index}") for index in range(5)]
        global_entries = [
            self._entry(f"g-{index}", context_id="global") for index in range(3)
        ]
        beta_entries = [
            self._entry(f"b-{index}", context_id="beta") for index in range(2)
        ]
        relationship_specs = []
        for index in range(4):
            relationship_specs.append(
                (
                    alpha_entries[index],
                    alpha_entries[index + 1],
                    "alpha",
                    f"alpha-{index}",
                )
            )
        for index in range(2):
            relationship_specs.append(
                (
                    global_entries[index],
                    global_entries[index + 1],
                    "global",
                    f"global-{index}",
                )
            )
        random.Random(44).shuffle(relationship_specs)
        valid_relationships = [
            self._relationship(
                source,
                target,
                context_id=context_id,
                relation_type=relation_type,
            )
            for source, target, context_id, relation_type in relationship_specs
        ]
        self._relationship(
            beta_entries[0],
            beta_entries[1],
            context_id="beta",
            relation_type="beta-only",
        )
        cross_context_edge = self._relationship(
            alpha_entries[0],
            beta_entries[0],
            context_id="alpha",
            relation_type="legacy-cross-context",
        )
        self._force_timestamp_ties()

        isolated = self.store.retrieval_graph_page(
            context_id="alpha",
            include_global=False,
            entry_limit=5,
            relationship_limit=5,
        )
        self.assertEqual(isolated["entry_total"], 5)
        self.assertEqual(isolated["relationship_total"], 4)

        first_global = self.store.retrieval_graph_page(
            context_id="alpha",
            include_global=True,
            entry_limit=5,
            relationship_limit=1,
        )
        replayed_global = self.store.retrieval_graph_page(
            context_id="alpha",
            include_global=True,
            entry_limit=5,
            relationship_limit=1,
            expected_revision=first_global["snapshot_revision"],
        )
        self.assertEqual(replayed_global, first_global)

        entry_ids: list[str] = []
        relationship_ids: list[str] = []
        entry_position = None
        relationship_position = None
        revision = None
        observed_finished_entry_stream = False
        while True:
            page = self.store.retrieval_graph_page(
                context_id="alpha",
                include_global=True,
                entry_limit=5,
                relationship_limit=1,
                entry_position=entry_position,
                relationship_position=relationship_position,
                expected_revision=revision,
            )
            revision = page["snapshot_revision"]
            self.assertEqual(page["entry_total"], 8)
            self.assertEqual(page["relationship_total"], 6)
            self.assertEqual(page["context_ids"], ["alpha", "global"])
            entry_ids.extend(entry["memory_id"] for entry in page["entries"])
            relationship_ids.extend(
                relationship["relationship_id"]
                for relationship in page["relationships"]
            )
            endpoint_ids = {
                entry["memory_id"] for entry in page["endpoint_entries"]
            }
            expected_endpoint_ids = {
                relationship[field]
                for relationship in page["relationships"]
                for field in ("source_memory_id", "target_memory_id")
            }
            self.assertEqual(endpoint_ids, expected_endpoint_ids)
            self.assertLessEqual(
                len(page["endpoint_entries"]),
                2 * page["relationship_returned"],
            )
            self.assertTrue(
                all(
                    entry["context_id"] in {"alpha", "global"}
                    for entry in page["endpoint_entries"]
                )
            )
            if entry_position == {"done": True}:
                observed_finished_entry_stream = True
                self.assertEqual(page["entry_returned"], 0)
            entry_position = page["entry_next_position"]
            relationship_position = page["relationship_next_position"]
            if (
                entry_position == {"done": True}
                and relationship_position == {"done": True}
            ):
                break

        expected_entries = sorted(
            (
                entry["memory_id"]
                for entry in alpha_entries + global_entries
            ),
            reverse=True,
        )
        expected_relationships = sorted(
            (relationship["relationship_id"] for relationship in valid_relationships),
            reverse=True,
        )
        self.assertTrue(observed_finished_entry_stream)
        self.assertEqual(entry_ids, expected_entries)
        self.assertEqual(relationship_ids, expected_relationships)
        self.assertEqual(len(entry_ids), len(set(entry_ids)))
        self.assertEqual(len(relationship_ids), len(set(relationship_ids)))
        self.assertNotIn(cross_context_edge["relationship_id"], relationship_ids)

    def test_graph_revision_binds_relationship_set(self) -> None:
        entries = [self._entry(f"node-{index}") for index in range(3)]
        self._relationship(
            entries[0],
            entries[1],
            context_id="alpha",
            relation_type="first",
        )
        page = self.store.retrieval_graph_page(
            context_id="alpha",
            entry_limit=2,
            relationship_limit=1,
        )
        self._relationship(
            entries[1],
            entries[2],
            context_id="alpha",
            relation_type="second",
        )
        with self.assertRaises(RetrievalSnapshotStaleError):
            self.store.retrieval_graph_page(
                context_id="alpha",
                entry_limit=2,
                relationship_limit=1,
                expected_revision=page["snapshot_revision"],
            )

    def test_cortex_page_filters_exact_boolean_and_honors_global_scope(self) -> None:
        alpha_true = [
            self._entry(
                f"cortex-{index}",
                metadata={"cortex_governor": True},
            )
            for index in range(3)
        ]
        self._entry("false", metadata={"cortex_governor": False})
        self._entry("numeric-one", metadata={"cortex_governor": 1})
        self._entry("missing", metadata={"kind": "ordinary"})
        malformed = self._entry("malformed", metadata={"kind": "ordinary"})
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE memory_entries SET metadata_json = ? WHERE memory_id = ?",
                    ("{malformed", malformed["memory_id"]),
                )
        global_true = self._entry(
            "global-cortex",
            context_id="global",
            metadata={"cortex_governor": True},
        )
        self._entry(
            "beta-cortex",
            context_id="beta",
            metadata={"cortex_governor": True},
        )
        self._force_timestamp_ties()

        local = self.store.retrieval_cortex_page(
            context_id="alpha",
            include_global=False,
            limit=10,
        )
        self.assertEqual(local["total"], 3)
        self.assertEqual(
            {entry["memory_id"] for entry in local["entries"]},
            {entry["memory_id"] for entry in alpha_true},
        )

        ids: list[str] = []
        position = None
        revision = None
        while True:
            page = self.store.retrieval_cortex_page(
                context_id="alpha",
                include_global=True,
                limit=1,
                position=position,
                expected_revision=revision,
            )
            revision = page["snapshot_revision"]
            self.assertEqual(page["total"], 4)
            ids.extend(entry["memory_id"] for entry in page["entries"])
            if not page["has_more"]:
                break
            position = page["next_position"]
        self.assertEqual(
            ids,
            sorted(
                [
                    *(entry["memory_id"] for entry in alpha_true),
                    global_true["memory_id"],
                ],
                reverse=True,
            ),
        )
        self.assertEqual(len(ids), len(set(ids)))

        self._entry("ordinary-follow-up", metadata={"cortex_governor": False})
        unchanged = self.store.retrieval_cortex_page(
            context_id="alpha",
            include_global=True,
            limit=1,
            expected_revision=revision,
        )
        self.assertEqual(unchanged["snapshot_revision"], revision)
        self._entry("new-cortex", metadata={"cortex_governor": True})
        with self.assertRaises(RetrievalSnapshotStaleError):
            self.store.retrieval_cortex_page(
                context_id="alpha",
                include_global=True,
                limit=1,
                expected_revision=revision,
            )

    def test_page_inputs_fail_closed(self) -> None:
        invalid_memory_calls = [
            {"context_ids": "alpha"},
            {"context_ids": []},
            {"context_ids": ["alpha", "alpha"]},
            {"context_ids": [" alpha"]},
            {"context_ids": ["e\u0301"]},
            {"context_ids": [f"c{index}" for index in range(65)]},
            {"context_ids": ["alpha"], "limit": True},
            {"context_ids": ["alpha"], "limit": 0},
            {"context_ids": ["alpha"], "limit": 501},
            {"context_ids": ["alpha"], "position": {"memory_id": "id"}},
            {
                "context_ids": ["alpha"],
                "position": {"updated_at": 1.0, "memory_id": "id"},
            },
            {
                "context_ids": ["alpha"],
                "position": {"updated_at": float("inf"), "memory_id": "id"},
            },
            {"context_ids": ["alpha"], "expected_revision": "A" * 64},
        ]
        for arguments in invalid_memory_calls:
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    self.store.retrieval_memory_page(**arguments)

        invalid_graph_calls = [
            {"context_id": " alpha"},
            {"context_id": "alpha", "include_global": 1},
            {"context_id": "alpha", "entry_limit": 0},
            {"context_id": "alpha", "relationship_limit": 501},
            {"context_id": "alpha", "entry_position": {"done": False}},
            {"context_id": "alpha", "entry_position": {"done": True}},
            {
                "context_id": "alpha",
                "relationship_position": {
                    "updated_at": 1.0,
                    "relationship_id": "edge",
                },
            },
            {
                "context_id": "alpha",
                "relationship_position": {"done": True, "extra": True},
            },
        ]
        for arguments in invalid_graph_calls:
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    self.store.retrieval_graph_page(**arguments)

        with self.assertRaises(ValueError):
            self.store.retrieval_cortex_page(
                context_id="alpha",
                include_global="true",
            )
        with self.assertRaises(ValueError):
            self.store.retrieval_cortex_page(
                context_id="alpha",
                position={"updated_at": 1.0, "memory_id": "id"},
            )

    def test_pages_use_generation_counters_not_unbounded_content_hash_scans(self) -> None:
        for index in range(12):
            self._entry(f"bounded-{index:02d}")
        statements: list[str] = []
        original_connect = self.store._connect_read_only

        def traced_connection():
            conn = original_connect()
            conn.set_trace_callback(statements.append)
            return conn

        with patch.object(
            self.store,
            "_connect_read_only",
            side_effect=traced_connection,
        ):
            page = self.store.retrieval_memory_page(
                context_ids=["alpha"],
                limit=2,
            )

        normalized = [" ".join(statement.split()).casefold() for statement in statements]
        self.assertEqual(page["returned"], 2)
        self.assertEqual(page["total"], 12)
        self.assertTrue(
            any("select count(*) from memory_entries" in statement for statement in normalized)
        )
        self.assertFalse(
            any(
                "order by context_id asc, memory_id asc" in statement
                for statement in normalized
            )
        )
        self.assertTrue(
            any("order by updated_at desc, memory_id desc limit" in statement for statement in normalized)
        )

    def test_corrupt_generation_counter_fails_closed(self) -> None:
        self._entry("generation-guard")
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    """
                    UPDATE store_metadata
                    SET value_json = ?
                    WHERE key = ?
                    """,
                    (
                        '"not-an-integer"',
                        "retrieval_snapshot_generation.v1.memory.alpha",
                    ),
                )
        with self.assertRaisesRegex(RuntimeError, "generation is invalid"):
            self.store.retrieval_memory_page(
                context_ids=["alpha"],
                limit=1,
            )

    def test_pages_work_through_read_only_audit_store_without_mutation(self) -> None:
        first = self._entry(
            "cortex",
            metadata={"cortex_governor": True},
        )
        second = self._entry("neighbor")
        self._relationship(
            first,
            second,
            context_id="alpha",
            relation_type="related",
        )
        before = self._database_rows()
        audit_store = DurableMemoryStore.open_existing_for_audit(self.db_path)
        observer_uri = self.db_path.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(observer_uri, uri=True)) as observer:
            before_data_version = int(
                observer.execute("PRAGMA data_version").fetchone()[0]
            )
            try:
                memory = audit_store.retrieval_memory_page(
                    context_ids=["alpha"],
                    limit=10,
                )
                graph = audit_store.retrieval_graph_page(
                    context_id="alpha",
                    entry_limit=10,
                    relationship_limit=10,
                )
                cortex = audit_store.retrieval_cortex_page(
                    context_id="alpha",
                    limit=10,
                )
            finally:
                audit_store.close()
            after_data_version = int(
                observer.execute("PRAGMA data_version").fetchone()[0]
            )
        after = self._database_rows()

        self.assertEqual(before, after)
        self.assertEqual(after_data_version, before_data_version)
        self.assertTrue(memory["read_only"])
        self.assertTrue(graph["read_only"])
        self.assertTrue(cortex["read_only"])
        self.assertEqual(memory["total"], 2)
        self.assertEqual(graph["relationship_total"], 1)
        self.assertEqual(cortex["total"], 1)


if __name__ == "__main__":
    unittest.main()

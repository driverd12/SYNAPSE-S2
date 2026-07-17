import json
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from memory_store import DurableMemoryStore


class DurableMemoryStoreTests(unittest.TestCase):
    def test_upsert_list_recall_export_and_backup_are_durable(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            export_path = Path(tmp) / "memory-export.json"
            backup_path = Path(tmp) / "memory-backup.sqlite3"
            store = DurableMemoryStore(db_path)

            entry = store.upsert_entry(
                tag="wing-load-analysis",
                context_id="demo",
                source_text="Full briefing text stays in durable local memory.",
                metadata={"classification": "internal", "priority": 7},
                embedding_dimensions=6,
                spike_indices=[2, 4],
                neuron_indices=[3, 6],
            )
            restored = DurableMemoryStore(db_path)
            entries = restored.list_entries(context_id="demo", limit=10)
            candidates = restored.recall_candidates(
                context_id="demo",
                query_spikes={2, 4},
                firing_values=[0.0, 0.0, 0.0, 1.5, 0.0, 0.0, 0.25],
                limit=5,
            )
            exported = restored.export_json(export_path, context_id="demo")
            backup = restored.backup(backup_path)

            self.assertTrue(db_path.exists())
            self.assertEqual(entry["tag"], "wing-load-analysis")
            self.assertEqual(entries[0]["source_text"], "Full briefing text stays in durable local memory.")
            self.assertEqual(entries[0]["metadata"]["priority"], 7)
            self.assertEqual(candidates[0]["tag"], "wing-load-analysis")
            self.assertGreater(candidates[0]["score"], 1.0)
            self.assertEqual(exported["entries"][0]["memory_id"], entry["memory_id"])
            self.assertTrue(export_path.exists())
            self.assertEqual(json.loads(export_path.read_text())["entries"][0]["tag"], "wing-load-analysis")
            self.assertEqual(backup["backup_path"], str(backup_path))
            self.assertTrue(backup_path.exists())

            with closing(sqlite3.connect(backup_path)) as conn:
                row_count = conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0]

            self.assertEqual(row_count, 1)

    def test_list_entries_by_ids_preserves_requested_order_and_context(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            first = store.upsert_entry(
                tag="first-node",
                context_id="demo",
                source_text="First ordered graph node.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1],
                neuron_indices=[1],
            )
            other_context = store.upsert_entry(
                tag="other-context-node",
                context_id="other",
                source_text="Filtered graph node.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[2],
                neuron_indices=[2],
            )
            second = store.upsert_entry(
                tag="second-node",
                context_id="demo",
                source_text="Second ordered graph node.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[3],
                neuron_indices=[3],
            )

            entries = store.list_entries_by_ids(
                [
                    second["memory_id"],
                    other_context["memory_id"],
                    first["memory_id"],
                    second["memory_id"],
                    "missing-node",
                ],
                context_id="demo",
            )

        self.assertEqual([entry["tag"] for entry in entries], ["second-node", "first-node"])

    def test_recall_uses_durable_spike_index_and_updates_on_upsert(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)

            first = store.upsert_entry(
                tag="indexed-recall",
                context_id="demo",
                source_text="First indexed recall text.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1, 2, 2, 4],
                neuron_indices=[1, 4],
            )
            store.upsert_entry(
                tag="other-recall",
                context_id="demo",
                source_text="Other indexed recall text.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[6, 7],
                neuron_indices=[6, 7],
            )

            with closing(sqlite3.connect(db_path)) as conn:
                indexed_rows = conn.execute(
                    """
                    SELECT spike_index
                    FROM memory_spikes
                    WHERE memory_id = ?
                    ORDER BY spike_index
                    """,
                    (first["memory_id"],),
                ).fetchall()
                query_plan = " ".join(
                    str(row)
                    for row in conn.execute(
                        """
                        EXPLAIN QUERY PLAN
                        SELECT e.memory_id
                        FROM memory_spikes AS s
                        JOIN memory_entries AS e
                            ON e.memory_id = s.memory_id
                        WHERE s.context_id IN (?, 'global')
                            AND s.spike_index IN (?, ?)
                        GROUP BY e.memory_id
                        """,
                        ("demo", 1, 4),
                    ).fetchall()
                )

            self.assertEqual([row[0] for row in indexed_rows], [1, 2, 4])
            self.assertIn("ix_memory_spikes_context_spike", query_plan)
            self.assertEqual(
                [
                    item["tag"]
                    for item in store.recall_candidates(
                        context_id="demo",
                        query_spikes={1, 4},
                        firing_values=[0.0] * 9,
                        limit=10,
                    )
                ],
                ["indexed-recall"],
            )

            store.upsert_entry(
                tag="indexed-recall",
                context_id="demo",
                source_text="Updated indexed recall text.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[6],
                neuron_indices=[6],
            )

            with closing(sqlite3.connect(db_path)) as conn:
                updated_rows = conn.execute(
                    """
                    SELECT spike_index
                    FROM memory_spikes
                    WHERE memory_id = ?
                    ORDER BY spike_index
                    """,
                    (first["memory_id"],),
                ).fetchall()

            self.assertEqual([row[0] for row in updated_rows], [6])
            self.assertEqual(
                store.recall_candidates(
                    context_id="demo",
                    query_spikes={1, 4},
                    firing_values=[0.0] * 9,
                    limit=10,
                ),
                [],
            )
            self.assertEqual(
                [
                    item["tag"]
                    for item in store.recall_candidates(
                        context_id="demo",
                        query_spikes={6},
                        firing_values=[0.0] * 9,
                        limit=10,
                    )
                ],
                ["indexed-recall", "other-recall"],
            )

    def test_surface_recall_uses_durable_term_index_and_updates_on_upsert(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)

            entry = store.upsert_entry(
                tag="surface-recall-node",
                context_id="demo",
                source_text="Cortex graph hardening improves operator recall.",
                metadata={
                    "display_label": "Cortex graph hardening",
                    "semantic_facets": ["operator safety", "graph endpoints"],
                },
                embedding_dimensions=8,
                spike_indices=[1, 2],
                neuron_indices=[1, 2],
            )
            store.upsert_entry(
                tag="unrelated-node",
                context_id="demo",
                source_text="Procurement budget note.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[5, 6],
                neuron_indices=[5, 6],
            )

            with closing(sqlite3.connect(db_path)) as conn:
                indexed_terms = [
                    row[0]
                    for row in conn.execute(
                        """
                        SELECT term
                        FROM memory_surface_terms
                        WHERE memory_id = ?
                        ORDER BY term
                        """,
                        (entry["memory_id"],),
                    ).fetchall()
                ]
                query_plan = " ".join(
                    str(row)
                    for row in conn.execute(
                        """
                        EXPLAIN QUERY PLAN
                        SELECT memory_id
                        FROM memory_surface_terms
                        WHERE context_id IN (?, 'global')
                            AND term IN (?, ?)
                        GROUP BY memory_id
                        """,
                        ("demo", "cortex", "graph"),
                    ).fetchall()
                )

            self.assertIn("cortex", indexed_terms)
            self.assertIn("operator", indexed_terms)
            self.assertIn("ix_memory_surface_terms_context_term", query_plan)
            self.assertGreater(store.stats(context_id="demo")["surface_term_count"], 0)
            self.assertEqual(
                [
                    item["tag"]
                    for item in store.surface_recall_candidates(
                        context_id="demo",
                        query_terms=["cortex", "graph"],
                        limit=10,
                    )
                ],
                ["surface-recall-node"],
            )

            store.upsert_entry(
                tag="surface-recall-node",
                context_id="demo",
                source_text="Updated node moved away from cortex graph vocabulary.",
                metadata={"display_label": "renewal budget"},
                embedding_dimensions=8,
                spike_indices=[7],
                neuron_indices=[7],
            )

            self.assertEqual(
                store.surface_recall_candidates(
                    context_id="demo",
                    query_terms=["operator", "safety"],
                    limit=10,
                ),
                [],
            )

    def test_relationships_are_upserted_listed_and_exported(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            export_path = Path(tmp) / "memory-export.json"
            store = DurableMemoryStore(db_path)
            first = store.upsert_entry(
                tag="brief-event-001",
                context_id="demo",
                source_text="Apple Silicon MLX spiking runtime.",
                metadata={"event_segment": True},
                embedding_dimensions=8,
                spike_indices=[1, 2],
                neuron_indices=[4, 5],
            )
            second = store.upsert_entry(
                tag="brief-event-002",
                context_id="demo",
                source_text="Procurement budget and contract risk.",
                metadata={"event_segment": True},
                embedding_dimensions=8,
                spike_indices=[5, 6],
                neuron_indices=[7, 8],
            )

            relationship = store.upsert_relationship(
                context_id="demo",
                source_memory_id=first["memory_id"],
                target_memory_id=second["memory_id"],
                relation_type="temporal_next",
                weight=0.87,
                evidence={"surprise_score": 0.71},
            )
            relationships = store.list_relationships(context_id="demo", limit=10)
            stats = store.stats(context_id="demo")
            exported = store.export_json(export_path, context_id="demo")

        self.assertEqual(relationship["relation_type"], "temporal_next")
        self.assertEqual(relationships[0]["source_tag"], "brief-event-001")
        self.assertEqual(relationships[0]["target_tag"], "brief-event-002")
        self.assertEqual(relationships[0]["evidence"]["surprise_score"], 0.71)
        self.assertEqual(stats["relationship_count"], 1)
        self.assertEqual(exported["relationships"][0]["weight"], 0.87)

    def test_context_link_suggestions_are_density_normalized_and_read_only(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            store.upsert_entry(
                tag="control-room-camera",
                context_id="CASP-Control-Room",
                source_text="PTZ camera presets use the control room network.",
                metadata={"semantic_facets": ["ptz camera", "control room network"]},
                embedding_dimensions=12,
                spike_indices=[1, 2, 3, 4],
                neuron_indices=[1, 2],
            )
            store.upsert_entry(
                tag="ptz-camera-work",
                context_id="PTZ-Camera-Work",
                source_text="PTZ camera network presets and operator framing.",
                metadata={"semantic_facets": ["ptz camera", "network presets"]},
                embedding_dimensions=12,
                spike_indices=[2, 3, 8],
                neuron_indices=[2, 3],
            )
            store.upsert_entry(
                tag="finance-note",
                context_id="Procurement",
                source_text="Supplier budget renewal and contract risk.",
                metadata={},
                embedding_dimensions=12,
                spike_indices=[10, 11],
                neuron_indices=[4, 5],
            )

            suggestions = store.suggest_context_links(min_score=0.01, limit=10)
            camera_suggestion = next(
                suggestion
                for suggestion in suggestions
                if {
                    suggestion["source_context_id"],
                    suggestion["target_context_id"],
                }
                == {"CASP-Control-Room", "PTZ-Camera-Work"}
            )

            self.assertEqual(store.list_context_links(), [])
            self.assertFalse(camera_suggestion["persisted"])
            self.assertTrue(camera_suggestion["requires_approval"])
            self.assertFalse(camera_suggestion["automatic_cross_namespace_write"])
            self.assertEqual(
                camera_suggestion["surface_dice"],
                round(
                    2.0 * camera_suggestion["surface_overlap_count"]
                    / (
                        camera_suggestion["evidence"]["surface_source_count"]
                        + camera_suggestion["evidence"]["surface_target_count"]
                    ),
                    6,
                ),
            )
            self.assertEqual(camera_suggestion["evidence"]["method"], "density-normalized-dice-v1")
            self.assertEqual(camera_suggestion["delay_semantics"], "visualization-only")
            self.assertGreaterEqual(camera_suggestion["suggested_phase_delay_ticks"], 0)
            self.assertLessEqual(camera_suggestion["suggested_phase_delay_ticks"], 4)

            with closing(sqlite3.connect(db_path)) as conn:
                table_exists = conn.execute(
                    """
                    SELECT COUNT(*) FROM sqlite_master
                    WHERE type = 'table' AND name = 'context_relationships'
                    """
                ).fetchone()[0]
            self.assertEqual(table_exists, 1)

    def test_approved_context_links_enable_only_one_hop_connected_recall(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            export_path = Path(tmp) / "memory-export.json"
            store = DurableMemoryStore(db_path)
            alpha = store.upsert_entry(
                tag="alpha-local",
                context_id="alpha",
                source_text="Control room camera overview.",
                metadata={},
                embedding_dimensions=12,
                spike_indices=[1, 2],
                neuron_indices=[1, 2],
            )
            beta = store.upsert_entry(
                tag="beta-connected",
                context_id="beta",
                source_text="Control room camera network detail.",
                metadata={},
                embedding_dimensions=12,
                spike_indices=[2, 3],
                neuron_indices=[2, 3],
            )
            gamma = store.upsert_entry(
                tag="gamma-two-hops",
                context_id="gamma",
                source_text="Remote camera maintenance detail.",
                metadata={},
                embedding_dimensions=12,
                spike_indices=[8, 9],
                neuron_indices=[8, 9],
            )
            alpha_beta = store.upsert_context_link(
                source_context_id="beta",
                target_context_id="alpha",
                relation_type="shares_network",
                confidence=0.91,
                approved_by="unit-test",
            )
            store.upsert_context_link(
                source_context_id="beta",
                target_context_id="gamma",
                relation_type="depends_on",
                confidence=0.8,
                approved_by="unit-test",
            )

            restored = DurableMemoryStore(db_path)
            local_contexts = restored.resolve_recall_contexts(
                context_id="alpha",
                scope="local",
            )
            connected_contexts = restored.resolve_recall_contexts(
                context_id="alpha",
                scope="connected",
            )
            all_contexts = restored.resolve_recall_contexts(
                context_id="alpha",
                scope="all",
            )
            local_recall = restored.recall_candidates(
                context_id="alpha",
                query_spikes={2, 3},
                firing_values=[0.0] * 12,
                limit=10,
            )
            connected_recall = restored.recall_candidates(
                context_id="alpha",
                query_spikes={2, 3},
                firing_values=[0.0] * 12,
                limit=10,
                recall_scope="connected",
            )
            all_recall = restored.recall_candidates(
                context_id="alpha",
                query_spikes={8, 9},
                firing_values=[0.0] * 12,
                limit=10,
                recall_scope="all",
            )
            exported = restored.export_json(export_path)
            stats = restored.stats()

        self.assertEqual(
            [record["context_id"] for record in local_contexts],
            ["alpha", "global"],
        )
        self.assertEqual(
            {record["context_id"] for record in connected_contexts},
            {"alpha", "beta", "global"},
        )
        self.assertNotIn("gamma", {record["context_id"] for record in connected_contexts})
        self.assertEqual(
            {record["context_id"] for record in all_contexts},
            {"alpha", "beta", "gamma", "global"},
        )
        self.assertNotIn(beta["memory_id"], {item["memory_id"] for item in local_recall})
        beta_hit = next(item for item in connected_recall if item["memory_id"] == beta["memory_id"])
        self.assertEqual(beta_hit["recall_provenance"], "connected")
        self.assertEqual(beta_hit["via_context_link_id"], alpha_beta["context_link_id"])
        gamma_hit = next(item for item in all_recall if item["memory_id"] == gamma["memory_id"])
        self.assertEqual(gamma_hit["recall_provenance"], "all")
        self.assertEqual(exported["context_links"][0]["approved_by"], "unit-test")
        self.assertEqual(stats["context_link_count"], 2)
        self.assertEqual(alpha["context_id"], "alpha")

    def test_context_bus_events_are_persisted_listed_and_exported(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            export_path = Path(tmp) / "memory-export.json"
            store = DurableMemoryStore(db_path)

            first = store.publish_context_event(
                context_id="demo",
                source_surface="dashboard",
                event_type="remember-trace",
                summary="operator-note captured and published",
                payload={"tag": "operator-note", "memory_id": "s2_demo"},
                agent_targets=["mcp-clients", "codex-desktop", "local-ide-adapters"],
            )
            second = store.publish_context_event(
                context_id="demo",
                source_surface="dashboard",
                event_type="ingest-events",
                summary="ops-brief segmented and published",
                payload={"source_tag": "ops-brief", "event_count": 3},
                agent_targets=["mcp-clients"],
            )
            restored = DurableMemoryStore(db_path)
            events = restored.list_context_events(context_id="demo", limit=10)
            since_first = restored.list_context_events(
                context_id="demo",
                since_event_id=first["event_id"],
                limit=10,
            )
            ack = restored.ack_context_events(
                context_id="demo",
                agent_id="codex-desktop",
                last_event_id=second["event_id"],
            )
            cursors = restored.list_context_cursors(context_id="demo")
            stats = restored.stats(context_id="demo")
            exported = restored.export_json(export_path, context_id="demo")

        self.assertEqual(first["context_id"], "demo")
        self.assertEqual(first["event_type"], "remember-trace")
        self.assertEqual(first["payload"]["tag"], "operator-note")
        self.assertIn("codex-desktop", first["agent_targets"])
        self.assertEqual([event["event_id"] for event in events], [first["event_id"], second["event_id"]])
        self.assertEqual([event["event_id"] for event in since_first], [second["event_id"]])
        self.assertEqual(ack["agent_id"], "codex-desktop")
        self.assertEqual(ack["last_event_id"], second["event_id"])
        self.assertEqual(ack["pending_event_count"], 0)
        self.assertEqual(cursors[0]["agent_id"], "codex-desktop")
        self.assertEqual(stats["context_bus_event_count"], 2)
        self.assertEqual(stats["context_bus_latest_event_id"], second["event_id"])
        self.assertEqual(stats["context_bus_ack_cursor_count"], 1)
        self.assertEqual(exported["context_events"][0]["summary"], "operator-note captured and published")
        self.assertEqual(exported["context_cursors"][0]["agent_id"], "codex-desktop")

    def test_delete_entry_cascades_relationships_and_memory_events(self):
        with TemporaryDirectory() as tmp:
            store = DurableMemoryStore(Path(tmp) / "synapse-memory.sqlite3")
            first = store.upsert_entry(
                tag="sensitive-event-001",
                context_id="demo",
                source_text="Sensitive partial truth that must be removed.",
                metadata={"event_segment": True},
                embedding_dimensions=8,
                spike_indices=[1, 2],
                neuron_indices=[3, 4],
            )
            second = store.upsert_entry(
                tag="retained-event-002",
                context_id="demo",
                source_text="Retained context.",
                metadata={"event_segment": True},
                embedding_dimensions=8,
                spike_indices=[5, 6],
                neuron_indices=[7, 8],
            )
            store.upsert_relationship(
                context_id="demo",
                source_memory_id=first["memory_id"],
                target_memory_id=second["memory_id"],
                relation_type="temporal_next",
                weight=0.88,
                evidence={"reason": "sequence"},
            )

            deletion = store.delete_entry(context_id="demo", memory_id=first["memory_id"])
            remaining_entries = store.list_entries(context_id="demo")
            remaining_relationships = store.list_relationships(context_id="demo")

        self.assertTrue(deletion["deleted"])
        self.assertEqual(deletion["deleted_memory_id"], first["memory_id"])
        self.assertEqual(deletion["deleted_relationship_count"], 1)
        self.assertGreaterEqual(deletion["deleted_memory_event_count"], 1)
        self.assertEqual([entry["tag"] for entry in remaining_entries], ["retained-event-002"])
        self.assertEqual(remaining_relationships, [])

    def test_delete_relationship_and_relationship_modes_are_precise(self):
        with TemporaryDirectory() as tmp:
            store = DurableMemoryStore(Path(tmp) / "synapse-memory.sqlite3")
            entries = [
                store.upsert_entry(
                    tag=f"event-{index}",
                    context_id="demo",
                    source_text=f"Event {index}",
                    metadata={"event_segment": True},
                    embedding_dimensions=8,
                    spike_indices=[index],
                    neuron_indices=[index],
                )
                for index in range(1, 4)
            ]
            temporal = store.upsert_relationship(
                context_id="demo",
                source_memory_id=entries[0]["memory_id"],
                target_memory_id=entries[1]["memory_id"],
                relation_type="temporal_next",
                weight=0.91,
            )
            semantic = store.upsert_relationship(
                context_id="demo",
                source_memory_id=entries[0]["memory_id"],
                target_memory_id=entries[2]["memory_id"],
                relation_type="semantic_overlap",
                weight=0.51,
            )
            removed_edge = store.delete_relationship(
                context_id="demo",
                relationship_id=temporal["relationship_id"],
            )
            removed_associative = store.delete_relationships_by_mode(
                context_id="demo",
                mode="associative",
            )
            remaining_relationships = store.list_relationships(context_id="demo")

        self.assertTrue(removed_edge["deleted"])
        self.assertEqual(removed_edge["relationship_id"], temporal["relationship_id"])
        self.assertEqual(removed_associative["deleted_relationship_count"], 1)
        self.assertEqual(removed_associative["deleted_relationship_ids"], [semantic["relationship_id"]])
        self.assertEqual(remaining_relationships, [])

    def test_delete_context_event_removes_single_deployment_record(self):
        with TemporaryDirectory() as tmp:
            store = DurableMemoryStore(Path(tmp) / "synapse-memory.sqlite3")
            first = store.publish_context_event(
                context_id="demo",
                source_surface="test",
                event_type="conversation-capture",
                summary="first",
            )
            second = store.publish_context_event(
                context_id="demo",
                source_surface="test",
                event_type="prune-memory",
                summary="second",
            )

            deletion = store.delete_context_event(
                context_id="demo",
                event_id=first["event_id"],
            )
            remaining = store.list_context_events(context_id="demo", limit=10)

        self.assertTrue(deletion["deleted"])
        self.assertEqual(deletion["event_id"], first["event_id"])
        self.assertEqual([event["event_id"] for event in remaining], [second["event_id"]])

    def test_namespace_graph_snapshot_is_context_isolated_and_excludes_legacy_bad_edges(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            first = store.upsert_entry(
                tag="alpha-first",
                context_id="alpha",
                source_text="First alpha node.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1],
                neuron_indices=[1],
                registered_at=10.0,
            )
            second = store.upsert_entry(
                tag="alpha-second",
                context_id="alpha",
                source_text="Second alpha node.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[2],
                neuron_indices=[2],
                registered_at=11.0,
            )
            other = store.upsert_entry(
                tag="beta-only",
                context_id="beta",
                source_text="Must remain isolated.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[3],
                neuron_indices=[3],
                registered_at=12.0,
            )
            valid = store.upsert_relationship(
                context_id="alpha",
                source_memory_id=first["memory_id"],
                target_memory_id=second["memory_id"],
                relation_type="temporal_next",
                weight=0.9,
            )
            # Legacy files can have been edited while foreign keys were off.
            # The snapshot must omit those rows rather than expose a cross-context
            # or missing endpoint through the drill-down API.
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    """
                    INSERT INTO memory_relationships (
                        relationship_id, context_id, source_memory_id, target_memory_id,
                        relation_type, weight, evidence_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "legacy-cross-context",
                        "alpha",
                        first["memory_id"],
                        other["memory_id"],
                        "legacy",
                        0.1,
                        "{}",
                        13.0,
                        13.0,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO memory_relationships (
                        relationship_id, context_id, source_memory_id, target_memory_id,
                        relation_type, weight, evidence_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "legacy-missing-endpoint",
                        "alpha",
                        first["memory_id"],
                        "missing-memory-id",
                        "legacy",
                        0.1,
                        "{}",
                        14.0,
                        14.0,
                    ),
                )
                conn.commit()

            first_snapshot = store.namespace_graph_snapshot(
                context_id="alpha",
                entry_scan_limit=10,
                relationship_scan_limit=10,
            )
            second_snapshot = store.namespace_graph_snapshot(
                context_id="alpha",
                entry_scan_limit=10,
                relationship_scan_limit=10,
            )
            deletion = store.delete_entry(
                context_id="alpha",
                memory_id=second["memory_id"],
            )
            after_prune = store.namespace_graph_snapshot(
                context_id="alpha",
                entry_scan_limit=10,
                relationship_scan_limit=10,
            )

        self.assertEqual(first_snapshot, second_snapshot)
        self.assertEqual(first_snapshot["entry_total"], 2)
        self.assertEqual(first_snapshot["relationship_total"], 1)
        self.assertEqual(
            [entry["memory_id"] for entry in first_snapshot["entries"]],
            sorted([first["memory_id"], second["memory_id"]]),
        )
        self.assertEqual(
            [edge["relationship_id"] for edge in first_snapshot["relationships"]],
            [valid["relationship_id"]],
        )
        self.assertTrue(first_snapshot["read_only"])
        self.assertTrue(deletion["deleted"])
        self.assertEqual(after_prune["entry_total"], 1)
        self.assertEqual(after_prune["relationship_total"], 0)
        self.assertEqual(after_prune["relationships"], [])


if __name__ == "__main__":
    unittest.main()

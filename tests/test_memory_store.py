import json
import sqlite3
import unittest
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

            with sqlite3.connect(backup_path) as conn:
                row_count = conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0]

            self.assertEqual(row_count, 1)

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
                tag="safe-event-002",
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
        self.assertEqual([entry["tag"] for entry in remaining_entries], ["safe-event-002"])
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


if __name__ == "__main__":
    unittest.main()

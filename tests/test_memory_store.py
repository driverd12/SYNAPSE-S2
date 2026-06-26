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


if __name__ == "__main__":
    unittest.main()

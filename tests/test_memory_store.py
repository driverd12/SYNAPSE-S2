import hashlib
import json
import sqlite3
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from memory_store import (
    LEGACY_OPTIONAL_SECRET_IDENTIFIER_COLUMNS,
    LEGACY_SECRET_CONTENT_COLUMNS,
    LEGACY_SECRET_IDENTIFIER_COLUMNS,
    SQLITE_APPLICATION_ID,
    DurableMemoryStore,
)


class DurableMemoryStoreTests(unittest.TestCase):
    @staticmethod
    def _capture_plan(
        store: DurableMemoryStore,
        *,
        capture_hex: str = "a",
        fingerprint_hex: str = "b",
        context_id: str = "demo",
    ) -> dict:
        first_memory_id = store.stable_memory_id(
            context_id=context_id,
            tag="capture-first",
        )
        second_memory_id = store.stable_memory_id(
            context_id=context_id,
            tag="capture-second",
        )
        return {
            "capture_id": "s2cap_" + capture_hex * 32,
            "request_fingerprint": fingerprint_hex * 64,
            "context_id": context_id,
            "source_tag": "codex-session",
            "speaker": "codex",
            "entries": [
                {
                    "memory_id": first_memory_id,
                    "tag": "capture-first",
                    "context_id": context_id,
                    "source_text": "First atomic capture trace.",
                    "metadata": {"sequence": 1},
                    "embedding_dimensions": 8,
                    "spike_indices": [1, 3],
                    "neuron_indices": [1, 3],
                    "registered_at": 100.0,
                },
                {
                    "memory_id": second_memory_id,
                    "tag": "capture-second",
                    "context_id": context_id,
                    "source_text": "Second atomic capture trace.",
                    "metadata": {"sequence": 2},
                    "embedding_dimensions": 8,
                    "spike_indices": [2, 4],
                    "neuron_indices": [2, 4],
                    "registered_at": 101.0,
                },
            ],
            "relationships": [
                {
                    "relationship_id": store.stable_relationship_id(
                        context_id=context_id,
                        source_memory_id=first_memory_id,
                        target_memory_id=second_memory_id,
                        relation_type="temporal_next",
                    ),
                    "context_id": context_id,
                    "source_memory_id": first_memory_id,
                    "target_memory_id": second_memory_id,
                    "relation_type": "temporal_next",
                    "weight": 0.91,
                    "evidence": {"reason": "capture-order"},
                    "created_at": 102.0,
                    "updated_at": 102.0,
                }
            ],
            "deployment": {
                "context_id": context_id,
                "source_surface": "test-suite",
                "event_type": "conversation-capture",
                "summary": "Atomic capture committed.",
                "payload": {"tag": "codex-session"},
                "agent_targets": ["mcp-clients"],
                "created_at": 103.0,
            },
            "result": {
                "event_count": 2,
            },
        }

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
            self.assertTrue(backup["verified"])
            self.assertEqual(backup["quick_check"], ["ok"])
            self.assertEqual(backup["foreign_key_error_count"], 0)
            self.assertEqual(len(backup["sha256"]), 64)
            self.assertTrue(backup_path.exists())

            with closing(sqlite3.connect(backup_path)) as conn:
                row_count = conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0]

            self.assertEqual(row_count, 1)

    def test_export_is_atomic_durable_and_preserves_prior_file_on_failure(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = DurableMemoryStore(root / "memory.sqlite3")
            output = root / "export.json"
            output.write_text("prior-export\n", encoding="utf-8")

            with patch("memory_store.os.replace", side_effect=OSError("injected")):
                with self.assertRaises(OSError):
                    store.export_json(output)

            self.assertEqual(output.read_text(encoding="utf-8"), "prior-export\n")
            self.assertEqual(list(root.glob(".export.json.*.tmp")), [])

            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda _index: store.export_json(output), range(8)))

            persisted = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(all(result["export_path"] == str(output) for result in results))
            self.assertEqual(persisted["version"], results[-1]["version"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(root.glob(".export.json.*.tmp")), [])

    def test_backup_is_verified_private_and_never_overwrites_a_destination(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = DurableMemoryStore(root / "memory.sqlite3")
            backup_path = root / "verified.sqlite3"

            result = store.backup(backup_path)
            digest = hashlib.sha256(backup_path.read_bytes()).hexdigest()

            self.assertTrue(result["verified"])
            self.assertEqual(result["sha256"], digest)
            self.assertEqual(result["size_bytes"], backup_path.stat().st_size)
            self.assertEqual(backup_path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                store.backup(backup_path)
            self.assertEqual(
                result["sha256"],
                hashlib.sha256(backup_path.read_bytes()).hexdigest(),
            )
            self.assertEqual(list(root.glob(".verified.sqlite3.*.tmp")), [])

            protected = root / "protected.sqlite3"
            protected.write_bytes(b"protected")
            symlink_path = root / "symlink-backup.sqlite3"
            symlink_path.symlink_to(protected)
            with self.assertRaises(FileExistsError):
                store.backup(symlink_path)
            self.assertEqual(protected.read_bytes(), b"protected")

            export_target = root / "protected-export.json"
            export_target.write_text("protected-export\n", encoding="utf-8")
            export_symlink = root / "symlink-export.json"
            export_symlink.symlink_to(export_target)
            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                store.export_json(export_symlink)
            self.assertEqual(
                export_target.read_text(encoding="utf-8"),
                "protected-export\n",
            )

    def test_caller_owned_database_and_output_parents_keep_permissions(self):
        with TemporaryDirectory() as tmp:
            shared = Path(tmp) / "shared-parent"
            shared.mkdir(mode=0o755)
            shared.chmod(0o755)
            store = DurableMemoryStore(shared / "memory.sqlite3")
            store.export_json(shared / "export.json")
            store.backup(shared / "backup.sqlite3")

            parent_mode = shared.stat().st_mode & 0o777
            database_mode = (shared / "memory.sqlite3").stat().st_mode & 0o777
            export_mode = (shared / "export.json").stat().st_mode & 0o777
            backup_mode = (shared / "backup.sqlite3").stat().st_mode & 0o777

        self.assertEqual(parent_mode, 0o755)
        self.assertEqual(database_mode, 0o600)
        self.assertEqual(export_mode, 0o600)
        self.assertEqual(backup_mode, 0o600)

    def test_database_export_and_backup_paths_reject_credential_shapes(self):
        with TemporaryDirectory() as tmp:
            marker = "SYNTHETIC_STORE_PATH_SECRET_42"
            store = DurableMemoryStore(Path(tmp) / "memory.sqlite3")
            unsafe_export = Path(tmp) / f"password={marker}-export.json"
            unsafe_backup = Path(tmp) / f"password={marker}-backup.sqlite3"
            unsafe_database = Path(tmp) / f"password={marker}-memory.sqlite3"

            with self.assertRaises(ValueError) as export_error:
                store.export_json(unsafe_export)
            with self.assertRaises(ValueError) as backup_error:
                store.backup(unsafe_backup)
            with self.assertRaises(ValueError) as database_error:
                DurableMemoryStore(unsafe_database)

        rendered = "\n".join(
            str(error.exception)
            for error in (export_error, backup_error, database_error)
        )
        self.assertNotIn(marker, rendered)
        self.assertFalse(unsafe_export.exists())
        self.assertFalse(unsafe_backup.exists())
        self.assertFalse(unsafe_database.exists())

    def test_every_durable_text_column_has_a_secret_migration_policy(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "memory.sqlite3"
            DurableMemoryStore(db_path)
            with closing(sqlite3.connect(db_path)) as conn:
                schema_text_columns: set[tuple[str, str]] = set()
                tables = [
                    str(row[0])
                    for row in conn.execute(
                        """
                        SELECT name FROM sqlite_master
                        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                        """
                    ).fetchall()
                ]
                for table_name in tables:
                    for row in conn.execute(
                        f'PRAGMA table_info("{table_name}")'
                    ).fetchall():
                        if "TEXT" in str(row[2]).upper():
                            schema_text_columns.add((table_name, str(row[1])))

        classified = set(LEGACY_SECRET_CONTENT_COLUMNS) | set(
            LEGACY_SECRET_IDENTIFIER_COLUMNS
        )
        self.assertEqual(schema_text_columns, classified)
        self.assertFalse(
            set(LEGACY_SECRET_CONTENT_COLUMNS)
            & set(LEGACY_SECRET_IDENTIFIER_COLUMNS)
        )

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
            leased = restored.lease_context_events(
                context_id="demo",
                agent_id="codex-desktop",
                consumer_instance_id="memory-store-test",
                consumer_groups=["mcp-clients", "local-ide-adapters"],
                limit=10,
            )
            ack = restored.acknowledge_context_deliveries(
                context_id="demo",
                agent_id="codex-desktop",
                acknowledgements=[
                    {"receipt_id": delivery["receipt_id"]}
                    for delivery in leased["deliveries"]
                ],
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
        self.assertEqual(ack["cursor"]["last_event_id"], second["event_id"])
        self.assertEqual(ack["cursor"]["pending_event_count"], 0)
        self.assertEqual(cursors[0]["agent_id"], "codex-desktop")
        self.assertEqual(stats["context_bus_event_count"], 2)
        self.assertEqual(stats["context_bus_latest_event_id"], second["event_id"])
        self.assertEqual(stats["context_bus_ack_cursor_count"], 1)
        self.assertEqual(exported["context_events"][0]["summary"], "operator-note captured and published")
        self.assertEqual(exported["context_cursors"][0]["agent_id"], "codex-desktop")
        self.assertEqual(len(exported["context_deliveries"]), 2)
        self.assertEqual(len(exported["context_delivery_receipts"]), 2)

    def test_context_event_boundary_redacts_wrapped_keys_and_raw_digests(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            marker = "SYNTHETIC_CONTEXT_EVENT_SECRET_42"

            event = store.publish_context_event(
                context_id="demo",
                source_surface="unit-test",
                event_type="secret-boundary",
                summary="authoritative context event boundary",
                payload={
                    "authorization_header": marker,
                    "auth_header": f"Bearer {marker}",
                    "input_sha256": "raw-input-equality-oracle",
                    "content_sha256": "content-equality-oracle",
                    "text_digest": "text-equality-oracle",
                    "prompt_hash": "prompt-equality-oracle",
                    "nested": {"payload_sha256": "nested-equality-oracle"},
                    "sha256": "verified-artifact-checksum",
                },
                agent_targets=["mcp-clients"],
            )
            listed = store.list_context_events(context_id="demo", limit=5)
            database_bytes = db_path.read_bytes()

        payload = event["payload"]
        self.assertEqual(payload["authorization_header"], "[REDACTED_SECRET]")
        self.assertEqual(payload["auth_header"], "[REDACTED_SECRET]")
        self.assertNotIn("input_sha256", payload)
        self.assertNotIn("content_sha256", payload)
        self.assertNotIn("text_digest", payload)
        self.assertNotIn("prompt_hash", payload)
        self.assertNotIn("payload_sha256", payload["nested"])
        self.assertEqual(payload["sha256"], "verified-artifact-checksum")
        self.assertGreaterEqual(payload["context_bus_redaction_count"], 7)
        self.assertFalse(payload["raw_payload_stored"])
        self.assertEqual(listed[0]["payload"], payload)
        self.assertNotIn(marker.encode(), database_bytes)
        self.assertNotIn(b"raw-input-equality-oracle", database_bytes)
        self.assertNotIn(b"nested-equality-oracle", database_bytes)
        self.assertNotIn(b"content-equality-oracle", database_bytes)
        self.assertNotIn(b"text-equality-oracle", database_bytes)
        self.assertNotIn(b"prompt-equality-oracle", database_bytes)

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

    def test_capture_plan_commits_once_and_replays_durable_result(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            plan = self._capture_plan(store)

            committed = store.commit_capture_plan(**plan)
            with closing(sqlite3.connect(db_path)) as conn:
                counts_after_commit = {
                    table: int(
                        conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    )
                    for table in (
                        "memory_entries",
                        "memory_spikes",
                        "memory_surface_terms",
                        "memory_events",
                        "memory_relationships",
                        "agent_context_events",
                        "agent_context_event_targets",
                        "capture_operations",
                    )
                }

            replayed = store.commit_capture_plan(**plan)
            fetched = store.get_capture_operation(plan["capture_id"])
            with closing(sqlite3.connect(db_path)) as conn:
                counts_after_replay = {
                    table: int(
                        conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    )
                    for table in counts_after_commit
                }
            stats = store.stats(context_id="demo")

        self.assertFalse(committed["idempotent_replay"])
        self.assertTrue(replayed["idempotent_replay"])
        self.assertEqual(fetched, replayed)
        self.assertEqual(
            {key: value for key, value in committed.items() if key != "idempotent_replay"},
            {key: value for key, value in replayed.items() if key != "idempotent_replay"},
        )
        self.assertEqual(counts_after_replay, counts_after_commit)
        self.assertEqual(counts_after_commit["memory_entries"], 2)
        self.assertEqual(counts_after_commit["memory_events"], 2)
        self.assertEqual(counts_after_commit["memory_relationships"], 1)
        self.assertEqual(counts_after_commit["agent_context_events"], 1)
        self.assertEqual(counts_after_commit["capture_operations"], 1)
        self.assertEqual(stats["capture_protocol_version"], "capture.v2")
        self.assertEqual(stats["capture_operation_count"], 1)
        self.assertEqual(stats["capture_operation_entry_count"], 2)
        self.assertEqual(stats["capture_operation_relationship_count"], 1)
        self.assertEqual(stats["capture_operation_schema_error_count"], 0)
        self.assertEqual(stats["capture_operation_integrity_error_count"], 0)
        self.assertEqual(stats["capture_operation_health"], "ready")
        self.assertEqual(
            committed["result"],
            {
                "status": "committed",
                "event_count": 2,
                "entry_count": 2,
                "relationship_count": 1,
            },
        )
        self.assertEqual(
            set(committed["deployment_event"]),
            {
                "event_id",
                "context_id",
                "event_type",
                "source_surface",
                "published_at",
            },
        )

    def test_concurrent_capture_plan_retries_serialize_to_one_commit(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            plan = self._capture_plan(store)

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(
                    executor.map(
                        lambda _: store.commit_capture_plan(**plan),
                        range(2),
                    )
                )

            with closing(sqlite3.connect(db_path)) as conn:
                counts = {
                    table: int(
                        conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    )
                    for table in (
                        "memory_entries",
                        "memory_events",
                        "memory_relationships",
                        "agent_context_events",
                        "capture_operations",
                    )
                }

        self.assertEqual(
            sorted(result["idempotent_replay"] for result in outcomes),
            [False, True],
        )
        self.assertEqual(
            counts,
            {
                "memory_entries": 2,
                "memory_events": 2,
                "memory_relationships": 1,
                "agent_context_events": 1,
                "capture_operations": 1,
            },
        )

    def test_capture_plan_rejects_identity_mismatch_without_writes(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            plan = self._capture_plan(store)
            store.commit_capture_plan(**plan)

            for field, replacement in (
                ("request_fingerprint", "c" * 64),
                ("context_id", "other"),
                ("source_tag", "other-source"),
                ("speaker", "operator"),
            ):
                mismatch = dict(plan)
                mismatch[field] = replacement
                with self.subTest(field=field):
                    with self.assertRaisesRegex(ValueError, field):
                        store.commit_capture_plan(**mismatch)

            with closing(sqlite3.connect(db_path)) as conn:
                counts = {
                    table: int(
                        conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    )
                    for table in (
                        "memory_entries",
                        "memory_events",
                        "memory_relationships",
                        "agent_context_events",
                        "capture_operations",
                    )
                }

        self.assertEqual(
            counts,
            {
                "memory_entries": 2,
                "memory_events": 2,
                "memory_relationships": 1,
                "agent_context_events": 1,
                "capture_operations": 1,
            },
        )

    def test_capture_plan_faults_roll_back_every_durable_surface(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)

            for offset, stage in enumerate(
                (
                    "after_entries",
                    "after_relationships",
                    "after_deployment",
                    "before_ledger",
                )
            ):
                plan = self._capture_plan(
                    store,
                    capture_hex="abcdef0123456789"[offset],
                    fingerprint_hex="fedcba9876543210"[offset],
                )

                def fail_at_stage(observed_stage, *, expected_stage=stage):
                    if observed_stage == expected_stage:
                        raise RuntimeError(f"fault:{expected_stage}")

                with self.subTest(stage=stage):
                    with self.assertRaisesRegex(RuntimeError, f"fault:{stage}"):
                        store.commit_capture_plan(**plan, fault_hook=fail_at_stage)
                    with closing(sqlite3.connect(db_path)) as conn:
                        counts = {
                            table: int(
                                conn.execute(
                                    f"SELECT COUNT(*) FROM {table}"
                                ).fetchone()[0]
                            )
                            for table in (
                                "memory_entries",
                                "memory_spikes",
                                "memory_surface_terms",
                                "memory_events",
                                "memory_relationships",
                                "agent_context_events",
                                "agent_context_event_targets",
                                "capture_operations",
                            )
                        }
                    self.assertEqual(set(counts.values()), {0})

    def test_capture_plan_validates_whole_plan_before_opening_transaction(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            valid = self._capture_plan(store)
            invalid_plans = []

            invalid_capture_id = dict(valid)
            invalid_capture_id["capture_id"] = "S2CAP_" + "A" * 32
            invalid_plans.append(("capture_id", invalid_capture_id))

            invalid_fingerprint = dict(valid)
            invalid_fingerprint["request_fingerprint"] = "B" * 64
            invalid_plans.append(("request_fingerprint", invalid_fingerprint))

            invalid_weight = dict(valid)
            invalid_weight["relationships"] = [dict(valid["relationships"][0])]
            invalid_weight["relationships"][0]["weight"] = float("nan")
            invalid_plans.append(("weight", invalid_weight))

            invalid_targets = dict(valid)
            invalid_targets["deployment"] = dict(valid["deployment"])
            invalid_targets["deployment"]["agent_targets"] = ["mcp-clients", 3]
            invalid_plans.append(("agent_targets", invalid_targets))

            invalid_result = dict(valid)
            invalid_result["result"] = {"bad": {1, 2}}
            invalid_plans.append(("result", invalid_result))

            for label, invalid in invalid_plans:
                with self.subTest(label=label):
                    with self.assertRaises(ValueError):
                        store.commit_capture_plan(**invalid)

            with closing(sqlite3.connect(db_path)) as conn:
                self.assertEqual(
                    int(conn.execute("SELECT COUNT(*) FROM capture_operations").fetchone()[0]),
                    0,
                )
                self.assertEqual(
                    int(conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0]),
                    0,
                )
                self.assertEqual(
                    int(conn.execute("SELECT COUNT(*) FROM agent_context_events").fetchone()[0]),
                    0,
                )

    def test_capture_plan_rejects_cross_context_and_unplanned_relationship_endpoints(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            foreign_entry = store.upsert_entry(
                tag="foreign-entry",
                context_id="other",
                source_text="Must never be attached to a demo capture.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[7],
                neuron_indices=[7],
            )
            valid = self._capture_plan(store)
            planned_source = valid["entries"][0]["memory_id"]
            unplanned_same_context = store.stable_memory_id(
                context_id="demo",
                tag="not-in-plan",
            )

            for label, target_memory_id in (
                ("cross-context", foreign_entry["memory_id"]),
                ("same-context-unplanned", unplanned_same_context),
            ):
                invalid = dict(valid)
                invalid["relationships"] = [dict(valid["relationships"][0])]
                invalid["relationships"][0].update(
                    {
                        "target_memory_id": target_memory_id,
                        "relationship_id": store.stable_relationship_id(
                            context_id="demo",
                            source_memory_id=planned_source,
                            target_memory_id=target_memory_id,
                            relation_type="temporal_next",
                        ),
                    }
                )
                with self.subTest(label=label):
                    with self.assertRaisesRegex(
                        ValueError,
                        "endpoints must reference entries in the same capture plan",
                    ):
                        store.commit_capture_plan(**invalid)

            with closing(sqlite3.connect(db_path)) as conn:
                self.assertEqual(
                    int(conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0]),
                    1,
                )
                self.assertEqual(
                    int(conn.execute("SELECT COUNT(*) FROM memory_relationships").fetchone()[0]),
                    0,
                )
                self.assertEqual(
                    int(conn.execute("SELECT COUNT(*) FROM agent_context_events").fetchone()[0]),
                    0,
                )
                self.assertEqual(
                    int(conn.execute("SELECT COUNT(*) FROM capture_operations").fetchone()[0]),
                    0,
                )

    def test_capture_receipt_survives_prune_and_replay_never_resurrects_graph(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            plan = self._capture_plan(store)
            committed = store.commit_capture_plan(**plan)

            for memory_id in [entry["memory_id"] for entry in plan["entries"]]:
                store.delete_entry(context_id="demo", memory_id=memory_id)
            store.delete_context_event(
                context_id="demo",
                event_id=committed["deployment_event"]["event_id"],
            )

            cached = store.get_capture_operation(plan["capture_id"])
            replayed = store.commit_capture_plan(**plan)
            stats = store.stats(context_id="demo")
            with closing(sqlite3.connect(db_path)) as conn:
                graph_counts = {
                    table: int(
                        conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    )
                    for table in (
                        "memory_entries",
                        "memory_events",
                        "memory_relationships",
                        "agent_context_events",
                        "capture_operations",
                    )
                }

        self.assertEqual(cached, replayed)
        self.assertTrue(replayed["idempotent_replay"])
        self.assertEqual(
            graph_counts,
            {
                "memory_entries": 0,
                "memory_events": 0,
                "memory_relationships": 0,
                "agent_context_events": 0,
                "capture_operations": 1,
            },
        )
        self.assertEqual(stats["capture_operation_pruned_deployment_count"], 1)
        self.assertEqual(stats["capture_operation_integrity_error_count"], 0)
        self.assertEqual(stats["capture_operation_health"], "ready")

    def test_capture_receipt_excludes_private_content_from_live_and_backup_rows(self):
        private_marker = "PRIVATE_CAPTURE_MARKER_7f09c4828d4b"
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            backup_path = Path(tmp) / "capture-backup.sqlite3"
            store = DurableMemoryStore(db_path)
            plan = self._capture_plan(store)
            plan["entries"][0]["source_text"] = (
                f"Operator content {private_marker} must stay outside the receipt."
            )
            plan["entries"][0]["metadata"] = {
                "namespace_title": private_marker,
            }
            plan["relationships"][0]["evidence"] = {
                "private_evidence": private_marker,
            }
            plan["deployment"]["summary"] = f"private summary {private_marker}"
            plan["deployment"]["payload"] = {
                "events": [{"source_text": private_marker}],
                "context_namespace": {"namespace_title": private_marker},
            }
            plan["result"] = {
                "event_count": 2,
                "events": [{"source_text": private_marker}],
                "context_namespace": {"namespace_title": private_marker},
                "relationship_evidence": private_marker,
            }

            committed = store.commit_capture_plan(**plan)
            with closing(sqlite3.connect(db_path)) as conn:
                live_result_json = str(
                    conn.execute(
                        "SELECT result_json FROM capture_operations WHERE capture_id = ?",
                        (plan["capture_id"],),
                    ).fetchone()[0]
                )
            self.assertNotIn(private_marker, live_result_json)
            self.assertLessEqual(len(live_result_json.encode("utf-8")), 2048)
            self.assertEqual(
                set(json.loads(live_result_json)["result"]),
                {"status", "event_count", "entry_count", "relationship_count"},
            )

            for entry in plan["entries"]:
                store.delete_entry(
                    context_id="demo",
                    memory_id=entry["memory_id"],
                )
            store.delete_context_event(
                context_id="demo",
                event_id=committed["deployment_event"]["event_id"],
            )
            store.backup(backup_path)

            with closing(sqlite3.connect(backup_path)) as conn:
                backup_result_json = str(
                    conn.execute(
                        "SELECT result_json FROM capture_operations WHERE capture_id = ?",
                        (plan["capture_id"],),
                    ).fetchone()[0]
                )
                backup_counts = {
                    table: int(
                        conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    )
                    for table in (
                        "memory_entries",
                        "memory_relationships",
                        "agent_context_events",
                        "capture_operations",
                    )
                }

        self.assertEqual(backup_result_json, live_result_json)
        self.assertNotIn(private_marker, backup_result_json)
        self.assertEqual(
            backup_counts,
            {
                "memory_entries": 0,
                "memory_relationships": 0,
                "agent_context_events": 0,
                "capture_operations": 1,
            },
        )

    def test_startup_transactionally_scrubs_legacy_full_capture_receipt(self):
        private_marker = "LEGACY_PRIVATE_MARKER_0c9c636ccab7"
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            deployment = store.publish_context_event(
                context_id="demo",
                source_surface="legacy-capture",
                event_type="conversation-capture",
                summary=f"legacy summary {private_marker}",
                payload={"source_text": private_marker},
                agent_targets=["mcp-clients"],
                created_at=203.0,
            )
            store.delete_context_event(
                context_id="demo",
                event_id=deployment["event_id"],
            )
            capture_id = "s2cap_" + "d" * 32
            fingerprint = "e" * 64
            committed_at = 204.0
            legacy_envelope = {
                "capture_id": capture_id,
                "protocol": "capture.v2",
                "request_fingerprint": fingerprint,
                "context_id": "demo",
                "source_tag": "legacy-session",
                "speaker": "operator",
                "result": {
                    "event_count": 2,
                    "events": [{"source_text": private_marker}],
                    "context_namespace": {"namespace_title": private_marker},
                    "relationships": [{"evidence": private_marker}],
                },
                "deployment_event": deployment,
                "entry_count": 3,
                "relationship_count": 1,
                "committed_at": committed_at,
            }
            legacy_json = json.dumps(
                legacy_envelope,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            self.assertIn(private_marker, legacy_json)
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "DELETE FROM store_migrations WHERE key = ?",
                    ("capture_operations_private_receipts_v1",),
                )
                conn.execute(
                    """
                    INSERT INTO capture_operations (
                        capture_id, protocol, request_fingerprint, context_id,
                        source_tag, speaker, result_json, deployment_event_id,
                        entry_count, relationship_count, committed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        capture_id,
                        "capture.v2",
                        fingerprint,
                        "demo",
                        "legacy-session",
                        "operator",
                        legacy_json,
                        deployment["event_id"],
                        3,
                        1,
                        committed_at,
                    ),
                )
                conn.commit()

            restored = DurableMemoryStore(db_path)
            receipt = restored.get_capture_operation(capture_id)
            with closing(sqlite3.connect(db_path)) as conn:
                scrubbed_json = str(
                    conn.execute(
                        "SELECT result_json FROM capture_operations WHERE capture_id = ?",
                        (capture_id,),
                    ).fetchone()[0]
                )
                migration_count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM store_migrations WHERE key = ?",
                        ("capture_operations_private_receipts_v1",),
                    ).fetchone()[0]
                )

        self.assertIsNotNone(receipt)
        self.assertNotIn(private_marker, scrubbed_json)
        self.assertLessEqual(len(scrubbed_json.encode("utf-8")), 2048)
        self.assertEqual(migration_count, 1)
        self.assertEqual(
            receipt["result"],
            {
                "status": "committed",
                "event_count": 2,
                "entry_count": 3,
                "relationship_count": 1,
            },
        )
        self.assertEqual(
            receipt["deployment_event"],
            {
                "event_id": deployment["event_id"],
                "context_id": "demo",
                "event_type": "conversation-capture",
                "source_surface": "legacy-capture",
                "published_at": 203.0,
            },
        )
        self.assertTrue(receipt["idempotent_replay"])

    def test_capture_ledger_detects_schema_and_result_integrity_tampering(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            plan = self._capture_plan(store)
            store.commit_capture_plan(**plan)

            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "UPDATE capture_operations SET result_json = '{}' WHERE capture_id = ?",
                    (plan["capture_id"],),
                )
                conn.commit()
            # Supply an already-open audit connection so stats can report the
            # degraded ledger instead of the normal startup gate failing fast.
            with closing(store._connect_read_only()) as conn:
                degraded = store.stats(context_id="demo", _conn=conn)
            self.assertEqual(degraded["capture_operation_integrity_error_count"], 1)
            self.assertEqual(degraded["capture_operation_health"], "degraded")
            with self.assertRaisesRegex(RuntimeError, "integrity validation"):
                DurableMemoryStore(db_path)

        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            DurableMemoryStore(db_path)
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute("DROP INDEX ix_capture_operations_context_committed")
                conn.execute(
                    """
                    CREATE INDEX ix_capture_operations_context_committed
                    ON capture_operations(source_tag)
                    """
                )
                conn.commit()
            with self.assertRaisesRegex(RuntimeError, "schema validation"):
                DurableMemoryStore(db_path)

    def test_failed_startup_integrity_does_not_publish_schema_markers(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            plan = self._capture_plan(store)
            store.commit_capture_plan(**plan)
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute("UPDATE capture_operations SET result_json = '{}'")
                conn.execute("PRAGMA application_id = 0")
                conn.execute("PRAGMA user_version = 1")
                conn.commit()

            with self.assertRaisesRegex(RuntimeError, "integrity validation"):
                DurableMemoryStore(db_path)

            with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
                self.assertEqual(
                    (
                        int(conn.execute("PRAGMA application_id").fetchone()[0]),
                        int(conn.execute("PRAGMA user_version").fetchone()[0]),
                    ),
                    (0, 1),
                )

    def test_foreign_application_id_is_rejected_without_mutation(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            DurableMemoryStore(db_path)
            foreign_application_id = SQLITE_APPLICATION_ID ^ 1
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(f"PRAGMA application_id = {foreign_application_id}")
                conn.execute("PRAGMA user_version = 1")
                conn.commit()

            with self.assertRaisesRegex(RuntimeError, "application_id"):
                DurableMemoryStore(db_path)

            with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
                self.assertEqual(
                    (
                        int(conn.execute("PRAGMA application_id").fetchone()[0]),
                        int(conn.execute("PRAGMA user_version").fetchone()[0]),
                    ),
                    (foreign_application_id, 1),
                )

    def test_secret_content_migration_scrubs_legacy_rows_and_reads_fail_safe(self):
        marker = "SYNTHETIC_ONLY_LEGACY_DB_SECRET_42"
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entry = store.upsert_entry(
                tag="legacy-secret-test",
                context_id="demo",
                source_text="Initially safe source text.",
                metadata={"safe": "retained"},
                embedding_dimensions=8,
                spike_indices=[1, 3],
                neuron_indices=[1, 3],
            )
            safe_entry = store.upsert_entry(
                tag="post-migration-read-defense",
                context_id="demo",
                source_text="Safe row retained for read-boundary testing.",
                metadata={"safe": "retained"},
                embedding_dimensions=8,
                spike_indices=[2, 4],
                neuron_indices=[2, 4],
            )
            digest_only_entry = store.upsert_entry(
                tag="legacy-raw-digest-oracle",
                context_id="demo",
                source_text="Already redacted historical source text.",
                metadata={"safe": "retained"},
                embedding_dimensions=8,
                spike_indices=[3, 5],
                neuron_indices=[3, 5],
            )
            already_redacted_entry = store.upsert_entry(
                tag="already-redacted-memory",
                context_id="demo",
                source_text="password=[REDACTED_SECRET]",
                metadata={"password": "[REDACTED_SECRET]", "safe": "retained"},
                embedding_dimensions=8,
                spike_indices=[4, 6],
                neuron_indices=[4, 6],
            )
            legacy_raw_digest = "ab" * 32
            event = store.publish_context_event(
                context_id="demo",
                source_surface="unit-test",
                event_type="legacy-secret-test",
                summary="Initially safe summary.",
                payload={"safe": "retained"},
                agent_targets=["mcp-clients"],
            )
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    """
                    UPDATE memory_entries
                    SET source_text = ?, metadata_json = ?
                    WHERE memory_id = ?
                    """,
                    (
                        f'password: "legacy phrase {marker}"',
                        json.dumps({"api_key": marker, "safe": "retained"}),
                        entry["memory_id"],
                    ),
                )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO memory_surface_terms (
                        memory_id, context_id, term, weight
                    ) VALUES (?, 'demo', ?, 99.0)
                    """,
                    (entry["memory_id"], marker.casefold()),
                )
                conn.execute(
                    """
                    UPDATE agent_context_events
                    SET summary = ?, payload_json = ?
                    WHERE event_id = ?
                    """,
                    (
                        f"Authorization: Bearer {marker}",
                        json.dumps({"client_secret": marker, "safe": "retained"}),
                        event["event_id"],
                    ),
                )
                conn.execute(
                    """
                    UPDATE memory_entries
                    SET metadata_json = ?
                    WHERE memory_id = ?
                    """,
                    (
                        json.dumps(
                            {
                                "safe": "retained",
                                "nested": {"input_sha256": legacy_raw_digest},
                            }
                        ),
                        digest_only_entry["memory_id"],
                    ),
                )
                conn.execute(
                    "DELETE FROM store_migrations WHERE key = 'secret_content_scrub_v1'"
                )
                conn.execute(
                    "DELETE FROM store_migrations WHERE key = 'raw_digest_oracle_scrub_v1'"
                )
                conn.commit()

            reopened = DurableMemoryStore(db_path)
            rendered_entry = reopened.get_entry(entry["memory_id"])
            rendered_digest_entry = reopened.get_entry(
                digest_only_entry["memory_id"]
            )
            rendered_already_redacted_entry = reopened.get_entry(
                already_redacted_entry["memory_id"]
            )
            rendered_event = reopened.list_context_events(
                context_id="demo",
                since_event_id=0,
                limit=20,
            )[0]
            with closing(sqlite3.connect(db_path)) as conn:
                durable = "\n".join(
                    str(value)
                    for value in conn.execute(
                        """
                        SELECT summary, payload_json
                        FROM agent_context_events WHERE event_id = ?
                        """,
                        (event["event_id"],),
                    ).fetchone()
                )
                surface_hit_count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM memory_surface_terms WHERE term = ?",
                        (marker.casefold(),),
                    ).fetchone()[0]
                )
                deleted_spike_count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM memory_spikes WHERE memory_id = ?",
                        (entry["memory_id"],),
                    ).fetchone()[0]
                )
                deleted_relationship_count = int(
                    conn.execute(
                        """
                        SELECT COUNT(*) FROM memory_relationships
                        WHERE source_memory_id = ? OR target_memory_id = ?
                        """,
                        (entry["memory_id"], entry["memory_id"]),
                    ).fetchone()[0]
                )
                audit_count = int(
                    conn.execute(
                        """
                        SELECT COUNT(*) FROM store_maintenance_receipts
                        WHERE operation_type = 'secret-content-scrub'
                        """
                    ).fetchone()[0]
                )
                already_redacted_spike_count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM memory_spikes WHERE memory_id = ?",
                        (already_redacted_entry["memory_id"],),
                    ).fetchone()[0]
                )
                already_redacted_surface_count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM memory_surface_terms WHERE memory_id = ?",
                        (already_redacted_entry["memory_id"],),
                    ).fetchone()[0]
                )

                # Defense in depth: even a post-migration direct SQL write is
                # redacted by public row conversion before it can be exported.
                conn.execute(
                    "UPDATE memory_entries SET source_text = ? WHERE memory_id = ?",
                    (f"password={marker}", safe_entry["memory_id"]),
                )
                conn.commit()
            post_migration_injection = reopened.get_entry(safe_entry["memory_id"])

        self.assertIsNone(rendered_entry)
        self.assertIsNotNone(rendered_digest_entry)
        self.assertEqual(rendered_digest_entry["metadata"]["safe"], "retained")
        self.assertNotIn(
            "input_sha256",
            json.dumps(rendered_digest_entry["metadata"], sort_keys=True),
        )
        self.assertNotIn(
            legacy_raw_digest,
            json.dumps(rendered_digest_entry["metadata"], sort_keys=True),
        )
        self.assertIsNotNone(rendered_already_redacted_entry)
        self.assertGreater(already_redacted_spike_count, 0)
        self.assertGreater(already_redacted_surface_count, 0)
        self.assertNotIn(marker, json.dumps(rendered_event, sort_keys=True))
        self.assertNotIn(marker, durable)
        self.assertNotIn(legacy_raw_digest, durable)
        self.assertEqual(rendered_event["payload"]["safe"], "retained")
        self.assertEqual(surface_hit_count, 0)
        self.assertEqual(deleted_spike_count, 0)
        self.assertEqual(deleted_relationship_count, 0)
        self.assertEqual(audit_count, 1)
        self.assertNotIn(
            marker,
            json.dumps(post_migration_injection, sort_keys=True),
        )

    def test_secret_migration_strips_raw_digest_from_malformed_json(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "memory.sqlite3"
            store = DurableMemoryStore(db_path)
            event = store.publish_context_event(
                context_id="demo",
                source_surface="unit-test",
                event_type="malformed-legacy-json",
                summary="safe summary",
                payload={"safe": True},
                agent_targets=["mcp-clients"],
            )
            digest = "ab" * 32
            marker = "SYNTHETIC_MALFORMED_JSON_SECRET_42"
            malformed = f'broken {{ input_sha256={digest}, password={marker}'
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "UPDATE agent_context_events SET payload_json = ? WHERE event_id = ?",
                    (malformed, event["event_id"]),
                )
                conn.execute(
                    "DELETE FROM store_migrations WHERE key = 'secret_content_scrub_v1'"
                )
                conn.commit()

            DurableMemoryStore(db_path)
            with closing(sqlite3.connect(db_path)) as conn:
                durable = str(
                    conn.execute(
                        "SELECT payload_json FROM agent_context_events WHERE event_id = ?",
                        (event["event_id"],),
                    ).fetchone()[0]
                )
                migration_count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM store_migrations WHERE key = 'secret_content_scrub_v1'"
                    ).fetchone()[0]
                )

        self.assertNotIn("input_sha256", durable)
        self.assertNotIn(digest, durable)
        self.assertNotIn(marker, durable)
        self.assertEqual(migration_count, 1)

    def test_secret_content_scrub_v3_rechecks_data_after_detection_upgrade(self):
        marker = "SYNTHETIC_V3_SECRET_VALUE_42"
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entry = store.upsert_entry(
                tag="legacy-v3-entry",
                context_id="demo",
                source_text="safe before legacy injection",
                metadata={},
                embedding_dimensions=4,
                spike_indices=[1],
                neuron_indices=[1],
            )
            event = store.publish_context_event(
                context_id="demo",
                source_surface="unit-test",
                event_type="legacy-v3-event",
                summary="safe summary",
                payload={"safe": True},
                agent_targets=["mcp-clients"],
            )
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "UPDATE memory_entries SET source_text = ? WHERE memory_id = ?",
                    (f"password={marker}", entry["memory_id"]),
                )
                conn.execute(
                    "UPDATE agent_context_events SET payload_json = ? WHERE event_id = ?",
                    (json.dumps({"client_secret": marker}), event["event_id"]),
                )
                conn.execute(
                    "DELETE FROM store_migrations WHERE key = 'secret_content_scrub_v3'"
                )
                conn.commit()

            reopened = DurableMemoryStore(db_path)
            scrubbed_event = reopened.list_context_events(
                context_id="demo",
                since_event_id=0,
                limit=20,
            )[0]
            with closing(sqlite3.connect(db_path)) as conn:
                migration_count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM store_migrations WHERE key = 'secret_content_scrub_v3'"
                    ).fetchone()[0]
                )
                receipt_count = int(
                    conn.execute(
                        """
                        SELECT COUNT(*) FROM store_maintenance_receipts
                        WHERE operation_type = 'secret-content-scrub'
                        """
                    ).fetchone()[0]
                )
            self.assertIsNone(reopened.get_entry(entry["memory_id"]))

        self.assertNotIn(marker, json.dumps(scrubbed_event, sort_keys=True))
        self.assertEqual(migration_count, 1)
        self.assertGreaterEqual(receipt_count, 1)

    def test_secret_identifier_migration_fails_closed_without_echoing_value(self):
        marker = "SYNTHETIC_ONLY_LEGACY_IDENTIFIER_SECRET_42"
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entry = store.upsert_entry(
                tag="safe-tag",
                context_id="demo",
                source_text="Safe source.",
                metadata={},
                embedding_dimensions=4,
                spike_indices=[1],
                neuron_indices=[1],
            )
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute("PRAGMA foreign_keys = OFF")
                conn.execute(
                    "UPDATE memory_entries SET context_id = ? WHERE memory_id = ?",
                    (f"password={marker}", entry["memory_id"]),
                )
                conn.execute(
                    "DELETE FROM store_migrations WHERE key = 'secret_identifier_audit_v1'"
                )
                conn.commit()

            with self.assertRaisesRegex(
                RuntimeError,
                "legacy secret-bearing identifiers",
            ) as raised:
                DurableMemoryStore(db_path)

        self.assertNotIn(marker, str(raised.exception))

    def test_empty_legacy_ack_receipts_table_is_retired_and_nonempty_fails_closed(self):
        legacy_columns = {
            ("agent_context_ack_receipts", column)
            for column in (
                "ack_id",
                "delivery_id",
                "context_id",
                "agent_id",
                "lease_token_sha256",
            )
        }
        self.assertEqual(
            set(LEGACY_OPTIONAL_SECRET_IDENTIFIER_COLUMNS),
            legacy_columns,
        )

        def create_legacy_table(conn: sqlite3.Connection) -> None:
            conn.execute(
                """
                CREATE TABLE agent_context_ack_receipts (
                    ack_id TEXT PRIMARY KEY,
                    delivery_id TEXT NOT NULL,
                    context_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    lease_token_sha256 TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "DELETE FROM store_migrations "
                "WHERE key = 'legacy_ack_receipts_retirement_v1'"
            )

        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "empty-legacy.sqlite3"
            DurableMemoryStore(db_path)
            with closing(sqlite3.connect(db_path)) as conn:
                create_legacy_table(conn)
                conn.commit()
            DurableMemoryStore(db_path)
            with closing(sqlite3.connect(db_path)) as conn:
                table_count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM sqlite_master "
                        "WHERE type = 'table' AND name = 'agent_context_ack_receipts'"
                    ).fetchone()[0]
                )
            self.assertEqual(table_count, 0)

        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "nonempty-legacy.sqlite3"
            DurableMemoryStore(db_path)
            marker = "ab" * 32
            with closing(sqlite3.connect(db_path)) as conn:
                create_legacy_table(conn)
                conn.execute(
                    """
                    INSERT INTO agent_context_ack_receipts (
                        ack_id, delivery_id, context_id, agent_id,
                        lease_token_sha256
                    ) VALUES ('ack-1', 'delivery-1', 'demo', 'agent-1', ?)
                    """,
                    (marker,),
                )
                conn.commit()
            with self.assertRaisesRegex(
                RuntimeError,
                "legacy acknowledgement receipts require governed repair",
            ) as raised:
                DurableMemoryStore(db_path)
            self.assertNotIn(marker, str(raised.exception))


if __name__ == "__main__":
    unittest.main()

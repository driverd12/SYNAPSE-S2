from __future__ import annotations

import stat
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from mlx_backend import SpikingAttentionBackend
from retrieval_cursor import (
    RetrievalCursorContextMismatchError,
    RetrievalCursorFilterMismatchError,
    RetrievalCursorModeMismatchError,
    RetrievalCursorScopeMismatchError,
    RetrievalCursorSnapshotMismatchError,
    RetrievalCursorTamperedError,
)
from token_contracts import MAX_RESPONSE_BYTES, project_response


class RetrievalPaginationIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.backends: list[SpikingAttentionBackend] = []
        self.addCleanup(self._close_backends)
        self.root = Path(self.temporary.name)
        self.backend = self._backend("primary")

    def _close_backends(self) -> None:
        for backend in reversed(self.backends):
            try:
                backend.memory_store.close()
            except Exception:
                pass

    def _backend(
        self,
        name: str,
        *,
        memory_path: Path | None = None,
    ) -> SpikingAttentionBackend:
        private = self.root / name
        private.mkdir(mode=0o700, parents=True, exist_ok=True)
        private.chmod(0o700)
        backend = SpikingAttentionBackend(
            dimension=16,
            num_neurons=12,
            default_top_k=4,
            recall_count=6,
            compile_graph=False,
            state_path=private / "runtime_state.json",
            memory_path=memory_path or private / "memory.sqlite3",
            embedding_provider_name="semantic-hash",
        )
        self.backends.append(backend)
        return backend

    def _entry(
        self,
        tag: str,
        *,
        context_id: str = "alpha",
        metadata: dict | None = None,
    ) -> dict:
        return self.backend.memory_store.upsert_entry(
            tag=tag,
            context_id=context_id,
            source_text=f"Pagination fixture {context_id}/{tag}.",
            metadata=metadata or {"source": "pagination-integration-test"},
            embedding_dimensions=8,
            spike_indices=[1, 3],
            neuron_indices=[2, 4],
        )

    def _relationship(
        self,
        source: dict,
        target: dict,
        *,
        relation_type: str,
    ) -> dict:
        return self.backend.memory_store.upsert_relationship(
            context_id="alpha",
            source_memory_id=source["memory_id"],
            target_memory_id=target["memory_id"],
            relation_type=relation_type,
            weight=0.8,
            evidence={"source": "pagination-integration-test"},
        )

    def _force_timestamp_ties(self) -> None:
        timestamp = 1_700_000_000.25
        with closing(self.backend.memory_store._connect()) as conn:
            with self.backend.memory_store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE memory_entries SET created_at = ?, updated_at = ?",
                    (timestamp, timestamp),
                )
                conn.execute(
                    "UPDATE memory_relationships SET created_at = ?, updated_at = ?",
                    (timestamp, timestamp),
                )

    def _seed_memory_scope(self) -> list[dict]:
        entries = [
            *(self._entry(f"alpha-{index}") for index in range(3)),
            *(
                self._entry(f"beta-{index}", context_id="beta")
                for index in range(2)
            ),
            *(
                self._entry(f"global-{index}", context_id="global")
                for index in range(2)
            ),
        ]
        self._entry("excluded", context_id="unrelated")
        self.backend.approve_namespace_link(
            source_context_id="alpha",
            target_context_id="beta",
            relation_type="approved-connected",
            direction="directed",
            weight=0.9,
            approved_by="integration-test",
            confirm=True,
        )
        self._force_timestamp_ties()
        return entries

    @staticmethod
    def _projected_memory_entries(projected: dict, mode: str) -> list[dict]:
        if mode == "compact":
            return projected["data"]["entries"]
        return projected["data"]["payload"]["entries"]

    def test_memory_cursor_traversal_has_no_duplicates_or_skips_in_compact_and_full_modes(
        self,
    ) -> None:
        included = self._seed_memory_scope()
        expected_ids = sorted(
            (entry["memory_id"] for entry in included),
            reverse=True,
        )

        for mode in ("compact", "full"):
            with self.subTest(mode=mode):
                raw_ids: list[str] = []
                projected_ids: list[str] = []
                cursor = ""
                page_count = 0
                snapshot_revision = None
                while True:
                    page_count += 1
                    self.assertLess(page_count, 10, "cursor traversal did not terminate")
                    raw = self.backend.list_memory(
                        context_id="alpha",
                        limit=2,
                        include_global=True,
                        include_vectors=False,
                        recall_scope="connected",
                        cursor=cursor,
                        response_mode=mode,
                    )
                    metadata = raw["_retrieval_page"]
                    snapshot_revision = snapshot_revision or metadata[
                        "snapshot_revision"
                    ]
                    self.assertEqual(
                        metadata["snapshot_revision"], snapshot_revision
                    )
                    self.assertEqual(metadata["returned"]["entries"], len(raw["entries"]))
                    raw_page_ids = [entry["memory_id"] for entry in raw["entries"]]
                    raw_ids.extend(raw_page_ids)

                    projected = project_response(
                        "memory-list",
                        raw,
                        mode=mode,
                        max_response_bytes=MAX_RESPONSE_BYTES,
                    )
                    projected_page_ids = [
                        entry["memory_id"]
                        for entry in self._projected_memory_entries(projected, mode)
                    ]
                    self.assertEqual(projected_page_ids, raw_page_ids)
                    projected_ids.extend(projected_page_ids)
                    self.assertTrue(projected["pagination"]["supported"])
                    self.assertEqual(
                        projected["pagination"]["next_cursor"],
                        metadata["next_cursor"],
                    )
                    self.assertEqual(
                        projected["continuation"]["cursor"],
                        metadata["next_cursor"],
                    )
                    if not metadata["has_more"]:
                        self.assertIsNone(metadata["next_cursor"])
                        break
                    cursor = projected["continuation"]["cursor"]
                    self.assertIsInstance(cursor, str)
                    self.assertTrue(cursor.startswith("s2rc2."))

                self.assertEqual(raw_ids, expected_ids)
                self.assertEqual(projected_ids, expected_ids)
                self.assertEqual(len(raw_ids), len(set(raw_ids)))
                self.assertEqual(page_count, 4)

        key_path = self.backend.state_path.parent / "retrieval_cursor.key"
        self.assertTrue(key_path.is_file())
        self.assertFalse(key_path.is_symlink())
        self.assertEqual(stat.S_IMODE(key_path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)

    def test_memory_cursor_rejects_tamper_and_every_request_binding_mismatch(
        self,
    ) -> None:
        self._seed_memory_scope()
        first = self.backend.list_memory(
            context_id="alpha",
            limit=2,
            include_global=True,
            include_vectors=False,
            recall_scope="connected",
            response_mode="compact",
        )
        cursor = first["_retrieval_page"]["next_cursor"]
        self.assertIsInstance(cursor, str)

        prefix, payload, signature = cursor.split(".")
        replacement = "A" if signature[0] != "A" else "B"
        tampered = ".".join((prefix, payload, replacement + signature[1:]))
        with self.assertRaises(RetrievalCursorTamperedError):
            self.backend.list_memory(
                context_id="alpha",
                limit=2,
                include_global=True,
                include_vectors=False,
                recall_scope="connected",
                cursor=tampered,
                response_mode="compact",
            )

        cases = (
            (
                RetrievalCursorContextMismatchError,
                {
                    "context_id": "beta",
                    "recall_scope": "connected",
                    "include_global": True,
                    "include_vectors": False,
                    "response_mode": "compact",
                },
            ),
            (
                RetrievalCursorModeMismatchError,
                {
                    "context_id": "alpha",
                    "recall_scope": "connected",
                    "include_global": True,
                    "include_vectors": False,
                    "response_mode": "full",
                },
            ),
            (
                RetrievalCursorFilterMismatchError,
                {
                    "context_id": "alpha",
                    "recall_scope": "connected",
                    "include_global": False,
                    "include_vectors": False,
                    "response_mode": "compact",
                },
            ),
            (
                RetrievalCursorFilterMismatchError,
                {
                    "context_id": "alpha",
                    "recall_scope": "connected",
                    "include_global": True,
                    "include_vectors": True,
                    "response_mode": "compact",
                },
            ),
            (
                RetrievalCursorScopeMismatchError,
                {
                    "context_id": "alpha",
                    "recall_scope": "local",
                    "include_global": True,
                    "include_vectors": False,
                    "response_mode": "compact",
                },
            ),
        )
        for error_type, arguments in cases:
            with self.subTest(error=error_type.__name__, arguments=arguments):
                with self.assertRaises(error_type):
                    self.backend.list_memory(
                        limit=2,
                        cursor=cursor,
                        **arguments,
                    )

    def test_memory_cursor_rejects_stale_snapshot_and_a_different_local_key(self) -> None:
        self._seed_memory_scope()
        first = self.backend.list_memory(
            context_id="alpha",
            limit=2,
            include_global=True,
            include_vectors=False,
            recall_scope="connected",
            response_mode="compact",
        )
        cursor = first["_retrieval_page"]["next_cursor"]
        self.assertIsInstance(cursor, str)

        self._entry("snapshot-mutation")
        with self.assertRaises(RetrievalCursorSnapshotMismatchError) as caught:
            self.backend.list_memory(
                context_id="alpha",
                limit=2,
                include_global=True,
                include_vectors=False,
                recall_scope="connected",
                cursor=cursor,
                response_mode="compact",
            )
        self.assertEqual(caught.exception.code, "retrieval_cursor_stale")

        current = self.backend.list_memory(
            context_id="alpha",
            limit=2,
            include_global=True,
            include_vectors=False,
            recall_scope="connected",
            response_mode="compact",
        )
        current_cursor = current["_retrieval_page"]["next_cursor"]
        other = self._backend(
            "other-origin",
            memory_path=self.backend.memory_store.db_path,
        )
        self.assertNotEqual(
            self.backend._get_retrieval_cursor_codec().origin_node,
            other._get_retrieval_cursor_codec().origin_node,
        )
        with self.assertRaises(RetrievalCursorTamperedError):
            other.list_memory(
                context_id="alpha",
                limit=2,
                include_global=True,
                include_vectors=False,
                recall_scope="connected",
                cursor=current_cursor,
                response_mode="compact",
            )

    def test_graph_cursor_advances_independent_streams_and_hydrates_endpoints(self) -> None:
        entries = [self._entry(f"graph-node-{index}") for index in range(3)]
        relationships = [
            self._relationship(
                entries[index % len(entries)],
                entries[(index + 1) % len(entries)],
                relation_type=f"edge-{index}",
            )
            for index in range(7)
        ]
        self._force_timestamp_ties()

        primary_ids: list[str] = []
        relationship_ids: list[str] = []
        cursor = ""
        observed_relationship_only_page = False
        page_count = 0
        while True:
            page_count += 1
            self.assertLess(page_count, 10, "graph cursor traversal did not terminate")
            raw = self.backend.list_memory_graph(
                context_id="alpha",
                limit=2,
                cursor=cursor,
                response_mode="compact",
                include_global=False,
            )
            metadata = raw["_retrieval_page"]
            page_primary_ids = [
                entry["memory_id"]
                for entry in raw["entries"]
                if "primary" in entry["graph_page_roles"]
            ]
            page_relationship_ids = [
                relationship["relationship_id"]
                for relationship in raw["relationships"]
            ]
            primary_ids.extend(page_primary_ids)
            relationship_ids.extend(page_relationship_ids)
            self.assertEqual(
                metadata["returned"]["nodes"], len(page_primary_ids)
            )
            self.assertEqual(
                metadata["returned"]["relationships"],
                len(page_relationship_ids),
            )

            visible_ids = {entry["memory_id"] for entry in raw["entries"]}
            endpoint_ids = {
                relationship[field]
                for relationship in raw["relationships"]
                for field in ("source_memory_id", "target_memory_id")
            }
            self.assertTrue(endpoint_ids.issubset(visible_ids))
            if not page_primary_ids and page_relationship_ids:
                observed_relationship_only_page = True
                self.assertTrue(
                    all(
                        "primary" not in entry["graph_page_roles"]
                        for entry in raw["entries"]
                    )
                )

            projected = project_response(
                "memory-graph",
                raw,
                mode="compact",
                max_response_bytes=MAX_RESPONSE_BYTES,
            )
            self.assertEqual(
                {node["memory_id"] for node in projected["data"]["nodes"]},
                visible_ids,
            )
            self.assertEqual(
                [edge["relationship_id"] for edge in projected["data"]["edges"]],
                page_relationship_ids,
            )
            self.assertEqual(projected["data"]["unresolved_edge_count"], 0)
            self.assertTrue(
                projected["completeness"]["all_returned_edge_endpoints_resolved"]
            )
            self.assertEqual(
                projected["pagination"]["next_cursor"], metadata["next_cursor"]
            )
            if not metadata["has_more"]:
                self.assertIsNone(projected["continuation"]["cursor"])
                break
            cursor = projected["continuation"]["cursor"]

        self.assertTrue(observed_relationship_only_page)
        self.assertEqual(
            primary_ids,
            sorted((entry["memory_id"] for entry in entries), reverse=True),
        )
        self.assertEqual(
            relationship_ids,
            sorted(
                (relationship["relationship_id"] for relationship in relationships),
                reverse=True,
            ),
        )
        self.assertEqual(len(primary_ids), len(set(primary_ids)))
        self.assertEqual(len(relationship_ids), len(set(relationship_ids)))

    def test_cortex_cursor_traversal_preserves_projected_working_memory(self) -> None:
        cortex_metadata = {
            "cortex_governor": True,
            "trace_type": "decision",
            "truth_posture": "observed",
            "confidence": 0.9,
            "source": "pagination-integration-test",
        }
        included = [
            *(
                self._entry(f"cortex-{index}", metadata=cortex_metadata)
                for index in range(5)
            ),
            self._entry(
                "global-cortex",
                context_id="global",
                metadata=cortex_metadata,
            ),
        ]
        self._entry("ordinary", metadata={"cortex_governor": False})
        self._entry(
            "numeric-cortex",
            metadata={"cortex_governor": 1},
        )
        self._entry(
            "beta-cortex",
            context_id="beta",
            metadata=cortex_metadata,
        )
        self._force_timestamp_ties()

        raw_ids: list[str] = []
        projected_ids: list[str] = []
        cursor = ""
        page_count = 0
        while True:
            page_count += 1
            self.assertLess(page_count, 10, "Cortex cursor traversal did not terminate")
            raw = self.backend.get_cortex_state(
                context_id="alpha",
                limit=2,
                cursor=cursor,
                response_mode="compact",
            )
            metadata = raw["_retrieval_page"]
            raw_page_ids = [item["memory_id"] for item in raw["working_memory"]]
            raw_ids.extend(raw_page_ids)
            self.assertEqual(
                metadata["returned"]["working_memory"], len(raw_page_ids)
            )

            projected = project_response(
                "cortex-state",
                raw,
                mode="compact",
                max_response_bytes=MAX_RESPONSE_BYTES,
            )
            projected_page_ids = [
                item["memory_id"] for item in projected["data"]["working_memory"]
            ]
            self.assertEqual(projected_page_ids, raw_page_ids)
            projected_ids.extend(projected_page_ids)
            self.assertEqual(
                projected["pagination"]["next_cursor"], metadata["next_cursor"]
            )
            if not metadata["has_more"]:
                self.assertIsNone(projected["continuation"]["cursor"])
                break
            cursor = projected["continuation"]["cursor"]

        expected_ids = sorted(
            (entry["memory_id"] for entry in included),
            reverse=True,
        )
        self.assertEqual(raw_ids, expected_ids)
        self.assertEqual(projected_ids, expected_ids)
        self.assertEqual(len(raw_ids), len(set(raw_ids)))

    def test_cortex_cursor_rejects_live_governor_session_changes(self) -> None:
        cortex_metadata = {
            "cortex_governor": True,
            "trace_type": "decision",
            "truth_posture": "observed",
            "confidence": 0.9,
            "source": "pagination-integration-test",
        }
        for index in range(3):
            self._entry(f"cortex-live-{index}", metadata=cortex_metadata)
        first = self.backend.get_cortex_state(
            context_id="alpha",
            limit=1,
            response_mode="compact",
        )
        cursor = first["_retrieval_page"]["next_cursor"]
        self.assertIsInstance(cursor, str)
        self.assertEqual(first["active_session_count"], 0)

        self.backend.cortex_sessions["ctx_live_snapshot_change"] = {
            "session_id": "ctx_live_snapshot_change",
            "context_id": "alpha",
            "agent_id": "codex-desktop",
            "status": "active",
            "task": "exercise the runtime snapshot fence",
            "mode": "strict",
            "updated_at": 1_800_000_000.0,
        }
        with self.assertRaises(RetrievalCursorSnapshotMismatchError):
            self.backend.get_cortex_state(
                context_id="alpha",
                limit=1,
                cursor=cursor,
                response_mode="compact",
            )


if __name__ == "__main__":
    unittest.main()

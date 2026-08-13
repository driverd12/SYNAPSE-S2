from __future__ import annotations

import hashlib
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from scripts import purge_namespaces as purge


class FakeCoreClient:
    def __init__(self, contexts: dict[str, dict] | None = None) -> None:
        self.contexts = contexts or {}
        self.links: list[dict] = []
        self.proposals: list[dict] = []
        self.prunes: list[dict] = []
        self.audits: list[dict] = []

    def _state(self, context: str) -> dict:
        return self.contexts.setdefault(
            context,
            {
                "memory_ids": [],
                "relationship_ids": [],
                "event_ids": [],
                "deliveries": 0,
                "receipts": 0,
                "tombstones": 0,
                "active_leases": 0,
                "catalog": False,
            },
        )

    def _snapshot(self, context: str, surface: str) -> str:
        state = self._state(context)
        value = repr(
            (
                surface,
                sorted(state["memory_ids"]),
                sorted(state["relationship_ids"]),
                sorted(state["event_ids"]),
            )
        ).encode()
        return hashlib.sha256(value).hexdigest()

    def namespace_catalog_contexts(self, contexts):
        return [
            context
            for context in contexts
            if self._state(context).get("catalog") is True
        ]

    def list_memory(self, **arguments):
        context = arguments["context_id"]
        state = self._state(context)
        entries = [
            {"context_id": context, "memory_id": memory_id}
            for memory_id in sorted(state["memory_ids"])
        ]
        return {
            "context_id": context,
            "entries": entries,
            "_retrieval_page": {
                "snapshot_revision": self._snapshot(context, "memory"),
                "total": {"entries": len(entries)},
                "has_more": False,
                "next_cursor": None,
            },
        }

    def list_memory_graph(self, **arguments):
        context = arguments["context_id"]
        state = self._state(context)
        relationships = [
            {"context_id": context, "relationship_id": relationship_id}
            for relationship_id in sorted(state["relationship_ids"])
        ]
        return {
            "context_id": context,
            "relationships": relationships,
            "_retrieval_page": {
                "snapshot_revision": self._snapshot(context, "graph"),
                "total": {"relationships": len(relationships)},
                "has_more": False,
                "next_cursor": None,
            },
        }

    def list_context_events(self, **arguments):
        context = arguments["context_id"]
        since = arguments["since_event_id"]
        events = [
            {"context_id": context, "event_id": event_id}
            for event_id in sorted(self._state(context)["event_ids"])
            if event_id > since
        ]
        return {
            "context_id": context,
            "events": events,
            "has_more": False,
            "next_event_id": events[-1]["event_id"] if events else since,
        }

    def status(self, *, context_id: str):
        state = self._state(context_id)
        relevant_links = self._relevant_links(context_id)
        return {
            "memory_context_entry_count": len(state["memory_ids"]),
            "memory_context_relationship_count": len(state["relationship_ids"]),
            "memory_selected_context_link_count": len(relevant_links),
            "context_bus_context_event_count": len(state["event_ids"]),
            "context_bus_delivery_count": state["deliveries"],
            "context_bus_active_lease_count": state["active_leases"],
            "context_bus_ack_receipt_count": state["receipts"],
            "context_bus_ack_tombstone_count": state["tombstones"],
            "active_cortex_session_count": 0,
        }

    def context_delivery_health(self, *, context_id: str):
        state = self._state(context_id)
        return {
            "status": state.get("delivery_status", "ready"),
            "structural_error_count": state.get("structural_errors", 0),
            "expired_active_lease_count": 0,
            "retry_exhausted_count": 0,
            "dead_letter_count": 0,
            "delivery_count": state["deliveries"],
            "receipt_count": state["receipts"],
            "ack_tombstone_count": state["tombstones"],
        }

    def list_namespace_link_proposals(self, **arguments):
        context = arguments["context_id"]
        proposals = [
            item
            for item in self.proposals
            if context in {item["source_context_id"], item["target_context_id"]}
            and item.get("effective_state") == "pending"
        ]
        return {"proposal_count": len(proposals), "proposals": proposals}

    def _relevant_links(self, context: str) -> list[dict]:
        return [
            item
            for item in self.links
            if context in {item["source_context_id"], item["target_context_id"]}
        ]

    def list_namespace_map(self, **arguments):
        nodes = []
        for context, state in sorted(self.contexts.items()):
            links = self._relevant_links(context)
            visible = bool(
                state["memory_ids"]
                or state["relationship_ids"]
                or state["event_ids"]
                or links
                or state["catalog"]
            )
            if not visible:
                continue
            nodes.append(
                {
                    "context_id": context,
                    "entry_count": len(state["memory_ids"]),
                    "relationship_count": len(state["relationship_ids"]),
                    "context_event_count": len(state["event_ids"]),
                    "context_link_count": len(links),
                    "surface_term_count": len(state["memory_ids"]),
                    "spike_index_count": len(state["memory_ids"]),
                    "last_activity_at": 1.0,
                }
            )
        return {"nodes": nodes, "links": list(self.links)}

    def prune_memory(self, **arguments):
        self.prunes.append(dict(arguments))
        state = self._state(arguments["context_id"])
        deleted = False
        if arguments["target_type"] == "memory":
            memory_id = arguments["memory_id"]
            if memory_id in state["memory_ids"]:
                state["memory_ids"].remove(memory_id)
                state["relationship_ids"].clear()
                deleted = True
        elif arguments["target_type"] == "context_event":
            event_id = arguments["event_id"]
            if event_id in state["event_ids"]:
                state["event_ids"].remove(event_id)
                if not state["event_ids"]:
                    state["deliveries"] = 0
                    state["receipts"] = 0
                deleted = True
        return {"result": {"deleted": deleted}, "agent_deployment": None}

    def publish_context_event(self, **arguments):
        self.audits.append(dict(arguments))
        return {"context_id": arguments["context_id"], "event_id": 999}


def candidate_state(*, catalog: bool = False) -> dict:
    return {
        "memory_ids": ["mem_a", "mem_b"],
        "relationship_ids": ["rel_a"],
        "event_ids": [41, 42],
        "deliveries": 2,
        "receipts": 2,
        "tombstones": 1,
        "active_leases": 0,
        "catalog": catalog,
    }


class NamespacePurgeTests(unittest.TestCase):
    def test_authoritative_client_uses_every_reviewed_split_route(self):
        binding = SimpleNamespace(
            authority_mode="authoritative-core-v6",
            socket_path=Path("/private/tmp/synapse-run/service.sock"),
            state_path=Path("/private/tmp/synapse-data/runtime_state.json"),
            replication_inbox_root=Path("/private/tmp/synapse-data/replication/inbox"),
            config_fingerprint="a" * 64,
        )
        core = object()
        with mock.patch.dict(
            purge.os.environ,
            {purge.BINDING_ENV: "/private/tmp/core-binding.json"},
        ), mock.patch(
            "scripts.purge_namespaces.apply_binding_environment",
            return_value=binding,
        ), mock.patch(
            "scripts.purge_namespaces.CoreClient",
            return_value=core,
        ) as constructor:
            observed_core, observed_binding = purge.authoritative_client()

        self.assertIs(observed_core, core)
        self.assertIs(observed_binding, binding)
        constructor.assert_called_once_with(
            socket_path=binding.socket_path,
            state_path=binding.state_path,
            replication_inbox_root=binding.replication_inbox_root,
            caller=purge.SOURCE_SURFACE,
            expected_config_fingerprint=binding.config_fingerprint,
            default_timeout_seconds=30.0,
        )

    def test_owner_bound_catalog_probe_detects_metadata_without_writing(self):
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            with closing(sqlite3.connect(database)) as conn:
                conn.execute(
                    "CREATE TABLE store_metadata (key TEXT PRIMARY KEY, value_json TEXT)"
                )
                conn.execute(
                    "INSERT INTO store_metadata (key, value_json) VALUES (?, ?)",
                    ("namespace_catalog.v1:alpha", "{}"),
                )
                conn.commit()

            observed = purge._cataloged_contexts(
                FakeCoreClient(),
                ["alpha", "beta"],
                expected_memory_path=database,
            )

        self.assertEqual(observed, frozenset({"alpha"}))

    def test_preview_is_exact_and_revision_is_order_independent(self):
        client = FakeCoreClient({"alpha": candidate_state(), "beta": candidate_state()})
        first = purge.build_plan(client, ["beta", "alpha"])
        second = purge.build_plan(client, ["alpha", "beta"])

        self.assertTrue(first.ready)
        self.assertEqual(first.revision, second.revision)
        alpha = first.public_preview()["namespaces"][0]
        self.assertEqual(alpha["context_id"], "alpha")
        self.assertEqual(alpha["counts"]["memory_nodes"], 2)
        self.assertEqual(alpha["counts"]["memory_relationships"], 1)
        self.assertEqual(alpha["counts"]["context_events"], 2)

    def test_protected_contexts_are_rejected(self):
        for context in ("default", "DEFAULT", "global"):
            with self.subTest(context=context):
                with self.assertRaisesRegex(purge.NamespacePurgeError, "protected_context"):
                    purge.normalize_contexts([context])

    def test_preview_blocks_links_proposals_leases_and_degraded_delivery(self):
        state = candidate_state()
        state["active_leases"] = 1
        state["delivery_status"] = "degraded"
        state["structural_errors"] = 1
        client = FakeCoreClient({"alpha": state, "beta": candidate_state()})
        client.links.append(
            {
                "context_link_id": "link_1",
                "source_context_id": "alpha",
                "target_context_id": "beta",
                "revision": "r1",
                "enabled": True,
                "effective_state": "approved",
            }
        )
        client.proposals.append(
            {
                "proposal_id": "proposal_1",
                "source_context_id": "alpha",
                "target_context_id": "beta",
                "revision": "r1",
                "effective_state": "pending",
            }
        )

        plan = purge.build_plan(client, ["alpha"])
        codes = {item["code"] for item in plan.blockers}
        self.assertIn("active-namespace-links", codes)
        self.assertIn("pending-namespace-link-proposals", codes)
        self.assertIn("active-delivery-leases", codes)
        self.assertIn("delivery-ledger-degraded", codes)

    def test_commit_requires_guards_and_publishes_one_default_audit(self):
        client = FakeCoreClient({"alpha": candidate_state()})
        plan = purge.build_plan(client, ["alpha"])
        with self.assertRaisesRegex(purge.NamespacePurgeError, "confirm_required"):
            purge.commit_purge(
                client,
                ["alpha"],
                expected_revision=plan.revision,
                reason="remove test namespace",
                confirm=False,
            )
        with self.assertRaisesRegex(purge.NamespacePurgeError, "reason_invalid"):
            purge.commit_purge(
                client,
                ["alpha"],
                expected_revision=plan.revision,
                reason="",
                confirm=True,
            )

        result = purge.commit_purge(
            client,
            ["alpha"],
            expected_revision=plan.revision,
            reason="remove screenshot-only test namespace",
            confirm=True,
        )

        self.assertEqual(result["status"], "purged")
        self.assertTrue(result["post_purge_verified"])
        self.assertEqual(len(client.prunes), 4)
        self.assertTrue(all(item["publish_audit"] is False for item in client.prunes))
        self.assertEqual(len(client.audits), 2)
        self.assertTrue(all(item["context_id"] == "default" for item in client.audits))
        self.assertEqual(client.audits[0]["event_type"], "namespace-purge-started")
        self.assertEqual(client.audits[1]["event_type"], "namespace-purge")
        self.assertEqual(result["started_audit_event_id"], 999)
        self.assertEqual(result["completed_audit_event_id"], 999)

    def test_stale_revision_refuses_before_mutation(self):
        client = FakeCoreClient({"alpha": candidate_state()})
        with self.assertRaisesRegex(purge.NamespacePurgeError, "revision_mismatch"):
            purge.commit_purge(
                client,
                ["alpha"],
                expected_revision="0" * 64,
                reason="remove test namespace",
                confirm=True,
            )
        self.assertEqual(client.prunes, [])
        self.assertEqual(client.audits, [])

    def test_cataloged_namespace_is_blocked_before_deletion(self):
        client = FakeCoreClient({"alpha": candidate_state(catalog=True)})
        plan = purge.build_plan(client, ["alpha"])
        self.assertFalse(plan.ready)
        self.assertIn(
            "cataloged-namespace-unsupported",
            {item["code"] for item in plan.blockers},
        )

        with self.assertRaisesRegex(purge.NamespacePurgeError, "purge_blocked"):
            purge.commit_purge(
                client,
                ["alpha"],
                expected_revision=plan.revision,
                reason="remove test namespace",
                confirm=True,
            )
        self.assertEqual(client.prunes, [])
        self.assertEqual(client.audits, [])

    def test_partial_failure_keeps_started_audit(self):
        class FailingClient(FakeCoreClient):
            def prune_memory(self, **arguments):
                if len(self.prunes) == 1:
                    raise RuntimeError("transport failed")
                return super().prune_memory(**arguments)

        client = FailingClient({"alpha": candidate_state()})
        plan = purge.build_plan(client, ["alpha"])

        with self.assertRaisesRegex(RuntimeError, "transport failed"):
            purge.commit_purge(
                client,
                ["alpha"],
                expected_revision=plan.revision,
                reason="remove test namespace",
                confirm=True,
            )

        self.assertEqual(len(client.audits), 1)
        self.assertEqual(client.audits[0]["event_type"], "namespace-purge-started")


if __name__ == "__main__":
    unittest.main()

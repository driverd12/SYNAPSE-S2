import json
import math
import sqlite3
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest import mock

from memory_store import DurableMemoryStore
from mlx_backend import SpikingAttentionBackend


class DurableContextEventDeliveryTests(unittest.TestCase):
    """Adversarial contract tests for durable context-event delivery.

    The contract deliberately separates publishing, leasing, and acknowledging:

    * publishing never implies delivery;
    * leasing creates a durable receipt and never advances the acknowledgement
      cursor;
    * only a matching ``delivery_id`` and current ``lease_token`` may
      acknowledge an event;
    * cursor advancement is contiguous across events eligible for that agent;
    * every batch mutation is atomic.

    All clocks are explicit so expiry behavior is deterministic and requires no
    sleeps.
    """

    context_id = "delivery-test"
    agent_id = "codex-desktop"

    def _store(self, directory: str) -> DurableMemoryStore:
        return DurableMemoryStore(Path(directory) / "synapse-memory.sqlite3")

    def _publish(
        self,
        store: DurableMemoryStore,
        ordinal: int,
        *,
        targets: list[str] | None = None,
    ) -> dict[str, Any]:
        return store.publish_context_event(
            context_id=self.context_id,
            source_surface="phase-2-test",
            event_type="delivery-contract",
            summary=f"event-{ordinal:02d}",
            payload={"ordinal": ordinal},
            agent_targets=targets if targets is not None else [self.agent_id],
            created_at=100.0 + ordinal,
        )

    def _lease(
        self,
        store: DurableMemoryStore,
        *,
        agent_id: str | None = None,
        consumer_instance_id: str | None = None,
        limit: int = 10,
        lease_seconds: float = 30.0,
        now: float = 1_000.0,
    ) -> dict[str, Any]:
        agent = agent_id or self.agent_id
        canonical_agent = agent.casefold()
        batch = store.lease_context_events(
            context_id=self.context_id,
            agent_id=agent,
            consumer_instance_id=(
                consumer_instance_id or f"{agent}-test-instance"
            ),
            consumer_groups=["mcp-clients"],
            limit=limit,
            lease_seconds=lease_seconds,
            now=now,
        )
        self.assertIsInstance(batch, dict)
        self.assertEqual(batch["context_id"], self.context_id)
        self.assertEqual(batch["agent_id"], canonical_agent)
        self.assertIsInstance(batch["deliveries"], list)
        self.assertIsInstance(batch["events"], list)
        self.assertIsInstance(batch["has_more"], bool)
        self.assertIsInstance(batch["cursor"], dict)

        deliveries = batch["deliveries"]
        events = batch["events"]
        self.assertEqual(
            [delivery["event_id"] for delivery in deliveries],
            [event["event_id"] for event in events],
        )
        for delivery, event in zip(deliveries, events, strict=True):
            self.assertEqual(delivery["context_id"], self.context_id)
            self.assertEqual(delivery["agent_id"], canonical_agent)
            self.assertEqual(delivery["event_id"], event["event_id"])
            self.assertEqual(delivery["event"]["event_id"], event["event_id"])
            self.assertTrue(delivery["delivery_id"])
            self.assertTrue(delivery["lease_token"])
            self.assertGreaterEqual(delivery["attempt_count"], 1)
        return batch

    def _acknowledgements(
        self,
        deliveries: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        return [
            {
                "delivery_id": delivery["delivery_id"],
                "lease_token": delivery["lease_token"],
            }
            for delivery in deliveries
        ]

    def _ack(
        self,
        store: DurableMemoryStore,
        deliveries: list[dict[str, Any]],
        *,
        agent_id: str | None = None,
        now: float = 1_001.0,
    ) -> dict[str, Any]:
        canonical_agent = (agent_id or self.agent_id).casefold()
        result = store.acknowledge_context_deliveries(
            context_id=self.context_id,
            agent_id=agent_id or self.agent_id,
            acknowledgements=self._acknowledgements(deliveries),
            now=now,
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(result["context_id"], self.context_id)
        self.assertEqual(result["agent_id"], canonical_agent)
        self.assertIsInstance(result["acknowledged"], list)
        self.assertIsInstance(result["cursor"], dict)
        return result

    def _cursor(
        self,
        store: DurableMemoryStore,
        *,
        agent_id: str | None = None,
    ) -> dict[str, Any] | None:
        rows = store.list_context_cursors(
            context_id=self.context_id,
            agent_id=agent_id or self.agent_id,
            limit=10,
        )
        self.assertLessEqual(len(rows), 1)
        return rows[0] if rows else None

    def test_publish_rejects_event_evidence_that_cannot_cross_the_public_contract(self):
        invalid_cases = (
            {"source_surface": "worker\nalpha"},
            {"source_surface": "/Users/alice/private-worker"},
            {"event_type": "event\x7ftype"},
            {"summary": "   \n\t"},
            {"summary": "\x00\x01"},
        )
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            for overrides in invalid_cases:
                request = {
                    "context_id": self.context_id,
                    "source_surface": "phase-6-test",
                    "event_type": "contract-boundary",
                    "summary": "renderable evidence",
                    "payload": {},
                    "agent_targets": [self.agent_id],
                    "created_at": 100.0,
                    **overrides,
                }
                with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                    store.publish_context_event(**request)

            with closing(sqlite3.connect(store.db_path)) as conn:
                event_count = int(
                    conn.execute("SELECT COUNT(*) FROM agent_context_events").fetchone()[0]
                )
        self.assertEqual(event_count, 0)

    def test_delivery_health_detects_legacy_unrenderable_event_evidence(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    """
                    INSERT INTO agent_context_events (
                        context_id, source_surface, event_type, summary,
                        payload_json, agent_targets_json, created_at
                    ) VALUES (?, ?, ?, ?, '{}', '[]', ?)
                    """,
                    (self.context_id, "legacy\nsource", "legacy-event", "", 100.0),
                )
                conn.commit()

            health = store.context_delivery_health(context_id=self.context_id)

        self.assertGreaterEqual(health["event_ledger_integrity_error_count"], 1)
        reasons = {
            reason
            for sample in health["event_ledger_integrity_error_samples"]
            for reason in sample["reasons"]
        }
        self.assertIn("source-surface-invalid", reasons)
        self.assertIn("summary-evidence-invalid", reasons)

    def test_fifo_batches_of_twenty_five_never_skip_the_oldest_backlog(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            published = [self._publish(store, ordinal) for ordinal in range(1, 26)]
            consumed: list[dict[str, Any]] = []

            for batch_index in range(5):
                batch = self._lease(
                    store,
                    limit=5,
                    now=1_000.0 + batch_index,
                )
                self.assertEqual(len(batch["deliveries"]), 5)
                self.assertEqual(batch["has_more"], batch_index < 4)
                self.assertEqual(
                    [event["payload"]["ordinal"] for event in batch["events"]],
                    list(range(batch_index * 5 + 1, batch_index * 5 + 6)),
                )
                consumed.extend(batch["events"])
                ack = self._ack(
                    store,
                    batch["deliveries"],
                    now=1_000.25 + batch_index,
                )
                self.assertEqual(len(ack["acknowledged"]), 5)

            empty = self._lease(store, limit=5, now=1_010.0)

        self.assertEqual(
            [event["event_id"] for event in consumed],
            [event["event_id"] for event in published],
        )
        self.assertEqual(empty["deliveries"], [])
        self.assertEqual(empty["events"], [])
        self.assertFalse(empty["has_more"])
        self.assertEqual(empty["cursor"]["last_event_id"], published[-1]["event_id"])

    def test_exact_targets_are_isolated_while_mcp_clients_is_a_shared_group(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            codex_only = self._publish(store, 1, targets=["codex-desktop"])
            claude_only = self._publish(store, 2, targets=["claude-desktop"])
            shared = self._publish(store, 3, targets=[])

            codex = self._lease(store, agent_id="codex-desktop", now=2_000.0)
            claude = self._lease(store, agent_id="claude-desktop", now=2_000.0)

        self.assertEqual(
            [event["event_id"] for event in codex["events"]],
            [codex_only["event_id"], shared["event_id"]],
        )
        self.assertEqual(
            [event["event_id"] for event in claude["events"]],
            [claude_only["event_id"], shared["event_id"]],
        )
        self.assertNotIn(claude_only["event_id"], {event["event_id"] for event in codex["events"]})
        self.assertNotIn(codex_only["event_id"], {event["event_id"] for event in claude["events"]})

    def test_active_lease_is_idempotent_and_does_not_create_a_second_receipt(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)

            first = self._lease(store, limit=1, lease_seconds=30.0, now=100.0)
            repeated = self._lease(store, limit=1, lease_seconds=30.0, now=129.999)

            first_delivery = first["deliveries"][0]
            repeated_delivery = repeated["deliveries"][0]
            with closing(sqlite3.connect(store.db_path)) as conn:
                delivery_count = conn.execute(
                    "SELECT COUNT(*) FROM agent_context_deliveries"
                ).fetchone()[0]

        self.assertEqual(repeated_delivery["delivery_id"], first_delivery["delivery_id"])
        self.assertEqual(repeated_delivery["lease_token"], first_delivery["lease_token"])
        self.assertEqual(repeated_delivery["attempt_count"], 1)
        self.assertEqual(delivery_count, 1)

    def test_prematurely_expired_current_receipt_fails_health_reopen_and_fast_path(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            owner = "premature-expiry-owner"
            delivery = self._lease(
                store,
                limit=1,
                lease_seconds=100.0,
                now=100.0,
                consumer_instance_id=owner,
            )["deliveries"][0]
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute("PRAGMA ignore_check_constraints = ON")
                conn.execute(
                    """
                    UPDATE agent_context_delivery_receipts
                    SET state = 'expired', updated_at = 100.0
                    WHERE receipt_id = ?
                    """,
                    (delivery["receipt_id"],),
                )
                conn.commit()

            health = store.context_delivery_health(
                context_id=self.context_id,
                now=150.0,
            )
            # Bypass the connection-level audit only to exercise the separate
            # fast-path guard. Production calls fail even earlier at startup.
            with mock.patch.object(store, "_run_migrations", return_value=None):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "active context delivery receipt failed integrity validation",
                ):
                    self._lease(
                        store,
                        limit=1,
                        lease_seconds=100.0,
                        now=150.0,
                        consumer_instance_id=owner,
                    )
            with self.assertRaisesRegex(
                RuntimeError,
                "live-delivery-integrity-error|data failed integrity validation",
            ):
                self._store(tmp)

        self.assertEqual(health["status"], "degraded")
        self.assertGreaterEqual(health["live_delivery_integrity_error_count"], 1)
        samples_json = json.dumps(
            health["live_delivery_integrity_error_samples"],
            sort_keys=True,
        )
        self.assertIn("expired-before-lease-expiry", samples_json)
        self.assertNotIn(delivery["receipt_id"], samples_json)

    def test_lease_rejects_non_finite_duration_before_clamping(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)

            for lease_seconds in (
                float("inf"),
                float("-inf"),
                float("nan"),
            ):
                with self.subTest(lease_seconds=lease_seconds):
                    with self.assertRaisesRegex(ValueError, "lease_seconds must be finite"):
                        store.lease_context_events(
                            context_id=self.context_id,
                            agent_id=self.agent_id,
                            consumer_instance_id="non-finite-duration-test",
                            consumer_groups=["mcp-clients"],
                            limit=1,
                            lease_seconds=lease_seconds,
                            now=100.0,
                        )

            with closing(sqlite3.connect(store.db_path)) as conn:
                consumer_count = conn.execute(
                    "SELECT COUNT(*) FROM agent_context_consumers"
                ).fetchone()[0]
                delivery_count = conn.execute(
                    "SELECT COUNT(*) FROM agent_context_deliveries"
                ).fetchone()[0]

        self.assertEqual(consumer_count, 0)
        self.assertEqual(delivery_count, 0)

    def test_expired_lease_rotates_token_increments_attempt_and_rejects_stale_token(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)

            first = self._lease(store, limit=1, lease_seconds=10.0, now=100.0)
            renewed = self._lease(store, limit=1, lease_seconds=10.0, now=110.001)
            old_delivery = first["deliveries"][0]
            new_delivery = renewed["deliveries"][0]

            with self.assertRaisesRegex(
                ValueError,
                "lease|token|stale|expired|receipt|acknowledge",
            ) as stale_error:
                store.acknowledge_context_deliveries(
                    context_id=self.context_id,
                    agent_id=self.agent_id,
                    acknowledgements=self._acknowledgements([old_delivery]),
                    now=111.0,
                )
            self.assertNotIn(old_delivery["receipt_id"], str(stale_error.exception))
            with closing(sqlite3.connect(store.db_path)) as conn:
                status_after_stale_ack = conn.execute(
                    "SELECT state FROM agent_context_deliveries WHERE delivery_id = ?",
                    (new_delivery["delivery_id"],),
                ).fetchone()[0]
            accepted = self._ack(store, [new_delivery], now=111.0)

        self.assertEqual(new_delivery["delivery_id"], old_delivery["delivery_id"])
        self.assertNotEqual(new_delivery["lease_token"], old_delivery["lease_token"])
        self.assertEqual(new_delivery["attempt_count"], 2)
        self.assertEqual(status_after_stale_ack, "leased")
        self.assertEqual(len(accepted["acknowledged"]), 1)

    def test_ack_after_expiry_before_re_lease_is_rejected_without_cursor_advance(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1)
            expired_delivery = self._lease(
                store,
                limit=1,
                lease_seconds=10.0,
                now=100.0,
            )["deliveries"][0]

            with self.assertRaisesRegex(
                ValueError,
                "expired|lease|receipt|acknowledge",
            ):
                store.acknowledge_context_deliveries(
                    context_id=self.context_id,
                    agent_id=self.agent_id,
                    acknowledgements=self._acknowledgements([expired_delivery]),
                    now=110.001,
                )
            cursor_after_rejection = self._cursor(store)
            renewed_delivery = self._lease(
                store,
                limit=1,
                lease_seconds=10.0,
                now=111.0,
            )["deliveries"][0]
            accepted = self._ack(store, [renewed_delivery], now=112.0)

        self.assertEqual(cursor_after_rejection["last_event_id"], 0)
        self.assertEqual(cursor_after_rejection["pending_event_count"], 1)
        self.assertEqual(
            renewed_delivery["delivery_id"],
            expired_delivery["delivery_id"],
        )
        self.assertNotEqual(
            renewed_delivery["receipt_id"],
            expired_delivery["receipt_id"],
        )
        self.assertEqual(renewed_delivery["attempt_count"], 2)
        self.assertEqual(accepted["cursor"]["last_event_id"], event["event_id"])

    def test_acknowledgement_is_idempotent_and_keeps_one_durable_receipt(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1)
            delivery = self._lease(store, limit=1, now=300.0)["deliveries"][0]

            first = self._ack(store, [delivery], now=301.0)
            repeated = self._ack(store, [delivery], now=302.0)
            with closing(sqlite3.connect(store.db_path)) as conn:
                receipt_count = conn.execute(
                    "SELECT COUNT(*) FROM agent_context_delivery_receipts WHERE delivery_id = ?",
                    (delivery["delivery_id"],),
                ).fetchone()[0]
                delivery_row = conn.execute(
                    "SELECT state, acknowledged_at FROM agent_context_deliveries WHERE delivery_id = ?",
                    (delivery["delivery_id"],),
                ).fetchone()

        self.assertEqual(len(first["acknowledged"]), 1)
        self.assertEqual(len(repeated["acknowledged"]), 1)
        self.assertEqual(
            repeated["acknowledged"][0]["receipt_id"],
            first["acknowledged"][0]["receipt_id"],
        )
        self.assertEqual(receipt_count, 1)
        self.assertEqual(delivery_row[0], "acknowledged")
        self.assertIsNotNone(delivery_row[1])
        self.assertEqual(repeated["cursor"]["last_event_id"], event["event_id"])

    def test_legacy_high_water_ack_cannot_jump_without_delivery_receipts(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            events = [self._publish(store, ordinal) for ordinal in range(1, 4)]
            initial_delivery = self._lease(
                store,
                limit=1,
                now=399.0,
            )["deliveries"][0]

            with self.assertRaisesRegex(ValueError, "receipt"):
                store.acknowledge_context_deliveries(
                    context_id=self.context_id,
                    agent_id=self.agent_id,
                    acknowledgements=[
                        {"delivery_id": initial_delivery["delivery_id"]}
                    ],
                    now=399.5,
                )

            rejected = False
            try:
                legacy_result = store.ack_context_events(
                    context_id=self.context_id,
                    agent_id=self.agent_id,
                    last_event_id=events[-1]["event_id"],
                )
            except (RuntimeError, ValueError):
                rejected = True
            else:
                rejected = bool(
                    legacy_result.get("rejected")
                    or legacy_result.get("deprecated")
                    or legacy_result.get("acknowledged") is False
                )

            cursor = self._cursor(store)
            leased = self._lease(store, limit=10, now=400.0)

        self.assertTrue(rejected, "legacy cursor-only acknowledgement must be rejected")
        if cursor is not None:
            self.assertEqual(cursor["last_event_id"], 0)
        self.assertEqual(
            [event["event_id"] for event in leased["events"]],
            [event["event_id"] for event in events],
        )

    def test_legacy_watermark_ack_rejects_zero_and_completed_cursor(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1)

            with self.assertRaisesRegex(ValueError, "exact receipt_id"):
                store.ack_context_events(
                    context_id=self.context_id,
                    agent_id=self.agent_id,
                    last_event_id=0,
                )

            delivery = self._lease(store, limit=1, now=405.0)["deliveries"][0]
            store.acknowledge_context_deliveries(
                context_id=self.context_id,
                agent_id=self.agent_id,
                acknowledgements=[{"receipt_id": delivery["receipt_id"]}],
                now=405.5,
            )
            self.assertEqual(self._cursor(store)["last_event_id"], event["event_id"])

            with self.assertRaisesRegex(ValueError, "exact receipt_id"):
                store.ack_context_events(
                    context_id=self.context_id,
                    agent_id=self.agent_id,
                    last_event_id=event["event_id"],
                )

    def test_pruning_acknowledged_event_repairs_derived_cursor_atomically(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1)
            delivery = self._lease(store, limit=1, now=406.0)["deliveries"][0]
            self._ack(store, [delivery], now=406.5)
            self.assertEqual(self._cursor(store)["last_event_id"], event["event_id"])

            deleted = store.delete_context_event(
                context_id=self.context_id,
                event_id=event["event_id"],
            )
            cursor = self._cursor(store)
            health = store.context_delivery_health(
                context_id=self.context_id,
                now=407.0,
            )

        self.assertTrue(deleted["deleted"])
        self.assertEqual(cursor["last_event_id"], 0)
        self.assertEqual(health["receipt_derived_cursor_mismatch_count"], 0)
        self.assertEqual(health["ack_tombstone_count"], 1)
        self.assertEqual(health["status"], "ready")

    def test_out_of_order_acknowledgements_do_not_move_cursor_past_a_hole(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            events = [self._publish(store, ordinal) for ordinal in range(1, 4)]
            leased = self._lease(store, limit=3, now=500.0)["deliveries"]

            later_ack = self._ack(store, leased[1:], now=501.0)
            cursor_with_hole = self._cursor(store)
            first_ack = self._ack(store, leased[:1], now=502.0)
            final_cursor = self._cursor(store)

        self.assertEqual(len(later_ack["acknowledged"]), 2)
        self.assertEqual(cursor_with_hole["last_event_id"], 0)
        self.assertEqual(first_ack["cursor"]["last_event_id"], events[-1]["event_id"])
        self.assertEqual(final_cursor["last_event_id"], events[-1]["event_id"])

    def test_concurrent_same_agent_lease_returns_one_delivery_and_token(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            barrier = threading.Barrier(3)

            def lease_once(instance_id: str) -> dict[str, Any]:
                barrier.wait(timeout=5.0)
                return store.lease_context_events(
                    context_id=self.context_id,
                    agent_id=self.agent_id,
                    consumer_instance_id=instance_id,
                    consumer_groups=["mcp-clients"],
                    limit=1,
                    lease_seconds=30.0,
                    now=600.0,
                )

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(lease_once, "codex-concurrent-a"),
                    executor.submit(lease_once, "codex-concurrent-b"),
                ]
                barrier.wait(timeout=5.0)
                batches = [future.result(timeout=10.0) for future in futures]

            winning_batches = [batch for batch in batches if batch["deliveries"]]
            blocked_batches = [batch for batch in batches if not batch["deliveries"]]
            delivery = winning_batches[0]["deliveries"][0]
            with closing(sqlite3.connect(store.db_path)) as conn:
                row_count = conn.execute(
                    "SELECT COUNT(*) FROM agent_context_deliveries"
                ).fetchone()[0]
                leased_receipt_count = conn.execute(
                    "SELECT COUNT(*) FROM agent_context_delivery_receipts WHERE state = 'leased'"
                ).fetchone()[0]

        self.assertEqual(len(winning_batches), 1)
        self.assertEqual(len(blocked_batches), 1)
        self.assertEqual(
            blocked_batches[0]["blocking_delivery"]["delivery_id"],
            delivery["delivery_id"],
        )
        self.assertNotIn("lease_token", blocked_batches[0]["blocking_delivery"])
        self.assertEqual(delivery["attempt_count"], 1)
        self.assertEqual(row_count, 1)
        self.assertEqual(leased_receipt_count, 1)

    def test_blocked_consumer_instance_receives_no_receipt_or_token_material(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            owner = self._lease(
                store,
                consumer_instance_id="lease-owner",
                limit=1,
                lease_seconds=30.0,
                now=650.0,
            )
            blocked = self._lease(
                store,
                consumer_instance_id="blocked-instance",
                limit=1,
                lease_seconds=30.0,
                now=651.0,
            )

        owner_delivery = owner["deliveries"][0]
        serialized_blocked_payload = json.dumps(blocked, sort_keys=True)
        self.assertEqual(blocked["deliveries"], [])
        self.assertEqual(blocked["events"], [])
        self.assertTrue(blocked["has_more"])
        self.assertEqual(
            blocked["blocking_delivery"]["delivery_id"],
            owner_delivery["delivery_id"],
        )
        self.assertNotIn("receipt_id", blocked["blocking_delivery"])
        self.assertNotIn("lease_token", blocked["blocking_delivery"])
        self.assertNotIn(owner_delivery["receipt_id"], serialized_blocked_payload)
        self.assertNotIn(owner_delivery["lease_token"], serialized_blocked_payload)

    def test_leased_backend_hydration_rejects_explicit_since_event_id(self):
        with TemporaryDirectory() as tmp:
            backend = SpikingAttentionBackend(
                dimension=8,
                num_neurons=8,
                default_top_k=2,
                compile_graph=False,
                state_path=Path(tmp) / "state.json",
            )

            with self.assertRaisesRegex(
                ValueError,
                "since_event_id.*observation-only|leased delivery",
            ):
                backend.hydrate_agent_context(
                    context_id=self.context_id,
                    agent_id=self.agent_id,
                    since_event_id=0,
                    claim_events=True,
                    consumer_instance_id="hydration-test",
                )

    def test_malformed_legacy_agent_targets_backfill_fails_closed(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1, targets=["mcp-clients"])
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    "DELETE FROM agent_context_event_targets WHERE event_id = ?",
                    (event["event_id"],),
                )
                conn.execute(
                    "UPDATE agent_context_events SET agent_targets_json = ? WHERE event_id = ?",
                    ('{"mcp-clients": true}', event["event_id"]),
                )
                conn.execute(
                    "DELETE FROM store_migrations WHERE key = ?",
                    ("context_event_targets_v2",),
                )
                conn.commit()

            restored = self._store(tmp)
            leased = self._lease(restored, limit=10, now=850.0)
            health = restored.context_delivery_health(context_id=self.context_id)
            with closing(sqlite3.connect(restored.db_path)) as conn:
                route_count = conn.execute(
                    "SELECT COUNT(*) FROM agent_context_event_targets WHERE event_id = ?",
                    (event["event_id"],),
                ).fetchone()[0]
                migration_count = conn.execute(
                    "SELECT COUNT(*) FROM store_migrations WHERE key = ?",
                    ("context_event_targets_v2",),
                ).fetchone()[0]

        self.assertEqual(leased["deliveries"], [])
        self.assertEqual(leased["events"], [])
        self.assertFalse(leased["has_more"])
        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["unrouted_event_count"], 1)
        self.assertEqual(health["target_integrity_error_count"], 0)
        self.assertEqual(route_count, 0)
        self.assertEqual(migration_count, 1)

    def test_empty_legacy_target_envelope_remains_intentionally_unrouted(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1, targets=["mcp-clients"])
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    "DELETE FROM agent_context_event_targets WHERE event_id = ?",
                    (event["event_id"],),
                )
                conn.execute(
                    "UPDATE agent_context_events SET agent_targets_json = '[]' WHERE event_id = ?",
                    (event["event_id"],),
                )
                conn.commit()

            reopened = self._store(tmp)
            health = reopened.context_delivery_health(context_id=self.context_id)
            leased = self._lease(reopened, limit=1, now=200.0)

        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["unrouted_event_count"], 1)
        self.assertEqual(health["target_integrity_error_count"], 0)
        self.assertEqual(leased["deliveries"], [])

    def test_unacknowledged_lease_and_ack_receipt_survive_store_restart(self):
        with TemporaryDirectory() as tmp:
            first_store = self._store(tmp)
            event = self._publish(first_store, 1)
            first_delivery = self._lease(first_store, limit=1, now=700.0)["deliveries"][0]

            restarted = self._store(tmp)
            repeated_delivery = self._lease(restarted, limit=1, now=701.0)["deliveries"][0]
            ack = self._ack(restarted, [repeated_delivery], now=702.0)

            verified = self._store(tmp)
            empty = self._lease(verified, limit=1, now=703.0)
            cursor = self._cursor(verified)
            with closing(sqlite3.connect(verified.db_path)) as conn:
                persisted_receipts = conn.execute(
                    "SELECT COUNT(*) FROM agent_context_delivery_receipts WHERE state = 'acknowledged'"
                ).fetchone()[0]

        self.assertEqual(repeated_delivery["delivery_id"], first_delivery["delivery_id"])
        self.assertEqual(repeated_delivery["lease_token"], first_delivery["lease_token"])
        self.assertEqual(len(ack["acknowledged"]), 1)
        self.assertEqual(empty["deliveries"], [])
        self.assertEqual(cursor["last_event_id"], event["event_id"])
        self.assertEqual(persisted_receipts, 1)

    def test_different_agents_consume_shared_event_independently(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1, targets=[])

            codex = self._lease(store, agent_id="codex-desktop", limit=1, now=800.0)
            claude = self._lease(store, agent_id="claude-desktop", limit=1, now=800.0)
            self._ack(store, codex["deliveries"], agent_id="codex-desktop", now=801.0)
            claude_still_pending = self._lease(
                store,
                agent_id="claude-desktop",
                limit=1,
                now=801.0,
            )
            codex_empty = self._lease(
                store,
                agent_id="codex-desktop",
                limit=1,
                now=801.0,
            )
            codex_cursor = self._cursor(store, agent_id="codex-desktop")
            claude_cursor = self._cursor(store, agent_id="claude-desktop")

        self.assertEqual(codex["events"][0]["event_id"], event["event_id"])
        self.assertEqual(claude["events"][0]["event_id"], event["event_id"])
        self.assertNotEqual(
            codex["deliveries"][0]["delivery_id"],
            claude["deliveries"][0]["delivery_id"],
        )
        self.assertEqual(
            claude_still_pending["deliveries"][0]["delivery_id"],
            claude["deliveries"][0]["delivery_id"],
        )
        self.assertEqual(codex_empty["deliveries"], [])
        self.assertEqual(codex_cursor["last_event_id"], event["event_id"])
        self.assertEqual(claude_cursor["last_event_id"], 0)

    def test_deleted_and_ineligible_event_ids_do_not_form_cursor_holes(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            deleted = self._publish(store, 1, targets=[self.agent_id])
            self._publish(store, 2, targets=["another-agent"])
            eligible = self._publish(store, 3, targets=[self.agent_id])
            store.delete_context_event(
                context_id=self.context_id,
                event_id=deleted["event_id"],
            )

            leased = self._lease(store, limit=10, now=900.0)
            ack = self._ack(store, leased["deliveries"], now=901.0)
            empty = self._lease(store, limit=10, now=902.0)

        self.assertEqual([event["event_id"] for event in leased["events"]], [eligible["event_id"]])
        self.assertEqual(ack["cursor"]["last_event_id"], eligible["event_id"])
        self.assertEqual(ack["cursor"]["pending_event_count"], 0)
        self.assertEqual(empty["deliveries"], [])

    def test_active_lease_blocks_event_deletion_until_release_or_expiry(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            released_event = self._publish(store, 1)
            active_delivery = self._lease(
                store,
                consumer_instance_id="deletion-owner",
                limit=1,
                lease_seconds=30.0,
                now=100.0,
            )["deliveries"][0]

            with mock.patch("memory_store.time.time", return_value=101.0):
                with self.assertRaisesRegex(ValueError, "active.*lease|release|expiry"):
                    store.delete_context_event(
                        context_id=self.context_id,
                        event_id=released_event["event_id"],
                    )
            release = store.release_context_deliveries(
                context_id=self.context_id,
                agent_id=self.agent_id,
                consumer_instance_id="deletion-owner",
                receipt_ids=[active_delivery["receipt_id"]],
                now=102.0,
            )
            with mock.patch("memory_store.time.time", return_value=102.001):
                deleted_after_release = store.delete_context_event(
                    context_id=self.context_id,
                    event_id=released_event["event_id"],
                )

            expired_event = self._publish(store, 2)
            self._lease(
                store,
                consumer_instance_id="deletion-owner",
                limit=1,
                lease_seconds=10.0,
                now=200.0,
            )
            with mock.patch("memory_store.time.time", return_value=201.0):
                with self.assertRaisesRegex(ValueError, "active.*lease|release|expiry"):
                    store.delete_context_event(
                        context_id=self.context_id,
                        event_id=expired_event["event_id"],
                    )
            with mock.patch("memory_store.time.time", return_value=210.001):
                deleted_after_expiry = store.delete_context_event(
                    context_id=self.context_id,
                    event_id=expired_event["event_id"],
                )

        self.assertEqual(release["released_count"], 1)
        self.assertTrue(deleted_after_release["deleted"])
        self.assertTrue(deleted_after_expiry["deleted"])

    def test_batch_acknowledgement_rolls_back_every_item_when_one_is_invalid(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            self._publish(store, 2)
            deliveries = self._lease(store, limit=2, now=1_000.0)["deliveries"]
            invalid_batch = self._acknowledgements(deliveries)
            invalid_batch[1] = {
                "delivery_id": "missing-delivery",
                "lease_token": "forged-token",
            }

            with self.assertRaisesRegex(
                ValueError,
                "delivery|token|acknowledg|receipt",
            ) as forged_error:
                store.acknowledge_context_deliveries(
                    context_id=self.context_id,
                    agent_id=self.agent_id,
                    acknowledgements=invalid_batch,
                    now=1_001.0,
                )
            self.assertNotIn("forged-token", str(forged_error.exception))
            self.assertNotIn(
                deliveries[0]["receipt_id"],
                str(forged_error.exception),
            )

            with closing(sqlite3.connect(store.db_path)) as conn:
                statuses = conn.execute(
                    "SELECT state FROM agent_context_deliveries ORDER BY event_id"
                ).fetchall()
                receipt_count = conn.execute(
                    "SELECT COUNT(*) FROM agent_context_delivery_receipts WHERE state = 'acknowledged'"
                ).fetchone()[0]
            cursor_after_failure = self._cursor(store)
            accepted = self._ack(store, deliveries, now=1_002.0)

        self.assertEqual([row[0] for row in statuses], ["leased", "leased"])
        self.assertEqual(receipt_count, 0)
        self.assertEqual(cursor_after_failure["last_event_id"], 0)
        self.assertEqual(len(accepted["acknowledged"]), 2)

    def test_prototype_delivery_schema_is_atomically_upgraded_without_token_reuse(self):
        with TemporaryDirectory() as tmp:
            prototype_agent = "Codex-Desktop"
            store = self._store(tmp)
            first_event = self._publish(store, 1)
            second_event = self._publish(store, 2)
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute("PRAGMA foreign_keys = OFF")
                conn.execute("DROP TABLE agent_context_delivery_receipts")
                conn.execute("DROP TABLE agent_context_deliveries")
                conn.executescript(
                    """
                    CREATE TABLE agent_context_deliveries (
                        delivery_id TEXT PRIMARY KEY,
                        context_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        event_id INTEGER NOT NULL,
                        status TEXT NOT NULL DEFAULT 'leased',
                        lease_token TEXT NOT NULL,
                        attempt_count INTEGER NOT NULL DEFAULT 1,
                        first_delivered_at REAL NOT NULL,
                        last_delivered_at REAL NOT NULL,
                        lease_expires_at REAL NOT NULL,
                        acknowledged_at REAL,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        UNIQUE(context_id, agent_id, event_id),
                        CHECK(status IN ('leased', 'acknowledged')),
                        CHECK(attempt_count >= 1),
                        FOREIGN KEY(event_id)
                            REFERENCES agent_context_events(event_id)
                            ON DELETE CASCADE
                    );
                    CREATE INDEX ix_agent_context_deliveries_agent_status_event
                    ON agent_context_deliveries(context_id, agent_id, status, event_id);
                    CREATE INDEX ix_agent_context_deliveries_lease_expiry
                    ON agent_context_deliveries(status, lease_expires_at);
                    """
                )
                conn.execute(
                    """
                    INSERT INTO agent_context_consumers (
                        agent_id, consumer_kind, enabled, created_at, updated_at
                    ) VALUES (?, 'prototype', 1, 1.0, 1.0)
                    ON CONFLICT(agent_id) DO NOTHING
                    """,
                    (prototype_agent,),
                )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO agent_context_delivery_cursors (
                        context_id, agent_id, last_contiguous_event_id, updated_at
                    ) VALUES (?, ?, 999, 1.0)
                    """,
                    (self.context_id, prototype_agent),
                )
                conn.executemany(
                    """
                    INSERT INTO agent_context_deliveries (
                        delivery_id,
                        context_id,
                        agent_id,
                        event_id,
                        status,
                        lease_token,
                        attempt_count,
                        first_delivered_at,
                        last_delivered_at,
                        lease_expires_at,
                        acknowledged_at,
                        created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            "prototype-ack",
                            self.context_id,
                            prototype_agent,
                            first_event["event_id"],
                            "acknowledged",
                            "old-reusable-ack-token",
                            1,
                            100.0,
                            101.0,
                            130.0,
                            120.0,
                            100.0,
                            120.0,
                        ),
                        (
                            "prototype-lease",
                            self.context_id,
                            prototype_agent,
                            second_event["event_id"],
                            "leased",
                            "old-reusable-lease-token",
                            1,
                            200.0,
                            201.0,
                            999.0,
                            None,
                            200.0,
                            201.0,
                        ),
                    ),
                )
                conn.execute(
                    "DELETE FROM store_migrations WHERE key = 'context_deliveries_v2'"
                )
                conn.commit()

            upgraded = self._store(tmp)
            with closing(sqlite3.connect(upgraded.db_path)) as conn:
                delivery_columns = [
                    row[1]
                    for row in conn.execute(
                        "PRAGMA table_info(agent_context_deliveries)"
                    ).fetchall()
                ]
                migrated_rows = conn.execute(
                    """
                    SELECT delivery.delivery_id,
                           delivery.state,
                           delivery.attempt_count,
                           receipt.state,
                           receipt.receipt_id
                    FROM agent_context_deliveries AS delivery
                    JOIN agent_context_delivery_receipts AS receipt
                      ON receipt.receipt_id = delivery.current_receipt_id
                    ORDER BY delivery.event_id
                    """
                ).fetchall()
                cursor_count = conn.execute(
                    "SELECT COUNT(*) FROM agent_context_delivery_cursors"
                ).fetchone()[0]
                migrated_agents = conn.execute(
                    "SELECT DISTINCT agent_id FROM agent_context_deliveries"
                ).fetchall()
                serialized_store = "\n".join(conn.iterdump())

            retried = self._lease(
                upgraded,
                limit=2,
                now=2_000.0,
                consumer_instance_id="post-migration",
            )
            health = upgraded.context_delivery_health(now=2_000.0)

        self.assertIn("current_receipt_id", delivery_columns)
        self.assertNotIn("lease_token", delivery_columns)
        self.assertEqual(
            [(row[1], row[2], row[3]) for row in migrated_rows],
            [("acknowledged", 1, "acknowledged"), ("leased", 1, "expired")],
        )
        self.assertTrue(all(str(row[4]).startswith("ctxrcpt_") for row in migrated_rows))
        self.assertEqual(cursor_count, 0)
        self.assertEqual(migrated_agents, [("codex-desktop",)])
        self.assertNotIn("old-reusable-ack-token", serialized_store)
        self.assertNotIn("old-reusable-lease-token", serialized_store)
        self.assertEqual(
            [delivery["event_id"] for delivery in retried["deliveries"]],
            [second_event["event_id"]],
        )
        self.assertEqual(retried["deliveries"][0]["attempt_count"], 2)
        self.assertEqual(health["status"], "ready")

    def test_target_reconciliation_catches_events_from_a_rolling_old_writer(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1, targets=["mcp-clients"])
            # Current publishers advance their own target high-water. Simulate
            # one rolling old writer that commits only the legacy envelope.
            with closing(sqlite3.connect(store.db_path)) as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO agent_context_events (
                        context_id,
                        source_surface,
                        event_type,
                        summary,
                        payload_json,
                        agent_targets_json,
                        created_at
                    ) VALUES (?, 'old-process', 'rolling-restart', 'late event', '{}', ?, 500.0)
                    """,
                    (self.context_id, json.dumps(["mcp-clients"])),
                )
                late_event_id = int(cursor.lastrowid)
                conn.commit()

            reconciled = self._store(tmp)
            with closing(sqlite3.connect(reconciled.db_path)) as conn:
                target_rows = conn.execute(
                    """
                    SELECT target_kind, target_id
                    FROM agent_context_event_targets
                    WHERE event_id = ?
                    """,
                    (late_event_id,),
                ).fetchall()
                highwater = json.loads(
                    conn.execute(
                        """
                        SELECT value_json
                        FROM store_metadata
                        WHERE key = 'context_event_targets_reconciled_through'
                        """
                    ).fetchone()[0]
                )
            leased = self._lease(reconciled, limit=10, now=1_000.0)

        self.assertEqual(target_rows, [("group", "mcp-clients")])
        self.assertGreaterEqual(highwater, late_event_id)
        self.assertIn(
            late_event_id,
            [delivery["event_id"] for delivery in leased["deliveries"]],
        )

    def test_atomic_publish_refuses_mismatched_rolling_writer_targets(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            first = self._publish(store, 1, targets=["agent-a"])
            with closing(store._connect()) as publish_connection:
                # The connection has completed its ordinary integrity preflight.
                # Reproduce a rolling writer committing a mismatched envelope
                # and route before this connection obtains BEGIN IMMEDIATE.
                with closing(sqlite3.connect(store.db_path)) as old_writer:
                    cursor = old_writer.execute(
                        """
                        INSERT INTO agent_context_events (
                            context_id, source_surface, event_type, summary,
                            payload_json, agent_targets_json, created_at
                        ) VALUES (?, 'old-process', 'rolling-mismatch',
                                  'mismatched old route', '{}', ?, 500.0)
                        """,
                        (self.context_id, json.dumps(["agent-a"])),
                    )
                    raced_event_id = int(cursor.lastrowid)
                    old_writer.execute(
                        """
                        INSERT INTO agent_context_event_targets (
                            event_id, target_kind, target_id, created_at
                        ) VALUES (?, 'agent', 'agent-b', 500.0)
                        """,
                        (raced_event_id,),
                    )
                    old_writer.commit()
                with self.assertRaisesRegex(
                    RuntimeError,
                    "target rows changed before atomic publication",
                ):
                    with store._transaction(publish_connection, immediate=True):
                        store._publish_context_event_conn(
                            publish_connection,
                            context_id=self.context_id,
                            source_surface="current-process",
                            event_type="must-rollback",
                            summary="current event must roll back",
                            payload_json="{}",
                            targets=["mcp-clients"],
                            created_at=501.0,
                        )
            with closing(sqlite3.connect(store.db_path)) as conn:
                events = conn.execute(
                    """
                    SELECT event_id, event_type
                    FROM agent_context_events
                    ORDER BY event_id
                    """
                ).fetchall()
                target_rows = conn.execute(
                    """
                    SELECT event_id, target_kind, target_id
                    FROM agent_context_event_targets
                    ORDER BY event_id, target_kind, target_id
                    """
                ).fetchall()
                highwater = json.loads(
                    conn.execute(
                        """
                        SELECT value_json FROM store_metadata
                        WHERE key = 'context_event_targets_reconciled_through'
                        """
                    ).fetchone()[0]
                )

        self.assertEqual(
            events,
            [
                (first["event_id"], "delivery-contract"),
                (raced_event_id, "rolling-mismatch"),
            ],
        )
        self.assertEqual(
            target_rows,
            [
                (first["event_id"], "agent", "agent-a"),
                (raced_event_id, "agent", "agent-b"),
            ],
        )
        self.assertEqual(highwater, first["event_id"])

    def test_publish_advances_target_reconciliation_highwater_atomically(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1, targets=["mcp-clients"])
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                highwater = json.loads(
                    conn.execute(
                        """
                        SELECT value_json
                        FROM store_metadata
                        WHERE key = 'context_event_targets_reconciled_through'
                        """
                    ).fetchone()[0]
                )
                target_rows = conn.execute(
                    """
                    SELECT target_kind, target_id
                    FROM agent_context_event_targets
                    WHERE event_id = ?
                    ORDER BY target_kind, target_id
                    """,
                    (event["event_id"],),
                ).fetchall()
                reconciliation_needed = (
                    store._context_event_target_reconciliation_needed(conn)
                )
            reopened = self._store(tmp)
            stats = reopened.stats(context_id=self.context_id)
            health = reopened.context_delivery_health(context_id=self.context_id)

        self.assertEqual(highwater, event["event_id"])
        self.assertEqual(
            [tuple(row) for row in target_rows],
            [("group", "mcp-clients")],
        )
        self.assertFalse(reconciliation_needed)
        self.assertEqual(stats["context_bus_latest_event_id"], event["event_id"])
        self.assertEqual(health["status"], "ready")

    def test_publish_never_normalizes_noncanonical_target_highwater(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            first = self._publish(store, 1, targets=["mcp-clients"])
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    """
                    UPDATE store_metadata
                    SET value_json = '1.0'
                    WHERE key = 'context_event_targets_reconciled_through'
                    """
                )
                conn.commit()
            with (
                mock.patch("memory_store.LOGGER.exception"),
                self.assertRaisesRegex(
                    RuntimeError,
                    "target high-water is noncanonical",
                ),
            ):
                self._publish(store, 2, targets=["mcp-clients"])
            with closing(sqlite3.connect(store.db_path)) as conn:
                highwater_raw = conn.execute(
                    """
                    SELECT value_json FROM store_metadata
                    WHERE key = 'context_event_targets_reconciled_through'
                    """
                ).fetchone()[0]
                event_ids = [
                    int(row[0])
                    for row in conn.execute(
                        "SELECT event_id FROM agent_context_events ORDER BY event_id"
                    )
                ]

        self.assertEqual(highwater_raw, "1.0")
        self.assertEqual(event_ids, [first["event_id"]])

    def test_publish_advances_existing_cursors_over_newly_ineligible_event(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            first = self._publish(store, 1, targets=[])
            for agent_id in ("codex-desktop", "claude-desktop"):
                leased = self._lease(
                    store,
                    agent_id=agent_id,
                    limit=1,
                    now=800.0,
                )
                self._ack(
                    store,
                    leased["deliveries"],
                    agent_id=agent_id,
                    now=801.0,
                )
            second = self._publish(store, 2, targets=["another-agent"])
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                cursors = conn.execute(
                    """
                    SELECT agent_id, last_contiguous_event_id
                    FROM agent_context_delivery_cursors
                    WHERE context_id = ?
                    ORDER BY agent_id
                    """,
                    (self.context_id,),
                ).fetchall()
                highwater = json.loads(
                    conn.execute(
                        """
                        SELECT value_json
                        FROM store_metadata
                        WHERE key = 'context_event_targets_reconciled_through'
                        """
                    ).fetchone()[0]
                )
                delivery_errors = store._context_delivery_data_errors(conn)
            reopened = self._store(tmp)
            stats = reopened.stats(context_id=self.context_id)
            health = reopened.context_delivery_health(context_id=self.context_id)

        self.assertLess(first["event_id"], second["event_id"])
        self.assertEqual(
            [
                (str(row["agent_id"]), int(row["last_contiguous_event_id"]))
                for row in cursors
            ],
            [
                ("claude-desktop", second["event_id"]),
                ("codex-desktop", second["event_id"]),
            ],
        )
        self.assertEqual(highwater, second["event_id"])
        self.assertEqual(delivery_errors, [])
        self.assertEqual(stats["context_bus_latest_event_id"], second["event_id"])
        self.assertEqual(health["receipt_derived_cursor_mismatch_count"], 0)
        self.assertEqual(health["status"], "ready")

    def test_invalid_prototype_delivery_rows_roll_back_the_schema_rebuild(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1)
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute("PRAGMA foreign_keys = OFF")
                conn.execute("DROP TABLE agent_context_delivery_receipts")
                conn.execute("DROP TABLE agent_context_deliveries")
                conn.executescript(
                    """
                    CREATE TABLE agent_context_deliveries (
                        delivery_id TEXT PRIMARY KEY,
                        context_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        event_id INTEGER NOT NULL,
                        status TEXT NOT NULL DEFAULT 'leased',
                        lease_token TEXT NOT NULL,
                        attempt_count INTEGER NOT NULL DEFAULT 1,
                        first_delivered_at REAL NOT NULL,
                        last_delivered_at REAL NOT NULL,
                        lease_expires_at REAL NOT NULL,
                        acknowledged_at REAL,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        UNIQUE(context_id, agent_id, event_id),
                        CHECK(status IN ('leased', 'acknowledged')),
                        CHECK(attempt_count >= 1),
                        FOREIGN KEY(event_id)
                            REFERENCES agent_context_events(event_id)
                            ON DELETE CASCADE
                    );
                    """
                )
                conn.execute(
                    """
                    INSERT INTO agent_context_deliveries (
                        delivery_id, context_id, agent_id, event_id, status,
                        lease_token, attempt_count, first_delivered_at,
                        last_delivered_at, lease_expires_at, acknowledged_at,
                        created_at, updated_at
                    ) VALUES ('orphan', 'wrong-context', ?, ?, 'leased',
                              'old-token', 1, 1.0, 1.0, 2.0, NULL, 1.0, 1.0)
                    """,
                    (self.agent_id, event["event_id"]),
                )
                conn.execute(
                    "DELETE FROM store_migrations WHERE key = 'context_deliveries_v2'"
                )
                conn.commit()

            with self.assertRaisesRegex(RuntimeError, "integrity validation"):
                self._store(tmp)
            with closing(sqlite3.connect(store.db_path)) as conn:
                columns_after_failure = [
                    row[1]
                    for row in conn.execute(
                        "PRAGMA table_info(agent_context_deliveries)"
                    ).fetchall()
                ]
                legacy_table_count = conn.execute(
                    """
                    SELECT COUNT(*) FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'agent_context_deliveries_v1_legacy'
                    """
                ).fetchone()[0]
                migration_count = conn.execute(
                    """
                    SELECT COUNT(*) FROM store_migrations
                    WHERE key = 'context_deliveries_v2'
                    """
                ).fetchone()[0]

        self.assertIn("lease_token", columns_after_failure)
        self.assertNotIn("current_receipt_id", columns_after_failure)
        self.assertEqual(legacy_table_count, 0)
        self.assertEqual(migration_count, 0)

    def test_delivery_agent_identity_is_casefolded_before_deduplication(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1, targets=["codex-desktop"])
            first = self._lease(
                store,
                agent_id="Codex-Desktop",
                consumer_instance_id="owner-a",
                limit=1,
                now=100.0,
            )
            blocked = self._lease(
                store,
                agent_id="codex-desktop",
                consumer_instance_id="owner-b",
                limit=1,
                now=101.0,
            )
            with closing(sqlite3.connect(store.db_path)) as conn:
                deliveries = conn.execute(
                    "SELECT agent_id, event_id FROM agent_context_deliveries"
                ).fetchall()
                consumers = conn.execute(
                    "SELECT agent_id FROM agent_context_consumers"
                ).fetchall()

        self.assertEqual(first["agent_id"], "codex-desktop")
        self.assertEqual(first["deliveries"][0]["event_id"], event["event_id"])
        self.assertEqual(blocked["deliveries"], [])
        self.assertIsNotNone(blocked["blocking_delivery"])
        self.assertEqual(deliveries, [("codex-desktop", event["event_id"])])
        self.assertEqual(consumers, [("codex-desktop",)])

    def test_descending_observation_uses_an_explicit_before_cursor(self):
        with TemporaryDirectory() as tmp:
            backend = SpikingAttentionBackend(
                dimension=8,
                num_neurons=8,
                default_top_k=2,
                compile_graph=False,
                state_path=Path(tmp) / "state.json",
                memory_path=Path(tmp) / "memory.sqlite3",
            )
            for ordinal in range(1, 6):
                backend.publish_context_event(
                    context_id=self.context_id,
                    source_surface="pagination-test",
                    event_type="observation",
                    summary=f"event-{ordinal}",
                    agent_targets=["broadcast"],
                )
            first = backend.list_context_events(
                context_id=self.context_id,
                order="desc",
                limit=2,
            )
            second = backend.list_context_events(
                context_id=self.context_id,
                order="desc",
                before_event_id=first["next_before_event_id"],
                limit=2,
            )

        self.assertEqual([row["event_id"] for row in first["events"]], [5, 4])
        self.assertTrue(first["has_more"])
        self.assertEqual(first["next_before_event_id"], 4)
        self.assertEqual([row["event_id"] for row in second["events"]], [3, 2])

    def test_ack_retry_remains_idempotent_after_acknowledged_event_prune(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1)
            delivery = self._lease(store, limit=1, now=100.0)["deliveries"][0]
            first = self._ack(store, [delivery], now=101.0)
            with mock.patch("memory_store.time.time", return_value=102.0):
                deleted = store.delete_context_event(
                    context_id=self.context_id,
                    event_id=event["event_id"],
                )
            repeated = self._ack(store, [delivery], now=103.0)
            exported = store.export_json()
            with closing(sqlite3.connect(store.db_path)) as conn:
                tombstones = conn.execute(
                    "SELECT receipt_digest FROM agent_context_delivery_ack_tombstones"
                ).fetchall()
                dump = "\n".join(conn.iterdump())

        self.assertEqual(first["acknowledged_count"], 1)
        self.assertTrue(deleted["deleted"])
        self.assertEqual(repeated["acknowledged_count"], 1)
        self.assertTrue(repeated["acknowledged"][0]["idempotent"])
        self.assertTrue(repeated["acknowledged"][0]["event_deleted"])
        self.assertEqual(len(tombstones), 1)
        self.assertNotIn(delivery["receipt_id"], dump)
        exported_tombstones = exported["context_delivery_ack_tombstones"]
        self.assertEqual(len(exported_tombstones), 1)
        self.assertNotIn("receipt_id", exported_tombstones[0])
        self.assertEqual(
            exported["export_contract"]["surfaces"]
            ["context_delivery_ack_tombstones"]["available_count"],
            1,
        )
        self.assertTrue(exported["export_contract"]["complete"])

    def test_corrupt_ack_tombstone_ownership_degrades_health_and_fails_reopen(self):
        corruptions = (
            (
                "noncanonical-context",
                "UPDATE agent_context_delivery_ack_tombstones "
                "SET context_id = ' ' || context_id || ' '",
            ),
            (
                "invalid-delivery-id",
                "UPDATE agent_context_delivery_ack_tombstones "
                "SET delivery_id = 'ctxdel/invalid'",
            ),
        )
        for label, corruption_sql in corruptions:
            with self.subTest(corruption=label), TemporaryDirectory() as tmp:
                store = self._store(tmp)
                event = self._publish(store, 1)
                delivery = self._lease(store, limit=1, now=100.0)[
                    "deliveries"
                ][0]
                self._ack(store, [delivery], now=101.0)
                with mock.patch("memory_store.time.time", return_value=102.0):
                    store.delete_context_event(
                        context_id=self.context_id,
                        event_id=event["event_id"],
                    )
                with closing(sqlite3.connect(store.db_path)) as conn:
                    conn.execute("PRAGMA ignore_check_constraints = ON")
                    conn.execute(corruption_sql)
                    conn.commit()

                health = store.context_delivery_health(now=103.0)
                samples_json = json.dumps(
                    health["ack_tombstone_integrity_error_samples"],
                    sort_keys=True,
                )
                with self.assertRaisesRegex(
                    RuntimeError,
                    "ack-tombstone-integrity-error|tombstones failed integrity",
                ):
                    self._store(tmp)

                self.assertEqual(health["status"], "degraded")
                self.assertEqual(
                    health["ack_tombstone_integrity_error_count"],
                    1,
                )
                self.assertNotIn(delivery["receipt_id"], samples_json)

    def test_constraint_free_ack_tombstone_table_is_rebuilt_without_data_loss(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1)
            delivery = self._lease(store, limit=1, now=100.0)["deliveries"][0]
            self._ack(store, [delivery], now=101.0)
            with mock.patch("memory_store.time.time", return_value=102.0):
                store.delete_context_event(
                    context_id=self.context_id,
                    event_id=event["event_id"],
                )
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    "DROP INDEX ix_agent_context_delivery_ack_tombstones_owner"
                )
                conn.execute(
                    """
                    ALTER TABLE agent_context_delivery_ack_tombstones
                    RENAME TO tombstones_exact
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE agent_context_delivery_ack_tombstones (
                        receipt_digest TEXT,
                        delivery_id TEXT,
                        context_id TEXT,
                        agent_id TEXT,
                        event_id INTEGER,
                        attempt_number INTEGER,
                        acknowledged_at REAL,
                        deleted_at REAL
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO agent_context_delivery_ack_tombstones
                    SELECT * FROM tombstones_exact
                    """
                )
                conn.execute("DROP TABLE tombstones_exact")
                conn.commit()

            reopened = self._store(tmp)
            health = reopened.context_delivery_health(context_id=self.context_id)
            exported = reopened.export_json(context_id=self.context_id)
            with closing(sqlite3.connect(reopened.db_path)) as conn:
                columns = conn.execute(
                    "PRAGMA table_info(agent_context_delivery_ack_tombstones)"
                ).fetchall()
                indexes = conn.execute(
                    "PRAGMA index_list(agent_context_delivery_ack_tombstones)"
                ).fetchall()

        self.assertEqual(health["status"], "ready")
        self.assertEqual(health["ack_tombstone_count"], 1)
        self.assertEqual(len(exported["context_delivery_ack_tombstones"]), 1)
        self.assertEqual(columns[0][5], 1)
        self.assertIn(
            "ix_agent_context_delivery_ack_tombstones_owner",
            {row[1] for row in indexes},
        )

    def test_ambiguous_ack_tombstone_history_fails_closed(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    "DROP INDEX ix_agent_context_delivery_ack_tombstones_owner"
                )
                conn.execute("DROP TABLE agent_context_delivery_ack_tombstones")
                conn.execute(
                    """
                    CREATE TABLE agent_context_delivery_ack_tombstones (
                        receipt_digest TEXT,
                        delivery_id TEXT,
                        context_id TEXT,
                        agent_id TEXT,
                        event_id INTEGER,
                        attempt_number INTEGER,
                        acknowledged_at REAL,
                        deleted_at REAL
                    )
                    """
                )
                digest = "a" * 64
                conn.executemany(
                    """
                    INSERT INTO agent_context_delivery_ack_tombstones
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (digest, "delivery-a", self.context_id, self.agent_id, 1, 1, 10.0, 11.0),
                        (digest, "delivery-b", self.context_id, self.agent_id, 2, 1, 12.0, 13.0),
                    ],
                )
                conn.commit()

            with self.assertRaisesRegex(RuntimeError, "tombstones failed integrity"):
                self._store(tmp)

    def test_duplicate_delivery_attempt_tombstones_fail_closed(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    "DROP INDEX ix_agent_context_delivery_ack_tombstones_owner"
                )
                conn.execute("DROP TABLE agent_context_delivery_ack_tombstones")
                conn.execute(
                    """
                    CREATE TABLE agent_context_delivery_ack_tombstones (
                        receipt_digest TEXT,
                        delivery_id TEXT,
                        context_id TEXT,
                        agent_id TEXT,
                        event_id INTEGER,
                        attempt_number INTEGER,
                        acknowledged_at REAL,
                        deleted_at REAL
                    )
                    """
                )
                conn.executemany(
                    """
                    INSERT INTO agent_context_delivery_ack_tombstones
                    VALUES (?, 'delivery-a', ?, ?, 1, 1, 10.0, 11.0)
                    """,
                    [
                        ("a" * 64, self.context_id, self.agent_id),
                        ("b" * 64, self.context_id, self.agent_id),
                    ],
                )
                conn.commit()

            with self.assertRaisesRegex(
                RuntimeError,
                "delivery_attempt_duplicate=1",
            ):
                self._store(tmp)

    def test_release_batch_requires_one_to_five_hundred_unique_receipts(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            with self.assertRaisesRegex(ValueError, "receipt_ids are required"):
                store.release_context_deliveries(
                    context_id=self.context_id,
                    agent_id=self.agent_id,
                    consumer_instance_id="release-owner",
                    receipt_ids=[],
                    now=100.0,
                )
            with self.assertRaisesRegex(ValueError, "at most 500"):
                store.release_context_deliveries(
                    context_id=self.context_id,
                    agent_id=self.agent_id,
                    consumer_instance_id="release-owner",
                    receipt_ids=[f"receipt-{index}" for index in range(501)],
                    now=100.0,
                )

    def test_corrupt_cursor_is_recomputed_from_ack_receipts_on_reopen(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1)
            first = self._lease(
                store,
                limit=1,
                now=100.0,
                consumer_instance_id="cursor-owner",
            )
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    """
                    UPDATE agent_context_delivery_cursors
                    SET last_contiguous_event_id = 999
                    WHERE context_id = ? AND agent_id = ?
                    """,
                    (self.context_id, self.agent_id),
                )
                conn.commit()

            repaired = self._store(tmp)
            health = repaired.context_delivery_health(
                context_id=self.context_id,
                now=101.0,
            )
            repeated = self._lease(
                repaired,
                limit=1,
                now=101.0,
                consumer_instance_id="cursor-owner",
            )
            cursor = self._cursor(repaired)

        self.assertEqual(first["deliveries"][0]["event_id"], event["event_id"])
        self.assertEqual(health["receipt_derived_cursor_mismatch_count"], 0)
        self.assertEqual(repeated["deliveries"][0]["event_id"], event["event_id"])
        self.assertEqual(cursor["last_event_id"], 0)
        self.assertEqual(cursor["cursor_basis"], "durable-disposition-derived")
        self.assertFalse(cursor["has_acknowledged_deliveries"])

    def test_negative_cursor_and_nonfinite_timestamp_degrade_then_repair(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            self._lease(store, limit=1, now=100.0)
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    """
                    UPDATE agent_context_delivery_cursors
                    SET last_contiguous_event_id = -1,
                        updated_at = ?
                    WHERE context_id = ? AND agent_id = ?
                    """,
                    (float("inf"), self.context_id, self.agent_id),
                )
                conn.commit()

            health = store.context_delivery_health(
                context_id=self.context_id,
                now=101.0,
            )
            repaired_store = self._store(tmp)
            repaired_cursor = repaired_store.list_context_cursors(
                context_id=self.context_id,
                agent_id=self.agent_id,
                limit=1,
            )[0]
            repaired_health = repaired_store.context_delivery_health(
                context_id=self.context_id,
                now=101.0,
            )

        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["receipt_derived_cursor_mismatch_count"], 1)
        mismatch = health["receipt_derived_cursor_mismatch_samples"][0]
        self.assertIsNone(mismatch["stored_event_id"])
        self.assertIn(
            "last-contiguous-event-id",
            mismatch["integrity_errors"],
        )
        self.assertIn("updated-at", mismatch["integrity_errors"])
        self.assertEqual(repaired_cursor["last_event_id"], 0)
        self.assertTrue(math.isfinite(repaired_cursor["updated_at"]))
        self.assertEqual(repaired_health["status"], "ready")

    def test_empty_cursor_identity_degrades_and_fails_reopen(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            self._lease(store, limit=1, now=100.0)
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    """
                    UPDATE agent_context_delivery_cursors
                    SET context_id = ''
                    WHERE context_id = ? AND agent_id = ?
                    """,
                    (self.context_id, self.agent_id),
                )
                conn.commit()

            health = store.context_delivery_health(now=101.0)
            with self.assertRaisesRegex(
                RuntimeError,
                "cursor identity failed integrity",
            ):
                self._store(tmp)

        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["receipt_derived_cursor_mismatch_count"], 1)
        self.assertIn(
            "context-id",
            health["receipt_derived_cursor_mismatch_samples"][0][
                "integrity_errors"
            ],
        )

    def test_wrong_named_delivery_index_is_replaced_with_exact_signature(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    "DROP INDEX ix_agent_context_deliveries_agent_state_event"
                )
                conn.execute(
                    """
                    CREATE INDEX ix_agent_context_deliveries_agent_state_event
                    ON agent_context_deliveries(event_id)
                    """
                )
                conn.commit()

            repaired = self._store(tmp)
            health = repaired.context_delivery_health()
            with closing(sqlite3.connect(repaired.db_path)) as conn:
                columns = [
                    row[2]
                    for row in conn.execute(
                        "PRAGMA index_info(ix_agent_context_deliveries_agent_state_event)"
                    ).fetchall()
                ]

        self.assertEqual(columns, ["context_id", "agent_id", "state", "event_id"])
        self.assertEqual(health["status"], "ready")

    def test_existing_v2_delivery_without_receipts_fails_closed(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            self._lease(store, limit=1, now=100.0)
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute("PRAGMA foreign_keys = OFF")
                conn.execute("DROP TABLE agent_context_delivery_receipts")
                conn.commit()

            with self.assertRaisesRegex(RuntimeError, "receipts are missing"):
                self._store(tmp)

    def test_invalid_delivery_receipt_state_pair_fails_closed(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            delivery = self._lease(store, limit=1, now=100.0)["deliveries"][0]
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute("PRAGMA ignore_check_constraints = ON")
                conn.execute(
                    """
                    UPDATE agent_context_delivery_receipts
                    SET state = 'acknowledged', acknowledged_at = 101.0
                    WHERE receipt_id = ?
                    """,
                    (delivery["receipt_id"],),
                )
                conn.commit()

            with self.assertRaisesRegex(
                RuntimeError,
                "data failed integrity validation|state-mismatch",
            ):
                self._store(tmp)

    def test_empty_current_receipt_and_infinite_expiry_degrade_and_fail_reopen(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            delivery = self._lease(
                store,
                limit=1,
                now=100.0,
                consumer_instance_id="integrity-owner",
            )["deliveries"][0]
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute("PRAGMA ignore_check_constraints = ON")
                conn.execute(
                    """
                    UPDATE agent_context_deliveries
                    SET current_receipt_id = '', lease_expires_at = ?
                    WHERE delivery_id = ?
                    """,
                    (float("inf"), delivery["delivery_id"]),
                )
                conn.execute(
                    """
                    UPDATE agent_context_delivery_receipts
                    SET receipt_id = '', lease_expires_at = ?
                    WHERE receipt_id = ?
                    """,
                    (float("inf"), delivery["receipt_id"]),
                )
                conn.commit()

            health = store.context_delivery_health(
                context_id=self.context_id,
                now=101.0,
            )
            serialized_health = json.dumps(health, sort_keys=True)
            with self.assertRaisesRegex(
                RuntimeError,
                "live-delivery-integrity-error|data failed integrity validation",
            ):
                self._store(tmp)

        self.assertEqual(health["status"], "degraded")
        self.assertGreaterEqual(health["live_delivery_integrity_error_count"], 2)
        self.assertIn("current-receipt-id-format", serialized_health)
        self.assertIn("lease-expires-at", serialized_health)
        self.assertNotIn(delivery["receipt_id"], serialized_health)

    def test_live_receipt_owner_and_timestamp_order_are_audited(self):
        corruptions = (
            (
                "empty-delivery-id",
                """
                UPDATE agent_context_deliveries
                SET delivery_id = ''
                WHERE current_receipt_id = ?
                """,
                "delivery-id-format",
            ),
            (
                "empty-context-id",
                """
                UPDATE agent_context_deliveries
                SET context_id = ''
                WHERE current_receipt_id = ?
                """,
                "context-id",
            ),
            (
                "empty-agent-id",
                """
                UPDATE agent_context_deliveries
                SET agent_id = ''
                WHERE current_receipt_id = ?
                """,
                "agent-id",
            ),
            (
                "empty-lease-owner",
                """
                UPDATE agent_context_deliveries
                SET lease_owner = ''
                WHERE current_receipt_id = ?
                """,
                "lease-owner",
            ),
            (
                "empty-consumer-instance",
                """
                UPDATE agent_context_delivery_receipts
                SET consumer_instance_id = ''
                WHERE receipt_id = ?
                """,
                "consumer-instance-id",
            ),
            (
                "owner-mismatch",
                """
                UPDATE agent_context_delivery_receipts
                SET consumer_instance_id = 'different-owner'
                WHERE receipt_id = ?
                """,
                "current-receipt-owner-mismatch",
            ),
            (
                "receipt-time-order",
                """
                UPDATE agent_context_delivery_receipts
                SET created_at = leased_at + 1.0
                WHERE receipt_id = ?
                """,
                "created-after-leased",
            ),
            (
                "delivery-state-nullability",
                """
                UPDATE agent_context_deliveries
                SET state = 'acknowledged', acknowledged_at = NULL
                WHERE current_receipt_id = ?
                """,
                "acknowledged-state-timestamps",
            ),
        )
        for label, mutation_sql, expected_error in corruptions:
            with self.subTest(label=label), TemporaryDirectory() as tmp:
                store = self._store(tmp)
                self._publish(store, 1)
                delivery = self._lease(
                    store,
                    limit=1,
                    now=100.0,
                    consumer_instance_id="integrity-owner",
                )["deliveries"][0]
                with closing(sqlite3.connect(store.db_path)) as conn:
                    conn.execute("PRAGMA ignore_check_constraints = ON")
                    conn.execute(mutation_sql, (delivery["receipt_id"],))
                    conn.commit()

                health = store.context_delivery_health(now=101.0)
                with self.assertRaisesRegex(
                    RuntimeError,
                    "live-delivery-integrity-error|data failed integrity validation|empty canonical agent",
                ):
                    self._store(tmp)

                self.assertEqual(health["status"], "degraded")
                self.assertGreaterEqual(
                    health["live_delivery_integrity_error_count"],
                    1,
                )
                self.assertIn(
                    expected_error,
                    json.dumps(
                        health["live_delivery_integrity_error_samples"],
                        sort_keys=True,
                    ),
                )

    def test_constraint_free_v2_rebuild_refuses_ambiguous_empty_receipts(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            delivery = self._lease(store, limit=1, now=100.0)["deliveries"][0]
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute("PRAGMA foreign_keys = OFF")
                for index_name in (
                    "ix_agent_context_deliveries_agent_state_event",
                    "ix_agent_context_deliveries_lease_expiry",
                    "ix_agent_context_delivery_receipts_delivery_attempt",
                    "ix_agent_context_delivery_receipts_state_expiry",
                ):
                    conn.execute(f'DROP INDEX "{index_name}"')
                conn.execute(
                    """
                    ALTER TABLE agent_context_delivery_receipts
                    RENAME TO agent_context_delivery_receipts_source
                    """
                )
                conn.execute(
                    """
                    ALTER TABLE agent_context_deliveries
                    RENAME TO agent_context_deliveries_source
                    """
                )
                conn.executescript(
                    """
                    CREATE TABLE agent_context_deliveries (
                        delivery_id TEXT,
                        context_id TEXT,
                        agent_id TEXT,
                        event_id INTEGER,
                        state TEXT,
                        attempt_count INTEGER,
                        current_receipt_id TEXT,
                        lease_owner TEXT,
                        first_delivered_at REAL,
                        last_delivered_at REAL,
                        lease_expires_at REAL,
                        acknowledged_at REAL,
                        cancelled_at REAL,
                        created_at REAL,
                        updated_at REAL
                    );
                    CREATE TABLE agent_context_delivery_receipts (
                        receipt_id TEXT,
                        delivery_id TEXT,
                        attempt_number INTEGER,
                        consumer_instance_id TEXT,
                        state TEXT,
                        leased_at REAL,
                        lease_expires_at REAL,
                        acknowledged_at REAL,
                        released_at REAL,
                        created_at REAL,
                        updated_at REAL
                    );
                    """
                )
                conn.execute(
                    """
                    INSERT INTO agent_context_deliveries
                    SELECT delivery_id, context_id, agent_id, event_id, state,
                           attempt_count, '', lease_owner, first_delivered_at,
                           last_delivered_at, lease_expires_at, acknowledged_at,
                           cancelled_at, created_at, updated_at
                    FROM agent_context_deliveries_source
                    """
                )
                conn.execute(
                    """
                    INSERT INTO agent_context_delivery_receipts
                    SELECT '', delivery_id, attempt_number,
                           consumer_instance_id, state, leased_at,
                           lease_expires_at, acknowledged_at, released_at,
                           created_at, updated_at
                    FROM agent_context_delivery_receipts_source
                    """
                )
                conn.execute("DROP TABLE agent_context_delivery_receipts_source")
                conn.execute("DROP TABLE agent_context_deliveries_source")
                conn.commit()

            with self.assertRaisesRegex(
                RuntimeError,
                "failed live integrity validation",
            ):
                self._store(tmp)
            with closing(sqlite3.connect(store.db_path)) as conn:
                delivery_columns = [
                    row[1]
                    for row in conn.execute(
                        "PRAGMA table_info(agent_context_deliveries)"
                    ).fetchall()
                ]
                legacy_table_count = conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM sqlite_master
                    WHERE type = 'table'
                      AND name IN (
                          'agent_context_deliveries_v2_legacy',
                          'agent_context_delivery_receipts_v2_legacy'
                      )
                    """
                ).fetchone()[0]

        self.assertEqual(delivery_columns[0], "delivery_id")
        self.assertEqual(legacy_table_count, 0)
        self.assertTrue(delivery["delivery_id"])

    def test_out_of_order_retry_history_degrades_health_and_fails_reopen(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            delivery = self._lease(store, limit=1, now=100.0)["deliveries"][0]
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute("PRAGMA ignore_check_constraints = ON")
                conn.execute(
                    """
                    INSERT INTO agent_context_delivery_receipts (
                        receipt_id, delivery_id, attempt_number,
                        consumer_instance_id, state, leased_at,
                        lease_expires_at, acknowledged_at, released_at,
                        created_at, updated_at
                    ) VALUES (?, ?, 2, 'injected-future-owner', 'expired',
                              101.0, 102.0, NULL, NULL, 101.0, 102.0)
                    """,
                    ("ctxrcpt_injected_future", delivery["delivery_id"]),
                )
                conn.commit()

            health = store.context_delivery_health(context_id=self.context_id)
            with self.assertRaisesRegex(
                RuntimeError,
                "receipt-history-mismatch|data failed integrity validation",
            ):
                self._store(tmp)

        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["receipt_history_mismatch_count"], 1)
        self.assertEqual(
            health["receipt_history_mismatch_samples"][0]["max_receipt_attempt"],
            2,
        )

    def test_retry_attempts_must_preserve_cross_attempt_causal_order(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            first = self._lease(
                store,
                limit=1,
                lease_seconds=1.0,
                now=100.0,
                consumer_instance_id="chronology-attempt-one",
            )["deliveries"][0]
            second = self._lease(
                store,
                limit=1,
                lease_seconds=10.0,
                now=102.0,
                consumer_instance_id="chronology-attempt-two",
            )["deliveries"][0]
            with closing(sqlite3.connect(store.db_path)) as conn:
                # Every changed value remains locally valid. Only the causal
                # relationship to attempt two is impossible.
                conn.execute(
                    """
                    UPDATE agent_context_delivery_receipts
                    SET lease_expires_at = 104.0,
                        updated_at = 104.0
                    WHERE delivery_id = ? AND attempt_number = 1
                    """,
                    (first["delivery_id"],),
                )
                conn.commit()

            health = store.context_delivery_health(
                context_id=self.context_id,
                now=103.0,
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "receipt-history-mismatch|data failed integrity validation",
            ):
                self._store(tmp)

        self.assertEqual(first["delivery_id"], second["delivery_id"])
        self.assertEqual(second["attempt_count"], 2)
        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["receipt_history_mismatch_count"], 1)
        chronology = health["receipt_history_mismatch_samples"][0]
        self.assertEqual(chronology["kind"], "attempt-chronology")
        self.assertEqual(chronology["prior_attempt_number"], 1)
        self.assertEqual(chronology["next_attempt_number"], 2)
        self.assertIn("prior-expiry-after-next-lease", chronology["errors"])

    def test_historical_cancelled_receipt_cannot_precede_a_retry(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            first = self._lease(
                store,
                limit=1,
                lease_seconds=1.0,
                now=100.0,
                consumer_instance_id="cancelled-history-one",
            )["deliveries"][0]
            second = self._lease(
                store,
                limit=1,
                lease_seconds=10.0,
                now=102.0,
                consumer_instance_id="cancelled-history-two",
            )["deliveries"][0]
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    """
                    UPDATE agent_context_delivery_receipts
                    SET state = 'cancelled'
                    WHERE delivery_id = ? AND attempt_number = 1
                    """,
                    (first["delivery_id"],),
                )
                conn.commit()

            health = store.context_delivery_health(
                context_id=self.context_id,
                now=103.0,
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "receipt-history-mismatch|data failed integrity validation",
            ):
                self._store(tmp)

        self.assertEqual(first["delivery_id"], second["delivery_id"])
        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["receipt_history_mismatch_count"], 1)
        sample = health["receipt_history_mismatch_samples"][0]
        self.assertEqual(sample["invalid_historical_state_count"], 1)
        self.assertNotIn(first["receipt_id"], json.dumps(sample, sort_keys=True))

    def test_first_receipt_must_anchor_delivery_first_delivered_at(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            first = self._lease(
                store,
                limit=1,
                lease_seconds=1.0,
                now=100.0,
                consumer_instance_id="anchor-attempt-one",
            )["deliveries"][0]
            second = self._lease(
                store,
                limit=1,
                lease_seconds=10.0,
                now=102.0,
                consumer_instance_id="anchor-attempt-two",
            )["deliveries"][0]
            with closing(sqlite3.connect(store.db_path)) as conn:
                # This remains valid within attempt one and relative to attempt
                # two, but contradicts the delivery's authoritative origin.
                conn.execute(
                    """
                    UPDATE agent_context_delivery_receipts
                    SET created_at = 99.0,
                        leased_at = 99.0
                    WHERE delivery_id = ? AND attempt_number = 1
                    """,
                    (first["delivery_id"],),
                )
                conn.commit()

            health = store.context_delivery_health(
                context_id=self.context_id,
                now=103.0,
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "receipt-history-mismatch|data failed integrity validation",
            ):
                self._store(tmp)

        self.assertEqual(first["delivery_id"], second["delivery_id"])
        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["receipt_history_mismatch_count"], 1)
        anchor = health["receipt_history_mismatch_samples"][0]
        self.assertTrue(anchor["first_receipt_anchor_mismatch"])
        self.assertEqual(anchor["first_delivered_at"], 100.0)
        self.assertEqual(anchor["first_receipt_leased_at"], 99.0)
        self.assertNotIn(first["receipt_id"], json.dumps(anchor, sort_keys=True))

    def test_group_observation_policy_does_not_require_a_prior_lease(self):
        with TemporaryDirectory() as tmp:
            backend = SpikingAttentionBackend(
                dimension=8,
                num_neurons=8,
                default_top_k=2,
                compile_graph=False,
                state_path=Path(tmp) / "state.json",
                memory_path=Path(tmp) / "memory.sqlite3",
            )
            event = backend.publish_context_event(
                context_id=self.context_id,
                source_surface="group-observation-test",
                event_type="group-policy",
                summary="visible before first claim",
                agent_targets=["mcp-clients"],
            )
            before = backend.list_context_events(
                context_id=self.context_id,
                agent_id="Claude-Desktop",
                limit=10,
            )
            leased = backend.lease_context_events(
                context_id=self.context_id,
                agent_id="Claude-Desktop",
                consumer_instance_id="claude-observer",
                limit=10,
            )

        self.assertEqual([row["event_id"] for row in before["events"]], [event["event_id"]])
        self.assertEqual(leased["agent_id"], "claude-desktop")
        self.assertEqual(leased["deliveries"][0]["event_id"], event["event_id"])

    def test_explicit_empty_group_policy_revokes_persisted_visibility(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = store.publish_context_event(
                context_id=self.context_id,
                source_surface="group-revocation-test",
                event_type="group-policy",
                summary="membership can be revoked without another lease",
                agent_targets=["mcp-clients"],
                created_at=100.0,
            )
            store.lease_context_events(
                context_id=self.context_id,
                agent_id="claude-desktop",
                consumer_instance_id="prior-group-member",
                consumer_groups=["mcp-clients"],
                limit=1,
                lease_seconds=60.0,
                now=101.0,
            )
            persisted = store.list_context_events(
                context_id=self.context_id,
                agent_id="claude-desktop",
                consumer_groups=None,
                limit=10,
            )
            revoked = store.list_context_events(
                context_id=self.context_id,
                agent_id="claude-desktop",
                consumer_groups=(),
                limit=10,
            )

        self.assertEqual([row["event_id"] for row in persisted], [event["event_id"]])
        self.assertEqual(revoked, [])

    def test_exact_targets_share_consumer_canonicalization(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = store.publish_context_event(
                context_id=self.context_id,
                source_surface="canonical-target-test",
                event_type="exact-target",
                summary="slash target canonicalizes to underscore",
                agent_targets=["Agent/Foo"],
                created_at=100.0,
            )
            leased = store.lease_context_events(
                context_id=self.context_id,
                agent_id="agent/foo",
                consumer_instance_id="canonical-agent",
                limit=1,
                now=101.0,
            )
            with closing(sqlite3.connect(store.db_path)) as conn:
                targets = conn.execute(
                    """
                    SELECT target_kind, target_id
                    FROM agent_context_event_targets
                    WHERE event_id = ?
                    """,
                    (event["event_id"],),
                ).fetchall()

        self.assertEqual(targets, [("agent", "agent_foo")])
        self.assertEqual(leased["agent_id"], "agent_foo")
        self.assertEqual(leased["events"][0]["event_id"], event["event_id"])

    def test_routed_target_kinds_and_envelope_parity_fail_closed(self):
        corruptions = (
            (
                "unknown-group",
                "group",
                "unknown-group",
                ["unknown-group"],
                "group-target-not-allowed",
            ),
            (
                "invalid-broadcast",
                "broadcast",
                "not-star",
                ["broadcast"],
                "broadcast-target-not-star",
            ),
            (
                "noncanonical-agent",
                "agent",
                "Agent/Foo",
                ["Agent/Foo"],
                "agent-target-noncanonical",
            ),
            (
                "empty-agent",
                "agent",
                "",
                [""],
                "agent-target-empty",
            ),
        )
        for label, target_kind, target_id, envelope, expected_reason in corruptions:
            with self.subTest(label=label), TemporaryDirectory() as tmp:
                store = self._store(tmp)
                event = self._publish(store, 1)
                with closing(sqlite3.connect(store.db_path)) as conn:
                    conn.execute(
                        """
                        UPDATE agent_context_event_targets
                        SET target_kind = ?, target_id = ?
                        WHERE event_id = ?
                        """,
                        (target_kind, target_id, event["event_id"]),
                    )
                    conn.execute(
                        """
                        UPDATE agent_context_events
                        SET agent_targets_json = ?
                        WHERE event_id = ?
                        """,
                        (json.dumps(envelope), event["event_id"]),
                    )
                    conn.commit()

                health = store.context_delivery_health(context_id=self.context_id)
                self.assertEqual(health["status"], "degraded")
                self.assertEqual(health["target_integrity_error_count"], 1)
                self.assertIn(
                    expected_reason,
                    health["target_integrity_error_samples"][0]["reasons"],
                )
                with self.assertRaisesRegex(
                    RuntimeError,
                    "context event targets failed integrity validation",
                ):
                    self._store(tmp)

    def test_sanctioned_target_rows_must_match_the_event_envelope(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1, targets=["mcp-clients"])
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    """
                    UPDATE agent_context_events
                    SET agent_targets_json = ?
                    WHERE event_id = ?
                    """,
                    (json.dumps([self.agent_id]), event["event_id"]),
                )
                conn.commit()

            health = store.context_delivery_health(context_id=self.context_id)
            self.assertEqual(health["target_integrity_error_count"], 1)
            self.assertEqual(
                health["target_integrity_error_samples"][0]["reasons"],
                ["target-row-envelope-mismatch"],
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "context event targets failed integrity validation",
            ):
                self._store(tmp)

    def test_routed_event_envelope_must_be_canonical_deduplicated_and_nonempty(self):
        for label, corrupted_envelope in (
            ("case-variant", ["A"]),
            ("duplicate", ["a", "a"]),
            ("empty-member", ["a", ""]),
        ):
            with self.subTest(label=label), TemporaryDirectory() as tmp:
                store = self._store(tmp)
                event = self._publish(store, 1, targets=["a"])
                # Reconcile the freshly published event first so the mutation
                # is an established-ledger corruption, not rolling-writer
                # legacy input that reconciliation is allowed to normalize.
                store = self._store(tmp)
                with closing(sqlite3.connect(store.db_path)) as conn:
                    conn.execute(
                        """
                        UPDATE agent_context_events
                        SET agent_targets_json = ?
                        WHERE event_id = ?
                        """,
                        (json.dumps(corrupted_envelope), event["event_id"]),
                    )
                    conn.commit()

                health = store.context_delivery_health(context_id=self.context_id)
                self.assertEqual(health["status"], "degraded")
                self.assertEqual(health["target_integrity_error_count"], 1)
                self.assertIn(
                    "agent-targets-envelope-noncanonical",
                    health["target_integrity_error_samples"][0]["reasons"],
                )
                with self.assertRaisesRegex(
                    RuntimeError,
                    "context event targets failed integrity validation",
                ):
                    self._store(tmp)

    def test_valid_envelope_missing_all_target_rows_blocks_health_reopen_and_lease(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1, targets=["a"])
            store = self._store(tmp)
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    "DELETE FROM agent_context_event_targets WHERE event_id = ?",
                    (event["event_id"],),
                )
                conn.commit()

            health = store.context_delivery_health(context_id=self.context_id)
            self.assertEqual(health["status"], "degraded")
            self.assertEqual(health["unrouted_event_count"], 1)
            self.assertEqual(health["target_integrity_error_count"], 1)
            self.assertIn(
                "missing-target-rows",
                health["target_integrity_error_samples"][0]["reasons"],
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "context event targets failed integrity validation",
            ):
                store.lease_context_events(
                    context_id=self.context_id,
                    agent_id="a",
                    consumer_instance_id="must-not-silently-skip",
                    limit=1,
                    now=200.0,
                )
            with self.assertRaisesRegex(
                RuntimeError,
                "context event targets failed integrity validation",
            ):
                self._store(tmp)
            with closing(sqlite3.connect(store.db_path)) as conn:
                delivery_count = conn.execute(
                    "SELECT COUNT(*) FROM agent_context_deliveries"
                ).fetchone()[0]

        self.assertEqual(delivery_count, 0)

    def test_publish_rejects_unreachable_context_ids_and_nonfinite_timestamps(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            for invalid_context in ("", " c ", "x" * 129):
                with self.subTest(context=repr(invalid_context)):
                    with self.assertRaisesRegex(ValueError, "context_id"):
                        store.publish_context_event(
                            context_id=invalid_context,
                            source_surface="publish-validation-test",
                            event_type="invalid-context",
                            summary="must not persist",
                            agent_targets=["a"],
                            created_at=0.0,
                        )
            for invalid_created_at in (
                float("nan"),
                float("inf"),
                float("-inf"),
            ):
                with self.subTest(created_at=invalid_created_at):
                    with self.assertRaisesRegex(ValueError, "created_at"):
                        store.publish_context_event(
                            context_id="c",
                            source_surface="publish-validation-test",
                            event_type="invalid-created-at",
                            summary="must not persist",
                            agent_targets=["a"],
                            created_at=invalid_created_at,
                        )
            epoch = store.publish_context_event(
                context_id="c",
                source_surface="publish-validation-test",
                event_type="epoch-created-at",
                summary="zero is a valid finite timestamp",
                agent_targets=["a"],
                created_at=0.0,
            )
            with closing(sqlite3.connect(store.db_path)) as conn:
                catalog_row = conn.execute(
                    """
                    SELECT value_json, updated_at
                    FROM store_metadata
                    WHERE key = ?
                    """,
                    ("namespace_catalog.v1:c",),
                ).fetchone()

        self.assertEqual(epoch["context_id"], "c")
        self.assertEqual(epoch["created_at"], 0.0)
        self.assertIsNotNone(catalog_row)
        assert catalog_row is not None
        catalog = json.loads(str(catalog_row[0]))
        self.assertEqual(catalog["created_at"], 0.0)
        self.assertEqual(catalog["last_seen_at"], 0.0)
        self.assertEqual(float(catalog_row[1]), 0.0)

    def test_invalid_event_ledger_addressing_degrades_health_and_fails_reopen(self):
        corruptions = (
            ("empty-context", "context_id", ""),
            ("spaced-context", "context_id", " delivery-test "),
            ("oversized-context", "context_id", "x" * 129),
            ("infinite-created-at", "created_at", float("inf")),
        )
        for label, column, value in corruptions:
            with self.subTest(label=label), TemporaryDirectory() as tmp:
                store = self._store(tmp)
                event = self._publish(store, 1)
                store = self._store(tmp)
                with closing(sqlite3.connect(store.db_path)) as conn:
                    conn.execute(
                        f"UPDATE agent_context_events SET {column} = ? WHERE event_id = ?",
                        (value, event["event_id"]),
                    )
                    conn.commit()

                health = store.context_delivery_health()
                self.assertEqual(health["status"], "degraded")
                self.assertEqual(health["event_ledger_integrity_error_count"], 1)
                sample = health["event_ledger_integrity_error_samples"][0]
                self.assertEqual(sample["event_id"], event["event_id"])
                self.assertNotIn("context_id", sample)
                self.assertLessEqual(len(health["event_ledger_integrity_error_samples"]), 10)
                with self.assertRaisesRegex(
                    RuntimeError,
                    "context event ledger failed integrity validation",
                ):
                    self._store(tmp)

    def test_unknown_consumer_group_and_paired_route_fail_closed(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1, targets=["mcp-clients"])
            self._lease(store, limit=1, now=101.0)
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    """
                    INSERT INTO agent_context_consumer_groups (
                        agent_id, group_id, created_at
                    ) VALUES (?, 'unknown-group', 102.0)
                    """,
                    (self.agent_id,),
                )
                conn.execute(
                    """
                    UPDATE agent_context_event_targets
                    SET target_kind = 'group', target_id = 'unknown-group'
                    WHERE event_id = ?
                    """,
                    (event["event_id"],),
                )
                conn.execute(
                    """
                    UPDATE agent_context_events
                    SET agent_targets_json = ?
                    WHERE event_id = ?
                    """,
                    (json.dumps(["unknown-group"]), event["event_id"]),
                )
                conn.commit()

            health = store.context_delivery_health(context_id=self.context_id)
            self.assertEqual(health["target_integrity_error_count"], 1)
            self.assertEqual(health["consumer_group_integrity_error_count"], 1)
            self.assertEqual(
                health["consumer_group_integrity_error_samples"][0]["group_id"],
                "unknown-group",
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "consumer-group-integrity-error|targets failed integrity",
            ):
                self._store(tmp)

    def test_target_reconciliation_highwater_ahead_of_ledger_fails_closed(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1)
            # Reopen once so the normal rolling-writer reconciliation reaches
            # this event before the metadata is adversarially advanced.
            store = self._store(tmp)
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    """
                    UPDATE store_metadata
                    SET value_json = ?
                    WHERE key = 'context_event_targets_reconciled_through'
                    """,
                    (json.dumps(event["event_id"] + 100),),
                )
                conn.commit()

            health = store.context_delivery_health(context_id=self.context_id)
            self.assertEqual(
                health["target_reconciliation_highwater_error_count"],
                1,
            )
            self.assertEqual(health["status"], "degraded")
            with self.assertRaisesRegex(
                RuntimeError,
                "reconciliation highwater failed integrity validation",
            ):
                self._store(tmp)

    def test_deleting_latest_event_clamps_target_reconciliation_highwater(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1)
            store = self._store(tmp)
            deleted = store.delete_context_event(
                context_id=self.context_id,
                event_id=event["event_id"],
            )
            reopened = self._store(tmp)
            health = reopened.context_delivery_health(context_id=self.context_id)
            with closing(sqlite3.connect(reopened.db_path)) as conn:
                highwater = json.loads(
                    conn.execute(
                        """
                        SELECT value_json
                        FROM store_metadata
                        WHERE key = 'context_event_targets_reconciled_through'
                        """
                    ).fetchone()[0]
                )

        self.assertTrue(deleted["deleted"])
        self.assertEqual(highwater, 0)
        self.assertEqual(health["target_reconciliation_highwater_error_count"], 0)
        self.assertEqual(health["status"], "ready")

    def test_unproducible_cancelled_delivery_cannot_advance_or_skip_cursor(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            event = self._publish(store, 1)
            owner = "cancelled-delivery-owner"
            delivery = self._lease(
                store,
                limit=1,
                lease_seconds=30.0,
                now=100.0,
                consumer_instance_id=owner,
            )["deliveries"][0]
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute("PRAGMA ignore_check_constraints = ON")
                conn.execute(
                    """
                    UPDATE agent_context_delivery_receipts
                    SET state = 'cancelled', updated_at = 101.0
                    WHERE receipt_id = ?
                    """,
                    (delivery["receipt_id"],),
                )
                conn.execute(
                    """
                    UPDATE agent_context_deliveries
                    SET state = 'cancelled',
                        cancelled_at = 101.0,
                        updated_at = 101.0
                    WHERE delivery_id = ?
                    """,
                    (delivery["delivery_id"],),
                )
                cursor_before = conn.execute(
                    """
                    SELECT last_contiguous_event_id
                    FROM agent_context_delivery_cursors
                    WHERE context_id = ? AND agent_id = ?
                    """,
                    (self.context_id, self.agent_id),
                ).fetchone()[0]
                conn.commit()

            health = store.context_delivery_health(
                context_id=self.context_id,
                now=102.0,
            )
            # Isolate candidate selection and the active-receipt guard from
            # the connection-level audit, which independently fails closed.
            with mock.patch.object(store, "_run_migrations", return_value=None):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "active context delivery receipt failed integrity validation",
                ):
                    self._lease(
                        store,
                        limit=1,
                        lease_seconds=30.0,
                        now=102.0,
                        consumer_instance_id=owner,
                    )
            with self.assertRaisesRegex(
                RuntimeError,
                "live-delivery-integrity-error|data failed integrity validation",
            ):
                self._store(tmp)
            with closing(sqlite3.connect(store.db_path)) as conn:
                cursor_after = conn.execute(
                    """
                    SELECT last_contiguous_event_id
                    FROM agent_context_delivery_cursors
                    WHERE context_id = ? AND agent_id = ?
                    """,
                    (self.context_id, self.agent_id),
                ).fetchone()[0]

        self.assertEqual(cursor_before, 0)
        self.assertEqual(cursor_after, 0)
        self.assertNotEqual(cursor_after, event["event_id"])
        self.assertEqual(health["status"], "degraded")
        self.assertGreaterEqual(health["live_delivery_integrity_error_count"], 1)
        self.assertNotIn(
            delivery["receipt_id"],
            json.dumps(
                health["live_delivery_integrity_error_samples"],
                sort_keys=True,
            ),
        )

    def test_retry_exhaustion_requires_governed_dead_letter_before_progress(self):
        with TemporaryDirectory() as tmp, mock.patch.dict(
            "os.environ",
            {"SYNAPSE_S2_CONTEXT_MAX_DELIVERY_ATTEMPTS": "2"},
        ):
            store = self._store(tmp)
            first_event = self._publish(store, 1)
            second_event = self._publish(store, 2)
            first_attempt = self._lease(
                store,
                limit=1,
                lease_seconds=1.0,
                now=100.0,
                consumer_instance_id="attempt-one",
            )["deliveries"][0]
            second_attempt = self._lease(
                store,
                limit=1,
                lease_seconds=1.0,
                now=102.0,
                consumer_instance_id="attempt-two",
            )["deliveries"][0]
            exhausted = self._lease(
                store,
                limit=1,
                lease_seconds=1.0,
                now=104.0,
                consumer_instance_id="attempt-three",
            )
            health_before = store.context_delivery_health(
                context_id=self.context_id,
                now=104.0,
            )
            stats_before = store.stats(context_id=self.context_id)
            with self.assertRaisesRegex(ValueError, "confirm=True"):
                store.dead_letter_context_delivery(
                    context_id=self.context_id,
                    agent_id=self.agent_id,
                    delivery_id=first_attempt["delivery_id"],
                    reason="consumer cannot deserialize this event",
                    now=104.0,
                )
            quarantined = store.dead_letter_context_delivery(
                context_id=self.context_id,
                agent_id=self.agent_id,
                delivery_id=first_attempt["delivery_id"],
                reason="consumer cannot deserialize this event",
                confirm=True,
                now=104.0,
            )
            next_batch = self._lease(
                store,
                limit=1,
                now=105.0,
                consumer_instance_id="after-quarantine",
            )
            health_after = store.context_delivery_health(
                context_id=self.context_id,
                now=105.0,
            )
            reopened = self._store(tmp).context_delivery_health(
                context_id=self.context_id,
                now=105.0,
            )
            with closing(sqlite3.connect(store.db_path)) as conn:
                audit_payload = conn.execute(
                    """
                    SELECT payload_json
                    FROM store_maintenance_receipts
                    WHERE operation_id = ?
                    """,
                    (quarantined["operation_id"],),
                ).fetchone()[0]

        self.assertNotEqual(first_attempt["receipt_id"], second_attempt["receipt_id"])
        self.assertEqual(exhausted["delivery_count"], 0)
        self.assertEqual(exhausted["blocking_delivery"]["reason"], "retry-exhausted")
        self.assertEqual(health_before["status"], "degraded")
        self.assertEqual(health_before["retry_exhausted_count"], 1)
        self.assertEqual(health_before["expired_active_lease_count"], 0)
        self.assertEqual(stats_before["context_bus_retry_exhausted_count"], 1)
        self.assertEqual(
            stats_before["context_bus_expired_retryable_lease_count"],
            0,
        )
        self.assertEqual(quarantined["cursor"]["last_event_id"], first_event["event_id"])
        self.assertEqual(
            quarantined["cursor"]["cursor_basis"],
            "durable-disposition-derived",
        )
        self.assertEqual(next_batch["events"][0]["event_id"], second_event["event_id"])
        self.assertEqual(health_after["status"], "ready")
        self.assertEqual(health_after["dead_letter_count"], 1)
        self.assertEqual(health_after["unaudited_dead_letter_count"], 0)
        self.assertEqual(reopened["status"], "ready")
        self.assertNotIn(second_attempt["receipt_id"], audit_payload)

    def test_dead_letter_requires_intact_governance_payload(self):
        with TemporaryDirectory() as tmp, mock.patch.dict(
            "os.environ",
            {"SYNAPSE_S2_CONTEXT_MAX_DELIVERY_ATTEMPTS": "2"},
        ):
            store = self._store(tmp)
            self._publish(store, 1)
            first = self._lease(
                store,
                limit=1,
                lease_seconds=1.0,
                now=100.0,
                consumer_instance_id="governance-attempt-one",
            )["deliveries"][0]
            self._lease(
                store,
                limit=1,
                lease_seconds=1.0,
                now=102.0,
                consumer_instance_id="governance-attempt-two",
            )
            governed = store.dead_letter_context_delivery(
                context_id=self.context_id,
                agent_id=self.agent_id,
                delivery_id=first["delivery_id"],
                reason="the consumer cannot decode this governed test event",
                confirm=True,
                now=104.0,
            )
            with closing(sqlite3.connect(store.db_path)) as conn:
                conn.execute(
                    """
                    UPDATE store_maintenance_receipts
                    SET payload_json = '{}'
                    WHERE operation_id = ?
                    """,
                    (governed["operation_id"],),
                )
                conn.commit()

            health = store.context_delivery_health(
                context_id=self.context_id,
                now=105.0,
            )
            with self.assertRaisesRegex(RuntimeError, "unaudited-dead-letter"):
                self._store(tmp)

        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["unaudited_dead_letter_count"], 1)
        self.assertIn(
            "missing-reason",
            health["unaudited_dead_letter_samples"][0]["issues"],
        )
        self.assertIn(
            "receipt-digest-mismatch",
            health["unaudited_dead_letter_samples"][0]["issues"],
        )

    def test_export_reports_truncated_ack_tombstone_surface(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            events = [self._publish(store, ordinal) for ordinal in (1, 2)]
            deliveries = self._lease(store, limit=2, now=100.0)["deliveries"]
            self._ack(store, deliveries, now=101.0)
            for event in events:
                store.delete_context_event(
                    context_id=self.context_id,
                    event_id=event["event_id"],
                )

            exported = store.export_json(
                context_id=self.context_id,
                limit=1,
            )

        tombstone_surface = exported["export_contract"]["surfaces"][
            "context_delivery_ack_tombstones"
        ]
        self.assertEqual(tombstone_surface["available_count"], 2)
        self.assertEqual(tombstone_surface["exported_count"], 1)
        self.assertTrue(tombstone_surface["truncated"])
        self.assertFalse(exported["export_contract"]["complete"])
        self.assertEqual(len(exported["context_delivery_ack_tombstones"]), 1)

    def test_export_is_snapshot_consistent_and_redacts_active_receipts(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            self._publish(store, 1)
            delivery = self._lease(store, limit=1, now=100.0)["deliveries"][0]
            original_list_events = store.list_context_events
            concurrent_event_id: list[int] = []

            def publish_during_export(**kwargs):
                concurrent = self._publish(store, 2)
                concurrent_event_id.append(concurrent["event_id"])
                return original_list_events(**kwargs)

            with mock.patch.object(
                store,
                "list_context_events",
                side_effect=publish_during_export,
            ):
                exported = store.export_json(context_id=self.context_id)
            actual_events = store.list_context_events(
                context_id=self.context_id,
                limit=10,
            )

        self.assertEqual(len(concurrent_event_id), 1)
        self.assertEqual(len(exported["context_events"]), 1)
        self.assertEqual(len(actual_events), 2)
        self.assertTrue(exported["export_contract"]["complete"])
        self.assertEqual(
            exported["export_contract"]["snapshot_consistency"],
            "sqlite-read-transaction",
        )
        serialized = json.dumps(exported, sort_keys=True)
        self.assertNotIn(delivery["receipt_id"], serialized)
        self.assertIn("receipt_digest", serialized)


if __name__ == "__main__":
    unittest.main()

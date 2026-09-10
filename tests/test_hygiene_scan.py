from __future__ import annotations

import hashlib
import json
from pathlib import Path
import threading
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from typing import Any, Callable

import hygiene_scan
from hygiene_scan import HygieneScanError, HygieneScanManager

CONTEXT = "ctx-alpha"


def make_entry(
    index: int,
    *,
    context_id: str = CONTEXT,
    source_text: str | None = None,
    tag: str | None = None,
    created_at: float | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "memory_id": f"mem-{index:04d}",
        "context_id": context_id,
        "tag": tag if tag is not None else f"tag-{index:04d}",
        "source_text": (
            source_text
            if source_text is not None
            else f"unique memory text number {index} with distinct details"
        ),
        "created_at": 1_000.0 + index if created_at is None else created_at,
        "updated_at": 2_000.0 + index,
        "metadata": metadata or {},
    }


class FakeClock:
    def __init__(self, now: float = 1_700_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)


class FakePagedBackend:
    """Temporary paged fake honoring the compact list_memory contract."""

    def __init__(self, entries: list[dict[str, Any]], *, revision: str = "rev-1") -> None:
        self.entries = list(entries)
        self.revision = revision
        self.calls: list[dict[str, Any]] = []
        self.contract_violations: list[str] = []
        self.cursors: dict[str, int] = {}
        self.cursor_counter = 0
        self.page_hook: Callable[[dict[str, Any], int], dict[str, Any] | None] | None = None
        self.pre_page_hook: Callable[[int], None] | None = None
        self.raise_on_call: tuple[int, Exception] | None = None

    def _check_contract(self, kwargs: dict[str, Any]) -> None:
        limit = kwargs.get("limit")
        checks = {
            "include_global must be False": kwargs.get("include_global") is False,
            "include_vectors must be False": kwargs.get("include_vectors") is False,
            "recall_scope must be local": kwargs.get("recall_scope") == "local",
            "response_mode must be compact": kwargs.get("response_mode") == "compact",
            "limit must be int in 1..500": type(limit) is int and 1 <= limit <= 500,
            "cursor must be a known or empty string": (
                kwargs.get("cursor") == "" or kwargs.get("cursor") in self.cursors
            ),
        }
        for message, passed in checks.items():
            if not passed:
                self.contract_violations.append(message)

    def list_memory(self, **kwargs: Any) -> dict[str, Any]:
        call_index = len(self.calls)
        self.calls.append(dict(kwargs))
        self._check_contract(kwargs)
        if self.pre_page_hook is not None:
            self.pre_page_hook(call_index)
        if self.raise_on_call is not None and call_index == self.raise_on_call[0]:
            raise self.raise_on_call[1]

        cursor = str(kwargs.get("cursor") or "")
        offset = self.cursors.get(cursor, 0) if cursor else 0
        limit = int(kwargs["limit"])
        total = len(self.entries)
        page_entries = [dict(entry) for entry in self.entries[offset : offset + limit]]
        count = len(page_entries)
        has_more = offset + count < total
        next_cursor = None
        if has_more:
            self.cursor_counter += 1
            next_cursor = f"cursor-{self.revision}-{self.cursor_counter:04d}"
            self.cursors[next_cursor] = offset + count
        payload: dict[str, Any] = {
            "context_id": kwargs.get("context_id"),
            "entry_count": count,
            "entries": page_entries,
            "_retrieval_page": {
                "schema": "retrieval-page/v2",
                "surface": "memory-list",
                "response_mode": "compact",
                "snapshot_revision": self.revision,
                "filters_sha256": "0" * 64,
                "ordering": "updated_at-desc,memory_id-desc",
                "total": {"entries": total},
                "returned": {"entries": count},
                "has_more": has_more,
                "next_cursor": next_cursor,
                "expires_at": 0,
                "origin_node": "fake-node",
            },
        }
        if self.page_hook is not None:
            hooked = self.page_hook(payload, call_index)
            if hooked is not None:
                payload = hooked
        return payload


class HygieneScanManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()

    def _manager(self, backend: FakePagedBackend, **kwargs: Any) -> HygieneScanManager:
        kwargs.setdefault("time_source", self.clock)
        return HygieneScanManager(backend, **kwargs)

    def _run_to_terminal(
        self,
        manager: HygieneScanManager,
        token: str,
        *,
        context: str = CONTEXT,
        max_steps: int = 100,
    ) -> dict[str, Any]:
        for _ in range(max_steps):
            report = manager.advance_scan(scan_token=token, context_id=context)
            if report["state"] != "running":
                return report
        self.fail("scan did not reach a terminal state")

    def _assert_contract(self, backend: FakePagedBackend) -> None:
        self.assertEqual(backend.contract_violations, [])
        for call in backend.calls:
            self.assertIs(call["include_global"], False)
            self.assertEqual(call["context_id"], CONTEXT)

    # ------------------------------------------------------------------
    # Happy path and progress accounting
    # ------------------------------------------------------------------

    def test_complete_scan_reports_no_findings_in_complete_scan_with_scope(self) -> None:
        backend = FakePagedBackend([make_entry(i) for i in range(7)])
        manager = self._manager(backend, page_limit=3)
        started = manager.start_scan(context_id=CONTEXT)
        token = started["scan_token"]
        self.assertEqual(started["state"], "running")
        self.assertEqual(started["scanned_entry_count"], 0)
        self.assertTrue(started["provisional"])
        self.assertNotIn("calculated_at", started)

        first = manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(first["state"], "running")
        self.assertEqual(first["scanned_entry_count"], 3)
        self.assertEqual(first["total_entry_count"], 7)
        self.assertAlmostEqual(first["scanned_fraction"], 3 / 7, places=5)
        self.assertFalse(first["scan_complete"])
        self.assertTrue(first["provisional"])

        final = self._run_to_terminal(manager, token)
        self.assertEqual(final["state"], "complete")
        self.assertTrue(final["scan_complete"])
        self.assertFalse(final["provisional"])
        self.assertEqual(final["scanned_entry_count"], 7)
        self.assertEqual(final["scanned_fraction"], 1.0)
        self.assertEqual(final["category_counts"], {})
        self.assertEqual(final["duplicate_candidates"], [])
        self.assertTrue(final["no_findings_in_complete_scan"])
        self.assertNotIn("clean_namespace", final)
        self.assertFalse(final["entry_classifier_configured"])
        self.assertFalse(final["core_availability_assessed"])
        self.assertFalse(final["cleanup_preservation_verified"])
        self.assertEqual(final["retained_state_budget_kind"], "estimated-payload-and-fixed-record-overhead")
        self.assertEqual(final["calculated_at"], self.clock.now)
        self.assertEqual(
            final["scope"],
            {
                "scan_kind": "exact-namespace",
                "context_id": CONTEXT,
                "snapshot_revision": "rev-1",
                "include_global": False,
                "recall_scope": "local",
            },
        )
        self.assertEqual(len(backend.calls), 3)
        self._assert_contract(backend)

        with self.assertRaises(HygieneScanError) as raised:
            manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(raised.exception.code, "scan-not-running")
        self.assertFalse(raised.exception.restart_required)

    def test_empty_namespace_completes_immediately_and_is_clean(self) -> None:
        backend = FakePagedBackend([])
        manager = self._manager(backend)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        report = manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(report["state"], "complete")
        self.assertEqual(report["total_entry_count"], 0)
        self.assertEqual(report["scanned_fraction"], 1.0)
        self.assertTrue(report["no_findings_in_complete_scan"])
        self.assertIn("calculated_at", report)
        self.assertIn("scope", report)
        self._assert_contract(backend)

    def test_status_reports_progress_without_backend_calls(self) -> None:
        backend = FakePagedBackend([make_entry(i) for i in range(9)])
        manager = self._manager(backend, page_limit=4)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        advanced = manager.advance_scan(scan_token=token, context_id=CONTEXT)
        calls_after_advance = len(backend.calls)
        status = manager.scan_status(scan_token=token, context_id=CONTEXT)
        again = manager.scan_status(scan_token=token, context_id=CONTEXT)
        self.assertEqual(len(backend.calls), calls_after_advance)
        self.assertEqual(status["scanned_entry_count"], advanced["scanned_entry_count"])
        self.assertEqual(again["state"], "running")

    # ------------------------------------------------------------------
    # Duplicate grouping and survivor mapping
    # ------------------------------------------------------------------

    def test_duplicates_across_page_boundary_and_beyond_250(self) -> None:
        straddle_text = "the same straddling note captured twice verbatim"
        deep_text = "an identical observation recorded early and again very late"
        entries = []
        for index in range(260):
            if index in {49, 50}:
                entries.append(make_entry(index, source_text=straddle_text))
            elif index in {4, 254}:
                entries.append(make_entry(index, source_text=deep_text))
            else:
                entries.append(make_entry(index))
        backend = FakePagedBackend(entries)
        manager = self._manager(backend, page_limit=50, max_entries_per_scan=1_000)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]

        manager.advance_scan(scan_token=token, context_id=CONTEXT)
        midway = manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(midway["scanned_entry_count"], 100)
        self.assertEqual(midway["duplicate_candidate_count"], 1)
        straddle = midway["duplicate_candidates"][0]
        self.assertEqual(straddle["memory_id"], "mem-0050")
        self.assertEqual(straddle["duplicate_of_memory_id"], "mem-0049")
        self.assertTrue(straddle["provisional"])

        final = self._run_to_terminal(manager, token)
        self.assertEqual(final["state"], "complete")
        self.assertEqual(final["scanned_entry_count"], 260)
        self.assertEqual(final["duplicate_candidate_count"], 2)
        self.assertEqual(final["category_counts"], {"duplicate_candidate": 2})
        self.assertFalse(final["no_findings_in_complete_scan"])
        by_candidate = {
            item["memory_id"]: item for item in final["duplicate_candidates"]
        }
        self.assertEqual(set(by_candidate), {"mem-0050", "mem-0254"})
        deep = by_candidate["mem-0254"]
        self.assertEqual(deep["duplicate_of_memory_id"], "mem-0004")
        self.assertEqual(deep["duplicate_of_tag"], "tag-0004")
        self.assertEqual(deep["duplicate_group_count"], 2)
        self.assertEqual(
            deep["duplicate_match"], "same-context-normalized-whole-source-text"
        )
        for item in final["duplicate_candidates"]:
            self.assertFalse(item["provisional"])
        expected_group_id = hashlib.sha256(
            ("memory-ids:" + "\0".join(["mem-0004", "mem-0254"])).encode("utf-8")
        ).hexdigest()[:12]
        self.assertEqual(deep["duplicate_group_id"], expected_group_id)
        self._assert_contract(backend)

    def test_grouping_uses_whole_normalized_text_never_prefixes(self) -> None:
        entries = [
            make_entry(0, source_text="alpha beta gamma"),
            make_entry(1, source_text="alpha beta gamma delta"),
            make_entry(2, source_text="  Alpha  BETA   gamma "),
            make_entry(3, source_text=""),
            make_entry(4, source_text="   "),
        ]
        backend = FakePagedBackend(entries)
        manager = self._manager(backend, page_limit=10)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        final = self._run_to_terminal(manager, token)
        self.assertEqual(final["state"], "complete")
        self.assertEqual(final["duplicate_candidate_count"], 1)
        candidate = final["duplicate_candidates"][0]
        self.assertEqual(candidate["memory_id"], "mem-0002")
        self.assertEqual(candidate["duplicate_of_memory_id"], "mem-0000")

    def test_truncated_scan_keeps_provisional_mapping_and_never_claims_clean(
        self,
    ) -> None:
        duplicated = "duplicated inside the scanned window"
        entries = [make_entry(i) for i in range(30)]
        entries[1] = make_entry(1, source_text=duplicated)
        entries[2] = make_entry(2, source_text=duplicated)
        backend = FakePagedBackend(entries)
        manager = self._manager(backend, page_limit=10, max_entries_per_scan=10)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        report = manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(report["state"], "truncated")
        self.assertEqual(report["scanned_entry_count"], 10)
        self.assertEqual(report["total_entry_count"], 30)
        self.assertFalse(report["scan_complete"])
        self.assertTrue(report["provisional"])
        self.assertFalse(report["no_findings_in_complete_scan"])
        self.assertNotIn("calculated_at", report)
        self.assertNotIn("scope", report)
        self.assertEqual(report["duplicate_candidate_count"], 1)
        self.assertTrue(report["duplicate_candidates"][0]["provisional"])
        with self.assertRaises(HygieneScanError) as raised:
            manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(raised.exception.code, "scan-not-running")

    # ------------------------------------------------------------------
    # Revision changes and backend exceptions fail closed
    # ------------------------------------------------------------------

    def test_revision_change_requires_restart_and_stays_failed(self) -> None:
        backend = FakePagedBackend([make_entry(i) for i in range(10)])

        def mutate(call_index: int) -> None:
            if call_index == 1:
                backend.revision = "rev-2"

        backend.pre_page_hook = mutate
        manager = self._manager(backend, page_limit=4)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        manager.advance_scan(scan_token=token, context_id=CONTEXT)
        with self.assertRaises(HygieneScanError) as raised:
            manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(raised.exception.code, "restart-required")
        self.assertTrue(raised.exception.restart_required)

        with self.assertRaises(HygieneScanError) as again:
            manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(again.exception.code, "scan-not-running")
        self.assertTrue(again.exception.restart_required)

        status = manager.scan_status(scan_token=token, context_id=CONTEXT)
        self.assertEqual(status["state"], "failed")
        self.assertEqual(status["failure_code"], "restart-required")
        self.assertFalse(status["scan_complete"])
        self.assertFalse(status["no_findings_in_complete_scan"])
        self.assertEqual(status["duplicate_candidates"], [])
        self.assertEqual(status["category_counts"], {})

    def test_backend_exception_maps_to_restart_required(self) -> None:
        backend = FakePagedBackend([make_entry(i) for i in range(10)])
        backend.raise_on_call = (1, RuntimeError("retrieval snapshot is stale"))
        manager = self._manager(backend, page_limit=4)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        manager.advance_scan(scan_token=token, context_id=CONTEXT)
        with self.assertRaises(HygieneScanError) as raised:
            manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(raised.exception.code, "restart-required")
        self.assertTrue(raised.exception.restart_required)

    # ------------------------------------------------------------------
    # Token privacy: expired, wrong-context, unknown are indistinguishable
    # ------------------------------------------------------------------

    def test_expired_wrong_context_and_unknown_tokens_look_identical(self) -> None:
        backend = FakePagedBackend([make_entry(i) for i in range(4)])
        manager = self._manager(backend, session_ttl_seconds=100)

        expired_token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        self.clock.advance(101)
        with self.assertRaises(HygieneScanError) as expired:
            manager.advance_scan(scan_token=expired_token, context_id=CONTEXT)

        live_token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        with self.assertRaises(HygieneScanError) as wrong_context:
            manager.advance_scan(scan_token=live_token, context_id="ctx-other")
        with self.assertRaises(HygieneScanError) as wrong_status:
            manager.scan_status(scan_token=live_token, context_id="ctx-other")
        with self.assertRaises(HygieneScanError) as unknown:
            manager.advance_scan(scan_token="not-a-real-token", context_id=CONTEXT)

        messages = {
            str(expired.exception),
            str(wrong_context.exception),
            str(wrong_status.exception),
            str(unknown.exception),
        }
        self.assertEqual(len(messages), 1)
        codes = {
            expired.exception.code,
            wrong_context.exception.code,
            wrong_status.exception.code,
            unknown.exception.code,
        }
        self.assertEqual(codes, {"invalid-token"})
        # The live token still works in its own context after the probe.
        report = manager.advance_scan(scan_token=live_token, context_id=CONTEXT)
        self.assertEqual(report["context_id"], CONTEXT)

    def test_discard_frees_capacity_and_invalidates_token(self) -> None:
        backend = FakePagedBackend([make_entry(i) for i in range(3)])
        manager = self._manager(backend, max_sessions=2)
        first = manager.start_scan(context_id=CONTEXT)["scan_token"]
        manager.start_scan(context_id=CONTEXT)
        with self.assertRaises(HygieneScanError) as raised:
            manager.start_scan(context_id=CONTEXT)
        self.assertEqual(raised.exception.code, "session-capacity")
        manager.discard_scan(scan_token=first, context_id=CONTEXT)
        manager.start_scan(context_id=CONTEXT)
        with self.assertRaises(HygieneScanError) as gone:
            manager.scan_status(scan_token=first, context_id=CONTEXT)
        self.assertEqual(gone.exception.code, "invalid-token")

    def test_discard_during_advance_is_rejected_without_clearing_findings(self) -> None:
        backend = FakePagedBackend([make_entry(i) for i in range(2)])
        manager = self._manager(backend, page_limit=1)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        manager.advance_scan(scan_token=token, context_id=CONTEXT)
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        backend.pre_page_hook = lambda _: (entered.set(), release.wait(2))
        results = []
        thread = threading.Thread(
            target=lambda: results.append(manager.advance_scan(scan_token=token, context_id=CONTEXT)),
        )
        thread.start()
        self.assertTrue(entered.wait(1))
        with self.assertRaises(HygieneScanError) as raised:
            manager.discard_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(raised.exception.code, "advance-in-progress")
        self.assertIn(token, manager._sessions)
        release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["scanned_entry_count"], 2)
        manager.discard_scan(scan_token=token, context_id=CONTEXT)
        with self.assertRaises(HygieneScanError):
            manager.scan_status(scan_token=token, context_id=CONTEXT)

    def test_terminal_sessions_are_evicted_to_allow_repeated_explicit_restarts(self) -> None:
        for terminal in ("complete", "failed", "truncated"):
            with self.subTest(terminal=terminal):
                entries = [make_entry(0)]
                if terminal == "failed":
                    entries[0]["metadata"] = "invalid"
                elif terminal == "truncated":
                    entries.append(make_entry(1))
                backend = FakePagedBackend(entries)
                manager = self._manager(backend, max_sessions=2, max_entries_per_scan=1)
                old_tokens = []
                for _ in range(6):
                    token = manager.start_scan(context_id=CONTEXT)["scan_token"]
                    old_tokens.append(token)
                    if terminal == "failed":
                        with self.assertRaises(HygieneScanError):
                            manager.advance_scan(scan_token=token, context_id=CONTEXT)
                    else:
                        manager.advance_scan(scan_token=token, context_id=CONTEXT)
                    self.assertEqual(manager.scan_status(scan_token=token, context_id=CONTEXT)["state"], terminal)
                    self.assertLessEqual(len(manager._sessions), 2)
                with self.assertRaises(HygieneScanError) as raised:
                    manager.scan_status(scan_token=old_tokens[0], context_id=CONTEXT)
                self.assertEqual(raised.exception.code, "invalid-token")

    def test_capacity_eviction_preserves_active_scans(self) -> None:
        backend = FakePagedBackend([make_entry(i) for i in range(3)])
        manager = self._manager(backend, page_limit=1, max_sessions=2)
        active = manager.start_scan(context_id=CONTEXT)["scan_token"]
        manager.advance_scan(scan_token=active, context_id=CONTEXT)
        terminal = manager.start_scan(context_id=CONTEXT)["scan_token"]
        self._run_to_terminal(manager, terminal)
        replacement = manager.start_scan(context_id=CONTEXT)["scan_token"]
        self.assertEqual(manager.scan_status(scan_token=active, context_id=CONTEXT)["state"], "running")
        self.assertEqual(manager.scan_status(scan_token=replacement, context_id=CONTEXT)["state"], "running")
        with self.assertRaises(HygieneScanError) as raised:
            manager.start_scan(context_id=CONTEXT)
        self.assertEqual(raised.exception.code, "session-capacity")

    def test_expiry_during_backend_page_never_revives_session_or_returns_findings(self) -> None:
        backend = FakePagedBackend([make_entry(i) for i in range(2)])
        manager = self._manager(backend, page_limit=1, session_ttl_seconds=1, max_sessions=1)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        manager.advance_scan(scan_token=token, context_id=CONTEXT)
        retained = manager._sessions[token]
        capacity_errors = []

        def expire(_):
            self.clock.advance(2)
            try:
                manager.start_scan(context_id=CONTEXT)
            except HygieneScanError as exc:
                capacity_errors.append(exc.code)

        backend.pre_page_hook = expire
        with self.assertRaises(HygieneScanError) as raised:
            manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(raised.exception.code, "invalid-token")
        self.assertEqual(capacity_errors, ["session-capacity"])
        self.assertNotIn(token, manager._sessions)
        self.assertEqual(retained.state, "expired")
        self.assertEqual(retained.groups, {})
        self.assertEqual(retained.seen_memory_ids, set())
        self.assertIsNotNone(manager.start_scan(context_id=CONTEXT)["scan_token"])

    def test_discard_between_resolution_and_session_lock_prevents_any_backend_call(self) -> None:
        backend = FakePagedBackend([make_entry(0)])
        manager = self._manager(backend)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        stale_reference = manager._sessions[token]
        manager.discard_scan(scan_token=token, context_id=CONTEXT)
        with patch.object(manager, "_resolve_session", return_value=stale_reference):
            with self.assertRaises(HygieneScanError) as raised:
                manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(raised.exception.code, "invalid-token")
        self.assertEqual(backend.calls, [])

    def test_malformed_record_fields_fail_closed_instead_of_reporting_no_findings(self) -> None:
        malformed = (
            ("memory_id", 123), ("memory_id", "x" * 201),
            ("source_text", {"unexpected": "object"}), ("source_text", None),
            ("tag", ["bad"]), ("metadata", "invalid"),
            ("metadata", {"confidence": float("nan")}),
            ("created_at", "invalid"), ("created_at", True),
            ("updated_at", float("inf")), ("updated_at", -1),
        )
        for field, value in malformed:
            with self.subTest(field=field, value=value):
                entry = make_entry(0)
                entry[field] = value
                backend = FakePagedBackend([entry])
                manager = self._manager(backend)
                token = manager.start_scan(context_id=CONTEXT)["scan_token"]
                with self.assertRaises(HygieneScanError) as raised:
                    manager.advance_scan(scan_token=token, context_id=CONTEXT)
                self.assertEqual(raised.exception.code, "invalid-page")
                status = manager.scan_status(scan_token=token, context_id=CONTEXT)
                self.assertFalse(status["no_findings_in_complete_scan"])
                self.assertNotIn("clean_namespace", status)
                self.assertEqual(status["duplicate_candidates"], [])

    def test_context_and_token_types_are_not_coerced(self) -> None:
        backend = FakePagedBackend([make_entry(0)])
        manager = self._manager(backend)
        for context in (1, None, [CONTEXT], " " + CONTEXT, "bad\ncontext"):
            with self.subTest(context=context), self.assertRaises(HygieneScanError) as raised:
                manager.start_scan(context_id=context)
            self.assertEqual(raised.exception.code, "invalid-context")
        with self.assertRaises(HygieneScanError) as raised:
            manager.advance_scan(scan_token=[], context_id=CONTEXT)
        self.assertEqual(raised.exception.code, "invalid-token")
        self.assertEqual(backend.calls, [])

    def test_default_survivor_preserves_session_boundary_copy_across_pages(self) -> None:
        text = "SYNAPSE-S2 MCP client session ended. Session: one."
        backend = FakePagedBackend([
            make_entry(0, source_text=text, tag="cortex-one", created_at=100),
            make_entry(1, source_text=text, tag="client-session-boundary-event-one", created_at=200),
        ])
        manager = self._manager(backend, page_limit=1)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        final = self._run_to_terminal(manager, token)
        self.assertEqual(final["duplicate_candidates"][0]["memory_id"], "mem-0000")
        self.assertEqual(final["duplicate_candidates"][0]["duplicate_of_memory_id"], "mem-0001")

    # ------------------------------------------------------------------
    # Overlapping advances are rejected deterministically
    # ------------------------------------------------------------------

    def test_overlapping_advance_is_rejected(self) -> None:
        backend = FakePagedBackend([make_entry(i) for i in range(6)])
        manager = self._manager(backend, page_limit=3)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        overlap_errors: list[HygieneScanError] = []

        def reenter(call_index: int) -> None:
            if call_index == 0:
                try:
                    manager.advance_scan(scan_token=token, context_id=CONTEXT)
                except HygieneScanError as exc:
                    overlap_errors.append(exc)

        backend.pre_page_hook = reenter
        report = manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(report["state"], "running")
        self.assertEqual(report["scanned_entry_count"], 3)
        self.assertEqual(len(overlap_errors), 1)
        self.assertEqual(overlap_errors[0].code, "advance-in-progress")

    # ------------------------------------------------------------------
    # Malformed pages fail closed and stay failed
    # ------------------------------------------------------------------

    def _expect_page_failure(
        self,
        *,
        entries: list[dict[str, Any]],
        tamper_factory: Callable[
            [FakePagedBackend], Callable[[dict[str, Any], int], dict[str, Any] | None]
        ],
        expected_code: str,
        page_limit: int = 5,
    ) -> HygieneScanError:
        backend = FakePagedBackend(entries)
        backend.page_hook = tamper_factory(backend)
        manager = self._manager(backend, page_limit=page_limit)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        error: HygieneScanError | None = None
        for _ in range(10):
            try:
                report = manager.advance_scan(scan_token=token, context_id=CONTEXT)
            except HygieneScanError as exc:
                error = exc
                break
            if report["state"] != "running":
                break
        self.assertIsNotNone(error, "malformed page did not fail the scan")
        assert error is not None
        self.assertEqual(error.code, expected_code)
        with self.assertRaises(HygieneScanError) as still_failed:
            manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(still_failed.exception.code, "scan-not-running")
        status = manager.scan_status(scan_token=token, context_id=CONTEXT)
        self.assertEqual(status["state"], "failed")
        self.assertFalse(status["no_findings_in_complete_scan"])
        self.assertEqual(status["duplicate_candidates"], [])
        return error

    def test_malformed_page_responses_fail_closed(self) -> None:
        base = [make_entry(i) for i in range(12)]

        def missing_page(_backend: FakePagedBackend):
            def tamper(payload: dict[str, Any], call_index: int):
                if call_index == 0:
                    payload.pop("_retrieval_page")
                return payload

            return tamper

        def wrong_surface(_backend: FakePagedBackend):
            def tamper(payload: dict[str, Any], call_index: int):
                if call_index == 0:
                    payload["_retrieval_page"]["surface"] = "memory-graph"
                return payload

            return tamper

        def returned_mismatch(_backend: FakePagedBackend):
            def tamper(payload: dict[str, Any], call_index: int):
                if call_index == 0:
                    payload["_retrieval_page"]["returned"]["entries"] += 1
                return payload

            return tamper

        def duplicate_id_in_page(_backend: FakePagedBackend):
            def tamper(payload: dict[str, Any], call_index: int):
                if call_index == 0:
                    payload["entries"][1]["memory_id"] = payload["entries"][0][
                        "memory_id"
                    ]
                return payload

            return tamper

        def repeated_id_across_pages(_backend: FakePagedBackend):
            def tamper(payload: dict[str, Any], call_index: int):
                if call_index == 1:
                    payload["entries"][0] = dict(base[0])
                return payload

            return tamper

        def total_changes(_backend: FakePagedBackend):
            def tamper(payload: dict[str, Any], call_index: int):
                if call_index == 1:
                    payload["_retrieval_page"]["total"]["entries"] += 1
                return payload

            return tamper

        def more_without_cursor(_backend: FakePagedBackend):
            def tamper(payload: dict[str, Any], call_index: int):
                if call_index == 0:
                    payload["_retrieval_page"]["next_cursor"] = None
                return payload

            return tamper

        def more_beyond_total(_backend: FakePagedBackend):
            def tamper(payload: dict[str, Any], call_index: int):
                page = payload["_retrieval_page"]
                if not page["has_more"]:
                    page["has_more"] = True
                    page["next_cursor"] = "cursor-beyond-total"
                return payload

            return tamper

        def out_of_scope_entry(_backend: FakePagedBackend):
            def tamper(payload: dict[str, Any], call_index: int):
                if call_index == 0:
                    payload["entries"][0]["context_id"] = "global"
                return payload

            return tamper

        def repeated_cursor(backend: FakePagedBackend):
            def tamper(payload: dict[str, Any], call_index: int):
                if call_index == 1 and payload["_retrieval_page"]["has_more"]:
                    payload["_retrieval_page"]["next_cursor"] = backend.calls[1][
                        "cursor"
                    ]
                return payload

            return tamper

        def returned_beyond_limit(_backend: FakePagedBackend):
            def tamper(payload: dict[str, Any], call_index: int):
                if call_index == 0:
                    payload["entries"].append(make_entry(900))
                    payload["_retrieval_page"]["returned"]["entries"] += 1
                return payload

            return tamper

        cases: list[tuple[str, Any, str]] = [
            ("missing retrieval page", missing_page, "invalid-page"),
            ("wrong surface", wrong_surface, "invalid-page"),
            ("returned count mismatch", returned_mismatch, "invalid-page"),
            ("duplicate id within page", duplicate_id_in_page, "invalid-page"),
            ("repeated id across pages", repeated_id_across_pages, "invalid-page"),
            ("total changed mid-scan", total_changes, "restart-required"),
            ("has_more without cursor", more_without_cursor, "invalid-page"),
            ("has_more past total", more_beyond_total, "invalid-page"),
            ("entry outside namespace", out_of_scope_entry, "invalid-page"),
            ("repeated cursor", repeated_cursor, "invalid-page"),
            ("returned beyond requested limit", returned_beyond_limit, "invalid-page"),
        ]
        for name, factory, expected_code in cases:
            with self.subTest(case=name):
                error = self._expect_page_failure(
                    entries=[dict(entry) for entry in base],
                    tamper_factory=factory,
                    expected_code=expected_code,
                )
                if expected_code == "restart-required":
                    self.assertTrue(error.restart_required)

    # ------------------------------------------------------------------
    # Budgets
    # ------------------------------------------------------------------

    def test_state_byte_budget_fails_closed(self) -> None:
        duplicated = "repeatedly captured identical text for budget pressure"
        entries = [
            make_entry(i, source_text=duplicated, tag="t" * 120) for i in range(40)
        ]
        backend = FakePagedBackend(entries)
        manager = self._manager(backend, page_limit=50, max_state_bytes=1_024)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        with self.assertRaises(HygieneScanError) as raised:
            manager.advance_scan(scan_token=token, context_id=CONTEXT)
        self.assertEqual(raised.exception.code, "state-budget-exceeded")
        status = manager.scan_status(scan_token=token, context_id=CONTEXT)
        self.assertEqual(status["state"], "failed")
        self.assertFalse(status["no_findings_in_complete_scan"])

    # ------------------------------------------------------------------
    # No raw content or content digests ever leave the manager
    # ------------------------------------------------------------------

    def test_reports_never_contain_source_text_or_content_digests(self) -> None:
        secret = "api_key=super-secret-payload-value that must never surface"
        entries = [
            make_entry(0, source_text=secret),
            make_entry(1, source_text=secret),
            make_entry(2, source_text="other note mentioning nothing at index 2"),
        ]
        backend = FakePagedBackend(entries)
        manager = self._manager(backend, page_limit=2)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        reports = [manager.advance_scan(scan_token=token, context_id=CONTEXT)]
        reports.append(manager.advance_scan(scan_token=token, context_id=CONTEXT))
        normalized = hygiene_scan.normalize_whole_source_text(secret)
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        for report in reports:
            dumped = json.dumps(report)
            self.assertNotIn(secret, dumped)
            self.assertNotIn("source_text", dumped)
            self.assertNotIn(digest, dumped)
            self.assertNotIn(digest[:12], dumped)
        retained_groups = manager._sessions[token].groups
        self.assertNotIn(secret, repr(retained_groups))
        for members in retained_groups.values():
            for member in members:
                self.assertEqual(set(member), {"memory_id", "tag", "sort_key"})
        final = reports[-1]
        self.assertEqual(final["state"], "complete")
        self.assertEqual(final["duplicate_candidate_count"], 1)
        candidate = final["duplicate_candidates"][0]
        self.assertEqual(candidate["duplicate_of_memory_id"], "mem-0000")
        self.assertEqual(
            candidate["duplicate_group_id"],
            hashlib.sha256(
                ("memory-ids:" + "\0".join(["mem-0000", "mem-0001"])).encode("utf-8")
            ).hexdigest()[:12],
        )

    def test_reported_candidate_list_is_bounded_but_counts_stay_exact(self) -> None:
        entries = [
            make_entry(0, source_text="first duplicated body"),
            make_entry(1, source_text="first duplicated body"),
            make_entry(2, source_text="second duplicated body"),
            make_entry(3, source_text="second duplicated body"),
        ]
        backend = FakePagedBackend(entries)
        manager = self._manager(backend, max_reported_candidates=1)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        final = self._run_to_terminal(manager, token)
        self.assertEqual(final["state"], "complete")
        self.assertEqual(final["duplicate_candidate_count"], 2)
        self.assertEqual(len(final["duplicate_candidates"]), 1)
        self.assertTrue(final["duplicate_candidates_truncated"])
        self.assertEqual(final["category_counts"], {"duplicate_candidate": 2})

    # ------------------------------------------------------------------
    # Caller-provided callbacks
    # ------------------------------------------------------------------

    def test_classifier_callback_feeds_category_counts(self) -> None:
        entries = [
            make_entry(0, metadata={"confidence": 0.4}),
            make_entry(1, metadata={"confidence": 0.9}),
            make_entry(2, metadata={"confidence": 0.2}),
        ]

        def classify(entry: dict[str, Any]) -> list[str]:
            confidence = float(entry.get("metadata", {}).get("confidence") or 1.0)
            return ["low_confidence_trace"] if confidence < 0.6 else []

        backend = FakePagedBackend(entries)
        manager = self._manager(backend, classify_entry=classify)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        final = self._run_to_terminal(manager, token)
        self.assertEqual(final["state"], "complete")
        self.assertEqual(final["category_counts"], {"low_confidence_trace": 2})
        self.assertFalse(final["no_findings_in_complete_scan"])

    def test_failing_or_reserved_category_classifier_fails_closed(self) -> None:
        entries = [make_entry(0)]
        for classify in (
            lambda entry: (_ for _ in ()).throw(ValueError("boom")),
            lambda entry: ["duplicate_candidate"],
        ):
            backend = FakePagedBackend([dict(entry) for entry in entries])
            manager = self._manager(backend, classify_entry=classify)
            token = manager.start_scan(context_id=CONTEXT)["scan_token"]
            with self.assertRaises(HygieneScanError) as raised:
                manager.advance_scan(scan_token=token, context_id=CONTEXT)
            self.assertEqual(raised.exception.code, "callback-failed")

    def test_custom_survivor_sort_key_selects_preferred_survivor(self) -> None:
        text = "one session close recorded by two writers"
        entries = [
            make_entry(0, source_text=text, tag="cortex-close", created_at=100.0),
            make_entry(
                1,
                source_text=text,
                tag="client-session-boundary-event-1",
                created_at=200.0,
            ),
        ]

        def survivor_key(entry: dict[str, Any]) -> tuple[Any, ...]:
            tag = str(entry.get("tag") or "")
            return (
                0 if tag.startswith("client-session-boundary-event-") else 1,
                float(entry.get("created_at") or 0.0),
                str(entry.get("memory_id") or ""),
            )

        backend = FakePagedBackend(entries)
        manager = self._manager(backend, survivor_sort_key=survivor_key)
        token = manager.start_scan(context_id=CONTEXT)["scan_token"]
        final = self._run_to_terminal(manager, token)
        candidate = final["duplicate_candidates"][0]
        self.assertEqual(candidate["memory_id"], "mem-0000")
        self.assertEqual(candidate["duplicate_of_memory_id"], "mem-0001")
        self.assertEqual(
            candidate["duplicate_of_tag"], "client-session-boundary-event-1"
        )


class HygieneScanBackendIntegrationTests(unittest.TestCase):
    def test_real_compact_pages_preserve_whole_text_and_detect_changed_snapshot(self):
        from mlx_backend import SpikingAttentionBackend

        with TemporaryDirectory() as directory:
            backend = SpikingAttentionBackend(
                dimension=32, num_neurons=24, default_top_k=6, recall_count=8,
                compile_graph=False, state_path=Path(directory) / "runtime_state.json",
                embedding_provider_name="semantic-hash",
            )
            try:
                for index, text in enumerate(("same whole memory", "a different memory", "same whole memory")):
                    backend.register_trace(
                        tag=f"hygiene-test-{index}", embedding=backend.embed_text(text),
                        context_id=CONTEXT, source_text=text,
                    )
                manager = HygieneScanManager(backend, page_limit=1)
                token = manager.start_scan(context_id=CONTEXT)["scan_token"]
                for _ in range(3):
                    final = manager.advance_scan(scan_token=token, context_id=CONTEXT)
                self.assertTrue(final["scan_complete"])
                self.assertEqual(final["scanned_entry_count"], 3)
                self.assertEqual(final["duplicate_candidate_count"], 1)
                self.assertFalse(final["no_findings_in_complete_scan"])
                self.assertEqual(final["duplicate_candidates"][0]["duplicate_match"], "same-context-normalized-whole-source-text")

                token = manager.start_scan(context_id=CONTEXT)["scan_token"]
                manager.advance_scan(scan_token=token, context_id=CONTEXT)
                backend.register_trace(
                    tag="hygiene-test-new", embedding=backend.embed_text("new memory"),
                    context_id=CONTEXT, source_text="new memory",
                )
                with self.assertRaises(HygieneScanError) as raised:
                    manager.advance_scan(scan_token=token, context_id=CONTEXT)
                self.assertEqual(raised.exception.code, "restart-required")
                self.assertTrue(raised.exception.restart_required)
                self.assertFalse(manager.scan_status(scan_token=token, context_id=CONTEXT)["scan_complete"])
            finally:
                backend.memory_store.close()


if __name__ == "__main__":
    unittest.main()

import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from namespace_enrichment import (
    LINK_PREFIX,
    PROPOSAL_PREFIX,
    NamespaceEnrichmentManager,
    NamespaceRevisionObserver,
    RevisionSnapshot,
    RevisionUnavailable,
)


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class RevisionSource:
    def __init__(self, clock):
        self.clock = clock
        self.revision = "a" * 64
        self.sequence = 0
        self.valid_until = None
        self.calls = 0
        self.fail_on = set()
        self.lock = threading.Lock()

    def __call__(self):
        with self.lock:
            self.calls += 1
            if self.calls in self.fail_on:
                raise RevisionUnavailable("private revision failure detail")
            self.sequence += 1
            return RevisionSnapshot(
                self.revision, self.sequence, self.clock(), self.valid_until,
            )


def empty_map(**kwargs):
    return {"selected_context_id": kwargs["context_id"], "nodes": [], "links": []}


class NamespaceRevisionObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "memory ?#%.sqlite3"
        self.clock = Clock()
        self.writer = self.create_database(self.path)
        self.addCleanup(self.writer.close)
        self.observer = NamespaceRevisionObserver(self.path, clock=self.clock)
        self.addCleanup(self.observer.close)

    @staticmethod
    def create_database(path):
        connection = sqlite3.connect(path, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE store_metadata(key TEXT PRIMARY KEY, value_json TEXT)")
        connection.execute("CREATE TABLE memory_entries(memory_id TEXT PRIMARY KEY, source_text TEXT)")
        connection.execute("INSERT INTO memory_entries VALUES ('one', 'first')")
        return connection

    def metadata(self, key, data):
        self.writer.execute(
            "INSERT OR REPLACE INTO store_metadata VALUES (?, ?)", (key, json.dumps(data)),
        )

    def test_constructor_and_missing_database_do_not_create_files(self):
        missing = Path(self.temp.name) / "missing" / "db.sqlite3"
        observer = NamespaceRevisionObserver(missing)
        self.addCleanup(observer.close)
        self.assertFalse(missing.parent.exists())
        with self.assertRaises(RevisionUnavailable):
            observer.snapshot()
        self.assertFalse(missing.parent.exists())

    def test_stable_reads_and_in_place_content_or_metadata_commits_invalidate(self):
        with patch.object(self.observer, "_read_expiries", wraps=self.observer._read_expiries) as expiry:
            first = self.observer.snapshot()
            again = self.observer.snapshot()
            self.assertEqual(first.revision, again.revision)
            self.assertGreater(again.sequence, first.sequence)
            self.assertEqual(expiry.call_count, 1)
            self.writer.execute("UPDATE memory_entries SET source_text='second' WHERE memory_id='one'")
            changed = self.observer.snapshot()
            self.assertNotEqual(first.revision, changed.revision)
            self.metadata("unrelated.revision", {"same_count": "changed"})
            metadata_changed = self.observer.snapshot()
            self.assertNotEqual(changed.revision, metadata_changed.revision)
            self.assertEqual(expiry.call_count, 3)

    def test_observer_is_query_only_and_new_connections_have_distinct_revisions(self):
        first = self.observer.snapshot()
        self.assertEqual(self.observer._connection.execute("PRAGMA query_only").fetchone()[0], 1)
        with self.assertRaises(sqlite3.OperationalError):
            self.observer._connection.execute("DELETE FROM memory_entries")
        another = NamespaceRevisionObserver(self.path, clock=self.clock)
        self.addCleanup(another.close)
        self.assertNotEqual(first.revision, another.snapshot().revision)
        self.assertEqual(self.writer.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0], 1)

    def test_file_identity_change_reopens_observer(self):
        # Use rollback journals for replacement: do not reuse the old WAL path.
        self.writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.writer.execute("PRAGMA journal_mode=DELETE")
        first = self.observer.snapshot()
        self.writer.close()
        replacement = self.path.with_name("replacement.sqlite3")
        other = self.create_database(replacement)
        other.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        other.execute("PRAGMA journal_mode=DELETE")
        other.close()
        os.replace(replacement, self.path)
        self.assertNotEqual(first.revision, self.observer.snapshot().revision)

    def test_symlink_and_closed_observer_fail_closed(self):
        link = self.path.with_name("link.sqlite3")
        link.symlink_to(self.path)
        observer = NamespaceRevisionObserver(link)
        self.addCleanup(observer.close)
        with self.assertRaises(RevisionUnavailable):
            observer.snapshot()
        self.observer.close()
        with self.assertRaises(RevisionUnavailable):
            self.observer.snapshot()

    def test_expiry_and_clock_reversal_change_revision_without_writes(self):
        self.metadata(PROPOSAL_PREFIX + "one", {"state": "pending", "proposal_expires_at": 1002})
        self.metadata(LINK_PREFIX + "two", {"state": "approved", "link_expires_at": 1004})
        first = self.observer.snapshot()
        self.assertEqual(first.valid_until, 1002)
        self.clock.now = 1002
        expired = self.observer.snapshot()
        self.assertNotEqual(first.revision, expired.revision)
        self.assertEqual(expired.valid_until, 1004)
        self.clock.now = 1004
        all_expired = self.observer.snapshot()
        self.assertNotEqual(expired.revision, all_expired.revision)
        self.assertIsNone(all_expired.valid_until)
        self.clock.now = 1001
        self.assertEqual(first.revision, self.observer.snapshot().revision)

    def test_malformed_or_unbounded_expiry_metadata_never_yields_revision(self):
        invalid = [
            {"state": "pending"},
            {"state": "unexpected", "proposal_expires_at": 1002},
            {"state": "pending", "proposal_expires_at": "1002"},
            {"state": "pending", "proposal_expires_at": -1},
            {"state": "pending", "proposal_expires_at": True},
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                self.metadata(PROPOSAL_PREFIX + "one", payload)
                with self.assertRaises(RevisionUnavailable):
                    self.observer.snapshot()
        self.writer.execute("UPDATE store_metadata SET value_json='invalid json'")
        with self.assertRaises(RevisionUnavailable):
            self.observer.snapshot()
        self.metadata(PROPOSAL_PREFIX + "one", {"state": "pending", "proposal_expires_at": 1002})
        self.metadata(PROPOSAL_PREFIX + "two", {"state": "pending", "proposal_expires_at": 1003})
        with patch("namespace_enrichment.MAX_EXPIRY_ROWS", 1):
            with self.assertRaises(RevisionUnavailable):
                self.observer.snapshot()


class NamespaceEnrichmentManagerTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.monotonic = Clock(0.0)
        self.source = RevisionSource(self.clock)
        self.calls = []

    def calculate(self, **kwargs):
        self.calls.append(kwargs)
        return empty_map(**kwargs)

    def manager(self, **kwargs):
        manager = NamespaceEnrichmentManager(
            revision_source=kwargs.pop("revision_source", self.source),
            calculate=kwargs.pop("calculate", self.calculate),
            clock=self.clock, monotonic=self.monotonic, **kwargs,
        )
        self.addCleanup(manager.close)
        return manager

    def settled(self, manager, context="default", options=None):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status = manager.status(context_id=context, options=options)
            if status["state"] not in {"queued", "running"}:
                return status
            time.sleep(0.002)
        self.fail("namespace job did not settle")

    def run_job(self, manager, context="default", options=None):
        manager.start(context_id=context, options=options)
        return self.settled(manager, context, options)

    def blocking_calculate(self):
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def calculate(**kwargs):
            self.calls.append(kwargs)
            entered.set()
            if not release.wait(3):
                raise RuntimeError("test release was not signaled")
            return empty_map(**kwargs)

        return calculate, entered, release

    def test_status_is_memory_only_and_initialization_never_starts_analysis(self):
        manager = self.manager()
        for _ in range(4):
            result = manager.status(context_id="default")
            self.assertEqual(result["state"], "stale")
            self.assertEqual(result["error_code"], "not_requested")
        self.assertEqual(self.source.calls, 0)
        self.assertEqual(self.calls, [])

    def test_explicit_analysis_is_revision_keyed_and_response_is_detached(self):
        manager = self.manager()
        result = self.run_job(manager)
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["calculated_at"], self.clock())
        self.assertTrue(self.calls[0]["include_density_metrics"])
        self.assertTrue(self.calls[0]["include_suggestions"])
        result["data"]["nodes"].append({"private": "client mutation"})
        cached = self.run_job(manager)
        self.assertEqual(cached["state"], "ready")
        self.assertTrue(cached["cache_hit"])
        self.assertNotEqual(result["job_id"], cached["job_id"])
        self.assertEqual(cached["data"]["nodes"], [])
        self.assertEqual(len(self.calls), 1)
        before_status_reads = self.source.calls
        manager.status(context_id="default")
        self.assertEqual(self.source.calls, before_status_reads)

    def test_context_and_options_isolate_results_and_cache(self):
        manager = self.manager()
        self.run_job(manager)
        other = self.run_job(manager, "other")
        self.assertEqual(other["data"]["selected_context_id"], "other")
        options = {"include_suggestions": False, "limit": 10}
        different = self.run_job(manager, options=options)
        self.assertFalse(different["cache_hit"])
        self.assertFalse(self.calls[-1]["include_suggestions"])
        self.assertEqual(self.calls[-1]["limit"], 10)
        self.assertEqual(len(self.calls), 3)
        self.assertTrue(self.run_job(manager)["cache_hit"])
        self.assertEqual(self.run_job(manager, "")["state"], "ready")

    def test_only_one_job_runs_and_repeated_same_request_is_idempotent(self):
        calculate, entered, release = self.blocking_calculate()
        manager = self.manager(calculate=calculate)
        first = manager.start(context_id="default")
        self.assertTrue(entered.wait(1))
        same = manager.start(context_id="default")
        other = manager.start(context_id="other")
        self.assertEqual(same["job_id"], first["job_id"])
        self.assertEqual(other["state"], "busy")
        self.assertEqual(other["error_code"], "another_job_active")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.source.calls, 1)
        release.set()
        self.assertEqual(self.settled(manager)["state"], "ready")

    def test_revision_changes_during_analysis_discard_result_and_allow_explicit_retry(self):
        calculate, entered, release = self.blocking_calculate()
        manager = self.manager(calculate=calculate)
        manager.start(context_id="default")
        self.assertTrue(entered.wait(1))
        self.source.revision = "b" * 64
        manager.observe_revision(self.source())
        release.set()
        result = self.settled(manager)
        self.assertEqual(result["state"], "stale")
        self.assertEqual(result["error_code"], "revision_changed")
        self.assertIsNone(result["data"])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.run_job(manager)["state"], "ready")
        self.assertEqual(len(self.calls), 2)

    def test_new_lightweight_observation_invalidates_cache_and_older_observation_cannot_revert(self):
        manager = self.manager()
        self.run_job(manager)
        older = self.source()
        self.source.revision = "b" * 64
        newer = self.source()
        manager.observe_revision(newer)
        manager.observe_revision(older)
        result = manager.status(context_id="default")
        self.assertEqual(result["state"], "stale")
        self.assertIsNone(result["data"])
        self.assertEqual(self.run_job(manager)["state"], "ready")
        self.assertEqual(len(self.calls), 2)

    def test_freshness_ttl_and_failed_observation_suppress_ready_data(self):
        manager = self.manager()
        self.run_job(manager)
        self.clock.now += 16
        self.assertEqual(manager.status(context_id="default")["error_code"], "revision_stale")
        manager.observe_revision(self.source())
        self.assertEqual(manager.status(context_id="default")["state"], "ready")
        older = self.source()
        self.clock.now += 1
        manager.invalidate_revision()
        manager.observe_revision(older)
        self.assertEqual(manager.status(context_id="default")["error_code"], "revision_unavailable")
        manager.observe_revision(self.source())
        self.assertEqual(manager.status(context_id="default")["state"], "ready")
        self.assertEqual(len(self.calls), 1)

    def test_expiry_and_clock_reversal_suppress_cached_data(self):
        self.source.valid_until = 1002
        manager = self.manager()
        self.run_job(manager)
        self.clock.now = 1002
        self.assertEqual(manager.status(context_id="default")["state"], "stale")
        self.assertIsNone(manager.status(context_id="default")["data"])
        self.clock.now = 999
        self.assertEqual(manager.status(context_id="default")["state"], "stale")

    def test_analysis_failure_is_sanitized_and_only_explicit_start_retries(self):
        attempts = []

        def calculate(**kwargs):
            attempts.append(kwargs)
            if len(attempts) == 1:
                raise RuntimeError("secret=never-serialize-this")
            return empty_map(**kwargs)

        manager = self.manager(calculate=calculate)
        result = self.run_job(manager)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["error_code"], "enrichment_failed")
        self.assertNotIn("never-serialize", json.dumps(result))
        manager.status(context_id="default")
        self.assertEqual(len(attempts), 1)
        self.assertEqual(self.run_job(manager)["state"], "ready")
        self.assertEqual(len(attempts), 2)

    def test_before_and_after_revision_failure_never_publish_or_cache(self):
        for fail_on in (1, 2):
            with self.subTest(fail_on=fail_on):
                source = RevisionSource(self.clock)
                source.fail_on.add(fail_on)
                calls = []

                def calculate(**kwargs):
                    calls.append(kwargs)
                    return empty_map(**kwargs)

                manager = self.manager(revision_source=source, calculate=calculate)
                result = self.run_job(manager)
                self.assertEqual(result["state"], "stale")
                self.assertEqual(result["error_code"], "revision_unavailable")
                self.assertIsNone(result["data"])
                self.assertEqual(len(calls), fail_on - 1)
                self.assertEqual(self.run_job(manager)["state"], "ready")
                self.assertEqual(len(calls), fail_on)

    def test_output_context_and_size_are_bounded(self):
        manager = self.manager(calculate=lambda **kwargs: {"selected_context_id": "other"})
        self.assertEqual(self.run_job(manager)["error_code"], "context_mismatch")
        oversized = self.manager(max_result_bytes=20)
        self.assertEqual(self.run_job(oversized)["error_code"], "result_exceeds_bound")

    def test_deadline_keeps_busy_slot_until_callback_returns_and_rejects_late_output(self):
        calculate, entered, release = self.blocking_calculate()
        manager = self.manager(calculate=calculate, max_duration_seconds=5)
        manager.start(context_id="default")
        self.assertTrue(entered.wait(1))
        self.monotonic.now = 6
        status = manager.status(context_id="default")
        self.assertEqual(status["state"], "running")
        self.assertTrue(status["deadline_exceeded"])
        self.assertEqual(manager.start(context_id="other")["state"], "busy")
        release.set()
        result = self.settled(manager)
        self.assertEqual(result["error_code"], "duration_exceeded")
        self.assertIsNone(result["data"])

    def test_cache_capacity_evicts_results_instead_of_growing_without_bound(self):
        manager = self.manager(max_cached_entries=2)
        for context in ("one", "two", "three"):
            self.assertEqual(self.run_job(manager, context)["state"], "ready")
        self.assertEqual(manager.status(context_id="one")["error_code"], "not_requested")
        self.assertFalse(self.run_job(manager, "one")["cache_hit"])
        self.assertEqual(len(self.calls), 4)

    def test_close_releases_revision_source_and_discards_late_completion(self):
        calculate, entered, release = self.blocking_calculate()
        closed = []
        manager = self.manager(calculate=calculate, close_revision_source=lambda: closed.append(True))
        manager.start(context_id="default")
        self.assertTrue(entered.wait(1))
        manager.close()
        self.assertEqual(closed, [True])
        self.assertEqual(manager.start(context_id="other")["error_code"], "closed")
        release.set()
        deadline = time.monotonic() + 1
        while manager._active is not None and time.monotonic() < deadline:
            time.sleep(0.002)
        self.assertIsNone(manager._active)
        self.assertIsNone(manager.status(context_id="default")["data"])

    def test_invalid_requests_are_rejected_without_revision_reads_or_analysis(self):
        manager = self.manager()
        for options in (
            {"unknown": True}, {"limit": 2001}, {"limit": True},
            {"include_suggestions": "true"}, {"min_suggestion_score": float("nan")},
            {"suggestion_limit": 101}, {"max_visual_phase_delay_ticks": 5},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                manager.start(context_id="default", options=options)
        for context in (" default", "../default", "x" * 129):
            with self.subTest(context=context), self.assertRaises(ValueError):
                manager.start(context_id=context)
        self.assertEqual(self.source.calls, 0)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()

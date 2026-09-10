"""Behavioral integration for explicit, bounded dashboard analysis."""

import json
import threading
import time
import unittest
from unittest import mock

from dashboard_server import DashboardRuntime, SynapseDashboardServer
from namespace_enrichment import RevisionSnapshot, RevisionUnavailable


class DashboardAnalysisTests(unittest.TestCase):
    def decode(self, response):
        status, _, body = response
        self.assertEqual(status, 200, body)
        return json.loads(body)

    @staticmethod
    def paged_backend(total=302):
        backend = mock.Mock()

        def page(**args):
            offset = int(args["cursor"] or "0")
            stop = min(total, offset + args["limit"])
            entries = [
                {
                    "memory_id": f"memory-{index}", "context_id": "demo",
                    "source_text": "same whole record" if index in (2, 301) else f"record {index}",
                    "tag": "scan-test", "metadata": {},
                    "created_at": float(index), "updated_at": float(index),
                }
                for index in range(offset, stop)
            ]
            return {"entries": entries, "_retrieval_page": {
                "surface": "memory-list", "response_mode": "compact",
                "snapshot_revision": "revision-one", "total": {"entries": total},
                "returned": {"entries": len(entries)}, "has_more": stop < total,
                "next_cursor": str(stop) if stop < total else None,
            }}

        backend.list_memory.side_effect = page
        return backend

    def test_hygiene_requires_each_page_and_covers_older_duplicates(self):
        backend = self.paged_backend()
        runtime = DashboardRuntime(backend)
        report = self.decode(runtime.handle("POST", "/api/memory-hygiene/scan", b'{"context_id":"demo"}'))
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["scanned_entry_count"], 50)
        self.assertFalse(report["no_findings_in_complete_scan"])
        self.assertEqual(backend.list_memory.call_count, 1)
        self.assertFalse(report["automatic_cleanup"])
        while not report["scan_complete"]:
            report = self.decode(runtime.handle("POST", "/api/memory-hygiene/scan", json.dumps({
                "context_id": "demo", "scan_id": report["scan_id"],
            }).encode()))
        self.assertEqual(report["scanned_entry_count"], 302)
        self.assertEqual(report["coverage_fraction"], 1)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["category_counts"]["duplicate_candidate"], 1)
        self.assertEqual(len(report["candidate_survivor_mapping"]), 1)
        self.assertFalse(report["candidate_survivor_mapping"][0]["provisional"])
        for call in backend.list_memory.call_args_list:
            self.assertFalse(call.kwargs["include_global"])
            self.assertEqual(call.kwargs["context_id"], "demo")
            self.assertLessEqual(call.kwargs["limit"], 50)
        backend.prune_memory.assert_not_called()

    def test_stale_hygiene_scan_reports_restart_instead_of_clean(self):
        backend = self.paged_backend()
        runtime = DashboardRuntime(backend)
        first = self.decode(runtime.handle("POST", "/api/memory-hygiene/scan", b'{"context_id":"demo"}'))
        backend.list_memory.side_effect = RuntimeError("snapshot changed")
        report = self.decode(runtime.handle("POST", "/api/memory-hygiene/scan", json.dumps({
            "context_id": "demo", "scan_id": first["scan_id"],
        }).encode()))
        self.assertEqual(report["status"], "restart_required")
        self.assertFalse(report["scan_complete"])
        self.assertNotIn("candidate_survivor_mapping", report)

    def test_expired_or_unknown_scan_token_offers_restart(self):
        backend = self.paged_backend()
        runtime = DashboardRuntime(backend)
        report = self.decode(runtime.handle("POST", "/api/memory-hygiene/scan", b'{"context_id":"demo","scan_id":"expired"}'))
        self.assertEqual(report["status"], "restart_required")
        self.assertEqual(report["error_code"], "invalid-token")
        self.assertFalse(report["scan_complete"])
        backend.list_memory.assert_not_called()

    def test_ordinary_map_is_lightweight_and_does_not_start_analysis(self):
        backend = mock.Mock()
        backend.list_namespace_map.return_value = {"nodes": []}
        runtime = DashboardRuntime(backend)
        self.decode(runtime.handle("GET", "/api/namespace-map?context_id=demo"))
        args = backend.list_namespace_map.call_args.kwargs
        self.assertFalse(args["include_density_metrics"])
        self.assertFalse(args["include_suggestions"])
        self.assertIsNone(runtime._namespace_enrichment)

    def test_status_is_memory_only_and_explicit_start_is_distinct(self):
        runtime = DashboardRuntime(mock.Mock())
        manager = mock.Mock()
        manager.status.return_value = {"state": "running", "context_id": "demo"}
        manager.start.return_value = {"state": "queued", "context_id": "demo"}
        runtime._namespace_enrichment = manager
        self.assertEqual(self.decode(runtime.handle("GET", "/api/namespace-enrichment?context_id=demo"))["state"], "running")
        manager.start.assert_not_called()
        runtime.backend.list_namespace_map.assert_not_called()
        self.assertEqual(self.decode(runtime.handle("POST", "/api/namespace-enrichment", b'{"context_id":"demo"}'))["state"], "queued")
        manager.start.assert_called_once_with(context_id="demo")

    def test_failed_revision_observation_invalidates_cached_analysis(self):
        runtime = DashboardRuntime(mock.Mock())
        runtime._namespace_enrichment = mock.Mock()
        runtime._namespace_revision_observer = mock.Mock()
        runtime._namespace_revision_observer.snapshot.side_effect = RevisionUnavailable("missing")
        runtime._observe_namespace_revision()
        runtime._namespace_enrichment.invalidate_revision.assert_called_once_with()

    def test_status_remains_available_while_analysis_owns_execution_lane(self):
        runtime = DashboardRuntime(mock.Mock())
        manager = mock.Mock()
        manager.status.return_value = {"state": "running", "context_id": "demo"}
        runtime._namespace_enrichment = manager
        server = SynapseDashboardServer(("127.0.0.1", 0), runtime)
        result = []
        thread = threading.Thread(target=lambda: result.append(server.handle_runtime_request(
            "GET", "/api/namespace-enrichment?context_id=demo", b"")))
        try:
            with runtime._execution_lock:
                thread.start()
                thread.join(timeout=1)
                self.assertFalse(thread.is_alive(), "status waited for the analysis lane")
            self.assertEqual(self.decode(result[0])["state"], "running")
        finally:
            thread.join(timeout=1)
            server.server_close()
        manager.close.assert_called_once_with()

    def test_second_start_returns_busy_without_waiting_for_analysis(self):
        runtime = DashboardRuntime(mock.Mock())
        manager = mock.Mock()
        manager.start.return_value = {"state": "busy", "context_id": "demo", "job_id": None}
        runtime._namespace_enrichment = manager
        server = SynapseDashboardServer(("127.0.0.1", 0), runtime)
        results = []
        thread = threading.Thread(target=lambda: results.append(server.handle_runtime_request(
            "POST", "/api/namespace-enrichment", b'{"context_id":"demo"}')))
        try:
            with runtime._execution_lock:
                thread.start()
                thread.join(timeout=1)
                self.assertFalse(thread.is_alive())
            self.assertEqual(self.decode(results[0])["state"], "busy")
        finally:
            thread.join(timeout=1)
            server.server_close()

    def test_closed_runtime_cannot_create_a_new_analysis_manager(self):
        runtime = DashboardRuntime(mock.Mock())
        runtime.close()
        with mock.patch("dashboard_server.NamespaceRevisionObserver") as observer:
            status, _, _ = runtime.handle("GET", "/api/namespace-enrichment?context_id=demo")
        self.assertEqual(status, 503)
        observer.assert_not_called()

    def test_queued_analysis_cannot_begin_backend_work_after_runtime_closes(self):
        backend = mock.Mock()
        runtime = DashboardRuntime(backend)
        self.addCleanup(runtime.close)
        observer = mock.Mock()
        observer.snapshot.return_value = RevisionSnapshot("a" * 64, 1, time.time(), None)
        with mock.patch("dashboard_server.NamespaceRevisionObserver", return_value=observer):
            manager = runtime._enrichment_manager()
        calculate = manager._calculate
        queued, returned = threading.Event(), threading.Event()

        def observe_queued_callback(**kwargs):
            queued.set()
            try:
                return calculate(**kwargs)
            finally:
                returned.set()

        with mock.patch.object(manager, "_calculate", side_effect=observe_queued_callback):
            with runtime._execution_lock:
                manager.start(context_id="demo")
                self.assertTrue(queued.wait(2), "analysis never reached the occupied lane")
                backend.list_namespace_map.assert_not_called()
                runtime.close()
            self.assertTrue(returned.wait(2), "closed analysis did not unwind")
        backend.list_namespace_map.assert_not_called()
        observer.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()

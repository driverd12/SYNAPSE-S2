from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "smoke_dashboard.py"
SPEC = importlib.util.spec_from_file_location("synapse_smoke_dashboard", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
smoke_dashboard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = smoke_dashboard
SPEC.loader.exec_module(smoke_dashboard)


class _Response:
    def __init__(self, body: bytes) -> None:
        self._body = io.BytesIO(body)

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body.read()


class DashboardSmokeTests(unittest.TestCase):
    def test_snapshot_timeout_has_cold_neural_headroom(self) -> None:
        self.assertGreater(smoke_dashboard.SNAPSHOT_HTTP_TIMEOUT_SECONDS, 30.0)
        self.assertLess(
            smoke_dashboard.SNAPSHOT_HTTP_TIMEOUT_SECONDS,
            smoke_dashboard.SMOKE_REQUEST_BUDGET_SECONDS,
        )

    def test_request_timeout_uses_stage_cap_when_budget_has_headroom(self) -> None:
        with mock.patch.object(smoke_dashboard.time, "monotonic", return_value=10.0):
            timeout = smoke_dashboard.request_timeout(
                deadline=100.0,
                stage_timeout=20.0,
                stage="graph",
            )

        self.assertEqual(timeout, 20.0)

    def test_request_timeout_clamps_to_remaining_whole_smoke_budget(self) -> None:
        with mock.patch.object(smoke_dashboard.time, "monotonic", return_value=74.5):
            timeout = smoke_dashboard.request_timeout(
                deadline=75.0,
                stage_timeout=20.0,
                stage="namespace map",
            )

        self.assertEqual(timeout, 0.5)

    def test_request_timeout_fails_before_request_after_budget_exhaustion(self) -> None:
        with mock.patch.object(smoke_dashboard.time, "monotonic", return_value=75.0):
            with self.assertRaisesRegex(
                TimeoutError,
                "budget exhausted before snapshot",
            ):
                smoke_dashboard.request_timeout(
                    deadline=75.0,
                    stage_timeout=60.0,
                    stage="snapshot",
                )

    def test_fetch_json_passes_explicit_timeout_and_headers(self) -> None:
        response = _Response(json.dumps({"ready": True}).encode("utf-8"))
        with mock.patch.object(
            smoke_dashboard.urllib.request,
            "urlopen",
            return_value=response,
        ) as urlopen:
            payload = smoke_dashboard.fetch_json(
                "http://127.0.0.1:8765/api/status",
                headers={"X-Synapse-Dashboard-Session": "session"},
                timeout=12.5,
            )

        self.assertEqual(payload, {"ready": True})
        request = urlopen.call_args.args[0]
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 12.5)
        self.assertEqual(
            request.get_header("X-synapse-dashboard-session"),
            "session",
        )

    def test_main_assigns_stage_specific_timeouts(self) -> None:
        server = mock.Mock()
        server.server_port = 18765
        thread = mock.Mock()
        snapshot = {
            "context_id": "default",
            "status": {
                "runtime": "ready",
                "memory_context_entry_count": 2,
                "memory_context_relationship_count": 3,
            },
            "profile": {"estimated_total_mb": 10.0},
        }
        graph = {"entries": [], "relationships": [], "entry_count": 0}
        namespace_map = {"nodes": [], "links": [], "node_count": 0}
        with (
            mock.patch.object(smoke_dashboard.sys, "argv", ["smoke_dashboard.py"]),
            mock.patch.object(smoke_dashboard.time, "monotonic", return_value=100.0),
            mock.patch.object(smoke_dashboard, "DashboardRuntime", return_value=mock.Mock()),
            mock.patch.object(
                smoke_dashboard,
                "SynapseDashboardServer",
                return_value=server,
            ),
            mock.patch.object(smoke_dashboard.threading, "Thread", return_value=thread),
            mock.patch.object(
                smoke_dashboard,
                "fetch_text",
                side_effect=["SYNAPSE-S2 Control", "Start Wizard", ".app-shell"],
            ) as fetch_text,
            mock.patch.object(
                smoke_dashboard,
                "bootstrap_session",
                return_value={"Cookie": "session"},
            ) as bootstrap,
            mock.patch.object(
                smoke_dashboard,
                "fetch_json",
                side_effect=[snapshot, graph, namespace_map],
            ) as fetch_json,
            mock.patch.object(smoke_dashboard.shutil, "which", return_value=None),
            mock.patch("sys.stdout", new=io.StringIO()),
        ):
            status = smoke_dashboard.main()

        self.assertEqual(status, 0)
        self.assertEqual(
            [call.kwargs["timeout"] for call in fetch_text.call_args_list],
            [5.0, 5.0, 5.0],
        )
        self.assertEqual(bootstrap.call_args.kwargs["timeout"], 5.0)
        self.assertEqual(
            [call.kwargs["timeout"] for call in fetch_json.call_args_list],
            [60.0, 20.0, 20.0],
        )
        thread.start.assert_called_once_with()
        server.shutdown.assert_called_once_with()
        server.server_close.assert_called_once_with()
        thread.join.assert_called_once_with(timeout=5)


if __name__ == "__main__":
    unittest.main()

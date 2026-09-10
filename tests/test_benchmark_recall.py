"""Benchmark evidence rejects scope drift and hides source data."""

import unittest
from unittest import mock

from scripts.benchmark_recall import (
    BenchmarkError,
    IDENTITY_FIELDS,
    number,
    project_health,
    project_namespaces,
)


class RecallBenchmarkEvidenceTests(unittest.TestCase):
    def test_health_requires_same_authority_and_production_readiness(self):
        client = mock.Mock()
        client.authority_identity = {key: "identity-1" for key in IDENTITY_FIELDS}
        payload = {
            "ready": True, "deployment_mode": "authoritative",
            "authority": {"ready": True}, "capture": {"ready": True, "last_success_age_ms": 20},
            "backend_lane": {"ready": True, "maintenance": False, "active": False},
        }
        client.health.return_value = payload
        observed = project_health(client)
        client.authority_identity["neural_epoch"] = "epoch-2"
        with self.assertRaisesRegex(BenchmarkError, "authority_identity_changed"):
            project_health(client, observed["identity"])
        payload["capture"]["ready"] = False
        with self.assertRaisesRegex(BenchmarkError, "production_health_not_ready"):
            project_health(client)

    def test_count_projection_drops_names_and_marks_bounded_inventory(self):
        payload = {"action": "list-namespace-map", "density_metrics_included": False,
                   "nodes": [{"context_id": "private-project-name", "entry_count": 7, "secret": "not exported"}]}
        projected = project_namespaces(payload)
        self.assertNotIn("private-project-name", str(projected))
        self.assertNotIn("not exported", str(projected))
        self.assertEqual(projected["observed_total_entries"], 7)
        payload["nodes"][0]["entry_count"] = True
        with self.assertRaises(BenchmarkError):
            project_namespaces(payload)

    def test_invalid_numeric_observations_cannot_become_timings(self):
        for value in (True, False, float("nan"), float("inf"), "12"):
            self.assertIsNone(number(value))
        self.assertEqual(number(12.5), 12.5)


if __name__ == "__main__":
    unittest.main()

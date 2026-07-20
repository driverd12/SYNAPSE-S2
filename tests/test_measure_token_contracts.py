from __future__ import annotations

import contextlib
import copy
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock


from memory_store import DurableMemoryStore
from scripts import measure_token_contracts as measurement


class TokenContractMeasurementTests(unittest.TestCase):
    @staticmethod
    def _populate_store(database_path: Path, *, context_id: str = "default") -> None:
        store = DurableMemoryStore(database_path)
        entries = []
        trace_types = ("goal", "constraint", "risk", "decision", "evidence")
        for index in range(60):
            trace_type = trace_types[index % len(trace_types)]
            entry = store.upsert_entry(
                tag=f"phase6-entry-{index:03d}",
                context_id=context_id,
                source_text=(
                    f"Bounded Phase 6 evidence sample {index:03d}. "
                    + "Memory provenance and deterministic contract evidence. " * 24
                ),
                metadata={
                    "source_surface": "phase6-unit",
                    "speaker": "test",
                    "cortex_governor": True,
                    "trace_type": trace_type,
                    "truth_posture": "verified",
                    "confidence": 0.9,
                    "title": f"Phase 6 trace {index:03d}",
                    "goal_state": "active",
                    "next_action": "Verify compact response boundaries.",
                },
                embedding_dimensions=32,
                spike_indices=[index % 32, (index + 3) % 32],
                neuron_indices=[index % 64, (index + 7) % 64],
                registered_at=1_700_000_000.0 + index,
            )
            entries.append(entry)
        for index in range(len(entries) - 1):
            store.upsert_relationship(
                context_id=context_id,
                source_memory_id=str(entries[index]["memory_id"]),
                target_memory_id=str(entries[index + 1]["memory_id"]),
                relation_type="phase6_related",
                weight=0.75,
                evidence={"method": "unit-fixture", "ordinal": index},
            )

    @staticmethod
    def _fake_surfaces() -> list[dict]:
        surfaces = []
        for name in (
            "memory-list",
            "memory-graph",
            "cortex-state",
            "agent-hydration",
        ):
            surfaces.append(
                {
                    "surface": name,
                    "requested_limit": 20,
                    "effective_limit": 8,
                    "installed_policy": {
                        "baseline": "legacy-requested-source",
                        "baseline_bytes": 1_000,
                        "compact_structured_bytes": 400,
                        "compact_safety_bytes": 200,
                        "reduction_bytes": 600,
                        "reduction_percent": 60.0,
                    },
                    "same_source": {
                        "baseline": "legacy-identical-source",
                        "baseline_bytes": 800,
                        "compact_structured_bytes": 400,
                        "compact_safety_bytes": 200,
                        "reduction_bytes": 400,
                        "reduction_percent": 50.0,
                    },
                    "full_diagnostic": {
                        "same_source_structured_bytes": 900,
                        "same_source_safety_bytes": 250,
                        "within_diagnostic_budget": True,
                    },
                    "contract": {
                        "schema": "synapse-s2.token-contract.v1",
                        "version": 1,
                        "profile": "compact",
                        "max_structured_bytes": 12_288,
                        "max_safety_bytes": 4_096,
                        "canonical_size_matches_declared": True,
                        "within_structured_budget": True,
                        "within_safety_budget": True,
                        "projection_deterministic": True,
                        "safety_summary_deterministic": True,
                        "truncated": False,
                        "omission_count": 0,
                        "omission_sections": [],
                        "completeness_known": False,
                        "completeness_reason": "authoritative-total-unavailable",
                        "provenance_present": True,
                        "public_boundary_stable": True,
                    },
                    "returned_counts": {"entries": 1},
                }
            )
        surfaces[-1]["delivery_safety"] = {
            "receipt_count": 8,
            "event_count": 8,
            "unique_receipt_count": 8,
            "unique_event_count": 8,
            "one_to_one": True,
            "ack_required": True,
        }
        return surfaces

    def test_real_restored_store_measurement_is_bounded_and_aggregate_only(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            live_db = root / "live" / "memory.sqlite3"
            live_db.parent.mkdir(mode=0o700)
            DurableMemoryStore(live_db).upsert_entry(
                tag="live-sentinel",
                context_id="default",
                source_text="Live state must remain unchanged.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1],
                neuron_indices=[1],
            )
            live_before = live_db.read_bytes()

            workspace = root / "disposable"
            workspace.mkdir(mode=0o700)
            restore_root = workspace / "isolated-restore"
            restore_root.mkdir(mode=0o700)
            restored_db = restore_root / "memory.sqlite3"
            restored_capture = restore_root / "capture-root"
            restored_capture.mkdir(mode=0o700)
            self._populate_store(restored_db)

            surfaces = measurement.measure_restored_database(
                database_path=restored_db,
                capture_root=restored_capture,
                workspace_root=workspace,
                context_id="default",
            )
            report = measurement._aggregate_report(
                surfaces=surfaces,
                recovery={
                    "bundle_verified": True,
                    "receipt_identity_trusted": True,
                    "isolated_restore_verified": True,
                    "cutover_ready": True,
                },
            )

            self.assertEqual(live_db.read_bytes(), live_before)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(len(report["surfaces"]), 4)
            self.assertTrue(all(report["gates"].values()))
            for surface in report["surfaces"]:
                self.assertLessEqual(
                    surface["installed_policy"]["compact_structured_bytes"],
                    measurement.INSTALLED_COMPACT_BYTES,
                )
                self.assertLessEqual(
                    surface["installed_policy"]["compact_safety_bytes"],
                    measurement.MCP_COMPACT_SAFETY_SUMMARY_BYTES,
                )
                self.assertTrue(
                    surface["full_diagnostic"]["within_diagnostic_budget"]
                )
            agent = next(
                item
                for item in report["surfaces"]
                if item["surface"] == "agent-hydration"
            )
            self.assertEqual(agent["delivery_safety"]["receipt_count"], 8)
            self.assertTrue(agent["delivery_safety"]["one_to_one"])
            rendered = json.dumps(report, sort_keys=True)
            self.assertNotIn(measurement.BENCHMARK_SECRET_CANARY, rendered)
            self.assertNotIn(measurement.BENCHMARK_PATH_CANARY, rendered)
            self.assertNotIn("ctxrcpt_", rendered)
            self.assertNotIn("s2mem_", rendered)
            measurement.assert_aggregate_only(report)

    def test_reduction_is_informational_not_an_acceptance_gate(self) -> None:
        surfaces = copy.deepcopy(self._fake_surfaces())
        for surface in surfaces:
            surface["installed_policy"].update(
                compact_structured_bytes=1_200,
                reduction_bytes=-200,
                reduction_percent=-20.0,
            )
            surface["same_source"].update(
                compact_structured_bytes=900,
                reduction_bytes=-100,
                reduction_percent=-12.5,
            )
        report = measurement._aggregate_report(
            surfaces=surfaces,
            recovery={
                "bundle_verified": True,
                "receipt_identity_trusted": True,
                "isolated_restore_verified": True,
                "cutover_ready": True,
            },
        )
        self.assertEqual(report["status"], "pass")
        self.assertTrue(all(report["gates"].values()))
        self.assertTrue(report["observations"]["reduction_is_informational"])
        self.assertFalse(
            report["observations"]["installed_policy_reduction_positive"]
        )
        self.assertFalse(report["observations"]["same_source_reduction_positive"])

    def test_orchestration_uses_private_temporary_restore_and_cleans_it(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            live_root = root / "live"
            live_root.mkdir(mode=0o700)
            live_db = live_root / "memory.sqlite3"
            DurableMemoryStore(live_db)
            receipt = live_root / "phase5.bundle.receipt.json"
            receipt.write_text("{}", encoding="utf-8")
            receipt.chmod(0o600)
            observed: dict[str, Path] = {}

            def fake_restore(
                receipt_path: Path,
                selected_live_db: Path,
                output_root: Path,
            ) -> dict:
                self.assertEqual(receipt_path, receipt.resolve())
                self.assertEqual(selected_live_db, live_db.resolve())
                observed["workspace"] = output_root.parent
                output_root.mkdir(mode=0o700)
                database = output_root / "memory.sqlite3"
                database.write_bytes(b"disposable")
                capture = output_root / "capture-root"
                capture.mkdir(mode=0o700)
                return {
                    "bundle_verified": True,
                    "receipt_identity_trusted": True,
                    "isolated_restore_verified": True,
                    "cutover_ready": True,
                    "database_path": database,
                    "capture_root": capture,
                }

            with mock.patch.object(
                measurement,
                "measure_restored_database",
                return_value=self._fake_surfaces(),
            ) as measured:
                report = measurement.run_acceptance_measurement(
                    receipt_path=receipt,
                    live_memory_db=live_db,
                    context_id="default",
                    restore_driver=fake_restore,
                )

            self.assertEqual(report["status"], "pass")
            self.assertFalse(observed["workspace"].exists())
            call = measured.call_args.kwargs
            self.assertNotEqual(call["database_path"], live_db.resolve())
            self.assertTrue(str(call["database_path"]).startswith(str(observed["workspace"])))

    def test_measurement_context_rejects_secret_and_control_material(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            live_db = root / "memory.sqlite3"
            DurableMemoryStore(live_db)
            receipt = root / "phase5.bundle.receipt.json"
            receipt.write_text("{}", encoding="utf-8")
            receipt.chmod(0o600)
            for invalid in (
                "password=synthetic-secret-1234",
                "bad\ncontext",
                "/Users/example/private/context",
            ):
                with self.subTest(invalid=invalid):
                    with self.assertRaisesRegex(
                        measurement.MeasurementError,
                        "valid public identifier",
                    ):
                        measurement.run_acceptance_measurement(
                            receipt_path=receipt,
                            live_memory_db=live_db,
                            context_id=invalid,
                            restore_driver=mock.Mock(),
                        )

    def test_parser_redacts_secret_bearing_errors(self) -> None:
        secret = "password=synthetic-secret-1234"
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit):
                measurement.build_parser().parse_args(
                    ["--receipt", "placeholder", "--unknown", secret]
                )
        self.assertNotIn(secret, stderr.getvalue())
        self.assertIn("[REDACTED_SECRET]", stderr.getvalue())

    def test_durable_evidence_requires_clean_tree_and_refuses_overwrite(self) -> None:
        report = measurement._aggregate_report(
            surfaces=self._fake_surfaces(),
            recovery={
                "bundle_verified": True,
                "receipt_identity_trusted": True,
                "isolated_restore_verified": True,
                "cutover_ready": True,
            },
        )
        with TemporaryDirectory() as temporary:
            repo = Path(temporary)
            output = repo / "evidence" / "phase6.json"
            with mock.patch.object(measurement, "_git_tree_is_clean", return_value=False):
                with self.assertRaisesRegex(measurement.MeasurementError, "dirty tree"):
                    measurement.write_durable_evidence(
                        report=report,
                        output_path=output,
                        repo_root=repo,
                    )
            with (
                mock.patch.object(
                    measurement,
                    "_git_tree_is_clean",
                    return_value=True,
                ),
                mock.patch.object(
                    measurement,
                    "_git_revision",
                    return_value="a" * 40,
                ),
            ):
                bound = measurement.write_durable_evidence(
                    report=report,
                    output_path=output,
                    repo_root=repo,
                )
                with self.assertRaisesRegex(
                    measurement.MeasurementError,
                    "already exists",
                ):
                    measurement.write_durable_evidence(
                        report=report,
                        output_path=output,
                        repo_root=repo,
                    )
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), bound)
            self.assertEqual(bound["source_control"]["revision"], "a" * 40)
            self.assertTrue(bound["source_control"]["clean_worktree"])

    def test_dirty_tree_bypass_is_test_mode_only(self) -> None:
        report = measurement._aggregate_report(
            surfaces=self._fake_surfaces(),
            recovery={
                "bundle_verified": True,
                "receipt_identity_trusted": True,
                "isolated_restore_verified": True,
                "cutover_ready": True,
            },
        )
        with TemporaryDirectory() as temporary:
            repo = Path(temporary)
            output = repo / "phase6.json"
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop(measurement.TEST_MODE_ENV, None)
                with self.assertRaisesRegex(measurement.MeasurementError, "test mode"):
                    measurement.write_durable_evidence(
                        report=report,
                        output_path=output,
                        repo_root=repo,
                        allow_dirty_test_only=True,
                    )
            with (
                mock.patch.dict(
                    os.environ,
                    {measurement.TEST_MODE_ENV: "1"},
                    clear=False,
                ),
                mock.patch.object(
                    measurement,
                    "_git_tree_is_clean",
                    return_value=False,
                ),
                mock.patch.object(
                    measurement,
                    "_git_revision",
                    return_value="b" * 40,
                ),
            ):
                bound = measurement.write_durable_evidence(
                    report=report,
                    output_path=output,
                    repo_root=repo,
                    allow_dirty_test_only=True,
                )
            self.assertTrue(output.is_file())
            self.assertFalse(bound["source_control"]["clean_worktree"])

    def test_durable_evidence_rejects_source_control_drift(self) -> None:
        report = measurement._aggregate_report(
            surfaces=self._fake_surfaces(),
            recovery={
                "bundle_verified": True,
                "receipt_identity_trusted": True,
                "isolated_restore_verified": True,
                "cutover_ready": True,
            },
        )
        with TemporaryDirectory() as temporary:
            repo = Path(temporary)
            output = repo / "phase6.json"
            with (
                mock.patch.object(
                    measurement,
                    "_git_tree_is_clean",
                    return_value=True,
                ),
                mock.patch.object(
                    measurement,
                    "_git_revision",
                    side_effect=["a" * 40, "b" * 40],
                ),
            ):
                with self.assertRaisesRegex(
                    measurement.MeasurementError,
                    "source control changed",
                ):
                    measurement.write_durable_evidence(
                        report=report,
                        output_path=output,
                        repo_root=repo,
                    )
            self.assertFalse(output.exists())

    def test_post_publication_drift_removes_only_our_evidence(self) -> None:
        report = measurement._aggregate_report(
            surfaces=self._fake_surfaces(),
            recovery={
                "bundle_verified": True,
                "receipt_identity_trusted": True,
                "isolated_restore_verified": True,
                "cutover_ready": True,
            },
        )
        with TemporaryDirectory() as temporary:
            repo = Path(temporary)
            output = repo / "phase6.json"
            with (
                mock.patch.object(
                    measurement,
                    "_git_tree_is_clean",
                    side_effect=[True, True, True, False],
                ),
                mock.patch.object(
                    measurement,
                    "_git_revision",
                    return_value="a" * 40,
                ),
            ):
                with self.assertRaisesRegex(
                    measurement.MeasurementError,
                    "worktree changed",
                ):
                    measurement.write_durable_evidence(
                        report=report,
                        output_path=output,
                        repo_root=repo,
                    )
            self.assertFalse(output.exists())

    def test_durable_evidence_never_replaces_a_racing_creator(self) -> None:
        report = measurement._aggregate_report(
            surfaces=self._fake_surfaces(),
            recovery={
                "bundle_verified": True,
                "receipt_identity_trusted": True,
                "isolated_restore_verified": True,
                "cutover_ready": True,
            },
        )
        with TemporaryDirectory() as temporary:
            repo = Path(temporary)
            output = repo / "phase6.json"
            real_link = os.link

            def racing_link(
                source: str,
                target: str,
                *,
                src_dir_fd: int,
                dst_dir_fd: int,
                follow_symlinks: bool,
            ) -> None:
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o644,
                    dir_fd=dst_dir_fd,
                )
                try:
                    os.write(descriptor, b"independent evidence\n")
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                real_link(
                    source,
                    target,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                    follow_symlinks=follow_symlinks,
                )

            with (
                mock.patch.object(
                    measurement,
                    "_git_tree_is_clean",
                    return_value=True,
                ),
                mock.patch.object(
                    measurement,
                    "_git_revision",
                    return_value="a" * 40,
                ),
                mock.patch.object(measurement.os, "link", side_effect=racing_link),
            ):
                with self.assertRaisesRegex(
                    measurement.MeasurementError,
                    "already exists",
                ):
                    measurement.write_durable_evidence(
                        report=report,
                        output_path=output,
                        repo_root=repo,
                    )
            self.assertEqual(output.read_bytes(), b"independent evidence\n")

    def test_durable_main_refuses_dirty_source_before_measurement(self) -> None:
        measured = mock.Mock()
        stdout = io.StringIO()
        with (
            mock.patch.object(
                measurement,
                "_repo_relative_output",
                return_value=(measurement.ROOT, Path("docs/evidence/phase6.json")),
            ),
            mock.patch.object(measurement, "_verify_import_attestation"),
            mock.patch.object(
                measurement,
                "_source_control_state",
                side_effect=measurement.MeasurementError(
                    "refusing durable evidence from a dirty tree"
                ),
            ),
            mock.patch.object(
                measurement,
                "run_acceptance_measurement",
                measured,
            ),
            contextlib.redirect_stdout(stdout),
        ):
            result = measurement.main(
                [
                    "--receipt",
                    "unused",
                    "--memory-db",
                    "unused",
                    "--output",
                    "docs/evidence/phase6.json",
                ]
            )
        self.assertEqual(result, 1)
        measured.assert_not_called()
        self.assertEqual(json.loads(stdout.getvalue())["status"], "failed")

    def test_durable_evidence_rejects_symlinked_parent_escape(self) -> None:
        report = measurement._aggregate_report(
            surfaces=self._fake_surfaces(),
            recovery={
                "bundle_verified": True,
                "receipt_identity_trusted": True,
                "isolated_restore_verified": True,
                "cutover_ready": True,
            },
        )
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            outside = root / "outside"
            repo.mkdir()
            outside.mkdir()
            (repo / "escaped").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(
                measurement.MeasurementError,
                "inside the repository",
            ):
                measurement.write_durable_evidence(
                    report=report,
                    output_path=repo / "escaped" / "phase6.json",
                    repo_root=repo,
                )
            self.assertFalse((outside / "phase6.json").exists())

    def test_durable_evidence_rejects_lexical_parent_escape(self) -> None:
        report = measurement._aggregate_report(
            surfaces=self._fake_surfaces(),
            recovery={
                "bundle_verified": True,
                "receipt_identity_trusted": True,
                "isolated_restore_verified": True,
                "cutover_ready": True,
            },
        )
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            with self.assertRaisesRegex(
                measurement.MeasurementError,
                "inside the repository",
            ):
                measurement.write_durable_evidence(
                    report=report,
                    output_path=repo / ".." / "escaped.json",
                    repo_root=repo,
                )

    def test_aggregate_filter_rejects_raw_identity_path_and_digest_material(self) -> None:
        forbidden = (
            {"memory_id": "s2mem_example"},
            {"value": "/Users/example/private.txt"},
            {"value": "a" * 64},
            {"value": "ctxrcpt_" + "A" * 43},
        )
        for payload in forbidden:
            with self.subTest(payload=payload):
                with self.assertRaises(measurement.MeasurementError):
                    measurement.assert_aggregate_only(payload)


if __name__ == "__main__":
    unittest.main()

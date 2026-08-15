from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

import dashboard_server
import mcp_server
import mlx_backend
import synapse_cli
from core_client import CoreClient


class RecoveryRouteSurfaceTests(unittest.TestCase):
    def _client(self, root: Path) -> CoreClient:
        return CoreClient(
            socket_path=root / "core" / "service.sock",
            state_path=root / "runtime_state.json",
            caller="surface-test",
        )

    def test_cli_omits_server_owned_fields_and_rejects_explicit_overrides(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = self._client(root)
            receipt = root / "backups" / "bundle.receipt.json"
            output_root = root / "recovery" / "proof"
            common = {
                "capture_root": None,
                "expected_database_sha256": None,
                "expected_capture_sha256": None,
                "expected_request_journal_sha256": None,
                "expected_runtime_state_sha256": None,
                "expected_media_sha256": None,
            }
            with mock.patch("synapse_cli.build_backend", return_value=client), mock.patch(
                "backend_router.build_maintenance_backend",
                return_value=client,
            ), mock.patch.object(
                client,
                "backup_recovery_bundle",
                return_value={"ok": True},
            ) as backup, mock.patch.object(
                client,
                "audit_capture_ledger",
                return_value={"ok": True},
            ) as audit, mock.patch.object(
                client,
                "repair_capture_ledger",
                return_value={"ok": True},
            ) as repair, mock.patch.object(
                client,
                "verify_recovery_bundle",
                return_value={"ok": True},
            ) as verify, mock.patch.object(
                client,
                "restore_recovery_bundle_isolated",
                return_value={"ok": True},
            ) as restore, mock.patch.object(
                client,
                "plan_recovery_retention",
                return_value={"ok": True},
            ) as plan, mock.patch.object(
                client,
                "apply_recovery_retention",
                return_value={"ok": True},
            ) as apply:
                synapse_cli.command_backup_recovery_bundle(
                    SimpleNamespace(
                        output=None,
                        capture_root=None,
                        purpose="cli",
                        pinned=True,
                        allow_noncanonical_capture_root=False,
                    )
                )
                synapse_cli.command_capture_ledger_integrity(
                    SimpleNamespace(
                        memory_db=None,
                        state=None,
                        capture_root=None,
                        repair=False,
                        confirm=False,
                        expected_revision=None,
                        sample_limit=5,
                    )
                )
                synapse_cli.command_capture_ledger_integrity(
                    SimpleNamespace(
                        memory_db=None,
                        state=None,
                        capture_root=None,
                        repair=True,
                        confirm=True,
                        expected_revision="a" * 64,
                        sample_limit=6,
                    )
                )
                synapse_cli.command_verify_recovery_bundle(
                    SimpleNamespace(receipt=str(receipt), **common)
                )
                synapse_cli.command_restore_recovery_bundle(
                    SimpleNamespace(
                        receipt=str(receipt),
                        output_root=str(output_root),
                        confirm=True,
                        **common,
                    )
                )
                synapse_cli.command_plan_recovery_retention(
                    SimpleNamespace(directory=None, keep_latest=4, max_age_days=10.0)
                )
                synapse_cli.command_apply_recovery_retention(
                    SimpleNamespace(
                        directory=None,
                        plan_token="b" * 64,
                        cutoff_created_at=123.0,
                        keep_latest=4,
                        max_age_days=10.0,
                        confirm=True,
                    )
                )

                with self.assertRaisesRegex(ValueError, "authoritative core"):
                    synapse_cli.command_backup_recovery_bundle(
                        SimpleNamespace(
                            output=None,
                            capture_root=str(root / "other"),
                            purpose="cli",
                            pinned=False,
                            allow_noncanonical_capture_root=False,
                        )
                    )
                with self.assertRaisesRegex(ValueError, "authoritative core"):
                    synapse_cli.command_plan_recovery_retention(
                        SimpleNamespace(
                            directory=str(root / "other"),
                            keep_latest=4,
                            max_age_days=10.0,
                        )
                    )

            backup.assert_called_once_with(path=None, purpose="cli", pinned=True)
            audit.assert_called_once_with(sample_limit=5)
            repair.assert_called_once_with(
                confirm=True,
                expected_revision="a" * 64,
                sample_limit=6,
            )
            verify.assert_called_once_with(
                str(receipt),
                expected_database_sha256=None,
                expected_capture_sha256=None,
                expected_request_journal_sha256=None,
                expected_runtime_state_sha256=None,
                expected_media_sha256=None,
            )
            restore.assert_called_once_with(
                str(receipt),
                str(output_root),
                expected_database_sha256=None,
                expected_capture_sha256=None,
                expected_request_journal_sha256=None,
                expected_runtime_state_sha256=None,
                expected_media_sha256=None,
                confirm=True,
            )
            plan.assert_called_once_with(keep_latest=4, max_age_days=10.0)
            apply.assert_called_once_with(
                plan_token="b" * 64,
                cutoff_created_at=123.0,
                keep_latest=4,
                max_age_days=10.0,
                confirm=True,
            )

    def test_module_wrappers_omit_server_owned_fields(self) -> None:
        with TemporaryDirectory() as temporary:
            client = self._client(Path(temporary))
            with mock.patch.object(
                mlx_backend,
                "_ENGINE_INSTANCE",
                client,
            ), mock.patch.object(
                mlx_backend,
                "_CONTROL_PLANE_INSTANCE",
                client,
            ), mock.patch.object(
                client,
                "call",
                side_effect=lambda operation, arguments: {
                    "operation": operation,
                    "arguments": arguments,
                },
            ) as call:
                mlx_backend.backup_recovery_bundle(purpose="module", pinned=True)
                mlx_backend.audit_capture_ledger(sample_limit=4)
                mlx_backend.repair_capture_ledger(
                    confirm=True,
                    expected_revision="a" * 64,
                    sample_limit=4,
                )
                mlx_backend.verify_recovery_bundle("/tmp/receipt.json")
                mlx_backend.restore_recovery_bundle_isolated(
                    "/tmp/receipt.json",
                    "/tmp/proof",
                    confirm=True,
                )
                mlx_backend.plan_recovery_retention(
                    keep_latest=2,
                    max_age_days=4.0,
                )
                mlx_backend.apply_recovery_retention(
                    plan_token="b" * 64,
                    cutoff_created_at=10.0,
                    keep_latest=2,
                    max_age_days=4.0,
                    confirm=True,
                )
                with self.assertRaisesRegex(ValueError, "authoritative core"):
                    mlx_backend.audit_capture_ledger(capture_root="/tmp/other")
                with self.assertRaisesRegex(ValueError, "authoritative core"):
                    mlx_backend.plan_recovery_retention(directory="/tmp/other")

            for recorded in call.call_args_list:
                arguments = recorded.args[1]
                self.assertNotIn("capture_root", arguments)
                self.assertNotIn("allow_noncanonical_capture_root", arguments)
                self.assertNotIn("directory", arguments)

    def test_dashboard_core_backup_uses_server_default_without_local_transport(self) -> None:
        with TemporaryDirectory() as temporary:
            client = self._client(Path(temporary))
            runtime = dashboard_server.DashboardRuntime(client)
            with mock.patch.object(
                client,
                "backup_recovery_bundle",
                return_value={"action": "backup-recovery-bundle"},
            ) as backup, mock.patch.object(
                runtime,
                "capture_daemon",
                side_effect=AssertionError("core backup must not touch client capture files"),
            ):
                status, _headers, body = runtime.handle("POST", "/api/backup", b"{}")

            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["action"], "backup-recovery-bundle")
            backup.assert_called_once_with(purpose="dashboard")

    def test_mcp_core_recovery_paths_use_authoritative_roots(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = self._client(root)
            module = SimpleNamespace(
                get_backend=lambda: client,
                backup_recovery_bundle=mock.Mock(return_value={"backup": True}),
                verify_recovery_bundle=mock.Mock(return_value={"verified": True}),
                restore_recovery_bundle_isolated=mock.Mock(
                    return_value={"restored": True}
                ),
                plan_recovery_retention=mock.Mock(return_value={"planned": True}),
                apply_recovery_retention=mock.Mock(return_value={"applied": True}),
            )
            receipt = root / "backups" / "bundle.receipt.json"
            restore_root = root / "recovery" / "proof"
            with mock.patch.object(
                mcp_server,
                "_load_backend",
                return_value=(None, module),
            ), mock.patch.object(
                mcp_server,
                "_load_capture_daemon",
                side_effect=AssertionError("core backup must not prepare local transport"),
            ):
                self.assertTrue(
                    json.loads(mcp_server.backup_spiking_recovery())["backup"]
                )
                self.assertTrue(
                    json.loads(
                        mcp_server.verify_spiking_recovery(str(receipt))
                    )["verified"]
                )
                self.assertTrue(
                    json.loads(
                        mcp_server.restore_spiking_recovery_proof(
                            str(receipt),
                            str(restore_root),
                            confirm=True,
                        )
                    )["restored"]
                )

            module.backup_recovery_bundle.assert_called_once_with(
                path=None,
                purpose="operator",
                pinned=False,
            )
            module.verify_recovery_bundle.assert_called_once_with(
                str(receipt),
                expected_database_sha256=None,
                expected_capture_sha256=None,
                expected_request_journal_sha256=None,
                expected_runtime_state_sha256=None,
                expected_media_sha256=None,
            )
            module.restore_recovery_bundle_isolated.assert_called_once_with(
                str(receipt),
                str(restore_root),
                expected_database_sha256=None,
                expected_capture_sha256=None,
                expected_request_journal_sha256=None,
                expected_runtime_state_sha256=None,
                expected_media_sha256=None,
                confirm=True,
            )


if __name__ == "__main__":
    unittest.main()

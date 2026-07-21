from __future__ import annotations

import json
import os
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import backend_router
import capture_daemon
import client_config
import mlx_backend
import synapse_cli
import transcript_capture
from core_client import CoreClient, CoreUnavailable
from core_client_binding import (
    BINDING_ENV,
    binding_for_config,
    write_core_client_binding,
)
from core_service import CoreConfig, write_core_config


class BackendRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous_engine = mlx_backend._ENGINE_INSTANCE
        self.previous_control = mlx_backend._CONTROL_PLANE_INSTANCE
        mlx_backend._ENGINE_INSTANCE = None
        mlx_backend._CONTROL_PLANE_INSTANCE = None
        self.addCleanup(self._restore_backend_instances)

    def _restore_backend_instances(self) -> None:
        mlx_backend._ENGINE_INSTANCE = self.previous_engine
        mlx_backend._CONTROL_PLANE_INSTANCE = self.previous_control

    @staticmethod
    def _write_candidate_binding(root: Path) -> tuple[Path, Path]:
        root = root.resolve()
        repo = root / "repo"
        data = repo / ".synapse_s2"
        core = data / "core"
        core.mkdir(parents=True, mode=0o700)
        config = CoreConfig(
            socket_path=core / "service.sock",
            state_path=data / "runtime_state.json",
            memory_path=data / "memory.sqlite3",
            capture_root=data,
            dimension=8,
            num_neurons=16,
            default_top_k=4,
        )
        write_core_config(core / "service.json", config)
        binding = binding_for_config(
            repo_root=repo,
            data_root=data,
            config=config,
            core_label="aero.boom.synapse-s2.core",
            authority_mode="candidate-local-v5",
        )
        binding_path = root / "home" / ".config" / "synapse-s2" / "core-binding.json"
        write_core_client_binding(binding_path, binding)
        return binding_path, data

    @staticmethod
    def _marker(
        *,
        service_required: bool,
        config_fingerprint: str = "a" * 64,
    ) -> dict[str, object]:
        timestamp = 1_800_000_000.0
        return {
            "schema_version": 1,
            "service_required": service_required,
            "epoch": 1,
            "instance_id": "core-routing-test",
            "config_fingerprint": config_fingerprint,
            "build_id": "build-routing-test",
            "protocol_version": "synapse-core.v1",
            "lock_generation_id": "lockfs-v1-1-2",
            "store_identity": "store-" + ("1" * 24),
            "request_journal_id": "journal-" + ("2" * 24),
            "request_journal_binding_schema": (
                "synapse-s2.request-journal-binding.v1"
            ),
            "request_journal_schema_version": 3,
            "root_generation_id": "generation-" + ("3" * 24),
            "embedding_space_identity": "b" * 64,
            "restored_target_binding_receipt_digest": None,
            "claimed_at": timestamp,
            "updated_at": timestamp,
        }

    @classmethod
    def _write_marker_database(
        cls,
        path: Path,
        *,
        service_required: bool,
        config_fingerprint: str = "a" * 64,
    ) -> None:
        marker = cls._marker(
            service_required=service_required,
            config_fingerprint=config_fingerprint,
        )
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "CREATE TABLE store_metadata "
                "(key TEXT PRIMARY KEY, value_json TEXT NOT NULL, "
                "updated_at REAL NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE store_migrations (key TEXT PRIMARY KEY)"
            )
            connection.execute(
                "INSERT INTO store_metadata (key, value_json, updated_at) "
                "VALUES (?, ?, ?)",
                (
                    "core_authority",
                    json.dumps(marker, sort_keys=True),
                    marker["updated_at"],
                ),
            )
            connection.execute(
                "INSERT INTO store_migrations (key) VALUES (?)",
                ("authoritative_core_v1",),
            )
            connection.execute("PRAGMA user_version = 6")
            connection.commit()

    def test_missing_database_detection_is_read_only(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "missing" / "memory.sqlite3"
            before = sorted(str(path.relative_to(root)) for path in root.rglob("*"))

            self.assertFalse(backend_router.database_requires_core(database))
            inspection = backend_router._inspect_database(database)

            after = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
            self.assertEqual(after, before)
            self.assertFalse(database.parent.exists())
            self.assertEqual(
                inspection.state,
                backend_router.DatabaseInspectionState.MISSING,
            )

    def test_missing_database_with_generation_evidence_never_bootstraps_v5(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "memory.sqlite3"
            core = root / "core"
            core.mkdir(mode=0o700)
            sentinel = core / "store-generation.json"
            sentinel.write_text('{"generation":"preserve"}\n', encoding="utf-8")
            before = sentinel.read_bytes()

            with patch.dict(
                os.environ,
                {"SYNAPSE_S2_MEMORY_DB": str(database)},
                clear=True,
            ), patch.object(
                mlx_backend,
                "SpikingAttentionBackend",
                side_effect=AssertionError("local constructor must not run"),
            ), self.assertRaisesRegex(
                backend_router.BackendRoutingError,
                "database loss",
            ):
                mlx_backend.get_backend()

            self.assertFalse(database.exists())
            self.assertEqual(sentinel.read_bytes(), before)

    def test_blank_database_with_request_journal_evidence_never_bootstraps_v5(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "memory.sqlite3"
            database.touch(mode=0o600)
            core = root / "core"
            core.mkdir(mode=0o700)
            journal = core / "requests.sqlite3"
            journal.write_bytes(b"journal-evidence")

            with patch.dict(
                os.environ,
                {"SYNAPSE_S2_MEMORY_DB": str(database)},
                clear=True,
            ), patch.object(
                mlx_backend,
                "SpikingAttentionBackend",
                side_effect=AssertionError("local constructor must not run"),
            ), self.assertRaisesRegex(
                backend_router.BackendRoutingError,
                "database loss",
            ):
                backend_router.build_environment_backend(
                    control_plane_only=True
                )

            self.assertEqual(database.read_bytes(), b"")
            self.assertEqual(journal.read_bytes(), b"journal-evidence")

    def test_uninspectable_database_with_binding_receipt_fails_without_mutation(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "memory.sqlite3"
            database.write_bytes(b"not-a-sqlite-database")
            core = root / "core"
            core.mkdir(mode=0o700)
            receipt = core / "requests.sqlite3.binding.receipt.json"
            receipt.write_text('{"binding":"preserve"}\n', encoding="utf-8")
            before_database = database.read_bytes()
            before_receipt = receipt.read_bytes()

            with patch.dict(
                os.environ,
                {"SYNAPSE_S2_MEMORY_DB": str(database)},
                clear=True,
            ), patch.object(
                mlx_backend,
                "SpikingAttentionBackend",
                side_effect=AssertionError("local constructor must not run"),
            ), self.assertRaisesRegex(
                backend_router.BackendRoutingError,
                "could not be inspected safely",
            ):
                backend_router.build_environment_backend(control_plane_only=True)

            self.assertEqual(database.read_bytes(), before_database)
            self.assertEqual(receipt.read_bytes(), before_receipt)

    def test_v5_disabled_service_marker_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            marker = self._marker(service_required=False)
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "CREATE TABLE store_metadata "
                    "(key TEXT PRIMARY KEY, value_json TEXT NOT NULL, "
                    "updated_at REAL NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO store_metadata (key, value_json, updated_at) "
                    "VALUES (?, ?, ?)",
                    (
                        "core_authority",
                        json.dumps(marker, sort_keys=True),
                        marker["updated_at"],
                    ),
                )
                connection.execute("PRAGMA user_version = 5")
                connection.commit()

            with self.assertRaisesRegex(
                backend_router.BackendRoutingError,
                "marker is invalid",
            ):
                backend_router.resolve_backend_route(memory_path=database)

    def test_v5_adoption_migration_without_marker_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "CREATE TABLE store_migrations (key TEXT PRIMARY KEY)"
                )
                connection.execute(
                    "INSERT INTO store_migrations (key) VALUES (?)",
                    ("authoritative_core_v1",),
                )
                connection.execute("PRAGMA user_version = 5")
                connection.commit()

            with self.assertRaisesRegex(
                backend_router.BackendRoutingError,
                "adoption state is inconsistent",
            ):
                backend_router.resolve_backend_route(memory_path=database)

    def test_v6_marker_without_adoption_migration_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            marker = self._marker(service_required=True)
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "CREATE TABLE store_metadata "
                    "(key TEXT PRIMARY KEY, value_json TEXT NOT NULL, "
                    "updated_at REAL NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO store_metadata (key, value_json, updated_at) "
                    "VALUES (?, ?, ?)",
                    (
                        "core_authority",
                        json.dumps(marker, sort_keys=True),
                        marker["updated_at"],
                    ),
                )
                connection.execute("PRAGMA user_version = 6")
                connection.commit()

            with self.assertRaisesRegex(
                backend_router.BackendRoutingError,
                "adoption state is inconsistent",
            ):
                backend_router.resolve_backend_route(memory_path=database)

    def test_v6_marker_must_match_the_complete_authority_schema(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "CREATE TABLE store_metadata "
                    "(key TEXT PRIMARY KEY, value_json TEXT NOT NULL, "
                    "updated_at REAL NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE store_migrations (key TEXT PRIMARY KEY)"
                )
                connection.execute(
                    "INSERT INTO store_metadata (key, value_json, updated_at) "
                    "VALUES (?, ?, ?)",
                    (
                        "core_authority",
                        json.dumps(
                            {"schema_version": 1, "service_required": True}
                        ),
                        1_800_000_000.0,
                    ),
                )
                connection.execute(
                    "INSERT INTO store_migrations (key) VALUES (?)",
                    ("authoritative_core_v1",),
                )
                connection.execute("PRAGMA user_version = 6")
                connection.commit()

            with self.assertRaisesRegex(
                backend_router.BackendRoutingError,
                "marker is invalid",
            ):
                backend_router.resolve_backend_route(memory_path=database)

    def test_v6_marker_derives_core_socket_without_local_construction(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "memory.sqlite3"
            self._write_marker_database(database, service_required=True)
            with patch.dict(
                os.environ,
                {"SYNAPSE_S2_MEMORY_DB": str(database)},
                clear=True,
            ), patch.object(
                mlx_backend,
                "SpikingAttentionBackend",
                side_effect=AssertionError("local constructor must not run"),
            ):
                backend = mlx_backend.get_backend()

            self.assertIsInstance(backend, CoreClient)
            self.assertEqual(
                backend.socket_path,
                root / "core" / "service.sock",
            )
            self.assertEqual(backend.expected_config_fingerprint, "a" * 64)

    def test_configured_service_uses_one_process_local_client_for_both_getters(self) -> None:
        with TemporaryDirectory() as temporary:
            socket_path = Path(temporary) / "core" / "service.sock"
            with patch.dict(
                os.environ,
                {"SYNAPSE_S2_CORE_SOCKET": str(socket_path)},
                clear=True,
            ), patch.object(
                mlx_backend,
                "SpikingAttentionBackend",
                side_effect=AssertionError("local constructor must not run"),
            ):
                engine = mlx_backend.get_backend()
                control = mlx_backend.get_control_plane_backend()

            self.assertIs(engine, control)
            self.assertIsInstance(engine, CoreClient)

    def test_configured_socket_pins_adjacent_governed_store_fingerprint(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            socket_path = root / "core" / "service.sock"
            database = root / "memory.sqlite3"
            self._write_marker_database(database, service_required=True)
            with patch.dict(
                os.environ,
                {"SYNAPSE_S2_CORE_SOCKET": str(socket_path)},
                clear=True,
            ):
                backend = backend_router.build_environment_backend(
                    control_plane_only=True
                )

            self.assertIsInstance(backend, CoreClient)
            self.assertEqual(backend.expected_config_fingerprint, "a" * 64)

    def test_service_outage_fails_closed_without_local_constructor(self) -> None:
        with TemporaryDirectory() as temporary:
            socket_path = Path(temporary) / "core" / "service.sock"
            with patch.dict(
                os.environ,
                {"SYNAPSE_S2_CORE_SOCKET": str(socket_path)},
                clear=True,
            ), patch.object(
                mlx_backend,
                "SpikingAttentionBackend",
                side_effect=AssertionError("local constructor must not run"),
            ):
                backend = mlx_backend.get_backend()
                with self.assertRaises(CoreUnavailable):
                    backend.status(context_id="default")

    def test_inherited_mlx_device_does_not_block_service_routing(self) -> None:
        with TemporaryDirectory() as temporary:
            socket_path = Path(temporary) / "core" / "service.sock"
            with patch.dict(
                os.environ,
                {
                    "MLX_DEVICE": "gpu",
                    "SYNAPSE_S2_CORE_SOCKET": str(socket_path),
                },
                clear=True,
            ):
                backend = backend_router.build_environment_backend(
                    control_plane_only=False
                )

            self.assertIsInstance(backend, CoreClient)

    def test_cli_capture_and_transcript_factories_route_to_core(self) -> None:
        with TemporaryDirectory() as temporary:
            socket_path = Path(temporary) / "core" / "service.sock"
            with patch.dict(
                os.environ,
                {"SYNAPSE_S2_CORE_SOCKET": str(socket_path)},
                clear=True,
            ), patch.object(
                mlx_backend,
                "SpikingAttentionBackend",
                side_effect=AssertionError("local constructor must not run"),
            ):
                cli_backend = synapse_cli.build_backend(
                    synapse_cli.build_parser().parse_args(["status"])
                )
                capture_backend = capture_daemon.backend_from_args(
                    capture_daemon.build_parser().parse_args(["--once"])
                )
                transcript_backend = transcript_capture.backend_from_args(
                    transcript_capture.build_parser().parse_args(["--once"])
                )

            for backend in (cli_backend, capture_backend, transcript_backend):
                self.assertIsInstance(backend, CoreClient)
                self.assertEqual(backend.socket_path, socket_path)

    def test_capture_entrypoints_reject_unreviewed_root_overrides(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            binding_path, _data = self._write_candidate_binding(root)
            outside = root / "outside-captures"
            cli_args = synapse_cli.build_parser().parse_args(
                ["capture-inbox-status", "--capture-root", str(outside)]
            )
            daemon_args = capture_daemon.build_parser().parse_args(
                ["--capture-root", str(outside), "--once"]
            )
            transcript_args = transcript_capture.build_parser().parse_args(
                ["--capture-root", str(outside), "--once"]
            )

            with patch.dict(
                os.environ,
                {BINDING_ENV: str(binding_path)},
                clear=True,
            ):
                for operation in (
                    lambda: synapse_cli.command_capture_inbox_status(cli_args),
                    lambda: capture_daemon.backend_from_args(daemon_args),
                    lambda: transcript_capture.backend_from_args(transcript_args),
                ):
                    with self.subTest(operation=operation), self.assertRaisesRegex(
                        backend_router.BackendRoutingError,
                        "conflicts with the reviewed core binding",
                    ):
                        operation()

            self.assertFalse(outside.exists())

    def test_capture_only_cli_hydrates_bound_root_before_observation(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            binding_path, data = self._write_candidate_binding(root)
            args = synapse_cli.build_parser().parse_args(["capture-inbox-status"])

            with patch.dict(
                os.environ,
                {BINDING_ENV: str(binding_path)},
                clear=True,
            ):
                payload = synapse_cli.command_capture_inbox_status(args)

            self.assertEqual(Path(payload["root"]), data.resolve())
            self.assertFalse((data / "capture_inbox").exists())

    def test_service_mode_rejects_local_override_instead_of_falling_back(self) -> None:
        with TemporaryDirectory() as temporary:
            socket_path = Path(temporary) / "core" / "service.sock"
            with patch.dict(
                os.environ,
                {"SYNAPSE_S2_CORE_SOCKET": str(socket_path)},
                clear=True,
            ), patch.object(
                mlx_backend,
                "SpikingAttentionBackend",
                side_effect=AssertionError("local constructor must not run"),
            ):
                args = synapse_cli.build_parser().parse_args(
                    ["--dimension", "16", "status"]
                )
                with self.assertRaisesRegex(
                    backend_router.BackendRoutingError,
                    "cannot override local backend fields",
                ):
                    synapse_cli.build_backend(args)

    def test_socket_and_database_mismatch_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "memory.sqlite3"
            self._write_marker_database(database, service_required=True)
            mismatched_socket = root / "other" / "service.sock"
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(
                    backend_router.BackendRoutingError,
                    "do not match",
                ):
                    backend_router.resolve_backend_route(
                        memory_path=database,
                        socket_path=mismatched_socket,
                    )

    def test_service_required_database_and_state_mismatch_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "memory.sqlite3"
            self._write_marker_database(database, service_required=True)
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(
                    backend_router.BackendRoutingError,
                    "service-required database do not match",
                ):
                    backend_router.resolve_backend_route(
                        memory_path=database,
                        state_path=root / "other" / "runtime_state.json",
                    )

    def test_maintenance_factory_never_opens_local_store_in_service_mode(self) -> None:
        with TemporaryDirectory() as temporary:
            socket_path = Path(temporary) / "core" / "service.sock"
            with patch.dict(
                os.environ,
                {"SYNAPSE_S2_CORE_SOCKET": str(socket_path)},
                clear=True,
            ), patch.object(
                backend_router,
                "LocalMaintenanceBackend",
                side_effect=AssertionError("local maintenance must not open"),
            ):
                backend = backend_router.build_maintenance_backend()

            self.assertIsInstance(backend, CoreClient)

    def test_v5_environment_factory_remains_explicitly_local(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "runtime_state.json"
            database = root / "memory.sqlite3"
            environment = {
                "SYNAPSE_S2_STATE_PATH": str(state),
                "SYNAPSE_S2_MEMORY_DB": str(database),
                "SYNAPSE_S2_DIMENSION": "4",
                "SYNAPSE_S2_NEURONS": "8",
                "SYNAPSE_S2_TOP_K": "2",
                "SYNAPSE_S2_EMBEDDING_PROVIDER": "semantic-hash",
            }
            with patch.dict(os.environ, environment, clear=True):
                backend = backend_router.build_environment_backend(
                    control_plane_only=True
                )
            self.addCleanup(backend.memory_store.close)

            self.assertIsInstance(backend, mlx_backend.SpikingAttentionBackend)
            self.assertEqual(backend.memory_store.db_path, database)
            with closing(sqlite3.connect(database)) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 5)

    def test_client_definition_contains_no_independent_core_configuration(self) -> None:
        with TemporaryDirectory() as temporary:
            root = (Path(temporary) / "SYNAPSE-S2").resolve()
            data_root = root / ".synapse_s2"
            core = data_root / "core"
            core.mkdir(parents=True, mode=0o700)
            data_root.chmod(0o700)
            config = CoreConfig(
                socket_path=data_root / "core" / "service.sock",
                state_path=data_root / "runtime_state.json",
                memory_path=data_root / "memory.sqlite3",
                capture_root=data_root,
                dimension=8,
                num_neurons=16,
                default_top_k=4,
            )
            write_core_config(core / "service.json", config)
            binding = binding_for_config(
                repo_root=root,
                data_root=data_root,
                config=config,
                core_label="aero.boom.synapse-s2.core",
                authority_mode="candidate-local-v5",
            )
            binding_path = Path(temporary) / "core-binding.json"
            write_core_client_binding(binding_path, binding)
            server = client_config.build_server_definition(
                repo_root=root,
                core_binding_path=binding_path,
                core_binding=binding,
            )
            forbidden = backend_router.LEGACY_CORE_CONFIG_ENV | {
                "SYNAPSE_S2_MEMORY_DB",
                "SYNAPSE_S2_STATE_PATH",
            }

            self.assertEqual(server["env"][BINDING_ENV], str(binding_path.resolve()))
            self.assertFalse(forbidden & set(server["env"]))


if __name__ == "__main__":
    unittest.main()

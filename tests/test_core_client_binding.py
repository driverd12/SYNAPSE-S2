from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import backend_router
import client_config
import synapse_cli
from core_client import CoreClient
from core_client_binding import (
    BINDING_ENV,
    CoreClientBindingError,
    apply_binding_environment,
    binding_for_config,
    load_bound_core_config,
    load_core_client_binding,
    write_core_client_binding,
)
from core_protocol import build_request
from core_service import AuthoritativeCoreService, CoreConfig, write_core_config


class CoreClientBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root / "repo"
        self.data = self.repo / ".synapse_s2"
        self.core = self.data / "core"
        self.core.mkdir(parents=True, mode=0o700)
        self.data.chmod(0o700)
        self.core.chmod(0o700)
        self.config = CoreConfig(
            socket_path=self.core / "service.sock",
            state_path=self.data / "runtime_state.json",
            memory_path=self.data / "memory.sqlite3",
            capture_root=self.data,
            dimension=8,
            num_neurons=16,
            default_top_k=4,
        )
        write_core_config(self.core / "service.json", self.config)
        self.binding_path = self.root / "home" / ".config" / "synapse-s2" / "core-binding.json"

    def binding(self, mode: str = "candidate-local-v5"):
        return binding_for_config(
            repo_root=self.repo,
            data_root=self.data,
            config=self.config,
            core_label="aero.boom.synapse-s2.core",
            authority_mode=mode,
        )

    def test_binding_is_atomic_private_canonical_and_round_trips(self) -> None:
        binding = self.binding()

        write_core_client_binding(self.binding_path, binding)
        loaded = load_core_client_binding(self.binding_path)

        self.assertEqual(loaded, binding)
        self.assertEqual(stat.S_IMODE(self.binding_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.binding_path.parent.stat().st_mode), 0o700)
        self.assertEqual(
            self.binding_path.read_bytes(),
            json.dumps(
                binding.to_wire(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n",
        )

    def test_binding_rejects_tamper_public_mode_hardlink_and_symlink(self) -> None:
        binding = self.binding()
        write_core_client_binding(self.binding_path, binding)
        payload = binding.to_wire()
        payload["socket_path"] = str(self.root / "other.sock")
        self.binding_path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(CoreClientBindingError):
            load_core_client_binding(self.binding_path)

        write_core_client_binding(self.binding_path, binding)
        self.binding_path.chmod(0o644)
        with self.assertRaises(CoreClientBindingError):
            load_core_client_binding(self.binding_path)
        self.binding_path.chmod(0o600)
        alias = self.binding_path.with_name("alias.json")
        os.link(self.binding_path, alias)
        with self.assertRaises(CoreClientBindingError):
            load_core_client_binding(self.binding_path)
        alias.unlink()
        outside = self.binding_path.with_name("outside.json")
        self.binding_path.rename(outside)
        self.binding_path.symlink_to(outside)
        with self.assertRaises(CoreClientBindingError):
            load_core_client_binding(self.binding_path)

    def test_candidate_and_authoritative_bindings_apply_disjoint_routes(self) -> None:
        for mode in ("candidate-local-v5", "authoritative-core-v6"):
            with self.subTest(mode=mode):
                write_core_client_binding(self.binding_path, self.binding(mode))
                env = {BINDING_ENV: str(self.binding_path)}
                loaded = apply_binding_environment(env)
                self.assertEqual(loaded.authority_mode, mode)
                self.assertEqual(env["SYNAPSE_S2_CAPTURE_ROOT"], str(self.data))
                if mode == "candidate-local-v5":
                    self.assertEqual(env["SYNAPSE_S2_MEMORY_DB"], str(self.config.memory_path))
                    self.assertEqual(env["SYNAPSE_S2_DIMENSION"], "8")
                    self.assertEqual(env["SYNAPSE_S2_NEURONS"], "16")
                    self.assertEqual(env["SYNAPSE_S2_TOP_K"], "4")
                    self.assertEqual(env["SYNAPSE_S2_EMBEDDING_PROVIDER"], "semantic-hash")
                    self.assertNotIn("SYNAPSE_S2_CORE_SOCKET", env)
                else:
                    self.assertEqual(env["SYNAPSE_S2_CORE_SOCKET"], str(self.config.socket_path))
                    self.assertEqual(
                        env["SYNAPSE_S2_EXPECTED_CORE_CONFIG_FINGERPRINT"],
                        self.config.fingerprint,
                    )
                    self.assertNotIn("SYNAPSE_S2_MEMORY_DB", env)

    def test_binding_fails_closed_for_missing_or_drifted_private_config(self) -> None:
        binding = self.binding()
        write_core_client_binding(self.binding_path, binding)
        config_path = self.core / "service.json"
        config_path.unlink()
        with self.assertRaises(CoreClientBindingError):
            apply_binding_environment({BINDING_ENV: str(self.binding_path)})

        drifted = CoreConfig(
            **{
                **self.config.__dict__,
                "dimension": 9,
            }
        )
        write_core_config(config_path, drifted)
        with self.assertRaises(CoreClientBindingError):
            load_bound_core_config(binding)

    def test_candidate_binding_hydrates_exact_neural_config_and_rejects_drift(self) -> None:
        neural_config = CoreConfig(
            socket_path=self.core / "service.sock",
            state_path=self.data / "runtime_state.json",
            memory_path=self.data / "memory.sqlite3",
            capture_root=self.data,
            dimension=12,
            num_neurons=24,
            default_top_k=6,
            recall_count=5,
            quick_pruning_interval_seconds=17.0,
            idle_deep_sleep_seconds=29.0,
            embedding_provider_name="mlx-neural",
            embedding_neural_model_id="mlx-community/test-model",
            embedding_neural_revision="a" * 40,
            embedding_neural_cache_dir=self.data / "models",
            embedding_neural_pooling="last",
            embedding_neural_max_tokens=96,
            embedding_neural_normalize=True,
            embedding_neural_local_files_only=True,
            mlx_device="gpu",
            require_native=True,
        )
        write_core_config(self.core / "service.json", neural_config)
        binding = binding_for_config(
            repo_root=self.repo,
            data_root=self.data,
            config=neural_config,
            core_label="aero.boom.synapse-s2.core",
            authority_mode="candidate-local-v5",
        )
        write_core_client_binding(self.binding_path, binding)
        env = {BINDING_ENV: str(self.binding_path)}

        apply_binding_environment(env)

        expected = {
            "MLX_DEVICE": "gpu",
            "SYNAPSE_S2_DIMENSION": "12",
            "SYNAPSE_S2_NEURONS": "24",
            "SYNAPSE_S2_TOP_K": "6",
            "SYNAPSE_S2_RECALL_COUNT": "5",
            "SYNAPSE_S2_QUICK_PRUNING_INTERVAL_SECONDS": "17.0",
            "SYNAPSE_S2_IDLE_DEEP_SLEEP_SECONDS": "29.0",
            "SYNAPSE_S2_NEURAL_MODEL": "mlx-community/test-model",
            "SYNAPSE_S2_NEURAL_REVISION": "a" * 40,
            "SYNAPSE_S2_NEURAL_POOLING": "last",
            "SYNAPSE_S2_NEURAL_MAX_TOKENS": "96",
            "SYNAPSE_S2_NEURAL_NORMALIZE": "true",
            "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY": "true",
            "SYNAPSE_S2_REQUIRE_NATIVE": "true",
        }
        for key, value in expected.items():
            self.assertEqual(env[key], value)
        self.assertNotIn("SYNAPSE_S2_NEURAL_MODEL_ID", env)

        with self.assertRaises(CoreClientBindingError):
            apply_binding_environment(
                {
                    BINDING_ENV: str(self.binding_path),
                    "SYNAPSE_S2_NEURAL_MODEL": "attacker/drift",
                }
            )

        with mock.patch("mlx_backend.SpikingAttentionBackend") as constructor:
            with mock.patch.dict(os.environ, {BINDING_ENV: str(self.binding_path)}, clear=True):
                backend_router.build_environment_backend(control_plane_only=False)
        constructor.assert_called_once_with(
            dimension=12,
            num_neurons=24,
            default_top_k=6,
            recall_count=5,
            quick_pruning_interval_seconds=17.0,
            idle_deep_sleep_seconds=29.0,
            embedding_provider_name="mlx-neural",
            require_native=True,
            control_plane_only=False,
        )

    def test_cli_uses_bound_config_for_omitted_defaults_and_rejects_explicit_default(self) -> None:
        binding = self.binding("candidate-local-v5")
        write_core_client_binding(self.binding_path, binding)
        omitted = synapse_cli.build_parser().parse_args(["status"])
        explicit = synapse_cli.build_parser().parse_args(
            ["--dimension", "1024", "status"]
        )

        with mock.patch.dict(
            os.environ,
            {BINDING_ENV: str(self.binding_path)},
            clear=True,
        ), mock.patch.object(
            synapse_cli.mlx_backend,
            "SpikingAttentionBackend",
        ) as constructor:
            synapse_cli.build_backend(omitted)
            with self.assertRaisesRegex(
                backend_router.BackendRoutingError,
                "explicit local backend configuration conflicts",
            ):
                synapse_cli.build_backend(explicit)

        constructor.assert_called_once_with(
            dimension=8,
            num_neurons=16,
            default_top_k=4,
            recall_count=10,
            quick_pruning_interval_seconds=300.0,
            idle_deep_sleep_seconds=1800.0,
            compile_graph=True,
            state_path=self.config.state_path,
            memory_path=self.config.memory_path,
            embedding_provider_name="semantic-hash",
            require_native=False,
        )

    def test_binding_rejects_inherited_fields_from_the_opposite_authority_mode(self) -> None:
        scenarios = (
            (
                "candidate-local-v5",
                {"SYNAPSE_S2_CORE_SOCKET": str(self.config.socket_path)},
            ),
            (
                "candidate-local-v5",
                {"SYNAPSE_S2_EXPECTED_CORE_CONFIG_FINGERPRINT": "a" * 64},
            ),
            (
                "authoritative-core-v6",
                {"SYNAPSE_S2_MEMORY_DB": str(self.config.memory_path)},
            ),
            (
                "authoritative-core-v6",
                {"SYNAPSE_S2_STATE_PATH": str(self.config.state_path)},
            ),
        )
        for mode, inherited in scenarios:
            with self.subTest(mode=mode, field=next(iter(inherited))):
                write_core_client_binding(self.binding_path, self.binding(mode))
                env = {BINDING_ENV: str(self.binding_path), **inherited}

                with self.assertRaises(CoreClientBindingError):
                    apply_binding_environment(env)

    def _write_governed_database(self, path: Path) -> None:
        updated_at = 1_700_000_001.0
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "CREATE TABLE store_metadata ("
                "key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at REAL NOT NULL)"
            )
            connection.execute("CREATE TABLE store_migrations (key TEXT PRIMARY KEY)")
            connection.execute(
                "INSERT INTO store_metadata (key, value_json, updated_at) VALUES (?, ?, ?)",
                (
                    "core_authority",
                    json.dumps(
                        {
                            "schema_version": 1,
                            "service_required": True,
                            "epoch": 1,
                            "instance_id": "core-binding-test",
                            "config_fingerprint": self.config.fingerprint,
                            "build_id": "b" * 64,
                            "protocol_version": "synapse-core.v1",
                            "lock_generation_id": "lockfs-v1-1-2",
                            "store_identity": "store-" + ("a" * 24),
                            "request_journal_id": "journal-" + ("b" * 24),
                            "request_journal_binding_schema": (
                                "synapse-s2.request-journal-binding.v1"
                            ),
                            "request_journal_schema_version": 3,
                            "root_generation_id": "generation-" + ("c" * 24),
                            "embedding_space_identity": (
                                self.config.embedding_space_identity
                            ),
                            "restored_target_binding_receipt_digest": None,
                            "claimed_at": 1_700_000_000.0,
                            "updated_at": updated_at,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    updated_at,
                ),
            )
            connection.execute(
                "INSERT INTO store_migrations (key) VALUES (?)",
                ("authoritative_core_v1",),
            )
            connection.execute("PRAGMA user_version = 6")
            connection.commit()

    def test_backend_router_consumes_binding_and_rejects_stale_mode(self) -> None:
        self._write_governed_database(self.config.memory_path)
        write_core_client_binding(
            self.binding_path,
            self.binding("authoritative-core-v6"),
        )
        with mock.patch.dict(
            os.environ,
            {BINDING_ENV: str(self.binding_path)},
            clear=True,
        ):
            backend = backend_router.build_environment_backend(
                control_plane_only=False
            )
            self.assertIsInstance(backend, CoreClient)
            self.assertEqual(backend.socket_path, self.config.socket_path)
            self.assertEqual(
                backend.expected_config_fingerprint,
                self.config.fingerprint,
            )

        write_core_client_binding(
            self.binding_path,
            self.binding("candidate-local-v5"),
        )
        with mock.patch.dict(
            os.environ,
            {BINDING_ENV: str(self.binding_path)},
            clear=True,
        ), self.assertRaisesRegex(
            backend_router.BackendRoutingError,
            "stale",
        ):
            backend_router.resolve_backend_route()

    def test_backend_router_rejects_capture_root_outside_reviewed_binding(self) -> None:
        write_core_client_binding(
            self.binding_path,
            self.binding("candidate-local-v5"),
        )
        with mock.patch.dict(
            os.environ,
            {BINDING_ENV: str(self.binding_path)},
            clear=True,
        ), self.assertRaisesRegex(
            backend_router.BackendRoutingError,
            "conflicts with the reviewed core binding",
        ):
            backend_router.resolve_backend_route(
                capture_root=self.root / "unreviewed-capture-root"
            )

    def test_capture_route_rejects_authoritative_binding_before_v6_adoption(self) -> None:
        write_core_client_binding(
            self.binding_path,
            self.binding("authoritative-core-v6"),
        )
        with mock.patch.dict(
            os.environ,
            {BINDING_ENV: str(self.binding_path)},
            clear=True,
        ), self.assertRaisesRegex(
            backend_router.BackendRoutingError,
            "does not match database governance",
        ):
            backend_router.resolve_backend_route(capture_root=self.data)

    def test_client_definition_uses_only_reviewed_binding_for_layout_routes(self) -> None:
        binding = self.binding("candidate-local-v5")
        write_core_client_binding(self.binding_path, binding)
        launcher = self.root / "home" / ".local" / "bin" / "synapse-s2-mcp"

        server = client_config.build_server_definition(
            repo_root=self.repo,
            launcher_path=launcher,
            core_binding_path=self.binding_path,
            core_binding=binding,
        )

        self.assertEqual(server["env"][BINDING_ENV], str(self.binding_path))
        self.assertNotIn("SYNAPSE_S2_CORE_SOCKET", server["env"])
        self.assertNotIn("SYNAPSE_S2_CAPTURE_ROOT", server["env"])
        self.assertNotIn("SYNAPSE_S2_EXPORT_DIR", server["env"])

    def test_server_rejects_stale_config_binding_before_journal_or_dispatch(self) -> None:
        service = AuthoritativeCoreService(
            self.config,
            backend_factory=lambda _lease: mock.Mock(),
        )
        request = build_request(
            request_id="req-stale-binding",
            caller="binding-test",
            deadline_unix_ms=int(time.time() * 1000) + 30_000,
            operation="register_text_trace",
            arguments={
                "tag": "test",
                "text": "test",
                "context_id": "default",
                "metadata": {},
            },
            authentication_key=bytes(range(32)),
            expected_config_fingerprint="0" * 64,
        )
        service._journal_accept = mock.Mock(
            side_effect=AssertionError("journal must not be reached")
        )
        service._handlers["register_text_trace"] = mock.Mock(
            side_effect=AssertionError("handler must not be reached")
        )

        response = service._execute_request(request)

        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "service_unavailable")
        service._journal_accept.assert_not_called()
        service._handlers["register_text_trace"].assert_not_called()


if __name__ == "__main__":
    unittest.main()

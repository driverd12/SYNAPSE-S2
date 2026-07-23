import json
import os
import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import client_config
from core_client_binding import (
    BINDING_ENV,
    CoreClientBinding,
    binding_for_config,
    write_core_client_binding,
)
from core_service import CoreConfig, write_core_config


DIRECT_ROUTE_ENV = {
    "MLX_DEVICE",
    "SYNAPSE_S2_CORE_SOCKET",
    "SYNAPSE_S2_CAPTURE_ROOT",
    "SYNAPSE_S2_DIMENSION",
    "SYNAPSE_S2_EMBEDDING_PROVIDER",
    "SYNAPSE_S2_EXPORT_DIR",
    "SYNAPSE_S2_MEMORY_DB",
    "SYNAPSE_S2_NEURAL_CACHE_DIR",
    "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY",
    "SYNAPSE_S2_NEURAL_MODEL",
    "SYNAPSE_S2_NEURONS",
    "SYNAPSE_S2_RECALL_COUNT",
    "SYNAPSE_S2_STATE_PATH",
    "SYNAPSE_S2_TOP_K",
}


class ClientConfigTests(unittest.TestCase):
    @staticmethod
    def _write_binding(*, home: Path, repo: Path) -> tuple[Path, CoreClientBinding]:
        repo = repo.resolve()
        data = repo / ".synapse_s2"
        core = data / "core"
        core.mkdir(mode=0o700, parents=True, exist_ok=True)
        data.chmod(0o700)
        core.chmod(0o700)
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
        binding_path = home / ".config" / "synapse-s2" / "core-binding.json"
        write_core_client_binding(binding_path, binding)
        return binding_path, binding

    def test_json_writer_is_idempotent_across_formatting_and_key_order(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "config.json"
            original = '{\n  "z": 2,\n  "a": {"b": true}\n}\n'
            target.write_text(original, encoding="utf-8")
            payload = {"a": {"b": True}, "z": 2}

            dry_run = client_config._write_json_if_changed(
                target,
                payload,
                dry_run=True,
            )
            applied = client_config._write_json_if_changed(
                target,
                payload,
                dry_run=False,
            )

            self.assertFalse(dry_run["would_change"])
            self.assertFalse(applied["changed"])
            self.assertIsNone(applied["backup_path"])
            self.assertEqual(target.read_text(encoding="utf-8"), original)
            self.assertEqual(list(target.parent.glob("config.json.bak-*")), [])

    def test_json_writer_does_not_equate_boolean_and_integer_values(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "config.json"
            target.write_text('{"enabled": 1}\n', encoding="utf-8")

            result = client_config._write_json_if_changed(
                target,
                {"enabled": True},
                dry_run=True,
            )

            self.assertTrue(result["would_change"])

    def test_existing_config_backup_is_private_complete_and_never_overwritten(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "config.json"
            target.write_text('{"version": 1}\n', encoding="utf-8")
            collision = target.with_name("config.json.bak-20260719-120000-collision")
            collision.write_text("older backup\n", encoding="utf-8")

            with (
                mock.patch("client_config.time.strftime", return_value="20260719-120000"),
                mock.patch(
                    "client_config.secrets.token_hex",
                    side_effect=["collision", "freshbackup"],
                ),
            ):
                result = client_config._write_text_if_changed(
                    target,
                    '{"version": 2}\n',
                    dry_run=False,
                )

            backup = Path(result["backup_path"])
            self.assertEqual(collision.read_text(encoding="utf-8"), "older backup\n")
            self.assertEqual(backup.name, "config.json.bak-20260719-120000-freshbackup")
            self.assertEqual(backup.read_text(encoding="utf-8"), '{"version": 1}\n')
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertEqual(target.read_text(encoding="utf-8"), '{"version": 2}\n')

    def test_existing_config_symlink_is_rejected(self):
        with TemporaryDirectory() as tmp:
            real = Path(tmp) / "real.json"
            real.write_text('{"safe": true}\n', encoding="utf-8")
            target = Path(tmp) / "config.json"
            os.symlink(real, target)

            with self.assertRaises(OSError):
                client_config._write_text_if_changed(
                    target,
                    '{"safe": false}\n',
                    dry_run=False,
                )

            self.assertEqual(real.read_text(encoding="utf-8"), '{"safe": true}\n')

    def test_install_rejects_symlinked_or_broad_roots_before_mutating(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            real_repo = root / "repo"
            real_repo.mkdir(mode=0o700)
            repo_alias = root / "repo-alias"
            os.symlink(real_repo, repo_alias)
            home = root / "home"
            home.mkdir(mode=0o700)

            with self.assertRaisesRegex(OSError, "symlink component"):
                client_config.install_client_configs(
                    home=home,
                    repo_root=repo_alias,
                    launcher_path=root / "bin" / "synapse-s2-mcp",
                    dry_run=True,
                )
            with self.assertRaisesRegex(OSError, "too broad"):
                client_config.install_client_configs(
                    home=home,
                    repo_root=Path("/"),
                    launcher_path=root / "bin" / "synapse-s2-mcp",
                    dry_run=True,
                )

            self.assertFalse((real_repo / ".mcp.json").exists())

    def test_server_definition_rejects_secret_shaped_path_without_reflection(self):
        with TemporaryDirectory() as tmp:
            secret = "api_key=secretvalue123456"
            with self.assertRaises(ValueError) as raised:
                client_config.build_server_definition(
                    repo_root=Path(tmp) / secret,
                    launcher_path=Path(tmp) / "synapse-s2-mcp",
                )

            self.assertNotIn(secret, str(raised.exception))

    def test_private_config_writer_preserves_existing_parent_mode(self):
        with TemporaryDirectory() as tmp:
            parent = Path(tmp) / "caller-owned"
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            target = parent / "config.json"

            client_config._write_text_if_changed(
                target,
                '{"safe": true}\n',
                dry_run=False,
            )

            self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_concurrent_config_change_is_not_overwritten(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "config.json"
            target.write_text('{"version": 1}\n', encoding="utf-8")
            real_backup = client_config._create_exclusive_private_backup

            def competing_write(path):
                backup = real_backup(path)
                path.write_text('{"version": "winning"}\n', encoding="utf-8")
                return backup

            with mock.patch(
                "client_config._create_exclusive_private_backup",
                side_effect=competing_write,
            ):
                with self.assertRaisesRegex(RuntimeError, "changed during update"):
                    client_config._write_text_if_changed(
                        target,
                        '{"version": 2}\n',
                        dry_run=False,
                    )

            backups = list(target.parent.glob("config.json.bak-*"))
            self.assertEqual(
                target.read_text(encoding="utf-8"),
                '{"version": "winning"}\n',
            )
            self.assertEqual(len(backups), 1)
            self.assertEqual(
                backups[0].read_text(encoding="utf-8"),
                '{"version": 1}\n',
            )
            self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
            lock_path = target.with_name(f".{target.name}.synapse-config.lock")
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)

    def test_server_definition_without_binding_preserves_canonical_v5_route(self):
        with TemporaryDirectory() as tmp:
            repo_root = Path(tmp) / "SYNAPSE-S2"
            launcher = Path(tmp) / "bin" / "synapse-s2-mcp"

            server = client_config.build_server_definition(
                repo_root=repo_root,
                launcher_path=launcher,
                client_agent_id="codex-desktop",
            )
            resolved_repo = repo_root.resolve()

        self.assertEqual(server["type"], "stdio")
        self.assertEqual(server["command"], str(launcher.resolve()))
        self.assertNotIn("PYTHONPATH", server["env"])
        self.assertNotIn(BINDING_ENV, server["env"])
        self.assertNotIn("SYNAPSE_S2_CORE_SOCKET", server["env"])
        self.assertEqual(server["env"]["MLX_DEVICE"], "gpu")
        self.assertEqual(
            server["env"]["SYNAPSE_S2_EMBEDDING_PROVIDER"],
            "mlx-neural",
        )
        self.assertEqual(
            server["env"]["SYNAPSE_S2_MEMORY_DB"],
            str(resolved_repo / ".synapse_s2" / "memory.sqlite3"),
        )
        self.assertEqual(
            server["env"]["SYNAPSE_S2_STATE_PATH"],
            str(resolved_repo / ".synapse_s2" / "runtime_state.json"),
        )
        self.assertEqual(server["env"]["SYNAPSE_S2_CAPTURE_ROOT"], str(resolved_repo / ".synapse_s2"))
        self.assertEqual(server["env"]["SYNAPSE_S2_CONTEXT_ID"], "default")
        self.assertEqual(
            server["env"]["SYNAPSE_S2_DEFAULT_RESPONSE_MODE"],
            "compact",
        )
        self.assertEqual(server["env"]["SYNAPSE_S2_MAX_RESPONSE_BYTES"], "12288")
        self.assertEqual(server["env"]["SYNAPSE_S2_CLIENT_AGENT_ID"], "codex-desktop")
        self.assertEqual(server["env"]["SYNAPSE_S2_CLIENT_SESSION_BRIDGE"], "1")
        self.assertEqual(server["env"]["SYNAPSE_S2_CLIENT_CORTEX"], "1")
        self.assertEqual(server["env"]["SYNAPSE_S2_CLIENT_CORTEX_MODE"], "strict")
        self.assertIn("codex-desktop", server["env"]["SYNAPSE_S2_CLIENT_STARTUP_PROMPT"])
        self.assertTrue(DIRECT_ROUTE_ENV - {"SYNAPSE_S2_CORE_SOCKET"} <= set(server["env"]))

    def test_server_definition_with_binding_is_binding_only(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            home = root / "home"
            repo = root / "repo"
            home.mkdir(mode=0o700)
            repo.mkdir(mode=0o700)
            binding_path, binding = self._write_binding(home=home, repo=repo)

            server = client_config.build_server_definition(
                repo_root=repo,
                launcher_path=home / ".local" / "bin" / "synapse-s2-mcp",
                core_binding_path=binding_path,
                core_binding=binding,
            )

        self.assertEqual(server["env"][BINDING_ENV], str(binding_path))
        self.assertNotIn("PYTHONPATH", server["env"])
        self.assertFalse(DIRECT_ROUTE_ENV & set(server["env"]))

    def test_server_definition_rejects_binding_without_its_reviewed_path(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            home = root / "home"
            repo = root / "repo"
            home.mkdir(mode=0o700)
            repo.mkdir(mode=0o700)
            _binding_path, binding = self._write_binding(home=home, repo=repo)

            with self.assertRaisesRegex(OSError, "supplied together"):
                client_config.build_server_definition(
                    repo_root=repo,
                    launcher_path=home / ".local" / "bin" / "synapse-s2-mcp",
                    core_binding=binding,
                )

    def test_install_merges_claude_codex_and_project_configs_without_clobbering(self):
        with TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            repo_root = Path(tmp) / "SYNAPSE-S2"
            repo_root.mkdir()
            launcher = home / ".local" / "bin" / "synapse-s2-mcp"
            desktop_config = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
            desktop_config.parent.mkdir(parents=True)
            desktop_config.write_text(
                json.dumps({"preferences": {"keepAwakeEnabled": True}}),
                encoding="utf-8",
            )
            claude_code_config = home / ".claude.json"
            claude_code_config.write_text(
                json.dumps(
                    {
                        "mcpServers": {"master-mold": {"command": "node"}},
                        "projects": {
                            "/existing": {
                                "enabledMcpjsonServers": ["master-mold"],
                                "disabledMcpjsonServers": [],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            codex_config = home / ".codex" / "config.toml"
            codex_config.parent.mkdir(parents=True)
            codex_config.write_text('model = "gpt-5.5"\n', encoding="utf-8")

            result = client_config.install_client_configs(
                home=home,
                repo_root=repo_root,
                launcher_path=launcher,
            )

            desktop = json.loads(desktop_config.read_text(encoding="utf-8"))
            claude_code = json.loads(claude_code_config.read_text(encoding="utf-8"))
            codex_text = codex_config.read_text(encoding="utf-8")
            project_manifest = json.loads(
                (repo_root / ".mcp.json").read_text(encoding="utf-8")
            )
            resolved_repo = str(repo_root.resolve())
            config_modes = {
                "desktop": desktop_config.stat().st_mode & 0o777,
                "claude_code": claude_code_config.stat().st_mode & 0o777,
                "codex": codex_config.stat().st_mode & 0o777,
                "project": (repo_root / ".mcp.json").stat().st_mode & 0o777,
            }

        self.assertTrue(desktop["preferences"]["keepAwakeEnabled"])
        self.assertIn("synapse-s2", desktop["mcpServers"])
        self.assertEqual(
            desktop["mcpServers"]["synapse-s2"]["env"]["SYNAPSE_S2_CLIENT_AGENT_ID"],
            "claude-desktop",
        )
        self.assertIn("master-mold", claude_code["mcpServers"])
        self.assertIn("synapse-s2", claude_code["mcpServers"])
        self.assertEqual(
            claude_code["mcpServers"]["synapse-s2"]["env"]["SYNAPSE_S2_CLIENT_AGENT_ID"],
            "claude-code",
        )
        self.assertIn(resolved_repo, claude_code["projects"])
        self.assertIn(
            "synapse-s2",
            claude_code["projects"][resolved_repo]["enabledMcpjsonServers"],
        )
        self.assertIn("[mcp_servers.synapse-s2]", codex_text)
        self.assertIn(str(launcher), codex_text)
        self.assertNotIn("PYTHONPATH", codex_text)
        self.assertIn('SYNAPSE_S2_CLIENT_AGENT_ID = "codex-desktop"', codex_text)
        self.assertIn('SYNAPSE_S2_CLIENT_SESSION_BRIDGE = "1"', codex_text)
        self.assertIn('SYNAPSE_S2_CLIENT_CORTEX = "1"', codex_text)
        self.assertIn('SYNAPSE_S2_CLIENT_CORTEX_MODE = "strict"', codex_text)
        self.assertIn(
            'SYNAPSE_S2_CLIENT_STARTUP_RECALL_MODE = "surface"',
            codex_text,
        )
        self.assertEqual(set(config_modes.values()), {0o600})
        self.assertNotIn("SYNAPSE_S2_CORE_SOCKET", codex_text)
        self.assertNotIn(BINDING_ENV, codex_text)
        self.assertIn('SYNAPSE_S2_EMBEDDING_PROVIDER = "mlx-neural"', codex_text)
        self.assertIn("SYNAPSE_S2_MEMORY_DB", codex_text)
        self.assertIn("SYNAPSE_S2_STATE_PATH", codex_text)
        self.assertIn("synapse-s2", project_manifest["mcpServers"])
        self.assertEqual(
            project_manifest["mcpServers"]["synapse-s2"]["env"]["SYNAPSE_S2_CLIENT_AGENT_ID"],
            "project-mcp",
        )
        self.assertTrue(result["restart_required"])
        self.assertEqual(
            sorted(result["clients"]),
            ["claude_code", "claude_desktop", "codex", "project_mcp"],
        )

    def test_install_auto_discovers_binding_and_removes_all_direct_route_fields(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            home = root / "home"
            repo = root / "repo"
            home.mkdir(mode=0o700)
            repo.mkdir(mode=0o700)
            launcher = home / ".local" / "bin" / "synapse-s2-mcp"
            binding_path, binding = self._write_binding(home=home, repo=repo)

            result = client_config.install_client_configs(
                home=home,
                repo_root=repo,
                launcher_path=launcher,
            )

            project = json.loads((repo / ".mcp.json").read_text(encoding="utf-8"))
            desktop = json.loads(
                (
                    home
                    / "Library"
                    / "Application Support"
                    / "Claude"
                    / "claude_desktop_config.json"
                ).read_text(encoding="utf-8")
            )
            claude = json.loads((home / ".claude.json").read_text(encoding="utf-8"))
            codex = (home / ".codex" / "config.toml").read_text(encoding="utf-8")

        definitions = (
            project["mcpServers"]["synapse-s2"],
            desktop["mcpServers"]["synapse-s2"],
            claude["mcpServers"]["synapse-s2"],
        )
        for definition in definitions:
            self.assertEqual(definition["env"][BINDING_ENV], str(binding_path))
            self.assertNotIn("PYTHONPATH", definition["env"])
            self.assertFalse(DIRECT_ROUTE_ENV & set(definition["env"]))
        self.assertIn(f'{BINDING_ENV} = "{binding_path}"', codex)
        self.assertNotIn("PYTHONPATH", codex)
        self.assertFalse(DIRECT_ROUTE_ENV & set(key for key in DIRECT_ROUTE_ENV if key in codex))
        self.assertEqual(result["core_binding"]["digest"], binding.digest)
        self.assertEqual(result["core_binding"]["authority_mode"], "candidate-local-v5")

    def test_codex_config_updates_existing_synapse_server_block(self):
        with TemporaryDirectory() as tmp:
            repo_root = Path(tmp) / "SYNAPSE-S2"
            launcher = Path(tmp) / "bin" / "synapse-s2-mcp"
            server = client_config.build_server_definition(
                repo_root=repo_root,
                launcher_path=launcher,
                client_agent_id="codex-desktop",
            )
            existing = """model = "gpt-5.5"

[mcp_servers.synapse-s2]
command = "/old/synapse-s2-mcp"
args = []

[mcp_servers.synapse-s2.env]
SYNAPSE_S2_CLIENT_AGENT_ID = "old-agent"

[mcp_servers.other]
command = "node"
"""

            merged = client_config.merge_codex_config_text(existing, server=server)

        self.assertIn('model = "gpt-5.5"', merged)
        self.assertIn("[mcp_servers.other]", merged)
        self.assertIn(str(launcher), merged)
        self.assertNotIn("PYTHONPATH", merged)
        self.assertIn('SYNAPSE_S2_CLIENT_AGENT_ID = "codex-desktop"', merged)
        self.assertNotIn("SYNAPSE_S2_CORE_SOCKET", merged)
        self.assertNotIn(BINDING_ENV, merged)
        self.assertIn('SYNAPSE_S2_EMBEDDING_PROVIDER = "mlx-neural"', merged)
        self.assertIn("SYNAPSE_S2_MEMORY_DB", merged)
        self.assertIn("SYNAPSE_S2_STATE_PATH", merged)
        self.assertNotIn("/old/synapse-s2-mcp", merged)
        self.assertNotIn("old-agent", merged)

    def test_codex_certification_profile_keeps_definition_but_disables_respawn(self):
        with TemporaryDirectory() as tmp:
            repo_root = Path(tmp) / "SYNAPSE-S2"
            launcher = Path(tmp) / "bin" / "synapse-s2-mcp"
            server = client_config.build_server_definition(
                repo_root=repo_root,
                launcher_path=launcher,
                client_agent_id="codex-desktop",
            )
            merged = client_config.merge_codex_config_text(
                'model = "gpt-5.5"\n',
                server=server,
                enabled=False,
            )

        server_block = merged.split("[mcp_servers.synapse-s2.env]", 1)[0]
        self.assertIn("[mcp_servers.synapse-s2]", server_block)
        self.assertIn(str(launcher), server_block)
        self.assertIn("enabled = false", server_block)
        self.assertNotIn("enabled = true", server_block)

    def test_install_reports_codex_certification_activation_profile(self):
        with TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            repo_root = Path(tmp) / "SYNAPSE-S2"
            launcher = home / ".local" / "bin" / "synapse-s2-mcp"

            result = client_config.install_client_configs(
                home=home,
                repo_root=repo_root,
                launcher_path=launcher,
                dry_run=True,
                codex_enabled=False,
            )

        self.assertFalse(result["codex_mcp_enabled"])
        self.assertEqual(
            result["activation_profile"],
            "certification-quiescence",
        )
        self.assertTrue(result["clients"]["codex"]["would_change"])

    def test_certification_profile_publication_is_idempotent_and_restorable(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            home = root / "home"
            repo_root = root / "SYNAPSE-S2"
            home.mkdir(mode=0o700)
            repo_root.mkdir(mode=0o700)
            launcher = home / ".local" / "bin" / "synapse-s2-mcp"

            first = client_config.install_client_configs(
                home=home,
                repo_root=repo_root,
                launcher_path=launcher,
                codex_enabled=False,
            )
            second = client_config.install_client_configs(
                home=home,
                repo_root=repo_root,
                launcher_path=launcher,
                codex_enabled=False,
            )
            restored = client_config.install_client_configs(
                home=home,
                repo_root=repo_root,
                launcher_path=launcher,
                codex_enabled=True,
            )
            codex = (home / ".codex" / "config.toml").read_text(encoding="utf-8")

        self.assertTrue(first["clients"]["codex"]["changed"])
        self.assertFalse(second["restart_required"])
        self.assertFalse(second["clients"]["codex"]["would_change"])
        self.assertTrue(restored["clients"]["codex"]["changed"])
        self.assertTrue(restored["codex_mcp_enabled"])
        self.assertEqual(restored["activation_profile"], "operational")
        self.assertEqual(codex.count("[mcp_servers.synapse-s2]"), 1)
        self.assertIn("enabled = true", codex)
        self.assertNotIn("enabled = false", codex)

    def test_install_rejects_non_boolean_codex_activation_before_io(self):
        with TemporaryDirectory() as tmp, self.assertRaisesRegex(
            TypeError,
            "codex_enabled must be a boolean",
        ):
            client_config.install_client_configs(
                home=Path(tmp) / "missing-home",
                repo_root=Path(tmp) / "missing-repo",
                launcher_path=Path(tmp) / "missing-launcher",
                codex_enabled=1,
            )

    def test_install_refuses_to_overwrite_malformed_existing_json(self):
        with TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            repo_root = Path(tmp) / "SYNAPSE-S2"
            repo_root.mkdir()
            launcher = home / ".local" / "bin" / "synapse-s2-mcp"
            desktop_config = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
            desktop_config.parent.mkdir(parents=True)
            desktop_config.write_text("{not valid json", encoding="utf-8")

            with self.assertRaises(ValueError) as raised:
                client_config.install_client_configs(
                    home=home,
                    repo_root=repo_root,
                    launcher_path=launcher,
                )

            self.assertIn("refusing to overwrite", str(raised.exception))
            self.assertEqual(desktop_config.read_text(encoding="utf-8"), "{not valid json")

    def test_all_client_publication_rolls_back_if_one_replace_fails(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            home = root / "home"
            repo = root / "repo"
            repo.mkdir(mode=0o700)
            home.mkdir(mode=0o700)
            targets = {
                repo / ".mcp.json": '{"prior":"project"}\n',
                home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json": '{"prior":"desktop"}\n',
                home / ".claude.json": '{"prior":"claude"}\n',
                home / ".codex" / "config.toml": 'model = "prior"\n',
            }
            for path, value in targets.items():
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_text(value, encoding="utf-8")
                path.chmod(0o600)
            desktop = next(path for path in targets if path.name == "claude_desktop_config.json")
            real_replace = os.replace
            failed = False

            def fail_once(source, destination):
                nonlocal failed
                if Path(destination) == desktop and not failed:
                    failed = True
                    raise OSError("injected publication failure")
                return real_replace(source, destination)

            with mock.patch("client_config.os.replace", side_effect=fail_once):
                with self.assertRaisesRegex(OSError, "injected"):
                    client_config.install_client_configs(
                        home=home,
                        repo_root=repo,
                        launcher_path=home / ".local" / "bin" / "synapse-s2-mcp",
                    )

            self.assertTrue(failed)
            for path, value in targets.items():
                self.assertEqual(path.read_text(encoding="utf-8"), value)
            journal = repo / ".synapse_s2" / "client-config-publication.journal.json"
            self.assertFalse(journal.exists())
            self.assertEqual(list(repo.rglob("*.tmp")), [])

    def test_prepared_publication_journal_recovers_after_process_crash(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            target = root / "config.json"
            target.write_text('{"version":1}\n', encoding="utf-8")
            target.chmod(0o600)
            original = target.read_bytes()
            desired = b'{"version":2}\n'
            backup = client_config._create_exclusive_private_backup(target)
            temporary = client_config._stage_private_payload(target, desired)
            journal = root / "journal.json"
            payload = {
                "schema": client_config.PUBLICATION_SCHEMA,
                "state": "prepared",
                "entries": [
                    {
                        "client": "test",
                        "target": str(target),
                        "original_exists": True,
                        "original_sha256": hashlib.sha256(original).hexdigest(),
                        "desired_sha256": hashlib.sha256(desired).hexdigest(),
                        "backup_path": str(backup),
                        "temp_path": str(temporary),
                    }
                ],
            }
            client_config._write_publication_journal(journal, payload)
            os.replace(temporary, target)

            recovered = client_config._recover_config_transaction(
                journal,
                allowed_targets={target},
            )

            self.assertTrue(recovered)
            self.assertEqual(target.read_bytes(), original)
            self.assertFalse(journal.exists())
            self.assertTrue(backup.exists())

    def test_install_recovers_pending_publication_before_reading_configs(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            home = root / "home"
            repo = root / "repo"
            home.mkdir(mode=0o700)
            repo.mkdir(mode=0o700)
            target = repo / ".mcp.json"
            target.write_text('{"prior":"project"}\n', encoding="utf-8")
            target.chmod(0o600)
            original = target.read_bytes()
            interrupted_payload = b"{interrupted-publication"
            backup = client_config._create_exclusive_private_backup(target)
            temporary = client_config._stage_private_payload(
                target,
                interrupted_payload,
            )
            journal = (
                repo
                / ".synapse_s2"
                / "client-config-publication.journal.json"
            )
            client_config._write_publication_journal(
                journal,
                {
                    "schema": client_config.PUBLICATION_SCHEMA,
                    "state": "prepared",
                    "entries": [
                        {
                            "client": "project_mcp",
                            "target": str(target),
                            "original_exists": True,
                            "original_sha256": hashlib.sha256(original).hexdigest(),
                            "desired_sha256": hashlib.sha256(
                                interrupted_payload
                            ).hexdigest(),
                            "backup_path": str(backup),
                            "temp_path": str(temporary),
                        }
                    ],
                },
            )
            os.replace(temporary, target)

            result = client_config.install_client_configs(
                home=home,
                repo_root=repo,
                launcher_path=home / ".local" / "bin" / "synapse-s2-mcp",
            )

            project = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(project["prior"], "project")
            self.assertIn("synapse-s2", project["mcpServers"])
            self.assertTrue(result["clients"]["project_mcp"]["changed"])
            self.assertFalse(journal.exists())
            self.assertTrue(backup.exists())

    def test_dry_run_fails_closed_when_publication_recovery_is_pending(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            home = root / "home"
            repo = root / "repo"
            home.mkdir(mode=0o700)
            repo.mkdir(mode=0o700)
            target = repo / ".mcp.json"
            target.write_text('{"prior":"project"}\n', encoding="utf-8")
            target.chmod(0o600)
            original = target.read_bytes()
            desired = b'{"desired":"disabled-profile"}\n'
            backup = client_config._create_exclusive_private_backup(target)
            temporary = client_config._stage_private_payload(target, desired)
            journal = (
                repo
                / ".synapse_s2"
                / "client-config-publication.journal.json"
            )
            client_config._write_publication_journal(
                journal,
                {
                    "schema": client_config.PUBLICATION_SCHEMA,
                    "state": "prepared",
                    "entries": [
                        {
                            "client": "project_mcp",
                            "target": str(target),
                            "original_exists": True,
                            "original_sha256": hashlib.sha256(original).hexdigest(),
                            "desired_sha256": hashlib.sha256(desired).hexdigest(),
                            "backup_path": str(backup),
                            "temp_path": str(temporary),
                        }
                    ],
                },
            )
            os.replace(temporary, target)

            with self.assertRaisesRegex(
                RuntimeError,
                "publication recovery is required before dry-run",
            ):
                client_config.install_client_configs(
                    home=home,
                    repo_root=repo,
                    launcher_path=home / ".local" / "bin" / "synapse-s2-mcp",
                    dry_run=True,
                    codex_enabled=False,
                )

            self.assertEqual(target.read_bytes(), desired)
            self.assertTrue(journal.exists())
            self.assertTrue(backup.exists())

    def test_hardlinked_client_config_and_lock_are_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            original = root / "original.json"
            target = root / "config.json"
            original.write_text("{}\n", encoding="utf-8")
            os.link(original, target)
            with self.assertRaises(OSError):
                client_config._write_text_if_changed(target, '{"safe":true}\n', dry_run=False)

            independent = root / "independent.json"
            independent.write_text("{}\n", encoding="utf-8")
            lock = root / ".independent.json.synapse-config.lock"
            lock.write_text("", encoding="utf-8")
            alias = root / "lock-alias"
            os.link(lock, alias)
            with self.assertRaisesRegex(ValueError, "lock is unsafe"):
                with client_config._exclusive_config_lock(independent):
                    pass


if __name__ == "__main__":
    unittest.main()

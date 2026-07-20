import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import client_config


class ClientConfigTests(unittest.TestCase):
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

    def test_server_definition_uses_shared_local_state_paths(self):
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
        self.assertEqual(server["command"], str(launcher))
        self.assertEqual(server["env"]["PYTHONPATH"], str(resolved_repo))
        self.assertEqual(server["env"]["MLX_DEVICE"], "gpu")
        self.assertEqual(server["env"]["SYNAPSE_S2_EMBEDDING_PROVIDER"], "mlx-neural")
        self.assertEqual(
            server["env"]["SYNAPSE_S2_NEURAL_MODEL"],
            "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ",
        )
        self.assertEqual(
            server["env"]["SYNAPSE_S2_NEURAL_CACHE_DIR"],
            str(resolved_repo / ".synapse_s2" / "models"),
        )
        self.assertEqual(
            server["env"]["SYNAPSE_S2_MEMORY_DB"],
            str(resolved_repo / ".synapse_s2" / "memory.sqlite3"),
        )
        self.assertEqual(server["env"]["SYNAPSE_S2_CAPTURE_ROOT"], str(resolved_repo / ".synapse_s2"))
        self.assertEqual(server["env"]["SYNAPSE_S2_CONTEXT_ID"], "default")
        self.assertEqual(server["env"]["SYNAPSE_S2_NEURONS"], "8192")
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
        self.assertIn('SYNAPSE_S2_CLIENT_AGENT_ID = "codex-desktop"', codex_text)
        self.assertIn('SYNAPSE_S2_CLIENT_SESSION_BRIDGE = "1"', codex_text)
        self.assertIn('SYNAPSE_S2_CLIENT_CORTEX = "1"', codex_text)
        self.assertIn('SYNAPSE_S2_CLIENT_CORTEX_MODE = "strict"', codex_text)
        self.assertIn(
            'SYNAPSE_S2_CLIENT_STARTUP_RECALL_MODE = "surface"',
            codex_text,
        )
        self.assertEqual(set(config_modes.values()), {0o600})
        self.assertIn('SYNAPSE_S2_EMBEDDING_PROVIDER = "mlx-neural"', codex_text)
        self.assertIn(
            'SYNAPSE_S2_NEURAL_MODEL = "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ"',
            codex_text,
        )
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
        self.assertIn('SYNAPSE_S2_CLIENT_AGENT_ID = "codex-desktop"', merged)
        self.assertIn('SYNAPSE_S2_EMBEDDING_PROVIDER = "mlx-neural"', merged)
        self.assertIn(
            'SYNAPSE_S2_NEURAL_MODEL = "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ"',
            merged,
        )
        self.assertNotIn("/old/synapse-s2-mcp", merged)
        self.assertNotIn("old-agent", merged)

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


if __name__ == "__main__":
    unittest.main()

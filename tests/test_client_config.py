import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import client_config


class ClientConfigTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

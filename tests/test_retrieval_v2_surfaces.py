from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

import mcp_server
import mlx_backend


ROOT = Path(__file__).resolve().parents[1]


class RetrievalV2McpSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.previous_engine = mlx_backend._ENGINE_INSTANCE
        self.previous_control_plane = mlx_backend._CONTROL_PLANE_INSTANCE
        self.backend = mlx_backend.SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=Path(self.temporary_directory.name) / "state.json",
            memory_path=Path(self.temporary_directory.name) / "memory.sqlite3",
            embedding_provider_name="semantic-hash",
        )
        mlx_backend._ENGINE_INSTANCE = self.backend
        mlx_backend._CONTROL_PLANE_INSTANCE = self.backend
        self.addCleanup(self._restore_backend)

    def _restore_backend(self) -> None:
        self.backend.memory_store.close()
        mlx_backend._ENGINE_INSTANCE = self.previous_engine
        mlx_backend._CONTROL_PLANE_INSTANCE = self.previous_control_plane

    def _payload(self, result) -> dict:
        if isinstance(result, dict):
            return result
        self.assertIsInstance(result.structured_content, dict)
        return result.structured_content

    def test_mcp_retrieval_v2_projects_after_compact_source_cap(self) -> None:
        self.backend.register_text_trace(
            tag="camera-memory",
            text="PTZ camera control room presets and routing evidence.",
            context_id="ops",
        )

        payload = self._payload(
            asyncio.run(
                mcp_server.mcp.call_tool(
                    "retrieve_spiking_memory_v2",
                    {
                        "prompt": "camera control room",
                        "context_id": "ops",
                        "recall_scope": "local",
                        "result_limit": 10,
                        "candidate_limit": 32,
                        "include_graph_neighbors": False,
                        "max_response_bytes": 4096,
                    },
                )
            )
        )

        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["operation"], "memory-retrieval")
        self.assertEqual(payload["response_contract"]["profile"], "compact")
        self.assertEqual(payload["pagination"]["requested_limit"], 10)
        self.assertEqual(payload["pagination"]["effective_limit"], 1)
        self.assertEqual(payload["pagination"]["returned"], 1)
        self.assertFalse(payload["pagination"]["supported"])
        self.assertFalse(payload["data"]["raw_input_stored"])
        self.assertEqual(payload["data"]["query"]["context_id"], "ops")
        self.assertEqual(payload["data"]["items"][0]["context_id"], "ops")

    def test_mcp_retrieval_v2_schema_allowlist_and_legacy_annotations(self) -> None:
        async def inspect():
            return {tool.name: tool for tool in await mcp_server.mcp.list_tools()}

        tools = asyncio.run(inspect())
        retrieval = tools["retrieve_spiking_memory_v2"]
        self.assertTrue(retrieval.annotations.readOnlyHint)
        self.assertEqual(
            retrieval.output_schema["properties"]["schema"]["const"],
            "synapse-s2.token-contract.v1",
        )
        properties = retrieval.parameters["properties"]
        self.assertEqual(
            properties["recall_scope"]["enum"],
            ["local", "connected", "all"],
        )
        self.assertEqual(
            properties["result_limit"]["maximum"],
            mlx_backend.RETRIEVAL_V2_MAX_RESULT_LIMIT,
        )
        self.assertEqual(
            properties["candidate_limit"]["maximum"],
            mlx_backend.RETRIEVAL_V2_MAX_CANDIDATE_LIMIT,
        )
        self.assertFalse(tools["query_spiking_attention"].annotations.readOnlyHint)
        self.assertFalse(tools["query_spiking_attention_text"].annotations.readOnlyHint)
        self.assertIn("Deprecated", tools["query_spiking_attention"].annotations.title)
        self.assertIn(
            "Deprecated",
            tools["query_spiking_attention_text"].annotations.title,
        )

    def test_mcp_retrieval_v2_rejects_invalid_bounds_and_unknown_fields(self) -> None:
        with mock.patch.object(
            self.backend,
            "retrieve_text_v2",
            wraps=self.backend.retrieve_text_v2,
        ) as retrieve:
            invalid = self._payload(
                mcp_server.retrieve_spiking_memory_v2(
                    "camera",
                    result_limit=8,
                    candidate_limit=7,
                    max_response_bytes=4096,
                )
            )
        retrieve.assert_not_called()
        self.assertFalse(invalid["ok"])
        self.assertEqual(invalid["operation"], "memory-retrieval")
        self.assertIn(
            "greater than or equal",
            invalid["data"]["error"]["message"],
        )

        secret = "SYNTHETIC_RETRIEVAL_UNKNOWN_SECRET_1234"
        result = asyncio.run(
            mcp_server.mcp.call_tool(
                "retrieve_spiking_memory_v2",
                {
                    "prompt": "camera",
                    "max_response_bytes": 4096,
                    "unexpected": {"password": secret},
                },
            )
        )
        rendered = json.dumps(
            {
                "content": [getattr(item, "text", "") for item in result.content],
                "structured": result.structured_content,
            },
            sort_keys=True,
        )
        self.assertNotIn(secret, rendered)
        self.assertFalse(result.is_error)
        self.assertFalse(result.structured_content["ok"])
        self.assertEqual(
            result.structured_content["operation"],
            "memory-retrieval",
        )


class RetrievalV2CliSurfaceTests(unittest.TestCase):
    def run_cli(
        self,
        *arguments: str,
        state_path: Path,
        memory_path: Path,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("SYNAPSE_S2_DEFAULT_RESPONSE_MODE", None)
        environment.pop("SYNAPSE_S2_MAX_RESPONSE_BYTES", None)
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "synapse_cli.py"),
                "--state",
                str(state_path),
                "--memory-db",
                str(memory_path),
                "--dimension",
                "32",
                "--neurons",
                "24",
                "--top-k",
                "6",
                "--embedding-provider",
                "semantic-hash",
                "--json",
                *arguments,
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_cli_retrieve_v2_compact_full_and_strict_bound_error(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            state_path = root / "state.json"
            memory_path = root / "memory.sqlite3"
            remembered = self.run_cli(
                "remember-text",
                "--context",
                "ops",
                "--tag",
                "camera-memory",
                "--text",
                "PTZ camera control room presets and routing evidence.",
                state_path=state_path,
                memory_path=memory_path,
            )
            compact = self.run_cli(
                "retrieve-v2",
                "--context",
                "ops",
                "--prompt",
                "camera control room",
                "--result-limit",
                "10",
                "--candidate-limit",
                "32",
                "--no-include-graph-neighbors",
                "--max-response-bytes",
                "4096",
                state_path=state_path,
                memory_path=memory_path,
            )
            full = self.run_cli(
                "retrieve-v2",
                "--context",
                "ops",
                "--text",
                "camera control room",
                "--result-limit",
                "2",
                "--candidate-limit",
                "16",
                "--response-mode",
                "full",
                "--max-response-bytes",
                "131072",
                state_path=state_path,
                memory_path=memory_path,
            )
            invalid = self.run_cli(
                "retrieve-v2",
                "--prompt",
                "camera",
                "--result-limit",
                "8",
                "--candidate-limit",
                "7",
                "--max-response-bytes",
                "4096",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(remembered.returncode, 0, remembered.stderr)
        self.assertEqual(compact.returncode, 0, compact.stderr)
        compact_payload = json.loads(compact.stdout)
        self.assertEqual(compact_payload["operation"], "memory-retrieval")
        self.assertEqual(compact_payload["pagination"]["requested_limit"], 10)
        self.assertEqual(compact_payload["pagination"]["effective_limit"], 1)
        self.assertEqual(compact_payload["data"]["query"]["context_id"], "ops")
        self.assertEqual(compact_payload["data"]["result_count"], 1)

        self.assertEqual(full.returncode, 0, full.stderr)
        full_payload = json.loads(full.stdout)
        self.assertEqual(full_payload["operation"], "memory-retrieval")
        self.assertEqual(full_payload["response_contract"]["profile"], "full")
        self.assertEqual(
            full_payload["data"]["payload"]["schema"],
            "synapse-retrieval.v2",
        )

        self.assertEqual(invalid.returncode, 1, invalid.stderr)
        invalid_payload = json.loads(invalid.stdout)
        self.assertEqual(invalid_payload["operation"], "memory-retrieval")
        self.assertFalse(invalid_payload["ok"])
        self.assertIn(
            "greater than or equal",
            invalid_payload["data"]["error"]["message"],
        )


if __name__ == "__main__":
    unittest.main()

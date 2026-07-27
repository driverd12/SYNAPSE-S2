import contextlib
import ast
import asyncio
import io
import inspect
import json
import logging
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

import mlx_backend
import mcp_server
from capture_daemon import CaptureInboxDaemon
from core_client import CoreOutcomeUnknown


class McpServerTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        test_backend = mlx_backend.SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=Path(self.tmpdir.name) / "state.json",
            memory_path=Path(self.tmpdir.name) / "memory.sqlite3",
        )
        mlx_backend._ENGINE_INSTANCE = test_backend
        mlx_backend._CONTROL_PLANE_INSTANCE = test_backend
        self.addCleanup(lambda: setattr(mlx_backend, "_ENGINE_INSTANCE", None))
        self.addCleanup(
            lambda: setattr(mlx_backend, "_CONTROL_PLANE_INSTANCE", None)
        )
        self.previous_export_dir = os.environ.get("SYNAPSE_S2_EXPORT_DIR")
        self.previous_capture_root = os.environ.get("SYNAPSE_S2_CAPTURE_ROOT")
        self.previous_client_agent_id = os.environ.get(
            "SYNAPSE_S2_CLIENT_AGENT_ID"
        )
        self.previous_response_mode = os.environ.get(
            "SYNAPSE_S2_DEFAULT_RESPONSE_MODE"
        )
        self.previous_response_budget = os.environ.get(
            "SYNAPSE_S2_MAX_RESPONSE_BYTES"
        )
        os.environ["SYNAPSE_S2_EXPORT_DIR"] = self.tmpdir.name
        os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = str(Path(self.tmpdir.name) / "capture-root")
        os.environ["SYNAPSE_S2_CLIENT_AGENT_ID"] = "codex-desktop"
        os.environ["SYNAPSE_S2_DEFAULT_RESPONSE_MODE"] = "compact"
        os.environ.pop("SYNAPSE_S2_MAX_RESPONSE_BYTES", None)
        self.addCleanup(self._restore_export_dir)
        self.addCleanup(self._restore_capture_root)
        self.addCleanup(self._restore_client_agent_id)
        self.addCleanup(self._restore_response_contract_environment)

    def test_recovery_tools_forward_expected_journal_and_runtime_digests(self):
        digest = "b" * 64
        runtime_digest = "c" * 64
        backend = mock.Mock()
        backend.verify_recovery_bundle.return_value = {"verified": True}
        backend.restore_recovery_bundle_isolated.return_value = {"verified": True}
        receipt = str(Path(self.tmpdir.name) / "bundle.receipt.json")
        output_root = str(Path(self.tmpdir.name) / "restore-proof")
        with mock.patch.object(
            mcp_server,
            "_load_backend",
            return_value=(None, backend),
        ):
            verified = json.loads(
                mcp_server.verify_spiking_recovery(
                    receipt,
                    expected_request_journal_sha256=digest,
                    expected_runtime_state_sha256=runtime_digest,
                )
            )
            restored = json.loads(
                mcp_server.restore_spiking_recovery_proof(
                    receipt,
                    output_root,
                    expected_request_journal_sha256=digest,
                    expected_runtime_state_sha256=runtime_digest,
                    confirm=True,
                )
            )

        self.assertTrue(verified["verified"])
        self.assertTrue(restored["verified"])
        backend.verify_recovery_bundle.assert_called_once_with(
            str(Path(receipt).resolve()),
            expected_database_sha256=None,
            expected_capture_sha256=None,
            expected_request_journal_sha256=digest,
            expected_runtime_state_sha256=runtime_digest,
        )
        backend.restore_recovery_bundle_isolated.assert_called_once_with(
            str(Path(receipt).resolve()),
            str(Path(output_root).resolve()),
            expected_database_sha256=None,
            expected_capture_sha256=None,
            expected_request_journal_sha256=digest,
            expected_runtime_state_sha256=runtime_digest,
            confirm=True,
        )

    def _contract_payload(self, response) -> dict:
        if isinstance(response, dict):
            return response
        structured = getattr(response, "structured_content", None)
        self.assertIsInstance(structured, dict)
        return structured

    def _full_contract_payload(self, response) -> dict:
        response = self._contract_payload(response)
        self.assertEqual(response["schema"], "synapse-s2.token-contract.v1")
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["response_contract"]["profile"], "full")
        return response["data"]["payload"]

    def _restore_export_dir(self):
        if self.previous_export_dir is None:
            os.environ.pop("SYNAPSE_S2_EXPORT_DIR", None)
        else:
            os.environ["SYNAPSE_S2_EXPORT_DIR"] = self.previous_export_dir

    def _restore_capture_root(self):
        if self.previous_capture_root is None:
            os.environ.pop("SYNAPSE_S2_CAPTURE_ROOT", None)
        else:
            os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = self.previous_capture_root

    def _restore_client_agent_id(self):
        if self.previous_client_agent_id is None:
            os.environ.pop("SYNAPSE_S2_CLIENT_AGENT_ID", None)
        else:
            os.environ["SYNAPSE_S2_CLIENT_AGENT_ID"] = (
                self.previous_client_agent_id
            )

    def _restore_response_contract_environment(self):
        if self.previous_response_mode is None:
            os.environ.pop("SYNAPSE_S2_DEFAULT_RESPONSE_MODE", None)
        else:
            os.environ["SYNAPSE_S2_DEFAULT_RESPONSE_MODE"] = (
                self.previous_response_mode
            )
        if self.previous_response_budget is None:
            os.environ.pop("SYNAPSE_S2_MAX_RESPONSE_BYTES", None)
        else:
            os.environ["SYNAPSE_S2_MAX_RESPONSE_BYTES"] = (
                self.previous_response_budget
            )

    def test_query_rejects_empty_embedding(self):
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            result = mcp_server.query_spiking_attention([], context_id="demo")

        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("invalid prompt_embedding", result)

    def test_public_tool_error_redacts_secret_and_local_path(self):
        secret = "sk-phase4-secret-1234567890"
        local_path = "/Users/dan.driver/private/synapse-token.json"
        with mock.patch.object(
            mcp_server,
            "_load_backend",
            side_effect=RuntimeError(f"token={secret} at {local_path}"),
        ):
            result = mcp_server.query_spiking_attention_text("hello")

        self.assertIn("spiking attention unavailable", result)
        self.assertIn("[REDACTED_SECRET]", result)
        self.assertIn("[LOCAL_PATH]", result)
        self.assertNotIn(secret, result)
        self.assertNotIn(local_path, result)

    def test_mutation_outcome_unknown_returns_fixed_reconciliation_handle(self):
        error = CoreOutcomeUnknown(
            caller="mcp-caller",
            request_id="req-mcp-ambiguous",
            operation="set_enabled",
        )
        with mock.patch.object(mcp_server, "_load_backend", side_effect=error):
            payload = json.loads(
                mcp_server.set_spiking_attention_enabled(
                    False,
                    context_id="default",
                )
            )

        self.assertEqual(
            payload["error"],
            {
                "code": "outcome_unknown",
                "message": "mutation outcome requires reconciliation",
                "reconciliation": {
                    "code": "outcome_unknown",
                    "caller": "mcp-caller",
                    "request_id": "req-mcp-ambiguous",
                    "operation": "set_enabled",
                    "replay_safe": False,
                },
            },
        )
        rendered = json.dumps(payload, sort_keys=True)
        for forbidden in ("arguments", "fingerprint", "response_sha256", "canary"):
            self.assertNotIn(forbidden, rendered)

    def test_core_request_status_tool_reconciles_without_replay(self):
        client = mock.Mock()
        client.request_status.return_value = {
            "caller": "mcp-caller",
            "request_id": "req-mcp-status",
            "state": "ambiguous",
            "operation": "set_enabled",
            "replay_safe": False,
            "retention_expiry_possible": False,
        }
        with mock.patch.object(
            mcp_server.CoreClient,
            "from_environment",
            return_value=client,
        ):
            payload = json.loads(
                mcp_server.get_core_request_status(
                    "mcp-caller",
                    "req-mcp-status",
                )
            )

        self.assertEqual(payload["state"], "ambiguous")
        self.assertFalse(payload["replay_safe"])
        client.request_status.assert_called_once_with(
            caller="mcp-caller",
            request_id="req-mcp-status",
        )

    def test_token_contract_tools_default_compact_and_honor_byte_budgets(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="compact-contract-memory",
                context_id="compact-contract",
                text="Compact MCP responses preserve provenance without vectors or local paths.",
                metadata={"surface": "mcp-test"},
            )
        )
        responses = {
            "memory-list": self._contract_payload(mcp_server.list_spiking_memory(
                context_id="compact-contract",
                max_response_bytes=4096,
            )),
            "memory-graph": self._contract_payload(mcp_server.list_spiking_memory_graph(
                context_id="compact-contract",
                max_response_bytes=4096,
            )),
            "cortex-state": self._contract_payload(mcp_server.get_spiking_cortex_state(
                context_id="compact-contract",
                max_response_bytes=4096,
            )),
            "agent-hydration": self._contract_payload(mcp_server.hydrate_spiking_agent_context(
                agent_id="codex-desktop",
                context_id="compact-contract",
                max_response_bytes=4096,
            )),
        }

        for operation, response in responses.items():
            with self.subTest(operation=operation):
                encoded = json.dumps(
                    response,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
                self.assertTrue(response["ok"], response)
                self.assertEqual(
                    response["schema"],
                    "synapse-s2.token-contract.v1",
                )
                self.assertEqual(response["operation"], operation)
                self.assertEqual(response["response_contract"]["profile"], "compact")
                self.assertEqual(response["response_contract"]["max_output_bytes"], 4096)
                self.assertEqual(
                    response["response_contract"]["serialized_bytes"],
                    len(encoded),
                )
                self.assertLessEqual(len(encoded), 4096)

        hydration = responses["agent-hydration"]
        receipts = [
            item["receipt_id"]
            for item in hydration["data"]["delivery"]["deployments"]
        ]
        self.assertEqual(len(receipts), 1)
        ack = json.loads(
            mcp_server.ack_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="compact-contract",
                receipt_ids=receipts,
            )
        )
        self.assertEqual(ack["acknowledged_count"], 1)
        self.assertEqual(
            hydration["data"]["event_window"]["latest_event_id"],
            registration["agent_deployment"]["event_id"],
        )
        compact_json = json.dumps(responses, sort_keys=True)
        self.assertNotIn(str(Path(self.tmpdir.name)), compact_json)
        self.assertNotIn("memory_db_path", compact_json)
        self.assertNotIn("lease_token", compact_json)
        self.assertNotIn("spike_indices", compact_json)
        self.assertNotIn("neuron_indices", compact_json)

    def test_compact_memory_rejects_vectors_before_loading_backend(self):
        with mock.patch.object(mcp_server, "_load_backend") as load_backend:
            response = self._contract_payload(mcp_server.list_spiking_memory(
                context_id="demo",
                include_vectors=True,
            ))

        load_backend.assert_not_called()
        self.assertFalse(response["ok"])
        self.assertEqual(response["operation"], "memory-list")
        self.assertIn("do not support vectors", response["data"]["error"]["message"])

    def test_contract_backend_error_preserves_valid_requested_budget(self):
        with mock.patch.object(
            mcp_server,
            "_load_backend",
            side_effect=RuntimeError("synthetic backend failure"),
        ):
            response = self._contract_payload(
                mcp_server.list_spiking_memory(
                    context_id="demo",
                    max_response_bytes=4096,
                )
            )

        self.assertFalse(response["ok"])
        self.assertEqual(response["response_contract"]["max_output_bytes"], 4096)

    def test_contract_argument_errors_preserve_valid_requested_budget(self):
        secret = "sk-budget-error-secret-1234567890"
        responses = (
            self._contract_payload(
                mcp_server.list_spiking_memory(
                    response_mode="unsupported",
                    max_response_bytes=4096,
                )
            ),
            self._contract_payload(
                mcp_server.list_spiking_memory(
                    context_id=f"api_key={secret}",
                    max_response_bytes=4096,
                )
            ),
        )

        for response in responses:
            self.assertFalse(response["ok"])
            self.assertEqual(
                response["response_contract"]["max_output_bytes"], 4096
            )
            self.assertNotIn(secret, json.dumps(response, sort_keys=True))

    def test_compact_hydration_caps_before_lease_and_exposes_every_receipt(self):
        backend = mlx_backend.get_backend()
        for ordinal in range(12):
            backend.publish_context_event(
                context_id="compact-cap",
                source_surface="mcp-contract-test",
                event_type="compact-cap",
                summary=f"compact event {ordinal}",
                agent_targets=["codex-desktop"],
            )

        with mock.patch.object(
            backend,
            "hydrate_agent_context",
            wraps=backend.hydrate_agent_context,
        ) as hydrate:
            response = self._contract_payload(mcp_server.hydrate_spiking_agent_context(
                agent_id="codex-desktop",
                context_id="compact-cap",
                limit=500,
                graph_limit=500,
                max_response_bytes=4096,
            ))

        self.assertTrue(response["ok"], response)
        effective_event_limit = hydrate.call_args.kwargs["event_limit"]
        self.assertGreaterEqual(effective_event_limit, 1)
        self.assertLess(effective_event_limit, 12)
        self.assertEqual(hydrate.call_args.kwargs["graph_limit"], 20)
        deployments = response["data"]["delivery"]["deployments"]
        self.assertEqual(len(deployments), effective_event_limit)
        self.assertEqual(
            len({item["receipt_id"] for item in deployments}),
            len(deployments),
        )
        self.assertEqual(
            len({item["event_id"] for item in deployments}),
            len(deployments),
        )
        self.assertTrue(all(isinstance(item["event"], dict) for item in deployments))
        self.assertTrue(response["data"]["delivery"]["has_more"])
        self.assertEqual(
            response["pagination"]["effective_limit"],
            effective_event_limit,
        )
        ack = json.loads(
            mcp_server.ack_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="compact-cap",
                receipt_ids=[item["receipt_id"] for item in deployments],
            )
        )
        self.assertEqual(ack["acknowledged_count"], effective_event_limit)

    def test_hydration_projection_failure_releases_all_leased_receipts(self):
        backend = mlx_backend.get_backend()
        backend.publish_context_event(
            context_id="projection-failure",
            source_surface="mcp-contract-test",
            event_type="projection-failure",
            summary="Release this receipt if projection fails.",
            agent_targets=["codex-desktop"],
        )
        secret = "sk-projection-secret-1234567890"
        local_path = "/Users/dan.driver/private/projection.json"
        with (
            mock.patch.object(
                backend,
                "release_context_events",
                wraps=backend.release_context_events,
            ) as release,
            mock.patch.object(
                mcp_server,
                "project_response",
                side_effect=RuntimeError(f"token={secret} at {local_path}"),
            ),
        ):
            response = self._contract_payload(mcp_server.hydrate_spiking_agent_context(
                agent_id="codex-desktop",
                context_id="projection-failure",
            ))

        self.assertFalse(response["ok"])
        release.assert_called_once()
        released_receipts = release.call_args.kwargs["receipt_ids"]
        self.assertEqual(len(released_receipts), 1)
        self.assertTrue(released_receipts[0].startswith("ctxrcpt_"))
        rendered = json.dumps(response, sort_keys=True)
        self.assertIn("[REDACTED_SECRET]", rendered)
        self.assertIn("[LOCAL_PATH]", rendered)
        self.assertNotIn(secret, rendered)
        self.assertNotIn(local_path, rendered)

    def test_hydration_failure_before_claim_never_creates_a_lease(self):
        backend = mlx_backend.get_backend()
        backend.publish_context_event(
            context_id="pre-claim-failure",
            source_surface="mcp-contract-test",
            event_type="pre-claim-failure",
            summary="This event must remain unleased if evidence assembly fails.",
            agent_targets=["codex-desktop"],
        )
        with (
            mock.patch.object(
                backend,
                "list_memory_graph",
                side_effect=RuntimeError("synthetic graph failure"),
            ),
            mock.patch.object(
                backend,
                "lease_context_events",
                wraps=backend.lease_context_events,
            ) as lease,
        ):
            response = self._contract_payload(
                mcp_server.hydrate_spiking_agent_context(
                    agent_id="codex-desktop",
                    context_id="pre-claim-failure",
                )
            )

        self.assertFalse(response["ok"])
        lease.assert_not_called()

    def test_backend_post_claim_hydration_failure_releases_receipts(self):
        backend = mlx_backend.get_backend()
        backend.publish_context_event(
            context_id="post-claim-failure",
            source_surface="mcp-contract-test",
            event_type="post-claim-failure",
            summary="This receipt must be released if final composition fails.",
            agent_targets=["codex-desktop"],
        )
        with (
            mock.patch.object(
                backend,
                "_compose_agent_hydration_payload",
                side_effect=RuntimeError("synthetic compose failure"),
            ),
            mock.patch.object(
                backend,
                "release_context_events",
                wraps=backend.release_context_events,
            ) as release,
        ):
            response = self._contract_payload(
                mcp_server.hydrate_spiking_agent_context(
                    agent_id="codex-desktop",
                    context_id="post-claim-failure",
                )
            )

        self.assertFalse(response["ok"])
        release.assert_called_once()
        self.assertEqual(len(release.call_args.kwargs["receipt_ids"]), 1)

    def test_invalid_any_contract_arguments_do_not_echo_secrets(self):
        secret = "sk-contract-argument-secret-1234567890"
        with self.assertLogs(mcp_server.LOGGER, level="WARNING") as captured:
            direct = self._contract_payload(mcp_server.list_spiking_memory(
                response_mode=f"api_key={secret}",
            ))
            in_memory = asyncio.run(
                mcp_server.mcp.call_tool(
                    "list_spiking_memory",
                    {"max_response_bytes": {"password": secret}},
                )
            )

        combined = "\n".join(captured.output) + json.dumps(direct, sort_keys=True) + repr(in_memory)
        self.assertNotIn(secret, combined)
        self.assertFalse(direct["ok"])
        self.assertIn("compact or full", direct["data"]["error"]["message"])
        self.assertFalse(in_memory.structured_content["ok"])
        self.assertIn(
            "must be an integer",
            in_memory.structured_content["data"]["error"]["message"],
        )

    def test_fastmcp_contract_tools_publish_output_schema_and_structured_content(self):
        async def inspect_tools():
            tools = await mcp_server.mcp.list_tools()
            result = await mcp_server.mcp.call_tool(
                "list_spiking_memory",
                {"context_id": "structured-output"},
            )
            return tools, result

        tools, result = asyncio.run(inspect_tools())
        selected_names = {
            "list_spiking_memory",
            "list_spiking_memory_graph",
            "hydrate_spiking_agent_context",
            "get_spiking_cortex_state",
        }
        selected = {tool.name: tool for tool in tools if tool.name in selected_names}
        self.assertEqual(set(selected), selected_names)
        for tool in selected.values():
            with self.subTest(tool=tool.name):
                self.assertEqual(
                    tool.output_schema["properties"]["schema"]["const"],
                    "synapse-s2.token-contract.v1",
                )
                self.assertFalse(tool.output_schema["additionalProperties"])
                self.assertEqual(
                    tool.parameters["properties"]["response_mode"]["type"],
                    "string",
                )
                self.assertEqual(
                    len(tool.parameters["properties"]["max_response_bytes"]["oneOf"]),
                    2,
                )

        self.assertFalse(result.is_error)
        self.assertEqual(
            result.structured_content["schema"],
            "synapse-s2.token-contract.v1",
        )
        guidance = result.content[0].text
        self.assertLess(len(guidance.encode("utf-8")), 512)
        self.assertIn("structuredContent", guidance)
        self.assertFalse(guidance.lstrip().startswith("{"))
        structured_bytes = json.dumps(
            result.structured_content,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self.assertEqual(
            len(structured_bytes),
            result.structured_content["response_contract"]["serialized_bytes"],
        )

    def test_fastmcp_contract_arguments_never_reflect_prevalidation_secrets(self):
        secret = "SYNTHETIC_ONLY_PREVALIDATION_SECRET_1234"
        credential = f"password={secret}"
        cases = (
            ("list_spiking_memory", {"context_id": {"password": secret}}),
            ("list_spiking_memory", {"limit": credential}),
            ("list_spiking_memory", {"include_vectors": credential}),
            ("list_spiking_memory_graph", {"context_id": {"password": secret}}),
            ("list_spiking_memory_graph", {"limit": credential}),
            ("hydrate_spiking_agent_context", {"agent_id": {"password": secret}}),
            (
                "hydrate_spiking_agent_context",
                {"agent_id": "codex-desktop", "context_id": {"password": secret}},
            ),
            (
                "hydrate_spiking_agent_context",
                {"agent_id": "codex-desktop", "prompt": {"password": secret}},
            ),
            (
                "hydrate_spiking_agent_context",
                {"agent_id": "codex-desktop", "limit": credential},
            ),
            (
                "hydrate_spiking_agent_context",
                {"agent_id": "codex-desktop", "graph_limit": credential},
            ),
            ("get_spiking_cortex_state", {"agent_id": {"password": secret}}),
            ("get_spiking_cortex_state", {"context_id": {"password": secret}}),
            ("get_spiking_cortex_state", {"limit": credential}),
        )
        for tool_name, arguments in cases:
            with self.subTest(tool=tool_name, field=next(iter(arguments))):
                arguments = {**arguments, "max_response_bytes": 4096}
                with self.assertLogs("synapse_s2.mcp", level="WARNING") as captured:
                    result = asyncio.run(
                        mcp_server.mcp.call_tool(tool_name, arguments)
                    )
                rendered = json.dumps(
                    {
                        "structured": result.structured_content,
                        "content": [
                            getattr(item, "text", "") for item in result.content
                        ],
                        "logs": captured.output,
                    },
                    sort_keys=True,
                )
                self.assertNotIn(secret, rendered)
                self.assertNotIn(credential, rendered)
                self.assertFalse(result.is_error)
                self.assertFalse(result.structured_content["ok"])
                self.assertEqual(
                    result.structured_content["response_contract"][
                        "max_output_bytes"
                    ],
                    4096,
                )

    def test_fastmcp_contract_tools_reject_unknown_arguments_before_validation(self):
        secret = "SYNTHETIC_UNKNOWN_ARGUMENT_SECRET_987654321"
        credential = f"password={secret}"
        local_path = "/Users/operator/private/unknown-argument-secret.json"
        cases = (
            ("list_spiking_memory", {}, "memory-list"),
            ("list_spiking_memory_graph", {}, "memory-graph"),
            (
                "hydrate_spiking_agent_context",
                {"agent_id": "codex-desktop"},
                "agent-hydration",
            ),
            ("get_spiking_cortex_state", {}, "cortex-state"),
        )
        for tool_name, required_arguments, operation in cases:
            for run_middleware in (True, False):
                with self.subTest(
                    tool=tool_name,
                    run_middleware=run_middleware,
                ):
                    arguments = {
                        **required_arguments,
                        "max_response_bytes": 4096,
                        secret: {
                            "password": credential,
                            "path": local_path,
                        },
                    }
                    with self.assertLogs(
                        "synapse_s2.mcp",
                        level="WARNING",
                    ) as captured:
                        result = asyncio.run(
                            mcp_server.mcp.call_tool(
                                tool_name,
                                arguments,
                                run_middleware=run_middleware,
                            )
                        )
                    rendered = json.dumps(
                        {
                            "structured": result.structured_content,
                            "content": [
                                getattr(item, "text", "")
                                for item in result.content
                            ],
                            "logs": captured.output,
                        },
                        sort_keys=True,
                    )
                    self.assertNotIn(secret, rendered)
                    self.assertNotIn(credential, rendered)
                    self.assertNotIn(local_path, rendered)
                    self.assertFalse(result.is_error)
                    self.assertFalse(result.structured_content["ok"])
                    self.assertEqual(
                        result.structured_content["operation"],
                        operation,
                    )
                    self.assertEqual(
                        result.structured_content["response_contract"][
                            "max_output_bytes"
                        ],
                        4096,
                    )
                    self.assertIn(
                        "undeclared tool arguments",
                        result.structured_content["data"]["error"]["message"],
                    )

    def test_fastmcp_transport_and_registry_bypasses_never_log_raw_arguments(self):
        secret = "SYNTHETIC_TRANSPORT_ARGUMENT_SECRET_13579"
        credential = f"password={secret}"
        local_path = "/Users/operator/private/transport-secret.json"
        cases = (
            ("list_spiking_memory", {}, "context_id"),
            ("list_spiking_memory_graph", {}, "context_id"),
            (
                "hydrate_spiking_agent_context",
                {"agent_id": "codex-desktop"},
                "prompt",
            ),
            ("get_spiking_cortex_state", {}, "context_id"),
        )

        async def exercise(tool_name, arguments):
            wire = await mcp_server.mcp._call_tool_mcp(tool_name, arguments)
            tool = await mcp_server.mcp.get_tool(tool_name)
            direct = await tool.run(arguments)
            internal = await tool._run(arguments)
            return wire, direct, internal

        transport_logger = logging.getLogger(
            "fastmcp.server.mixins.mcp_operations"
        )
        previous_level = transport_logger.level
        transport_logger.setLevel(logging.DEBUG)
        try:
            for tool_name, required_arguments, declared_field in cases:
                payloads = (
                    {
                        **required_arguments,
                        "max_response_bytes": 4096,
                        secret: {
                            "password": credential,
                            "path": local_path,
                        },
                    },
                    {
                        **required_arguments,
                        declared_field: {
                            "password": credential,
                            "path": local_path,
                        },
                        "max_response_bytes": 4096,
                    },
                )
                for arguments in payloads:
                    with self.subTest(
                        tool=tool_name,
                        unknown_argument=secret in arguments,
                    ):
                        with self.assertLogs(level="DEBUG") as captured:
                            wire, direct, internal = asyncio.run(
                                exercise(tool_name, arguments)
                            )
                        wire_content, wire_structured = wire
                        rendered = json.dumps(
                            {
                                "wire": {
                                    "content": [
                                        item.model_dump(by_alias=True)
                                        for item in wire_content
                                    ],
                                    "structuredContent": wire_structured,
                                },
                                "direct": direct.structured_content,
                                "internal": internal.structured_content,
                                "logs": captured.output,
                            },
                            sort_keys=True,
                            default=str,
                        )
                        normalized = re.sub(r"\s+", "", rendered)
                        self.assertNotIn(secret, normalized)
                        self.assertNotIn(credential, normalized)
                        self.assertNotIn(local_path, normalized)
                        self.assertFalse(wire_structured["ok"])
                        self.assertFalse(direct.structured_content["ok"])
                        self.assertFalse(internal.structured_content["ok"])
        finally:
            transport_logger.setLevel(previous_level)

    def test_fastmcp_real_in_memory_transport_never_logs_unknown_arguments(self):
        from fastmcp import Client

        secret = "SYNTHETIC_REAL_TRANSPORT_SECRET_24680"
        credential = f"password={secret}"
        local_path = "/Users/operator/private/real-transport-secret.json"
        cases = (
            ("list_spiking_memory", {}),
            ("list_spiking_memory_graph", {}),
            (
                "hydrate_spiking_agent_context",
                {"agent_id": "codex-desktop"},
            ),
            ("get_spiking_cortex_state", {}),
        )

        async def exercise():
            results = {}
            async with Client(mcp_server.mcp) as client:
                for tool_name, required_arguments in cases:
                    results[tool_name] = await client.call_tool(
                        tool_name,
                        {
                            **required_arguments,
                            "max_response_bytes": 4096,
                            secret: {
                                "password": credential,
                                "path": local_path,
                            },
                        },
                    )
            return results

        fastmcp_logger = logging.getLogger("fastmcp")
        previous_level = fastmcp_logger.level
        fastmcp_logger.setLevel(logging.DEBUG)
        try:
            with self.assertLogs(level="DEBUG") as captured:
                results = asyncio.run(exercise())
        finally:
            fastmcp_logger.setLevel(previous_level)

        rendered = json.dumps(
            {
                "logs": captured.output,
                "results": {
                    tool_name: {
                        "content": [
                            item.model_dump(by_alias=True)
                            for item in result.content
                        ],
                        "structuredContent": result.structured_content,
                    }
                    for tool_name, result in results.items()
                },
            },
            sort_keys=True,
            default=str,
        )
        normalized = re.sub(r"\s+", "", rendered)
        self.assertNotIn(secret, normalized)
        self.assertNotIn(credential, normalized)
        self.assertNotIn(local_path, normalized)
        for tool_name, result in results.items():
            with self.subTest(tool=tool_name):
                self.assertFalse(result.is_error)
                self.assertFalse(result.structured_content["ok"])
                self.assertEqual(
                    result.structured_content["response_contract"][
                        "max_output_bytes"
                    ],
                    4096,
                )

    def test_invalid_mcp_budget_errors_keep_the_installed_ceiling(self):
        cases = (
            ("list_spiking_memory", {}),
            ("list_spiking_memory_graph", {}),
            ("hydrate_spiking_agent_context", {"agent_id": "codex-desktop"}),
            ("get_spiking_cortex_state", {}),
        )
        secret = "password=SYNTHETIC_INVALID_BUDGET_1234"
        with mock.patch.dict(
            os.environ,
            {"SYNAPSE_S2_MAX_RESPONSE_BYTES": "12288"},
            clear=False,
        ):
            for tool_name, arguments in cases:
                with self.subTest(tool=tool_name):
                    result = asyncio.run(
                        mcp_server.mcp.call_tool(
                            tool_name,
                            {**arguments, "max_response_bytes": secret},
                        )
                    )
                    rendered = json.dumps(
                        {
                            "structured": result.structured_content,
                            "content": [
                                getattr(item, "text", "") for item in result.content
                            ],
                        },
                        sort_keys=True,
                    )
                    self.assertNotIn(secret, rendered)
                    self.assertFalse(result.structured_content["ok"])
                    self.assertEqual(
                        result.structured_content["response_contract"][
                            "max_output_bytes"
                        ],
                        12288,
                    )

    def test_fastmcp_hydration_safety_summary_keeps_every_receipt_consumable(self):
        backend = mlx_backend.get_backend()
        for mode in ("compact", "full"):
            with self.subTest(mode=mode):
                context_id = f"safety-summary-{mode}"
                backend.publish_context_event(
                    context_id=context_id,
                    source_surface="mcp-contract-test",
                    event_type="safety-summary-event",
                    summary="Fallback clients need bounded evidence before acknowledging.",
                    agent_targets=["codex-desktop"],
                )
                result = asyncio.run(
                    mcp_server.mcp.call_tool(
                        "hydrate_spiking_agent_context",
                        {
                            "agent_id": "codex-desktop",
                            "context_id": context_id,
                            "response_mode": mode,
                            "max_response_bytes": 4096 if mode == "compact" else 131072,
                        },
                    )
                )
                prefix = "SYNAPSE-S2 safety summary: "
                self.assertTrue(result.content[0].text.startswith(prefix))
                summary = json.loads(result.content[0].text[len(prefix) :])
                structured = result.structured_content
                fallback_receipts = summary["delivery"]["receipts"]
                structured_deployments = (
                    structured["data"]["delivery"]["deployments"]
                    if mode == "compact"
                    else structured["data"]["payload"]["deliveries"]
                )
                self.assertEqual(
                    {(item["receipt_id"], item["event_id"]) for item in fallback_receipts},
                    {(item["receipt_id"], item["event_id"]) for item in structured_deployments},
                )
                self.assertTrue(all(item["event_type"] for item in fallback_receipts))
                self.assertTrue(all(item["source_surface"] for item in fallback_receipts))
                self.assertTrue(all(item["summary"] for item in fallback_receipts))
                self.assertTrue(
                    all(item["trust"] == "untrusted-event-evidence" for item in fallback_receipts)
                )
                self.assertLess(len(result.content[0].text.encode("utf-8")), 4096)
                ack = json.loads(
                    mcp_server.ack_spiking_context_deployments(
                        agent_id="codex-desktop",
                        context_id=context_id,
                        receipt_ids=[item["receipt_id"] for item in fallback_receipts],
                    )
                )
                self.assertEqual(ack["acknowledged_count"], len(fallback_receipts))

    def test_compact_safety_summary_is_bounded_for_eight_maximum_text_receipts(self):
        backend = mlx_backend.get_backend()
        context_id = "safety-summary-worst-compact"
        for index in range(8):
            backend.publish_context_event(
                context_id=context_id,
                source_surface=f"source-{index}-" + ("s" * 70),
                event_type=f"event-{index}-" + ("e" * 71),
                summary=(f"receipt evidence {index} " + ("x" * 1_000)),
                agent_targets=["codex-desktop"],
            )
        result = asyncio.run(
            mcp_server.mcp.call_tool(
                "hydrate_spiking_agent_context",
                {
                    "agent_id": "codex-desktop",
                    "context_id": context_id,
                    "limit": 8,
                    "response_mode": "compact",
                    "max_response_bytes": 12_288,
                },
            )
        )
        prefix = mcp_server.MCP_SAFETY_SUMMARY_PREFIX
        text_content = result.content[0].text
        self.assertTrue(text_content.startswith(prefix))
        self.assertLessEqual(
            len(text_content.encode("utf-8")),
            mcp_server.MCP_COMPACT_SAFETY_SUMMARY_BYTES,
        )
        summary = json.loads(text_content[len(prefix) :])
        receipts = summary["delivery"]["receipts"]
        structured_receipts = result.structured_content["data"]["delivery"]["deployments"]
        self.assertEqual(len(receipts), 8)
        self.assertEqual(
            {(item["receipt_id"], item["event_id"]) for item in receipts},
            {
                (item["receipt_id"], item["event_id"])
                for item in structured_receipts
            },
        )
        self.assertTrue(summary["delivery"]["receipt_decision_supported"])
        self.assertTrue(summary["delivery"]["evidence_text_truncated"])
        self.assertGreater(summary["delivery"]["omitted_text_characters"], 0)
        self.assertTrue(
            all(item["trust"] == "untrusted-event-evidence" for item in receipts)
        )
        ack = json.loads(
            mcp_server.ack_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id=context_id,
                receipt_ids=[item["receipt_id"] for item in receipts],
            )
        )
        self.assertEqual(ack["acknowledged_count"], 8)

    def test_compact_safety_summary_survives_maximum_ids_and_unicode_evidence(self):
        events = []
        deliveries = []
        for index in range(1, 9):
            events.append(
                {
                    "event_id": index,
                    "context_id": "default",
                    "event_type": "🧠" * 128,
                    "source_surface": "神" * 128,
                    "summary": "🚀" * 360,
                    "created_at": 1_900_000_000.0 + index,
                    "payload_summary": {"event_count": 1},
                }
            )
            deliveries.append(
                {
                    "receipt_id": "ctxrcpt_" + f"{index:043d}",
                    "delivery_id": ("d" * 158) + f"{index:02d}",
                    "event_id": index,
                    "context_id": "default",
                    "agent_id": "codex-desktop",
                    "consumer_instance_id": "c" * 256,
                    "state": "leased",
                    "attempt_count": 1,
                    "redelivered": False,
                    "ack_required": True,
                    "lease_expires_at": 1_900_000_100.0 + index,
                }
            )
        payload = {
            "context_id": "default",
            "agent_id": "codex-desktop",
            "protocol_version": "context-delivery.v2",
            "delivery_mode": "leased-at-least-once",
            "claim_events": True,
            "ack_required": True,
            "has_more_events": False,
            "remaining_pending_count": 8,
            "max_delivery_attempts": 3,
            "since_event_id": 0,
            "latest_event_id": 8,
            "new_event_count": 8,
            "events": events,
            "deliveries": deliveries,
            "recall_items": [],
            "graph_entries": [],
            "graph_relationships": [],
            "graph_summary": {
                "entry_count": 0,
                "relationship_count": 0,
                "relationship_modes": {"total": 0, "by_type": {}},
            },
            "namespace_connectivity": {
                "scope": "local-authoritative-store",
                "local_namespace_count": 1,
                "bridge_record_limit": 100,
                "active_bridge_records_returned": 0,
                "incident_bridge_records_returned": 0,
                "inbound_only_bridge_records_returned": 0,
                "bridge_records_truncated": False,
                "connected_context_count_lower_bound": 0,
                "connected_context_ids": [],
                "connected_context_ids_truncated": False,
                "pending_proposals_returned": 0,
                "pending_proposal_records_truncated": False,
                "pending_context_count_lower_bound": 0,
                "pending_context_ids": [],
                "pending_context_ids_truncated": False,
                "suggestion_evaluation": "on-demand-namespace-map",
                "automatic_cross_namespace_write": False,
                "multi_mac_live_sync": False,
            },
            "cortex_state": {
                "context_id": "default",
                "agent_id": "codex-desktop",
                "active_session_count": 0,
                "goal_count": 0,
                "typed_memory_counts": {},
            },
        }
        structured = mcp_server.project_response(
            "agent-hydration",
            payload,
            mode="compact",
            max_response_bytes=12_288,
        )
        result = mcp_server._contract_tool_result(structured)
        text_content = result.content[0].text

        self.assertLessEqual(
            len(text_content.encode("utf-8")),
            mcp_server.MCP_COMPACT_SAFETY_SUMMARY_BYTES,
        )
        summary = json.loads(
            text_content[len(mcp_server.MCP_SAFETY_SUMMARY_PREFIX) :]
        )
        receipts = summary["delivery"]["receipts"]
        self.assertEqual(len(receipts), 8)
        self.assertTrue(summary["delivery"]["receipt_decision_supported"])
        self.assertTrue(
            all(
                item["event_type"]
                and item["source_surface"]
                and item["summary"]
                for item in receipts
            )
        )
        self.assertEqual(
            {item["receipt_id"] for item in receipts},
            {item["receipt_id"] for item in deliveries},
        )

    def test_direct_tool_calls_guard_secret_bearing_context_and_agent_ids(self):
        secret = "sk-mcp-identifier-secret-1234567890"
        credential_id = f"password={secret}"

        plain_result = mcp_server.query_spiking_attention(
            [1.0],
            context_id=credential_id,
        )
        namespace_result = mcp_server.list_spiking_namespace_map(
            context_id=credential_id,
        )
        cortex_result = mcp_server.enter_spiking_cortex(
            agent_id=credential_id,
            context_id="default",
            task="safe task",
        )
        delivery_result = mcp_server.pull_spiking_context_deployments(
            agent_id=credential_id,
            context_id="default",
        )

        for result in (
            plain_result,
            namespace_result,
            cortex_result,
            delivery_result,
        ):
            with self.subTest(result=result):
                self.assertIn("must not contain credential material", result)
                self.assertNotIn(secret, result)

        self.assertIn("error", json.loads(namespace_result))
        self.assertIn("error", json.loads(cortex_result))
        self.assertIn("error", json.loads(delivery_result))

    def test_public_mcp_identifier_sanitizers_are_inside_tool_try_blocks(self):
        tree = ast.parse(inspect.getsource(mcp_server))
        sanitizer_names = {
            "_sanitize_context_id",
            "_sanitize_agent_id",
            "_delivery_agent_id",
        }
        violations: list[str] = []

        for function in (
            node for node in tree.body if isinstance(node, ast.FunctionDef)
        ):
            if not any(
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "tool"
                for decorator in function.decorator_list
            ):
                continue

            protected_calls = {
                id(node)
                for statement in function.body
                if isinstance(statement, ast.Try)
                for node in ast.walk(statement)
                if isinstance(node, ast.Call)
            }
            for call in (
                node for node in ast.walk(function) if isinstance(node, ast.Call)
            ):
                if (
                    isinstance(call.func, ast.Name)
                    and call.func.id in sanitizer_names
                    and id(call) not in protected_calls
                ):
                    violations.append(
                        f"{function.name}:{call.lineno}:{call.func.id}"
                    )

        self.assertEqual(violations, [])

    def test_direct_main_applies_binding_before_starting_session_bridge(self):
        order: list[str] = []

        def apply_binding():
            order.append("binding")

        def run_bridge(_run_server):
            order.append("bridge")

        with mock.patch.object(
            mcp_server,
            "apply_binding_environment",
            side_effect=apply_binding,
        ), mock.patch(
            "client_session_bridge.run_with_client_session_bridge",
            side_effect=run_bridge,
        ):
            mcp_server.main()

        self.assertEqual(order, ["binding", "bridge"])

    def test_capture_adapter_loader_applies_binding_before_returning_module(self):
        with mock.patch.object(
            mcp_server,
            "apply_binding_environment",
        ) as apply_binding:
            loaded = mcp_server._load_capture_daemon()

        apply_binding.assert_called_once_with()
        self.assertEqual(loaded.__name__, "capture_daemon")

    def test_unavailable_mcp_startup_error_is_sanitized(self):
        secret = "sk-startup-secret-1234567890"
        local_path = "/Users/dan.driver/private/fastmcp.py"
        with (
            mock.patch.object(
                mcp_server,
                "_FASTMCP_IMPORT_ERROR",
                RuntimeError(f"api_key={secret} from {local_path}"),
            ),
            mock.patch.object(mcp_server.LOGGER, "error") as log_error,
            self.assertRaises(SystemExit) as raised,
        ):
            mcp_server._UnavailableMCP().run()

        self.assertEqual(raised.exception.code, 1)
        message = str(log_error.call_args.args[0])
        self.assertIn("Import error:", message)
        self.assertIn("[REDACTED_SECRET]", message)
        self.assertIn("[LOCAL_PATH]", message)
        self.assertNotIn(secret, message)
        self.assertNotIn(local_path, message)

    def test_query_sanitizes_context_id(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="sanitized-memory",
                context_id="../demo with spaces",
                prompt_embedding=[0.0, 1.0, 9.0, 2.0, 7.0, -4.0],
            )
        )
        result = mcp_server.query_spiking_attention(
            [0.0, 1.0, 9.0, 2.0, 7.0, -4.0],
            context_id="../demo with spaces",
        )

        self.assertEqual(registration["context_id"], "demo_with_spaces")
        self.assertIn("sanitized-memory", result)
        self.assertIn("demo_with_spaces", result)
        self.assertNotIn("..", result)

    def test_namespace_map_compatibility_helper_requires_confirmation_before_linking(self):
        for context, tag, vector in (
            ("alpha", "alpha-memory", [1.0, 0.0, 1.0, 0.0, 0.0, 0.0]),
            ("beta", "beta-memory", [1.0, 0.0, 0.8, 0.0, 0.0, 0.0]),
        ):
            mcp_server.remember_spiking_context(
                tag=tag,
                context_id=context,
                prompt_embedding=vector,
                text=f"{context} shared topic",
            )

        refused = json.loads(
            mcp_server.approve_spiking_namespace_link(
                source_context_id="alpha",
                target_context_id="beta",
            )
        )
        approved = json.loads(
            mcp_server.approve_spiking_namespace_link(
                source_context_id="alpha",
                target_context_id="beta",
                weight=0.75,
                evidence={"source": "mcp-unit-test"},
                confirm=True,
            )
        )
        namespace_map = json.loads(
            mcp_server.list_spiking_namespace_map(context_id="alpha")
        )

        self.assertIn("confirm=true is required", refused["error"])
        self.assertTrue(approved["approved"])
        self.assertFalse(approved["automatic_cross_namespace_write"])
        self.assertEqual(namespace_map["node_count"], 2)
        self.assertEqual(namespace_map["link_count"], 1)
        self.assertEqual(namespace_map["connected_scope_hops"], 1)

    def test_namespace_proposal_mcp_isolated_then_cas_rejected(self):
        for context in ("alpha", "beta"):
            mcp_server.remember_spiking_context(
                tag=f"{context}-governed-memory",
                context_id=context,
                prompt_embedding=[1.0, 0.0, 0.5, 0.0, 0.0, 0.0],
                text=f"{context} governed bridge evidence",
            )
        proposed = json.loads(
            mcp_server.propose_spiking_namespace_link(
                source_context_id="alpha",
                target_context_id="beta",
                reason="MCP operator requested deliberate bridge review.",
                governance_request_id="mcp-proposal",
            )
        )
        pending_map = json.loads(
            mcp_server.list_spiking_namespace_map(context_id="alpha")
        )
        proposal = proposed["proposal"]
        reviewed = json.loads(
            mcp_server.reject_spiking_namespace_link(
                proposal_id=proposal["proposal_id"],
                expected_revision=proposal["revision"],
                reason="MCP caller rejected the proposal without gaining recall.",
                governance_request_id="mcp-review",
            )
        )
        audit = json.loads(mcp_server.audit_spiking_namespace_link_governance())
        history = json.loads(
            mcp_server.list_spiking_namespace_link_history(
                proposal_id=proposal["proposal_id"],
            )
        )
        final_map = json.loads(
            mcp_server.list_spiking_namespace_map(context_id="alpha")
        )

        self.assertEqual(proposed["state"], "pending")
        self.assertEqual(pending_map["link_count"], 0)
        self.assertEqual(reviewed["state"], "rejected")
        self.assertEqual(final_map["link_count"], 0)
        self.assertGreaterEqual(history["event_count"], 2)
        self.assertEqual(audit["status"], "ready")

    def test_mcp_bridge_tools_cannot_grant_their_own_recall(self):
        async def inspect_tools():
            return {tool.name: tool for tool in await mcp_server.mcp.list_tools()}

        tools = asyncio.run(inspect_tools())
        self.assertNotIn("approve_spiking_namespace_link", tools)
        self.assertNotIn("review_spiking_namespace_link", tools)
        self.assertIn("propose_spiking_namespace_link", tools)
        self.assertIn("reject_spiking_namespace_link", tools)
        self.assertIn("list_spiking_namespace_link_history", tools)
        self.assertIn("audit_spiking_namespace_link_governance", tools)
        self.assertFalse(tools["propose_spiking_namespace_link"].annotations.readOnlyHint)
        self.assertFalse(tools["reject_spiking_namespace_link"].annotations.readOnlyHint)
        self.assertTrue(
            tools["list_spiking_namespace_link_history"].annotations.readOnlyHint
        )

    def test_mcp_replication_surface_is_read_only_status_only(self):
        async def inspect_tools():
            return {tool.name: tool for tool in await mcp_server.mcp.list_tools()}

        tools = asyncio.run(inspect_tools())
        self.assertIn("get_spiking_replication_identity", tools)
        self.assertIn("get_spiking_replication_status", tools)
        self.assertTrue(
            tools["get_spiking_replication_identity"].annotations.readOnlyHint
        )
        self.assertTrue(
            tools["get_spiking_replication_status"].annotations.readOnlyHint
        )
        for forbidden in (
            "pair_spiking_replication_peer",
            "revoke_spiking_replication_peer",
            "create_spiking_replication_checkpoint",
            "stage_spiking_replication_checkpoint",
            "ack_spiking_replication_checkpoint",
        ):
            self.assertNotIn(forbidden, tools)

        core = mock.Mock()
        core.replication_identity.return_value = {"schema": "node"}
        core.replication_status.return_value = {"schema": "status"}
        with mock.patch.object(mcp_server, "_load_backend", return_value=(None, object())), mock.patch.object(
            mcp_server,
            "_loaded_core_client",
            return_value=core,
        ):
            identity = json.loads(mcp_server.get_spiking_replication_identity())
            status = json.loads(mcp_server.get_spiking_replication_status())
        self.assertEqual(identity["schema"], "node")
        self.assertEqual(status["schema"], "status")
        core.replication_identity.assert_called_once_with()
        core.replication_status.assert_called_once_with()

    def test_sleep_consolidation_returns_status_string(self):
        result = mcp_server.trigger_sleep_consolidation()

        self.assertIn("deep-sleep", result)

    def test_resource_profile_tool_reports_memory_estimate(self):
        profile = json.loads(
            mcp_server.profile_spiking_resources(benchmark_quick_prune=True)
        )

        self.assertEqual(profile["dimension"], 6)
        self.assertEqual(profile["num_neurons"], 10)
        self.assertIn("estimated_total_mb", profile)
        self.assertTrue(profile["quick_pruning"]["within_60ms_budget"])

    def test_embedding_provider_benchmark_tool_reports_provenance(self):
        self.assertTrue(
            hasattr(mcp_server, "benchmark_spiking_embedding_provider"),
            "MCP server must expose benchmark_spiking_embedding_provider",
        )
        benchmark = json.loads(
            mcp_server.benchmark_spiking_embedding_provider(
                text="MCP provider benchmark",
                runs=2,
                dimensions=6,
            )
        )

        self.assertEqual(benchmark["action"], "provider-benchmark")
        self.assertEqual(benchmark["runs"], 2)
        self.assertEqual(benchmark["dimensions"], 6)
        self.assertEqual(len(benchmark["sample_latencies_ms"]), 2)
        self.assertEqual(benchmark["embedding_provider"]["provider"], "semantic-hash-v1")

    def test_native_certification_tool_reports_evidence_shape(self):
        certification = json.loads(
            mcp_server.certify_spiking_runtime(
                strict_native=False,
                benchmark_quick_prune=True,
            )
        )

        self.assertEqual(certification["action"], "certify-runtime")
        self.assertIn("checks", certification)
        self.assertIn("resource_profile", certification)
        self.assertIn("quick_pruning", certification["resource_profile"])
        self.assertIn("mlx_available", certification["checks"])

    def test_idle_maintenance_tool_can_force_deep_sleep(self):
        result = json.loads(mcp_server.trigger_idle_maintenance(force_deep_sleep=True))

        self.assertEqual(result["mode"], "deep-sleep")
        self.assertEqual(result["trigger"], "idle-force")
        self.assertTrue(result["maintenance_run"])
        self.assertEqual(result["phase_count"], 7)

    def test_toggle_tool_disables_query_and_status_reports_state(self):
        disabled = json.loads(mcp_server.set_spiking_attention_enabled(False))
        status = json.loads(mcp_server.get_spiking_attention_status(context_id="demo"))
        disabled_query = mcp_server.query_spiking_attention(
            [0.0, 1.0, 9.0, 2.0, 7.0, -4.0],
            context_id="demo",
        )
        enabled = json.loads(mcp_server.set_spiking_attention_enabled(True))

        self.assertFalse(disabled["global_enabled"])
        self.assertFalse(status["effective_enabled"])
        self.assertIn("disabled", disabled_query.lower())
        self.assertTrue(enabled["global_enabled"])

    def test_remember_trace_tool_makes_query_return_named_context(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="exec-briefing-memory",
                context_id="demo",
                prompt_embedding=[0.0, 1.0, 9.0, 2.0, 7.0, -4.0],
                text="Tomorrow's executive SYNAPSE-S2 briefing",
                metadata={"source": "unit-test"},
            )
        )
        result = mcp_server.query_spiking_attention(
            [0.0, 1.0, 9.1, 2.1, 7.2, -4.0],
            context_id="demo",
        )

        self.assertEqual(registration["tag"], "exec-briefing-memory")
        self.assertTrue(registration["agent_deployment"]["published"])
        self.assertEqual(registration["agent_deployment"]["event_type"], "remember-trace")
        self.assertIn("exec-briefing-memory", result)

    def test_text_remember_tool_records_embedding_provider_provenance(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="mcp-semantic-memory",
                context_id="demo",
                text="Apple Silicon Metal acceleration",
                metadata={"surface": "mcp"},
            )
        )
        listing = self._full_contract_payload(
            mcp_server.list_spiking_memory(
                context_id="demo",
                limit=5,
                response_mode="full",
            )
        )
        status = json.loads(mcp_server.get_spiking_attention_status(context_id="demo"))

        self.assertEqual(registration["embedding_provider"]["provider"], "semantic-hash-v1")
        self.assertEqual(
            listing["entries"][0]["metadata"]["embedding_provider"]["provider"],
            "semantic-hash-v1",
        )
        self.assertEqual(status["embedding_provider"]["provider"], "semantic-hash-v1")

    def test_text_query_tool_uses_local_deterministic_embedding(self):
        mcp_server.remember_spiking_context(
            tag="local-demo-memory",
            context_id="demo",
            text="SYNAPSE-S2 local spiking memory demo",
            metadata={},
        )

        result = mcp_server.query_spiking_attention_text(
            prompt="SYNAPSE-S2 local spiking memory demo",
            context_id="demo",
            recall_scope="local",
        )

        self.assertIn("local-demo-memory", result)

        invalid_scope = mcp_server.query_spiking_attention_text(
            prompt="SYNAPSE-S2 local spiking memory demo",
            context_id="demo",
            recall_scope="unbounded",
        )
        self.assertIn("recall_scope must be local, connected, or all", invalid_scope)

    def test_memory_list_export_and_backup_tools_are_json_safe(self):
        mcp_server.remember_spiking_context(
            tag="ops-handoff-memory",
            context_id="demo",
            text="Real memory is inspectable through MCP.",
            metadata={"surface": "mcp"},
        )

        listing = self._full_contract_payload(
            mcp_server.list_spiking_memory(
                context_id="demo",
                limit=5,
                response_mode="full",
            )
        )
        exported = json.loads(mcp_server.export_spiking_memory(context_id="demo"))
        backup = json.loads(
            mcp_server.backup_spiking_memory(
                output_path=str(Path(self.tmpdir.name) / "backup.sqlite3")
            )
        )

        self.assertEqual(listing["entry_count"], 1)
        self.assertEqual(listing["entries"][0]["tag"], "ops-handoff-memory")
        self.assertNotIn("spike_indices", listing["entries"][0])
        self.assertNotIn("neuron_indices", listing["entries"][0])
        self.assertEqual(exported["entries"][0]["source_text"], "Real memory is inspectable through MCP.")
        self.assertTrue(Path(backup["backup_path"]).exists())

    def test_mcp_database_only_backup_rejects_verified_bundle_lane(self):
        verified_directory = Path(self.tmpdir.name) / "backups" / "verified"
        verified_directory.mkdir(mode=0o700, parents=True)
        output = verified_directory / "database-only.sqlite3"

        result = json.loads(
            mcp_server.backup_spiking_memory(output_path=str(output))
        )

        self.assertIn("error", result)
        self.assertRegex(
            json.dumps(result, sort_keys=True).lower(),
            r"verified|paired|reserved|database-only|recovery lane",
        )
        self.assertFalse(output.exists())
        self.assertFalse(output.with_name(output.name + ".receipt.json").exists())

    def test_capture_ledger_tools_require_a_reviewed_repair(self):
        CaptureInboxDaemon(root=self.tmpdir.name).prepare_transport()
        audit = json.loads(
            mcp_server.audit_capture_ledger_integrity(sample_limit=7)
        )
        unconfirmed = json.loads(
            mcp_server.repair_capture_ledger_integrity(
                expected_revision=audit["audit_revision"],
                sample_limit=7,
            )
        )
        missing_revision = json.loads(
            mcp_server.repair_capture_ledger_integrity(
                expected_revision="",
                confirm=True,
                sample_limit=7,
            )
        )
        repaired = json.loads(
            mcp_server.repair_capture_ledger_integrity(
                expected_revision=audit["audit_revision"],
                confirm=True,
                sample_limit=7,
            )
        )

        self.assertEqual(audit["action"], "capture-ledger-audit")
        self.assertEqual(audit["status"], "ready")
        self.assertEqual(audit["sample_limit"], 7)
        rendered_audit = json.dumps(audit, sort_keys=True)
        for private_field in (
            '"_candidates"',
            '"file_sha256"',
            '"relative_path"',
            '"request_fingerprint"',
        ):
            self.assertNotIn(private_field, rendered_audit)

        self.assertIn("requires confirm=True", unconfirmed["error"])
        self.assertIn(
            "reviewed 64-character audit revision",
            missing_revision["error"],
        )
        self.assertEqual(repaired["action"], "capture-ledger-repair")
        self.assertEqual(repaired["state"], "no-repair-needed")
        self.assertTrue(repaired["repair_confirmed"])
        self.assertEqual(repaired["expected_revision"], audit["audit_revision"])

    def test_capture_ledger_tool_errors_redact_secrets_and_local_paths(self):
        secret = "sk-capture-ledger-secret-1234567890"
        local_path = "/Users/dan.driver/private/capture-ledger.json"
        with mock.patch.object(
            mcp_server,
            "_load_backend",
            side_effect=RuntimeError(f"token={secret} at {local_path}"),
        ):
            audit = json.loads(mcp_server.audit_capture_ledger_integrity())
            repair = json.loads(
                mcp_server.repair_capture_ledger_integrity(
                    expected_revision="a" * 64,
                    confirm=True,
                )
            )

        for payload in (audit, repair):
            with self.subTest(payload=payload):
                rendered = json.dumps(payload, sort_keys=True)
                self.assertIn("[REDACTED_SECRET]", rendered)
                self.assertIn("[LOCAL_PATH]", rendered)
                self.assertNotIn(secret, rendered)
                self.assertNotIn(local_path, rendered)

    def test_paired_recovery_tools_create_verify_and_restore_isolated_proof(self):
        capture_root = Path(self.tmpdir.name)
        os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = str(capture_root)
        CaptureInboxDaemon(root=capture_root).prepare_transport()
        bundle = json.loads(
            mcp_server.backup_spiking_recovery(
                output_path=str(capture_root / "paired.sqlite3"),
                purpose="mcp-test",
                pinned=True,
            )
        )

        verified = json.loads(
            mcp_server.verify_spiking_recovery(bundle["bundle_receipt_path"])
        )
        rejected = json.loads(
            mcp_server.restore_spiking_recovery_proof(
                bundle["bundle_receipt_path"],
                str(capture_root / "restore-rejected"),
            )
        )
        restored = json.loads(
            mcp_server.restore_spiking_recovery_proof(
                bundle["bundle_receipt_path"],
                str(capture_root / "restore-proof"),
                confirm=True,
            )
        )

        self.assertTrue(bundle["bundle_verified"])
        self.assertTrue(bundle["cutover_ready"])
        self.assertTrue(bundle["capture_ledger_binding"]["verified"])
        self.assertTrue(verified["verified"])
        self.assertTrue(verified["cutover_ready"])
        self.assertEqual(
            verified["capture_ledger_binding"],
            bundle["capture_ledger_binding"],
        )
        self.assertIn("confirm", rejected["error"])
        self.assertTrue(restored["verified"])
        self.assertTrue(restored["cutover_ready"])
        self.assertEqual(
            restored["capture_ledger_binding"],
            bundle["capture_ledger_binding"],
        )
        self.assertTrue(Path(restored["recovery_proof_path"]).exists())

    def test_recovery_restore_tool_rejects_output_outside_export_root(self):
        payload = json.loads(
            mcp_server.restore_spiking_recovery_proof(
                str(Path(self.tmpdir.name) / "missing.bundle.receipt.json"),
                "/tmp/synapse-recovery-outside-export",
                confirm=True,
            )
        )

        self.assertIn("error", payload)
        self.assertIn("export root", payload["error"])

    def test_memory_list_tool_can_include_vector_details_when_requested(self):
        mcp_server.remember_spiking_context(
            tag="mcp-vector-memory",
            context_id="demo",
            text="MCP can include vector details on request.",
            metadata={"surface": "mcp"},
        )

        listing = self._full_contract_payload(
            mcp_server.list_spiking_memory(
                context_id="demo",
                limit=5,
                include_vectors=True,
                response_mode="full",
            )
        )

        self.assertEqual(listing["entries"][0]["tag"], "mcp-vector-memory")
        self.assertIn("spike_indices", listing["entries"][0])
        self.assertIn("neuron_indices", listing["entries"][0])

    def test_mcp_ingests_text_events_and_lists_memory_graph(self):
        text = (
            "Apple Silicon MLX compiles spiking kernels into Metal. "
            "Sparse spike populations recall local context. "
            "Procurement reviews supplier budget exposure and contract risk. "
            "Finance tracks renewal owners and approval status."
        )

        ingestion = json.loads(
            mcp_server.ingest_spiking_memory_text(
                tag="mcp-brief",
                text=text,
                context_id="demo",
                surprise_threshold=0.58,
                min_segment_sentences=1,
            )
        )
        graph = self._full_contract_payload(
            mcp_server.list_spiking_memory_graph(
                context_id="demo",
                response_mode="full",
            )
        )

        self.assertGreaterEqual(ingestion["event_count"], 2)
        self.assertTrue(ingestion["agent_deployment"]["published"])
        self.assertGreaterEqual(graph["relationship_count"], 1)
        self.assertEqual(graph["relationships"][0]["relation_type"], "temporal_next")

    def test_mcp_captures_conversation_and_prunes_memory_graph_items(self):
        capture = json.loads(
            mcp_server.capture_spiking_conversation(
                text=(
                    "User wants conversation details visible in SYNAPSE-S2. "
                    "Codex captures a durable session event. "
                    "Sensitive partial truths can be pruned later."
                ),
                context_id="demo",
                source_tag="mcp-session",
                speaker="codex",
            )
        )
        graph = self._full_contract_payload(
            mcp_server.list_spiking_memory_graph(
                context_id="demo",
                response_mode="full",
            )
        )
        memory_id = next(
            entry["memory_id"]
            for entry in graph["entries"]
            if entry["tag"].startswith("mcp-session-event")
        )
        relationship_id = graph["relationships"][0]["relationship_id"]

        edge_prune = json.loads(
            mcp_server.prune_spiking_memory(
                target_type="relationship",
                context_id="demo",
                relationship_id=relationship_id,
                reason="bad edge",
            )
        )
        self.assertIn("confirm", edge_prune["error"])

        edge_prune = json.loads(
            mcp_server.prune_spiking_memory(
                target_type="relationship",
                context_id="demo",
                relationship_id=relationship_id,
                reason="bad edge",
                confirm=True,
            )
        )
        memory_prune = json.loads(
            mcp_server.prune_spiking_memory(
                target_type="event",
                context_id="demo",
                memory_id=memory_id,
                reason="bad event",
                confirm=True,
            )
        )

        self.assertGreaterEqual(capture["event_count"], 2)
        self.assertIn("context_namespace", capture)
        self.assertGreaterEqual(capture["context_namespace"]["node_count"], 2)
        self.assertTrue(capture["agent_deployment"]["published"])
        self.assertTrue(edge_prune["result"]["deleted"])
        self.assertTrue(memory_prune["result"]["deleted"])

    def test_mcp_capture_conversation_redacts_secret_payloads(self):
        capture = json.loads(
            mcp_server.capture_spiking_conversation(
                text=(
                    "Thread: MCP redaction. "
                    "Event: api_key=sk-mcp-secret123 should not persist."
                ),
                context_id="demo",
                source_tag="mcp-redaction",
                speaker="codex",
            )
        )
        graph = self._full_contract_payload(
            mcp_server.list_spiking_memory_graph(
                context_id="demo",
                response_mode="full",
            )
        )
        deployments = json.loads(
            mcp_server.pull_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
            )
        )
        combined = json.dumps(
            {"capture": capture, "graph": graph, "deployments": deployments},
            sort_keys=True,
            default=str,
        )

        self.assertNotIn("sk-mcp-secret123", combined)
        self.assertIn("[REDACTED_SECRET]", combined)

    def test_mcp_capture_conversation_replays_supplied_capture_id(self):
        capture_id = "s2cap_" + ("8" * 32)
        request = {
            "text": "Thread: MCP retry. Event: the same tool request is committed once.",
            "context_id": "demo",
            "source_tag": "mcp-retry",
            "speaker": "codex",
            "capture_id": capture_id,
        }

        first = json.loads(mcp_server.capture_spiking_conversation(**request))
        replay = json.loads(mcp_server.capture_spiking_conversation(**request))

        self.assertEqual(first["capture_id"], capture_id)
        self.assertEqual(replay["capture_id"], capture_id)
        self.assertFalse(first["idempotent_replay"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(
            first["agent_deployment"]["event_id"],
            replay["agent_deployment"]["event_id"],
        )

    def test_mcp_capture_inbox_tools_drop_process_and_redact(self):
        drop = json.loads(
            mcp_server.drop_spiking_capture_inbox(
                text=(
                    "MCP wrappers can drop session notes into the magic inbox. "
                    "The sidecar processes api_key=sk-test-secret123 safely."
                ),
                context_id="demo",
                source_tag="mcp-magic",
                speaker="codex",
            )
        )
        status_before = json.loads(mcp_server.get_spiking_capture_inbox_status())
        rejected = json.loads(mcp_server.process_spiking_capture_inbox(max_files=10))
        processed = json.loads(
            mcp_server.process_spiking_capture_inbox(max_files=10, confirm=True)
        )
        graph = self._full_contract_payload(
            mcp_server.list_spiking_memory_graph(
                context_id="demo",
                response_mode="full",
            )
        )

        self.assertFalse(Path(drop["drop_path"]).exists())
        self.assertEqual(status_before["pending_file_count"], 1)
        self.assertIn("confirm", rejected["error"])
        self.assertEqual(processed["processed_file_count"], 1)
        self.assertTrue(
            any(entry["tag"].startswith("mcp-magic-event") for entry in graph["entries"])
        )
        self.assertTrue(
            all("sk-test-secret123" not in entry["source_text"] for entry in graph["entries"])
        )

    def test_mcp_capture_error_resolution_requires_preflight_and_confirmation(self):
        root = Path(os.environ["SYNAPSE_S2_CAPTURE_ROOT"])
        status = json.loads(mcp_server.get_spiking_capture_inbox_status())
        del status
        CaptureInboxDaemon(root=root).prepare_transport()
        error_path = root / "capture_errors" / "terminal.evidence.json"
        error_path.write_text(
            json.dumps(
                {
                    "artifact_type": "stale-capture-inbox-temp",
                    "raw_payload_retained": False,
                    "content_digest_recorded": False,
                    "disposition": "recovered-discard-complete",
                }
            ),
            encoding="utf-8",
        )
        error_path.chmod(0o600)

        preflight = json.loads(
            mcp_server.preflight_spiking_capture_error_resolution(
                reason="reviewed terminal evidence",
            )
        )
        rejected = json.loads(
            mcp_server.resolve_spiking_capture_errors(
                preflight_token=preflight["preflight_token"],
                reason="reviewed terminal evidence",
            )
        )
        resolved = json.loads(
            mcp_server.resolve_spiking_capture_errors(
                preflight_token=preflight["preflight_token"],
                reason="reviewed terminal evidence",
                confirm=True,
            )
        )

        self.assertEqual(preflight["selected_count"], 1)
        self.assertNotIn(error_path.name, json.dumps(preflight))
        self.assertIn("confirm=true", rejected["error"])
        self.assertEqual(resolved["resolved_count"], 1)

    def test_mcp_transcript_source_register_poll_and_clipboard_capture(self):
        transcript = Path(self.tmpdir.name) / "claude-session.log"
        transcript.write_text("Existing Claude transcript line.\n", encoding="utf-8")

        registered = json.loads(
            mcp_server.register_spiking_transcript_source(
                source_id="claude-file",
                path=str(transcript),
                context_id="demo",
                source_tag="claude-file",
                speaker="claude",
                confirmed=True,
            )
        )
        transcript.write_text(
            transcript.read_text(encoding="utf-8")
            + "New Claude Desktop transcript delta. api_key=sk-mcp-secret123\n",
            encoding="utf-8",
        )
        polled = json.loads(
            mcp_server.poll_spiking_transcript_sources(source_id="claude-file")
        )
        clipboard = json.loads(
            mcp_server.capture_spiking_clipboard(
                text="Selected app transcript copied intentionally. token=sk-clip-secret123",
                context_id="demo",
                source_tag="frontmost-selection",
                speaker="operator",
            )
        )
        listed = json.loads(mcp_server.list_spiking_transcript_sources())
        graph = self._full_contract_payload(
            mcp_server.list_spiking_memory_graph(
                context_id="demo",
                response_mode="full",
            )
        )

        self.assertEqual(registered["source_id"], "claude-file")
        self.assertGreaterEqual(polled["captured_event_count"], 1)
        self.assertEqual(clipboard["adapter_kind"], "clipboard-once")
        self.assertEqual(listed["source_count"], 1)
        self.assertTrue(
            any(
                entry["metadata"].get("transcript_adapter") is True
                for entry in graph["entries"]
            )
        )
        self.assertTrue(
            all("sk-mcp-secret123" not in entry["source_text"] for entry in graph["entries"])
        )

    def test_mcp_app_connect_can_register_manual_local_app(self):
        connected = json.loads(
            mcp_server.connect_spiking_app(
                app_name="Manual MCP Probe",
                bundle_id="local.manual.probe",
                pid=424242,
                context_id="demo",
                source_tag="manual-probe",
                speaker="codex",
                confirmed=True,
                allow_manual=True,
            )
        )
        connections = json.loads(mcp_server.list_spiking_app_connections())

        self.assertEqual(connected["app_name"], "Manual MCP Probe")
        self.assertEqual(connected["bundle_id"], "local.manual.probe")
        self.assertEqual(connections["connection_count"], 1)

    def test_context_deployment_tool_lists_published_thoughts_for_connected_agents(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="agent-visible-memory",
                context_id="demo",
                text="Connected agents should pull this context update.",
                metadata={"surface": "mcp"},
            )
        )

        deployments = json.loads(
            mcp_server.pull_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
                limit=10,
            )
        )
        receipt_id = deployments["deliveries"][0]["receipt_id"]
        acknowledged = json.loads(
            mcp_server.ack_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
                receipt_id=receipt_id,
            )
        )
        after_registration = json.loads(
            mcp_server.pull_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
                limit=10,
            )
        )

        self.assertEqual(deployments["delivery_mode"], "leased-at-least-once")
        self.assertEqual(deployments["events"][0]["payload"]["tag"], "agent-visible-memory")
        self.assertEqual(acknowledged["acknowledged_count"], 1)
        self.assertEqual(after_registration["events"], [])

    def test_context_deployment_ack_tool_records_agent_cursor(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="ack-visible-memory",
                context_id="demo",
                text="Connected agents should acknowledge this context update.",
                metadata={"surface": "mcp"},
            )
        )

        leased = json.loads(
            mcp_server.pull_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
                limit=10,
            )
        )
        ack = json.loads(
            mcp_server.ack_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
                receipt_id=leased["deliveries"][0]["receipt_id"],
            )
        )
        cursors = json.loads(
            mcp_server.list_spiking_context_cursors(context_id="demo")
        )

        self.assertEqual(ack["agent_id"], "codex-desktop")
        self.assertEqual(ack["cursor"]["pending_event_count"], 0)
        self.assertEqual(
            ack["cursor"]["last_event_id"],
            registration["agent_deployment"]["event_id"],
        )
        self.assertEqual(cursors["cursors"][0]["agent_id"], "codex-desktop")

    def test_agent_context_hydration_tool_requires_explicit_receipt_ack(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="mcp-agent-brief-memory",
                context_id="demo",
                text="MCP agent hydration should recall deployment context.",
                metadata={"surface": "mcp"},
            )
        )

        first = self._full_contract_payload(
            mcp_server.hydrate_spiking_agent_context(
                agent_id="codex-desktop",
                context_id="demo",
                prompt="deployment context",
                response_mode="full",
            )
        )
        ack = json.loads(
            mcp_server.ack_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
                receipt_id=first["deliveries"][0]["receipt_id"],
            )
        )
        second = self._full_contract_payload(
            mcp_server.hydrate_spiking_agent_context(
                agent_id="codex-desktop",
                context_id="demo",
                prompt="deployment context",
                response_mode="full",
            )
        )

        self.assertEqual(first["action"], "agent-context-hydrate")
        self.assertEqual(
            first["latest_event_id"],
            registration["agent_deployment"]["event_id"],
        )
        self.assertEqual(first["new_event_count"], 1)
        self.assertIsNone(first["ack"])
        self.assertFalse(first["acknowledged"])
        self.assertTrue(first["ack_required"])
        self.assertEqual(ack["acknowledged_count"], 1)
        self.assertIn("mcp-agent-brief-memory", first["briefing_markdown"])
        self.assertIn("mcp-agent-brief-memory", first["recall_result"])
        self.assertIn("payload_summary", first["events"][0])
        self.assertNotIn(
            "MCP agent hydration should recall deployment context.",
            json.dumps(first["events"]),
        )
        self.assertIn("source_text_bytes", first["events"][0]["payload_summary"])
        self.assertEqual(second["new_event_count"], 0)
        self.assertEqual(
            second["since_event_id"],
            registration["agent_deployment"]["event_id"],
        )

    def test_cortex_governor_tools_enter_tick_commit_and_state(self):
        self.assertTrue(hasattr(mcp_server, "enter_spiking_cortex"))
        self.assertTrue(hasattr(mcp_server, "tick_spiking_cortex"))
        self.assertTrue(hasattr(mcp_server, "close_spiking_cortex"))
        self.assertTrue(hasattr(mcp_server, "commit_spiking_cortical_trace"))
        self.assertTrue(hasattr(mcp_server, "moderate_spiking_cortical_trace"))
        self.assertTrue(hasattr(mcp_server, "get_spiking_cortex_state"))

        entered = json.loads(
            mcp_server.enter_spiking_cortex(
                agent_id="mcp-agent",
                context_id="demo",
                task="Govern MCP agent work.",
                mode="strict",
            )
        )
        tick = json.loads(
            mcp_server.tick_spiking_cortex(
                agent_id="mcp-agent",
                context_id="demo",
                session_id=entered["session_id"],
                observation="Preparing a mutation.",
                proposed_action="Edit code and run tests.",
                intended_files=["mlx_backend.py", "mcp_server.py"],
                intended_tools=["pytest tests/test_mcp_server.py"],
                mutation_intent=True,
                confidence=0.4,
            )
        )
        committed = json.loads(
            mcp_server.commit_spiking_cortical_trace(
                agent_id="mcp-agent",
                context_id="demo",
                session_id=entered["session_id"],
                trace_type="validation",
                truth_posture="test-validated",
                text="MCP cortex tools returned structured governance state.",
                evidence_json='{"tests":["tests.test_mcp_server"]}',
            )
        )
        moderated = json.loads(
            mcp_server.moderate_spiking_cortical_trace(
                context_id="demo",
                memory_id=committed["memory_id"],
                action="promote",
                reason="MCP operator verified",
            )
        )
        state = self._full_contract_payload(
            mcp_server.get_spiking_cortex_state(
                agent_id="mcp-agent",
                context_id="demo",
                response_mode="full",
            )
        )
        closed = json.loads(
            mcp_server.close_spiking_cortex(
                agent_id="mcp-agent",
                context_id="demo",
                session_id=entered["session_id"],
                reason="mcp-test-complete",
            )
        )
        closed_state = self._full_contract_payload(
            mcp_server.get_spiking_cortex_state(
                agent_id="mcp-agent",
                context_id="demo",
                response_mode="full",
            )
        )

        self.assertEqual(entered["action"], "enter-spiking-cortex")
        self.assertEqual(tick["decision"], "verify-first")
        self.assertEqual(tick["intended_files"], ["mlx_backend.py", "mcp_server.py"])
        self.assertEqual(tick["intended_tools"], ["pytest tests/test_mcp_server.py"])
        self.assertEqual(committed["trace_type"], "validation")
        self.assertEqual(moderated["moderation_action"], "promote")
        self.assertGreaterEqual(state["typed_memory_counts"]["validation"], 1)
        self.assertIn("cognitive_governance", state["policy"])
        self.assertEqual(closed["action"], "close-spiking-cortex")
        self.assertEqual(closed["status"], "closed")
        self.assertEqual(closed["cortex_state"]["active_session_count"], 0)
        self.assertEqual(closed_state["active_session_count"], 0)

    def test_goal_ledger_mcp_tools_create_update_list_and_surface_in_cortex_state(self):
        self.assertTrue(hasattr(mcp_server, "create_spiking_goal"))
        self.assertTrue(hasattr(mcp_server, "update_spiking_goal"))
        self.assertTrue(hasattr(mcp_server, "list_spiking_goals"))

        created = json.loads(
            mcp_server.create_spiking_goal(
                agent_id="mcp-agent",
                context_id="demo",
                title="Prepare SYNAPSE-S2 operator handoff",
                owner="operator",
                state="in_progress",
                next_action="Run Start Work and verify receipts.",
            )
        )
        updated = json.loads(
            mcp_server.update_spiking_goal(
                agent_id="mcp-agent",
                context_id="demo",
                goal_id=created["memory_id"],
                state="blocked",
                evidence="Waiting on external GitHub mirror creation.",
                next_action="Retry mirror after authentication is available.",
            )
        )
        listed = json.loads(mcp_server.list_spiking_goals(context_id="demo"))
        state = self._full_contract_payload(
            mcp_server.get_spiking_cortex_state(
                context_id="demo",
                response_mode="full",
            )
        )

        self.assertEqual(created["action"], "goal-create")
        self.assertEqual(updated["action"], "goal-update")
        self.assertEqual(listed["action"], "goal-list")
        self.assertEqual(listed["goals"][0]["state"], "blocked")
        self.assertIn("operator handoff", listed["goals"][0]["title"])
        self.assertEqual(state["goals"][0]["state"], "blocked")

    def test_mcp_cortex_prune_requires_explicit_confirmation(self):
        entered = json.loads(
            mcp_server.enter_spiking_cortex(
                agent_id="mcp-agent",
                context_id="demo",
                task="Confirm Cortex prune safety.",
                mode="strict",
            )
        )
        committed = json.loads(
            mcp_server.commit_spiking_cortical_trace(
                agent_id="mcp-agent",
                context_id="demo",
                session_id=entered["session_id"],
                trace_type="assumption",
                truth_posture="inferred",
                text="MCP Cortex prune should require explicit confirmation.",
                confidence=0.42,
            )
        )

        rejected = json.loads(
            mcp_server.moderate_spiking_cortical_trace(
                context_id="demo",
                memory_id=committed["memory_id"],
                action="prune",
                reason="missing confirmation",
            )
        )
        accepted = json.loads(
            mcp_server.moderate_spiking_cortical_trace(
                context_id="demo",
                memory_id=committed["memory_id"],
                action="prune",
                reason="confirmed removal",
                confirm=True,
            )
        )

        self.assertIn("confirm", rejected["error"])
        self.assertEqual(accepted["moderation_action"], "prune")
        self.assertTrue(accepted["prune"]["result"]["deleted"])

    def test_memory_export_tool_rejects_paths_outside_export_root(self):
        result = json.loads(
            mcp_server.export_spiking_memory(
                context_id="demo",
                output_path="/tmp/synapse-s2-outside-export.json",
            )
        )

        self.assertIn("error", result)
        self.assertIn("export root", result["error"])

    def test_output_tools_reject_credential_shaped_paths_without_echo_or_write(self):
        secret = "sk-mcp-output-path-secret-1234567890"
        credential_component = f"password={secret}"
        credential_root = Path(self.tmpdir.name) / credential_component
        calls = (
            mcp_server.export_spiking_memory(
                context_id="demo",
                output_path=str(credential_root / "memory.json"),
            ),
            mcp_server.backup_spiking_memory(
                output_path=str(credential_root / "memory.sqlite3"),
            ),
            mcp_server.certify_spiking_runtime(
                output_path=str(credential_root / "certification.json"),
            ),
        )

        for result in calls:
            with self.subTest(result=result):
                payload = json.loads(result)
                self.assertIn("error", payload)
                self.assertIn("output_path must not contain credential material", result)
                self.assertNotIn(secret, result)

        self.assertFalse(credential_root.exists())

    def test_delivery_tools_fail_closed_without_configured_identity(self):
        configured = os.environ.pop("SYNAPSE_S2_CLIENT_AGENT_ID", None)
        override = os.environ.pop(
            "SYNAPSE_S2_ALLOW_UNCONFIGURED_DELIVERY_IDENTITY",
            None,
        )
        try:
            hydration = self._contract_payload(mcp_server.hydrate_spiking_agent_context(
                agent_id="codex-desktop",
                context_id="demo",
            ))
            pull = json.loads(
                mcp_server.pull_spiking_context_deployments(
                    agent_id="codex-desktop",
                    context_id="demo",
                )
            )
        finally:
            if configured is not None:
                os.environ["SYNAPSE_S2_CLIENT_AGENT_ID"] = configured
            if override is not None:
                os.environ[
                    "SYNAPSE_S2_ALLOW_UNCONFIGURED_DELIVERY_IDENTITY"
                ] = override

        self.assertFalse(hydration["ok"])
        self.assertIn(
            "SYNAPSE_S2_CLIENT_AGENT_ID",
            hydration["data"]["error"]["message"],
        )
        self.assertIn("error", pull)
        self.assertNotIn("UnboundLocalError", json.dumps(hydration))

    def test_delivery_identity_alias_and_atomic_batch_ack(self):
        for ordinal in (1, 2):
            mlx_backend.get_backend().publish_context_event(
                context_id="demo",
                source_surface="mcp-batch-test",
                event_type="batch-ack",
                summary=f"batch event {ordinal}",
                agent_targets=["codex-desktop"],
            )
        leased = json.loads(
            mcp_server.pull_spiking_context_deployments(
                agent_id="Codex-Desktop",
                context_id="demo",
                limit=10,
            )
        )
        receipts = [row["receipt_id"] for row in leased["deliveries"]]
        ack = json.loads(
            mcp_server.ack_spiking_context_deployments(
                agent_id="CODEX-DESKTOP",
                context_id="demo",
                receipt_ids=receipts,
            )
        )

        self.assertEqual(leased["agent_id"], "codex-desktop")
        self.assertEqual(len(receipts), 2)
        self.assertEqual(ack["acknowledged_count"], 2)
        self.assertEqual(
            {row["receipt_id"] for row in ack["acknowledged"]},
            set(receipts),
        )

    def test_mcp_delivery_instance_id_has_process_nonce(self):
        parts = mcp_server.MCP_DELIVERY_INSTANCE_ID.split("-")
        self.assertEqual(parts[0], "mcp")
        self.assertEqual(int(parts[1]), os.getpid())
        self.assertEqual(len(parts[2]), 32)

    def test_release_tool_rejects_unbounded_receipt_batches(self):
        empty = json.loads(
            mcp_server.release_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
                receipt_ids=[],
            )
        )
        oversized = json.loads(
            mcp_server.release_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
                receipt_ids=[f"receipt-{index}" for index in range(501)],
            )
        )

        self.assertIn("non-empty", empty["error"])
        self.assertIn("at most 500", oversized["error"])

    def test_ack_and_release_tool_errors_never_echo_bearer_receipts(self):
        forged_receipt = "ctxrcpt_" + ("A" * 43)
        mcp_server.pull_spiking_context_deployments(
            agent_id="codex-desktop",
            context_id="demo",
            limit=1,
        )
        ack = json.loads(
            mcp_server.ack_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
                receipt_id=forged_receipt,
            )
        )
        release = json.loads(
            mcp_server.release_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
                receipt_ids=[forged_receipt],
            )
        )

        self.assertIn("error", ack)
        self.assertIn("error", release)
        self.assertNotIn(forged_receipt, json.dumps(ack, sort_keys=True))
        self.assertNotIn(forged_receipt, json.dumps(release, sort_keys=True))

    def test_dead_letter_tool_requires_confirmation_and_records_governance(self):
        with mock.patch.dict(
            os.environ,
            {"SYNAPSE_S2_CONTEXT_MAX_DELIVERY_ATTEMPTS": "2"},
        ):
            backend = mlx_backend.get_backend()
            event = backend.publish_context_event(
                context_id="dead-letter-tool",
                source_surface="mcp-test",
                event_type="poison",
                summary="retry exhaustion test",
                agent_targets=["codex-desktop"],
            )
            first = backend.memory_store.lease_context_events(
                context_id="dead-letter-tool",
                agent_id="codex-desktop",
                consumer_instance_id="mcp-attempt-one",
                limit=1,
                lease_seconds=1.0,
                now=100.0,
            )["deliveries"][0]
            backend.memory_store.lease_context_events(
                context_id="dead-letter-tool",
                agent_id="codex-desktop",
                consumer_instance_id="mcp-attempt-two",
                limit=1,
                lease_seconds=1.0,
                now=102.0,
            )
            rejected = json.loads(
                mcp_server.dead_letter_spiking_context_delivery(
                    agent_id="codex-desktop",
                    context_id="dead-letter-tool",
                    delivery_id=first["delivery_id"],
                    reason="test consumer cannot decode event",
                )
            )
            accepted = json.loads(
                mcp_server.dead_letter_spiking_context_delivery(
                    agent_id="codex-desktop",
                    context_id="dead-letter-tool",
                    delivery_id=first["delivery_id"],
                    reason="test consumer cannot decode event",
                    confirm=True,
                )
            )

        self.assertIn("confirm=True", rejected["error"])
        self.assertEqual(accepted["action"], "context-delivery-dead-letter")
        self.assertEqual(accepted["event_id"], event["event_id"])
        self.assertTrue(accepted["operation_id"].startswith("s2maint_"))


if __name__ == "__main__":
    unittest.main()

"""Authoritative Core, CLI, MCP, and token-contract Memora lifecycle tests."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

import mcp_server
import synapse_cli
from core_client import CoreClient, CoreRemoteError
from core_service import AuthoritativeCoreService, BUILD_SOURCE_MANIFEST, CoreConfig
from embedding_providers import EmbeddingProvider, EmbeddingResult
from mlx_backend import SpikingAttentionBackend
from token_contracts import project_response


class _LearnedSurfaceProvider(EmbeddingProvider):
    provider_id = "mlx-neural-v1"

    def info(self, *, dimensions: int) -> dict:
        return {
            "provider": self.provider_id,
            "provider_type": "mlx-neural",
            "model_id": "test/memora-surface",
            "revision": "a" * 40,
            "configuration_sha256": "c" * 64,
            "dimensions": dimensions,
            "semantic": True,
            "local_only": True,
            "ready": True,
        }

    def embed(self, text: str, *, dimensions: int) -> EmbeddingResult:
        digest = hashlib.sha256(str(text).encode("utf-8")).digest()
        vector = [
            (digest[index % len(digest)] + 1) / 256.0
            for index in range(dimensions)
        ]
        return EmbeddingResult(
            vector=vector,
            provenance=self.info(dimensions=dimensions),
        )


class MemoraLifecycleSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        root = Path(self.temporary_directory.name)
        state_root = root / "state"
        state_root.mkdir(mode=0o700)
        os.chmod(state_root, 0o700)
        cache_root = state_root / "model-cache"
        cache_root.mkdir(mode=0o700)
        self.config = CoreConfig(
            socket_path=state_root / "core" / "service.sock",
            state_path=state_root / "runtime_state.json",
            memory_path=state_root / "memory.sqlite3",
            dimension=32,
            num_neurons=24,
            default_top_k=6,
            recall_count=8,
            embedding_provider_name="mlx-neural-v1",
            embedding_neural_model_id="test/memora-surface",
            embedding_neural_revision="a" * 40,
            embedding_neural_cache_dir=cache_root,
            embedding_neural_pooling="first",
            embedding_neural_max_tokens=128,
            embedding_neural_normalize=True,
            embedding_neural_local_files_only=True,
            authority_timeout_seconds=0.0,
        )

        def backend_factory(authority_lease):
            return SpikingAttentionBackend(
                dimension=self.config.dimension,
                num_neurons=self.config.num_neurons,
                default_top_k=self.config.default_top_k,
                recall_count=self.config.recall_count,
                compile_graph=False,
                state_path=self.config.state_path,
                memory_path=self.config.memory_path,
                embedding_provider=_LearnedSurfaceProvider(),
                authority_lease=authority_lease,
            )

        self.service = AuthoritativeCoreService(
            self.config,
            backend_factory=backend_factory,
        )
        self.failures: list[BaseException] = []

        def run() -> None:
            try:
                self.service.serve_forever()
            except BaseException as exc:  # pragma: no cover - assertion reports it
                self.failures.append(exc)

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not self.config.socket_path.exists():
            if self.failures:
                break
            time.sleep(0.02)
        self.assertEqual(self.failures, [])
        self.assertTrue(self.config.socket_path.exists())
        self.client = CoreClient(
            socket_path=self.config.socket_path,
            caller="memora-surface-test",
            default_timeout_seconds=5.0,
        )
        self.addCleanup(self._close_service)

    def _close_service(self) -> None:
        self.service.close()
        self.thread.join(timeout=5.0)

    def _plan(self, context_id: str = "ops") -> dict:
        for index in range(2):
            self.client.register_text_trace(
                tag=f"memora-surface-{index}",
                text=f"Governed cue source evidence {index}.",
                context_id=context_id,
                metadata={
                    "display_label": f"Memora Surface {index}",
                    "semantic_facets": ["project citadel"],
                    "keywords": ["project citadel"],
                },
            )
        plan = self.client.memora_shadow_plan(context_id=context_id)
        self.assertTrue(plan["learned"])
        self.assertTrue(plan["clusters"])
        return plan

    def _propose(self, *, request_id: str = "memora-surface-proposal") -> dict:
        plan = self._plan()
        return self.client.propose_memora_binding(
            context_id="ops",
            plan_digest=plan["plan_digest"],
            cluster_ordinal=plan["clusters"][0]["cluster_ordinal"],
            proposed_by="workflow-proposer",
            reason="Review the bounded learned cue proposal.",
            governance_request_id=request_id,
        )

    def test_authoritative_core_client_lifecycle_cas_replay_and_audit(self) -> None:
        proposed = self._propose()
        binding = proposed["binding"]
        self.assertEqual(binding["state"], "proposed")
        self.assertTrue(binding["proposed_by"].startswith("core:local-owner:"))
        self.assertNotIn("workflow-proposer", binding["proposed_by"])

        with self.assertRaises(CoreRemoteError) as same_role:
            self.client.promote_memora_binding(
                binding_id=binding["binding_id"],
                expected_revision=binding["revision"],
                reviewed_by="workflow-proposer",
                reason="Self review must fail.",
                confirm=True,
                governance_request_id="memora-surface-self-review",
            )
        self.assertEqual(same_role.exception.code, "invalid_request")

        promote_arguments = {
            "binding_id": binding["binding_id"],
            "expected_revision": binding["revision"],
            "reviewed_by": "workflow-reviewer",
            "reason": "Independent workflow role reviewed the proposal.",
            "confirm": True,
            "governance_request_id": "memora-surface-promotion",
        }
        promoted = self.client.promote_memora_binding(**promote_arguments)
        replay = self.client.promote_memora_binding(**promote_arguments)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["historical_revision"], promoted["revision"])
        self.assertEqual(replay["current_state"], "promoted")
        self.assertEqual(replay["binding"]["revision"], promoted["revision"])
        self.assertEqual(promoted["state"], "promoted")
        self.assertNotEqual(
            promoted["binding"]["proposed_by"],
            promoted["binding"]["reviewed_by"],
        )

        listed = self.client.list_memora_bindings(
            context_id="ops", state="promoted", limit=50
        )
        self.assertEqual(listed["total"], 1)
        self.assertTrue(listed["bindings"][0]["effectiveness"]["effective"])
        got = self.client.get_memora_binding(binding_id=binding["binding_id"])
        self.assertEqual(got["revision"], promoted["revision"])
        history = self.client.memora_binding_history(
            binding_id=binding["binding_id"], limit=50
        )
        self.assertEqual([event["action"] for event in history["events"]], ["promote", "propose"])
        audit = self.client.audit_memora_binding(binding_id=binding["binding_id"])
        self.assertTrue(audit["chain_valid"])
        self.assertTrue(audit["catalog_cross_checked"])

        with self.assertRaises(CoreRemoteError) as unconfirmed:
            self.client.revoke_memora_binding(
                binding_id=binding["binding_id"],
                expected_revision=promoted["revision"],
                revoked_by="workflow-revoker",
                reason="Missing confirmation must fail.",
                confirm=False,
            )
        self.assertIn(
            unconfirmed.exception.code,
            {"invalid_request", "protocol_violation"},
        )
        revoked = self.client.revoke_memora_binding(
            binding_id=binding["binding_id"],
            expected_revision=promoted["revision"],
            revoked_by="workflow-revoker",
            reason="Stop governed cue routing.",
            confirm=True,
            governance_request_id="memora-surface-revoke",
        )
        self.assertEqual(revoked["state"], "revoked")

        rejected_proposal = self._propose(request_id="memora-surface-reject-proposal")
        rejected = self.client.reject_memora_binding(
            binding_id=rejected_proposal["binding_id"],
            expected_revision=rejected_proposal["revision"],
            reviewed_by="workflow-reviewer",
            reason="Reject the second reviewed proposal.",
            governance_request_id="memora-surface-reject",
        )
        self.assertEqual(rejected["state"], "rejected")

    def test_cli_and_token_contract_surface_are_bounded_and_keyless(self) -> None:
        proposed = self._propose(request_id="memora-cli-proposal")
        binding_id = proposed["binding_id"]
        parser = synapse_cli.build_parser()

        def run_cli(*arguments: str) -> dict:
            parsed = parser.parse_args(["--json", *arguments])
            with mock.patch.object(
                synapse_cli, "build_backend", return_value=self.client
            ):
                return parsed.func(parsed)

        args = parser.parse_args(
            [
                "--json",
                "memora-binding",
                "--binding-id",
                binding_id,
                "--max-response-bytes",
                "24576",
            ]
        )
        with mock.patch.object(synapse_cli, "build_backend", return_value=self.client):
            envelope = args.func(args)
        rendered = json.dumps(envelope, sort_keys=True)
        self.assertTrue(envelope["ok"])
        self.assertEqual(envelope["operation"], "memora-governance")
        projected_binding = envelope["data"]["bindings"][0]["binding"]
        self.assertEqual(projected_binding["binding_id"], binding_id)
        self.assertNotIn("sources", projected_binding)
        for forbidden in (
            "source_witnesses",
            "public_key",
            "signature",
            "last_request_fingerprint",
        ):
            self.assertNotIn(forbidden, rendered)

        direct = project_response(
            "memora-governance",
            self.client.get_memora_binding(binding_id=binding_id),
            mode="full",
            max_response_bytes=24_576,
        )
        self.assertEqual(direct["data"], envelope["data"])

        listed = run_cli(
            "memora-bindings",
            "--context",
            "ops",
            "--state",
            "proposed",
        )
        self.assertEqual(listed["data"]["kind"], "catalog")
        promoted = run_cli(
            "memora-promote",
            "--binding-id",
            binding_id,
            "--expected-revision",
            proposed["revision"],
            "--reviewed-by",
            "cli-reviewer",
            "--reason",
            "CLI reviewer approved the proposal.",
            "--governance-request-id",
            "memora-cli-promote",
            "--confirm",
        )
        promoted_binding = promoted["data"]["bindings"][0]["binding"]
        self.assertEqual(promoted_binding["state"], "promoted")
        for command in ("memora-history", "memora-audit"):
            inspected = run_cli(command, "--binding-id", binding_id)
            self.assertTrue(inspected["ok"])
            self.assertTrue(inspected["data"]["events"])
        revoked = run_cli(
            "memora-revoke",
            "--binding-id",
            binding_id,
            "--expected-revision",
            promoted_binding["revision"],
            "--revoked-by",
            "cli-revoker",
            "--reason",
            "CLI operator stopped cue routing.",
            "--governance-request-id",
            "memora-cli-revoke",
            "--confirm",
        )
        self.assertEqual(
            revoked["data"]["bindings"][0]["binding"]["state"], "revoked"
        )

        next_plan = self.client.memora_shadow_plan(context_id="ops")
        proposed_via_cli = run_cli(
            "memora-propose",
            "--context",
            "ops",
            "--plan-digest",
            next_plan["plan_digest"],
            "--cluster-ordinal",
            str(next_plan["clusters"][0]["cluster_ordinal"]),
            "--proposed-by",
            "cli-proposer",
            "--reason",
            "CLI proposal for rejection coverage.",
            "--governance-request-id",
            "memora-cli-propose-second",
        )
        second = proposed_via_cli["data"]["bindings"][0]["binding"]
        rejected = run_cli(
            "memora-reject",
            "--binding-id",
            second["binding_id"],
            "--expected-revision",
            second["revision"],
            "--reviewed-by",
            "cli-reviewer",
            "--reason",
            "CLI reviewer rejected the second proposal.",
            "--governance-request-id",
            "memora-cli-reject",
        )
        self.assertEqual(
            rejected["data"]["bindings"][0]["binding"]["state"], "rejected"
        )

    def test_mcp_is_read_plan_propose_only(self) -> None:
        plan = self._plan()
        backend_module = SimpleNamespace(get_backend=lambda: self.client)
        with mock.patch.object(mcp_server, "_load_backend", return_value=(None, backend_module)):
            proposal_result = asyncio.run(
                mcp_server.mcp.call_tool(
                    "propose_spiking_memora_binding",
                    {
                        "context_id": "ops",
                        "plan_digest": plan["plan_digest"],
                        "cluster_ordinal": plan["clusters"][0]["cluster_ordinal"],
                        "reason": "MCP may propose for operator review only.",
                        "proposed_by": "mcp-proposer",
                        "governance_request_id": "memora-mcp-proposal",
                        "max_response_bytes": 24_576,
                    },
                )
            )
            payload = proposal_result.structured_content
            self.assertTrue(payload["ok"], payload)
            binding_id = payload["data"]["bindings"][0]["binding"]["binding_id"]
            read_result = asyncio.run(
                mcp_server.mcp.call_tool(
                    "get_spiking_memora_binding",
                    {"binding_id": binding_id, "max_response_bytes": 24_576},
                )
            )
        self.assertTrue(read_result.structured_content["ok"])

        async def inspect_tools():
            return {tool.name: tool for tool in await mcp_server.mcp.list_tools()}

        tools = asyncio.run(inspect_tools())
        expected = {
            "plan_spiking_memora_shadow",
            "list_spiking_memora_bindings",
            "get_spiking_memora_binding",
            "propose_spiking_memora_binding",
            "list_spiking_memora_binding_history",
            "audit_spiking_memora_binding",
        }
        self.assertTrue(expected.issubset(tools))
        self.assertFalse(tools["propose_spiking_memora_binding"].annotations.readOnlyHint)
        for name in expected - {"propose_spiking_memora_binding"}:
            self.assertTrue(tools[name].annotations.readOnlyHint)
        for forbidden in (
            "promote_spiking_memora_binding",
            "reject_spiking_memora_binding",
            "revoke_spiking_memora_binding",
        ):
            self.assertNotIn(forbidden, tools)

    def test_governance_sources_are_build_and_prep_inputs(self) -> None:
        expected = {"memora_governance.py", "memora_shadow.py"}
        self.assertTrue(expected.issubset(BUILD_SOURCE_MANIFEST))
        prep_text = (
            Path(__file__).resolve().parents[1] / "scripts" / "prep_tomorrow.sh"
        ).read_text(encoding="utf-8")
        for filename in expected:
            with self.subTest(filename=filename):
                self.assertIn(filename, prep_text)


if __name__ == "__main__":
    unittest.main()

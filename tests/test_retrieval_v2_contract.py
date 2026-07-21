from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mlx_backend import SpikingAttentionBackend
from token_contracts import (
    DEFAULT_RESPONSE_BYTES,
    ResponseContractError,
    canonical_response_bytes,
    project_response,
)


class RetrievalV2ContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        state_path = Path(self.temporary_directory.name) / "runtime_state.json"
        self.backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=state_path,
            embedding_provider_name="semantic-hash",
        )
        self.addCleanup(self.backend.memory_store.close)

    def _payload(self) -> dict:
        prompt = "camera calibration control room"
        for context_id in ("alpha", "beta"):
            self.backend.register_trace(
                tag=f"{context_id}-camera",
                embedding=self.backend.embed_text(prompt),
                context_id=context_id,
                source_text=f"Camera calibration control room evidence for {context_id}.",
                metadata={
                    "display_label": f"{context_id.title()} camera evidence",
                    "display_summary": "Verified camera calibration note.",
                    "source": "retrieval-contract-test",
                },
            )
        self.backend.approve_namespace_link(
            source_context_id="alpha",
            target_context_id="beta",
            relation_type="camera-control",
            direction="directed",
            weight=0.9,
            approved_by="unit-test",
            confirm=True,
        )
        payload = self.backend.retrieve_text_v2(
            prompt,
            context_id="alpha",
            recall_scope="connected",
            result_limit=4,
            candidate_limit=16,
            include_graph_neighbors=False,
        )
        payload["_response_source"] = {
            "requested_limit": 12,
            "effective_limit": 4,
        }
        return payload

    def test_compact_and_full_are_structured_bounded_and_prompt_free(self) -> None:
        payload = self._payload()
        compact = project_response(
            "memory-retrieval",
            payload,
            mode="compact",
            max_response_bytes=DEFAULT_RESPONSE_BYTES["memory-retrieval"],
        )
        full = project_response(
            "memory-retrieval",
            payload,
            mode="full",
            max_response_bytes=128 * 1024,
        )

        self.assertEqual(compact["operation"], "memory-retrieval")
        self.assertFalse(compact["pagination"]["supported"])
        self.assertEqual(compact["pagination"]["returned"], len(payload["items"]))
        self.assertEqual(compact["pagination"]["requested_limit"], 12)
        self.assertEqual(compact["pagination"]["effective_limit"], 4)
        self.assertEqual(
            {record["context_id"] for record in compact["data"]["scope"]["contexts"]},
            {"alpha", "beta", "global"},
        )
        self.assertEqual(full["completeness"]["complete"], payload["completeness"]["complete"])
        self.assertEqual(full["pagination"]["has_more"], payload["completeness"]["has_more"])
        self.assertEqual(compact, project_response("retrieve-v2", payload))
        self.assertLessEqual(
            len(canonical_response_bytes(compact)),
            DEFAULT_RESPONSE_BYTES["memory-retrieval"],
        )
        json.dumps(compact, sort_keys=True, allow_nan=False)
        self.assertNotIn("prompt", compact["data"]["query"])
        self.assertTrue(
            all(
                item["raw_source_included"] is False
                for item in compact["data"]["items"]
            )
        )
        self.assertFalse(compact["data"]["raw_input_stored"])

    def test_contract_rejects_completeness_ranker_and_bridge_tampering(self) -> None:
        payload = self._payload()

        inconsistent = copy.deepcopy(payload)
        inconsistent["completeness"]["has_more"] = not inconsistent[
            "completeness"
        ]["has_more"]
        with self.assertRaisesRegex(ResponseContractError, "has_more"):
            project_response("memory-retrieval", inconsistent)

        ranker_mismatch = copy.deepcopy(payload)
        ranker_mismatch["items"][0]["ranker_version"] = "999.0"
        with self.assertRaisesRegex(ResponseContractError, "ranker identity"):
            project_response("memory-retrieval", ranker_mismatch)

        beta_item = next(
            item
            for item in payload["items"]
            if item["context_id"] == "beta"
        )
        unauthorized = copy.deepcopy(payload)
        target = next(
            item
            for item in unauthorized["items"]
            if item["memory_id"] == beta_item["memory_id"]
        )
        target["scope_provenance"]["context_link"]["target_context_id"] = "gamma"
        with self.assertRaisesRegex(ResponseContractError, "does not authorize"):
            project_response("memory-retrieval", unauthorized)

        unapproved = copy.deepcopy(payload)
        connected_scope = next(
            record
            for record in unapproved["scope"]["contexts"]
            if record["provenance"] == "connected"
        )
        connected_scope["context_link"]["approved"] = False
        with self.assertRaisesRegex(ResponseContractError, "approved link"):
            project_response("memory-retrieval", unapproved)


if __name__ == "__main__":
    unittest.main()

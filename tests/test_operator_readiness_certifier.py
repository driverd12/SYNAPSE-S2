import argparse
import copy
import dataclasses
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

from core_client_binding import (
    BINDING_ENV,
    EXPECTED_CONFIG_ENV,
    binding_for_config,
    write_core_client_binding,
)
from core_service import CoreConfig, write_core_config

from scripts.operator_readiness_certify import (
    CheckResult,
    MCP_COMPACT_BUDGET,
    MCP_CONTRACT_SCHEMA,
    MCP_SAFETY_BUDGET,
    MCP_SAFETY_PREFIX,
    MCP_SAFETY_SCHEMA,
    OperatorReadinessCertifier,
    app_preview_status,
    build_parser,
    choose_app,
    classify_overall,
    json_safe,
    mcp_compact_contract_probe_status,
    render_runbook_markdown,
    render_summary_markdown,
    sanitize_evidence_text,
    write_private_text,
)


class OperatorReadinessCertifierTests(unittest.TestCase):
    @staticmethod
    def _set_canonical_contract_size(structured):
        contract = structured["response_contract"]
        contract["serialized_bytes"] = 0
        contract["estimated_tokens"] = 0
        for _ in range(12):
            measured = len(
                json.dumps(
                    structured,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            )
            estimated = (measured + 3) // 4
            if (
                contract["serialized_bytes"] == measured
                and contract["estimated_tokens"] == estimated
            ):
                return measured
            contract["serialized_bytes"] = measured
            contract["estimated_tokens"] = estimated
        raise AssertionError("serialized_bytes did not reach a fixed point")

    @classmethod
    def _compact_mcp_result(cls, *, camel_case=False):
        cursor = "s2rc2.payload." + ("a" * 43)
        structured = {
            "schema": MCP_CONTRACT_SCHEMA,
            "version": 1,
            "operation": "memory-list",
            "ok": True,
            "data": {
                "context_id": "default",
                "recall_scope": "local",
                "one_hop_only": False,
                "returned": 1,
                "entries": [
                    {
                        "memory_id": "s2mem_fixture",
                        "tag": "fixture",
                        "context_id": "default",
                        "excerpt": "bounded evidence",
                        "trust": "untrusted-memory-evidence",
                        "embedding_dimensions": 8,
                        "spike_count": 2,
                        "neuron_count": 2,
                        "created_at": 1.0,
                        "updated_at": 1.0,
                        "provenance": {
                            "recall_scope": "local",
                            "source_surface": "unit-test",
                        },
                    }
                ],
            },
            "provenance": {
                "source": "sqlite-memory-store",
                "context_id": "default",
                "recall_scope": "local",
                "origin_node": "s2origin_" + ("b" * 32),
            },
            "warnings": [],
            "pagination": {
                "supported": True,
                "strategy": "authenticated-keyset-v2",
                "requested_limit": 1,
                "effective_limit": 1,
                "returned": 1,
                "total": {"entries": 2},
                "has_more": True,
                "next_cursor": cursor,
                "snapshot_revision": "c" * 64,
                "expires_at": 1_900_000_000,
            },
            "completeness": {
                "complete": False,
                "snapshot_bound": True,
                "authoritative_total": True,
                "source_limit_reduced": False,
                "reason": "more-pages-available",
            },
            "continuation": {
                "strategy": "use-authenticated-keyset-cursor",
                "cursor": cursor,
                "expires_at": 1_900_000_000,
            },
            "response_contract": {
                "profile": "compact",
                "max_output_bytes": MCP_COMPACT_BUDGET,
                "serialized_bytes": 0,
                "estimated_tokens": 0,
                "truncated": False,
                "omissions": {},
            },
        }
        cls._set_canonical_contract_size(structured)
        safety = {
            "schema": MCP_SAFETY_SCHEMA,
            "operation": "memory-list",
            "ok": True,
            "structuredContent_required": True,
            "max_bytes": MCP_SAFETY_BUDGET,
            "warnings": [],
            "continuation": {
                "strategy": "use-authenticated-keyset-cursor"
            },
        }
        return {
            "isError" if camel_case else "is_error": False,
            "structuredContent" if camel_case else "structured_content": structured,
            "content": [
                {
                    "type": "text",
                    "text": MCP_SAFETY_PREFIX
                    + json.dumps(
                        safety,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                }
            ],
        }

    @staticmethod
    def _args(default_output_dir: Path, **overrides):
        values = {
            "context": "default",
            "agent_id": "codex-desktop",
            "run_id": "operator-readiness-unit-test",
            "output_dir": str(default_output_dir),
            "launcher": str(default_output_dir / "synapse-s2-mcp"),
            "core_socket": "",
            "core_binding": "",
            "core_label": "aero.boom.synapse-s2.core",
            "noncanonical_layout_manifest": "",
            "expected_embedding_provider": None,
            "expected_dimension": None,
            "expected_neurons": None,
            "expected_top_k": None,
            "expected_neural_model": None,
            "expected_neural_revision": None,
            "expected_neural_pooling": None,
            "expected_neural_max_tokens": None,
            "expected_neural_normalize": None,
            "expected_neural_cache_dir": None,
            "expected_neural_local_files_only": None,
            "app_name": "",
            "zip": False,
            "json": True,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def _write_candidate_binding(
        self,
        root: Path,
        *,
        authority_mode: str = "candidate-local-v5",
        fingerprint: str | None = None,
    ):
        repo = Path(__file__).resolve().parents[1]
        data = root / "candidate-data"
        core = data / "core"
        core.mkdir(parents=True, mode=0o700)
        data.chmod(0o700)
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
        core_paths = SimpleNamespace(
            data_root=data,
            config=core / "service.json",
            socket=config.socket_path,
            state=config.state_path,
            memory_db=config.memory_path,
            capture_root=data,
        )
        binding = binding_for_config(
            repo_root=repo,
            data_root=data,
            config=config,
            core_label="aero.boom.synapse-s2.core",
            authority_mode=authority_mode,
        )
        if fingerprint is not None:
            binding = dataclasses.replace(binding, config_fingerprint=fingerprint)
        binding_path = root / "binding" / "core-binding.json"
        write_core_client_binding(binding_path, binding)
        return binding_path, binding, core_paths

    def test_cli_commands_use_core_route_without_local_topology(self):
        with TemporaryDirectory() as tmp:
            socket_path = (
                Path(__file__).resolve().parents[1]
                / ".synapse_s2"
                / "core"
                / "service.sock"
            )
            with mock.patch(
                "scripts.operator_readiness_certify.default_binding_path",
                return_value=Path(tmp) / "missing-core-binding.json",
            ):
                certifier = OperatorReadinessCertifier(
                    self._args(
                        Path(tmp),
                        core_socket=str(socket_path),
                    )
                )

            command = certifier._cli_command("doctor", "--context", "default")
            env = certifier._base_env()

        self.assertNotIn("--dimension", command)
        self.assertNotIn("--neurons", command)
        self.assertNotIn("--top-k", command)
        self.assertEqual(env["SYNAPSE_S2_CORE_SOCKET"], str(socket_path.resolve()))
        self.assertNotIn("SYNAPSE_S2_DIMENSION", env)
        self.assertNotIn("SYNAPSE_S2_NEURONS", env)
        self.assertNotIn("SYNAPSE_S2_TOP_K", env)

    def test_default_binding_is_discovered_validated_and_isolates_subprocess_env(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            binding_path, binding, core_paths = self._write_candidate_binding(root)
            hostile = {
                BINDING_ENV: str(root / "wrong-binding.json"),
                EXPECTED_CONFIG_ENV: "f" * 64,
                "MLX_DEVICE": "cpu",
                "SYNAPSE_S2_CORE_SOCKET": str(root / "wrong.sock"),
                "SYNAPSE_S2_MEMORY_DB": str(root / "wrong.sqlite3"),
                "SYNAPSE_S2_STATE_PATH": str(root / "wrong.json"),
                "SYNAPSE_S2_EXPORT_DIR": str(root / "wrong-export"),
                "SYNAPSE_S2_CAPTURE_ROOT": str(root / "wrong-capture"),
                "SYNAPSE_S2_DIMENSION": "7",
            }
            with (
                mock.patch.dict(os.environ, {BINDING_ENV: ""}, clear=False),
                mock.patch(
                    "scripts.operator_readiness_certify.default_binding_path",
                    return_value=binding_path,
                ),
                mock.patch(
                    "scripts.operator_readiness_certify.database_requires_core",
                    return_value=False,
                ),
                mock.patch(
                    "scripts.operator_readiness_certify.resolve_candidate_core_paths",
                    return_value=core_paths,
                ),
            ):
                certifier = OperatorReadinessCertifier(self._args(root / "run"))
                with mock.patch.dict(os.environ, hostile, clear=False):
                    env = certifier._base_env()

        self.assertEqual(certifier.core_binding, binding)
        self.assertEqual(env[BINDING_ENV], str(binding_path))
        for name in (
            EXPECTED_CONFIG_ENV,
            "MLX_DEVICE",
            "SYNAPSE_S2_CORE_SOCKET",
            "SYNAPSE_S2_MEMORY_DB",
            "SYNAPSE_S2_STATE_PATH",
            "SYNAPSE_S2_EXPORT_DIR",
            "SYNAPSE_S2_CAPTURE_ROOT",
            "SYNAPSE_S2_DIMENSION",
        ):
            self.assertNotIn(name, env)

    def test_explicit_binding_rejects_candidate_fingerprint_drift(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            binding_path, _, core_paths = self._write_candidate_binding(
                root,
                fingerprint="f" * 64,
            )
            with (
                mock.patch(
                    "scripts.operator_readiness_certify.resolve_candidate_core_paths",
                    return_value=core_paths,
                ),
                mock.patch(
                    "scripts.operator_readiness_certify.database_requires_core",
                    return_value=False,
                ),
                self.assertRaisesRegex(ValueError, "fingerprint does not match"),
            ):
                OperatorReadinessCertifier(
                    self._args(root / "run", core_binding=str(binding_path))
                )

    def test_matching_socket_is_assertion_only_when_binding_is_present(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            binding_path, binding, core_paths = self._write_candidate_binding(root)
            with (
                mock.patch(
                    "scripts.operator_readiness_certify.resolve_candidate_core_paths",
                    return_value=core_paths,
                ),
                mock.patch(
                    "scripts.operator_readiness_certify.database_requires_core",
                    return_value=False,
                ),
            ):
                certifier = OperatorReadinessCertifier(
                    self._args(
                        root / "run",
                        core_binding=str(binding_path),
                        core_socket=str(binding.socket_path),
                    )
                )
                env = certifier._base_env()

        self.assertEqual(env[BINDING_ENV], str(binding_path))
        self.assertNotIn("SYNAPSE_S2_CORE_SOCKET", env)

    def test_client_config_probe_uses_the_reviewed_binding_path(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            binding_path, _, core_paths = self._write_candidate_binding(root)
            with (
                mock.patch(
                    "scripts.operator_readiness_certify.resolve_candidate_core_paths",
                    return_value=core_paths,
                ),
                mock.patch(
                    "scripts.operator_readiness_certify.database_requires_core",
                    return_value=False,
                ),
            ):
                certifier = OperatorReadinessCertifier(
                    self._args(root / "run", core_binding=str(binding_path))
                )
            with mock.patch.object(certifier, "_run_command") as run_command:
                certifier._check_client_config()

        command = run_command.call_args.kwargs["command"]
        self.assertEqual(
            command[command.index("--core-binding") + 1],
            str(binding_path),
        )

    def test_parser_defaults_follow_candidate_config_without_parallel_defaults(self):
        with TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=True):
            args = build_parser().parse_args(
                [
                    "--output-dir",
                    tmp,
                    "--launcher",
                    str(Path(tmp) / "synapse-s2-mcp"),
                ]
            )
            certifier = OperatorReadinessCertifier(args)

        self.assertIsNone(args.expected_embedding_provider)
        self.assertIsNone(args.expected_dimension)
        self.assertEqual(
            certifier.core_config_contract["config_fingerprint"],
            certifier.candidate_config.fingerprint,
        )
        self.assertEqual(
            certifier.candidate_config.embedding_provider_name,
            "semantic-hash",
        )

    def test_candidate_expectation_mismatch_is_rejected_before_evidence_write(self):
        with TemporaryDirectory() as tmp, self.assertRaisesRegex(
            ValueError,
            "dimension expectation does not match",
        ):
            OperatorReadinessCertifier(
                self._args(Path(tmp), expected_dimension=999)
            )

    def test_semantic_benchmark_must_match_exact_candidate_provider_and_dimensions(self):
        with TemporaryDirectory() as tmp:
            certifier = OperatorReadinessCertifier(self._args(Path(tmp)))
            observed = []

            def run_command(_check_id, **kwargs):
                payload = {
                    "dimensions": certifier.candidate_config.dimension,
                    "vector_nonzero_count": 7,
                    "average_latency_ms": 1.25,
                    "embedding_provider": {
                        "provider": "semantic-hash-v1",
                        "provider_type": "semantic-hash",
                        "model_id": "semantic-hash-v1",
                        "dimensions": certifier.candidate_config.dimension,
                        "local_only": True,
                    },
                }
                observed.append(kwargs["evaluator"](0, payload, "", ""))
                payload["embedding_provider"]["dimensions"] -= 1
                observed.append(kwargs["evaluator"](0, payload, "", ""))

            with mock.patch.object(certifier, "_run_command", side_effect=run_command):
                certifier._check_neural_embedding()

        self.assertEqual(observed[0][0], "ready")
        self.assertEqual(observed[1][0], "blocked")
        self.assertTrue(observed[0][3]["exact_matches"]["provider_dimensions"])
        self.assertFalse(observed[1][3]["exact_matches"]["provider_dimensions"])

    def test_mcp_compact_contract_probe_accepts_snake_and_camel_wire_shapes(self):
        for camel_case in (False, True):
            with self.subTest(camel_case=camel_case):
                parsed = self._compact_mcp_result(camel_case=camel_case)
                structured_key = (
                    "structuredContent" if camel_case else "structured_content"
                )
                expected_size = len(
                    json.dumps(
                        parsed[structured_key],
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    ).encode("utf-8")
                )
                status, detail, repair, metrics = (
                    mcp_compact_contract_probe_status(0, parsed, "", "")
                )

                self.assertEqual(status, "ready")
                self.assertIn("independent byte", detail)
                self.assertEqual(repair, "")
                self.assertEqual(metrics["contract_schema"], MCP_CONTRACT_SCHEMA)
                self.assertEqual(metrics["profile"], "compact")
                self.assertEqual(
                    metrics["requested_max_output_bytes"], MCP_COMPACT_BUDGET
                )
                self.assertEqual(
                    metrics["effective_max_output_bytes"], MCP_COMPACT_BUDGET
                )
                self.assertEqual(
                    metrics["declared_serialized_bytes"], expected_size
                )
                self.assertEqual(
                    metrics["canonical_structured_content_bytes"], expected_size
                )
                self.assertFalse(metrics["transport_framing_included"])

    def test_mcp_compact_contract_probe_fails_closed_on_contract_tampering(self):
        def mutate_structured(parsed, mutator):
            mutated = copy.deepcopy(parsed)
            structured = mutated["structured_content"]
            mutator(structured)
            self._set_canonical_contract_size(structured)
            return mutated

        valid = self._compact_mcp_result()
        cases = {
            "wrong-schema": mutate_structured(
                valid, lambda value: value.__setitem__("schema", "wrong")
            ),
            "missing-schema": mutate_structured(
                valid, lambda value: value.pop("schema")
            ),
            "wrong-version": mutate_structured(
                valid, lambda value: value.__setitem__("version", True)
            ),
            "wrong-operation": mutate_structured(
                valid, lambda value: value.__setitem__("operation", "memory-graph")
            ),
            "full-profile": mutate_structured(
                valid,
                lambda value: value["response_contract"].__setitem__(
                    "profile", "full"
                ),
            ),
            "wrong-budget": mutate_structured(
                valid,
                lambda value: value["response_contract"].__setitem__(
                    "max_output_bytes", MCP_COMPACT_BUDGET + 1
                ),
            ),
            "outer-error": {**copy.deepcopy(valid), "is_error": True},
            "missing-structured": {
                key: value
                for key, value in copy.deepcopy(valid).items()
                if key != "structured_content"
            },
            "ambiguous-structured": {
                **copy.deepcopy(valid),
                "structuredContent": copy.deepcopy(valid["structured_content"]),
            },
        }
        falsified_size = copy.deepcopy(valid)
        falsified_size["structured_content"]["response_contract"][
            "serialized_bytes"
        ] += 1
        cases["falsified-size"] = falsified_size
        oversized = mutate_structured(
            valid,
            lambda value: value.__setitem__("padding", "x" * MCP_COMPACT_BUDGET),
        )
        cases["over-budget"] = oversized

        for name, parsed in cases.items():
            with self.subTest(case=name):
                status, _, repair, metrics = mcp_compact_contract_probe_status(
                    0, parsed, "", ""
                )
                self.assertEqual(status, "blocked")
                self.assertTrue(repair)
                self.assertEqual(metrics, {})

    def test_mcp_compact_contract_probe_fails_closed_on_safety_tampering(self):
        valid = self._compact_mcp_result()

        def safety_mutation(mutator):
            mutated = copy.deepcopy(valid)
            text = mutated["content"][0]["text"]
            safety = json.loads(text[len(MCP_SAFETY_PREFIX) :])
            mutator(safety)
            mutated["content"][0]["text"] = MCP_SAFETY_PREFIX + json.dumps(
                safety,
                sort_keys=True,
                separators=(",", ":"),
            )
            return mutated

        cases = {
            "missing-prefix": copy.deepcopy(valid),
            "malformed-json": copy.deepcopy(valid),
            "wrong-schema": safety_mutation(
                lambda value: value.__setitem__("schema", "wrong")
            ),
            "wrong-operation": safety_mutation(
                lambda value: value.__setitem__("operation", "memory-graph")
            ),
            "wrong-budget": safety_mutation(
                lambda value: value.__setitem__("max_bytes", MCP_SAFETY_BUDGET + 1)
            ),
            "not-required": safety_mutation(
                lambda value: value.__setitem__("structuredContent_required", False)
            ),
            "too-many-content-items": copy.deepcopy(valid),
            "over-budget": copy.deepcopy(valid),
        }
        cases["missing-prefix"]["content"][0]["text"] = "{}"
        cases["malformed-json"]["content"][0]["text"] = MCP_SAFETY_PREFIX + "{"
        cases["too-many-content-items"]["content"].append(
            {"type": "text", "text": "extra"}
        )
        cases["over-budget"]["content"][0]["text"] = (
            MCP_SAFETY_PREFIX + "x" * MCP_SAFETY_BUDGET
        )

        for name, parsed in cases.items():
            with self.subTest(case=name):
                status, _, _, _ = mcp_compact_contract_probe_status(
                    0, parsed, "", ""
                )
                self.assertEqual(status, "blocked")

    def test_mcp_compact_contract_probe_rejects_leaks_and_forged_evidence(self):
        marker = "SYNTHETIC_ONLY_PROBE_SECRET_1234"
        raw_digest = "a" * 64
        valid = self._compact_mcp_result()

        def mutation(mutator):
            parsed = copy.deepcopy(valid)
            structured = parsed["structured_content"]
            mutator(structured["data"]["entries"][0])
            self._set_canonical_contract_size(structured)
            return parsed

        cases = {
            "secret": mutation(
                lambda entry: entry.__setitem__("excerpt", f"password={marker}")
            ),
            "local-path": mutation(
                lambda entry: entry.__setitem__(
                    "excerpt", "/Users/example/private/evidence.txt"
                )
            ),
            "raw-digest": mutation(
                lambda entry: entry.__setitem__(
                    "excerpt", f"input_sha256={raw_digest}"
                )
            ),
            "forged-trust": mutation(
                lambda entry: entry.__setitem__("trust", "trusted")
            ),
            "forbidden-source-text": mutation(
                lambda entry: entry.__setitem__("source_text", "hidden evidence")
            ),
        }
        outer_secret = copy.deepcopy(valid)
        outer_secret["debug"] = f"password={marker}"
        cases["outer-result-secret"] = outer_secret
        annotated_secret = copy.deepcopy(valid)
        annotated_secret["content"][0]["annotations"] = {
            "debug": f"password={marker}"
        }
        cases["content-annotation-secret"] = annotated_secret
        outer_path = copy.deepcopy(valid)
        outer_path["debug"] = "/Users/example/private/mcp-result.json"
        cases["outer-result-path"] = outer_path
        for name, parsed in cases.items():
            with self.subTest(case=name):
                status, _, _, _ = mcp_compact_contract_probe_status(
                    0, parsed, "", ""
                )
                self.assertEqual(status, "blocked")

    def test_mcp_compact_contract_probe_rejects_malformed_semantic_values(self):
        valid = self._compact_mcp_result()

        def structured_mutation(mutator):
            parsed = copy.deepcopy(valid)
            structured = parsed["structured_content"]
            mutator(structured)
            self._set_canonical_contract_size(structured)
            return parsed

        cases = {
            "harmless-outer-extra": {**copy.deepcopy(valid), "debug": "extra"},
            "mixed-wire-conventions": {
                "is_error": False,
                "structuredContent": copy.deepcopy(valid["structured_content"]),
                "content": copy.deepcopy(valid["content"]),
            },
            "content-annotation": copy.deepcopy(valid),
            "malformed-entry-count": structured_mutation(
                lambda value: value["data"]["entries"][0].__setitem__(
                    "spike_count", "2"
                )
            ),
            "malformed-warning": structured_mutation(
                lambda value: value.__setitem__(
                    "warnings",
                    [
                        {
                            "code": "pagination-unsupported",
                            "severity": False,
                            "message": [],
                            "action_required": "no",
                        }
                    ],
                )
            ),
            "malformed-pagination": structured_mutation(
                lambda value: value["pagination"].update(
                    {
                        "supported": "no",
                        "strategy": "execute-shell",
                        "requested_limit": False,
                        "effective_limit": False,
                        "has_more": "no",
                        "next_cursor": {"cursor": "forged"},
                    }
                )
            ),
            "malformed-completeness": structured_mutation(
                lambda value: value["completeness"].update(
                    {
                        "complete": "yes",
                        "source_limit_reduced": "no",
                        "reason": {"claim": "forged"},
                    }
                )
            ),
            "malformed-continuation": structured_mutation(
                lambda value: value.__setitem__(
                    "continuation",
                    {"strategy": ["execute-shell"], "cursor": {"forged": True}},
                )
            ),
        }
        cases["content-annotation"]["content"][0]["annotations"] = {"audience": []}

        def safety_mutation(mutator):
            parsed = copy.deepcopy(valid)
            text = parsed["content"][0]["text"]
            safety = json.loads(text[len(MCP_SAFETY_PREFIX) :])
            mutator(safety)
            parsed["content"][0]["text"] = MCP_SAFETY_PREFIX + json.dumps(
                safety,
                sort_keys=True,
                separators=(",", ":"),
            )
            return parsed

        cases["malformed-safety-warning"] = safety_mutation(
            lambda value: value.__setitem__(
                "warnings",
                [
                    {
                        "code": "pagination-unsupported",
                        "severity": "urgent",
                        "action_required": "no",
                    }
                ],
            )
        )
        cases["forged-safety-continuation"] = safety_mutation(
            lambda value: value.__setitem__(
                "continuation", {"strategy": "execute-shell"}
            )
        )

        for name, parsed in cases.items():
            with self.subTest(case=name):
                status, _, repair, metrics = mcp_compact_contract_probe_status(
                    0, parsed, "", ""
                )
                self.assertEqual(status, "blocked")
                self.assertTrue(repair)
                self.assertEqual(metrics, {})

    def test_mcp_connect_checks_use_read_only_launcher_and_probe_contract(self):
        with TemporaryDirectory() as tmp:
            certifier = OperatorReadinessCertifier(self._args(Path(tmp)))
            with mock.patch.object(certifier, "_run_command") as run_command:
                certifier._check_mcp_connect()

        calls = run_command.call_args_list
        self.assertEqual(
            [call.args[0] for call in calls],
            ["mcp_connect", "mcp_status_call", "mcp_contract_probe"],
        )
        for call in calls:
            command = call.kwargs["command"]
            launcher_spec = command[command.index("--command") + 1]
            self.assertIn("SYNAPSE_S2_CLIENT_SESSION_BRIDGE=0", launcher_spec)
            self.assertIn("SYNAPSE_S2_CLIENT_CORTEX=0", launcher_spec)
        probe = calls[2]
        self.assertTrue(probe.kwargs["required"])
        command = probe.kwargs["command"]
        self.assertEqual(command[command.index("--target") + 1], "list_spiking_memory")
        self.assertEqual(
            json.loads(command[command.index("--input-json") + 1]),
            {
                "context_id": "default",
                "limit": 1,
                "response_mode": "compact",
                "max_response_bytes": MCP_COMPACT_BUDGET,
            },
        )
        self.assertEqual(command[command.index("--timeout") + 1], "30")
        self.assertEqual(probe.kwargs["timeout"], 60)

    def test_recall_check_requires_structured_read_only_retrieval_v2(self):
        with TemporaryDirectory() as tmp:
            certifier = OperatorReadinessCertifier(self._args(Path(tmp)))
            memory = {
                "memory_id": "s2mem_readiness_fixture",
                "tag": "operator-readiness-unit-test-memory-write",
            }
            with mock.patch.object(certifier, "_run_command") as run_command:
                certifier._check_recall(memory)

        call = run_command.call_args
        command = call.kwargs["command"]
        evaluator = call.kwargs["evaluator"]
        self.assertIn("retrieve-v2", command)
        self.assertNotIn("query-text", command)
        self.assertEqual(command[command.index("--scope") + 1], "local")
        self.assertEqual(command[command.index("--response-mode") + 1], "compact")

        valid = {
            "schema": "synapse-s2.token-contract.v1",
            "operation": "memory-retrieval",
            "ok": True,
            "data": {
                "raw_input_stored": False,
                "query": {
                    "context_id": "default",
                    "recall_scope": "local",
                    "raw_input_stored": False,
                },
                "ranker": {
                    "id": "hybrid-ranker",
                    "version": 2,
                    "score_semantics": "uncalibrated-ranking-signal",
                },
                "items": [
                    {
                        "memory_id": memory["memory_id"],
                        "tag": memory["tag"],
                        "label": "readiness proof",
                        "summary": "operator-readiness-unit-test",
                        "excerpt": "bounded evidence",
                    }
                ],
            },
            "provenance": {
                "source": "authoritative-retrieval-v2",
                "context_id": "default",
                "raw_input_stored": False,
                "snapshot_id": "s2snap_fixture",
            },
        }
        ready = evaluator(0, valid, "", "")
        invalid = copy.deepcopy(valid)
        invalid["data"]["raw_input_stored"] = True
        blocked = evaluator(0, invalid, "", "")

        self.assertEqual(ready[0], "ready")
        self.assertIn(memory["memory_id"], ready[3]["matched_evidence"])
        self.assertEqual(blocked[0], "blocked")

    def test_installed_launcher_status_attests_bound_config_and_embedding_identity(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            binding_path, binding, core_paths = self._write_candidate_binding(root)
            with (
                mock.patch(
                    "scripts.operator_readiness_certify.resolve_candidate_core_paths",
                    return_value=core_paths,
                ),
                mock.patch(
                    "scripts.operator_readiness_certify.database_requires_core",
                    return_value=False,
                ),
            ):
                certifier = OperatorReadinessCertifier(
                    self._args(root / "run", core_binding=str(binding_path))
                )
            with mock.patch.object(certifier, "_run_command") as run_command:
                certifier._check_mcp_connect()
            evaluator = run_command.call_args_list[1].kwargs["evaluator"]
            config = certifier.candidate_config
            runtime = {
                "runtime": "ready",
                "dimension": config.dimension,
                "num_neurons": config.num_neurons,
                "default_top_k": config.default_top_k,
                "recall_count": config.recall_count,
                "quick_pruning_interval_seconds": (
                    config.quick_pruning_interval_seconds
                ),
                "idle_deep_sleep_seconds": config.idle_deep_sleep_seconds,
                "mlx_device": config.mlx_device,
                "mlx_available": True,
                "embedding_provider": {
                    "provider": "semantic-hash-v1",
                    "provider_type": "semantic-hash",
                },
            }
            envelope = {"content": [{"type": "text", "text": json.dumps(runtime)}]}

            ready = evaluator(0, envelope, "", "")
            runtime["dimension"] += 1
            drifted = evaluator(
                0,
                {"content": [{"type": "text", "text": json.dumps(runtime)}]},
                "",
                "",
            )

        self.assertEqual(ready[0], "ready")
        self.assertEqual(drifted[0], "blocked")
        self.assertEqual(
            ready[3]["observed_effective_config_fingerprint"],
            binding.config_fingerprint,
        )
        self.assertEqual(
            ready[3]["observed_embedding_space_identity"],
            binding.embedding_space_identity,
        )
        self.assertEqual(ready[3]["config_digest"], binding.config_digest)
        self.assertTrue(ready[3]["exact_matches"]["dimension"])
        self.assertFalse(drifted[3]["exact_matches"]["dimension"])

    def test_private_evidence_writer_preserves_existing_parent_mode(self):
        with TemporaryDirectory() as tmp:
            parent = Path(tmp) / "caller-owned"
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            target = parent / "evidence.json"

            write_private_text(target, '{"safe": true}\n')

            self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_private_evidence_writer_preserves_original_on_replace_failure(self):
        with TemporaryDirectory() as tmp:
            parent = Path(tmp)
            target = parent / "evidence.json"
            target.write_text("original\n", encoding="utf-8")

            with (
                mock.patch(
                    "scripts.operator_readiness_certify.os.replace",
                    side_effect=OSError("synthetic replace failure"),
                ),
                self.assertRaisesRegex(OSError, "synthetic replace failure"),
            ):
                write_private_text(target, "replacement\n")

            self.assertEqual(target.read_text(encoding="utf-8"), "original\n")
            self.assertEqual(list(parent.glob(".evidence.json.*.tmp")), [])

    def test_certifier_rejects_secret_and_traversing_identifiers_before_write(self):
        marker = "SYNTHETIC_ONLY_READINESS_SECRET_42"
        with TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "evidence"
            for run_id in ("../escape", "nested/run", "/tmp/escape", ".", ".."):
                with self.subTest(run_id=run_id), self.assertRaisesRegex(
                    ValueError,
                    "one safe basename component",
                ):
                    OperatorReadinessCertifier(
                        self._args(output_root, run_id=run_id)
                    )

            sensitive_overrides = (
                {"run_id": f"password={marker}"},
                {"output_dir": str(Path(tmp) / f"api_key={marker}")},
                {"launcher": str(Path(tmp) / f"token={marker}")},
                {"expected_embedding_provider": f"password={marker}"},
                {"expected_neural_model": f"api_key={marker}"},
                {
                    "expected_neural_cache_dir": str(
                        Path(tmp) / f"token={marker}"
                    )
                },
            )
            for overrides in sensitive_overrides:
                with self.subTest(overrides=tuple(overrides)), self.assertRaisesRegex(
                    ValueError,
                    "must not contain credential material",
                ):
                    OperatorReadinessCertifier(
                        self._args(output_root, **overrides)
                    )

            sensitive_target = Path(tmp) / f"password={marker}"
            sensitive_target.mkdir()
            safe_alias = Path(tmp) / "safe-output-alias"
            safe_alias.symlink_to(sensitive_target, target_is_directory=True)
            with self.assertRaisesRegex(
                ValueError,
                "must not contain credential material",
            ):
                OperatorReadinessCertifier(
                    self._args(output_root, output_dir=str(safe_alias))
                )

            self.assertFalse(output_root.exists())

    def test_json_safe_redacts_secrets_and_removes_raw_digest_oracles(self):
        marker = "sk-synthetic-evidence-secret-1234567890"
        raw_digest = "a" * 64

        rendered = json_safe(
            {
                "safe": True,
                "nested": {
                    "input_sha256": raw_digest,
                    "message": f"api_key={marker}",
                    "note": f"input_sha256={raw_digest}",
                },
                "items": [{"payload_sha256": raw_digest, "count": 3}],
            }
        )
        serialized = json.dumps(rendered, sort_keys=True)

        self.assertNotIn(marker, serialized)
        self.assertNotIn(raw_digest, serialized)
        self.assertNotIn("input_sha256", serialized)
        self.assertNotIn("payload_sha256", serialized)
        self.assertIn("[REMOVED_RAW_DIGEST_FIELD]", serialized)
        self.assertIn("[REDACTED_SECRET]", serialized)
        fallback = sanitize_evidence_text(
            f"diagnostic input_sha256={raw_digest} api_key={marker}"
        )
        self.assertNotIn(raw_digest, fallback)
        self.assertNotIn("input_sha256", fallback)
        self.assertNotIn(marker, fallback)

    def test_command_json_is_sanitized_before_artifact_persistence(self):
        marker = "sk-synthetic-command-secret-1234567890"
        raw_digest = "b" * 64
        with TemporaryDirectory() as tmp:
            certifier = OperatorReadinessCertifier(self._args(Path(tmp)))
            certifier.pack_dir.mkdir(mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            completed = __import__("subprocess").CompletedProcess(
                ["synthetic"],
                0,
                stdout=json.dumps(
                    {
                        "ready": True,
                        "input_sha256": raw_digest,
                        "nested": {"api_key": marker},
                    }
                ),
                stderr="",
            )

            with mock.patch(
                "scripts.operator_readiness_certify.subprocess.run",
                return_value=completed,
            ):
                result = certifier._run_command(
                    "synthetic",
                    label="Synthetic command",
                    command=["synthetic"],
                    required=True,
                    timeout=1,
                    evaluator=lambda *_: ("ready", "safe", "", {}),
                )

            artifact_text = "\n".join(
                Path(path).read_text(encoding="utf-8")
                for path in result.artifact_paths.values()
            )
            self.assertNotIn(marker, artifact_text)
            self.assertNotIn(raw_digest, artifact_text)
            self.assertNotIn("input_sha256", artifact_text)
            self.assertIn("[REDACTED_SECRET]", artifact_text)
            self.assertNotIn("input_sha256", result.parsed)

    def test_command_evaluator_sees_raw_wire_but_persistence_stays_sanitized(self):
        marker = "sk-synthetic-raw-evaluator-secret-1234567890"
        observed = {}
        with TemporaryDirectory() as tmp:
            certifier = OperatorReadinessCertifier(self._args(Path(tmp)))
            certifier.pack_dir.mkdir(mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            completed = __import__("subprocess").CompletedProcess(
                ["synthetic"],
                0,
                stdout=json.dumps(
                    {"ready": True, "nested": {"api_key": marker}}
                ),
                stderr="",
            )

            def evaluator(_returncode, parsed, _stdout, _stderr):
                observed["parsed"] = parsed
                return "ready", "safe", "", {}

            with mock.patch(
                "scripts.operator_readiness_certify.subprocess.run",
                return_value=completed,
            ):
                result = certifier._run_command(
                    "synthetic-raw",
                    label="Synthetic raw command",
                    command=["synthetic"],
                    required=True,
                    timeout=1,
                    evaluator=evaluator,
                )

            self.assertEqual(observed["parsed"]["nested"]["api_key"], marker)
            self.assertNotIn(marker, json.dumps(result.parsed, sort_keys=True))
            persisted = "\n".join(
                Path(path).read_text(encoding="utf-8")
                for path in result.artifact_paths.values()
            )
            self.assertNotIn(marker, persisted)

    def test_json_artifacts_and_zip_remain_parseable_after_string_sanitization(self):
        raw_digest = "d" * 64
        with TemporaryDirectory() as tmp:
            certifier = OperatorReadinessCertifier(
                self._args(Path(tmp), zip=True)
            )
            certifier.pack_dir.mkdir(mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            certifier.metadata = {
                "run_id": certifier.run_id,
                "context_id": certifier.context,
                "agent_id": certifier.agent_id,
                "embedding_provider": "semantic-hash",
                "nested": {"note": f"input_sha256={raw_digest}"},
            }

            result = certifier._finalize()
            manifest_text = Path(result["manifest_path"]).read_text(
                encoding="utf-8"
            )
            manifest = json.loads(manifest_text)
            self.assertIn("[REMOVED_RAW_DIGEST_FIELD]", manifest["nested"]["note"])
            self.assertNotIn(raw_digest, manifest_text)

            with zipfile.ZipFile(result["archive_path"]) as archive:
                for name in archive.namelist():
                    if name.endswith(".json"):
                        archived = archive.read(name).decode("utf-8")
                        json.loads(archived)
                        self.assertNotIn(raw_digest, archived)

    def test_final_zip_contains_only_private_sanitized_run_artifacts(self):
        marker = "sk-synthetic-zip-secret-1234567890"
        raw_digest = "c" * 64
        with TemporaryDirectory() as tmp:
            certifier = OperatorReadinessCertifier(
                self._args(Path(tmp), zip=True)
            )
            certifier.output_root.chmod(0o755)
            certifier.pack_dir.mkdir(mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            certifier.metadata = {
                "run_id": certifier.run_id,
                "context_id": certifier.context,
                "agent_id": certifier.agent_id,
                "git": {"head": "abc123"},
                "embedding_provider": "semantic-hash",
                "input_sha256": raw_digest,
            }
            certifier.results = [
                CheckResult(
                    check_id="memory_write",
                    label="Memory write",
                    status="ready",
                    required=True,
                    detail=f"api_key={marker}",
                    metrics={"payload_sha256": raw_digest, "safe": True},
                )
            ]
            rogue = certifier.pack_dir / "untracked.txt"
            rogue.write_text(f"api_key={marker}", encoding="utf-8")

            result = certifier._finalize()
            archive_path = Path(result["archive_path"])

            self.assertEqual(stat.S_IMODE(archive_path.stat().st_mode), 0o600)
            with zipfile.ZipFile(archive_path) as archive:
                self.assertNotIn("untracked.txt", archive.namelist())
                payload = b"\n".join(
                    archive.read(name) for name in archive.namelist()
                ).decode("utf-8")
                for info in archive.infolist():
                    self.assertEqual((info.external_attr >> 16) & 0o777, 0o600)
            self.assertNotIn(marker, payload)
            self.assertNotIn(raw_digest, payload)
            self.assertNotIn("input_sha256", payload)
            self.assertNotIn("payload_sha256", payload)
            for evidence_path in certifier._evidence_files:
                self.assertEqual(
                    stat.S_IMODE(evidence_path.stat().st_mode),
                    0o600,
                )

    def test_choose_app_prefers_requested_then_high_signal_defaults(self):
        apps = [
            {"app_name": "Slack", "pid": 1},
            {"app_name": "Google Chrome", "pid": 2},
            {"app_name": "Terminal", "pid": 3},
        ]

        self.assertEqual(choose_app(apps, preferred="Terminal")["app_name"], "Terminal")
        self.assertEqual(choose_app(apps)["app_name"], "Google Chrome")
        self.assertIsNone(choose_app([]))

    def test_app_preview_status_accepts_honest_blocked_preview_without_memory_write(self):
        parsed = {
            "action": "preview-app-snapshot",
            "app_name": "Codex",
            "writes_memory": False,
            "snapshot_quality": {
                "signal_chars": 0,
                "quality": "blocked",
                "blocked_reason": "Accessibility blocked this app",
            },
            "quality_badge": {
                "status": "blocked",
                "label": "Accessibility blocked",
                "next_action": "Use selected-text capture.",
            },
            "capability_badge": {
                "level": "selection_capture_recommended",
                "label": "Selection capture recommended",
            },
            "capture_guidance": [
                "Select the useful text in Codex, then run selected-text capture.",
            ],
        }

        status, detail, repair, metrics = app_preview_status(parsed)

        self.assertEqual(status, "ready")
        self.assertIn("writes_memory=false", detail)
        self.assertIn("selected-text", repair)
        self.assertEqual(metrics["quality_status"], "blocked")
        self.assertFalse(metrics["writes_memory"])

    def test_app_preview_status_blocks_silent_or_mutating_preview(self):
        status, detail, _, _ = app_preview_status(
            {
                "action": "preview-app-snapshot",
                "writes_memory": True,
                "quality_badge": {"status": "ready"},
                "capability_badge": {"level": "rich_text_available"},
            }
        )

        self.assertEqual(status, "blocked")
        self.assertIn("wrote memory", detail)

    def test_summary_and_runbook_make_required_failures_visible(self):
        results = [
            CheckResult(
                check_id="memory_write",
                label="Memory write",
                status="ready",
                required=True,
                detail="Wrote trace readiness as s2_123.",
            ),
            CheckResult(
                check_id="dashboard",
                label="Dashboard render smoke",
                status="blocked",
                required=True,
                detail="Dashboard warning tokens found.",
                repair="Fix dashboard warnings.",
            ),
        ]
        manifest = {
            "run_id": "operator-readiness-test",
            "context_id": "demo",
            "agent_id": "codex-desktop",
            "overall_status": classify_overall(results),
            "operator_trustworthy": False,
            "required_ready": 1,
            "required_total": 2,
            "git": {"head": "abc123"},
            "embedding_provider": "mlx-neural",
        }

        summary = render_summary_markdown(manifest, results)
        runbook = render_runbook_markdown(manifest)

        self.assertEqual(manifest["overall_status"], "blocked")
        self.assertIn("Operator trustworthy: `false`", summary)
        self.assertIn("Fix dashboard warnings.", summary)
        self.assertIn("scripts/operator_readiness_certify.py", runbook)
        self.assertIn("--expect-embedding-provider mlx-neural", runbook)
        self.assertIn("compact MCP contract", runbook)
        self.assertIn("12,288-byte structured", runbook)
        self.assertIn("4,096-byte safety", runbook)

    def test_pack_summary_is_json_serializable_shape(self):
        result = CheckResult(
            check_id="recall",
            label="Recall proof",
            status="ready",
            required=True,
            detail="Recall returned the readiness write.",
            metrics={"matched_evidence": ["s2_123"]},
        )

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps({"checks": [result.to_manifest()]}), encoding="utf-8")
            loaded = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(loaded["checks"][0]["check_id"], "recall")
        self.assertEqual(loaded["checks"][0]["metrics"]["matched_evidence"], ["s2_123"])


if __name__ == "__main__":
    unittest.main()

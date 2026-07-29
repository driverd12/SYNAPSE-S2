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
from client_config import CLIENT_CONFIG_PLAN_SCHEMA
from core_authority import CoreAuthorityLease
from core_runtime_paths import canonical_core_socket_path
from core_service import CoreConfig, write_core_config
from capture_daemon import CaptureInboxDaemon
from memory_store import DurableMemoryStore
from recovery_manager import VerifiedRecoveryManager
from scripts import core_cutover_preflight as preflight

from scripts.operator_readiness_certify import (
    CAPTURE_DRAIN_BATCH_SIZE,
    CAPTURE_DRAIN_MAX_PASSES,
    CheckResult,
    MCP_COMPACT_BUDGET,
    MCP_CONTRACT_SCHEMA,
    MCP_SAFETY_BUDGET,
    MCP_SAFETY_PREFIX,
    MCP_SAFETY_SCHEMA,
    OperatorReadinessCertifier,
    REQUIRED_PROOFS,
    RUNTIME_BUILD_IDENTITY_SCHEMA,
    app_preview_status,
    build_parser,
    choose_app,
    classify_overall,
    json_safe,
    mcp_compact_contract_probe_status,
    read_private_regular_bytes,
    readiness_recall_marker,
    render_runbook_markdown,
    render_summary_markdown,
    runtime_status_from_mcp_envelope,
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
            socket_path=canonical_core_socket_path(data),
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

    def _bound_certifier(
        self,
        root: Path,
        *,
        run_id: str = "operator-readiness-guard-test",
        authority_mode: str = "candidate-local-v5",
        **arg_overrides,
    ):
        root = root.resolve()
        binding_path, binding, core_paths = self._write_candidate_binding(
            root,
            authority_mode=authority_mode,
        )
        with (
            mock.patch(
                "scripts.operator_readiness_certify.resolve_candidate_core_paths",
                return_value=core_paths,
            ),
            mock.patch(
                "scripts.operator_readiness_certify.database_requires_core",
                return_value=(authority_mode == "authoritative-core-v6"),
            ),
        ):
            certifier = OperatorReadinessCertifier(
                self._args(
                    root / "evidence",
                    run_id=run_id,
                    core_binding=str(binding_path),
                    **arg_overrides,
                )
            )
        return certifier, binding, core_paths

    @staticmethod
    def _capture_status(*, pending: int = 0, processing: int = 0):
        return {
            "transport_ready": True,
            "missing_transport_directories": [],
            "unsafe_transport_directories": [],
            "pending_file_count": pending,
            "processing_file_count": processing,
            "inbox_temp_file_count": 0,
            "processing_empty_claim_count": 0,
            "processing_malformed_claim_count": 0,
            "error_file_count": 0,
            "unresolved_error_count": 0,
            "unsafe_error_artifact_count": 0,
            "error_resolution_pending_count": 0,
            "error_resolution_failed_count": 0,
        }

    @staticmethod
    def _required_ready_results():
        return [
            CheckResult(
                check_id=check_id,
                label=check_id.replace("_", " ").title(),
                status="ready",
                required=True,
                detail="Synthetic unit-test readiness evidence.",
            )
            for check_id in REQUIRED_PROOFS
        ]

    @staticmethod
    def _guarded_recovery_evidence(*, recovery_proof_path: Path):
        recovery_proof_path = recovery_proof_path.resolve()
        binding = {
            "schema": "synapse-s2.capture-ledger-binding-proof.v1",
            "verified": True,
            "verified_capture_count": 7,
            "revision": "a" * 64,
        }
        reconciliation = {
            "missing_authoritative_ledger_count": 0,
            "replay_required_capture_count": 0,
            "replay_required_file_count": 0,
            "identifierless_replay_file_count": 0,
            "unclassified_file_count": 0,
        }
        audit = {
            "action": "capture-ledger-audit",
            "status": "ready",
            "verification_passed": True,
            "audit_revision": "b" * 64,
            "processed_file_count": 7,
            "processed_total_bytes": 700,
            "processed_v2_capture_count": 7,
            "ledger_capture_count": 7,
            "missing_authoritative_ledger_count": 0,
            "ledger_binding_mismatch_count": 0,
            "repairable_capture_count": 0,
            "blocked_capture_count": 0,
        }
        recovery_proof_path.write_text(
            json.dumps(
                {
                    "schema": "synapse-s2.recovery-bundle-restore.v2",
                    "mode": "isolated-recovery-proof",
                    "verified": True,
                    "cutover_ready": True,
                    "auth_algorithm": "ed25519",
                    "auth_key_id": "unit-test-public-key-id",
                    "signing_public_key": "unit-test-public-key-material",
                    "receipt_digest": "c" * 64,
                    "receipt_signature": "unit-test-signature",
                    "missing_transport_ledger_count": 0,
                    "capture_ledger_binding": binding,
                    "reconciliation": reconciliation,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        recovery_proof_path.chmod(0o600)
        return {
            "verified": True,
            "capture_ledger_before": copy.deepcopy(audit),
            "capture_ledger_after": copy.deepcopy(audit),
            "capture_transport_at_publication": {
                "ledger_verification_passed": True,
                "ledger_audit_revision": "b" * 64,
            },
            "bundle": {
                "bundle_verified": True,
                "cutover_ready": True,
                "capture_file_count": 7,
                "capture_ledger_binding": binding,
                "reconciliation": reconciliation,
            },
            "verification": {
                "verified": True,
                "cutover_ready": True,
                "receipt_identity_trusted": True,
                "capture_database_binding": {
                    "auth_key_id": "unit-test-public-key-id",
                },
                "capture_ledger_binding": binding,
                "reconciliation": reconciliation,
            },
            "restore": {
                "verified": True,
                "cutover_ready": True,
                "capture_file_count": 7,
                "missing_transport_ledger_count": 0,
                "capture_ledger_binding": binding,
                "reconciliation": reconciliation,
                "recovery_proof_path": str(recovery_proof_path),
            },
        }

    def test_cli_commands_use_core_route_without_local_topology(self):
        with TemporaryDirectory() as tmp:
            socket_path = canonical_core_socket_path(
                Path(__file__).resolve().parents[1] / ".synapse_s2"
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

    def test_probe_environment_drops_ambient_credentials_and_injection_controls(self):
        with TemporaryDirectory() as tmp:
            canaries = {
                "GITHUB_TOKEN": "synthetic-github-canary",
                "OPENAI_API_KEY": "synthetic-openai-canary",
                "HF_TOKEN": "synthetic-hf-canary",
                "PYTHONPATH": "/synthetic/injection",
                "PYTHONHOME": "/synthetic/python-home",
                "DYLD_INSERT_LIBRARIES": "/synthetic/library.dylib",
            }
            with mock.patch.dict(os.environ, canaries, clear=False):
                certifier = OperatorReadinessCertifier(self._args(Path(tmp)))
                env = certifier._base_env()

            self.assertTrue(set(canaries).isdisjoint(env))
            self.assertEqual(env["PYTHONNOUSERSITE"], "1")
            self.assertIn("PATH", env)
            self.assertIn("HOME", env)

            certifier.artifact_dir.mkdir(parents=True, exist_ok=True)
            observed = {}

            def run(*_args, **kwargs):
                observed["env"] = kwargs["env"]
                return SimpleNamespace(returncode=0, stdout="{}", stderr="")

            with mock.patch(
                "scripts.operator_readiness_certify.subprocess.run",
                side_effect=run,
            ):
                certifier._run_command(
                    "empty-env",
                    label="Explicit empty environment",
                    command=["/usr/bin/true"],
                    required=False,
                    timeout=1,
                    evaluator=lambda *_args: ("ready", "ok", "", {}),
                    env={},
                )
            self.assertEqual(observed["env"], {})

    def test_runtime_status_envelope_rejects_error_and_ambiguous_channels(self):
        runtime = {
            "runtime": "ready",
            "dimension": 8,
            "num_neurons": 16,
            "embedding_provider": {},
        }
        text_channel = {
            "isError": False,
            "content": [{"type": "text", "text": json.dumps(runtime)}],
        }
        self.assertEqual(runtime_status_from_mcp_envelope(text_channel), runtime)
        self.assertEqual(
            runtime_status_from_mcp_envelope(
                {"isError": False, "structuredContent": runtime}
            ),
            runtime,
        )
        self.assertEqual(
            runtime_status_from_mcp_envelope(
                {
                    **text_channel,
                    "structured_content": {"result": json.dumps(runtime)},
                }
            ),
            runtime,
        )
        rejected = (
            {**text_channel, "isError": True},
            {**text_channel, "error": "outer failure"},
            {
                **text_channel,
                "structuredContent": copy.deepcopy(runtime),
            },
            {
                "isError": False,
                "content": [
                    {"type": "text", "text": json.dumps(runtime)},
                    {"type": "text", "text": json.dumps(runtime)},
                ],
            },
            {
                "isError": False,
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({"error": "failed", "old": runtime}),
                    }
                ],
            },
        )
        for payload in rejected:
            with self.subTest(payload=payload):
                self.assertIsNone(runtime_status_from_mcp_envelope(payload))

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

    def test_client_config_probe_requires_exact_disabled_codex_profile(self):
        with TemporaryDirectory() as tmp:
            certifier, binding, _ = self._bound_certifier(
                Path(tmp),
                authority_mode="authoritative-core-v6",
                handoff_running_core=True,
                codex_disabled_for_certification=True,
            )
            with mock.patch.object(certifier, "_run_command") as run_command:
                certifier._check_client_config()

        call = run_command.call_args
        self.assertIn("--codex-disabled-for-certification", call.kwargs["command"])
        self.assertEqual(
            call.kwargs["command"][
                call.kwargs["command"].index("--launcher") + 1
            ],
            str(certifier.launcher),
        )
        evaluator = call.kwargs["evaluator"]
        parsed = {
            "schema": CLIENT_CONFIG_PLAN_SCHEMA,
            "codex_mcp_enabled": False,
            "activation_profile": "certification-quiescence",
            "repo_root": str(Path(__file__).resolve().parents[1]),
            "launcher_path": str(certifier.launcher),
            "publication_recovery_required": False,
            "core_binding": {
                "path": str(certifier.core_binding_path),
                "digest": binding.digest,
                "authority_mode": binding.authority_mode,
                "config_path": str(binding.config_path),
                "config_digest": binding.config_digest,
                "config_fingerprint": binding.config_fingerprint,
                "embedding_space_identity": binding.embedding_space_identity,
            },
            "restart_required": False,
            "clients": {
                name: {"would_change": False, "changed": False}
                for name in ("project_mcp", "claude_desktop", "claude_code", "codex")
            },
        }
        ready = evaluator(0, parsed, "", "")
        wrong = evaluator(
            0,
            {**parsed, "codex_mcp_enabled": True, "activation_profile": "operational"},
            "",
            "",
        )
        drifted_binding = copy.deepcopy(parsed)
        drifted_binding["core_binding"]["digest"] = "0" * 64
        drifted = evaluator(0, drifted_binding, "", "")
        self.assertEqual(ready[0], "ready")
        self.assertFalse(ready[3]["codex_mcp_enabled"])
        self.assertEqual(ready[3]["core_binding"]["digest"], binding.digest)
        self.assertEqual(wrong[0], "blocked")
        self.assertEqual(drifted[0], "blocked")

    def test_codex_certification_profile_supports_bound_first_cutover(self):
        with TemporaryDirectory() as tmp:
            certifier, binding, _ = self._bound_certifier(
                Path(tmp),
                authority_mode="candidate-local-v5",
                codex_disabled_for_certification=True,
                handoff_running_core=False,
            )

        self.assertTrue(certifier.args.codex_disabled_for_certification)
        self.assertFalse(certifier.args.handoff_running_core)
        self.assertEqual(certifier.core_binding.digest, binding.digest)

    def test_codex_certification_profile_requires_reviewed_binding(self):
        with TemporaryDirectory() as tmp, mock.patch(
            "scripts.operator_readiness_certify.default_binding_path",
            return_value=Path(tmp) / "missing-core-binding.json",
        ), self.assertRaisesRegex(
            ValueError,
            "requires a reviewed core binding",
        ):
            OperatorReadinessCertifier(
                self._args(
                    Path(tmp),
                    codex_disabled_for_certification=True,
                )
            )

    def test_readiness_recall_marker_is_deterministic_unique_and_alphabetic(self):
        first = readiness_recall_marker("operator-readiness-unit-test")
        repeated = readiness_recall_marker("operator-readiness-unit-test")
        different = readiness_recall_marker("operator-readiness-unit-test-2")

        self.assertEqual(first, repeated)
        self.assertNotEqual(first, different)
        self.assertRegex(first, r"^synapseproof[a-p]{24}$")

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
            "mlx-neural",
        )
        self.assertEqual(
            certifier.candidate_config.embedding_neural_model_id,
            "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ",
        )
        self.assertEqual(
            certifier.candidate_config.embedding_neural_revision,
            "6c3ae70858513f1a78e9cdca3cae330d9075cd2a",
        )
        self.assertTrue(
            certifier.candidate_config.embedding_neural_local_files_only
        )
        self.assertEqual(certifier.candidate_config.mlx_device, "gpu")

    def test_delivery_publication_repair_flag_requires_explicit_core_handoff(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            binding_path, _, core_paths = self._write_candidate_binding(root)
            args = build_parser().parse_args(
                [
                    "--output-dir",
                    str(root / "evidence"),
                    "--launcher",
                    str(root / "synapse-s2-mcp"),
                    "--core-binding",
                    str(binding_path),
                    "--repair-delivery-publication-after-handoff",
                ]
            )
            self.assertTrue(args.repair_delivery_publication_after_handoff)
            self.assertFalse(args.handoff_running_core)
            with (
                mock.patch(
                    "scripts.operator_readiness_certify.resolve_candidate_core_paths",
                    return_value=core_paths,
                ),
                mock.patch(
                    "scripts.operator_readiness_certify.database_requires_core",
                    return_value=False,
                ),
                self.assertRaisesRegex(
                    ValueError,
                    "delivery publication repair requires --handoff-running-core",
                ),
            ):
                OperatorReadinessCertifier(args)

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

    def test_authoritative_runtime_build_identity_requires_exact_current_build(self):
        with TemporaryDirectory() as tmp:
            certifier, _, _ = self._bound_certifier(
                Path(tmp),
                authority_mode="authoritative-core-v6",
            )
            with mock.patch.object(certifier, "_run_command") as run_command:
                certifier._check_runtime_build_identity()

        call = run_command.call_args
        self.assertEqual(call.args[0], "runtime_build_identity")
        self.assertTrue(call.kwargs["required"])
        command = call.kwargs["command"]
        self.assertIn("health", command)
        evaluator = call.kwargs["evaluator"]
        valid = {
            "health": {"ready": True},
            "identity": {
                "build_id": certifier.expected_source_build_id,
                "config_fingerprint": certifier.candidate_config.fingerprint,
            },
        }
        status, _, _, metrics = evaluator(0, valid, "", "")
        self.assertEqual(status, "ready")
        self.assertEqual(metrics["schema"], RUNTIME_BUILD_IDENTITY_SCHEMA)
        self.assertEqual(metrics["proof_mode"], "authoritative-core-health")
        self.assertTrue(metrics["matched"])

        mismatched = copy.deepcopy(valid)
        mismatched["identity"]["build_id"] = "source-" + "0" * 24
        status, _, repair, metrics = evaluator(0, mismatched, "", "")
        self.assertEqual(status, "blocked")
        self.assertTrue(repair)
        self.assertFalse(metrics["matched"])
        self.assertFalse(metrics["exact_matches"]["source_build"])

    def test_run_stops_before_live_functional_probes_on_build_mismatch(self):
        with TemporaryDirectory() as tmp:
            certifier, _, _ = self._bound_certifier(
                Path(tmp),
                authority_mode="authoritative-core-v6",
            )
            blocked = CheckResult(
                check_id="runtime_build_identity",
                label="Runtime build identity",
                status="blocked",
                required=True,
                detail="Synthetic runtime build mismatch.",
            )
            certifier._run_metadata = mock.Mock(
                return_value={
                    "git": {
                        "head": "709330378b0902841cb15a0b82971eea4fe3969e",
                        "branch": "main",
                        "status_short": "",
                    }
                }
            )
            certifier._write_json = mock.Mock()
            certifier._check_runtime_build_identity = mock.Mock(
                return_value=blocked
            )
            certifier._check_mcp_connect = mock.Mock()
            certifier._check_memory_write = mock.Mock()
            certifier._guarded_recovery_and_finalize = mock.Mock()
            certifier._finalize = mock.Mock(
                return_value={"overall_status": "blocked"}
            )

            result = certifier.run()

            self.assertEqual(result["overall_status"], "blocked")
            certifier._check_runtime_build_identity.assert_called_once_with()
            certifier._check_mcp_connect.assert_not_called()
            certifier._check_memory_write.assert_not_called()
            certifier._guarded_recovery_and_finalize.assert_not_called()
            certifier._finalize.assert_called_once_with()

    def test_run_stops_before_expensive_probes_on_dirty_source_checkout(self):
        with TemporaryDirectory() as tmp:
            certifier, _, _ = self._bound_certifier(
                Path(tmp),
                authority_mode="authoritative-core-v6",
            )
            certifier._run_metadata = mock.Mock(
                return_value={
                    "git": {
                        "head": "709330378b0902841cb15a0b82971eea4fe3969e",
                        "branch": "main",
                        "status_short": "M .mcp.json",
                    }
                }
            )
            certifier._write_json = mock.Mock()
            certifier._check_runtime_build_identity = mock.Mock()
            certifier._check_mcp_connect = mock.Mock()
            certifier._guarded_recovery_and_finalize = mock.Mock()
            certifier._finalize = mock.Mock(
                return_value={"overall_status": "blocked"}
            )

            result = certifier.run()

            self.assertEqual(result["overall_status"], "blocked")
            self.assertEqual(certifier.results[0].check_id, "source_checkout_clean")
            self.assertEqual(certifier.results[0].status, "blocked")
            self.assertFalse(certifier.results[0].required)
            certifier._check_runtime_build_identity.assert_not_called()
            certifier._check_mcp_connect.assert_not_called()
            certifier._guarded_recovery_and_finalize.assert_not_called()
            certifier._finalize.assert_called_once_with()

    def test_recall_check_requires_structured_read_only_retrieval_v2(self):
        with TemporaryDirectory() as tmp:
            certifier = OperatorReadinessCertifier(self._args(Path(tmp)))
            memory = {
                "memory_id": "s2mem_readiness_fixture",
                "tag": "operator-readiness-unit-test-memory-write",
                "readiness_recall_marker": certifier.recall_marker,
            }
            with mock.patch.object(certifier, "_run_command") as run_command:
                certifier._check_recall(memory)

        call = run_command.call_args
        command = call.kwargs["command"]
        evaluator = call.kwargs["evaluator"]
        self.assertIn("retrieve-v2", command)
        self.assertNotIn("query-text", command)
        self.assertIn("--no-include-graph-neighbors", command)
        self.assertEqual(
            command[command.index("--prompt") + 1],
            f"SYNAPSE readiness retrieval proof marker {certifier.recall_marker}",
        )
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
                        "label": f"readiness proof {certifier.recall_marker}",
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
        self.assertEqual(memory["memory_id"], ready[3]["matched_memory_id"])
        self.assertEqual(certifier.recall_marker, ready[3]["matched_recall_marker"])
        self.assertEqual(blocked[0], "blocked")

        crowded = copy.deepcopy(valid)
        crowded["data"]["items"] = [
            {
                "memory_id": "s2mem_historical_fixture",
                "tag": "operator-readiness-old-memory-write",
                "label": "readiness proof",
                "summary": "generic historical certification trace",
                "excerpt": "real memory write proof",
            }
        ]
        missing_exact_write = evaluator(0, crowded, "", "")
        self.assertEqual(missing_exact_write[0], "blocked")
        self.assertEqual(
            missing_exact_write[3]["expected_recall_marker"],
            certifier.recall_marker,
        )

        split_evidence = copy.deepcopy(valid)
        split_evidence["data"]["items"] = [
            {
                "memory_id": memory["memory_id"],
                "tag": memory["tag"],
                "label": "exact identity without marker",
            },
            {
                "memory_id": "s2mem_wrong_identity",
                "tag": "wrong-tag",
                "label": certifier.recall_marker,
            },
        ]
        self.assertEqual(evaluator(0, split_evidence, "", "")[0], "blocked")

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
            envelope = {
                "isError": False,
                "content": [{"type": "text", "text": json.dumps(runtime)}],
            }

            ready = evaluator(0, envelope, "", "")
            runtime["dimension"] += 1
            drifted = evaluator(
                0,
                {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps(runtime)}],
                },
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

    def test_neural_launcher_status_uses_canonical_runtime_config_and_rejects_conflicts(self):
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
            config = dataclasses.replace(
                certifier.candidate_config,
                embedding_provider_name="mlx-neural",
                embedding_neural_model_id=(
                    "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ"
                ),
                embedding_neural_revision=(
                    "6c3ae70858513f1a78e9cdca3cae330d9075cd2a"
                ),
                embedding_neural_cache_dir=root / "models",
                embedding_neural_pooling="mean",
                embedding_neural_max_tokens=512,
                embedding_neural_normalize=True,
                embedding_neural_local_files_only=True,
                mlx_device="gpu",
                require_native=True,
            )
            certifier.candidate_config = config
            with mock.patch.object(certifier, "_run_command") as run_command:
                certifier._check_mcp_connect()
            evaluator = run_command.call_args_list[1].kwargs["evaluator"]
            runtime_config = {
                "schema": "synapse-s2.embedding-runtime-config.v1",
                "provider": "mlx-neural-v1",
                "model_id": config.embedding_neural_model_id,
                "revision": config.embedding_neural_revision,
                "cache_dir": str(config.embedding_neural_cache_dir),
                "pooling": config.embedding_neural_pooling,
                "max_tokens": config.embedding_neural_max_tokens,
                "normalize": config.embedding_neural_normalize,
                "local_files_only": config.embedding_neural_local_files_only,
            }
            provider = {
                "provider": "mlx-neural-v1",
                "provider_type": "mlx-neural",
                "model_id": runtime_config["model_id"],
                "revision": runtime_config["revision"],
                "cache_dir": runtime_config["cache_dir"],
                "pooling": runtime_config["pooling"],
                "max_tokens": runtime_config["max_tokens"],
                "normalized": runtime_config["normalize"],
                "local_files_only": runtime_config["local_files_only"],
                "runtime_config": runtime_config,
            }
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
                "embedding_provider": provider,
            }

            def evaluate(payload):
                envelope = {
                    "isError": False,
                    "content": [
                        {"type": "text", "text": json.dumps(payload)}
                    ]
                }
                return evaluator(0, envelope, "", "")

            ready = evaluate(runtime)
            legacy_details = copy.deepcopy(runtime)
            legacy_details["embedding_provider"]["details"] = {
                "revision": "legacy-value-must-not-override-canonical",
                "max_tokens": 1,
                "local_files_only": False,
            }
            still_ready = evaluate(legacy_details)
            top_level_conflict = copy.deepcopy(runtime)
            top_level_conflict["embedding_provider"]["revision"] = "d" * 40
            blocked_top_level = evaluate(top_level_conflict)
            canonical_conflict = copy.deepcopy(runtime)
            canonical_conflict["embedding_provider"]["runtime_config"][
                "max_tokens"
            ] += 1
            blocked_canonical = evaluate(canonical_conflict)
            missing_canonical = copy.deepcopy(runtime)
            missing_canonical["embedding_provider"].pop("runtime_config")
            blocked_missing = evaluate(missing_canonical)

        self.assertEqual(ready[0], "ready")
        self.assertEqual(still_ready[0], "ready")
        self.assertTrue(
            ready[3]["exact_matches"]["neural_runtime_config"]
        )
        self.assertTrue(
            ready[3]["exact_matches"]["neural_top_level_consistent"]
        )
        self.assertEqual(blocked_top_level[0], "blocked")
        self.assertFalse(
            blocked_top_level[3]["exact_matches"][
                "neural_top_level_consistent"
            ]
        )
        self.assertEqual(blocked_canonical[0], "blocked")
        self.assertFalse(
            blocked_canonical[3]["exact_matches"]["neural_max_tokens"]
        )
        self.assertEqual(blocked_missing[0], "blocked")
        self.assertFalse(
            blocked_missing[3]["exact_matches"]["neural_runtime_config"]
        )

    def test_doctor_timeout_is_bounded_and_candidate_aware(self):
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
                certifier._check_doctor()
            semantic_timeout = run_command.call_args.kwargs["timeout"]

            certifier.candidate_config = dataclasses.replace(
                certifier.candidate_config,
                embedding_provider_name="mlx-neural",
                embedding_neural_model_id="unit/pinned-neural-model",
                embedding_neural_revision="a" * 40,
                embedding_neural_cache_dir=root / "models",
                embedding_neural_pooling="mean",
                embedding_neural_max_tokens=512,
                embedding_neural_normalize=True,
                embedding_neural_local_files_only=True,
            )
            with mock.patch.object(certifier, "_run_command") as run_command:
                certifier._check_doctor()
            neural_timeout = run_command.call_args.kwargs["timeout"]

        self.assertEqual(semantic_timeout, 60)
        self.assertEqual(neural_timeout, 300)
        self.assertGreater(neural_timeout, semantic_timeout)
        self.assertLessEqual(neural_timeout, 300)

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

    def test_finalize_builds_archive_before_authoritative_manifest(self):
        with TemporaryDirectory() as tmp:
            certifier, _, _ = self._bound_certifier(
                Path(tmp),
                run_id="manifest-last",
            )
            certifier.args.zip = True
            certifier.pack_dir.mkdir(parents=True, mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            certifier.metadata = {
                "run_id": certifier.run_id,
                "context_id": certifier.context,
                "agent_id": certifier.agent_id,
                "git": {"head": "unit-test", "status_short": ""},
                "embedding_provider": "semantic-hash",
            }
            certifier.results = self._required_ready_results()
            manifest_path = certifier.pack_dir / "manifest.json"

            def fail_archive(*_args, **kwargs):
                self.assertFalse(manifest_path.exists())
                self.assertIn("manifest.json", kwargs["virtual_json_members"])
                raise RuntimeError("synthetic archive failure")

            with (
                mock.patch(
                    "scripts.operator_readiness_certify.write_private_evidence_zip",
                    side_effect=fail_archive,
                ),
                self.assertRaisesRegex(RuntimeError, "synthetic archive failure"),
            ):
                certifier._finalize()
            self.assertFalse(manifest_path.exists())

    def test_finalize_blocks_missing_and_duplicate_required_proofs(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = {
                "missing": (
                    [
                        result
                        for result in self._required_ready_results()
                        if result.check_id != "dashboard"
                    ],
                    "dashboard",
                ),
                "duplicate": (
                    self._required_ready_results()
                    + [
                        CheckResult(
                            check_id="dashboard",
                            label="Duplicate dashboard proof",
                            status="ready",
                            required=True,
                            detail="A duplicate must never inflate readiness.",
                        )
                    ],
                    "dashboard",
                ),
                "optional-shadow": (
                    self._required_ready_results()
                    + [
                        CheckResult(
                            check_id="dashboard",
                            label="Optional shadow dashboard proof",
                            status="ready",
                            required=False,
                            detail="A nonrequired shadow must still block ambiguity.",
                        )
                    ],
                    "dashboard",
                ),
            }
            for case_name, (results, expected_id) in cases.items():
                with self.subTest(case=case_name):
                    certifier, _, _ = self._bound_certifier(
                        root / case_name,
                        run_id=f"proof-contract-{case_name}",
                    )
                    certifier.pack_dir.mkdir(parents=True, mode=0o700)
                    certifier.artifact_dir.mkdir(mode=0o700)
                    certifier.metadata = {
                        "run_id": certifier.run_id,
                        "context_id": certifier.context,
                        "agent_id": certifier.agent_id,
                        "git": {"head": "unit-test", "status_short": ""},
                        "embedding_provider": "semantic-hash",
                    }
                    certifier.results = results

                    result = certifier._finalize()
                    manifest = json.loads(
                        Path(result["manifest_path"]).read_text(encoding="utf-8")
                    )

                    self.assertEqual(result["overall_status"], "blocked")
                    self.assertFalse(result["operator_trustworthy"])
                    self.assertFalse(manifest["required_proof_contract"]["valid"])
                    self.assertIn(expected_id, result["failed_required"])
                    self.assertIn(
                        expected_id,
                        manifest["required_proof_contract"][
                            "missing" if case_name == "missing" else "duplicates"
                        ],
                    )
                    self.assertEqual(result["required_total"], len(REQUIRED_PROOFS))

    def test_capture_drain_is_bounded_and_stops_on_no_progress(self):
        def run_scenario(
            root: Path,
            *,
            statuses: list[dict],
            drains: list[dict],
        ):
            certifier, _, _ = self._bound_certifier(root)
            status_iter = iter(statuses)
            drain_iter = iter(drains)
            calls: list[tuple[str, list[str]]] = []

            def run_command(
                check_id,
                *,
                label,
                command,
                required,
                timeout,
                evaluator,
                env=None,
            ):
                del timeout, env
                payload = (
                    next(drain_iter)
                    if check_id.startswith("capture_inbox_drain_")
                    else next(status_iter)
                )
                status, detail, repair, metrics = evaluator(
                    0,
                    payload,
                    json.dumps(payload),
                    "",
                )
                result = CheckResult(
                    check_id=check_id,
                    label=label,
                    status=status,
                    required=required,
                    detail=detail,
                    repair=repair,
                    command=command,
                    returncode=0,
                    parsed=payload,
                    metrics=metrics,
                )
                certifier.results.append(result)
                calls.append((check_id, command))
                return result

            with mock.patch.object(certifier, "_run_command", side_effect=run_command):
                final = certifier._check_capture_inbox()
            return certifier, final, calls

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            certifier, ready, calls = run_scenario(
                root / "progress",
                statuses=[
                    self._capture_status(pending=501),
                    self._capture_status(pending=251),
                    self._capture_status(pending=1),
                    self._capture_status(pending=0),
                    self._capture_status(pending=0),
                ],
                drains=[
                    {"processed_file_count": 250, "error_file_count": 0},
                    {"processed_file_count": 250, "error_file_count": 0},
                    {"processed_file_count": 1, "error_file_count": 0},
                ],
            )
            drain_calls = [
                command
                for check_id, command in calls
                if check_id.startswith("capture_inbox_drain_")
            ]
            self.assertEqual(ready.status, "ready")
            self.assertEqual(ready.metrics["drain_passes"], 3)
            self.assertEqual(ready.metrics["processed_file_count"], 501)
            self.assertEqual(len(drain_calls), 3)
            for command in drain_calls:
                self.assertEqual(
                    command[command.index("--max-files") + 1],
                    str(CAPTURE_DRAIN_BATCH_SIZE),
                )
                self.assertIn("--confirm", command)
            required_capture = [
                result
                for result in certifier.results
                if result.required and result.check_id == "capture_inbox"
            ]
            self.assertEqual(len(required_capture), 1)

            certifier, blocked, _ = run_scenario(
                root / "stalled",
                statuses=[
                    self._capture_status(pending=1),
                    self._capture_status(pending=1),
                    self._capture_status(pending=1),
                ],
                drains=[
                    {
                        "processed_file_count": 0,
                        "deferred_file_count": 1,
                        "error_file_count": 0,
                    }
                ],
            )
            self.assertEqual(blocked.status, "blocked")
            self.assertEqual(blocked.metrics["drain_passes"], 1)
            self.assertLess(
                blocked.metrics["drain_passes"],
                CAPTURE_DRAIN_MAX_PASSES,
            )
            with (
                mock.patch(
                    "scripts.operator_readiness_certify.CoreAuthorityLease.acquire_core"
                ) as acquire_core,
                mock.patch.object(
                    certifier,
                    "_finalize",
                    return_value={"overall_status": "blocked"},
                ),
            ):
                certifier._guarded_recovery_and_finalize()
            acquire_core.assert_not_called()

    def test_run_orders_dashboard_and_capture_before_guard(self):
        with TemporaryDirectory() as tmp:
            certifier, _, _ = self._bound_certifier(Path(tmp))
            events: list[str] = []

            def record(name, value=None):
                def invoke(*_args, **_kwargs):
                    events.append(name)
                    return value

                return mock.Mock(side_effect=invoke)

            certifier._run_metadata = mock.Mock(
                return_value={
                    "run_id": certifier.run_id,
                    "context_id": certifier.context,
                    "agent_id": certifier.agent_id,
                    "git": {
                        "head": "709330378b0902841cb15a0b82971eea4fe3969e",
                        "branch": "main",
                        "status_short": "",
                    },
                }
            )
            certifier._write_json = mock.Mock()
            ordered_methods = (
                "_check_runtime_build_identity",
                "_check_local_launcher",
                "_check_client_config",
                "_check_mcp_connect",
                "_check_neural_embedding",
                "_check_doctor",
                "_check_start_work",
                "_check_memory_write",
                "_check_recall",
                "_check_app_preview",
                "_check_wrap_session",
                "_check_dashboard",
                "_check_capture_inbox",
            )
            for method_name in ordered_methods:
                value = {} if method_name == "_check_memory_write" else None
                if method_name == "_check_runtime_build_identity":
                    value = CheckResult(
                        check_id="runtime_build_identity",
                        label="Runtime build identity",
                        status="ready",
                        required=True,
                        detail="Synthetic current-build proof.",
                    )
                setattr(
                    certifier,
                    method_name,
                    record(method_name.removeprefix("_check_"), value),
                )
            certifier._guarded_recovery_and_finalize = record(
                "guard",
                {"overall_status": "ready"},
            )

            result = certifier.run()

            self.assertEqual(result["overall_status"], "ready")
            self.assertEqual(
                events,
                [
                    "runtime_build_identity",
                    "local_launcher",
                    "client_config",
                    "mcp_connect",
                    "neural_embedding",
                    "doctor",
                    "start_work",
                    "memory_write",
                    "recall",
                    "app_preview",
                    "wrap_session",
                    "dashboard",
                    "capture_inbox",
                    "guard",
                ],
            )

    def test_core_handoff_does_not_mutate_launchd_when_phase_a_is_not_ready(self):
        with TemporaryDirectory() as tmp:
            certifier, _, _ = self._bound_certifier(
                Path(tmp),
                authority_mode="authoritative-core-v6",
                handoff_running_core=True,
            )
            guarded_ids = {
                "authority_guard",
                "guarded_quiescence",
                "capture_ledger_audit",
                "recovery_backup",
                "recovery_verify",
                "recovery_restore",
            }
            certifier.results = [
                CheckResult(
                    check_id=check_id,
                    label=check_id,
                    status=("blocked" if check_id == "doctor" else "ready"),
                    required=True,
                    detail="Synthetic Phase-A result.",
                )
                for check_id in REQUIRED_PROOFS
                if check_id not in guarded_ids
            ]

            with mock.patch(
                "scripts.operator_readiness_certify.LaunchCtl"
            ) as launchctl:
                ready = certifier._handoff_running_core_for_guard()

            self.assertFalse(ready)
            launchctl.assert_not_called()
            handoff = certifier.results[-1]
            self.assertEqual(handoff.check_id, "core_phase_handoff")
            self.assertEqual(handoff.status, "blocked")
            self.assertFalse(handoff.required)
            self.assertEqual(handoff.metrics, {"action_taken": False})

    def test_core_handoff_disables_and_unloads_only_exact_bound_v6_label(self):
        with TemporaryDirectory() as tmp:
            certifier, binding, _ = self._bound_certifier(
                Path(tmp),
                authority_mode="authoritative-core-v6",
                handoff_running_core=True,
            )
            guarded_ids = {
                "authority_guard",
                "guarded_quiescence",
                "capture_ledger_audit",
                "recovery_backup",
                "recovery_verify",
                "recovery_restore",
            }
            certifier.results = [
                CheckResult(
                    check_id=check_id,
                    label=check_id,
                    status="ready",
                    required=True,
                    detail="Synthetic Phase-A readiness evidence.",
                )
                for check_id in REQUIRED_PROOFS
                if check_id not in guarded_ids
            ]
            controller = mock.Mock()
            controller.snapshot.side_effect = [
                {
                    "loaded": True,
                    "running": True,
                    "pid": 4242,
                },
                {
                    "loaded": False,
                    "running": False,
                    "pid": None,
                },
            ]
            controller.disabled.return_value = True

            with mock.patch(
                "scripts.operator_readiness_certify.LaunchCtl",
                return_value=controller,
            ) as launchctl:
                ready = certifier._handoff_running_core_for_guard()

            self.assertTrue(ready, certifier.results[-1])
            launchctl.assert_called_once_with(
                "/bin/launchctl",
                uid=os.getuid(),
                label=binding.core_label,
            )
            controller.disable.assert_called_once_with()
            controller.bootout.assert_called_once_with(
                wait_seconds=mock.ANY,
            )
            self.assertEqual(controller.snapshot.call_count, 2)
            controller.disabled.assert_called_once_with()
            handoff = certifier.results[-1]
            self.assertEqual(handoff.check_id, "core_phase_handoff")
            self.assertEqual(handoff.status, "ready")
            self.assertEqual(
                handoff.metrics,
                {
                    "action_taken": True,
                    "prior_loaded": True,
                    "prior_running": True,
                    "prior_pid_present": True,
                    "final_loaded": False,
                    "final_running": False,
                    "disabled_policy_verified": True,
                },
            )

    def test_delivery_publication_repair_uses_locked_installer_and_bounded_artifact(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            certifier, _, _ = self._bound_certifier(
                root,
                authority_mode="authoritative-core-v6",
                handoff_running_core=True,
                repair_delivery_publication_after_handoff=True,
            )
            certifier.pack_dir.mkdir(parents=True, mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            secret_marker = "must-not-enter-readiness-evidence"
            audit = {
                "protocol_version": "context-delivery-publication-repair.v1",
                "status": "repairable",
                "audit_revision": "b" * 64,
                "repair_required": True,
                "cursor_mismatch_count": 2,
                "target_reconciliation_needed": True,
                "repair_receipt_integrity_error_count": 0,
                "repair_receipt_semantic_error_count": 0,
                "unreviewed_payload": secret_marker,
            }
            result = {
                "status": "repaired",
                "operation_id": "s2maint_" + ("1" * 32),
                "expected_revision": "b" * 64,
                "after": {
                    "audit_revision": "a" * 64,
                    "status": "ready",
                    "repair_receipt_integrity_error_count": 0,
                    "repair_receipt_semantic_error_count": 0,
                },
                "reconciled_target_highwater": True,
                "repaired_cursor_count": 2,
                "safety_backup": {
                    "sha256": "a" * 64,
                    "size_bytes": 4096,
                    "verified": True,
                    "path": f"/private/{secret_marker}",
                },
                "maintenance_receipt_verified": True,
                "checkpoint": [0, 4, 4],
                "quick_check": ["ok"],
                "foreign_key_error_count": 0,
                "verification_passed": True,
                "unreviewed_payload": secret_marker,
            }
            audit_envelope = {
                "ok": True,
                "action": "context-delivery-integrity",
                "status": "repairable",
                "service_state": {
                    "loaded": False,
                    "running": False,
                    "disabled": True,
                },
                "audit": audit,
                "repair": None,
            }
            repair_envelope = {
                **audit_envelope,
                "status": "repaired",
                "repair": result,
            }
            completed = [
                mock.Mock(
                    returncode=0,
                    stdout=json.dumps(audit_envelope),
                    stderr="",
                ),
                mock.Mock(
                    returncode=0,
                    stdout=json.dumps(repair_envelope),
                    stderr="",
                ),
            ]

            with mock.patch(
                "scripts.operator_readiness_certify.subprocess.run",
                side_effect=completed,
            ) as run:
                ready = certifier._repair_delivery_publication_after_handoff(
                    handoff_ready=True,
                )

            self.assertTrue(ready, certifier.results[-1])
            self.assertEqual(run.call_count, 2)
            audit_command = run.call_args_list[0].args[0]
            repair_command = run.call_args_list[1].args[0]
            self.assertIn("context-delivery-integrity", audit_command)
            self.assertNotIn("--repair", audit_command)
            self.assertIn("--repair", repair_command)
            self.assertIn("--confirm", repair_command)
            self.assertEqual(
                repair_command[
                    repair_command.index("--expected-revision") + 1
                ],
                "b" * 64,
            )

            repair = certifier.results[-1]
            self.assertEqual(repair.check_id, "context_delivery_publication_repair")
            self.assertEqual(repair.status, "ready")
            self.assertFalse(repair.required)
            parsed_path = Path(repair.artifact_paths["parsed"])
            parsed_bytes = parsed_path.read_bytes()
            self.assertNotIn(secret_marker.encode("utf-8"), parsed_bytes)
            parsed = json.loads(parsed_bytes)
            self.assertEqual(
                set(parsed),
                {
                    "protocol_version",
                    "status",
                    "operation_id",
                    "audit_revision_before",
                    "audit_revision_after",
                    "repair_required",
                    "reconciled_target_highwater",
                    "repaired_cursor_count",
                    "safety_backup",
                    "maintenance_receipt_verified",
                    "checkpoint",
                    "quick_check",
                    "foreign_key_error_count",
                    "after_status",
                    "verification_passed",
                    "installer_lock_enforced",
                },
            )
            self.assertEqual(
                set(parsed["safety_backup"]),
                {"sha256", "size_bytes", "verified"},
            )
            self.assertTrue(parsed["maintenance_receipt_verified"])
            self.assertEqual(parsed["checkpoint"], [0, 4, 4])
            self.assertEqual(parsed["quick_check"], ["ok"])
            self.assertEqual(parsed["foreign_key_error_count"], 0)
            self.assertEqual(parsed["after_status"], "ready")
            self.assertTrue(parsed["installer_lock_enforced"])

    def test_concurrent_local_lease_blocks_guarded_recovery_without_artifacts(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            certifier, _, core_paths = self._bound_certifier(root)
            certifier.pack_dir.mkdir(parents=True, mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            certifier.metadata = {
                "run_id": certifier.run_id,
                "context_id": certifier.context,
                "agent_id": certifier.agent_id,
                "git": {"head": "unit-test", "status_short": ""},
                "embedding_provider": "semantic-hash",
            }
            certifier.results = [
                CheckResult(
                    check_id="capture_inbox",
                    label="Capture inbox",
                    status="ready",
                    required=True,
                    detail="Phase A was clean.",
                )
            ]
            local_lease = CoreAuthorityLease.acquire_local(core_paths.memory_db)
            try:
                with (
                    mock.patch(
                        "scripts.operator_readiness_certify.AUTHORITY_GUARD_TIMEOUT_SECONDS",
                        0.0,
                    ),
                    mock.patch(
                        "scripts.operator_readiness_certify.VerifiedRecoveryManager"
                    ) as recovery_manager,
                ):
                    result = certifier._guarded_recovery_and_finalize()
            finally:
                local_lease.close()

            by_id = {result.check_id: result for result in certifier.results}
            self.assertEqual(result["overall_status"], "blocked")
            self.assertEqual(by_id["authority_guard"].status, "blocked")
            self.assertEqual(by_id["guarded_quiescence"].status, "blocked")
            for check_id in (
                "capture_ledger_audit",
                "recovery_backup",
                "recovery_verify",
                "recovery_restore",
            ):
                self.assertEqual(by_id[check_id].status, "blocked")
            recovery_manager.assert_not_called()
            self.assertFalse(
                (certifier.artifact_dir / "recovery_verify.parsed.json").exists()
            )
            self.assertFalse(
                (
                    certifier.artifact_dir
                    / "recovery_restore_proof.receipt.json"
                ).exists()
            )

    def test_guarded_manager_uses_no_recovery_subprocess_and_publishes_artifacts(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            certifier, _, core_paths = self._bound_certifier(root)
            certifier.args.zip = True
            certifier.pack_dir.mkdir(parents=True, mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            certifier.metadata = {
                "run_id": certifier.run_id,
                "context_id": certifier.context,
                "agent_id": certifier.agent_id,
                "git": {"head": "unit-test", "status_short": ""},
                "embedding_provider": "semantic-hash",
            }
            certifier.results = [
                CheckResult(
                    check_id="capture_inbox",
                    label="Capture inbox",
                    status="ready",
                    required=True,
                    detail="Phase A was clean.",
                )
            ]
            proof_source = root / "isolated-proof.json"
            proof_source.write_text(
                json.dumps({"verified": True, "mode": "isolated-recovery-proof"}),
                encoding="utf-8",
            )
            evidence = self._guarded_recovery_evidence(
                recovery_proof_path=proof_source
            )
            state = {
                "active": False,
                "exited": False,
                "manifest_existed_on_exit": False,
            }

            class Publication:
                def publish(self, callback):
                    if not state["active"]:
                        raise AssertionError("publication escaped the capture guard")
                    return callback(evidence)

            class Transaction:
                def __enter__(self):
                    state["active"] = True
                    return Publication()

                def __exit__(self, _exc_type, _exc, _traceback):
                    state["manifest_existed_on_exit"] = (
                        certifier.pack_dir / "manifest.json"
                    ).is_file()
                    state["active"] = False
                    state["exited"] = True
                    return False

            manager = mock.Mock()
            manager.guarded_recovery_transaction.return_value = Transaction()
            store = mock.Mock()
            inventory = {
                "inventory_available": True,
                "process_findings": [],
                "process_findings_truncated": False,
                "loaded_categories": [],
                "launch_agents": {},
            }
            with (
                mock.patch(
                    "scripts.operator_readiness_certify.DurableMemoryStore.open_existing_for_core_maintenance",
                    return_value=store,
                ),
                mock.patch(
                    "scripts.operator_readiness_certify.VerifiedRecoveryManager",
                    return_value=manager,
                ),
                mock.patch.object(
                    certifier,
                    "_collect_quiescence_inventory",
                    return_value=(True, inventory),
                ),
                mock.patch.object(
                    certifier,
                    "_run_command",
                    side_effect=AssertionError(
                        "guarded recovery must not use a subprocess"
                    ),
                ),
            ):
                result = certifier._guarded_recovery_and_finalize()

            by_id = {result.check_id: result for result in certifier.results}
            self.assertTrue(state["exited"])
            self.assertFalse(state["manifest_existed_on_exit"])
            self.assertTrue((certifier.pack_dir / "manifest.json").is_file())
            store.close.assert_called_once_with()
            manager.guarded_recovery_transaction.assert_called_once()
            for check_id in (
                "capture_ledger_audit",
                "recovery_backup",
                "recovery_verify",
                "recovery_restore",
            ):
                self.assertEqual(by_id[check_id].status, "ready", check_id)
                self.assertEqual(by_id[check_id].command, [])
            verify_path = Path(by_id["recovery_verify"].artifact_paths["parsed"])
            restore_path = Path(
                by_id["recovery_restore"].artifact_paths["recovery_proof"]
            )
            self.assertEqual(verify_path.parent, certifier.artifact_dir)
            verified_artifact = json.loads(verify_path.read_text())
            self.assertTrue(verified_artifact["verified"])
            self.assertEqual(
                verified_artifact["capture_database_binding"]["auth_key_id"],
                "unit-test-public-key-id",
            )
            self.assertEqual(restore_path.parent, certifier.artifact_dir)
            self.assertTrue(json.loads(restore_path.read_text())["verified"])
            self.assertEqual(restore_path.read_bytes(), proof_source.read_bytes())
            with zipfile.ZipFile(certifier.archive_path) as archive:
                self.assertEqual(
                    archive.read("artifacts/recovery_verify.parsed.json"),
                    verify_path.read_bytes(),
                )
                self.assertEqual(
                    archive.read(
                        "artifacts/recovery_restore_proof.receipt.json"
                    ),
                    proof_source.read_bytes(),
                )
            self.assertEqual(result["overall_status"], "blocked")
            with CoreAuthorityLease.acquire_local(core_paths.memory_db):
                pass

    def test_finalize_failure_releases_authority_and_guard_context(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            certifier, _, core_paths = self._bound_certifier(root)
            certifier.pack_dir.mkdir(parents=True, mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            certifier.results = [
                CheckResult(
                    check_id="capture_inbox",
                    label="Capture inbox",
                    status="ready",
                    required=True,
                    detail="Phase A was clean.",
                )
            ]
            proof_source = root / "isolated-proof.json"
            proof_source.write_text(
                json.dumps({"verified": True, "mode": "isolated-recovery-proof"}),
                encoding="utf-8",
            )
            evidence = self._guarded_recovery_evidence(
                recovery_proof_path=proof_source
            )
            state = {"active": False, "exited": False}

            class Publication:
                def publish(self, callback):
                    return callback(evidence)

            class Transaction:
                def __enter__(self):
                    state["active"] = True
                    return Publication()

                def __exit__(self, _exc_type, _exc, _traceback):
                    state["active"] = False
                    state["exited"] = True
                    return False

            manager = mock.Mock()
            manager.guarded_recovery_transaction.return_value = Transaction()
            store = mock.Mock()
            inventory = {
                "inventory_available": True,
                "process_findings": [],
                "process_findings_truncated": False,
                "loaded_categories": [],
                "launch_agents": {},
            }
            with (
                mock.patch(
                    "scripts.operator_readiness_certify.DurableMemoryStore.open_existing_for_core_maintenance",
                    return_value=store,
                ),
                mock.patch(
                    "scripts.operator_readiness_certify.VerifiedRecoveryManager",
                    return_value=manager,
                ),
                mock.patch.object(
                    certifier,
                    "_collect_quiescence_inventory",
                    return_value=(True, inventory),
                ),
                mock.patch.object(
                    certifier,
                    "_finalize",
                    side_effect=RuntimeError("synthetic finalize failure"),
                ),
                self.assertRaisesRegex(RuntimeError, "synthetic finalize failure"),
            ):
                certifier._guarded_recovery_and_finalize()

            self.assertTrue(state["exited"])
            self.assertFalse(state["active"])
            store.close.assert_called_once_with()
            with CoreAuthorityLease.acquire_local(core_paths.memory_db):
                pass

    def test_signed_recovery_proof_requires_owner_only_source(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            certifier, _, _ = self._bound_certifier(root)
            certifier.pack_dir.mkdir(parents=True, mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            proof_source = root / "isolated-proof.json"
            evidence = self._guarded_recovery_evidence(
                recovery_proof_path=proof_source
            )
            proof_source.chmod(0o644)

            certifier._record_guarded_recovery_evidence(
                evidence,
                duration_ms=1.0,
            )

            by_id = {result.check_id: result for result in certifier.results}
            self.assertEqual(by_id["recovery_restore"].status, "blocked")
            self.assertNotIn(
                "recovery_proof",
                by_id["recovery_restore"].artifact_paths,
            )
            self.assertFalse(
                (
                    certifier.artifact_dir
                    / "recovery_restore_proof.receipt.json"
                ).exists()
            )

            private_parent = root / "private-proof-parent"
            private_parent.mkdir(mode=0o700)
            private_source = private_parent / "proof.receipt.json"
            private_source.write_bytes(b"{}\n")
            private_source.chmod(0o600)
            linked_parent = root / "linked-proof-parent"
            linked_parent.symlink_to(private_parent, target_is_directory=True)
            with self.assertRaises(OSError):
                read_private_regular_bytes(
                    linked_parent / private_source.name,
                    max_bytes=1024,
                )

    def test_signed_recovery_proof_destination_is_no_clobber_and_no_follow(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            certifier, _, _ = self._bound_certifier(root)
            certifier.pack_dir.mkdir(parents=True, mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            payload = {
                "schema": "synapse-s2.recovery-bundle-restore.v2",
                "verified": True,
            }
            source_bytes = (
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            destination = certifier.artifact_dir / "signed.receipt.json"
            destination.write_bytes(b"existing-private-artifact")
            destination.chmod(0o600)

            with self.assertRaises(FileExistsError):
                certifier._write_signed_json_artifact(
                    destination,
                    source_bytes=source_bytes,
                    expected_payload=payload,
                )
            self.assertEqual(destination.read_bytes(), b"existing-private-artifact")

            destination.unlink()
            protected = certifier.artifact_dir / "protected.receipt.json"
            protected.write_bytes(b"protected-private-artifact")
            protected.chmod(0o600)
            destination.symlink_to(protected.name)
            with self.assertRaises(FileExistsError):
                certifier._write_signed_json_artifact(
                    destination,
                    source_bytes=source_bytes,
                    expected_payload=payload,
                )
            self.assertTrue(destination.is_symlink())
            self.assertEqual(protected.read_bytes(), b"protected-private-artifact")

    def test_recovery_recording_never_deletes_preexisting_proof_artifact(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            certifier, _, _ = self._bound_certifier(root)
            certifier.pack_dir.mkdir(parents=True, mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            proof_source = root / "isolated-proof.json"
            evidence = self._guarded_recovery_evidence(
                recovery_proof_path=proof_source
            )
            destination = (
                certifier.artifact_dir
                / "recovery_restore_proof.receipt.json"
            )
            original = b"preexisting-private-proof-artifact"
            destination.write_bytes(original)
            destination.chmod(0o600)

            certifier._record_guarded_recovery_evidence(
                evidence,
                duration_ms=1.0,
            )

            by_id = {result.check_id: result for result in certifier.results}
            self.assertEqual(by_id["recovery_restore"].status, "blocked")
            self.assertEqual(destination.read_bytes(), original)
            self.assertNotIn(
                "recovery_proof",
                by_id["recovery_restore"].artifact_paths,
            )

    def test_exact_copied_real_signed_proof_passes_preflight_signature(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            database = root / "memory.sqlite3"
            store = DurableMemoryStore(database)
            try:
                store.upsert_entry(
                    tag="readiness-signed-copy",
                    context_id="certifier-tests",
                    source_text="Synthetic signed-copy integration proof.",
                    metadata={"fixture": True},
                    embedding_dimensions=8,
                    spike_indices=[1, 3],
                    neuron_indices=[2, 4],
                    registered_at=100.0,
                )
                daemon = CaptureInboxDaemon(root=root)
                daemon._ensure_transport_dirs(daemon.paths())
                manager = VerifiedRecoveryManager(store, capture_root=root)
                bundle = manager.create_bundle(
                    root / "readiness-copy.sqlite3",
                    purpose="readiness-signed-copy-test",
                    pinned=False,
                )
                verified = manager.verify_bundle(bundle["bundle_receipt_path"])
                restored = manager.restore_bundle_isolated(
                    bundle["bundle_receipt_path"],
                    root / "isolated-restore",
                    confirm=True,
                )
            finally:
                store.close()

            source = Path(restored["recovery_proof_path"])
            source_bytes = read_private_regular_bytes(
                source,
                max_bytes=1024 * 1024,
            )
            signed_payload = json.loads(source_bytes.decode("utf-8"))
            self.assertNotEqual(json_safe(signed_payload), signed_payload)

            certifier, _, _ = self._bound_certifier(root / "certifier")
            certifier.pack_dir.mkdir(parents=True, mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            copied = certifier.artifact_dir / "recovery_restore_proof.receipt.json"
            certifier._write_signed_json_artifact(
                copied,
                source_bytes=source_bytes,
                expected_payload=signed_payload,
            )
            certifier._record_in_process_check(
                "recovery_verify",
                label="Recovery bundle verification",
                status="ready",
                detail="Synthetic exact verification copy.",
                repair="",
                parsed=verified,
                metrics={"verified": True},
                duration_ms=1.0,
                preserve_crypto_fields=True,
            )
            verified_copy_path = (
                certifier.artifact_dir / "recovery_verify.parsed.json"
            )
            verified_copy = json.loads(verified_copy_path.read_text())

            self.assertEqual(copied.read_bytes(), source_bytes)
            self.assertEqual(verified_copy, verified)
            self.assertNotEqual(json_safe(verified_copy), verified_copy)
            result = preflight.verify_recovery_binding(
                parsed=verified_copy,
                receipt_path=Path(bundle["bundle_receipt_path"]),
                restore_proof=signed_payload,
                restore_proof_path=copied,
                memory_db=database,
                capture_root=root,
            )
            self.assertTrue(result["isolated_restore_verified"])
            self.assertTrue(result["restore_eligible"])

    def test_guard_exit_failure_never_publishes_authoritative_manifest(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            certifier, _, core_paths = self._bound_certifier(root)
            certifier.pack_dir.mkdir(parents=True, mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            certifier.results = [
                CheckResult(
                    check_id="capture_inbox",
                    label="Capture inbox",
                    status="ready",
                    required=True,
                    detail="Phase A was clean.",
                )
            ]
            proof_source = root / "isolated-proof.json"
            evidence = self._guarded_recovery_evidence(
                recovery_proof_path=proof_source
            )
            state = {"callback": False, "exited": False}

            class Publication:
                def publish(self, callback):
                    state["callback"] = True
                    return callback(evidence)

            class Transaction:
                def __enter__(self):
                    return Publication()

                def __exit__(self, _exc_type, _exc, _traceback):
                    state["exited"] = True
                    raise RuntimeError("synthetic guard exit failure")

            manager = mock.Mock()
            manager.guarded_recovery_transaction.return_value = Transaction()
            store = mock.Mock()
            inventory = {
                "inventory_available": True,
                "process_findings": [],
                "process_findings_truncated": False,
                "loaded_categories": [],
                "quiescence_policy_blockers": [],
                "launch_agents": {},
            }
            with (
                mock.patch(
                    "scripts.operator_readiness_certify.DurableMemoryStore.open_existing_for_core_maintenance",
                    return_value=store,
                ),
                mock.patch(
                    "scripts.operator_readiness_certify.VerifiedRecoveryManager",
                    return_value=manager,
                ),
                mock.patch.object(
                    certifier,
                    "_collect_quiescence_inventory",
                    return_value=(True, inventory),
                ),
                self.assertRaisesRegex(RuntimeError, "synthetic guard exit failure"),
            ):
                certifier._guarded_recovery_and_finalize()

            self.assertTrue(state["callback"])
            self.assertTrue(state["exited"])
            self.assertFalse((certifier.pack_dir / "manifest.json").exists())
            store.close.assert_called_once_with()
            with CoreAuthorityLease.acquire_local(core_paths.memory_db):
                pass

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

    def test_memory_write_retains_primary_commit_when_notification_is_unknown(self):
        with TemporaryDirectory() as tmp:
            certifier, _, _ = self._bound_certifier(Path(tmp))
            payload = {
                "tag": "operator-readiness-memory-write",
                "memory_id": "s2_" + ("3" * 32),
                "spike_count": 7,
                "persisted": True,
                "agent_deployment": {
                    "published": None,
                    "state": "outcome_unknown",
                    "replay_safe": False,
                    "reconciliation": {
                        "code": "outcome_unknown",
                        "caller": "certifier-cli",
                        "request_id": "req-certifier-publish",
                        "operation": "publish_context_event",
                        "replay_safe": False,
                    },
                },
            }

            def run_command(
                check_id,
                *,
                label,
                command,
                required,
                timeout,
                evaluator,
                env=None,
            ):
                del timeout, env
                status, detail, repair, metrics = evaluator(
                    0,
                    payload,
                    json.dumps(payload),
                    "",
                )
                result = CheckResult(
                    check_id=check_id,
                    label=label,
                    status=status,
                    required=required,
                    detail=detail,
                    repair=repair,
                    command=command,
                    returncode=0,
                    parsed=payload,
                    metrics=metrics,
                )
                certifier.results.append(result)
                return result

            with mock.patch.object(
                certifier,
                "_run_command",
                side_effect=run_command,
            ):
                memory = certifier._check_memory_write()

        result = certifier.results[-1]
        self.assertEqual(result.status, "ready")
        self.assertEqual(memory["memory_id"], payload["memory_id"])
        self.assertFalse(result.metrics["deployment_published"])
        self.assertEqual(result.metrics["deployment_state"], "outcome_unknown")
        self.assertIn("explicitly unresolved", result.detail)

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

    def test_successful_app_support_checks_preserve_exact_required_contract(self):
        with TemporaryDirectory() as tmp:
            certifier, _, _ = self._bound_certifier(
                Path(tmp),
                run_id="app-support-proof-contract",
            )
            certifier.pack_dir.mkdir(parents=True, mode=0o700)
            certifier.artifact_dir.mkdir(mode=0o700)
            certifier.metadata = {
                "run_id": certifier.run_id,
                "context_id": certifier.context,
                "agent_id": certifier.agent_id,
                "git": {"head": "unit-test", "status_short": ""},
                "embedding_provider": "semantic-hash",
            }
            certifier.results = [
                result
                for result in self._required_ready_results()
                if result.check_id != "app_preview"
            ]
            parsed_by_check = {
                "app_list": {
                    "apps": [
                        {
                            "app_name": "Codex",
                            "bundle_id": "com.openai.codex",
                            "pid": 123,
                        }
                    ]
                },
                "app_connect": {
                    "app_name": "Codex",
                    "connection_id": "app-support-unit-test",
                },
                "app_preview": {
                    "action": "preview-app-snapshot",
                    "app_name": "Codex",
                    "writes_memory": False,
                    "snapshot_quality": {"signal_chars": 128},
                    "quality_badge": {"status": "ready"},
                    "capability_badge": {"level": "rich_text_available"},
                    "capture_guidance": [],
                },
            }

            def run_command(
                check_id,
                *,
                label,
                command,
                required,
                timeout,
                evaluator,
                env=None,
            ):
                del timeout, env
                status, detail, repair, metrics = evaluator(
                    0,
                    parsed_by_check[check_id],
                    "",
                    "",
                )
                result = CheckResult(
                    check_id=check_id,
                    label=label,
                    status=status,
                    required=required,
                    detail=detail,
                    repair=repair,
                    command=command,
                    returncode=0,
                    metrics=metrics,
                )
                certifier.results.append(result)
                return result

            with mock.patch.object(certifier, "_run_command", side_effect=run_command):
                certifier._check_app_preview()

            by_id = {result.check_id: result for result in certifier.results}
            self.assertFalse(by_id["app_list"].required)
            self.assertFalse(by_id["app_connect"].required)
            self.assertTrue(by_id["app_preview"].required)

            result = certifier._finalize()
            manifest = json.loads(
                Path(result["manifest_path"]).read_text(encoding="utf-8")
            )

            self.assertEqual(result["overall_status"], "ready")
            self.assertTrue(result["operator_trustworthy"])
            self.assertEqual(result["required_ready"], len(REQUIRED_PROOFS))
            self.assertEqual(result["required_total"], len(REQUIRED_PROOFS))
            self.assertEqual(result["failed_required"], [])
            self.assertTrue(manifest["required_proof_contract"]["valid"])
            self.assertEqual(
                manifest["required_proof_contract"].get(
                    "unexpected_required",
                    [],
                ),
                [],
            )

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

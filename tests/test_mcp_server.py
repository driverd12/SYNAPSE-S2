import contextlib
import ast
import io
import inspect
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

import mlx_backend
import mcp_server
from capture_daemon import CaptureInboxDaemon


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
        os.environ["SYNAPSE_S2_EXPORT_DIR"] = self.tmpdir.name
        os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = str(Path(self.tmpdir.name) / "capture-root")
        os.environ["SYNAPSE_S2_CLIENT_AGENT_ID"] = "codex-desktop"
        self.addCleanup(self._restore_export_dir)
        self.addCleanup(self._restore_capture_root)
        self.addCleanup(self._restore_client_agent_id)

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

    def test_namespace_map_requires_confirmation_before_linking(self):
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
        listing = json.loads(mcp_server.list_spiking_memory(context_id="demo", limit=5))
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

        listing = json.loads(mcp_server.list_spiking_memory(context_id="demo", limit=5))
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
        CaptureInboxDaemon(root=self.tmpdir.name).status()
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
        CaptureInboxDaemon(root=capture_root).status()
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

        listing = json.loads(
            mcp_server.list_spiking_memory(
                context_id="demo",
                limit=5,
                include_vectors=True,
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
        graph = json.loads(mcp_server.list_spiking_memory_graph(context_id="demo"))

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
        graph = json.loads(mcp_server.list_spiking_memory_graph(context_id="demo"))
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
        graph = json.loads(mcp_server.list_spiking_memory_graph(context_id="demo"))
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
        graph = json.loads(mcp_server.list_spiking_memory_graph(context_id="demo"))

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
        graph = json.loads(mcp_server.list_spiking_memory_graph(context_id="demo"))

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

        first = json.loads(
            mcp_server.hydrate_spiking_agent_context(
                agent_id="codex-desktop",
                context_id="demo",
                prompt="deployment context",
            )
        )
        ack = json.loads(
            mcp_server.ack_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
                receipt_id=first["deliveries"][0]["receipt_id"],
            )
        )
        second = json.loads(
            mcp_server.hydrate_spiking_agent_context(
                agent_id="codex-desktop",
                context_id="demo",
                prompt="deployment context",
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
        state = json.loads(
            mcp_server.get_spiking_cortex_state(
                agent_id="mcp-agent",
                context_id="demo",
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
        closed_state = json.loads(
            mcp_server.get_spiking_cortex_state(
                agent_id="mcp-agent",
                context_id="demo",
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
        state = json.loads(mcp_server.get_spiking_cortex_state(context_id="demo"))

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
            hydration = json.loads(
                mcp_server.hydrate_spiking_agent_context(
                    agent_id="codex-desktop",
                    context_id="demo",
                )
            )
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

        self.assertIn("error", hydration)
        self.assertIn("SYNAPSE_S2_CLIENT_AGENT_ID", hydration["error"])
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

import errno
import json
import hashlib
import os
import sqlite3
import threading
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
import time
import subprocess
from contextlib import closing
from typing import Any
from unittest.mock import patch

import mlx.core as mx

import embedding_providers
import mlx_backend
from core_authority import CoreAuthorityError, CoreAuthorityLease
from core_protocol import DEFAULT_MAX_FRAME_BYTES, canonical_json_bytes
from memory_store import ContextDeliveryRejected
from mlx_backend import BackendUnavailable
from mlx_backend import SpikingAttentionBackend


class SpikingAttentionBackendTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.state_path = Path(self.tmpdir.name) / "state.json"

    def test_neural_resource_envelope_precedes_constructor_allocation(self):
        with patch.object(
            mlx_backend,
            "_require_mx",
            side_effect=AssertionError("MLX must not be reached"),
        ) as require_mx:
            with self.assertRaisesRegex(ValueError, "384 MiB resource envelope"):
                SpikingAttentionBackend(
                    dimension=10_000,
                    num_neurons=8_192,
                    compile_graph=False,
                    state_path=self.state_path,
                )
        require_mx.assert_not_called()

    def test_execution_context_binds_the_thread_local_mlx_stream(self):
        entered: list[object] = []
        exited: list[object] = []
        stream_token = object()

        class Scope:
            def __enter__(self):
                entered.append(stream_token)

            def __exit__(self, exc_type, exc, traceback):
                exited.append(stream_token)

        class StreamAPI:
            def stream(self, selected_stream):
                self.asserted_stream = selected_stream
                return Scope()

        backend = object.__new__(SpikingAttentionBackend)
        backend._mx = StreamAPI()
        backend._execution_stream = stream_token

        with backend.execution_context():
            self.assertEqual(entered, [stream_token])
            self.assertEqual(exited, [])

        self.assertIs(backend._mx.asserted_stream, stream_token)
        self.assertEqual(exited, [stream_token])

    def test_persistent_neural_state_crosses_constructor_worker_boundary(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            quick_pruning_interval_seconds=0.0,
            state_path=self.state_path,
        )
        failures: list[BaseException] = []
        result: dict[str, Any] = {}

        def register_from_worker() -> None:
            try:
                with backend.execution_context():
                    result.update(
                        backend.register_text_trace(
                            tag="worker-thread-trace",
                            text="Worker-thread MLX state materialization proof.",
                            context_id="thread-proof",
                        )
                    )
            except BaseException as exc:  # pragma: no cover - asserted below
                failures.append(exc)

        with patch.object(mlx_backend.LOGGER, "warning") as warning:
            worker = threading.Thread(target=register_from_worker)
            worker.start()
            worker.join(timeout=10.0)

        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(result.get("memory_id"))
        self.assertIsNotNone(backend.memory_store.get_entry(result["memory_id"]))
        self.assertFalse(
            any(
                "mx.eval failed" in str(call.args[0])
                for call in warning.call_args_list
                if call.args
            )
        )

    def test_namespace_connectivity_excludes_inbound_directed_recall(self):
        backend = SpikingAttentionBackend(
            dimension=16,
            num_neurons=12,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            quick_pruning_interval_seconds=0.0,
            state_path=self.state_path,
        )
        backend.approve_namespace_link(
            source_context_id="upstream",
            target_context_id="downstream",
            relation_type="related",
            direction="directed",
            approved_by="test-operator",
            confirm=True,
        )

        connectivity = backend._agent_namespace_connectivity(context="downstream")

        self.assertEqual(connectivity["active_bridge_records_returned"], 0)
        self.assertEqual(connectivity["incident_bridge_records_returned"], 1)
        self.assertEqual(
            connectivity["inbound_only_bridge_records_returned"], 1
        )
        self.assertFalse(connectivity["bridge_records_truncated"])
        self.assertEqual(connectivity["connected_context_ids"], [])

    def test_namespace_connectivity_ignores_ungoverned_legacy_links(self):
        backend = SpikingAttentionBackend(
            dimension=16,
            num_neurons=12,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            quick_pruning_interval_seconds=0.0,
            state_path=self.state_path,
        )
        backend.memory_store.upsert_context_link(
            source_context_id="legacy-a",
            target_context_id="legacy-b",
            relation_type="related",
            approved_by="legacy-test",
        )

        connectivity = backend._agent_namespace_connectivity(context="legacy-a")
        resolved = backend.resolve_recall_contexts(
            context_id="legacy-a",
            recall_scope="connected",
        )

        self.assertEqual(connectivity["active_bridge_records_returned"], 0)
        self.assertEqual(connectivity["incident_bridge_records_returned"], 0)
        self.assertEqual(connectivity["connected_context_ids"], [])
        self.assertEqual(
            [record["context_id"] for record in resolved],
            ["legacy-a", "global"],
        )

    def test_oversized_embedding_is_rejected_before_materialization_or_resize(self):
        class OversizedEmbeddingProbe:
            shape = (10_000,)

            def __iter__(self):
                raise AssertionError("probe must not be materialized")

        class RejectingArrayAPI:
            float32 = object()

            def __init__(self) -> None:
                self.array_calls = 0

            def array(self, _value, *, dtype):
                self.array_calls += 1
                raise AssertionError(f"unexpected materialization as {dtype}")

        backend = object.__new__(SpikingAttentionBackend)
        backend.dimension = 1_024
        backend.num_neurons = 8_192
        backend.W_syn = object()
        backend.W_syn_decay_multiplier = 0.5
        backend._mx = RejectingArrayAPI()
        original_projection = backend.W_syn

        with self.assertRaisesRegex(ValueError, "384 MiB resource envelope"):
            backend._coerce_embedding(OversizedEmbeddingProbe())
        self.assertEqual(backend._mx.array_calls, 0)

        with patch.object(
            backend,
            "_balanced_matrix",
            side_effect=AssertionError("projection allocation must not run"),
        ) as allocate:
            with self.assertRaisesRegex(ValueError, "384 MiB resource envelope"):
                backend._ensure_projection_shape(10_000)
        allocate.assert_not_called()
        self.assertEqual(backend.dimension, 1_024)
        self.assertIs(backend.W_syn, original_projection)
        self.assertEqual(backend.W_syn_decay_multiplier, 0.5)

    def test_in_budget_projection_resize_preserves_configurable_topology(self):
        backend = object.__new__(SpikingAttentionBackend)
        backend.dimension = 8
        backend.num_neurons = 16
        backend.W_syn = object()
        backend.W_syn_decay_multiplier = 0.5
        resized_projection = object()

        with patch.object(
            backend,
            "_balanced_matrix",
            return_value=resized_projection,
        ) as allocate:
            backend._ensure_projection_shape(12)

        allocate.assert_called_once_with(
            (12, 16),
            scale=0.01,
            excitatory_ratio=0.8,
        )
        self.assertEqual(backend.dimension, 12)
        self.assertIs(backend.W_syn, resized_projection)
        self.assertEqual(backend.W_syn_decay_multiplier, 1.0)

    def test_private_json_writer_preserves_existing_parent_mode(self):
        parent = Path(self.tmpdir.name) / "caller-owned"
        parent.mkdir(mode=0o755)
        parent.chmod(0o755)
        target = parent / "private.json"

        mlx_backend._atomic_write_private_json(target, {"safe": True})

        self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_private_json_writer_secures_only_directories_it_creates(self):
        existing = Path(self.tmpdir.name) / "existing"
        existing.mkdir(mode=0o755)
        existing.chmod(0o755)
        target = existing / "created" / "nested" / "private.json"

        mlx_backend._atomic_write_private_json(target, {"safe": True})

        self.assertEqual(existing.stat().st_mode & 0o777, 0o755)
        self.assertEqual(target.parent.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_runtime_state_lock_rejects_unsafe_existing_identity_without_repair(self):
        root = Path(self.tmpdir.name)

        wrong_mode_state = root / "wrong-mode.json"
        wrong_mode_lock = root / ".wrong-mode.json.lock"
        wrong_mode_lock.write_text("preserve", encoding="utf-8")
        wrong_mode_lock.chmod(0o644)
        wrong_mode_inode = wrong_mode_lock.stat().st_ino
        with self.assertRaisesRegex(RuntimeError, "identity is unsafe"):
            with mlx_backend._exclusive_runtime_state_lock(wrong_mode_state):
                self.fail("unsafe lock must not be acquired")
        self.assertEqual(wrong_mode_lock.read_text(encoding="utf-8"), "preserve")
        self.assertEqual(wrong_mode_lock.stat().st_ino, wrong_mode_inode)
        self.assertEqual(wrong_mode_lock.stat().st_mode & 0o777, 0o644)

        hardlink_state = root / "hardlink.json"
        hardlink_target = root / "hardlink-target"
        hardlink_target.write_text("preserve", encoding="utf-8")
        hardlink_target.chmod(0o600)
        hardlink_lock = root / ".hardlink.json.lock"
        os.link(hardlink_target, hardlink_lock)
        with self.assertRaisesRegex(RuntimeError, "identity is unsafe"):
            with mlx_backend._exclusive_runtime_state_lock(hardlink_state):
                self.fail("hard-linked lock must not be acquired")
        self.assertEqual(hardlink_target.read_text(encoding="utf-8"), "preserve")
        self.assertEqual(hardlink_target.stat().st_nlink, 2)

        symlink_state = root / "symlink-lock.json"
        symlink_target = root / "symlink-lock-target"
        symlink_target.write_text("preserve", encoding="utf-8")
        symlink_target.chmod(0o600)
        (root / ".symlink-lock.json.lock").symlink_to(symlink_target)
        with self.assertRaises(OSError):
            with mlx_backend._exclusive_runtime_state_lock(symlink_state):
                self.fail("symlink lock must not be acquired")
        self.assertEqual(symlink_target.read_text(encoding="utf-8"), "preserve")

    @staticmethod
    def _logical_database_dump(path: Path) -> str:
        connection = sqlite3.connect(path)
        try:
            return "\n".join(connection.iterdump())
        finally:
            connection.close()

    def test_core_preclaim_bootstrap_observes_canonical_state_without_writes(self):
        memory_path = Path(self.tmpdir.name) / "memory.sqlite3"
        local = SpikingAttentionBackend(
            dimension=16,
            num_neurons=12,
            compile_graph=False,
            state_path=self.state_path,
            memory_path=memory_path,
        )
        local._persist_runtime_state()
        local.memory_store.close()
        state_before = self.state_path.read_bytes()
        state_inode = self.state_path.stat().st_ino
        database_before = self._logical_database_dump(memory_path)

        lease = CoreAuthorityLease.acquire_core(
            memory_path,
            timeout_seconds=0.0,
            instance_id="core-observation-test",
        )
        try:
            core_backend = SpikingAttentionBackend(
                dimension=16,
                num_neurons=12,
                compile_graph=False,
                state_path=self.state_path,
                memory_path=memory_path,
                authority_lease=lease,
            )
            self.assertTrue(core_backend._core_preclaim_bootstrap)
        finally:
            lease.close()

        self.assertEqual(self.state_path.read_bytes(), state_before)
        self.assertEqual(self.state_path.stat().st_ino, state_inode)
        self.assertEqual(self._logical_database_dump(memory_path), database_before)

    def test_core_preclaim_rejects_legacy_trace_migration_without_writing(self):
        memory_path = Path(self.tmpdir.name) / "memory.sqlite3"
        local = SpikingAttentionBackend(
            dimension=16,
            num_neurons=12,
            compile_graph=False,
            state_path=self.state_path,
            memory_path=memory_path,
        )
        local.memory_store.close()
        legacy_payload = {
            "version": 1,
            "global_enabled": True,
            "context_overrides": {},
            "cortex_sessions": {},
            "registered_traces": [
                {
                    "tag": "must-not-migrate",
                    "context_id": "default",
                    "source_text": "legacy trace",
                    "metadata": {},
                    "embedding_dimensions": 16,
                    "spike_indices": [0],
                    "neuron_indices": [0],
                    "registered_at": 123.0,
                }
            ],
        }
        self.state_path.write_text(
            json.dumps(legacy_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.state_path.chmod(0o600)
        state_before = self.state_path.read_bytes()
        state_inode = self.state_path.stat().st_ino
        database_before = self._logical_database_dump(memory_path)

        lease = CoreAuthorityLease.acquire_core(
            memory_path,
            timeout_seconds=0.0,
            instance_id="core-legacy-rejection-test",
        )
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                "requires canonical runtime state",
            ):
                SpikingAttentionBackend(
                    dimension=16,
                    num_neurons=12,
                    compile_graph=False,
                    state_path=self.state_path,
                    memory_path=memory_path,
                    authority_lease=lease,
                )
        finally:
            lease.close()

        self.assertEqual(self.state_path.read_bytes(), state_before)
        self.assertEqual(self.state_path.stat().st_ino, state_inode)
        self.assertEqual(self._logical_database_dump(memory_path), database_before)

    def test_runtime_state_path_rejects_credentials_before_file_or_lock_creation(self):
        marker = "SYNTHETIC_ONLY_RUNTIME_PATH_SECRET_42"
        secret_path = (
            Path(self.tmpdir.name)
            / f"password={marker}"
            / "runtime_state.json"
        )

        with self.assertRaises(ValueError) as explicit_error:
            SpikingAttentionBackend(
                dimension=4,
                num_neurons=6,
                compile_graph=False,
                state_path=secret_path,
            )
        self.assertNotIn(marker, str(explicit_error.exception))
        self.assertIn("credential material", str(explicit_error.exception))
        self.assertFalse(secret_path.parent.exists())

        with patch.dict(
            mlx_backend.os.environ,
            {"SYNAPSE_S2_STATE_PATH": str(secret_path)},
            clear=False,
        ):
            with self.assertRaises(ValueError) as env_error:
                SpikingAttentionBackend(
                    dimension=4,
                    num_neurons=6,
                    compile_graph=False,
                )
        self.assertNotIn(marker, str(env_error.exception))
        self.assertIn("credential material", str(env_error.exception))
        self.assertFalse(secret_path.parent.exists())

    def _capture_storage_counts(self, backend):
        with closing(sqlite3.connect(backend.memory_store.db_path)) as conn:
            return tuple(
                int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in (
                    "memory_entries",
                    "memory_events",
                    "memory_relationships",
                    "agent_context_events",
                    "capture_operations",
                )
            )

    def test_encode_to_spikes_top_k_selects_standardized_top_coordinates(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=8,
            default_top_k=2,
            compile_graph=False,
            state_path=self.state_path,
        )

        spikes = backend.encode_to_spikes_top_k(mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]))

        self.assertEqual(spikes.tolist(), [0.0, 0.0, 1.0, 0.0, 1.0, 0.0])

    def test_encode_to_spikes_top_k_keeps_tied_sparse_vectors_bounded(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=8,
            default_top_k=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        spikes = backend.encode_to_spikes_top_k(mx.array([0.0] * 8))

        self.assertEqual(sum(spikes.tolist()), 3.0)

    def test_query_without_registered_memory_reports_raw_activation_not_fake_tags(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        result = backend.query(mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]), context_id="demo")

        self.assertIn("No registered historical context matched", result)
        self.assertIn("raw_activation_top_neurons=", result)
        self.assertNotIn("demo::neuron-", result)
        self.assertEqual(len(backend.memory_mapping), 0)

    def test_register_trace_returns_named_tag_from_query(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        registration = backend.register_trace(
            tag="wing-load-analysis",
            embedding=mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
            context_id="demo",
            metadata={"source": "unit-test"},
        )
        result = backend.query(
            mx.array([0.0, 1.0, 8.9, 2.1, 6.8, -4.0]),
            context_id="demo",
        )

        self.assertEqual(registration["tag"], "wing-load-analysis")
        self.assertIn("wing-load-analysis", result)
        self.assertNotIn("demo::neuron-", result)

    def test_lowest_trace_boundary_redacts_source_and_metadata(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )
        marker = "SYNTHETIC_ONLY_SECRET_VALUE_42"

        backend.register_trace(
            tag="vector-memory",
            embedding=mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
            context_id="demo",
            source_text=f"password={marker}",
            metadata={
                "apiKey": marker,
                "authorization_header": marker,
                "api_key_value": marker,
                "password_hint": marker,
                "safe": "preserved",
            },
        )
        entry = backend.list_memory(context_id="demo")["entries"][0]
        rendered = json.dumps(entry, sort_keys=True)

        self.assertNotIn(marker, rendered)
        self.assertIn("[REDACTED_SECRET]", entry["source_text"])
        self.assertEqual(entry["metadata"]["apiKey"], "[REDACTED_SECRET]")
        self.assertEqual(
            entry["metadata"]["authorization_header"],
            "[REDACTED_SECRET]",
        )
        self.assertEqual(entry["metadata"]["api_key_value"], "[REDACTED_SECRET]")
        self.assertEqual(entry["metadata"]["password_hint"], "[REDACTED_SECRET]")
        self.assertEqual(entry["metadata"]["safe"], "preserved")
        self.assertEqual(self.state_path.stat().st_mode & 0o777, 0o600)

    def test_embedding_and_event_segmentation_never_receive_raw_secrets(self):
        backend = SpikingAttentionBackend(
            dimension=16,
            num_neurons=12,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        marker = "SYNTHETIC_ONLY_SECRET_VALUE_42"
        observed_provider_text: list[str] = []
        original_embed = backend.embedding_provider.embed

        def recording_embed(text, *, dimensions):
            observed_provider_text.append(text)
            return original_embed(text, dimensions=dimensions)

        with patch.object(backend.embedding_provider, "embed", side_effect=recording_embed):
            payload = backend.embed_text_payload(f"api_key={marker}")

        with patch.object(
            mlx_backend.BayesianSurpriseEventSegmenter,
            "segment",
            autospec=True,
            return_value=[],
        ) as segment:
            backend.ingest_text_events(
                text=f"Event: provider boundary password={marker}",
                context_id="demo",
                source_tag="secret-boundary",
            )

        segment_text = segment.call_args.args[1]
        self.assertTrue(observed_provider_text)
        self.assertNotIn(marker, observed_provider_text[0])
        self.assertNotIn(marker, segment_text)
        self.assertGreaterEqual(payload["input_redaction_count"], 1)
        self.assertFalse(payload["raw_input_stored"])

    def test_secret_bearing_durable_identifiers_are_rejected(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=8,
            compile_graph=False,
            state_path=self.state_path,
        )
        marker = "SYNTHETIC_ONLY_SECRET_VALUE_42"

        with self.assertRaisesRegex(ValueError, "credential material"):
            backend.register_text_trace(
                tag=f"api_key={marker}",
                text="safe text",
                context_id="demo",
            )
        with self.assertRaisesRegex(ValueError, "credential material"):
            backend.capture_conversation(
                text="safe text",
                context_id="demo",
                source_tag="capture",
                speaker=f"token={marker}",
            )

    def test_namespace_map_suggestions_require_explicit_link_approval(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=16,
            default_top_k=2,
            recall_count=5,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.register_trace(
            tag="casp-camera-network",
            embedding=mx.array([9.0, 8.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]),
            context_id="CASP-Control-Room",
            source_text="PTZ camera presets share the control room network.",
            metadata={"semantic_facets": ["ptz camera", "control room network"]},
        )
        backend.register_trace(
            tag="ptz-camera-presets",
            embedding=mx.array([8.8, 8.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]),
            context_id="PTZ-Camera-Work",
            source_text="PTZ camera network presets and framing.",
            metadata={"semantic_facets": ["ptz camera", "network presets"]},
        )
        backend.register_trace(
            tag="supplier-budget",
            embedding=mx.array([0.0, 0.0, 0.0, 0.0, 9.0, 8.0, 0.0, 0.0]),
            context_id="Procurement",
            source_text="Supplier renewal budget and contract risk.",
        )

        suggestions = backend.suggest_namespace_links(min_score=0.01)
        map_before = backend.list_namespace_map(
            context_id="CASP-Control-Room",
            min_suggestion_score=0.01,
        )
        lightweight_map = backend.list_namespace_map(
            context_id="CASP-Control-Room",
            include_suggestions=False,
            include_density_metrics=False,
        )
        with self.assertRaisesRegex(ValueError, "confirm=true"):
            backend.approve_namespace_link(
                source_context_id="CASP-Control-Room",
                target_context_id="PTZ-Camera-Work",
                relation_type="shares_network",
            )
        approval = backend.approve_namespace_link(
            source_context_id="CASP-Control-Room",
            target_context_id="PTZ-Camera-Work",
            relation_type="shares_network",
            weight=0.93,
            evidence={"reason": "operator-verified shared control-room network"},
            confirm=True,
        )
        map_after = backend.list_namespace_map(
            context_id="CASP-Control-Room",
            min_suggestion_score=0.01,
        )

        self.assertGreaterEqual(suggestions["suggestion_count"], 1)
        self.assertTrue(suggestions["read_only"])
        self.assertEqual(
            suggestions["method"],
            "density-normalized-dice-plus-containment-v2",
        )
        self.assertFalse(lightweight_map["density_metrics_included"])
        self.assertEqual(lightweight_map["suggestions"], [])
        self.assertTrue(
            all("surface_term_count" not in node for node in lightweight_map["nodes"])
        )
        self.assertEqual(map_before["link_count"], 0)
        self.assertEqual(map_before["node_count"], 3)
        self.assertEqual(map_after["link_count"], 1)
        self.assertEqual(map_after["default_recall_scope"], "local")
        self.assertEqual(map_after["connected_scope_hops"], 1)
        self.assertFalse(map_after["automatic_cross_namespace_write"])
        link = approval["link"]
        self.assertEqual(link["direction"], "bidirectional")
        self.assertEqual(link["weight"], 0.93)
        self.assertGreater(link["dice_score"], 0.0)
        self.assertEqual(link["delay_semantics"], "visualization-only")
        self.assertIn("suggested_phase_delay_ticks", link)
        selected_node = next(node for node in map_after["nodes"] if node["selected"])
        self.assertIn("PTZ-Camera-Work", selected_node["connected_context_ids"])

        backend.approve_namespace_link(
            source_context_id="Procurement",
            target_context_id="CASP-Control-Room",
            relation_type="feeds",
            direction="directed",
            confirm=True,
        )
        procurement_map = backend.list_namespace_map(context_id="Procurement")
        casp_map = backend.list_namespace_map(context_id="CASP-Control-Room")
        procurement_node = next(
            node for node in procurement_map["nodes"] if node["selected"]
        )
        casp_node = next(node for node in casp_map["nodes"] if node["selected"])
        self.assertIn("CASP-Control-Room", procurement_node["connected_context_ids"])
        self.assertNotIn("Procurement", casp_node["connected_context_ids"])
        self.assertTrue(
            next(
                node
                for node in procurement_map["nodes"]
                if node["context_id"] == "CASP-Control-Room"
            )["connected_to_selected"]
        )
        self.assertFalse(
            next(
                node
                for node in casp_map["nodes"]
                if node["context_id"] == "Procurement"
            )["connected_to_selected"]
        )

    def test_compat_approval_replay_after_revoke_reports_inactive(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=16,
            default_top_k=2,
            recall_count=5,
            compile_graph=False,
            state_path=self.state_path,
        )
        approved = backend.approve_namespace_link(
            source_context_id="alpha",
            target_context_id="beta",
            relation_type="related",
            confirm=True,
        )
        revoked = backend.revoke_namespace_link(
            context_link_id=approved["link"]["context_link_id"],
            expected_revision=approved["proposal"]["revision"],
            revoked_by="operator",
            reason="The compatibility bridge is retired.",
            confirm=True,
        )
        replay = backend.approve_namespace_link(
            source_context_id="alpha",
            target_context_id="beta",
            relation_type="related",
            confirm=True,
        )

        self.assertEqual(revoked["state"], "revoked")
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["governance_state"], "revoked")
        self.assertFalse(replay["approved"])
        self.assertFalse(replay["authorization_active"])
        self.assertFalse(replay["link"]["enabled"])

    def test_query_recall_scope_is_local_then_approved_one_hop_then_all(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=16,
            default_top_k=2,
            recall_count=5,
            compile_graph=False,
            state_path=self.state_path,
        )
        alpha_vector = mx.array([0.0, 0.0, 0.0, 0.0, 9.0, 8.0, 0.0, 0.0])
        beta_vector = mx.array([9.0, 8.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
        gamma_vector = mx.array([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 9.0, 8.0])
        backend.register_trace(
            tag="alpha-local",
            embedding=alpha_vector,
            context_id="alpha",
            source_text="Alpha local memory.",
        )
        backend.register_trace(
            tag="beta-connected",
            embedding=beta_vector,
            context_id="beta",
            source_text="Beta connected camera memory.",
        )
        backend.register_trace(
            tag="gamma-two-hops",
            embedding=gamma_vector,
            context_id="gamma",
            source_text="Gamma remote camera memory.",
        )

        local_result = backend.query(beta_vector, context_id="alpha")
        backend.approve_namespace_link(
            source_context_id="alpha",
            target_context_id="beta",
            relation_type="related",
            confirm=True,
        )
        backend.approve_namespace_link(
            source_context_id="beta",
            target_context_id="gamma",
            relation_type="related",
            confirm=True,
        )
        connected_result = backend.query(
            beta_vector,
            context_id="alpha",
            recall_scope="connected",
        )
        two_hop_result = backend.query(
            gamma_vector,
            context_id="alpha",
            recall_scope="connected",
        )
        all_result = backend.query(
            gamma_vector,
            context_id="alpha",
            recall_scope="all",
        )
        connected_memory = backend.list_memory(
            context_id="alpha",
            recall_scope="connected",
        )

        self.assertNotIn("beta-connected", local_result)
        self.assertIn("beta-connected", connected_result)
        self.assertIn("scope=connected", connected_result)
        self.assertIn("provenance=connected", connected_result)
        self.assertNotIn("gamma-two-hops", two_hop_result)
        self.assertIn("gamma-two-hops", all_result)
        self.assertIn("scope=all", all_result)
        self.assertIn("provenance=all", all_result)
        self.assertEqual(
            {entry["context_id"] for entry in connected_memory["entries"]},
            {"alpha", "beta"},
        )
        beta_entry = next(
            entry
            for entry in connected_memory["entries"]
            if entry["context_id"] == "beta"
        )
        self.assertEqual(beta_entry["recall_provenance"], "connected")
        self.assertTrue(beta_entry["via_context_link_id"])

    def test_local_recall_ignores_legacy_cross_context_memory_relationship(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=16,
            default_top_k=2,
            recall_count=1,
            compile_graph=False,
            state_path=self.state_path,
        )
        alpha_vector = mx.array([9.0, 8.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
        beta_vector = mx.array([0.0, 0.0, 9.0, 8.0, 0.0, 0.0, 0.0, 0.0])
        alpha = backend.register_trace(
            tag="alpha-local",
            embedding=alpha_vector,
            context_id="alpha",
            source_text="Alpha local memory.",
        )
        beta = backend.register_trace(
            tag="beta-isolated",
            embedding=beta_vector,
            context_id="beta",
            source_text="Beta must remain isolated.",
        )
        # Legacy databases can contain relationship rows whose endpoint belongs
        # to another context. Local recall must not follow such an edge.
        with closing(sqlite3.connect(backend.memory_store.db_path)) as connection:
            connection.execute(
                """
                INSERT INTO memory_relationships (
                    relationship_id, context_id, source_memory_id, target_memory_id,
                    relation_type, weight, evidence_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "legacy-cross-context",
                    "alpha",
                    alpha["memory_id"],
                    beta["memory_id"],
                    "legacy",
                    0.9,
                    "{}",
                    12.0,
                    12.0,
                ),
            )
            connection.commit()

        local_result = backend.query(
            alpha_vector,
            context_id="alpha",
            recall_scope="local",
        )

        self.assertIn("alpha-local", local_result)
        self.assertNotIn("beta-isolated", local_result)

    def test_registered_trace_persists_to_state_file(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "synapse-state.json"
            memory_path = Path(tmp) / "synapse-memory.sqlite3"
            backend = SpikingAttentionBackend(
                dimension=6,
                num_neurons=10,
                default_top_k=2,
                recall_count=3,
                compile_graph=False,
                state_path=state_path,
                memory_path=memory_path,
            )
            backend.register_trace(
                tag="procurement-memory",
                embedding=mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
                context_id="ops",
                metadata={"ticket": "S2"},
                source_text="Procurement memory should survive backend restarts.",
            )

            restored = SpikingAttentionBackend(
                dimension=6,
                num_neurons=10,
                default_top_k=2,
                recall_count=3,
                compile_graph=False,
                state_path=state_path,
                memory_path=memory_path,
            )
            result = restored.query(
                mx.array([0.0, 1.0, 8.8, 2.0, 6.9, -4.1]),
                context_id="ops",
            )
            memory = restored.list_memory(context_id="ops")

        self.assertIn("procurement-memory", result)
        self.assertEqual(memory["entries"][0]["source_text"], "Procurement memory should survive backend restarts.")
        self.assertEqual(memory["entries"][0]["metadata"], {"ticket": "S2"})
        self.assertEqual(memory["memory_db_path"], str(memory_path))

    def test_ingest_text_events_segments_persists_and_links_memory_graph(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        text = (
            "Apple Silicon MLX compiles spiking neural kernels into Metal. "
            "The local SNN tracks sparse top-k spike populations for recall. "
            "Procurement then reviews supplier budget exposure and contract risk. "
            "Finance needs renewal timing, approval owners, and payment status."
        )

        ingestion = backend.ingest_text_events(
            text=text,
            context_id="board-demo",
            source_tag="morning-brief",
            surprise_threshold=0.58,
            min_segment_sentences=1,
        )
        graph = backend.list_memory_graph(context_id="board-demo")
        recall = backend.query(
            backend.embed_text("supplier budget contract risk"),
            context_id="board-demo",
        )

        self.assertGreaterEqual(ingestion["event_count"], 2)
        self.assertGreaterEqual(ingestion["relationship_count"], 1)
        self.assertTrue(ingestion["events"][0]["tag"].startswith("morning-brief-event-001-"))
        self.assertTrue(graph["relationships"])
        self.assertEqual(graph["relationships"][0]["relation_type"], "temporal_next")
        self.assertIn("morning-brief-event", recall)

    def test_ingest_text_events_records_embedding_surprise_metadata(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )

        ingestion = backend.ingest_text_events(
            text=(
                "Metal compiles local kernels for M-series acceleration. "
                "On-chip GPU execution keeps native compute efficient. "
                "Finance approval owners track contract renewal risk."
            ),
            context_id="default",
            source_tag="semantic-surprise",
            surprise_threshold=0.40,
            min_segment_sentences=1,
        )
        memory = backend.list_memory(context_id="default", limit=10)
        first_event = next(
            entry
            for entry in memory["entries"]
            if entry["tag"].startswith("semantic-surprise-event-001-")
        )

        self.assertEqual(
            ingestion["events"][0]["segment"]["surprise_mode"],
            "embedding",
        )
        self.assertEqual(first_event["metadata"]["surprise_mode"], "embedding")
        self.assertIn("semantic_surprise_score", first_event["metadata"])
        self.assertEqual(
            first_event["metadata"]["surprise_model"]["embedding_provider"],
            "semantic-hash-v1",
        )
        self.assertTrue(ingestion["surprise_model"]["semantic"])

    def test_memory_graph_summarizes_temporal_and_associative_relationship_modes(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        text = (
            "Supplier contract renewal risk needs local recall. "
            "Apple Silicon kernels compile spiking attention locally. "
            "Supplier contract payment ownership needs associative follow-up."
        )

        backend.ingest_text_events(
            text=text,
            context_id="board-demo",
            source_tag="mode-brief",
            surprise_threshold=0.58,
            min_segment_sentences=1,
        )
        graph = backend.list_memory_graph(context_id="board-demo")

        self.assertEqual(
            graph["relationship_summary"]["total"],
            graph["relationship_count"],
        )
        self.assertGreaterEqual(graph["relationship_summary"]["temporal"], 2)
        self.assertGreaterEqual(graph["relationship_summary"]["associative"], 1)
        self.assertEqual(
            graph["relationship_summary"]["by_type"]["temporal_next"],
            graph["relationship_summary"]["temporal"],
        )
        self.assertEqual(
            graph["relationship_summary"]["by_type"]["semantic_overlap"],
            graph["relationship_summary"]["associative"],
        )

    def test_memory_graph_prioritizes_relationship_endpoints_over_recent_noise(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=16,
            default_top_k=3,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        source = backend.register_trace(
            tag="old-critical-source",
            embedding=[0.1, 0.9, 0.2, 0.8, 0.0, -0.1, 0.4, 0.7],
            context_id="demo",
            metadata={"display_label": "old critical source"},
            source_text="Older critical source node.",
        )
        target = backend.register_trace(
            tag="old-critical-target",
            embedding=[0.0, 0.7, 0.3, 0.9, 0.1, -0.2, 0.5, 0.6],
            context_id="demo",
            metadata={"display_label": "old critical target"},
            source_text="Older critical target node.",
        )
        backend.memory_store.upsert_relationship(
            context_id="demo",
            source_memory_id=source["memory_id"],
            target_memory_id=target["memory_id"],
            relation_type="semantic_overlap",
            weight=0.93,
            evidence={"keywords": ["critical", "edge"]},
        )
        for index in range(6):
            backend.register_trace(
                tag=f"new-noise-{index}",
                embedding=[float(index), 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7],
                context_id="demo",
                source_text=f"New unrelated dashboard note {index}.",
            )

        graph = backend.list_memory_graph(context_id="demo", limit=3)
        graph_ids = {entry["memory_id"] for entry in graph["entries"]}

        self.assertEqual(graph["graph_entry_strategy"], "relationship_endpoints_first")
        self.assertEqual(graph["relationship_endpoint_count"], 2)
        self.assertIn(source["memory_id"], graph_ids)
        self.assertIn(target["memory_id"], graph_ids)
        self.assertEqual(graph["relationships"][0]["source_label"], "old critical source")
        self.assertEqual(graph["relationships"][0]["target_label"], "old critical target")

    def test_memory_graph_entries_include_bounded_neural_inspector_samples(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=16,
            default_top_k=3,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.register_trace(
            tag="inspector-memory",
            embedding=[0.0, 0.2, 0.9, -0.7, 0.4, 0.8, -0.1, 0.3],
            context_id="demo",
        )

        graph = backend.list_memory_graph(context_id="demo", limit=5)
        entry = graph["entries"][0]
        status = backend.status(context_id="demo")

        self.assertEqual(entry["tag"], "inspector-memory")
        self.assertEqual(entry["spike_count"], 3)
        self.assertEqual(entry["neuron_count"], 3)
        self.assertEqual(status["beta"], 0.95)
        self.assertEqual(status["threshold"], 1.0)
        self.assertIn("spike_coordinate_sample", entry)
        self.assertIn("neuron_index_sample", entry)
        self.assertLessEqual(len(entry["spike_coordinate_sample"]), 12)
        self.assertLessEqual(len(entry["neuron_index_sample"]), 12)
        self.assertTrue(
            all(isinstance(value, int) for value in entry["spike_coordinate_sample"])
        )
        self.assertTrue(
            all(isinstance(value, int) for value in entry["neuron_index_sample"])
        )

    def test_query_expands_recall_with_related_event_graph_neighbors(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=1,
            compile_graph=False,
            state_path=self.state_path,
        )
        text = (
            "Apple Silicon MLX compiles spiking neural kernels into Metal. "
            "The local SNN tracks sparse top-k spike populations for recall. "
            "Procurement reviews supplier budget exposure and contract risk."
        )
        backend.ingest_text_events(
            text=text,
            context_id="board-demo",
            source_tag="graph-brief",
            surprise_threshold=0.58,
            min_segment_sentences=1,
        )

        recall = backend.query(
            backend.embed_text("Apple Silicon MLX compiles spiking neural kernels into Metal."),
            context_id="board-demo",
        )

        self.assertIn("graph-brief-event-001", recall)
        self.assertIn("graph-brief-event-002", recall)

    def test_text_embedding_is_deterministic_for_cli_and_mcp_demo_use(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=16,
            compile_graph=False,
            state_path=self.state_path,
        )

        first = backend.embed_text("offboarding risk review", dimensions=32)
        second = backend.embed_text("offboarding risk review", dimensions=32)
        third = backend.embed_text("wing load analysis", dimensions=32)

        self.assertEqual(first.tolist(), second.tolist())
        self.assertNotEqual(first.tolist(), third.tolist())

    def test_text_embedding_provider_status_and_provenance_are_visible(self):
        backend = SpikingAttentionBackend(
            dimension=48,
            num_neurons=24,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )

        payload = backend.embed_text_payload("Apple Silicon Metal acceleration", dimensions=48)
        registration = backend.register_text_trace(
            tag="semantic-provider-memory",
            text="Apple Silicon Metal acceleration",
            context_id="demo",
            metadata={"source": "unit-test"},
        )
        memory = backend.list_memory(context_id="demo")
        status = backend.status(context_id="demo")

        self.assertEqual(payload["provenance"]["provider"], "semantic-hash-v1")
        self.assertTrue(payload["provenance"]["semantic"])
        self.assertEqual(status["embedding_provider"]["provider"], "semantic-hash-v1")
        self.assertTrue(status["embedding_provider"]["semantic"])
        self.assertEqual(registration["embedding_provider"]["provider"], "semantic-hash-v1")
        self.assertEqual(
            memory["entries"][0]["metadata"]["embedding_provider"]["provider"],
            "semantic-hash-v1",
        )
        self.assertEqual(memory["entries"][0]["metadata"]["source"], "unit-test")

    def test_backend_accepts_closed_embedding_configuration_without_env_drift(self):
        cache_dir = str((Path(self.tmpdir.name) / "model-cache").resolve())
        config = embedding_providers.EmbeddingProviderConfig(
            provider="mlx-neural-v1",
            neural=embedding_providers.MLXNeuralEmbeddingConfig(
                model_id="unit/pinned-backend-model",
                cache_dir=cache_dir,
                revision="c" * 40,
                pooling="first",
                max_tokens=211,
                normalize=False,
                local_files_only=True,
            ),
        )
        with patch.dict(
            os.environ,
            {
                "SYNAPSE_S2_EMBEDDING_PROVIDER": "lexical-hash",
                "SYNAPSE_S2_NEURAL_MODEL": "environment/other-model",
                "SYNAPSE_S2_NEURAL_REVISION": "d" * 40,
                "SYNAPSE_S2_NEURAL_POOLING": "last",
                "SYNAPSE_S2_NEURAL_MAX_TOKENS": "3",
                "SYNAPSE_S2_NEURAL_NORMALIZE": "true",
                "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY": "false",
            },
            clear=False,
        ):
            backend = SpikingAttentionBackend(
                dimension=16,
                num_neurons=12,
                compile_graph=False,
                state_path=self.state_path,
                embedding_provider_config=config,
            )
            info = backend.embedding_provider_info()

        self.assertEqual(backend.embedding_provider_name, "mlx-neural-v1")
        self.assertEqual(info["configuration_source"], "explicit")
        self.assertEqual(info["runtime_config"]["model_id"], "unit/pinned-backend-model")
        self.assertEqual(info["runtime_config"]["revision"], "c" * 40)
        self.assertEqual(info["runtime_config"]["cache_dir"], cache_dir)
        self.assertEqual(info["runtime_config"]["pooling"], "first")
        self.assertEqual(info["runtime_config"]["max_tokens"], 211)
        self.assertFalse(info["runtime_config"]["normalize"])
        self.assertTrue(info["runtime_config"]["local_files_only"])

    def test_backend_accepts_preconstructed_embedding_provider_exclusively(self):
        class FakeRuntime:
            model_id = "unit/injected-model"
            source = "unit/injected-model"
            native_mlx = True

            def embed_text(self, text, *, pooling, max_tokens):
                return [1.0, 2.0, 3.0]

        provider = embedding_providers.MLXNeuralEmbeddingProvider(
            model_id="unit/injected-model",
            runtime_factory=lambda _config: FakeRuntime(),
            normalize=False,
        )
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider=provider,
        )

        payload = backend.embed_text_payload("injected provider", dimensions=8)

        self.assertIs(backend.embedding_provider, provider)
        self.assertEqual(backend.embedding_provider_name, "mlx-neural-v1")
        self.assertEqual(payload["provenance"]["model_id"], "unit/injected-model")
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            SpikingAttentionBackend(
                dimension=8,
                num_neurons=6,
                compile_graph=False,
                state_path=Path(self.tmpdir.name) / "conflict-state.json",
                embedding_provider=provider,
                embedding_provider_name="semantic-hash",
            )

    def test_semantic_provider_improves_related_phrase_recall_without_exact_tokens(self):
        backend = SpikingAttentionBackend(
            dimension=96,
            num_neurons=48,
            default_top_k=8,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        backend.register_text_trace(
            tag="native-metal-memory",
            text="Apple Silicon Metal kernels accelerate the local spiking runtime.",
            context_id="demo",
        )

        result = backend.query(
            backend.embed_text("M-series MLX GPU compute path"),
            context_id="demo",
        )

        self.assertIn("native-metal-memory", result)

    def test_native_certification_reports_checks_and_writes_evidence(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            evidence_path = Path(tmp) / "certification.json"
            backend = SpikingAttentionBackend(
                dimension=8,
                num_neurons=6,
                compile_graph=False,
                state_path=state_path,
            )

            certification = backend.certify_runtime(
                strict_native=False,
                benchmark_quick_prune=True,
                output_path=evidence_path,
            )
            evidence_exists = evidence_path.exists()
            evidence_mode = evidence_path.stat().st_mode & 0o777

        self.assertTrue(evidence_exists)
        self.assertEqual(evidence_mode, 0o600)
        self.assertEqual(certification["action"], "certify-runtime")
        self.assertIn("checks", certification)
        self.assertIn("resource_profile", certification)
        self.assertIn("quick_pruning", certification["resource_profile"])
        self.assertEqual(certification["evidence_path"], str(evidence_path.resolve()))
        self.assertEqual(certification["checks"]["mlx_available"]["passed"], True)
        self.assertIn("embedding_provider_native_mlx", certification["checks"])

    def test_native_certification_rejects_secret_shaped_output_path(self):
        marker = "SYNTHETIC_CERT_PATH_SECRET_42"
        output = Path(self.tmpdir.name) / f"password={marker}.json"
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )

        with self.assertRaises(ValueError) as raised:
            backend.certify_runtime(output_path=output)

        self.assertNotIn(marker, str(raised.exception))
        self.assertFalse(output.exists())

    def test_native_certification_retries_cold_quick_prune_sample(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        samples = [
            {"elapsed_ms": 67.0, "within_60ms_budget": False},
            {"elapsed_ms": 11.5, "within_60ms_budget": True},
        ]

        def fake_quick_prune(*, trigger: str = "manual") -> dict:
            sample = dict(samples.pop(0))
            sample.update(
                {
                    "mode": "quick-pruning",
                    "trigger": trigger,
                    "gpu_non_llm": True,
                    "decay_strategy": "lazy-scalar",
                    "membrane_reset": True,
                }
            )
            return sample

        backend.run_quick_pruning = fake_quick_prune  # type: ignore[method-assign]

        certification = backend.certify_runtime(benchmark_quick_prune=True)
        quick_profile = certification["resource_profile"]["quick_pruning"]

        self.assertTrue(certification["checks"]["quick_pruning_budget"]["passed"])
        self.assertEqual(quick_profile["elapsed_ms"], 11.5)
        self.assertEqual(quick_profile["sample_count"], 2)
        self.assertTrue(quick_profile["cold_start_retry_used"])
        self.assertEqual(
            [sample["elapsed_ms"] for sample in quick_profile["samples"]],
            [67.0, 11.5],
        )

    def test_native_certification_strict_mode_fails_when_lif_downgrades(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend._mlxsnn_lif_layer = None

        certification = backend.certify_runtime(strict_native=True)

        self.assertFalse(certification["ready"])
        self.assertTrue(certification["strict_native"])
        self.assertIn("mlxsnn_lif_execution_path", certification["failed_checks"])

    def test_require_native_constructor_raises_when_mlxsnn_is_unavailable(self):
        original_mlxsnn = mlx_backend.mlxsnn
        try:
            mlx_backend.mlxsnn = None
            with self.assertRaises(BackendUnavailable):
                SpikingAttentionBackend(
                    dimension=8,
                    num_neurons=6,
                    compile_graph=False,
                    state_path=self.state_path,
                    require_native=True,
                )
        finally:
            mlx_backend.mlxsnn = original_mlxsnn

    def test_global_toggle_disables_and_reenables_queries(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        disabled = backend.set_enabled(False)
        disabled_query = backend.query(
            mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
            context_id="demo",
        )
        enabled = backend.set_enabled(True)
        enabled_query = backend.query(
            mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
            context_id="demo",
        )

        self.assertFalse(disabled["global_enabled"])
        self.assertIn("disabled", disabled_query.lower())
        self.assertTrue(enabled["global_enabled"])
        self.assertIn("No registered historical context matched", enabled_query)
        self.assertNotIn("demo::neuron-", enabled_query)

    def test_context_toggle_overrides_global_state(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        backend.set_enabled(True)
        backend.set_enabled(False, context_id="quiet-demo")

        quiet_query = backend.query(
            mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
            context_id="quiet-demo",
        )
        active_query = backend.query(
            mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
            context_id="active-demo",
        )

        self.assertIn("disabled", quiet_query.lower())
        self.assertIn("No registered historical context matched", active_query)
        self.assertNotIn("active-demo::neuron-", active_query)

    def test_toggle_state_persists_to_state_file(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "synapse-state.json"
            backend = SpikingAttentionBackend(
                dimension=4,
                num_neurons=6,
                compile_graph=False,
                state_path=state_path,
            )

            backend.set_enabled(False, context_id="demo")
            restored = SpikingAttentionBackend(
                dimension=4,
                num_neurons=6,
                compile_graph=False,
                state_path=state_path,
            )

            # Exercise the restored backend while its durable store and
            # authority lock still exist.  A backend must fail closed once
            # its entire temporary state directory has been removed.
            status = restored.status(context_id="demo")

        self.assertTrue(status["global_enabled"])
        self.assertFalse(status["effective_enabled"])
        self.assertEqual(status["context_overrides"], {"demo": False})

    def test_stale_backends_merge_distinct_overrides_and_global_control(self):
        backend_a = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend_b = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )

        backend_a.set_enabled(False, context_id="alpha")
        backend_a.set_enabled(False)
        backend_b.set_enabled(True, context_id="beta")

        restored = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )

        self.assertFalse(restored.global_enabled)
        self.assertEqual(
            restored.context_overrides,
            {"alpha": False, "beta": True},
        )

    def test_toggle_intent_survives_failed_atomic_persist(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )

        with patch.object(
            mlx_backend,
            "_atomic_write_private_json",
            side_effect=OSError("simulated runtime-state write failure"),
        ):
            with self.assertRaises(OSError):
                backend.set_enabled(False, context_id="alpha")

        self.assertEqual(backend._dirty_context_overrides, {"alpha"})
        backend._persist_runtime_state()
        self.assertEqual(backend._dirty_context_overrides, set())

        with patch.object(
            mlx_backend,
            "_atomic_write_private_json",
            side_effect=OSError("simulated runtime-state write failure"),
        ):
            with self.assertRaises(OSError):
                backend.set_enabled(False)

        self.assertTrue(backend._global_enabled_dirty)
        backend._persist_runtime_state()
        self.assertFalse(backend._global_enabled_dirty)

        restored = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        self.assertFalse(restored.global_enabled)
        self.assertEqual(restored.context_overrides, {"alpha": False})

    def test_runtime_state_commit_revalidates_authority_before_replace(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend._persist_runtime_state()
        before = self.state_path.read_bytes()
        before_inode = self.state_path.stat().st_ino
        lock_path = backend.memory_store.db_path.parent / "core" / "authority.lock"
        displaced = lock_path.with_name("authority.lock.displaced")
        original_assert = backend.memory_store.assert_active_authority
        calls = 0

        def replace_before_commit() -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                lock_path.rename(displaced)
                lock_path.write_bytes(b"replacement")
                lock_path.chmod(0o600)
            original_assert()

        with patch.object(
            backend.memory_store,
            "assert_active_authority",
            side_effect=replace_before_commit,
        ):
            with self.assertRaises(CoreAuthorityError):
                backend.set_enabled(False, context_id="alpha")

        self.assertGreaterEqual(calls, 2)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(self.state_path.stat().st_ino, before_inode)

    def test_status_reports_demo_readiness_fields(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )

        status = backend.status(context_id="demo")

        self.assertEqual(status["context_id"], "demo")
        self.assertTrue(status["effective_enabled"])
        self.assertEqual(status["dimension"], 4)
        self.assertEqual(status["num_neurons"], 6)
        self.assertIn("mlx_available", status)
        self.assertIn("mlxsnn_available", status)
        self.assertIn("memory_db_path", status)
        self.assertIn("memory_entry_count", status)
        self.assertIn("memory_event_count", status)
        self.assertEqual(status["quick_pruning_interval_seconds"], 300.0)
        self.assertEqual(status["idle_deep_sleep_seconds"], 1800.0)
        self.assertEqual(
            status["consolidation_phase_names"],
            [
                "connection-weight-decay",
                "synaptic-clustering",
                "semantic-merging",
                "threshold-rescoring",
                "trace-promotion",
                "relationship-extraction",
                "neurogenesis",
            ],
        )

    def test_resource_profile_reports_topology_memory_and_pruning_budget(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )

        profile = backend.resource_profile(benchmark_quick_prune=True)

        self.assertEqual(profile["dimension"], 8)
        self.assertEqual(profile["num_neurons"], 6)
        self.assertEqual(profile["arrays"]["W_syn"]["elements"], 48)
        self.assertEqual(profile["arrays"]["W_lateral"]["elements"], 36)
        self.assertGreater(profile["estimated_total_mb"], 0.0)
        self.assertIn("within_target_envelope", profile)
        self.assertEqual(profile["target_envelope_mb"], {"min": 96.0, "max": 384.0})
        self.assertTrue(profile["quick_pruning"]["within_60ms_budget"])

    def test_backend_exports_and_backs_up_real_memory_store(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            export_path = Path(tmp) / "memory-export.json"
            backup_path = Path(tmp) / "memory-backup.sqlite3"
            backend = SpikingAttentionBackend(
                dimension=6,
                num_neurons=10,
                default_top_k=2,
                recall_count=3,
                compile_graph=False,
                state_path=state_path,
                memory_path=memory_path,
            )
            backend.register_trace(
                tag="ops-memory",
                embedding=mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
                context_id="ops",
                metadata={"owner": "it"},
                source_text="Operators can inspect and export this memory.",
            )

            listing = backend.list_memory(context_id="ops")
            exported = backend.export_memory(path=export_path, context_id="ops")
            backup = backend.backup_memory(backup_path)
            export_exists = export_path.exists()
            backup_exists = backup_path.exists()

        self.assertEqual(listing["entry_count"], 1)
        self.assertEqual(exported["entries"][0]["tag"], "ops-memory")
        self.assertTrue(export_exists)
        self.assertEqual(backup["entry_count"], 1)
        self.assertTrue(backup_exists)

    def test_backend_publishes_context_events_for_connected_agents(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        event = backend.publish_context_event(
            context_id="demo",
            source_surface="unit-test",
            event_type="remember-trace",
            summary="operator-note deployed",
            payload={"tag": "operator-note", "memory_id": "s2_demo"},
        )
        listing = backend.list_context_events(context_id="demo", limit=5)
        status = backend.status(context_id="demo")

        self.assertTrue(event["published"])
        self.assertEqual(event["delivery_mode"], "leased-at-least-once")
        self.assertEqual(event["agent_targets"], ["mcp-clients", "codex-desktop", "local-ide-adapters"])
        self.assertEqual(listing["events"][0]["summary"], "operator-note deployed")
        self.assertEqual(status["context_bus_context_event_count"], 1)
        self.assertEqual(status["context_bus_latest_event_id"], event["event_id"])

    def test_backend_tracks_context_event_delivery_receipts_by_agent(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )
        first = backend.publish_context_event(
            context_id="demo",
            source_surface="unit-test",
            event_type="remember-trace",
            summary="first deployed",
            payload={"tag": "first"},
        )
        second = backend.publish_context_event(
            context_id="demo",
            source_surface="unit-test",
            event_type="ingest-events",
            summary="second deployed",
            payload={"tag": "second"},
        )

        leased = backend.lease_context_events(
            context_id="demo",
            agent_id="codex-desktop",
            consumer_instance_id="backend-test",
            limit=1,
        )
        ack = backend.ack_context_events(
            context_id="demo",
            agent_id="codex-desktop",
            receipt_id=leased["deliveries"][0]["receipt_id"],
        )
        cursors = backend.list_context_cursors(context_id="demo")
        status = backend.status(context_id="demo")

        self.assertEqual(ack["agent_id"], "codex-desktop")
        self.assertEqual(ack["cursor"]["last_event_id"], first["event_id"])
        self.assertEqual(ack["cursor"]["latest_event_id"], second["event_id"])
        self.assertEqual(ack["cursor"]["pending_event_count"], 1)
        self.assertEqual(cursors["cursor_count"], 1)
        self.assertEqual(cursors["cursors"][0]["agent_id"], "codex-desktop")
        self.assertEqual(status["context_bus_ack_cursor_count"], 1)

    def test_backend_rejects_cursor_only_context_ack_even_at_zero(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        with self.assertRaisesRegex(ContextDeliveryRejected, "exact receipt_id"):
            backend.ack_context_events(
                context_id="demo",
                agent_id="codex-desktop",
                last_event_id=0,
            )

    def test_delivery_rejection_class_excludes_invalid_runtime_configuration(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        with patch.dict(
            os.environ,
            {"SYNAPSE_S2_CONTEXT_MAX_DELIVERY_ATTEMPTS": "not-an-integer"},
        ), self.assertRaises(ValueError) as raised:
            backend.dead_letter_context_delivery(
                context_id="demo",
                agent_id="codex-desktop",
                delivery_id="ctxdel_" + "a" * 32,
                reason="retry budget exhausted",
                confirm=True,
            )

        self.assertNotIsInstance(raised.exception, ContextDeliveryRejected)

    def test_backend_status_reports_ack_tombstones_after_safe_prune(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )
        event = backend.publish_context_event(
            context_id="demo",
            source_surface="unit-test",
            event_type="tombstone-status",
            summary="status preserves acknowledged deletion evidence",
            agent_targets=["codex-desktop"],
        )
        delivery = backend.lease_context_events(
            context_id="demo",
            agent_id="codex-desktop",
            consumer_instance_id="backend-tombstone-test",
            limit=1,
        )["deliveries"][0]
        backend.ack_context_events(
            context_id="demo",
            agent_id="codex-desktop",
            receipt_id=delivery["receipt_id"],
        )
        backend.memory_store.delete_context_event(
            context_id="demo",
            event_id=event["event_id"],
        )

        status = backend.status(context_id="demo")

        self.assertEqual(status["context_bus_ack_tombstone_count"], 1)

    def test_agent_context_hydration_briefs_recalls_and_advances_cursor(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        registration = backend.register_trace(
            tag="agent-brief-memory",
            embedding=backend.embed_text("agent hydration should recall the sidecar context"),
            context_id="demo",
            source_text="agent hydration should recall the sidecar context",
            metadata={"source": "unit-test"},
        )
        event = backend.publish_context_event(
            context_id="demo",
            source_surface="unit-test",
            event_type="remember-trace",
            summary="agent-brief-memory captured and published",
            payload={"tag": registration["tag"], "memory_id": registration["memory_id"]},
            agent_targets=["codex-hydrator"],
        )

        first = backend.hydrate_agent_context(
            context_id="demo",
            agent_id="codex-hydrator",
            prompt="sidecar context recall",
        )
        ack = backend.ack_context_events(
            context_id="demo",
            agent_id="codex-hydrator",
            receipt_id=first["deliveries"][0]["receipt_id"],
        )
        second = backend.hydrate_agent_context(
            context_id="demo",
            agent_id="codex-hydrator",
            prompt="sidecar context recall",
        )

        self.assertEqual(first["action"], "agent-context-hydrate")
        self.assertEqual(first["context_id"], "demo")
        self.assertEqual(first["agent_id"], "codex-hydrator")
        self.assertEqual(first["new_event_count"], 1)
        self.assertEqual(first["latest_event_id"], event["event_id"])
        self.assertIsNone(first["ack"])
        self.assertFalse(first["acknowledged"])
        self.assertTrue(first["ack_required"])
        self.assertEqual(ack["cursor"]["last_event_id"], event["event_id"])
        self.assertIn("agent-brief-memory captured and published", first["briefing_markdown"])
        self.assertIn("agent-brief-memory", first["recall_result"])
        self.assertEqual(first["graph_summary"]["entry_count"], 1)
        self.assertEqual(
            first["namespace_connectivity"],
            {
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
        )
        self.assertIn("Internal memory relationships above are not namespace bridges", first["briefing_markdown"])
        self.assertEqual(second["new_event_count"], 0)
        self.assertEqual(second["since_event_id"], event["event_id"])
        self.assertFalse(second["ack_required"])

    def test_control_plane_surface_hydration_defers_neural_substrate(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            control_plane_only=True,
        )
        full_backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        full_backend.register_text_trace(
            tag="surface-bootstrap-memory",
            context_id="demo",
            text="surface bootstrap recalls durable local context",
        )

        hydrated = backend.hydrate_agent_context(
            context_id="demo",
            agent_id="codex-desktop",
            prompt="surface bootstrap durable context",
            claim_events=False,
            recall_mode="surface",
        )

        self.assertTrue(backend.control_plane_only)
        self.assertIsNone(backend.W_lateral)
        self.assertEqual(hydrated["recall_mode"], "surface")
        self.assertEqual(
            hydrated["recall_provenance"],
            "sqlite-surface-bootstrap",
        )
        self.assertIn("surface-bootstrap-memory", hydrated["recall_result"])
        with self.assertRaisesRegex(mlx_backend.BackendUnavailable, "deferred"):
            backend.query_text("must not materialize")

    def test_cortex_governor_enters_ticks_and_commits_typed_trace(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.commit_cortical_trace(
            context_id="demo",
            agent_id="operator",
            session_id="seed-session",
            trace_type="constraint",
            truth_posture="operator-confirmed",
            text="Operator requires tests before claiming Cortex Governor is complete.",
            evidence={"source": "unit-test"},
        )
        backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id="seed-session",
            trace_type="assumption",
            truth_posture="inferred",
            text="Maybe the dashboard already carries intended file scope.",
            evidence={"source": "unit-test"},
            confidence=0.42,
        )
        backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id="seed-session",
            trace_type="correction",
            truth_posture="operator-confirmed",
            text="Correction: Cortex ticks must declare intended files and tools before mutation.",
            evidence={"source": "unit-test"},
        )

        entry = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Implement the Cortex Governor release with tests.",
            mode="strict",
        )
        tick = backend.cortex_tick(
            context_id="demo",
            agent_id="codex",
            session_id=entry["session_id"],
            observation="About to edit backend and MCP files.",
            proposed_action="Modify mlx_backend.py and mcp_server.py, then run tests.",
            intended_files=["mlx_backend.py", "mcp_server.py"],
            intended_tools=["apply_patch", "python -m unittest tests.test_backend"],
            mutation_intent=True,
            confidence=0.42,
        )
        commit = backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id=entry["session_id"],
            trace_type="validation",
            truth_posture="test-validated",
            text="Cortex Governor tests passed for backend, CLI, MCP, and dashboard surfaces.",
            evidence={"tests": ["tests.test_backend"], "commit": "pending"},
        )
        state = backend.get_cortex_state(context_id="demo", agent_id="codex")
        close = backend.close_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            session_id=entry["session_id"],
            reason="unit-test-complete",
        )
        closed_state = backend.get_cortex_state(context_id="demo", agent_id="codex")

        self.assertEqual(entry["action"], "enter-spiking-cortex")
        self.assertEqual(entry["mode"], "strict")
        self.assertIn("verify-before-mutation", entry["governance_contract"])
        self.assertEqual(entry["agent_deployment"]["event_type"], "cortex-entered")
        self.assertEqual(tick["action"], "cortex-tick")
        self.assertEqual(tick["session_id"], entry["session_id"])
        self.assertEqual(tick["decision"], "verify-first")
        self.assertEqual(tick["intended_files"], ["mlx_backend.py", "mcp_server.py"])
        self.assertEqual(
            tick["intended_tools"],
            ["apply_patch", "python -m unittest tests.test_backend"],
        )
        self.assertTrue(
            any(item["code"] == "mutation-verification-required" for item in tick["warnings"])
        )
        self.assertFalse(
            any(item["code"] == "missing-intent-scope" for item in tick["warnings"])
        )
        self.assertGreaterEqual(len(tick["recalled_constraints"]), 1)
        self.assertTrue(tick["capture_recommendation"]["recommended"])
        self.assertGreaterEqual(len(tick["cortex_state"]["capture_queue"]), 1)
        self.assertEqual(commit["action"], "commit-cortical-trace")
        self.assertEqual(commit["trace_type"], "validation")
        self.assertEqual(commit["truth_posture"], "test-validated")
        self.assertGreaterEqual(commit["confidence"], 0.85)
        self.assertEqual(commit["agent_deployment"]["event_type"], "cortex-trace-committed")
        self.assertEqual(state["action"], "cortex-state")
        self.assertEqual(state["active_goal"], "Implement the Cortex Governor release with tests.")
        self.assertEqual(state["active_sessions"][0]["session_id"], entry["session_id"])
        self.assertEqual(state["active_sessions"][0]["last_intended_files"], ["mlx_backend.py", "mcp_server.py"])
        self.assertIn("Resolve the surfaced correction", state["suggested_next_move"])
        self.assertEqual(len(state["capture_queue"]), 0)
        self.assertGreaterEqual(len(state["unverified_assumptions"]), 1)
        self.assertGreaterEqual(len(state["contradictions"]), 1)
        self.assertGreaterEqual(state["typed_memory_counts"]["validation"], 1)
        self.assertTrue(
            any(item["trace_type"] == "validation" for item in state["high_confidence_truths"])
        )
        self.assertEqual(close["action"], "close-spiking-cortex")
        self.assertEqual(close["status"], "closed")
        self.assertEqual(close["agent_deployment"]["event_type"], "cortex-closed")
        self.assertEqual(close["cortex_state"]["active_session_count"], 0)
        self.assertEqual(closed_state["active_session_count"], 0)

    def test_cortex_boundaries_redact_before_provider_hash_storage_and_response(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        marker = "SYNTHETIC_ONLY_CORTEX_SECRET_42"
        observed_provider_text: list[str] = []
        original_embed = backend.embedding_provider.embed

        def recording_embed(text, *, dimensions):
            observed_provider_text.append(text)
            return original_embed(text, dimensions=dimensions)

        with patch.object(backend.embedding_provider, "embed", side_effect=recording_embed):
            entered = backend.enter_spiking_cortex(
                context_id="demo",
                agent_id="codex",
                task=f"Review production state password={marker}",
                mode="security",
            )
            tick = backend.cortex_tick(
                context_id="demo",
                agent_id="codex",
                session_id=entered["session_id"],
                observation=f"Observed Authorization: Bearer {marker}",
                proposed_action=f"Inspect /tmp/report?api_key={marker}",
                intended_files=[f"/tmp/report?token={marker}"],
                intended_tools=[f"curl -H 'Authorization: ApiKey {marker}'"],
                mutation_intent=False,
            )
            hydrated = backend.hydrate_agent_context(
                context_id="demo",
                agent_id="codex",
                prompt=f"Recall password={marker}",
                claim_events=False,
            )
            committed = backend.commit_cortical_trace(
                context_id="demo",
                agent_id="codex",
                session_id=entered["session_id"],
                trace_type="risk",
                text=f"Credential finding api_key={marker}",
                evidence={"api_key": marker, "safe": "retained"},
            )
            closed = backend.close_spiking_cortex(
                context_id="demo",
                agent_id="codex",
                session_id=entered["session_id"],
                reason=f"done password={marker}",
            )

        public_payload = json.dumps(
            {
                "entered": entered,
                "tick": tick,
                "hydrated": hydrated,
                "committed": committed,
                "closed": closed,
            },
            sort_keys=True,
        )
        durable_state = self.state_path.read_text(encoding="utf-8")
        with closing(sqlite3.connect(backend.memory_store.db_path)) as conn:
            durable_rows = json.dumps(
                conn.execute(
                    "SELECT source_text, metadata_json FROM memory_entries"
                ).fetchall(),
                sort_keys=True,
            )

        self.assertNotIn(marker, public_payload)
        self.assertNotIn(marker, durable_state)
        self.assertNotIn(marker, durable_rows)
        self.assertTrue(observed_provider_text)
        self.assertTrue(all(marker not in text for text in observed_provider_text))
        self.assertGreaterEqual(entered["input_redaction_count"], 1)
        self.assertGreaterEqual(tick["input_redaction_count"], 2)
        self.assertGreaterEqual(hydrated["input_redaction_count"], 1)
        self.assertEqual(committed["metadata"]["evidence"]["api_key"], "[REDACTED_SECRET]")
        self.assertEqual(committed["metadata"]["evidence"]["safe"], "retained")

        with self.assertRaisesRegex(ValueError, "credential material"):
            backend.cortex_tick(
                context_id="demo",
                agent_id="codex",
                session_id=f"password={marker}",
            )

    def test_runtime_state_scrubs_legacy_secret_bearing_cortex_session_keys(self):
        marker = "SYNTHETIC_ONLY_LEGACY_SESSION_SECRET_42"
        self.state_path.write_text(
            json.dumps(
                {
                    "version": 2,
                    "global_enabled": True,
                    "context_overrides": {},
                    "cortex_sessions": {
                        f"password={marker}": {
                            "context_id": "demo",
                            "agent_id": "codex",
                            "task": f"Review api_key={marker}",
                            "status": "closed",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        backend = SpikingAttentionBackend(
            dimension=16,
            num_neurons=12,
            compile_graph=False,
            state_path=self.state_path,
        )
        rewritten = self.state_path.read_text(encoding="utf-8")

        self.assertNotIn(marker, rewritten)
        self.assertEqual(len(backend.cortex_sessions), 1)
        session_id = next(iter(backend.cortex_sessions))
        self.assertTrue(session_id.startswith("ctx_legacy_"))
        self.assertEqual(self.state_path.stat().st_mode & 0o777, 0o600)

    def test_unreadable_runtime_state_is_safely_quarantined_with_repair_status(self):
        marker = "SYNTHETIC_UNREADABLE_RUNTIME_SECRET_42"
        digest = "ab" * 32
        self.state_path.write_text(
            f'broken {{ password={marker}, input_sha256={digest}',
            encoding="utf-8",
        )

        backend = SpikingAttentionBackend(
            dimension=16,
            num_neurons=12,
            compile_graph=False,
            state_path=self.state_path,
        )
        repaired_text = self.state_path.read_text(encoding="utf-8")
        repaired = json.loads(repaired_text)
        quarantine = self.state_path.parent / "runtime_state_quarantine"
        artifacts = list(quarantine.glob("runtime-state-repair-*.json"))
        artifact_text = artifacts[0].read_text(encoding="utf-8")
        status = backend.status(context_id="default")

        self.assertEqual(len(artifacts), 1)
        self.assertNotIn(marker, repaired_text)
        self.assertNotIn(marker, artifact_text)
        self.assertNotIn(digest, artifact_text)
        self.assertNotIn("input_sha256", artifact_text)
        self.assertEqual(repaired["runtime_state_repair"]["status"], "repair-required")
        self.assertEqual(status["runtime_state_repair"]["status"], "repair-required")
        self.assertFalse(status["runtime_state_repair"]["raw_source_retained"])
        self.assertEqual(self.state_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(quarantine.stat().st_mode & 0o777, 0o700)
        self.assertEqual(artifacts[0].stat().st_mode & 0o777, 0o600)

    def test_runtime_state_symlink_is_refused_without_mutating_target(self):
        target = self.state_path.parent / "caller-owned-state.json"
        original = '{"global_enabled": false}\n'
        target.write_text(original, encoding="utf-8")
        self.state_path.symlink_to(target)

        with self.assertRaisesRegex(RuntimeError, "must not be a symlink"):
            SpikingAttentionBackend(
                dimension=16,
                num_neurons=12,
                compile_graph=False,
                state_path=self.state_path,
            )

        self.assertEqual(target.read_text(encoding="utf-8"), original)
        self.assertTrue(self.state_path.is_symlink())

    def test_runtime_state_fifo_is_quarantined_without_blocking_startup(self):
        os.mkfifo(self.state_path, 0o600)
        result: dict[str, object] = {}

        def construct_backend() -> None:
            try:
                result["backend"] = SpikingAttentionBackend(
                    dimension=16,
                    num_neurons=12,
                    compile_graph=False,
                    state_path=self.state_path,
                )
            except BaseException as exc:  # pragma: no cover - assertion aid
                result["error"] = exc

        worker = threading.Thread(target=construct_backend, daemon=True)
        worker.start()
        worker.join(timeout=2.0)

        self.assertFalse(worker.is_alive(), "runtime FIFO blocked backend startup")
        self.assertNotIn("error", result)
        self.assertTrue(self.state_path.is_file())
        artifacts = list(
            (self.state_path.parent / "runtime_state_quarantine").glob(
                "runtime-state-repair-*.json"
            )
        )
        artifact = json.loads(artifacts[0].read_text(encoding="utf-8"))
        self.assertFalse(artifact["sanitized_snapshot_preserved"])
        self.assertEqual(artifact["sanitized_source_text"], "")

    def test_oversized_runtime_state_is_bounded_and_quarantined(self):
        with self.state_path.open("wb") as handle:
            handle.truncate(mlx_backend.MAX_RUNTIME_STATE_BYTES + 1)

        backend = SpikingAttentionBackend(
            dimension=16,
            num_neurons=12,
            compile_graph=False,
            state_path=self.state_path,
        )
        artifacts = list(
            (self.state_path.parent / "runtime_state_quarantine").glob(
                "runtime-state-repair-*.json"
            )
        )
        artifact = json.loads(artifacts[0].read_text(encoding="utf-8"))

        self.assertEqual(
            artifact["source_size_bytes"],
            mlx_backend.MAX_RUNTIME_STATE_BYTES + 1,
        )
        self.assertTrue(artifact["sanitized_snapshot_truncated"])
        self.assertEqual(
            backend.status(context_id="default")["runtime_state_repair"]["status"],
            "repair-required",
        )
        self.assertLess(self.state_path.stat().st_size, 64_000)

    def test_runtime_state_secure_read_rejects_symlink_swap(self):
        target = self.state_path.parent / "swap-target.json"
        target.write_text('{"global_enabled": false}\n', encoding="utf-8")
        self.state_path.write_text('{"global_enabled": true}\n', encoding="utf-8")
        original_target = target.read_text(encoding="utf-8")
        real_open = os.open
        swapped = False

        def swap_before_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if Path(path) == self.state_path and not swapped:
                swapped = True
                self.state_path.unlink()
                self.state_path.symlink_to(target)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(mlx_backend.os, "open", side_effect=swap_before_open):
            with self.assertRaises(OSError):
                mlx_backend._read_bounded_regular_text(
                    self.state_path,
                    max_bytes=mlx_backend.MAX_RUNTIME_STATE_BYTES,
                )

        self.assertTrue(self.state_path.is_symlink())
        self.assertEqual(target.read_text(encoding="utf-8"), original_target)

    def test_runtime_state_repairs_secret_records_without_losing_safe_records(self):
        marker = "SYNTHETIC_ONLY_RUNTIME_STATE_SECRET_42"
        self.state_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "global_enabled": False,
                    "context_overrides": {
                        "safe-context": False,
                        f"password={marker}": True,
                        "secret-value": f"api_key={marker}",
                    },
                    "cortex_sessions": {
                        "safe-session": {
                            "context_id": "safe-context",
                            "agent_id": "codex",
                            "task": "Preserve this session",
                        },
                        "secret-context-session": {
                            "context_id": f"password={marker}",
                            "agent_id": "codex",
                        },
                        "secret-agent-session": {
                            "context_id": "safe-context",
                            "agent_id": f"api_key={marker}",
                        },
                    },
                    "registered_traces": [
                        {
                            "tag": "safe-trace",
                            "context_id": "safe-context",
                            "source_text": f"Safe note with password={marker}",
                            "metadata": {"safe": True, "api_key": marker},
                            "embedding_dimensions": 16,
                            "spike_indices": [0, 1],
                            "neuron_indices": [0, 1],
                            "registered_at": 123.0,
                        },
                        {
                            "tag": f"password={marker}",
                            "context_id": "safe-context",
                            "source_text": "must be dropped",
                            "embedding_dimensions": 16,
                            "spike_indices": [2],
                            "neuron_indices": [2],
                        },
                        {
                            "tag": "secret-context-trace",
                            "context_id": f"api_key={marker}",
                            "source_text": "must be dropped",
                            "embedding_dimensions": 16,
                            "spike_indices": [3],
                            "neuron_indices": [3],
                        },
                    ],
                    "unknown_secret_field": f"token={marker}",
                }
            ),
            encoding="utf-8",
        )

        backend = SpikingAttentionBackend(
            dimension=16,
            num_neurons=12,
            compile_graph=False,
            state_path=self.state_path,
        )

        rewritten_text = self.state_path.read_text(encoding="utf-8")
        rewritten = json.loads(rewritten_text)
        entries = backend.list_memory(context_id="safe-context")["entries"]

        self.assertNotIn(marker, rewritten_text)
        self.assertEqual(backend.context_overrides, {"safe-context": False})
        self.assertEqual(set(backend.cortex_sessions), {"safe-session"})
        self.assertEqual([entry["tag"] for entry in entries], ["safe-trace"])
        self.assertIn("[REDACTED_SECRET]", entries[0]["source_text"])
        self.assertEqual(entries[0]["metadata"]["api_key"], "[REDACTED_SECRET]")
        self.assertNotIn("registered_traces", rewritten)
        self.assertNotIn("unknown_secret_field", rewritten)
        self.assertFalse(backend.global_enabled)
        self.assertEqual(self.state_path.stat().st_mode & 0o777, 0o600)

    def test_cortex_close_survives_stale_backend_runtime_persist(self):
        backend_a = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        first = backend_a.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Stale process first session.",
            mode="strict",
        )
        second = backend_a.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Stale process second session.",
            mode="strict",
        )

        backend_b = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend_b.close_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            session_id=first["session_id"],
            reason="closed-by-fresh-process",
        )
        backend_b.close_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            session_id=second["session_id"],
            reason="closed-by-fresh-process",
        )

        # Simulates a long-running dashboard/backend persisting an unrelated
        # setting after another process closed the sessions.
        backend_a.set_enabled(True, context_id="demo")

        backend_c = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        state = backend_c.get_cortex_state(context_id="demo", agent_id="codex")

        self.assertEqual(state["active_session_count"], 0)
        self.assertEqual(backend_c.cortex_sessions[first["session_id"]]["status"], "closed")
        self.assertEqual(backend_c.cortex_sessions[second["session_id"]]["status"], "closed")

    def test_agent_context_hydration_includes_cortex_state(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        session = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Hydrate with governed memory.",
            mode="strict",
        )
        backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id=session["session_id"],
            trace_type="decision",
            truth_posture="operator-confirmed",
            text="Cortex hydration must expose active goals, decisions, and risks.",
            evidence={"source": "unit-test"},
        )

        hydrated = backend.hydrate_agent_context(
            context_id="demo",
            agent_id="codex",
            prompt="governed memory",
        )

        self.assertIn("cortex_state", hydrated)
        self.assertGreaterEqual(hydrated["cortex_state"]["typed_memory_counts"]["decision"], 1)
        self.assertIn("## Cortex Governor", hydrated["briefing_markdown"])
        self.assertIn("Active Sessions", hydrated["briefing_markdown"])

    def test_public_memory_read_surface_preserves_dashboard_contracts(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        registered = backend.register_trace(
            tag="public-memory-surface",
            embedding=backend.embed_text("Public memory surface"),
            context_id="demo",
            source_text="Public memory surface",
            metadata={"source": "unit-test"},
        )

        entry = backend.get_memory_entry(registered["memory_id"])
        vector_entry = backend.get_memory_entry(
            registered["memory_id"],
            include_vectors=True,
        )
        recall_contexts = backend.resolve_recall_contexts(
            context_id="demo",
            recall_scope="local",
        )
        revision = backend.memory_entries_revision(
            context_ids=[record["context_id"] for record in recall_contexts],
        )
        audit = backend.audit_semantic_indexes(
            context_id="demo",
            sample_limit=5,
        )

        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry["memory_id"], registered["memory_id"])
        self.assertEqual(entry["source_text"], "Public memory surface")
        self.assertNotIn("spike_indices", entry)
        self.assertIn("spike_count", entry)
        self.assertIsNotNone(vector_entry)
        assert vector_entry is not None
        self.assertIn("spike_indices", vector_entry)
        self.assertEqual(
            [record["context_id"] for record in recall_contexts],
            ["demo", "global"],
        )
        self.assertEqual(revision["entry_count"], 1)
        self.assertTrue(revision["revision"])
        self.assertEqual(audit["status"], "ready")
        self.assertTrue(audit["snapshot_stable"])

    def test_public_client_cortex_ownership_surface_is_scoped_and_persisted(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        entered = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Exercise the public client Cortex lifecycle.",
            recall_mode="disabled",
        )
        attached = backend.attach_client_cortex_session(
            context_id="demo",
            agent_id="codex",
            session_id=entered["session_id"],
            client_bridge_session_id="unit-test-bridge",
            owner_pid=os.getpid(),
            owner_ppid=os.getppid(),
            owner_started_at=time.time(),
        )

        self.assertEqual(attached["lease_kind"], "mcp-client")
        self.assertEqual(
            attached["client_bridge_session_id"],
            "unit-test-bridge",
        )
        with self.assertRaisesRegex(ValueError, "client bridge mismatch"):
            backend.finish_client_cortex_session(
                context_id="demo",
                agent_id="codex",
                session_id=entered["session_id"],
                client_bridge_session_id="different-bridge",
            )

        finished = backend.finish_client_cortex_session(
            context_id="demo",
            agent_id="codex",
            session_id=entered["session_id"],
            client_bridge_session_id="unit-test-bridge",
            reason="unit-test-complete",
        )
        state = backend.get_cortex_state(context_id="demo", agent_id="codex")

        self.assertEqual(finished["status"], "finished")
        self.assertEqual(finished["finish_reason"], "unit-test-complete")
        self.assertEqual(state["active_session_count"], 0)

    def test_late_client_finish_overrides_orphan_and_survives_reload(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        entered = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Finish after automatic orphan maintenance.",
            recall_mode="disabled",
        )
        child = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
        child.wait(timeout=5)
        owner_started_at = time.time() - 60.0
        backend.attach_client_cortex_session(
            context_id="demo",
            agent_id="codex",
            session_id=entered["session_id"],
            client_bridge_session_id="late-finish-bridge",
            owner_pid=child.pid,
            owner_ppid=os.getpid(),
            owner_started_at=owner_started_at,
        )
        ownership = backend.orphaned_mcp_cortex_session_candidates()
        maintenance = backend.reap_confirmed_orphaned_cortex_sessions(
            ownerships=ownership
        )
        orphaned = dict(backend.cortex_sessions[entered["session_id"]])
        caller_finished_at = orphaned["updated_at"] - 30.0

        finished = backend.finish_client_cortex_session(
            context_id="demo",
            agent_id="codex",
            session_id=entered["session_id"],
            client_bridge_session_id="late-finish-bridge",
            reason="late-wrapper-exit",
            finished_at=caller_finished_at,
        )
        reloaded = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        persisted = reloaded.cortex_sessions[entered["session_id"]]

        self.assertEqual(maintenance["reaped_count"], 1)
        self.assertEqual(orphaned["status"], "orphaned")
        self.assertIn("orphan_reason", orphaned)
        self.assertEqual(finished["status"], "finished")
        self.assertEqual(finished["finished_at"], caller_finished_at)
        self.assertGreaterEqual(finished["updated_at"], orphaned["updated_at"])
        self.assertNotIn("orphan_reason", finished)
        self.assertEqual(persisted["status"], "finished")
        self.assertEqual(persisted["finished_at"], caller_finished_at)
        self.assertNotIn("orphan_reason", persisted)

    def test_cortex_state_scans_beyond_visible_limit_for_typed_counts(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        session = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Keep governed memory visible with a small UI limit.",
            mode="strict",
        )
        backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id=session["session_id"],
            trace_type="validation",
            truth_posture="test-validated",
            text="Cortex typed counts must survive newer non-cortex graph entries.",
            evidence={"source": "unit-test", "tests": ["tests.test_backend"]},
        )
        for index in range(8):
            backend.register_text_trace(
                tag=f"ordinary-memory-{index}",
                context_id="demo",
                text=f"Ordinary newer memory {index} should not hide cortical counts.",
                metadata={"source": "unit-test"},
            )

        state = backend.get_cortex_state(context_id="demo", agent_id="codex", limit=2)

        self.assertGreaterEqual(state["typed_memory_counts"]["validation"], 1)
        self.assertLessEqual(len(state["working_memory"]), 2)

    def test_cortex_orphan_maintenance_reaps_only_dead_mcp_owner(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        dead_session = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Represent a wrapped MCP client process.",
            mode="strict",
        )
        live_session = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex-live",
            task="Represent a live wrapped MCP client process.",
            mode="strict",
        )
        non_mcp_session = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="operator",
            task="Represent a non-MCP governed session.",
            mode="strict",
        )
        child = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
        child.wait(timeout=5)
        raw_dead_session = dict(
            backend.cortex_sessions[dead_session["session_id"]]
        )
        raw_dead_session.update(
            {
                "lease_kind": "mcp-client",
                "owner_pid": child.pid,
                "owner_started_at": time.time(),
                "client_bridge_session_id": "unit-test-dead-bridge",
            }
        )
        backend.cortex_sessions[dead_session["session_id"]] = (
            backend._normalize_cortex_session(raw_dead_session)
        )
        raw_live_session = dict(
            backend.cortex_sessions[live_session["session_id"]]
        )
        raw_live_session.update(
            {
                "lease_kind": "mcp-client",
                "owner_pid": os.getpid(),
                "owner_started_at": time.time(),
                "client_bridge_session_id": "unit-test-live-bridge",
            }
        )
        backend.cortex_sessions[live_session["session_id"]] = (
            backend._normalize_cortex_session(raw_live_session)
        )
        backend._persist_runtime_state()

        state_before = backend.get_cortex_state(context_id="demo")
        self.assertEqual(state_before["active_session_count"], 3)
        self.assertEqual(
            backend.cortex_sessions[dead_session["session_id"]]["status"],
            "active",
        )
        candidates = backend.orphaned_mcp_cortex_session_candidates()
        self.assertEqual(
            [item["session_id"] for item in candidates],
            [dead_session["session_id"]],
        )

        maintenance = backend.reap_orphaned_cortex_sessions(context_id="demo")
        state = backend.get_cortex_state(context_id="demo")

        self.assertEqual(state["active_session_count"], 2)
        self.assertEqual(maintenance["reaped_count"], 1)
        self.assertEqual(
            maintenance["session_ids"],
            [dead_session["session_id"]],
        )
        self.assertEqual(
            backend.cortex_sessions[dead_session["session_id"]]["status"],
            "orphaned",
        )
        self.assertEqual(
            backend.cortex_sessions[live_session["session_id"]]["status"],
            "active",
        )
        self.assertEqual(
            backend.cortex_sessions[non_mcp_session["session_id"]]["status"],
            "active",
        )

    def test_process_probe_treats_only_esrch_as_definitely_missing(self):
        with patch.object(os, "kill", side_effect=ProcessLookupError()):
            self.assertFalse(SpikingAttentionBackend._process_is_alive(12345))
        with patch.object(os, "kill", side_effect=OSError(errno.ESRCH, "missing")):
            self.assertFalse(SpikingAttentionBackend._process_is_alive(12345))
        with patch.object(os, "kill", side_effect=PermissionError(errno.EPERM, "denied")):
            self.assertTrue(SpikingAttentionBackend._process_is_alive(12345))
        with patch.object(os, "kill", side_effect=OSError(errno.EIO, "unknown")):
            self.assertTrue(SpikingAttentionBackend._process_is_alive(12345))
        self.assertTrue(SpikingAttentionBackend._process_is_alive(0))

    def test_orphan_reap_rolls_back_in_memory_when_persistence_fails(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        entered = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Keep active if orphan persistence fails.",
            recall_mode="disabled",
        )
        child = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
        child.wait(timeout=5)
        backend.attach_client_cortex_session(
            context_id="demo",
            agent_id="codex",
            session_id=entered["session_id"],
            client_bridge_session_id="rollback-bridge",
            owner_pid=child.pid,
            owner_ppid=os.getpid(),
            owner_started_at=time.time() - 60.0,
        )
        ownerships = backend.orphaned_mcp_cortex_session_candidates()

        with patch.object(
            backend,
            "_persist_runtime_state",
            side_effect=RuntimeError("fixture persistence failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "fixture persistence failure"):
                backend.reap_confirmed_orphaned_cortex_sessions(
                    ownerships=ownerships
                )

        self.assertEqual(
            backend.cortex_sessions[entered["session_id"]]["status"],
            "active",
        )
        self.assertNotIn(
            "orphan_reason",
            backend.cortex_sessions[entered["session_id"]],
        )

    def test_unknown_process_probe_never_becomes_orphan_candidate(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        entered = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Treat an indeterminate owner probe conservatively.",
            recall_mode="disabled",
        )
        backend.attach_client_cortex_session(
            context_id="demo",
            agent_id="codex",
            session_id=entered["session_id"],
            client_bridge_session_id="unknown-probe-bridge",
            owner_pid=12345,
            owner_ppid=0,
            owner_started_at=time.time() - 60.0,
        )

        with patch.object(os, "kill", side_effect=OSError(errno.EIO, "unknown")):
            candidates = backend.orphaned_mcp_cortex_session_candidates()

        self.assertEqual(candidates, [])
        self.assertEqual(
            backend.cortex_sessions[entered["session_id"]]["status"],
            "active",
        )

    def test_moderate_cortex_trace_promotes_demotes_and_prunes(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        session = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Moderate a cortical trace.",
            mode="strict",
        )
        committed = backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id=session["session_id"],
            trace_type="assumption",
            truth_posture="inferred",
            text="This assumption needs operator moderation.",
            confidence=0.42,
        )

        promoted = backend.moderate_cortex_trace(
            context_id="demo",
            memory_id=committed["memory_id"],
            action="promote",
            reason="operator verified",
        )
        demoted = backend.moderate_cortex_trace(
            context_id="demo",
            memory_id=committed["memory_id"],
            action="demote",
            reason="operator marked stale",
        )
        pruned = backend.moderate_cortex_trace(
            context_id="demo",
            memory_id=committed["memory_id"],
            action="prune",
            reason="operator removed trace",
            confirm=True,
        )
        state = backend.get_cortex_state(context_id="demo", agent_id="codex")

        self.assertEqual(promoted["action"], "moderate-cortex-trace")
        self.assertEqual(promoted["moderation_action"], "promote")
        self.assertGreaterEqual(promoted["trace"]["confidence"], 0.9)
        self.assertEqual(promoted["trace"]["truth_posture"], "operator-confirmed")
        self.assertEqual(demoted["moderation_action"], "demote")
        self.assertLessEqual(demoted["trace"]["confidence"], 0.35)
        self.assertEqual(demoted["trace"]["truth_posture"], "stale")
        self.assertTrue(pruned["prune"]["result"]["deleted"])
        self.assertNotIn("assumption", state["typed_memory_counts"])

    def test_cortex_prune_requires_explicit_confirmation(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        committed = backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id="moderation-session",
            trace_type="assumption",
            truth_posture="inferred",
            text="This trace should require explicit confirmation before prune.",
            confidence=0.42,
        )

        with self.assertRaisesRegex(ValueError, "confirm"):
            backend.moderate_cortex_trace(
                context_id="demo",
                memory_id=committed["memory_id"],
                action="prune",
                reason="missing confirmation",
            )

        still_present = backend.memory_store.get_entry(committed["memory_id"])
        self.assertIsNotNone(still_present)

    def test_test_validated_cortex_commit_requires_concrete_evidence(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )

        with self.assertRaisesRegex(ValueError, "concrete validation evidence"):
            backend.commit_cortical_trace(
                context_id="demo",
                agent_id="codex",
                session_id="validation-session",
                trace_type="validation",
                truth_posture="test-validated",
                text="This claim lacks a concrete validation artifact.",
                evidence={"source": "unit-test"},
            )

        with self.assertRaisesRegex(ValueError, "concrete validation evidence"):
            backend.commit_cortical_trace(
                context_id="demo",
                agent_id="codex",
                session_id="validation-session",
                trace_type="validation",
                truth_posture="test-validated",
                text="Secret-only output is not surviving validation evidence.",
                evidence={"output": "sk-proj-" + ("A" * 64)},
            )

        with self.assertRaisesRegex(ValueError, "concrete validation evidence"):
            backend.commit_cortical_trace(
                context_id="demo",
                agent_id="codex",
                session_id="validation-session",
                trace_type="validation",
                truth_posture="test-validated",
                text="A stripped raw digest is not validation evidence.",
                evidence={"output": "raw_content_sha256: " + ("a" * 64)},
            )

        with self.assertRaisesRegex(ValueError, "concrete validation evidence"):
            backend.commit_cortical_trace(
                context_id="demo",
                agent_id="codex",
                session_id="validation-session",
                trace_type="validation",
                truth_posture="test-validated",
                text="An unserializable placeholder is not validation evidence.",
                evidence={"output": object()},
            )

        committed = backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id="validation-session",
            trace_type="validation",
            truth_posture="test-validated",
            text="This claim includes a concrete validation artifact.",
            evidence={"tests": ["tests.test_backend"], "command": "python -m unittest"},
        )

        self.assertEqual(committed["truth_posture"], "test-validated")
        self.assertGreaterEqual(committed["confidence"], 0.85)

    def test_capture_conversation_creates_event_graph_and_context_deployment(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )

        capture = backend.capture_conversation(
            text=(
                "User asked that future Codex conversations appear in the graph. "
                "Codex added a durable capture path for session notes. "
                "Operators can prune sensitive or partial information later."
            ),
            context_id="demo",
            source_tag="codex-session",
            speaker="codex",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=20)
        deployments = backend.list_context_events(context_id="demo", limit=10)

        self.assertGreaterEqual(capture["event_count"], 2)
        self.assertTrue(capture["agent_deployment"]["published"])
        self.assertEqual(capture["agent_deployment"]["event_type"], "conversation-capture")
        self.assertGreaterEqual(graph["relationship_summary"]["temporal"], 1)
        self.assertTrue(
            all(
                entry["metadata"].get("conversation_capture") is True
                for entry in graph["entries"]
                if entry["tag"].startswith("codex-session-event")
            )
        )
        self.assertEqual(
            deployments["events"][-1]["payload"]["source_tag"],
            "codex-session",
        )

    def test_capture_conversation_automates_context_namespace_and_typed_nodes(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )

        capture = backend.capture_conversation(
            text=(
                "Thread: Namespace automation release. "
                "Goal: automatically create visible contextual memory namespaces. "
                "Objective: grow graph nodes for each new topic, feature, goal, and event. "
                "Event: user began the namespace automation feature and expects nodes to grow."
            ),
            context_id="demo",
            source_tag="namespace-session",
            speaker="codex",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=40)
        deployments = backend.list_context_events(context_id="demo", limit=10)
        namespace = capture["context_namespace"]
        typed_entries = [
            entry
            for entry in graph["entries"]
            if entry["metadata"].get("context_automation") is True
        ]
        typed_memory_types = {
            entry["metadata"].get("context_memory_type")
            for entry in typed_entries
        }
        namespace_relationships = [
            relationship
            for relationship in graph["relationships"]
            if relationship["relation_type"] == "namespace_contains"
        ]

        self.assertEqual(namespace["namespace_id"], "namespace-automation-release")
        self.assertGreaterEqual(namespace["node_count"], 5)
        self.assertIn("namespace", typed_memory_types)
        self.assertIn("topic", typed_memory_types)
        self.assertIn("goal", typed_memory_types)
        self.assertIn("objective", typed_memory_types)
        self.assertIn("event", typed_memory_types)
        self.assertGreaterEqual(len(namespace_relationships), 4)
        self.assertTrue(
            any(
                entry["metadata"].get("context_namespace")
                == "namespace-automation-release"
                for entry in graph["entries"]
                if entry["tag"].startswith("namespace-session-event")
            )
        )
        self.assertEqual(
            deployments["events"][-1]["payload"]["context_namespace"]["namespace_id"],
            "namespace-automation-release",
        )

    def test_capture_conversation_adds_surface_node_details_and_relationship_labels(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )

        backend.capture_conversation(
            text=(
                "Thread: Surface detail release. "
                "Goal: add granular shorthand labels to graph memory nodes. "
                "Objective: related-topic searches should recall semantic facets, not only event tags. "
                "Event: user inspected spike nodes and asked for fine surface detail."
            ),
            context_id="demo",
            source_tag="surface-session",
            speaker="codex",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=40)
        detailed_entries = [
            entry
            for entry in graph["entries"]
            if entry["metadata"].get("context_namespace") == "surface-detail-release"
        ]
        namespace_relationships = [
            relationship
            for relationship in graph["relationships"]
            if relationship["relation_type"] == "namespace_contains"
        ]
        recall = backend.query(
            backend.embed_text("fine grained related topic search facets"),
            context_id="demo",
        )

        self.assertTrue(detailed_entries)
        self.assertTrue(
            all(entry["metadata"].get("display_label") for entry in detailed_entries)
        )
        self.assertTrue(
            all(entry["metadata"].get("display_summary") for entry in detailed_entries)
        )
        self.assertTrue(
            all(entry["metadata"].get("semantic_facets") for entry in detailed_entries)
        )
        self.assertTrue(namespace_relationships)
        self.assertTrue(
            all(relationship.get("source_label") for relationship in namespace_relationships)
        )
        self.assertTrue(
            all(relationship.get("target_label") for relationship in namespace_relationships)
        )
        self.assertIn("label=", recall)
        self.assertIn("facets=", recall)
        self.assertIn("surface", recall.lower())

    def test_query_text_uses_surface_facets_for_related_topic_recall(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        backend.capture_conversation(
            text=(
                "Thread: Surface detail release. "
                "Goal: make graph nodes expose short semantic labels, summaries, and facets. "
                "Objective: related-topic recall should show why nodes matched instead of only raw event tags."
            ),
            context_id="demo",
            source_tag="surface-session",
            speaker="codex",
        )
        backend.capture_conversation(
            text=(
                "Thread: Startup boundary noise. "
                "Event: clients ended and reported generic recall statistics."
            ),
            context_id="demo",
            source_tag="client-session-boundary",
            speaker="codex",
        )

        recall = backend.query_text(
            "surface detail semantic facets related topic",
            context_id="demo",
        )

        self.assertIn("Surface detail release", recall)
        self.assertIn("facets=", recall)
        self.assertIn("semantic", recall.lower())

    def test_query_text_ranks_fresh_concrete_operational_trace_before_broad_summary(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        old_registration = backend.register_text_trace(
            tag="old-readiness-summary",
            text=(
                "SYNAPSE-S2 Monday readiness covers default topology, App Connect, "
                "Codex, Cursor, Claude installed state, W_lateral, W_syn, estimated "
                "neurons, and operator evidence."
            ),
            context_id="demo",
            metadata={
                "display_label": (
                    "SYNAPSE-S2 Monday readiness default topology App Connect "
                    "Codex Cursor Claude installed W_lateral W_syn estimated neurons"
                ),
                "semantic_facets": [
                    (
                        "default topology app connect codex cursor claude installed "
                        "w_lateral w_syn estimated neurons"
                    )
                ],
            },
        )
        backend.register_text_trace(
            tag="fresh-raised-topology-evidence",
            text=(
                "SYNAPSE-S2 default topology now uses 8192 neurons with an estimated "
                "288 MB substrate. W_lateral and W_syn sit inside the raised memory "
                "envelope. App Connect Codex and Cursor were tested; Claude is not installed."
            ),
            context_id="demo",
            metadata={"source": "unit-test"},
        )

        query_text = (
            "8192 neurons 288 MB W_lateral W_syn App Connect Codex Cursor "
            "Claude not installed default topology estimated"
        )
        recall = backend.query_text(query_text, context_id="demo")
        candidates = backend._surface_text_recall_candidates(
            context="demo",
            prompt_text=query_text,
        )
        scored_by_tag = {str(candidate["tag"]): candidate for candidate in candidates}
        fresh_candidate = scored_by_tag["fresh-raised-topology-evidence"]
        old_candidate = scored_by_tag["old-readiness-summary"]

        self.assertIn("fresh-raised-topology-evidence", recall)
        self.assertIn("old-readiness-summary", recall)
        self.assertIn("fresh-raised-topology-evidence", recall.split(" / ")[0])
        self.assertGreater(
            fresh_candidate["score"],
            old_candidate["score"],
        )
        self.assertIn(
            "8192",
            fresh_candidate["metadata"]["surface_text_overlap"],
        )
        self.assertIn(
            "288",
            fresh_candidate["metadata"]["surface_text_overlap"],
        )

        spike_heavy_old_candidate = backend.memory_store.get_entry(
            old_registration["memory_id"]
        )
        self.assertIsNotNone(spike_heavy_old_candidate)
        spike_heavy_old_candidate = dict(spike_heavy_old_candidate)
        spike_heavy_old_candidate["score"] = 0.96
        merged = backend._merge_surface_text_recall_candidates(
            context="demo",
            prompt_text=query_text,
            candidates=[spike_heavy_old_candidate],
        )
        self.assertEqual(merged[0]["tag"], "fresh-raised-topology-evidence")

    def test_surface_merge_does_not_bury_concrete_subfact_under_spike_only_summary(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        old_registration = backend.register_text_trace(
            tag="old-spike-heavy-summary",
            text=(
                "SYNAPSE-S2 Monday readiness covers default topology, App Connect, "
                "Codex, Cursor, Claude installed state, and estimated neurons."
            ),
            context_id="demo",
            metadata={
                "semantic_facets": [
                    "default topology app connect codex cursor claude installed estimated neurons"
                ],
            },
        )
        backend.register_text_trace(
            tag="fresh-topology-array-evidence",
            text=(
                "Default topology uses 8192 neurons and 288 MB. "
                "W_lateral and W_syn sit inside the raised envelope."
            ),
            context_id="demo",
            metadata={"source": "unit-test"},
        )
        query_text = (
            "8192 neurons 288 MB W_lateral W_syn App Connect Codex Cursor "
            "Claude not installed default topology estimated"
        )
        spike_heavy_old_candidate = backend.memory_store.get_entry(
            old_registration["memory_id"]
        )
        self.assertIsNotNone(spike_heavy_old_candidate)
        spike_heavy_old_candidate = dict(spike_heavy_old_candidate)
        spike_heavy_old_candidate["score"] = 0.96

        merged = backend._merge_surface_text_recall_candidates(
            context="demo",
            prompt_text=query_text,
            candidates=[spike_heavy_old_candidate],
        )

        self.assertEqual(merged[0]["tag"], "fresh-topology-array-evidence")

    def test_repeated_conversation_captures_keep_distinct_event_nodes(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )

        first = backend.capture_conversation(
            text="Thread: Repeated captures. Event: first retained memory must remain.",
            context_id="demo",
            source_tag="codex-session",
            speaker="codex",
        )
        second = backend.capture_conversation(
            text="Thread: Repeated captures. Event: second retained memory must be additive.",
            context_id="demo",
            source_tag="codex-session",
            speaker="codex",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=80)
        event_entries = [
            entry
            for entry in graph["entries"]
            if entry["tag"].startswith("codex-session-event")
        ]
        event_text = " ".join(entry["source_text"] for entry in event_entries)

        self.assertNotEqual(
            first["events"][0]["memory_id"],
            second["events"][0]["memory_id"],
        )
        self.assertGreaterEqual(len(event_entries), 2)
        self.assertIn("first retained memory", event_text)
        self.assertIn("second retained memory", event_text)

    def test_capture_conversation_replays_same_capture_id_without_new_effects_or_embeddings(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        capture_id = "s2cap_" + ("a" * 32)
        request = {
            "text": (
                "Thread: Exactly once replay. "
                "Event: a producer may retry after losing the first response."
            ),
            "context_id": "demo",
            "source_tag": "exactly-once",
            "speaker": "codex",
            "capture_id": capture_id,
        }

        first = backend.capture_conversation(**request)
        first_counts = self._capture_storage_counts(backend)
        original_embed = backend.embed_text_payload

        def unexpected_embed(*_args, **_kwargs):
            raise AssertionError("committed replay must resolve before embeddings")

        backend.embed_text_payload = unexpected_embed
        try:
            replay = backend.capture_conversation(**request)
        finally:
            backend.embed_text_payload = original_embed

        self.assertFalse(first["idempotent_replay"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["protocol"], "capture.v2")
        self.assertEqual(replay["capture_protocol"], "capture.v2")
        self.assertEqual(replay["capture_id"], capture_id)
        self.assertTrue(replay["receipt_compact"])
        self.assertEqual(replay["event_count"], first["event_count"])
        self.assertEqual(
            replay["relationship_count"],
            first["relationship_count"],
        )
        self.assertNotIn("events", replay)
        self.assertEqual(
            replay["agent_deployment"]["event_id"],
            first["agent_deployment"]["event_id"],
        )
        self.assertEqual(self._capture_storage_counts(backend), first_counts)
        self.assertNotIn("request_fingerprint", replay)

    def test_capture_conversation_rejects_capture_id_conflict_without_new_effects(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        capture_id = "s2cap_" + ("b" * 32)
        backend.capture_conversation(
            text="Thread: Capture conflict. Event: the original durable request.",
            context_id="demo",
            source_tag="conflict",
            speaker="codex",
            capture_id=capture_id,
        )
        committed_counts = self._capture_storage_counts(backend)

        with self.assertRaisesRegex(ValueError, "different capture request"):
            backend.capture_conversation(
                text="Thread: Capture conflict. Event: a different payload is rejected.",
                context_id="demo",
                source_tag="conflict",
                speaker="codex",
                capture_id=capture_id,
            )

        self.assertEqual(self._capture_storage_counts(backend), committed_counts)

    def test_capture_conversation_same_content_with_distinct_ids_creates_distinct_occurrences(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        request = {
            "text": (
                "Thread: Distinct occurrences. "
                "Event: identical text can represent two intentional captures."
            ),
            "context_id": "demo",
            "source_tag": "occurrence",
            "speaker": "codex",
        }

        first = backend.capture_conversation(
            **request,
            capture_id="s2cap_" + ("c" * 32),
        )
        second = backend.capture_conversation(
            **request,
            capture_id="s2cap_" + ("d" * 32),
        )

        self.assertEqual(first["sequence_id"], second["sequence_id"])
        self.assertNotEqual(
            first["events"][0]["memory_id"],
            second["events"][0]["memory_id"],
        )
        self.assertNotEqual(
            first["agent_deployment"]["event_id"],
            second["agent_deployment"]["event_id"],
        )
        self.assertEqual(self._capture_storage_counts(backend)[-1], 2)

    def test_capture_conversation_lost_response_replays_committed_receipt_and_refreshes_cache(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        capture_id = "s2cap_" + ("e" * 32)
        request = {
            "text": (
                "Thread: Lost response. "
                "Event: SQLite commits before the transport response disappears."
            ),
            "context_id": "demo",
            "source_tag": "lost-response",
            "speaker": "codex",
            "capture_id": capture_id,
        }
        real_commit = backend.memory_store.commit_capture_plan

        def commit_then_drop_response(**kwargs):
            real_commit(**kwargs)
            raise ConnectionError("simulated response loss after commit")

        backend.memory_store.commit_capture_plan = commit_then_drop_response
        try:
            with self.assertRaisesRegex(ConnectionError, "response loss"):
                backend.capture_conversation(**request)
        finally:
            backend.memory_store.commit_capture_plan = real_commit
        committed_counts = self._capture_storage_counts(backend)

        replay = backend.capture_conversation(**request)

        self.assertTrue(replay["idempotent_replay"])
        self.assertTrue(replay["receipt_compact"])
        self.assertEqual(self._capture_storage_counts(backend), committed_counts)
        self.assertTrue(
            any(
                trace.get("metadata", {}).get("capture_id") == capture_id
                for trace in backend.registered_traces
            )
        )

    def test_capture_batch_coalesces_runtime_refreshes(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        refreshes: list[str] = []
        backend._surface_recall_cache["stale"] = {"value": True}

        with patch.object(
            backend,
            "_refresh_registered_traces",
            side_effect=lambda: refreshes.append("traces"),
        ), patch.object(
            backend,
            "_persist_runtime_state",
            side_effect=lambda: refreshes.append("runtime"),
        ), patch.object(
            backend,
            "_mark_activity",
            side_effect=lambda: refreshes.append("activity"),
        ):
            with backend.capture_batch():
                backend._refresh_after_capture(committed_new_operation=False)
                with backend.capture_batch():
                    backend._refresh_after_capture(
                        committed_new_operation=True
                    )
                self.assertEqual(refreshes, [])
                self.assertIn("stale", backend._surface_recall_cache)

        self.assertEqual(refreshes, ["traces", "runtime", "activity"])
        self.assertEqual(backend._surface_recall_cache, {})

    def test_replay_capture_operation_avoids_reobserving_dynamic_input(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        capture_id = "s2cap_" + ("5" * 32)
        first = backend.capture_conversation(
            text="Thread: Dynamic adapter. Event: the first observed surface is durable.",
            context_id="demo",
            source_tag="app-connect",
            speaker="operator",
            capture_id=capture_id,
        )
        committed_counts = self._capture_storage_counts(backend)

        replay = backend.replay_capture_operation(
            capture_id,
            context_id="demo",
            source_tag="app-connect",
            speaker="operator",
        )

        self.assertIsNotNone(replay)
        self.assertTrue(replay["idempotent_replay"])
        self.assertTrue(replay["receipt_compact"])
        self.assertEqual(replay["event_count"], first["event_count"])
        self.assertNotIn("events", replay)
        self.assertEqual(self._capture_storage_counts(backend), committed_counts)
        self.assertIsNone(
            backend.replay_capture_operation(
                "s2cap_" + ("6" * 32),
                context_id="demo",
                source_tag="app-connect",
                speaker="operator",
            )
        )
        with self.assertRaisesRegex(ValueError, "different capture producer"):
            backend.replay_capture_operation(
                capture_id,
                context_id="other-context",
                source_tag="app-connect",
                speaker="operator",
            )

    def test_capture_conversation_replay_after_prune_does_not_resurrect_data(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        capture_id = "s2cap_" + ("f" * 32)
        request = {
            "text": "Thread: Governed prune. Event: this occurrence is removed by policy.",
            "context_id": "demo",
            "source_tag": "prune-replay",
            "speaker": "codex",
            "capture_id": capture_id,
        }
        first = backend.capture_conversation(**request)
        memory_id = str(first["events"][0]["memory_id"])
        deployment_event_id = int(first["agent_deployment"]["event_id"])
        backend.memory_store.delete_entry(
            context_id="demo",
            memory_id=memory_id,
        )
        backend.memory_store.delete_context_event(
            context_id="demo",
            event_id=deployment_event_id,
        )
        governed_counts = self._capture_storage_counts(backend)

        replay = backend.capture_conversation(**request)

        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(
            replay["agent_deployment"]["event_id"],
            deployment_event_id,
        )
        self.assertIsNone(backend.memory_store.get_entry(memory_id))
        self.assertNotIn(
            deployment_event_id,
            {
                int(event["event_id"])
                for event in backend.memory_store.list_context_events(
                    context_id="demo",
                    limit=100,
                )
            },
        )
        self.assertEqual(self._capture_storage_counts(backend), governed_counts)

    def test_capture_conversation_store_fault_rolls_back_every_planned_effect(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        capture_id = "s2cap_" + ("1" * 32)
        request = {
            "text": (
                "Thread: Atomic capture. "
                "Goal: all graph and delivery rows commit together. "
                "Event: a fault after entry writes must roll everything back."
            ),
            "context_id": "demo",
            "source_tag": "atomic-capture",
            "speaker": "codex",
            "capture_id": capture_id,
        }
        baseline = self._capture_storage_counts(backend)
        real_commit = backend.memory_store.commit_capture_plan

        def commit_with_fault(**kwargs):
            def fail_after_entries(stage):
                if stage == "after_entries":
                    raise RuntimeError("injected capture transaction fault")

            return real_commit(**kwargs, fault_hook=fail_after_entries)

        backend.memory_store.commit_capture_plan = commit_with_fault
        try:
            with self.assertRaisesRegex(RuntimeError, "transaction fault"):
                backend.capture_conversation(**request)
        finally:
            backend.memory_store.commit_capture_plan = real_commit

        self.assertEqual(self._capture_storage_counts(backend), baseline)
        committed = backend.capture_conversation(**request)
        self.assertFalse(committed["idempotent_replay"])
        self.assertEqual(self._capture_storage_counts(backend)[-1], 1)

    def test_capture_conversation_committed_success_survives_runtime_refresh_failure(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        capture_id = "s2cap_" + ("3" * 32)
        original_persist = backend._persist_runtime_state

        def fail_runtime_refresh():
            raise OSError("simulated repairable runtime cache failure")

        backend._persist_runtime_state = fail_runtime_refresh
        try:
            capture = backend.capture_conversation(
                text=(
                    "Thread: Authoritative receipt. "
                    "Event: SQLite success survives a repairable JSON refresh failure."
                ),
                context_id="demo",
                source_tag="runtime-refresh",
                speaker="codex",
                capture_id=capture_id,
            )
        finally:
            backend._persist_runtime_state = original_persist

        self.assertFalse(capture["idempotent_replay"])
        self.assertIsNotNone(backend.memory_store.get_capture_operation(capture_id))
        self.assertEqual(self._capture_storage_counts(backend)[-1], 1)

    def test_capture_conversation_drops_raw_secret_digest_from_plan_and_receipt(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        raw_text = (
            "Thread: Capture secret boundary. "
            "Event: api_key=sk-secret-digest-value must be redacted.\n"
            "passphrase=correct horse battery synthetic-secret-phrase\n"
            "auth_header=Bearer synthetic-auth-header-secret"
        )
        raw_digest = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        capture_id = "s2cap_" + ("2" * 32)

        capture = backend.capture_conversation(
            text=raw_text,
            context_id="demo",
            source_tag="secret-boundary",
            speaker="codex",
            capture_id=capture_id,
            metadata={
                "input_sha256": raw_digest,
                "content_sha256": "content-equality-oracle",
                "api_key": "plain-metadata-secret",
                "auth_header": "Bearer metadata-auth-secret",
            },
        )
        operation = backend.memory_store.get_capture_operation(capture_id)
        graph = backend.list_memory_graph(context_id="demo", limit=100)
        combined = json.dumps(
            {"capture": capture, "operation": operation, "graph": graph},
            sort_keys=True,
            default=str,
        )

        self.assertNotIn("sk-secret-digest-value", combined)
        self.assertNotIn("plain-metadata-secret", combined)
        self.assertNotIn("synthetic-secret-phrase", combined)
        self.assertNotIn("synthetic-auth-header-secret", combined)
        self.assertNotIn("metadata-auth-secret", combined)
        self.assertNotIn("content-equality-oracle", combined)
        self.assertNotIn(raw_digest, combined)
        self.assertIn("[REDACTED_SECRET]", combined)

    def test_capture_conversation_raw_input_digest_is_not_part_of_idempotency_identity(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        capture_id = "s2cap_" + ("4" * 32)
        request = {
            "text": "Thread: Digest omission. Event: raw digests are not durable identity.",
            "context_id": "demo",
            "source_tag": "digest-omission",
            "speaker": "codex",
            "capture_id": capture_id,
        }
        backend.capture_conversation(
            **request,
            metadata={"input_sha256": "9" * 64},
        )

        replay = backend.capture_conversation(**request)

        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(self._capture_storage_counts(backend)[-1], 1)

    def test_capture_conversation_rejects_noncanonical_producer_capture_ids(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        for invalid_capture_id in (
            "",
            "S2CAP_" + ("a" * 32),
            "s2cap_abc",
            " s2cap_" + ("a" * 32),
        ):
            with self.subTest(capture_id=invalid_capture_id):
                with self.assertRaisesRegex(ValueError, "canonical"):
                    backend.capture_conversation(
                        text="Thread: Invalid identity. Event: reject malformed IDs.",
                        capture_id=invalid_capture_id,
                    )

    def test_direct_capture_redacts_memory_and_context_bus_payloads(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )

        capture = backend.capture_conversation(
            text=(
                "Thread: Secret redaction. "
                "Event: direct capture includes api_key=sk-direct-secret123 and "
                '{"client_secret": "plain-direct-secret"}.'
            ),
            context_id="demo",
            source_tag="direct-secret",
            speaker="codex",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=30)
        deployments = backend.list_context_events(context_id="demo", limit=10)
        combined_graph_text = json.dumps(graph, sort_keys=True, default=str)
        combined_deployment_text = json.dumps(deployments, sort_keys=True, default=str)
        combined_response_text = json.dumps(capture, sort_keys=True, default=str)

        self.assertNotIn("sk-direct-secret123", combined_graph_text)
        self.assertNotIn("plain-direct-secret", combined_graph_text)
        self.assertNotIn("sk-direct-secret123", combined_deployment_text)
        self.assertNotIn("plain-direct-secret", combined_deployment_text)
        self.assertNotIn("sk-direct-secret123", combined_response_text)
        self.assertNotIn("plain-direct-secret", combined_response_text)
        self.assertIn("[REDACTED_SECRET]", combined_graph_text)

    def test_surface_recall_cache_invalidates_when_memory_changes(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=6,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        backend.capture_conversation(
            text=(
                "Thread: Surface recall cache. "
                "Goal: cache normalized graph surfaces without stale query results."
            ),
            context_id="demo",
            source_tag="surface-cache",
            speaker="codex",
        )

        first = backend.query_text("surface recall cache stale query", context_id="demo")
        self.assertIn("Surface recall cache", first)
        self.assertTrue(backend._surface_recall_cache)

        backend.register_text_trace(
            tag="cache-hardening-follow-up",
            text="Surface recall cache invalidation should expose new hardening follow-up nodes immediately.",
            context_id="demo",
            metadata={"source": "unit-test"},
        )
        second = backend.query_text("surface recall cache hardening follow-up", context_id="demo")

        self.assertIn("cache-hardening-follow-up", second)

    def test_prune_memory_removes_nodes_edges_modes_and_context_events(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        capture = backend.capture_conversation(
            text=(
                "First event must be removable. "
                "Second event remains available. "
                "Shared event terms create associative links."
            ),
            context_id="demo",
            source_tag="prune-session",
            speaker="user",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=20)
        first_entry = next(
            entry for entry in graph["entries"] if entry["tag"].startswith("prune-session-event")
        )
        first_relationship = graph["relationships"][0]

        with self.assertRaisesRegex(TypeError, "confirm"):
            backend.prune_memory(
                context_id="demo",
                target_type="relationship",
                relationship_id=first_relationship["relationship_id"],
                reason="direct callers cannot bypass confirmation",
            )
        self.assertTrue(
            any(
                relationship["relationship_id"]
                == first_relationship["relationship_id"]
                for relationship in backend.list_memory_graph(
                    context_id="demo",
                    limit=20,
                )["relationships"]
            )
        )

        edge_deletion = backend.prune_memory(
            context_id="demo",
            target_type="relationship",
            relationship_id=first_relationship["relationship_id"],
            reason="bad edge",
            confirm=True,
        )
        entry_deletion = backend.prune_memory(
            context_id="demo",
            target_type="event",
            memory_id=first_entry["memory_id"],
            reason="sensitive event",
            confirm=True,
        )
        mode_deletion = backend.prune_memory(
            context_id="demo",
            target_type="temporal",
            reason="drop temporal links",
            confirm=True,
        )
        event_deletion = backend.prune_memory(
            context_id="demo",
            target_type="context_event",
            event_id=capture["agent_deployment"]["event_id"],
            reason="remove deployment record",
            confirm=True,
        )
        remaining_graph = backend.list_memory_graph(context_id="demo", limit=20)
        remaining_deployments = backend.list_context_events(context_id="demo", limit=10)

        self.assertEqual(edge_deletion["action"], "prune-memory")
        self.assertTrue(edge_deletion["result"]["deleted"])
        self.assertTrue(entry_deletion["result"]["deleted"])
        self.assertGreaterEqual(mode_deletion["result"]["deleted_relationship_count"], 0)
        self.assertTrue(event_deletion["result"]["deleted"])
        self.assertNotIn(
            first_entry["memory_id"],
            [entry["memory_id"] for entry in remaining_graph["entries"]],
        )
        self.assertNotIn(
            capture["agent_deployment"]["event_id"],
            [event["event_id"] for event in remaining_deployments["events"]],
        )

    def test_temporal_prune_removes_typed_context_sequence_edges(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.capture_conversation(
            text=(
                "Thread: Temporal cleanup. "
                "Goal: remove wrong order. "
                "Objective: typed sequence edges should prune with temporal links. "
                "Event: operator requested cleanup."
            ),
            context_id="demo",
            source_tag="temporal-cleanup",
            speaker="codex",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=80)

        deletion = backend.prune_memory(
            context_id="demo",
            target_type="temporal",
            reason="drop all temporal ordering",
            confirm=True,
        )
        remaining_graph = backend.list_memory_graph(context_id="demo", limit=80)

        self.assertGreaterEqual(graph["relationship_summary"]["by_type"]["typed_context_sequence"], 1)
        self.assertGreaterEqual(graph["relationship_summary"]["temporal"], 1)
        self.assertTrue(deletion["result"]["deleted"])
        self.assertNotIn(
            "typed_context_sequence",
            remaining_graph["relationship_summary"]["by_type"],
        )

    def test_quick_pruning_decays_weights_and_resets_membrane(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.state = {
            "mem": mx.ones((6,)),
            "spk": mx.ones((6,)),
        }
        before_weight = float(backend.W_syn[0, 0])

        status = backend.run_quick_pruning()

        self.assertEqual(status["mode"], "quick-pruning")
        self.assertEqual(status["trigger"], "manual")
        self.assertTrue(status["gpu_non_llm"])
        self.assertTrue(status["within_60ms_budget"])
        self.assertLessEqual(abs(float(backend.W_syn[0, 0])), abs(before_weight) + 1e-6)
        self.assertEqual(backend.state["mem"].tolist(), [0.0] * 6)

    def test_quick_pruning_uses_lazy_scalar_decay_for_large_substrates(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
            quick_pruning_eager_decay_elements=1,
        )
        before_weight = float(backend.W_syn[0, 0])

        status = backend.run_quick_pruning()

        self.assertEqual(status["decay_strategy"], "lazy-scalar")
        self.assertEqual(float(backend.W_syn[0, 0]), before_weight)
        self.assertLess(status["W_syn_decay_multiplier"], 1.0)
        self.assertLess(status["W_lateral_decay_multiplier"], 1.0)
        self.assertTrue(status["within_60ms_budget"])

    def test_query_auto_runs_quick_pruning_after_configured_interval(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            default_top_k=2,
            compile_graph=False,
            state_path=self.state_path,
            quick_pruning_interval_seconds=300.0,
        )
        backend.last_pruning_monotonic = time.monotonic() - 301.0

        result = backend.query(mx.array([0.0, 2.0, 7.0, -1.0]), context_id="demo")

        self.assertIn("No registered historical context matched", result)
        self.assertNotIn("demo::neuron-", result)
        self.assertEqual(backend.quick_pruning_count, 1)
        self.assertEqual(backend.last_maintenance["mode"], "quick-pruning")
        self.assertEqual(backend.last_maintenance["trigger"], "auto:query")

    def test_deep_sleep_consolidation_builds_semantic_hierarchy(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.memory_mapping = {
            1: "demo::neuron-000001",
            2: "demo::neuron-000002",
        }
        backend.active_traces = mx.array([0.0, 2.0, 1.5, 0.0, 0.0, 0.0])

        status = backend.run_deep_sleep_consolidation()

        self.assertEqual(status["mode"], "deep-sleep")
        self.assertIn("demo", backend.semantic_hierarchy)
        self.assertEqual(
            backend.semantic_hierarchy["demo"]["members"],
            ["demo::neuron-000001", "demo::neuron-000002"],
        )

    def test_deep_sleep_reports_all_proposal_consolidation_phases(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.register_trace(
            tag="proposal-memory",
            embedding=mx.array([0.0, 1.0, 9.0, 2.0]),
            context_id="proposal",
            metadata={"source": "unit-test"},
            source_text="Proposal lifecycle coverage.",
        )

        status = backend.run_deep_sleep_consolidation()
        phase_names = [phase["name"] for phase in status["phases"]]

        self.assertEqual(status["phase_count"], 7)
        self.assertEqual(
            phase_names,
            [
                "connection-weight-decay",
                "synaptic-clustering",
                "semantic-merging",
                "threshold-rescoring",
                "trace-promotion",
                "relationship-extraction",
                "neurogenesis",
            ],
        )
        self.assertEqual(status["phases"][4]["promoted_trace_count"], 1)
        self.assertEqual(status["phases"][5]["contexts"], ["proposal"])

    def test_deep_sleep_consolidation_includes_relationship_graph(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.ingest_text_events(
            text=(
                "Apple Silicon MLX compiles spiking kernels into Metal. "
                "Sparse spike populations recall local context. "
                "Procurement reviews supplier budget exposure and contract risk."
            ),
            context_id="board-demo",
            source_tag="sleep-brief",
            surprise_threshold=0.58,
            min_segment_sentences=1,
        )

        status = backend.run_deep_sleep_consolidation()

        self.assertEqual(status["mode"], "deep-sleep")
        self.assertIn("relationships", backend.semantic_hierarchy["board-demo"])
        self.assertGreaterEqual(
            backend.semantic_hierarchy["board-demo"]["relationship_count"],
            1,
        )

    def test_namespace_detail_is_deterministic_isolated_and_keeps_all_ganglia_visible(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        namespace = backend.register_text_trace(
            tag="alpha-namespace",
            text="Namespace anchor password=alpha-drill-secret.",
            context_id="alpha",
            metadata={
                "context_memory_type": "namespace",
                "display_label": "Alpha api_key=sk-alpha-drill-secret",
                "embedding_provider": {"model_id": "token=alpha-model-secret"},
            },
        )
        member = backend.register_text_trace(
            tag="alpha-member",
            text="Member text api_key=sk-member-drill-secret.",
            context_id="alpha",
            metadata={
                "context_memory_type": "event",
                "context_namespace": "alpha-topic",
                "semantic_facets": ["zeta", "alpha", "zeta"],
            },
        )
        other_cluster = backend.register_text_trace(
            tag="alpha-objective",
            text="Objective password=objective-drill-secret.",
            context_id="alpha",
            metadata={"context_memory_type": "objective"},
        )
        fallback = backend.register_text_trace(
            tag="alpha-fallback",
            text="Fallback isolated stored memory.",
            context_id="alpha",
            metadata={},
        )
        backend.memory_store.upsert_relationship(
            context_id="alpha",
            source_memory_id=namespace["memory_id"],
            target_memory_id=member["memory_id"],
            relation_type="namespace_contains",
            weight=1.0,
            evidence={"api_key=sk-evidence-key-secret": "password=evidence-secret"},
        )
        backend.memory_store.upsert_relationship(
            context_id="alpha",
            source_memory_id=member["memory_id"],
            target_memory_id=other_cluster["memory_id"],
            relation_type="temporal_next",
            weight=0.8,
        )
        backend.register_text_trace(
            tag="beta-secret",
            text="Other context password=beta-drill-secret.",
            context_id="beta",
            metadata={"context_memory_type": "event"},
        )
        before_alpha = backend.memory_store.stats(context_id="alpha")
        before_beta = backend.memory_store.stats(context_id="beta")

        first = backend.list_namespace_detail(
            context_id="alpha",
            level="neurons",
            limit=1,
        )
        repeated = backend.list_namespace_detail(
            context_id="alpha",
            level="neurons",
            limit=1,
        )
        complete = backend.list_namespace_detail(
            context_id="alpha",
            level="neurons",
            limit=20,
        )
        selected_cluster_id = next(
            cluster["cluster_id"]
            for cluster in complete["clusters"]
            if other_cluster["memory_id"] in cluster["member_memory_id_sample"]
        )
        selected = backend.list_namespace_detail(
            context_id="alpha",
            level="neurons",
            cluster_id=selected_cluster_id,
            limit=20,
        )
        ganglion = backend.list_namespace_detail(
            context_id="alpha",
            level="ganglion",
            limit=20,
        )
        bounded_ganglion = backend.list_namespace_detail(
            context_id="alpha",
            level="ganglion",
            limit=1,
        )
        after_alpha = backend.memory_store.stats(context_id="alpha")
        after_beta = backend.memory_store.stats(context_id="beta")
        rendered = json.dumps(complete, sort_keys=True)

        self.assertEqual(first, repeated)
        self.assertTrue(first["read_only"])
        self.assertFalse(first["automatic_cross_namespace_write"])
        self.assertEqual(first["counts"]["memory_total"], 4)
        self.assertEqual(first["counts"]["eligible_nodes"], 4)
        self.assertEqual(first["counts"]["returned_nodes"], 1)
        self.assertGreaterEqual(first["counts"]["returned_clusters"], 3)
        self.assertTrue(first["truncation"]["nodes"]["truncated"])
        self.assertEqual(first["truncation"]["clusters"]["returned"], 3)
        self.assertEqual(first["truncation"]["clusters"]["limit"], 500)
        self.assertEqual({node["context_id"] for node in complete["nodes"]}, {"alpha"})
        self.assertEqual(
            {node["memory_id"] for node in complete["nodes"]},
            {
                namespace["memory_id"],
                member["memory_id"],
                other_cluster["memory_id"],
                fallback["memory_id"],
            },
        )
        assigned_memory_ids = [
            memory_id
            for cluster in complete["clusters"]
            for memory_id in cluster["member_memory_id_sample"]
        ]
        self.assertEqual(len(assigned_memory_ids), len(set(assigned_memory_ids)))
        self.assertEqual(set(assigned_memory_ids), {node["memory_id"] for node in complete["nodes"]})
        self.assertEqual(selected["selected_cluster_id"], selected_cluster_id)
        self.assertEqual(selected["counts"]["eligible_clusters"], 1)
        self.assertEqual({node["cluster_id"] for node in selected["nodes"]}, {selected_cluster_id})
        self.assertEqual({cluster["cluster_id"] for cluster in selected["clusters"]}, {selected_cluster_id})
        self.assertEqual(ganglion["level"], "ganglion")
        self.assertEqual(ganglion["nodes"], [])
        self.assertEqual(ganglion["counts"]["eligible_nodes"], 0)
        self.assertEqual(ganglion["counts"]["returned_nodes"], 0)
        self.assertTrue(ganglion["read_only"])
        self.assertFalse(ganglion["automatic_cross_namespace_write"])
        self.assertEqual(ganglion["counts"]["eligible_edges"], 1)
        self.assertEqual(ganglion["counts"]["returned_edges"], 1)
        aggregate = ganglion["edges"][0]
        self.assertEqual(aggregate["edge_type"], "temporal_next")
        self.assertEqual(aggregate["weight"], 0.8)
        self.assertEqual(aggregate["average_weight"], 0.8)
        self.assertEqual(aggregate["stored_relationship_count"], 1)
        self.assertFalse(ganglion["counts"]["eligible_edges_is_lower_bound"])
        self.assertLessEqual(
            complete["response_bytes"],
            mlx_backend.NAMESPACE_DETAIL_RESPONSE_MAX_BYTES,
        )
        self.assertEqual(
            complete["response_bytes"],
            len(canonical_json_bytes(complete)),
        )
        self.assertEqual(
            complete["truncation"]["response_byte_limit"],
            mlx_backend.NAMESPACE_DETAIL_RESPONSE_MAX_BYTES,
        )
        oversized = {
            **complete,
            "nodes": [
                {
                    **complete["nodes"][index % len(complete["nodes"])],
                    "node_id": f"oversized-node-{index:05d}",
                    "memory_id": f"oversized-memory-{index:05d}",
                    "excerpt": "x" * 240,
                }
                for index in range(4_000)
            ],
            "counts": {
                **complete["counts"],
                "eligible_nodes": 4_000,
                "returned_nodes": 4_000,
            },
            "truncation": {
                **complete["truncation"],
                "nodes": {
                    **complete["truncation"]["nodes"],
                    "total": 4_000,
                    "returned": 4_000,
                    "truncated": False,
                },
            },
            "response_bytes": 0,
        }
        bounded = backend._bound_namespace_detail_payload(oversized)
        self.assertLessEqual(
            len(canonical_json_bytes(bounded)),
            mlx_backend.NAMESPACE_DETAIL_RESPONSE_MAX_BYTES,
        )
        self.assertEqual(
            bounded["response_bytes"],
            len(canonical_json_bytes(bounded)),
        )
        self.assertLess(
            len(
                canonical_json_bytes(
                    {
                        "protocol_version": "synapse-core.v1",
                        "request_id": "req-namespace-detail-budget",
                        "caller": "namespace-detail-budget-test",
                        "operation": "list_namespace_detail",
                        "request_fingerprint": "b" * 64,
                        "operation_sequence": 1,
                        "server_time_unix_ms": 1,
                        "identity": {
                            "authority_epoch": "epoch-test",
                            "config_fingerprint": "a" * 64,
                            "build_id": "source-test",
                        },
                        "ok": True,
                        "result": bounded,
                        "error": None,
                    }
                )
            ),
            DEFAULT_MAX_FRAME_BYTES,
        )
        self.assertTrue(bounded["truncation"]["response_trimmed_for_bytes"])
        self.assertTrue(bounded["truncation"]["nodes"]["truncated"])
        self.assertLess(len(bounded["nodes"]), len(oversized["nodes"]))
        fixed_point_payload = {
            **complete,
            "clusters": [],
            "edges": [],
            "nodes": [
                {
                    **complete["nodes"][0],
                    "excerpt": "",
                }
            ],
            "response_bytes": 0,
        }
        fixed_point_base = len(canonical_json_bytes(fixed_point_payload))
        fixed_point_payload["nodes"][0]["excerpt"] = "x" * max(
            0,
            100_000 - fixed_point_base,
        )
        fixed_point = backend._bound_namespace_detail_payload(
            fixed_point_payload
        )
        self.assertEqual(
            fixed_point["response_bytes"],
            len(canonical_json_bytes(fixed_point)),
        )

        ganglion_clusters = [
            {
                **ganglion["clusters"][index % len(ganglion["clusters"])],
                "cluster_id": f"pressure-cluster-{index:04d}",
                "node_id": f"pressure-cluster-{index:04d}",
            }
            for index in range(300)
        ]
        ganglion_edges = [
            {
                **ganglion["edges"][0],
                "edge_id": f"pressure-edge-{index:04d}",
                "source_id": ganglion_clusters[index % 299]["cluster_id"],
                "target_id": ganglion_clusters[(index % 299) + 1]["cluster_id"],
            }
            for index in range(1_200)
        ]
        pressured_ganglion = backend._bound_namespace_detail_payload(
            {
                **ganglion,
                "clusters": ganglion_clusters,
                "nodes": [],
                "edges": ganglion_edges,
                "counts": {
                    **ganglion["counts"],
                    "eligible_clusters": len(ganglion_clusters),
                    "returned_clusters": len(ganglion_clusters),
                    "eligible_edges": len(ganglion_edges),
                    "returned_edges": len(ganglion_edges),
                },
                "truncation": {
                    **ganglion["truncation"],
                    "clusters": {
                        "total": len(ganglion_clusters),
                        "returned": len(ganglion_clusters),
                        "truncated": False,
                    },
                    "nodes": {
                        "total": 0,
                        "returned": 0,
                        "truncated": False,
                    },
                    "edges": {
                        "total": len(ganglion_edges),
                        "returned": len(ganglion_edges),
                        "truncated": False,
                    },
                },
                "response_bytes": 0,
            }
        )
        self.assertEqual(pressured_ganglion["nodes"], [])
        self.assertGreater(len(pressured_ganglion["edges"]), 0)
        self.assertEqual(
            pressured_ganglion["response_bytes"],
            len(canonical_json_bytes(pressured_ganglion)),
        )
        returned_cluster_ids = {
            cluster["cluster_id"]
            for cluster in pressured_ganglion["clusters"]
        }
        self.assertTrue(
            all(
                edge["source_id"] in returned_cluster_ids
                and edge["target_id"] in returned_cluster_ids
                for edge in pressured_ganglion["edges"]
            )
        )
        self.assertTrue(bounded_ganglion["truncation"]["truncated"])
        self.assertTrue(bounded_ganglion["truncation"]["clusters"]["truncated"])
        self.assertTrue(bounded_ganglion["truncation"]["edges"]["truncated"])
        self.assertFalse(
            bounded_ganglion["truncation"]["source_scan"]["entries_truncated"]
        )
        self.assertFalse(
            bounded_ganglion["truncation"]["source_scan"][
                "relationships_truncated"
            ]
        )
        self.assertNotIn("alpha-drill-secret", rendered)
        self.assertNotIn("member-drill-secret", rendered)
        self.assertNotIn("objective-drill-secret", rendered)
        self.assertNotIn("evidence-secret", rendered)
        self.assertNotIn("evidence-key-secret", rendered)
        self.assertNotIn("alpha-model-secret", rendered)
        self.assertNotIn("beta-drill-secret", rendered)
        self.assertEqual(before_alpha, after_alpha)
        self.assertEqual(before_beta, after_beta)
        with self.assertRaisesRegex(ValueError, "level must"):
            backend.list_namespace_detail(context_id="alpha", level="unknown")
        with self.assertRaisesRegex(ValueError, "cluster_id is only valid"):
            backend.list_namespace_detail(
                context_id="alpha",
                level="cortex",
                cluster_id=selected_cluster_id,
            )
        with self.assertRaisesRegex(ValueError, "unknown cluster_id"):
            backend.list_namespace_detail(
                context_id="alpha",
                level="neurons",
                cluster_id="s2g_not-in-alpha",
            )

    def test_idle_maintenance_runs_deep_sleep_after_idle_threshold(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
            idle_deep_sleep_seconds=1.0,
        )
        backend.memory_mapping = {
            1: "idle::neuron-000001",
            2: "idle::neuron-000002",
        }
        backend.active_traces = mx.array([0.0, 2.0, 1.5, 0.0, 0.0, 0.0])
        backend.last_activity_monotonic = time.monotonic() - 2.0

        status = backend.run_idle_maintenance()

        self.assertEqual(status["mode"], "deep-sleep")
        self.assertEqual(status["trigger"], "idle-threshold")
        self.assertTrue(status["maintenance_run"])
        self.assertEqual(status["phase_count"], 7)
        self.assertEqual(backend.deep_sleep_count, 1)


if __name__ == "__main__":
    unittest.main()

"""Phase-5B3a dormant held-root model-static evidence tests.

All filesystem work is confined to owner-private ``/private/tmp`` fixtures.
The packet never reads or writes live SYNAPSE-S2 state, configuration, model
caches, processes, services, selectors, journals, or activation state.
"""

import ast
import copy
import hashlib
import importlib.util
import inspect
import json
import os
import stat
import sys
import unittest
from unittest import mock


_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SOURCE = os.path.join(
    _REPO, "scripts", "release_environment_model_static_evidence.py"
)
_STORAGE_TEST_SOURCE = os.path.join(
    _REPO, "tests", "test_release_environment_storage.py"
)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from scripts import release_environment_evidence as b2  # noqa: E402
from scripts import release_environment_model_static_evidence as b3  # noqa: E402


def _load_storage_test_support():
    spec = importlib.util.spec_from_file_location(
        "_phase5b3_storage_test_support", _STORAGE_TEST_SOURCE
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


storage_support = _load_storage_test_support()


PINNED_SOURCE_SHA256 = (
    "01102b6feb296013b07cdffe484d6f83d97a621062d7a1d3a5332c66e890f09e"
)
PINNED_CONTRACT_ID = (
    "environment-model-static-contract-"
    "a7e5668083829acde97890fcbc554db59478fdf989b127db2fa03735d111bc37"
)
CONTRACT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-MODEL-STATIC-CONTRACT\0v1\0"
)
FRAGMENT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-MODEL-STATIC-FRAGMENT\0v1\0"
)
RESULT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-MODEL-STATIC-RESULT\0v1\0"
)
MODEL_REVISION = "6c3ae70858513f1a78e9cdca3cae330d9075cd2a"
MODEL_ID = "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ"
MODEL_PAYLOADS = {
    "config.json": b'{"model_type":"synthetic"}',
    "model.safetensors": b"synthetic-model-weights",
}


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def domain_hash(domain, value):
    return hashlib.sha256(domain + canonical(value)).hexdigest()


def source_hash(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def model_plan_fixture():
    entries = [
        {
            "path": name,
            "kind": "file",
            "mode": "0600",
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        for name, payload in sorted(MODEL_PAYLOADS.items())
    ]
    return {
        "schema": b2.MODEL_SNAPSHOT_PLAN_SCHEMA,
        "environment_policy_id": b2.ENVIRONMENT_POLICY_ID,
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "cache_root_relative": b2.MODEL_CACHE_ROOT_RELATIVE,
        "snapshot_root_relative": b2.MODEL_SNAPSHOT_ROOT_PREFIX + MODEL_REVISION,
        "entry_count": len(entries),
        "total_bytes": sum(entry["size"] for entry in entries),
        "entries": entries,
    }


def core_config_fixture(environment_root):
    root = "/private/tmp/synapse-model-static-evidence"
    return {
        "protocol_version": "synapse-core-config.v1",
        "socket_path": root + "/data/core/service.sock",
        "state_path": root + "/data/runtime_state.json",
        "memory_path": root + "/data/memory.db",
        "capture_root": root + "/capture",
        "dimension": 1024,
        "num_neurons": 8192,
        "default_top_k": 256,
        "recall_count": 10,
        "quick_pruning_interval_seconds": 300.0,
        "idle_deep_sleep_seconds": 1800.0,
        "embedding_provider_name": "mlx-neural",
        "embedding_neural_model_id": MODEL_ID,
        "embedding_neural_revision": MODEL_REVISION,
        "embedding_neural_cache_dir": (
            environment_root + "/share/synapse-s2/model-cache-v1"
        ),
        "embedding_neural_pooling": "mean",
        "embedding_neural_max_tokens": 512,
        "embedding_neural_normalize": True,
        "embedding_neural_local_files_only": True,
        "mlx_device": "gpu",
        "require_native": True,
        "capture_poll_seconds": 2.0,
        "capture_max_files": 50,
        "poll_transcript_sources": False,
        "max_transcript_bytes": 256_000,
        "max_frame_bytes": 1_048_576,
        "authority_timeout_seconds": 15.0,
    }


def runtime_config_fixture(core):
    return {
        "schema": "synapse-s2.embedding-runtime-config.v1",
        "provider": "mlx-neural-v1",
        "model_id": core["embedding_neural_model_id"],
        "revision": core["embedding_neural_revision"],
        "cache_dir": core["embedding_neural_cache_dir"],
        "pooling": core["embedding_neural_pooling"],
        "max_tokens": core["embedding_neural_max_tokens"],
        "normalize": core["embedding_neural_normalize"],
        "local_files_only": True,
    }


def embedding_space_identity(core):
    identity = {
        "schema": "synapse-s2.embedding-space.v1",
        "provider": "mlx-neural-v1",
        "dimensions": core["dimension"],
        "num_neurons": core["num_neurons"],
        "spike_encoder": "zscore-top-k-v1",
        "default_top_k": core["default_top_k"],
        "neuron_projection": "synaptic-matrix-v1",
        "neural": {
            "model_id": core["embedding_neural_model_id"],
            "revision": core["embedding_neural_revision"],
            "pooling": core["embedding_neural_pooling"],
            "max_tokens": core["embedding_neural_max_tokens"],
            "normalize": core["embedding_neural_normalize"],
        },
    }
    return hashlib.sha256(canonical(identity)).hexdigest()


class ModelStaticFixture:
    def __init__(self, extra_kind=None, configured_cache="held"):
        self.storage = storage_support.StorageFixture()
        self.plan = model_plan_fixture()
        configured_environment_root = self.storage.environment_root
        self.alternate_environment_root = None
        if configured_cache == "alternate":
            self.alternate_environment_root = (
                self.storage.base + "/alternate-environment"
            )
            self.storage._mkdir(self.alternate_environment_root)
            alternate_root = self.alternate_environment_root
            for segment in (
                "share",
                "synapse-s2",
                "model-cache-v1",
                "snapshots",
                MODEL_REVISION,
            ):
                alternate_root += "/" + segment
                self.storage._mkdir(alternate_root)
            self.storage._write(
                alternate_root + "/config.json",
                b'{"model_type":"alternate"}',
                0o600,
            )
            self.storage._write(
                alternate_root + "/model.safetensors",
                b"different-unmeasured-model-weights",
                0o600,
            )
            configured_environment_root = self.alternate_environment_root
        elif configured_cache != "held":
            raise AssertionError(configured_cache)
        self.core = core_config_fixture(configured_environment_root)
        self.runtime = runtime_config_fixture(self.core)
        root = self.storage.operation_root
        for segment in (
            "share",
            "synapse-s2",
            "model-cache-v1",
            "snapshots",
            MODEL_REVISION,
        ):
            root += "/" + segment
            self.storage._mkdir(root)
        self.model_root = root
        for name, payload in MODEL_PAYLOADS.items():
            self.storage._write(root + "/" + name, payload, 0o600)
        if extra_kind == "revision":
            self.storage._mkdir(
                os.path.dirname(root) + "/" + ("7d" * 20)
            )
        elif extra_kind == "forbidden-file":
            self.storage._write(root + "/weights.py", b"pass\n", 0o600)
        plan_sha256 = b2._model_snapshot_plan(self.plan)
        bindings = storage_support.valid_bindings()
        bindings.update(
            {
                "layout_id": self.storage.layout_plan["layout_id"],
                "stage_result_sha256": hashlib.sha256(
                    canonical(self.storage.stage_result)
                ).hexdigest(),
                "stage_journal_head_sha256": self.storage.stage_head,
                "core_config_fingerprint": hashlib.sha256(
                    canonical(self.core)
                ).hexdigest(),
                "embedding_space_identity": embedding_space_identity(self.core),
                "embedding_provider": "mlx-neural",
                "model_id": MODEL_ID,
                "model_revision": MODEL_REVISION,
                "embedding_runtime_config_sha256": hashlib.sha256(
                    canonical(self.runtime)
                ).hexdigest(),
                "expected_model_snapshot_sha256": plan_sha256,
                "environment_policy_id": b2.ENVIRONMENT_POLICY_ID,
            }
        )
        planned = storage_support.release_environment.plan_environment_request(
            **bindings
        )
        if planned["status"] != "planned":
            raise AssertionError(planned)
        old_state = self.storage.state_root
        old_operation = self.storage.operation_root
        self.storage.request = planned["request"]
        self.storage.request_sha256 = planned["request_sha256"]
        self.storage.state_root = (
            self.storage.journal_root
            + "/"
            + storage_support.rs.STATE_ROOT_PREFIX
            + self.storage.request_sha256
        )
        self.storage.operation_name = (
            storage_support.rs.OPERATION_PREFIX + self.storage.request_sha256
        )
        self.storage.operation_root = (
            self.storage.operations_root + "/" + self.storage.operation_name
        )
        os.rename(old_state, self.storage.state_root)
        os.rename(old_operation, self.storage.operation_root)
        self.model_root = (
            self.storage.operation_root
            + "/share/synapse-s2/model-cache-v1/snapshots/"
            + MODEL_REVISION
        )
        finalized = self.storage.finalize()
        if finalized["status"] != "success":
            raise AssertionError(finalized)

    def call(self, **overrides):
        values = {
            "environment_request": self.storage.request,
            "layout_plan": self.storage.layout_plan,
            "stage_result": self.storage.stage_result,
            "planned_core_config": self.core,
            "planned_embedding_runtime_config": self.runtime,
        }
        values.update(overrides)
        return b3.inspect_prebuilt_environment_model_static_evidence(
            self.storage.authority_root,
            self.storage.state_root,
            self.storage.journal_root,
            **values,
        )

    def close(self):
        self.storage.close()


class TestPinnedContract(unittest.TestCase):
    def test_source_and_contract_are_frozen(self):
        self.assertEqual(source_hash(_SOURCE), PINNED_SOURCE_SHA256)
        projection = b3.environment_model_static_contract_projection()
        body = {key: projection[key] for key in b3.CONTRACT_BODY_KEYS}
        self.assertEqual(
            projection["contract_id"],
            "environment-model-static-contract-" + domain_hash(CONTRACT_DOMAIN, body),
        )
        self.assertEqual(projection["contract_id"], PINNED_CONTRACT_ID)
        self.assertEqual(tuple(projection), b3.CONTRACT_KEYS)
        self.assertEqual(projection["upstream_compatibility_profile_version"], 3)
        self.assertEqual(
            tuple(tuple(binding) for binding in projection["model_cache_binding"]),
            b3.MODEL_CACHE_BINDING,
        )
        self.assertEqual(
            tuple(
                tuple(binding)
                for binding in projection["environment_document_bindings"]
            ),
            b3.ENVIRONMENT_DOCUMENT_BINDINGS,
        )
        self.assertIn("layout_plan", projection["environment_fragment_keys"])
        self.assertIn("stage_result", projection["environment_fragment_keys"])

    def test_upstream_pins_are_exact_and_one_way(self):
        source_parent = b3.__file__.rsplit("/", 1)[0]
        self.assertEqual(
            source_hash(source_parent + "/release_environment_storage.py"),
            b3.PHASE5B1_SOURCE_SHA256,
        )
        self.assertEqual(
            source_hash(source_parent + "/release_environment_evidence.py"),
            b3.PHASE5B2_SOURCE_SHA256,
        )
        with open(_SOURCE, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        self.assertNotIn("PHASE5B3_SOURCE_SHA256", names)

    def test_only_producer_has_exact_no_authority_injection_signature(self):
        signature = inspect.signature(
            b3.inspect_prebuilt_environment_model_static_evidence
        )
        self.assertEqual(
            tuple(signature.parameters),
            (
                "environment_authority_root",
                "environment_state_root",
                "stage_journal_root",
                "environment_request",
                "layout_plan",
                "stage_result",
                "planned_core_config",
                "planned_embedding_runtime_config",
            ),
        )
        for forbidden in ("plan", "path", "fd", "observer"):
            self.assertNotIn(forbidden, signature.parameters)
        producers = [
            name
            for name, value in vars(b3).items()
            if callable(value) and not name.startswith("_") and "produce" in name
        ]
        self.assertEqual(producers, [])

    def test_projection_keeps_all_authority_claims_false(self):
        projection = b3.environment_model_static_contract_projection()
        self.assertEqual(
            tuple(projection["fixed_false_result_fields"]),
            b3.FIXED_FALSE_RESULT_FIELDS,
        )
        self.assertIn("no-model-load-or-inference", projection["nonclaims"])
        self.assertIn("no-activation", projection["nonclaims"])
        self.assertNotIn("live_state_accessed", projection["result_keys"])


class TestHeldRootProduction(unittest.TestCase):
    def setUp(self):
        self.fixture = ModelStaticFixture()

    def tearDown(self):
        self.fixture.close()

    def test_golden_fragment_replays_and_preserves_durable_sentinel(self):
        before = self.storage_sentinel()
        result = self.fixture.call()
        self.assertEqual(result["status"], "success", result)
        self.assertEqual(result["reason"], b3.SUCCESS_REASON)
        self.assertTrue(result["document_valid"])
        self.assertTrue(result["held_snapshot_reproved"])
        self.assertTrue(result["model_static_fragment_produced"])
        for key in b3.FIXED_FALSE_RESULT_FIELDS:
            self.assertIs(result[key], False)
        fragment = result["model_static_fragment"]
        self.assertEqual(fragment["static_roles_present"], list(b3.STATIC_ROLES_PRESENT))
        self.assertEqual(fragment["static_roles_pending"], list(b3.STATIC_ROLES_PENDING))
        self.assertIs(fragment["static_evidence_complete"], False)
        environment = fragment["environment"]
        self.assertEqual(environment["layout_plan"], self.fixture.storage.layout_plan)
        self.assertEqual(environment["stage_result"], self.fixture.storage.stage_result)
        manifest_paths = {
            entry["path"] for entry in environment["storage_manifest"]["entries"]
        }
        self.assertIn("pyvenv.cfg", manifest_paths)
        self.assertIn("lib/__pycache__/module.cpython-314.pyc", manifest_paths)
        self.assertEqual(
            environment["storage_request_record"]["operation_fingerprint"],
            environment["storage_prepare_record"]["operation_fingerprint"],
        )
        expected_cache = (
            environment["layout_plan"]["environment_root"]
            + "/"
            + b3.MODEL_CACHE_ROOT_RELATIVE
        )
        model = fragment["model"]["model_manifest"]
        self.assertEqual(
            json.loads(model["core_config_canonical_json"])[
                "embedding_neural_cache_dir"
            ],
            expected_cache,
        )
        self.assertEqual(
            json.loads(model["embedding_runtime_config_canonical_json"])[
                "cache_dir"
            ],
            expected_cache,
        )
        self.assertEqual(model["snapshot_plan"], self.fixture.plan)
        self.assertEqual(
            b2._model_manifest(
                model,
                self.fixture.storage.request,
                fragment["environment"]["environment_request_sha256"],
                fragment["environment"]["storage_digest"],
            ),
            fragment["model"]["model_manifest_sha256"],
        )
        self.assertEqual(result, b3.validate_environment_model_static_result(result))
        self.assertEqual(b3.environment_model_static_result_exit_code(result), 0)
        rendered = json.loads(b3.render_environment_model_static_result(result))
        self.assertEqual(rendered["result_sha256"], result["result_sha256"])
        self.assertEqual(self.storage_sentinel(), before)

    def test_repeat_is_byte_deterministic_and_no_descriptor_escapes(self):
        first = self.fixture.call()
        second = self.fixture.call()
        self.assertEqual(first["status"], "success", first)
        self.assertEqual(first, second)
        encoded = canonical(first)
        self.assertNotIn(b"environment_root_fd", encoded)
        self.assertNotIn(b"snapshot_observer", encoded)

    def test_planned_config_mismatch_is_fixed_blocked(self):
        core = copy.deepcopy(self.fixture.core)
        core["embedding_neural_revision"] = "8e" * 20
        result = self.fixture.call(planned_core_config=core)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], b3.BLOCKED_REASON)
        self.assertIsNone(result["storage_inspect_result"])
        self.assertIsNone(result["model_static_fragment"])

    def test_different_configured_cache_root_is_fixed_blocked(self):
        fixture = ModelStaticFixture(configured_cache="alternate")
        try:
            held_weights = (
                fixture.storage.environment_root
                + "/share/synapse-s2/model-cache-v1/snapshots/"
                + MODEL_REVISION
                + "/model.safetensors"
            )
            configured_weights = (
                fixture.alternate_environment_root
                + "/share/synapse-s2/model-cache-v1/snapshots/"
                + MODEL_REVISION
                + "/model.safetensors"
            )
            with open(held_weights, "rb") as handle:
                held_sha256 = hashlib.sha256(handle.read()).hexdigest()
            with open(configured_weights, "rb") as handle:
                configured_sha256 = hashlib.sha256(handle.read()).hexdigest()
            self.assertNotEqual(held_sha256, configured_sha256)
            with mock.patch.object(b3, "_load_frozen_upstreams") as loader:
                result = fixture.call()
            loader.assert_not_called()
            self.assertEqual(result["status"], "blocked")
            self.assertIsNone(result["storage_inspect_result"])
            self.assertIsNone(result["model_static_fragment"])
        finally:
            fixture.close()

    def test_layout_environment_root_is_replay_bound(self):
        forged = copy.deepcopy(self.fixture.call())
        fragment = forged["model_static_fragment"]
        fragment["environment"]["layout_plan"]["environment_root"] = (
            "/private/tmp/forged-environment"
        )
        fragment["fragment_sha256"] = domain_hash(
            FRAGMENT_DOMAIN,
            {
                key: fragment[key]
                for key in b3.FRAGMENT_KEYS
                if key != "fragment_sha256"
            },
        )
        forged["model_static_fragment_sha256"] = fragment["fragment_sha256"]
        forged["result_sha256"] = domain_hash(
            RESULT_DOMAIN,
            {
                key: forged[key]
                for key in b3.RESULT_KEYS
                if key != "result_sha256"
            },
        )
        replayed = b3.validate_environment_model_static_result(forged)
        self.assertEqual(replayed["status"], "blocked")
        self.assertEqual(b3.environment_model_static_result_exit_code(forged), 3)

    def test_oversize_input_aborts_before_source_or_environment_io(self):
        oversized = {"payload": ["x" * 4096] * 400}
        with mock.patch.object(b3, "_load_frozen_upstreams") as loader:
            result = self.fixture.call(planned_core_config=oversized)
        loader.assert_not_called()
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(result["storage_inspect_result"])

    def test_giant_integer_aborts_before_canonical_allocation_or_io(self):
        hostile = {"value": 2**100_000}
        with mock.patch.object(b3, "_load_frozen_upstreams") as loader:
            result = self.fixture.call(planned_core_config=hostile)
        loader.assert_not_called()
        self.assertEqual(result["status"], "blocked")

    def test_frozen_upstream_source_drift_blocks(self):
        with mock.patch.object(b3, "PHASE5B1_SOURCE_SHA256", "00" * 32):
            result = self.fixture.call()
        self.assertEqual(result["status"], "blocked")

    def test_result_tamper_cannot_render_or_exit_success(self):
        result = self.fixture.call()
        tampered = copy.deepcopy(result)
        tampered["static_evidence_complete"] = True
        tampered["result_sha256"] = domain_hash(
            RESULT_DOMAIN,
            {key: tampered[key] for key in b3.RESULT_KEYS if key != "result_sha256"},
        )
        replayed = b3.validate_environment_model_static_result(tampered)
        self.assertEqual(replayed["status"], "blocked")
        self.assertEqual(b3.environment_model_static_result_exit_code(tampered), 3)
        self.assertEqual(
            b3.render_environment_model_static_result(tampered), b3._RENDER_FALLBACK
        )

    def test_public_hash_rewrite_cannot_bypass_semantic_replay(self):
        forged = copy.deepcopy(self.fixture.call())
        fragment = forged["model_static_fragment"]
        fragment["environment"]["environment_request"]["model_id"] = (
            "mlx-community/forged-model"
        )
        fragment_body = {
            key: fragment[key]
            for key in b3.FRAGMENT_KEYS
            if key != "fragment_sha256"
        }
        fragment["fragment_sha256"] = domain_hash(
            FRAGMENT_DOMAIN, fragment_body
        )
        forged["model_static_fragment_sha256"] = fragment["fragment_sha256"]
        forged["result_sha256"] = domain_hash(
            RESULT_DOMAIN,
            {key: forged[key] for key in b3.RESULT_KEYS if key != "result_sha256"},
        )
        self.assertEqual(
            b3.validate_environment_model_static_result(forged)["status"],
            "blocked",
        )

    def test_nested_b1_extra_field_is_replay_rejected(self):
        forged = copy.deepcopy(self.fixture.call())
        storage = forged["storage_inspect_result"]
        storage["attacker_extra"] = False
        storage["result_sha256"] = domain_hash(
            b3._B1_STORAGE_RESULT_DOMAIN,
            {key: storage[key] for key in storage if key != "result_sha256"},
        )
        forged["result_sha256"] = domain_hash(
            RESULT_DOMAIN,
            {key: forged[key] for key in b3.RESULT_KEYS if key != "result_sha256"},
        )
        self.assertEqual(
            b3.validate_environment_model_static_result(forged)["status"],
            "blocked",
        )

    def test_nested_b1_identity_must_equal_fragment_request(self):
        replacements = {
            "layout_plan_id": "layout-" + ("a1" * 32),
            "product_id": "product-" + ("b2" * 32),
            "policy_id": "inventory-policy-" + ("c3" * 32),
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                forged = copy.deepcopy(self.fixture.call())
                storage = forged["storage_inspect_result"]
                storage[field] = replacement
                storage["result_sha256"] = domain_hash(
                    b3._B1_STORAGE_RESULT_DOMAIN,
                    {
                        key: storage[key]
                        for key in storage
                        if key != "result_sha256"
                    },
                )
                forged["result_sha256"] = domain_hash(
                    RESULT_DOMAIN,
                    {
                        key: forged[key]
                        for key in b3.RESULT_KEYS
                        if key != "result_sha256"
                    },
                )
                self.assertEqual(
                    b3.validate_environment_model_static_result(forged)[
                        "status"
                    ],
                    "blocked",
                )

    def test_b2_valid_model_plan_tree_mismatch_is_replay_rejected(self):
        forged = copy.deepcopy(self.fixture.call())
        fragment = forged["model_static_fragment"]
        environment = fragment["environment"]
        model = fragment["model"]
        request = environment["environment_request"]
        plan = model["model_manifest"]["snapshot_plan"]
        plan["entries"][0]["sha256"] = "ab" * 32
        plan_sha256 = b2._model_snapshot_plan(plan)
        request["expected_model_snapshot_sha256"] = plan_sha256
        request_sha256 = b2._phase5a_request(request)

        request_record = environment["storage_request_record"]
        request_record.update(
            {
                "request": request,
                "request_sha256": request_sha256,
                "operation_id": "operation-" + request_sha256,
            }
        )
        request_record_body = {
            key: request_record[key]
            for key in b2.STORAGE_REQUEST_KEYS
            if key != "request_record_sha256"
        }
        request_record["request_record_sha256"] = b2._domain_hash(
            b2._STORAGE_DOMAINS["request"], request_record_body
        )
        request_record_sha256 = b2._storage_request(
            request_record, request, request_sha256
        )

        manifest = environment["storage_manifest"]
        manifest["request_sha256"] = request_sha256
        manifest["operation_id"] = "operation-" + request_sha256
        manifest_sha256 = b2._tree_manifest(
            manifest, request, request_sha256
        )
        prepare = environment["storage_prepare_record"]
        prepare.update(
            {
                "request_record_sha256": request_record_sha256,
                "request_sha256": request_sha256,
                "operation_id": "operation-" + request_sha256,
                "manifest_sha256": manifest_sha256,
            }
        )
        prepare_body = {
            key: prepare[key]
            for key in b2.STORAGE_PREPARE_KEYS
            if key != "prepare_sha256"
        }
        prepare["prepare_sha256"] = b2._domain_hash(
            b2._STORAGE_DOMAINS["prepare"], prepare_body
        )
        prepare_sha256 = b2._storage_prepare(
            prepare,
            request,
            request_sha256,
            request_record,
            manifest,
            manifest_sha256,
        )
        storage_digest = b2._storage_digest(
            {
                "request_sha256": request_sha256,
                "manifest_sha256": manifest_sha256,
                "prepare_sha256": prepare_sha256,
            }
        )
        environment.update(
            {
                "environment_request_sha256": request_sha256,
                "storage_request_record_sha256": request_record_sha256,
                "storage_manifest_sha256": manifest_sha256,
                "storage_prepare_sha256": prepare_sha256,
                "storage_digest": storage_digest,
            }
        )
        model_manifest = model["model_manifest"]
        model_manifest.update(
            {
                "request_sha256": request_sha256,
                "storage_digest": storage_digest,
                "snapshot_plan_sha256": plan_sha256,
                "post_publication_snapshot_sha256": plan_sha256,
            }
        )
        model["model_manifest_sha256"] = b2._model_manifest(
            model_manifest, request, request_sha256, storage_digest
        )
        fragment_body = {
            key: fragment[key]
            for key in b3.FRAGMENT_KEYS
            if key != "fragment_sha256"
        }
        fragment["fragment_sha256"] = domain_hash(
            FRAGMENT_DOMAIN, fragment_body
        )
        storage_result = forged["storage_inspect_result"]
        storage_result.update(
            {
                "request_sha256": request_sha256,
                "manifest_sha256": manifest_sha256,
                "prepare_sha256": prepare_sha256,
                "storage_digest": storage_digest,
                "operation_id": "operation-" + request_sha256,
            }
        )
        storage_result["result_sha256"] = domain_hash(
            b3._B1_STORAGE_RESULT_DOMAIN,
            {
                key: storage_result[key]
                for key in storage_result
                if key != "result_sha256"
            },
        )
        forged["model_static_fragment_sha256"] = fragment["fragment_sha256"]
        forged["result_sha256"] = domain_hash(
            RESULT_DOMAIN,
            {key: forged[key] for key in b3.RESULT_KEYS if key != "result_sha256"},
        )
        # Every individual B2 document remains valid; only the B3 partial
        # cross-document tree/plan correlation is false.
        self.assertEqual(
            b2._model_manifest(
                model_manifest, request, request_sha256, storage_digest
            ),
            model["model_manifest_sha256"],
        )
        self.assertEqual(
            b3.validate_environment_model_static_result(forged)["status"],
            "blocked",
        )

    def test_observer_descriptor_is_revoked_before_success_escapes(self):
        observed = []
        original = b3._validate_context_and_build_candidate

        def capture(context, *args, **kwargs):
            observed.append(context["environment_root_fd"])
            return original(context, *args, **kwargs)

        with mock.patch.object(
            b3, "_validate_context_and_build_candidate", capture
        ):
            result = self.fixture.call()
        self.assertEqual(result["status"], "success", result)
        self.assertEqual(len(observed), 1)
        with self.assertRaises(OSError):
            os.fstat(observed[0])

    def test_post_scan_tree_drift_is_caught_by_b1_final_reproof(self):
        original = b3._derive_model_snapshot_plan

        def mutate_after_scan(*args, **kwargs):
            value = original(*args, **kwargs)
            path = (
                self.fixture.storage.environment_root
                + "/share/synapse-s2/model-cache-v1/snapshots/"
                + MODEL_REVISION
                + "/config.json"
            )
            with open(path, "ab") as handle:
                handle.write(b"drift")
            return value

        with mock.patch.object(b3, "_derive_model_snapshot_plan", mutate_after_scan):
            result = self.fixture.call()
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(result["model_static_fragment"])

    def test_model_opens_require_nofollow_and_cloexec(self):
        real_open = os.open
        observed = []

        def recording_open(path, flags, *args, **kwargs):
            if path in MODEL_PAYLOADS:
                observed.append((path, flags))
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(b3.os, "open", recording_open):
            result = self.fixture.call()
        self.assertEqual(result["status"], "success", result)
        self.assertEqual({name for name, _flags in observed}, set(MODEL_PAYLOADS))
        for _name, flags in observed:
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_CLOEXEC)

    def test_local_capability_gate_precedes_source_loading(self):
        with mock.patch.object(b3, "_load_frozen_upstreams") as loader:
            with mock.patch.object(b3.sys, "platform", "linux"):
                result = self.fixture.call()
        loader.assert_not_called()
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["reason"], b3.UNSUPPORTED_REASON)

    def test_zero_nofollow_capability_precedes_source_loading(self):
        with mock.patch.object(b3, "_load_frozen_upstreams") as loader:
            with mock.patch.object(b3.os, "O_NOFOLLOW", 0):
                result = self.fixture.call()
        loader.assert_not_called()
        self.assertEqual(result["status"], "unsupported")

    def storage_sentinel(self):
        return self.fixture.storage._snapshot(self.fixture.storage.sentinel_path)


class TestModelSubtreeRefusals(unittest.TestCase):
    def _assert_blocked(self, extra_kind):
        fixture = ModelStaticFixture(extra_kind=extra_kind)
        try:
            result = fixture.call()
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["reason"], b3.BLOCKED_REASON)
            self.assertIsNone(result["model_static_fragment"])
        finally:
            fixture.close()

    def test_extra_revision_is_not_a_fallback_candidate(self):
        self._assert_blocked("revision")

    def test_executable_model_suffix_is_refused(self):
        self._assert_blocked("forbidden-file")


class TestCloseOnce(unittest.TestCase):
    def test_absolute_walk_does_not_retry_ambiguous_close_after_fd_reuse(self):
        real_close = os.close
        real_open = os.open
        calls = {}
        replacement = [None]
        target = [None]

        def injected(fd):
            calls[fd] = calls.get(fd, 0) + 1
            if target[0] is None:
                target[0] = fd
                real_close(fd)
                replacement[0] = real_open("/dev/null", os.O_RDONLY)
                raise OSError(5, "injected ambiguous close")
            return real_close(fd)

        try:
            with mock.patch.object(b3.os, "close", injected):
                with self.assertRaises(b3._Refused):
                    b3._open_absolute_directory("/private/tmp", "close-once")
            self.assertEqual(calls[target[0]], 1)
            os.fstat(replacement[0])
        finally:
            if replacement[0] is not None:
                real_close(replacement[0])

    def test_source_file_close_eio_is_not_retried_and_parent_is_closed(self):
        real_close = os.close
        real_open = os.open
        calls = {}
        target = [None]
        replacement = [None]
        target_calls = [0]

        def injected(fd):
            calls[fd] = calls.get(fd, 0) + 1
            if target[0] is not None and fd == target[0]:
                target_calls[0] += 1
            try:
                is_regular = stat.S_ISREG(os.fstat(fd).st_mode)
            except OSError:
                is_regular = False
            if target[0] is None and is_regular:
                target[0] = fd
                target_calls[0] = 1
                real_close(fd)
                replacement[0] = real_open("/dev/null", os.O_RDONLY)
                raise OSError(5, "injected ambiguous close")
            return real_close(fd)

        parent = os.path.dirname(_SOURCE)
        try:
            with mock.patch.object(b3.os, "close", injected):
                with self.assertRaises(b3._Refused):
                    b3._read_frozen_source(
                        parent,
                        "release_environment_storage.py",
                        b3.PHASE5B1_SOURCE_SHA256,
                        "phase5b1",
                    )
            self.assertIsNotNone(target[0])
            self.assertEqual(target_calls[0], 1)
            os.fstat(replacement[0])
        finally:
            if replacement[0] is not None:
                real_close(replacement[0])


class TestModuleAudit(unittest.TestCase):
    def test_module_has_no_network_process_or_write_surface(self):
        with open(_SOURCE, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertTrue(
            imports.isdisjoint(
                {"socket", "subprocess", "urllib", "requests", "http", "ctypes"}
            )
        )
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(
            calls.isdisjoint(
                {
                    "write",
                    "replace",
                    "rename",
                    "unlink",
                    "remove",
                    "mkdir",
                    "makedirs",
                    "chmod",
                    "system",
                    "popen",
                    "fork",
                    "execve",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()

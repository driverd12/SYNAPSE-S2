"""Independent tests for the pure Phase-5B2a evidence document contract."""

import ast
import builtins
import copy
import hashlib
import importlib.util
import json
import os
import sys
import unittest


_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SOURCE = os.path.join(_REPO, "scripts", "release_environment_evidence.py")
_PHASE5A_SOURCE = os.path.join(_REPO, "scripts", "release_environment.py")
_PHASE5B1_SOURCE = os.path.join(
    _REPO, "scripts", "release_environment_storage.py"
)
sys.path.insert(0, os.path.join(_REPO, "scripts"))

import release_environment as phase5a  # noqa: E402
import release_environment_evidence as evidence  # noqa: E402


PINNED_PHASE5A_SHA256 = (
    "42da38a8710ebdeaaabf11741859f4822a943df3d6b9d8deff2236fa64672308"
)
PINNED_PHASE5B1_SHA256 = (
    "6a7fb7bfa2f0a0d321a424a535d3310d2f37d1f4c7a2b16017d1b12fc5e3f206"
)
PINNED_PHASE5A_CONTRACT_ID = (
    "environment-contract-"
    "fec40398c01456d33b1bf5980b737987d1825fea8194d102af7d0afd939cfe3e"
)
PINNED_PHASE5B1_CONTRACT_ID = (
    "environment-storage-contract-"
    "9d10496d94003ad2d46905f19155de31c48a3834914c60469a739a73298c20aa"
)
PINNED_POLICY_ID = (
    "environment-policy-"
    "dd1e455f357853660c8cda6b2af4503587ff6736c844020d57be3a127c8e8735"
)
PINNED_CONTRACT_ID = (
    "environment-evidence-contract-"
    "eabdbb0f337582b15b5f31a21f243c6784ba051a92907cf4137daf9b41fb1313"
)
PINNED_MODEL_PLAN_SHA256 = (
    "93a03ccfa6ee1306f02b4625f81b0afd07771fcfb7c2600865408e4879dee7c7"
)
PINNED_REQUEST_SHA256 = (
    "fc1a77bce488a520b4b38d720d4872c87581fb3b6bfe09a0f8d61d5df4fcbe14"
)
PINNED_REQUEST_RECORD_SHA256 = (
    "f790c4b9ea3bab576cc8c98aebd962c85c14766ebc95c59fd0445086152e33ed"
)
PINNED_TREE_MANIFEST_SHA256 = (
    "c878568f779a979ec1599d688fe59708cfd37b395c8a729e6caae45135187750"
)
PINNED_PREPARE_SHA256 = (
    "8f6f06c573947f89c5492bd5cbfb867a26bed438d792eae81b5675aa6165e3c5"
)
PINNED_STORAGE_DIGEST = (
    "5214e6794764b09aeb882f996126019dec0c89149da4ca08e99d4656a4e689e4"
)
PINNED_INSTALLED_MANIFEST_SHA256 = (
    "1f5a25f122f6bfd619c340a76577b08e66fa0b5f5865a5f002b4a29325206b60"
)
PINNED_NATIVE_MANIFEST_SHA256 = (
    "8a288abfabdcee69975e5ddfec01650057375b881ebeb8cd4622cbab666bfebc"
)
PINNED_MODEL_MANIFEST_SHA256 = (
    "a91f588bd43722ffc5384bc74be3636fa84c2c28a7d6ce8a611f4b9d38a758f4"
)
PINNED_EVIDENCE_SET_SHA256 = (
    "58676431c07eb79502c8f4b0c18dc0eb1139185f165eac975aa60cf6986bb92e"
)
PINNED_MODEL_RESULT_SHA256 = (
    "43058ebdb16ba045ea9189a790ffc6517b3512b8e98938f349567a5456c67c11"
)
PINNED_EVIDENCE_RESULT_SHA256 = (
    "f301d3d9fc2f88bb41bfac5eec103c90103b9c167df544432a796de096d72220"
)

DOMAINS = {
    "phase5a_request": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-REQUEST\0v1\0",
    "policy": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-POLICY\0v1\0",
    "contract": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-CONTRACT\0v1\0",
    "model_plan": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-MODEL-SNAPSHOT-PLAN\0v1\0"
    ),
    "evidence_set": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-SET\0v1\0",
    "installed": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-"
        b"INSTALLED-DISTRIBUTION-MANIFEST\0v1\0"
    ),
    "native": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-NATIVE-FILE-MANIFEST\0v1\0"
    ),
    "model_manifest": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-MODEL-MANIFEST\0v1\0"
    ),
    "result": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-RESULT\0v1\0",
    "storage_request": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-REQUEST\0v1\0"
    ),
    "tree": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-TREE-MANIFEST\0v1\0"
    ),
    "prepare": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-PREPARE\0v1\0",
    "storage_digest": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-DIGEST\0v1\0"
    ),
}


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def domain_hash(name, value):
    return hashlib.sha256(DOMAINS[name] + canonical(value)).hexdigest()


def raw_sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def source_sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def valid_model_plan():
    entries = [
        {
            "path": "config.json", "kind": "file", "mode": "0600",
            "size": 7, "sha256": "11" * 32,
        },
        {
            "path": "model.safetensors", "kind": "file", "mode": "0600",
            "size": 13, "sha256": "22" * 32,
        },
    ]
    return {
        "schema": evidence.MODEL_SNAPSHOT_PLAN_SCHEMA,
        "environment_policy_id": PINNED_POLICY_ID,
        "model_id": "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ",
        "model_revision": "6c3ae70858513f1a78e9cdca3cae330d9075cd2a",
        "cache_root_relative": "share/synapse-s2/model-cache-v1",
        "snapshot_root_relative": (
            "share/synapse-s2/model-cache-v1/snapshots/"
            "6c3ae70858513f1a78e9cdca3cae330d9075cd2a"
        ),
        "entry_count": len(entries), "total_bytes": 20, "entries": entries,
    }


def valid_core_config(model_plan=None):
    if model_plan is None:
        model_plan = valid_model_plan()
    root = "/private/tmp/synapse-evidence"
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
        "embedding_neural_model_id": model_plan["model_id"],
        "embedding_neural_revision": model_plan["model_revision"],
        "embedding_neural_cache_dir": (
            root + "/environment/share/synapse-s2/model-cache-v1"
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


def valid_runtime_config(core_config):
    return {
        "schema": "synapse-s2.embedding-runtime-config.v1",
        "provider": "mlx-neural-v1",
        "model_id": core_config["embedding_neural_model_id"],
        "revision": core_config["embedding_neural_revision"],
        "cache_dir": core_config["embedding_neural_cache_dir"],
        "pooling": core_config["embedding_neural_pooling"],
        "max_tokens": core_config["embedding_neural_max_tokens"],
        "normalize": core_config["embedding_neural_normalize"],
        "local_files_only": True,
    }


def embedding_space_identity(core_config):
    identity = {
        "schema": "synapse-s2.embedding-space.v1",
        "provider": "mlx-neural-v1",
        "dimensions": core_config["dimension"],
        "num_neurons": core_config["num_neurons"],
        "spike_encoder": "zscore-top-k-v1",
        "default_top_k": core_config["default_top_k"],
        "neuron_projection": "synaptic-matrix-v1",
        "neural": {
            "model_id": core_config["embedding_neural_model_id"],
            "revision": core_config["embedding_neural_revision"],
            "pooling": core_config["embedding_neural_pooling"],
            "max_tokens": core_config["embedding_neural_max_tokens"],
            "normalize": core_config["embedding_neural_normalize"],
        },
    }
    return raw_sha(identity)


def valid_phase5a_request(
    model_plan=None, *, core_document=None, runtime_document=None,
    embedding_identity=None,
):
    if model_plan is None:
        model_plan = valid_model_plan()
    if core_document is None:
        core_document = valid_core_config(model_plan)
    if runtime_document is None:
        runtime_document = valid_runtime_config(core_document)
    if embedding_identity is None:
        embedding_identity = embedding_space_identity(core_document)
    core = canonical(core_document)
    runtime = canonical(runtime_document)
    bindings = {
        "activation_policy_receipt_sha256": "1a" * 32,
        "root_key_id": "ed25519-" + "2b" * 32,
        "trust_generation": 4,
        "trust_bundle_sha256": "3c" * 32,
        "release_envelope_sha256": "4d" * 32,
        "compatibility_ticket_sha256": "5e" * 32,
        "compatibility_result_sha256": "6f" * 32,
        "channel": "stable", "version": "2.14.0", "release_sequence": 12,
        "source_sha": "7a" * 20,
        "candidate_source_build_id": "source-" + "8b" * 12,
        "candidate_product_id": "product-" + "9c" * 32,
        "inventory_policy_id": "inventory-policy-" + "0d" * 32,
        "candidate_dependency_component_id": "component-" + "1e" * 32,
        "surfaces_digest": "2f" * 32,
        "layout_schema": "synapse-s2.installed-layout-contract.v1",
        "layout_mode": "inactive-versioned-v1",
        "layout_contract_id": (
            "layout-contract-"
            "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada"
        ),
        "layout_id": "layout-" + "4b" * 32,
        "stage_result_sha256": "5c" * 32,
        "stage_journal_head_sha256": "6d" * 32,
        "staged_product_id": "product-" + "9c" * 32,
        "staged_source_build_id": "source-" + "8b" * 12,
        "host_id_sha256": "7e" * 32,
        "core_config_fingerprint": hashlib.sha256(core).hexdigest(),
        "embedding_space_identity": embedding_identity,
        "embedding_provider": "mlx-neural",
        "model_id": model_plan["model_id"],
        "model_revision": model_plan["model_revision"],
        "embedding_runtime_config_sha256": hashlib.sha256(runtime).hexdigest(),
        "expected_model_snapshot_sha256": domain_hash("model_plan", model_plan),
        "dependency_lock_sha256": "2d" * 32,
        "project_metadata_sha256": "3e" * 32,
        "environment_policy_id": PINNED_POLICY_ID,
        "target_system": "darwin", "target_machine": "arm64",
        "target_python_implementation": "cpython", "target_python_abi": "cp312",
        "target_base_executable_sha256": "5a" * 32,
    }
    planned = phase5a.plan_environment_request(**bindings)
    if planned["status"] != "planned":
        raise AssertionError(planned)
    return planned["request"], core.decode("ascii"), runtime.decode("ascii")


def valid_evidence_fixture(model_plan=None, phase5a_bundle=None):
    plan = valid_model_plan() if model_plan is None else model_plan
    if phase5a_bundle is None:
        phase5a_bundle = valid_phase5a_request(plan)
    request, core_json, runtime_json = phase5a_bundle
    request_sha = domain_hash("phase5a_request", request)
    operation_id = "operation-" + request_sha
    preimage = {"device": 3, "inode": 4, "mode": 448, "nlink": 2}
    operation = {"device": 3, "inode": 5, "mode": 448, "nlink": 5}
    request_body = {
        "schema": evidence.STORAGE_REQUEST_SCHEMA,
        "storage_contract_id": PINNED_PHASE5B1_CONTRACT_ID,
        "phase5a_contract_id": PINNED_PHASE5A_CONTRACT_ID,
        "request": request,
        "request_sha256": request_sha,
        "layout_id": request["layout_id"],
        "layout_plan_sha256": "71" * 32,
        "stage_result_sha256": request["stage_result_sha256"],
        "stage_journal_entry_sha256": request["stage_journal_head_sha256"],
        "operation_id": operation_id,
        "environment_preimage_fingerprint": preimage,
        "operation_fingerprint": operation,
    }
    request_record = dict(request_body)
    request_record["request_record_sha256"] = domain_hash(
        "storage_request", request_body
    )
    tree_entries = [
        {"path": "bin", "kind": "directory", "mode": "0700", "size": 0,
         "sha256": ""},
        {"path": "bin/python", "kind": "file", "mode": "0700", "size": 9,
         "sha256": "72" * 32},
        {"path": "lib", "kind": "directory", "mode": "0700", "size": 0,
         "sha256": ""},
        {"path": "lib/package.py", "kind": "file", "mode": "0600", "size": 7,
         "sha256": "73" * 32},
        {"path": "share", "kind": "directory", "mode": "0700", "size": 0,
         "sha256": ""},
        {"path": "share/synapse-s2", "kind": "directory", "mode": "0700",
         "size": 0, "sha256": ""},
        {"path": "share/synapse-s2/model-cache-v1", "kind": "directory",
         "mode": "0700", "size": 0, "sha256": ""},
        {"path": "share/synapse-s2/model-cache-v1/snapshots",
         "kind": "directory", "mode": "0700", "size": 0, "sha256": ""},
        {"path": (
            "share/synapse-s2/model-cache-v1/snapshots/"
            "6c3ae70858513f1a78e9cdca3cae330d9075cd2a"
         ), "kind": "directory", "mode": "0700", "size": 0, "sha256": ""},
        {"path": (
            "share/synapse-s2/model-cache-v1/snapshots/"
            "6c3ae70858513f1a78e9cdca3cae330d9075cd2a/config.json"
         ), "kind": "file", "mode": "0600", "size": 7, "sha256": "11" * 32},
        {"path": (
            "share/synapse-s2/model-cache-v1/snapshots/"
            "6c3ae70858513f1a78e9cdca3cae330d9075cd2a/model.safetensors"
         ), "kind": "file", "mode": "0600", "size": 13, "sha256": "22" * 32},
    ]
    manifest = {
        "schema": evidence.TREE_MANIFEST_SCHEMA,
        "storage_contract_id": PINNED_PHASE5B1_CONTRACT_ID,
        "request_sha256": request_sha, "operation_id": operation_id,
        "product_id": request["candidate_product_id"],
        "inventory_policy_id": request["inventory_policy_id"],
        "entry_count": len(tree_entries), "total_bytes": 36,
        "entries": tree_entries,
    }
    manifest_sha = domain_hash("tree", manifest)
    prepare_body = {
        "schema": evidence.STORAGE_PREPARE_SCHEMA,
        "storage_contract_id": PINNED_PHASE5B1_CONTRACT_ID,
        "request_record_sha256": request_record["request_record_sha256"],
        "request_sha256": request_sha, "operation_id": operation_id,
        "layout_id": request["layout_id"], "manifest_sha256": manifest_sha,
        "manifest_entry_count": len(tree_entries), "manifest_total_bytes": 36,
        "environment_preimage_fingerprint": preimage,
        "operation_fingerprint": operation,
        "stage_result_sha256": request["stage_result_sha256"],
        "stage_journal_entry_sha256": request["stage_journal_head_sha256"],
    }
    prepare = dict(prepare_body)
    prepare["prepare_sha256"] = domain_hash("prepare", prepare_body)
    storage_digest = hashlib.sha256(
        DOMAINS["storage_digest"] + request_sha.encode("ascii")
        + manifest_sha.encode("ascii")
        + prepare["prepare_sha256"].encode("ascii")
    ).hexdigest()
    installed = {
        "schema": evidence.INSTALLED_DISTRIBUTION_MANIFEST_SCHEMA,
        "evidence_contract_id": PINNED_CONTRACT_ID,
        "environment_policy_id": PINNED_POLICY_ID,
        "request_sha256": request_sha, "storage_digest": storage_digest,
        "candidate_product_id": request["candidate_product_id"],
        "dependency_component_id": request["candidate_dependency_component_id"],
        "dependency_lock_sha256": request["dependency_lock_sha256"],
        "project_metadata_sha256": request["project_metadata_sha256"],
        "distribution_count": 1, "file_count": 1, "total_bytes": 7,
        "distributions": [{
            "normalized_name": "demo", "version": "1.0",
            "source_kind": "wheel", "source_identity_sha256": "81" * 32,
            "metadata_sha256": "82" * 32, "wheel_sha256": "83" * 32,
            "record_sha256": "84" * 32, "direct_url_sha256": None,
        }],
        "files": [{
            "path": "lib/package.py", "distribution": "demo", "mode": "0600",
            "size": 7, "sha256": "73" * 32, "record_sha256": "84" * 32,
        }],
    }
    native = {
        "schema": evidence.NATIVE_FILE_MANIFEST_SCHEMA,
        "evidence_contract_id": PINNED_CONTRACT_ID,
        "environment_policy_id": PINNED_POLICY_ID,
        "request_sha256": request_sha, "storage_digest": storage_digest,
        "candidate_product_id": request["candidate_product_id"],
        "target_machine": "arm64", "file_count": 1,
        "files": [{
            "path": "bin/python", "owner": "base-interpreter", "mode": "0700",
            "size": 9, "sha256": "72" * 32, "architectures": ["arm64"],
            "minimum_os": "14.0", "load_commands_sha256": "86" * 32,
            "dependencies": ["libSystem.B.dylib"], "rpaths": [],
        }],
    }
    model_manifest = {
        "schema": evidence.MODEL_MANIFEST_SCHEMA,
        "evidence_contract_id": PINNED_CONTRACT_ID,
        "environment_policy_id": PINNED_POLICY_ID,
        "request_sha256": request_sha, "storage_digest": storage_digest,
        "candidate_product_id": request["candidate_product_id"],
        "core_config_canonical_json": core_json,
        "core_config_fingerprint": request["core_config_fingerprint"],
        "embedding_space_identity": request["embedding_space_identity"],
        "embedding_runtime_config_canonical_json": runtime_json,
        "embedding_runtime_config_sha256": request["embedding_runtime_config_sha256"],
        "embedding_provider": request["embedding_provider"],
        "model_id": request["model_id"], "model_revision": request["model_revision"],
        "cache_root_relative": "share/synapse-s2/model-cache-v1",
        "snapshot_plan": plan,
        "snapshot_plan_sha256": request["expected_model_snapshot_sha256"],
        "post_publication_snapshot_sha256": request["expected_model_snapshot_sha256"],
    }
    docs = {slot: None for slot in evidence.EVIDENCE_SLOTS}
    docs.update({
        "environment_manifest_sha256": manifest,
        "installed_distribution_manifest_sha256": installed,
        "native_file_manifest_sha256": native,
        "model_manifest_sha256": model_manifest,
    })
    digests = {slot: None for slot in evidence.EVIDENCE_SLOTS}
    digests.update({
        "environment_manifest_sha256": manifest_sha,
        "installed_distribution_manifest_sha256": domain_hash("installed", installed),
        "native_file_manifest_sha256": domain_hash("native", native),
        "model_manifest_sha256": domain_hash("model_manifest", model_manifest),
    })
    evidence_set = {
        "schema": evidence.EVIDENCE_SET_SCHEMA, "mode": evidence.MODE,
        "evidence_contract_id": PINNED_CONTRACT_ID,
        "environment_policy_id": PINNED_POLICY_ID,
        "phase5a_source_sha256": PINNED_PHASE5A_SHA256,
        "phase5a_contract_id": PINNED_PHASE5A_CONTRACT_ID,
        "phase5b1_source_sha256": PINNED_PHASE5B1_SHA256,
        "phase5b1_contract_id": PINNED_PHASE5B1_CONTRACT_ID,
        "environment_request": request, "environment_request_sha256": request_sha,
        "storage_request_record": request_record,
        "storage_request_record_sha256": request_record["request_record_sha256"],
        "storage_prepare_record": prepare,
        "storage_prepare_sha256": prepare["prepare_sha256"],
        "storage_manifest": manifest, "storage_manifest_sha256": manifest_sha,
        "storage_digest": storage_digest,
        "documents_by_slot": docs, "digests_by_slot": digests,
    }
    return plan, request, evidence_set


def _tree_dfs_order(entries):
    by_path = {entry["path"]: entry for entry in entries}
    children = {}
    for path in by_path:
        children.setdefault(path.rpartition("/")[0], []).append(path)
    ordered = []
    visited = set()

    def visit(parent):
        for path in sorted(children.get(parent, ())):
            visited.add(path)
            ordered.append(by_path[path])
            if by_path[path]["kind"] == "directory":
                visit(path)

    visit("")
    for path in sorted(set(by_path) - visited):
        ordered.append(by_path[path])
    return ordered


def rehash_storage_fixture(document, *, sync_operation_nlink=True):
    request_record = document["storage_request_record"]
    manifest = document["storage_manifest"]
    manifest["entries"] = _tree_dfs_order(manifest["entries"])
    manifest["entry_count"] = len(manifest["entries"])
    manifest["total_bytes"] = sum(
        entry["size"] for entry in manifest["entries"]
        if entry["kind"] == "file"
    )
    if sync_operation_nlink:
        direct_directories = sum(
            1 for entry in manifest["entries"]
            if entry["kind"] == "directory" and "/" not in entry["path"]
        )
        request_record["operation_fingerprint"]["nlink"] = 2 + direct_directories
    request_body = {
        key: request_record[key]
        for key in evidence.STORAGE_REQUEST_KEYS
        if key != "request_record_sha256"
    }
    request_record["request_record_sha256"] = domain_hash(
        "storage_request", request_body
    )
    document["storage_request_record_sha256"] = request_record[
        "request_record_sha256"
    ]

    manifest_sha = domain_hash("tree", manifest)
    document["storage_manifest_sha256"] = manifest_sha
    document["documents_by_slot"]["environment_manifest_sha256"] = (
        copy.deepcopy(manifest)
    )
    document["digests_by_slot"]["environment_manifest_sha256"] = manifest_sha

    prepare = document["storage_prepare_record"]
    prepare.update({
        "request_record_sha256": request_record["request_record_sha256"],
        "manifest_sha256": manifest_sha,
        "manifest_entry_count": manifest["entry_count"],
        "manifest_total_bytes": manifest["total_bytes"],
        "environment_preimage_fingerprint": copy.deepcopy(
            request_record["environment_preimage_fingerprint"]
        ),
        "operation_fingerprint": copy.deepcopy(
            request_record["operation_fingerprint"]
        ),
    })
    prepare_body = {
        key: prepare[key]
        for key in evidence.STORAGE_PREPARE_KEYS
        if key != "prepare_sha256"
    }
    prepare["prepare_sha256"] = domain_hash("prepare", prepare_body)
    document["storage_prepare_sha256"] = prepare["prepare_sha256"]
    storage_digest = hashlib.sha256(
        DOMAINS["storage_digest"]
        + document["environment_request_sha256"].encode("ascii")
        + manifest_sha.encode("ascii")
        + prepare["prepare_sha256"].encode("ascii")
    ).hexdigest()
    document["storage_digest"] = storage_digest
    role_domains = {
        "installed_distribution_manifest_sha256": "installed",
        "native_file_manifest_sha256": "native",
        "model_manifest_sha256": "model_manifest",
    }
    for slot, domain in role_domains.items():
        role = document["documents_by_slot"][slot]
        role["storage_digest"] = storage_digest
        document["digests_by_slot"][slot] = domain_hash(domain, role)


def rehash_static_role(document, slot, domain):
    role = document["documents_by_slot"][slot]
    document["digests_by_slot"][slot] = domain_hash(domain, role)


class EqualityProbe:
    calls = 0

    def __eq__(self, _other):
        type(self).calls += 1
        raise SystemExit("equality hook")

    def __ne__(self, _other):
        type(self).calls += 1
        raise SystemExit("equality hook")


class ResultSubclass(dict):
    pass


class EnvironmentEvidenceTests(unittest.TestCase):
    def test_upstream_source_and_contract_pins(self):
        self.assertEqual(source_sha(_PHASE5A_SOURCE), PINNED_PHASE5A_SHA256)
        self.assertEqual(source_sha(_PHASE5B1_SOURCE), PINNED_PHASE5B1_SHA256)
        self.assertEqual(phase5a.environment_contract_projection()["environment_contract_id"], PINNED_PHASE5A_CONTRACT_ID)
        self.assertEqual(evidence.PHASE5A_CONTRACT_ID, PINNED_PHASE5A_CONTRACT_ID)
        self.assertEqual(evidence.PHASE5B1_CONTRACT_ID, PINNED_PHASE5B1_CONTRACT_ID)

    def test_policy_projection_and_identity_are_independently_replayed(self):
        projection = evidence.environment_policy_projection()
        body = dict(projection)
        claimed = body.pop("environment_policy_id")
        self.assertEqual(claimed, PINNED_POLICY_ID)
        self.assertEqual("environment-policy-" + domain_hash("policy", body), claimed)
        self.assertEqual(
            projection["numeric_bound_comparator_bindings"],
            [
                ["value", "minimum", "__ge__"],
                ["value", "maximum", "__le__"],
            ],
        )
        self.assertEqual(
            projection["secret_shape_document_bindings"],
            [
                [
                    "core_config", "protocol_version",
                    "synapse-core-config.v1",
                    ["provider", "model_id", "model_revision"],
                ],
                [
                    "model_snapshot_plan", "schema",
                    "synapse-s2.release-environment-model-snapshot-plan.v1",
                    ["model_id", "model_revision"],
                ],
            ],
        )
        self.assertTrue(
            projection["all_non_null_absolute_paths_secret_shape_checked"]
        )
        self.assertEqual(projection["secret_shape_document_exact_matches"], 1)
        self.assertEqual(
            projection["distribution_name_normalization_transform"],
            [
                r"\A[a-z0-9][a-z0-9._-]{0,63}\Z",
                "sub", r"[-_.]+", "-", "lower", "fullmatch",
                r"\A[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z",
            ],
        )
        self.assertEqual(
            projection["distribution_name_normalization_checks"],
            [
                ["value", "canonical", "__eq__", True],
                [
                    "pattern_match_type_name", "none_type_name",
                    "__eq__", False,
                ],
            ],
        )
        self.assertEqual(
            projection["document_string_pattern_bindings"],
            {
                name: [list(binding) for binding in bindings]
                for name, bindings
                in evidence.DOCUMENT_STRING_PATTERN_BINDINGS.items()
            },
        )
        self.assertEqual(
            projection["native_sublist_string_pattern_bindings"],
            [
                list(binding)
                for binding in evidence.NATIVE_SUBLIST_STRING_PATTERN_BINDINGS
            ],
        )
        self.assertEqual(
            projection["helper_string_pattern_bindings"],
            [
                list(binding)
                for binding in evidence.HELPER_STRING_PATTERN_BINDINGS
            ],
        )
        self.assertEqual(
            projection["path_rejection_predicate_bindings"],
            {
                name: [list(binding) for binding in bindings]
                for name, bindings
                in evidence.PATH_REJECTION_PREDICATE_BINDINGS.items()
            },
        )
        self.assertEqual(
            projection["path_rejection_predicate_combiner"],
            "reject-on-any-predicate-match",
        )
        materialization = projection["materialization_profile"]
        self.assertEqual(materialization["directory_mode"], "0700")
        self.assertEqual(materialization["regular_file_mode"], "0600")
        self.assertEqual(materialization["executable_file_modes"], {"bin/python": "0700"})
        self.assertFalse(materialization["ordinary_uv_venv_automatically_admissible"])
        self.assertEqual(
            projection["model_snapshot_profile"]["allowed_file_suffixes"],
            [".json", ".safetensors", ".txt"],
        )
        self.assertEqual(
            projection["model_file_suffix_rule_bindings"],
            [
                ["forbidden_suffixes", "endswith", False],
                ["allowed_suffixes", "endswith", True],
            ],
        )
        configuration = projection["configuration_profile"]
        self.assertEqual(tuple(configuration["core_config_keys"]), evidence.CORE_CONFIG_KEYS)
        self.assertEqual(
            tuple(configuration["runtime_config_keys"]),
            evidence.EMBEDDING_RUNTIME_CONFIG_KEYS,
        )
        self.assertEqual(
            configuration["runtime_config_bindings"],
            [
                list(binding)
                for binding in evidence.EMBEDDING_RUNTIME_CONFIG_BINDINGS
            ],
        )
        self.assertEqual(
            configuration["runtime_config_constant_values"],
            [
                list(binding)
                for binding in evidence.EMBEDDING_RUNTIME_CONSTANT_VALUES
            ],
        )
        self.assertEqual(configuration["runtime_provider"], "mlx-neural-v1")
        self.assertTrue(configuration["local_files_only"])
        self.assertTrue(configuration["require_native"])
        self.assertEqual(
            configuration["integer_bounds"]["dimension"], [1, 65_536]
        )
        self.assertEqual(
            configuration["float_bounds"]["capture_poll_seconds"],
            ["0.25", "300.0"],
        )
        self.assertEqual(
            configuration["path_validation"],
            "ascii-absolute-lexically-normal-no-root-no-dot-components-"
            "no-trailing-or-double-slash-no-filesystem-resolution",
        )
        self.assertEqual(configuration["path_codepoint_minimum"], 32)
        self.assertEqual(configuration["path_codepoint_maximum"], 126)
        self.assertEqual(
            configuration["path_syntax_values"],
            [
                ["separator", "/"], ["root", "/"],
                ["current_prefix", "./"], ["double_separator", "//"],
            ],
        )
        self.assertEqual(
            configuration["path_forbidden_components"], ["", ".", ".."]
        )
        self.assertEqual(
            configuration["path_role_bindings"],
            [
                ["socket_path", False], ["state_path", False],
                ["memory_path", False], ["capture_root", True],
                ["cache_dir", False],
            ],
        )
        self.assertEqual(
            configuration["parent_suffix_bindings"],
            [
                ["state_path", "memory_path", "runtime_state.json"],
                ["socket_path", "memory_path", "core/service.sock"],
            ],
        )
        self.assertEqual(
            configuration["suffix_bindings"],
            [["cache_dir", "share/synapse-s2/model-cache-v1"]],
        )
        self.assertEqual(
            configuration["path_byte_bounds"], [["socket_path", 103]]
        )
        self.assertEqual(
            configuration["distinct_paths"],
            ["socket_path", "state_path", "memory_path"],
        )
        self.assertEqual(
            tuple(configuration["secret_shape_patterns"]),
            evidence._SECRET_SHAPE_PATTERNS,
        )
        self.assertEqual(
            configuration["state_path"], "memory-parent/runtime_state.json"
        )
        self.assertEqual(
            configuration["integer_bound_roles"],
            [list(binding) for binding in evidence.CORE_CONFIG_INTEGER_BOUND_ROLES],
        )
        self.assertEqual(
            configuration["float_bound_roles"],
            [list(binding) for binding in evidence.CORE_CONFIG_FLOAT_BOUND_ROLES],
        )
        self.assertEqual(
            configuration["boolean_roles"],
            list(evidence.CORE_CONFIG_BOOLEAN_ROLES),
        )
        self.assertEqual(
            configuration["order_relations"],
            [["default_top_k", "num_neurons", "less-than-or-equal"]],
        )
        self.assertEqual(
            configuration["comparator_bindings"],
            [["less-than-or-equal", "__le__"]],
        )
        self.assertEqual(
            configuration["neural_matrix_terms"],
            [
                ["dimension", "num_neurons", 1],
                ["num_neurons", "num_neurons", 1],
                ["num_neurons", None, 3],
            ],
        )
        self.assertEqual(
            configuration["runtime_core_bindings"],
            [
                "model_id", "revision", "cache_dir", "pooling",
                "max_tokens", "normalize", "local_files_only",
            ],
        )
        self.assertEqual(
            configuration["embedding_space_outer_bindings"],
            [
                ["schema", "constant:embedding-space-schema"],
                ["provider", "constant:embedding-runtime-provider"],
                ["dimensions", "core-config:dimension"],
                ["num_neurons", "core-config:num_neurons"],
                ["spike_encoder", "constant:embedding-spike-encoder"],
                ["default_top_k", "core-config:default_top_k"],
                ["neuron_projection", "constant:embedding-neuron-projection"],
                ["neural", "nested:embedding-space-neural-bindings"],
            ],
        )
        self.assertEqual(
            configuration["embedding_space_neural_bindings"],
            [
                ["model_id", "core-config:embedding_neural_model_id"],
                ["revision", "core-config:embedding_neural_revision"],
                ["pooling", "core-config:embedding_neural_pooling"],
                ["max_tokens", "core-config:embedding_neural_max_tokens"],
                ["normalize", "core-config:embedding_neural_normalize"],
            ],
        )
        self.assertEqual(
            configuration["embedding_space_constant_values"],
            [
                ["embedding-space-schema", "synapse-s2.embedding-space.v1"],
                ["embedding-runtime-provider", "mlx-neural-v1"],
                ["embedding-spike-encoder", "zscore-top-k-v1"],
                ["embedding-neuron-projection", "synaptic-matrix-v1"],
            ],
        )
        self.assertEqual(
            tuple(projection["document_binding_tables"]),
            tuple(evidence.DOCUMENT_BINDING_TABLES),
        )
        self.assertEqual(
            projection["document_binding_tables"]["installed_manifest"][-2:],
            [
                ["dependency_lock_sha256", "request:dependency_lock_sha256"],
                ["project_metadata_sha256", "request:project_metadata_sha256"],
            ],
        )
        self.assertEqual(
            projection["cross_manifest_tree_file_fields"],
            ["mode", "size", "sha256"],
        )
        self.assertEqual(
            projection["storage_digest_component_roles"],
            ["request_sha256", "manifest_sha256", "prepare_sha256"],
        )
        self.assertEqual(
            projection["distribution_digest_relation_roles"],
            [
                "source_identity_digest", "metadata_digest",
                "wheel_digest", "record_digest",
            ],
        )
        self.assertEqual(
            projection["parent_directory_kind_by_role"],
            [
                ["tree_manifest", "directory"],
                ["model_snapshot_plan", "directory"],
            ],
        )
        self.assertEqual(
            projection["document_relation_fields"]["native_manifest"],
            [
                list(binding)
                for binding in evidence.DOCUMENT_RELATION_FIELDS[
                    "native_manifest"
                ]
            ],
        )
        self.assertEqual(
            projection["document_aggregation_bindings"],
            {
                name: [list(binding) for binding in bindings]
                for name, bindings
                in evidence.DOCUMENT_AGGREGATION_BINDINGS.items()
            },
        )
        self.assertEqual(
            projection["document_value_relation_bindings"],
            [
                list(binding)
                for binding in evidence.DOCUMENT_VALUE_RELATION_BINDINGS
            ],
        )
        self.assertEqual(
            projection["collection_relation_bindings"],
            [list(binding) for binding in evidence.COLLECTION_RELATION_BINDINGS],
        )
        self.assertEqual(
            projection["collection_order_direction_bindings"],
            [["ascending", False]],
        )

    def test_contract_projection_and_slots_are_closed(self):
        projection = evidence.environment_evidence_contract_projection()
        body = dict(projection)
        claimed = body.pop("contract_id")
        self.assertEqual(claimed, PINNED_CONTRACT_ID)
        self.assertEqual("environment-evidence-contract-" + domain_hash("contract", body), claimed)
        self.assertEqual(tuple(projection["evidence_slots"]), tuple(phase5a.OBSERVATION_DIGESTS))
        self.assertEqual(tuple(projection["static_slots"]), evidence.STATIC_SLOTS)
        self.assertEqual(
            projection["static_slot_validator_roles"],
            [list(binding) for binding in evidence.STATIC_SLOT_VALIDATOR_ROLES],
        )
        self.assertEqual(
            projection["static_slot_validator_bindings"],
            [
                [slot, role, function_name, list(argument_roles)]
                for slot, role, function_name, argument_roles
                in evidence.STATIC_SLOT_VALIDATOR_BINDINGS
            ],
        )
        self.assertEqual(
            projection["static_slot_validator_binding_fields"],
            [
                "slot", "document_role", "validator_function",
                "argument_roles",
            ],
        )
        self.assertEqual(
            projection["static_validator_context_roles"],
            ["request", "request_sha256", "storage_digest"],
        )
        self.assertEqual(
            projection["static_validator_context_bindings"],
            [
                ["request", "request"],
                ["request_sha256", "request_sha"],
                ["storage_digest", "storage_digest"],
            ],
        )
        self.assertEqual(
            projection["static_primary_storage_role"], "tree_manifest"
        )
        self.assertEqual(
            projection["result_truth"]["exit_codes"],
            {"document_valid": 0, "unsupported": 1, "invalid": 2},
        )
        self.assertEqual(
            projection["result_truth"]["exit_path_bindings"],
            [list(binding) for binding in evidence.RESULT_EXIT_PATH_BINDINGS],
        )
        self.assertEqual(
            projection["result_truth"]["exit_predicate_comparator_method"],
            "__eq__",
        )
        self.assertEqual(
            projection["result_truth"]["exit_predicate_action_bindings"],
            [[False, 0], [True, 1]],
        )
        self.assertEqual(
            projection["result_truth"][
                "exit_predicate_action_binding_fields"
            ],
            ["comparison_result", "selection_count"],
        )
        self.assertEqual(
            projection["result_truth"]["exit_selection_sequence_method"],
            "__mul__",
        )
        self.assertEqual(
            projection["result_truth"]["exit_selection_collection_method"],
            "extend",
        )
        self.assertEqual(
            projection["result_truth"]["exit_traversal_method"],
            "__iter__",
        )
        self.assertEqual(
            projection["result_truth"]["exit_selected_path_binding"],
            ["__getitem__", 0],
        )
        self.assertEqual(
            projection["result_truth"][
                "exit_selected_path_binding_fields"
            ],
            ["selection_method", "selection_index"],
        )
        self.assertEqual(
            projection["result_truth"]["unsupported_render_bindings"],
            [
                [evidence.COMMAND_MODEL_PLAN, evidence.COMMAND_MODEL_PLAN],
                [
                    evidence.COMMAND_EVIDENCE_SET,
                    evidence.COMMAND_EVIDENCE_SET,
                ],
            ],
        )
        self.assertEqual(
            projection["result_truth"][
                "unsupported_render_binding_fields"
            ],
            ["template_command", "line_command"],
        )
        self.assertIs(
            projection["result_truth"][
                "unsupported_render_match_expected"
            ],
            True,
        )
        self.assertEqual(
            projection["result_truth"]["render_validity_bindings"],
            [[False, "render_fallback"], [True, "render_valid"]],
        )
        self.assertEqual(
            projection["result_truth"][
                "render_validity_selector_binding_fields"
            ],
            [
                "value_role", "selector_method", "expected_result",
                "comparator_method",
            ],
        )
        self.assertEqual(
            projection["result_truth"][
                "render_validity_selector_binding"
            ],
            ["valid", "__bool__", True, "__eq__"],
        )
        self.assertEqual(
            projection["result_truth"]["render_line_source_bindings"],
            [[False, "fallback"], [True, "rendered"]],
        )
        self.assertEqual(
            projection["policy"]["document_binding_tables"][
                "render_line_values"
            ],
            [
                ["fallback", "local:fallback_line"],
                ["rendered", "local:line"],
            ],
        )
        self.assertEqual(
            projection["policy"]["document_binding_tables"][
                "render_fallback_value"
            ],
            [["line", "local:fallback_line"]],
        )
        self.assertEqual(
            projection["policy"]["document_binding_tables"][
                "render_precomputed_value"
            ],
            [["line", "argument:line"]],
        )
        self.assertIs(
            projection["result_truth"][
                "render_dynamic_candidate_action_result"
            ],
            True,
        )
        self.assertEqual(
            projection["result_truth"]["reason_bindings"],
            [list(binding) for binding in evidence.RESULT_REASON_BINDINGS],
        )
        self.assertEqual(
            projection["result_truth"]["document_valid_binding"],
            ["status", "__eq__", "document_valid"],
        )
        self.assertEqual(
            projection["result_truth"]["derived_bindings"],
            [
                [target, kind, source, list(argument_roles)]
                for target, kind, source, argument_roles
                in evidence.RESULT_DERIVED_BINDINGS
            ],
        )
        self.assertEqual(
            projection["result_truth"]["self_hash_field"],
            "result_sha256",
        )
        self.assertEqual(
            projection["result_truth"]["replay_bindings"],
            [
                [command, validator_role, list(argument_fields)]
                for command, validator_role, argument_fields
                in evidence.RESULT_REPLAY_BINDINGS
            ],
        )
        self.assertEqual(
            projection["result_truth"]["unsupported_template_match_binding"],
            ["exact-native-tree", "__eq__"],
        )
        self.assertEqual(
            projection["result_truth"]["result_field_bindings"],
            [
                list(binding)
                for binding in evidence.DOCUMENT_BINDING_TABLES["result"]
            ],
        )
        self.assertEqual(
            projection["result_truth"]["render_field_bindings"],
            [
                list(binding)
                for binding in evidence.DOCUMENT_BINDING_TABLES["render"]
            ],
        )
        self.assertEqual(
            projection["result_truth"]["false_flag_bindings"],
            [[key, False] for key in evidence.FALSE_FLAGS],
        )
        self.assertEqual(
            projection["implementation_identity"],
            {
                "contract_id_self_authenticates_source_bytes": False,
                "source_sha256_authority": "external-release-inventory",
                "preimport_source_replacement_requires_external_sha256_check": True,
                "runtime_guard_scope": (
                    "post-import-global-rebinding-and-projection-drift"
                ),
            },
        )
        self.assertEqual(tuple(projection["dynamic_pending_slots"]), evidence.DYNAMIC_PENDING_SLOTS)
        self.assertEqual(len(evidence.NONCLAIMS), 22)
        self.assertIn(
            "no-self-source-byte-authentication-preimport-source-pin-is-external",
            evidence.NONCLAIMS,
        )
        self.assertRegex(PINNED_CONTRACT_ID, projection["patterns"]["contract_id"])
        self.assertEqual(projection["limits"]["phase5b1_tree_entries"], 20_000)
        self.assertEqual(projection["limits"]["phase5b1_document_bytes"], 1_000_000)
        self.assertEqual(projection["limits"]["max_key_characters"], 128)
        self.assertEqual(
            projection["limits"]["model_snapshot_minimum_entries"], 1
        )
        self.assertEqual(
            projection["limits"]["model_snapshot_minimum_total_bytes"], 1
        )
        self.assertEqual(projection["limits"]["native_sublist_items"], 128)
        self.assertEqual(
            projection["limits"]["max_native_document_integer_abs"],
            2**64 - 1,
        )
        self.assertEqual(
            projection["limits"]["native_text_minimum_characters"], 1
        )
        validator = projection["validator_policy"]
        self.assertEqual(
            validator["native_sorted_unique_fields"],
            ["architectures", "dependencies", "rpaths"],
        )
        self.assertEqual(
            validator["native_base_interpreter_cardinality"], "exactly-one"
        )
        self.assertEqual(
            validator["numeric_field_bounds"]["model_snapshot_plan.entry_count"],
            [1, 20_000],
        )
        self.assertIn(
            "entry-count-equals-entry-list-length-and-is-nonempty",
            validator["document_relations"]["model_snapshot_plan"],
        )
        self.assertIn(
            "storage_request_record_sha256", projection["hash_bindings"]
        )
        self.assertIn("storage_digest", projection["hash_bindings"])

    def test_independent_literal_digest_vector(self):
        plan, request, document = valid_evidence_fixture()
        plan_result = evidence.validate_model_snapshot_plan_document(plan)
        result = evidence.validate_environment_evidence_set_document(request, document)
        self.assertEqual(domain_hash("model_plan", plan), PINNED_MODEL_PLAN_SHA256)
        self.assertEqual(domain_hash("phase5a_request", request), PINNED_REQUEST_SHA256)
        self.assertEqual(document["storage_request_record_sha256"], PINNED_REQUEST_RECORD_SHA256)
        self.assertEqual(document["storage_manifest_sha256"], PINNED_TREE_MANIFEST_SHA256)
        self.assertEqual(document["storage_prepare_sha256"], PINNED_PREPARE_SHA256)
        self.assertEqual(document["storage_digest"], PINNED_STORAGE_DIGEST)
        self.assertEqual(document["digests_by_slot"]["installed_distribution_manifest_sha256"], PINNED_INSTALLED_MANIFEST_SHA256)
        self.assertEqual(document["digests_by_slot"]["native_file_manifest_sha256"], PINNED_NATIVE_MANIFEST_SHA256)
        self.assertEqual(document["digests_by_slot"]["model_manifest_sha256"], PINNED_MODEL_MANIFEST_SHA256)
        self.assertEqual(domain_hash("evidence_set", document), PINNED_EVIDENCE_SET_SHA256)
        self.assertEqual(plan_result["result_sha256"], PINNED_MODEL_RESULT_SHA256)
        self.assertEqual(result["result_sha256"], PINNED_EVIDENCE_RESULT_SHA256)

    def test_model_snapshot_plan_round_trip_and_literal_digest(self):
        plan = valid_model_plan()
        result = evidence.validate_model_snapshot_plan_document(plan)
        self.assertEqual(result["status"], evidence.STATUS_DOCUMENT_VALID)
        self.assertEqual(result["model_snapshot_plan_sha256"], domain_hash("model_plan", plan))
        self.assertEqual(evidence.environment_evidence_result_exit_code(result), 0)
        rendered = json.loads(evidence.render_environment_evidence_result(result))
        self.assertEqual(tuple(sorted(rendered)), tuple(sorted(evidence.RENDER_KEYS)))
        self.assertNotIn("model_id", rendered)
        self.assertNotIn(plan["model_id"], canonical(rendered).decode("ascii"))

    def test_model_plan_rejects_executable_alias_and_content_drift(self):
        for mutate in (
            lambda p: p.update({"environment_policy_id": "environment-policy-" + "ff" * 32}),
            lambda p: p["entries"][0].update({"path": "loader.py"}),
            lambda p: p["entries"][0].update({"path": "payload.exe"}),
            lambda p: p["entries"][0].update({"mode": "0700"}),
            lambda p: p.update({"total_bytes": p["total_bytes"] + 1}),
            lambda p: p["entries"].reverse(),
        ):
            plan = valid_model_plan()
            mutate(plan)
            result = evidence.validate_model_snapshot_plan_document(plan)
            self.assertEqual(result["status"], evidence.STATUS_UNSUPPORTED)
            self.assertEqual(evidence.environment_evidence_result_exit_code(result), 1)

    def test_complete_evidence_set_is_document_valid_but_never_verified(self):
        _plan, request, document = valid_evidence_fixture()
        result = evidence.validate_environment_evidence_set_document(request, document)
        self.assertEqual(result["status"], evidence.STATUS_DOCUMENT_VALID)
        self.assertTrue(result["document_valid"])
        self.assertFalse(result["evidence_verified"])
        self.assertFalse(result["receipt_issuable"])
        self.assertFalse(result["receipt_published"])
        self.assertFalse(result["blocker_5_complete"])
        self.assertTrue(all(value is False for value in result["flags"].values()))
        self.assertEqual(result["environment_request_sha256"], domain_hash("phase5a_request", request))
        self.assertEqual(result["evidence_set_sha256"], domain_hash("evidence_set", document))
        self.assertEqual(evidence.environment_evidence_result_exit_code(result), 0)

    def test_core_runtime_and_embedding_identity_are_independently_replayed(self):
        plan = valid_model_plan()
        core = valid_core_config(plan)
        runtime = valid_runtime_config(core)
        request, core_json, runtime_json = valid_phase5a_request(plan)
        self.assertEqual(tuple(sorted(core)), tuple(sorted(evidence.CORE_CONFIG_KEYS)))
        self.assertEqual(
            tuple(sorted(runtime)),
            tuple(sorted(evidence.EMBEDDING_RUNTIME_CONFIG_KEYS)),
        )
        self.assertEqual(request["core_config_fingerprint"], raw_sha(core))
        self.assertEqual(
            request["embedding_runtime_config_sha256"], raw_sha(runtime)
        )
        self.assertEqual(
            request["embedding_space_identity"],
            embedding_space_identity(core),
        )
        self.assertEqual(core_json, canonical(core).decode("ascii"))
        self.assertEqual(runtime_json, canonical(runtime).decode("ascii"))
        _plan, request, document = valid_evidence_fixture(
            plan, (request, core_json, runtime_json)
        )
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_DOCUMENT_VALID,
        )

    def test_embedding_identity_value_bindings_drive_runtime_and_identity(self):
        core = valid_core_config()
        request = {
            "embedding_provider": core["embedding_provider_name"],
            "model_id": core["embedding_neural_model_id"],
            "model_revision": core["embedding_neural_revision"],
            "embedding_space_identity": embedding_space_identity(core),
            "host_id_sha256": "ab" * 32,
        }
        evidence._core_config(core, request)
        baseline = evidence.environment_evidence_contract_projection()[
            "contract_id"
        ]
        original = evidence.EMBEDDING_SPACE_OUTER_BINDINGS
        mutated = list(original)
        mutated[2] = (mutated[2][0], original[3][1])
        mutated[3] = (mutated[3][0], original[2][1])
        evidence.EMBEDDING_SPACE_OUTER_BINDINGS = tuple(mutated)
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            with self.assertRaises(evidence._Reject):
                evidence._core_config(core, request)
            swapped_identity = {
                "schema": "synapse-s2.embedding-space.v1",
                "provider": "mlx-neural-v1",
                "dimensions": core["num_neurons"],
                "num_neurons": core["dimension"],
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
            request["embedding_space_identity"] = raw_sha(swapped_identity)
            evidence._core_config(core, request)
        finally:
            evidence.EMBEDDING_SPACE_OUTER_BINDINGS = original

        original_tables = evidence.DOCUMENT_BINDING_TABLES
        redirected_tables = dict(original_tables)
        redirected_tables["request_embedding_space_identity"] = (
            ("host_id_sha256", "derived:embedding_space_identity"),
        )
        evidence.DOCUMENT_BINDING_TABLES = redirected_tables
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            with self.assertRaises(evidence._Reject):
                evidence._core_config(core, request)
            request["host_id_sha256"] = embedding_space_identity(core)
            request["embedding_space_identity"] = "cd" * 32
            evidence._core_config(core, request)
        finally:
            evidence.DOCUMENT_BINDING_TABLES = original_tables

    def test_runtime_config_value_bindings_drive_runtime_and_identity(self):
        plan = valid_model_plan()
        core = valid_core_config(plan)
        runtime = valid_runtime_config(core)
        request, _core_json, _runtime_json = valid_phase5a_request(plan)
        evidence._embedding_runtime_config(runtime, request, core)
        baseline = evidence.environment_evidence_contract_projection()[
            "contract_id"
        ]
        original = evidence.EMBEDDING_RUNTIME_CONFIG_BINDINGS
        mutated = list(original)
        mutated[2] = (mutated[2][0], original[3][1])
        mutated[3] = (mutated[3][0], original[2][1])
        evidence.EMBEDDING_RUNTIME_CONFIG_BINDINGS = tuple(mutated)
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            with self.assertRaises(evidence._Reject):
                evidence._embedding_runtime_config(runtime, request, core)
            swapped = dict(runtime)
            swapped["model_id"] = request["model_revision"]
            swapped["revision"] = request["model_id"]
            evidence._embedding_runtime_config(swapped, request, core)
        finally:
            evidence.EMBEDDING_RUNTIME_CONFIG_BINDINGS = original

    def test_document_binding_tables_drive_cross_document_sources(self):
        _plan, request, document = valid_evidence_fixture()
        installed = document["documents_by_slot"][
            "installed_distribution_manifest_sha256"
        ]
        request_sha = document["environment_request_sha256"]
        storage_digest = document["storage_digest"]
        evidence._installed_manifest(
            installed, request, request_sha, storage_digest
        )
        baseline = evidence.environment_evidence_contract_projection()[
            "contract_id"
        ]
        original = evidence.DOCUMENT_BINDING_TABLES
        installed_bindings = list(original["installed_manifest"])
        installed_bindings[-2] = (
            installed_bindings[-2][0], installed_bindings[-1][1]
        )
        installed_bindings[-1] = (
            installed_bindings[-1][0], original["installed_manifest"][-2][1]
        )
        mutated_tables = dict(original)
        mutated_tables["installed_manifest"] = tuple(installed_bindings)
        evidence.DOCUMENT_BINDING_TABLES = mutated_tables
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            with self.assertRaises(evidence._Reject):
                evidence._installed_manifest(
                    installed, request, request_sha, storage_digest
                )
            swapped = copy.deepcopy(installed)
            swapped["environment_policy_id"] = evidence.environment_policy_id()
            swapped["dependency_lock_sha256"] = request[
                "project_metadata_sha256"
            ]
            swapped["project_metadata_sha256"] = request[
                "dependency_lock_sha256"
            ]
            evidence._installed_manifest(
                swapped, request, request_sha, storage_digest
            )
        finally:
            evidence.DOCUMENT_BINDING_TABLES = original

    def test_relation_fields_drive_native_architecture_membership(self):
        _plan, request, document = valid_evidence_fixture()
        native = document["documents_by_slot"][
            "native_file_manifest_sha256"
        ]
        request_sha = document["environment_request_sha256"]
        storage_digest = document["storage_digest"]
        evidence._native_manifest(
            native, request, request_sha, storage_digest
        )
        baseline = evidence.environment_evidence_contract_projection()[
            "contract_id"
        ]
        original = evidence.DOCUMENT_RELATION_FIELDS
        native_relations = list(original["native_manifest"])
        target_index = next(
            index for index, (role, _field) in enumerate(native_relations)
            if role == "target_machine"
        )
        native_relations[target_index] = (
            "target_machine", "request_sha256"
        )
        mutated_relations = dict(original)
        mutated_relations["native_manifest"] = tuple(native_relations)
        evidence.DOCUMENT_RELATION_FIELDS = mutated_relations
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            with self.assertRaises(evidence._Reject):
                evidence._native_manifest(
                    native, request, request_sha, storage_digest
                )
            redirected = copy.deepcopy(native)
            redirected["environment_policy_id"] = (
                evidence.environment_policy_id()
            )
            redirected["files"][0]["architectures"] = [
                redirected["request_sha256"]
            ]
            evidence._native_manifest(
                redirected, request, request_sha, storage_digest
            )
        finally:
            evidence.DOCUMENT_RELATION_FIELDS = original

    def test_coordinated_core_runtime_semantic_forgery_is_rejected(self):
        plan = valid_model_plan()
        forged_core = {"not_core_config": True}
        forged_runtime = {
            "schema": "synapse-s2.embedding-runtime-config.v1",
            "provider": "remote-contradiction",
            "model_id": "different/model",
            "revision": "00" * 20,
            "cache_dir": "/private/tmp/remote-cache",
            "pooling": "first",
            "max_tokens": 1,
            "normalize": False,
            "local_files_only": False,
        }
        bundle = valid_phase5a_request(
            plan,
            core_document=forged_core,
            runtime_document=forged_runtime,
            embedding_identity="ab" * 32,
        )
        _plan, request, document = valid_evidence_fixture(plan, bundle)
        result = evidence.validate_environment_evidence_set_document(
            request, document
        )
        self.assertEqual(result["status"], evidence.STATUS_UNSUPPORTED)
        self.assertEqual(evidence.environment_evidence_result_exit_code(result), 1)

    def test_core_and_runtime_field_semantics_are_closed(self):
        for capture_root, expected_status in (
            (None, evidence.STATUS_DOCUMENT_VALID),
            ("/", evidence.STATUS_UNSUPPORTED),
        ):
            plan = valid_model_plan()
            core = valid_core_config(plan)
            core["capture_root"] = capture_root
            bundle = valid_phase5a_request(
                plan,
                core_document=core,
                runtime_document=valid_runtime_config(core),
                embedding_identity=embedding_space_identity(core),
            )
            _plan, request, document = valid_evidence_fixture(plan, bundle)
            self.assertEqual(
                evidence.validate_environment_evidence_set_document(
                    request, document
                )["status"],
                expected_status,
                capture_root,
            )
        core_mutations = (
            ("missing-key", lambda value: value.pop("capture_root")),
            ("protocol", lambda value: value.update({"protocol_version": "wrong.v1"})),
            ("state-path", lambda value: value.update({"state_path": "/private/tmp/wrong"})),
            ("socket-path", lambda value: value.update({"socket_path": "/private/tmp/wrong.sock"})),
            ("dimension", lambda value: value.update({"dimension": 0})),
            ("matrix", lambda value: value.update({"dimension": 65_536, "num_neurons": 131_072})),
            ("provider", lambda value: value.update({"embedding_provider_name": "semantic-hash"})),
            ("relative-cache", lambda value: value.update({"embedding_neural_cache_dir": "relative/cache"})),
            ("local-only", lambda value: value.update({"embedding_neural_local_files_only": False})),
            ("device", lambda value: value.update({"mlx_device": "cpu"})),
            ("native", lambda value: value.update({"require_native": False})),
        )
        for name, mutate in core_mutations:
            plan = valid_model_plan()
            core = valid_core_config(plan)
            runtime = valid_runtime_config(core)
            identity = embedding_space_identity(core)
            mutate(core)
            bundle = valid_phase5a_request(
                plan,
                core_document=core,
                runtime_document=runtime,
                embedding_identity=identity,
            )
            _plan, request, document = valid_evidence_fixture(plan, bundle)
            self.assertEqual(
                evidence.validate_environment_evidence_set_document(
                    request, document
                )["status"],
                evidence.STATUS_UNSUPPORTED,
                name,
            )

        runtime_mutations = (
            ("missing-key", lambda value: value.pop("pooling")),
            ("schema", lambda value: value.update({"schema": "wrong.v1"})),
            ("provider", lambda value: value.update({"provider": "remote"})),
            ("model", lambda value: value.update({"model_id": "different/model"})),
            ("revision", lambda value: value.update({"revision": "00" * 20})),
            ("cache", lambda value: value.update({"cache_dir": "/private/tmp/other"})),
            ("pooling", lambda value: value.update({"pooling": "first"})),
            ("tokens", lambda value: value.update({"max_tokens": 1})),
            ("normalize", lambda value: value.update({"normalize": False})),
            ("local-only", lambda value: value.update({"local_files_only": False})),
        )
        for name, mutate in runtime_mutations:
            plan = valid_model_plan()
            core = valid_core_config(plan)
            runtime = valid_runtime_config(core)
            mutate(runtime)
            bundle = valid_phase5a_request(
                plan, core_document=core, runtime_document=runtime
            )
            _plan, request, document = valid_evidence_fixture(plan, bundle)
            self.assertEqual(
                evidence.validate_environment_evidence_set_document(
                    request, document
                )["status"],
                evidence.STATUS_UNSUPPORTED,
                name,
            )

        plan = valid_model_plan()
        bundle = valid_phase5a_request(plan, embedding_identity="cd" * 32)
        _plan, request, document = valid_evidence_fixture(plan, bundle)
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

    def test_absolute_path_codepoint_bounds_are_closed(self):
        def status_for_capture_root(path):
            plan = valid_model_plan()
            core = valid_core_config(plan)
            core["capture_root"] = path
            runtime = valid_runtime_config(core)
            bundle = valid_phase5a_request(
                plan,
                core_document=core,
                runtime_document=runtime,
                embedding_identity=embedding_space_identity(core),
            )
            _plan, request, document = valid_evidence_fixture(plan, bundle)
            return evidence.validate_environment_evidence_set_document(
                request, document
            )["status"]

        self.assertEqual(
            status_for_capture_root("/private/tmp/printable-~-path"),
            evidence.STATUS_DOCUMENT_VALID,
        )
        for codepoint in (31, 127):
            self.assertEqual(
                status_for_capture_root(
                    "/private/tmp/control-" + chr(codepoint) + "-path"
                ),
                evidence.STATUS_UNSUPPORTED,
                codepoint,
            )

    def test_core_numeric_relation_tables_drive_runtime(self):
        plan = valid_model_plan()
        core = valid_core_config(plan)
        core.update({
            "dimension": 4093,
            "num_neurons": 8192,
            "default_top_k": 8192,
        })
        request, _core_json, _runtime_json = valid_phase5a_request(
            plan,
            core_document=core,
            runtime_document=valid_runtime_config(core),
            embedding_identity=embedding_space_identity(core),
        )
        evidence._core_config(core, request)

        original = evidence.CORE_CONFIG_NEURAL_MATRIX_TERMS
        evidence.CORE_CONFIG_NEURAL_MATRIX_TERMS = (
            original[:-1] + (("num_neurons", None, 4),)
        )
        try:
            with self.assertRaises(evidence._Reject):
                evidence._core_config(core, request)
        finally:
            evidence.CORE_CONFIG_NEURAL_MATRIX_TERMS = original

    def test_secret_shaped_identifiers_and_paths_are_rejected(self):
        for secret_model_id in (
            "owner/hf_abcdefghijklmnop",
            "owner/sk-abcdefgh",
        ):
            plan = valid_model_plan()
            plan["model_id"] = secret_model_id
            self.assertEqual(
                evidence.validate_model_snapshot_plan_document(plan)["status"],
                evidence.STATUS_UNSUPPORTED,
            )

        def status_for_assignment(assignment):
            plan = valid_model_plan()
            core = valid_core_config(plan)
            core["embedding_neural_cache_dir"] = (
                f"/private/tmp/{assignment}/environment/"
                "share/synapse-s2/model-cache-v1"
            )
            runtime = valid_runtime_config(core)
            bundle = valid_phase5a_request(
                plan,
                core_document=core,
                runtime_document=runtime,
                embedding_identity=embedding_space_identity(core),
            )
            _plan, request, document = valid_evidence_fixture(plan, bundle)
            return evidence.validate_environment_evidence_set_document(
                request, document
            )["status"]

        for assignment in (
            "api_key=abcdefgh", "access_token=abcdefgh",
            "client_secret=abcdefgh", "passphrase=abcdefgh",
            "database_url=abcdefgh",
            '{"api_key":"abcdefgh"}',
            "{'client_secret':'abcdefgh'}",
        ):
            self.assertEqual(
                status_for_assignment(assignment),
                evidence.STATUS_UNSUPPORTED,
                assignment,
            )
        for safe_assignment in (
            "token_count=5",
            '{"token_count":"5"}',
            "transport_token_stored=false",
        ):
            self.assertEqual(
                status_for_assignment(safe_assignment),
                evidence.STATUS_DOCUMENT_VALID,
                safe_assignment,
            )

    def test_secret_shape_field_bindings_drive_runtime_and_identity(self):
        plan = valid_model_plan()
        plan["model_id"] = "owner/hf_abcdefghijklmnop"
        with self.assertRaises(evidence._Reject):
            evidence._model_snapshot_plan(plan)
        baseline = evidence.environment_evidence_contract_projection()[
            "contract_id"
        ]
        original = evidence.SECRET_SHAPE_DOCUMENT_BINDINGS
        evidence.SECRET_SHAPE_DOCUMENT_BINDINGS = (
            original[0],
            (
                original[1][0], original[1][1], original[1][2],
                ("model_revision",),
            ),
        )
        try:
            plan["environment_policy_id"] = evidence.environment_policy_id()
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            self.assertEqual(
                evidence._model_snapshot_plan(plan),
                domain_hash("model_plan", plan),
            )
        finally:
            evidence.SECRET_SHAPE_DOCUMENT_BINDINGS = original

    def test_document_string_pattern_bindings_drive_runtime_and_identity(self):
        plan = valid_model_plan()
        plan["model_id"] = "singlemodel"
        with self.assertRaises(evidence._Reject):
            evidence._model_snapshot_plan(plan)
        baseline = evidence.environment_evidence_contract_projection()[
            "contract_id"
        ]
        original = evidence.DOCUMENT_STRING_PATTERN_BINDINGS
        mutated = dict(original)
        model_bindings = list(mutated["model_snapshot_plan"])
        model_bindings[0] = (model_bindings[0][0], evidence._LABEL_PATTERN)
        mutated["model_snapshot_plan"] = tuple(model_bindings)
        evidence.DOCUMENT_STRING_PATTERN_BINDINGS = mutated
        try:
            plan["environment_policy_id"] = evidence.environment_policy_id()
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            self.assertEqual(
                evidence.validate_model_snapshot_plan_document(plan)[
                    "status"
                ],
                evidence.STATUS_UNSUPPORTED,
            )
            self.assertEqual(
                evidence._model_snapshot_plan(plan),
                domain_hash("model_plan", plan),
            )
        finally:
            evidence.DOCUMENT_STRING_PATTERN_BINDINGS = original

        original_helpers = evidence.HELPER_STRING_PATTERN_BINDINGS
        with self.assertRaises(evidence._Reject):
            evidence._tree_relative_path(".hidden")
        evidence.HELPER_STRING_PATTERN_BINDINGS = tuple(
            (
                role,
                evidence._RELATIVE_PATH_PATTERN
                if role == "tree_component" else pattern,
            )
            for role, pattern in original_helpers
        )
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            self.assertEqual(
                evidence._tree_relative_path(".hidden"), ".hidden"
            )
        finally:
            evidence.HELPER_STRING_PATTERN_BINDINGS = original_helpers

    def test_path_predicate_bindings_drive_runtime_and_identity(self):
        baseline = evidence.environment_evidence_contract_projection()[
            "contract_id"
        ]
        with self.assertRaises(evidence._Reject):
            evidence._absolute_path("relative")
        original = evidence.PATH_REJECTION_PREDICATE_BINDINGS
        mutated = dict(original)
        absolute_bindings = list(original["absolute_path"])
        absolute_bindings[0] = absolute_bindings[0][:-1] + (True,)
        mutated["absolute_path"] = tuple(absolute_bindings)
        evidence.PATH_REJECTION_PREDICATE_BINDINGS = mutated
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            self.assertEqual(
                evidence._absolute_path("relative"), "relative"
            )
        finally:
            evidence.PATH_REJECTION_PREDICATE_BINDINGS = original

        original_combiner = evidence.PATH_REJECTION_PREDICATE_COMBINER
        evidence.PATH_REJECTION_PREDICATE_COMBINER = (
            "reject-on-no-predicate-match"
        )
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            with self.assertRaises(evidence._Reject):
                evidence._absolute_path("/valid")
        finally:
            evidence.PATH_REJECTION_PREDICATE_COMBINER = original_combiner

    def test_dynamic_roles_are_exact_pending_null(self):
        for slot in evidence.DYNAMIC_PENDING_SLOTS:
            _plan, request, document = valid_evidence_fixture()
            document["documents_by_slot"][slot] = {"schema": evidence.SLOT_SCHEMAS[slot]}
            document["digests_by_slot"][slot] = "91" * 32
            result = evidence.validate_environment_evidence_set_document(request, document)
            self.assertEqual(result["status"], evidence.STATUS_UNSUPPORTED, slot)

    def test_every_static_digest_and_storage_binding_is_recomputed(self):
        mutations = (
            lambda d: d["digests_by_slot"].update({"environment_manifest_sha256": "92" * 32}),
            lambda d: d["digests_by_slot"].update({"installed_distribution_manifest_sha256": "93" * 32}),
            lambda d: d["digests_by_slot"].update({"native_file_manifest_sha256": "94" * 32}),
            lambda d: d["digests_by_slot"].update({"model_manifest_sha256": "95" * 32}),
            lambda d: d.update({"storage_digest": "96" * 32}),
            lambda d: d["storage_prepare_record"].update({"manifest_total_bytes": 999}),
            lambda d: d["storage_request_record"].update({"layout_id": "layout-" + "97" * 32}),
        )
        for mutate in mutations:
            _plan, request, document = valid_evidence_fixture()
            mutate(document)
            self.assertEqual(
                evidence.validate_environment_evidence_set_document(request, document)["status"],
                evidence.STATUS_UNSUPPORTED,
            )

    def test_request_transplant_and_model_cross_bindings_fail(self):
        mutations = (
            lambda d: d["environment_request"].update({"host_id_sha256": "98" * 32}),
            lambda d: d["documents_by_slot"]["model_manifest_sha256"].update({"model_revision": "99" * 20}),
            lambda d: d["documents_by_slot"]["installed_distribution_manifest_sha256"].update({"dependency_lock_sha256": "9a" * 32}),
            lambda d: d["documents_by_slot"]["native_file_manifest_sha256"].update({"target_machine": "x86_64"}),
        )
        for mutate in mutations:
            _plan, request, document = valid_evidence_fixture()
            mutate(document)
            self.assertEqual(evidence.validate_environment_evidence_set_document(request, document)["status"], evidence.STATUS_UNSUPPORTED)

    def test_cross_manifest_contradictions_fail_even_after_role_rehash(self):
        cases = (
            ("installed_distribution_manifest_sha256", "files", "sha256", "aa" * 32, "installed"),
            ("native_file_manifest_sha256", "files", "sha256", "bb" * 32, "native"),
        )
        for slot, collection, field, value, domain in cases:
            _plan, request, document = valid_evidence_fixture()
            role = document["documents_by_slot"][slot]
            role[collection][0][field] = value
            document["digests_by_slot"][slot] = domain_hash(domain, role)
            result = evidence.validate_environment_evidence_set_document(request, document)
            self.assertEqual(result["status"], evidence.STATUS_UNSUPPORTED, slot)

        _plan, request, document = valid_evidence_fixture()
        docs = document["documents_by_slot"]
        installed = docs["installed_distribution_manifest_sha256"]
        native = docs["native_file_manifest_sha256"]
        docs["installed_distribution_manifest_sha256"] = native
        docs["native_file_manifest_sha256"] = installed
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

    def test_record_owner_snapshot_root_and_casefold_aliases_fail(self):
        _plan, request, document = valid_evidence_fixture()
        installed = document["documents_by_slot"]["installed_distribution_manifest_sha256"]
        installed["files"][0]["record_sha256"] = "cc" * 32
        document["digests_by_slot"]["installed_distribution_manifest_sha256"] = domain_hash("installed", installed)
        self.assertEqual(evidence.validate_environment_evidence_set_document(request, document)["status"], evidence.STATUS_UNSUPPORTED)

        plan = valid_model_plan()
        plan["snapshot_root_relative"] = "share/synapse-s2/model-cache-v1/other"
        self.assertEqual(evidence.validate_model_snapshot_plan_document(plan)["status"], evidence.STATUS_UNSUPPORTED)

        plan = valid_model_plan()
        alias = copy.deepcopy(plan["entries"][0])
        alias["path"] = "CONFIG.JSON"
        plan["entries"].append(alias)
        plan["entries"].sort(key=lambda entry: entry["path"])
        plan["entry_count"] += 1
        plan["total_bytes"] += alias["size"]
        self.assertEqual(evidence.validate_model_snapshot_plan_document(plan)["status"], evidence.STATUS_UNSUPPORTED)

    def test_persisted_fingerprint_modes_and_links_replay_phase5b1(self):
        _plan, request, document = valid_evidence_fixture()
        request_record = document["storage_request_record"]
        request_record["environment_preimage_fingerprint"].update({
            "device": evidence.MAX_INT + 1,
            "inode": evidence.MAX_INT + 2,
        })
        request_record["operation_fingerprint"].update({
            "device": evidence.MAX_INT + 1,
            "inode": evidence.MAX_INT + 3,
        })
        rehash_storage_fixture(document)
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_DOCUMENT_VALID,
        )

        request_record["environment_preimage_fingerprint"]["device"] = (
            evidence.MAX_NATIVE_INT + 1
        )
        rehash_storage_fixture(document)
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

        mutations = (
            lambda record: record["environment_preimage_fingerprint"].update(
                {"mode": 0o40700}
            ),
            lambda record: record["environment_preimage_fingerprint"].update(
                {"nlink": 3}
            ),
            lambda record: record["operation_fingerprint"].update({"mode": 0o755}),
            lambda record: record["operation_fingerprint"].update({"nlink": 1}),
            lambda record: record["operation_fingerprint"].update({"device": 4}),
            lambda record: record["operation_fingerprint"].update({"inode": 4}),
        )
        for mutate in mutations:
            _plan, request, document = valid_evidence_fixture()
            mutate(document["storage_request_record"])
            rehash_storage_fixture(document, sync_operation_nlink=False)
            result = evidence.validate_environment_evidence_set_document(
                request, document
            )
            self.assertEqual(result["status"], evidence.STATUS_UNSUPPORTED)

    def test_tree_replays_phase5b1_paths_bounds_and_dfs_order(self):
        _plan, request, document = valid_evidence_fixture()
        document["storage_manifest"]["entries"].extend([
            {"path": "pkg", "kind": "directory", "mode": "0700",
             "size": 0, "sha256": ""},
            {"path": "pkg/item", "kind": "file", "mode": "0600",
             "size": 1, "sha256": "31" * 32},
            {"path": "pkg.py", "kind": "file", "mode": "0600",
             "size": 1, "sha256": "32" * 32},
        ])
        rehash_storage_fixture(document)
        paths = [entry["path"] for entry in document["storage_manifest"]["entries"]]
        self.assertLess(paths.index("pkg/item"), paths.index("pkg.py"))
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_DOCUMENT_VALID,
        )

        invalid_entries = (
            {"path": ".hidden", "kind": "file", "mode": "0600",
             "size": 1, "sha256": "33" * 32},
            {"path": "x" * 201, "kind": "directory", "mode": "0700",
             "size": 0, "sha256": ""},
            {"path": "oversized", "kind": "file", "mode": "0600",
             "size": evidence.PHASE5B1_MAX_TREE_FILE_BYTES + 1,
             "sha256": "34" * 32},
        )
        for entry in invalid_entries:
            _plan, request, document = valid_evidence_fixture()
            document["storage_manifest"]["entries"].append(entry)
            rehash_storage_fixture(document)
            self.assertEqual(
                evidence.validate_environment_evidence_set_document(
                    request, document
                )["status"],
                evidence.STATUS_UNSUPPORTED,
            )

        _plan, request, document = valid_evidence_fixture()
        document["storage_manifest"]["entries"].extend([
            {"path": "file-parent", "kind": "file", "mode": "0600",
             "size": 1, "sha256": "36" * 32},
            {"path": "file-parent/child", "kind": "file", "mode": "0600",
             "size": 1, "sha256": "37" * 32},
        ])
        rehash_storage_fixture(document)
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

        _plan, request, document = valid_evidence_fixture()
        parent = ""
        for index in range(evidence.PHASE5B1_MAX_TREE_DEPTH + 1):
            parent = (parent + "/" if parent else "") + f"d{index:02d}"
            document["storage_manifest"]["entries"].append({
                "path": parent, "kind": "directory", "mode": "0700",
                "size": 0, "sha256": "",
            })
        rehash_storage_fixture(document)
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

        _plan, request, document = valid_evidence_fixture()
        parent = ""
        for index in range(evidence.PHASE5B1_MAX_TREE_DEPTH):
            parent = (parent + "/" if parent else "") + f"p{index:02d}"
            document["storage_manifest"]["entries"].append({
                "path": parent, "kind": "directory", "mode": "0700",
                "size": 0, "sha256": "",
            })
        document["storage_manifest"]["entries"].append({
            "path": parent + "/leaf", "kind": "file", "mode": "0600",
            "size": 1, "sha256": "35" * 32,
        })
        rehash_storage_fixture(document)
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_DOCUMENT_VALID,
        )

        _plan, request, document = valid_evidence_fixture()
        for index in range(7):
            document["storage_manifest"]["entries"].append({
                "path": f"large{index}", "kind": "file", "mode": "0600",
                "size": evidence.PHASE5B1_MAX_TREE_FILE_BYTES,
                "sha256": f"{40 + index:02x}" * 32,
            })
        rehash_storage_fixture(document)
        self.assertGreater(
            document["storage_manifest"]["total_bytes"],
            evidence.PHASE5B1_MAX_TREE_TOTAL_BYTES,
        )
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

    def test_tree_parent_closure_and_document_byte_bound(self):
        _plan, request, document = valid_evidence_fixture()
        document["storage_manifest"]["entries"].append({
            "path": "missing-parent/file", "kind": "file", "mode": "0600",
            "size": 1, "sha256": "53" * 32,
        })
        rehash_storage_fixture(document)
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

        _plan, request, document = valid_evidence_fixture()
        for index in range(6000):
            name = f"bulk{index:05d}-" + "x" * 180
            document["storage_manifest"]["entries"].append({
                "path": name, "kind": "directory", "mode": "0700",
                "size": 0, "sha256": "",
            })
        rehash_storage_fixture(document)
        self.assertGreater(
            len(canonical(document["storage_manifest"])),
            evidence.PHASE5B1_MAX_DOC_BYTES,
        )
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

    def test_model_cache_is_exact_single_nonempty_revision(self):
        plan = valid_model_plan()
        plan["entries"] = [copy.deepcopy(plan["entries"][0])]
        plan["entries"][0]["size"] = 1
        plan["entry_count"] = 1
        plan["total_bytes"] = 1
        self.assertEqual(
            evidence.validate_model_snapshot_plan_document(plan)["status"],
            evidence.STATUS_DOCUMENT_VALID,
        )

        plan = valid_model_plan()
        plan["entries"] = [{
            "path": "weights", "kind": "directory", "mode": "0700",
            "size": 0, "sha256": "",
        }]
        plan["entry_count"] = 1
        plan["total_bytes"] = 0
        self.assertEqual(
            evidence.validate_model_snapshot_plan_document(plan)["status"],
            evidence.STATUS_UNSUPPORTED,
        )

        plan = valid_model_plan()
        plan["entries"] = []
        plan["entry_count"] = 0
        plan["total_bytes"] = 0
        self.assertEqual(
            evidence.validate_model_snapshot_plan_document(plan)["status"],
            evidence.STATUS_UNSUPPORTED,
        )

        root = "share/synapse-s2/model-cache-v1/snapshots/"
        additions = (
            {"path": root + "f" * 40, "kind": "directory", "mode": "0700",
             "size": 0, "sha256": ""},
            {"path": root + "6c3ae70858513f1a78e9cdca3cae330d9075cd2a/extra.json",
             "kind": "file", "mode": "0600", "size": 3,
             "sha256": "51" * 32},
        )
        for entry in additions:
            _plan, request, document = valid_evidence_fixture()
            document["storage_manifest"]["entries"].append(entry)
            rehash_storage_fixture(document)
            self.assertEqual(
                evidence.validate_environment_evidence_set_document(
                    request, document
                )["status"],
                evidence.STATUS_UNSUPPORTED,
            )

    def test_distribution_names_are_canonical_pep503_names(self):
        self.assertEqual(
            evidence._normalized_distribution_name("demo-pkg"), "demo-pkg"
        )
        for invalid in ("demo_pkg", "demo.pkg", "demo-"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(evidence._Reject):
                    evidence._normalized_distribution_name(invalid)
        _plan, request, document = valid_evidence_fixture()
        installed = document["documents_by_slot"][
            "installed_distribution_manifest_sha256"
        ]
        installed["distributions"][0]["normalized_name"] = "demo-pkg"
        installed["files"][0]["distribution"] = "demo-pkg"
        alias = copy.deepcopy(installed["distributions"][0])
        alias["normalized_name"] = "demo_pkg"
        alias["record_sha256"] = "52" * 32
        installed["distributions"].append(alias)
        installed["distribution_count"] = 2
        rehash_static_role(
            document, "installed_distribution_manifest_sha256", "installed"
        )
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

    def test_distribution_normalization_rules_drive_runtime_and_identity(self):
        baseline = evidence.environment_evidence_contract_projection()[
            "contract_id"
        ]
        original = evidence.DISTRIBUTION_NAME_NORMALIZATION_CHECKS
        evidence.DISTRIBUTION_NAME_NORMALIZATION_CHECKS = original[:-1]
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            self.assertEqual(
                evidence._normalized_distribution_name("demo-"), "demo-"
            )
        finally:
            evidence.DISTRIBUTION_NAME_NORMALIZATION_CHECKS = original

    def test_projected_aggregations_drive_every_claimed_count_and_total(self):
        plan, request, document = valid_evidence_fixture()
        request_sha = document["environment_request_sha256"]
        storage_digest = document["storage_digest"]
        installed = document["documents_by_slot"][
            "installed_distribution_manifest_sha256"
        ]
        native = document["documents_by_slot"][
            "native_file_manifest_sha256"
        ]
        tree = document["storage_manifest"]

        self.assertEqual(
            evidence._model_snapshot_plan(plan), PINNED_MODEL_PLAN_SHA256
        )
        self.assertEqual(
            evidence._tree_manifest(tree, request, request_sha),
            PINNED_TREE_MANIFEST_SHA256,
        )
        self.assertEqual(
            evidence._installed_manifest(
                installed, request, request_sha, storage_digest
            ),
            PINNED_INSTALLED_MANIFEST_SHA256,
        )
        self.assertEqual(
            evidence._native_manifest(
                native, request, request_sha, storage_digest
            ),
            PINNED_NATIVE_MANIFEST_SHA256,
        )

        cases = (
            (evidence._model_snapshot_plan, (plan,), "entry_count"),
            (evidence._model_snapshot_plan, (plan,), "total_bytes"),
            (evidence._tree_manifest, (tree, request, request_sha), "entry_count"),
            (evidence._tree_manifest, (tree, request, request_sha), "total_bytes"),
            (
                evidence._installed_manifest,
                (installed, request, request_sha, storage_digest),
                "distribution_count",
            ),
            (
                evidence._installed_manifest,
                (installed, request, request_sha, storage_digest),
                "file_count",
            ),
            (
                evidence._installed_manifest,
                (installed, request, request_sha, storage_digest),
                "total_bytes",
            ),
            (
                evidence._native_manifest,
                (native, request, request_sha, storage_digest),
                "file_count",
            ),
        )
        for validator, arguments, field in cases:
            with self.subTest(validator=validator.__name__, field=field):
                mutated = copy.deepcopy(arguments[0])
                mutated[field] += 1
                with self.assertRaisesRegex(
                    evidence._Reject, "aggregation-relation"
                ):
                    validator(mutated, *arguments[1:])

    def test_projected_order_and_record_ownership_relations_reject_rehashes(self):
        plan = valid_model_plan()
        plan["entries"].reverse()
        self.assertEqual(
            evidence.validate_model_snapshot_plan_document(plan)["status"],
            evidence.STATUS_UNSUPPORTED,
        )

        plan = valid_model_plan()
        plan["entries"].append({
            "path": "extra.json", "kind": "alien", "mode": "0600",
            "size": 5, "sha256": "99" * 32,
        })
        plan["entries"].sort(key=lambda entry: entry["path"])
        plan["entry_count"] = len(plan["entries"])
        self.assertEqual(
            evidence.validate_model_snapshot_plan_document(plan)["status"],
            evidence.STATUS_UNSUPPORTED,
        )

        _plan, request, document = valid_evidence_fixture()
        installed = document["documents_by_slot"][
            "installed_distribution_manifest_sha256"
        ]
        installed["files"][0]["record_sha256"] = "85" * 32
        rehash_static_role(
            document, "installed_distribution_manifest_sha256", "installed"
        )
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

    def test_distribution_source_and_base_interpreter_roles_are_closed(self):
        _plan, request, document = valid_evidence_fixture()
        installed = document["documents_by_slot"][
            "installed_distribution_manifest_sha256"
        ]
        installed["distributions"][0]["source_kind"] = "git"
        rehash_static_role(
            document, "installed_distribution_manifest_sha256", "installed"
        )
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

        _plan, request, document = valid_evidence_fixture()
        installed = document["documents_by_slot"][
            "installed_distribution_manifest_sha256"
        ]
        installed["distributions"][0]["direct_url_sha256"] = "99" * 32
        rehash_static_role(
            document, "installed_distribution_manifest_sha256", "installed"
        )
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

        _plan, request, document = valid_evidence_fixture()
        installed = document["documents_by_slot"][
            "installed_distribution_manifest_sha256"
        ]
        installed["files"] = []
        installed["file_count"] = 0
        installed["total_bytes"] = 0
        rehash_static_role(
            document, "installed_distribution_manifest_sha256", "installed"
        )
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

        _plan, request, document = valid_evidence_fixture()
        native = document["documents_by_slot"]["native_file_manifest_sha256"]
        native["files"].append({
            "path": "lib/package.py", "owner": "demo", "mode": "0600",
            "size": 7, "sha256": "73" * 32, "architectures": ["arm64"],
            "minimum_os": "14.0", "load_commands_sha256": "87" * 32,
            "dependencies": [], "rpaths": [],
        })
        native["file_count"] = 2
        rehash_static_role(document, "native_file_manifest_sha256", "native")
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_DOCUMENT_VALID,
        )
        native["files"][1]["owner"] = "other"
        rehash_static_role(document, "native_file_manifest_sha256", "native")
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

        _plan, request, document = valid_evidence_fixture()
        native = document["documents_by_slot"]["native_file_manifest_sha256"]
        native["files"][0]["owner"] = "demo"
        rehash_static_role(document, "native_file_manifest_sha256", "native")
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )

    def test_native_sublist_bound_and_order_are_exact(self):
        for field in evidence.NATIVE_SUBLIST_FIELDS:
            for count, expected in (
                (
                    evidence.NATIVE_SUBLIST_MAX_ITEMS,
                    evidence.STATUS_DOCUMENT_VALID,
                ),
                (
                    evidence.NATIVE_SUBLIST_MAX_ITEMS + 1,
                    evidence.STATUS_UNSUPPORTED,
                ),
            ):
                _plan, request, document = valid_evidence_fixture()
                native = document["documents_by_slot"][
                    "native_file_manifest_sha256"
                ]
                if field == "architectures":
                    values = [f"arch{index:03d}" for index in range(count - 1)]
                    values.append("arm64")
                    values.sort()
                else:
                    values = [f"{field}{index:03d}" for index in range(count)]
                native["files"][0][field] = values
                rehash_static_role(
                    document, "native_file_manifest_sha256", "native"
                )
                self.assertEqual(
                    evidence.validate_environment_evidence_set_document(
                        request, document
                    )["status"],
                    expected,
                    (field, count),
                )

        for field, values in (
            ("architectures", ["arm64", "arm64"]),
            ("dependencies", ["libB.dylib", "libA.dylib"]),
            ("rpaths", ["@loader_path", "@loader_path"]),
        ):
            _plan, request, document = valid_evidence_fixture()
            native = document["documents_by_slot"][
                "native_file_manifest_sha256"
            ]
            native["files"][0][field] = values
            rehash_static_role(
                document, "native_file_manifest_sha256", "native"
            )
            self.assertEqual(
                evidence.validate_environment_evidence_set_document(
                    request, document
                )["status"],
                evidence.STATUS_UNSUPPORTED,
                field,
            )

        for field in evidence.NATIVE_TEXT_SUBLIST_FIELDS:
            _plan, request, document = valid_evidence_fixture()
            native = document["documents_by_slot"][
                "native_file_manifest_sha256"
            ]
            native["files"][0][field] = [""]
            rehash_static_role(
                document, "native_file_manifest_sha256", "native"
            )
            self.assertEqual(
                evidence.validate_environment_evidence_set_document(
                    request, document
                )["status"],
                evidence.STATUS_UNSUPPORTED,
                field,
            )

    def test_runtime_semantic_drift_fails_closed_under_frozen_contract_id(self):
        saved_validate_plan = evidence.validate_model_snapshot_plan_document
        original_schema = evidence.MODEL_SNAPSHOT_PLAN_SCHEMA
        plan = valid_model_plan()
        mutated_schema = original_schema + ".mutated"
        evidence.MODEL_SNAPSHOT_PLAN_SCHEMA = mutated_schema
        plan["schema"] = mutated_schema
        try:
            result = evidence.validate_model_snapshot_plan_document(plan)
            self.assertEqual(result["status"], evidence.STATUS_UNSUPPORTED)
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()["contract_id"],
                evidence.EVIDENCE_CONTRACT_ID,
            )
        finally:
            evidence.MODEL_SNAPSHOT_PLAN_SCHEMA = original_schema

        original_patterns = evidence._SECRET_SHAPE_PATTERNS
        original_policy_id = evidence.ENVIRONMENT_POLICY_ID
        original_contract_id = evidence.EVIDENCE_CONTRACT_ID
        evidence._SECRET_SHAPE_PATTERNS = original_patterns + (r"\Anever\Z",)
        try:
            mutated_policy_id = evidence.environment_policy_id()
            evidence.ENVIRONMENT_POLICY_ID = mutated_policy_id
            mutated_contract_id = (
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ]
            )
            evidence.EVIDENCE_CONTRACT_ID = mutated_contract_id
            plan = valid_model_plan()
            plan["environment_policy_id"] = mutated_policy_id
            self.assertTrue(evidence._runtime_projection_intact())
            self.assertFalse(evidence._runtime_contract_intact())
            self.assertEqual(
                saved_validate_plan(plan)["status"],
                evidence.STATUS_UNSUPPORTED,
            )
        finally:
            evidence._SECRET_SHAPE_PATTERNS = original_patterns
            evidence.ENVIRONMENT_POLICY_ID = original_policy_id
            evidence.EVIDENCE_CONTRACT_ID = original_contract_id

        original_binding_keys = evidence.PHASE5A_BINDING_KEYS
        evidence.PHASE5A_BINDING_KEYS = original_binding_keys[:-1]
        try:
            _plan, request, document = valid_evidence_fixture()
            result = evidence.validate_environment_evidence_set_document(
                request, document
            )
            self.assertEqual(result["status"], evidence.STATUS_UNSUPPORTED)
            self.assertFalse(evidence._runtime_contract_intact())
        finally:
            evidence.PHASE5A_BINDING_KEYS = original_binding_keys

        original_prefix = evidence.MODEL_SNAPSHOT_ROOT_PREFIX
        evidence.MODEL_SNAPSHOT_ROOT_PREFIX = (
            evidence.MODEL_CACHE_ROOT_RELATIVE + "/alternate-snapshots/"
        )
        plan = valid_model_plan()
        plan["snapshot_root_relative"] = (
            evidence.MODEL_SNAPSHOT_ROOT_PREFIX + plan["model_revision"]
        )
        try:
            self.assertEqual(
                evidence.validate_model_snapshot_plan_document(plan)["status"],
                evidence.STATUS_UNSUPPORTED,
            )
            self.assertFalse(evidence._runtime_contract_intact())
        finally:
            evidence.MODEL_SNAPSHOT_ROOT_PREFIX = original_prefix

        _plan, request, document = valid_evidence_fixture()
        valid_result_before_drift = evidence.validate_model_snapshot_plan_document(
            valid_model_plan()
        )
        original_guard = evidence._runtime_contract_intact
        original_anchors = evidence._RUNTIME_FUNCTION_ANCHORS
        original_core_validator = evidence._core_config
        original_runtime_validator = evidence._embedding_runtime_config
        original_valid_result = evidence._valid_result
        evidence._core_config = lambda value, _request: (value, "ab" * 32)
        evidence._embedding_runtime_config = (
            lambda value, _request, _core: value
        )
        evidence._runtime_contract_intact = lambda: True
        evidence._RUNTIME_FUNCTION_ANCHORS = ()
        evidence._valid_result = lambda _result: True
        try:
            self.assertTrue(evidence._runtime_contract_intact())
            self.assertFalse(original_guard())
            result = evidence.validate_environment_evidence_set_document(
                request, document
            )
            self.assertEqual(result["status"], evidence.STATUS_UNSUPPORTED)
            self.assertNotEqual(
                evidence.render_environment_evidence_result(result),
                evidence._FALLBACK_LINE,
            )
            self.assertEqual(evidence.environment_evidence_result_exit_code(result), 1)

            valid = original_valid_result
            forged = copy.deepcopy(valid_result_before_drift)
            forged["evidence_verified"] = True
            body = {
                key: forged[key]
                for key in evidence.RESULT_KEYS
                if key != "result_sha256"
            }
            forged["result_sha256"] = domain_hash("result", body)
            self.assertFalse(valid(forged))
            self.assertEqual(
                evidence.render_environment_evidence_result(forged),
                evidence._FALLBACK_LINE,
            )
            self.assertEqual(
                evidence.environment_evidence_result_exit_code(forged), 2
            )
        finally:
            evidence._runtime_contract_intact = original_guard
            evidence._RUNTIME_FUNCTION_ANCHORS = original_anchors
            evidence._core_config = original_core_validator
            evidence._embedding_runtime_config = original_runtime_validator
            evidence._valid_result = original_valid_result

    def test_public_closure_fallback_ignores_ordinary_global_rebinding(self):
        saved_validate_plan = evidence.validate_model_snapshot_plan_document
        saved_validate_evidence = (
            evidence.validate_environment_evidence_set_document
        )
        saved_render = evidence.render_environment_evidence_result
        saved_exit = evidence.environment_evidence_result_exit_code
        _plan, request, document = valid_evidence_fixture()
        plan_fallback = saved_validate_plan(None)
        evidence_fallback = saved_validate_evidence(None, None)
        self.assertEqual(plan_fallback["status"], evidence.STATUS_UNSUPPORTED)
        self.assertEqual(
            evidence_fallback["status"], evidence.STATUS_UNSUPPORTED
        )

        mutations = (
            ("_result", lambda *_args, **_kwargs: {"forged": True}),
            ("_unsupported", lambda *_args, **_kwargs: {"forged": True}),
        ) + tuple(
            (name, object())
            for name in evidence.RUNTIME_INTEGRITY_GLOBAL_NAMES
            if name not in {"_result", "_unsupported"}
        ) + tuple(
            (name, object())
            for name in evidence.RUNTIME_INTEGRITY_BUILTIN_NAMES
        )
        for name, replacement in mutations:
            with self.subTest(name=name):
                present = hasattr(evidence, name)
                original = getattr(evidence, name, None)
                setattr(evidence, name, replacement)
                try:
                    self.assertEqual(saved_validate_plan(valid_model_plan()), plan_fallback)
                    self.assertEqual(
                        saved_validate_evidence(request, document),
                        evidence_fallback,
                    )
                    self.assertNotEqual(
                        saved_render(plan_fallback), evidence._FALLBACK_LINE
                    )
                    self.assertEqual(saved_exit(plan_fallback), 1)
                finally:
                    if present:
                        setattr(evidence, name, original)
                    else:
                        delattr(evidence, name)

        valid_before_rebinding = saved_validate_plan(valid_model_plan())
        original_unsupported_status = evidence.STATUS_UNSUPPORTED
        evidence.STATUS_UNSUPPORTED = evidence.STATUS_DOCUMENT_VALID
        try:
            valid_after_rebinding = saved_validate_plan(valid_model_plan())
            self.assertEqual(valid_after_rebinding, valid_before_rebinding)
            self.assertTrue(evidence._runtime_contract_intact())
            self.assertTrue(evidence._valid_result(valid_after_rebinding))
            self.assertNotEqual(
                saved_render(valid_after_rebinding), evidence._FALLBACK_LINE
            )
            self.assertEqual(saved_exit(valid_after_rebinding), 0)
        finally:
            evidence.STATUS_UNSUPPORTED = original_unsupported_status

    def test_operation_id_is_request_digest_derived(self):
        _plan, request, document = valid_evidence_fixture()
        expected = "operation-" + PINNED_REQUEST_SHA256
        self.assertEqual(document["storage_request_record"]["operation_id"], expected)
        self.assertEqual(document["storage_prepare_record"]["operation_id"], expected)
        self.assertEqual(document["storage_manifest"]["operation_id"], expected)
        document["storage_manifest"]["operation_id"] = "operation-" + "dd" * 32
        document["documents_by_slot"]["environment_manifest_sha256"] = document["storage_manifest"]
        document["storage_manifest_sha256"] = domain_hash("tree", document["storage_manifest"])
        document["digests_by_slot"]["environment_manifest_sha256"] = document["storage_manifest_sha256"]
        self.assertEqual(evidence.validate_environment_evidence_set_document(request, document)["status"], evidence.STATUS_UNSUPPORTED)

    def test_coordinated_result_rehash_cannot_forge_success(self):
        plan = valid_model_plan()
        result = evidence.validate_model_snapshot_plan_document(plan)
        forged = copy.deepcopy(result)
        forged["evidence_verified"] = True
        body = {key: forged[key] for key in evidence.RESULT_KEYS if key != "result_sha256"}
        forged["result_sha256"] = domain_hash("result", body)
        self.assertEqual(evidence.environment_evidence_result_exit_code(forged), 2)
        self.assertEqual(evidence.render_environment_evidence_result(forged), evidence._FALLBACK_LINE)

    def test_coordinated_evidence_rehash_cannot_promote_pending_role(self):
        _plan, request, document = valid_evidence_fixture()
        slot = "model_probe_sha256"
        document["documents_by_slot"][slot] = {"schema": evidence.MODEL_PROBE_SCHEMA}
        document["digests_by_slot"][slot] = "9b" * 32
        forged_sha = domain_hash("evidence_set", document)
        self.assertRegex(forged_sha, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(evidence.validate_environment_evidence_set_document(request, document)["status"], evidence.STATUS_UNSUPPORTED)

    def test_native_unsupported_results_render_and_exit_nonzero(self):
        for result, expected_command, expected_reason in (
            (
                evidence.validate_model_snapshot_plan_document(None),
                evidence.COMMAND_MODEL_PLAN,
                evidence.REASON_MODEL_PLAN_UNSUPPORTED,
            ),
            (
                evidence.validate_environment_evidence_set_document(
                    None, None
                ),
                evidence.COMMAND_EVIDENCE_SET,
                evidence.REASON_EVIDENCE_SET_UNSUPPORTED,
            ),
        ):
            self.assertEqual(result["status"], evidence.STATUS_UNSUPPORTED)
            line = evidence.render_environment_evidence_result(result)
            self.assertNotEqual(line, evidence._FALLBACK_LINE)
            rendered = json.loads(line)
            self.assertEqual(rendered["command"], expected_command)
            self.assertEqual(rendered["reason"], expected_reason)
            self.assertEqual(evidence.environment_evidence_result_exit_code(result), 1)
            shortened = copy.deepcopy(result)
            shortened["nonclaims"].pop()
            self.assertFalse(evidence._valid_result(shortened))
            self.assertEqual(
                evidence.render_environment_evidence_result(shortened),
                evidence._FALLBACK_LINE,
            )
            self.assertEqual(
                evidence.environment_evidence_result_exit_code(shortened), 2
            )
            class PlainStrSubclass(str):
                pass
            subclass_key = {
                (PlainStrSubclass(key) if key == "schema" else key): value
                for key, value in result.items()
            }
            self.assertFalse(evidence._valid_result(subclass_key))
            self.assertEqual(
                evidence.render_environment_evidence_result(subclass_key),
                evidence._FALLBACK_LINE,
            )
            self.assertEqual(
                evidence.environment_evidence_result_exit_code(subclass_key), 2
            )

        baseline = evidence.environment_evidence_contract_projection()[
            "contract_id"
        ]
        original = evidence.RESULT_UNSUPPORTED_RENDER_BINDINGS
        evidence.RESULT_UNSUPPORTED_RENDER_BINDINGS = (
            (evidence.COMMAND_MODEL_PLAN, evidence.COMMAND_EVIDENCE_SET),
            (evidence.COMMAND_EVIDENCE_SET, evidence.COMMAND_MODEL_PLAN),
        )
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            validate_plan, _validate_evidence, _valid, render, _exit = (
                evidence._make_public_apis()
            )
            unsupported = validate_plan(None)
            self.assertEqual(
                json.loads(render(unsupported))["command"],
                evidence.COMMAND_EVIDENCE_SET,
            )
            self.assertEqual(
                json.loads(
                    evidence.render_environment_evidence_result(unsupported)
                )["command"],
                evidence.COMMAND_MODEL_PLAN,
            )
        finally:
            evidence.RESULT_UNSUPPORTED_RENDER_BINDINGS = original

        valid = evidence.validate_model_snapshot_plan_document(
            valid_model_plan()
        )
        forged = copy.deepcopy(valid)
        forged["evidence_verified"] = True
        body = {
            key: forged[key]
            for key in evidence.RESULT_KEYS
            if key != "result_sha256"
        }
        forged["result_sha256"] = domain_hash("result", body)
        validity_original = evidence.RESULT_RENDER_VALIDITY_BINDINGS
        evidence.RESULT_RENDER_VALIDITY_BINDINGS = (
            (False, "render_valid"),
            (True, "render_fallback"),
        )
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            _validate_plan, _validate_evidence, _valid, render, _exit = (
                evidence._make_public_apis()
            )
            self.assertNotEqual(render(forged), evidence._FALLBACK_LINE)
            self.assertEqual(
                evidence.render_environment_evidence_result(forged),
                evidence._FALLBACK_LINE,
            )
        finally:
            evidence.RESULT_RENDER_VALIDITY_BINDINGS = validity_original

        selector_original = (
            evidence.RESULT_RENDER_VALIDITY_SELECTOR_BINDING
        )
        contract_id_original = evidence.EVIDENCE_CONTRACT_ID
        guard_original = evidence._runtime_contract_intact
        anchors_original = evidence._RUNTIME_FUNCTION_ANCHORS
        evidence.RESULT_RENDER_VALIDITY_SELECTOR_BINDING = (
            "valid", "__bool__", False, "__eq__",
        )
        try:
            mutated_contract_id = (
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ]
            )
            self.assertNotEqual(mutated_contract_id, baseline)
            evidence.EVIDENCE_CONTRACT_ID = mutated_contract_id
            mutated_guard, mutated_anchors = evidence._make_runtime_guard()
            evidence._runtime_contract_intact = mutated_guard
            evidence._RUNTIME_FUNCTION_ANCHORS = mutated_anchors
            validate_plan, _validate_evidence, _valid, render, _exit = (
                evidence._make_public_apis()
            )
            mutated_result = validate_plan(valid_model_plan())
            self.assertEqual(
                mutated_result["status"], evidence.STATUS_DOCUMENT_VALID
            )
            self.assertEqual(render(mutated_result), evidence._FALLBACK_LINE)
        finally:
            evidence.RESULT_RENDER_VALIDITY_SELECTOR_BINDING = (
                selector_original
            )
            evidence.EVIDENCE_CONTRACT_ID = contract_id_original
            evidence._runtime_contract_intact = guard_original
            evidence._RUNTIME_FUNCTION_ANCHORS = anchors_original

        tables_original = evidence.DOCUMENT_BINDING_TABLES
        policy_id_original = evidence.ENVIRONMENT_POLICY_ID
        contract_id_original = evidence.EVIDENCE_CONTRACT_ID
        guard_original = evidence._runtime_contract_intact
        anchors_original = evidence._RUNTIME_FUNCTION_ANCHORS
        evidence.DOCUMENT_BINDING_TABLES = {
            **tables_original,
            "render_fallback_value": (("line", "local:_result"),),
        }
        try:
            mutated_policy_id = evidence.environment_policy_id()
            evidence.ENVIRONMENT_POLICY_ID = mutated_policy_id
            mutated_contract_id = (
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ]
            )
            self.assertNotEqual(mutated_contract_id, baseline)
            evidence.EVIDENCE_CONTRACT_ID = mutated_contract_id
            mutated_guard, mutated_anchors = evidence._make_runtime_guard()
            evidence._runtime_contract_intact = mutated_guard
            evidence._RUNTIME_FUNCTION_ANCHORS = mutated_anchors
            _validate_plan, _validate_evidence, _valid, render, _exit = (
                evidence._make_public_apis()
            )
            alternate_line = '{"mutated":true}'
            self.assertEqual(render(alternate_line), alternate_line)
        finally:
            evidence.DOCUMENT_BINDING_TABLES = tables_original
            evidence.ENVIRONMENT_POLICY_ID = policy_id_original
            evidence.EVIDENCE_CONTRACT_ID = contract_id_original
            evidence._runtime_contract_intact = guard_original
            evidence._RUNTIME_FUNCTION_ANCHORS = anchors_original

        tables_original = evidence.DOCUMENT_BINDING_TABLES
        policy_id_original = evidence.ENVIRONMENT_POLICY_ID
        contract_id_original = evidence.EVIDENCE_CONTRACT_ID
        guard_original = evidence._runtime_contract_intact
        anchors_original = evidence._RUNTIME_FUNCTION_ANCHORS
        evidence.DOCUMENT_BINDING_TABLES = {
            **tables_original,
            "render_precomputed_value": (
                ("line", "argument:different_line"),
            ),
        }
        try:
            mutated_policy_id = evidence.environment_policy_id()
            evidence.ENVIRONMENT_POLICY_ID = mutated_policy_id
            mutated_contract_id = (
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ]
            )
            self.assertNotEqual(mutated_contract_id, baseline)
            evidence.EVIDENCE_CONTRACT_ID = mutated_contract_id
            mutated_guard, mutated_anchors = evidence._make_runtime_guard()
            evidence._runtime_contract_intact = mutated_guard
            evidence._RUNTIME_FUNCTION_ANCHORS = mutated_anchors
            validate_plan, _validate_evidence, _valid, render, _exit = (
                evidence._make_public_apis()
            )
            unsupported = validate_plan(None)
            self.assertEqual(unsupported["status"], evidence.STATUS_UNSUPPORTED)
            self.assertEqual(render(unsupported), evidence._FALLBACK_LINE)
        finally:
            evidence.DOCUMENT_BINDING_TABLES = tables_original
            evidence.ENVIRONMENT_POLICY_ID = policy_id_original
            evidence.EVIDENCE_CONTRACT_ID = contract_id_original
            evidence._runtime_contract_intact = guard_original
            evidence._RUNTIME_FUNCTION_ANCHORS = anchors_original

        dynamic_original = (
            evidence.RESULT_RENDER_DYNAMIC_CANDIDATE_ACTION_RESULT
        )
        evidence.RESULT_RENDER_DYNAMIC_CANDIDATE_ACTION_RESULT = False
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            _validate_plan, _validate_evidence, _valid, render, _exit = (
                evidence._make_public_apis()
            )
            self.assertEqual(render(valid), evidence._FALLBACK_LINE)
        finally:
            evidence.RESULT_RENDER_DYNAMIC_CANDIDATE_ACTION_RESULT = (
                dynamic_original
            )
        self.assertNotEqual(
            evidence.render_environment_evidence_result(valid),
            evidence._FALLBACK_LINE,
        )

    def test_result_exit_path_bindings_drive_runtime_and_identity(self):
        baseline = evidence.environment_evidence_contract_projection()[
            "contract_id"
        ]
        original = evidence.RESULT_EXIT_PATH_BINDINGS
        mutated = tuple(
            (
                role, binding[1], binding[2], "constant-status",
                evidence.STATUS_DOCUMENT_VALID,
            ) if role == "unsupported-template" else binding
            for binding in original
            for role in (binding[0],)
        )
        evidence.RESULT_EXIT_PATH_BINDINGS = mutated
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            validate_plan, _validate_evidence, _valid, _render, exit_code = (
                evidence._make_public_apis()
            )
            unsupported = validate_plan(None)
            self.assertEqual(unsupported["status"], evidence.STATUS_UNSUPPORTED)
            self.assertEqual(exit_code(unsupported), 0)
            self.assertEqual(
                evidence.environment_evidence_result_exit_code(unsupported),
                1,
            )
        finally:
            evidence.RESULT_EXIT_PATH_BINDINGS = original

        action_original = evidence.RESULT_EXIT_PREDICATE_ACTION_BINDINGS
        evidence.RESULT_EXIT_PREDICATE_ACTION_BINDINGS = (
            (False, 1),
            (True, 0),
        )
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            _validate_plan, _validate_evidence, _valid, _render, exit_code = (
                evidence._make_public_apis()
            )
            malformed = {"status": evidence.STATUS_DOCUMENT_VALID}
            self.assertEqual(exit_code(malformed), 0)
            self.assertEqual(
                evidence.environment_evidence_result_exit_code(malformed), 2
            )
        finally:
            evidence.RESULT_EXIT_PREDICATE_ACTION_BINDINGS = action_original

        traversal_original = evidence.RESULT_EXIT_TRAVERSAL_METHOD
        evidence.RESULT_EXIT_TRAVERSAL_METHOD = "__reversed__"
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            validate_plan, _validate_evidence, _valid, _render, exit_code = (
                evidence._make_public_apis()
            )
            unsupported = validate_plan(None)
            self.assertEqual(unsupported["status"], evidence.STATUS_UNSUPPORTED)
            self.assertEqual(exit_code(unsupported), 2)
            self.assertEqual(
                evidence.environment_evidence_result_exit_code(unsupported), 1
            )
        finally:
            evidence.RESULT_EXIT_TRAVERSAL_METHOD = traversal_original

        selection_original = evidence.RESULT_EXIT_SELECTED_PATH_BINDING
        evidence.RESULT_EXIT_SELECTED_PATH_BINDING = ("__getitem__", -1)
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            validate_plan, _validate_evidence, _valid, _render, exit_code = (
                evidence._make_public_apis()
            )
            unsupported = validate_plan(None)
            self.assertEqual(unsupported["status"], evidence.STATUS_UNSUPPORTED)
            self.assertEqual(exit_code(unsupported), 2)
            self.assertEqual(
                evidence.environment_evidence_result_exit_code(unsupported), 1
            )
        finally:
            evidence.RESULT_EXIT_SELECTED_PATH_BINDING = selection_original

        expectation_mutated = tuple(
            (
                role, binding[1], False, binding[3], binding[4],
            ) if role == "unsupported-template" else binding
            for binding in original
            for role in (binding[0],)
        )
        evidence.RESULT_EXIT_PATH_BINDINGS = expectation_mutated
        try:
            self.assertNotEqual(
                evidence.environment_evidence_contract_projection()[
                    "contract_id"
                ],
                baseline,
            )
            _validate_plan, _validate_evidence, _valid, _render, exit_code = (
                evidence._make_public_apis()
            )
            malformed = {"status": evidence.STATUS_DOCUMENT_VALID}
            self.assertEqual(exit_code(malformed), 0)
            self.assertEqual(
                evidence.environment_evidence_result_exit_code(malformed), 2
            )
        finally:
            evidence.RESULT_EXIT_PATH_BINDINGS = original

    def test_renderer_is_exact_redacted_surface(self):
        _plan, request, document = valid_evidence_fixture()
        result = evidence.validate_environment_evidence_set_document(request, document)
        line = evidence.render_environment_evidence_result(result)
        rendered = json.loads(line)
        self.assertEqual(
            rendered,
            {
                "schema": "synapse-s2.release-environment-evidence-render.v1",
                "result_schema": (
                    "synapse-s2.release-environment-evidence-result.v1"
                ),
                "command": result["command"],
                "status": result["status"],
                "reason": result["reason"],
                "evidence_contract_id": result["evidence_contract_id"],
                "environment_policy_id": result["environment_policy_id"],
                "model_snapshot_plan_sha256": (
                    result["model_snapshot_plan_sha256"]
                ),
                "environment_request_sha256": (
                    result["environment_request_sha256"]
                ),
                "evidence_set_sha256": result["evidence_set_sha256"],
                "document_valid": result["document_valid"],
                "evidence_verified": False,
                "receipt_issuable": False,
                "receipt_published": False,
                "blocker_5_complete": False,
                "result_sha256": result["result_sha256"],
            },
        )
        for secret in (
            request["model_id"], request["root_key_id"], "lib/package.py",
            "base-interpreter", request["candidate_product_id"],
        ):
            self.assertNotIn(secret, line)
        self.assertLessEqual(len(line.encode("ascii")), evidence.MAX_RENDER_BYTES)

    def test_hostile_types_run_no_equality_hooks(self):
        EqualityProbe.calls = 0
        plan = valid_model_plan()
        plan["schema"] = EqualityProbe()
        self.assertEqual(evidence.validate_model_snapshot_plan_document(plan)["status"], evidence.STATUS_UNSUPPORTED)
        _p, request, document = valid_evidence_fixture()
        document["schema"] = EqualityProbe()
        self.assertEqual(evidence.validate_environment_evidence_set_document(request, document)["status"], evidence.STATUS_UNSUPPORTED)
        _p, request, document = valid_evidence_fixture()
        document["documents_by_slot"][evidence.DYNAMIC_PENDING_SLOTS[0]] = (
            EqualityProbe()
        )
        self.assertEqual(
            evidence.validate_environment_evidence_set_document(
                request, document
            )["status"],
            evidence.STATUS_UNSUPPORTED,
        )
        self.assertEqual(EqualityProbe.calls, 0)

    def test_renderer_and_exit_are_total_for_hostile_values(self):
        class Boom:
            def __eq__(self, _other):
                raise SystemExit("boom")
            def __str__(self):
                raise KeyboardInterrupt("boom")
        hostile = {key: None for key in evidence.RESULT_KEYS}
        hostile["status"] = Boom()
        self.assertEqual(evidence.render_environment_evidence_result(hostile), evidence._FALLBACK_LINE)
        self.assertEqual(evidence.environment_evidence_result_exit_code(hostile), 2)
        self.assertEqual(evidence.render_environment_evidence_result(ResultSubclass()), evidence._FALLBACK_LINE)

    def test_wrong_cardinality_rejects_before_sorted(self):
        original = getattr(evidence, "sorted", None)
        native_sorted = builtins.sorted
        invalid = {"schema": "x"}
        def guarded(value, *args, **kwargs):
            if value is invalid:
                raise AssertionError("invalid input reached sorted")
            return native_sorted(value, *args, **kwargs)
        evidence.sorted = guarded
        try:
            result = evidence.validate_model_snapshot_plan_document(invalid)
            self.assertEqual(result["status"], evidence.STATUS_UNSUPPORTED)
        finally:
            if original is None:
                delattr(evidence, "sorted")
            else:
                evidence.sorted = original

    def test_contract_identity_changes_for_bound_policy_and_domain_mutations(self):
        baseline = evidence.environment_evidence_contract_projection()["contract_id"]
        original_depth = evidence.MAX_DEPTH
        evidence.MAX_DEPTH = original_depth + 1
        try:
            self.assertNotEqual(evidence.environment_evidence_contract_projection()["contract_id"], baseline)
        finally:
            evidence.MAX_DEPTH = original_depth
        original = evidence._DOMAINS["contract"]
        evidence._DOMAINS["contract"] = original + b"x"
        try:
            self.assertNotEqual(evidence.environment_evidence_contract_projection()["contract_id"], baseline)
        finally:
            evidence._DOMAINS["contract"] = original

        mutation_cases = (
            ("_PHASE5A_PATTERNS", {**evidence._PHASE5A_PATTERNS, "channel": r"\Ax\Z"}),
            ("FALSE_FLAGS", evidence.FALSE_FLAGS + ("future_false_flag",)),
            ("FALSE_FLAG_BINDINGS", tuple((key, True) if key == "evidence_verified" else (key, value) for key, value in evidence.FALSE_FLAG_BINDINGS)),
            ("DISTRIBUTION_SOURCE_KINDS", evidence.DISTRIBUTION_SOURCE_KINDS + ("sdist",)),
            ("MODEL_FORBIDDEN_SUFFIXES", evidence.MODEL_FORBIDDEN_SUFFIXES + (".bin",)),
            ("MODEL_ALLOWED_FILE_SUFFIXES", evidence.MODEL_ALLOWED_FILE_SUFFIXES + (".bin",)),
            ("MODEL_FILE_SUFFIX_RULE_BINDINGS", evidence.MODEL_FILE_SUFFIX_RULE_BINDINGS[::-1]),
            ("SECRET_SHAPE_DOCUMENT_BINDINGS", evidence.SECRET_SHAPE_DOCUMENT_BINDINGS[:-1]),
            ("SECRET_SHAPE_DOCUMENT_EXACT_MATCHES", 2),
            ("DISTRIBUTION_NAME_NORMALIZATION_TRANSFORM", evidence.DISTRIBUTION_NAME_NORMALIZATION_TRANSFORM[:-1] + (r"\A[a-z0-9-]+\Z",)),
            ("DISTRIBUTION_NAME_NORMALIZATION_CHECKS", evidence.DISTRIBUTION_NAME_NORMALIZATION_CHECKS[:-1]),
            ("DOCUMENT_STRING_PATTERN_BINDINGS", {**evidence.DOCUMENT_STRING_PATTERN_BINDINGS, "model_snapshot_plan": (("model_id", evidence._LABEL_PATTERN),) + evidence.DOCUMENT_STRING_PATTERN_BINDINGS["model_snapshot_plan"][1:]}),
            ("HELPER_STRING_PATTERN_BINDINGS", tuple((role, evidence._RELATIVE_PATH_PATTERN if role == "tree_component" else pattern) for role, pattern in evidence.HELPER_STRING_PATTERN_BINDINGS)),
            ("PATH_REJECTION_PREDICATE_BINDINGS", {**evidence.PATH_REJECTION_PREDICATE_BINDINGS, "relative_path": evidence.PATH_REJECTION_PREDICATE_BINDINGS["relative_path"][:-1]}),
            ("PATH_REJECTION_PREDICATE_COMPARATOR_METHOD", "__ne__"),
            ("PATH_REJECTION_PREDICATE_COMBINER", "accept-on-any-predicate-match"),
            ("PATH_REJECTION_PREDICATE_COMBINER_BINDINGS", ((evidence.PATH_REJECTION_PREDICATE_COMBINER, evidence.POLICY_MEMBERSHIP_METHOD, False),)),
            ("NATIVE_SUBLIST_STRING_PATTERN_BINDINGS", (("architectures", evidence._LABEL_PATTERN),)),
            ("CORE_CONFIG_SCHEMA", evidence.CORE_CONFIG_SCHEMA + ".changed"),
            ("CORE_CONFIG_KEYS", evidence.CORE_CONFIG_KEYS[:-1]),
            ("EMBEDDING_RUNTIME_CONFIG_KEYS", evidence.EMBEDDING_RUNTIME_CONFIG_KEYS[:-1]),
            ("CORE_CONFIG_MAX_SOCKET_BYTES", evidence.CORE_CONFIG_MAX_SOCKET_BYTES - 1),
            ("ABSOLUTE_PATH_MIN_CODEPOINT", evidence.ABSOLUTE_PATH_MIN_CODEPOINT - 1),
            ("ABSOLUTE_PATH_MAX_CODEPOINT", evidence.ABSOLUTE_PATH_MAX_CODEPOINT + 1),
            ("PATH_SYNTAX_VALUES", evidence.PATH_SYNTAX_VALUES[:-1]),
            ("PATH_FORBIDDEN_COMPONENTS", evidence.PATH_FORBIDDEN_COMPONENTS[:-1]),
            ("CORE_CONFIG_PATH_ROLE_BINDINGS", evidence.CORE_CONFIG_PATH_ROLE_BINDINGS[:-1]),
            ("CORE_CONFIG_DISTINCT_PATH_ROLES", evidence.CORE_CONFIG_DISTINCT_PATH_ROLES[:-1]),
            ("CORE_CONFIG_PARENT_SUFFIX_BINDINGS", evidence.CORE_CONFIG_PARENT_SUFFIX_BINDINGS[::-1]),
            ("CORE_CONFIG_SUFFIX_BINDINGS", evidence.CORE_CONFIG_SUFFIX_BINDINGS + (("capture_root", "capture"),)),
            ("CORE_CONFIG_PATH_BYTE_BOUNDS", evidence.CORE_CONFIG_PATH_BYTE_BOUNDS + (("state_path", 4096),)),
            ("CORE_CONFIG_INTEGER_BOUNDS", {**evidence.CORE_CONFIG_INTEGER_BOUNDS, "dimension": (2, 65_536)}),
            ("CORE_CONFIG_FLOAT_BOUNDS", {**evidence.CORE_CONFIG_FLOAT_BOUNDS, "capture_poll_seconds": (0.5, 300.0)}),
            ("CORE_CONFIG_INTEGER_BOUND_ROLES", evidence.CORE_CONFIG_INTEGER_BOUND_ROLES[:-1]),
            ("CORE_CONFIG_FLOAT_BOUND_ROLES", evidence.CORE_CONFIG_FLOAT_BOUND_ROLES[:-1]),
            ("CORE_CONFIG_BOOLEAN_ROLES", evidence.CORE_CONFIG_BOOLEAN_ROLES[:-1]),
            ("CORE_CONFIG_ORDER_RELATIONS", (("default_top_k", "num_neurons", "less-than"),)),
            ("CORE_CONFIG_COMPARATOR_BINDINGS", (("less-than-or-equal", "__lt__"),)),
            ("CORE_CONFIG_NEURAL_MATRIX_TERMS", evidence.CORE_CONFIG_NEURAL_MATRIX_TERMS[:-1]),
            ("MAX_KEY_CHARS", evidence.MAX_KEY_CHARS + 1),
            ("MAX_NATIVE_INT", evidence.MAX_NATIVE_INT - 1),
            ("MODEL_SNAPSHOT_MIN_ENTRIES", evidence.MODEL_SNAPSHOT_MIN_ENTRIES + 1),
            ("MODEL_SNAPSHOT_MIN_TOTAL_BYTES", evidence.MODEL_SNAPSHOT_MIN_TOTAL_BYTES + 1),
            ("DIRECTORY_ENTRY_EMPTY_SIZE", evidence.DIRECTORY_ENTRY_EMPTY_SIZE + 1),
            ("DIRECTORY_ENTRY_EMPTY_DIGEST", "00"),
            ("TREE_FILE_DEFAULT_MODE", "0700"),
            ("NATIVE_SUBLIST_FIELDS", evidence.NATIVE_SUBLIST_FIELDS[:-1]),
            ("NATIVE_SORTED_UNIQUE_FIELDS", evidence.NATIVE_SORTED_UNIQUE_FIELDS[:-1]),
            ("NATIVE_TEXT_SUBLIST_FIELDS", evidence.NATIVE_TEXT_SUBLIST_FIELDS[:-1]),
            ("NATIVE_SUBLIST_MAX_ITEMS", evidence.NATIVE_SUBLIST_MAX_ITEMS - 1),
            ("NATIVE_TEXT_MIN_CHARS", evidence.NATIVE_TEXT_MIN_CHARS + 1),
            ("STORAGE_DIGEST_COMPONENT_ROLES", evidence.STORAGE_DIGEST_COMPONENT_ROLES[::-1]),
            ("DISTRIBUTION_DIGEST_RELATION_ROLES", evidence.DISTRIBUTION_DIGEST_RELATION_ROLES[:-1]),
            ("PARENT_DIRECTORY_KIND_BY_ROLE", (("tree_manifest", "file"),) + evidence.PARENT_DIRECTORY_KIND_BY_ROLE[1:]),
            ("_SECRET_SHAPE_PATTERNS", evidence._SECRET_SHAPE_PATTERNS + (r"\Anever\Z",)),
            ("_SENSITIVE_ASSIGNMENT_KEY_PATTERN", evidence._SENSITIVE_ASSIGNMENT_KEY_PATTERN + "x"),
            ("EMBEDDING_SPIKE_ENCODER", evidence.EMBEDDING_SPIKE_ENCODER + "-changed"),
            ("EMBEDDING_SPACE_OUTER_BINDINGS", evidence.EMBEDDING_SPACE_OUTER_BINDINGS[:-1]),
            ("EMBEDDING_SPACE_NEURAL_BINDINGS", evidence.EMBEDDING_SPACE_NEURAL_BINDINGS[:-1]),
            ("EMBEDDING_SPACE_CONSTANT_VALUES", evidence.EMBEDDING_SPACE_CONSTANT_VALUES[:-1]),
            ("EMBEDDING_RUNTIME_CONFIG_BINDINGS", evidence.EMBEDDING_RUNTIME_CONFIG_BINDINGS[:-1]),
            ("EMBEDDING_RUNTIME_CONSTANT_VALUES", evidence.EMBEDDING_RUNTIME_CONSTANT_VALUES[:-1]),
            ("DOCUMENT_BINDING_CONSTANT_VALUES", evidence.DOCUMENT_BINDING_CONSTANT_VALUES[:-1]),
            ("POLICY_MEMBERSHIP_METHOD", "__eq__"),
            ("PATH_PREFIX_MATCH_METHOD", "endswith"),
            ("DOCUMENT_BINDING_TABLES", {**evidence.DOCUMENT_BINDING_TABLES, "installed_manifest": evidence.DOCUMENT_BINDING_TABLES["installed_manifest"][:-1]}),
            ("DOCUMENT_BINDING_TABLES", {**evidence.DOCUMENT_BINDING_TABLES, "result": tuple((target, "argument:status") if target == "command" else (target, descriptor) for target, descriptor in evidence.DOCUMENT_BINDING_TABLES["result"])}),
            ("DOCUMENT_BINDING_TABLES", {**evidence.DOCUMENT_BINDING_TABLES, "render": tuple((target, "result:status") if target == "command" else (target, descriptor) for target, descriptor in evidence.DOCUMENT_BINDING_TABLES["render"])}),
            ("DOCUMENT_BINDING_TABLES", {**evidence.DOCUMENT_BINDING_TABLES, "render_line_values": (("fallback", "local:line"), ("rendered", "local:fallback_line"))}),
            ("DOCUMENT_BINDING_TABLES", {**evidence.DOCUMENT_BINDING_TABLES, "render_fallback_value": (("line", "local:unsupported_plan_line"),)}),
            ("DOCUMENT_BINDING_TABLES", {**evidence.DOCUMENT_BINDING_TABLES, "render_precomputed_value": (("line", "argument:different_line"),)}),
            ("CROSS_MANIFEST_TREE_FILE_FIELDS", evidence.CROSS_MANIFEST_TREE_FILE_FIELDS[:-1]),
            ("CROSS_MANIFEST_MODEL_FILE_FIELDS", evidence.CROSS_MANIFEST_MODEL_FILE_FIELDS[:-1]),
            ("DOCUMENT_RELATION_FIELDS", {**evidence.DOCUMENT_RELATION_FIELDS, "native_manifest": evidence.DOCUMENT_RELATION_FIELDS["native_manifest"][:-1]}),
            ("DOCUMENT_AGGREGATION_OPERATIONS", evidence.DOCUMENT_AGGREGATION_OPERATIONS[::-1]),
            ("DOCUMENT_AGGREGATION_COMPARATOR_METHOD", "__ne__"),
            ("DOCUMENT_AGGREGATION_BINDINGS", {**evidence.DOCUMENT_AGGREGATION_BINDINGS, "model_snapshot_plan": evidence.DOCUMENT_AGGREGATION_BINDINGS["model_snapshot_plan"][::-1]}),
            ("DOCUMENT_VALUE_RELATION_BINDINGS", evidence.DOCUMENT_VALUE_RELATION_BINDINGS[::-1]),
            ("COLLECTION_ORDER_DIRECTION_BINDINGS", (("ascending", True),)),
            ("COLLECTION_RELATION_BINDINGS", evidence.COLLECTION_RELATION_BINDINGS[::-1]),
            ("COLLECTION_RELATION_COMPARATOR_METHOD", "__ne__"),
            ("DISTRIBUTION_DIRECT_URL_BINDINGS", (("wheel", "present-sha256"), ("git", "absent"))),
            ("OPTIONAL_VALUE_PRESENCE_BINDINGS", (("absent", "__ne__", False), ("present-sha256", "__eq__", True))),
            ("OPTIONAL_PATH_ACTION_BINDINGS", evidence.OPTIONAL_PATH_ACTION_BINDINGS[::-1]),
            ("OPTIONAL_PATH_ALLOWED_ACTIONS", evidence.OPTIONAL_PATH_ALLOWED_ACTIONS[::-1]),
            ("EXECUTABLE_MODE_CLASSIFICATION_METHOD", "__ne__"),
            ("EXECUTABLE_PATH_MEMBERSHIP_METHOD", "__eq__"),
            ("STORAGE_TOP_LEVEL_DIRECTORY_BINDING", ("entry_kind", "file", "__eq__", "entry_path", "__contains__", False)),
            ("STORAGE_NLINK_COMBINE_METHOD", "__sub__"),
            ("TREE_FILE_MODE_BINDING", ("path", "executable_modes", "path", "get")),
            ("TREE_FILE_MODE_BINDING_FIELDS", evidence.TREE_FILE_MODE_BINDING_FIELDS[:-1]),
            ("ENTRY_KIND_VALIDATOR_BINDINGS", evidence.ENTRY_KIND_VALIDATOR_BINDINGS[::-1]),
            ("ENTRY_FIXED_FIELD_BINDINGS", evidence.ENTRY_FIXED_FIELD_BINDINGS[::-1]),
            ("ENTRY_FIELD_COMPARATOR_METHOD", "__ne__"),
            ("ENTRY_SUFFIX_MATCH_METHOD", "startswith"),
            ("TREE_REQUIRED_ENTRY_RELATION_METHOD", "issuperset"),
            ("STATIC_SLOT_VALIDATOR_ROLES", evidence.STATIC_SLOT_VALIDATOR_ROLES[::-1]),
            ("STATIC_SLOT_VALIDATOR_BINDINGS", evidence.STATIC_SLOT_VALIDATOR_BINDINGS[::-1]),
            ("STATIC_SLOT_VALIDATOR_BINDING_FIELDS", evidence.STATIC_SLOT_VALIDATOR_BINDING_FIELDS[:-1]),
            ("STATIC_VALIDATOR_CONTEXT_BINDINGS", evidence.STATIC_VALIDATOR_CONTEXT_BINDINGS[::-1]),
            ("STATIC_VALIDATOR_CONTEXT_ROLES", evidence.STATIC_VALIDATOR_CONTEXT_ROLES[::-1]),
            ("STATIC_PRIMARY_STORAGE_ROLE", "installed_manifest"),
            ("RUNTIME_INTEGRITY_FUNCTION_NAMES", evidence.RUNTIME_INTEGRITY_FUNCTION_NAMES[:-1]),
            ("RUNTIME_INTEGRITY_MODULE_NAMES", evidence.RUNTIME_INTEGRITY_MODULE_NAMES[:-1]),
            ("RUNTIME_INTEGRITY_BUILTIN_NAMES", evidence.RUNTIME_INTEGRITY_BUILTIN_NAMES[:-1]),
            ("RUNTIME_INTEGRITY_GLOBAL_NAMES", evidence.RUNTIME_INTEGRITY_GLOBAL_NAMES[:-1]),
            ("RESULT_REASON_BINDINGS", (
                (
                    evidence.COMMAND_MODEL_PLAN,
                    evidence.STATUS_DOCUMENT_VALID,
                    evidence.REASON_MODEL_PLAN_VALID + "-changed",
                ),
            ) + evidence.RESULT_REASON_BINDINGS[1:]),
            ("RESULT_DOCUMENT_VALID_BINDING", ("status", "__ne__", evidence.STATUS_DOCUMENT_VALID)),
            ("RESULT_DERIVED_BINDINGS", evidence.RESULT_DERIVED_BINDINGS[::-1]),
            ("RESULT_REPLAY_BINDINGS", evidence.RESULT_REPLAY_BINDINGS[::-1]),
            ("UNSUPPORTED_TEMPLATE_MATCH_BINDING", ("exact-native-tree", "__ne__")),
            ("RESULT_EXIT_CODE_BINDINGS", ((evidence.STATUS_DOCUMENT_VALID, 1), (evidence.STATUS_UNSUPPORTED, 0), (evidence.STATUS_INVALID, 2))),
            ("RESULT_EXIT_PATH_BINDINGS", tuple((role, binding[1], binding[2], "constant-status", evidence.STATUS_DOCUMENT_VALID) if role == "unsupported-template" else binding for binding in evidence.RESULT_EXIT_PATH_BINDINGS for role in (binding[0],))),
            ("RESULT_EXIT_PREDICATE_COMPARATOR_METHOD", "__ne__"),
            ("RESULT_EXIT_PREDICATE_ACTION_BINDING_FIELDS", evidence.RESULT_EXIT_PREDICATE_ACTION_BINDING_FIELDS[:-1]),
            ("RESULT_EXIT_PREDICATE_ACTION_BINDINGS", ((False, 1), (True, 0))),
            ("RESULT_EXIT_SELECTION_SEQUENCE_METHOD", "__add__"),
            ("RESULT_EXIT_SELECTION_COLLECTION_METHOD", "append"),
            ("RESULT_EXIT_TRAVERSAL_METHOD", "__reversed__"),
            ("RESULT_EXIT_SELECTED_PATH_BINDING_FIELDS", evidence.RESULT_EXIT_SELECTED_PATH_BINDING_FIELDS[:-1]),
            ("RESULT_EXIT_SELECTED_PATH_BINDING", ("__getitem__", -1)),
            ("RESULT_EXIT_NORMAL_PATH_ROLES", evidence.RESULT_EXIT_NORMAL_PATH_ROLES[::-1]),
            ("RESULT_EXIT_EXCEPTION_PATH_ROLE", "invalid-result"),
            ("RESULT_EXIT_EXCEPTION_PREDICATE_FUNCTION", "exit_matches_any"),
            ("RESULT_UNSUPPORTED_RENDER_BINDING_FIELDS", evidence.RESULT_UNSUPPORTED_RENDER_BINDING_FIELDS[:-1]),
            ("RESULT_UNSUPPORTED_RENDER_BINDINGS", ((evidence.COMMAND_MODEL_PLAN, evidence.COMMAND_EVIDENCE_SET), (evidence.COMMAND_EVIDENCE_SET, evidence.COMMAND_MODEL_PLAN))),
            ("RESULT_UNSUPPORTED_RENDER_MATCH_EXPECTED", False),
            ("RESULT_RENDER_VALIDITY_BINDING_FIELDS", evidence.RESULT_RENDER_VALIDITY_BINDING_FIELDS[:-1]),
            ("RESULT_RENDER_VALIDITY_BINDINGS", ((False, "render_valid"), (True, "render_fallback"))),
            ("RESULT_RENDER_VALIDITY_SELECTOR_BINDING_FIELDS", evidence.RESULT_RENDER_VALIDITY_SELECTOR_BINDING_FIELDS[:-1]),
            ("RESULT_RENDER_VALIDITY_SELECTOR_BINDING", ("valid", "__bool__", False, "__eq__")),
            ("RESULT_RENDER_LINE_SOURCE_BINDING_FIELDS", evidence.RESULT_RENDER_LINE_SOURCE_BINDING_FIELDS[:-1]),
            ("RESULT_RENDER_LINE_SOURCE_BINDINGS", ((False, "rendered"), (True, "fallback"))),
            ("RESULT_RENDER_LINE_SOURCE_ROLES", evidence.RESULT_RENDER_LINE_SOURCE_ROLES[::-1]),
            ("RESULT_RENDER_DYNAMIC_CANDIDATE_ACTION_RESULT", False),
            ("RESULT_SELF_HASH_FIELD", "different_result_sha256"),
            ("RESULT_FALSE_FIELDS", evidence.RESULT_FALSE_FIELDS[:-1]),
            ("_FALLBACK_LINE", evidence._FALLBACK_LINE + " "),
        )
        for name, mutated in mutation_cases:
            with self.subTest(name=name):
                original_value = getattr(evidence, name)
                setattr(evidence, name, mutated)
                try:
                    self.assertNotEqual(
                        evidence.environment_evidence_contract_projection()["contract_id"],
                        baseline,
                        name,
                    )
                finally:
                    setattr(evidence, name, original_value)

        original_bounds = evidence.NUMERIC_BOUND_COMPARATOR_BINDINGS
        evidence.NUMERIC_BOUND_COMPARATOR_BINDINGS = (
            ("value", "minimum", "__gt__"),
            ("value", "maximum", "__le__"),
        )
        try:
            with self.assertRaises(evidence._Reject):
                evidence.environment_evidence_contract_projection()
        finally:
            evidence.NUMERIC_BOUND_COMPARATOR_BINDINGS = original_bounds

        original_equality = evidence.DOCUMENT_BINDING_COMPARATOR_METHOD
        evidence.DOCUMENT_BINDING_COMPARATOR_METHOD = "__ne__"
        try:
            with self.assertRaises(evidence._Reject):
                evidence.environment_evidence_contract_projection()
            result = evidence.validate_model_snapshot_plan_document(
                valid_model_plan()
            )
            self.assertEqual(result["status"], evidence.STATUS_UNSUPPORTED)
        finally:
            evidence.DOCUMENT_BINDING_COMPARATOR_METHOD = original_equality

    def test_purity_ast_and_public_api(self):
        with open(_SOURCE, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        imports = set()
        forbidden_calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            if isinstance(node, ast.ImportFrom):
                imports.add(node.module or "")
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {
                    "open", "exec", "eval", "compile", "__import__",
                }:
                    forbidden_calls.add(node.func.id)
        self.assertEqual(imports, {"hashlib", "json", "math", "re"})
        self.assertEqual(forbidden_calls, set())
        public = {
            "environment_evidence_contract_projection",
            "environment_policy_projection", "environment_policy_id",
            "validate_model_snapshot_plan_document",
            "validate_environment_evidence_set_document",
            "render_environment_evidence_result",
            "environment_evidence_result_exit_code",
        }
        self.assertTrue(public.issubset(set(dir(evidence))))

    def test_public_calls_do_not_use_filesystem(self):
        original_open = builtins.open
        def blocked(*_args, **_kwargs):
            raise AssertionError("filesystem access")
        builtins.open = blocked
        try:
            plan, request, document = valid_evidence_fixture()
            self.assertEqual(evidence.validate_model_snapshot_plan_document(plan)["status"], evidence.STATUS_DOCUMENT_VALID)
            result = evidence.validate_environment_evidence_set_document(request, document)
            self.assertEqual(result["status"], evidence.STATUS_DOCUMENT_VALID)
            evidence.environment_evidence_contract_projection()
            evidence.environment_policy_projection()
            evidence.render_environment_evidence_result(result)
            evidence.environment_evidence_result_exit_code(result)
        finally:
            builtins.open = original_open


if __name__ == "__main__":
    unittest.main()

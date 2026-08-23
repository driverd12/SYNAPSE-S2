"""Phase-5B3b dormant held-root environment-static evidence tests.

All filesystem work is confined to owner-private ``/private/tmp`` fixtures.
The packet never reads or writes live SYNAPSE-S2 state, configuration, model
caches, processes, services, selectors, journals, or activation state.
"""

import ast
import base64
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
    "96a1a770056e4ebcfd26f44ec855bb9ba8f2d7dc8405c0d335ba2942df9b1968"
)
PINNED_CONTRACT_ID = (
    "environment-static-contract-"
    "fd2af17a71695c7fdb112ed50dc8fe72a26c1fa57c5ae3289162ff767357a00f"
)
CONTRACT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STATIC-CONTRACT\0v1\0"
)
FRAGMENT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STATIC-FRAGMENT\0v1\0"
)
RESULT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STATIC-RESULT\0v1\0"
)
MODEL_REVISION = "6c3ae70858513f1a78e9cdca3cae330d9075cd2a"
MODEL_ID = "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ"
MODEL_PAYLOADS = {
    "config.json": b'{"model_type":"synthetic"}',
    "model.safetensors": b"synthetic-model-weights",
}
LOCK_PAYLOAD = b"version = 1\nrevision = 3\n"
PROJECT_PAYLOAD = b'[project]\nname = "synapse-s2"\nversion = "2.14.0"\n'
PACKAGE_PAYLOAD = b'VERSION = "1.0"\n'
METADATA_PAYLOAD = b"Metadata-Version: 2.3\nName: Demo_Pkg\nVersion: 1.0\n\n"
WHEEL_PAYLOAD = (
    b"Wheel-Version: 1.0\nGenerator: synthetic\n"
    b"Root-Is-Purelib: true\nTag: py3-none-any\n"
)
DIRECT_URL_PAYLOAD = (
    b'{"url":"https://github.com/example/demo.git","vcs_info":'
    b'{"commit_id":"1111111111111111111111111111111111111111",'
    b'"requested_revision":"main","vcs":"git"}}'
)


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


def rehash_installed_result(forged):
    """Recompute every documentary binding after an installed/tree mutation."""
    fragment = forged["environment_static_fragment"]
    environment = fragment["environment"]
    installed = fragment["installed"]
    document = installed["installed_distribution_manifest"]
    manifest = environment["storage_manifest"]
    request = environment["environment_request"]
    request_sha256 = environment["environment_request_sha256"]

    document["files"].sort(key=lambda entry: entry["path"])
    document["file_count"] = len(document["files"])
    document["total_bytes"] = sum(entry["size"] for entry in document["files"])
    manifest["entries"].sort(key=lambda entry: entry["path"])
    manifest["entry_count"] = len(manifest["entries"])
    manifest["total_bytes"] = sum(entry["size"] for entry in manifest["entries"])
    manifest_sha256 = b2._tree_manifest(manifest, request, request_sha256)

    prepare = environment["storage_prepare_record"]
    prepare.update(
        {
            "manifest_sha256": manifest_sha256,
            "manifest_entry_count": manifest["entry_count"],
            "manifest_total_bytes": manifest["total_bytes"],
        }
    )
    prepare["prepare_sha256"] = b2._domain_hash(
        b2._STORAGE_DOMAINS["prepare"],
        {
            key: prepare[key]
            for key in b2.STORAGE_PREPARE_KEYS
            if key != "prepare_sha256"
        },
    )
    prepare_sha256 = b2._storage_prepare(
        prepare,
        request,
        request_sha256,
        environment["storage_request_record"],
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
            "storage_manifest_sha256": manifest_sha256,
            "storage_prepare_sha256": prepare_sha256,
            "storage_digest": storage_digest,
        }
    )
    document["storage_digest"] = storage_digest
    installed["installed_distribution_manifest_sha256"] = b2._installed_manifest(
        document, request, request_sha256, storage_digest
    )
    model = fragment["model"]
    model["model_manifest"]["storage_digest"] = storage_digest
    model["model_manifest_sha256"] = b2._model_manifest(
        model["model_manifest"], request, request_sha256, storage_digest
    )
    fragment["fragment_sha256"] = domain_hash(
        FRAGMENT_DOMAIN,
        {
            key: fragment[key]
            for key in b3.FRAGMENT_KEYS
            if key != "fragment_sha256"
        },
    )
    storage_result = forged["storage_inspect_result"]
    storage_result.update(
        {
            "manifest_sha256": manifest_sha256,
            "prepare_sha256": prepare_sha256,
            "storage_digest": storage_digest,
        }
    )
    storage_result["result_sha256"] = domain_hash(
        b3._B1_STORAGE_RESULT_DOMAIN,
        {key: storage_result[key] for key in storage_result if key != "result_sha256"},
    )
    forged["environment_static_fragment_sha256"] = fragment["fragment_sha256"]
    forged["result_sha256"] = domain_hash(
        RESULT_DOMAIN,
        {key: forged[key] for key in b3.RESULT_KEYS if key != "result_sha256"},
    )
    return forged


def source_hash(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def record_row(path, payload):
    digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
    return (
        path.encode("utf-8")
        + b",sha256="
        + digest
        + b","
        + str(len(payload)).encode("ascii")
        + b"\n"
    )


def installed_payloads(source_kind="wheel", variant=None):
    dist_info = "Demo_Pkg-1.0.dist-info"
    metadata_payload = METADATA_PAYLOAD
    wheel_payload = WHEEL_PAYLOAD
    wheel_variants = {
        "wheel-empty": b"",
        "wheel-arbitrary": b"arbitrary\n",
        "wheel-missing-version": (
            b"Generator: synthetic\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "wheel-duplicate-version": (
            WHEEL_PAYLOAD + b"Wheel-Version: 1.0\n"
        ),
        "wheel-malformed": (
            b"Wheel-Version 1.0\nGenerator: synthetic\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "wheel-continuation": WHEEL_PAYLOAD + b" continued\n",
        "wheel-control": WHEEL_PAYLOAD + b"Generator: bad\x00value\n",
        "wheel-blank": WHEEL_PAYLOAD + b"\n",
        "wheel-invalid-tag": (
            b"Wheel-Version: 1.0\nGenerator: synthetic\n"
            b"Root-Is-Purelib: true\nTag: py3-any\n"
        ),
        "wheel-invalid-version": (
            b"Wheel-Version: 2.0\nGenerator: synthetic\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "wheel-invalid-purelib": (
            b"Wheel-Version: 1.0\nGenerator: synthetic\n"
            b"Root-Is-Purelib: True\nTag: py3-none-any\n"
        ),
        "wheel-missing-purelib": (
            b"Wheel-Version: 1.0\nGenerator: synthetic\nTag: py3-none-any\n"
        ),
        "wheel-missing-tag": (
            b"Wheel-Version: 1.0\nGenerator: synthetic\n"
            b"Root-Is-Purelib: true\n"
        ),
        "wheel-duplicate-generator": (
            WHEEL_PAYLOAD + b"Generator: second\n"
        ),
        "wheel-empty-generator": WHEEL_PAYLOAD.replace(
            b"Generator: synthetic", b"Generator: "
        ),
        "wheel-duplicate-tag": WHEEL_PAYLOAD + b"Tag: py3-none-any\n",
        "wheel-unsorted-tags": (
            b"Wheel-Version: 1.0\nGenerator: synthetic\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\nTag: cp312-cp312-any\n"
        ),
        "wheel-crlf": WHEEL_PAYLOAD.replace(b"\n", b"\r\n"),
        "wheel-invalid-utf8": WHEEL_PAYLOAD + b"Generator: \xff\n",
        "wheel-unknown-build": WHEEL_PAYLOAD + b"Build: 1\n",
        "wheel-oversize-generator": (
            b"Wheel-Version: 1.0\nGenerator: " + b"g" * 257 + b"\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "valid-wheel-false-platform": (
            b"Wheel-Version: 1.0\nGenerator: synthetic\n"
            b"Root-Is-Purelib: false\n"
            b"Tag: cp312-cp312-macosx_11_0_arm64\nTag: py3-none-any\n"
        ),
        "valid-wheel-dot-compressed": (
            b"Wheel-Version: 1.0\nGenerator: synthetic\n"
            b"Root-Is-Purelib: true\nTag: py2.py3-none-any\n"
        ),
        "valid-wheel-sensitive-generator-api": WHEEL_PAYLOAD.replace(
            b"Generator: synthetic", b"Generator: api_key=abcdefgh"
        ),
        "valid-wheel-sensitive-generator-bearer": WHEEL_PAYLOAD.replace(
            b"Generator: synthetic",
            b"Generator: Bearer abcdefghijklmnopqrstuvwxyz0123456789",
        ),
        "valid-wheel-sensitive-generator-url": WHEEL_PAYLOAD.replace(
            b"Generator: synthetic",
            b"Generator: https://user:secret@example.invalid/tool",
        ),
        "valid-wheel-sensitive-tag": WHEEL_PAYLOAD.replace(
            b"Tag: py3-none-any", b"Tag: hf_abcdefghijklmnop-none-any"
        ),
        "wheel-missing-generator": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
    }
    metadata_variants = {
        "metadata-empty": b"",
        "metadata-missing-version-header": (
            b"Name: Demo_Pkg\nVersion: 1.0\n\n"
        ),
        "metadata-missing-name": (
            b"Metadata-Version: 2.3\nVersion: 1.0\n\n"
        ),
        "metadata-missing-release-version": (
            b"Metadata-Version: 2.3\nName: Demo_Pkg\n\n"
        ),
        "metadata-duplicate-version-header": (
            METADATA_PAYLOAD.replace(
                b"Metadata-Version: 2.3\n",
                b"Metadata-Version: 2.3\nMetadata-Version: 2.3\n",
            )
        ),
        "metadata-unsupported-version": METADATA_PAYLOAD.replace(
            b"Metadata-Version: 2.3", b"Metadata-Version: 1.0"
        ),
        "metadata-malformed-header": METADATA_PAYLOAD.replace(
            b"Name: Demo_Pkg", b"Bad_Name: value\nName: Demo_Pkg"
        ),
        "metadata-continuation": METADATA_PAYLOAD.replace(
            b"Name: Demo_Pkg\n", b"Name: Demo_Pkg\n continued\n"
        ),
        "metadata-control": METADATA_PAYLOAD.replace(
            b"Name: Demo_Pkg", b"Name: Demo\x00Pkg"
        ),
        "metadata-crlf": METADATA_PAYLOAD.replace(b"\n", b"\r\n"),
        "metadata-duplicate-name": METADATA_PAYLOAD.replace(
            b"Name: Demo_Pkg\n", b"Name: Demo_Pkg\nName: Demo_Pkg\n"
        ),
        "metadata-duplicate-version": METADATA_PAYLOAD.replace(
            b"Version: 1.0\n", b"Version: 1.0\nVersion: 1.0\n"
        ),
        "metadata-version-case-alias": METADATA_PAYLOAD.replace(
            b"Metadata-Version: 2.3\n", b"metadata-version: 2.3\n"
        ),
        "metadata-name-case-alias": METADATA_PAYLOAD.replace(
            b"Name: Demo_Pkg\n", b"name: Demo_Pkg\n"
        ),
        "metadata-release-case-alias": METADATA_PAYLOAD.replace(
            b"Version: 1.0\n", b"version: 1.0\n"
        ),
        "metadata-version-case-duplicate": METADATA_PAYLOAD.replace(
            b"Metadata-Version: 2.3\n",
            b"Metadata-Version: 2.3\nmetadata-version: 2.3\n",
        ),
        "metadata-name-case-duplicate": METADATA_PAYLOAD.replace(
            b"Name: Demo_Pkg\n", b"Name: Demo_Pkg\nname: Evil\n"
        ),
        "metadata-release-case-duplicate": METADATA_PAYLOAD.replace(
            b"Version: 1.0\n", b"Version: 1.0\nversion: 9.9\n"
        ),
        "metadata-invalid-utf8-body": METADATA_PAYLOAD + b"Description: \xff\n",
    }
    if variant in wheel_variants:
        wheel_payload = wheel_variants[variant]
    if variant in metadata_variants:
        metadata_payload = metadata_variants[variant]
    payloads = {
        "demo_pkg/__init__.py": PACKAGE_PAYLOAD,
        dist_info + "/METADATA": metadata_payload,
        dist_info + "/WHEEL": wheel_payload,
    }
    if source_kind == "git":
        payloads[dist_info + "/direct_url.json"] = DIRECT_URL_PAYLOAD
    rows_by_path = {
        path: record_row(path, payload) for path, payload in payloads.items()
    }
    record_path = dist_info + "/RECORD"
    rows_by_path[record_path] = record_path.encode("utf-8") + b",,\n"
    if variant == "record-missing-hash":
        rows_by_path["demo_pkg/__init__.py"] = b"demo_pkg/__init__.py,,\n"
    elif variant == "record-missing-size":
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(PACKAGE_PAYLOAD).digest()
        ).rstrip(b"=")
        rows_by_path["demo_pkg/__init__.py"] = (
            b"demo_pkg/__init__.py,sha256=" + digest + b",\n"
        )
    elif variant == "record-bad-digest":
        rows_by_path["demo_pkg/__init__.py"] = (
            b"demo_pkg/__init__.py,sha256=" + b"A" * 43 + b"," +
            str(len(PACKAGE_PAYLOAD)).encode("ascii") + b"\n"
        )
    elif variant == "record-bad-size":
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(PACKAGE_PAYLOAD).digest()
        ).rstrip(b"=")
        rows_by_path["demo_pkg/__init__.py"] = (
            b"demo_pkg/__init__.py,sha256=" + digest + b",999\n"
        )
    elif variant == "record-leading-zero-size":
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(PACKAGE_PAYLOAD).digest()
        ).rstrip(b"=")
        rows_by_path["demo_pkg/__init__.py"] = (
            b"demo_pkg/__init__.py,sha256="
            + digest
            + b",0"
            + str(len(PACKAGE_PAYLOAD)).encode("ascii")
            + b"\n"
        )
    elif variant == "record-padded-hash":
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(PACKAGE_PAYLOAD).digest()
        ).rstrip(b"=")
        rows_by_path["demo_pkg/__init__.py"] = (
            b"demo_pkg/__init__.py,sha256="
            + digest
            + b"=,"
            + str(len(PACKAGE_PAYLOAD)).encode("ascii")
            + b"\n"
        )
    elif variant == "record-noncanonical-hash":
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(PACKAGE_PAYLOAD).digest()
        ).rstrip(b"=")
        alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        final_index = alphabet.index(digest[-1:])
        replacement = alphabet[(final_index & ~3) | ((final_index + 1) & 3)]
        noncanonical = digest[:-1] + bytes([replacement])
        rows_by_path["demo_pkg/__init__.py"] = (
            b"demo_pkg/__init__.py,sha256="
            + noncanonical
            + b","
            + str(len(PACKAGE_PAYLOAD)).encode("ascii")
            + b"\n"
        )
    elif variant == "record-self-nonempty":
        rows_by_path[record_path] = (
            record_path.encode("ascii") + b",sha256=" + b"A" * 43 + b",1\n"
        )
    elif variant == "record-two-columns":
        rows_by_path["demo_pkg/__init__.py"] = (
            b"demo_pkg/__init__.py,sha256=" + b"A" * 43 + b"\n"
        )
    rows = b"".join(rows_by_path[path] for path in sorted(rows_by_path))
    if variant == "record-reordered":
        rows = b"".join(
            rows_by_path[path] for path in reversed(sorted(rows_by_path))
        )
    elif variant == "record-traversal":
        rows += b"../escape.py,sha256=" + b"A" * 43 + b",1\n"
    elif variant == "record-absolute":
        rows += b"/escape.py,sha256=" + b"A" * 43 + b",1\n"
    elif variant == "record-backslash":
        rows += b"demo_pkg\\escape.py,sha256=" + b"A" * 43 + b",1\n"
    elif variant == "record-duplicate":
        rows += record_row("demo_pkg/__init__.py", PACKAGE_PAYLOAD)
    elif variant == "record-casefold-alias":
        rows += record_row("DEMO_PKG/__init__.py", PACKAGE_PAYLOAD)
    elif variant == "record-dot-component":
        rows += record_row("demo_pkg/./escape.py", b"x")
    elif variant == "record-empty-component":
        rows += record_row("demo_pkg//escape.py", b"x")
    elif variant == "record-invalid-utf8":
        rows += b"\xff"
    elif variant == "record-nul":
        rows += b"\x00"
    elif variant == "record-crlf":
        rows = rows.replace(b"\n", b"\r\n")
    elif variant == "record-quoted":
        target = dist_info + "/METADATA"
        rows = rows.replace(
            target.encode("ascii") + b",",
            b'"' + target.encode("ascii") + b'",',
        )
    elif variant == "oversize-record":
        rows += b"x" * (b3.MAX_CONTROL_FILE_BYTES + 1 - len(rows))
    payloads[record_path] = rows
    if variant == "unknown-file":
        payloads["unowned.py"] = b"unknown\n"
    elif variant == "oversize-metadata":
        payloads[dist_info + "/METADATA"] = (
            METADATA_PAYLOAD + b"X-Long: " + b"x" * (2 * 1024 * 1024) + b"\n"
        )
        payloads[record_path] = payloads[record_path].replace(
            record_row(dist_info + "/METADATA", METADATA_PAYLOAD),
            record_row(dist_info + "/METADATA", payloads[dist_info + "/METADATA"]),
        )
    elif variant == "two-wheels":
        other = "Other-2.0.dist-info"
        other_metadata = b"Metadata-Version: 2.3\nName: Other\nVersion: 2.0\n\n"
        other_package = b'VERSION = "2.0"\n'
        other_files = {
            "other_pkg/__init__.py": other_package,
            other + "/METADATA": other_metadata,
            other + "/WHEEL": WHEEL_PAYLOAD,
        }
        payloads.update(other_files)
        other_record = other + "/RECORD"
        other_rows_by_path = {
            path: record_row(path, payload)
            for path, payload in other_files.items()
        }
        other_rows_by_path[other_record] = (
            other_record.encode("ascii") + b",,\n"
        )
        payloads[other_record] = b"".join(
            other_rows_by_path[path] for path in sorted(other_rows_by_path)
        )
    elif variant == "record-overlap":
        other = "Other-2.0.dist-info"
        other_metadata = b"Metadata-Version: 2.3\nName: Other\nVersion: 2.0\n\n"
        other_controls = {
            other + "/METADATA": other_metadata,
            other + "/WHEEL": WHEEL_PAYLOAD,
        }
        payloads.update(other_controls)
        other_record = other + "/RECORD"
        other_rows_by_path = {
            path: record_row(path, payload)
            for path, payload in other_controls.items()
        }
        other_rows_by_path["demo_pkg/__init__.py"] = record_row(
            "demo_pkg/__init__.py", PACKAGE_PAYLOAD
        )
        other_rows_by_path[other_record] = other_record.encode("ascii") + b",,\n"
        other_rows = b"".join(
            other_rows_by_path[path] for path in sorted(other_rows_by_path)
        )
        payloads[other_record] = other_rows
    return payloads


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
    def __init__(
        self,
        extra_kind=None,
        configured_cache="held",
        *,
        source_kind="wheel",
        installed_variant=None,
        materialization_mismatch=False,
    ):
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
        materialization_root = root
        for segment in ("share", "synapse-s2", "materialization-v1"):
            materialization_root += "/" + segment
            if not os.path.exists(materialization_root):
                self.storage._mkdir(materialization_root)
        self.storage._write(
            materialization_root + "/uv.lock", LOCK_PAYLOAD, 0o600
        )
        self.storage._write(
            materialization_root + "/pyproject.toml", PROJECT_PAYLOAD, 0o600
        )
        site_root = root + "/lib/python3.12/site-packages"
        for path in (
            root + "/lib/python3.12",
            site_root,
        ):
            self.storage._mkdir(path)
        self.site_packages_root = site_root
        payloads = installed_payloads(source_kind, installed_variant)
        if installed_variant == "egg-info":
            payloads["legacy.egg-info/PKG-INFO"] = b"legacy\n"
        elif installed_variant == "editable":
            payloads["__editable__.demo.pth"] = b"/private/tmp/source\n"
        if installed_variant == "bad-git-url":
            dist_info = "Demo_Pkg-1.0.dist-info"
            payloads[dist_info + "/direct_url.json"] = (
                b'{"url":"https://user:secret@github.com/example/demo.git",'
                b'"vcs_info":{"commit_id":"1111111111111111111111111111111111111111",'
                b'"vcs":"git"}}'
            )
            payloads = installed_payloads("git") | {
                dist_info + "/direct_url.json": payloads[
                    dist_info + "/direct_url.json"
                ]
            }
            direct_path = dist_info + "/direct_url.json"
            record_path = dist_info + "/RECORD"
            payloads[record_path] = payloads[record_path].replace(
                record_row(direct_path, DIRECT_URL_PAYLOAD),
                record_row(direct_path, payloads[direct_path]),
            )
        for relative, payload in sorted(payloads.items()):
            parent = site_root
            for segment in relative.split("/")[:-1]:
                parent += "/" + segment
                if not os.path.exists(parent):
                    self.storage._mkdir(parent)
            self.storage._write(site_root + "/" + relative, payload, 0o600)
        for segment in (
            "share",
            "synapse-s2",
            "model-cache-v1",
            "snapshots",
            MODEL_REVISION,
        ):
            root += "/" + segment
            if not os.path.exists(root):
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
                "dependency_lock_sha256": (
                    "00" * 32
                    if materialization_mismatch
                    else hashlib.sha256(LOCK_PAYLOAD).hexdigest()
                ),
                "project_metadata_sha256": hashlib.sha256(
                    PROJECT_PAYLOAD
                ).hexdigest(),
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
        self.site_packages_root = (
            self.storage.environment_root + "/lib/python3.12/site-packages"
        )

    def call(self, **overrides):
        values = {
            "environment_request": self.storage.request,
            "layout_plan": self.storage.layout_plan,
            "stage_result": self.storage.stage_result,
            "planned_core_config": self.core,
            "planned_embedding_runtime_config": self.runtime,
        }
        values.update(overrides)
        return b3.inspect_prebuilt_environment_static_evidence(
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
        projection = b3.environment_static_contract_projection()
        body = {key: projection[key] for key in b3.CONTRACT_BODY_KEYS}
        self.assertEqual(
            projection["contract_id"],
            "environment-static-contract-" + domain_hash(CONTRACT_DOMAIN, body),
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
        self.assertEqual(
            tuple(
                tuple(binding)
                for binding in projection["installed_distribution_binding"]
            ),
            b3.INSTALLED_DISTRIBUTION_BINDING,
        )
        self.assertEqual(
            dict(b3.INSTALLED_DISTRIBUTION_BINDING)["dist_info_tree_shape"],
            (
                "exact-case-top-level-dist-info-name-requires-directory-kind-"
                "in-producer-and-replay"
            ),
        )
        self.assertEqual(
            tuple(
                tuple(binding)
                for binding in projection["python_site_packages_policy"]
            ),
            b3.PYTHON_SITE_PACKAGES_POLICY,
        )
        capture_policy = dict(
            tuple(binding) for binding in projection["capture_policy"]
        )
        self.assertEqual(
            capture_policy["read_open_flags"],
            "O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK",
        )
        self.assertEqual(
            capture_policy["directory_iteration"],
            "held-duplicate-fd-os-scandir-incremental",
        )
        self.assertEqual(
            capture_policy["directory_entry_maximum"],
            b3.MAX_TREE_ENTRIES,
        )
        self.assertEqual(
            capture_policy["directory_retention"],
            "refuse-on-maximum-plus-one-before-retain-or-sort",
        )
        self.assertEqual(
            projection["limits"]["max_tree_entries"],
            b3.MAX_TREE_ENTRIES,
        )
        self.assertIn("layout_plan", projection["environment_fragment_keys"])
        self.assertIn("stage_result", projection["environment_fragment_keys"])
        self.assertEqual(
            tuple(projection["static_roles_present"]),
            b3.STATIC_ROLES_PRESENT,
        )
        self.assertEqual(
            tuple(projection["static_roles_pending"]),
            ("native_file_manifest_sha256",),
        )
        self.assertEqual(
            tuple(projection["source_identity_preimage_keys"]),
            b3.SOURCE_IDENTITY_PREIMAGE_KEYS,
        )
        self.assertEqual(
            tuple(
                tuple(binding)
                for binding in projection["metadata_header_policy"]
            ),
            b3.METADATA_HEADER_POLICY,
        )
        self.assertEqual(
            tuple(
                tuple(binding) for binding in projection["wheel_header_policy"]
            ),
            b3.WHEEL_HEADER_POLICY,
        )
        self.assertEqual(
            tuple(tuple(binding) for binding in projection["capture_policy"]),
            b3.CAPTURE_POLICY,
        )
        capture_policy = dict(projection["capture_policy"])
        self.assertEqual(
            capture_policy["per_file_max_bytes"], b3.MAX_CONTROL_FILE_BYTES
        )
        self.assertEqual(
            capture_policy["installed_aggregate_bytes"],
            b3.MAX_CAPTURED_CONTROL_BYTES,
        )
        self.assertEqual(
            capture_policy["materialization_aggregate_bytes"],
            b3.MAX_MATERIALIZATION_CAPTURED_BYTES,
        )
        self.assertEqual(
            tuple(tuple(binding) for binding in projection["record_policy"]),
            b3.RECORD_POLICY,
        )
        self.assertEqual(
            tuple(binding[0] for binding in projection["record_policy"]),
            b3.RECORD_POLICY_KEYS,
        )
        self.assertEqual(
            len(b3.RECORD_POLICY_KEYS), len(set(b3.RECORD_POLICY_KEYS))
        )
        self.assertEqual(
            tuple(
                binding[0]
                for binding in projection["python_site_packages_policy"]
            ),
            b3.PYTHON_SITE_PACKAGES_POLICY_KEYS,
        )
        self.assertEqual(
            len(b3.PYTHON_SITE_PACKAGES_POLICY_KEYS),
            len(set(b3.PYTHON_SITE_PACKAGES_POLICY_KEYS)),
        )
        self.assertEqual(
            tuple(projection["wheel_metadata_semantics_keys"]),
            b3.WHEEL_METADATA_SEMANTICS_KEYS,
        )
        self.assertEqual(
            projection["domains"]["wheel_tags"],
            b3.WHEEL_TAGS_DOMAIN.decode("ascii"),
        )
        self.assertIn(
            "coordinated-unauthenticated-raw-semantics-rehash-forgery-not-prevented",
            projection["nonclaims"],
        )

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
            b3.inspect_prebuilt_environment_static_evidence
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
        for parameter in signature.parameters:
            self.assertNotIn("archive", parameter.casefold())
            self.assertNotIn("wheel", parameter.casefold())
            self.assertNotIn("url", parameter.casefold())
        self.assertFalse(
            hasattr(b3, "inspect_prebuilt_environment_model_static_evidence")
        )
        producers = [
            name
            for name, value in vars(b3).items()
            if callable(value) and not name.startswith("_") and "produce" in name
        ]
        self.assertEqual(producers, [])

    def test_projection_keeps_all_authority_claims_false(self):
        projection = b3.environment_static_contract_projection()
        self.assertEqual(
            tuple(projection["fixed_false_result_fields"]),
            b3.FIXED_FALSE_RESULT_FIELDS,
        )
        self.assertIn("no-model-load-or-inference", projection["nonclaims"])
        self.assertIn("no-activation", projection["nonclaims"])
        self.assertIn(
            "no-original-wheel-archive-hash-or-provenance",
            projection["nonclaims"],
        )
        self.assertIn(
            "wheel-sha256-means-raw-wheel-metadata-only",
            projection["nonclaims"],
        )
        self.assertIn("no-uv-resolution-or-lock-provenance", projection["nonclaims"])
        self.assertIn("no-installed-importability-claim", projection["nonclaims"])
        self.assertIn("producer-emits-wheel-source-kind-only", projection["nonclaims"])
        self.assertIn(
            "no-inventory-policy-admission-or-currentness",
            projection["nonclaims"],
        )
        self.assertIn(
            "no-compatibility-profile-admission-or-currentness",
            projection["nonclaims"],
        )
        self.assertIn(
            "no-outside-site-packages-or-install-scheme-evidence",
            projection["nonclaims"],
        )
        self.assertIn(
            "no-full-core-metadata-semantic-validation",
            projection["nonclaims"],
        )
        self.assertIn(
            "no-raw-wheel-generator-or-tag-values-in-result",
            projection["nonclaims"],
        )
        self.assertIn(
            "non-null-git-direct-url-uninhabited-under-frozen-phase5b2-validator",
            projection["nonclaims"],
        )
        self.assertEqual(
            dict(b3.INSTALLED_DISTRIBUTION_BINDING)["source_kind"],
            (
                "wheel-means-strict-dist-info-controls-record-complete-and-"
                "direct-url-absent"
            ),
        )
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
        self.assertTrue(result["environment_static_fragment_produced"])
        for key in b3.FIXED_FALSE_RESULT_FIELDS:
            self.assertIs(result[key], False)
        fragment = result["environment_static_fragment"]
        self.assertEqual(
            fragment["static_roles_present"], list(b3.STATIC_ROLES_PRESENT)
        )
        self.assertEqual(
            fragment["static_roles_pending"], list(b3.STATIC_ROLES_PENDING)
        )
        self.assertIs(fragment["static_evidence_complete"], False)
        installed = fragment["installed"]["installed_distribution_manifest"]
        self.assertEqual(installed["distribution_count"], 1)
        self.assertEqual(installed["distributions"][0]["normalized_name"], "demo-pkg")
        self.assertEqual(installed["distributions"][0]["source_kind"], "wheel")
        self.assertIsNone(installed["distributions"][0]["direct_url_sha256"])
        self.assertEqual(
            installed["distributions"][0]["metadata_sha256"],
            hashlib.sha256(METADATA_PAYLOAD).hexdigest(),
        )
        self.assertEqual(
            installed["distributions"][0]["wheel_sha256"],
            hashlib.sha256(WHEEL_PAYLOAD).hexdigest(),
        )
        distribution = installed["distributions"][0]
        wheel_semantics = fragment["installed"]["wheel_metadata_semantics"][0]
        self.assertEqual(
            wheel_semantics,
            {
                "normalized_name": "demo-pkg",
                "wheel_sha256": hashlib.sha256(WHEEL_PAYLOAD).hexdigest(),
                "wheel_version": "1.0",
                "root_is_purelib": True,
                "generator_sha256": hashlib.sha256(b"synthetic").hexdigest(),
                "tag_count": 1,
                "tags_sha256": domain_hash(
                    b3.WHEEL_TAGS_DOMAIN, ["py3-none-any"]
                ),
            },
        )
        source_identity_preimage = {
            "schema": b3.SOURCE_IDENTITY_SCHEMA,
            "source_kind": distribution["source_kind"],
            "normalized_name": distribution["normalized_name"],
            "version": distribution["version"],
            "dependency_component_id": installed["dependency_component_id"],
            "dependency_lock_sha256": installed["dependency_lock_sha256"],
            "project_metadata_sha256": installed["project_metadata_sha256"],
            "wheel_version": wheel_semantics["wheel_version"],
            "wheel_root_is_purelib": wheel_semantics["root_is_purelib"],
            "wheel_generator_sha256": wheel_semantics[
                "generator_sha256"
            ],
            "wheel_tag_count": wheel_semantics["tag_count"],
            "wheel_tags_sha256": wheel_semantics["tags_sha256"],
            "metadata_sha256": distribution["metadata_sha256"],
            "wheel_sha256": distribution["wheel_sha256"],
            "record_sha256": distribution["record_sha256"],
            "direct_url_sha256": distribution["direct_url_sha256"],
        }
        self.assertEqual(
            tuple(source_identity_preimage),
            b3.SOURCE_IDENTITY_PREIMAGE_KEYS,
        )
        self.assertEqual(
            distribution["source_identity_sha256"],
            domain_hash(b3.SOURCE_IDENTITY_DOMAIN, source_identity_preimage),
        )
        self.assertEqual(
            installed["dependency_lock_sha256"],
            hashlib.sha256(LOCK_PAYLOAD).hexdigest(),
        )
        self.assertEqual(
            installed["project_metadata_sha256"],
            hashlib.sha256(PROJECT_PAYLOAD).hexdigest(),
        )
        self.assertEqual(
            b2._installed_manifest(
                installed,
                self.fixture.storage.request,
                fragment["environment"]["environment_request_sha256"],
                fragment["environment"]["storage_digest"],
            ),
            fragment["installed"]["installed_distribution_manifest_sha256"],
        )
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
        self.assertEqual(result, b3.validate_environment_static_result(result))
        self.assertEqual(b3.environment_static_result_exit_code(result), 0)
        rendered = json.loads(b3.render_environment_static_result(result))
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
        self.assertIsNone(result["environment_static_fragment"])

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
            self.assertIsNone(result["environment_static_fragment"])
        finally:
            fixture.close()

    def test_layout_environment_root_is_replay_bound(self):
        forged = copy.deepcopy(self.fixture.call())
        fragment = forged["environment_static_fragment"]
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
        forged["environment_static_fragment_sha256"] = fragment["fragment_sha256"]
        forged["result_sha256"] = domain_hash(
            RESULT_DOMAIN,
            {
                key: forged[key]
                for key in b3.RESULT_KEYS
                if key != "result_sha256"
            },
        )
        replayed = b3.validate_environment_static_result(forged)
        self.assertEqual(replayed["status"], "blocked")
        self.assertEqual(b3.environment_static_result_exit_code(forged), 3)

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
        replayed = b3.validate_environment_static_result(tampered)
        self.assertEqual(replayed["status"], "blocked")
        self.assertEqual(b3.environment_static_result_exit_code(tampered), 3)
        self.assertEqual(
            b3.render_environment_static_result(tampered), b3._RENDER_FALLBACK
        )

    def test_public_hash_rewrite_cannot_bypass_semantic_replay(self):
        forged = copy.deepcopy(self.fixture.call())
        fragment = forged["environment_static_fragment"]
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
        forged["environment_static_fragment_sha256"] = fragment["fragment_sha256"]
        forged["result_sha256"] = domain_hash(
            RESULT_DOMAIN,
            {key: forged[key] for key in b3.RESULT_KEYS if key != "result_sha256"},
        )
        self.assertEqual(
            b3.validate_environment_static_result(forged)["status"],
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
            b3.validate_environment_static_result(forged)["status"],
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
                    b3.validate_environment_static_result(forged)[
                        "status"
                    ],
                    "blocked",
                )

    def test_b2_valid_model_plan_tree_mismatch_is_replay_rejected(self):
        forged = copy.deepcopy(self.fixture.call())
        fragment = forged["environment_static_fragment"]
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
        forged["environment_static_fragment_sha256"] = fragment["fragment_sha256"]
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
            b3.validate_environment_static_result(forged)["status"],
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
        self.assertIsNone(result["environment_static_fragment"])

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
        for name in MODEL_PAYLOADS:
            self.assertTrue(
                any(
                    flags & os.O_NONBLOCK
                    for observed_name, flags in observed
                    if observed_name == name
                )
            )

    def test_local_capability_gate_precedes_source_loading(self):
        with mock.patch.object(b3, "_load_frozen_upstreams") as loader:
            with mock.patch.object(b3.sys, "platform", "linux"):
                result = self.fixture.call()
        loader.assert_not_called()
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["reason"], b3.UNSUPPORTED_REASON)

    def test_zero_security_flag_capability_precedes_source_loading(self):
        for name in ("O_NOFOLLOW", "O_NONBLOCK"):
            with self.subTest(name=name):
                with mock.patch.object(b3, "_load_frozen_upstreams") as loader:
                    with mock.patch.object(b3.os, name, 0):
                        result = self.fixture.call()
                loader.assert_not_called()
                self.assertEqual(result["status"], "unsupported")
                self.assertEqual(result["reason"], b3.UNSUPPORTED_REASON)

    def test_scandir_capability_precedes_source_loading(self):
        with mock.patch.object(b3, "_load_frozen_upstreams") as loader:
            with mock.patch.object(b3.os, "scandir", None):
                result = self.fixture.call()
        loader.assert_not_called()
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["reason"], b3.UNSUPPORTED_REASON)

    def storage_sentinel(self):
        return self.fixture.storage._snapshot(self.fixture.storage.sentinel_path)


class TestModelSubtreeRefusals(unittest.TestCase):
    def _assert_blocked(self, extra_kind):
        fixture = ModelStaticFixture(extra_kind=extra_kind)
        try:
            result = fixture.call()
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["reason"], b3.BLOCKED_REASON)
            self.assertIsNone(result["environment_static_fragment"])
        finally:
            fixture.close()

    def test_extra_revision_is_not_a_fallback_candidate(self):
        self._assert_blocked("revision")

    def test_executable_model_suffix_is_refused(self):
        self._assert_blocked("forbidden-file")


class TestInstalledDistributionEvidence(unittest.TestCase):
    def test_git_distribution_is_strictly_parsed_then_frozen_b2_blocks(self):
        self.assertIsNone(b3._validate_pep610_git(DIRECT_URL_PAYLOAD))
        fixture = ModelStaticFixture(source_kind="git")
        try:
            result = fixture.call()
            self.assertEqual(result["status"], "blocked", result)
            self.assertIsNone(result["environment_static_fragment"])
            self.assertIn(
                "non-null-git-direct-url-uninhabited-under-frozen-phase5b2-validator",
                result["nonclaims"],
            )
        finally:
            fixture.close()

    def test_wheel_metadata_mutations_are_refused_after_record_rebinding(self):
        variants = (
            "wheel-empty",
            "wheel-arbitrary",
            "wheel-missing-version",
            "wheel-duplicate-version",
            "wheel-malformed",
            "wheel-continuation",
            "wheel-control",
            "wheel-blank",
            "wheel-invalid-tag",
            "wheel-invalid-version",
            "wheel-invalid-purelib",
            "wheel-missing-purelib",
            "wheel-missing-generator",
            "wheel-missing-tag",
            "wheel-duplicate-generator",
            "wheel-empty-generator",
            "wheel-duplicate-tag",
            "wheel-unsorted-tags",
            "wheel-crlf",
            "wheel-invalid-utf8",
            "wheel-unknown-build",
            "wheel-oversize-generator",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                fixture = ModelStaticFixture(installed_variant=variant)
                try:
                    result = fixture.call()
                    self.assertEqual(result["status"], "blocked", result)
                    self.assertIsNone(result["environment_static_fragment"])
                finally:
                    fixture.close()

    def test_valid_wheel_profiles_project_exact_held_semantics(self):
        expected = {
            "valid-wheel-false-platform": {
                "root_is_purelib": False,
                "tags": [
                    "cp312-cp312-macosx_11_0_arm64",
                    "py3-none-any",
                ],
            },
            "valid-wheel-dot-compressed": {
                "root_is_purelib": True,
                "tags": ["py2.py3-none-any"],
            },
        }
        for variant, fields in expected.items():
            with self.subTest(variant=variant):
                fixture = ModelStaticFixture(installed_variant=variant)
                try:
                    result = fixture.call()
                    self.assertEqual(result["status"], "success", result)
                    fragment = result["environment_static_fragment"]
                    semantics = fragment["installed"][
                        "wheel_metadata_semantics"
                    ][0]
                    self.assertEqual(semantics["wheel_version"], "1.0")
                    self.assertEqual(
                        semantics["generator_sha256"],
                        hashlib.sha256(b"synthetic").hexdigest(),
                    )
                    self.assertEqual(
                        semantics["root_is_purelib"],
                        fields["root_is_purelib"],
                    )
                    self.assertEqual(semantics["tag_count"], len(fields["tags"]))
                    self.assertEqual(
                        semantics["tags_sha256"],
                        domain_hash(b3.WHEEL_TAGS_DOMAIN, fields["tags"]),
                    )
                    self.assertEqual(
                        fragment["static_roles_pending"],
                        ["native_file_manifest_sha256"],
                    )
                    self.assertIs(fragment["static_evidence_complete"], False)
                finally:
                    fixture.close()

    def test_sensitive_wheel_generator_and_tag_values_are_digest_only(self):
        baseline_fixture = ModelStaticFixture()
        cases = {
            "valid-wheel-sensitive-generator-api": (
                b"api_key=abcdefgh",
                ["py3-none-any"],
            ),
            "valid-wheel-sensitive-generator-bearer": (
                b"Bearer abcdefghijklmnopqrstuvwxyz0123456789",
                ["py3-none-any"],
            ),
            "valid-wheel-sensitive-generator-url": (
                b"https://user:secret@example.invalid/tool",
                ["py3-none-any"],
            ),
            "valid-wheel-sensitive-tag": (
                b"synthetic",
                ["hf_abcdefghijklmnop-none-any"],
            ),
        }
        try:
            baseline = baseline_fixture.call()
            self.assertEqual(baseline["status"], "success", baseline)
            baseline_distribution = baseline["environment_static_fragment"][
                "installed"
            ]["installed_distribution_manifest"]["distributions"][0]
            baseline_raw = canonical(baseline)
            self.assertNotIn(b"synthetic", baseline_raw)
            self.assertNotIn(b"py3-none-any", baseline_raw)
            projection_raw = canonical(
                b3.environment_static_contract_projection()
            )
            for variant, (generator, tags) in cases.items():
                with self.subTest(variant=variant):
                    fixture = ModelStaticFixture(installed_variant=variant)
                    try:
                        result = fixture.call()
                        self.assertEqual(result["status"], "success", result)
                        raw_result = canonical(result)
                        raw_render = b3.render_environment_static_result(
                            result
                        ).encode("ascii")
                        raw_nonclaims = canonical(result["nonclaims"])
                        sensitive_values = [generator, *(
                            tag.encode("ascii") for tag in tags
                        )]
                        for sensitive in sensitive_values:
                            self.assertNotIn(sensitive, raw_result)
                            self.assertNotIn(sensitive, raw_render)
                            self.assertNotIn(sensitive, raw_nonclaims)
                            self.assertNotIn(sensitive, projection_raw)
                        fragment = result["environment_static_fragment"]
                        semantics = fragment["installed"][
                            "wheel_metadata_semantics"
                        ][0]
                        self.assertEqual(
                            tuple(semantics),
                            b3.WHEEL_METADATA_SEMANTICS_KEYS,
                        )
                        self.assertEqual(
                            semantics["generator_sha256"],
                            hashlib.sha256(generator).hexdigest(),
                        )
                        self.assertEqual(semantics["tag_count"], len(tags))
                        self.assertEqual(
                            semantics["tags_sha256"],
                            domain_hash(b3.WHEEL_TAGS_DOMAIN, tags),
                        )
                        distribution = fragment["installed"][
                            "installed_distribution_manifest"
                        ]["distributions"][0]
                        self.assertNotEqual(
                            distribution["wheel_sha256"],
                            baseline_distribution["wheel_sha256"],
                        )
                        self.assertNotEqual(
                            distribution["source_identity_sha256"],
                            baseline_distribution["source_identity_sha256"],
                        )
                    finally:
                        fixture.close()
        finally:
            baseline_fixture.close()

    def test_metadata_header_mutations_are_refused_after_record_rebinding(self):
        variants = (
            "metadata-empty",
            "metadata-missing-version-header",
            "metadata-missing-name",
            "metadata-missing-release-version",
            "metadata-duplicate-version-header",
            "metadata-unsupported-version",
            "metadata-malformed-header",
            "metadata-continuation",
            "metadata-control",
            "metadata-crlf",
            "metadata-duplicate-name",
            "metadata-duplicate-version",
            "metadata-version-case-alias",
            "metadata-name-case-alias",
            "metadata-release-case-alias",
            "metadata-version-case-duplicate",
            "metadata-name-case-duplicate",
            "metadata-release-case-duplicate",
            "metadata-invalid-utf8-body",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                fixture = ModelStaticFixture(installed_variant=variant)
                try:
                    result = fixture.call()
                    self.assertEqual(result["status"], "blocked", result)
                    self.assertIsNone(result["environment_static_fragment"])
                finally:
                    fixture.close()

    def test_requested_revision_dot_empty_and_parent_components_are_refused(self):
        document = json.loads(DIRECT_URL_PAYLOAD.decode("ascii"))
        for revision in (".", "..", "refs/./main", "refs/../main", "refs//main"):
            with self.subTest(revision=revision):
                candidate = copy.deepcopy(document)
                candidate["vcs_info"]["requested_revision"] = revision
                with self.assertRaises(b3._Refused):
                    b3._validate_pep610_git(canonical(candidate))

    def test_record_row_limit_is_enforced_during_streaming_iteration(self):
        payload = b"x"
        encoded = base64.urlsafe_b64encode(
            hashlib.sha256(payload).digest()
        ).rstrip(b"=").decode("ascii")
        observed = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
        yielded = [0]

        class ObservedFiles:
            def get(self, _path):
                return observed

        def bounded_infinite_reader(*_args, **_kwargs):
            index = 0
            while True:
                if index > b3.MAX_RECORD_ROWS:
                    raise AssertionError("reader was eagerly exhausted")
                yielded[0] += 1
                yield [f"p{index}", "sha256=" + encoded, "1"]
                index += 1

        with mock.patch.object(
            b3.csv, "reader", bounded_infinite_reader
        ):
            with self.assertRaises(b3._Refused):
                b3._strict_record_rows(
                    b"x", "self/RECORD", ObservedFiles()
                )
        self.assertEqual(yielded[0], b3.MAX_RECORD_ROWS + 1)

    def test_captured_control_aggregate_limit_is_exact(self):
        for maximum in (
            b3.MAX_CAPTURED_CONTROL_BYTES,
            b3.MAX_MATERIALIZATION_CAPTURED_BYTES,
        ):
            with self.subTest(maximum=maximum):
                counters = {"captured_bytes": 0}
                b3._capture_budget(
                    counters,
                    maximum - 1,
                    maximum,
                    "test",
                    commit=True,
                )
                b3._capture_budget(
                    counters, 1, maximum, "test", commit=True
                )
                self.assertEqual(counters["captured_bytes"], maximum)
                with self.assertRaises(b3._Refused):
                    b3._capture_budget(
                        counters, 1, maximum, "test", commit=True
                    )

    def test_capture_growth_probe_refuses_installed_and_materialization(self):
        fixture = ModelStaticFixture()
        cases = (
            (
                fixture.site_packages_root + "/Demo_Pkg-1.0.dist-info",
                "WHEEL",
                b3.MAX_CAPTURED_CONTROL_BYTES,
            ),
            (
                fixture.storage.environment_root
                + "/share/synapse-s2/materialization-v1",
                "uv.lock",
                b3.MAX_MATERIALIZATION_CAPTURED_BYTES,
            ),
        )
        try:
            for parent_path, name, maximum in cases:
                with self.subTest(name=name):
                    full_path = parent_path + "/" + name
                    declared_size = os.stat(full_path).st_size
                    parent_fd = os.open(parent_path, b3._DIR_FLAGS)
                    real_read = os.read
                    requests = []
                    returned = []
                    grew = [False]
                    counters = {"captured_bytes": 0}

                    def growing_read(fd, size):
                        requests.append(size)
                        chunk = real_read(fd, size)
                        returned.append(len(chunk))
                        if chunk and not grew[0]:
                            with open(full_path, "ab") as handle:
                                handle.write(b"x")
                            grew[0] = True
                        return chunk

                    try:
                        with mock.patch.object(b3.os, "read", growing_read):
                            with self.assertRaises(b3._Refused):
                                b3._read_static_file(
                                    parent_fd,
                                    name,
                                    os.fstat(parent_fd).st_dev,
                                    "test/" + name,
                                    "test-capture",
                                    capture=True,
                                    capture_counters=counters,
                                    capture_maximum=maximum,
                                )
                    finally:
                        os.close(parent_fd)
                    self.assertEqual(requests, [declared_size, 1])
                    self.assertEqual(returned, [declared_size, 1])
                    self.assertEqual(sum(returned), declared_size + 1)
                    self.assertLessEqual(declared_size, b3.MAX_CONTROL_FILE_BYTES)
                    self.assertEqual(counters["captured_bytes"], 0)
        finally:
            fixture.close()

    def test_oversized_mock_read_is_refused_before_digest_or_retention(self):
        fixture = ModelStaticFixture()
        parent_path = (
            fixture.site_packages_root + "/Demo_Pkg-1.0.dist-info"
        )
        parent_fd = os.open(parent_path, b3._DIR_FLAGS)
        counters = {"captured_bytes": 0}
        requests = []
        returned = []
        update_lengths = []
        real_sha256 = hashlib.sha256

        class TrackingHash:
            def __init__(self):
                self.inner = real_sha256()

            def update(self, value):
                update_lengths.append(len(value))
                self.inner.update(value)

            def hexdigest(self):
                return self.inner.hexdigest()

        def oversized_read(_fd, size):
            requests.append(size)
            chunk = b"x" * (b3.MAX_CONTROL_FILE_BYTES + 1)
            returned.append(len(chunk))
            return chunk

        try:
            with mock.patch.object(b3.os, "read", oversized_read):
                with mock.patch.object(b3.hashlib, "sha256", TrackingHash):
                    with self.assertRaises(b3._Refused):
                        b3._read_static_file(
                            parent_fd,
                            "WHEEL",
                            os.fstat(parent_fd).st_dev,
                            "test/WHEEL",
                            "test-capture",
                            capture=True,
                            capture_counters=counters,
                            capture_maximum=b3.MAX_CAPTURED_CONTROL_BYTES,
                        )
            self.assertEqual(len(requests), 1)
            self.assertLessEqual(requests[0], b3.MAX_CONTROL_FILE_BYTES)
            self.assertEqual(returned, [b3.MAX_CONTROL_FILE_BYTES + 1])
            self.assertEqual(update_lengths, [])
            self.assertEqual(counters["captured_bytes"], 0)
        finally:
            os.close(parent_fd)
            fixture.close()

    def test_no_wheel_archive_input_or_scanner_is_used(self):
        fixture = ModelStaticFixture()
        dummy_wheel = fixture.storage.base + "/never-read.whl"
        fixture.storage._write(dummy_wheel, b"not-a-wheel-archive", 0o600)
        real_open = os.open
        opened = []

        def recording_open(path, flags, *args, **kwargs):
            opened.append(path)
            return real_open(path, flags, *args, **kwargs)

        try:
            with mock.patch.object(b3.os, "open", recording_open):
                result = fixture.call()
            self.assertEqual(result["status"], "success", result)
            self.assertNotIn(dummy_wheel, opened)
            distribution = result["environment_static_fragment"]["installed"][
                "installed_distribution_manifest"
            ]["distributions"][0]
            self.assertEqual(tuple(distribution), b2.DISTRIBUTION_ENTRY_KEYS)
            for forbidden in (
                "archive_sha256",
                "wheel_archive_sha256",
                "archive_path",
                "source_url",
            ):
                self.assertNotIn(forbidden, distribution)
            with open(_SOURCE, encoding="utf-8") as handle:
                tree = ast.parse(handle.read())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(
                        alias.name.split(".", 1)[0] for alias in node.names
                    )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".", 1)[0])
            self.assertTrue(imported.isdisjoint({"zipfile", "tarfile"}))
        finally:
            fixture.close()

    def test_materialization_raw_copy_mismatch_is_refused(self):
        fixture = ModelStaticFixture(materialization_mismatch=True)
        try:
            result = fixture.call()
            self.assertEqual(result["status"], "blocked")
            self.assertIsNone(result["environment_static_fragment"])
        finally:
            fixture.close()

    def test_record_and_ownership_failures_are_refused(self):
        variants = (
            "record-missing-hash",
            "record-missing-size",
            "record-bad-digest",
            "record-bad-size",
            "record-leading-zero-size",
            "record-padded-hash",
            "record-noncanonical-hash",
            "record-self-nonempty",
            "record-two-columns",
            "record-reordered",
            "record-traversal",
            "record-absolute",
            "record-backslash",
            "record-dot-component",
            "record-empty-component",
            "record-invalid-utf8",
            "record-nul",
            "record-crlf",
            "record-quoted",
            "oversize-record",
            "record-duplicate",
            "record-casefold-alias",
            "record-overlap",
            "unknown-file",
            "egg-info",
            "editable",
            "oversize-metadata",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                fixture = ModelStaticFixture(installed_variant=variant)
                try:
                    result = fixture.call()
                    self.assertEqual(result["status"], "blocked", result)
                    self.assertIsNone(result["environment_static_fragment"])
                finally:
                    fixture.close()

    def test_credential_bearing_git_url_is_refused(self):
        fixture = ModelStaticFixture(
            source_kind="git", installed_variant="bad-git-url"
        )
        try:
            result = fixture.call()
            self.assertEqual(result["status"], "blocked")
        finally:
            fixture.close()

    def test_special_file_under_site_packages_is_fail_closed(self):
        fixture = ModelStaticFixture()
        try:
            os.symlink(
                "demo_pkg/__init__.py",
                fixture.site_packages_root + "/alias.py",
            )
            result = fixture.call()
            self.assertEqual(result["status"], "blocked")
            self.assertIsNone(result["environment_static_fragment"])
        finally:
            fixture.close()

    def test_fifo_substitution_is_nonblocking_and_fail_closed(self):
        cases = (
            (
                "materialization",
                "share/synapse-s2/materialization-v1/uv.lock",
                "uv.lock",
            ),
            (
                "installed-wheel",
                "lib/python3.12/site-packages/"
                "Demo_Pkg-1.0.dist-info/WHEEL",
                "WHEEL",
            ),
        )
        for label, relative_path, basename in cases:
            with self.subTest(label=label):
                fixture = ModelStaticFixture()
                absolute_path = (
                    fixture.storage.environment_root + "/" + relative_path
                )
                displaced_path = fixture.storage.base + "/displaced-" + label
                original_read = b3._read_static_file
                real_open = os.open
                target_parent_fd = [None]
                target_flags = []
                swapped = [False]

                def swap_then_read(
                    parent_fd,
                    name,
                    device,
                    observed_relative_path,
                    token,
                    **kwargs,
                ):
                    if (
                        observed_relative_path == relative_path
                        and not swapped[0]
                    ):
                        target_parent_fd[0] = parent_fd
                        os.rename(absolute_path, displaced_path)
                        os.mkfifo(absolute_path, 0o600)
                        os.chmod(absolute_path, 0o600)
                        swapped[0] = True
                    return original_read(
                        parent_fd,
                        name,
                        device,
                        observed_relative_path,
                        token,
                        **kwargs,
                    )

                def guarded_open(path, flags, *args, **kwargs):
                    if (
                        swapped[0]
                        and path == basename
                        and kwargs.get("dir_fd") == target_parent_fd[0]
                    ):
                        target_flags.append(flags)
                        if not flags & os.O_NONBLOCK:
                            raise OSError("test prevented blocking FIFO open")
                    return real_open(path, flags, *args, **kwargs)

                try:
                    with mock.patch.object(
                        b3, "_read_static_file", swap_then_read
                    ):
                        with mock.patch.object(b3.os, "open", guarded_open):
                            result = fixture.call()
                    self.assertTrue(swapped[0])
                    self.assertEqual(len(target_flags), 1)
                    self.assertTrue(target_flags[0] & os.O_NONBLOCK)
                    self.assertTrue(stat.S_ISFIFO(os.lstat(absolute_path).st_mode))
                    self.assertEqual(result["status"], "blocked", result)
                    self.assertIsNone(result["environment_static_fragment"])
                finally:
                    fixture.close()

    def test_python_abi_to_site_packages_rule_is_strict(self):
        request = {"target_python_implementation": "cpython"}
        accepted = {
            "cp38": "lib/python3.8/site-packages",
            "cp314": "lib/python3.14/site-packages",
            "cp399": "lib/python3.99/site-packages",
        }
        for abi, expected in accepted.items():
            with self.subTest(abi=abi):
                request["target_python_abi"] = abi
                self.assertEqual(b3._site_packages_relative(request), expected)
        for abi in (
            "cp37",
            "cp301",
            "cp3",
            "cp3100",
            "cp3.12",
            "pypy312",
        ):
            with self.subTest(abi=abi):
                request["target_python_abi"] = abi
                with self.assertRaises(b3._Refused):
                    b3._site_packages_relative(request)
        request.update(
            {
                "target_python_implementation": "pypy",
                "target_python_abi": "cp314",
            }
        )
        with self.assertRaises(b3._Refused):
            b3._site_packages_relative(request)

    def test_representative_projected_executable_policy_selectors_are_consumed(
        self,
    ):
        request = {
            "target_python_implementation": "cpython",
            "target_python_abi": "cp38",
        }
        raised_minimum = tuple(
            (key, 9 if key == "minor_minimum" else value)
            for key, value in b3.PYTHON_SITE_PACKAGES_POLICY
        )
        with mock.patch.object(
            b3, "PYTHON_SITE_PACKAGES_POLICY", raised_minimum
        ):
            with self.assertRaises(b3._Refused):
                b3._site_packages_relative(request)
        with mock.patch.object(
            b3,
            "PYTHON_SITE_PACKAGES_POLICY",
            b3.PYTHON_SITE_PACKAGES_POLICY[:-1],
        ):
            with self.assertRaises(b3._Refused):
                b3._site_packages_relative(request)
        permissive_decimal = tuple(
            (
                key,
                "permissive-leading-zero" if key == "minor_decimal" else value,
            )
            for key, value in b3.PYTHON_SITE_PACKAGES_POLICY
        )
        with mock.patch.object(
            b3, "PYTHON_SITE_PACKAGES_POLICY", permissive_decimal
        ):
            with self.assertRaises(b3._Refused):
                b3._site_packages_relative(request)

        self.assertEqual(
            dict(b3.RECORD_POLICY)["executable_selector_keys"],
            ",".join(b3.RECORD_EXECUTABLE_SELECTOR_KEYS),
        )
        short_paths = tuple(
            (key, 3 if key == "path_max_characters" else value)
            for key, value in b3.RECORD_POLICY
        )
        with mock.patch.object(b3, "RECORD_POLICY", short_paths):
            with self.assertRaises(b3._Refused):
                b3._strict_installed_relative_path("abcd")
        with mock.patch.object(
            b3, "RECORD_POLICY", tuple(reversed(b3.RECORD_POLICY))
        ):
            with self.assertRaises(b3._Refused):
                b3._strict_installed_relative_path("a")

    def test_post_installed_scan_drift_is_caught_before_success(self):
        fixture = ModelStaticFixture()
        original = b3._derive_installed_distribution_manifest

        def mutate_after_scan(*args, **kwargs):
            value = original(*args, **kwargs)
            with open(
                fixture.site_packages_root + "/demo_pkg/__init__.py", "ab"
            ) as handle:
                handle.write(b"drift")
            return value

        try:
            with mock.patch.object(
                b3,
                "_derive_installed_distribution_manifest",
                mutate_after_scan,
            ):
                result = fixture.call()
            self.assertEqual(result["status"], "blocked")
        finally:
            fixture.close()

    def test_installed_file_opens_require_nofollow_and_cloexec(self):
        fixture = ModelStaticFixture()
        real_open = os.open
        observed = []
        watched = {
            "METADATA",
            "WHEEL",
            "RECORD",
            "__init__.py",
            "uv.lock",
            "pyproject.toml",
            "release_environment_storage.py",
            "release_environment_evidence.py",
        }

        def recording_open(path, flags, *args, **kwargs):
            if path in watched:
                observed.append((path, flags))
            return real_open(path, flags, *args, **kwargs)

        try:
            with mock.patch.object(b3.os, "open", recording_open):
                result = fixture.call()
            self.assertEqual(result["status"], "success", result)
            self.assertTrue(watched.issubset({name for name, _flags in observed}))
            for _name, flags in observed:
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_CLOEXEC)
            for name in watched:
                self.assertTrue(
                    any(
                        flags & os.O_NONBLOCK
                        for observed_name, flags in observed
                        if observed_name == name
                    )
                )
        finally:
            fixture.close()

    def test_coordinated_source_identity_rehash_is_replay_refused(self):
        fixture = ModelStaticFixture()
        try:
            forged = copy.deepcopy(fixture.call())
            fragment = forged["environment_static_fragment"]
            installed = fragment["installed"]
            document = installed["installed_distribution_manifest"]
            document["distributions"][0]["source_identity_sha256"] = "ab" * 32
            installed["installed_distribution_manifest_sha256"] = (
                b2._installed_manifest(
                    document,
                    fragment["environment"]["environment_request"],
                    fragment["environment"]["environment_request_sha256"],
                    fragment["environment"]["storage_digest"],
                )
            )
            fragment["fragment_sha256"] = domain_hash(
                FRAGMENT_DOMAIN,
                {
                    key: fragment[key]
                    for key in b3.FRAGMENT_KEYS
                    if key != "fragment_sha256"
                },
            )
            forged["environment_static_fragment_sha256"] = fragment[
                "fragment_sha256"
            ]
            forged["result_sha256"] = domain_hash(
                RESULT_DOMAIN,
                {
                    key: forged[key]
                    for key in b3.RESULT_KEYS
                    if key != "result_sha256"
                },
            )
            self.assertEqual(
                b3.validate_environment_static_result(forged)["status"],
                "blocked",
            )
        finally:
            fixture.close()

    def test_coordinated_regular_dist_info_full_rehash_is_replay_refused(self):
        fixture = ModelStaticFixture(installed_variant="two-wheels")
        try:
            forged = copy.deepcopy(fixture.call())
            self.assertEqual(forged["status"], "success", forged)
            fragment = forged["environment_static_fragment"]
            environment = fragment["environment"]
            installed = fragment["installed"]
            document = installed["installed_distribution_manifest"]
            manifest = environment["storage_manifest"]
            request = environment["environment_request"]
            site_packages = b3._site_packages_relative(request)
            prefix = site_packages + "/"
            relative = "Bogus.dist-info"
            full_path = prefix + relative
            payload = b"producer-impossible-regular-dist-info"
            payload_sha256 = hashlib.sha256(payload).hexdigest()
            demo_distribution = next(
                item
                for item in document["distributions"]
                if item["normalized_name"] == "demo-pkg"
            )
            document["files"].append(
                {
                    "path": full_path,
                    "distribution": "demo-pkg",
                    "mode": "0600",
                    "size": len(payload),
                    "sha256": payload_sha256,
                    "record_sha256": demo_distribution["record_sha256"],
                }
            )
            manifest["entries"].append(
                {
                    "kind": "file",
                    "mode": "0600",
                    "path": full_path,
                    "sha256": payload_sha256,
                    "size": len(payload),
                }
            )

            owner_files = {
                entry["path"][len(prefix) :]: entry
                for entry in document["files"]
                if entry["distribution"] == "demo-pkg"
            }
            record_relative = "Demo_Pkg-1.0.dist-info/RECORD"
            record_raw = b3._canonical_record_bytes(
                set(owner_files), owner_files, record_relative
            )
            record_sha256 = hashlib.sha256(record_raw).hexdigest()
            record_full_path = prefix + record_relative
            manifest_by_path = {
                entry["path"]: entry for entry in manifest["entries"]
            }
            for entry in (
                owner_files[record_relative],
                manifest_by_path[record_full_path],
            ):
                entry["size"] = len(record_raw)
                entry["sha256"] = record_sha256
            demo_distribution["record_sha256"] = record_sha256
            for entry in document["files"]:
                if entry["distribution"] == "demo-pkg":
                    entry["record_sha256"] = record_sha256
            semantics = next(
                item
                for item in installed["wheel_metadata_semantics"]
                if item["normalized_name"] == "demo-pkg"
            )
            demo_distribution["source_identity_sha256"] = (
                b3._source_identity_sha256(
                    demo_distribution,
                    dependency_component_id=document["dependency_component_id"],
                    dependency_lock_sha256=document["dependency_lock_sha256"],
                    project_metadata_sha256=document["project_metadata_sha256"],
                    wheel_metadata_semantics=semantics,
                )
            )
            rehash_installed_result(forged)

            # B1/B2 and every documentary hash accept the coordinated rewrite.
            self.assertEqual(
                b2._installed_manifest(
                    document,
                    request,
                    environment["environment_request_sha256"],
                    environment["storage_digest"],
                ),
                installed["installed_distribution_manifest_sha256"],
            )
            frozen_b1, _frozen_b2 = b3._load_frozen_upstreams()
            frozen_b1["_validate_result_replay"](forged["storage_inspect_result"])
            b3._validate_fragment(fragment)
            b3._validate_storage_success(forged["storage_inspect_result"], fragment)
            with self.assertRaises(b3._Refused):
                b3._crosscheck_installed_manifest_tree(
                    manifest,
                    request,
                    document,
                    installed["wheel_metadata_semantics"],
                )
            self.assertEqual(
                b3.validate_environment_static_result(forged)["status"],
                "blocked",
            )
        finally:
            fixture.close()

    def test_coordinated_dist_info_owner_transplant_full_rehash_is_refused(self):
        fixture = ModelStaticFixture(installed_variant="two-wheels")
        try:
            forged = copy.deepcopy(fixture.call())
            self.assertEqual(forged["status"], "success", forged)
            fragment = forged["environment_static_fragment"]
            environment = fragment["environment"]
            installed = fragment["installed"]
            document = installed["installed_distribution_manifest"]
            manifest = environment["storage_manifest"]
            request = environment["environment_request"]
            request_sha256 = environment["environment_request_sha256"]
            site_packages = b3._site_packages_relative(request)
            prefix = site_packages + "/"

            transplanted_owners = {
                "Demo_Pkg-1.0.dist-info/METADATA": "other",
                "Demo_Pkg-1.0.dist-info/WHEEL": "other",
                "Other-2.0.dist-info/METADATA": "demo-pkg",
                "Other-2.0.dist-info/WHEEL": "demo-pkg",
            }
            for entry in document["files"]:
                relative = entry["path"][len(prefix) :]
                if relative in transplanted_owners:
                    entry["distribution"] = transplanted_owners[relative]

            manifest_by_path = {
                entry["path"]: entry for entry in manifest["entries"]
            }
            distributions = {
                entry["normalized_name"]: entry
                for entry in document["distributions"]
            }
            record_paths = {
                "demo-pkg": "Demo_Pkg-1.0.dist-info/RECORD",
                "other": "Other-2.0.dist-info/RECORD",
            }
            for owner, record_relative in record_paths.items():
                owner_files = {
                    entry["path"][len(prefix) :]: entry
                    for entry in document["files"]
                    if entry["distribution"] == owner
                }
                record_raw = b3._canonical_record_bytes(
                    set(owner_files), owner_files, record_relative
                )
                record_sha256 = hashlib.sha256(record_raw).hexdigest()
                record_full_path = prefix + record_relative
                for entry in (
                    owner_files[record_relative],
                    manifest_by_path[record_full_path],
                ):
                    entry["size"] = len(record_raw)
                    entry["sha256"] = record_sha256
                distributions[owner]["record_sha256"] = record_sha256
                for entry in document["files"]:
                    if entry["distribution"] == owner:
                        entry["record_sha256"] = record_sha256

            semantics = {
                entry["normalized_name"]: entry
                for entry in installed["wheel_metadata_semantics"]
            }
            for owner, distribution in distributions.items():
                distribution["source_identity_sha256"] = (
                    b3._source_identity_sha256(
                        distribution,
                        dependency_component_id=document[
                            "dependency_component_id"
                        ],
                        dependency_lock_sha256=document[
                            "dependency_lock_sha256"
                        ],
                        project_metadata_sha256=document[
                            "project_metadata_sha256"
                        ],
                        wheel_metadata_semantics=semantics[owner],
                    )
                )

            document["total_bytes"] = sum(
                entry["size"] for entry in document["files"]
            )
            manifest["total_bytes"] = sum(
                entry["size"] for entry in manifest["entries"]
            )
            manifest_sha256 = b2._tree_manifest(
                manifest, request, request_sha256
            )
            prepare = environment["storage_prepare_record"]
            prepare.update(
                {
                    "manifest_sha256": manifest_sha256,
                    "manifest_entry_count": manifest["entry_count"],
                    "manifest_total_bytes": manifest["total_bytes"],
                }
            )
            prepare["prepare_sha256"] = b2._domain_hash(
                b2._STORAGE_DOMAINS["prepare"],
                {
                    key: prepare[key]
                    for key in b2.STORAGE_PREPARE_KEYS
                    if key != "prepare_sha256"
                },
            )
            prepare_sha256 = b2._storage_prepare(
                prepare,
                request,
                request_sha256,
                environment["storage_request_record"],
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
                    "storage_manifest_sha256": manifest_sha256,
                    "storage_prepare_sha256": prepare_sha256,
                    "storage_digest": storage_digest,
                }
            )
            document["storage_digest"] = storage_digest
            installed["installed_distribution_manifest_sha256"] = (
                b2._installed_manifest(
                    document, request, request_sha256, storage_digest
                )
            )
            model = fragment["model"]
            model["model_manifest"]["storage_digest"] = storage_digest
            model["model_manifest_sha256"] = b2._model_manifest(
                model["model_manifest"],
                request,
                request_sha256,
                storage_digest,
            )
            fragment["fragment_sha256"] = domain_hash(
                FRAGMENT_DOMAIN,
                {
                    key: fragment[key]
                    for key in b3.FRAGMENT_KEYS
                    if key != "fragment_sha256"
                },
            )
            storage_result = forged["storage_inspect_result"]
            storage_result.update(
                {
                    "manifest_sha256": manifest_sha256,
                    "prepare_sha256": prepare_sha256,
                    "storage_digest": storage_digest,
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
            forged["environment_static_fragment_sha256"] = fragment[
                "fragment_sha256"
            ]
            forged["result_sha256"] = domain_hash(
                RESULT_DOMAIN,
                {
                    key: forged[key]
                    for key in b3.RESULT_KEYS
                    if key != "result_sha256"
                },
            )

            # B1/B2 and every documentary digest accept the coordinated rewrite;
            # B3 must still reject cross-owned files under either .dist-info.
            self.assertEqual(
                b2._installed_manifest(
                    document, request, request_sha256, storage_digest
                ),
                installed["installed_distribution_manifest_sha256"],
            )
            frozen_b1, _frozen_b2 = b3._load_frozen_upstreams()
            frozen_b1["_validate_result_replay"](storage_result)
            b3._validate_fragment(fragment)
            b3._validate_storage_success(storage_result, fragment)
            with self.assertRaises(b3._Refused):
                b3._crosscheck_installed_manifest_tree(
                    manifest,
                    request,
                    document,
                    installed["wheel_metadata_semantics"],
                )
            self.assertEqual(
                b3.validate_environment_static_result(forged)["status"],
                "blocked",
            )
        finally:
            fixture.close()

    def test_wheel_semantics_transplant_with_outer_rehash_is_replay_refused(self):
        fixture = ModelStaticFixture()
        donor = ModelStaticFixture(installed_variant="valid-wheel-false-platform")
        try:
            forged = copy.deepcopy(fixture.call())
            donor_result = donor.call()
            fragment = forged["environment_static_fragment"]
            fragment["installed"]["wheel_metadata_semantics"] = copy.deepcopy(
                donor_result["environment_static_fragment"]["installed"][
                    "wheel_metadata_semantics"
                ]
            )
            fragment["fragment_sha256"] = domain_hash(
                FRAGMENT_DOMAIN,
                {
                    key: fragment[key]
                    for key in b3.FRAGMENT_KEYS
                    if key != "fragment_sha256"
                },
            )
            forged["environment_static_fragment_sha256"] = fragment[
                "fragment_sha256"
            ]
            forged["result_sha256"] = domain_hash(
                RESULT_DOMAIN,
                {
                    key: forged[key]
                    for key in b3.RESULT_KEYS
                    if key != "result_sha256"
                },
            )
            self.assertEqual(
                b3.validate_environment_static_result(forged)["status"],
                "blocked",
            )
        finally:
            donor.close()
            fixture.close()


class TestBoundedDirectoryEnumeration(unittest.TestCase):
    class Entry:
        def __init__(self, name):
            self.name = name

    class Iterator:
        def __init__(self, total, *, reverse=False, interrupt_at=None, close_error=False):
            self.total = total
            self.reverse = reverse
            self.interrupt_at = interrupt_at
            self.close_error = close_error
            self.index = 0
            self.yielded = 0
            self.close_calls = 0

        def __next__(self):
            if self.interrupt_at is not None and self.index == self.interrupt_at:
                raise self.Interrupt()
            if self.index >= self.total:
                raise StopIteration
            value = self.total - self.index - 1 if self.reverse else self.index
            self.index += 1
            self.yielded += 1
            return TestBoundedDirectoryEnumeration.Entry(f"n{value:05d}")

        def close(self):
            self.close_calls += 1
            if self.close_error:
                raise OSError("injected scandir close failure")

        class Interrupt(BaseException):
            pass

    def _call_with_iterator(self, iterator):
        parent_fd = os.open("/private/tmp", b3._DIR_FLAGS)
        real_close_owned = b3._close_owned
        closed = []
        self.closed_scan_fds = closed

        def recording_close(fd, token):
            closed.append((fd, token))
            return real_close_owned(fd, token)

        try:
            with mock.patch.object(b3.os, "scandir", return_value=iterator):
                with mock.patch.object(
                    b3, "_close_owned", side_effect=recording_close
                ):
                    value = b3._safe_names(parent_fd, "bounded-list")
            return value, closed
        finally:
            os.close(parent_fd)

    def test_safe_names_exact_limit_succeeds_sorted_and_closes_once(self):
        iterator = self.Iterator(b3.MAX_TREE_ENTRIES, reverse=True)
        value, closed = self._call_with_iterator(iterator)
        self.assertEqual(len(value), b3.MAX_TREE_ENTRIES)
        self.assertEqual(value[0], "n00000")
        self.assertEqual(value[-1], f"n{b3.MAX_TREE_ENTRIES - 1:05d}")
        self.assertEqual(iterator.yielded, b3.MAX_TREE_ENTRIES)
        self.assertEqual(iterator.close_calls, 1)
        self.assertEqual(len(closed), 1)

    def test_safe_names_max_plus_one_stops_and_closes_once(self):
        iterator = self.Iterator(b3.MAX_TREE_ENTRIES + 100)
        with self.assertRaises(b3._Refused):
            self._call_with_iterator(iterator)
        self.assertEqual(iterator.yielded, b3.MAX_TREE_ENTRIES + 1)
        self.assertEqual(iterator.close_calls, 1)
        self.assertEqual(len(self.closed_scan_fds), 1)

    def test_safe_names_baseexception_cleans_resources_once(self):
        iterator = self.Iterator(10, interrupt_at=1)
        with self.assertRaises(self.Iterator.Interrupt):
            self._call_with_iterator(iterator)
        self.assertEqual(iterator.yielded, 1)
        self.assertEqual(iterator.close_calls, 1)
        self.assertEqual(len(self.closed_scan_fds), 1)

    def test_safe_names_iterator_close_failure_is_not_retried(self):
        iterator = self.Iterator(0, close_error=True)
        with self.assertRaises(b3._Refused):
            self._call_with_iterator(iterator)
        self.assertEqual(iterator.close_calls, 1)
        self.assertEqual(len(self.closed_scan_fds), 1)


class TestCloseOnce(unittest.TestCase):
    def test_installed_file_close_eio_is_not_retried_after_fd_reuse(self):
        fixture = ModelStaticFixture()
        real_close = os.close
        real_open = os.open
        target = [None]
        target_calls = [0]
        replacement = [None]

        def recording_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if path == "METADATA" and target[0] is None:
                target[0] = fd
            return fd

        def injected_close(fd):
            if target[0] is not None and fd == target[0]:
                target_calls[0] += 1
                if target_calls[0] == 1:
                    real_close(fd)
                    replacement[0] = real_open("/dev/null", os.O_RDONLY)
                    raise OSError(5, "injected ambiguous close")
            return real_close(fd)

        try:
            with mock.patch.object(b3.os, "open", recording_open):
                with mock.patch.object(b3.os, "close", injected_close):
                    result = fixture.call()
            self.assertEqual(result["status"], "blocked")
            self.assertIsNotNone(target[0])
            self.assertEqual(target_calls[0], 1)
            os.fstat(replacement[0])
        finally:
            if replacement[0] is not None:
                real_close(replacement[0])
            fixture.close()

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
        self.assertIn("scandir", calls)
        self.assertNotIn("listdir", calls)
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

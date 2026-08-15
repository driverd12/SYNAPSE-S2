"""Focused Stage 1B contracts for the official SYNAPSE-S2 Memory adapter."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from official_longmem import bootstrap as bootstrap_module  # noqa: E402

OFFICIAL_ROOT = Path(
    os.environ.get(
        "LONGMEM_V2_OFFICIAL_ROOT",
        "/private/tmp/s2-frontier-review.CqgTZr/longmemeval-v2",
    )
)
SMALL_BACKEND = {
    "dimension": 32,
    "num_neurons": 64,
    "default_top_k": 8,
    "recall_count": 16,
    "embedding_provider": "semantic-hash",
}


def _trajectory(trajectory_id: str, text: str) -> dict[str, object]:
    return {
        "id": trajectory_id,
        "goal": "remember the bounded observation",
        "states": [
            {
                "url": "https://example.test/item",
                "action": "inspect item",
                "thought": "retain the useful detail",
                "accessibility_tree": text,
            }
        ],
    }


@unittest.skipUnless(
    OFFICIAL_ROOT.is_dir(),
    f"pinned official checkout not present at {OFFICIAL_ROOT}",
)
class OfficialLongMemAdapterTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        if bootstrap_module.active_run_root() is not None:
            bootstrap_module.deactivate_run_root()
        cls.run_root = bootstrap_module.activate_run_root()
        cls.original_pycache_prefix = sys.pycache_prefix
        pycache = Path(
            tempfile.mkdtemp(prefix="adapter-tests-", dir=cls.run_root.pycache_parent)
        )
        os.chmod(pycache, 0o700)
        sys.pycache_prefix = str(pycache)
        bootstrap_module.bootstrap_official(OFFICIAL_ROOT)
        import memory_modules.memory as official
        import official_longmem.synapse_s2_memory as adapter

        cls.official = official
        cls.adapter = adapter

    @classmethod
    def tearDownClass(cls) -> None:
        sys.pycache_prefix = cls.original_pycache_prefix
        if bootstrap_module.active_run_root() is not None:
            bootstrap_module.deactivate_run_root()

    def setUp(self) -> None:
        self.memories: list[object] = []
        self.external_roots: list[Path] = []
        self.output_root = Path(
            tempfile.mkdtemp(prefix="adapter-case-", dir=self.run_root.output_parent)
        )
        os.chmod(self.output_root, 0o700)

    def tearDown(self) -> None:
        failures: list[BaseException] = []
        for memory in reversed(self.memories):
            try:
                memory.close()
            except BaseException as exc:  # pragma: no cover - cleanup evidence
                failures.append(exc)
        if self.output_root.exists():
            try:
                bootstrap_module.remove_tree_checked(
                    self.output_root,
                    owner="adapter test output",
                    safe_root=self.run_root.base,
                )
            except BaseException as exc:  # pragma: no cover - cleanup evidence
                failures.append(exc)
        for root in self.external_roots:
            shutil.rmtree(root, ignore_errors=True)
        if failures:
            raise failures[0]

    def _build(self, **overrides: object):
        params: dict[str, object] = {"backend": dict(SMALL_BACKEND)}
        params.update(overrides)
        memory = self.official.build_memory(
            {"memory_type": "synapse_s2", "memory_params": params}
        )
        self.memories.append(memory)
        return memory

    def _manifest_digest(self, artifact: Path) -> str:
        return hashlib.sha256(
            (artifact / self.adapter.MANIFEST_NAME).read_bytes()
        ).hexdigest()

    def _requested_config(
        self, artifact: Path, *, digest: str | None = None, release: bool = False
    ) -> dict[str, object]:
        config = json.loads(
            (artifact / self.adapter.MEMORY_CONFIG_NAME).read_text(encoding="utf-8")
        )
        config["memory_params"][self.adapter.EXPECTED_MANIFEST_SHA256_PARAM] = (
            digest or self._manifest_digest(artifact)
        )
        config["memory_params"][self.adapter.RELEASE_AFTER_QUERY_PARAM] = release
        return config

    def _sealed_artifact(self, name: str = "artifact") -> Path:
        memory = self._build()
        memory.insert(_trajectory("traj-alpha", "red stapler total 12.99"))
        artifact = self.output_root / name
        memory.save_memory(artifact)
        memory.close()
        return artifact

    def _rewrite_manifest(self, artifact: Path, manifest: dict[str, object]) -> str:
        raw = self.adapter._canonical_json_bytes(manifest)
        path = artifact / self.adapter.MANIFEST_NAME
        path.write_bytes(raw)
        os.chmod(path, 0o600)
        return hashlib.sha256(raw).hexdigest()

    def test_operations_require_wrapper_created_run_contract(self) -> None:
        memory = self._build()
        with mock.patch.object(
            self.adapter._bootstrap, "active_run_root", return_value=None
        ):
            with self.assertRaisesRegex(RuntimeError, "wrapper-created"):
                memory.insert(_trajectory("traj-no-wrapper", "text"))

    def test_long_configured_workspace_uses_short_private_runtime_and_is_removed(self) -> None:
        workspace = (
            self.output_root
            / ("outer segment " + "x" * 80)
            / ("inner segment " + "y" * 80)
            / "question workspace"
        )
        memory = self._build(workspace_dir=str(workspace))
        memory.insert(_trajectory("traj-space", "red stapler near lamp"))
        runtime_root = memory._runtime.runtime_root
        socket_path = (
            runtime_root / "repo" / ".synapse_s2" / "core" / "service.sock"
        )
        self.assertTrue(workspace.is_relative_to(self.run_root.base))
        self.assertEqual(stat.S_IMODE(workspace.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(runtime_root.stat().st_mode), 0o700)
        self.assertLessEqual(len(str(socket_path).encode("utf-8")), 103)
        memory.close()
        self.assertFalse(workspace.exists())
        self.assertFalse(runtime_root.exists())

    def test_redaction_precedes_truncation_and_persisted_binding_is_not_content_hash(
        self,
    ) -> None:
        raw = "A" * 500 + " sk-123456789012345678901234567890"
        sanitized, truncated = self.adapter._sanitize_bounded(raw, 512)
        self.assertTrue(truncated)
        self.assertNotIn("sk-123", sanitized)

        memory = self._build(insert={"max_state_text_bytes": 512})
        trajectory = _trajectory(
            "traj-redacted",
            "A" * 465 + " sk-123456789012345678901234567890",
        )
        prepared = memory._prepared_states(trajectory, "traj-redacted")
        private_identity = memory._trajectory_fingerprint(
            trajectory, "traj-redacted", prepared
        )
        memory.insert(trajectory)
        record = memory._ledger["trajectories"]["traj-redacted"]
        entry = memory._runtime.adapter.get_entry(record["memory_ids"][0])
        source_text = entry["source_text"]
        metadata = entry["metadata"]
        self.assertNotIn("sk-123", source_text)
        self.assertNotEqual(record["fingerprint"], private_identity)
        self.assertNotEqual(
            record["fingerprint"],
            hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        )
        self.assertNotIn("trajectory_fingerprint", metadata)
        self.assertEqual(metadata["trajectory_binding"], record["fingerprint"])

        artifact = self.output_root / "redacted-artifact"
        workspace_text = str(memory._runtime.workspace_dir)
        runtime_text = str(memory._runtime.runtime_root)
        memory.save_memory(artifact)
        for filename in (
            self.adapter.MEMORY_CONFIG_NAME,
            self.adapter.LEDGER_NAME,
            self.adapter.MANIFEST_NAME,
        ):
            rendered = (artifact / filename).read_text(encoding="utf-8")
            self.assertNotIn("sk-123", rendered)
            self.assertNotIn(private_identity, rendered)
            self.assertNotIn(workspace_text, rendered)
            self.assertNotIn(runtime_text, rendered)
        public_config = json.loads(
            (artifact / self.adapter.MEMORY_CONFIG_NAME).read_text(encoding="utf-8")
        )
        self.assertEqual(
            set(public_config["memory_params"]), set(self.adapter.PUBLIC_PARAM_KEYS)
        )

    def test_vision_mode_is_fixed_and_screenshot_errors_are_content_free(self) -> None:
        private_mode = "/private/operator/secret-vision-mode"
        with self.assertRaises(RuntimeError) as invalid_mode:
            self._build(image={"vision_mode": private_mode})
        self.assertNotIn(private_mode, str(invalid_mode.exception))

        memory = self._build()
        private_source = "/private/operator/sk-12345678901234567890.png"
        trajectory = _trajectory("traj-missing-image", "image observation")
        trajectory["states"][0]["screenshot"] = private_source
        with self.assertRaises(RuntimeError) as missing_source:
            memory.insert(trajectory)
        self.assertNotIn(private_source, str(missing_source.exception))
        self.assertIn("unavailable", str(missing_source.exception))

    def test_save_validates_destination_before_base_config_write(self) -> None:
        memory = self._build()
        memory.insert(_trajectory("traj-safe-save", "safe save"))
        external = Path(tempfile.mkdtemp(prefix="s2lm-outside-", dir="/private/tmp"))
        os.chmod(external, 0o700)
        self.external_roots.append(external)
        destination = external / "artifact"
        with self.assertRaisesRegex(RuntimeError, "disposable path validation"):
            memory.save_memory(destination)
        self.assertFalse(destination.exists())
        self.assertFalse((destination / self.adapter.MEMORY_CONFIG_NAME).exists())

    def test_load_requires_exact_out_of_band_manifest_pin_and_roundtrips(self) -> None:
        artifact = self._sealed_artifact()
        with self.assertRaisesRegex(RuntimeError, "caller-supplied"):
            self.official.load_memory(artifact)

        wrong = self._requested_config(artifact, digest="0" * 64)
        with self.assertRaisesRegex(RuntimeError, "caller-supplied digest"):
            self.official.load_memory(artifact, requested_config=wrong)

        loaded = self.official.load_memory(
            artifact, requested_config=self._requested_config(artifact)
        )
        self.memories.append(loaded)
        items = loaded.query("what was the stapler total")
        self.assertTrue(items)
        self.assertTrue(any(item["type"] == "text" for item in items))

    def test_exact_inventory_rejects_unlisted_symlink(self) -> None:
        artifact = self._sealed_artifact()
        (artifact / "unlisted").symlink_to(artifact / self.adapter.STORE_DIR_NAME)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.official.load_memory(
                artifact, requested_config=self._requested_config(artifact)
            )

    def test_resigned_retrieval_index_tamper_fails_semantic_restore(self) -> None:
        artifact = self._sealed_artifact()
        db_path = artifact / self.adapter.STORE_FILE_RELATIVE
        connection = sqlite3.connect(db_path)
        try:
            connection.execute(
                "UPDATE memory_entries SET spike_indices_json = '[]'"
            )
            connection.execute("DELETE FROM memory_spikes")
            connection.commit()
        finally:
            connection.close()
        os.chmod(db_path, 0o600)

        manifest_path = artifact / self.adapter.MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        db_raw = db_path.read_bytes()
        manifest["files"][self.adapter.STORE_FILE_RELATIVE] = {
            "sha256": hashlib.sha256(db_raw).hexdigest(),
            "bytes": len(db_raw),
        }
        resigned_digest = self._rewrite_manifest(artifact, manifest)
        requested = self._requested_config(artifact, digest=resigned_digest)
        with self.assertRaisesRegex(RuntimeError, "retrieval coordinates"):
            self.official.load_memory(artifact, requested_config=requested)
        self.assertFalse(any(self.run_root.runtime_parent.iterdir()))
        self.assertFalse(any(self.run_root.workspace_parent.iterdir()))

    def test_resigned_duplicate_event_fails_bounded_semantic_restore(self) -> None:
        artifact = self._sealed_artifact()
        db_path = artifact / self.adapter.STORE_FILE_RELATIVE
        connection = sqlite3.connect(db_path)
        try:
            connection.execute(
                "INSERT INTO memory_events "
                "(memory_id, event_type, payload_json, created_at) "
                "SELECT memory_id, event_type, payload_json, created_at "
                "FROM memory_events ORDER BY event_id LIMIT 1"
            )
            connection.commit()
        finally:
            connection.close()
        os.chmod(db_path, 0o600)

        manifest_path = artifact / self.adapter.MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        db_raw = db_path.read_bytes()
        manifest["files"][self.adapter.STORE_FILE_RELATIVE] = {
            "sha256": hashlib.sha256(db_raw).hexdigest(),
            "bytes": len(db_raw),
        }
        resigned_digest = self._rewrite_manifest(artifact, manifest)
        requested = self._requested_config(artifact, digest=resigned_digest)
        with self.assertRaisesRegex(RuntimeError, "ledger event binding"):
            self.official.load_memory(artifact, requested_config=requested)
        self.assertFalse(any(self.run_root.runtime_parent.iterdir()))
        self.assertFalse(any(self.run_root.workspace_parent.iterdir()))

    def test_source_build_binding_and_random_artifact_bindings(self) -> None:
        first = self._sealed_artifact("artifact-one")
        second = self._sealed_artifact("artifact-two")
        first_ledger = json.loads(
            (first / self.adapter.LEDGER_NAME).read_text(encoding="utf-8")
        )
        second_ledger = json.loads(
            (second / self.adapter.LEDGER_NAME).read_text(encoding="utf-8")
        )
        self.assertNotEqual(
            first_ledger["trajectories"]["traj-alpha"]["fingerprint"],
            second_ledger["trajectories"]["traj-alpha"]["fingerprint"],
        )
        manifest = json.loads(
            (first / self.adapter.MANIFEST_NAME).read_text(encoding="utf-8")
        )
        self.assertRegex(manifest["source_build_id"], r"^source-[0-9a-f]{64}$")
        self.assertEqual(
            set(manifest["source_manifest"]),
            set(self.adapter.EXECUTABLE_SOURCE_MODULES)
            | {
                f"build:{relative}"
                for relative in self.adapter.EXECUTABLE_BUILD_FILES
            },
        )

    def test_release_after_query_closes_owned_roots_idempotently(self) -> None:
        memory = self._build(release_after_query=True)
        memory.insert(_trajectory("traj-release", "release after one question"))
        runtime_root = memory._runtime.runtime_root
        workspace = memory._runtime.workspace_dir
        items = memory.query("what should be released")
        metadata = memory.post_query_hook(
            query="what should be released",
            query_image=None,
            memory_context=items,
        )
        self.assertTrue(metadata["released_after_query"])
        self.assertIsNone(memory._runtime)
        self.assertFalse(runtime_root.exists())
        self.assertFalse(workspace.exists())
        memory.close()
        with self.assertRaisesRegex(RuntimeError, "closed"):
            memory.query("cannot reuse a released question memory")


if __name__ == "__main__":
    unittest.main()

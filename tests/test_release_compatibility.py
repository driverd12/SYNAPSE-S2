"""Focused contracts for the dormant exact-build compatibility verifier."""

import builtins
import codecs
import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
COMPATIBILITY_PATH = ROOT / "scripts" / "release_compatibility.py"
PLANNER_PATH = ROOT / "scripts" / "release_update_plan.py"
PROVENANCE_PATH = ROOT / "scripts" / "release_provenance.py"
SIGNER_PATH = ROOT / "scripts" / "sign_release_provenance.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compatibility = _load_module(
    "release_compatibility_under_test", COMPATIBILITY_PATH
)
planner = _load_module("release_update_plan_for_compatibility", PLANNER_PATH)
provenance = _load_module(
    "release_provenance_for_compatibility", PROVENANCE_PATH
)
signer = _load_module("release_signer_for_compatibility", SIGNER_PATH)

_CRYPTO_AVAILABLE = all(
    module._ED25519 is not None
    for module in (compatibility, provenance, signer)
)
if _CRYPTO_AVAILABLE:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519


ISSUED = 1_750_000_000
EXPIRES = 1_900_000_000
NOW = 1_800_000_000

EXPECTED_SURFACE_FILES = {
    "authority-runtime": (
        "core_authority.py", "core_client_binding.py", "core_service.py",
        "memory_store.py",
    ),
    "capture": (
        "capture_daemon.py", "transcript_capture.py", "memory_store.py",
        "mlx_backend.py", "replacement_policy.py", "core_service.py",
        "scripts/core_agent_installer.py",
    ),
    "context-delivery": (
        "memory_store.py", "mlx_backend.py", "core_service.py",
        "core_protocol.py", "mcp_server.py",
    ),
    "core-config": (
        "core_protocol.py", "core_service.py", "core_client_binding.py",
        "client_config.py", "scripts/core_agent_installer.py",
        "scripts/core_cutover_preflight.py",
    ),
    "disk-safety": ("core_path_policy.py",),
    "store-schema": (
        "memory_store.py", "core_service.py", "scripts/core_agent_installer.py",
    ),
    "embedding-space": (
        "embedding_providers.py", "mlx_backend.py", "core_service.py",
    ),
    "installed-layout": (
        "scripts/installed_layout.py", "scripts/release_stage.py",
        "scripts/release_update_plan.py", "core_client_binding.py",
        "client_config.py", "scripts/core_agent_installer.py",
    ),
    "platform-runtime": (
        "core_protocol.py", "core_runtime_paths.py", "scripts/release_stage.py",
        "pyproject.toml", "uv.lock",
    ),
    "readiness-quiescence": (
        "operator_readiness_contract.py",
        "scripts/operator_readiness_certify.py",
        "scripts/core_cutover_preflight.py", "scripts/core_agent_installer.py",
    ),
    "recovery": (
        "recovery_manager.py", "memory_store.py", "core_request_journal.py",
        "capture_daemon.py", "scripts/repair_torn_core_adoption.py",
        "scripts/core_agent_installer.py", "scripts/core_cutover_preflight.py",
    ),
    "replication": (
        "replication_protocol.py", "replication_store.py",
        "replication_manager.py",
    ),
    "request-journal": (
        "core_request_journal.py", "core_service.py", "recovery_manager.py",
    ),
}


class CompatibilityFixture(unittest.TestCase):
    """A small synthetic tree still exercises all 199 closed paths."""

    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if not _CRYPTO_AVAILABLE:
            raise unittest.SkipTest(
                "trusted cryptography 49 unavailable; run under project venv"
            )
        cls.root_private = ed25519.Ed25519PrivateKey.generate()
        cls.release_private = ed25519.Ed25519PrivateKey.generate()
        cls.compatibility_private = ed25519.Ed25519PrivateKey.generate()
        cls.root_public = cls.root_private.public_key().public_bytes_raw().hex()
        cls.release_public = (
            cls.release_private.public_key().public_bytes_raw().hex()
        )
        cls.compatibility_public = (
            cls.compatibility_private.public_key().public_bytes_raw().hex()
        )
        cls.root_key_id = compatibility.key_id_for_public_key(cls.root_public)
        cls.release_key_id = compatibility.key_id_for_public_key(
            cls.release_public
        )
        cls.compatibility_key_id = compatibility.key_id_for_public_key(
            cls.compatibility_public
        )

    def setUp(self) -> None:
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory(
            prefix="s2compat-", dir="/private/tmp"
        )
        self.base = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)
        self.documents = self.base / "documents"
        self.documents.mkdir(mode=0o700)
        self.current = self.base / "current"
        self._write_exact_root(self.current)
        self.candidate = self.base / "candidate"
        shutil.copytree(self.current, self.candidate)

        # Exact ignored current-root state: metadata may be screened, but
        # this deliberately unreadable content must never be opened.
        live = self.current / ".synapse_s2"
        live.mkdir(mode=0o700)
        secret = live / "must-not-be-read"
        secret.write_bytes(b"private live-state fixture")
        secret.chmod(0o000)

        self.current_observation, self.candidate_observation = (
            self._observe_pair(self.current, self.candidate)
        )
        self._install_chain()

    def _write_exact_root(self, root: Path) -> None:
        root.mkdir(mode=0o700)
        manifest_source = (
            "BUILD_SOURCE_MANIFEST = "
            + repr(compatibility.TRUSTED_MANIFEST)
            + "\n"
        ).encode("utf-8")
        for _, _, relative in compatibility.PRODUCT_INVENTORY:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = (
                manifest_source
                if relative == "core_service.py"
                else f"fixture:{relative}\n".encode("utf-8")
            )
            target.write_bytes(payload)
            target.chmod(0o644)

    @staticmethod
    def _observe_pair(current: Path, candidate: Path) -> tuple[dict, dict]:
        snapshots = []
        try:
            product_budget = {
                "remaining": compatibility.MAX_PRODUCT_TOTAL_BYTES
            }
            manifest_budget = {
                "remaining": compatibility.MAX_TOTAL_MANIFEST_BYTES
            }
            name_budget = {
                "remaining": compatibility.MAX_PRODUCT_SCANNED_NAME_BYTES
            }
            observations = []
            registries = []
            for root, allow_state in ((current, True), (candidate, False)):
                snapshot = compatibility._RootSnapshot(str(root))
                snapshots.append(snapshot)
                ignored = []
                registries.append(ignored)
                observations.append(
                    compatibility._capture_root_observation(
                        snapshot,
                        product_budget,
                        manifest_budget,
                        name_budget,
                        allow_state,
                        ignored,
                    )
                )
            for snapshot, ignored in zip(snapshots, registries):
                compatibility._recheck_ignored_entries(snapshot, ignored)
                snapshot.recheck()
            return observations[0], observations[1]
        finally:
            for snapshot in snapshots:
                snapshot.close()

    @staticmethod
    def _signed(unsigned: dict, key, domain: bytes) -> dict:
        document = dict(unsigned)
        document["signature"] = key.sign(
            domain + compatibility.canonical_bytes(unsigned)
        ).hex()
        return document

    @classmethod
    def _delegation(cls, role: str) -> dict:
        if role == compatibility.DELEGATION_ROLE_RELEASE:
            key_id, public = cls.release_key_id, cls.release_public
        else:
            key_id = cls.compatibility_key_id
            public = cls.compatibility_public
        return {
            "key_id": key_id,
            "public_key": public,
            "role": role,
            "channels": ["stable"],
            "not_before": ISSUED,
            "not_after": EXPIRES,
            "sequence_minimum": 1,
            "sequence_maximum": 100,
        }

    def _write_document(self, name: str, document: dict, mode=0o644) -> Path:
        path = self.documents / name
        path.write_bytes(compatibility.canonical_bytes(document))
        path.chmod(mode)
        return path

    def _install_chain(
        self,
        *,
        bundle_overrides=None,
        envelope_overrides=None,
        ticket_overrides=None,
        floor_overrides=None,
        floor_installed_overrides=None,
        envelope_signer=None,
        ticket_signer=None,
    ) -> None:
        root = {
            "schema": compatibility.ROOT_SCHEMA,
            "root_key_id": self.root_key_id,
            "root_public_key": self.root_public,
        }
        self.root_path = self._write_document("root.json", root)

        bundle = {
            "schema": compatibility.BUNDLE_SCHEMA_V2,
            "root_key_id": self.root_key_id,
            "generation": 7,
            "issued_at": ISSUED,
            "expires_at": EXPIRES,
            "channel_minimum_sequences": {"stable": 1},
            "delegations": [
                self._delegation(compatibility.DELEGATION_ROLE_COMPATIBILITY),
                self._delegation(compatibility.DELEGATION_ROLE_RELEASE),
            ],
            "revoked_key_ids": [],
        }
        bundle.update(bundle_overrides or {})
        bundle = self._signed(
            bundle, self.root_private, compatibility._BUNDLE_SIGNING_DOMAIN_V2
        )
        self.bundle_path = self._write_document("bundle.json", bundle)
        bundle_sha = hashlib.sha256(
            compatibility.canonical_bytes(bundle)
        ).hexdigest()

        envelope = {
            "schema": compatibility.ENVELOPE_SCHEMA,
            "channel": "stable",
            "version": "2.0.0",
            "sequence": 5,
            "source_sha": "f" * 40,
            "product_schema": compatibility.PRODUCT_SCHEMA,
            "inventory_policy_id": compatibility._inventory_policy_id(),
            "product_id": self.candidate_observation["product_id"],
            "trust_generation": 7,
            "issued_at": ISSUED + 10,
            "expires_at": EXPIRES - 10,
            "key_id": self.release_key_id,
        }
        envelope.update(envelope_overrides or {})
        envelope_key = envelope_signer or self.release_private
        envelope = self._signed(
            envelope, envelope_key, compatibility._ENVELOPE_SIGNING_DOMAIN
        )
        self.envelope_path = self._write_document("envelope.json", envelope)
        envelope_sha = hashlib.sha256(
            compatibility.canonical_bytes(envelope)
        ).hexdigest()

        digests = compatibility._surface_digests(self.current_observation)
        dependency_id = self.current_observation["dependency_component_id"]
        ticket = {
            "schema": compatibility.TICKET_SCHEMA,
            "profile": compatibility.SURFACE_MODE,
            "profile_version": compatibility.PROFILE_VERSION,
            "compatibility_observation_schema": (
                compatibility.COMPATIBILITY_OBSERVATION_SCHEMA
            ),
            "product_schema": compatibility.PRODUCT_SCHEMA,
            "channel": envelope["channel"],
            "version": envelope["version"],
            "sequence": envelope["sequence"],
            "source_sha": envelope["source_sha"],
            "current_source_build_id": self.current_observation[
                "source_build_id"
            ],
            "candidate_source_build_id": self.candidate_observation[
                "source_build_id"
            ],
            "current_product_id": self.current_observation["product_id"],
            "candidate_product_id": self.candidate_observation["product_id"],
            "inventory_policy_id": compatibility._inventory_policy_id(),
            "current_dependency_component_id": dependency_id,
            "candidate_dependency_component_id": dependency_id,
            "surface_digests": digests,
            "surfaces_digest": compatibility._surfaces_digest(
                digests, dependency_id
            ),
            "layout_schema": compatibility.LAYOUT_SCHEMA,
            "layout_mode": compatibility.EXPECTED_LAYOUT_CONTRACT_MODE,
            "layout_contract_id": compatibility.EXPECTED_LAYOUT_CONTRACT_ID,
            "trust_generation": 7,
            "trust_bundle_sha256": bundle_sha,
            "envelope_sha256": envelope_sha,
            "host_evidence_receipt_schema": (
                compatibility.HOST_EVIDENCE_RECEIPT_SCHEMA
            ),
            "host_evidence_policy": compatibility.HOST_EVIDENCE_POLICY,
            "migration": compatibility.MIGRATION_POLICY,
            "downgrade": compatibility.DOWNGRADE_POLICY,
            "issued_at": ISSUED + 20,
            "expires_at": EXPIRES - 20,
            "key_id": self.compatibility_key_id,
        }
        ticket.update(ticket_overrides or {})
        ticket_key = ticket_signer or self.compatibility_private
        ticket = self._signed(
            ticket, ticket_key, compatibility._TICKET_SIGNING_DOMAIN
        )
        self.ticket_path = self._write_document("ticket.json", ticket)

        installed = {
            "sequence": 4,
            "envelope_sha256": "0" * 64,
            "source_sha": "e" * 40,
            "inventory_policy_id": compatibility._inventory_policy_id(),
            "product_id": self.current_observation["product_id"],
        }
        installed.update(floor_installed_overrides or {})
        floor = {
            "schema": compatibility.FLOOR_SCHEMA,
            "root_key_id": self.root_key_id,
            "trust_generation": 7,
            "trust_bundle_sha256": bundle_sha,
            "committed_at": ISSUED,
            "revoked_key_ids": list(bundle["revoked_key_ids"]),
            "channels": {
                "stable": {"minimum_sequence": 1, "installed": installed}
            },
        }
        floor.update(floor_overrides or {})
        self.floor_path = self._write_document("floor.json", floor, 0o600)
        self.bundle = bundle
        self.envelope = envelope
        self.ticket = ticket
        self.floor = floor

    def verify(self, *, current=None, candidate=None, now=NOW) -> dict:
        with mock.patch.object(compatibility, "_now", return_value=now):
            return self._invoke(current=current, candidate=candidate)

    def _invoke(self, *, current=None, candidate=None) -> dict:
        return compatibility.verify_compatibility_ticket(
            str(self.root_path),
            str(self.bundle_path),
            str(self.envelope_path),
            str(self.ticket_path),
            str(self.floor_path),
            str(current or self.current),
            str(candidate or self.candidate),
        )

    def fresh_candidate(self, name: str) -> Path:
        destination = self.base / name
        shutil.copytree(
            self.current,
            destination,
            ignore=shutil.ignore_patterns(".synapse_s2"),
        )
        return destination

    def assert_status(self, result: dict, status: str, exit_code: int) -> None:
        self.assertEqual(result["status"], status)
        self.assertEqual(compatibility.compatibility_exit_code(result), exit_code)
        self.assertIs(result["apply_supported"], False)
        self.assertIs(result["apply_performed"], False)
        self.assertIs(result["live_authority"], False)


class ExactBuildVerificationTests(CompatibilityFixture):
    def test_valid_dual_role_exact_roots_verify(self) -> None:
        before = self.floor_path.read_bytes()
        result = self.verify()
        self.assert_status(result, "verified", 0)
        self.assertEqual(self.floor_path.read_bytes(), before)
        self.assertEqual(result["surface_count"], 13)
        self.assertEqual(result["current_product_id"], result["candidate_product_id"])
        self.assertEqual(
            result["current_source_build_id"], result["candidate_source_build_id"]
        )
        self.assertEqual(
            result["current_dependency_component_id"],
            result["candidate_dependency_component_id"],
        )
        self.assertEqual(self.floor_path.stat().st_mode & 0o777, 0o600)

    def test_planner_vocabulary_ids_and_budgets_are_exactly_pinned(self) -> None:
        compatibility._validate_static_vocabulary()
        planner._validate_product_inventory()
        self.assertEqual(compatibility.TRUSTED_MANIFEST, planner.TRUSTED_MANIFEST)
        self.assertEqual(compatibility.PRODUCT_INVENTORY, planner.PRODUCT_INVENTORY)
        self.assertEqual(len(compatibility.PRODUCT_INVENTORY), 199)
        self.assertEqual(
            compatibility._inventory_policy_id(), planner._inventory_policy_id()
        )
        self.assertEqual(compatibility.MAX_TOTAL_MANIFEST_BYTES, 64 * 1024 * 1024)
        self.assertEqual(
            compatibility.MAX_TOTAL_MANIFEST_BYTES,
            planner.MAX_TOTAL_MANIFEST_BYTES,
        )
        self.assertEqual(compatibility.MAX_PRODUCT_TOTAL_BYTES, 128 * 1024 * 1024)
        self.assertEqual(
            compatibility.MAX_PRODUCT_TOTAL_BYTES, planner.MAX_PRODUCT_TOTAL_BYTES
        )
        for compatibility_name, planner_name in (
            ("MAX_SOURCE_FILE_BYTES", "MAX_MANIFEST_FILE_BYTES"),
            ("MAX_PRODUCT_INVENTORY_ENTRIES", "MAX_PRODUCT_INVENTORY_ENTRIES"),
            ("MAX_PRODUCT_DIRECTORY_ENTRIES", "MAX_PRODUCT_DIRECTORY_ENTRIES"),
            ("MAX_PRODUCT_NAME_BYTES", "MAX_PRODUCT_NAME_BYTES"),
            ("MAX_PRODUCT_PATH_BYTES", "MAX_PRODUCT_PATH_BYTES"),
            ("MAX_PRODUCT_SCANNED_NAME_BYTES", "MAX_PRODUCT_SCANNED_NAME_BYTES"),
        ):
            self.assertEqual(
                getattr(compatibility, compatibility_name),
                getattr(planner, planner_name),
            )
        self.assertEqual(
            compatibility.PRODUCT_CURRENT_ROOT_IGNORED_DIRS,
            planner.PRODUCT_CURRENT_ROOT_IGNORED_DIRS,
        )
        self.assertEqual(
            compatibility.PRODUCT_CURRENT_ROOT_IGNORED_FILES,
            planner.PRODUCT_CURRENT_ROOT_IGNORED_FILES,
        )
        self.assertEqual(
            compatibility.PRODUCT_CURRENT_CACHE_DIR_PATHS,
            planner.PRODUCT_CURRENT_CACHE_DIR_PATHS,
        )
        self.assertEqual(
            compatibility._PRODUCT_CURRENT_BACKUP_RE.pattern,
            planner._PRODUCT_CURRENT_BACKUP_RE.pattern,
        )
        layout = _load_module(
            "installed_layout_for_compatibility",
            ROOT / "scripts" / "installed_layout.py",
        )
        self.assertEqual(
            compatibility.EXPECTED_LAYOUT_CONTRACT_ID,
            layout._layout_contract_id(layout.MODE_INACTIVE_VERSIONED),
        )

        source_snapshot = planner._RootSnapshot(self.current)
        try:
            source_id, _ = planner._capture_root_state(
                source_snapshot,
                {"remaining": planner.MAX_TOTAL_MANIFEST_BYTES},
            )
            source_snapshot.recheck()
        finally:
            source_snapshot.close()
        product_snapshot = planner._RootSnapshot(self.current)
        ignored = []
        try:
            records = planner._capture_product_state(
                product_snapshot,
                {"remaining": planner.MAX_PRODUCT_TOTAL_BYTES},
                {"remaining": planner.MAX_PRODUCT_SCANNED_NAME_BYTES},
                True,
                ignored,
            )
            planner._recheck_ignored_entries(product_snapshot, ignored)
            product_snapshot.recheck()
        finally:
            product_snapshot.close()
        identity = planner._product_identity(records)
        self.assertEqual(self.current_observation["source_build_id"], source_id)
        self.assertEqual(
            self.current_observation["product_id"], identity["product_id"]
        )
        self.assertEqual(
            self.current_observation["dependency_component_id"],
            identity["component_ids"]["dependencies"],
        )

    def test_exact_thirteen_surface_digests_match_between_roots(self) -> None:
        self.assertEqual(compatibility.SURFACE_FILES, EXPECTED_SURFACE_FILES)
        current = compatibility._surface_digests(self.current_observation)
        candidate = compatibility._surface_digests(self.candidate_observation)
        self.assertEqual(tuple(sorted(current)), compatibility.COMPATIBILITY_SURFACES)
        self.assertEqual(len(current), 13)
        self.assertEqual(current, candidate)
        self.assertEqual(self.ticket["surface_digests"], current)
        self.assertEqual(
            compatibility._BUNDLE_SIGNING_DOMAIN_V2,
            b"SYNAPSE-S2\x00RELEASE-TRUST-BUNDLE\x00v2\x00",
        )
        self.assertEqual(
            compatibility._ENVELOPE_SIGNING_DOMAIN,
            b"SYNAPSE-S2\x00RELEASE-ENVELOPE\x00v1\x00",
        )
        self.assertEqual(
            compatibility._TICKET_SIGNING_DOMAIN,
            b"SYNAPSE-S2\x00BUILD-COMPATIBILITY-TICKET\x00v1\x00",
        )

    def test_surface_and_dependency_drift_have_specific_tokens(self) -> None:
        (self.candidate / "memory_store.py").write_bytes(b"surface drift\n")
        self.assert_status(self.verify(), "blocked:surface-changed", 3)
        shutil.rmtree(self.candidate)
        shutil.copytree(self.current, self.candidate, ignore=shutil.ignore_patterns(".synapse_s2"))
        (self.candidate / "uv.lock").write_bytes(b"dependency drift\n")
        self.assert_status(self.verify(), "blocked:dependency-changed", 3)

    def test_candidate_tree_anomalies_all_fail_closed(self) -> None:
        expected = {
            "sitecustomize": "unsupported:unexpected-entry",
            "symlink": "unsupported:file-unsafe",
            "hardlink": "unsupported:file-unsafe",
            "fifo": "unsupported:file-unsafe",
            "missing": "unsupported:file-missing",
            "mode": "unsupported:file-unsafe",
        }
        for case, status in expected.items():
            with self.subTest(case=case):
                candidate = self.fresh_candidate("candidate-" + case)
                target = candidate / "README.md"
                if case == "sitecustomize":
                    (candidate / "sitecustomize.py").write_text("raise SystemExit(9)\n")
                elif case == "symlink":
                    target.unlink()
                    target.symlink_to(".gitattributes")
                elif case == "hardlink":
                    target.unlink()
                    os.link(candidate / ".gitattributes", target)
                elif case == "fifo":
                    target.unlink()
                    os.mkfifo(target)
                elif case == "missing":
                    target.unlink()
                else:
                    target.chmod(0o666)
                self.assert_status(
                    self.verify(candidate=candidate), status, 2
                )

    def test_candidate_and_pythonpath_code_never_execute(self) -> None:
        candidate = self.fresh_candidate("candidate-code")
        candidate_canary = self.base / "candidate-canary"
        (candidate / "mcp_server.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(candidate_canary)!r}).write_text('executed')\n"
        )
        self.assert_status(
            self.verify(candidate=candidate), "blocked:surface-changed", 3
        )
        self.assertFalse(candidate_canary.exists())

        codec_lookups = []

        def codec_hook(name):
            codec_lookups.append(name)
            return None

        codecs.register(codec_hook)
        try:
            prefixes = (
                b"# coding: s2_attacker_codec\n",
                b"#!/usr/bin/env python\n# coding=s2_attacker_codec\n",
                b"\xef\xbb\xbf# coding: s2_attacker_codec\n",
                b"\xef\xbb\xbf",
            )
            for index, prefix in enumerate(prefixes):
                codec_candidate = self.fresh_candidate(
                    f"candidate-codec-{index}"
                )
                core = codec_candidate / "core_service.py"
                core.write_bytes(prefix + core.read_bytes())
                self.assert_status(
                    self.verify(candidate=codec_candidate),
                    "unsupported:manifest-missing",
                    2,
                )
        finally:
            codecs.unregister(codec_hook)
        self.assertEqual(codec_lookups, [])

        hostile = self.base / "hostile-pythonpath"
        hostile.mkdir()
        pythonpath_canary = self.base / "pythonpath-canary"
        (hostile / "sitecustomize.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(pythonpath_canary)!r}).write_text('executed')\n"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(hostile)
        process = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(COMPATIBILITY_PATH),
                compatibility.COMMAND_VERIFY_TICKET,
                "--root-file",
                str(self.root_path),
                "--trust-bundle",
                str(self.bundle_path),
                "--envelope",
                str(self.envelope_path),
                "--ticket",
                str(self.ticket_path),
                "--floor",
                str(self.floor_path),
                "--current-root",
                str(self.current),
                "--candidate-root",
                str(self.candidate),
            ],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stdout)
        self.assertEqual(process.stderr, "")
        self.assertEqual(process.stdout.count("\n"), 1)
        self.assertEqual(
            __import__("json").loads(process.stdout)["status"], "verified"
        )
        self.assertFalse(pythonpath_canary.exists())

    def test_floor_clock_lifetime_and_authority_gates(self) -> None:
        alternate = self.documents / "floor-alternate"
        alternate.write_bytes(b"B")
        alternate.chmod(0o600)
        held = self.documents / "floor-held"
        original_capture = compatibility._capture_root_observation
        fired = False

        def aba(*args, **kwargs):
            nonlocal fired
            result = original_capture(*args, **kwargs)
            if not fired:
                fired = True
                os.rename(self.floor_path, held)
                os.rename(alternate, self.floor_path)
                os.rename(self.floor_path, alternate)
                os.rename(held, self.floor_path)
            return result

        with mock.patch.object(
            compatibility, "_capture_root_observation", new=aba
        ):
            self.assert_status(self.verify(), "unsupported:floor-raced", 2)

        with mock.patch.object(
            compatibility, "_now", side_effect=(NOW, NOW - 1)
        ):
            self.assert_status(
                self._invoke(), "unsupported:clock-regression", 2
            )

        cases = (
            (
                {"ticket_overrides": {"issued_at": ISSUED + 9}},
                "blocked:lifetime-outside-envelope",
            ),
            (
                {"envelope_overrides": {"sequence": 4}},
                "blocked:sequence-not-advancing",
            ),
            (
                {"floor_installed_overrides": {"product_id": "product-" + "0" * 64}},
                "blocked:installed-product-mismatch",
            ),
            (
                {
                    "envelope_overrides": {"key_id": self.compatibility_key_id},
                    "envelope_signer": self.compatibility_private,
                },
                "blocked:delegation-role-mismatch",
            ),
            (
                {
                    "ticket_overrides": {"key_id": self.release_key_id},
                    "ticket_signer": self.release_private,
                },
                "blocked:delegation-role-mismatch",
            ),
            (
                {"bundle_overrides": {"revoked_key_ids": [self.compatibility_key_id]}},
                "blocked:key-revoked",
            ),
        )
        for arguments, status in cases:
            with self.subTest(status=status):
                self._install_chain(**arguments)
                self.assert_status(self.verify(), status, 3)

    def test_output_is_deterministic_bounded_and_redacted(self) -> None:
        result = self.verify()
        first = compatibility.render_result(result)
        second = compatibility.render_result(self.verify())
        self.assertEqual(first, second)
        self.assertNotIn("\n", first)
        self.assertLessEqual(
            len(first.encode("utf-8")), compatibility.MAX_RESULT_BYTES
        )
        for secret in (
            str(self.base),
            self.root_public,
            self.release_public,
            self.compatibility_public,
            self.bundle["signature"],
            self.envelope["signature"],
            self.ticket["signature"],
        ):
            self.assertNotIn(secret, first)

    def test_supported_api_makes_no_writes_or_external_calls(self) -> None:
        real_open = os.open
        opened = []

        def read_only_open(path, flags, *args, **kwargs):
            opened.append((str(path), flags))
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            self.assertFalse(flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            return real_open(path, flags, *args, **kwargs)

        before = self.floor_path.read_bytes()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(os, "open", new=read_only_open))
            for name in (
                "write", "mkdir", "makedirs", "rename", "replace",
                "remove", "unlink", "link", "symlink", "truncate",
            ):
                stack.enter_context(
                    mock.patch.object(
                        os, name, side_effect=AssertionError("filesystem write")
                    )
                )
            stack.enter_context(
                mock.patch.object(
                    builtins, "open", side_effect=AssertionError("open write lane")
                )
            )
            stack.enter_context(
                mock.patch.object(socket, "socket", side_effect=AssertionError("network"))
            )
            stack.enter_context(
                mock.patch.object(sqlite3, "connect", side_effect=AssertionError("sqlite"))
            )
            stack.enter_context(
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess"))
            )
            self.assert_status(self.verify(), "verified", 0)
        self.assertEqual(self.floor_path.read_bytes(), before)
        self.assertTrue(opened)
        self.assertFalse(
            any(name in (".synapse_s2", "must-not-be-read") for name, _ in opened)
        )

    def test_all_descriptors_close_on_success_and_failure(self) -> None:
        real_open, real_close = os.open, os.close
        real_read = compatibility._RootSnapshot.read_file_with_stat
        for inject_failure in (False, True):
            with self.subTest(inject_failure=inject_failure):
                outstanding = set()
                calls = 0

                def tracked_open(*args, **kwargs):
                    descriptor = real_open(*args, **kwargs)
                    outstanding.add(descriptor)
                    return descriptor

                def tracked_close(descriptor):
                    try:
                        return real_close(descriptor)
                    finally:
                        outstanding.discard(descriptor)

                def maybe_fail(snapshot, *args, **kwargs):
                    nonlocal calls
                    calls += 1
                    if inject_failure and calls == 2:
                        raise compatibility._Refusal("injected")
                    return real_read(snapshot, *args, **kwargs)

                try:
                    with (
                        mock.patch.object(os, "open", new=tracked_open),
                        mock.patch.object(os, "close", new=tracked_close),
                        mock.patch.object(
                            compatibility._RootSnapshot,
                            "read_file_with_stat",
                            new=maybe_fail,
                        ),
                    ):
                        result = self.verify()
                    leaked = set(outstanding)
                finally:
                    for descriptor in list(outstanding):
                        real_close(descriptor)
                        outstanding.discard(descriptor)
                self.assertEqual(leaked, set())
                expected = "unsupported:injected" if inject_failure else "verified"
                self.assertEqual(result["status"], expected)


class CompatibilitySignerTests(CompatibilityFixture):
    """The offline signer can mint only tickets this verifier can use."""

    def setUp(self) -> None:
        super().setUp()
        self.signing_root = self.base / "signing"
        self.signing_root.mkdir(mode=0o700)
        self._artifact_number = 0
        self.root_key_path = self._write_private_key(
            "root.key", self.root_private
        )
        self.release_key_path = self._write_private_key(
            "release.key", self.release_private
        )
        self.compatibility_key_path = self._write_private_key(
            "compatibility.key", self.compatibility_private
        )
        self.unknown_private = ed25519.Ed25519PrivateKey.generate()
        self.unknown_public = (
            self.unknown_private.public_key().public_bytes_raw().hex()
        )
        self.unknown_key_id = compatibility.key_id_for_public_key(
            self.unknown_public
        )
        self.unknown_key_path = self._write_private_key(
            "unknown.key", self.unknown_private
        )

    @staticmethod
    def _clone(document: dict) -> dict:
        return json.loads(json.dumps(document))

    def _next_name(self, stem: str) -> str:
        self._artifact_number += 1
        return f"{stem}-{self._artifact_number}.json"

    def _write_private_key(self, name: str, key) -> Path:
        path = self.signing_root / name
        path.write_bytes(key.private_bytes_raw())
        path.chmod(0o600)
        return path

    def _unsigned_ticket(self, **overrides) -> dict:
        ticket = self._clone(self.ticket)
        ticket.pop("signature")
        ticket.update(overrides)
        return ticket

    def _signed_bundle_path(self, unsigned: dict, stem="bundle") -> Path:
        domain = (
            compatibility._BUNDLE_SIGNING_DOMAIN_V2
            if unsigned["schema"] == compatibility.BUNDLE_SCHEMA_V2
            else provenance._BUNDLE_SIGNING_DOMAIN
        )
        signed = self._signed(unsigned, self.root_private, domain)
        return self._write_document(self._next_name(stem), signed)

    def _sign_bundle(
        self, unsigned: dict, *, key_path=None, output_path=None
    ) -> tuple[dict, Path]:
        unsigned_path = self._write_document(
            self._next_name("bundle-unsigned"), unsigned
        )
        output_path = output_path or (
            self.signing_root / self._next_name("bundle-signed")
        )
        result = signer.sign_trust_bundle(
            str(key_path or self.root_key_path),
            str(self.root_path),
            str(unsigned_path),
            str(output_path),
            str(self.signing_root),
        )
        return result, output_path

    def _sign_ticket(
        self,
        *,
        overrides=None,
        key_path=None,
        bundle_path=None,
        unsigned=None,
        output_path=None,
        bind_bundle=True,
    ) -> tuple[dict, Path]:
        bundle_path = bundle_path or self.bundle_path
        document = self._clone(unsigned or self._unsigned_ticket())
        if bind_bundle:
            bundle_bytes = bundle_path.read_bytes()
            bundle = compatibility.parse_canonical_document(bundle_bytes)
            document["trust_generation"] = bundle["generation"]
            document["trust_bundle_sha256"] = hashlib.sha256(
                bundle_bytes
            ).hexdigest()
        document.update(overrides or {})
        unsigned_path = self._write_document(
            self._next_name("ticket-unsigned"), document
        )
        output_path = output_path or (
            self.signing_root / self._next_name("ticket-signed")
        )
        result = signer.sign_compatibility_ticket(
            str(key_path or self.compatibility_key_path),
            str(self.root_path),
            str(bundle_path),
            str(unsigned_path),
            str(output_path),
            str(self.signing_root),
        )
        return result, output_path

    def _assert_signer_status(self, result: dict, status: str) -> None:
        self.assertEqual(result["command"], signer.COMMAND_SIGN_TICKET)
        self.assertEqual(result["status"], status)
        self.assertEqual(
            signer.signing_exit_code(result),
            0 if status == signer.STATUS_SIGNED else 2,
        )

    def test_signer_verifier_vocabulary_is_byte_pinned(self) -> None:
        common = {
            "ROOT_SCHEMA": "synapse-s2.release-root.v1",
            "BUNDLE_SCHEMA_V2": "synapse-s2.release-trust-bundle.v2",
            "ENVELOPE_SCHEMA": "synapse-s2.release-envelope.v1",
            "PRODUCT_SCHEMA": "synapse-s2.product-release-plan.v1",
            "DELEGATION_ROLE_RELEASE": "release",
            "DELEGATION_ROLE_COMPATIBILITY": "compatibility-review",
            "_BUNDLE_SIGNING_DOMAIN_V2": (
                b"SYNAPSE-S2\x00RELEASE-TRUST-BUNDLE\x00v2\x00"
            ),
            "_ENVELOPE_SIGNING_DOMAIN": (
                b"SYNAPSE-S2\x00RELEASE-ENVELOPE\x00v1\x00"
            ),
        }
        for module in (signer, provenance, compatibility):
            for name, expected in common.items():
                with self.subTest(module=module.__name__, name=name):
                    self.assertEqual(getattr(module, name), expected)

        ticket_lane = {
            "TICKET_SCHEMA": "synapse-s2.build-compatibility-ticket.v1",
            "_TICKET_SIGNING_DOMAIN": (
                b"SYNAPSE-S2\x00BUILD-COMPATIBILITY-TICKET\x00v1\x00"
            ),
            "COMPATIBILITY_OBSERVATION_SCHEMA": (
                "synapse-s2.compatibility-observation.v1"
            ),
            "LAYOUT_SCHEMA": "synapse-s2.installed-layout-contract.v1",
            "HOST_EVIDENCE_RECEIPT_SCHEMA": (
                "synapse-s2.host-evidence-receipt.v1"
            ),
            "SURFACE_MODE": "exact-build-only",
            "PROFILE_VERSION": 1,
            "HOST_EVIDENCE_POLICY": "required-later",
            "MIGRATION_POLICY": "blocked",
            "DOWNGRADE_POLICY": "blocked",
            "EXPECTED_LAYOUT_CONTRACT_MODE": "inactive-versioned-v1",
            "EXPECTED_LAYOUT_CONTRACT_ID": (
                "layout-contract-"
                "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada"
            ),
        }
        for module in (signer, compatibility):
            for name, expected in ticket_lane.items():
                with self.subTest(module=module.__name__, name=name):
                    self.assertEqual(getattr(module, name), expected)
        self.assertEqual(
            signer.COMPATIBILITY_SURFACES,
            compatibility.COMPATIBILITY_SURFACES,
        )
        self.assertEqual(
            signer.COMPATIBILITY_SURFACES,
            tuple(sorted(EXPECTED_SURFACE_FILES)),
        )
        self.assertEqual(len(signer.COMPATIBILITY_SURFACES), 13)
        self.assertEqual(
            (signer.KEY_SCHEMA, signer.BUNDLE_SCHEMA, provenance.BUNDLE_SCHEMA),
            (
                "synapse-s2.release-key.v1",
                "synapse-s2.release-trust-bundle.v1",
                "synapse-s2.release-trust-bundle.v1",
            ),
        )
        self.assertEqual(
            (
                signer._BUNDLE_SIGNING_DOMAIN,
                provenance._BUNDLE_SIGNING_DOMAIN,
            ),
            (
                b"SYNAPSE-S2\x00RELEASE-TRUST-BUNDLE\x00v1\x00",
                b"SYNAPSE-S2\x00RELEASE-TRUST-BUNDLE\x00v1\x00",
            ),
        )

    def test_compatibility_review_keygen_and_api_cli_end_to_end(self) -> None:
        generated_private = self.signing_root / "generated-compatibility.key"
        generated_public = self.signing_root / "generated-compatibility.json"
        generated = signer.keygen(
            signer.DELEGATION_ROLE_COMPATIBILITY,
            str(generated_private),
            str(generated_public),
            str(self.signing_root),
        )
        self.assertEqual(generated["status"], signer.STATUS_GENERATED)
        self.assertEqual(generated_private.stat().st_mode & 0o777, 0o600)
        public_document = signer.parse_canonical_document(
            generated_public.read_bytes()
        )
        self.assertEqual(
            public_document["role"], signer.DELEGATION_ROLE_COMPATIBILITY
        )

        # Offline means literal offline time handling: the signer must not
        # consult the wall clock while deciding whether to sign.
        with mock.patch.object(
            time, "time", side_effect=AssertionError("clock read")
        ):
            api_result, api_output = self._sign_ticket()
        self._assert_signer_status(api_result, signer.STATUS_SIGNED)
        self.ticket_path = api_output
        self.assert_status(self.verify(), "verified", 0)
        self.assertEqual(len(compatibility.PRODUCT_INVENTORY), 199)

        cli_output = self.signing_root / "ticket-cli.json"
        cli_input = self._write_document(
            "ticket-cli-unsigned.json", self._unsigned_ticket()
        )
        process = subprocess.run(
            [
                sys.executable,
                "-I",
                str(SIGNER_PATH),
                signer.COMMAND_SIGN_TICKET,
                "--private-key",
                str(self.compatibility_key_path),
                "--root-file",
                str(self.root_path),
                "--trust-bundle",
                str(self.bundle_path),
                "--input",
                str(cli_input),
                "--output",
                str(cli_output),
                "--signing-root",
                str(self.signing_root),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stdout)
        self.assertEqual(process.stderr, "")
        self.assertEqual(json.loads(process.stdout)["status"], "signed")
        self.ticket_path = cli_output
        self.assert_status(self.verify(), "verified", 0)

        for index, (full_option, abbreviated) in enumerate(
            (
                ("--trust-bundle", "--trust-b"),
                ("--private-key", "--private-k"),
                ("--root-file", "--root-f"),
                ("--signing-root", "--signing-r"),
            )
        ):
            arguments = [
                signer.COMMAND_SIGN_TICKET,
                "--private-key",
                str(self.compatibility_key_path),
                "--root-file",
                str(self.root_path),
                "--trust-bundle",
                str(self.bundle_path),
                "--input",
                str(cli_input),
                "--output",
                str(self.signing_root / f"abbreviated-{index}.json"),
                "--signing-root",
                str(self.signing_root),
            ]
            arguments[arguments.index(full_option)] = abbreviated
            refused = subprocess.run(
                [sys.executable, "-I", str(SIGNER_PATH), *arguments],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(refused.returncode, 2, refused.stdout)
            self.assertEqual(refused.stderr, "")
            self.assertEqual(refused.stdout.count("\n"), 1)
            self.assertEqual(
                json.loads(refused.stdout)["status"],
                "unsupported:invalid-arguments",
            )

    def test_exact_layout_and_v2_revoked_delegation_are_refused(self) -> None:
        result, output = self._sign_ticket(
            overrides={"layout_contract_id": "layout-contract-" + "0" * 64}
        )
        self._assert_signer_status(result, "unsupported:ticket-invalid")
        self.assertFalse(output.exists())

        # Keep both live role sets while adding a third delegated key that
        # is also revoked.  This specifically proves full delegation /
        # revocation disjointness, not merely that each role has a survivor.
        unsigned = self._clone(self.bundle)
        unsigned.pop("signature")
        extra = self._delegation(
            compatibility.DELEGATION_ROLE_COMPATIBILITY
        )
        extra["key_id"] = self.unknown_key_id
        extra["public_key"] = self.unknown_public
        unsigned["delegations"].append(extra)
        unsigned["revoked_key_ids"] = [self.unknown_key_id]
        unsigned_path = self._write_document(
            "revoked-delegate-v2.json", unsigned
        )
        bundle_output = self.signing_root / "revoked-delegate-v2.json"
        result = signer.sign_trust_bundle(
            str(self.root_key_path),
            str(self.root_path),
            str(unsigned_path),
            str(bundle_output),
            str(self.signing_root),
        )
        self.assertEqual(result["status"], "unsupported:bundle-invalid")
        self.assertFalse(bundle_output.exists())

    def test_v2_bundle_roles_domain_and_role_separation(self) -> None:
        unsigned = self._clone(self.bundle)
        unsigned.pop("signature")
        result, output = self._sign_bundle(unsigned)
        self.assertEqual(result["status"], signer.STATUS_SIGNED)
        signed = signer.parse_canonical_document(output.read_bytes())
        payload = (
            signer._BUNDLE_SIGNING_DOMAIN_V2
            + signer.canonical_bytes(unsigned)
        )
        root_public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(self.root_public)
        )
        root_public_key.verify(bytes.fromhex(signed["signature"]), payload)
        with self.assertRaises(InvalidSignature):
            root_public_key.verify(
                bytes.fromhex(signed["signature"]),
                signer._BUNDLE_SIGNING_DOMAIN
                + signer.canonical_bytes(unsigned),
            )

        invalid = []
        duplicate = self._clone(unsigned)
        duplicate["delegations"].append(
            self._clone(duplicate["delegations"][0])
        )
        invalid.append((duplicate, self.root_key_path, "bundle-invalid"))
        delegated_root = self._clone(unsigned)
        delegated_root["delegations"][0].update(
            {"key_id": self.root_key_id, "public_key": self.root_public}
        )
        invalid.append(
            (delegated_root, self.root_key_path, "bundle-root-delegated")
        )
        wrong_role = self._clone(unsigned)
        wrong_role["delegations"][0]["role"] = "operator"
        invalid.append((wrong_role, self.root_key_path, "bundle-invalid"))
        missing_role = self._clone(unsigned)
        missing_role["delegations"] = [
            delegation
            for delegation in missing_role["delegations"]
            if delegation["role"] == signer.DELEGATION_ROLE_RELEASE
        ]
        invalid.append((missing_role, self.root_key_path, "bundle-invalid"))
        invalid.append((unsigned, self.release_key_path, "key-role-mismatch"))
        for document, key_path, token in invalid:
            with self.subTest(token=token):
                refused, refused_output = self._sign_bundle(
                    document, key_path=key_path
                )
                self.assertEqual(refused["status"], "unsupported:" + token)
                self.assertFalse(refused_output.exists())

    def test_root_and_release_keys_cannot_sign_tickets(self) -> None:
        cases = (
            (
                self.root_key_path,
                self.root_key_id,
                "unsupported:key-role-mismatch",
            ),
            (
                self.release_key_path,
                self.release_key_id,
                "unsupported:delegation-role-mismatch",
            ),
        )
        for key_path, key_id, expected in cases:
            with self.subTest(status=expected):
                result, output = self._sign_ticket(
                    key_path=key_path,
                    overrides={"key_id": key_id},
                )
                self._assert_signer_status(result, expected)
                self.assertFalse(output.exists())

    def test_revoked_unknown_and_mismatched_ticket_keys_are_refused(self) -> None:
        revoked_bundle = self._clone(self.bundle)
        revoked_bundle.pop("signature")
        revoked_bundle["revoked_key_ids"] = [self.unknown_key_id]
        revoked_bundle_path = self._signed_bundle_path(
            revoked_bundle, "revoked-unknown-bundle"
        )
        cases = (
            (
                self.unknown_key_path,
                self.unknown_key_id,
                revoked_bundle_path,
                "unsupported:key-revoked",
            ),
            (
                self.unknown_key_path,
                self.unknown_key_id,
                self.bundle_path,
                "unsupported:delegation-unknown",
            ),
            (
                self.unknown_key_path,
                self.compatibility_key_id,
                self.bundle_path,
                "unsupported:ticket-key-mismatch",
            ),
        )
        for key_path, key_id, bundle_path, expected in cases:
            with self.subTest(status=expected):
                result, output = self._sign_ticket(
                    key_path=key_path,
                    bundle_path=bundle_path,
                    overrides={"key_id": key_id},
                )
                self._assert_signer_status(result, expected)
                self.assertFalse(output.exists())

    def test_ticket_bundle_grant_and_closed_schema_failures(self) -> None:
        ordinary_cases = (
            (
                {"trust_generation": self.bundle["generation"] + 1},
                "trust-generation-mismatch",
            ),
            ({"trust_bundle_sha256": "0" * 64}, "ticket-bundle-mismatch"),
            ({"channel": "beta"}, "channel-not-delegated"),
            ({"sequence": 101}, "sequence-outside-delegation"),
            (
                {"issued_at": ISSUED - 1},
                "delegation-window",
            ),
        )
        for overrides, token in ordinary_cases:
            with self.subTest(token=token):
                result, output = self._sign_ticket(overrides=overrides)
                self._assert_signer_status(result, "unsupported:" + token)
                self.assertFalse(output.exists())

        narrowed_bundle = self._clone(self.bundle)
        narrowed_bundle.pop("signature")
        narrowed_bundle["issued_at"] = ISSUED + 15
        narrowed_bundle_path = self._signed_bundle_path(
            narrowed_bundle, "narrowed-bundle"
        )
        result, output = self._sign_ticket(
            bundle_path=narrowed_bundle_path,
            overrides={"issued_at": ISSUED + 10},
        )
        self._assert_signer_status(
            result, "unsupported:lifetime-outside-trust"
        )
        self.assertFalse(output.exists())

        unequal_dependency = self._unsigned_ticket(
            candidate_dependency_component_id="component-" + "0" * 64
        )
        missing_surface = self._unsigned_ticket()
        missing_surface["surface_digests"].pop(
            signer.COMPATIBILITY_SURFACES[0]
        )
        already_signed = self._clone(self.ticket)
        for document in (unequal_dependency, missing_surface):
            with self.subTest(closed_schema=sorted(document)):
                result, output = self._sign_ticket(unsigned=document)
                self._assert_signer_status(
                    result, "unsupported:ticket-invalid"
                )
                self.assertFalse(output.exists())
        result, output = self._sign_ticket(unsigned=already_signed)
        self._assert_signer_status(
            result, "unsupported:document-already-signed"
        )
        self.assertFalse(output.exists())

        v1_bundle = self._clone(self.bundle)
        v1_bundle.pop("signature")
        v1_bundle["schema"] = provenance.BUNDLE_SCHEMA
        v1_bundle["delegations"] = [
            delegation
            for delegation in v1_bundle["delegations"]
            if delegation["role"] == provenance.DELEGATION_ROLE_RELEASE
        ]
        v1_path = self._signed_bundle_path(v1_bundle, "v1-bundle")
        result, output = self._sign_ticket(bundle_path=v1_path)
        self._assert_signer_status(
            result, "unsupported:document-type-mismatch"
        )
        self.assertFalse(output.exists())

        tampered_bundle = self._clone(self.bundle)
        tampered_bundle["generation"] += 1
        tampered_bundle_path = self._write_document(
            "tampered-bundle.json", tampered_bundle
        )
        result, output = self._sign_ticket(bundle_path=tampered_bundle_path)
        self._assert_signer_status(
            result, "unsupported:bundle-signature-invalid"
        )
        self.assertFalse(output.exists())

    def test_phase_a_cross_binds_envelope_surfaces_and_dependencies(self) -> None:
        cases = []
        wrong_envelope = {"envelope_sha256": "0" * 64}
        cases.append((wrong_envelope, "blocked:ticket-envelope-mismatch"))

        surface_digests = self._clone(self.ticket["surface_digests"])
        surface_digests[signer.COMPATIBILITY_SURFACES[0]] = "0" * 64
        cases.append(
            ({"surface_digests": surface_digests}, "blocked:surface-mismatch")
        )
        cases.append(
            ({"surfaces_digest": "0" * 64}, "blocked:surfaces-digest-mismatch")
        )
        wrong_dependency = "component-" + "0" * 64
        cases.append(
            (
                {
                    "current_dependency_component_id": wrong_dependency,
                    "candidate_dependency_component_id": wrong_dependency,
                },
                "blocked:dependency-mismatch",
            )
        )
        for overrides, expected in cases:
            with self.subTest(status=expected):
                result, output = self._sign_ticket(overrides=overrides)
                self._assert_signer_status(result, signer.STATUS_SIGNED)
                self.ticket_path = output
                self.assert_status(self.verify(), expected, 3)

        result, output = self._sign_ticket()
        self._assert_signer_status(result, signer.STATUS_SIGNED)
        tampered = signer.parse_canonical_document(output.read_bytes())
        tampered["issued_at"] += 1
        self.ticket_path = self._write_document(
            "ticket-tampered-after-signing.json", tampered
        )
        self.assert_status(
            self.verify(), "blocked:ticket-signature-invalid", 3
        )

    def test_ticket_publish_is_exclusive_atomic_honest_and_redacted(self) -> None:
        occupied = self.signing_root / "occupied-ticket.json"
        occupied.write_bytes(b"sentinel")
        occupied.chmod(0o644)
        result, output = self._sign_ticket(output_path=occupied)
        self._assert_signer_status(result, "unsupported:output-exists")
        self.assertEqual(output, occupied)
        self.assertEqual(occupied.read_bytes(), b"sentinel")

        entries_before = sorted(path.name for path in self.signing_root.iterdir())
        with mock.patch.object(signer.os, "write", return_value=0):
            result, output = self._sign_ticket()
        self._assert_signer_status(
            result, "unsupported:output-write-failed"
        )
        self.assertFalse(output.exists())
        self.assertEqual(
            sorted(path.name for path in self.signing_root.iterdir()),
            entries_before,
        )
        self.assertFalse(
            [path for path in self.signing_root.iterdir() if ".tmp-" in path.name]
        )

        real_fsync = os.fsync
        fsync_calls = []

        def fail_directory_fsync(descriptor):
            fsync_calls.append(descriptor)
            if len(fsync_calls) == 2:
                raise OSError(5, "injected")
            return real_fsync(descriptor)

        with mock.patch.object(signer.os, "fsync", new=fail_directory_fsync):
            result, output = self._sign_ticket()
        self._assert_signer_status(
            result, "outcome_unknown:output-publish"
        )
        published = signer.parse_canonical_document(output.read_bytes())
        self.assertIn("signature", published)
        self.assertFalse(
            [path for path in self.signing_root.iterdir() if ".tmp-" in path.name]
        )

        refused, refused_output = self._sign_ticket(
            key_path=self.unknown_key_path,
            overrides={"key_id": self.compatibility_key_id},
        )
        self._assert_signer_status(
            refused, "unsupported:ticket-key-mismatch"
        )
        self.assertFalse(refused_output.exists())
        rendered = signer.render_result(refused)
        self.assertNotIn("\n", rendered)
        self.assertLessEqual(
            len(rendered.encode("utf-8")), signer.MAX_RESULT_BYTES
        )
        for secret in (
            str(self.base),
            self.unknown_key_path.read_bytes().hex(),
            self.root_public,
            self.release_public,
            self.compatibility_public,
            self.bundle["signature"],
            self.ticket["signature"],
        ):
            self.assertNotIn(secret, rendered)


class PlatformGateTests(unittest.TestCase):
    def _assert_pre_io_platform_refusal(self, module) -> None:
        with (
            mock.patch.object(module, "_validate_static_vocabulary") as vocabulary,
            mock.patch.object(module, "_validate_path_argument") as operand,
            mock.patch.object(module, "_read_safe_document") as document_io,
            mock.patch.object(module, "_HeldFloorDocument") as floor_io,
            mock.patch.object(module, "_RootSnapshot") as root_io,
            mock.patch.object(module.os, "open") as os_open,
        ):
            result = module.verify_compatibility_ticket(*(["relative"] * 7))
        self.assertEqual(result["status"], "unsupported:platform-unsupported")
        for blocked_call in (
            vocabulary, operand, document_io, floor_io, root_io, os_open
        ):
            blocked_call.assert_not_called()

    def test_missing_and_noncallable_pread_fail_before_operand_io(self) -> None:
        original = os.pread
        del os.pread
        try:
            missing = _load_module(
                "release_compatibility_missing_pread", COMPATIBILITY_PATH
            )
        finally:
            os.pread = original
        self.assertFalse(missing._PLATFORM_SUPPORTED)
        self._assert_pre_io_platform_refusal(missing)
        with mock.patch.object(os, "pread", None):
            noncallable = _load_module(
                "release_compatibility_noncallable_pread", COMPATIBILITY_PATH
            )
        self.assertFalse(noncallable._PLATFORM_SUPPORTED)
        self._assert_pre_io_platform_refusal(noncallable)

    def test_follow_symlink_stat_capability_fails_before_operand_io(self) -> None:
        capabilities = set(os.supports_follow_symlinks)
        capabilities.discard(os.stat)
        with mock.patch.object(os, "supports_follow_symlinks", capabilities):
            module = _load_module(
                "release_compatibility_no_follow_stat", COMPATIBILITY_PATH
            )
        self.assertFalse(module._PLATFORM_SUPPORTED)
        self._assert_pre_io_platform_refusal(module)


class ModuleHygieneTests(unittest.TestCase):
    def test_api_import_restores_process_state(self) -> None:
        path_before = list(sys.path)
        bytecode_before = sys.dont_write_bytecode
        fresh = _load_module("release_compatibility_hygiene", COMPATIBILITY_PATH)
        self.assertEqual(sys.path, path_before)
        self.assertEqual(sys.dont_write_bytecode, bytecode_before)
        self.assertEqual(fresh._ORIGINAL_SYS_PATH, path_before)
        self.assertEqual(fresh._ORIGINAL_DONT_WRITE_BYTECODE, bytecode_before)


if __name__ == "__main__":
    unittest.main()

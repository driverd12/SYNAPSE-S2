from __future__ import annotations

import io
import json
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]

from scripts import core_cutover_preflight as preflight
from operator_readiness_contract import (
    OPERATOR_READINESS_REQUIRED_PROOF_IDS,
    quiescence_policy_contract,
    quiescence_policy_digest,
    ready_operator_proof_contract,
)


class CoreCutoverPreflightFiniteTests(unittest.TestCase):
    @staticmethod
    def _memora_audit(*, promoted: int = 0) -> dict[str, object]:
        return {
            "schema": "synapse-s2.memora-recovery-audit.v1",
            "audit_revision": "9" * 64,
            "catalog_count": promoted,
            "binding_projection_count": promoted,
            "governance_event_receipt_count": promoted * 2,
            "source_witness_count": promoted * 4,
            "cue_count": promoted * 2,
            "promoted_binding_count": promoted,
            "effective_binding_count": promoted,
            "ineffective_promoted_binding_count": 0,
            "provider_drift_binding_count": 0,
            "source_drift_binding_count": 0,
            "active_provider_revision": "8" * 64 if promoted else "absent",
            "integrity_valid": True,
            "effective_bindings_valid": True,
            "raw_cue_terms_included": False,
            "raw_source_text_included": False,
            "vectors_included": False,
        }

    @staticmethod
    def _media_summary(*, bundle_schema: str, restore_schema: str, references: int = 0):
        included = references > 0
        return {
            "recovery_bundle_schema": bundle_schema,
            "recovery_restore_schema": restore_schema,
            "media_included": included,
            "media_recovery_complete": True,
            "media_sha256": "1" * 64 if included else None,
            "media_manifest_sha256": "2" * 64 if included else None,
            "media_object_count": references,
            "media_reference_count": references,
        }

    def test_media_summary_accepts_zero_v1_v2_v3_and_referenced_v3(self) -> None:
        for bundle_schema, restore_schema in (
            (
                preflight.LEGACY_RECOVERY_BUNDLE_SCHEMA,
                preflight.LEGACY_RECOVERY_BUNDLE_RESTORE_SCHEMA,
            ),
            (
                preflight.PRIOR_RECOVERY_BUNDLE_SCHEMA,
                preflight.PRIOR_RECOVERY_BUNDLE_RESTORE_SCHEMA,
            ),
            (
                preflight.RECOVERY_BUNDLE_SCHEMA,
                preflight.RECOVERY_BUNDLE_RESTORE_SCHEMA,
            ),
        ):
            summary = self._media_summary(
                bundle_schema=bundle_schema,
                restore_schema=restore_schema,
            )
            self.assertEqual(
                preflight._validate_media_recovery_summary(summary),
                summary,
            )
        referenced = self._media_summary(
            bundle_schema=preflight.RECOVERY_BUNDLE_SCHEMA,
            restore_schema=preflight.RECOVERY_BUNDLE_RESTORE_SCHEMA,
            references=2,
        )
        self.assertEqual(
            preflight._validate_media_recovery_summary(referenced),
            referenced,
        )

    def test_media_summary_refuses_omission_mismatch_and_legacy_references(self) -> None:
        current = self._media_summary(
            bundle_schema=preflight.RECOVERY_BUNDLE_SCHEMA,
            restore_schema=preflight.RECOVERY_BUNDLE_RESTORE_SCHEMA,
            references=2,
        )
        mutations = (
            lambda value: value.pop("media_recovery_complete"),
            lambda value: value.__setitem__(
                "recovery_restore_schema",
                preflight.PRIOR_RECOVERY_BUNDLE_RESTORE_SCHEMA,
            ),
            lambda value: value.__setitem__("media_object_count", 1),
        )
        for mutate in mutations:
            changed = dict(current)
            mutate(changed)
            with self.assertRaises(preflight.CutoverPreflightError):
                preflight._validate_media_recovery_summary(changed)
        legacy = self._media_summary(
            bundle_schema=preflight.LEGACY_RECOVERY_BUNDLE_SCHEMA,
            restore_schema=preflight.LEGACY_RECOVERY_BUNDLE_RESTORE_SCHEMA,
            references=1,
        )
        with self.assertRaisesRegex(
            preflight.CutoverPreflightError,
            "legacy",
        ):
            preflight._validate_media_recovery_summary(legacy)

    def test_media_artifact_binding_rejects_old_or_tampered_restore_proof(self) -> None:
        summary = self._media_summary(
            bundle_schema=preflight.RECOVERY_BUNDLE_SCHEMA,
            restore_schema=preflight.RECOVERY_BUNDLE_RESTORE_SCHEMA,
            references=1,
        )
        parsed = {
            "media_included": True,
            "media_recovery_complete": True,
            "media_reference_count": 1,
            "media": {
                "sha256": "1" * 64,
                "manifest_sha256": "2" * 64,
                "object_count": 1,
                "referenced_count": 1,
                "verified": True,
            },
        }
        proof = {
            "schema": preflight.RECOVERY_BUNDLE_RESTORE_SCHEMA,
            "media_included": True,
            "media_recovery_complete": True,
            "media_reference_count": 1,
            "media_sha256": "1" * 64,
            "media_manifest_sha256": "2" * 64,
            "media_object_count": 1,
        }
        preflight._validate_recovery_media_artifact_binding(
            summary=summary,
            parsed=parsed,
            restore_proof=proof,
        )
        for changed in (
            {key: value for key, value in proof.items() if key != "media_sha256"},
            {**proof, "media_sha256": "f" * 64},
        ):
            with self.assertRaises(preflight.CutoverPreflightError):
                preflight._validate_recovery_media_artifact_binding(
                    summary=summary,
                    parsed=parsed,
                    restore_proof=changed,
                )

    def test_memora_summary_rejects_omission_tamper_and_provider_drift(self) -> None:
        audit = self._memora_audit(promoted=1)
        self.assertEqual(
            preflight._validate_memora_recovery_summary(audit),
            audit,
        )
        invalid = (
            None,
            {key: value for key, value in audit.items() if key != "audit_revision"},
            {
                **audit,
                "effective_binding_count": 0,
                "ineffective_promoted_binding_count": 1,
                "provider_drift_binding_count": 1,
                "effective_bindings_valid": False,
            },
        )
        for value in invalid:
            with self.assertRaises(preflight.CutoverPreflightError):
                preflight._validate_memora_recovery_summary(value)

    def test_cli_rejects_non_finite_maximum_evidence_age_with_json_failure(self) -> None:
        for value in ("nan", "inf", "-inf"):
            with self.subTest(value=value):
                output = io.StringIO()
                with redirect_stdout(output):
                    status = preflight.main(
                        [f"--maximum-evidence-age-seconds={value}", "--inventory-only"]
                    )
                self.assertEqual(status, 1)
                payload = json.loads(output.getvalue())
                self.assertEqual(
                    payload,
                    {"ready": False, "error": "evidence maximum age is invalid"},
                )
                self.assertNotIn(value, output.getvalue().lower())

    def test_direct_calls_reject_non_finite_or_unbounded_maximum_age(self) -> None:
        missing = Path("/private/tmp/synapse-preflight-not-opened.json")
        for value in (
            float("nan"),
            float("inf"),
            float("-inf"),
            0.0,
            preflight.MAXIMUM_EVIDENCE_AGE_SECONDS + 1.0,
        ):
            with self.subTest(value=value), self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "^evidence maximum age is invalid$",
            ):
                preflight.validate_evidence_contract(
                    missing,
                    root=ROOT,
                    maximum_age_seconds=value,
                    require_git_binding=False,
                )

            with self.subTest(run_preflight=value), self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "^evidence maximum age is invalid$",
            ):
                preflight.run_preflight(
                    root=ROOT,
                    memory_db=missing,
                    capture_root=missing.parent,
                    evidence_manifest=None,
                    maximum_evidence_age_seconds=value,
                    require_quiescent=False,
                    inventory_only=True,
                    launchctl_bin="/bin/false",
                    ps_bin="/bin/false",
                )

    def test_manifest_created_at_nan_is_rejected_as_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="synapse-preflight-nonfinite-manifest-"
        ) as temporary:
            manifest = Path(temporary).resolve() / "manifest.json"
            for value in ("NaN", "Infinity", "-Infinity", "1e309"):
                with self.subTest(value=value):
                    manifest.write_text(
                        f'{{"created_at":{value},"operator_trustworthy":true,'
                        '"overall_status":"ready"}',
                        encoding="utf-8",
                    )
                    manifest.chmod(0o600)
                    with self.assertRaisesRegex(
                        preflight.CutoverPreflightError,
                        "^evidence manifest is not valid JSON$",
                    ):
                        preflight.validate_evidence_contract(
                            manifest,
                            root=ROOT,
                            maximum_age_seconds=7200.0,
                            require_git_binding=False,
                        )

    def test_verification_verified_at_nan_is_rejected_as_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="synapse-preflight-nonfinite-verification-"
        ) as temporary:
            pack = Path(temporary).resolve() / "pack"
            artifacts = pack / "artifacts"
            artifacts.mkdir(parents=True)
            parsed = artifacts / "recovery_verify.parsed.json"
            parsed.write_text(
                '{"verified":true,"verified_at":NaN}',
                encoding="utf-8",
            )
            parsed.chmod(0o600)
            reconciliation = {
                "missing_authoritative_ledger_count": 0,
                "replay_required_capture_count": 0,
                "replay_required_file_count": 0,
                "identifierless_replay_file_count": 0,
                "unclassified_file_count": 0,
            }
            metrics = {
                "verified": True,
                "cutover_ready": True,
                "capture_ledger_binding": {"verified": True},
                "reconciliation": reconciliation,
                "recovery_bundle_schema": preflight.RECOVERY_BUNDLE_SCHEMA,
                "recovery_restore_schema": (
                    preflight.RECOVERY_BUNDLE_RESTORE_SCHEMA
                ),
                "media_included": False,
                "media_recovery_complete": True,
                "media_sha256": None,
                "media_manifest_sha256": None,
                "media_object_count": 0,
                "media_reference_count": 0,
                "memora_integrity": self._memora_audit(),
            }
            recovery_checks = {
                check_id: {
                    "check_id": check_id,
                    "required": True,
                    "status": "ready",
                    "metrics": metrics,
                    "artifact_paths": (
                        {"parsed": str(parsed)}
                        if check_id == "recovery_verify"
                        else {}
                    ),
                }
                for check_id in (
                    "recovery_backup",
                    "recovery_verify",
                    "recovery_restore",
                )
            }
            config_fingerprint = "f" * 64
            build_id = preflight._manifest_build_id(ROOT)
            checks = [
                recovery_checks.get(
                    check_id,
                    {
                        "check_id": check_id,
                        "required": True,
                        "status": "ready",
                        "metrics": (
                            {
                                "schema": preflight.RUNTIME_BUILD_IDENTITY_SCHEMA,
                                "proof_mode": "candidate-local-source",
                                "authority_mode": "candidate-local-v5",
                                "expected_source_build_id": build_id,
                                "observed_runtime_build_id": build_id,
                                "expected_config_fingerprint": config_fingerprint,
                                "observed_config_fingerprint": config_fingerprint,
                                "matched": True,
                            }
                            if check_id == "runtime_build_identity"
                            else {}
                        ),
                        "artifact_paths": {},
                    },
                )
                for check_id in OPERATOR_READINESS_REQUIRED_PROOF_IDS
            ]
            proofs = {str(check["check_id"]): check for check in checks}
            manifest = pack / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "overall_status": "ready",
                        "operator_trustworthy": True,
                        "created_at": time.time(),
                        "git": {"head": "0" * 40, "status_short": ""},
                        "expected_source_build_id": build_id,
                        "core_config_contract": {},
                        "authority_route": {
                            "mode": "candidate-local-v5",
                            "candidate_config_fingerprint": config_fingerprint,
                        },
                        "quiescence_policy_contract": quiescence_policy_contract(),
                        "quiescence_policy_digest": quiescence_policy_digest(),
                        "required_total": len(OPERATOR_READINESS_REQUIRED_PROOF_IDS),
                        "required_ready": len(OPERATOR_READINESS_REQUIRED_PROOF_IDS),
                        "failed_required": [],
                        "required_proof_contract": ready_operator_proof_contract(),
                        "checks": checks,
                        "proofs": proofs,
                    }
                ),
                encoding="utf-8",
            )
            manifest.chmod(0o600)
            with mock.patch.object(
                preflight,
                "validate_core_config_evidence_contract",
                return_value={"config_fingerprint": config_fingerprint},
            ), self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "^recovery verification artifact is not valid JSON$",
            ):
                preflight.validate_evidence_contract(
                    manifest,
                    root=ROOT,
                    maximum_age_seconds=7200.0,
                    require_git_binding=False,
                )

    def test_main_converts_unexpected_failure_to_content_free_json(self) -> None:
        canary = "sensitive-malformed-evidence-canary"
        output = io.StringIO()
        with mock.patch.object(
            preflight,
            "run_preflight",
            side_effect=ValueError(canary),
        ), redirect_stdout(output):
            status = preflight.main([])
        self.assertEqual(status, 1)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"ready": False, "error": "cutover preflight failed safely"},
        )
        self.assertNotIn(canary, output.getvalue())


if __name__ == "__main__":
    unittest.main()

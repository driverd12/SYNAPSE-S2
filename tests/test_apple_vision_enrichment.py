from __future__ import annotations

import base64
import json
import os
import stat
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from apple_vision_enrichment import (
    AppleVisionEnricher,
    AppleVisionError,
    ocr_cue_text,
    privatize_vision_enrichment,
    validate_vision_enrichment,
)
from core_client_binding import CoreClientBinding


def _raw_enrichment() -> dict:
    feature = struct.pack("<4f", 0.25, -0.5, 1.0, 0.0)
    return {
        "schema": "synapse-s2.apple-vision-enrichment.v1",
        "provider": "apple-vision",
        "mode": "all",
        "status": "ready",
        "input_derivative": "source-transient-downsampled",
        "input_dimensions": {"width": 128, "height": 64},
        "feature_print": {
            "status": "ready",
            "schema": "synapse-s2.apple-vision-feature-print.v1",
            "request_revision": 2,
            "element_type": "float32",
            "element_count": 4,
            "encoding": "base64-little-endian",
            "data": base64.b64encode(feature).decode("ascii"),
        },
        "ocr": {
            "status": "ready",
            "schema": "synapse-s2.apple-vision-ocr.v1",
            "request_revision": 3,
            "recognition_level": "accurate",
            "language_correction": True,
            "automatic_language_detection": True,
            "observation_count": 2,
            "mean_confidence": 0.875,
            "text": "Rack 42\napi_key=sk-synthetic1234567890",
            "truncated": False,
        },
    }


class AppleVisionEnrichmentTests(unittest.TestCase):
    def test_private_projection_redacts_ocr_and_removes_feature_vector(self) -> None:
        projected, feature = privatize_vision_enrichment(_raw_enrichment())

        self.assertEqual(feature, struct.pack("<4f", 0.25, -0.5, 1.0, 0.0))
        self.assertNotIn("data", projected["feature_print"])
        self.assertEqual(projected["feature_print"]["byte_count"], 16)
        self.assertNotIn("sk-synthetic", projected["ocr"]["text"])
        self.assertGreater(projected["ocr"]["redaction_count"], 0)
        self.assertIn("Rack 42", ocr_cue_text(projected))

    def test_nonfinite_and_wrong_shape_feature_values_fail_closed(self) -> None:
        invalid = _raw_enrichment()
        invalid["feature_print"]["data"] = base64.b64encode(
            struct.pack("<4f", 0.0, float("nan"), 1.0, 2.0)
        ).decode("ascii")
        with self.assertRaisesRegex(AppleVisionError, "values"):
            validate_vision_enrichment(invalid)

        invalid = _raw_enrichment()
        invalid["feature_print"]["element_count"] = 5
        with self.assertRaisesRegex(AppleVisionError, "shape"):
            validate_vision_enrichment(invalid)

    def test_unknown_fields_and_inconsistent_status_fail_closed(self) -> None:
        invalid = _raw_enrichment()
        invalid["unexpected"] = "value"
        with self.assertRaisesRegex(AppleVisionError, "contract"):
            validate_vision_enrichment(invalid)

        invalid = _raw_enrichment()
        invalid["status"] = "partial"
        with self.assertRaisesRegex(AppleVisionError, "inconsistent"):
            validate_vision_enrichment(invalid)

    def test_ocr_is_redacted_before_output_truncation(self) -> None:
        enrichment = _raw_enrichment()
        enrichment["ocr"]["text"] = "A" * 8_185 + " sk-12345678901234567890"

        projected, _feature = privatize_vision_enrichment(enrichment)

        self.assertNotIn("sk-123", projected["ocr"]["text"])
        self.assertGreater(projected["ocr"]["redaction_count"], 0)
        self.assertTrue(projected["ocr"]["truncated"])

    def test_helper_build_compiles_private_digest_bound_source_copy(self) -> None:
        private_tmp = Path("/private/tmp")
        with tempfile.TemporaryDirectory(
            prefix="s2-vision-build-test-",
            dir=str(private_tmp) if private_tmp.is_dir() else None,
        ) as name:
            root = Path(name)
            data_root = root / ".synapse_s2"
            core_root = data_root / "core"
            core_root.mkdir(parents=True, mode=0o700)
            data_root.chmod(0o700)
            core_root.chmod(0o700)
            source = root / "helper.swift"
            source.write_text("// synthetic helper source\n", encoding="utf-8")
            binding = CoreClientBinding(
                repo_root=root,
                data_root=data_root,
                config_path=core_root / "service.json",
                socket_path=core_root / "service.sock",
                state_path=data_root / "runtime_state.json",
                memory_path=data_root / "memory.sqlite3",
                capture_root=data_root,
                export_root=data_root / "exports",
                backup_root=data_root / "backups",
                recovery_root=data_root / "recovery",
                replication_inbox_root=data_root / "replication" / "inbox",
                core_label="vision-test-core",
                config_digest="a" * 64,
                config_fingerprint="b" * 64,
                embedding_space_identity="c" * 64,
                layout="canonical",
                authority_mode="authoritative-core-v6",
            )
            compiled_sources: list[Path] = []

            def runner(arguments, **_kwargs):
                if "swiftc" in arguments:
                    copied = Path(arguments[arguments.index("-o") - 1])
                    compiled_sources.append(copied)
                    self.assertNotEqual(copied, source)
                    self.assertEqual(copied.read_bytes(), source.read_bytes())
                    self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o600)
                    output = Path(arguments[arguments.index("-o") + 1])
                    output.write_bytes(b"\xcf\xfa\xed\xfe" + b"x" * 64)
                    return subprocess.CompletedProcess(arguments, 0, b"", b"")
                payload = _raw_enrichment()
                payload["schema"] = "synapse-s2.apple-vision-helper-result.v1"
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    (json.dumps(payload) + "\n").encode("utf-8"),
                    b"",
                )

            enricher = AppleVisionEnricher(
                binding,
                helper_source=source,
                command_runner=runner,
            )
            input_path = root / "input.jpg"
            input_path.write_bytes(b"\xff\xd8\xffsynthetic")
            input_path.chmod(0o600)
            result = enricher.enrich(
                input_path,
                "all",
                "source-transient-downsampled",
            )

            self.assertEqual(result["status"], "ready")
            self.assertEqual(len(compiled_sources), 1)
            helper = next((data_root / "vision-helper").glob("*/helper"))
            self.assertEqual(stat.S_IMODE(helper.stat().st_mode), 0o700)

            cache_root = helper.parent
            helper.unlink()
            (cache_root / "manifest.json").unlink()
            self.assertEqual(list(cache_root.iterdir()), [])
            rebuilt = enricher.enrich(
                input_path,
                "all",
                "source-transient-downsampled",
            )
            self.assertEqual(rebuilt["status"], "ready")
            self.assertEqual(len(compiled_sources), 2)


if __name__ == "__main__":
    unittest.main()

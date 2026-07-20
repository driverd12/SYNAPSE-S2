from __future__ import annotations

import json
import io
import logging
import unittest

from redaction import (
    REDACTED_SECRET,
    SecretRedactingFormatter,
    is_sensitive_key,
    redact_capture_text,
    redact_sensitive_value,
    reject_sensitive_identifier,
    safe_public_error,
    strip_untrusted_raw_digest_fields,
    strip_untrusted_raw_digest_text,
)


SYNTHETIC_MARKER = "SYNTHETIC_ONLY_SECRET_VALUE_42"


class RedactionTests(unittest.TestCase):
    def test_common_secret_text_forms_are_redacted(self):
        samples = (
            f"OPENAI_API_KEY={SYNTHETIC_MARKER}",
            f'{{"clientSecret":"{SYNTHETIC_MARKER}"}}',
            f"Authorization: Bearer {SYNTHETIC_MARKER}",
            f"Authorization: ApiKey {SYNTHETIC_MARKER}",
            f"Cookie: session={SYNTHETIC_MARKER}",
            f"//registry.example/:_authToken={SYNTHETIC_MARKER}",
            f'password: "synthetic phrase {SYNTHETIC_MARKER}"',
            f"password='synthetic phrase {SYNTHETIC_MARKER}'",
            f"passphrase=correct horse battery staple {SYNTHETIC_MARKER}",
            f"auth_header=Bearer synthetic phrase {SYNTHETIC_MARKER}",
            f"postgresql://operator:{SYNTHETIC_MARKER}@localhost/synapse",
            "-----BEGIN PRIVATE KEY-----\nsynthetic-private-material\n"
            "-----END PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\n"
            f"unterminated-{SYNTHETIC_MARKER}",
            "sk-synthetic1234567890",
            "ghp_synthetic12345678901234567890",
            "aaaaabbbbb.cccccddddd.eeeeefffff",
        )
        for sample in samples:
            with self.subTest(sample=sample.splitlines()[0][:40]):
                redacted, count = redact_capture_text(sample)
                self.assertGreaterEqual(count, 1)
                self.assertNotIn(SYNTHETIC_MARKER, redacted)
                self.assertTrue(
                    "[REDACTED" in redacted,
                    redacted,
                )

    def test_recursive_redaction_is_key_aware_and_preserves_safe_counters(self):
        value = {
            "apiKey": SYNTHETIC_MARKER,
            "authorization_header": SYNTHETIC_MARKER,
            "auth_header": f"Bearer {SYNTHETIC_MARKER}",
            "authentication": SYNTHETIC_MARKER,
            "bearer": SYNTHETIC_MARKER,
            "api_key_value": SYNTHETIC_MARKER,
            "password_hint": SYNTHETIC_MARKER,
            "wrapped_client_secret_material": SYNTHETIC_MARKER,
            "nested": {
                "client_secret": SYNTHETIC_MARKER,
                "description": f"token={SYNTHETIC_MARKER}",
            },
            "token_count": 17,
            "max_tokens": 128,
            "max_output_bytes": 4096,
            "estimated_tokens": 1024,
            "response_contract": {"profile": "compact"},
            "token_budget": 999,
            "estimated_token_count": 999,
            "lease_token": "synthetic-not-a-real-secret",
            "redaction_count": 2,
        }

        safe, count = redact_sensitive_value(value)

        self.assertGreaterEqual(count, 3)
        self.assertEqual(safe["apiKey"], REDACTED_SECRET)
        self.assertEqual(safe["authorization_header"], REDACTED_SECRET)
        self.assertEqual(safe["auth_header"], REDACTED_SECRET)
        self.assertEqual(safe["authentication"], REDACTED_SECRET)
        self.assertEqual(safe["bearer"], REDACTED_SECRET)
        self.assertEqual(safe["api_key_value"], REDACTED_SECRET)
        self.assertEqual(safe["password_hint"], REDACTED_SECRET)
        self.assertEqual(safe["wrapped_client_secret_material"], REDACTED_SECRET)
        self.assertEqual(safe["nested"]["client_secret"], REDACTED_SECRET)
        self.assertNotIn(SYNTHETIC_MARKER, str(safe))
        self.assertEqual(safe["token_count"], 17)
        self.assertEqual(safe["max_tokens"], 128)
        self.assertEqual(safe["max_output_bytes"], 4096)
        self.assertEqual(safe["estimated_tokens"], 1024)
        self.assertEqual(safe["response_contract"], {"profile": "compact"})
        self.assertEqual(safe["token_budget"], REDACTED_SECRET)
        self.assertEqual(safe["estimated_token_count"], REDACTED_SECRET)
        self.assertEqual(safe["lease_token"], REDACTED_SECRET)
        self.assertEqual(safe["redaction_count"], 2)
        self.assertTrue(is_sensitive_key("secretAccessKey"))
        self.assertTrue(is_sensitive_key("authorization_header"))
        self.assertTrue(is_sensitive_key("auth_header"))
        self.assertTrue(is_sensitive_key("authentication"))
        self.assertTrue(is_sensitive_key("bearer"))
        self.assertTrue(is_sensitive_key("request_api_key_value"))
        self.assertTrue(is_sensitive_key("password_hint"))
        self.assertFalse(is_sensitive_key("token_count"))

    def test_wrapped_secret_assignment_keys_are_redacted_in_unstructured_text(self):
        samples = (
            f"authorization_header={SYNTHETIC_MARKER}",
            f"api_key_value: {SYNTHETIC_MARKER}",
            f'{{"password_hint": "{SYNTHETIC_MARKER}"}}',
        )

        for sample in samples:
            with self.subTest(sample=sample):
                safe, count = redact_capture_text(sample)
                self.assertGreaterEqual(count, 1)
                self.assertNotIn(SYNTHETIC_MARKER, safe)

        telemetry, telemetry_count = redact_capture_text(
            "token_count=17 transport_token_stored=false"
        )
        self.assertEqual(telemetry_count, 0)
        self.assertEqual(
            telemetry,
            "token_count=17 transport_token_stored=false",
        )

    def test_recursive_and_unserializable_values_fail_closed(self):
        cyclic: list[object] = []
        cyclic.append(cyclic)

        safe_cycle, cycle_count = redact_sensitive_value(cyclic)
        safe_object, object_count = redact_sensitive_value(object())

        self.assertGreaterEqual(cycle_count, 1)
        self.assertEqual(safe_cycle, ["[REDACTED_RECURSION]"])
        self.assertGreaterEqual(object_count, 1)
        self.assertIn("UNSERIALIZABLE", str(safe_object))

    def test_public_error_is_redacted_path_free_control_free_and_bounded(self):
        error = RuntimeError(
            f"api_key={SYNTHETIC_MARKER} at "
            "/Users/operator/private/config.json\x00 "
            + ("x" * 600)
        )

        rendered = safe_public_error(error, max_chars=120)

        self.assertNotIn(SYNTHETIC_MARKER, rendered)
        self.assertNotIn("/Users/operator", rendered)
        self.assertNotIn("\x00", rendered)
        self.assertLessEqual(len(rendered), 120)

    def test_public_error_masks_cross_platform_local_paths(self):
        paths = (
            "/Volumes/OperatorDisk/private/config.json",
            "/home/operator/.config/private.json",
            "/root/.ssh/id_ed25519",
            "/data/synapse/private.sqlite3",
            "/workspace/Agentic Playground/SYNAPSE-S2/state.json",
            "/run/secrets/runtime",
            "/dev/disk4",
            "/proc/1234/environ",
            r"C:\Users\operator\private\config.json",
            r"C:\ProgramData\Synapse S2\private\config.json",
            r"\\fileserver\operators\private\config.json",
        )

        for path in paths:
            with self.subTest(path=path):
                rendered = safe_public_error(RuntimeError(f"failed at {path}"))
                self.assertEqual(rendered, "failed at [LOCAL_PATH]")
                self.assertNotIn("operator", rendered.casefold())

    def test_public_error_preserves_remote_url_but_masks_local_url_parameters(self):
        remote = "https://example.com/Users/public/docs"
        unix_query = "https://example.com/view?file=/Users/operator/private/db.sqlite3"
        encoded_query = "https://example.com/view?file=%2Froot%2F.ssh%2Fid_ed25519"
        windows_query = r"https://example.com/view?path=C:\Users\Dan\secret.txt"
        fragment_path = "https://example.com/view#open=/data/private/ledger.sqlite3"

        self.assertEqual(safe_public_error(remote), remote)
        for url in (unix_query, encoded_query, windows_query, fragment_path):
            with self.subTest(url=url):
                rendered = safe_public_error(url)
                self.assertIn("example.com", rendered)
                self.assertNotIn("Users", rendered)
                self.assertNotIn("id_ed25519", rendered)
                self.assertNotIn("secret.txt", rendered)
                self.assertNotIn("ledger.sqlite3", rendered)
                self.assertIn("LOCAL_PATH", rendered)

    def test_log_formatter_redacts_messages_and_tracebacks(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(SecretRedactingFormatter("%(levelname)s %(message)s"))
        logger = logging.getLogger("synapse-s2-redaction-test")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)

        try:
            raise RuntimeError(f"password={SYNTHETIC_MARKER}")
        except RuntimeError:
            logger.exception("Authorization: ApiKey %s", SYNTHETIC_MARKER)

        rendered = stream.getvalue()
        self.assertNotIn(SYNTHETIC_MARKER, rendered)
        self.assertIn("[REDACTED_SECRET]", rendered)

    def test_sensitive_identifiers_are_rejected_without_echoing_secret(self):
        with self.assertRaisesRegex(ValueError, "credential material") as raised:
            reject_sensitive_identifier(
                f"namespace-api_key={SYNTHETIC_MARKER}",
                field="context_id",
            )

        self.assertNotIn(SYNTHETIC_MARKER, str(raised.exception))

    def test_raw_content_digest_oracles_are_removed_recursively(self):
        safe, removed = strip_untrusted_raw_digest_fields(
            {
                "sha256": "verified-backup-checksum",
                "nested": {
                    "input_sha256": "a" * 64,
                    "raw-source-sha256": "b" * 64,
                },
                "items": [{"payload_sha256": "c" * 64, "count": 3}],
                "content_sha256": "d" * 64,
                "content_digest_recorded": False,
                "text_digest": "text-oracle",
                "prompt_hash": "prompt-oracle",
                "message_body_sha512": "e" * 128,
                "body_checksum": "body-oracle",
                "content_shape": "sphere",
                "content_shared": True,
                "text_shadow": "visible",
                "prompt_sharding": "balanced",
                "backup_sha256": "verified-backup-checksum-2",
            }
        )

        self.assertEqual(removed, 8)
        self.assertEqual(safe["sha256"], "verified-backup-checksum")
        self.assertEqual(
            safe["backup_sha256"],
            "verified-backup-checksum-2",
        )
        self.assertEqual(safe["content_shape"], "sphere")
        self.assertTrue(safe["content_shared"])
        self.assertEqual(safe["text_shadow"], "visible")
        self.assertEqual(safe["prompt_sharding"], "balanced")
        self.assertFalse(safe["content_digest_recorded"])
        self.assertEqual(safe["nested"], {})
        self.assertEqual(safe["items"], [{"count": 3}])

    def test_raw_content_digest_assignments_are_removed_from_nested_strings(self):
        marker = "f" * 64
        safe, removed = strip_untrusted_raw_digest_fields(
            {
                "reason": f"legacy payload_sha256={marker} evidence",
                "nested": [f'error: contentDigest="{marker}"'],
                "operational": "backup sha256 remains a receipt",
            }
        )

        self.assertEqual(removed, 2)
        self.assertNotIn(marker, json.dumps(safe, sort_keys=True))
        self.assertIn("[REMOVED_RAW_DIGEST_FIELD]", safe["reason"])
        self.assertEqual(safe["operational"], "backup sha256 remains a receipt")

    def test_raw_content_digest_oracles_are_removed_from_malformed_text(self):
        safe, removed = strip_untrusted_raw_digest_text(
            'broken { input_sha256=' + ("a" * 64)
            + ', "payload-sha256": "' + ("b" * 64) + '"'
            + ', content_sha512=' + ("c" * 128)
            + ', text_digest=text-oracle'
            + ', prompt_hash="prompt oracle"'
            + ', contentSha256=' + ("d" * 64)
            + ', promptDigest=prompt-camel-oracle'
            + ', rawPayloadSHA256=' + ("e" * 64)
            + ', content_shape=sphere'
        )

        self.assertEqual(removed, 8)
        self.assertNotIn("input_sha256", safe)
        self.assertNotIn("payload-sha256", safe)
        self.assertNotIn("a" * 64, safe)
        self.assertNotIn("b" * 64, safe)
        self.assertNotIn("c" * 128, safe)
        self.assertNotIn("text-oracle", safe)
        self.assertNotIn("prompt oracle", safe)
        self.assertNotIn("d" * 64, safe)
        self.assertNotIn("prompt-camel-oracle", safe)
        self.assertNotIn("e" * 64, safe)
        self.assertIn("content_shape=sphere", safe)


if __name__ == "__main__":
    unittest.main()

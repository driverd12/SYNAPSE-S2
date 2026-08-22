"""Tests for the incumbent-only release provenance verifier and the
separate offline signer.

Every private key generated here is a disposable test fixture living in a
temporary directory that is deleted in tearDownClass; no real key is ever
generated or persisted.
"""

import ast
import importlib.util
import json
import os
import shutil
import stat as stat_module
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "release_provenance.py"
SIGNER_PATH = ROOT / "scripts" / "sign_release_provenance.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provenance = _load_module("release_provenance_under_test", VERIFIER_PATH)
signer = _load_module("sign_release_provenance_under_test", SIGNER_PATH)

_CRYPTO_AVAILABLE = (
    provenance._ED25519 is not None and signer._ED25519 is not None
)
if _CRYPTO_AVAILABLE:
    from cryptography.hazmat.primitives.asymmetric import ed25519

ISSUED = 1_755_000_000
EXPIRES = 1_900_000_000
NOW = 1_755_500_000

# Fixed golden vectors: deterministic Ed25519 test seeds (never real keys)
# pinning the exact signing domains and canonical encoding. Any change to
# the domain constants, canonical form, or document schemas breaks these
# hardcoded signatures.
GOLDEN_ROOT_SEED = bytes(range(32))
GOLDEN_RELEASE_SEED = bytes(range(32, 64))
GOLDEN_ROOT_PUBLIC_HEX = (
    "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
)
GOLDEN_ROOT_KEY_ID = (
    "ed25519-d84a31e1a28d78ba1677bc5f3acc0287"
    "f6ce6ac5fec451052153284ed3a97714"
)
GOLDEN_RELEASE_PUBLIC_HEX = (
    "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
)
GOLDEN_RELEASE_KEY_ID = (
    "ed25519-4f7a11e890df75abc7b5b7fcd5daf6ad"
    "4ba3ac991688b3c60620016481e12f89"
)
GOLDEN_BUNDLE_SIGNATURE = (
    "68e100a7f1273ceb40fc881c92208cc697ddbabe4681b826e765358412585ac6"
    "8c36054e46714ff1ba4c9416c81e9e366aa98f1f6a3d3f265a4dfc79d1e9dc04"
)
GOLDEN_ENVELOPE_SIGNATURE = (
    "4c72309f323719398479a5ce5e9a7e7701f46ecdff149808b589042dd577bfae"
    "0d241dc5f2184631ddba41dc4c4ca593260db6e7b95bbc6c1ec1bd9f4f433e0b"
)

PROVENANCE_RESULT_KEYS = frozenset(
    (
        "schema",
        "mode",
        "command",
        "status",
        "apply_supported",
        "apply_performed",
        "channel",
        "version",
        "sequence",
        "trust_generation",
        "source_sha",
        "inventory_policy_id",
        "product_id",
        "bundle_sha256",
        "envelope_sha256",
        "floor_present",
        "floor_advanced",
        "idempotent",
        "nonclaims",
    )
)

SIGNER_RESULT_KEYS = frozenset(
    (
        "schema",
        "mode",
        "command",
        "status",
        "key_role",
        "key_id",
        "document_schema",
        "document_sha256",
        "nonclaims",
    )
)


def canonical(document) -> bytes:
    return provenance.canonical_bytes(document)


class ProvenanceFixture(unittest.TestCase):
    """Shared disposable key material plus a valid default chain."""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not _CRYPTO_AVAILABLE:
            raise unittest.SkipTest(
                "trusted cryptography 49 unavailable; run under the "
                "project virtual environment"
            )
        # /private/tmp only, and resolve() besides: macOS default tempdirs
        # live under the /var -> /private/var symlink, which the no-follow
        # ancestor walk correctly refuses.
        cls.base = Path(
            tempfile.mkdtemp(
                prefix="release-provenance-tests-", dir="/private/tmp"
            )
        ).resolve()
        os.chmod(cls.base, 0o700)
        cls.root_private = ed25519.Ed25519PrivateKey.generate()
        cls.release_private = ed25519.Ed25519PrivateKey.generate()
        cls.other_private = ed25519.Ed25519PrivateKey.generate()
        cls.root_public_hex = (
            cls.root_private.public_key().public_bytes_raw().hex()
        )
        cls.release_public_hex = (
            cls.release_private.public_key().public_bytes_raw().hex()
        )
        cls.other_public_hex = (
            cls.other_private.public_key().public_bytes_raw().hex()
        )
        cls.root_key_id = provenance.key_id_for_public_key(
            cls.root_public_hex
        )
        cls.release_key_id = provenance.key_id_for_public_key(
            cls.release_public_hex
        )
        cls.other_key_id = provenance.key_id_for_public_key(
            cls.other_public_hex
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.dir = Path(tempfile.mkdtemp(dir=self.base))
        os.chmod(self.dir, 0o700)
        self.root_path = self.write("root.json", canonical(self.root_doc()))
        self.floor_path = self.dir / "floor.json"
        self.signing_root = self.dir / "signing"
        self.signing_root.mkdir()
        os.chmod(self.signing_root, 0o700)

    # -- document builders -------------------------------------------------

    @classmethod
    def root_doc(cls, **overrides) -> dict:
        document = {
            "schema": "synapse-s2.release-root.v1",
            "root_key_id": cls.root_key_id,
            "root_public_key": cls.root_public_hex,
        }
        document.update(overrides)
        return document

    @classmethod
    def bundle_doc(cls, **overrides) -> dict:
        document = {
            "schema": "synapse-s2.release-trust-bundle.v1",
            "root_key_id": cls.root_key_id,
            "generation": 1,
            "issued_at": ISSUED,
            "expires_at": EXPIRES,
            "channel_minimum_sequences": {"stable": 1},
            "delegations": [
                {
                    "key_id": cls.release_key_id,
                    "public_key": cls.release_public_hex,
                    "role": "release",
                    "channels": ["stable"],
                    "not_before": ISSUED,
                    "not_after": EXPIRES,
                    "sequence_minimum": 1,
                    "sequence_maximum": 1_000_000,
                }
            ],
            "revoked_key_ids": [],
        }
        document.update(overrides)
        return document

    @classmethod
    def envelope_doc(cls, **overrides) -> dict:
        document = {
            "schema": "synapse-s2.release-envelope.v1",
            "channel": "stable",
            "version": "1.2.3",
            "sequence": 5,
            "source_sha": "f" * 40,
            "product_schema": "synapse-s2.product-release-plan.v1",
            "inventory_policy_id": "inventory-policy-" + "a" * 64,
            "product_id": "product-" + "b" * 64,
            "trust_generation": 1,
            "issued_at": ISSUED + 1,
            "expires_at": EXPIRES,
            "key_id": cls.release_key_id,
        }
        document.update(overrides)
        return document

    @classmethod
    def sign_bundle(cls, unsigned: dict, key=None) -> dict:
        key = key if key is not None else cls.root_private
        payload = provenance._BUNDLE_SIGNING_DOMAIN
        payload += provenance.canonical_bytes(unsigned)
        signed = dict(unsigned)
        signed["signature"] = key.sign(payload).hex()
        return signed

    @classmethod
    def sign_envelope(cls, unsigned: dict, key=None) -> dict:
        key = key if key is not None else cls.release_private
        payload = provenance._ENVELOPE_SIGNING_DOMAIN
        payload += provenance.canonical_bytes(unsigned)
        signed = dict(unsigned)
        signed["signature"] = key.sign(payload).hex()
        return signed

    # -- filesystem helpers ------------------------------------------------

    def write(self, name: str, data: bytes, mode: int = 0o644) -> Path:
        path = self.dir / name
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, mode)
        return path

    def write_chain(self, bundle=None, envelope=None):
        bundle = bundle if bundle is not None else self.bundle_doc()
        envelope = envelope if envelope is not None else self.envelope_doc()
        if "signature" not in bundle:
            bundle = self.sign_bundle(bundle)
        if "signature" not in envelope:
            envelope = self.sign_envelope(envelope)
        bundle_path = self.write("bundle.json", canonical(bundle))
        envelope_path = self.write("envelope.json", canonical(envelope))
        return bundle_path, envelope_path

    # -- command helpers ---------------------------------------------------

    def verify(self, bundle_path, envelope_path, now=NOW, **kwargs):
        with mock.patch.object(provenance, "_now", return_value=now):
            return provenance.verify_release(
                str(self.root_path),
                str(bundle_path),
                str(envelope_path),
                str(self.floor_path),
                **kwargs,
            )

    def accept(self, bundle_path, now=NOW, confirm=True):
        with mock.patch.object(provenance, "_now", return_value=now):
            return provenance.accept_trust_bundle(
                str(self.root_path),
                str(bundle_path),
                str(self.floor_path),
                confirm=confirm,
            )

    def record(self, bundle_path, envelope_path, now=NOW, confirm=True,
               **kwargs):
        with mock.patch.object(provenance, "_now", return_value=now):
            return provenance.record_installed_release(
                str(self.root_path),
                str(bundle_path),
                str(envelope_path),
                str(self.floor_path),
                confirm=confirm,
                **kwargs,
            )

    # -- assertions ---------------------------------------------------------

    def assert_shape(self, result: dict) -> None:
        self.assertEqual(set(result), set(PROVENANCE_RESULT_KEYS))
        self.assertIs(result["apply_supported"], False)
        self.assertIs(result["apply_performed"], False)
        self.assertEqual(
            result["nonclaims"], list(provenance.RESULT_NONCLAIMS)
        )
        rendered = provenance.render_result(result)
        self.assertNotIn("\n", rendered)
        self.assertLessEqual(
            len(rendered.encode("utf-8")), provenance.MAX_RESULT_BYTES
        )

    def assert_success(self, result: dict, status: str) -> None:
        self.assert_shape(result)
        self.assertEqual(result["status"], status)
        self.assertEqual(provenance.provenance_exit_code(result), 0)

    def assert_blocked(self, result: dict, token: str) -> None:
        self.assert_shape(result)
        self.assertEqual(result["status"], "blocked:" + token)
        self.assertEqual(provenance.provenance_exit_code(result), 3)

    def assert_refused(self, result: dict, token: str) -> None:
        self.assert_shape(result)
        self.assertEqual(result["status"], "unsupported:" + token)
        self.assertEqual(provenance.provenance_exit_code(result), 2)


class CanonicalDocumentTests(ProvenanceFixture):
    def test_round_trip_of_a_canonical_document(self):
        document = {"a": 1, "b": "x"}
        parsed = provenance.parse_canonical_document(canonical(document))
        self.assertEqual(parsed, document)

    def parse_refusal(self, data: bytes) -> str:
        with self.assertRaises(provenance._Refusal) as caught:
            provenance.parse_canonical_document(data)
        return caught.exception.token

    def test_trailing_newline_is_noncanonical(self):
        self.assertEqual(
            self.parse_refusal(provenance.canonical_bytes({"a": 1}) + b"\n"),
            "document-noncanonical",
        )

    def test_unsorted_keys_are_noncanonical(self):
        self.assertEqual(
            self.parse_refusal(b'{"b":1,"a":2}'), "document-noncanonical"
        )

    def test_whitespace_is_noncanonical(self):
        self.assertEqual(
            self.parse_refusal(b'{"a": 1}'), "document-noncanonical"
        )

    def test_duplicate_keys_are_rejected(self):
        self.assertEqual(
            self.parse_refusal(b'{"a":1,"a":2}'), "document-duplicate-key"
        )

    def test_floats_are_rejected(self):
        self.assertEqual(self.parse_refusal(b'{"a":1.5}'), "document-float")

    def test_nonfinite_constants_are_rejected(self):
        self.assertEqual(
            self.parse_refusal(b'{"a":NaN}'), "document-nonfinite"
        )

    def test_bad_utf8_is_rejected(self):
        self.assertEqual(
            self.parse_refusal(b'\xff\xfe{"a":1}'), "document-encoding"
        )

    def test_unescaped_non_ascii_is_noncanonical(self):
        self.assertEqual(
            self.parse_refusal('{"a":"é"}'.encode("utf-8")),
            "document-noncanonical",
        )

    def test_top_level_array_is_rejected(self):
        self.assertEqual(self.parse_refusal(b"[1]"), "document-malformed")

    def test_oversize_document_is_rejected(self):
        data = canonical({"a": "x" * provenance.MAX_DOCUMENT_BYTES})
        self.assertEqual(self.parse_refusal(data), "document-oversize")

    def test_key_id_derivation_is_domain_separated(self):
        import hashlib

        expected = "ed25519-" + hashlib.sha256(
            b"SYNAPSE-S2\x00ED25519-PUBLIC-KEY\x00v1\x00"
            + bytes.fromhex(self.root_public_hex)
        ).hexdigest()
        self.assertEqual(
            provenance.key_id_for_public_key(self.root_public_hex), expected
        )
        self.assertEqual(
            signer.key_id_for_public_key(self.root_public_hex), expected
        )


class ChainVerificationTests(ProvenanceFixture):
    def test_valid_chain_verifies_without_a_floor(self):
        bundle_path, envelope_path = self.write_chain()
        result = self.verify(bundle_path, envelope_path)
        self.assert_success(result, "verified")
        self.assertIs(result["floor_present"], False)
        self.assertIs(result["floor_advanced"], False)
        self.assertIs(result["idempotent"], False)
        self.assertEqual(result["channel"], "stable")
        self.assertEqual(result["version"], "1.2.3")
        self.assertEqual(result["sequence"], 5)
        self.assertEqual(result["trust_generation"], 1)
        self.assertEqual(result["source_sha"], "f" * 40)
        self.assertFalse(self.floor_path.exists())

    def test_root_document_tampering_is_refused(self):
        bundle_path, envelope_path = self.write_chain()
        for overrides in (
            {"schema": "synapse-s2.release-root.v2"},
            {"root_key_id": "ed25519-" + "0" * 64},
            {"root_public_key": self.other_public_hex},
        ):
            self.root_path = self.write(
                "root-tampered.json", canonical(self.root_doc(**overrides))
            )
            self.assert_refused(
                self.verify(bundle_path, envelope_path), "root-invalid"
            )

    def test_substituted_root_key_blocks_the_bundle(self):
        # A different but internally consistent root: the bundle no longer
        # names the trusted root key.
        self.root_path = self.write(
            "root-other.json",
            canonical(
                {
                    "schema": "synapse-s2.release-root.v1",
                    "root_key_id": self.other_key_id,
                    "root_public_key": self.other_public_hex,
                }
            ),
        )
        bundle_path, envelope_path = self.write_chain()
        self.assert_blocked(
            self.verify(bundle_path, envelope_path), "bundle-root-mismatch"
        )

    def test_every_signed_bundle_field_tamper_is_caught(self):
        signed = self.sign_bundle(self.bundle_doc())
        expectations = {
            "generation": (2, "blocked:bundle-signature-invalid"),
            "issued_at": (ISSUED + 7, "blocked:bundle-signature-invalid"),
            "expires_at": (EXPIRES - 7, "blocked:bundle-signature-invalid"),
            "channel_minimum_sequences": (
                {"stable": 2},
                "blocked:bundle-signature-invalid",
            ),
            "revoked_key_ids": (
                [self.other_key_id],
                "blocked:bundle-signature-invalid",
            ),
            "signature": (
                signed["signature"][:-2] + "00"
                if not signed["signature"].endswith("00")
                else signed["signature"][:-2] + "11",
                "blocked:bundle-signature-invalid",
            ),
            "schema": ("synapse-s2.x.v1", "unsupported:bundle-invalid"),
            "root_key_id": (
                self.other_key_id,
                "blocked:bundle-root-mismatch",
            ),
        }
        self.assertEqual(
            set(expectations) | {"delegations"}, set(signed)
        )
        for field, (value, status) in expectations.items():
            tampered = dict(signed)
            tampered[field] = value
            bundle_path = self.write(
                f"bundle-{field}.json", canonical(tampered)
            )
            envelope_path = self.write(
                f"envelope-{field}.json",
                canonical(self.sign_envelope(self.envelope_doc())),
            )
            result = self.verify(bundle_path, envelope_path)
            self.assertEqual(result["status"], status, field)
        tampered = dict(signed)
        delegation = dict(tampered["delegations"][0])
        delegation["not_after"] = EXPIRES - 1
        tampered["delegations"] = [delegation]
        bundle_path = self.write("bundle-delegations.json", canonical(tampered))
        _, envelope_path = self.write_chain()
        self.assert_blocked(
            self.verify(bundle_path, envelope_path),
            "bundle-signature-invalid",
        )

    def test_non_string_bundle_schema_preserves_bundle_invalid_taxonomy(self):
        for schema in ([], {}):
            with self.subTest(schema=schema):
                bundle_path, envelope_path = self.write_chain(
                    bundle=self.bundle_doc(schema=schema)
                )
                self.assert_refused(
                    self.verify(bundle_path, envelope_path), "bundle-invalid"
                )

    def test_every_signed_envelope_field_tamper_is_caught(self):
        signed = self.sign_envelope(self.envelope_doc())
        expectations = {
            "channel": ("beta", "blocked:channel-not-delegated"),
            "version": ("9.9.9", "blocked:envelope-signature-invalid"),
            "sequence": (6, "blocked:envelope-signature-invalid"),
            "source_sha": ("e" * 40, "blocked:envelope-signature-invalid"),
            "inventory_policy_id": (
                "inventory-policy-" + "c" * 64,
                "blocked:envelope-signature-invalid",
            ),
            "product_id": (
                "product-" + "d" * 64,
                "blocked:envelope-signature-invalid",
            ),
            "trust_generation": (2, "blocked:trust-generation-mismatch"),
            "issued_at": (ISSUED + 9, "blocked:envelope-signature-invalid"),
            "expires_at": (
                EXPIRES - 9,
                "blocked:envelope-signature-invalid",
            ),
            "key_id": (self.other_key_id, "blocked:delegation-unknown"),
            "signature": (
                signed["signature"][:-2] + "00"
                if not signed["signature"].endswith("00")
                else signed["signature"][:-2] + "11",
                "blocked:envelope-signature-invalid",
            ),
            "schema": ("synapse-s2.x.v1", "unsupported:envelope-invalid"),
            "product_schema": (
                "synapse-s2.other.v1",
                "unsupported:envelope-invalid",
            ),
        }
        self.assertEqual(set(expectations), set(signed))
        bundle_path = self.write(
            "bundle.json", canonical(self.sign_bundle(self.bundle_doc()))
        )
        for field, (value, status) in expectations.items():
            tampered = dict(signed)
            tampered[field] = value
            envelope_path = self.write(
                f"envelope-{field}.json", canonical(tampered)
            )
            result = self.verify(bundle_path, envelope_path)
            self.assertEqual(result["status"], status, field)

    def test_bundle_signed_by_the_wrong_key_is_blocked(self):
        bundle = self.sign_bundle(self.bundle_doc(), key=self.other_private)
        bundle_path, envelope_path = self.write_chain(bundle=bundle)
        self.assert_blocked(
            self.verify(bundle_path, envelope_path),
            "bundle-signature-invalid",
        )

    def test_envelope_signed_by_the_wrong_key_is_blocked(self):
        envelope = self.sign_envelope(
            self.envelope_doc(), key=self.other_private
        )
        bundle_path, envelope_path = self.write_chain(envelope=envelope)
        self.assert_blocked(
            self.verify(bundle_path, envelope_path),
            "envelope-signature-invalid",
        )

    def test_root_key_never_signs_envelopes(self):
        envelope = self.sign_envelope(
            self.envelope_doc(key_id=self.root_key_id),
            key=self.root_private,
        )
        bundle_path, envelope_path = self.write_chain(envelope=envelope)
        self.assert_blocked(
            self.verify(bundle_path, envelope_path), "root-signed-envelope"
        )

    def test_self_delegation_of_the_root_key_is_refused(self):
        delegation = {
            "key_id": self.root_key_id,
            "public_key": self.root_public_hex,
            "role": "release",
            "channels": ["stable"],
            "not_before": ISSUED,
            "not_after": EXPIRES,
            "sequence_minimum": 1,
            "sequence_maximum": 1_000_000,
        }
        bundle = self.bundle_doc(delegations=[delegation])
        bundle_path, envelope_path = self.write_chain(bundle=bundle)
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "bundle-root-delegated"
        )

    def test_revoking_the_root_key_is_refused(self):
        bundle = self.bundle_doc(revoked_key_ids=[self.root_key_id])
        bundle_path, envelope_path = self.write_chain(bundle=bundle)
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "bundle-root-revoked"
        )

    def test_undelegated_key_is_blocked(self):
        envelope = self.sign_envelope(
            self.envelope_doc(key_id=self.other_key_id),
            key=self.other_private,
        )
        bundle_path, envelope_path = self.write_chain(envelope=envelope)
        self.assert_blocked(
            self.verify(bundle_path, envelope_path), "delegation-unknown"
        )

    def test_revoked_key_is_blocked(self):
        bundle = self.bundle_doc(revoked_key_ids=[self.release_key_id])
        bundle_path, envelope_path = self.write_chain(bundle=bundle)
        self.assert_blocked(
            self.verify(bundle_path, envelope_path), "key-revoked"
        )

    def test_wrong_delegation_role_is_refused(self):
        bundle = self.bundle_doc()
        delegation = dict(bundle["delegations"][0])
        delegation["role"] = "root"
        bundle["delegations"] = [delegation]
        bundle_path, envelope_path = self.write_chain(bundle=bundle)
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "bundle-invalid"
        )

    def test_envelope_issued_outside_the_delegation_window_is_blocked(self):
        bundle = self.bundle_doc()
        delegation = dict(bundle["delegations"][0])
        delegation["not_before"] = ISSUED + 100
        bundle["delegations"] = [delegation]
        bundle_path, envelope_path = self.write_chain(bundle=bundle)
        self.assert_blocked(
            self.verify(bundle_path, envelope_path), "delegation-window"
        )

    def test_expired_delegation_is_blocked_even_for_old_envelopes(self):
        bundle = self.bundle_doc()
        delegation = dict(bundle["delegations"][0])
        delegation["not_after"] = NOW - 10
        bundle["delegations"] = [delegation]
        envelope = self.envelope_doc(expires_at=NOW - 20)
        bundle_path, envelope_path = self.write_chain(
            bundle=bundle, envelope=envelope
        )
        self.assert_blocked(
            self.verify(bundle_path, envelope_path), "delegation-expired"
        )

    def test_not_yet_valid_delegation_is_blocked(self):
        bundle = self.bundle_doc()
        delegation = dict(bundle["delegations"][0])
        delegation["not_before"] = NOW + 100
        bundle["delegations"] = [delegation]
        envelope = self.envelope_doc(issued_at=NOW + 200)
        bundle_path, envelope_path = self.write_chain(
            bundle=bundle, envelope=envelope
        )
        self.assert_blocked(
            self.verify(bundle_path, envelope_path),
            "delegation-not-yet-valid",
        )

    def test_envelope_validity_must_fit_inside_the_delegation(self):
        bundle = self.bundle_doc()
        delegation = dict(bundle["delegations"][0])
        delegation["not_after"] = EXPIRES - 50
        bundle["delegations"] = [delegation]
        bundle_path, envelope_path = self.write_chain(bundle=bundle)
        self.assert_blocked(
            self.verify(bundle_path, envelope_path), "delegation-window"
        )

    def test_sequence_outside_the_delegation_bounds_is_blocked(self):
        for bounds in ((1, 4), (6, 10)):
            bundle = self.bundle_doc()
            delegation = dict(bundle["delegations"][0])
            delegation["sequence_minimum"] = bounds[0]
            delegation["sequence_maximum"] = bounds[1]
            bundle["delegations"] = [delegation]
            bundle_path, envelope_path = self.write_chain(bundle=bundle)
            self.assert_blocked(
                self.verify(bundle_path, envelope_path),
                "sequence-outside-delegation",
            )

    def test_inverted_or_missing_sequence_bounds_are_refused(self):
        bundle = self.bundle_doc()
        delegation = dict(bundle["delegations"][0])
        delegation["sequence_minimum"] = 5
        delegation["sequence_maximum"] = 4
        bundle["delegations"] = [delegation]
        bundle_path, envelope_path = self.write_chain(bundle=bundle)
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "bundle-invalid"
        )
        bundle = self.bundle_doc()
        delegation = dict(bundle["delegations"][0])
        del delegation["sequence_minimum"]
        del delegation["sequence_maximum"]
        bundle["delegations"] = [delegation]
        bundle_path, envelope_path = self.write_chain(bundle=bundle)
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "bundle-invalid"
        )

    def test_sequence_below_the_bundle_minimum_is_blocked(self):
        bundle = self.bundle_doc(channel_minimum_sequences={"stable": 9})
        bundle_path, envelope_path = self.write_chain(bundle=bundle)
        self.assert_blocked(
            self.verify(bundle_path, envelope_path), "sequence-below-minimum"
        )

    def test_time_windows_are_enforced(self):
        bundle_path, envelope_path = self.write_chain()
        for now, token in (
            (ISSUED - 1, "bundle-not-yet-valid"),
            (EXPIRES, "bundle-expired"),
            (ISSUED, "envelope-not-yet-valid"),
        ):
            self.assert_blocked(
                self.verify(bundle_path, envelope_path, now=now), token
            )
        envelope = self.envelope_doc(expires_at=NOW)
        bundle_path, envelope_path = self.write_chain(envelope=envelope)
        self.assert_blocked(
            self.verify(bundle_path, envelope_path), "envelope-expired"
        )

    def test_expected_identity_mismatches_are_blocked(self):
        bundle_path, envelope_path = self.write_chain()
        for kwargs, token in (
            (
                {"expected_source_sha": "0" * 40},
                "expected-source-sha-mismatch",
            ),
            (
                {"expected_inventory_policy_id": "inventory-policy-" + "0" * 64},
                "expected-inventory-policy-mismatch",
            ),
            (
                {"expected_product_id": "product-" + "0" * 64},
                "expected-product-id-mismatch",
            ),
        ):
            self.assert_blocked(
                self.verify(bundle_path, envelope_path, **kwargs), token
            )
        result = self.verify(
            bundle_path,
            envelope_path,
            expected_source_sha="f" * 40,
            expected_inventory_policy_id="inventory-policy-" + "a" * 64,
            expected_product_id="product-" + "b" * 64,
        )
        self.assert_success(result, "verified")

    def test_boolean_as_integer_is_refused(self):
        bundle = self.sign_bundle(self.bundle_doc())
        bundle["generation"] = True
        bundle_path = self.write("bundle-bool.json", canonical(bundle))
        _, envelope_path = self.write_chain()
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "bundle-invalid"
        )

    def test_bad_hex_lengths_are_refused(self):
        envelope = self.sign_envelope(self.envelope_doc())
        envelope["source_sha"] = "f" * 39
        bundle_path, _ = self.write_chain()
        envelope_path = self.write("envelope-hex.json", canonical(envelope))
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "envelope-invalid"
        )

    def test_delegation_and_revocation_bounds_are_enforced(self):
        keys = [ed25519.Ed25519PrivateKey.generate() for _ in range(17)]
        delegations = []
        for key in keys:
            public_hex = key.public_key().public_bytes_raw().hex()
            delegations.append(
                {
                    "key_id": provenance.key_id_for_public_key(public_hex),
                    "public_key": public_hex,
                    "role": "release",
                    "channels": ["stable"],
                    "not_before": ISSUED,
                    "not_after": EXPIRES,
                    "sequence_minimum": 1,
                    "sequence_maximum": 1_000_000,
                }
            )
        bundle = self.bundle_doc(delegations=delegations)
        bundle_path, envelope_path = self.write_chain(bundle=bundle)
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "bundle-invalid"
        )
        revoked = sorted(
            "ed25519-" + format(index, "064x") for index in range(65)
        )
        bundle = self.bundle_doc(revoked_key_ids=revoked)
        bundle_path, envelope_path = self.write_chain(bundle=bundle)
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "bundle-invalid"
        )

    def test_unknown_and_missing_fields_are_refused(self):
        bundle = self.sign_bundle(self.bundle_doc())
        extra = dict(bundle)
        extra["comment"] = "x"
        bundle_path = self.write("bundle-extra.json", canonical(extra))
        _, envelope_path = self.write_chain()
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "bundle-invalid"
        )
        missing = dict(bundle)
        del missing["revoked_key_ids"]
        bundle_path = self.write("bundle-missing.json", canonical(missing))
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "bundle-invalid"
        )


class FloorSemanticsTests(ProvenanceFixture):
    def accepted_floor(self, bundle=None):
        bundle_path = self.write(
            "accepted-bundle.json",
            canonical(self.sign_bundle(bundle or self.bundle_doc())),
        )
        result = self.accept(bundle_path)
        self.assert_success(result, "accepted")
        return bundle_path

    def test_accept_creates_an_owner_only_canonical_floor(self):
        self.accepted_floor()
        observed = os.lstat(self.floor_path)
        self.assertTrue(stat_module.S_ISREG(observed.st_mode))
        self.assertEqual(stat_module.S_IMODE(observed.st_mode), 0o600)
        self.assertEqual(observed.st_nlink, 1)
        floor = provenance.parse_canonical_document(
            self.floor_path.read_bytes()
        )
        self.assertEqual(floor["schema"], "synapse-s2.release-floor.v1")
        self.assertEqual(floor["trust_generation"], 1)
        self.assertEqual(floor["committed_at"], NOW)
        self.assertEqual(
            floor["channels"],
            {"stable": {"minimum_sequence": 1, "installed": None}},
        )
        self.assertEqual(floor["revoked_key_ids"], [])

    def test_accept_requires_confirm(self):
        bundle_path, _ = self.write_chain()
        self.assert_refused(
            self.accept(bundle_path, confirm=False), "confirm-required"
        )
        self.assertFalse(self.floor_path.exists())

    def test_accept_is_idempotent_for_the_committed_bundle(self):
        bundle_path = self.accepted_floor()
        before = self.floor_path.read_bytes()
        result = self.accept(bundle_path)
        self.assert_success(result, "accepted")
        self.assertIs(result["idempotent"], True)
        self.assertIs(result["floor_advanced"], False)
        self.assertEqual(self.floor_path.read_bytes(), before)

    def test_accept_blocks_a_stale_generation(self):
        self.accepted_floor(self.bundle_doc(generation=2))
        bundle_path = self.write(
            "old-bundle.json", canonical(self.sign_bundle(self.bundle_doc()))
        )
        self.assert_blocked(
            self.accept(bundle_path), "trust-generation-stale"
        )

    def test_accept_blocks_equal_generation_equivocation(self):
        self.accepted_floor()
        variant = self.bundle_doc(expires_at=EXPIRES - 1)
        bundle_path = self.write(
            "variant-bundle.json", canonical(self.sign_bundle(variant))
        )
        self.assert_blocked(
            self.accept(bundle_path), "trust-bundle-equivocation"
        )

    def test_accept_advances_to_a_higher_generation(self):
        self.accepted_floor()
        newer_path = self.write(
            "newer-bundle.json",
            canonical(self.sign_bundle(self.bundle_doc(generation=2))),
        )
        result = self.accept(newer_path)
        self.assert_success(result, "accepted")
        self.assertIs(result["floor_advanced"], True)
        self.assertEqual(result["trust_generation"], 2)

    def test_accept_blocks_a_channel_minimum_rollback(self):
        self.accepted_floor(
            self.bundle_doc(channel_minimum_sequences={"stable": 5})
        )
        lowered = self.bundle_doc(
            generation=2, channel_minimum_sequences={"stable": 3}
        )
        bundle_path = self.write(
            "lowered-bundle.json", canonical(self.sign_bundle(lowered))
        )
        self.assert_blocked(self.accept(bundle_path), "minimum-rollback")

    def test_accept_preserves_the_installed_release(self):
        bundle_path, envelope_path = self.write_chain()
        self.accepted_floor()
        self.assert_success(
            self.record(bundle_path, envelope_path), "recorded"
        )
        newer = self.bundle_doc(
            generation=2,
            delegations=[],
            channel_minimum_sequences={"stable": 1},
        )
        newer_path = self.write(
            "gen2-bundle.json", canonical(self.sign_bundle(newer))
        )
        self.assert_success(self.accept(newer_path), "accepted")
        floor = provenance.parse_canonical_document(
            self.floor_path.read_bytes()
        )
        self.assertEqual(floor["channels"]["stable"]["installed"]["sequence"], 5)

    def test_forgotten_revocation_blocks_the_new_bundle(self):
        self.accepted_floor(
            self.bundle_doc(revoked_key_ids=[self.other_key_id])
        )
        floor_before = self.floor_path.read_bytes()
        forgetful = self.bundle_doc(generation=2, revoked_key_ids=[])
        bundle_path = self.write(
            "forgetful-bundle.json", canonical(self.sign_bundle(forgetful))
        )
        self.assert_blocked(self.accept(bundle_path), "revocation-forgotten")
        self.assertEqual(self.floor_path.read_bytes(), floor_before)
        envelope_path = self.write(
            "forgetful-envelope.json",
            canonical(
                self.sign_envelope(self.envelope_doc(trust_generation=2))
            ),
        )
        self.assert_blocked(
            self.verify(bundle_path, envelope_path), "revocation-forgotten"
        )

    def test_redelegating_a_floor_revoked_key_is_blocked(self):
        self.accepted_floor(
            self.bundle_doc(revoked_key_ids=[self.other_key_id])
        )
        delegation = {
            "key_id": self.other_key_id,
            "public_key": self.other_public_hex,
            "role": "release",
            "channels": ["stable"],
            "not_before": ISSUED,
            "not_after": EXPIRES,
            "sequence_minimum": 1,
            "sequence_maximum": 1_000_000,
        }
        redelegated = self.bundle_doc(
            generation=2,
            delegations=self.bundle_doc()["delegations"] + [delegation],
            revoked_key_ids=[self.other_key_id],
        )
        bundle_path = self.write(
            "redelegated-bundle.json",
            canonical(self.sign_bundle(redelegated)),
        )
        self.assert_blocked(
            self.accept(bundle_path), "revoked-key-redelegated"
        )

    def test_revocations_accumulate_across_generations(self):
        self.accepted_floor()
        floor = provenance.parse_canonical_document(
            self.floor_path.read_bytes()
        )
        self.assertEqual(floor["revoked_key_ids"], [])
        gen2 = self.bundle_doc(
            generation=2, revoked_key_ids=[self.other_key_id]
        )
        gen2_path = self.write(
            "gen2-revoking.json", canonical(self.sign_bundle(gen2))
        )
        self.assert_success(self.accept(gen2_path), "accepted")
        floor = provenance.parse_canonical_document(
            self.floor_path.read_bytes()
        )
        self.assertEqual(floor["revoked_key_ids"], [self.other_key_id])
        extra = "ed25519-" + "0" * 64
        gen3 = self.bundle_doc(
            generation=3,
            revoked_key_ids=sorted([self.other_key_id, extra]),
        )
        gen3_path = self.write(
            "gen3-revoking.json", canonical(self.sign_bundle(gen3))
        )
        self.assert_success(self.accept(gen3_path), "accepted")
        floor = provenance.parse_canonical_document(
            self.floor_path.read_bytes()
        )
        self.assertEqual(
            floor["revoked_key_ids"], sorted([self.other_key_id, extra])
        )
        envelope_path = self.write(
            "gen3-envelope.json",
            canonical(
                self.sign_envelope(self.envelope_doc(trust_generation=3))
            ),
        )
        self.assert_success(self.record(gen3_path, envelope_path), "recorded")
        floor = provenance.parse_canonical_document(
            self.floor_path.read_bytes()
        )
        self.assertEqual(
            floor["revoked_key_ids"], sorted([self.other_key_id, extra])
        )

    def test_unsorted_floor_revocations_are_refused(self):
        self.accepted_floor()
        floor = provenance.parse_canonical_document(
            self.floor_path.read_bytes()
        )
        floor["revoked_key_ids"] = sorted(
            ["ed25519-" + "0" * 64, "ed25519-" + "1" * 64], reverse=True
        )
        self.write("floor.json", canonical(floor), mode=0o600)
        bundle_path, envelope_path = self.write_chain()
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "floor-invalid"
        )

    def test_verify_with_a_higher_generation_bundle_never_advances(self):
        self.accepted_floor()
        floor_before = self.floor_path.read_bytes()
        newer = self.bundle_doc(generation=2)
        envelope = self.envelope_doc(trust_generation=2)
        bundle_path, envelope_path = self.write_chain(
            bundle=newer, envelope=envelope
        )
        result = self.verify(bundle_path, envelope_path)
        self.assert_success(result, "verified")
        self.assertIs(result["floor_present"], True)
        self.assertIs(result["floor_advanced"], False)
        self.assertEqual(self.floor_path.read_bytes(), floor_before)

    def test_verify_blocks_a_stale_generation_against_the_floor(self):
        self.accepted_floor(self.bundle_doc(generation=2))
        bundle_path, envelope_path = self.write_chain()
        self.assert_blocked(
            self.verify(bundle_path, envelope_path),
            "trust-generation-stale",
        )

    def test_record_requires_the_bundle_to_be_accepted(self):
        bundle_path, envelope_path = self.write_chain()
        self.assert_blocked(
            self.record(bundle_path, envelope_path), "trust-not-accepted"
        )
        self.accepted_floor()
        newer = self.bundle_doc(generation=2)
        envelope = self.envelope_doc(trust_generation=2)
        newer_bundle, newer_envelope = self.write_chain(
            bundle=newer, envelope=envelope
        )
        self.assert_blocked(
            self.record(newer_bundle, newer_envelope), "trust-not-accepted"
        )

    def test_record_and_idempotent_rerecord(self):
        bundle_path, envelope_path = self.write_chain()
        self.accepted_floor()
        result = self.record(bundle_path, envelope_path)
        self.assert_success(result, "recorded")
        self.assertIs(result["floor_advanced"], True)
        floor_bytes = self.floor_path.read_bytes()
        again = self.record(bundle_path, envelope_path)
        self.assert_success(again, "recorded")
        self.assertIs(again["idempotent"], True)
        self.assertIs(again["floor_advanced"], False)
        self.assertEqual(self.floor_path.read_bytes(), floor_bytes)
        verified = self.verify(bundle_path, envelope_path)
        self.assert_success(verified, "verified")
        self.assertIs(verified["idempotent"], True)

    def test_record_requires_confirm(self):
        bundle_path, envelope_path = self.write_chain()
        self.accepted_floor()
        self.assert_refused(
            self.record(bundle_path, envelope_path, confirm=False),
            "confirm-required",
        )

    def test_sequence_rollback_is_blocked(self):
        bundle_path, envelope_path = self.write_chain()
        self.accepted_floor()
        self.assert_success(
            self.record(bundle_path, envelope_path), "recorded"
        )
        older = self.sign_envelope(self.envelope_doc(sequence=4))
        older_path = self.write("older-envelope.json", canonical(older))
        self.assert_blocked(
            self.verify(bundle_path, older_path), "sequence-rollback"
        )
        self.assert_blocked(
            self.record(bundle_path, older_path), "sequence-rollback"
        )

    def test_equal_sequence_equivocation_is_blocked(self):
        bundle_path, envelope_path = self.write_chain()
        self.accepted_floor()
        self.assert_success(
            self.record(bundle_path, envelope_path), "recorded"
        )
        variant = self.sign_envelope(self.envelope_doc(version="1.2.4"))
        variant_path = self.write("variant-envelope.json", canonical(variant))
        self.assert_blocked(
            self.verify(bundle_path, variant_path), "release-equivocation"
        )

    def test_sequence_below_the_floor_minimum_is_blocked(self):
        self.accepted_floor(
            self.bundle_doc(channel_minimum_sequences={"stable": 5})
        )
        # A newer, not-yet-accepted bundle lowers the channel minimum: the
        # committed floor minimum still applies on verify.
        newer = self.bundle_doc(
            generation=2, channel_minimum_sequences={"stable": 3}
        )
        envelope = self.envelope_doc(sequence=4, trust_generation=2)
        bundle_path, envelope_path = self.write_chain(
            bundle=newer, envelope=envelope
        )
        self.assert_blocked(
            self.verify(bundle_path, envelope_path), "sequence-below-floor"
        )

    def test_clock_rollback_is_blocked(self):
        bundle_path, envelope_path = self.write_chain()
        self.accepted_floor()
        self.assert_blocked(
            self.verify(bundle_path, envelope_path, now=NOW - 10),
            "clock-before-floor",
        )
        self.assert_blocked(
            self.accept(bundle_path, now=NOW - 10), "clock-before-floor"
        )

    def test_group_writable_floor_is_refused(self):
        bundle_path, envelope_path = self.write_chain()
        self.accepted_floor()
        os.chmod(self.floor_path, 0o644)
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "unsafe-file"
        )

    def test_tampered_floor_schema_is_refused(self):
        bundle_path, envelope_path = self.write_chain()
        self.accepted_floor()
        floor = provenance.parse_canonical_document(
            self.floor_path.read_bytes()
        )
        floor["operator_note"] = "x"
        self.floor_path.write_bytes(canonical(floor))
        os.chmod(self.floor_path, 0o600)
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "floor-invalid"
        )

    def test_held_lock_refuses_the_mutation(self):
        import fcntl

        bundle_path, _ = self.write_chain()
        lock_path = str(self.floor_path) + ".lock"
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_refused(self.accept(bundle_path), "floor-locked")
            self.assertFalse(self.floor_path.exists())
        finally:
            os.close(lock_fd)

    def test_fsync_failure_leaves_the_floor_untouched(self):
        bundle_path, _ = self.write_chain()
        self.accepted_floor()
        before = self.floor_path.read_bytes()
        newer_path = self.write(
            "gen2.json",
            canonical(self.sign_bundle(self.bundle_doc(generation=2))),
        )
        with mock.patch.object(
            provenance.os, "fsync", side_effect=OSError(5, "io")
        ):
            self.assert_refused(self.accept(newer_path), "floor-write-failed")
        self.assertEqual(self.floor_path.read_bytes(), before)
        self.assertFalse(
            [name for name in os.listdir(self.dir) if ".tmp-" in name]
        )

    def test_stale_unknown_temp_is_preserved_not_deleted(self):
        bundle_path, _ = self.write_chain()
        stale_path = self.dir / ("." + self.floor_path.name + ".tmp-stale")
        stale_path.write_bytes(b"stale")
        os.chmod(stale_path, 0o600)
        self.assert_success(self.accept(bundle_path), "accepted")
        self.assertEqual(stale_path.read_bytes(), b"stale")
        self.assertTrue(self.floor_path.exists())

    def test_temp_name_collision_never_deletes_the_unknown_file(self):
        bundle_path, _ = self.write_chain()
        fixed_leaf = "." + self.floor_path.name + ".tmp-fixed"
        foreign = self.dir / fixed_leaf
        foreign.write_bytes(b"foreign")
        os.chmod(foreign, 0o600)
        with mock.patch.object(
            provenance, "_floor_temp_leaf", return_value=fixed_leaf
        ):
            self.assert_refused(self.accept(bundle_path), "temp-exists")
        self.assertEqual(foreign.read_bytes(), b"foreign")
        self.assertFalse(self.floor_path.exists())

    def test_lock_replacement_after_flock_is_refused(self):
        import fcntl

        bundle_path, _ = self.write_chain()
        lock_path = str(self.floor_path) + ".lock"
        real_flock = fcntl.flock

        def replace_lock(fd, operation):
            real_flock(fd, operation)
            os.unlink(lock_path)
            replacement = os.open(
                lock_path, os.O_RDWR | os.O_CREAT, 0o600
            )
            os.close(replacement)

        with mock.patch.object(provenance.fcntl, "flock", replace_lock):
            self.assert_refused(
                self.accept(bundle_path), "floor-lock-replaced"
            )
        self.assertFalse(self.floor_path.exists())

    def test_concurrent_floor_swap_loses_no_update(self):
        self.accepted_floor()
        newer_path = self.write(
            "gen2.json",
            canonical(self.sign_bundle(self.bundle_doc(generation=2))),
        )
        real_fsync = os.fsync
        state = {"swapped": False}

        def swap_then_fsync(fd):
            if not state["swapped"]:
                state["swapped"] = True
                intruder = self.dir / "intruder"
                intruder.write_bytes(b"intruder")
                os.chmod(intruder, 0o600)
                os.rename(intruder, self.floor_path)
            real_fsync(fd)

        with mock.patch.object(provenance.os, "fsync", swap_then_fsync):
            self.assert_refused(self.accept(newer_path), "floor-raced")
        self.assertEqual(self.floor_path.read_bytes(), b"intruder")
        self.assertFalse(
            [name for name in os.listdir(self.dir) if ".tmp-" in name]
        )

    def test_post_rename_fsync_failure_is_outcome_unknown(self):
        self.accepted_floor()
        newer_path = self.write(
            "gen2.json",
            canonical(self.sign_bundle(self.bundle_doc(generation=2))),
        )
        real_fsync = os.fsync
        calls = []

        def flaky_fsync(fd):
            calls.append(fd)
            if len(calls) == 2:
                raise OSError(5, "io")
            real_fsync(fd)

        with mock.patch.object(provenance.os, "fsync", flaky_fsync):
            result = self.accept(newer_path)
        self.assert_shape(result)
        self.assertEqual(result["status"], "outcome_unknown:floor-commit")
        self.assertEqual(provenance.provenance_exit_code(result), 2)
        floor = provenance.parse_canonical_document(
            self.floor_path.read_bytes()
        )
        self.assertEqual(floor["trust_generation"], 2)
        reconciled = self.accept(newer_path)
        self.assert_success(reconciled, "accepted")
        self.assertIs(reconciled["idempotent"], True)
        self.assertFalse(
            [name for name in os.listdir(self.dir) if ".tmp-" in name]
        )

    def test_ancestor_swap_during_floor_rename_is_outcome_unknown(self):
        # An attacker detaches and recreates the floor's parent directory
        # in the instant between the atomic rename and the post-publish
        # verification: the committed floor is durable only in a
        # directory the requested path no longer reaches, so the result
        # must be outcome-unknown, never accepted.
        bundle_path = self.write(
            "accepted-bundle.json",
            canonical(self.sign_bundle(self.bundle_doc())),
        )
        detached = self.base / f"detached-{self.id().split('.')[-1]}"
        real_rename = os.rename
        state = {"swapped": False}

        def swapping_rename(src, dst, **kwargs):
            real_rename(src, dst, **kwargs)
            if (
                not state["swapped"]
                and dst == "floor.json"
                and kwargs.get("dst_dir_fd") is not None
            ):
                state["swapped"] = True
                real_rename(self.dir, detached)
                os.mkdir(self.dir)
                os.chmod(self.dir, 0o700)

        with mock.patch.object(provenance.os, "rename", swapping_rename):
            result = self.accept(bundle_path)
        self.assertTrue(state["swapped"])
        self.assert_shape(result)
        self.assertEqual(result["status"], "outcome_unknown:floor-commit")
        self.assertEqual(provenance.provenance_exit_code(result), 2)
        # The requested path must not have been reported as committed:
        # the recreated parent holds no floor at all.
        self.assertFalse(self.floor_path.exists())
        # The committed floor is intact, canonical, and owner-only in
        # the detached directory, with no temp leftovers beside it.
        displaced_floor = detached / "floor.json"
        observed = os.lstat(displaced_floor)
        self.assertTrue(stat_module.S_ISREG(observed.st_mode))
        self.assertEqual(stat_module.S_IMODE(observed.st_mode), 0o600)
        floor = provenance.parse_canonical_document(
            displaced_floor.read_bytes()
        )
        self.assertEqual(floor["trust_generation"], 1)
        self.assertFalse(
            [name for name in os.listdir(detached) if ".tmp-" in name]
        )

    def test_floor_swap_after_final_stat_is_outcome_unknown(self):
        # An attacker swaps the visible floor leaf for their own file in
        # the instant after the post-rename stat: the requested path no
        # longer names the committed floor, so the result must be
        # outcome-unknown, never accepted.
        bundle_path = self.write(
            "accepted-bundle.json",
            canonical(self.sign_bundle(self.bundle_doc())),
        )
        attacker_bytes = b'{"attacker":true}'
        attacker_path = self.write(
            "attacker.json", attacker_bytes, mode=0o600
        )
        displaced = self.dir / "displaced.json"
        real_rename = os.rename
        real_stat = os.stat
        state = {"renamed": False, "swapped": False}

        def tracking_rename(src, dst, **kwargs):
            real_rename(src, dst, **kwargs)
            if dst == "floor.json" and kwargs.get("dst_dir_fd") is not None:
                state["renamed"] = True

        def swap_after_final_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if (
                state["renamed"]
                and not state["swapped"]
                and path == "floor.json"
                and kwargs.get("dir_fd") is not None
            ):
                state["swapped"] = True
                real_rename(self.floor_path, displaced)
                real_rename(attacker_path, self.floor_path)
            return result

        with mock.patch.object(
            provenance.os, "rename", tracking_rename
        ), mock.patch.object(provenance.os, "stat", swap_after_final_stat):
            result = self.accept(bundle_path)
        self.assertTrue(state["swapped"])
        self.assert_shape(result)
        self.assertEqual(result["status"], "outcome_unknown:floor-commit")
        self.assertEqual(provenance.provenance_exit_code(result), 2)
        # The attacker's file occupies the requested path — success must
        # not have been claimed for it.
        self.assertEqual(self.floor_path.read_bytes(), attacker_bytes)
        # The committed floor itself is intact where the attacker moved
        # it, canonical and owner-only, with no temp leftovers.
        observed = os.lstat(displaced)
        self.assertTrue(stat_module.S_ISREG(observed.st_mode))
        self.assertEqual(stat_module.S_IMODE(observed.st_mode), 0o600)
        floor = provenance.parse_canonical_document(displaced.read_bytes())
        self.assertEqual(floor["trust_generation"], 1)
        self.assertFalse(
            [name for name in os.listdir(self.dir) if ".tmp-" in name]
        )

    def _post_rename_reopen_read_injection(self, on_reopen_eof):
        """Patch context firing on_reopen_eof exactly once, at the EOF
        read of the second post-rename open of the visible floor leaf
        (the final reopen/reread verification window)."""
        real_rename = os.rename
        real_open = os.open
        real_read = os.read
        state = {
            "renamed": False,
            "opens": 0,
            "reopen_fd": None,
            "swapped": False,
        }

        def tracking_rename(src, dst, **kwargs):
            real_rename(src, dst, **kwargs)
            if dst == "floor.json" and kwargs.get("dst_dir_fd") is not None:
                state["renamed"] = True

        def tracking_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if (
                state["renamed"]
                and path == "floor.json"
                and kwargs.get("dir_fd") is not None
            ):
                state["opens"] += 1
                if state["opens"] == 2:
                    state["reopen_fd"] = fd
            return fd

        def swapping_read(fd, size):
            chunk = real_read(fd, size)
            if (
                not state["swapped"]
                and state["reopen_fd"] is not None
                and fd == state["reopen_fd"]
                and chunk == b""
            ):
                state["swapped"] = True
                on_reopen_eof(real_rename)
            return chunk

        patches = (
            mock.patch.object(provenance.os, "rename", tracking_rename),
            mock.patch.object(provenance.os, "open", tracking_open),
            mock.patch.object(provenance.os, "read", swapping_read),
        )
        return patches, state

    def test_floor_swap_after_reopen_read_is_outcome_unknown(self):
        # An attacker swaps the visible floor leaf for their own file in
        # the instant after the final reopen's re-read completes: the
        # requested path no longer names the re-read floor, so the
        # result must be outcome-unknown, never accepted.
        bundle_path = self.write(
            "accepted-bundle.json",
            canonical(self.sign_bundle(self.bundle_doc())),
        )
        attacker_bytes = b'{"attacker":true}'
        attacker_path = self.write(
            "attacker.json", attacker_bytes, mode=0o600
        )
        displaced = self.dir / "displaced.json"

        def swap_leaf(real_rename):
            real_rename(self.floor_path, displaced)
            real_rename(attacker_path, self.floor_path)

        patches, state = self._post_rename_reopen_read_injection(swap_leaf)
        with patches[0], patches[1], patches[2]:
            result = self.accept(bundle_path)
        self.assertTrue(state["swapped"])
        self.assert_shape(result)
        self.assertEqual(result["status"], "outcome_unknown:floor-commit")
        self.assertEqual(provenance.provenance_exit_code(result), 2)
        # The attacker's file occupies the requested path — success must
        # not have been claimed for it.
        self.assertEqual(self.floor_path.read_bytes(), attacker_bytes)
        # The committed floor itself is intact where the attacker moved
        # it, canonical and owner-only, with no temp leftovers.
        observed = os.lstat(displaced)
        self.assertTrue(stat_module.S_ISREG(observed.st_mode))
        self.assertEqual(stat_module.S_IMODE(observed.st_mode), 0o600)
        floor = provenance.parse_canonical_document(displaced.read_bytes())
        self.assertEqual(floor["trust_generation"], 1)
        self.assertFalse(
            [name for name in os.listdir(self.dir) if ".tmp-" in name]
        )

    def test_ancestor_swap_after_reopen_read_is_outcome_unknown(self):
        # An attacker detaches and recreates the floor's parent directory
        # in the instant after the final reopen's re-read completes: the
        # committed floor is reachable only through a directory the
        # requested path no longer names, so the result must be
        # outcome-unknown, never accepted.
        bundle_path = self.write(
            "accepted-bundle.json",
            canonical(self.sign_bundle(self.bundle_doc())),
        )
        detached = self.base / f"detached-{self.id().split('.')[-1]}"

        def swap_parent(real_rename):
            real_rename(self.dir, detached)
            os.mkdir(self.dir)
            os.chmod(self.dir, 0o700)

        patches, state = self._post_rename_reopen_read_injection(swap_parent)
        with patches[0], patches[1], patches[2]:
            result = self.accept(bundle_path)
        self.assertTrue(state["swapped"])
        self.assert_shape(result)
        self.assertEqual(result["status"], "outcome_unknown:floor-commit")
        self.assertEqual(provenance.provenance_exit_code(result), 2)
        # The requested path must not have been reported as committed:
        # the recreated parent holds no floor at all.
        self.assertFalse(self.floor_path.exists())
        # The committed floor is intact, canonical, and owner-only in
        # the detached directory, with no temp leftovers beside it.
        displaced_floor = detached / "floor.json"
        observed = os.lstat(displaced_floor)
        self.assertTrue(stat_module.S_ISREG(observed.st_mode))
        self.assertEqual(stat_module.S_IMODE(observed.st_mode), 0o600)
        floor = provenance.parse_canonical_document(
            displaced_floor.read_bytes()
        )
        self.assertEqual(floor["trust_generation"], 1)
        self.assertFalse(
            [name for name in os.listdir(detached) if ".tmp-" in name]
        )

    def test_umask_cannot_loosen_or_break_floor_and_lock_modes(self):
        bundle_path, _ = self.write_chain()
        previous = os.umask(0o777)
        try:
            self.assert_success(self.accept(bundle_path), "accepted")
        finally:
            os.umask(previous)
        floor_mode = stat_module.S_IMODE(os.lstat(self.floor_path).st_mode)
        self.assertEqual(floor_mode, 0o600)
        lock_path = str(self.floor_path) + ".lock"
        lock_mode = stat_module.S_IMODE(os.lstat(lock_path).st_mode)
        self.assertEqual(lock_mode, 0o600)

    def test_world_accessible_floor_parent_is_refused(self):
        bundle_path, _ = self.write_chain()
        os.chmod(self.dir, 0o777)
        try:
            self.assert_refused(self.accept(bundle_path), "unsafe-parent")
            self.assertFalse(self.floor_path.exists())
        finally:
            os.chmod(self.dir, 0o700)


class FilesystemSafetyTests(ProvenanceFixture):
    def chain(self):
        return self.write_chain()

    def test_relative_and_traversal_paths_are_refused(self):
        bundle_path, envelope_path = self.chain()
        for bad in ("relative/root.json", "/a/../b", "/a//b", "/a/./b"):
            with mock.patch.object(provenance, "_now", return_value=NOW):
                result = provenance.verify_release(
                    bad,
                    str(bundle_path),
                    str(envelope_path),
                    str(self.floor_path),
                )
            self.assert_refused(result, "invalid-arguments")

    def test_live_store_and_recovery_paths_are_forbidden(self):
        bundle_path, envelope_path = self.chain()
        for bad in (
            "/tmp/.synapse_s2/root.json",
            "/tmp/recovery/root.json",
        ):
            with mock.patch.object(provenance, "_now", return_value=NOW):
                result = provenance.verify_release(
                    bad,
                    str(bundle_path),
                    str(envelope_path),
                    str(self.floor_path),
                )
            self.assert_refused(result, "forbidden-path")

    def test_symlinked_document_is_refused(self):
        bundle_path, envelope_path = self.chain()
        link = self.dir / "root-link.json"
        os.symlink(self.root_path, link)
        self.root_path = link
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "unsafe-file"
        )

    def test_symlinked_ancestor_is_refused(self):
        bundle_path, envelope_path = self.chain()
        real_dir = self.dir / "real"
        real_dir.mkdir()
        shutil.copyfile(self.root_path, real_dir / "root.json")
        os.chmod(real_dir / "root.json", 0o644)
        link_dir = self.dir / "link"
        os.symlink(real_dir, link_dir)
        self.root_path = link_dir / "root.json"
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "unsafe-path"
        )

    def test_hardlinked_document_is_refused(self):
        bundle_path, envelope_path = self.chain()
        os.link(self.root_path, self.dir / "root-alias.json")
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "unsafe-file"
        )

    def test_fifo_document_is_refused(self):
        bundle_path, envelope_path = self.chain()
        fifo = self.dir / "root-fifo.json"
        os.mkfifo(fifo)
        self.root_path = fifo
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "unsafe-file"
        )

    def test_group_writable_document_is_refused(self):
        bundle_path, envelope_path = self.chain()
        os.chmod(self.root_path, 0o664)
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "unsafe-file"
        )

    def test_fingerprint_change_is_a_validation_race(self):
        bundle_path, envelope_path = self.chain()
        counter = iter(range(1_000_000))

        def unstable(observed):
            return next(counter)

        with mock.patch.object(provenance, "_fingerprint", unstable):
            self.assert_refused(
                self.verify(bundle_path, envelope_path), "validation-race"
            )

    def test_missing_document_is_refused(self):
        bundle_path, envelope_path = self.chain()
        os.unlink(self.root_path)
        self.assert_refused(
            self.verify(bundle_path, envelope_path), "file-missing"
        )

    def test_forbidden_path_components_are_case_insensitive(self):
        bundle_path, envelope_path = self.chain()
        for bad in (
            "/tmp/.SYNAPSE_S2/root.json",
            "/tmp/Recovery/root.json",
            "/tmp/UPDATER-STATE/root.json",
        ):
            with mock.patch.object(provenance, "_now", return_value=NOW):
                result = provenance.verify_release(
                    bad,
                    str(bundle_path),
                    str(envelope_path),
                    str(self.floor_path),
                )
            self.assert_refused(result, "forbidden-path")

    def test_component_rename_during_read_is_a_validation_race(self):
        sub = self.dir / "sub"
        sub.mkdir()
        os.chmod(sub, 0o755)
        moved_root = sub / "root.json"
        shutil.copyfile(self.root_path, moved_root)
        os.chmod(moved_root, 0o644)
        self.root_path = moved_root
        bundle_path, envelope_path = self.chain()
        real_read = os.read
        state = {"renamed": False}

        def rename_component(fd, size):
            if not state["renamed"]:
                state["renamed"] = True
                os.rename(sub, self.dir / "sub-moved")
            return real_read(fd, size)

        with mock.patch.object(
            provenance, "_fingerprint", lambda observed: ("constant",)
        ), mock.patch.object(provenance.os, "read", rename_component):
            self.assert_refused(
                self.verify(bundle_path, envelope_path), "validation-race"
            )

    def test_leaf_swap_during_read_is_a_validation_race(self):
        bundle_path, envelope_path = self.chain()
        decoy = self.dir / "decoy.json"
        shutil.copyfile(self.root_path, decoy)
        os.chmod(decoy, 0o644)
        real_read = os.read
        state = {"swapped": False}

        def swap_leaf(fd, size):
            if not state["swapped"]:
                state["swapped"] = True
                os.rename(self.root_path, self.dir / "root-aside.json")
                os.rename(decoy, self.root_path)
            return real_read(fd, size)

        with mock.patch.object(
            provenance, "_fingerprint", lambda observed: ("constant",)
        ), mock.patch.object(provenance.os, "read", swap_leaf):
            self.assert_refused(
                self.verify(bundle_path, envelope_path), "validation-race"
            )


class ReadOnlyVerifyTripwireTests(ProvenanceFixture):
    def test_verify_never_writes_renames_unlinks_or_locks(self):
        bundle_path, envelope_path = self.write_chain()
        entries_before = sorted(os.listdir(self.dir))
        tripwires = [
            mock.patch.object(
                provenance.os,
                name,
                side_effect=AssertionError(f"os.{name} during verify"),
            )
            for name in ("write", "rename", "unlink", "fsync", "mkdir")
        ]
        tripwires.append(
            mock.patch.object(
                provenance.fcntl,
                "flock",
                side_effect=AssertionError("flock during verify"),
            )
        )
        with tripwires[0], tripwires[1], tripwires[2], tripwires[3], \
                tripwires[4], tripwires[5]:
            result = self.verify(bundle_path, envelope_path)
        self.assert_success(result, "verified")
        self.assertEqual(sorted(os.listdir(self.dir)), entries_before)

    def test_verifier_imports_are_a_closed_allowlist(self):
        names = self.imported_modules(VERIFIER_PATH)
        self.assertEqual(
            names,
            {
                "sys",
                "argparse",
                "hashlib",
                "json",
                "os",
                "re",
                "stat",
                "time",
                "fcntl",
                "cryptography",
                "cryptography.hazmat.primitives.asymmetric",
            },
        )

    def test_signer_imports_are_a_closed_allowlist(self):
        names = self.imported_modules(SIGNER_PATH)
        self.assertEqual(
            names,
            {
                "sys",
                "argparse",
                "hashlib",
                "json",
                "os",
                "re",
                "stat",
                "cryptography",
                "cryptography.hazmat.primitives.asymmetric",
            },
        )

    def imported_modules(self, path: Path) -> set:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
                names.add(node.module)
        forbidden = {
            "socket",
            "subprocess",
            "sqlite3",
            "http",
            "urllib",
            "importlib",
            "ctypes",
            "shutil",
            "pickle",
        }
        self.assertFalse(names & forbidden)
        return names

    def test_no_repository_module_is_imported(self):
        for path in (VERIFIER_PATH, SIGNER_PATH):
            for name in self.imported_modules(path):
                self.assertFalse(name.startswith("scripts"))
                self.assertNotIn("release_update", name)
                self.assertNotIn("core_service", name)
                self.assertNotIn("server", name)

    def test_bootstrap_nonclaim_is_documented(self):
        source = VERIFIER_PATH.read_text(encoding="utf-8")
        module_doc = " ".join(
            ast.get_docstring(ast.parse(source)).split()
        )
        self.assertIn(
            "cannot use a candidate verifier to authenticate itself",
            module_doc,
        )
        self.assertIn("out-of-band", module_doc)
        self.assertIn("out-of-band", provenance._BOOTSTRAP_NONCLAIM_HELP)


class ResultContractTests(ProvenanceFixture):
    def test_result_is_deterministic_and_bounded(self):
        bundle_path, envelope_path = self.write_chain()
        first = self.verify(bundle_path, envelope_path)
        second = self.verify(bundle_path, envelope_path)
        self.assertEqual(
            provenance.render_result(first), provenance.render_result(second)
        )

    def test_failure_results_carry_no_paths_keys_or_signatures(self):
        bundle_path, envelope_path = self.write_chain()
        os.chmod(self.root_path, 0o666)
        result = self.verify(bundle_path, envelope_path)
        rendered = provenance.render_result(result)
        self.assertNotIn(str(self.dir), rendered)
        self.assertNotIn(self.root_public_hex, rendered)
        self.assertIsNone(result["channel"])
        self.assertIsNone(result["bundle_sha256"])

    def test_oversize_result_collapses_deterministically(self):
        result = provenance._build_result(
            "verify-release", "verified", channel="x" * 8000
        )
        rendered = provenance.render_result(result)
        self.assertIn("unsupported:output-oversize", rendered)
        self.assertLessEqual(
            len(rendered.encode("utf-8")), provenance.MAX_RESULT_BYTES
        )

    def test_exit_code_taxonomy(self):
        for status, expected in (
            ("verified", 0),
            ("accepted", 0),
            ("recorded", 0),
            ("blocked:sequence-rollback", 3),
            ("unsupported:document-malformed", 2),
            ("outcome_unknown:floor-commit", 2),
            ("garbage", 2),
        ):
            result = provenance._build_result("verify-release", status)
            self.assertEqual(
                provenance.provenance_exit_code(result), expected, status
            )


class SignerSafetyTests(ProvenanceFixture):
    def keygen(self, role, private_name, public_name):
        return signer.keygen(
            role,
            str(self.signing_root / private_name),
            str(self.signing_root / public_name),
            str(self.signing_root),
        )

    def write_signing(self, name: str, data: bytes, mode: int = 0o600):
        path = self.signing_root / name
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, mode)
        return path

    def assert_signer_refused(self, result, token):
        self.assertEqual(set(result), set(SIGNER_RESULT_KEYS))
        self.assertEqual(result["status"], "unsupported:" + token)
        self.assertEqual(signer.signing_exit_code(result), 2)

    def test_keygen_writes_an_owner_only_raw_key(self):
        result = self.keygen("root", "root.key", "root-pub.json")
        self.assertEqual(result["status"], "generated")
        self.assertEqual(signer.signing_exit_code(result), 0)
        observed = os.lstat(self.signing_root / "root.key")
        self.assertEqual(stat_module.S_IMODE(observed.st_mode), 0o600)
        self.assertEqual(observed.st_nlink, 1)
        self.assertEqual(observed.st_size, 32)
        public_stat = os.lstat(self.signing_root / "root-pub.json")
        self.assertEqual(stat_module.S_IMODE(public_stat.st_mode), 0o644)
        public = provenance.parse_canonical_document(
            (self.signing_root / "root-pub.json").read_bytes()
        )
        _, public_key = provenance._validate_root_document(public)
        self.assertEqual(
            result["key_id"], provenance.key_id_for_public_key(public_key)
        )

    def test_keygen_never_overwrites_and_keeps_the_original_key(self):
        first = self.keygen("root", "root.key", "root-pub.json")
        self.assertEqual(first["status"], "generated")
        original = (self.signing_root / "root.key").read_bytes()
        result = self.keygen("root", "root.key", "other.json")
        self.assert_signer_refused(result, "output-exists")
        self.assertEqual(
            (self.signing_root / "root.key").read_bytes(), original
        )
        self.assertFalse((self.signing_root / "other.json").exists())

    def test_private_key_hygiene_is_enforced(self):
        self.keygen("release", "rel.key", "rel.json")
        unsigned = self.write(
            "envelope.unsigned", canonical(self.envelope_doc())
        )
        root_doc_path = self.root_path

        def sign_with(key_path):
            return signer.sign_release(
                str(key_path),
                str(root_doc_path),
                str(unsigned),
                str(self.signing_root / "signed.json"),
                str(self.signing_root),
            )

        key_path = self.signing_root / "rel.key"
        os.chmod(key_path, 0o644)
        self.assert_signer_refused(sign_with(key_path), "private-key-unsafe")
        os.chmod(key_path, 0o600)
        short = self.write_signing("short.key", b"\x00" * 16)
        self.assert_signer_refused(sign_with(short), "private-key-unsafe")
        os.link(key_path, self.signing_root / "rel-alias.key")
        self.assert_signer_refused(sign_with(key_path), "unsafe-file")
        os.unlink(self.signing_root / "rel-alias.key")
        link = self.signing_root / "rel-link.key"
        os.symlink(key_path, link)
        self.assert_signer_refused(sign_with(link), "unsafe-file")
        self.assert_signer_refused(
            sign_with("/tmp/.synapse_s2/rel.key"), "forbidden-path"
        )
        self.assert_signer_refused(
            sign_with("/tmp/recovery/rel.key"), "forbidden-path"
        )
        self.assert_signer_refused(
            sign_with("/tmp/.SYNAPSE_S2/rel.key"), "forbidden-path"
        )
        self.assert_signer_refused(
            sign_with("/tmp/Updater-State/rel.key"), "forbidden-path"
        )
        self.assert_signer_refused(sign_with("relative.key"),
                                   "invalid-arguments")
        outside = self.write("outside.key", b"\x00" * 32, mode=0o600)
        self.assert_signer_refused(
            sign_with(outside), "outside-signing-root"
        )

    def test_key_roles_are_enforced_when_signing(self):
        self.keygen("root", "root.key", "rootdoc.json")
        self.keygen("release", "rel.key", "rel.json")
        root_doc_path = self.signing_root / "rootdoc.json"
        release_doc = provenance.parse_canonical_document(
            (self.signing_root / "rel.json").read_bytes()
        )
        root_doc = provenance.parse_canonical_document(
            root_doc_path.read_bytes()
        )
        bundle = self.bundle_doc(
            root_key_id=root_doc["root_key_id"],
            delegations=[
                {
                    "key_id": release_doc["key_id"],
                    "public_key": release_doc["public_key"],
                    "role": "release",
                    "channels": ["stable"],
                    "not_before": ISSUED,
                    "not_after": EXPIRES,
                    "sequence_minimum": 1,
                    "sequence_maximum": 1_000_000,
                }
            ],
        )
        unsigned_bundle = self.write("bundle.unsigned", canonical(bundle))
        envelope = self.envelope_doc(key_id=release_doc["key_id"])
        unsigned_envelope = self.write(
            "envelope.unsigned", canonical(envelope)
        )
        result = signer.sign_trust_bundle(
            str(self.signing_root / "rel.key"),
            str(root_doc_path),
            str(unsigned_bundle),
            str(self.signing_root / "bundle.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "key-role-mismatch")
        result = signer.sign_release(
            str(self.signing_root / "root.key"),
            str(root_doc_path),
            str(unsigned_envelope),
            str(self.signing_root / "envelope.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "key-role-mismatch")
        result = signer.sign_trust_bundle(
            str(self.signing_root / "root.key"),
            str(root_doc_path),
            str(unsigned_bundle),
            str(self.signing_root / "bundle.json"),
            str(self.signing_root),
        )
        self.assertEqual(result["status"], "signed")
        result = signer.sign_release(
            str(self.signing_root / "rel.key"),
            str(root_doc_path),
            str(unsigned_envelope),
            str(self.signing_root / "envelope.json"),
            str(self.signing_root),
        )
        self.assertEqual(result["status"], "signed")

    def test_signer_rejects_wrong_document_types_and_resigning(self):
        self.keygen("root", "root.key", "rootdoc.json")
        root_doc_path = self.signing_root / "rootdoc.json"
        wrong = self.write("wrong.unsigned", canonical(self.envelope_doc()))
        result = signer.sign_trust_bundle(
            str(self.signing_root / "root.key"),
            str(root_doc_path),
            str(wrong),
            str(self.signing_root / "out1.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "document-type-mismatch")
        root_doc = provenance.parse_canonical_document(
            root_doc_path.read_bytes()
        )
        already = self.sign_bundle(
            self.bundle_doc(root_key_id=root_doc["root_key_id"])
        )
        already_path = self.write("already.json", canonical(already))
        result = signer.sign_trust_bundle(
            str(self.signing_root / "root.key"),
            str(root_doc_path),
            str(already_path),
            str(self.signing_root / "out2.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "document-already-signed")

    def test_signer_rejects_an_envelope_naming_a_different_key(self):
        self.keygen("release", "rel.key", "rel.json")
        unsigned = self.write(
            "envelope.unsigned",
            canonical(self.envelope_doc(key_id=self.other_key_id)),
        )
        result = signer.sign_release(
            str(self.signing_root / "rel.key"),
            str(self.root_path),
            str(unsigned),
            str(self.signing_root / "out.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "envelope-key-mismatch")

    def test_signer_output_carries_no_key_material_or_signatures(self):
        import re as re_module

        self.keygen("root", "root.key", "rootdoc.json")
        root_doc_path = self.signing_root / "rootdoc.json"
        root_doc = provenance.parse_canonical_document(
            root_doc_path.read_bytes()
        )
        unsigned = self.write(
            "bundle.unsigned",
            canonical(
                self.bundle_doc(
                    root_key_id=root_doc["root_key_id"], delegations=[]
                )
            ),
        )
        result = signer.sign_trust_bundle(
            str(self.signing_root / "root.key"),
            str(root_doc_path),
            str(unsigned),
            str(self.signing_root / "bundle.json"),
            str(self.signing_root),
        )
        self.assertEqual(result["status"], "signed")
        rendered = signer.render_result(result)
        private_hex = (self.signing_root / "root.key").read_bytes().hex()
        self.assertNotIn(private_hex, rendered)
        self.assertNotIn(str(self.dir), rendered)
        self.assertIsNone(
            re_module.search(r"[0-9a-f]{128}", rendered)
        )
        self.assertNotIn("\n", rendered)
        self.assertLessEqual(
            len(rendered.encode("utf-8")), signer.MAX_RESULT_BYTES
        )

    def test_signed_output_verifies_and_a_flipped_byte_does_not(self):
        self.keygen("root", "root.key", "rootdoc.json")
        self.keygen("release", "rel.key", "rel.json")
        root_doc_path = self.signing_root / "rootdoc.json"
        root_doc = provenance.parse_canonical_document(
            root_doc_path.read_bytes()
        )
        release_doc = provenance.parse_canonical_document(
            (self.signing_root / "rel.json").read_bytes()
        )
        bundle = self.bundle_doc(
            root_key_id=root_doc["root_key_id"],
            delegations=[
                {
                    "key_id": release_doc["key_id"],
                    "public_key": release_doc["public_key"],
                    "role": "release",
                    "channels": ["stable"],
                    "not_before": ISSUED,
                    "not_after": EXPIRES,
                    "sequence_minimum": 1,
                    "sequence_maximum": 1_000_000,
                }
            ],
        )
        unsigned_bundle = self.write("bundle.unsigned", canonical(bundle))
        envelope = self.envelope_doc(key_id=release_doc["key_id"])
        unsigned_envelope = self.write(
            "envelope.unsigned", canonical(envelope)
        )
        signer.sign_trust_bundle(
            str(self.signing_root / "root.key"),
            str(root_doc_path),
            str(unsigned_bundle),
            str(self.signing_root / "bundle.json"),
            str(self.signing_root),
        )
        signer.sign_release(
            str(self.signing_root / "rel.key"),
            str(root_doc_path),
            str(unsigned_envelope),
            str(self.signing_root / "envelope.json"),
            str(self.signing_root),
        )
        self.root_path = root_doc_path
        result = self.verify(
            self.signing_root / "bundle.json",
            self.signing_root / "envelope.json",
        )
        self.assert_success(result, "verified")
        signed = provenance.parse_canonical_document(
            (self.signing_root / "envelope.json").read_bytes()
        )
        flipped = dict(signed)
        tail = "00" if not signed["signature"].endswith("00") else "11"
        flipped["signature"] = signed["signature"][:-2] + tail
        flipped_path = self.write("flipped.json", canonical(flipped))
        self.assert_blocked(
            self.verify(self.signing_root / "bundle.json", flipped_path),
            "envelope-signature-invalid",
        )

    def test_signing_root_must_be_private_and_outside_any_repository(self):
        loose = self.dir / "loose-root"
        loose.mkdir()
        os.chmod(loose, 0o755)
        result = signer.keygen(
            "root",
            str(loose / "k.key"),
            str(loose / "p.json"),
            str(loose),
        )
        self.assert_signer_refused(result, "signing-root-unsafe")
        os.chmod(loose, 0o777)
        result = signer.keygen(
            "root",
            str(loose / "k.key"),
            str(loose / "p.json"),
            str(loose),
        )
        self.assert_signer_refused(result, "signing-root-unsafe")
        repo = self.dir / "repo"
        (repo / ".git").mkdir(parents=True)
        inner = repo / "signing"
        inner.mkdir()
        os.chmod(inner, 0o700)
        result = signer.keygen(
            "root",
            str(inner / "k.key"),
            str(inner / "p.json"),
            str(inner),
        )
        self.assert_signer_refused(result, "repository-path")
        marked = self.dir / "marked"
        marked.mkdir()
        os.chmod(marked, 0o700)
        (marked / ".git").write_text("gitdir: elsewhere\n")
        result = signer.keygen(
            "root",
            str(marked / "k.key"),
            str(marked / "p.json"),
            str(marked),
        )
        self.assert_signer_refused(result, "repository-path")

    def test_keygen_outputs_must_live_inside_the_signing_root(self):
        result = signer.keygen(
            "root",
            str(self.dir / "escape.key"),
            str(self.signing_root / "p.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "outside-signing-root")
        self.assertFalse((self.dir / "escape.key").exists())
        result = signer.keygen(
            "root",
            str(self.signing_root / "k.key"),
            str(self.dir / "escape.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "outside-signing-root")
        self.assertFalse((self.signing_root / "k.key").exists())

    def test_unsafe_output_parents_are_refused(self):
        shared = self.signing_root / "shared"
        shared.mkdir()
        os.chmod(shared, 0o755)
        result = signer.keygen(
            "root",
            str(shared / "k.key"),
            str(self.signing_root / "p.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "unsafe-parent")
        loose = self.signing_root / "loose"
        loose.mkdir()
        os.chmod(loose, 0o777)
        result = signer.keygen(
            "root",
            str(self.signing_root / "k.key"),
            str(loose / "p.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "unsafe-parent")
        self.assertFalse((self.signing_root / "k.key").exists())

    def test_umask_cannot_loosen_signer_output_modes(self):
        previous = os.umask(0o777)
        try:
            result = self.keygen("root", "root.key", "root-pub.json")
        finally:
            os.umask(previous)
        self.assertEqual(result["status"], "generated")
        key_mode = stat_module.S_IMODE(
            os.lstat(self.signing_root / "root.key").st_mode
        )
        public_mode = stat_module.S_IMODE(
            os.lstat(self.signing_root / "root-pub.json").st_mode
        )
        self.assertEqual(key_mode, 0o600)
        self.assertEqual(public_mode, 0o644)

    def test_malformed_unsigned_documents_are_refused_before_signing(self):
        self.keygen("root", "root.key", "rootdoc.json")
        self.keygen("release", "rel.key", "rel.json")
        root_doc_path = self.signing_root / "rootdoc.json"
        root_doc = provenance.parse_canonical_document(
            root_doc_path.read_bytes()
        )
        bad_generation = self.write(
            "bad-generation.unsigned",
            canonical(
                self.bundle_doc(
                    root_key_id=root_doc["root_key_id"], generation=0
                )
            ),
        )
        result = signer.sign_trust_bundle(
            str(self.signing_root / "root.key"),
            str(root_doc_path),
            str(bad_generation),
            str(self.signing_root / "bad1.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "bundle-invalid")
        bundle = self.bundle_doc(root_key_id=root_doc["root_key_id"])
        delegation = dict(bundle["delegations"][0])
        del delegation["sequence_minimum"]
        del delegation["sequence_maximum"]
        bundle["delegations"] = [delegation]
        missing_bounds = self.write(
            "missing-bounds.unsigned", canonical(bundle)
        )
        result = signer.sign_trust_bundle(
            str(self.signing_root / "root.key"),
            str(root_doc_path),
            str(missing_bounds),
            str(self.signing_root / "bad2.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "bundle-invalid")
        inverted = self.bundle_doc(root_key_id=root_doc["root_key_id"])
        delegation = dict(inverted["delegations"][0])
        delegation["sequence_minimum"] = 9
        delegation["sequence_maximum"] = 8
        inverted["delegations"] = [delegation]
        inverted_path = self.write("inverted.unsigned", canonical(inverted))
        result = signer.sign_trust_bundle(
            str(self.signing_root / "root.key"),
            str(root_doc_path),
            str(inverted_path),
            str(self.signing_root / "bad3.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "bundle-invalid")
        bad_sha = self.write(
            "bad-sha.unsigned",
            canonical(self.envelope_doc(source_sha="zz" * 20)),
        )
        result = signer.sign_release(
            str(self.signing_root / "rel.key"),
            str(root_doc_path),
            str(bad_sha),
            str(self.signing_root / "bad4.json"),
            str(self.signing_root),
        )
        self.assert_signer_refused(result, "envelope-invalid")
        for name in ("bad1.json", "bad2.json", "bad3.json", "bad4.json"):
            self.assertFalse((self.signing_root / name).exists())

    def test_partial_write_publishes_nothing(self):
        self.keygen("root", "root.key", "rootdoc.json")
        root_doc_path = self.signing_root / "rootdoc.json"
        root_doc = provenance.parse_canonical_document(
            root_doc_path.read_bytes()
        )
        unsigned = self.write(
            "bundle.unsigned",
            canonical(self.bundle_doc(root_key_id=root_doc["root_key_id"])),
        )
        entries_before = sorted(os.listdir(self.signing_root))
        with mock.patch.object(
            signer.os, "write", lambda fd, data: 0
        ):
            result = signer.sign_trust_bundle(
                str(self.signing_root / "root.key"),
                str(root_doc_path),
                str(unsigned),
                str(self.signing_root / "bundle.json"),
                str(self.signing_root),
            )
        self.assert_signer_refused(result, "output-write-failed")
        self.assertEqual(
            sorted(os.listdir(self.signing_root)), entries_before
        )

    def test_keygen_failure_orphans_no_secret(self):
        real_write = os.write

        def fail_private_writes(fd, data):
            if len(data) == 32:
                return 0
            return real_write(fd, data)

        with mock.patch.object(signer.os, "write", fail_private_writes):
            result = self.keygen("root", "root.key", "root-pub.json")
        self.assert_signer_refused(result, "output-write-failed")
        self.assertFalse((self.signing_root / "root.key").exists())
        self.assertFalse((self.signing_root / "root-pub.json").exists())
        self.assertFalse(
            [
                name
                for name in os.listdir(self.signing_root)
                if ".tmp-" in name
            ]
        )

    def test_post_publish_fsync_failure_is_outcome_unknown(self):
        self.keygen("root", "root.key", "rootdoc.json")
        root_doc_path = self.signing_root / "rootdoc.json"
        root_doc = provenance.parse_canonical_document(
            root_doc_path.read_bytes()
        )
        unsigned = self.write(
            "bundle.unsigned",
            canonical(self.bundle_doc(root_key_id=root_doc["root_key_id"])),
        )
        real_fsync = os.fsync
        calls = []

        def flaky_fsync(fd):
            calls.append(fd)
            if len(calls) == 2:
                raise OSError(5, "io")
            real_fsync(fd)

        with mock.patch.object(signer.os, "fsync", flaky_fsync):
            result = signer.sign_trust_bundle(
                str(self.signing_root / "root.key"),
                str(root_doc_path),
                str(unsigned),
                str(self.signing_root / "bundle.json"),
                str(self.signing_root),
            )
        self.assertEqual(set(result), set(SIGNER_RESULT_KEYS))
        self.assertEqual(result["status"], "outcome_unknown:output-publish")
        self.assertEqual(signer.signing_exit_code(result), 2)
        published = provenance.parse_canonical_document(
            (self.signing_root / "bundle.json").read_bytes()
        )
        self.assertIn("signature", published)

    def test_signer_temp_collision_never_deletes_the_unknown_file(self):
        self.keygen("root", "root.key", "rootdoc.json")
        root_doc_path = self.signing_root / "rootdoc.json"
        root_doc = provenance.parse_canonical_document(
            root_doc_path.read_bytes()
        )
        unsigned = self.write(
            "bundle.unsigned",
            canonical(self.bundle_doc(root_key_id=root_doc["root_key_id"])),
        )
        fixed_leaf = ".bundle.json.tmp-fixed"
        foreign = self.signing_root / fixed_leaf
        foreign.write_bytes(b"foreign")
        os.chmod(foreign, 0o600)
        with mock.patch.object(
            signer, "_output_temp_leaf", return_value=fixed_leaf
        ):
            result = signer.sign_trust_bundle(
                str(self.signing_root / "root.key"),
                str(root_doc_path),
                str(unsigned),
                str(self.signing_root / "bundle.json"),
                str(self.signing_root),
            )
        self.assert_signer_refused(result, "temp-exists")
        self.assertEqual(foreign.read_bytes(), b"foreign")
        self.assertFalse((self.signing_root / "bundle.json").exists())

    def bundle_signing_setup(self):
        self.keygen("root", "root.key", "rootdoc.json")
        root_doc_path = self.signing_root / "rootdoc.json"
        root_doc = provenance.parse_canonical_document(
            root_doc_path.read_bytes()
        )
        unsigned = self.write(
            "bundle.unsigned",
            canonical(self.bundle_doc(root_key_id=root_doc["root_key_id"])),
        )
        return root_doc_path, unsigned

    def sign_bundle_to(self, root_doc_path, unsigned, output_path):
        return signer.sign_trust_bundle(
            str(self.signing_root / "root.key"),
            str(root_doc_path),
            str(unsigned),
            str(output_path),
            str(self.signing_root),
        )

    def assert_no_signer_temp_leftovers(self, directory):
        self.assertFalse(
            [name for name in os.listdir(directory) if ".tmp-" in name]
        )

    def test_output_leaf_swap_after_final_read_is_outcome_unknown(self):
        # PoC case 1: the published leaf is swapped for attacker bytes
        # immediately after the signer's verification read.  Success here
        # would bless a path whose visible bytes were never verified.
        root_doc_path, unsigned = self.bundle_signing_setup()
        output_path = self.signing_root / "bundle.json"
        displaced_path = self.signing_root / "displaced.json"
        attacker_path = self.signing_root / "attacker.json"
        attacker_bytes = b'{"attacker": true}'
        attacker_path.write_bytes(attacker_bytes)
        os.chmod(attacker_path, 0o644)
        real_read = os.read
        state = {"swapped": False}

        def swap_after_first_output_read(fd, size):
            chunk = real_read(fd, size)
            if not state["swapped"] and chunk and output_path.exists():
                state["swapped"] = True
                os.rename(output_path, displaced_path)
                os.rename(attacker_path, output_path)
            return chunk

        fd_count_before = len(os.listdir("/dev/fd"))
        with mock.patch.object(
            signer.os, "read", swap_after_first_output_read
        ):
            result = self.sign_bundle_to(
                root_doc_path, unsigned, output_path
            )
        fd_count_after = len(os.listdir("/dev/fd"))
        self.assertTrue(state["swapped"])
        self.assertEqual(set(result), set(SIGNER_RESULT_KEYS))
        self.assertEqual(result["status"], "outcome_unknown:output-publish")
        self.assertEqual(signer.signing_exit_code(result), 2)
        self.assertEqual(fd_count_after, fd_count_before)
        # The race is honestly reported, never blessed or rolled back:
        # the requested path holds the attacker bytes and the trusted
        # signed document sits displaced, exactly as the race left them.
        self.assertEqual(output_path.read_bytes(), attacker_bytes)
        displaced = provenance.parse_canonical_document(
            displaced_path.read_bytes()
        )
        self.assertIn("signature", displaced)
        self.assertEqual(
            stat_module.S_IMODE(os.lstat(displaced_path).st_mode), 0o644
        )
        self.assert_no_signer_temp_leftovers(self.signing_root)
        # No-clobber survives the ambiguous outcome: a rerun refuses
        # rather than overwriting whatever bears the name now.
        rerun = self.sign_bundle_to(root_doc_path, unsigned, output_path)
        self.assert_signer_refused(rerun, "output-exists")
        self.assertEqual(output_path.read_bytes(), attacker_bytes)

    def test_ancestor_swap_during_publish_link_is_outcome_unknown(self):
        # PoC case 2: an ancestor directory is renamed aside and
        # recreated while os.link runs, so the requested absolute path
        # never receives the output.  Success here would claim a publish
        # that is invisible at the requested path.
        root_doc_path, unsigned = self.bundle_signing_setup()
        outdir = self.signing_root / "out"
        outdir.mkdir()
        os.chmod(outdir, 0o700)
        detached = self.signing_root / "out-detached"
        output_path = outdir / "bundle.json"
        real_link = os.link
        state = {"swapped": False}

        def link_then_swap_ancestor(*args, **kwargs):
            real_link(*args, **kwargs)
            if not state["swapped"]:
                state["swapped"] = True
                os.rename(outdir, detached)
                os.mkdir(outdir)
                os.chmod(outdir, 0o700)

        fd_count_before = len(os.listdir("/dev/fd"))
        with mock.patch.object(signer.os, "link", link_then_swap_ancestor):
            result = self.sign_bundle_to(
                root_doc_path, unsigned, output_path
            )
        fd_count_after = len(os.listdir("/dev/fd"))
        self.assertTrue(state["swapped"])
        self.assertEqual(set(result), set(SIGNER_RESULT_KEYS))
        self.assertEqual(result["status"], "outcome_unknown:output-publish")
        self.assertEqual(signer.signing_exit_code(result), 2)
        self.assertEqual(fd_count_after, fd_count_before)
        # The requested absolute output is absent -- success would have
        # been a lie -- and the trusted bytes sit only in the detached
        # original directory, at the exact requested mode.
        self.assertFalse(output_path.exists())
        self.assertEqual(os.listdir(outdir), [])
        stranded = detached / "bundle.json"
        published = provenance.parse_canonical_document(
            stranded.read_bytes()
        )
        self.assertIn("signature", published)
        observed = os.lstat(stranded)
        self.assertEqual(stat_module.S_IMODE(observed.st_mode), 0o644)
        self.assertEqual(observed.st_nlink, 1)
        self.assert_no_signer_temp_leftovers(detached)

    def test_publish_re_proof_keeps_fd_no_clobber_and_mode_invariants(
        self,
    ):
        # The post-read re-proof must not disturb the success path: fds
        # stay balanced, the published mode is exact, and no-clobber
        # still refuses a second publish to the same name.
        root_doc_path, unsigned = self.bundle_signing_setup()
        output_path = self.signing_root / "bundle.json"
        fd_count_before = len(os.listdir("/dev/fd"))
        result = self.sign_bundle_to(root_doc_path, unsigned, output_path)
        fd_count_after = len(os.listdir("/dev/fd"))
        self.assertEqual(result["status"], "signed")
        self.assertEqual(signer.signing_exit_code(result), 0)
        self.assertEqual(fd_count_after, fd_count_before)
        observed = os.lstat(output_path)
        self.assertEqual(stat_module.S_IMODE(observed.st_mode), 0o644)
        self.assertEqual(observed.st_nlink, 1)
        published_bytes = output_path.read_bytes()
        published = provenance.parse_canonical_document(published_bytes)
        self.assertIn("signature", published)
        self.assert_no_signer_temp_leftovers(self.signing_root)
        rerun = self.sign_bundle_to(root_doc_path, unsigned, output_path)
        self.assert_signer_refused(rerun, "output-exists")
        self.assertEqual(output_path.read_bytes(), published_bytes)


class CliTests(ProvenanceFixture):
    """Subprocess tests of the hardened ``python -I`` invocation."""

    def run_cli(self, script: Path, *argv, env=None):
        process = subprocess.run(
            [sys.executable, "-I", str(script), *argv],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        return process

    def chain_args(self, bundle_path, envelope_path):
        return (
            "--root-file",
            str(self.root_path),
            "--trust-bundle",
            str(bundle_path),
            "--envelope",
            str(envelope_path),
            "--floor",
            str(self.floor_path),
        )

    def test_full_operator_flow_over_the_cli(self):
        bundle_path, envelope_path = self.write_chain()
        args = self.chain_args(bundle_path, envelope_path)
        process = self.run_cli(VERIFIER_PATH, "verify-release", *args)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, "")
        first = json.loads(process.stdout)
        self.assertEqual(first["status"], "verified")
        self.assertEqual(set(first), set(PROVENANCE_RESULT_KEYS))
        repeat = self.run_cli(VERIFIER_PATH, "verify-release", *args)
        self.assertEqual(process.stdout, repeat.stdout)
        process = self.run_cli(
            VERIFIER_PATH,
            "accept-trust-bundle",
            "--root-file",
            str(self.root_path),
            "--trust-bundle",
            str(bundle_path),
            "--floor",
            str(self.floor_path),
            "--confirm",
        )
        self.assertEqual(process.returncode, 0, process.stdout)
        self.assertEqual(json.loads(process.stdout)["status"], "accepted")
        process = self.run_cli(
            VERIFIER_PATH, "record-installed-release", *args, "--confirm"
        )
        self.assertEqual(process.returncode, 0, process.stdout)
        recorded = json.loads(process.stdout)
        self.assertEqual(recorded["status"], "recorded")
        self.assertIs(recorded["floor_advanced"], True)
        process = self.run_cli(
            VERIFIER_PATH, "record-installed-release", *args, "--confirm"
        )
        self.assertEqual(process.returncode, 0, process.stdout)
        self.assertIs(json.loads(process.stdout)["idempotent"], True)
        self.assertNotIn(str(self.dir), process.stdout)

    def test_blocked_and_refused_exit_codes_over_the_cli(self):
        bundle_path, envelope_path = self.write_chain()
        args = self.chain_args(bundle_path, envelope_path)
        process = self.run_cli(
            VERIFIER_PATH,
            "verify-release",
            *args,
            "--expected-source-sha",
            "0" * 40,
        )
        self.assertEqual(process.returncode, 3, process.stdout)
        self.assertIn("expected-source-sha-mismatch", process.stdout)
        process = self.run_cli(
            VERIFIER_PATH, "record-installed-release", *args
        )
        self.assertEqual(process.returncode, 2, process.stdout)
        self.assertIn("confirm-required", process.stdout)

    def test_invalid_arguments_yield_the_json_contract(self):
        for argv in ((), ("no-such-command",), ("verify-release",)):
            process = self.run_cli(VERIFIER_PATH, *argv)
            self.assertEqual(process.returncode, 2, process.stdout)
            result = json.loads(process.stdout)
            self.assertEqual(
                result["status"], "unsupported:invalid-arguments"
            )
            self.assertEqual(set(result), set(PROVENANCE_RESULT_KEYS))

    def test_hostile_pythonpath_cannot_hijack_imports(self):
        bundle_path, envelope_path = self.write_chain()
        hostile = self.dir / "hostile"
        hostile.mkdir()
        canary = self.dir / "canary"
        attack = (
            "import pathlib\n"
            f"pathlib.Path({str(canary)!r}).write_text('hijacked')\n"
            "raise SystemExit(13)\n"
        )
        for name in ("cryptography.py", "json.py", "hashlib.py"):
            (hostile / name).write_text(attack)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(hostile)
        process = self.run_cli(
            VERIFIER_PATH,
            "verify-release",
            *self.chain_args(bundle_path, envelope_path),
            env=env,
        )
        self.assertEqual(process.returncode, 0, process.stdout)
        self.assertIn('"status":"verified"', process.stdout)
        self.assertFalse(canary.exists())

    def test_help_documents_the_bootstrap_nonclaim(self):
        process = self.run_cli(VERIFIER_PATH, "--help")
        self.assertEqual(process.returncode, 0)
        # argparse re-wraps lines (including at hyphens); flatten first.
        flattened = " ".join(process.stdout.split()).replace("- ", "-")
        self.assertIn("out-of-band", flattened)
        self.assertIn("cannot use a candidate verifier", flattened)

    def test_signer_cli_keygen_and_invalid_arguments(self):
        process = self.run_cli(
            SIGNER_PATH,
            "keygen",
            "root",
            "--private-key-out",
            str(self.signing_root / "cli-root.key"),
            "--public-out",
            str(self.signing_root / "cli-root.json"),
            "--signing-root",
            str(self.signing_root),
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["status"], "generated")
        self.assertEqual(set(result), set(SIGNER_RESULT_KEYS))
        private_hex = (self.signing_root / "cli-root.key").read_bytes().hex()
        self.assertNotIn(private_hex, process.stdout)
        process = self.run_cli(SIGNER_PATH, "keygen", "other")
        self.assertEqual(process.returncode, 2)
        self.assertIn("unsupported:invalid-arguments", process.stdout)

    def test_signer_cli_signs_a_chain_the_verifier_cli_accepts(self):
        root_args = (
            "--signing-root",
            str(self.signing_root),
        )
        for role, key_name, public_name in (
            ("root", "cli-root.key", "cli-rootdoc.json"),
            ("release", "cli-rel.key", "cli-rel.json"),
        ):
            process = self.run_cli(
                SIGNER_PATH,
                "keygen",
                role,
                "--private-key-out",
                str(self.signing_root / key_name),
                "--public-out",
                str(self.signing_root / public_name),
                *root_args,
            )
            self.assertEqual(process.returncode, 0, process.stdout)
        root_doc_path = self.signing_root / "cli-rootdoc.json"
        root_doc = provenance.parse_canonical_document(
            root_doc_path.read_bytes()
        )
        release_doc = provenance.parse_canonical_document(
            (self.signing_root / "cli-rel.json").read_bytes()
        )
        bundle = self.bundle_doc(
            root_key_id=root_doc["root_key_id"],
            delegations=[
                {
                    "key_id": release_doc["key_id"],
                    "public_key": release_doc["public_key"],
                    "role": "release",
                    "channels": ["stable"],
                    "not_before": ISSUED,
                    "not_after": EXPIRES,
                    "sequence_minimum": 1,
                    "sequence_maximum": 1_000_000,
                }
            ],
        )
        unsigned_bundle = self.write("cli-bundle.unsigned", canonical(bundle))
        envelope = self.envelope_doc(key_id=release_doc["key_id"])
        unsigned_envelope = self.write(
            "cli-envelope.unsigned", canonical(envelope)
        )
        process = self.run_cli(
            SIGNER_PATH,
            "sign-trust-bundle",
            "--private-key",
            str(self.signing_root / "cli-root.key"),
            "--root-file",
            str(root_doc_path),
            "--input",
            str(unsigned_bundle),
            "--output",
            str(self.signing_root / "cli-bundle.json"),
            *root_args,
        )
        self.assertEqual(process.returncode, 0, process.stdout)
        self.assertEqual(json.loads(process.stdout)["status"], "signed")
        process = self.run_cli(
            SIGNER_PATH,
            "sign-release",
            "--private-key",
            str(self.signing_root / "cli-rel.key"),
            "--root-file",
            str(root_doc_path),
            "--input",
            str(unsigned_envelope),
            "--output",
            str(self.signing_root / "cli-envelope.json"),
            *root_args,
        )
        self.assertEqual(process.returncode, 0, process.stdout)
        self.assertEqual(json.loads(process.stdout)["status"], "signed")
        self.root_path = root_doc_path
        process = self.run_cli(
            VERIFIER_PATH,
            "verify-release",
            *self.chain_args(
                self.signing_root / "cli-bundle.json",
                self.signing_root / "cli-envelope.json",
            ),
        )
        self.assertEqual(process.returncode, 0, process.stdout)
        self.assertEqual(json.loads(process.stdout)["status"], "verified")


class GoldenVectorTests(ProvenanceFixture):
    """Fixed vectors pinning the exact domains and canonical encoding."""

    @staticmethod
    def golden_bundle_doc() -> dict:
        return {
            "schema": "synapse-s2.release-trust-bundle.v1",
            "root_key_id": GOLDEN_ROOT_KEY_ID,
            "generation": 1,
            "issued_at": ISSUED,
            "expires_at": EXPIRES,
            "channel_minimum_sequences": {"stable": 1},
            "delegations": [
                {
                    "key_id": GOLDEN_RELEASE_KEY_ID,
                    "public_key": GOLDEN_RELEASE_PUBLIC_HEX,
                    "role": "release",
                    "channels": ["stable"],
                    "not_before": ISSUED,
                    "not_after": EXPIRES,
                    "sequence_minimum": 1,
                    "sequence_maximum": 1_000_000,
                }
            ],
            "revoked_key_ids": [],
        }

    @staticmethod
    def golden_envelope_doc() -> dict:
        return {
            "schema": "synapse-s2.release-envelope.v1",
            "channel": "stable",
            "version": "1.2.3",
            "sequence": 5,
            "source_sha": "f" * 40,
            "product_schema": "synapse-s2.product-release-plan.v1",
            "inventory_policy_id": "inventory-policy-" + "a" * 64,
            "product_id": "product-" + "b" * 64,
            "trust_generation": 1,
            "issued_at": ISSUED + 1,
            "expires_at": EXPIRES,
            "key_id": GOLDEN_RELEASE_KEY_ID,
        }

    def test_signing_domains_are_exact_in_both_tools(self):
        bundle_domain = b"SYNAPSE-S2\x00RELEASE-TRUST-BUNDLE\x00v1\x00"
        self.assertEqual(provenance._BUNDLE_SIGNING_DOMAIN, bundle_domain)
        self.assertEqual(signer._BUNDLE_SIGNING_DOMAIN, bundle_domain)
        envelope_domain = b"SYNAPSE-S2\x00RELEASE-ENVELOPE\x00v1\x00"
        self.assertEqual(provenance._ENVELOPE_SIGNING_DOMAIN, envelope_domain)
        self.assertEqual(signer._ENVELOPE_SIGNING_DOMAIN, envelope_domain)
        key_domain = b"SYNAPSE-S2\x00ED25519-PUBLIC-KEY\x00v1\x00"
        self.assertEqual(provenance._KEY_ID_DOMAIN, key_domain)
        self.assertEqual(signer._KEY_ID_DOMAIN, key_domain)

    def test_golden_public_keys_and_key_ids(self):
        root_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            GOLDEN_ROOT_SEED
        )
        release_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            GOLDEN_RELEASE_SEED
        )
        self.assertEqual(
            root_key.public_key().public_bytes_raw().hex(),
            GOLDEN_ROOT_PUBLIC_HEX,
        )
        self.assertEqual(
            release_key.public_key().public_bytes_raw().hex(),
            GOLDEN_RELEASE_PUBLIC_HEX,
        )
        for module in (provenance, signer):
            self.assertEqual(
                module.key_id_for_public_key(GOLDEN_ROOT_PUBLIC_HEX),
                GOLDEN_ROOT_KEY_ID,
            )
            self.assertEqual(
                module.key_id_for_public_key(GOLDEN_RELEASE_PUBLIC_HEX),
                GOLDEN_RELEASE_KEY_ID,
            )

    def test_golden_signatures_are_reproduced_exactly(self):
        root_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            GOLDEN_ROOT_SEED
        )
        release_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            GOLDEN_RELEASE_SEED
        )
        bundle_payload = (
            provenance._BUNDLE_SIGNING_DOMAIN
            + provenance.canonical_bytes(self.golden_bundle_doc())
        )
        self.assertEqual(
            root_key.sign(bundle_payload).hex(), GOLDEN_BUNDLE_SIGNATURE
        )
        envelope_payload = (
            provenance._ENVELOPE_SIGNING_DOMAIN
            + provenance.canonical_bytes(self.golden_envelope_doc())
        )
        self.assertEqual(
            release_key.sign(envelope_payload).hex(),
            GOLDEN_ENVELOPE_SIGNATURE,
        )

    def test_golden_chain_verifies_end_to_end(self):
        root_doc = {
            "schema": "synapse-s2.release-root.v1",
            "root_key_id": GOLDEN_ROOT_KEY_ID,
            "root_public_key": GOLDEN_ROOT_PUBLIC_HEX,
        }
        bundle = dict(self.golden_bundle_doc())
        bundle["signature"] = GOLDEN_BUNDLE_SIGNATURE
        envelope = dict(self.golden_envelope_doc())
        envelope["signature"] = GOLDEN_ENVELOPE_SIGNATURE
        self.root_path = self.write("golden-root.json", canonical(root_doc))
        bundle_path = self.write("golden-bundle.json", canonical(bundle))
        envelope_path = self.write(
            "golden-envelope.json", canonical(envelope)
        )
        self.floor_path = self.dir / "golden-floor.json"
        result = self.verify(bundle_path, envelope_path)
        self.assert_success(result, "verified")


class V2DelegationTests(ProvenanceFixture):
    """Compact role/domain checks added without changing the v1 contract."""

    @classmethod
    def compatibility_delegation(cls, *, key_id=None, public_key=None) -> dict:
        return {
            "key_id": key_id or cls.other_key_id,
            "public_key": public_key or cls.other_public_hex,
            "role": provenance.DELEGATION_ROLE_COMPATIBILITY,
            "channels": ["stable"],
            "not_before": ISSUED,
            "not_after": EXPIRES,
            "sequence_minimum": 1,
            "sequence_maximum": 1_000_000,
        }

    @classmethod
    def v2_bundle(cls, **overrides) -> dict:
        document = cls.bundle_doc(
            schema=provenance.BUNDLE_SCHEMA_V2,
            delegations=[
                cls.bundle_doc()["delegations"][0],
                cls.compatibility_delegation(),
            ],
        )
        document.update(overrides)
        return document

    @classmethod
    def sign_v2(cls, unsigned: dict, domain=None) -> dict:
        signed = dict(unsigned)
        signed["signature"] = cls.root_private.sign(
            (domain or provenance._BUNDLE_SIGNING_DOMAIN_V2)
            + provenance.canonical_bytes(unsigned)
        ).hex()
        return signed

    def verify_bundle(self, bundle: dict, envelope=None) -> dict:
        envelope = envelope or self.sign_envelope(self.envelope_doc())
        bundle_path = self.write("bundle-v2.json", canonical(bundle))
        envelope_path = self.write("envelope-v2.json", canonical(envelope))
        return self.verify(bundle_path, envelope_path)

    def test_v1_v2_domains_are_separate_and_v1_golden_is_unchanged(self):
        self.assertEqual(
            provenance._BUNDLE_SIGNING_DOMAIN,
            b"SYNAPSE-S2\x00RELEASE-TRUST-BUNDLE\x00v1\x00",
        )
        self.assertEqual(
            provenance._BUNDLE_SIGNING_DOMAIN_V2,
            b"SYNAPSE-S2\x00RELEASE-TRUST-BUNDLE\x00v2\x00",
        )
        self.assertNotEqual(
            provenance._BUNDLE_SIGNING_DOMAIN,
            provenance._BUNDLE_SIGNING_DOMAIN_V2,
        )
        root_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            GOLDEN_ROOT_SEED
        )
        golden_payload = (
            provenance._BUNDLE_SIGNING_DOMAIN
            + provenance.canonical_bytes(GoldenVectorTests.golden_bundle_doc())
        )
        self.assertEqual(
            root_key.sign(golden_payload).hex(), GOLDEN_BUNDLE_SIGNATURE
        )

        v2_wrong_domain = self.sign_v2(
            self.v2_bundle(), provenance._BUNDLE_SIGNING_DOMAIN
        )
        self.assert_blocked(
            self.verify_bundle(v2_wrong_domain), "bundle-signature-invalid"
        )
        v1 = self.bundle_doc()
        v1_wrong_domain = dict(v1)
        v1_wrong_domain["signature"] = self.root_private.sign(
            provenance._BUNDLE_SIGNING_DOMAIN_V2 + canonical(v1)
        ).hex()
        self.assert_blocked(
            self.verify_bundle(v1_wrong_domain), "bundle-signature-invalid"
        )
        self.assert_success(
            self.verify_bundle(self.sign_v2(self.v2_bundle())), "verified"
        )

    def test_v2_requires_both_roles_and_rejects_duplicate_role_keys(self):
        release = self.bundle_doc()["delegations"][0]
        compatibility_role = self.compatibility_delegation()
        invalid_delegations = (
            [release],
            [compatibility_role],
            [release, release, compatibility_role],
            [
                release,
                self.compatibility_delegation(
                    key_id=self.release_key_id,
                    public_key=self.release_public_hex,
                ),
            ],
        )
        for delegations in invalid_delegations:
            with self.subTest(delegations=delegations):
                bundle = self.sign_v2(
                    self.v2_bundle(delegations=delegations)
                )
                self.assert_refused(
                    self.verify_bundle(bundle), "bundle-invalid"
                )

    def test_release_envelope_rejects_compatibility_role(self):
        bundle = self.sign_v2(self.v2_bundle())
        envelope = self.envelope_doc(key_id=self.other_key_id)
        envelope = self.sign_envelope(envelope, key=self.other_private)
        self.assert_blocked(
            self.verify_bundle(bundle, envelope),
            "delegation-role-mismatch",
        )


class ModuleHygieneTests(unittest.TestCase):
    def test_api_import_restores_process_state(self):
        # Capture process state immediately before a fresh isolated
        # import; the module must restore exactly what it found, no
        # matter what other test modules did to sys.path earlier.
        path_before = list(sys.path)
        bytecode_before = sys.dont_write_bytecode
        fresh = _load_module(
            "release_provenance_hygiene_probe", VERIFIER_PATH
        )
        self.assertEqual(sys.path, path_before)
        self.assertEqual(sys.dont_write_bytecode, bytecode_before)
        self.assertEqual(fresh._ORIGINAL_SYS_PATH, path_before)
        self.assertEqual(fresh._ORIGINAL_DONT_WRITE_BYTECODE, bytecode_before)

    def test_platform_gate_fails_closed(self):
        with mock.patch.object(provenance, "_PLATFORM_SUPPORTED", False):
            result = provenance.verify_release(
                "/a/root.json", "/a/bundle.json", "/a/env.json", "/a/floor"
            )
        self.assertEqual(result["status"], "unsupported:platform-unsupported")

    def test_missing_trusted_cryptography_fails_closed(self):
        with mock.patch.object(provenance, "_ED25519", None):
            result = provenance.verify_release(
                "/a/root.json", "/a/bundle.json", "/a/env.json", "/a/floor"
            )
        self.assertEqual(result["status"], "unsupported:crypto-unavailable")
        with mock.patch.object(signer, "_ED25519", None):
            result = signer.keygen("root", "/a/k", "/a/p", "/a")
        self.assertEqual(result["status"], "unsupported:crypto-unavailable")

    @unittest.skipUnless(_CRYPTO_AVAILABLE, "trusted cryptography required")
    def test_crypto_version_and_origin_are_pinned(self):
        import cryptography

        self.assertIsNotNone(provenance._import_trusted_cryptography())
        self.assertIsNotNone(signer._import_trusted_cryptography())
        with mock.patch.object(cryptography, "__version__", "49.1.0"):
            self.assertIsNone(provenance._import_trusted_cryptography())
            self.assertIsNone(signer._import_trusted_cryptography())
        with mock.patch.object(cryptography, "__version__", "49.0.0.post1"):
            self.assertIsNone(provenance._import_trusted_cryptography())
            self.assertIsNone(signer._import_trusted_cryptography())
        with mock.patch.object(
            cryptography,
            "__file__",
            "/elsewhere/cryptography/__init__.py",
        ):
            self.assertIsNone(provenance._import_trusted_cryptography())
            self.assertIsNone(signer._import_trusted_cryptography())


if __name__ == "__main__":
    unittest.main()

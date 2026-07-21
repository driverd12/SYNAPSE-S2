from __future__ import annotations

import json
import os
import stat
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core_protocol import canonical_json_bytes
from retrieval_cursor import (
    MAX_RETRIEVAL_CURSOR_BYTES,
    MAX_RETRIEVAL_CURSOR_TTL_SECONDS,
    RetrievalCursorCodec,
    RetrievalCursorContextMismatchError,
    RetrievalCursorContractMismatchError,
    RetrievalCursorExpiredError,
    RetrievalCursorFilterMismatchError,
    RetrievalCursorMalformedError,
    RetrievalCursorModeMismatchError,
    RetrievalCursorOrderingMismatchError,
    RetrievalCursorOriginMismatchError,
    RetrievalCursorScopeMismatchError,
    RetrievalCursorSnapshotMismatchError,
    RetrievalCursorSurfaceMismatchError,
    RetrievalCursorTamperedError,
    RetrievalKeyError,
    canonical_ordering,
    derive_origin_node,
    load_or_create_retrieval_key,
)


class RetrievalCursorKeyTests(unittest.TestCase):
    def test_first_creation_is_private_durable_and_stable(self) -> None:
        with TemporaryDirectory() as temporary:
            key_path = Path(temporary) / "cursor-private" / "retrieval.key"
            with patch("retrieval_cursor.os.fsync", wraps=os.fsync) as fsync:
                first = load_or_create_retrieval_key(key_path)
            second = load_or_create_retrieval_key(key_path)

            self.assertEqual(len(first), 32)
            self.assertEqual(first, second)
            self.assertEqual(key_path.read_bytes(), first)
            self.assertEqual(stat.S_IMODE(key_path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
            self.assertGreaterEqual(fsync.call_count, 2)

    def test_simultaneous_first_creators_converge_on_one_key(self) -> None:
        with TemporaryDirectory() as temporary:
            private = Path(temporary) / "cursor-private"
            private.mkdir(mode=0o700)
            key_path = private / "retrieval.key"
            with ThreadPoolExecutor(max_workers=12) as executor:
                keys = list(
                    executor.map(
                        lambda _index: load_or_create_retrieval_key(key_path),
                        range(48),
                    )
                )

            self.assertEqual(len(set(keys)), 1)
            self.assertEqual(key_path.read_bytes(), keys[0])
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
            self.assertEqual(list(private.glob(".retrieval.key.tmp-*")), [])

    def test_failed_first_creation_never_publishes_a_partial_key(self) -> None:
        with TemporaryDirectory() as temporary:
            private = Path(temporary) / "cursor-private"
            private.mkdir(mode=0o700)
            key_path = private / "retrieval.key"
            with patch("retrieval_cursor.os.fsync", side_effect=OSError("injected")):
                with self.assertRaises(RetrievalKeyError):
                    load_or_create_retrieval_key(key_path)

            self.assertFalse(key_path.exists())
            self.assertEqual(list(private.glob(".retrieval.key.tmp-*")), [])
            self.assertEqual(len(load_or_create_retrieval_key(key_path)), 32)

    def test_rejects_symlink_parent_and_symlink_key(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_parent = root / "real"
            real_parent.mkdir(mode=0o700)
            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(RetrievalKeyError):
                load_or_create_retrieval_key(linked_parent / "retrieval.key")

            target = real_parent / "target"
            target.write_bytes(b"x" * 32)
            target.chmod(0o600)
            key_path = real_parent / "retrieval.key"
            key_path.symlink_to(target)
            with self.assertRaises(RetrievalKeyError):
                load_or_create_retrieval_key(key_path)

    def test_rejects_wrong_types_hard_links_permissions_owner_and_size(self) -> None:
        cases = ("directory", "fifo", "hard-link", "wide-mode", "bad-size")
        for case in cases:
            with self.subTest(case=case), TemporaryDirectory() as temporary:
                private = Path(temporary) / "private"
                private.mkdir(mode=0o700)
                key_path = private / "retrieval.key"
                if case == "directory":
                    key_path.mkdir()
                elif case == "fifo":
                    os.mkfifo(key_path, mode=0o600)
                elif case == "hard-link":
                    source = private / "source"
                    source.write_bytes(b"x" * 32)
                    source.chmod(0o600)
                    os.link(source, key_path)
                elif case == "wide-mode":
                    key_path.write_bytes(b"x" * 32)
                    key_path.chmod(0o640)
                else:
                    key_path.write_bytes(b"short")
                    key_path.chmod(0o600)
                with self.assertRaises(RetrievalKeyError):
                    load_or_create_retrieval_key(key_path)

        with TemporaryDirectory() as temporary:
            private = Path(temporary) / "private"
            private.mkdir(mode=0o755)
            with self.assertRaises(RetrievalKeyError):
                load_or_create_retrieval_key(private / "retrieval.key")

        with TemporaryDirectory() as temporary:
            private = Path(temporary) / "private"
            private.mkdir(mode=0o700)
            key_path = private / "retrieval.key"
            key_path.write_bytes(b"x" * 32)
            key_path.chmod(0o600)
            with patch("retrieval_cursor.os.getuid", return_value=os.getuid() + 1):
                with self.assertRaises(RetrievalKeyError):
                    load_or_create_retrieval_key(key_path)


class RetrievalCursorCodecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1_000_000
        self.key = bytes(range(32))
        self.codec = RetrievalCursorCodec(self.key, clock=lambda: self.now)
        self.ordering = canonical_ordering(
            (
                {"field": "updated_at", "direction": "desc"},
                {"field": "memory_id", "direction": "desc"},
            ),
            unique_tie_breaker="memory_id",
        )
        self.arguments = {
            "surface": "memory-list",
            "response_mode": "compact",
            "context_id": "default",
            "recall_scope": "connected",
            "filters": {"node_type": "memory", "include_global": True},
            "ordering": self.ordering,
            "position": {"updated_at": 42.5, "memory_id": "s2mem_abc"},
            "snapshot_revision": "revision_7",
            "ttl_seconds": 60,
        }
        self.expectations = {
            "expected_surface": "memory-list",
            "expected_response_mode": "compact",
            "expected_context_id": "default",
            "expected_recall_scope": "connected",
            "expected_filters": {"include_global": True, "node_type": "memory"},
            "expected_ordering": self.ordering,
            "expected_snapshot_revision": "revision_7",
        }

    def _payload(self, token: str) -> dict:
        encoded = token.split(".")[1]
        raw = __import__("base64").urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        return json.loads(raw)

    def test_round_trip_is_deterministic_and_binds_every_required_field(self) -> None:
        token = self.codec.encode(**self.arguments)
        reordered = dict(self.arguments)
        reordered["filters"] = {"include_global": True, "node_type": "memory"}
        self.assertEqual(token, self.codec.encode(**reordered))
        self.assertLessEqual(len(token.encode("ascii")), MAX_RETRIEVAL_CURSOR_BYTES)

        cursor = self.codec.decode(token, **self.expectations)
        self.assertEqual(cursor.surface, "memory-list")
        self.assertEqual(cursor.response_mode, "compact")
        self.assertEqual(cursor.context_id, "default")
        self.assertEqual(cursor.recall_scope, "connected")
        self.assertEqual(cursor.filters, self.expectations["expected_filters"])
        self.assertEqual(cursor.ordering, self.ordering)
        self.assertEqual(cursor.position["memory_id"], "s2mem_abc")
        self.assertEqual(cursor.snapshot_revision, "revision_7")
        self.assertEqual(cursor.issued_at, self.now)
        self.assertEqual(cursor.expires_at, self.now + 60)
        self.assertEqual(cursor.origin_node, derive_origin_node(self.key))
        self.assertEqual(cursor.to_wire(), self._payload(token))

        authenticated = self.codec.decode(
            token,
            **{
                **self.expectations,
                "expected_filters": None,
                "expected_snapshot_revision": None,
            },
        )
        self.assertEqual(authenticated.filters, cursor.filters)
        self.assertEqual(
            authenticated.snapshot_revision,
            cursor.snapshot_revision,
        )

    def test_tamper_and_expiry_fail_closed_with_public_safe_errors(self) -> None:
        token = self.codec.encode(**self.arguments)
        prefix, payload, signature = token.split(".")
        replacement = "A" if signature[0] != "A" else "B"
        tampered = ".".join((prefix, payload, replacement + signature[1:]))
        with self.assertRaises(RetrievalCursorTamperedError) as caught:
            self.codec.decode(tampered, **self.expectations)
        self.assertEqual(
            caught.exception.to_public_error(),
            {"code": "retrieval_cursor_tampered", "retryable": False},
        )
        self.assertNotIn(token, str(caught.exception))

        self.now += 59
        self.codec.decode(token, **self.expectations)
        self.now += 1
        with self.assertRaises(RetrievalCursorExpiredError):
            self.codec.decode(token, **self.expectations)

    def test_every_binding_mismatch_has_a_typed_failure(self) -> None:
        token = self.codec.encode(**self.arguments)
        different_order = canonical_ordering(
            (
                {"field": "updated_at", "direction": "asc"},
                {"field": "memory_id", "direction": "desc"},
            ),
            unique_tie_breaker="memory_id",
        )
        cases = (
            (
                RetrievalCursorSurfaceMismatchError,
                {"expected_surface": "memory-graph"},
            ),
            (RetrievalCursorModeMismatchError, {"expected_response_mode": "full"}),
            (RetrievalCursorContextMismatchError, {"expected_context_id": "JAMES"}),
            (RetrievalCursorScopeMismatchError, {"expected_recall_scope": "local"}),
            (
                RetrievalCursorFilterMismatchError,
                {"expected_filters": {"node_type": "goal", "include_global": True}},
            ),
            (
                RetrievalCursorOrderingMismatchError,
                {"expected_ordering": different_order},
            ),
            (
                RetrievalCursorSnapshotMismatchError,
                {"expected_snapshot_revision": "revision_8"},
            ),
            (
                RetrievalCursorOriginMismatchError,
                {"expected_origin_node": "s2origin_" + ("f" * 32)},
            ),
        )
        for error_type, change in cases:
            with self.subTest(error=error_type.__name__):
                expectations = dict(self.expectations)
                expectations.update(change)
                with self.assertRaises(error_type) as caught:
                    self.codec.decode(token, **expectations)
                self.assertTrue(caught.exception.public_safe)
                self.assertEqual(str(caught.exception), caught.exception.code)

        other_contract = RetrievalCursorCodec(
            self.key,
            clock=lambda: self.now,
            token_contract_schema="synapse-s2.token-contract.v9",
            token_contract_version=9,
        )
        with self.assertRaises(RetrievalCursorContractMismatchError):
            other_contract.decode(token, **self.expectations)

    def test_distinct_local_keys_have_distinct_origins_and_reject_cross_host_tokens(self) -> None:
        other = RetrievalCursorCodec(bytes(reversed(range(32))), clock=lambda: self.now)
        token = self.codec.encode(**self.arguments)
        self.assertNotEqual(self.codec.origin_node, other.origin_node)
        with self.assertRaises(RetrievalCursorTamperedError):
            other.decode(token, **self.expectations)

        payload = self._payload(token)
        payload["origin_node"] = "s2origin_" + ("e" * 32)
        wrong_origin = self.codec._seal_payload_bytes(canonical_json_bytes(payload))
        with self.assertRaises(RetrievalCursorOriginMismatchError):
            self.codec.decode(wrong_origin, **self.expectations)

    def test_extra_missing_and_noncanonical_signed_payloads_are_rejected(self) -> None:
        token = self.codec.encode(**self.arguments)
        payload = self._payload(token)

        extra = dict(payload)
        extra["unexpected"] = True
        with self.assertRaises(RetrievalCursorMalformedError):
            self.codec.decode(
                self.codec._seal_payload_bytes(canonical_json_bytes(extra)),
                **self.expectations,
            )

        missing = dict(payload)
        missing.pop("position")
        with self.assertRaises(RetrievalCursorMalformedError):
            self.codec.decode(
                self.codec._seal_payload_bytes(canonical_json_bytes(missing)),
                **self.expectations,
            )

        noncanonical = json.dumps(payload, sort_keys=False, indent=1).encode("utf-8")
        with self.assertRaises(RetrievalCursorMalformedError):
            self.codec.decode(
                self.codec._seal_payload_bytes(noncanonical),
                **self.expectations,
            )

    def test_malformed_size_ttl_order_and_position_are_rejected(self) -> None:
        token = self.codec.encode(**self.arguments)
        malformed = (
            "",
            "not-a-cursor",
            "s2rc2.invalid!.signature",
            "x" * (MAX_RETRIEVAL_CURSOR_BYTES + 1),
            token + ".extra",
        )
        for value in malformed:
            with self.subTest(value=value[:24]):
                with self.assertRaises(RetrievalCursorMalformedError):
                    self.codec.decode(value, **self.expectations)

        for ttl in (0, MAX_RETRIEVAL_CURSOR_TTL_SECONDS + 1, True):
            with self.subTest(ttl=ttl):
                arguments = dict(self.arguments)
                arguments["ttl_seconds"] = ttl
                with self.assertRaises(RetrievalCursorMalformedError):
                    self.codec.encode(**arguments)

        for field, value in (
            ("response_mode", "diagnostic"),
            ("recall_scope", "broad"),
        ):
            with self.subTest(field=field, value=value):
                arguments = dict(self.arguments)
                arguments[field] = value
                with self.assertRaises(RetrievalCursorMalformedError):
                    self.codec.encode(**arguments)

        invalid_order = {
            "terms": [{"field": "updated_at", "direction": "desc"}],
            "unique_tie_breaker": "memory_id",
        }
        arguments = dict(self.arguments)
        arguments["ordering"] = invalid_order
        with self.assertRaises(RetrievalCursorMalformedError):
            self.codec.encode(**arguments)

        arguments = dict(self.arguments)
        arguments["position"] = {"updated_at": 42.5}
        with self.assertRaises(RetrievalCursorMalformedError):
            self.codec.encode(**arguments)

        arguments = dict(self.arguments)
        arguments["filters"] = {"oversized": "x" * 5000}
        with self.assertRaises(RetrievalCursorMalformedError):
            self.codec.encode(**arguments)

    def test_signed_out_of_policy_lifetime_and_future_issue_are_rejected(self) -> None:
        token = self.codec.encode(**self.arguments)
        payload = self._payload(token)
        payload["expires_at"] = payload["issued_at"] + MAX_RETRIEVAL_CURSOR_TTL_SECONDS + 1
        with self.assertRaises(RetrievalCursorMalformedError):
            self.codec.decode(
                self.codec._seal_payload_bytes(canonical_json_bytes(payload)),
                **self.expectations,
            )

        payload = self._payload(token)
        payload["issued_at"] = self.now + 31
        payload["expires_at"] = payload["issued_at"] + 60
        with self.assertRaises(RetrievalCursorMalformedError):
            self.codec.decode(
                self.codec._seal_payload_bytes(canonical_json_bytes(payload)),
                **self.expectations,
            )


if __name__ == "__main__":
    unittest.main()

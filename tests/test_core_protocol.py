from __future__ import annotations

import json
import os
import socket
import struct
import unittest
from unittest.mock import patch

from core_protocol import (
    LONG_RECOVERY_OPERATIONS,
    MAX_DEADLINE_HORIZON_MS,
    PROTOCOL_VERSION,
    RECOVERY_MAX_DEADLINE_HORIZON_MS,
    CoreProtocolError,
    CoreTransportError,
    build_request,
    canonical_json_bytes,
    decode_canonical_json,
    encode_frame,
    peer_uid,
    receive_frame,
    redact_for_log,
    safe_error,
    validate_request,
)


class CoreProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = bytes(range(32))

    def request(self) -> dict[str, object]:
        return build_request(
            request_id="req-123",
            caller="test-client",
            deadline_unix_ms=9_999_999_999_999,
            operation="status",
            arguments={"context_id": "default"},
            authentication_key=self.key,
        )

    def test_canonical_frame_round_trip_and_key_never_crosses_wire(self) -> None:
        request = self.request()
        frame = encode_frame(request)
        self.assertNotIn(self.key.hex().encode("ascii"), frame)
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        left.sendall(frame)
        self.assertEqual(receive_frame(right), request)

    def test_decode_rejects_noncanonical_duplicate_nan_and_deep_json(self) -> None:
        malformed = (
            b'{"a":1, "b":2}',
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
        )
        for payload in malformed:
            with self.subTest(payload=payload):
                with self.assertRaises(CoreProtocolError):
                    decode_canonical_json(payload)

        deep: object = "leaf"
        for _index in range(18):
            deep = [deep]
        with self.assertRaises(CoreProtocolError):
            canonical_json_bytes(deep)

    def test_receive_rejects_oversized_and_partial_frames(self) -> None:
        left, right = socket.socketpair()
        left.sendall(struct.pack("!I", 1_048_577))
        with self.assertRaises(CoreProtocolError):
            receive_frame(right)
        left.close()
        right.close()

        left, right = socket.socketpair()
        left.sendall(struct.pack("!I", 20) + b"{}")
        left.close()
        with self.assertRaises(CoreProtocolError):
            receive_frame(right)
        right.close()

        left, right = socket.socketpair()
        left.sendall(b"\x00\x00")
        left.close()
        with self.assertRaises(CoreProtocolError):
            receive_frame(right)
        right.close()

    def test_receive_frame_uses_one_deadline_across_header_and_payload(self) -> None:
        payload = canonical_json_bytes({"ok": True})
        connection = ScriptedSocket(
            [struct.pack("!I", len(payload)), payload],
            timeout=1.0,
        )
        with patch(
            "core_protocol.time.monotonic",
            side_effect=(100.0, 100.2, 100.8),
        ):
            self.assertEqual(receive_frame(connection), {"ok": True})

        self.assertAlmostEqual(connection.timeouts[0], 0.8)
        self.assertAlmostEqual(connection.timeouts[1], 0.2)
        self.assertEqual(connection.timeouts[-1], 1.0)

    def test_receive_frame_rejects_trickle_after_shared_deadline(self) -> None:
        payload = canonical_json_bytes({"ok": True})
        connection = ScriptedSocket(
            [struct.pack("!I", len(payload)), payload[:1], payload[1:]],
            timeout=1.0,
        )
        with patch(
            "core_protocol.time.monotonic",
            side_effect=(200.0, 200.1, 200.5, 201.0),
        ), self.assertRaises(CoreTransportError):
            receive_frame(connection)

        self.assertEqual(connection.recv_count, 2)
        self.assertEqual(connection.timeouts[-1], 1.0)

    def test_receive_frame_rejects_an_already_elapsed_explicit_deadline(self) -> None:
        connection = ScriptedSocket([], timeout=None)
        with patch("core_protocol.time.monotonic", return_value=300.0), self.assertRaises(
            CoreTransportError
        ):
            receive_frame(connection, deadline_monotonic=300.0)

        self.assertEqual(connection.recv_count, 0)
        self.assertIsNone(connection.timeouts[-1])

    def test_request_rejects_unknown_fields_bad_hmac_and_expired_deadline(self) -> None:
        request = self.request()
        request["unexpected"] = True
        with self.assertRaises(CoreProtocolError):
            validate_request(
                request,
                authentication_key=self.key,
                now_unix_ms=None,
            )

        request = self.request()
        request["request_fingerprint"] = "0" * 64
        with self.assertRaisesRegex(CoreProtocolError, "authentication_failed"):
            validate_request(
                request,
                authentication_key=self.key,
                now_unix_ms=None,
            )

        request = build_request(
            request_id="req-expired",
            caller="test-client",
            deadline_unix_ms=1_000,
            operation="status",
            arguments={},
            authentication_key=self.key,
        )
        with self.assertRaisesRegex(CoreProtocolError, "deadline_exceeded"):
            validate_request(
                request,
                authentication_key=self.key,
                now_unix_ms=1_001,
            )

    def test_only_closed_recovery_operations_receive_the_extended_deadline(self) -> None:
        now_unix_ms = 1_900_000_000_000
        self.assertEqual(MAX_DEADLINE_HORIZON_MS, 300_000)
        self.assertEqual(RECOVERY_MAX_DEADLINE_HORIZON_MS, 3_600_000)
        self.assertEqual(
            LONG_RECOVERY_OPERATIONS,
            frozenset(
                {
                    "backup_recovery_bundle",
                    "audit_capture_ledger",
                    "repair_capture_ledger",
                    "verify_recovery_bundle",
                    "restore_recovery_bundle_isolated",
                    "plan_recovery_retention",
                    "apply_recovery_retention",
                    "restore_retired_recovery",
                    "replication_create_checkpoint",
                    "replication_stage_checkpoint",
                }
            ),
        )

        for operation in sorted(LONG_RECOVERY_OPERATIONS):
            with self.subTest(operation=operation):
                accepted = build_request(
                    request_id=f"req-{operation}",
                    caller="test-client",
                    deadline_unix_ms=(
                        now_unix_ms + RECOVERY_MAX_DEADLINE_HORIZON_MS
                    ),
                    operation=operation,
                    arguments={},
                    authentication_key=self.key,
                )
                self.assertEqual(
                    validate_request(
                        accepted,
                        authentication_key=self.key,
                        now_unix_ms=now_unix_ms,
                    ),
                    accepted,
                )
                too_long = build_request(
                    request_id=f"req-too-long-{operation}",
                    caller="test-client",
                    deadline_unix_ms=(
                        now_unix_ms + RECOVERY_MAX_DEADLINE_HORIZON_MS + 1
                    ),
                    operation=operation,
                    arguments={},
                    authentication_key=self.key,
                )
                with self.assertRaises(CoreProtocolError):
                    validate_request(
                        too_long,
                        authentication_key=self.key,
                        now_unix_ms=now_unix_ms,
                    )

        ordinary_operations = (
            "health",
            "request_status",
            "replication_status",
            "approve_namespace_link",
            "replication_pair_peer",
            "replication_revoke_peer",
            "replication_record_acknowledgement",
            "backup_recovery_bundle_extra",
        )
        for operation in ordinary_operations:
            with self.subTest(ordinary_operation=operation):
                ordinary = build_request(
                    request_id=f"req-ordinary-too-long-{operation}",
                    caller="test-client",
                    deadline_unix_ms=(
                        now_unix_ms + MAX_DEADLINE_HORIZON_MS + 1
                    ),
                    operation=operation,
                    arguments={},
                    authentication_key=self.key,
                )
                with self.assertRaises(CoreProtocolError):
                    validate_request(
                        ordinary,
                        authentication_key=self.key,
                        now_unix_ms=now_unix_ms,
                    )

    def test_request_identifiers_reject_secret_shapes_without_reflection(self) -> None:
        canary = "sk-secret-identifier-12345678901234567890"
        for field in ("request_id", "caller", "operation"):
            arguments = {
                "request_id": "req-safe",
                "caller": "caller-safe",
                "operation": "status",
            }
            arguments[field] = canary
            with self.subTest(field=field), self.assertRaises(
                CoreProtocolError
            ) as raised:
                build_request(
                    **arguments,
                    deadline_unix_ms=9_999_999_999_999,
                    arguments={},
                    authentication_key=self.key,
                )
            self.assertNotIn(canary, str(raised.exception))
            self.assertNotIn(canary, repr(raised.exception))

    def test_json_encoder_rejects_nonfinite_unknown_and_huge_integer_types(self) -> None:
        for value in (float("nan"), float("inf"), object(), 2**80):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(CoreProtocolError):
                    canonical_json_bytes({"value": value})

    def test_json_failures_are_normalized_for_surrogates_and_huge_integers(self) -> None:
        for value in ("\ud800", {"\ud800": "value"}):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(CoreProtocolError):
                    canonical_json_bytes(value)
        for payload in (b'"\\ud800"', b"1" * 5_000):
            with self.subTest(payload_prefix=payload[:16]):
                with self.assertRaises(CoreProtocolError):
                    decode_canonical_json(payload)

    def test_peer_uid_is_current_user_when_host_supports_credentials(self) -> None:
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        observed = peer_uid(left)
        if observed is not None:
            self.assertEqual(observed, os.getuid())

    def test_diagnostic_redaction_removes_secret_values(self) -> None:
        canary = "sk-super-secret-canary-1234567890"
        redacted = redact_for_log(
            {"authorization": canary, "nested": [canary], "safe": PROTOCOL_VERSION}
        )
        rendered = json.dumps(redacted)
        self.assertNotIn(canary, rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_outcome_unknown_is_always_non_retryable(self) -> None:
        self.assertEqual(
            safe_error("outcome_unknown", retryable=True),
            {"code": "outcome_unknown", "retryable": False},
        )

    def test_invalid_request_is_a_content_free_safe_error(self) -> None:
        self.assertEqual(
            safe_error("invalid_request", retryable=True),
            {"code": "invalid_request", "retryable": False},
        )


class ScriptedSocket:
    def __init__(self, chunks: list[bytes], *, timeout: float | None) -> None:
        self._chunks = list(chunks)
        self._timeout = timeout
        self.timeouts: list[float | None] = []
        self.recv_count = 0

    def gettimeout(self) -> float | None:
        return self._timeout

    def settimeout(self, value: float | None) -> None:
        self._timeout = value
        self.timeouts.append(value)

    def recv(self, size: int) -> bytes:
        self.recv_count += 1
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if len(chunk) <= size:
            return chunk
        self._chunks.insert(0, chunk[size:])
        return chunk[:size]


if __name__ == "__main__":
    unittest.main()

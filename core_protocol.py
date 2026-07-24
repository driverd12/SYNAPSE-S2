from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import socket
import stat
import struct
import time
from pathlib import Path
from typing import Any, Mapping


PROTOCOL_VERSION = "synapse-core.v1"
CORE_CONFIG_VERSION = "synapse-core-config.v1"
DEFAULT_MAX_FRAME_BYTES = 1_048_576
MIN_MAX_FRAME_BYTES = 4_096
HARD_MAX_FRAME_BYTES = 4_194_304
MAX_JSON_DEPTH = 16
MAX_CONTAINER_ITEMS = 10_000
MAX_STRING_BYTES = 262_144
MAX_DEADLINE_HORIZON_MS = 300_000
RECOVERY_MAX_DEADLINE_HORIZON_MS = 3_600_000
LONG_RECOVERY_OPERATIONS = frozenset(
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
)

REQUEST_FIELDS = frozenset(
    {
        "protocol_version",
        "request_id",
        "caller",
        "deadline_unix_ms",
        "operation",
        "arguments",
        "expected_config_fingerprint",
        "request_fingerprint",
    }
)
IDENTITY_FIELDS = frozenset(
    {
        "authority_id",
        "neural_epoch",
        "config_fingerprint",
        "build_id",
        "store_identity",
        "schema_identity",
    }
)
RESPONSE_FIELDS = frozenset(
    {
        "protocol_version",
        "request_id",
        "caller",
        "operation",
        "request_fingerprint",
        "operation_sequence",
        "server_time_unix_ms",
        "identity",
        "ok",
        "result",
        "error",
    }
)
ERROR_FIELDS = frozenset({"code", "retryable"})
RECONCILIATION_FIELDS = frozenset(
    {"code", "caller", "request_id", "operation", "replay_safe"}
)

_IDENTIFIER_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_FINGERPRINT_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_SAFE_ERROR_CODES = frozenset(
    {
        "authentication_failed",
        "deadline_exceeded",
        "invalid_request",
        "operation_failed",
        "operation_unavailable",
        "outcome_unknown",
        "path_not_authorized",
        "protocol_violation",
        "request_conflict",
        "service_unavailable",
    }
)
_SECRET_PATTERNS = (
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
)
_SECRET_KEY_RE = re.compile(
    r"(?:authorization|cookie|credential|password|private[_-]?key|secret|token)",
    re.IGNORECASE,
)


class CoreProtocolError(RuntimeError):
    """A stable, content-free protocol failure safe to cross trust boundaries."""

    def __init__(self, code: str = "protocol_violation") -> None:
        normalized = code if code in _SAFE_ERROR_CODES else "protocol_violation"
        super().__init__(normalized)
        self.code = normalized


class CoreTransportError(RuntimeError):
    """A content-free transport failure."""

    def __init__(self, code: str = "service_unavailable") -> None:
        normalized = code if code in _SAFE_ERROR_CODES else "service_unavailable"
        super().__init__(normalized)
        self.code = normalized


def safe_error(code: str, *, retryable: bool = False) -> dict[str, Any]:
    """Return the only error shape allowed on the authoritative-core wire."""

    normalized = code if code in _SAFE_ERROR_CODES else "operation_failed"
    return {
        "code": normalized,
        "retryable": (
            False
            if normalized in {"invalid_request", "outcome_unknown"}
            else bool(retryable)
        ),
    }


def contains_secret_shape(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in _SECRET_PATTERNS)


def redact_for_log(value: Any, *, _depth: int = 0) -> Any:
    """Return a bounded diagnostic projection without secret values or content."""

    if _depth >= 4:
        return "[REDACTED]"
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:32]:
            key = str(raw_key)[:64]
            if _SECRET_KEY_RE.search(key):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_for_log(item, _depth=_depth + 1)
        return redacted
    if isinstance(value, (list, tuple)):
        return [redact_for_log(item, _depth=_depth + 1) for item in value[:32]]
    if isinstance(value, str):
        if contains_secret_shape(value):
            return "[REDACTED]"
        return value[:128]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return f"<{type(value).__name__}>"


def _reject_constant(_value: str) -> None:
    raise CoreProtocolError()


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoreProtocolError()
        result[key] = value
    return result


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise CoreProtocolError()
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > 9_223_372_036_854_775_807:
            raise CoreProtocolError()
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CoreProtocolError()
        return
    if isinstance(value, str):
        try:
            encoded_length = len(value.encode("utf-8"))
        except (UnicodeError, ValueError, OverflowError) as exc:
            raise CoreProtocolError() from exc
        if encoded_length > MAX_STRING_BYTES:
            raise CoreProtocolError()
        return
    if isinstance(value, list):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise CoreProtocolError()
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise CoreProtocolError()
        for key, item in value.items():
            if not isinstance(key, str):
                raise CoreProtocolError()
            try:
                encoded_key_length = len(key.encode("utf-8"))
            except (UnicodeError, ValueError, OverflowError) as exc:
                raise CoreProtocolError() from exc
            if encoded_key_length > 256:
                raise CoreProtocolError()
            _validate_json_value(item, depth=depth + 1)
        return
    raise CoreProtocolError()


def canonical_json_bytes(value: Any) -> bytes:
    try:
        _validate_json_value(value)
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except CoreProtocolError:
        raise
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError) as exc:
        raise CoreProtocolError() from exc


def decode_canonical_json(payload: bytes) -> Any:
    try:
        decoded = payload.decode("utf-8")
        value = json.loads(
            decoded,
            parse_constant=_reject_constant,
            object_pairs_hook=_object_without_duplicates,
        )
    except CoreProtocolError:
        raise
    except (UnicodeError, ValueError, OverflowError, RecursionError) as exc:
        raise CoreProtocolError() from exc
    try:
        _validate_json_value(value)
        if not hmac.compare_digest(canonical_json_bytes(value), payload):
            raise CoreProtocolError()
    except CoreProtocolError:
        raise
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError) as exc:
        raise CoreProtocolError() from exc
    return value


def encode_frame(value: Any, *, max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES) -> bytes:
    bounded_max = validate_max_frame_bytes(max_frame_bytes)
    payload = canonical_json_bytes(value)
    if not payload or len(payload) > bounded_max:
        raise CoreProtocolError()
    return struct.pack("!I", len(payload)) + payload


def _set_remaining_receive_timeout(
    connection: socket.socket,
    *,
    deadline_monotonic: float | None,
) -> None:
    if deadline_monotonic is None:
        return
    remaining_seconds = deadline_monotonic - time.monotonic()
    if remaining_seconds <= 0.0:
        raise CoreTransportError()
    try:
        connection.settimeout(remaining_seconds)
    except (OSError, TimeoutError) as exc:
        raise CoreTransportError() from exc


def _receive_exact(
    connection: socket.socket,
    size: int,
    *,
    deadline_monotonic: float | None = None,
) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        _set_remaining_receive_timeout(
            connection,
            deadline_monotonic=deadline_monotonic,
        )
        try:
            chunk = connection.recv(remaining)
        except (OSError, TimeoutError) as exc:
            raise CoreTransportError() from exc
        if not chunk:
            raise CoreProtocolError()
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_frame(
    connection: socket.socket,
    *,
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
    deadline_monotonic: float | None = None,
) -> Any:
    """Receive one frame within one absolute header-and-payload deadline.

    When no explicit monotonic deadline is supplied, a finite timeout already
    configured on the socket becomes the total frame budget. The remaining
    budget is applied before every ``recv`` so a peer cannot refresh the full
    timeout by trickling partial header or payload bytes.
    """

    bounded_max = validate_max_frame_bytes(max_frame_bytes)
    try:
        original_timeout = connection.gettimeout()
    except (OSError, TimeoutError) as exc:
        raise CoreTransportError() from exc

    socket_deadline: float | None = None
    if original_timeout is not None:
        try:
            timeout_seconds = float(original_timeout)
        except (TypeError, ValueError, OverflowError) as exc:
            raise CoreTransportError() from exc
        if not math.isfinite(timeout_seconds) or timeout_seconds < 0.0:
            raise CoreTransportError()
        socket_deadline = time.monotonic() + timeout_seconds

    if deadline_monotonic is not None:
        if (
            isinstance(deadline_monotonic, bool)
            or not isinstance(deadline_monotonic, (int, float))
            or not math.isfinite(float(deadline_monotonic))
        ):
            raise CoreTransportError()
        explicit_deadline = float(deadline_monotonic)
        effective_deadline = (
            explicit_deadline
            if socket_deadline is None
            else min(socket_deadline, explicit_deadline)
        )
    else:
        effective_deadline = socket_deadline

    try:
        header = _receive_exact(
            connection,
            4,
            deadline_monotonic=effective_deadline,
        )
        payload_size = struct.unpack("!I", header)[0]
        if payload_size <= 0 or payload_size > bounded_max:
            raise CoreProtocolError()
        payload = _receive_exact(
            connection,
            payload_size,
            deadline_monotonic=effective_deadline,
        )
        return decode_canonical_json(payload)
    finally:
        if effective_deadline is not None:
            try:
                connection.settimeout(original_timeout)
            except (OSError, TimeoutError):
                pass


def send_frame(
    connection: socket.socket,
    value: Any,
    *,
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
) -> None:
    try:
        connection.sendall(encode_frame(value, max_frame_bytes=max_frame_bytes))
    except CoreProtocolError:
        raise
    except (OSError, TimeoutError) as exc:
        raise CoreTransportError() from exc


def validate_max_frame_bytes(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CoreProtocolError()
    if value < MIN_MAX_FRAME_BYTES or value > HARD_MAX_FRAME_BYTES:
        raise CoreProtocolError()
    return value


def _identifier(value: Any) -> str:
    if (
        not isinstance(value, str)
        or _IDENTIFIER_RE.fullmatch(value) is None
        or contains_secret_shape(value)
    ):
        raise CoreProtocolError()
    return value


def _request_signing_payload(request: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: request[key]
        for key in sorted(REQUEST_FIELDS - {"request_fingerprint"})
    }


def request_fingerprint(request: Mapping[str, Any], authentication_key: bytes) -> str:
    if not isinstance(authentication_key, bytes) or len(authentication_key) < 32:
        raise CoreProtocolError("authentication_failed")
    try:
        signing_payload = _request_signing_payload(request)
    except (KeyError, TypeError) as exc:
        raise CoreProtocolError() from exc
    return hmac.new(
        authentication_key,
        canonical_json_bytes(signing_payload),
        hashlib.sha256,
    ).hexdigest()


def build_request(
    *,
    request_id: str,
    caller: str,
    deadline_unix_ms: int,
    operation: str,
    arguments: Mapping[str, Any] | None,
    authentication_key: bytes,
    expected_config_fingerprint: str | None = None,
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id,
        "caller": caller,
        "deadline_unix_ms": deadline_unix_ms,
        "operation": operation,
        "arguments": dict(arguments or {}),
        "expected_config_fingerprint": expected_config_fingerprint,
    }
    request["request_fingerprint"] = request_fingerprint(
        request,
        authentication_key,
    )
    validate_request(request, authentication_key=authentication_key, now_unix_ms=None)
    return request


def validate_request(
    value: Any,
    *,
    authentication_key: bytes,
    now_unix_ms: int | None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != REQUEST_FIELDS:
        raise CoreProtocolError()
    if value["protocol_version"] != PROTOCOL_VERSION:
        raise CoreProtocolError()
    _identifier(value["request_id"])
    _identifier(value["caller"])
    _identifier(value["operation"])
    deadline = value["deadline_unix_ms"]
    if isinstance(deadline, bool) or not isinstance(deadline, int) or deadline <= 0:
        raise CoreProtocolError()
    if not isinstance(value["arguments"], dict):
        raise CoreProtocolError()
    _validate_json_value(value["arguments"], depth=1)
    expected_config = value["expected_config_fingerprint"]
    if expected_config is not None and (
        not isinstance(expected_config, str)
        or _FINGERPRINT_RE.fullmatch(expected_config) is None
    ):
        raise CoreProtocolError()
    fingerprint = value["request_fingerprint"]
    if not isinstance(fingerprint, str) or _FINGERPRINT_RE.fullmatch(fingerprint) is None:
        raise CoreProtocolError("authentication_failed")
    expected = request_fingerprint(value, authentication_key)
    if not hmac.compare_digest(fingerprint, expected):
        raise CoreProtocolError("authentication_failed")
    if now_unix_ms is not None:
        if deadline < now_unix_ms:
            raise CoreProtocolError("deadline_exceeded")
        maximum_horizon_ms = (
            RECOVERY_MAX_DEADLINE_HORIZON_MS
            if value["operation"] in LONG_RECOVERY_OPERATIONS
            else MAX_DEADLINE_HORIZON_MS
        )
        if deadline - now_unix_ms > maximum_horizon_ms:
            raise CoreProtocolError()
    return value


def validate_identity(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or frozenset(value) != IDENTITY_FIELDS:
        raise CoreProtocolError()
    for item in value.values():
        _identifier(item)
    if _FINGERPRINT_RE.fullmatch(value["config_fingerprint"]) is None:
        raise CoreProtocolError()
    return value


def validate_response(value: Any, *, expected_request: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != RESPONSE_FIELDS:
        raise CoreProtocolError()
    if value["protocol_version"] != PROTOCOL_VERSION:
        raise CoreProtocolError()
    for key in ("request_id", "caller", "operation", "request_fingerprint"):
        if value[key] != expected_request[key]:
            raise CoreProtocolError()
    sequence = value["operation_sequence"]
    server_time = value["server_time_unix_ms"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise CoreProtocolError()
    if isinstance(server_time, bool) or not isinstance(server_time, int) or server_time <= 0:
        raise CoreProtocolError()
    validate_identity(value["identity"])
    if not isinstance(value["ok"], bool):
        raise CoreProtocolError()
    if value["ok"]:
        if value["error"] is not None:
            raise CoreProtocolError()
        _validate_json_value(value["result"], depth=1)
    else:
        if value["result"] is not None:
            raise CoreProtocolError()
        error = value["error"]
        if not isinstance(error, dict) or frozenset(error) != ERROR_FIELDS:
            raise CoreProtocolError()
        if error["code"] not in _SAFE_ERROR_CODES or not isinstance(
            error["retryable"], bool
        ):
            raise CoreProtocolError()
        if (
            error["code"] in {"invalid_request", "outcome_unknown"}
            and error["retryable"]
        ):
            raise CoreProtocolError()
    return value


def validate_reconciliation_projection(value: Any) -> dict[str, Any]:
    """Validate the only public handle for reconciling an ambiguous mutation."""

    if not isinstance(value, dict) or frozenset(value) != RECONCILIATION_FIELDS:
        raise CoreProtocolError()
    if value["code"] != "outcome_unknown" or value["replay_safe"] is not False:
        raise CoreProtocolError()
    for key in ("caller", "request_id", "operation"):
        _identifier(value[key])
    return dict(value)


def validate_private_file(path: Path, *, expected_mode: int = 0o600) -> os.stat_result:
    try:
        observed = path.lstat()
    except FileNotFoundError as exc:
        raise CoreTransportError() from exc
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
        raise CoreTransportError()
    if observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) != expected_mode:
        raise CoreTransportError()
    return observed


def validate_private_socket(path: Path) -> os.stat_result:
    try:
        parent = path.parent.lstat()
        observed = path.lstat()
    except FileNotFoundError as exc:
        raise CoreTransportError() from exc
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise CoreTransportError()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise CoreTransportError()
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISSOCK(observed.st_mode):
        raise CoreTransportError()
    if observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) != 0o600:
        raise CoreTransportError()
    return observed


def peer_uid(connection: socket.socket) -> int | None:
    """Return a Unix peer UID when the host exposes a supported credential API."""

    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        try:
            uid, _gid = getpeereid()
            return int(uid)
        except (OSError, TypeError, ValueError):
            pass
    if hasattr(socket, "SO_PEERCRED"):
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _pid, uid, _gid = struct.unpack("3i", raw[:12])
            return int(uid)
        except (OSError, TypeError, ValueError, struct.error):
            pass
    if hasattr(socket, "LOCAL_PEERCRED"):
        try:
            # Darwin's xucred begins with cr_version followed by cr_uid.
            raw = connection.getsockopt(0, socket.LOCAL_PEERCRED, 76)
            _version, uid = struct.unpack_from("@II", raw)
            return int(uid)
        except (OSError, TypeError, ValueError, struct.error):
            pass
    return None

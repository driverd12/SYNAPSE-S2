from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import math
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from core_protocol import CoreProtocolError, canonical_json_bytes, decode_canonical_json


RETRIEVAL_CURSOR_SCHEMA = "synapse-s2.retrieval-cursor.v2"
RETRIEVAL_CURSOR_VERSION = 2
RETRIEVAL_CURSOR_PREFIX = "s2rc2"
DEFAULT_TOKEN_CONTRACT_SCHEMA = "synapse-s2.token-contract.v1"
DEFAULT_TOKEN_CONTRACT_VERSION = 1
RETRIEVAL_CURSOR_KEY_BYTES = 32
MAX_RETRIEVAL_CURSOR_BYTES = 4096
DEFAULT_RETRIEVAL_CURSOR_TTL_SECONDS = 900
MIN_RETRIEVAL_CURSOR_TTL_SECONDS = 1
MAX_RETRIEVAL_CURSOR_TTL_SECONDS = 3600
MAX_RETRIEVAL_CURSOR_CLOCK_SKEW_SECONDS = 30

_SIGNING_KEY_DOMAIN = b"SYNAPSE-S2\x00retrieval-cursor-signing-key\x00v2\x00"
_SIGNATURE_DOMAIN = b"SYNAPSE-S2\x00retrieval-cursor-payload\x00v2\x00"
_ORIGIN_DOMAIN = b"SYNAPSE-S2\x00retrieval-cursor-origin\x00v1\x00"
_SAFE_IDENTIFIER_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")
_ORIGIN_RE = re.compile(r"\As2origin_[0-9a-f]{32}\Z")
_B64URL_RE = re.compile(r"\A[A-Za-z0-9_-]+\Z")
_ORDER_DIRECTIONS = frozenset({"asc", "desc"})
_RESPONSE_MODES = frozenset({"compact", "full"})
_RECALL_SCOPES = frozenset({"local", "connected", "all"})
_PAYLOAD_FIELDS = frozenset(
    {
        "schema",
        "version",
        "token_contract_schema",
        "token_contract_version",
        "surface",
        "response_mode",
        "context_id",
        "recall_scope",
        "filters",
        "ordering",
        "position",
        "snapshot_revision",
        "issued_at",
        "expires_at",
        "origin_node",
    }
)


class RetrievalKeyError(RuntimeError):
    """A local cursor key cannot be used without weakening its trust boundary."""

    code = "retrieval_cursor_key_invalid"
    public_safe = True

    def __init__(self) -> None:
        super().__init__(self.code)

    def to_public_error(self) -> dict[str, Any]:
        return {"code": self.code, "retryable": False}


class RetrievalCursorError(ValueError):
    """Base class for content-free Retrieval v2 continuation failures."""

    code = "retrieval_cursor_invalid"
    public_safe = True

    def __init__(self) -> None:
        super().__init__(self.code)

    def to_public_error(self) -> dict[str, Any]:
        return {"code": self.code, "retryable": False}


class RetrievalCursorMalformedError(RetrievalCursorError):
    code = "retrieval_cursor_malformed"


class RetrievalCursorTamperedError(RetrievalCursorError):
    code = "retrieval_cursor_tampered"


class RetrievalCursorExpiredError(RetrievalCursorError):
    code = "retrieval_cursor_expired"


class RetrievalCursorContractMismatchError(RetrievalCursorError):
    code = "retrieval_cursor_wrong_contract"


class RetrievalCursorSurfaceMismatchError(RetrievalCursorError):
    code = "retrieval_cursor_wrong_surface"


class RetrievalCursorModeMismatchError(RetrievalCursorError):
    code = "retrieval_cursor_wrong_mode"


class RetrievalCursorContextMismatchError(RetrievalCursorError):
    code = "retrieval_cursor_wrong_context"


class RetrievalCursorScopeMismatchError(RetrievalCursorError):
    code = "retrieval_cursor_wrong_scope"


class RetrievalCursorFilterMismatchError(RetrievalCursorError):
    code = "retrieval_cursor_wrong_filter"


class RetrievalCursorOrderingMismatchError(RetrievalCursorError):
    code = "retrieval_cursor_wrong_order"


class RetrievalCursorSnapshotMismatchError(RetrievalCursorError):
    code = "retrieval_cursor_stale"


class RetrievalCursorOriginMismatchError(RetrievalCursorError):
    code = "retrieval_cursor_wrong_origin"


@dataclass(frozen=True)
class RetrievalCursor:
    """One authenticated, fully validated Retrieval v2 continuation position."""

    token_contract_schema: str
    token_contract_version: int
    surface: str
    response_mode: str
    context_id: str
    recall_scope: str
    filters: dict[str, Any]
    ordering: dict[str, Any]
    position: dict[str, Any]
    snapshot_revision: str | int
    issued_at: int
    expires_at: int
    origin_node: str

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": RETRIEVAL_CURSOR_SCHEMA,
            "version": RETRIEVAL_CURSOR_VERSION,
            "token_contract_schema": self.token_contract_schema,
            "token_contract_version": self.token_contract_version,
            "surface": self.surface,
            "response_mode": self.response_mode,
            "context_id": self.context_id,
            "recall_scope": self.recall_scope,
            "filters": _canonical_object(self.filters),
            "ordering": _canonical_object(self.ordering),
            "position": _canonical_object(self.position),
            "snapshot_revision": self.snapshot_revision,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "origin_node": self.origin_node,
        }


def _mode(mode: int) -> int:
    return stat.S_IMODE(mode)


def _validate_private_parent_identity(identity: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(identity.st_mode)
        or identity.st_uid != os.getuid()
        or _mode(identity.st_mode) != 0o700
    ):
        raise RetrievalKeyError()


def _open_private_parent(path: Path) -> int:
    parent = path.parent
    created = False
    try:
        visible = parent.lstat()
    except FileNotFoundError:
        try:
            parent.mkdir(mode=0o700, parents=False)
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise RetrievalKeyError() from exc
        try:
            visible = parent.lstat()
        except OSError as exc:
            raise RetrievalKeyError() from exc
    if stat.S_ISLNK(visible.st_mode):
        raise RetrievalKeyError()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(parent, flags)
    except OSError as exc:
        raise RetrievalKeyError() from exc
    try:
        opened = os.fstat(descriptor)
        if created:
            os.fchmod(descriptor, 0o700)
            opened = os.fstat(descriptor)
        _validate_private_parent_identity(opened)
        if (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino):
            raise RetrievalKeyError()
        current = parent.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise RetrievalKeyError()
        _validate_private_parent_identity(current)
        if created:
            os.fsync(descriptor)
            try:
                ancestor = os.open(
                    parent.parent,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                )
            except OSError as exc:
                raise RetrievalKeyError() from exc
            try:
                os.fsync(ancestor)
            finally:
                os.close(ancestor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_key_identity(identity: os.stat_result) -> None:
    if (
        not stat.S_ISREG(identity.st_mode)
        or identity.st_uid != os.getuid()
        or identity.st_nlink != 1
        or _mode(identity.st_mode) != 0o600
        or identity.st_size != RETRIEVAL_CURSOR_KEY_BYTES
    ):
        raise RetrievalKeyError()


def _read_key_at(parent_descriptor: int, name: str) -> bytes | None:
    try:
        visible = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RetrievalKeyError() from exc
    if stat.S_ISLNK(visible.st_mode):
        raise RetrievalKeyError()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise RetrievalKeyError() from exc
    try:
        opened = os.fstat(descriptor)
        _validate_key_identity(opened)
        if (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino):
            raise RetrievalKeyError()
        chunks: list[bytes] = []
        remaining = RETRIEVAL_CURSOR_KEY_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        key = b"".join(chunks)
        final = os.fstat(descriptor)
        _validate_key_identity(final)
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            stat.S_ISLNK(current.st_mode)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise RetrievalKeyError()
        if len(key) != RETRIEVAL_CURSOR_KEY_BYTES:
            raise RetrievalKeyError()
        return key
    except RetrievalKeyError:
        raise
    except OSError as exc:
        raise RetrievalKeyError() from exc
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError as exc:
            raise RetrievalKeyError() from exc
        if written <= 0:
            raise RetrievalKeyError()
        view = view[written:]


def _create_key_at(parent_descriptor: int, name: str) -> bytes:
    key = secrets.token_bytes(RETRIEVAL_CURSOR_KEY_BYTES)
    temporary_name = f".{name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_descriptor)
    except OSError as exc:
        raise RetrievalKeyError() from exc
    try:
        staged: os.stat_result | None = None
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, key)
            os.fsync(descriptor)
            staged = os.fstat(descriptor)
            _validate_key_identity(staged)
        finally:
            os.close(descriptor)
        try:
            os.replace(
                temporary_name,
                name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            os.fsync(parent_descriptor)
            published = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if staged is None or (published.st_dev, published.st_ino) != (
                staged.st_dev,
                staged.st_ino,
            ):
                raise RetrievalKeyError()
            _validate_key_identity(published)
        except RetrievalKeyError:
            raise
        except OSError as exc:
            raise RetrievalKeyError() from exc
    except RetrievalKeyError:
        raise
    except OSError as exc:
        raise RetrievalKeyError() from exc
    finally:
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        except OSError:
            pass
    return key


def load_or_create_retrieval_key(path: str | os.PathLike[str]) -> bytes:
    """Load one private 32-byte key, atomically creating it on first use.

    The configured parent is the security boundary. Existing unsafe objects are
    never repaired in place. A directory advisory lock makes simultaneous first
    creators converge on the same fully written, fsynced key.
    """

    key_path = Path(path).expanduser()
    if key_path.name in {"", ".", ".."}:
        raise RetrievalKeyError()
    parent_descriptor = _open_private_parent(key_path)
    try:
        try:
            fcntl.flock(parent_descriptor, fcntl.LOCK_EX)
        except OSError as exc:
            raise RetrievalKeyError() from exc
        key = _read_key_at(parent_descriptor, key_path.name)
        if key is None:
            _create_key_at(parent_descriptor, key_path.name)
            key = _read_key_at(parent_descriptor, key_path.name)
        if key is None or len(key) != RETRIEVAL_CURSOR_KEY_BYTES:
            raise RetrievalKeyError()
        _validate_private_parent_identity(os.fstat(parent_descriptor))
        visible_parent = key_path.parent.lstat()
        opened_parent = os.fstat(parent_descriptor)
        if (
            stat.S_ISLNK(visible_parent.st_mode)
            or (visible_parent.st_dev, visible_parent.st_ino)
            != (opened_parent.st_dev, opened_parent.st_ino)
        ):
            raise RetrievalKeyError()
        _validate_private_parent_identity(visible_parent)
        return key
    finally:
        try:
            fcntl.flock(parent_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(parent_descriptor)


def derive_origin_node(local_key: bytes) -> str:
    key = _validate_local_key(local_key)
    digest = hmac.new(key, _ORIGIN_DOMAIN, hashlib.sha256).hexdigest()[:32]
    return f"s2origin_{digest}"


def canonical_ordering(
    terms: Sequence[Mapping[str, Any]],
    *,
    unique_tie_breaker: str,
) -> dict[str, Any]:
    """Build the only supported stable keyset-ordering descriptor shape."""

    descriptor = {
        "terms": [dict(term) for term in terms],
        "unique_tie_breaker": unique_tie_breaker,
    }
    return _validate_ordering(descriptor)


def _validate_local_key(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != RETRIEVAL_CURSOR_KEY_BYTES:
        raise RetrievalKeyError()
    return value


def _canonical_object(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RetrievalCursorMalformedError()
    try:
        canonical = decode_canonical_json(canonical_json_bytes(dict(value)))
    except (CoreProtocolError, TypeError, ValueError, OverflowError) as exc:
        raise RetrievalCursorMalformedError() from exc
    if not isinstance(canonical, dict):
        raise RetrievalCursorMalformedError()
    return canonical


def _safe_identifier(value: Any, *, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise RetrievalCursorMalformedError()
    if _SAFE_IDENTIFIER_RE.fullmatch(value) is None:
        raise RetrievalCursorMalformedError()
    return value


def _validate_response_mode(value: Any) -> str:
    normalized = _safe_identifier(value)
    if normalized not in _RESPONSE_MODES:
        raise RetrievalCursorMalformedError()
    return normalized


def _validate_recall_scope(value: Any) -> str:
    normalized = _safe_identifier(value)
    if normalized not in _RECALL_SCOPES:
        raise RetrievalCursorMalformedError()
    return normalized


def _validate_snapshot_revision(value: Any) -> str | int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise RetrievalCursorMalformedError()
    if isinstance(value, str):
        return _safe_identifier(value)
    if value < 0 or value > 9_223_372_036_854_775_807:
        raise RetrievalCursorMalformedError()
    return value


def _validate_ordering(value: Mapping[str, Any]) -> dict[str, Any]:
    ordering = _canonical_object(value)
    if set(ordering) != {"terms", "unique_tie_breaker"}:
        raise RetrievalCursorMalformedError()
    terms = ordering.get("terms")
    tie_breaker = _safe_identifier(ordering.get("unique_tie_breaker"))
    if not isinstance(terms, list) or not terms or len(terms) > 16:
        raise RetrievalCursorMalformedError()
    fields: list[str] = []
    normalized_terms: list[dict[str, str]] = []
    for term in terms:
        if not isinstance(term, dict) or set(term) != {"field", "direction"}:
            raise RetrievalCursorMalformedError()
        field = _safe_identifier(term.get("field"))
        direction = term.get("direction")
        if direction not in _ORDER_DIRECTIONS or field in fields:
            raise RetrievalCursorMalformedError()
        fields.append(field)
        normalized_terms.append({"field": field, "direction": str(direction)})
    if fields[-1] != tie_breaker:
        raise RetrievalCursorMalformedError()
    return {"terms": normalized_terms, "unique_tie_breaker": tie_breaker}


def _validate_position(value: Mapping[str, Any], ordering: Mapping[str, Any]) -> dict[str, Any]:
    position = _canonical_object(value)
    expected_fields = {
        str(term["field"])
        for term in ordering["terms"]
        if isinstance(term, dict) and "field" in term
    }
    if set(position) != expected_fields:
        raise RetrievalCursorMalformedError()
    for item in position.values():
        if isinstance(item, bool) or not isinstance(item, (str, int, float, type(None))):
            raise RetrievalCursorMalformedError()
        if isinstance(item, float) and not math.isfinite(item):
            raise RetrievalCursorMalformedError()
    return position


def _canonical_equal(left: Any, right: Any) -> bool:
    try:
        left_bytes = canonical_json_bytes(left)
        right_bytes = canonical_json_bytes(right)
    except CoreProtocolError as exc:
        raise RetrievalCursorMalformedError() from exc
    return hmac.compare_digest(left_bytes, right_bytes)


def _b64url_encode(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or _B64URL_RE.fullmatch(value) is None:
        raise RetrievalCursorMalformedError()
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeError) as exc:
        raise RetrievalCursorMalformedError() from exc
    if not hmac.compare_digest(_b64url_encode(decoded), value):
        raise RetrievalCursorMalformedError()
    return decoded


class RetrievalCursorCodec:
    """Issue and verify local, snapshot-bound Retrieval v2 continuations."""

    def __init__(
        self,
        local_key: bytes,
        *,
        clock: Callable[[], float] = time.time,
        token_contract_schema: str = DEFAULT_TOKEN_CONTRACT_SCHEMA,
        token_contract_version: int = DEFAULT_TOKEN_CONTRACT_VERSION,
        max_ttl_seconds: int = MAX_RETRIEVAL_CURSOR_TTL_SECONDS,
    ) -> None:
        self._local_key = _validate_local_key(local_key)
        if not callable(clock):
            raise RetrievalCursorMalformedError()
        self._clock = clock
        self.token_contract_schema = _safe_identifier(
            token_contract_schema,
            maximum=128,
        )
        if (
            isinstance(token_contract_version, bool)
            or not isinstance(token_contract_version, int)
            or token_contract_version < 1
        ):
            raise RetrievalCursorMalformedError()
        self.token_contract_version = token_contract_version
        if (
            isinstance(max_ttl_seconds, bool)
            or not isinstance(max_ttl_seconds, int)
            or not MIN_RETRIEVAL_CURSOR_TTL_SECONDS
            <= max_ttl_seconds
            <= MAX_RETRIEVAL_CURSOR_TTL_SECONDS
        ):
            raise RetrievalCursorMalformedError()
        self.max_ttl_seconds = max_ttl_seconds
        self.origin_node = derive_origin_node(self._local_key)
        self._signing_key = hmac.new(
            self._local_key,
            _SIGNING_KEY_DOMAIN,
            hashlib.sha256,
        ).digest()

    @classmethod
    def from_key_path(
        cls,
        path: str | os.PathLike[str],
        **options: Any,
    ) -> "RetrievalCursorCodec":
        return cls(load_or_create_retrieval_key(path), **options)

    def _now(self) -> int:
        try:
            observed = float(self._clock())
        except (TypeError, ValueError, OverflowError) as exc:
            raise RetrievalCursorMalformedError() from exc
        if not math.isfinite(observed) or observed < 0:
            raise RetrievalCursorMalformedError()
        return int(observed)

    def _signature(self, payload: bytes) -> bytes:
        return hmac.new(
            self._signing_key,
            _SIGNATURE_DOMAIN + payload,
            hashlib.sha256,
        ).digest()

    def _seal_payload_bytes(self, payload: bytes) -> str:
        token = ".".join(
            (
                RETRIEVAL_CURSOR_PREFIX,
                _b64url_encode(payload),
                _b64url_encode(self._signature(payload)),
            )
        )
        if len(token.encode("ascii")) > MAX_RETRIEVAL_CURSOR_BYTES:
            raise RetrievalCursorMalformedError()
        return token

    def encode(
        self,
        *,
        surface: str,
        response_mode: str,
        context_id: str,
        recall_scope: str,
        filters: Mapping[str, Any],
        ordering: Mapping[str, Any],
        position: Mapping[str, Any],
        snapshot_revision: str | int,
        ttl_seconds: int = DEFAULT_RETRIEVAL_CURSOR_TTL_SECONDS,
    ) -> str:
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or not MIN_RETRIEVAL_CURSOR_TTL_SECONDS
            <= ttl_seconds
            <= self.max_ttl_seconds
        ):
            raise RetrievalCursorMalformedError()
        normalized_ordering = _validate_ordering(ordering)
        issued_at = self._now()
        cursor = RetrievalCursor(
            token_contract_schema=self.token_contract_schema,
            token_contract_version=self.token_contract_version,
            surface=_safe_identifier(surface),
            response_mode=_validate_response_mode(response_mode),
            context_id=_safe_identifier(context_id),
            recall_scope=_validate_recall_scope(recall_scope),
            filters=_canonical_object(filters),
            ordering=normalized_ordering,
            position=_validate_position(position, normalized_ordering),
            snapshot_revision=_validate_snapshot_revision(snapshot_revision),
            issued_at=issued_at,
            expires_at=issued_at + ttl_seconds,
            origin_node=self.origin_node,
        )
        return self._seal_payload_bytes(canonical_json_bytes(cursor.to_wire()))

    def decode(
        self,
        token: str,
        *,
        expected_surface: str,
        expected_response_mode: str,
        expected_context_id: str,
        expected_recall_scope: str,
        expected_filters: Mapping[str, Any] | None,
        expected_ordering: Mapping[str, Any],
        expected_snapshot_revision: str | int | None,
        expected_origin_node: str | None = None,
    ) -> RetrievalCursor:
        if not isinstance(token, str):
            raise RetrievalCursorMalformedError()
        try:
            token_size = len(token.encode("ascii"))
        except (UnicodeError, ValueError) as exc:
            raise RetrievalCursorMalformedError() from exc
        if not 1 <= token_size <= MAX_RETRIEVAL_CURSOR_BYTES:
            raise RetrievalCursorMalformedError()
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != RETRIEVAL_CURSOR_PREFIX:
            raise RetrievalCursorMalformedError()
        payload_bytes = _b64url_decode(parts[1])
        signature = _b64url_decode(parts[2])
        if len(signature) != hashlib.sha256().digest_size:
            raise RetrievalCursorMalformedError()
        if not hmac.compare_digest(signature, self._signature(payload_bytes)):
            raise RetrievalCursorTamperedError()
        try:
            payload = decode_canonical_json(payload_bytes)
        except CoreProtocolError as exc:
            raise RetrievalCursorMalformedError() from exc
        if not isinstance(payload, dict) or set(payload) != _PAYLOAD_FIELDS:
            raise RetrievalCursorMalformedError()
        if (
            payload.get("schema") != RETRIEVAL_CURSOR_SCHEMA
            or type(payload.get("version")) is not int
            or payload.get("version") != RETRIEVAL_CURSOR_VERSION
        ):
            raise RetrievalCursorMalformedError()

        contract_schema = _safe_identifier(payload.get("token_contract_schema"))
        contract_version = payload.get("token_contract_version")
        surface = _safe_identifier(payload.get("surface"))
        response_mode = _validate_response_mode(payload.get("response_mode"))
        context_id = _safe_identifier(payload.get("context_id"))
        recall_scope = _validate_recall_scope(payload.get("recall_scope"))
        filters = _canonical_object(payload.get("filters"))
        ordering = _validate_ordering(payload.get("ordering"))
        position = _validate_position(payload.get("position"), ordering)
        snapshot_revision = _validate_snapshot_revision(payload.get("snapshot_revision"))
        issued_at = payload.get("issued_at")
        expires_at = payload.get("expires_at")
        origin_node = payload.get("origin_node")
        if (
            type(contract_version) is not int
            or contract_version < 1
            or type(issued_at) is not int
            or type(expires_at) is not int
            or issued_at < 0
            or expires_at < 0
            or not isinstance(origin_node, str)
            or _ORIGIN_RE.fullmatch(origin_node) is None
        ):
            raise RetrievalCursorMalformedError()
        lifetime = expires_at - issued_at
        if not MIN_RETRIEVAL_CURSOR_TTL_SECONDS <= lifetime <= self.max_ttl_seconds:
            raise RetrievalCursorMalformedError()

        observed_at = self._now()
        if issued_at > observed_at + MAX_RETRIEVAL_CURSOR_CLOCK_SKEW_SECONDS:
            raise RetrievalCursorMalformedError()
        if observed_at >= expires_at:
            raise RetrievalCursorExpiredError()

        if (
            contract_schema != self.token_contract_schema
            or contract_version != self.token_contract_version
        ):
            raise RetrievalCursorContractMismatchError()
        expected_origin = (
            self.origin_node if expected_origin_node is None else expected_origin_node
        )
        if not isinstance(expected_origin, str) or _ORIGIN_RE.fullmatch(expected_origin) is None:
            raise RetrievalCursorMalformedError()
        if not hmac.compare_digest(origin_node, expected_origin):
            raise RetrievalCursorOriginMismatchError()
        if surface != _safe_identifier(expected_surface):
            raise RetrievalCursorSurfaceMismatchError()
        if response_mode != _validate_response_mode(expected_response_mode):
            raise RetrievalCursorModeMismatchError()
        if context_id != _safe_identifier(expected_context_id):
            raise RetrievalCursorContextMismatchError()
        if recall_scope != _validate_recall_scope(expected_recall_scope):
            raise RetrievalCursorScopeMismatchError()
        if expected_filters is not None and not _canonical_equal(
            filters,
            _canonical_object(expected_filters),
        ):
            raise RetrievalCursorFilterMismatchError()
        if not _canonical_equal(ordering, _validate_ordering(expected_ordering)):
            raise RetrievalCursorOrderingMismatchError()
        if expected_snapshot_revision is not None and not _canonical_equal(
            snapshot_revision,
            _validate_snapshot_revision(expected_snapshot_revision),
        ):
            raise RetrievalCursorSnapshotMismatchError()

        return RetrievalCursor(
            token_contract_schema=contract_schema,
            token_contract_version=contract_version,
            surface=surface,
            response_mode=response_mode,
            context_id=context_id,
            recall_scope=recall_scope,
            filters=filters,
            ordering=ordering,
            position=position,
            snapshot_revision=snapshot_revision,
            issued_at=issued_at,
            expires_at=expires_at,
            origin_node=origin_node,
        )


def encode_retrieval_cursor(*, local_key: bytes, **arguments: Any) -> str:
    """Functional API for one-shot cursor issuance."""

    return RetrievalCursorCodec(local_key).encode(**arguments)


def decode_retrieval_cursor(
    token: str,
    *,
    local_key: bytes,
    **expectations: Any,
) -> RetrievalCursor:
    """Functional API for one-shot fail-closed cursor verification."""

    return RetrievalCursorCodec(local_key).decode(token, **expectations)


# Compatibility spelling for callers that treat this as the cursor-key store.
load_or_create_cursor_key = load_or_create_retrieval_key

from __future__ import annotations

import argparse
import copy
import json
import logging
import re
import sys
import unicodedata
from typing import Any, Iterable
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit


REDACTED_SECRET = "[REDACTED_SECRET]"
REDACTED_JWT = "[REDACTED_JWT]"
REDACTED_PRIVATE_KEY = "[REDACTED_PRIVATE_KEY]"
SECRET_SAFE_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
MAX_REDACTION_DEPTH = 32
UNTRUSTED_RAW_DIGEST_KEYS = frozenset(
    {
        "input_sha256",
        "raw_input_sha256",
        "raw_sha256",
        "raw_text_sha256",
        "payload_sha256",
        "source_text_sha256",
    }
)
_UNTRUSTED_CONTENT_DIGEST_PREFIXES = (
    "source_text",
    "content",
    "message",
    "payload",
    "prompt",
    "input",
    "text",
    "body",
    "raw",
)
_UNTRUSTED_CONTENT_DIGEST_MARKERS = frozenset(
    {"hash", "digest", "checksum", "fingerprint"}
)
_UNTRUSTED_RAW_DIGEST_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"(?P<key_quote>['\"])(?P<quoted_key>[A-Za-z][A-Za-z0-9_-]{0,255})"
    r"(?P=key_quote)|(?P<plain_key>[A-Za-z][A-Za-z0-9_-]{0,255})"
    r")\s*[:=]\s*"
    r"(?:'[^'\r\n]*'|\"[^\"\r\n]*\"|[^\s,;}{\]]+)"
)

_SENSITIVE_KEY_PARTS = {
    "token",
    "secret",
    "api_key",
    "api_token",
    "access_token",
    "refresh_token",
    "auth_token",
    "bearer_token",
    "session_token",
    "client_secret",
    "client_key",
    "access_key",
    "secret_access_key",
    "aws_access_key_id",
    "aws_secret_access_key",
    "account_key",
    "secret_key",
    "encryption_key",
    "private_key",
    "signing_key",
    "signing_secret",
    "webhook_secret",
    "password",
    "passwd",
    "passphrase",
    "authorization",
    "auth",
    "auth_header",
    "authentication",
    "bearer",
    "proxy_authorization",
    "credential",
    "credentials",
    "connection_string",
    "database_url",
    "dsn",
    "sas_token",
    "cookie",
    "set_cookie",
}
_SAFE_CREDENTIAL_ADJACENT_KEYS = {
    # These are bounded telemetry fields, not caller-defined containers for
    # credential material. Keep this allowlist deliberately exact: suffixes
    # such as ``_value``, ``_header``, or ``_hint`` remain fail-closed.
    "token_count",
    "transport_token_stored",
}
_SENSITIVE_ASSIGNMENT_KEY = (
    r"(?!(?:token[_-]?count|transport[_-]?token[_-]?stored)\b)"
    r"[_.-]*(?:[A-Za-z0-9]+[_-])*(?:"
    r"api[_-]?key|api[_-]?token|access[_-]?token|refresh[_-]?token|"
    r"auth[_-]?token|bearer[_-]?token|session[_-]?token|"
    r"client[_-]?(?:secret|key)|secret[_-]?key|private[_-]?key|"
    r"secret[_-]?access[_-]?key|access[_-]?key|account[_-]?key|"
    r"signing[_-]?(?:key|secret)|webhook[_-]?secret|"
    r"connection[_-]?string|database[_-]?url|sas[_-]?token|dsn|"
    r"token|secret|password|passwd|passphrase|"
    r"auth|authentication|bearer|authorization|"
    r"proxy[_-]?authorization|credentials?"
    r")(?:[_-][A-Za-z0-9]+)*"
)


SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        REDACTED_PRIVATE_KEY,
    ),
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*\Z",
            re.DOTALL,
        ),
        REDACTED_PRIVATE_KEY,
    ),
    (
        re.compile(
            r"(?i)\b(?:Cookie|Set-Cookie)\s*:\s*[^\r\n]+"
        ),
        "Cookie: [REDACTED_SECRET]",
    ),
    (
        re.compile(
            r"(?i)\b(?P<header>Proxy-Authorization|Authorization)\s*:\s*"
            r"(?P<scheme>[A-Za-z][A-Za-z0-9._~-]*)\s+[^\s,;]+"
        ),
        r"\g<header>: \g<scheme> [REDACTED_SECRET]",
    ),
    (
        re.compile(
            rf"(?i)(?P<quote>['\"])(?P<key>{_SENSITIVE_ASSIGNMENT_KEY})"
            rf"(?P=quote)\s*:\s*(?P<value_quote>['\"])"
            rf"(?:\\.|[^'\"\\])*(?P=value_quote)"
        ),
        r"\g<quote>\g<key>\g<quote>: \g<value_quote>[REDACTED_SECRET]\g<value_quote>",
    ),
    (
        re.compile(
            rf"(?i)\b(?P<key>{_SENSITIVE_ASSIGNMENT_KEY})\b\s*[:=]\s*"
            r"(?P<quote>['\"])(?:\\.|[^\\\r\n])*?(?P=quote)"
        ),
        r"\g<key>=\g<quote>[REDACTED_SECRET]\g<quote>",
    ),
    (
        re.compile(
            rf"(?i)\b(?P<key>{_SENSITIVE_ASSIGNMENT_KEY})\b\s*[:=]\s*"
            r"[^'\"\r\n,;}{&]+?(?="
            r"\s+(?:at|from|in)\s+/(?:Users|private|var|tmp|opt|etc|Library)/"
            r"|$|['\"\r\n,;}{&])"
        ),
        r"\g<key>=[REDACTED_SECRET]",
    ),
    (
        re.compile(
            r"(?i)\b(?P<scheme>[a-z][a-z0-9+.-]*://)"
            r"[^/\s:@]+:[^/\s@]+@"
        ),
        r"\g<scheme>[REDACTED_SECRET]@",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"), REDACTED_SECRET),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{16,}\b"), REDACTED_SECRET),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"), REDACTED_SECRET),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b"), REDACTED_SECRET),
    (re.compile(r"\bnpm_[A-Za-z0-9]{16,}\b"), REDACTED_SECRET),
    (re.compile(r"\bpypi-[A-Za-z0-9_-]{16,}\b"), REDACTED_SECRET),
    (re.compile(r"\bhf_[A-Za-z0-9]{16,}\b"), REDACTED_SECRET),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{16,}\b"), REDACTED_SECRET),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED_SECRET),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"), REDACTED_SECRET),
    (re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}\b"), REDACTED_SECRET),
    (
        re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        REDACTED_JWT,
    ),
)

_PUBLIC_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:"
    r"/(?!/)[^\r\n,;:<>'\"]+"
    r"|[A-Za-z]:\\[^\r\n,;:<>'\"]+"
    r"|\\\\[^\\\r\n,;:<>'\"]+\\[^\\\r\n,;:<>'\"]+"
    r"(?:\\[^\r\n,;:<>'\"]+)*"
    r")"
)
_PUBLIC_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>'\"]+", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+")


def _mask_public_paths(value: str) -> str:
    """Mask local absolute paths while preserving non-local URL components."""

    parts: list[str] = []
    cursor = 0
    for match in _PUBLIC_URL_RE.finditer(value):
        parts.append(_PUBLIC_PATH_RE.sub("[LOCAL_PATH]", value[cursor : match.start()]))
        url = match.group(0)
        try:
            parsed = urlsplit(url)
            query_items: list[tuple[str, str]] = []
            for key, raw_value in parse_qsl(parsed.query, keep_blank_values=True):
                decoded = unquote(raw_value)
                query_items.append(
                    (key, _PUBLIC_PATH_RE.sub("[LOCAL_PATH]", decoded))
                )
            fragment = _PUBLIC_PATH_RE.sub(
                "[LOCAL_PATH]",
                unquote(parsed.fragment),
            )
            url = urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    urlencode(query_items),
                    fragment,
                )
            )
        except Exception:
            url = _PUBLIC_PATH_RE.sub("[LOCAL_PATH]", url)
        parts.append(url)
        cursor = match.end()
    parts.append(_PUBLIC_PATH_RE.sub("[LOCAL_PATH]", value[cursor:]))
    return "".join(parts)


def _normalized_key(value: Any) -> str:
    raw = str(value or "").strip()
    raw = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", raw)
    raw = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", raw)
    text = re.sub(r"[^a-z0-9]+", "_", raw.casefold())
    return text.strip("_")


def is_sensitive_key(value: Any) -> bool:
    """Return whether a mapping key conventionally contains credential material."""

    normalized = _normalized_key(value)
    if not normalized:
        return False
    if normalized in _SAFE_CREDENTIAL_ADJACENT_KEYS:
        return False
    return any(
        normalized == part
        or normalized.startswith(f"{part}_")
        or normalized.endswith(f"_{part}")
        or f"_{part}_" in normalized
        for part in _SENSITIVE_KEY_PARTS
    )


def is_untrusted_raw_digest_key(value: Any) -> bool:
    """Return whether a key can encode an oracle over unstored raw content."""

    normalized = _normalized_key(value)
    if not normalized:
        return False
    # Exact boolean attestation used by the capture discard ledger. It records
    # that no raw-content digest was retained; it is not itself an equality
    # oracle. Keep the exception exact so value-bearing digest keys still fail
    # closed.
    if normalized == "content_digest_recorded":
        return False
    if normalized in UNTRUSTED_RAW_DIGEST_KEYS:
        return True
    for prefix in _UNTRUSTED_CONTENT_DIGEST_PREFIXES:
        boundary = f"{prefix}_"
        if not normalized.startswith(boundary):
            continue
        suffix_parts = normalized[len(boundary) :].split("_")
        return any(
            re.fullmatch(r"sha(?:1|224|256|384|512)?", part) is not None
            or part in _UNTRUSTED_CONTENT_DIGEST_MARKERS
            for part in suffix_parts
        )
    return False


def redact_capture_text(text: str) -> tuple[str, int]:
    redacted = str(text or "")
    total = 0
    for pattern, replacement in SECRET_PATTERNS:
        redacted, count = pattern.subn(replacement, redacted)
        total += int(count)
    return redacted, total


def reject_sensitive_identifier(value: Any, *, field: str) -> str:
    """Return a string identifier or reject credential-shaped input.

    Identifiers become filenames, durable index columns, request fingerprints,
    and log dimensions. Replacing a secret with a shared redaction sentinel in
    those fields would create ambiguous identities, so this boundary is
    intentionally fail-closed instead.
    """

    raw = str(value or "")
    _, redaction_count = redact_capture_text(raw)
    if redaction_count:
        raise ValueError(f"{field} must not contain credential material")
    return raw


def strip_untrusted_raw_digest_fields(
    value: Any,
    *,
    _depth: int = 0,
    _seen: set[int] | None = None,
) -> tuple[Any, int]:
    """Remove recursively nested digests derived from untrusted raw content.

    These hashes are not credentials themselves, but retaining them creates a
    durable equality oracle for content that the redaction boundary promises
    not to store. Operational checksums such as verified-backup ``sha256`` are
    deliberately preserved; only raw-input/content-labelled digest fields are
    removed.
    """

    if _depth > MAX_REDACTION_DEPTH:
        return "[REDACTED_EXCESSIVE_NESTING]", 1
    seen = _seen if _seen is not None else set()
    if isinstance(value, str):
        safe_text, removed = strip_untrusted_raw_digest_text(value)
        if removed:
            safe_text = safe_text.replace(
                "[REMOVED_RAW_DIGEST]",
                "[REMOVED_RAW_DIGEST_FIELD]",
            )
        return safe_text, removed
    if isinstance(value, (dict, list, tuple)):
        identity = id(value)
        if identity in seen:
            return "[REDACTED_RECURSION]", 1
        seen.add(identity)
        try:
            if isinstance(value, dict):
                removed = 0
                clean: dict[Any, Any] = {}
                for key, item in value.items():
                    if is_untrusted_raw_digest_key(key):
                        removed += 1
                        continue
                    safe_item, item_removed = strip_untrusted_raw_digest_fields(
                        item,
                        _depth=_depth + 1,
                        _seen=seen,
                    )
                    clean[key] = safe_item
                    removed += int(item_removed)
                return clean, removed
            clean_items: list[Any] = []
            removed = 0
            for item in value:
                safe_item, item_removed = strip_untrusted_raw_digest_fields(
                    item,
                    _depth=_depth + 1,
                    _seen=seen,
                )
                clean_items.append(safe_item)
                removed += int(item_removed)
            if isinstance(value, tuple):
                return tuple(clean_items), removed
            return clean_items, removed
        finally:
            seen.discard(identity)
    return value, 0


def strip_untrusted_raw_digest_text(text: str) -> tuple[str, int]:
    """Remove raw-content digest assignments from malformed/unstructured text."""

    raw = str(text or "")
    spans: list[tuple[int, int]] = []
    offset = 0
    # Advance from each match start rather than its end so nested-looking text
    # such as ``error: payload_sha256=...`` cannot hide the inner assignment
    # behind the outer, non-sensitive label.
    while offset < len(raw):
        match = _UNTRUSTED_RAW_DIGEST_ASSIGNMENT_RE.search(raw, offset)
        if match is None:
            break
        key = match.group("quoted_key") or match.group("plain_key") or ""
        if is_untrusted_raw_digest_key(key):
            span = match.span()
            if not spans or spans[-1] != span:
                spans.append(span)
        offset = max(offset + 1, match.start() + 1)

    if not spans:
        return raw, 0
    safe_parts: list[str] = []
    cursor = 0
    for start, end in spans:
        if start < cursor:
            continue
        safe_parts.append(raw[cursor:start])
        safe_parts.append("[REMOVED_RAW_DIGEST]")
        cursor = end
    safe_parts.append(raw[cursor:])
    return "".join(safe_parts), len(spans)


def _unique_mapping_key(key: str, existing: dict[str, Any]) -> str:
    if key not in existing:
        return key
    ordinal = 2
    while f"{key}#{ordinal}" in existing:
        ordinal += 1
    return f"{key}#{ordinal}"


def redact_sensitive_value(
    value: Any,
    *,
    _depth: int = 0,
    _seen: set[int] | None = None,
) -> tuple[Any, int]:
    """Recursively redact secret-shaped values and key-aware credential fields.

    The function is deliberately total for untrusted metadata: cycles and
    excessive nesting are replaced with a sentinel instead of raising or
    falling back to an unredacted ``repr``.
    """

    if _depth > MAX_REDACTION_DEPTH:
        return "[REDACTED_EXCESSIVE_NESTING]", 1
    if isinstance(value, str):
        return redact_capture_text(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return REDACTED_SECRET, 1

    seen = _seen if _seen is not None else set()
    if isinstance(value, (dict, list, tuple, set, frozenset)):
        identity = id(value)
        if identity in seen:
            return "[REDACTED_RECURSION]", 1
        seen.add(identity)
        try:
            if isinstance(value, dict):
                total = 0
                redacted: dict[str, Any] = {}
                for raw_key, item in value.items():
                    key, key_redactions = redact_capture_text(str(raw_key))
                    key = _unique_mapping_key(key, redacted)
                    total += int(key_redactions)
                    if is_sensitive_key(raw_key):
                        redacted[key] = REDACTED_SECRET
                        total += 1
                        continue
                    safe_item, count = redact_sensitive_value(
                        item,
                        _depth=_depth + 1,
                        _seen=seen,
                    )
                    redacted[key] = safe_item
                    total += int(count)
                return redacted, total

            total = 0
            redacted_items: list[Any] = []
            for item in value:
                safe_item, count = redact_sensitive_value(
                    item,
                    _depth=_depth + 1,
                    _seen=seen,
                )
                redacted_items.append(safe_item)
                total += int(count)
            if isinstance(value, tuple):
                return tuple(redacted_items), total
            return redacted_items, total
        finally:
            seen.discard(identity)

    try:
        json.dumps(value, allow_nan=False)
    except Exception:
        # Unknown objects are untrusted. Redact their string form, and if it
        # contains no recognizable secret return only its type rather than an
        # arbitrary repr that may embed credentials.
        text, count = redact_capture_text(str(value))
        if count:
            return text, count
        return f"[UNSERIALIZABLE_{type(value).__name__}]", 1
    return value, 0


def safe_public_error(
    error: BaseException | str,
    *,
    fallback: str = "request failed",
    max_chars: int = 240,
) -> str:
    """Return a bounded, redacted error suitable for an API or MCP response."""

    raw = str(error or "")
    redacted, _ = redact_capture_text(raw)
    redacted = _mask_public_paths(redacted)
    redacted = _CONTROL_RE.sub(" ", redacted)
    compact = " ".join(redacted.split()) or str(fallback or "request failed")
    limit = max(32, min(int(max_chars), 2_048))
    if len(compact) > limit:
        compact = compact[: max(0, limit - 1)].rstrip() + "…"
    return compact


def validate_public_identifier(
    value: Any,
    *,
    field: str,
    max_chars: int,
) -> str:
    """Require an identifier to survive the public redaction boundary exactly."""

    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string identifier")
    raw = reject_sensitive_identifier(value, field=field)
    if (
        not raw
        or raw != raw.strip()
        or len(raw) > int(max_chars)
        or any(unicodedata.category(char).startswith("C") for char in raw)
        or safe_public_error(
            raw,
            fallback="invalid identifier",
            max_chars=int(max_chars),
        )
        != raw
    ):
        raise ValueError(f"{field} is invalid")
    return raw


def mask_public_paths(value: Any) -> str:
    """Mask absolute local filesystem paths without otherwise rewriting text."""

    return _mask_public_paths(str(value or ""))


def secret_safe_cli_text(value: Any) -> str:
    """Redact argparse output while preserving its normal line formatting."""

    redacted, _ = redact_capture_text(str(value or ""))
    redacted = _mask_public_paths(redacted)
    return _CONTROL_RE.sub(" ", redacted)


class SecretSafeArgumentParser(argparse.ArgumentParser):
    """Stock argparse behavior with a secret-safe output boundary.

    ``argparse`` includes rejected user values in type-conversion and
    unknown-argument errors.  Sanitizing its single output hook protects usage,
    help, and exit-2 errors, including parsers created for subcommands.
    """

    def _print_message(self, message: str | None, file: Any = None) -> None:
        if not message:
            return
        target = file if file is not None else sys.stderr
        target.write(secret_safe_cli_text(message))


class SecretRedactingFormatter(logging.Formatter):
    """Logging formatter that redacts both messages and traceback text."""

    def format(self, record: logging.LogRecord) -> str:
        safe_record = copy.copy(record)
        message, _ = redact_capture_text(record.getMessage())
        safe_record.msg = message
        safe_record.args = ()
        safe_record.exc_text = None
        return super().format(safe_record)

    def formatException(self, exc_info: Any) -> str:
        rendered = super().formatException(exc_info)
        return redact_capture_text(rendered)[0]


def install_secret_safe_formatters(
    handlers: Iterable[logging.Handler],
    *,
    format_string: str = SECRET_SAFE_LOG_FORMAT,
) -> None:
    for handler in handlers:
        handler.setFormatter(SecretRedactingFormatter(format_string))

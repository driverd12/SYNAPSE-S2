from __future__ import annotations

import json
import re
from typing import Any


SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|token|secret|password)\b\s*[:=]\s*['\"]?([^'\"\s,;}{]+)['\"]?"
        ),
        r"\1=[REDACTED_SECRET]",
    ),
    (
        re.compile(
            r"(?i)(['\"])(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|token|secret|password)\1\s*:\s*(['\"])[^'\"]+\3"
        ),
        r"\1\2\1: \3[REDACTED_SECRET]\3",
    ),
    (
        re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]+"),
        "Authorization: Bearer [REDACTED_SECRET]",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{16,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{16,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_SECRET]"),
    (
        re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "[REDACTED_JWT]",
    ),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
)


def redact_capture_text(text: str) -> tuple[str, int]:
    redacted = str(text or "")
    total = 0
    for pattern, replacement in SECRET_PATTERNS:
        redacted, count = pattern.subn(replacement, redacted)
        total += int(count)
    return redacted, total


def redact_sensitive_value(value: Any) -> tuple[Any, int]:
    if isinstance(value, str):
        return redact_capture_text(value)
    if isinstance(value, dict):
        total = 0
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            safe_item, count = redact_sensitive_value(item)
            redacted[str(key)] = safe_item
            total += count
        return redacted, total
    if isinstance(value, list):
        total = 0
        redacted_list: list[Any] = []
        for item in value:
            safe_item, count = redact_sensitive_value(item)
            redacted_list.append(safe_item)
            total += count
        return redacted_list, total
    if isinstance(value, tuple):
        safe_list, total = redact_sensitive_value(list(value))
        return tuple(safe_list), total
    try:
        json.dumps(value)
    except Exception:
        text, count = redact_capture_text(str(value))
        return text, count
    return value, 0

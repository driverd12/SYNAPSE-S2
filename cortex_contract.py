from __future__ import annotations

import json
import re
from collections.abc import Mapping

from redaction import redact_sensitive_value, strip_untrusted_raw_digest_fields


CONCRETE_VALIDATION_EVIDENCE_KEYS = frozenset(
    {
        "artifact",
        "artifact_path",
        "artifacts",
        "check",
        "checks",
        "command",
        "commands",
        "commit",
        "output",
        "output_summary",
        "proof",
        "report",
        "test_command",
        "test_output",
        "tests",
        "validated_by",
        "validation",
        "verification",
    }
)
_NON_EVIDENCE_SENTINEL_RE = re.compile(
    r"\[(?:REDACTED_[A-Z0-9_]+|REMOVED_RAW_DIGEST(?:_FIELD)?|"
    r"UNSERIALIZABLE_[A-Za-z0-9_]+)\]"
)


def _has_surviving_evidence_value(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(_has_surviving_evidence_value(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_has_surviving_evidence_value(item) for item in value)
    if value is None or isinstance(value, bool):
        return False
    text = str(value).strip()
    if _NON_EVIDENCE_SENTINEL_RE.search(text):
        return False
    return bool(text)


def has_concrete_validation_evidence(evidence: object) -> bool:
    """Return whether evidence contains a recognized non-empty validation proof."""

    if not isinstance(evidence, Mapping):
        return False
    for key, value in evidence.items():
        normalized_key = str(key or "").strip().lower().replace("-", "_")
        if normalized_key not in CONCRETE_VALIDATION_EVIDENCE_KEYS:
            continue
        if _has_surviving_evidence_value(value):
            return True
    return False


def canonicalize_validation_evidence(evidence: object) -> dict[str, object]:
    """Apply the exact safe evidence boundary used before contract validation."""

    if not isinstance(evidence, Mapping):
        return {}
    safe_value, _ = redact_sensitive_value(dict(evidence))
    safe_value, _ = strip_untrusted_raw_digest_fields(safe_value)
    if not isinstance(safe_value, dict):
        return {}
    try:
        decoded = json.loads(json.dumps(safe_value, allow_nan=False))
    except (TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}

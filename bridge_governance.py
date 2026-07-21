"""Durable, auditable governance for cross-namespace recall bridges.

The authoritative v6 schema deliberately remains unchanged.  Current proposal
and link projections live under private, versioned ``store_metadata`` keys;
every state transition is recorded append-only in
``store_maintenance_receipts``.  Projection, receipt, and active
``context_relationships`` changes share one ``BEGIN IMMEDIATE`` transaction.

Only an effective ``approved`` projection may authorize connected recall.
Suggestions and pending proposals never create or enable a durable link, and
no operation in this module copies memories between namespaces.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import math
import re
import time
from typing import Any, Callable, Iterable, Mapping

from memory_store import DurableMemoryStore, _decode_json, _json_dumps
from redaction import (
    redact_capture_text,
    redact_sensitive_value,
    reject_sensitive_identifier,
    strip_untrusted_raw_digest_fields,
)


PROPOSAL_SCHEMA = "synapse-s2.bridge-proposal.v1"
LINK_PROJECTION_SCHEMA = "synapse-s2.bridge-link-projection.v1"
EVENT_SCHEMA = "synapse-s2.bridge-governance-event.v1"
AUDIT_SCHEMA = "synapse-s2.bridge-governance-audit.v1"

PROPOSAL_KEY_PREFIX = "bridge_governance.proposal.v1."
LINK_KEY_PREFIX = "bridge_governance.link.v1."
EVENT_OPERATION_PREFIX = "bridge-governance-v1."

DEFAULT_PROPOSAL_TTL_SECONDS = 7 * 24 * 60 * 60
MIN_PROPOSAL_TTL_SECONDS = 60
MAX_PROPOSAL_TTL_SECONDS = 30 * 24 * 60 * 60
MIN_LINK_TTL_SECONDS = 60
MAX_LINK_TTL_SECONDS = 366 * 24 * 60 * 60
MAX_EVIDENCE_BYTES = 8_192
MAX_REASON_BYTES = 1_024
MAX_LIST_LIMIT = 2_000
MAX_AUDIT_ROWS = 10_000
MAX_EVIDENCE_NODES = 2_048
MAX_EVIDENCE_DEPTH = 32

PROPOSAL_STATES = frozenset(
    {"pending", "approved", "rejected", "disabled", "revoked", "expired"}
)
TERMINAL_STATES = frozenset({"rejected", "revoked", "expired"})
ACTIVE_STATE = "approved"
ALLOWED_TRANSITIONS = frozenset(
    {
        (None, "pending"),
        ("pending", "approved"),
        ("pending", "rejected"),
        ("pending", "expired"),
        ("approved", "disabled"),
        ("approved", "revoked"),
        ("approved", "expired"),
        ("disabled", "revoked"),
        ("disabled", "expired"),
    }
)

_CONTEXT_RE = re.compile(r"[^A-Za-z0-9_.:-]+")
_RELATION_RE = re.compile(r"[^A-Za-z0-9_.:-]+")
_ACTOR_RE = re.compile(r"[^A-Za-z0-9_.:@-]+")
_CANONICAL_PROPOSAL_ID_RE = re.compile(r"s2bgp_[0-9a-f]{32}")
_REVISION_RE = re.compile(r"[0-9a-f]{64}")

_EVENT_ACTOR_FIELDS = {
    "propose": "proposed_by",
    "approve": "reviewed_by",
    "reject": "reviewed_by",
    "disable": "disabled_by",
    "revoke": "revoked_by",
    "expire": "expired_by",
}
_IMMUTABLE_PROPOSAL_FIELDS = (
    "schema",
    "proposal_id",
    "context_link_id",
    "source_context_id",
    "target_context_id",
    "relation_type",
    "direction",
    "weight",
    "evidence",
    "evidence_redaction_count",
    "proposal_reason",
    "reason_redaction_count",
    "proposed_by",
    "proposed_at",
    "proposal_expires_at",
    "link_expires_at",
    "created_request_id",
    "compatibility_mode",
    "automatic_cross_namespace_write",
)


class BridgeGovernanceError(RuntimeError):
    """Base class for content-free bridge-governance failures."""


class BridgeGovernanceValidationError(BridgeGovernanceError, ValueError):
    """A governance request was rejected before any durable commit."""


class BridgeGovernanceConflict(BridgeGovernanceError):
    """A request id, active link, or immutable proposal conflicts."""


class BridgeGovernanceNotFound(BridgeGovernanceError):
    """A requested proposal or governed link does not exist."""


class BridgeGovernanceStaleRevision(BridgeGovernanceError):
    """The reviewed projection changed after the caller observed it."""


class BridgeGovernanceExpired(BridgeGovernanceError):
    """The proposal review window is no longer open."""


class BridgeGovernanceInvalidTransition(BridgeGovernanceError):
    """A requested lifecycle transition is not permitted."""


class BridgeGovernanceIntegrityError(BridgeGovernanceError):
    """Durable projection or ledger data is malformed."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _projection_revision(projection: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in projection.items() if key != "revision"}
    return _digest(unsigned)


def _with_revision(projection: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(projection)
    result.pop("revision", None)
    result["revision"] = _projection_revision(result)
    return result


def _finite_time(value: Any, *, field: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise BridgeGovernanceValidationError(f"{field} must be a finite timestamp") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise BridgeGovernanceValidationError(f"{field} must be a finite timestamp")
    return parsed


def _unit_interval(value: Any, *, field: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise BridgeGovernanceValidationError(f"{field} must be between 0 and 1") from exc
    if not math.isfinite(parsed) or parsed < 0.0 or parsed > 1.0:
        raise BridgeGovernanceValidationError(f"{field} must be between 0 and 1")
    return round(parsed, 6)


def _clean_identifier(
    value: Any,
    *,
    field: str,
    pattern: re.Pattern[str],
    maximum: int,
) -> str:
    try:
        raw = reject_sensitive_identifier(value, field=field).strip()
    except ValueError as exc:
        raise BridgeGovernanceValidationError(f"{field} is invalid") from exc
    cleaned = pattern.sub("_", raw).strip("._-:@")
    if not cleaned:
        raise BridgeGovernanceValidationError(f"{field} is required")
    return cleaned[:maximum]


def _clean_context(value: Any, *, field: str) -> str:
    return _clean_identifier(
        value,
        field=field,
        pattern=_CONTEXT_RE,
        maximum=128,
    )


def _clean_actor(value: Any, *, field: str) -> str:
    return _clean_identifier(
        value,
        field=field,
        pattern=_ACTOR_RE,
        maximum=128,
    )


def _clean_relation(value: Any) -> str:
    try:
        raw = reject_sensitive_identifier(value or "related", field="relation_type")
    except ValueError as exc:
        raise BridgeGovernanceValidationError("relation_type is invalid") from exc
    cleaned = _RELATION_RE.sub("_", raw.strip().lower()).strip("._-:")
    return (cleaned or "related")[:96]


def _clean_request_id(
    value: Any | None,
    *,
    action: str,
    request_fingerprint: str,
) -> str:
    if value is None or not str(value).strip():
        if not action or _REVISION_RE.fullmatch(request_fingerprint) is None:
            raise BridgeGovernanceValidationError(
                "automatic governance request identity is unavailable"
            )
        seed = f"bridge-governance-auto:v1\x1f{action}\x1f{request_fingerprint}"
        return "s2bgr_auto_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
    try:
        raw = reject_sensitive_identifier(
            value, field="governance_request_id"
        ).strip()
    except ValueError as exc:
        raise BridgeGovernanceValidationError(
            "governance_request_id is invalid"
        ) from exc
    if (
        not raw
        or len(raw.encode("utf-8")) > 160
        or _ACTOR_RE.search(raw) is not None
    ):
        raise BridgeGovernanceValidationError(
            "governance_request_id must be 1-160 canonical identifier characters"
        )
    return raw


def _clean_proposal_id(value: Any) -> str:
    try:
        raw = reject_sensitive_identifier(value, field="proposal_id").strip()
    except ValueError as exc:
        raise BridgeGovernanceValidationError("proposal_id is invalid") from exc
    if _CANONICAL_PROPOSAL_ID_RE.fullmatch(raw) is None:
        raise BridgeGovernanceValidationError(
            "proposal_id must be canonical s2bgp_ plus 32 lowercase hex characters"
        )
    return raw


def _clean_revision(value: Any) -> str:
    try:
        raw = reject_sensitive_identifier(value, field="expected_revision").strip()
    except ValueError as exc:
        raise BridgeGovernanceValidationError("expected_revision is invalid") from exc
    if _REVISION_RE.fullmatch(raw) is None:
        raise BridgeGovernanceValidationError(
            "expected_revision must be exactly 64 lowercase hex characters"
        )
    return raw


def _clean_reason(value: Any, *, required: bool = True) -> tuple[str, int]:
    redacted, redaction_count = redact_capture_text(str(value or "").strip())
    encoded = redacted.encode("utf-8")
    if len(encoded) > MAX_REASON_BYTES:
        redacted = encoded[:MAX_REASON_BYTES].decode("utf-8", errors="ignore").strip()
    if required and not redacted:
        raise BridgeGovernanceValidationError("reason is required")
    return redacted, int(redaction_count)


def _clean_evidence(value: Any) -> tuple[dict[str, Any], int]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise BridgeGovernanceValidationError("evidence must be an object")
    stack: list[tuple[Any, int]] = [(value, 0)]
    observed_nodes = 0
    while stack:
        current, depth = stack.pop()
        observed_nodes += 1
        if observed_nodes > MAX_EVIDENCE_NODES or depth > MAX_EVIDENCE_DEPTH:
            raise BridgeGovernanceValidationError(
                "evidence structure exceeds the supported complexity limit"
            )
        if isinstance(current, dict):
            if len(current) > 256:
                raise BridgeGovernanceValidationError(
                    "evidence objects may contain at most 256 fields"
                )
            stack.extend((key, depth + 1) for key in current)
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (list, tuple)):
            if len(current) > 512:
                raise BridgeGovernanceValidationError(
                    "evidence arrays may contain at most 512 items"
                )
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str) and len(current.encode("utf-8")) > 16_384:
            raise BridgeGovernanceValidationError(
                "evidence strings may contain at most 16384 bytes"
            )
    safe, redactions = redact_sensitive_value(value)
    safe, digest_removals = strip_untrusted_raw_digest_fields(safe)
    if not isinstance(safe, dict):
        safe = {}
        redactions += 1
    try:
        encoded = _canonical_json(safe).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BridgeGovernanceValidationError(
            "evidence must be finite JSON data"
        ) from exc
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise BridgeGovernanceValidationError(
            f"redacted evidence must be at most {MAX_EVIDENCE_BYTES} bytes"
        )
    return safe, int(redactions) + int(digest_removals)


class BridgeGovernance:
    """Versioned bridge proposal and decision service over a durable store."""

    def __init__(
        self,
        store: DurableMemoryStore,
        *,
        require_distinct_reviewer: bool = True,
        allow_compatibility_approval: bool = False,
        clock: Callable[[], float] = time.time,
        allow_test_time: bool = False,
    ) -> None:
        if not isinstance(store, DurableMemoryStore):
            raise TypeError("store must be a DurableMemoryStore")
        self.store = store
        self.require_distinct_reviewer = bool(require_distinct_reviewer)
        self.allow_compatibility_approval = bool(allow_compatibility_approval)
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._clock = clock
        self._allow_test_time = bool(allow_test_time)

    def _trusted_now(self, supplied: float | None) -> float:
        if supplied is not None and not self._allow_test_time:
            raise BridgeGovernanceValidationError(
                "caller-supplied authorization time is not permitted"
            )
        value = self._clock() if supplied is None else supplied
        return _finite_time(value, field="now")

    @staticmethod
    def _proposal_key(proposal_id: str) -> str:
        return PROPOSAL_KEY_PREFIX + proposal_id

    @staticmethod
    def _link_key(context_link_id: str) -> str:
        return LINK_KEY_PREFIX + context_link_id

    @staticmethod
    def _operation_id(action: str, request_id: str) -> str:
        seed = f"bridge-governance:v1\x1f{action}\x1f{request_id}".encode("utf-8")
        return "s2bg_" + hashlib.sha256(seed).hexdigest()[:32]

    @staticmethod
    def _request_fingerprint(action: str, request: Mapping[str, Any]) -> str:
        return _digest(
            {
                "schema": EVENT_SCHEMA,
                "action": action,
                "request": dict(request),
            }
        )

    @staticmethod
    def _read_json_row(conn: Any, key: str) -> dict[str, Any] | None:
        row = conn.execute(
            "SELECT value_json FROM store_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(str(row["value_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BridgeGovernanceIntegrityError("bridge governance projection is invalid") from exc
        if not isinstance(value, dict):
            raise BridgeGovernanceIntegrityError("bridge governance projection is invalid")
        return value

    def _validated_proposal_conn(
        self,
        conn: Any,
        proposal_id: str,
    ) -> dict[str, Any]:
        """Read a proposal only when its projection is bound to its last receipt."""

        clean_id = _clean_proposal_id(proposal_id)
        proposal = self._read_json_row(conn, self._proposal_key(clean_id))
        if proposal is None:
            raise BridgeGovernanceNotFound("bridge proposal was not found")
        try:
            revision_valid = proposal.get("revision") == _projection_revision(proposal)
            event_count = int(proposal.get("event_count", 0))
        except (TypeError, ValueError, OverflowError):
            revision_valid = False
            event_count = 0
        if (
            proposal.get("schema") != PROPOSAL_SCHEMA
            or proposal.get("proposal_id") != clean_id
            or proposal.get("state") not in PROPOSAL_STATES
            or not isinstance(proposal.get("compatibility_mode"), bool)
            or proposal.get("automatic_cross_namespace_write") is not False
            or not revision_valid
            or event_count < 1
        ):
            raise BridgeGovernanceIntegrityError(
                "bridge proposal projection failed integrity validation"
            )
        event_id = str(proposal.get("last_event_id") or "")
        row = conn.execute(
            """
            SELECT operation_type, context_id, before_revision,
                   after_revision, payload_json, created_at
            FROM store_maintenance_receipts
            WHERE operation_id = ?
            """,
            (event_id,),
        ).fetchone()
        if row is None:
            raise BridgeGovernanceIntegrityError(
                "bridge proposal lost its last governance receipt"
            )
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BridgeGovernanceIntegrityError(
                "bridge proposal receipt is invalid"
            ) from exc
        result = payload.get("result") if isinstance(payload, dict) else None
        result_proposal = result.get("proposal") if isinstance(result, dict) else None
        action = str(payload.get("action") or "") if isinstance(payload, dict) else ""
        request_id = str(payload.get("request_id") or "") if isinstance(payload, dict) else ""
        actor_field = _EVENT_ACTOR_FIELDS.get(action)
        expected_reason = (
            proposal.get("proposal_reason")
            if action == "propose"
            else proposal.get("decision_reason")
        )
        try:
            receipt_created_at = float(row["created_at"])
            proposal_updated_at = float(proposal.get("updated_at"))
            created_at_matches = (
                math.isfinite(receipt_created_at)
                and receipt_created_at == proposal_updated_at
            )
        except (TypeError, ValueError, OverflowError):
            created_at_matches = False
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != EVENT_SCHEMA
            or payload.get("event_id") != event_id
            or self._operation_id(action, request_id) != event_id
            or row["operation_type"] != EVENT_OPERATION_PREFIX + action
            or row["context_id"] != proposal.get("source_context_id")
            or row["before_revision"] != payload.get("before_revision")
            or row["after_revision"] != proposal.get("revision")
            or not created_at_matches
            or payload.get("after_revision") != proposal.get("revision")
            or payload.get("after_state") != proposal.get("state")
            or payload.get("proposal_id") != clean_id
            or payload.get("context_link_id") != proposal.get("context_link_id")
            or payload.get("event_sequence") != event_count
            or payload.get("automatic_cross_namespace_write") is not False
            or _REVISION_RE.fullmatch(
                str(payload.get("request_fingerprint") or "")
            )
            is None
            or payload.get("request_fingerprint")
            != proposal.get("last_request_fingerprint")
            or payload.get("reason") != expected_reason
            or not isinstance(result, dict)
            or result.get("state") != proposal.get("state")
            or result_proposal != proposal
            or not self._result_envelope_matches(
                action=action,
                result=result,
                proposal=proposal,
            )
            or actor_field is None
            or payload.get("actor") != proposal.get(actor_field)
        ):
            raise BridgeGovernanceIntegrityError(
                "bridge proposal does not match its last governance receipt"
            )
        return proposal

    def _validated_link_conn(
        self,
        conn: Any,
        *,
        proposal: Mapping[str, Any],
        observed_at: float,
    ) -> dict[str, Any] | None:
        """Return a structurally valid governed link, or fail closed on mismatch."""

        link_id = str(proposal.get("context_link_id") or "")
        projection = self._read_json_row(conn, self._link_key(link_id))
        durable = conn.execute(
            "SELECT * FROM context_relationships WHERE context_link_id = ?",
            (link_id,),
        ).fetchone()
        if projection is None and durable is None:
            return None
        if projection is None or durable is None:
            raise BridgeGovernanceIntegrityError(
                "governed namespace link surfaces are incomplete"
            )
        try:
            projection_valid = projection.get("revision") == _projection_revision(
                projection
            )
        except (TypeError, ValueError, OverflowError) as exc:
            raise BridgeGovernanceIntegrityError(
                "governed namespace link projection is invalid"
            ) from exc
        if (
            projection.get("schema") != LINK_PROJECTION_SCHEMA
            or not projection_valid
            or projection.get("proposal_id") != proposal.get("proposal_id")
            or projection.get("proposal_revision") != proposal.get("revision")
            or projection.get("state") != proposal.get("state")
            or projection.get("last_event_id") != proposal.get("last_event_id")
            or projection.get("link_expires_at")
            != proposal.get("link_expires_at")
            or projection.get("updated_at") != proposal.get("updated_at")
            or projection.get("automatic_cross_namespace_write") is not False
            or not self._link_structures_match(
                proposal=proposal,
                projection=projection,
                durable=durable,
            )
        ):
            raise BridgeGovernanceIntegrityError(
                "governed namespace link failed structural validation"
            )
        # Expiry is authoritative at read time even before the maintenance sweep
        # materializes the disabled row. Persisted enablement follows the last
        # durable lifecycle event, not wall-clock projection.
        expected_enabled = proposal.get("state") == "approved"
        if projection.get("enabled") is not expected_enabled or bool(
            durable["enabled"]
        ) != expected_enabled:
            raise BridgeGovernanceIntegrityError(
                "governed namespace link authorization state is inconsistent"
            )
        evidence = _decode_json(str(durable["evidence_json"]), {})
        governance = evidence.get("governance") if isinstance(evidence, dict) else None
        if (
            not isinstance(governance, dict)
            or governance.get("schema") != LINK_PROJECTION_SCHEMA
            or governance.get("proposal_id") != proposal.get("proposal_id")
            or governance.get("proposal_revision") != proposal.get("revision")
            or governance.get("state") != proposal.get("state")
            or governance.get("last_event_id") != proposal.get("last_event_id")
            or governance.get("link_expires_at")
            != proposal.get("link_expires_at")
            or governance.get("automatic_cross_namespace_write") is not False
        ):
            raise BridgeGovernanceIntegrityError(
                "governed namespace link evidence binding is invalid"
            )
        result = self.store._row_to_context_link(durable)
        receipt = conn.execute(
            "SELECT payload_json FROM store_maintenance_receipts "
            "WHERE operation_id = ?",
            (proposal.get("last_event_id"),),
        ).fetchone()
        try:
            receipt_payload = json.loads(str(receipt["payload_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BridgeGovernanceIntegrityError(
                "governed namespace link receipt is invalid"
            ) from exc
        receipt_result = (
            receipt_payload.get("result")
            if isinstance(receipt_payload, dict)
            else None
        )
        receipt_link = (
            receipt_result.get("link")
            if isinstance(receipt_result, dict)
            else None
        )
        if not isinstance(receipt_link, dict) or receipt_link != result:
            raise BridgeGovernanceIntegrityError(
                "governed namespace link does not match its lifecycle receipt"
            )
        result["governance"] = projection
        return result

    @staticmethod
    def _write_projection(conn: Any, key: str, value: Mapping[str, Any], now: float) -> None:
        conn.execute(
            """
            INSERT INTO store_metadata (key, value_json, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at = excluded.updated_at
            """,
            (key, _json_dumps(dict(value)), now),
        )

    def _replay_event(
        self,
        conn: Any,
        *,
        action: str,
        request_id: str,
        request_fingerprint: str,
        observed_at: float,
    ) -> dict[str, Any] | None:
        operation_id = self._operation_id(action, request_id)
        row = conn.execute(
            """
            SELECT operation_type, payload_json, created_at
            FROM store_maintenance_receipts
            WHERE operation_id = ?
            """,
            (operation_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BridgeGovernanceIntegrityError("bridge governance event is invalid") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != EVENT_SCHEMA
            or payload.get("event_id") != operation_id
            or payload.get("action") != action
            or payload.get("request_id") != request_id
            or payload.get("request_fingerprint") != request_fingerprint
            or row["operation_type"] != EVENT_OPERATION_PREFIX + action
        ):
            raise BridgeGovernanceConflict("governance_request_id conflicts with prior use")
        result = payload.get("result")
        if not isinstance(result, dict):
            raise BridgeGovernanceIntegrityError("bridge governance replay result is invalid")
        historical_proposal = result.get("proposal")
        expected_reason = (
            historical_proposal.get("proposal_reason")
            if isinstance(historical_proposal, dict) and action == "propose"
            else (
                historical_proposal.get("decision_reason")
                if isinstance(historical_proposal, dict)
                else None
            )
        )
        try:
            historical_revision_valid = (
                isinstance(historical_proposal, dict)
                and historical_proposal.get("revision")
                == _projection_revision(historical_proposal)
            )
            created_at_valid = (
                isinstance(historical_proposal, dict)
                and math.isfinite(float(row["created_at"]))
                and float(row["created_at"])
                == float(historical_proposal.get("updated_at"))
            )
        except (TypeError, ValueError, OverflowError):
            historical_revision_valid = False
            created_at_valid = False
        if (
            not isinstance(historical_proposal, dict)
            or historical_proposal.get("proposal_id") != payload.get("proposal_id")
            or historical_proposal.get("context_link_id")
            != payload.get("context_link_id")
            or historical_proposal.get("revision") != payload.get("after_revision")
            or historical_proposal.get("state") != payload.get("after_state")
            or not historical_revision_valid
            or not created_at_valid
            or result.get("state") != payload.get("after_state")
            or not self._result_envelope_matches(
                action=action,
                result=result,
                proposal=historical_proposal,
            )
            or payload.get("reason") != expected_reason
            or payload.get("request_fingerprint")
            != historical_proposal.get("last_request_fingerprint")
            or _EVENT_ACTOR_FIELDS.get(action) is None
            or payload.get("actor")
            != historical_proposal.get(_EVENT_ACTOR_FIELDS[action])
        ):
            raise BridgeGovernanceIntegrityError(
                "bridge governance replay result does not match its event"
            )
        current = self._validated_proposal_conn(
            conn,
            str(payload["proposal_id"]),
        )
        effective_state = self._effective_state(current, observed_at)
        current_link = self._validated_link_conn(
            conn,
            proposal=current,
            observed_at=observed_at,
        )
        if current.get("state") in {"approved", "disabled"} and current_link is None:
            raise BridgeGovernanceIntegrityError(
                "approved bridge replay lost its governed link"
            )
        materialization_pending = effective_state != str(current.get("state") or "")
        if materialization_pending and current_link is not None:
            current_link = dict(current_link)
            current_link["durable_enabled"] = bool(current_link.get("enabled"))
            current_link["enabled"] = False
            current_link["effective_state"] = effective_state
            current_link["expiry_materialization_pending"] = True
            governance = current_link.get("governance")
            if isinstance(governance, dict):
                current_link["governance"] = {
                    **governance,
                    "effective_state": effective_state,
                    "effective_enabled": False,
                    "expiry_materialization_pending": True,
                }
        refreshed = dict(result)
        refreshed.pop("link_active", None)
        refreshed["historical_state"] = str(result.get("state") or "")
        refreshed["proposal"] = current
        refreshed["state"] = effective_state
        refreshed["materialization_pending"] = materialization_pending
        refreshed["authorization_active"] = bool(
            effective_state == "approved"
            and current_link is not None
            and current_link.get("enabled")
        )
        if current_link is not None:
            refreshed["link"] = current_link
        else:
            refreshed.pop("link", None)
        return refreshed

    def _insert_event(
        self,
        conn: Any,
        *,
        action: str,
        request_id: str,
        request_fingerprint: str,
        proposal: Mapping[str, Any],
        before_state: str | None,
        before_revision: str,
        actor: str,
        reason: str,
        event_sequence: int,
        result: Mapping[str, Any],
        now: float,
    ) -> str:
        operation_id = self._operation_id(action, request_id)
        after_revision = str(proposal["revision"])
        stored_result = dict(result)
        stored_result["link_active"] = bool(
            stored_result.pop("authorization_active", False)
        )
        payload = {
            "schema": EVENT_SCHEMA,
            "event_id": operation_id,
            "action": action,
            "request_id": request_id,
            "request_fingerprint": request_fingerprint,
            "proposal_id": str(proposal["proposal_id"]),
            "context_link_id": str(proposal["context_link_id"]),
            "actor": actor,
            "reason": reason,
            "before_state": before_state,
            "after_state": str(proposal["state"]),
            "before_revision": before_revision,
            "after_revision": after_revision,
            "event_sequence": int(event_sequence),
            "automatic_cross_namespace_write": False,
            "result": stored_result,
        }
        conn.execute(
            """
            INSERT INTO store_maintenance_receipts (
                operation_id, operation_type, context_id,
                before_revision, after_revision, payload_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                operation_id,
                EVENT_OPERATION_PREFIX + action,
                str(proposal["source_context_id"]),
                before_revision,
                after_revision,
                _json_dumps(payload),
                now,
            ),
        )
        return operation_id

    @staticmethod
    def _bounded_expiry(
        value: Any | None,
        *,
        now: float,
        default_ttl: int | None,
        minimum_ttl: int,
        maximum_ttl: int,
        field: str,
    ) -> float | None:
        if value is None:
            return None if default_ttl is None else now + float(default_ttl)
        expiry = _finite_time(value, field=field)
        ttl = expiry - now
        if ttl < minimum_ttl or ttl > maximum_ttl:
            raise BridgeGovernanceValidationError(
                f"{field} must be between {minimum_ttl} and {maximum_ttl} seconds from now"
            )
        return expiry

    def _normalized_link_request(
        self,
        *,
        source_context_id: Any,
        target_context_id: Any,
        relation_type: Any,
        weight: Any,
        evidence: Any,
        direction: Any,
    ) -> dict[str, Any]:
        source = _clean_context(source_context_id, field="source_context_id")
        target = _clean_context(target_context_id, field="target_context_id")
        if source == target:
            raise BridgeGovernanceValidationError(
                "source and target namespaces must be distinct"
            )
        try:
            normalized_direction = self.store._normalize_context_link_direction(
                str(direction)
            )
        except ValueError as exc:
            raise BridgeGovernanceValidationError(
                "direction must be bidirectional or directed"
            ) from exc
        if normalized_direction == "bidirectional" and target < source:
            source, target = target, source
        relation = _clean_relation(relation_type)
        safe_evidence, evidence_redactions = _clean_evidence(evidence)
        context_link_id = self.store.stable_context_link_id(
            source_context_id=source,
            target_context_id=target,
            relation_type=relation,
            direction=normalized_direction,
        )
        return {
            "source_context_id": source,
            "target_context_id": target,
            "relation_type": relation,
            "direction": normalized_direction,
            "weight": _unit_interval(weight, field="weight"),
            "evidence": safe_evidence,
            "evidence_redaction_count": evidence_redactions,
            "context_link_id": context_link_id,
        }

    @staticmethod
    def _proposal_result(
        action: str,
        proposal: Mapping[str, Any],
        *,
        link: Mapping[str, Any] | None = None,
        idempotent_replay: bool = False,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "action": action,
            "proposal": dict(proposal),
            "state": str(proposal["state"]),
            "authorization_active": bool(
                str(proposal["state"]) == "approved"
                and link is not None
                and bool(link.get("enabled"))
            ),
            "idempotent_replay": bool(idempotent_replay),
            "compatibility_mode": bool(proposal.get("compatibility_mode")),
            "automatic_cross_namespace_write": False,
        }
        if link is not None:
            result["link"] = dict(link)
        return result

    @staticmethod
    def _result_envelope_matches(
        *,
        action: str,
        result: Mapping[str, Any],
        proposal: Mapping[str, Any],
    ) -> bool:
        link = result.get("link")
        state = str(proposal.get("state") or "")
        if action in {"propose", "reject"}:
            link_shape_valid = link is None
        elif action in {"approve", "disable", "revoke"}:
            link_shape_valid = isinstance(link, dict)
        elif action == "expire":
            was_materialized = bool(proposal.get("reviewed_at"))
            link_shape_valid = isinstance(link, dict) == was_materialized
        else:
            return False
        expected_keys = {
            "action",
            "proposal",
            "state",
            "link_active",
            "idempotent_replay",
            "compatibility_mode",
            "automatic_cross_namespace_write",
        }
        if isinstance(link, dict):
            expected_keys.add("link")
        expected_active = bool(
            state == "approved"
            and isinstance(link, dict)
            and link.get("enabled") is True
        )
        return bool(
            set(result) == expected_keys
            and link_shape_valid
            and result.get("action") == f"{action}-namespace-link"
            and result.get("state") == state
            and "authorization_active" not in result
            and result.get("link_active") is expected_active
            and result.get("idempotent_replay") is False
            and isinstance(result.get("compatibility_mode"), bool)
            and result.get("compatibility_mode")
            is bool(proposal.get("compatibility_mode"))
            and result.get("automatic_cross_namespace_write") is False
        )

    @staticmethod
    def _historical_link_matches(
        *,
        action: str,
        link: Mapping[str, Any],
        proposal: Mapping[str, Any],
        expected_created_at: float | None = None,
        require_first_creation: bool = False,
    ) -> bool:
        expected_keys = {
            "context_link_id",
            "source_context_id",
            "target_context_id",
            "relation_type",
            "direction",
            "confidence",
            "weight",
            "evidence",
            "enabled",
            "approved",
            "approved_by",
            "approved_at",
            "created_at",
            "updated_at",
            "automatic_cross_namespace_write",
        }
        expected_evidence = dict(proposal.get("evidence") or {})
        expected_evidence["governance"] = {
            "schema": LINK_PROJECTION_SCHEMA,
            "proposal_id": proposal.get("proposal_id"),
            "proposal_revision": proposal.get("revision"),
            "state": proposal.get("state"),
            "link_expires_at": proposal.get("link_expires_at"),
            "last_event_id": proposal.get("last_event_id"),
            "automatic_cross_namespace_write": False,
        }
        try:
            confidence = float(link.get("confidence"))
            weight = float(link.get("weight"))
            proposal_weight = float(proposal.get("weight"))
            approved_at = float(link.get("approved_at"))
            reviewed_at = float(proposal.get("reviewed_at"))
            created_at = float(link.get("created_at"))
            updated_at = float(link.get("updated_at"))
            proposal_updated_at = float(proposal.get("updated_at"))
        except (TypeError, ValueError, OverflowError):
            return False
        if action == "approve":
            expected_enabled = True
        elif action in {"disable", "revoke", "expire"}:
            expected_enabled = False
        else:
            return False
        created_at_valid = (
            math.isfinite(created_at)
            and created_at > 0.0
            and created_at <= updated_at
        )
        if expected_created_at is not None:
            created_at_valid = created_at_valid and created_at == expected_created_at
        elif require_first_creation:
            created_at_valid = created_at_valid and created_at == reviewed_at
        return bool(
            set(link) == expected_keys
            and link.get("context_link_id") == proposal.get("context_link_id")
            and link.get("source_context_id") == proposal.get("source_context_id")
            and link.get("target_context_id") == proposal.get("target_context_id")
            and link.get("relation_type") == proposal.get("relation_type")
            and link.get("direction") == proposal.get("direction")
            and math.isfinite(confidence)
            and confidence == weight == proposal_weight
            and link.get("evidence") == expected_evidence
            and link.get("enabled") is expected_enabled
            and link.get("approved") is True
            and link.get("approved_by") == proposal.get("reviewed_by")
            and approved_at == reviewed_at
            and math.isfinite(updated_at)
            and updated_at == proposal_updated_at
            and created_at_valid
            and link.get("automatic_cross_namespace_write") is False
        )

    def _new_pending_projection(
        self,
        *,
        proposal_id: str,
        normalized: Mapping[str, Any],
        proposed_by: str,
        reason: str,
        reason_redactions: int,
        proposal_expires_at: float,
        link_expires_at: float | None,
        request_id: str,
        request_fingerprint: str,
        compatibility_mode: bool,
        event_id: str,
        now: float,
    ) -> dict[str, Any]:
        return _with_revision(
            {
                "schema": PROPOSAL_SCHEMA,
                "proposal_id": proposal_id,
                "context_link_id": normalized["context_link_id"],
                "source_context_id": normalized["source_context_id"],
                "target_context_id": normalized["target_context_id"],
                "relation_type": normalized["relation_type"],
                "direction": normalized["direction"],
                "weight": normalized["weight"],
                "evidence": dict(normalized["evidence"]),
                "evidence_redaction_count": int(normalized["evidence_redaction_count"]),
                "proposal_reason": reason,
                "reason_redaction_count": int(reason_redactions),
                "proposed_by": proposed_by,
                "proposed_at": now,
                "proposal_expires_at": proposal_expires_at,
                "link_expires_at": link_expires_at,
                "state": "pending",
                "previous_revision": "",
                "reviewed_by": "",
                "reviewed_at": 0.0,
                "decision_reason": "",
                "disabled_by": "",
                "disabled_at": 0.0,
                "revoked_by": "",
                "revoked_at": 0.0,
                "expired_by": "",
                "expired_at": 0.0,
                "last_event_id": event_id,
                "event_count": 1,
                "created_request_id": request_id,
                "last_request_fingerprint": request_fingerprint,
                "compatibility_mode": bool(compatibility_mode),
                "updated_at": now,
                "automatic_cross_namespace_write": False,
            }
        )

    @staticmethod
    def _transition_projection(
        proposal: Mapping[str, Any],
        *,
        state: str,
        event_id: str,
        actor_field: str,
        at_field: str,
        actor: str,
        reason: str,
        request_fingerprint: str,
        now: float,
    ) -> dict[str, Any]:
        before_state = str(proposal.get("state") or "")
        if (before_state, state) not in ALLOWED_TRANSITIONS:
            raise BridgeGovernanceInvalidTransition(
                f"bridge proposal cannot transition from {before_state} to {state}"
            )
        updated = dict(proposal)
        updated["previous_revision"] = str(proposal["revision"])
        updated["state"] = state
        updated[actor_field] = actor
        updated[at_field] = now
        if state in {"approved", "rejected"}:
            updated["decision_reason"] = reason
        elif state == "disabled":
            updated["decision_reason"] = reason
        elif state == "revoked":
            updated["decision_reason"] = reason
        elif state == "expired":
            updated["decision_reason"] = reason
        updated["last_event_id"] = event_id
        updated["last_request_fingerprint"] = request_fingerprint
        updated["event_count"] = int(proposal.get("event_count", 0)) + 1
        updated["updated_at"] = now
        return _with_revision(updated)

    def propose_namespace_link(
        self,
        *,
        source_context_id: str,
        target_context_id: str,
        relation_type: str = "related",
        weight: float = 1.0,
        evidence: dict[str, Any] | None = None,
        direction: str = "bidirectional",
        proposed_by: str,
        reason: str,
        proposal_expires_at: float | None = None,
        link_expires_at: float | None = None,
        governance_request_id: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        timestamp = self._trusted_now(now)
        normalized = self._normalized_link_request(
            source_context_id=source_context_id,
            target_context_id=target_context_id,
            relation_type=relation_type,
            weight=weight,
            evidence=evidence,
            direction=direction,
        )
        proposer = _clean_actor(proposed_by, field="proposed_by")
        safe_reason, reason_redactions = _clean_reason(reason)
        expiry_marker = (
            "default" if proposal_expires_at is None else _finite_time(
                proposal_expires_at, field="proposal_expires_at"
            )
        )
        link_expiry_marker = (
            None if link_expires_at is None else _finite_time(
                link_expires_at, field="link_expires_at"
            )
        )
        request = {
            **normalized,
            "proposed_by": proposer,
            "reason": safe_reason,
            "proposal_expires_at": expiry_marker,
            "link_expires_at": link_expiry_marker,
        }
        fingerprint = self._request_fingerprint("propose", request)
        request_id = _clean_request_id(
            governance_request_id,
            action="propose",
            request_fingerprint=fingerprint,
        )
        proposal_id = "s2bgp_" + hashlib.sha256(
            f"bridge-proposal:v1\x1f{request_id}\x1f{fingerprint}".encode("utf-8")
        ).hexdigest()[:32]
        event_id = self._operation_id("propose", request_id)

        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                replay = self._replay_event(
                    conn,
                    action="propose",
                    request_id=request_id,
                    request_fingerprint=fingerprint,
                    observed_at=timestamp,
                )
                if replay is not None:
                    replay["idempotent_replay"] = True
                    return replay
                if self._read_json_row(conn, self._proposal_key(proposal_id)) is not None:
                    raise BridgeGovernanceConflict("proposal identity already exists")
                proposal_expiry = self._bounded_expiry(
                    proposal_expires_at,
                    now=timestamp,
                    default_ttl=DEFAULT_PROPOSAL_TTL_SECONDS,
                    minimum_ttl=MIN_PROPOSAL_TTL_SECONDS,
                    maximum_ttl=MAX_PROPOSAL_TTL_SECONDS,
                    field="proposal_expires_at",
                )
                assert proposal_expiry is not None
                link_expiry = self._bounded_expiry(
                    link_expires_at,
                    now=timestamp,
                    default_ttl=None,
                    minimum_ttl=MIN_LINK_TTL_SECONDS,
                    maximum_ttl=MAX_LINK_TTL_SECONDS,
                    field="link_expires_at",
                )
                proposal = self._new_pending_projection(
                    proposal_id=proposal_id,
                    normalized=normalized,
                    proposed_by=proposer,
                    reason=safe_reason,
                    reason_redactions=reason_redactions,
                    proposal_expires_at=proposal_expiry,
                    link_expires_at=link_expiry,
                    request_id=request_id,
                    request_fingerprint=fingerprint,
                    compatibility_mode=False,
                    event_id=event_id,
                    now=timestamp,
                )
                result = self._proposal_result("propose-namespace-link", proposal)
                self._write_projection(
                    conn,
                    self._proposal_key(proposal_id),
                    proposal,
                    timestamp,
                )
                self.store._record_namespace_catalog_conn(
                    conn,
                    context_id=str(proposal["source_context_id"]),
                    observed_at=timestamp,
                )
                self.store._record_namespace_catalog_conn(
                    conn,
                    context_id=str(proposal["target_context_id"]),
                    observed_at=timestamp,
                )
                self._insert_event(
                    conn,
                    action="propose",
                    request_id=request_id,
                    request_fingerprint=fingerprint,
                    proposal=proposal,
                    before_state=None,
                    before_revision="",
                    actor=proposer,
                    reason=safe_reason,
                    event_sequence=1,
                    result=result,
                    now=timestamp,
                )
                return result

    def _materialize_approved_link(
        self,
        conn: Any,
        *,
        proposal: Mapping[str, Any],
        actor: str,
        now: float,
    ) -> dict[str, Any]:
        existing_projection = self._read_json_row(
            conn,
            self._link_key(str(proposal["context_link_id"])),
        )
        if (
            existing_projection is not None
            and existing_projection.get("proposal_id") != proposal.get("proposal_id")
            and existing_projection.get("state") == "approved"
        ):
            raise BridgeGovernanceConflict("namespace link already has an active approval")
        existing_durable = conn.execute(
            "SELECT * FROM context_relationships WHERE context_link_id = ?",
            (proposal["context_link_id"],),
        ).fetchone()
        if (
            existing_durable is not None
            and not self._durable_structure_matches_proposal(
                proposal=proposal,
                durable=existing_durable,
            )
        ):
            raise BridgeGovernanceIntegrityError(
                "existing namespace link structure does not match the proposal"
            )
        safe_evidence = dict(proposal.get("evidence") or {})
        safe_evidence["governance"] = {
            "schema": LINK_PROJECTION_SCHEMA,
            "proposal_id": proposal["proposal_id"],
            "proposal_revision": proposal["revision"],
            "state": proposal["state"],
            "link_expires_at": proposal.get("link_expires_at"),
            "last_event_id": proposal["last_event_id"],
            "automatic_cross_namespace_write": False,
        }
        structural_conflict = conn.execute(
            """
            SELECT context_link_id
            FROM context_relationships
            WHERE source_context_id = ?
              AND target_context_id = ?
              AND relation_type = ?
              AND direction = ?
              AND context_link_id != ?
            LIMIT 1
            """,
            (
                proposal["source_context_id"],
                proposal["target_context_id"],
                proposal["relation_type"],
                proposal["direction"],
                proposal["context_link_id"],
            ),
        ).fetchone()
        if structural_conflict is not None:
            raise BridgeGovernanceConflict(
                "a legacy namespace edge requires explicit adoption before approval"
            )
        conn.execute(
            """
            INSERT INTO context_relationships (
                context_link_id, source_context_id, target_context_id,
                relation_type, direction, confidence, evidence_json, enabled,
                approved_by, approved_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
            ON CONFLICT(context_link_id) DO UPDATE SET
                confidence = excluded.confidence,
                evidence_json = excluded.evidence_json,
                enabled = 1,
                approved_by = excluded.approved_by,
                approved_at = excluded.approved_at,
                updated_at = excluded.updated_at
            """,
            (
                proposal["context_link_id"],
                proposal["source_context_id"],
                proposal["target_context_id"],
                proposal["relation_type"],
                proposal["direction"],
                proposal["weight"],
                _json_dumps(safe_evidence),
                actor,
                now,
                now,
                now,
            ),
        )
        row = conn.execute(
            "SELECT * FROM context_relationships WHERE context_link_id = ?",
            (proposal["context_link_id"],),
        ).fetchone()
        if row is None:
            raise BridgeGovernanceIntegrityError("approved link was not materialized")
        return self.store._row_to_context_link(row)

    def _write_link_projection(
        self,
        conn: Any,
        *,
        proposal: Mapping[str, Any],
        enabled: bool,
        now: float,
    ) -> dict[str, Any]:
        projection = _with_revision(
            {
                "schema": LINK_PROJECTION_SCHEMA,
                "context_link_id": proposal["context_link_id"],
                "proposal_id": proposal["proposal_id"],
                "proposal_revision": proposal["revision"],
                "source_context_id": proposal["source_context_id"],
                "target_context_id": proposal["target_context_id"],
                "relation_type": proposal["relation_type"],
                "direction": proposal["direction"],
                "weight": proposal["weight"],
                "state": proposal["state"],
                "enabled": bool(enabled),
                "link_expires_at": proposal.get("link_expires_at"),
                "last_event_id": proposal["last_event_id"],
                "updated_at": now,
                "automatic_cross_namespace_write": False,
            }
        )
        self._write_projection(
            conn,
            self._link_key(str(proposal["context_link_id"])),
            projection,
            now,
        )
        return projection

    def review_namespace_link(
        self,
        *,
        proposal_id: str,
        decision: str,
        reviewed_by: str,
        reason: str,
        expected_revision: str,
        governance_request_id: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        clean_proposal_id = _clean_proposal_id(proposal_id)
        normalized_decision = str(decision or "").strip().lower()
        if normalized_decision not in {"approve", "reject"}:
            raise BridgeGovernanceValidationError("decision must be approve or reject")
        reviewer = _clean_actor(reviewed_by, field="reviewed_by")
        safe_reason, _reason_redactions = _clean_reason(reason)
        clean_expected = _clean_revision(expected_revision)
        timestamp = self._trusted_now(now)
        action = normalized_decision
        request = {
            "proposal_id": clean_proposal_id,
            "decision": normalized_decision,
            "reviewed_by": reviewer,
            "reason": safe_reason,
            "expected_revision": clean_expected,
        }
        fingerprint = self._request_fingerprint(action, request)
        request_id = _clean_request_id(
            governance_request_id,
            action=action,
            request_fingerprint=fingerprint,
        )
        event_id = self._operation_id(action, request_id)

        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                replay = self._replay_event(
                    conn,
                    action=action,
                    request_id=request_id,
                    request_fingerprint=fingerprint,
                    observed_at=timestamp,
                )
                if replay is not None:
                    replay["idempotent_replay"] = True
                    return replay
                proposal = self._validated_proposal_conn(conn, clean_proposal_id)
                if proposal.get("revision") != clean_expected:
                    raise BridgeGovernanceStaleRevision("bridge proposal revision is stale")
                if proposal.get("state") != "pending":
                    raise BridgeGovernanceInvalidTransition("bridge proposal is not pending")
                if timestamp >= float(proposal["proposal_expires_at"]):
                    raise BridgeGovernanceExpired("bridge proposal review window expired")
                if (
                    normalized_decision == "approve"
                    and proposal.get("link_expires_at") is not None
                    and timestamp >= float(proposal["link_expires_at"])
                ):
                    raise BridgeGovernanceExpired(
                        "bridge link authorization window expired before review"
                    )
                if (
                    self.require_distinct_reviewer
                    and reviewer == proposal.get("proposed_by")
                ):
                    raise BridgeGovernanceInvalidTransition(
                        "bridge proposal reviewer must differ from proposer"
                    )
                next_state = "approved" if normalized_decision == "approve" else "rejected"
                reviewed = self._transition_projection(
                    proposal,
                    state=next_state,
                    event_id=event_id,
                    actor_field="reviewed_by",
                    at_field="reviewed_at",
                    actor=reviewer,
                    reason=safe_reason,
                    request_fingerprint=fingerprint,
                    now=timestamp,
                )
                link = None
                if next_state == "approved":
                    link = self._materialize_approved_link(
                        conn,
                        proposal=reviewed,
                        actor=reviewer,
                        now=timestamp,
                    )
                    self._write_link_projection(
                        conn,
                        proposal=reviewed,
                        enabled=True,
                        now=timestamp,
                    )
                self._write_projection(
                    conn,
                    self._proposal_key(clean_proposal_id),
                    reviewed,
                    timestamp,
                )
                result = self._proposal_result(
                    f"{normalized_decision}-namespace-link",
                    reviewed,
                    link=link,
                )
                self._insert_event(
                    conn,
                    action=action,
                    request_id=request_id,
                    request_fingerprint=fingerprint,
                    proposal=reviewed,
                    before_state="pending",
                    before_revision=clean_expected,
                    actor=reviewer,
                    reason=safe_reason,
                    event_sequence=int(reviewed["event_count"]),
                    result=result,
                    now=timestamp,
                )
                return result

    def approve_namespace_link_compat(
        self,
        *,
        source_context_id: str,
        target_context_id: str,
        relation_type: str = "related",
        weight: float = 1.0,
        evidence: dict[str, Any] | None = None,
        direction: str = "bidirectional",
        approved_by: str,
        reason: str,
        link_expires_at: float | None = None,
        governance_request_id: str | None = None,
        confirm: bool = False,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Compatibility lane: atomically record proposal and approval events."""
        if not self.allow_compatibility_approval:
            raise BridgeGovernanceInvalidTransition(
                "compatibility approval requires an explicitly privileged service"
            )
        if self.require_distinct_reviewer:
            raise BridgeGovernanceInvalidTransition(
                "compatibility approval cannot bypass distinct reviewer policy"
            )
        if confirm is not True:
            raise BridgeGovernanceValidationError(
                "confirm=true is required for direct compatibility approval"
            )
        timestamp = self._trusted_now(now)
        normalized = self._normalized_link_request(
            source_context_id=source_context_id,
            target_context_id=target_context_id,
            relation_type=relation_type,
            weight=weight,
            evidence=evidence,
            direction=direction,
        )
        actor = _clean_actor(approved_by, field="approved_by")
        safe_reason, reason_redactions = _clean_reason(reason)
        link_expiry_marker = (
            None if link_expires_at is None else _finite_time(
                link_expires_at, field="link_expires_at"
            )
        )
        request = {
            **normalized,
            "approved_by": actor,
            "reason": safe_reason,
            "link_expires_at": link_expiry_marker,
            "compatibility_mode": True,
        }
        propose_fingerprint = self._request_fingerprint("propose", request)
        approve_fingerprint = self._request_fingerprint("approve", request)
        request_id = _clean_request_id(
            governance_request_id,
            action="approve-compat",
            request_fingerprint=approve_fingerprint,
        )
        propose_request_id = request_id + ".propose"
        approve_request_id = request_id + ".approve"
        proposal_id = "s2bgp_" + hashlib.sha256(
            f"bridge-compat:v1\x1f{request_id}\x1f{approve_fingerprint}".encode("utf-8")
        ).hexdigest()[:32]
        propose_event_id = self._operation_id("propose", propose_request_id)
        approve_event_id = self._operation_id("approve", approve_request_id)

        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                replay = self._replay_event(
                    conn,
                    action="approve",
                    request_id=approve_request_id,
                    request_fingerprint=approve_fingerprint,
                    observed_at=timestamp,
                )
                if replay is not None:
                    replay["idempotent_replay"] = True
                    return replay
                if self._read_json_row(conn, self._proposal_key(proposal_id)) is not None:
                    raise BridgeGovernanceConflict("proposal identity already exists")
                link_expiry = self._bounded_expiry(
                    link_expires_at,
                    now=timestamp,
                    default_ttl=None,
                    minimum_ttl=MIN_LINK_TTL_SECONDS,
                    maximum_ttl=MAX_LINK_TTL_SECONDS,
                    field="link_expires_at",
                )
                pending = self._new_pending_projection(
                    proposal_id=proposal_id,
                    normalized=normalized,
                    proposed_by=actor,
                    reason=safe_reason,
                    reason_redactions=reason_redactions,
                    proposal_expires_at=timestamp + DEFAULT_PROPOSAL_TTL_SECONDS,
                    link_expires_at=link_expiry,
                    request_id=request_id,
                    request_fingerprint=propose_fingerprint,
                    compatibility_mode=True,
                    event_id=propose_event_id,
                    now=timestamp,
                )
                approved = self._transition_projection(
                    pending,
                    state="approved",
                    event_id=approve_event_id,
                    actor_field="reviewed_by",
                    at_field="reviewed_at",
                    actor=actor,
                    reason=safe_reason,
                    request_fingerprint=approve_fingerprint,
                    now=timestamp,
                )
                link = self._materialize_approved_link(
                    conn,
                    proposal=approved,
                    actor=actor,
                    now=timestamp,
                )
                self._write_projection(
                    conn,
                    self._proposal_key(proposal_id),
                    approved,
                    timestamp,
                )
                self.store._record_namespace_catalog_conn(
                    conn,
                    context_id=str(approved["source_context_id"]),
                    observed_at=timestamp,
                )
                self.store._record_namespace_catalog_conn(
                    conn,
                    context_id=str(approved["target_context_id"]),
                    observed_at=timestamp,
                )
                self._write_link_projection(
                    conn,
                    proposal=approved,
                    enabled=True,
                    now=timestamp,
                )
                pending_result = self._proposal_result(
                    "propose-namespace-link",
                    pending,
                )
                result = self._proposal_result(
                    "approve-namespace-link",
                    approved,
                    link=link,
                )
                self._insert_event(
                    conn,
                    action="propose",
                    request_id=propose_request_id,
                    request_fingerprint=propose_fingerprint,
                    proposal=pending,
                    before_state=None,
                    before_revision="",
                    actor=actor,
                    reason=safe_reason,
                    event_sequence=1,
                    result=pending_result,
                    now=timestamp,
                )
                self._insert_event(
                    conn,
                    action="approve",
                    request_id=approve_request_id,
                    request_fingerprint=approve_fingerprint,
                    proposal=approved,
                    before_state="pending",
                    before_revision=str(pending["revision"]),
                    actor=actor,
                    reason=safe_reason,
                    event_sequence=2,
                    result=result,
                    now=timestamp,
                )
                return result

    def _deactivate_link(
        self,
        *,
        context_link_id: str,
        action: str,
        actor: str,
        reason: str,
        expected_revision: str,
        governance_request_id: str | None,
        confirm: bool,
        now: float | None,
    ) -> dict[str, Any]:
        if confirm is not True:
            raise BridgeGovernanceValidationError(
                f"confirm=true is required to {action} a namespace link"
            )
        link_id = _clean_identifier(
            context_link_id,
            field="context_link_id",
            pattern=_ACTOR_RE,
            maximum=160,
        )
        clean_actor = _clean_actor(actor, field="actor")
        safe_reason, _reason_redactions = _clean_reason(reason)
        clean_expected = _clean_revision(expected_revision)
        timestamp = self._trusted_now(now)
        request = {
            "context_link_id": link_id,
            "actor": clean_actor,
            "reason": safe_reason,
            "expected_revision": clean_expected,
            "action": action,
        }
        fingerprint = self._request_fingerprint(action, request)
        request_id = _clean_request_id(
            governance_request_id,
            action=action,
            request_fingerprint=fingerprint,
        )
        event_id = self._operation_id(action, request_id)
        next_state = "disabled" if action == "disable" else "revoked"

        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                replay = self._replay_event(
                    conn,
                    action=action,
                    request_id=request_id,
                    request_fingerprint=fingerprint,
                    observed_at=timestamp,
                )
                if replay is not None:
                    replay["idempotent_replay"] = True
                    return replay
                link_projection = self._read_json_row(conn, self._link_key(link_id))
                if link_projection is None:
                    raise BridgeGovernanceNotFound("governed namespace link was not found")
                proposal_id = _clean_proposal_id(link_projection.get("proposal_id"))
                proposal = self._validated_proposal_conn(conn, proposal_id)
                if proposal.get("context_link_id") != link_id:
                    raise BridgeGovernanceIntegrityError(
                        "link projection points at an unrelated proposal"
                    )
                if self._validated_link_conn(
                    conn,
                    proposal=proposal,
                    observed_at=timestamp,
                ) is None:
                    raise BridgeGovernanceIntegrityError(
                        "governed namespace link is missing"
                    )
                if proposal.get("revision") != clean_expected:
                    raise BridgeGovernanceStaleRevision("bridge proposal revision is stale")
                if action == "disable" and proposal.get("state") != "approved":
                    raise BridgeGovernanceInvalidTransition("only an approved link can be disabled")
                if action == "revoke" and proposal.get("state") not in {"approved", "disabled"}:
                    raise BridgeGovernanceInvalidTransition("link cannot be revoked from its current state")
                transitioned = self._transition_projection(
                    proposal,
                    state=next_state,
                    event_id=event_id,
                    actor_field="disabled_by" if action == "disable" else "revoked_by",
                    at_field="disabled_at" if action == "disable" else "revoked_at",
                    actor=clean_actor,
                    reason=safe_reason,
                    request_fingerprint=fingerprint,
                    now=timestamp,
                )
                row = conn.execute(
                    "SELECT * FROM context_relationships WHERE context_link_id = ?",
                    (link_id,),
                ).fetchone()
                if row is None:
                    raise BridgeGovernanceIntegrityError("governed link projection is missing")
                evidence = _decode_json(str(row["evidence_json"]), {})
                evidence = dict(evidence) if isinstance(evidence, dict) else {}
                evidence["governance"] = {
                    "schema": LINK_PROJECTION_SCHEMA,
                    "proposal_id": proposal_id,
                    "proposal_revision": transitioned["revision"],
                    "state": next_state,
                    "link_expires_at": transitioned.get("link_expires_at"),
                    "last_event_id": event_id,
                    "automatic_cross_namespace_write": False,
                }
                conn.execute(
                    """
                    UPDATE context_relationships
                    SET enabled = 0, evidence_json = ?, updated_at = ?
                    WHERE context_link_id = ?
                    """,
                    (_json_dumps(evidence), timestamp, link_id),
                )
                self._write_projection(
                    conn,
                    self._proposal_key(proposal_id),
                    transitioned,
                    timestamp,
                )
                self._write_link_projection(
                    conn,
                    proposal=transitioned,
                    enabled=False,
                    now=timestamp,
                )
                durable_row = conn.execute(
                    "SELECT * FROM context_relationships WHERE context_link_id = ?",
                    (link_id,),
                ).fetchone()
                assert durable_row is not None
                result = self._proposal_result(
                    f"{action}-namespace-link",
                    transitioned,
                    link=self.store._row_to_context_link(durable_row),
                )
                self._insert_event(
                    conn,
                    action=action,
                    request_id=request_id,
                    request_fingerprint=fingerprint,
                    proposal=transitioned,
                    before_state=str(proposal["state"]),
                    before_revision=clean_expected,
                    actor=clean_actor,
                    reason=safe_reason,
                    event_sequence=int(transitioned["event_count"]),
                    result=result,
                    now=timestamp,
                )
                return result

    def disable_namespace_link(
        self,
        *,
        context_link_id: str,
        disabled_by: str,
        reason: str,
        expected_revision: str,
        governance_request_id: str | None = None,
        confirm: bool = False,
        now: float | None = None,
    ) -> dict[str, Any]:
        return self._deactivate_link(
            context_link_id=context_link_id,
            action="disable",
            actor=disabled_by,
            reason=reason,
            expected_revision=expected_revision,
            governance_request_id=governance_request_id,
            confirm=confirm,
            now=now,
        )

    def revoke_namespace_link(
        self,
        *,
        context_link_id: str,
        revoked_by: str,
        reason: str,
        expected_revision: str,
        governance_request_id: str | None = None,
        confirm: bool = False,
        now: float | None = None,
    ) -> dict[str, Any]:
        return self._deactivate_link(
            context_link_id=context_link_id,
            action="revoke",
            actor=revoked_by,
            reason=reason,
            expected_revision=expected_revision,
            governance_request_id=governance_request_id,
            confirm=confirm,
            now=now,
        )

    def _expire_projection_conn(
        self,
        conn: Any,
        *,
        proposal: Mapping[str, Any],
        timestamp: float,
    ) -> dict[str, Any]:
        proposal_id = str(proposal["proposal_id"])
        validated = self._validated_proposal_conn(conn, proposal_id)
        if validated != dict(proposal):
            raise BridgeGovernanceIntegrityError(
                "bridge expiry candidate changed after selection"
            )
        proposal = validated
        request_id = f"expiry.{proposal_id}.{int(timestamp)}"
        action = "expire"
        reason = (
            "proposal review window expired"
            if proposal.get("state") == "pending"
            else "approved namespace link expired"
        )
        request = {
            "proposal_id": proposal_id,
            "before_revision": proposal["revision"],
            "reason": reason,
        }
        fingerprint = self._request_fingerprint(action, request)
        replay = self._replay_event(
            conn,
            action=action,
            request_id=request_id,
            request_fingerprint=fingerprint,
            observed_at=timestamp,
        )
        if replay is not None:
            return replay
        event_id = self._operation_id(action, request_id)
        expired = self._transition_projection(
            proposal,
            state="expired",
            event_id=event_id,
            actor_field="expired_by",
            at_field="expired_at",
            actor="system-expiry",
            reason=reason,
            request_fingerprint=fingerprint,
            now=timestamp,
        )
        link = None
        if proposal.get("state") in {"approved", "disabled"}:
            row = conn.execute(
                "SELECT * FROM context_relationships WHERE context_link_id = ?",
                (proposal["context_link_id"],),
            ).fetchone()
            if row is None:
                raise BridgeGovernanceIntegrityError("expiring governed link is missing")
            evidence = _decode_json(str(row["evidence_json"]), {})
            evidence = dict(evidence) if isinstance(evidence, dict) else {}
            evidence["governance"] = {
                "schema": LINK_PROJECTION_SCHEMA,
                "proposal_id": proposal_id,
                "proposal_revision": expired["revision"],
                "state": "expired",
                "link_expires_at": expired.get("link_expires_at"),
                "last_event_id": event_id,
                "automatic_cross_namespace_write": False,
            }
            conn.execute(
                """
                UPDATE context_relationships
                SET enabled = 0, evidence_json = ?, updated_at = ?
                WHERE context_link_id = ?
                """,
                (_json_dumps(evidence), timestamp, proposal["context_link_id"]),
            )
            self._write_link_projection(
                conn,
                proposal=expired,
                enabled=False,
                now=timestamp,
            )
            durable = conn.execute(
                "SELECT * FROM context_relationships WHERE context_link_id = ?",
                (proposal["context_link_id"],),
            ).fetchone()
            assert durable is not None
            link = self.store._row_to_context_link(durable)
        self._write_projection(
            conn,
            self._proposal_key(proposal_id),
            expired,
            timestamp,
        )
        result = self._proposal_result("expire-namespace-link", expired, link=link)
        self._insert_event(
            conn,
            action=action,
            request_id=request_id,
            request_fingerprint=fingerprint,
            proposal=expired,
            before_state=str(proposal["state"]),
            before_revision=str(proposal["revision"]),
            actor="system-expiry",
            reason=reason,
            event_sequence=int(expired["event_count"]),
            result=result,
            now=timestamp,
        )
        return result

    def expire_due(
        self,
        *,
        now: float | None = None,
        limit: int = 500,
    ) -> dict[str, Any]:
        timestamp = self._trusted_now(now)
        bounded_limit = self._bounded_limit(limit)
        expired: list[dict[str, Any]] = []
        invalid_projection_count = 0
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                rows = conn.execute(
                    """
                    SELECT key, value_json
                    FROM store_metadata
                    WHERE substr(key, 1, length(?)) = ?
                    ORDER BY updated_at, key
                    """,
                    (PROPOSAL_KEY_PREFIX, PROPOSAL_KEY_PREFIX),
                )
                for row in rows:
                    try:
                        proposal = json.loads(str(row["value_json"]))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        invalid_projection_count += 1
                        continue
                    if not isinstance(proposal, dict):
                        invalid_projection_count += 1
                        continue
                    try:
                        state = proposal.get("state")
                        due = (
                            state == "pending"
                            and timestamp >= float(proposal["proposal_expires_at"])
                        ) or (
                            state in {"approved", "disabled"}
                            and proposal.get("link_expires_at") is not None
                            and timestamp >= float(proposal["link_expires_at"])
                        )
                    except (KeyError, TypeError, ValueError, OverflowError):
                        invalid_projection_count += 1
                        continue
                    if due:
                        expired.append(
                            self._expire_projection_conn(
                                conn,
                                proposal=proposal,
                                timestamp=timestamp,
                            )
                        )
                        if len(expired) >= bounded_limit:
                            break
        return {
            "action": "expire-namespace-links",
            "expired_count": len(expired),
            "expired": expired,
            "invalid_projection_count": invalid_projection_count,
            "automatic_cross_namespace_write": False,
        }

    @staticmethod
    def _bounded_limit(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise BridgeGovernanceValidationError("limit must be an integer")
        if value < 1 or value > MAX_LIST_LIMIT:
            raise BridgeGovernanceValidationError(
                f"limit must be between 1 and {MAX_LIST_LIMIT}"
            )
        return value

    @staticmethod
    def _effective_state(proposal: Mapping[str, Any], now: float) -> str:
        state = str(proposal.get("state") or "")
        if state == "pending" and now >= float(proposal.get("proposal_expires_at") or 0):
            return "expired"
        if (
            state in {"approved", "disabled"}
            and proposal.get("link_expires_at") is not None
            and now >= float(proposal["link_expires_at"])
        ):
            return "expired"
        return state

    def list_namespace_link_proposals(
        self,
        *,
        context_id: str | None = None,
        state: str | None = None,
        limit: int = 500,
        now: float | None = None,
    ) -> dict[str, Any]:
        context = None if context_id is None else _clean_context(context_id, field="context_id")
        requested_state = None if state is None else str(state).strip().lower()
        if requested_state is not None and requested_state not in PROPOSAL_STATES:
            raise BridgeGovernanceValidationError("state is invalid")
        bounded_limit = self._bounded_limit(limit)
        timestamp = self._trusted_now(now)
        proposals: list[dict[str, Any]] = []
        with closing(self.store._connect_read_only()) as conn:
            rows = conn.execute(
                """
                SELECT value_json
                FROM store_metadata
                WHERE substr(key, 1, length(?)) = ?
                ORDER BY updated_at DESC, key
                """,
                (PROPOSAL_KEY_PREFIX, PROPOSAL_KEY_PREFIX),
            )
            for row in rows:
                try:
                    proposal = json.loads(str(row["value_json"]))
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise BridgeGovernanceIntegrityError(
                        "bridge proposal projection is invalid"
                    ) from exc
                if not isinstance(proposal, dict):
                    raise BridgeGovernanceIntegrityError(
                        "bridge proposal projection is invalid"
                    )
                proposal = self._validated_proposal_conn(
                    conn,
                    str(proposal.get("proposal_id") or ""),
                )
                if context is not None and context not in {
                    proposal.get("source_context_id"),
                    proposal.get("target_context_id"),
                }:
                    continue
                decorated = dict(proposal)
                decorated["effective_state"] = self._effective_state(
                    proposal, timestamp
                )
                if (
                    requested_state is not None
                    and decorated["effective_state"] != requested_state
                ):
                    continue
                proposals.append(decorated)
                if len(proposals) >= bounded_limit:
                    break
        return {
            "action": "list-namespace-link-proposals",
            "proposal_count": len(proposals),
            "proposals": proposals,
            "read_only": True,
            "automatic_cross_namespace_write": False,
        }

    def get_namespace_link_proposal(
        self,
        *,
        proposal_id: str,
        now: float | None = None,
    ) -> dict[str, Any]:
        timestamp = self._trusted_now(now)
        with closing(self.store._connect_read_only()) as conn:
            proposal = self._validated_proposal_conn(conn, proposal_id)
        result = dict(proposal)
        result["effective_state"] = self._effective_state(proposal, timestamp)
        return result

    def list_namespace_link_history(
        self,
        *,
        proposal_id: str | None = None,
        context_link_id: str | None = None,
        limit: int = 500,
    ) -> dict[str, Any]:
        clean_proposal = None if proposal_id is None else _clean_proposal_id(proposal_id)
        clean_link = None
        if context_link_id is not None:
            clean_link = _clean_identifier(
                context_link_id,
                field="context_link_id",
                pattern=_ACTOR_RE,
                maximum=160,
            )
        bounded_limit = self._bounded_limit(limit)
        events: list[dict[str, Any]] = []
        link_created_at_by_id: dict[str, float] = {}
        with closing(self.store._connect_read_only()) as conn:
            rows = conn.execute(
                """
                SELECT operation_id, operation_type, context_id,
                       before_revision, after_revision, payload_json, created_at
                FROM store_maintenance_receipts
                WHERE substr(operation_type, 1, length(?)) = ?
                ORDER BY created_at, operation_id
                LIMIT ?
                """,
                (
                    EVENT_OPERATION_PREFIX,
                    EVENT_OPERATION_PREFIX,
                    MAX_AUDIT_ROWS + 1,
                ),
            ).fetchall()
            if len(rows) > MAX_AUDIT_ROWS:
                raise BridgeGovernanceIntegrityError(
                    "bridge governance history exceeds validated capacity"
                )
            for row in rows:
                try:
                    payload = json.loads(str(row["payload_json"]))
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise BridgeGovernanceIntegrityError(
                        "bridge governance event is invalid"
                    ) from exc
                if not isinstance(payload, dict):
                    raise BridgeGovernanceIntegrityError(
                        "bridge governance event is invalid"
                    )
                action = str(payload.get("action") or "")
                request_id = str(payload.get("request_id") or "")
                result = payload.get("result")
                result_proposal = (
                    result.get("proposal") if isinstance(result, dict) else None
                )
                actor_field = _EVENT_ACTOR_FIELDS.get(action)
                expected_reason = (
                    result_proposal.get("proposal_reason")
                    if isinstance(result_proposal, dict) and action == "propose"
                    else (
                        result_proposal.get("decision_reason")
                        if isinstance(result_proposal, dict)
                        else None
                    )
                )
                try:
                    result_revision_valid = (
                        isinstance(result_proposal, dict)
                        and result_proposal.get("revision")
                        == _projection_revision(result_proposal)
                    )
                    created_at_valid = (
                        isinstance(result_proposal, dict)
                        and math.isfinite(float(row["created_at"]))
                        and float(row["created_at"])
                        == float(result_proposal.get("updated_at"))
                    )
                except (TypeError, ValueError, OverflowError):
                    result_revision_valid = False
                    created_at_valid = False
                context_matches = (
                    isinstance(result_proposal, dict)
                    and row["context_id"]
                    == result_proposal.get("source_context_id")
                )
                if (
                    not isinstance(result_proposal, dict)
                    or payload.get("schema") != EVENT_SCHEMA
                    or payload.get("event_id") != row["operation_id"]
                    or self._operation_id(action, request_id) != row["operation_id"]
                    or row["operation_type"] != EVENT_OPERATION_PREFIX + action
                    or not context_matches
                    or row["before_revision"] != payload.get("before_revision")
                    or row["after_revision"] != payload.get("after_revision")
                    or payload.get("proposal_id")
                    != result_proposal.get("proposal_id")
                    or payload.get("context_link_id")
                    != result_proposal.get("context_link_id")
                    or payload.get("after_state") != result_proposal.get("state")
                    or not result_revision_valid
                    or not self._result_envelope_matches(
                        action=action,
                        result=result,
                        proposal=result_proposal,
                    )
                    or not created_at_valid
                    or payload.get("reason") != expected_reason
                    or _REVISION_RE.fullmatch(
                        str(payload.get("request_fingerprint") or "")
                    )
                    is None
                    or payload.get("request_fingerprint")
                    != result_proposal.get("last_request_fingerprint")
                    or actor_field is None
                    or payload.get("actor") != result_proposal.get(actor_field)
                    or payload.get("automatic_cross_namespace_write") is not False
                ):
                    raise BridgeGovernanceIntegrityError(
                        "bridge governance history failed integrity validation"
                    )
                result_link = result.get("link") if isinstance(result, dict) else None
                if isinstance(result_link, dict):
                    link_id = str(result_proposal.get("context_link_id") or "")
                    expected_created_at = link_created_at_by_id.get(link_id)
                    if not self._historical_link_matches(
                        action=action,
                        link=result_link,
                        proposal=result_proposal,
                        expected_created_at=expected_created_at,
                        require_first_creation=(
                            expected_created_at is None and action == "approve"
                        ),
                    ):
                        raise BridgeGovernanceIntegrityError(
                            "bridge governance history link failed integrity validation"
                        )
                    if expected_created_at is None:
                        link_created_at_by_id[link_id] = float(
                            result_link["created_at"]
                        )
                if (
                    clean_proposal is not None
                    and payload.get("proposal_id") != clean_proposal
                ):
                    continue
                if clean_link is not None and payload.get("context_link_id") != clean_link:
                    continue
                events.append(
                    {
                        **payload,
                        "created_at": float(row["created_at"]),
                        "receipt_before_revision": str(row["before_revision"]),
                        "receipt_after_revision": str(row["after_revision"]),
                    }
                )
        events.sort(
            key=lambda item: (
                float(item.get("created_at") or 0.0),
                str(item.get("event_id") or ""),
            ),
            reverse=True,
        )
        events = events[:bounded_limit]
        return {
            "action": "list-namespace-link-history",
            "event_count": len(events),
            "events": events,
            "read_only": True,
            "append_only": True,
            "automatic_cross_namespace_write": False,
        }

    def _link_structures_match(
        self,
        *,
        proposal: Mapping[str, Any],
        projection: Mapping[str, Any],
        durable: Mapping[str, Any],
    ) -> bool:
        fields = (
            "context_link_id",
            "source_context_id",
            "target_context_id",
            "relation_type",
            "direction",
        )
        if any(
            str(proposal.get(field) or "")
            != str(projection.get(field) or "")
            or str(proposal.get(field) or "")
            != str(durable[field] or "")
            for field in fields
        ):
            return False
        try:
            proposal_weight = float(proposal["weight"])
            projection_weight = float(projection["weight"])
            durable_weight = float(durable["confidence"])
        except (KeyError, TypeError, ValueError, OverflowError):
            return False
        if not (
            math.isfinite(proposal_weight)
            and math.isclose(proposal_weight, projection_weight, abs_tol=1e-9)
            and math.isclose(proposal_weight, durable_weight, abs_tol=1e-9)
        ):
            return False
        for surface in (proposal, projection, durable):
            try:
                expected = self.store.stable_context_link_id(
                    source_context_id=str(surface["source_context_id"]),
                    target_context_id=str(surface["target_context_id"]),
                    relation_type=str(surface["relation_type"]),
                    direction=str(surface["direction"]),
                )
            except (KeyError, TypeError, ValueError):
                return False
            if expected != str(surface["context_link_id"]):
                return False
        return True

    def _durable_structure_matches_proposal(
        self,
        *,
        proposal: Mapping[str, Any],
        durable: Mapping[str, Any],
    ) -> bool:
        fields = (
            "context_link_id",
            "source_context_id",
            "target_context_id",
            "relation_type",
            "direction",
        )
        if any(
            str(proposal.get(field) or "") != str(durable[field] or "")
            for field in fields
        ):
            return False
        try:
            expected = self.store.stable_context_link_id(
                source_context_id=str(durable["source_context_id"]),
                target_context_id=str(durable["target_context_id"]),
                relation_type=str(durable["relation_type"]),
                direction=str(durable["direction"]),
            )
        except (KeyError, TypeError, ValueError):
            return False
        return expected == str(proposal.get("context_link_id") or "")

    def list_active_namespace_links(
        self,
        *,
        context_id: str | None = None,
        limit: int = 1_000,
        now: float | None = None,
    ) -> list[dict[str, Any]]:
        context = None if context_id is None else _clean_context(context_id, field="context_id")
        bounded_limit = self._bounded_limit(limit)
        timestamp = self._trusted_now(now)
        links: list[dict[str, Any]] = []
        with closing(self.store._connect_read_only()) as conn:
            rows = conn.execute(
                """
                SELECT value_json
                FROM store_metadata
                WHERE substr(key, 1, length(?)) = ?
                ORDER BY key
                """,
                (LINK_KEY_PREFIX, LINK_KEY_PREFIX),
            )
            for row in rows:
                try:
                    projection = json.loads(str(row["value_json"]))
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise BridgeGovernanceIntegrityError(
                        "bridge link projection is invalid"
                    ) from exc
                if not isinstance(projection, dict):
                    raise BridgeGovernanceIntegrityError("bridge link projection is invalid")
                try:
                    projection_revision_valid = (
                        projection.get("revision") == _projection_revision(projection)
                    )
                except (TypeError, ValueError, OverflowError):
                    projection_revision_valid = False
                if not projection_revision_valid:
                    continue
                if projection.get("state") != "approved" or projection.get("enabled") is not True:
                    continue
                expiry = projection.get("link_expires_at")
                if expiry is not None and timestamp >= float(expiry):
                    continue
                if context is not None and context not in {
                    projection.get("source_context_id"),
                    projection.get("target_context_id"),
                }:
                    continue
                proposal_id = str(projection.get("proposal_id") or "")
                try:
                    proposal = self._validated_proposal_conn(conn, proposal_id)
                except (BridgeGovernanceIntegrityError, BridgeGovernanceNotFound):
                    continue
                try:
                    proposal_valid = (
                        proposal is not None
                        and proposal.get("schema") == PROPOSAL_SCHEMA
                        and proposal.get("revision") == _projection_revision(proposal)
                        and proposal.get("state") == "approved"
                        and self._effective_state(proposal, timestamp) == "approved"
                        and proposal.get("context_link_id")
                        == projection.get("context_link_id")
                        and proposal.get("revision")
                        == projection.get("proposal_revision")
                        and proposal.get("last_event_id")
                        == projection.get("last_event_id")
                    )
                except (TypeError, ValueError, OverflowError):
                    proposal_valid = False
                if not proposal_valid:
                    continue
                try:
                    link = self._validated_link_conn(
                        conn,
                        proposal=proposal,
                        observed_at=timestamp,
                    )
                except (BridgeGovernanceIntegrityError, BridgeGovernanceNotFound):
                    continue
                if link is None or not bool(link.get("enabled")):
                    continue
                links.append(link)
                if len(links) >= bounded_limit:
                    break
        return links

    def resolve_recall_contexts(
        self,
        *,
        context_id: str,
        scope: str = "local",
        now: float | None = None,
    ) -> list[dict[str, Any]]:
        """Fail-closed scope resolver that enforces governance and expiry."""
        context = _clean_context(context_id, field="context_id")
        normalized_scope = self.store._normalize_recall_scope(scope)
        if normalized_scope != "connected":
            return self.store.resolve_recall_contexts(
                context_id=context,
                scope=normalized_scope,
            )
        records: list[dict[str, Any]] = [
            {
                "context_id": context,
                "recall_scope": "connected",
                "recall_provenance": "local",
                "via_context_link_id": "",
                "via_relation_type": "",
            }
        ]
        seen = {context}
        for link in self.list_active_namespace_links(context_id=context, now=now):
            source = str(link["source_context_id"])
            target = str(link["target_context_id"])
            direction = str(link["direction"])
            if source == context:
                neighbor = target
            elif target == context and direction == "bidirectional":
                neighbor = source
            else:
                # A structurally unrelated row can never become a recall edge.
                continue
            if not neighbor or neighbor in seen or neighbor == "global":
                continue
            seen.add(neighbor)
            records.append(
                {
                    "context_id": neighbor,
                    "recall_scope": "connected",
                    "recall_provenance": "connected",
                    "via_context_link_id": str(link["context_link_id"]),
                    "via_relation_type": str(link["relation_type"]),
                    "via_direction": direction,
                }
            )
        records[1:] = sorted(records[1:], key=lambda row: str(row["context_id"]))
        if "global" not in seen:
            records.append(
                {
                    "context_id": "global",
                    "recall_scope": "connected",
                    "recall_provenance": "global",
                    "via_context_link_id": "",
                    "via_relation_type": "",
                }
            )
        return records

    def audit_integrity(self, *, now: float | None = None) -> dict[str, Any]:
        timestamp = self._trusted_now(now)
        errors: list[str] = []
        proposals: dict[str, dict[str, Any]] = {}
        link_projections: dict[str, dict[str, Any]] = {}
        events_by_proposal: dict[str, list[dict[str, Any]]] = {}
        durable_links: dict[str, Any] = {}
        metadata_row_digests: list[tuple[str, str]] = []
        receipt_row_digests: list[tuple[str, str]] = []
        durable_row_digests: list[tuple[str, str]] = []
        link_created_at_by_id: dict[str, float] = {}
        expiry_due_count = 0

        with closing(self.store._connect_read_only()) as conn:
            metadata_rows = conn.execute(
                """
                SELECT key, value_json
                FROM store_metadata
                WHERE substr(key, 1, length(?)) = ?
                   OR substr(key, 1, length(?)) = ?
                ORDER BY key
                LIMIT ?
                """,
                (
                    PROPOSAL_KEY_PREFIX,
                    PROPOSAL_KEY_PREFIX,
                    LINK_KEY_PREFIX,
                    LINK_KEY_PREFIX,
                    MAX_AUDIT_ROWS + 1,
                ),
            ).fetchall()
            if len(metadata_rows) > MAX_AUDIT_ROWS:
                errors.append("audit-capacity:metadata")
                metadata_rows = metadata_rows[:MAX_AUDIT_ROWS]
            for row in metadata_rows:
                key = str(row["key"])
                metadata_row_digests.append(
                    (
                        key,
                        _digest(
                            {
                                "key": key,
                                "value_json": str(row["value_json"]),
                            }
                        ),
                    )
                )
                try:
                    value = json.loads(str(row["value_json"]))
                except (TypeError, ValueError, json.JSONDecodeError):
                    errors.append(f"invalid-json:{key}")
                    continue
                if not isinstance(value, dict):
                    errors.append(f"invalid-projection:{key}")
                    continue
                try:
                    revision_matches = value.get("revision") == _projection_revision(value)
                except (TypeError, ValueError, OverflowError):
                    revision_matches = False
                if not revision_matches:
                    errors.append(f"revision-mismatch:{key}")
                if key.startswith(PROPOSAL_KEY_PREFIX):
                    proposal_id = key[len(PROPOSAL_KEY_PREFIX) :]
                    proposals[proposal_id] = value
                    if value.get("schema") != PROPOSAL_SCHEMA:
                        errors.append(f"proposal-schema:{proposal_id}")
                    if value.get("proposal_id") != proposal_id:
                        errors.append(f"proposal-key-mismatch:{proposal_id}")
                    if value.get("state") not in PROPOSAL_STATES:
                        errors.append(f"proposal-state:{proposal_id}")
                    if value.get("automatic_cross_namespace_write") is not False:
                        errors.append(f"proposal-auto-write:{proposal_id}")
                else:
                    link_id = key[len(LINK_KEY_PREFIX) :]
                    link_projections[link_id] = value
                    if value.get("schema") != LINK_PROJECTION_SCHEMA:
                        errors.append(f"link-schema:{link_id}")
                    if value.get("context_link_id") != link_id:
                        errors.append(f"link-key-mismatch:{link_id}")
                    if value.get("automatic_cross_namespace_write") is not False:
                        errors.append(f"link-auto-write:{link_id}")

            receipt_rows = conn.execute(
                """
                SELECT operation_id, operation_type, context_id, before_revision,
                       after_revision, payload_json, created_at
                FROM store_maintenance_receipts
                WHERE substr(operation_type, 1, length(?)) = ?
                ORDER BY created_at, operation_id
                LIMIT ?
                """,
                (EVENT_OPERATION_PREFIX, EVENT_OPERATION_PREFIX, MAX_AUDIT_ROWS + 1),
            ).fetchall()
            if len(receipt_rows) > MAX_AUDIT_ROWS:
                errors.append("audit-capacity:events")
                receipt_rows = receipt_rows[:MAX_AUDIT_ROWS]
            for row in receipt_rows:
                operation_id = str(row["operation_id"])
                receipt_row_digests.append(
                    (operation_id, _digest(dict(row)))
                )
                try:
                    payload = json.loads(str(row["payload_json"]))
                except (TypeError, ValueError, json.JSONDecodeError):
                    errors.append(f"event-invalid-json:{operation_id}")
                    continue
                if not isinstance(payload, dict) or payload.get("schema") != EVENT_SCHEMA:
                    errors.append(f"event-schema:{operation_id}")
                    continue
                action = str(payload.get("action") or "")
                proposal_id = str(payload.get("proposal_id") or "")
                request_id = str(payload.get("request_id") or "")
                if (
                    payload.get("event_id") != operation_id
                    or self._operation_id(action, request_id) != operation_id
                    or row["operation_type"] != EVENT_OPERATION_PREFIX + action
                    or payload.get("before_revision") != row["before_revision"]
                    or payload.get("after_revision") != row["after_revision"]
                    or payload.get("automatic_cross_namespace_write") is not False
                ):
                    errors.append(f"event-receipt-mismatch:{operation_id}")
                result = payload.get("result")
                result_proposal = (
                    result.get("proposal") if isinstance(result, dict) else None
                )
                try:
                    result_revision_valid = (
                        isinstance(result_proposal, dict)
                        and result_proposal.get("revision")
                        == _projection_revision(result_proposal)
                    )
                    event_created_at_valid = (
                        isinstance(result_proposal, dict)
                        and math.isfinite(float(row["created_at"]))
                        and float(row["created_at"])
                        == float(result_proposal.get("updated_at"))
                    )
                except (TypeError, ValueError, OverflowError):
                    result_revision_valid = False
                    event_created_at_valid = False
                expected_event_reason = (
                    result_proposal.get("proposal_reason")
                    if isinstance(result_proposal, dict) and action == "propose"
                    else (
                        result_proposal.get("decision_reason")
                        if isinstance(result_proposal, dict)
                        else None
                    )
                )
                if (
                    not isinstance(result, dict)
                    or not isinstance(result_proposal, dict)
                    or result.get("state") != payload.get("after_state")
                    or result_proposal.get("proposal_id") != proposal_id
                    or result_proposal.get("context_link_id")
                    != payload.get("context_link_id")
                    or result_proposal.get("revision")
                    != payload.get("after_revision")
                    or result_proposal.get("state") != payload.get("after_state")
                    or not result_revision_valid
                ):
                    errors.append(f"event-result-mismatch:{operation_id}")
                if (
                    not isinstance(result, dict)
                    or not isinstance(result_proposal, dict)
                    or not self._result_envelope_matches(
                        action=action,
                        result=result,
                        proposal=result_proposal,
                    )
                ):
                    errors.append(f"event-result-envelope:{operation_id}")
                result_link = (
                    result.get("link") if isinstance(result, dict) else None
                )
                if isinstance(result_link, dict) and isinstance(result_proposal, dict):
                    link_id = str(result_proposal.get("context_link_id") or "")
                    expected_created_at = link_created_at_by_id.get(link_id)
                    if not self._historical_link_matches(
                        action=action,
                        link=result_link,
                        proposal=result_proposal,
                        expected_created_at=expected_created_at,
                        require_first_creation=(
                            expected_created_at is None and action == "approve"
                        ),
                    ):
                        errors.append(f"event-link-mismatch:{operation_id}")
                    elif expected_created_at is None:
                        link_created_at_by_id[link_id] = float(
                            result_link["created_at"]
                        )
                if payload.get("reason") != expected_event_reason:
                    errors.append(f"event-reason-mismatch:{operation_id}")
                if (
                    not isinstance(result_proposal, dict)
                    or _REVISION_RE.fullmatch(
                        str(payload.get("request_fingerprint") or "")
                    )
                    is None
                    or payload.get("request_fingerprint")
                    != result_proposal.get("last_request_fingerprint")
                ):
                    errors.append(f"event-fingerprint-mismatch:{operation_id}")
                if not event_created_at_valid:
                    errors.append(f"event-created-at-mismatch:{operation_id}")
                actor_field = _EVENT_ACTOR_FIELDS.get(action)
                if (
                    actor_field is None
                    or not isinstance(result_proposal, dict)
                    or payload.get("actor") != result_proposal.get(actor_field)
                ):
                    errors.append(f"event-actor-mismatch:{operation_id}")
                if (
                    isinstance(result_proposal, dict)
                    and row["context_id"]
                    != result_proposal.get("source_context_id")
                ):
                    errors.append(f"event-context-mismatch:{operation_id}")
                events_by_proposal.setdefault(proposal_id, []).append(payload)

            link_rows = conn.execute(
                "SELECT * FROM context_relationships ORDER BY context_link_id LIMIT ?",
                (MAX_AUDIT_ROWS + 1,),
            ).fetchall()
            if len(link_rows) > MAX_AUDIT_ROWS:
                errors.append("audit-capacity:durable-links")
                link_rows = link_rows[:MAX_AUDIT_ROWS]
            durable_links = {str(row["context_link_id"]): row for row in link_rows}
            durable_row_digests = [
                (str(row["context_link_id"]), _digest(dict(row)))
                for row in link_rows
            ]

        for proposal_id, proposal in proposals.items():
            events = events_by_proposal.get(proposal_id, [])
            try:
                events.sort(key=lambda item: int(item.get("event_sequence", -1)))
            except (TypeError, ValueError, OverflowError):
                errors.append(f"event-sequence-invalid:{proposal_id}")
                events.sort(key=lambda item: str(item.get("event_id") or ""))
            previous_state: str | None = None
            previous_revision = ""
            immutable_baseline: dict[str, Any] | None = None
            for expected_sequence, event in enumerate(events, start=1):
                sequence = event.get("event_sequence")
                before_state = event.get("before_state")
                after_state = event.get("after_state")
                if sequence != expected_sequence:
                    errors.append(f"event-sequence:{proposal_id}")
                if before_state != previous_state or event.get("before_revision") != previous_revision:
                    errors.append(f"event-chain:{proposal_id}:{expected_sequence}")
                if (before_state, after_state) not in ALLOWED_TRANSITIONS:
                    errors.append(f"event-transition:{proposal_id}:{expected_sequence}")
                event_result = event.get("result")
                event_proposal = (
                    event_result.get("proposal")
                    if isinstance(event_result, dict)
                    else None
                )
                if isinstance(event_proposal, dict):
                    immutable_values = {
                        field: event_proposal.get(field)
                        for field in _IMMUTABLE_PROPOSAL_FIELDS
                    }
                    if immutable_baseline is None:
                        immutable_baseline = immutable_values
                    elif immutable_values != immutable_baseline:
                        errors.append(
                            f"proposal-immutability:{proposal_id}:{expected_sequence}"
                        )
                previous_state = str(after_state) if after_state is not None else None
                previous_revision = str(event.get("after_revision") or "")
            if not events:
                errors.append(f"proposal-missing-history:{proposal_id}")
            else:
                last = events[-1]
                if (
                    proposal.get("last_event_id") != last.get("event_id")
                    or proposal.get("revision") != last.get("after_revision")
                    or proposal.get("state") != last.get("after_state")
                    or proposal.get("event_count") != len(events)
                    or not isinstance(last.get("result"), dict)
                    or last["result"].get("proposal") != proposal
                ):
                    errors.append(f"projection-event-mismatch:{proposal_id}")
            try:
                effective = self._effective_state(proposal, timestamp)
            except (TypeError, ValueError, OverflowError):
                effective = "invalid"
                errors.append(f"proposal-expiry-invalid:{proposal_id}")
            if effective == "expired" and proposal.get("state") in {
                "pending",
                "approved",
                "disabled",
            }:
                expiry_due_count += 1

        for orphan_proposal in sorted(set(events_by_proposal) - set(proposals)):
            errors.append(f"history-missing-projection:{orphan_proposal}")

        materialized_link_ids: set[str] = set()
        for proposal_id, proposal in proposals.items():
            link_id = str(proposal.get("context_link_id") or "")
            events = events_by_proposal.get(proposal_id, [])
            if any(event.get("after_state") == "approved" for event in events):
                materialized_link_ids.add(link_id)
            if proposal.get("state") == "approved":
                current_projection = link_projections.get(link_id)
                if current_projection is None:
                    errors.append(f"approved-link-missing-projection:{link_id}")
                elif current_projection.get("proposal_id") != proposal_id:
                    errors.append(f"approved-link-owner-mismatch:{link_id}")
        for link_id in sorted(materialized_link_ids):
            if link_id not in link_projections:
                errors.append(f"materialized-link-missing-projection:{link_id}")
            if link_id not in durable_links:
                errors.append(f"materialized-link-missing-durable:{link_id}")

        for link_id, link_projection in link_projections.items():
            proposal_id = str(link_projection.get("proposal_id") or "")
            proposal = proposals.get(proposal_id)
            durable = durable_links.get(link_id)
            if proposal is None:
                errors.append(f"link-missing-proposal:{link_id}")
                continue
            if (
                proposal.get("context_link_id") != link_id
                or link_projection.get("proposal_revision") != proposal.get("revision")
                or link_projection.get("state") != proposal.get("state")
                or link_projection.get("last_event_id") != proposal.get("last_event_id")
                or link_projection.get("link_expires_at")
                != proposal.get("link_expires_at")
                or link_projection.get("updated_at") != proposal.get("updated_at")
                or link_projection.get("automatic_cross_namespace_write") is not False
            ):
                errors.append(f"link-proposal-mismatch:{link_id}")
            if proposal.get("state") in {"pending", "rejected"}:
                errors.append(f"impossible-link-state:{link_id}")
            if durable is None:
                errors.append(f"link-missing-durable-row:{link_id}")
                continue
            try:
                expected_enabled = proposal.get("state") == "approved"
            except (TypeError, ValueError, OverflowError):
                expected_enabled = False
                errors.append(f"proposal-expiry-invalid:{proposal_id}")
            if link_projection.get("enabled") is not expected_enabled:
                errors.append(f"link-projection-enabled-mismatch:{link_id}")
            if bool(durable["enabled"]) != expected_enabled:
                errors.append(f"link-enabled-mismatch:{link_id}")
            if not self._link_structures_match(
                proposal=proposal,
                projection=link_projection,
                durable=durable,
            ):
                errors.append(f"link-structure-mismatch:{link_id}")
            evidence = _decode_json(str(durable["evidence_json"]), {})
            governance = evidence.get("governance") if isinstance(evidence, dict) else None
            expected_evidence = dict(proposal.get("evidence") or {})
            expected_evidence["governance"] = {
                "schema": LINK_PROJECTION_SCHEMA,
                "proposal_id": proposal_id,
                "proposal_revision": proposal.get("revision"),
                "state": proposal.get("state"),
                "link_expires_at": proposal.get("link_expires_at"),
                "last_event_id": proposal.get("last_event_id"),
                "automatic_cross_namespace_write": False,
            }
            if (
                not isinstance(governance, dict)
                or evidence != expected_evidence
            ):
                errors.append(f"link-evidence-mismatch:{link_id}")
            try:
                provenance_matches = (
                    durable["approved_by"] == proposal.get("reviewed_by")
                    and float(durable["approved_at"] or 0.0)
                    == float(proposal.get("reviewed_at") or 0.0)
                    and float(durable["updated_at"] or 0.0)
                    == float(proposal.get("updated_at") or 0.0)
                )
            except (TypeError, ValueError, OverflowError):
                provenance_matches = False
            if not provenance_matches:
                errors.append(f"link-provenance-mismatch:{link_id}")
            proposal_events = events_by_proposal.get(proposal_id, [])
            last_result = (
                proposal_events[-1].get("result") if proposal_events else None
            )
            receipt_link = (
                last_result.get("link") if isinstance(last_result, dict) else None
            )
            if (
                not isinstance(receipt_link, dict)
                or receipt_link != self.store._row_to_context_link(durable)
            ):
                errors.append(f"link-receipt-mismatch:{link_id}")

        for ungoverned_link in sorted(set(durable_links) - set(link_projections)):
            errors.append(f"ungoverned-durable-link:{ungoverned_link}")

        unique_errors = sorted(set(errors))
        audit_revision = _digest(
            {
                "schema": AUDIT_SCHEMA,
                "proposal_revisions": sorted(
                    (key, str(value.get("revision") or ""))
                    for key, value in proposals.items()
                ),
                "link_revisions": sorted(
                    (key, str(value.get("revision") or ""))
                    for key, value in link_projections.items()
                ),
                "metadata_row_digests": sorted(metadata_row_digests),
                "receipt_row_digests": sorted(receipt_row_digests),
                "durable_row_digests": sorted(durable_row_digests),
                "event_count": sum(len(rows) for rows in events_by_proposal.values()),
                "expiry_due_count": expiry_due_count,
                "errors": unique_errors,
            }
        )
        return {
            "schema": AUDIT_SCHEMA,
            "status": "ready" if not unique_errors else "degraded",
            "audit_revision": audit_revision,
            "proposal_count": len(proposals),
            "link_projection_count": len(link_projections),
            "durable_link_count": len(durable_links),
            "event_count": sum(len(rows) for rows in events_by_proposal.values()),
            "expiry_due_count": expiry_due_count,
            "expiry_materialization_required": bool(expiry_due_count),
            "error_count": len(unique_errors),
            "error_samples": unique_errors[:100],
            "automatic_cross_namespace_write": False,
        }


__all__ = [
    "AUDIT_SCHEMA",
    "BridgeGovernance",
    "BridgeGovernanceConflict",
    "BridgeGovernanceError",
    "BridgeGovernanceExpired",
    "BridgeGovernanceIntegrityError",
    "BridgeGovernanceInvalidTransition",
    "BridgeGovernanceNotFound",
    "BridgeGovernanceStaleRevision",
    "BridgeGovernanceValidationError",
    "EVENT_SCHEMA",
    "LINK_PROJECTION_SCHEMA",
    "PROPOSAL_SCHEMA",
]

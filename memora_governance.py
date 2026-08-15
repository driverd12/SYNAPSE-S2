"""Memora-inspired Governed Cue Scaffolding v1: durable binding lifecycle.

This module governs the promotion of Memora Shadow cluster proposals into
durable, revocable cue bindings.  It deliberately mirrors
:mod:`bridge_governance`:

* bindings live as self-revisioned projections under versioned private
  ``store_metadata`` keys plus a per-namespace catalog projection;
* every lifecycle change writes an append-only ``store_maintenance_receipts``
  row in the same ``BEGIN IMMEDIATE`` transaction (exactly-once via request
  id + request fingerprint replay);
* promotion and revocation require an explicit ``confirm`` and an exact
  optimistic ``expected_revision`` compare-and-swap;
* every read fails closed: a projection that does not match its own content
  digest, its deep structural bounds, its catalog entry, or its last receipt
  raises an integrity error and contributes no routing effect.

Honesty constraints enforced here:

* proposals are recomputed server-side (a wire caller supplies only the
  namespace, the reviewed plan digest, and the cluster ordinal; cue terms,
  sources, and witnesses are derived from the authoritative recomputation
  installed by the in-process backend);
* per-source witnesses are computed in the same read transaction as the
  planner inputs and are covered by the plan digest, and the proposal
  transaction re-verifies both the transaction-coupled namespace revision
  and every live witness before anything is stored (no plan/witness TOCTOU);
* projections and receipts store no vectors and no raw source text -- only
  identifiers, digests, timestamps, and short re-redacted derived cue terms
  explicitly marked as untrusted routing evidence;
* only ``learned`` plans (ready pinned local-only neural provider with full
  model/revision/config identity, every identity boolean literally true)
  may even be proposed, and the exact provider identity is revalidated at
  promotion time and again at retrieval time;
* each cue routes only to its exact ``supporting_memory_ids`` subset, never
  to the whole cluster;
* a changed, deleted, oversized, or re-provisioned source makes the binding
  ineffective (fail closed) without deleting anything;
* nothing in this module promotes automatically.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import math
import re
import time
from typing import Any, Callable, Iterable, Mapping

from memory_store import DurableMemoryStore, MEMORA_WITNESS_SCHEMA, _json_dumps
from memora_shadow import (
    MEMORA_SHADOW_MAX_METADATA_BYTES,
    MEMORA_SHADOW_MAX_SOURCE_TEXT_BYTES,
    MEMORA_SHADOW_SCHEMA,
    plan_digest as compute_plan_digest,
)
from redaction import redact_capture_text, reject_sensitive_identifier

BINDING_SCHEMA = "synapse-s2.memora-binding.v1"
CATALOG_SCHEMA = "synapse-s2.memora-catalog.v1"
EVENT_SCHEMA = "synapse-s2.memora-governance-event.v1"

BINDING_KEY_PREFIX = "memora_governance.binding.v1."
CATALOG_KEY_PREFIX = "memora_governance.catalog.v1."
EVENT_OPERATION_PREFIX = "memora-governance-v1."

CUE_TRUST_MARKER = "untrusted-derived-routing-evidence"
SUPPORTED_PROVIDER_TYPE = "mlx-neural"

MAX_REASON_BYTES = 1_024
MAX_CUE_TERM_BYTES = 64
MAX_CUES_PER_BINDING = 8
MAX_SOURCES_PER_BINDING = 64
MAX_PROVIDER_DIMENSIONS = 65_536
MAX_CATALOG_BINDINGS = 512
MAX_OPEN_PROPOSALS = 64
MAX_LIST_LIMIT = 256
# The lifecycle writes at most a handful of events per binding (propose,
# promote/reject, revoke/supersede); this bound keeps chain walks finite
# while leaving generous headroom.
MAX_BINDING_EVENTS = 64
MAX_EFFECTIVE_BINDINGS = 32

# Recovery/readiness walks are deliberately finite.  These ceilings cover
# many fully populated namespace catalogs while preventing a malformed store
# from turning a certification read into an unbounded receipt-chain scan.
MAX_RECOVERY_CATALOGS = 64
MAX_RECOVERY_BINDINGS = 2_048
MAX_RECOVERY_EVENTS = 32_768

MEMORA_RECOVERY_AUDIT_SCHEMA = "synapse-s2.memora-recovery-audit.v1"
MEMORA_RECOVERY_AUDIT_KEYS = frozenset(
    {
        "schema",
        "audit_revision",
        "catalog_count",
        "binding_projection_count",
        "governance_event_receipt_count",
        "source_witness_count",
        "cue_count",
        "promoted_binding_count",
        "effective_binding_count",
        "ineffective_promoted_binding_count",
        "provider_drift_binding_count",
        "source_drift_binding_count",
        "active_provider_revision",
        "integrity_valid",
        "effective_bindings_valid",
        "raw_cue_terms_included",
        "raw_source_text_included",
        "vectors_included",
    }
)

BINDING_STATES = frozenset(
    {"proposed", "promoted", "rejected", "revoked", "superseded"}
)
EFFECTIVE_STATE = "promoted"
TERMINAL_STATES = frozenset({"rejected", "revoked", "superseded"})
ALLOWED_TRANSITIONS = frozenset(
    {
        ("proposed", "promoted"),
        ("proposed", "rejected"),
        ("promoted", "revoked"),
        ("promoted", "superseded"),
    }
)

_EVENT_ACTOR_FIELDS = {
    "propose": "proposed_by",
    "promote": "reviewed_by",
    "reject": "reviewed_by",
    "revoke": "revoked_by",
    "supersede": "superseded_by",
}

# Provider identity string fields that must match exactly (nonempty on both
# sides) for a binding to be promotable or effective.
_PROVIDER_IDENTITY_FIELDS = (
    "provider",
    "provider_type",
    "model_id",
    "revision",
    "config_fingerprint",
)
# Provider identity booleans that must be literally True on both sides.
_PROVIDER_TRUE_FIELDS = ("semantic", "local_only", "ready", "learned")

# Source witnesses are non-content lifecycle witnesses (see memory_store
# MEMORA_WITNESS_SCHEMA): the row's exact identity and version times, byte
# counts with gate-relative oversized flags, and the per-memory
# memory_events frontier.  Witnesses never carry content, content digests,
# or signatures/keys over content -- a stored digest or public signature of
# untrusted content would be a durable offline equality oracle.  Every
# supported mutation appends a memory event and advances updated_at, so a
# changed, replaced, or deleted source invalidates its witness; out-of-band
# SQLite tamper bypassing the mutation API is outside witness scope and is
# handled by store/recovery integrity auditing.

_ACTOR_RE = re.compile(r"[^A-Za-z0-9_.:@-]+")
_CANONICAL_BINDING_ID_RE = re.compile(r"s2mb_[0-9a-f]{32}")
_ABSTRACTION_ID_RE = re.compile(r"s2abs_[0-9a-f]{32}")
_EVENT_ID_RE = re.compile(r"s2mg_[0-9a-f]{32}")
_REVISION_RE = re.compile(r"[0-9a-f]{64}")
_MEMORY_ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,200}")
_CUE_ID_RE = re.compile(r"s2shcue_[0-9a-f]{20}")
_ALLOWED_CUE_ASPECTS = frozenset({"semantic-facet", "keyword", "label-token"})


class MemoraGovernanceError(RuntimeError):
    pass


class MemoraGovernanceValidationError(MemoraGovernanceError, ValueError):
    pass


class MemoraGovernanceConflict(MemoraGovernanceError):
    pass


class MemoraGovernanceNotFound(MemoraGovernanceError):
    pass


class MemoraGovernanceStaleRevision(MemoraGovernanceError):
    pass


class MemoraGovernanceInvalidTransition(MemoraGovernanceError):
    pass


class MemoraGovernanceIntegrityError(MemoraGovernanceError):
    pass


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


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and _REVISION_RE.fullmatch(value) is not None


def _is_finite_positive(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) > 0
    )


def _is_exact_nonneg_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def validate_memora_recovery_audit(value: Any) -> dict[str, Any]:
    """Validate the closed, content-free Memora recovery proof contract."""

    if not isinstance(value, Mapping) or set(value) != MEMORA_RECOVERY_AUDIT_KEYS:
        raise MemoraGovernanceIntegrityError(
            "memora recovery audit contract is invalid"
        )
    payload = dict(value)
    count_fields = (
        "catalog_count",
        "binding_projection_count",
        "governance_event_receipt_count",
        "source_witness_count",
        "cue_count",
        "promoted_binding_count",
        "effective_binding_count",
        "ineffective_promoted_binding_count",
        "provider_drift_binding_count",
        "source_drift_binding_count",
    )
    if (
        payload.get("schema") != MEMORA_RECOVERY_AUDIT_SCHEMA
        or not _is_hex64(payload.get("audit_revision"))
        or payload.get("active_provider_revision") != "absent"
        and not _is_hex64(payload.get("active_provider_revision"))
        or any(not _is_exact_nonneg_int(payload.get(field)) for field in count_fields)
        or payload.get("integrity_valid") is not True
        or type(payload.get("effective_bindings_valid")) is not bool
        or payload.get("raw_cue_terms_included") is not False
        or payload.get("raw_source_text_included") is not False
        or payload.get("vectors_included") is not False
    ):
        raise MemoraGovernanceIntegrityError(
            "memora recovery audit contract is invalid"
        )
    promoted = int(payload["promoted_binding_count"])
    effective = int(payload["effective_binding_count"])
    ineffective = int(payload["ineffective_promoted_binding_count"])
    provider_drift = int(payload["provider_drift_binding_count"])
    source_drift = int(payload["source_drift_binding_count"])
    if (
        promoted > int(payload["binding_projection_count"])
        or effective + ineffective != promoted
        or provider_drift > ineffective
        or source_drift > ineffective
        or bool(payload["effective_bindings_valid"]) != (ineffective == 0)
        or (promoted == 0) != (payload["active_provider_revision"] == "absent")
        or int(payload["catalog_count"]) > MAX_RECOVERY_CATALOGS
        or int(payload["binding_projection_count"]) > MAX_RECOVERY_BINDINGS
        or int(payload["governance_event_receipt_count"]) > MAX_RECOVERY_EVENTS
    ):
        raise MemoraGovernanceIntegrityError(
            "memora recovery audit counts are inconsistent"
        )
    return payload


def _finite_time(value: Any, *, field: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise MemoraGovernanceValidationError(
            f"{field} must be a finite timestamp"
        ) from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise MemoraGovernanceValidationError(f"{field} must be a finite timestamp")
    return parsed


def _clean_actor(value: Any, *, field: str) -> str:
    try:
        raw = reject_sensitive_identifier(value, field=field).strip()
    except ValueError as exc:
        raise MemoraGovernanceValidationError(f"{field} is invalid") from exc
    cleaned = _ACTOR_RE.sub("_", raw).strip("._-:@")
    if not cleaned:
        raise MemoraGovernanceValidationError(f"{field} is required")
    return cleaned[:128]


def _clean_context(value: Any, *, field: str = "context_id") -> str:
    return _clean_actor(value, field=field)


def _clean_request_id(
    value: Any | None,
    *,
    action: str,
    request_fingerprint: str,
) -> str:
    if value is None or not str(value).strip():
        if not action or _REVISION_RE.fullmatch(request_fingerprint) is None:
            raise MemoraGovernanceValidationError(
                "automatic governance request identity is unavailable"
            )
        seed = f"memora-governance-auto:v1\x1f{action}\x1f{request_fingerprint}"
        return "s2mgr_auto_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
    try:
        raw = reject_sensitive_identifier(
            value, field="governance_request_id"
        ).strip()
    except ValueError as exc:
        raise MemoraGovernanceValidationError(
            "governance_request_id is invalid"
        ) from exc
    if (
        not raw
        or len(raw.encode("utf-8")) > 160
        or _ACTOR_RE.search(raw) is not None
    ):
        raise MemoraGovernanceValidationError(
            "governance_request_id must be 1-160 canonical identifier characters"
        )
    return raw


def _clean_binding_id(value: Any) -> str:
    try:
        raw = reject_sensitive_identifier(value, field="binding_id").strip()
    except ValueError as exc:
        raise MemoraGovernanceValidationError("binding_id is invalid") from exc
    if _CANONICAL_BINDING_ID_RE.fullmatch(raw) is None:
        raise MemoraGovernanceValidationError(
            "binding_id must be canonical s2mb_ plus 32 lowercase hex characters"
        )
    return raw


def _clean_revision(value: Any) -> str:
    try:
        raw = reject_sensitive_identifier(value, field="expected_revision").strip()
    except ValueError as exc:
        raise MemoraGovernanceValidationError("expected_revision is invalid") from exc
    if _REVISION_RE.fullmatch(raw) is None:
        raise MemoraGovernanceValidationError(
            "expected_revision must be exactly 64 lowercase hex characters"
        )
    return raw


def _clean_reason(value: Any, *, required: bool = True) -> tuple[str, int]:
    redacted, redaction_count = redact_capture_text(str(value or "").strip())
    encoded = redacted.encode("utf-8")
    if len(encoded) > MAX_REASON_BYTES:
        redacted = encoded[:MAX_REASON_BYTES].decode("utf-8", errors="ignore").strip()
    if required and not redacted:
        raise MemoraGovernanceValidationError("reason is required")
    return redacted, int(redaction_count)


def _require_confirm(value: Any) -> None:
    if value is not True:
        raise MemoraGovernanceValidationError(
            "confirm must be the exact boolean true for this governed mutation"
        )


def validate_provider_identity(identity: Any, *, source: str) -> dict[str, Any]:
    """Full fail-closed provider identity validation (raises on any gap)."""

    if not isinstance(identity, Mapping):
        raise MemoraGovernanceValidationError(
            f"{source} provider identity is missing"
        )
    for field in _PROVIDER_IDENTITY_FIELDS:
        value = identity.get(field)
        if not isinstance(value, str) or not value.strip():
            raise MemoraGovernanceValidationError(
                f"{source} provider identity field {field} is missing"
            )
    if identity.get("provider_type") != SUPPORTED_PROVIDER_TYPE:
        raise MemoraGovernanceValidationError(
            f"{source} provider type is not the supported local neural provider"
        )
    for field in _PROVIDER_TRUE_FIELDS:
        if identity.get(field) is not True:
            raise MemoraGovernanceValidationError(
                f"{source} provider identity field {field} must be literally true"
            )
    dimensions = identity.get("dimensions")
    if (
        type(dimensions) is not int
        or dimensions < 1
        or dimensions > MAX_PROVIDER_DIMENSIONS
    ):
        raise MemoraGovernanceValidationError(
            f"{source} provider dimensions are not an exact bounded integer"
        )
    return {
        "provider": str(identity["provider"]),
        "provider_type": str(identity["provider_type"]),
        "model_id": str(identity["model_id"]),
        "revision": str(identity["revision"]),
        "config_fingerprint": str(identity["config_fingerprint"]),
        "dimensions": dimensions,
        "semantic": True,
        "local_only": True,
        "ready": True,
        "learned": True,
    }


def provider_identities_match(
    stored: Mapping[str, Any],
    active: Mapping[str, Any],
) -> list[str]:
    """Return mismatch reasons between two provider identities (empty = match).

    Compares every identity field: the exact string identity quintuple, the
    exact dimensions, and the literally-true booleans on both sides.
    """

    reasons: list[str] = []
    for field in _PROVIDER_IDENTITY_FIELDS:
        stored_value = stored.get(field)
        active_value = active.get(field)
        if (
            not isinstance(stored_value, str)
            or not stored_value
            or not isinstance(active_value, str)
            or not active_value
        ):
            reasons.append(f"provider-identity-missing:{field}")
        elif stored_value != active_value:
            reasons.append(f"provider-drift:{field}")
    stored_dimensions = stored.get("dimensions")
    active_dimensions = active.get("dimensions")
    if (
        type(stored_dimensions) is not int
        or type(active_dimensions) is not int
        or stored_dimensions != active_dimensions
    ):
        reasons.append("provider-drift:dimensions")
    for field in _PROVIDER_TRUE_FIELDS:
        if stored.get(field) is not True:
            reasons.append(f"provider-not-true:stored:{field}")
        if active.get(field) is not True:
            reasons.append(f"provider-not-true:active:{field}")
    return reasons


class MemoraGovernance:
    """Governed Memora cue-binding lifecycle over a durable store."""

    def __init__(
        self,
        store: DurableMemoryStore,
        *,
        plan_recomputer: Callable[..., Mapping[str, Any]] | None = None,
        clock: Callable[[], float] = time.time,
        allow_test_time: bool = False,
    ) -> None:
        if not isinstance(store, DurableMemoryStore):
            raise TypeError("store must be a DurableMemoryStore")
        self.store = store
        if plan_recomputer is not None and not callable(plan_recomputer):
            raise TypeError("plan_recomputer must be callable")
        # The only trusted source of proposal content: an in-process
        # recomputation over authoritative rows, installed by the backend.
        # Wire surfaces (Core/MCP/CLI/HTTP) never carry plans or witnesses.
        self._plan_recomputer = plan_recomputer
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._clock = clock
        self._allow_test_time = bool(allow_test_time)

    def _trusted_now(self, supplied: float | None) -> float:
        if supplied is not None and not self._allow_test_time:
            raise MemoraGovernanceValidationError(
                "caller-supplied authorization time is not permitted"
            )
        value = self._clock() if supplied is None else supplied
        return _finite_time(value, field="now")

    @staticmethod
    def _binding_key(binding_id: str) -> str:
        return BINDING_KEY_PREFIX + binding_id

    @staticmethod
    def _catalog_key(context_id: str) -> str:
        return CATALOG_KEY_PREFIX + context_id

    @staticmethod
    def _operation_id(action: str, request_id: str) -> str:
        seed = f"memora-governance:v1\x1f{action}\x1f{request_id}".encode("utf-8")
        return "s2mg_" + hashlib.sha256(seed).hexdigest()[:32]

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
            raise MemoraGovernanceIntegrityError(
                "memora governance projection is invalid"
            ) from exc
        if not isinstance(value, dict):
            raise MemoraGovernanceIntegrityError(
                "memora governance projection is invalid"
            )
        return value

    @staticmethod
    def _write_projection(
        conn: Any, key: str, value: Mapping[str, Any], now: float
    ) -> None:
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

    # ------------------------------------------------------------------
    # Deep structural validation (fail closed, no silent truncation)
    # ------------------------------------------------------------------

    @staticmethod
    def _validated_binding_structure(binding: Mapping[str, Any]) -> None:
        """Strictly bound and type every internal field of a projection.

        Any violation rejects the whole projection with an integrity error.
        Nothing is dropped or truncated to make a malformed projection
        usable: a corrupt or tampered binding contributes zero routing
        effect.
        """

        def _fail(detail: str) -> None:
            raise MemoraGovernanceIntegrityError(
                f"memora binding projection failed deep validation: {detail}"
            )

        context = binding.get("context_id")
        if not isinstance(context, str) or not context:
            _fail("context")
        for field in ("created_at", "updated_at", "proposed_at"):
            if not _is_finite_positive(binding.get(field)):
                _fail(field)
        for field in ("reviewed_at", "revoked_at", "superseded_at"):
            value = binding.get(field)
            if value is not None and not _is_finite_positive(value):
                _fail(field)
        for field in ("automatic_promotion", "raw_source_text_stored", "vectors_stored"):
            if binding.get(field) is not False:
                _fail(field)
        for field in ("supersedes_binding_id", "superseded_by_binding_id"):
            value = binding.get(field)
            if value is not None and (
                not isinstance(value, str)
                or _CANONICAL_BINDING_ID_RE.fullmatch(value) is None
            ):
                _fail(field)
        if (
            not _is_exact_nonneg_int(binding.get("event_count"))
            or binding["event_count"] < 1
            or binding["event_count"] > MAX_BINDING_EVENTS
        ):
            _fail("event_count")
        previous = binding.get("previous_revision")
        if previous is not None and not _is_hex64(previous):
            _fail("previous_revision")
        if not isinstance(binding.get("last_event_id"), str) or (
            _EVENT_ID_RE.fullmatch(binding["last_event_id"]) is None
        ):
            _fail("last_event_id")
        if not _is_hex64(binding.get("last_request_fingerprint")):
            _fail("last_request_fingerprint")

        plan = binding.get("plan")
        if not isinstance(plan, dict):
            _fail("plan")
        if not _is_hex64(plan.get("plan_digest")):
            _fail("plan.plan_digest")
        if not _is_exact_nonneg_int(plan.get("cluster_ordinal")):
            _fail("plan.cluster_ordinal")
        if not isinstance(plan.get("cluster_id"), str) or not plan["cluster_id"]:
            _fail("plan.cluster_id")
        if not isinstance(plan.get("planner_version"), str) or (
            not plan["planner_version"]
        ):
            _fail("plan.planner_version")
        if plan.get("learned") is not True:
            _fail("plan.learned")
        threshold = plan.get("similarity_threshold")
        if (
            not isinstance(threshold, (int, float))
            or isinstance(threshold, bool)
            or not math.isfinite(float(threshold))
            or not (0.0 <= float(threshold) <= 1.0)
        ):
            _fail("plan.similarity_threshold")

        try:
            validate_provider_identity(binding.get("provider"), source="stored")
        except MemoraGovernanceValidationError:
            _fail("provider")

        snapshot = binding.get("namespace_snapshot")
        if not isinstance(snapshot, dict):
            _fail("namespace_snapshot")
        if not _is_hex64(snapshot.get("snapshot_revision")):
            _fail("namespace_snapshot.snapshot_revision")
        for field in ("entry_count", "sampled_count"):
            if not _is_exact_nonneg_int(snapshot.get(field)):
                _fail(f"namespace_snapshot.{field}")
        if type(snapshot.get("sampling_truncated")) is not bool:
            _fail("namespace_snapshot.sampling_truncated")

        limits = binding.get("limits")
        if (
            not isinstance(limits, dict)
            or limits.get("max_source_text_bytes")
            != MEMORA_SHADOW_MAX_SOURCE_TEXT_BYTES
            or limits.get("max_metadata_bytes") != MEMORA_SHADOW_MAX_METADATA_BYTES
        ):
            # The byte gates are approved constants: a projection claiming
            # different gates was not produced by this pipeline.
            _fail("limits")

        sources = binding.get("sources")
        if (
            not isinstance(sources, list)
            or not sources
            or len(sources) > MAX_SOURCES_PER_BINDING
        ):
            _fail("sources")
        source_ids: set[str] = set()
        for witness in sources:
            if not isinstance(witness, dict):
                _fail("sources.entry")
            memory_id = witness.get("memory_id")
            if (
                not isinstance(memory_id, str)
                or _MEMORY_ID_RE.fullmatch(memory_id) is None
                or memory_id in source_ids
            ):
                _fail("sources.memory_id")
            source_ids.add(memory_id)
            if witness.get("context_id") != context:
                _fail("sources.context_id")
            if witness.get("schema") != MEMORA_WITNESS_SCHEMA:
                _fail("sources.schema")
            for field in ("source_text_bytes", "metadata_bytes"):
                if not _is_exact_nonneg_int(witness.get(field)):
                    _fail(f"sources.{field}")
            for field in ("created_at", "updated_at", "last_event_at"):
                if not _is_finite_positive(witness.get(field)):
                    _fail(f"sources.{field}")
            # Every row created through the mutation API carries at least one
            # upsert event, so a promotable witness frontier is never empty.
            for field in ("event_count", "upsert_event_count", "last_event_id"):
                value = witness.get(field)
                if not _is_exact_nonneg_int(value) or value < 1:
                    _fail(f"sources.{field}")
            if witness.get("source_text_oversized") is not False or (
                witness.get("metadata_oversized") is not False
            ):
                _fail("sources.oversized")

        abstraction = binding.get("abstraction")
        if not isinstance(abstraction, dict):
            _fail("abstraction")
        if (
            not isinstance(abstraction.get("abstraction_id"), str)
            or _ABSTRACTION_ID_RE.fullmatch(abstraction["abstraction_id"]) is None
        ):
            _fail("abstraction.abstraction_id")
        if abstraction.get("medoid_memory_id") not in source_ids:
            _fail("abstraction.medoid_memory_id")
        if abstraction.get("member_count") != len(source_ids):
            _fail("abstraction.member_count")
        display_term = abstraction.get("display_term")
        if not isinstance(display_term, str) or (
            len(display_term.encode("utf-8")) > MAX_CUE_TERM_BYTES
        ):
            _fail("abstraction.display_term")
        if abstraction.get("trust") != CUE_TRUST_MARKER:
            _fail("abstraction.trust")

        cues = binding.get("cues")
        if not isinstance(cues, list) or not cues or len(cues) > MAX_CUES_PER_BINDING:
            _fail("cues")
        seen_cue_ids: set[str] = set()
        seen_terms: set[str] = set()
        for cue in cues:
            if not isinstance(cue, dict):
                _fail("cues.entry")
            cue_id = cue.get("cue_id")
            if (
                not isinstance(cue_id, str)
                or _CUE_ID_RE.fullmatch(cue_id) is None
                or cue_id in seen_cue_ids
            ):
                _fail("cues.cue_id")
            seen_cue_ids.add(cue_id)
            term = cue.get("term")
            if (
                not isinstance(term, str)
                or not term
                or term != term.strip().lower()
                or len(term.encode("utf-8")) > MAX_CUE_TERM_BYTES
                or term in seen_terms
            ):
                _fail("cues.term")
            seen_terms.add(term)
            if cue.get("aspect") not in _ALLOWED_CUE_ASPECTS:
                _fail("cues.aspect")
            supporting = cue.get("supporting_memory_ids")
            if (
                not isinstance(supporting, list)
                or not supporting
                or supporting != sorted(set(supporting))
                or not all(item in source_ids for item in supporting)
            ):
                _fail("cues.supporting_memory_ids")
            if cue.get("member_support") != len(supporting):
                _fail("cues.member_support")
            if cue.get("trust") != CUE_TRUST_MARKER:
                _fail("cues.trust")

    # ------------------------------------------------------------------
    # Fail-closed projection/receipt validation
    # ------------------------------------------------------------------

    def _validated_binding_conn(self, conn: Any, binding_id: str) -> dict[str, Any]:
        """Read a binding only when it is bound to its own last receipt."""

        clean_id = _clean_binding_id(binding_id)
        binding = self._read_json_row(conn, self._binding_key(clean_id))
        if binding is None:
            raise MemoraGovernanceNotFound("memora binding was not found")
        try:
            revision_valid = binding.get("revision") == _projection_revision(binding)
            event_count = int(binding.get("event_count", 0))
        except (TypeError, ValueError, OverflowError):
            revision_valid = False
            event_count = 0
        if (
            binding.get("schema") != BINDING_SCHEMA
            or binding.get("binding_id") != clean_id
            or binding.get("state") not in BINDING_STATES
            or binding.get("automatic_promotion") is not False
            or not revision_valid
            or event_count < 1
        ):
            raise MemoraGovernanceIntegrityError(
                "memora binding projection failed integrity validation"
            )
        self._validated_binding_structure(binding)
        event_id = str(binding.get("last_event_id") or "")
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
            raise MemoraGovernanceIntegrityError(
                "memora binding lost its last governance receipt"
            )
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MemoraGovernanceIntegrityError(
                "memora binding receipt is invalid"
            ) from exc
        action = str(payload.get("action") or "") if isinstance(payload, dict) else ""
        request_id = (
            str(payload.get("request_id") or "") if isinstance(payload, dict) else ""
        )
        actor_field = _EVENT_ACTOR_FIELDS.get(action)
        expected_reason = (
            binding.get("proposal_reason")
            if action == "propose"
            else binding.get("decision_reason")
        )
        result = payload.get("result") if isinstance(payload, dict) else None
        result_binding = result.get("binding") if isinstance(result, dict) else None
        try:
            receipt_created_at = float(row["created_at"])
            binding_updated_at = float(binding.get("updated_at"))
            created_at_matches = (
                math.isfinite(receipt_created_at)
                and receipt_created_at == binding_updated_at
            )
        except (TypeError, ValueError, OverflowError):
            created_at_matches = False
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != EVENT_SCHEMA
            or payload.get("event_id") != event_id
            or self._operation_id(action, request_id) != event_id
            or row["operation_type"] != EVENT_OPERATION_PREFIX + action
            or row["context_id"] != binding.get("context_id")
            or row["before_revision"] != payload.get("before_revision")
            or row["after_revision"] != binding.get("revision")
            or not created_at_matches
            or payload.get("after_revision") != binding.get("revision")
            or payload.get("after_state") != binding.get("state")
            or payload.get("binding_id") != clean_id
            or payload.get("event_sequence") != event_count
            or payload.get("automatic_promotion") is not False
            or _REVISION_RE.fullmatch(
                str(payload.get("request_fingerprint") or "")
            )
            is None
            or payload.get("request_fingerprint")
            != binding.get("last_request_fingerprint")
            or payload.get("before_revision")
            != ("" if binding.get("previous_revision") is None
                else binding.get("previous_revision"))
            or payload.get("reason") != expected_reason
            or not isinstance(result, dict)
            or result.get("state") != binding.get("state")
            or result_binding != binding
            or actor_field is None
            or payload.get("actor") != binding.get(actor_field)
        ):
            raise MemoraGovernanceIntegrityError(
                "memora binding does not match its last governance receipt"
            )
        return binding

    def _validated_catalog_conn(
        self, conn: Any, context_id: str
    ) -> dict[str, Any] | None:
        catalog = self._read_json_row(conn, self._catalog_key(context_id))
        if catalog is None:
            return None
        try:
            revision_valid = catalog.get("revision") == _projection_revision(catalog)
        except (TypeError, ValueError, OverflowError):
            revision_valid = False
        entries = catalog.get("bindings")
        if (
            catalog.get("schema") != CATALOG_SCHEMA
            or catalog.get("context_id") != context_id
            or not revision_valid
            or not isinstance(entries, list)
            or len(entries) > MAX_CATALOG_BINDINGS
        ):
            raise MemoraGovernanceIntegrityError(
                "memora catalog projection failed integrity validation"
            )
        seen: set[str] = set()
        for item in entries:
            if (
                not isinstance(item, dict)
                or _CANONICAL_BINDING_ID_RE.fullmatch(
                    str(item.get("binding_id") or "")
                )
                is None
                or item.get("state") not in BINDING_STATES
                or not isinstance(item.get("abstraction_id"), str)
                or _ABSTRACTION_ID_RE.fullmatch(item["abstraction_id"]) is None
                or not _is_hex64(item.get("revision"))
                or not _is_finite_positive(item.get("updated_at"))
            ):
                raise MemoraGovernanceIntegrityError(
                    "memora catalog entry failed integrity validation"
                )
            if item["binding_id"] in seen:
                raise MemoraGovernanceIntegrityError(
                    "memora catalog contains a duplicate binding"
                )
            seen.add(item["binding_id"])
        return catalog

    @staticmethod
    def _catalog_cross_check(
        *,
        requested_context: str,
        catalog_entry: Mapping[str, Any],
        binding: Mapping[str, Any],
    ) -> None:
        """A catalog row must exactly describe its projection, in scope.

        A binding whose projection lives in another namespace, or whose
        catalog entry disagrees on any identity field, is an integrity
        failure and yields no cue.
        """

        if (
            binding.get("context_id") != requested_context
            or catalog_entry.get("binding_id") != binding.get("binding_id")
            or catalog_entry.get("state") != binding.get("state")
            or catalog_entry.get("abstraction_id")
            != (binding.get("abstraction") or {}).get("abstraction_id")
            or catalog_entry.get("revision") != binding.get("revision")
            or catalog_entry.get("updated_at") != binding.get("updated_at")
        ):
            raise MemoraGovernanceIntegrityError(
                "memora catalog entry does not match its binding projection"
            )

    def _catalog_upsert_conn(
        self,
        conn: Any,
        *,
        context_id: str,
        binding: Mapping[str, Any],
        now: float,
    ) -> dict[str, Any]:
        catalog = self._validated_catalog_conn(conn, context_id)
        if catalog is None:
            entries: list[dict[str, Any]] = []
            event_count = 0
        else:
            entries = [dict(item) for item in catalog["bindings"]]
            event_count = int(catalog.get("event_count", 0))
        entry = {
            "binding_id": str(binding["binding_id"]),
            "state": str(binding["state"]),
            "abstraction_id": str(binding["abstraction"]["abstraction_id"]),
            "updated_at": float(binding["updated_at"]),
            "revision": str(binding["revision"]),
        }
        replaced = False
        for index, item in enumerate(entries):
            if item["binding_id"] == entry["binding_id"]:
                entries[index] = entry
                replaced = True
                break
        if not replaced:
            if len(entries) >= MAX_CATALOG_BINDINGS:
                raise MemoraGovernanceConflict(
                    "memora catalog is full for this namespace"
                )
            entries.append(entry)
        entries.sort(key=lambda item: item["binding_id"])
        updated = _with_revision(
            {
                "schema": CATALOG_SCHEMA,
                "context_id": context_id,
                "bindings": entries,
                "event_count": event_count + 1,
                "updated_at": now,
            }
        )
        self._write_projection(conn, self._catalog_key(context_id), updated, now)
        return updated

    # ------------------------------------------------------------------
    # Witness + provider verification
    # ------------------------------------------------------------------

    @staticmethod
    def _binding_gates(binding: Mapping[str, Any]) -> tuple[int, int]:
        limits = binding.get("limits") if isinstance(binding.get("limits"), dict) else {}
        text_gate = limits.get("max_source_text_bytes")
        metadata_gate = limits.get("max_metadata_bytes")
        if type(text_gate) is not int or type(metadata_gate) is not int:
            raise MemoraGovernanceIntegrityError(
                "memora binding is missing its materialization gates"
            )
        return text_gate, metadata_gate

    def _witness_mismatches_conn(
        self, conn: Any, binding: Mapping[str, Any]
    ) -> list[str]:
        """Verify stored lifecycle witnesses against live rows (fail closed).

        Verification recomputes each live row's lifecycle facts (identity,
        version times, byte counts, oversized flags, memory-event frontier)
        and requires exact equality, so a deleted, changed, moved, or
        grown-oversized source -- including a same-length replacement made
        through the MemoryStore API, which appends a memory event --
        invalidates the binding.  No content, digest, or key material is
        stored, so nothing here can act as an offline equality oracle.
        Out-of-band SQLite tamper bypassing the mutation API is outside
        witness scope and is handled by store/recovery integrity auditing.
        """

        sources = binding.get("sources")
        if not isinstance(sources, list) or not sources:
            return ["witnesses-missing"]
        text_gate, metadata_gate = self._binding_gates(binding)
        witnesses: dict[str, Mapping[str, Any]] = {}
        for item in sources:
            if not isinstance(item, Mapping):
                return ["witnesses-malformed"]
            witnesses[str(item.get("memory_id") or "")] = item
        results = self.store.memora_verify_witnesses_conn(
            conn,
            witnesses,
            text_gate=text_gate,
            metadata_gate=metadata_gate,
        )
        reasons: list[str] = []
        for memory_id in sorted(results):
            for reason in results[memory_id]:
                reasons.append(f"{reason}:{memory_id}")
        return reasons

    def binding_effectiveness_conn(
        self,
        conn: Any,
        binding: Mapping[str, Any],
        *,
        active_provider_identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Evaluate whether a validated binding may route right now."""

        reasons: list[str] = []
        if binding.get("state") != EFFECTIVE_STATE:
            reasons.append(f"state:{binding.get('state')}")
        provider = (
            binding.get("provider")
            if isinstance(binding.get("provider"), dict)
            else {}
        )
        if not isinstance(active_provider_identity, Mapping):
            reasons.append("provider-identity-missing:active")
        else:
            reasons.extend(
                provider_identities_match(provider, active_provider_identity)
            )
        if not reasons:
            reasons.extend(self._witness_mismatches_conn(conn, binding))
        return {"effective": not reasons, "reasons": reasons}

    # ------------------------------------------------------------------
    # Exactly-once replay
    # ------------------------------------------------------------------

    def _replay_event(
        self,
        conn: Any,
        *,
        action: str,
        request_id: str,
        request_fingerprint: str,
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
            raise MemoraGovernanceIntegrityError(
                "memora governance event is invalid"
            ) from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != EVENT_SCHEMA
            or payload.get("event_id") != operation_id
            or payload.get("action") != action
            or payload.get("request_id") != request_id
            or payload.get("request_fingerprint") != request_fingerprint
            or row["operation_type"] != EVENT_OPERATION_PREFIX + action
        ):
            raise MemoraGovernanceConflict(
                "governance_request_id conflicts with prior use"
            )
        result = payload.get("result")
        if not isinstance(result, dict):
            raise MemoraGovernanceIntegrityError(
                "memora governance replay result is invalid"
            )
        historical = result.get("binding")
        try:
            historical_revision_valid = (
                isinstance(historical, dict)
                and historical.get("revision") == _projection_revision(historical)
            )
        except (TypeError, ValueError, OverflowError):
            historical_revision_valid = False
        operation = action + "-memora-binding"
        envelope_valid = False
        if isinstance(historical, dict):
            try:
                envelope_valid = result == self._result_envelope(
                    operation, historical
                )
            except (KeyError, TypeError, ValueError):
                envelope_valid = False
        if (
            not isinstance(historical, dict)
            or historical.get("binding_id") != payload.get("binding_id")
            or historical.get("revision") != payload.get("after_revision")
            or historical.get("state") != payload.get("after_state")
            or not historical_revision_valid
            or historical.get("last_event_id") != operation_id
            or historical.get("last_request_fingerprint") != request_fingerprint
            or not envelope_valid
        ):
            raise MemoraGovernanceIntegrityError(
                "memora governance replay result does not match its event"
            )
        current = self._validated_binding_conn(conn, str(payload["binding_id"]))
        # Replay must prove the historical event is a validated member of the
        # binding's receipt chain, not merely a receipt that self-describes:
        # this walk re-validates every event, including non-last ones.
        chain = self._binding_events_conn(conn, current)
        if not any(
            event["event_id"] == operation_id
            and event["event_sequence"] == payload.get("event_sequence")
            and event["after_revision"] == payload.get("after_revision")
            for event in chain
        ):
            raise MemoraGovernanceIntegrityError(
                "replayed event is not part of its binding's receipt chain"
            )
        # The replay envelope is rebuilt from validated data only (the
        # recomputed envelope over the validated current projection); no
        # stored top-level field is ever returned unchecked.
        refreshed = self._result_envelope(operation, current)
        refreshed["historical_state"] = str(historical.get("state") or "")
        refreshed["historical_revision"] = str(historical.get("revision") or "")
        refreshed["current_state"] = str(current.get("state") or "")
        refreshed["currently_effective_state"] = (
            current.get("state") == EFFECTIVE_STATE
        )
        if current.get("state") == EFFECTIVE_STATE:
            # A promoted binding replayed later still reports source drift
            # honestly: mismatched witnesses mean it no longer routes.
            refreshed["current_witness_mismatches"] = sorted(
                self._witness_mismatches_conn(conn, current)
            )
        refreshed["idempotent_replay"] = True
        return refreshed

    # ------------------------------------------------------------------
    # Receipt-chain validation (audit / history / replay)
    # ------------------------------------------------------------------

    def _history_receipt_conn(
        self,
        conn: Any,
        *,
        binding_id: str,
        context_id: str,
        after_revision: str,
    ) -> tuple[Any, dict[str, Any]]:
        """Fetch exactly one chain receipt keyed by its after_revision."""

        rows = conn.execute(
            """
            SELECT operation_id, operation_type, context_id, before_revision,
                   after_revision, payload_json, created_at
            FROM store_maintenance_receipts
            WHERE after_revision = ?
              AND context_id = ?
              AND operation_type LIKE ?
            """,
            (after_revision, context_id, EVENT_OPERATION_PREFIX + "%"),
        ).fetchall()
        matched: tuple[Any, dict[str, Any]] | None = None
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise MemoraGovernanceIntegrityError(
                    "memora governance chain receipt is invalid"
                ) from exc
            if not isinstance(payload, dict) or (
                payload.get("binding_id") != binding_id
            ):
                continue
            if matched is not None:
                raise MemoraGovernanceIntegrityError(
                    "memora governance chain has a duplicate receipt"
                )
            matched = (row, payload)
        if matched is None:
            raise MemoraGovernanceIntegrityError(
                "memora binding is missing a receipt from its chain"
            )
        return matched

    def _binding_events_conn(
        self, conn: Any, binding: Mapping[str, Any]
    ) -> list[dict[str, Any]]:
        """Walk and fully validate the binding's receipt chain, latest first.

        Every event -- not only the last -- is validated: operation identity,
        context, before/after revisions, created_at, actor field, result
        envelope, deep structure of the historical projection, and the
        ``previous_revision`` linkage between consecutive events.  Any gap or
        tamper anywhere in the chain fails closed.
        """

        binding_id = str(binding["binding_id"])
        context_id = str(binding["context_id"])
        events: list[dict[str, Any]] = []
        expected_revision = str(binding["revision"])
        expected_sequence = int(binding["event_count"])
        expected_state = str(binding["state"])
        if expected_sequence < 1 or expected_sequence > MAX_BINDING_EVENTS:
            raise MemoraGovernanceIntegrityError(
                "memora binding event count is out of bounds"
            )
        while True:
            row, payload = self._history_receipt_conn(
                conn,
                binding_id=binding_id,
                context_id=context_id,
                after_revision=expected_revision,
            )
            action = str(payload.get("action") or "")
            request_id = str(payload.get("request_id") or "")
            actor_field = _EVENT_ACTOR_FIELDS.get(action)
            result = payload.get("result")
            historical = (
                result.get("binding") if isinstance(result, dict) else None
            )
            before_revision = payload.get("before_revision")
            before_state = payload.get("before_state")
            try:
                created_at = float(row["created_at"])
                created_at_valid = math.isfinite(created_at) and created_at > 0
            except (TypeError, ValueError, OverflowError):
                created_at = 0.0
                created_at_valid = False
            try:
                historical_revision_valid = (
                    isinstance(historical, dict)
                    and historical.get("revision")
                    == _projection_revision(historical)
                )
            except (TypeError, ValueError, OverflowError):
                historical_revision_valid = False
            # The stored result must be exactly the recomputed envelope over
            # its own historical projection: no unchecked top-level field
            # can survive into history, audit, or replay output.
            envelope_valid = False
            if isinstance(historical, dict) and isinstance(result, dict):
                try:
                    envelope_valid = result == self._result_envelope(
                        action + "-memora-binding", historical
                    )
                except (KeyError, TypeError, ValueError):
                    envelope_valid = False
            reason_field = (
                "proposal_reason" if action == "propose" else "decision_reason"
            )
            if (
                payload.get("schema") != EVENT_SCHEMA
                or actor_field is None
                or payload.get("event_id") != str(row["operation_id"])
                or self._operation_id(action, request_id)
                != str(row["operation_id"])
                or row["operation_type"] != EVENT_OPERATION_PREFIX + action
                or row["context_id"] != context_id
                or row["before_revision"] != before_revision
                or row["after_revision"] != payload.get("after_revision")
                or payload.get("after_revision") != expected_revision
                or payload.get("event_sequence") != expected_sequence
                or payload.get("after_state") != expected_state
                or payload.get("automatic_promotion") is not False
                or not _is_hex64(payload.get("request_fingerprint"))
                or not created_at_valid
                or not isinstance(result, dict)
                or not historical_revision_valid
                or not isinstance(historical, dict)
                or not envelope_valid
                or historical.get("binding_id") != binding_id
                or historical.get("context_id") != context_id
                or historical.get("state") != expected_state
                or historical.get("event_count") != expected_sequence
                # The projection this event produced must itself point back
                # at this exact receipt: its recorded last event id and last
                # request fingerprint are bound to the receipt row.
                or historical.get("last_event_id") != str(row["operation_id"])
                or historical.get("last_request_fingerprint")
                != payload.get("request_fingerprint")
                # The receipt's reason must be the reason the projection
                # recorded for this proposal/decision.
                or payload.get("reason") != historical.get(reason_field)
                or historical.get("previous_revision")
                != (None if before_revision == "" else before_revision)
                or float(historical.get("updated_at") or 0.0) != created_at
                or payload.get("actor") != historical.get(actor_field)
            ):
                raise MemoraGovernanceIntegrityError(
                    "memora governance chain event failed validation"
                )
            self._validated_binding_structure(historical)
            if expected_sequence == 1:
                if (
                    action != "propose"
                    or before_revision != ""
                    or before_state is not None
                ):
                    raise MemoraGovernanceIntegrityError(
                        "memora governance chain does not begin with a proposal"
                    )
            else:
                if (
                    not _is_hex64(before_revision)
                    or before_state not in BINDING_STATES
                    or (before_state, expected_state) not in ALLOWED_TRANSITIONS
                ):
                    raise MemoraGovernanceIntegrityError(
                        "memora governance chain transition is invalid"
                    )
            events.append(
                {
                    "event_id": str(row["operation_id"]),
                    "operation_type": str(row["operation_type"]),
                    "action": action,
                    "actor": str(payload.get("actor") or ""),
                    "reason": str(payload.get("reason") or ""),
                    "before_state": before_state,
                    "after_state": expected_state,
                    "before_revision": before_revision,
                    "after_revision": expected_revision,
                    "event_sequence": expected_sequence,
                    "request_fingerprint": str(payload["request_fingerprint"]),
                    "created_at": created_at,
                }
            )
            if expected_sequence == 1:
                break
            expected_revision = str(before_revision)
            expected_state = str(before_state)
            expected_sequence -= 1
            if len(events) > MAX_BINDING_EVENTS:
                raise MemoraGovernanceIntegrityError(
                    "memora governance chain exceeds its event bound"
                )
        return events

    def audit_integrity(self, binding_id: str) -> dict[str, Any]:
        """Full fail-closed audit of one binding for certify/evidence packs.

        Validates the projection (self-digest, deep structure, last receipt),
        its catalog cross-check, and every event in its receipt chain.  Any
        tamper anywhere raises :class:`MemoraGovernanceIntegrityError`.
        """

        clean_id = _clean_binding_id(binding_id)
        with closing(self.store._connect_read_only()) as conn:
            with self.store._transaction(conn):
                binding = self._validated_binding_conn(conn, clean_id)
                self._catalog_entry_for_binding_conn(conn, binding)
                chain = self._binding_events_conn(conn, binding)
        return {
            "schema": "synapse-s2.memora-audit.v1",
            "binding_id": clean_id,
            "context_id": str(binding["context_id"]),
            "state": str(binding["state"]),
            "revision": str(binding["revision"]),
            "event_count": int(binding["event_count"]),
            "events_validated": len(chain),
            "chain_valid": True,
            "catalog_cross_checked": True,
            "automatic_promotion": False,
            "events": chain,
        }

    def audit_recovery_integrity(
        self,
        *,
        active_provider_identity: Mapping[str, Any] | None = None,
        expected_provider_revision: str | None = None,
    ) -> dict[str, Any]:
        """Audit every governed projection and receipt without exposing cues.

        Recovery and readiness need an aggregate assertion, not a page of
        individual bindings.  This walk validates every namespace catalog,
        every cataloged projection, every event in each projection's receipt
        chain, and the absence of orphan projections or governance receipts.
        It returns only counts and deterministic revisions; cue terms, source
        identifiers, source text, vectors, and event payloads never leave the
        read transaction.

        A promoted binding is considered effective only against the exact
        active learned-provider identity supplied by the caller.  Read-only
        downstream verifiers that deliberately do not construct the neural
        backend may instead supply the already signed provider revision; the
        audit then proves every promoted projection carries that exact
        identity before evaluating its witnesses.
        """

        catalog_upper = CATALOG_KEY_PREFIX + "\uffff"
        binding_upper = BINDING_KEY_PREFIX + "\uffff"
        with closing(self.store._connect_read_only()) as conn:
            with self.store._transaction(conn):
                catalog_total = int(
                    conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM store_metadata
                        WHERE key >= ? AND key < ?
                        """,
                        (CATALOG_KEY_PREFIX, catalog_upper),
                    ).fetchone()[0]
                )
                binding_total = int(
                    conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM store_metadata
                        WHERE key >= ? AND key < ?
                        """,
                        (BINDING_KEY_PREFIX, binding_upper),
                    ).fetchone()[0]
                )
                receipt_total = int(
                    conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM store_maintenance_receipts
                        WHERE operation_type LIKE ?
                        """,
                        (EVENT_OPERATION_PREFIX + "%",),
                    ).fetchone()[0]
                )
                if (
                    catalog_total > MAX_RECOVERY_CATALOGS
                    or binding_total > MAX_RECOVERY_BINDINGS
                    or receipt_total > MAX_RECOVERY_EVENTS
                ):
                    raise MemoraGovernanceIntegrityError(
                        "memora recovery audit exceeds its finite bounds"
                    )
                catalog_rows = conn.execute(
                    """
                    SELECT key
                    FROM store_metadata
                    WHERE key >= ? AND key < ?
                    ORDER BY key ASC
                    LIMIT ?
                    """,
                    (CATALOG_KEY_PREFIX, catalog_upper, MAX_RECOVERY_CATALOGS + 1),
                ).fetchall()
                binding_rows = conn.execute(
                    """
                    SELECT key
                    FROM store_metadata
                    WHERE key >= ? AND key < ?
                    ORDER BY key ASC
                    LIMIT ?
                    """,
                    (BINDING_KEY_PREFIX, binding_upper, MAX_RECOVERY_BINDINGS + 1),
                ).fetchall()
                if len(catalog_rows) != catalog_total or len(binding_rows) != binding_total:
                    raise MemoraGovernanceIntegrityError(
                        "memora recovery inventory changed during audit"
                    )

                inventory: list[dict[str, Any]] = []
                bindings: list[dict[str, Any]] = []
                expected_binding_keys: set[str] = set()
                seen_binding_ids: set[str] = set()
                source_witness_count = 0
                cue_count = 0
                validated_event_count = 0
                for row in catalog_rows:
                    key = str(row["key"])
                    context = _clean_context(key[len(CATALOG_KEY_PREFIX) :])
                    catalog = self._validated_catalog_conn(conn, context)
                    if catalog is None:
                        raise MemoraGovernanceIntegrityError(
                            "memora catalog disappeared during recovery audit"
                        )
                    catalog_event_count = catalog.get("event_count")
                    if (
                        not _is_exact_nonneg_int(catalog_event_count)
                        or not _is_finite_positive(catalog.get("updated_at"))
                    ):
                        raise MemoraGovernanceIntegrityError(
                            "memora catalog lifecycle counters are invalid"
                        )
                    namespace_events = 0
                    inventory_bindings: list[dict[str, Any]] = []
                    for entry in catalog["bindings"]:
                        binding_id = str(entry["binding_id"])
                        if binding_id in seen_binding_ids:
                            raise MemoraGovernanceIntegrityError(
                                "memora binding appears in multiple catalogs"
                            )
                        seen_binding_ids.add(binding_id)
                        expected_binding_keys.add(self._binding_key(binding_id))
                        binding = self._validated_binding_conn(conn, binding_id)
                        self._catalog_cross_check(
                            requested_context=context,
                            catalog_entry=entry,
                            binding=binding,
                        )
                        chain = self._binding_events_conn(conn, binding)
                        event_count = int(binding["event_count"])
                        if len(chain) != event_count:
                            raise MemoraGovernanceIntegrityError(
                                "memora receipt chain count is inconsistent"
                            )
                        namespace_events += event_count
                        validated_event_count += event_count
                        if validated_event_count > MAX_RECOVERY_EVENTS:
                            raise MemoraGovernanceIntegrityError(
                                "memora recovery receipt audit exceeds its bound"
                            )
                        source_witness_count += len(binding["sources"])
                        cue_count += len(binding["cues"])
                        bindings.append(binding)
                        inventory_bindings.append(
                            {
                                "binding_id": binding_id,
                                "revision": str(binding["revision"]),
                                "state": str(binding["state"]),
                                "event_count": event_count,
                                "last_event_id": str(binding["last_event_id"]),
                            }
                        )
                    if int(catalog_event_count) != namespace_events:
                        raise MemoraGovernanceIntegrityError(
                            "memora catalog event count is inconsistent"
                        )
                    inventory.append(
                        {
                            "context_id": context,
                            "catalog_revision": str(catalog["revision"]),
                            "bindings": inventory_bindings,
                        }
                    )

                actual_binding_keys = {str(row["key"]) for row in binding_rows}
                if actual_binding_keys != expected_binding_keys:
                    raise MemoraGovernanceIntegrityError(
                        "memora recovery audit found an orphan or missing projection"
                    )
                if validated_event_count != receipt_total:
                    raise MemoraGovernanceIntegrityError(
                        "memora recovery audit found an orphan or missing receipt"
                    )

                promoted = [
                    binding
                    for binding in bindings
                    if binding.get("state") == EFFECTIVE_STATE
                ]
                provider_revision = "absent"
                validated_provider: dict[str, Any] | None = None
                if promoted:
                    if active_provider_identity is not None:
                        validated_provider = validate_provider_identity(
                            active_provider_identity,
                            source="active",
                        )
                        provider_revision = _digest(validated_provider)
                        if (
                            expected_provider_revision is not None
                            and expected_provider_revision != provider_revision
                        ):
                            raise MemoraGovernanceIntegrityError(
                                "active Memora provider revision does not match evidence"
                            )
                    elif not _is_hex64(expected_provider_revision):
                        raise MemoraGovernanceIntegrityError(
                            "promoted memora bindings require an active provider identity or signed revision"
                        )
                    else:
                        provider_revision = str(expected_provider_revision)
                elif expected_provider_revision not in (None, "absent"):
                    raise MemoraGovernanceIntegrityError(
                        "empty Memora governance cannot claim an active provider revision"
                    )

                effective_count = 0
                provider_drift_count = 0
                source_drift_count = 0
                for binding in promoted:
                    effective_provider = validated_provider
                    if effective_provider is None:
                        effective_provider = validate_provider_identity(
                            binding.get("provider"),
                            source="stored",
                        )
                        if _digest(effective_provider) != provider_revision:
                            provider_drift_count += 1
                            continue
                    verdict = self.binding_effectiveness_conn(
                        conn,
                        binding,
                        active_provider_identity=effective_provider,
                    )
                    reasons = [str(reason) for reason in verdict["reasons"]]
                    if verdict["effective"]:
                        effective_count += 1
                    else:
                        if any(reason.startswith("provider-drift:") for reason in reasons):
                            provider_drift_count += 1
                        if any(
                            not reason.startswith("provider-drift:")
                            for reason in reasons
                        ):
                            source_drift_count += 1

        promoted_count = len(promoted)
        ineffective_count = promoted_count - effective_count
        return validate_memora_recovery_audit(
            {
                "schema": MEMORA_RECOVERY_AUDIT_SCHEMA,
                "audit_revision": _digest(
                    {
                        "schema": MEMORA_RECOVERY_AUDIT_SCHEMA,
                        "catalogs": inventory,
                    }
                ),
                "catalog_count": catalog_total,
                "binding_projection_count": binding_total,
                "governance_event_receipt_count": receipt_total,
                "source_witness_count": source_witness_count,
                "cue_count": cue_count,
                "promoted_binding_count": promoted_count,
                "effective_binding_count": effective_count,
                "ineffective_promoted_binding_count": ineffective_count,
                "provider_drift_binding_count": provider_drift_count,
                "source_drift_binding_count": source_drift_count,
                "active_provider_revision": provider_revision,
                "integrity_valid": True,
                "effective_bindings_valid": ineffective_count == 0,
                "raw_cue_terms_included": False,
                "raw_source_text_included": False,
                "vectors_included": False,
            }
        )

    def _insert_event(
        self,
        conn: Any,
        *,
        action: str,
        request_id: str,
        request_fingerprint: str,
        binding: Mapping[str, Any],
        before_state: str | None,
        before_revision: str,
        actor: str,
        reason: str,
        event_sequence: int,
        result: Mapping[str, Any],
        now: float,
    ) -> str:
        operation_id = self._operation_id(action, request_id)
        after_revision = str(binding["revision"])
        payload = {
            "schema": EVENT_SCHEMA,
            "event_id": operation_id,
            "action": action,
            "request_id": request_id,
            "request_fingerprint": request_fingerprint,
            "binding_id": str(binding["binding_id"]),
            "actor": actor,
            "reason": reason,
            "before_state": before_state,
            "after_state": str(binding["state"]),
            "before_revision": before_revision,
            "after_revision": after_revision,
            "event_sequence": int(event_sequence),
            "automatic_promotion": False,
            "result": dict(result),
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
                str(binding["context_id"]),
                before_revision,
                after_revision,
                _json_dumps(payload),
                now,
            ),
        )
        return operation_id

    @staticmethod
    def _result_envelope(operation: str, binding: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "operation": operation,
            "binding_id": str(binding["binding_id"]),
            "context_id": str(binding["context_id"]),
            "state": str(binding["state"]),
            "revision": str(binding["revision"]),
            "binding": dict(binding),
            "automatic_promotion": False,
        }

    # ------------------------------------------------------------------
    # Server-side proposal derivation
    # ------------------------------------------------------------------

    @staticmethod
    def _validated_plan_cluster(
        *,
        context_id: str,
        plan: Mapping[str, Any],
        supplied_plan_digest: str,
        cluster_ordinal: int,
    ) -> dict[str, Any]:
        if not isinstance(plan, Mapping) or plan.get("schema") != MEMORA_SHADOW_SCHEMA:
            raise MemoraGovernanceValidationError("recomputed plan is invalid")
        recomputed_digest = str(plan.get("plan_digest") or "")
        if (
            _REVISION_RE.fullmatch(recomputed_digest) is None
            or compute_plan_digest(plan) != recomputed_digest
        ):
            raise MemoraGovernanceIntegrityError(
                "recomputed plan digest is inconsistent"
            )
        supplied = str(supplied_plan_digest or "").strip()
        if _REVISION_RE.fullmatch(supplied) is None:
            raise MemoraGovernanceValidationError(
                "plan_digest must be exactly 64 lowercase hex characters"
            )
        if supplied != recomputed_digest:
            raise MemoraGovernanceStaleRevision(
                "namespace snapshot moved: the recomputed plan no longer matches "
                "the reviewed plan_digest"
            )
        if str(plan.get("context_id") or "") != context_id:
            raise MemoraGovernanceValidationError(
                "recomputed plan does not belong to the requested namespace"
            )
        if type(cluster_ordinal) is not int or cluster_ordinal < 0:
            raise MemoraGovernanceValidationError(
                "cluster_ordinal must be a non-negative integer"
            )
        clusters = plan.get("clusters")
        if not isinstance(clusters, list) or cluster_ordinal >= len(clusters):
            raise MemoraGovernanceNotFound(
                "cluster_ordinal does not exist in the recomputed plan"
            )
        cluster = clusters[cluster_ordinal]
        if not isinstance(cluster, Mapping):
            raise MemoraGovernanceIntegrityError("recomputed cluster is invalid")
        return dict(cluster)

    @staticmethod
    def _validated_cluster_sources(cluster: Mapping[str, Any]) -> list[str]:
        """Canonical, unique source ids that exactly match the member count."""

        raw_ids = cluster.get("source_memory_ids")
        if not isinstance(raw_ids, list) or not raw_ids:
            raise MemoraGovernanceValidationError(
                "recomputed cluster has no source ids"
            )
        source_ids: list[str] = []
        for value in raw_ids:
            if not isinstance(value, str) or _MEMORY_ID_RE.fullmatch(value) is None:
                raise MemoraGovernanceValidationError(
                    "recomputed cluster source id is not canonical"
                )
            source_ids.append(value)
        if len(set(source_ids)) != len(source_ids):
            raise MemoraGovernanceValidationError(
                "recomputed cluster source ids are not unique"
            )
        if len(source_ids) > MAX_SOURCES_PER_BINDING:
            raise MemoraGovernanceValidationError(
                "recomputed cluster exceeds the source bound"
            )
        if cluster.get("member_count") != len(source_ids):
            raise MemoraGovernanceValidationError(
                "recomputed cluster member count does not match its sources"
            )
        medoid = str(cluster.get("medoid_memory_id") or "")
        if medoid not in source_ids:
            raise MemoraGovernanceValidationError(
                "recomputed cluster medoid is not a cluster member"
            )
        return source_ids

    @staticmethod
    def _validated_cluster_cues(
        cluster: Mapping[str, Any], source_ids: list[str]
    ) -> list[dict[str, Any]]:
        """Bounded, canonical, re-redacted cue rows.

        Any malformed cue rejects the whole proposal -- nothing is silently
        dropped or truncated into a partially-validated binding.  Each cue
        preserves its exact ``supporting_memory_ids`` subset; retrieval
        routes a matched cue only to that subset, never the whole cluster.
        """

        source_id_set = set(source_ids)
        raw_cues = cluster.get("proposed_cues")
        if (
            not isinstance(raw_cues, list)
            or not raw_cues
            or len(raw_cues) > MAX_CUES_PER_BINDING
        ):
            raise MemoraGovernanceValidationError(
                "recomputed cluster cues are missing or exceed the cue bound"
            )
        cues: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        seen_terms: set[str] = set()
        for raw_cue in raw_cues:
            if not isinstance(raw_cue, Mapping):
                raise MemoraGovernanceValidationError(
                    "recomputed cue entry is invalid"
                )
            cue_id = str(raw_cue.get("cue_id") or "")
            aspect = str(raw_cue.get("aspect") or "")
            member_support = raw_cue.get("member_support")
            supporting = raw_cue.get("supporting_memory_ids")
            if (
                _CUE_ID_RE.fullmatch(cue_id) is None
                or cue_id in seen_ids
                or aspect not in _ALLOWED_CUE_ASPECTS
                or type(member_support) is not int
                or member_support < 1
                or member_support > len(source_ids)
            ):
                raise MemoraGovernanceValidationError(
                    "recomputed cue identity is not canonical"
                )
            if (
                not isinstance(supporting, list)
                or not supporting
                or supporting != sorted(set(supporting))
                or not all(
                    isinstance(item, str) and item in source_id_set
                    for item in supporting
                )
                or len(supporting) != member_support
            ):
                raise MemoraGovernanceValidationError(
                    "recomputed cue supporting ids are not an exact subset of "
                    "the cluster sources"
                )
            term = str(raw_cue.get("label") or "")
            redacted_term, hits = redact_capture_text(term)
            if (
                not term
                or hits
                or redacted_term != term
                or term != term.strip().lower()
                or len(term.encode("utf-8")) > MAX_CUE_TERM_BYTES
                or term in seen_terms
            ):
                raise MemoraGovernanceValidationError(
                    "recomputed cue term is not canonical redacted text"
                )
            seen_ids.add(cue_id)
            seen_terms.add(term)
            cues.append(
                {
                    "cue_id": cue_id,
                    "term": term,
                    "aspect": aspect,
                    "member_support": member_support,
                    "supporting_memory_ids": list(supporting),
                    "trust": CUE_TRUST_MARKER,
                }
            )
        return cues

    def _namespace_snapshot_revision_conn(self, conn: Any, context: str) -> str:
        """Transaction-coupled namespace revision, same recipe as the planner page."""

        selected = self.store._canonical_retrieval_context_ids([context])
        placeholders = ",".join("?" for _ in selected)
        total = int(
            conn.execute(
                f"""
                SELECT COUNT(*)
                FROM memory_entries
                WHERE context_id IN ({placeholders})
                """,
                selected,
            ).fetchone()[0]
        )
        return self.store._retrieval_generation_snapshot_revision(
            conn=conn,
            kind="memora-source-page",
            context_ids=selected,
            channels=("memory",),
            counts={"entries": total},
        )

    @staticmethod
    def _normalized_witness(
        witness: Mapping[str, Any], *, context: str, memory_id: str
    ) -> dict[str, Any]:
        record = {
            "schema": str(witness.get("schema") or ""),
            "memory_id": memory_id,
            "context_id": str(witness.get("context_id") or ""),
            "created_at": float(witness.get("created_at") or 0.0),
            "updated_at": float(witness.get("updated_at") or 0.0),
            "source_text_bytes": int(witness.get("source_text_bytes") or 0),
            "source_text_oversized": witness.get("source_text_oversized") is True,
            "metadata_bytes": int(witness.get("metadata_bytes") or 0),
            "metadata_oversized": witness.get("metadata_oversized") is True,
            "event_count": int(witness.get("event_count") or 0),
            "upsert_event_count": int(witness.get("upsert_event_count") or 0),
            "last_event_id": int(witness.get("last_event_id") or 0),
            "last_event_at": float(witness.get("last_event_at") or 0.0),
        }
        if record["context_id"] != context:
            raise MemoraGovernanceValidationError(
                "witness namespace does not match the binding namespace"
            )
        if record["source_text_oversized"] or record["metadata_oversized"]:
            # An oversized column's bytes were never materialized to the
            # planner, so its lifecycle facts describe content the review
            # never saw; oversized rows stay inspect-only.
            raise MemoraGovernanceValidationError(
                "oversized sources cannot be promotion witnesses"
            )
        if record["schema"] != MEMORA_WITNESS_SCHEMA:
            raise MemoraGovernanceValidationError("witness schema is invalid")
        # Every row created through the mutation API carries at least one
        # upsert event; a witness with an empty frontier cannot come from
        # this pipeline and is never promotable.
        if (
            record["event_count"] < 1
            or record["upsert_event_count"] < 1
            or record["last_event_id"] < 1
            or not _is_finite_positive(record["last_event_at"])
        ):
            raise MemoraGovernanceValidationError(
                "witness lifecycle frontier is incomplete"
            )
        if not _is_finite_positive(record["created_at"]) or not (
            _is_finite_positive(record["updated_at"])
        ):
            raise MemoraGovernanceValidationError("witness timestamps are invalid")
        return record

    def _verified_source_witnesses_conn(
        self,
        conn: Any,
        *,
        context: str,
        source_ids: list[str],
        plan_witnesses: Mapping[str, Any],
        text_gate: int,
        metadata_gate: int,
    ) -> list[dict[str, Any]]:
        """Verify plan witnesses against live rows inside the governance txn.

        The plan carried lifecycle witnesses computed in the same read
        transaction as the planner inputs (and covered by the plan digest).
        Here every lifecycle fact -- row identity, version times, byte
        counts, oversized flags, memory-event frontier -- must exactly match
        a fresh in-transaction read of its live row, or the proposal fails
        closed as stale.
        """

        normalized: dict[str, dict[str, Any]] = {}
        for memory_id in sorted(source_ids):
            planned_raw = plan_witnesses.get(memory_id)
            if not isinstance(planned_raw, Mapping):
                raise MemoraGovernanceValidationError(
                    "the recomputed plan carries no witness for a cluster source"
                )
            normalized[memory_id] = self._normalized_witness(
                planned_raw, context=context, memory_id=memory_id
            )
        results = self.store.memora_verify_witnesses_conn(
            conn,
            normalized,
            text_gate=text_gate,
            metadata_gate=metadata_gate,
        )
        for memory_id in sorted(normalized):
            reasons = results.get(memory_id)
            if reasons is None or reasons:
                raise MemoraGovernanceStaleRevision(
                    "a cluster source changed between planning and proposal"
                )
        return [normalized[memory_id] for memory_id in sorted(normalized)]

    def propose_binding(
        self,
        *,
        context_id: str,
        plan_digest: str,
        cluster_ordinal: int,
        proposed_by: str,
        reason: str,
        governance_request_id: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Create a proposed binding from a server-recomputed plan cluster.

        The caller contributes only the namespace, the reviewed
        ``plan_digest``, and the ``cluster_ordinal``.  The plan itself is
        recomputed through the backend-installed recomputer, its witnesses
        were computed in the same read transaction as the planner inputs and
        are covered by the reviewed digest, and the governance transaction
        re-verifies both the transaction-coupled namespace revision and
        every live witness before storing anything -- so nothing a wire
        caller sends can fabricate proposal content, and no mutation can
        slip between planning and proposing.

        Only learned plans may be proposed: fallback hash plans are
        inspectable through the shadow-plan surface but never enter the
        governed lifecycle.

        Governed v1 scope: durable proposal/promotion applies only to the
        canonical first-page/default shadow planner configuration -- the
        recomputer takes the namespace alone and recomputes under canonical
        defaults.  Shadow exploration may paginate with non-default knobs
        and cursors, but those plans are inspect-only: no cursor, cue, or
        source payload is accepted here, and no approval action exists for
        them.

        Proposals have no TTL: staleness is enforced by content, not time.
        A proposal whose sources changed, disappeared, or whose provider
        identity drifted fails witness/identity verification at promotion
        and at retrieval, so an old proposal can never promote stale truth.
        """

        if self._plan_recomputer is None:
            raise MemoraGovernanceValidationError(
                "this governance instance has no authoritative plan recomputer"
            )
        timestamp = self._trusted_now(now)
        context = _clean_context(context_id)
        proposer = _clean_actor(proposed_by, field="proposed_by")
        safe_reason, reason_redactions = _clean_reason(reason)
        supplied_digest = str(plan_digest or "").strip()
        if _REVISION_RE.fullmatch(supplied_digest) is None:
            raise MemoraGovernanceValidationError(
                "plan_digest must be exactly 64 lowercase hex characters"
            )
        if type(cluster_ordinal) is not int or cluster_ordinal < 0:
            raise MemoraGovernanceValidationError(
                "cluster_ordinal must be a non-negative integer"
            )
        request = {
            "context_id": context,
            "plan_digest": supplied_digest,
            "cluster_ordinal": int(cluster_ordinal),
            "proposed_by": proposer,
            "reason": safe_reason,
        }
        fingerprint = self._request_fingerprint("propose", request)
        request_id = _clean_request_id(
            governance_request_id,
            action="propose",
            request_fingerprint=fingerprint,
        )
        binding_id = "s2mb_" + hashlib.sha256(
            f"memora-binding:v1\x1f{request_id}\x1f{fingerprint}".encode("utf-8")
        ).hexdigest()[:32]
        event_id = self._operation_id("propose", request_id)

        # Exactly-once replay resolves BEFORE any plan recomputation: a
        # lost-response retry must return the validated original receipt
        # even when the namespace has drifted since the original write
        # (recomputation would otherwise fail closed as stale and mask the
        # already-recorded outcome).  Conflicting reuse of a request id
        # still rejects here.
        with closing(self.store._connect_read_only()) as conn:
            with self.store._transaction(conn):
                replay = self._replay_event(
                    conn,
                    action="propose",
                    request_id=request_id,
                    request_fingerprint=fingerprint,
                )
        if replay is not None:
            return replay

        plan = self._plan_recomputer(context)
        cluster = self._validated_plan_cluster(
            context_id=context,
            plan=plan,
            supplied_plan_digest=supplied_digest,
            cluster_ordinal=cluster_ordinal,
        )
        if plan.get("learned") is not True:
            raise MemoraGovernanceValidationError(
                "only learned plans may enter governance; the active provider "
                "is a non-learned fallback"
            )
        provider = validate_provider_identity(plan.get("provider"), source="plan")
        source_ids = self._validated_cluster_sources(cluster)
        cues = self._validated_cluster_cues(cluster, source_ids)

        limits = plan.get("limits") if isinstance(plan.get("limits"), Mapping) else {}
        text_gate = limits.get("max_source_text_bytes")
        metadata_gate = limits.get("max_metadata_bytes")
        if (
            text_gate != MEMORA_SHADOW_MAX_SOURCE_TEXT_BYTES
            or metadata_gate != MEMORA_SHADOW_MAX_METADATA_BYTES
        ):
            raise MemoraGovernanceValidationError(
                "recomputed plan does not carry the approved byte gates"
            )
        snapshot = plan.get("snapshot") if isinstance(plan.get("snapshot"), Mapping) else {}
        plan_snapshot_revision = str(snapshot.get("revision") or "")
        if not _is_hex64(plan_snapshot_revision):
            raise MemoraGovernanceValidationError(
                "recomputed plan snapshot revision is invalid"
            )
        plan_witnesses = plan.get("source_witnesses")
        if not isinstance(plan_witnesses, Mapping):
            raise MemoraGovernanceValidationError(
                "recomputed plan carries no source witnesses"
            )

        abstraction_id = "s2abs_" + hashlib.sha256(
            (
                "memora-abstraction:v1\x1f"
                + context
                + "\x1f"
                + "\x1f".join(sorted(source_ids))
            ).encode("utf-8")
        ).hexdigest()[:32]
        top_cue_term = cues[0]["term"]

        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                replay = self._replay_event(
                    conn,
                    action="propose",
                    request_id=request_id,
                    request_fingerprint=fingerprint,
                )
                if replay is not None:
                    return replay
                if (
                    self._read_json_row(conn, self._binding_key(binding_id))
                    is not None
                ):
                    raise MemoraGovernanceConflict(
                        "binding identity already exists"
                    )
                in_txn_revision = self._namespace_snapshot_revision_conn(
                    conn, context
                )
                if in_txn_revision != plan_snapshot_revision:
                    raise MemoraGovernanceStaleRevision(
                        "the namespace changed between planning and proposal"
                    )
                source_witnesses = self._verified_source_witnesses_conn(
                    conn,
                    context=context,
                    source_ids=source_ids,
                    plan_witnesses=plan_witnesses,
                    text_gate=text_gate,
                    metadata_gate=metadata_gate,
                )
                catalog = self._validated_catalog_conn(conn, context)
                open_proposals = 0
                if catalog is not None:
                    for item in catalog["bindings"]:
                        if item["state"] == "proposed":
                            open_proposals += 1
                if open_proposals >= MAX_OPEN_PROPOSALS:
                    raise MemoraGovernanceConflict(
                        "too many open memora proposals in this namespace"
                    )
                binding = _with_revision(
                    {
                        "schema": BINDING_SCHEMA,
                        "schema_version": 1,
                        "binding_id": binding_id,
                        "context_id": context,
                        "state": "proposed",
                        "automatic_promotion": False,
                        "created_at": timestamp,
                        "updated_at": timestamp,
                        "proposed_by": proposer,
                        "proposed_at": timestamp,
                        "proposal_reason": safe_reason,
                        "proposal_reason_redactions": reason_redactions,
                        "reviewed_by": None,
                        "reviewed_at": None,
                        "revoked_by": None,
                        "revoked_at": None,
                        "superseded_by": None,
                        "superseded_at": None,
                        "superseded_by_binding_id": None,
                        "supersedes_binding_id": None,
                        "decision_reason": None,
                        "plan": {
                            "planner_version": str(
                                (plan.get("planner") or {}).get("name")
                                if isinstance(plan.get("planner"), Mapping)
                                else ""
                            ),
                            "plan_digest": supplied_digest,
                            "cluster_ordinal": int(cluster_ordinal),
                            "cluster_id": str(cluster.get("cluster_id") or ""),
                            "similarity_threshold": float(
                                limits.get("similarity_threshold") or 0.0
                            ),
                            "learned": True,
                        },
                        "provider": provider,
                        "namespace_snapshot": {
                            "snapshot_revision": plan_snapshot_revision,
                            "entry_count": int(snapshot.get("entry_count") or 0),
                            "sampled_count": int(snapshot.get("sampled_count") or 0),
                            "sampling_truncated": bool(
                                snapshot.get("sampling_truncated")
                            ),
                        },
                        "limits": {
                            "max_source_text_bytes": text_gate,
                            "max_metadata_bytes": metadata_gate,
                        },
                        "abstraction": {
                            "abstraction_id": abstraction_id,
                            "medoid_memory_id": str(
                                cluster.get("medoid_memory_id") or ""
                            ),
                            "member_count": len(source_ids),
                            "display_term": top_cue_term,
                            "trust": CUE_TRUST_MARKER,
                        },
                        "cues": cues,
                        "sources": source_witnesses,
                        "raw_source_text_stored": False,
                        "vectors_stored": False,
                        "previous_revision": None,
                        "last_event_id": event_id,
                        "last_request_fingerprint": fingerprint,
                        "event_count": 1,
                    }
                )
                result = self._result_envelope("propose-memora-binding", binding)
                self._write_projection(
                    conn, self._binding_key(binding_id), binding, timestamp
                )
                self._catalog_upsert_conn(
                    conn, context_id=context, binding=binding, now=timestamp
                )
                self._insert_event(
                    conn,
                    action="propose",
                    request_id=request_id,
                    request_fingerprint=fingerprint,
                    binding=binding,
                    before_state=None,
                    before_revision="",
                    actor=proposer,
                    reason=safe_reason,
                    event_sequence=1,
                    result=result,
                    now=timestamp,
                )
                return result

    # ------------------------------------------------------------------
    # Lifecycle transitions
    # ------------------------------------------------------------------

    @staticmethod
    def _transition_projection(
        binding: Mapping[str, Any],
        *,
        state: str,
        event_id: str,
        actor_field: str,
        at_field: str,
        actor: str,
        reason: str,
        request_fingerprint: str,
        now: float,
        extra: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        before_state = str(binding.get("state") or "")
        if (before_state, state) not in ALLOWED_TRANSITIONS:
            raise MemoraGovernanceInvalidTransition(
                f"memora binding cannot transition from {before_state} to {state}"
            )
        updated = dict(binding)
        updated["previous_revision"] = str(binding["revision"])
        updated["state"] = state
        updated[actor_field] = actor
        updated[at_field] = now
        updated["decision_reason"] = reason
        updated["last_event_id"] = event_id
        updated["last_request_fingerprint"] = request_fingerprint
        updated["event_count"] = int(binding.get("event_count", 0)) + 1
        updated["updated_at"] = now
        for key, value in dict(extra or {}).items():
            updated[key] = value
        return _with_revision(updated)

    def _decide(
        self,
        *,
        action: str,
        operation: str,
        binding_id: str,
        target_state: str,
        expected_revision: str,
        actor: str,
        actor_request_field: str,
        reason: str,
        governance_request_id: str | None,
        now: float | None,
        confirm_required: bool,
        confirm: Any = None,
    ) -> dict[str, Any]:
        timestamp = self._trusted_now(now)
        if confirm_required:
            _require_confirm(confirm)
        clean_id = _clean_binding_id(binding_id)
        clean_revision = _clean_revision(expected_revision)
        clean_actor = _clean_actor(actor, field=actor_request_field)
        safe_reason, _ = _clean_reason(reason)
        request = {
            "binding_id": clean_id,
            "expected_revision": clean_revision,
            actor_request_field: clean_actor,
            "reason": safe_reason,
            "target_state": target_state,
        }
        fingerprint = self._request_fingerprint(action, request)
        request_id = _clean_request_id(
            governance_request_id,
            action=action,
            request_fingerprint=fingerprint,
        )
        event_id = self._operation_id(action, request_id)
        actor_field = _EVENT_ACTOR_FIELDS[action]
        at_field = {
            "promote": "reviewed_at",
            "reject": "reviewed_at",
            "revoke": "revoked_at",
        }[action]

        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                replay = self._replay_event(
                    conn,
                    action=action,
                    request_id=request_id,
                    request_fingerprint=fingerprint,
                )
                if replay is not None:
                    return replay
                binding = self._validated_binding_conn(conn, clean_id)
                # The current catalog entry must exactly agree with the
                # projection before any transition: a missing, stale,
                # wrong-state, or cross-context catalog row is an integrity
                # failure, never something the transition's own catalog
                # upsert silently heals.
                self._catalog_entry_for_binding_conn(conn, binding)
                if str(binding["revision"]) != clean_revision:
                    raise MemoraGovernanceStaleRevision(
                        "memora binding revision does not match expected_revision"
                    )
                before_state = str(binding["state"])
                before_revision = str(binding["revision"])
                updated = self._transition_projection(
                    binding,
                    state=target_state,
                    event_id=event_id,
                    actor_field=actor_field,
                    at_field=at_field,
                    actor=clean_actor,
                    reason=safe_reason,
                    request_fingerprint=fingerprint,
                    now=timestamp,
                )
                result = self._result_envelope(operation, updated)
                self._write_projection(
                    conn, self._binding_key(clean_id), updated, timestamp
                )
                self._catalog_upsert_conn(
                    conn,
                    context_id=str(updated["context_id"]),
                    binding=updated,
                    now=timestamp,
                )
                self._insert_event(
                    conn,
                    action=action,
                    request_id=request_id,
                    request_fingerprint=fingerprint,
                    binding=updated,
                    before_state=before_state,
                    before_revision=before_revision,
                    actor=clean_actor,
                    reason=safe_reason,
                    event_sequence=int(updated["event_count"]),
                    result=result,
                    now=timestamp,
                )
                return result

    def promote_binding(
        self,
        *,
        binding_id: str,
        expected_revision: str,
        reviewed_by: str,
        reason: str,
        confirm: Any,
        active_provider_identity: Mapping[str, Any],
        supersedes_binding_id: str | None = None,
        governance_request_id: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Promote one proposed binding into an effective governed cue binding.

        Operator-only: this method is intentionally not reachable through the
        agent-facing MCP surface.  Requires an exact ``confirm``, the exact
        current projection revision, a learned plan, an exact match with the
        active provider identity, and live witness verification for every
        source -- all inside one immediate transaction.

        All per-request state (actor, reason, timestamp, and the derived
        supersede request identity) lives in immutable locals captured
        lexically by this call, so concurrent promotions on a shared backend
        can never cross-contaminate receipts or projections.
        """

        _require_confirm(confirm)
        active_identity = validate_provider_identity(
            active_provider_identity, source="active"
        )
        supersedes = (
            _clean_binding_id(supersedes_binding_id)
            if supersedes_binding_id is not None
            else None
        )
        timestamp = self._trusted_now(now)
        clean_id = _clean_binding_id(binding_id)
        clean_revision = _clean_revision(expected_revision)
        clean_actor = _clean_actor(reviewed_by, field="reviewed_by")
        safe_reason, _ = _clean_reason(reason)
        promote_request = {
            "binding_id": clean_id,
            "expected_revision": clean_revision,
            "reviewed_by": clean_actor,
            "reason": safe_reason,
            "target_state": "promoted",
            "supersedes_binding_id": supersedes,
        }
        promote_fingerprint = self._request_fingerprint("promote", promote_request)
        promote_request_id = _clean_request_id(
            governance_request_id,
            action="promote",
            request_fingerprint=promote_fingerprint,
        )
        promote_event_id = self._operation_id("promote", promote_request_id)
        # Deterministic supersede identity derived from this promote request:
        # a replay regenerates the identical receipt pair.
        supersede_request_id = promote_request_id + ".supersede"
        supersede_fingerprint = self._request_fingerprint(
            "supersede",
            {**promote_request, "derived_from": promote_request_id},
        )

        def _promotion_gates(conn: Any, binding: dict[str, Any]) -> dict[str, Any]:
            if clean_actor == str(binding.get("proposed_by") or ""):
                # Distinct reviewer is mandatory, mirroring bridge
                # governance: no self-promotion and no compatibility bypass.
                raise MemoraGovernanceValidationError(
                    "promotion requires a distinct reviewer: reviewed_by must "
                    "differ from proposed_by"
                )
            plan_info = (
                binding.get("plan") if isinstance(binding.get("plan"), dict) else {}
            )
            if plan_info.get("learned") is not True or (
                (binding.get("provider") or {}).get("learned") is not True
            ):
                raise MemoraGovernanceValidationError(
                    "only learned plans may be promoted; fallback hash plans "
                    "are inspect-only"
                )
            drift = provider_identities_match(
                binding.get("provider") or {},
                active_identity,
            )
            if drift:
                raise MemoraGovernanceConflict(
                    "provider identity drift blocks promotion: "
                    + ", ".join(sorted(drift))
                )
            mismatches = self._witness_mismatches_conn(conn, binding)
            if mismatches:
                raise MemoraGovernanceConflict(
                    "source witnesses changed since proposal: "
                    + ", ".join(sorted(mismatches))
                )
            catalog = self._validated_catalog_conn(
                conn, str(binding["context_id"])
            )
            abstraction_id = str(binding["abstraction"]["abstraction_id"])
            active_promoted = 0
            if catalog is not None:
                for item in catalog["bindings"]:
                    if item["state"] == EFFECTIVE_STATE:
                        active_promoted += 1
                    if (
                        item["state"] == EFFECTIVE_STATE
                        and item["abstraction_id"] == abstraction_id
                        and item["binding_id"] != binding["binding_id"]
                        and item["binding_id"] != supersedes
                    ):
                        raise MemoraGovernanceConflict(
                            "another promoted binding already covers this "
                            "abstraction; supersede it explicitly"
                        )
            # Transactional capacity gate: retrieval evaluates at most
            # MAX_EFFECTIVE_BINDINGS promoted bindings per namespace, so a
            # promotion that would exceed that ceiling is rejected here
            # unless this same transaction atomically supersedes one (net
            # active count unchanged).  A state=promoted row that retrieval
            # would silently ignore is never stored.
            net_active_after = active_promoted + 1 - (
                1 if supersedes is not None else 0
            )
            if net_active_after > MAX_EFFECTIVE_BINDINGS:
                raise MemoraGovernanceConflict(
                    "promoted binding capacity "
                    f"({MAX_EFFECTIVE_BINDINGS}) reached for this namespace; "
                    "supersede an existing promoted binding in the same "
                    "promotion or revoke one first"
                )
            extra: dict[str, Any] = {}
            if supersedes is not None:
                target = self._validated_binding_conn(conn, supersedes)
                if str(target.get("context_id")) != str(binding["context_id"]):
                    raise MemoraGovernanceValidationError(
                        "supersedes target belongs to a different namespace"
                    )
                # The supersede target's catalog row must also agree exactly
                # before this transaction rewrites it.
                self._catalog_entry_for_binding_conn(conn, target)
                if target.get("state") != EFFECTIVE_STATE:
                    raise MemoraGovernanceInvalidTransition(
                        "supersedes target is not currently promoted"
                    )
                superseded = self._transition_projection(
                    target,
                    state="superseded",
                    event_id=self._operation_id(
                        "supersede", supersede_request_id
                    ),
                    actor_field="superseded_by",
                    at_field="superseded_at",
                    actor=clean_actor,
                    reason=safe_reason,
                    request_fingerprint=supersede_fingerprint,
                    now=timestamp,
                    extra={"superseded_by_binding_id": str(binding["binding_id"])},
                )
                superseded_result = self._result_envelope(
                    "supersede-memora-binding", superseded
                )
                self._write_projection(
                    conn,
                    self._binding_key(supersedes),
                    superseded,
                    timestamp,
                )
                self._catalog_upsert_conn(
                    conn,
                    context_id=str(superseded["context_id"]),
                    binding=superseded,
                    now=timestamp,
                )
                self._insert_event(
                    conn,
                    action="supersede",
                    request_id=supersede_request_id,
                    request_fingerprint=supersede_fingerprint,
                    binding=superseded,
                    before_state=EFFECTIVE_STATE,
                    before_revision=str(target["revision"]),
                    actor=clean_actor,
                    reason=safe_reason,
                    event_sequence=int(superseded["event_count"]),
                    result=superseded_result,
                    now=timestamp,
                )
                extra["supersedes_binding_id"] = supersedes
            return extra

        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                replay = self._replay_event(
                    conn,
                    action="promote",
                    request_id=promote_request_id,
                    request_fingerprint=promote_fingerprint,
                )
                if replay is not None:
                    return replay
                binding = self._validated_binding_conn(conn, clean_id)
                # Exact catalog agreement is a precondition of promotion: a
                # missing, stale, wrong-state, or cross-context catalog row
                # fails integrity here and is never healed by the
                # transition's own catalog upsert.
                self._catalog_entry_for_binding_conn(conn, binding)
                if str(binding["revision"]) != clean_revision:
                    raise MemoraGovernanceStaleRevision(
                        "memora binding revision does not match expected_revision"
                    )
                extra = _promotion_gates(conn, binding)
                before_state = str(binding["state"])
                before_revision = str(binding["revision"])
                updated = self._transition_projection(
                    binding,
                    state="promoted",
                    event_id=promote_event_id,
                    actor_field="reviewed_by",
                    at_field="reviewed_at",
                    actor=clean_actor,
                    reason=safe_reason,
                    request_fingerprint=promote_fingerprint,
                    now=timestamp,
                    extra=extra,
                )
                result = self._result_envelope("promote-memora-binding", updated)
                self._write_projection(
                    conn,
                    self._binding_key(str(updated["binding_id"])),
                    updated,
                    timestamp,
                )
                self._catalog_upsert_conn(
                    conn,
                    context_id=str(updated["context_id"]),
                    binding=updated,
                    now=timestamp,
                )
                self._insert_event(
                    conn,
                    action="promote",
                    request_id=promote_request_id,
                    request_fingerprint=promote_fingerprint,
                    binding=updated,
                    before_state=before_state,
                    before_revision=before_revision,
                    actor=clean_actor,
                    reason=safe_reason,
                    event_sequence=int(updated["event_count"]),
                    result=result,
                    now=timestamp,
                )
                return result

    def reject_binding(
        self,
        *,
        binding_id: str,
        expected_revision: str,
        reviewed_by: str,
        reason: str,
        governance_request_id: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        return self._decide(
            action="reject",
            operation="reject-memora-binding",
            binding_id=binding_id,
            target_state="rejected",
            expected_revision=expected_revision,
            actor=reviewed_by,
            actor_request_field="reviewed_by",
            reason=reason,
            governance_request_id=governance_request_id,
            now=now,
            confirm_required=False,
        )

    def revoke_binding(
        self,
        *,
        binding_id: str,
        expected_revision: str,
        revoked_by: str,
        reason: str,
        confirm: Any,
        governance_request_id: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Revoke a promoted binding: routing stops, sources stay untouched."""

        return self._decide(
            action="revoke",
            operation="revoke-memora-binding",
            binding_id=binding_id,
            target_state="revoked",
            expected_revision=expected_revision,
            actor=revoked_by,
            actor_request_field="revoked_by",
            reason=reason,
            governance_request_id=governance_request_id,
            now=now,
            confirm_required=True,
            confirm=confirm,
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def _catalog_entry_for_binding_conn(
        self, conn: Any, binding: Mapping[str, Any]
    ) -> None:
        """Cross-check a binding against its namespace catalog entry."""

        context = str(binding.get("context_id") or "")
        catalog = self._validated_catalog_conn(conn, context)
        if catalog is None:
            raise MemoraGovernanceIntegrityError(
                "memora binding has no namespace catalog"
            )
        for item in catalog["bindings"]:
            if item["binding_id"] == binding.get("binding_id"):
                self._catalog_cross_check(
                    requested_context=context,
                    catalog_entry=item,
                    binding=binding,
                )
                return
        raise MemoraGovernanceIntegrityError(
            "memora binding is missing from its namespace catalog"
        )

    def get_binding(
        self,
        binding_id: str,
        *,
        active_provider_identity: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        with closing(self.store._connect_read_only()) as conn:
            with self.store._transaction(conn):
                binding = self._validated_binding_conn(conn, binding_id)
                self._catalog_entry_for_binding_conn(conn, binding)
                payload: dict[str, Any] = {
                    "schema": BINDING_SCHEMA,
                    "binding": binding,
                    "state": str(binding["state"]),
                    "revision": str(binding["revision"]),
                }
                if active_provider_identity is not None:
                    payload["effectiveness"] = self.binding_effectiveness_conn(
                        conn,
                        binding,
                        active_provider_identity=active_provider_identity,
                    )
                return payload

    def list_bindings(
        self,
        *,
        context_id: str,
        state: str | None = None,
        limit: int = 50,
        active_provider_identity: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        context = _clean_context(context_id)
        if state is not None and state not in BINDING_STATES:
            raise MemoraGovernanceValidationError("state filter is invalid")
        if type(limit) is not int or limit < 1 or limit > MAX_LIST_LIMIT:
            raise MemoraGovernanceValidationError(
                f"limit must be an exact integer between 1 and {MAX_LIST_LIMIT}"
            )
        with closing(self.store._connect_read_only()) as conn:
            with self.store._transaction(conn):
                catalog = self._validated_catalog_conn(conn, context)
                if catalog is None:
                    return {
                        "schema": CATALOG_SCHEMA,
                        "context_id": context,
                        "catalog_revision": "absent",
                        "bindings": [],
                        "total": 0,
                        "returned": 0,
                        "truncated": False,
                    }
                selected = [
                    item
                    for item in catalog["bindings"]
                    if state is None or item["state"] == state
                ]
                truncated = len(selected) > limit
                rows: list[dict[str, Any]] = []
                for item in selected[:limit]:
                    binding = self._validated_binding_conn(
                        conn, str(item["binding_id"])
                    )
                    self._catalog_cross_check(
                        requested_context=context,
                        catalog_entry=item,
                        binding=binding,
                    )
                    entry: dict[str, Any] = {"binding": binding}
                    if active_provider_identity is not None:
                        entry["effectiveness"] = self.binding_effectiveness_conn(
                            conn,
                            binding,
                            active_provider_identity=active_provider_identity,
                        )
                    rows.append(entry)
                return {
                    "schema": CATALOG_SCHEMA,
                    "context_id": context,
                    "catalog_revision": str(catalog["revision"]),
                    "bindings": rows,
                    "total": len(selected),
                    "returned": len(rows),
                    "truncated": truncated,
                }

    def binding_history(
        self,
        binding_id: str,
        *,
        limit: int = 50,
        before_sequence: int | None = None,
    ) -> dict[str, Any]:
        """Paged, fully validated event history for one binding.

        The history is the binding's own receipt chain, walked and validated
        backwards from the current projection -- it is keyed by the binding,
        never a scan-then-filter over a namespace's oldest receipts.  Pages
        report honest truncation via ``truncated``/``next_before_sequence``.
        """

        clean_id = _clean_binding_id(binding_id)
        if type(limit) is not int or limit < 1 or limit > MAX_LIST_LIMIT:
            raise MemoraGovernanceValidationError(
                f"limit must be an exact integer between 1 and {MAX_LIST_LIMIT}"
            )
        if before_sequence is not None and (
            type(before_sequence) is not int or before_sequence < 2
        ):
            raise MemoraGovernanceValidationError(
                "before_sequence must be an exact integer of at least 2"
            )
        with closing(self.store._connect_read_only()) as conn:
            with self.store._transaction(conn):
                binding = self._validated_binding_conn(conn, clean_id)
                chain = self._binding_events_conn(conn, binding)
        if before_sequence is not None:
            chain = [
                event
                for event in chain
                if event["event_sequence"] < before_sequence
            ]
        page = chain[:limit]
        truncated = len(chain) > limit
        return {
            "schema": EVENT_SCHEMA,
            "binding_id": clean_id,
            "context_id": str(binding["context_id"]),
            "events": page,
            "returned": len(page),
            "total_events": int(binding["event_count"]),
            "truncated": truncated,
            "next_before_sequence": (
                page[-1]["event_sequence"] if truncated and page else None
            ),
            "current_state": str(binding["state"]),
            "current_revision": str(binding["revision"]),
        }

    # ------------------------------------------------------------------
    # Retrieval integration
    # ------------------------------------------------------------------

    def cue_governance_revisions(
        self, context_ids: Iterable[str]
    ) -> dict[str, str]:
        """Per-namespace cue-governance revisions for retrieval snapshots."""

        selected = sorted({_clean_context(value) for value in context_ids})
        revisions: dict[str, str] = {}
        with closing(self.store._connect_read_only()) as conn:
            with self.store._transaction(conn):
                for context in selected:
                    catalog = self._validated_catalog_conn(conn, context)
                    revisions[context] = (
                        str(catalog["revision"]) if catalog is not None else "absent"
                    )
        return revisions

    def effective_bindings(
        self,
        *,
        context_id: str,
        active_provider_identity: Mapping[str, Any],
        max_bindings: int | None = None,
    ) -> dict[str, Any]:
        """Return promoted, witness-verified, provider-matched bindings.

        Fail-closed per binding: a binding that fails deep integrity
        validation, its catalog cross-check, witness verification, or
        provider identity matching contributes nothing and is counted with
        its reasons.  Integrity failures are reported, never hidden.

        ``max_bindings`` lets a bounded caller cap deep validation work at
        its remaining global budget: validation stops after that many
        promoted bindings and the overflow is reported as ``truncated``
        instead of being silently validated past the caller's ceiling.
        """

        context = _clean_context(context_id)
        binding_budget = MAX_EFFECTIVE_BINDINGS
        if max_bindings is not None:
            if type(max_bindings) is not int or max_bindings < 0:
                raise MemoraGovernanceValidationError(
                    "max_bindings must be a non-negative integer"
                )
            binding_budget = min(binding_budget, max_bindings)
        considered = 0
        invalidated: list[dict[str, Any]] = []
        integrity_failures: list[str] = []
        effective: list[dict[str, Any]] = []
        truncated = False
        with closing(self.store._connect_read_only()) as conn:
            with self.store._transaction(conn):
                try:
                    catalog = self._validated_catalog_conn(conn, context)
                except MemoraGovernanceIntegrityError:
                    return {
                        "context_id": context,
                        "catalog_revision": "integrity-error",
                        "bindings": [],
                        "considered": 0,
                        "invalidated": [],
                        "integrity_failures": ["catalog"],
                        "truncated": False,
                    }
                if catalog is None:
                    return {
                        "context_id": context,
                        "catalog_revision": "absent",
                        "bindings": [],
                        "considered": 0,
                        "invalidated": [],
                        "integrity_failures": [],
                        "truncated": False,
                    }
                promoted = sorted(
                    (
                        item
                        for item in catalog["bindings"]
                        if item["state"] == EFFECTIVE_STATE
                    ),
                    key=lambda item: item["binding_id"],
                )
                truncated = len(promoted) > binding_budget
                for item in promoted[:binding_budget]:
                    binding_id = str(item["binding_id"])
                    considered += 1
                    try:
                        binding = self._validated_binding_conn(conn, binding_id)
                        self._catalog_cross_check(
                            requested_context=context,
                            catalog_entry=item,
                            binding=binding,
                        )
                    except (
                        MemoraGovernanceIntegrityError,
                        MemoraGovernanceNotFound,
                    ):
                        integrity_failures.append(binding_id)
                        continue
                    verdict = self.binding_effectiveness_conn(
                        conn,
                        binding,
                        active_provider_identity=active_provider_identity,
                    )
                    if verdict["effective"]:
                        effective.append(binding)
                    else:
                        invalidated.append(
                            {
                                "binding_id": binding_id,
                                "reasons": sorted(verdict["reasons"]),
                            }
                        )
        return {
            "context_id": context,
            "catalog_revision": str(catalog["revision"]),
            "bindings": effective,
            "considered": considered,
            "invalidated": invalidated,
            "integrity_failures": integrity_failures,
            "truncated": truncated,
        }

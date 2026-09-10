"""In-memory bounded, resumable memory-hygiene scanning sessions.

This module owns only scan-session bookkeeping.  It walks a namespace one
bounded ``backend.list_memory`` page per advance, keyed to an opaque random
scan token bound to one exact context and one snapshot revision.  It never
persists anything, never stores or returns raw source text, and never
deletes, approves, or otherwise mutates memory: it only reports progress,
category counts, and a provisional candidate-to-survivor duplicate mapping
that the caller may review elsewhere.

The retained-state byte budget estimates UTF-8 payload plus fixed record
overhead; it is not a process-RAM cap. Entry, session and reported-candidate
counts have separate hard bounds. Raw source text is never retained.

Deliberate stdlib-only: the manager must not couple to live stores or tools.
Backend-raised staleness (cursor snapshot mismatch, expired cursors) is
therefore caught as a plain exception and converted into a fail-closed
restart-required error rather than by importing backend exception types.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import threading
import time
from typing import Any, Callable, Iterable, NoReturn

__all__ = [
    "HygieneScanError",
    "HygieneScanManager",
    "default_duplicate_key",
    "default_survivor_sort_key",
    "normalize_whole_source_text",
]

DEFAULT_PAGE_LIMIT = 100
DEFAULT_MAX_ENTRIES_PER_SCAN = 5_000
DEFAULT_MAX_STATE_BYTES = 512_000
DEFAULT_SESSION_TTL_SECONDS = 600.0
DEFAULT_MAX_SESSIONS = 8
DEFAULT_MAX_REPORTED_CANDIDATES = 200

_BACKEND_PAGE_LIMIT_CEILING = 500
_MAX_CONTEXT_ID_LENGTH = 128
_MAX_CATEGORY_NAME_LENGTH = 64
_MAX_DISTINCT_CATEGORIES = 32
_MAX_DUPLICATE_KEY_LENGTH = 256
_MAX_SORT_KEY_ELEMENTS = 8
_MAX_SORT_KEY_STRING_LENGTH = 200
_MAX_RETAINED_TAG_LENGTH = 120
_RECORD_BYTE_OVERHEAD = 48

# Duplicate detection is derived from callbacks, so callbacks may not emit
# this reserved category themselves.
_DUPLICATE_CATEGORY = "duplicate_candidate"

# One message for unknown, expired, and wrong-context tokens: a caller who
# guesses tokens or presents another context's token must learn nothing.
_INVALID_TOKEN_MESSAGE = "hygiene scan token is not valid for this context"


class HygieneScanError(RuntimeError):
    """Fail-closed scan error carrying a stable machine-readable code."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        restart_required: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.restart_required = restart_required


def normalize_whole_source_text(source_text: str) -> str:
    """Normalize a WHOLE source text for same-context duplicate grouping."""

    normalized = " ".join(str(source_text or "").casefold().split())
    return re.sub(r"\s+([,.;:])", r"\1", normalized)


def default_duplicate_key(entry: dict[str, Any]) -> str | None:
    """Group same-context whole-text matches; prefixes never collide.

    The digest of normalized content is an internal grouping aid only and
    must never surface in reports, group ids, or errors, or it would become
    a raw-content equality oracle.
    """

    normalized = normalize_whole_source_text(str(entry.get("source_text") or ""))
    if not normalized:
        return None
    context_id = str(entry.get("context_id") or "")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"context:{context_id}:source:{digest}"


def default_survivor_sort_key(entry: dict[str, Any]) -> tuple[Any, ...]:
    """Preserve the session boundary copy, then prefer the oldest exact match."""

    metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
    tag = str(entry.get("tag") or "")
    created = float(entry.get("created_at") or entry.get("updated_at") or 0.0)
    return (
        0 if tag.startswith("client-session-boundary-event-") else 1,
        0 if metadata.get("client_session_bridge") is True else 1,
        created,
        str(entry.get("memory_id") or ""),
    )


class _ScanSession:
    __slots__ = (
        "token",
        "context_id",
        "created_at",
        "expires_at",
        "lock",
        "state",
        "failure_code",
        "cursor",
        "seen_cursors",
        "seen_memory_ids",
        "expected_total",
        "expected_revision",
        "scanned",
        "pages",
        "category_counts",
        "groups",
        "state_bytes",
        "calculated_at",
    )

    def __init__(self, *, token: str, context_id: str, now: float, ttl: float) -> None:
        self.token = token
        self.context_id = context_id
        self.created_at = now
        self.expires_at = now + ttl
        self.lock = threading.Lock()
        self.state = "running"
        self.failure_code: str | None = None
        self.cursor = ""
        self.seen_cursors: set[str] = set()
        self.seen_memory_ids: set[str] = set()
        self.expected_total: int | None = None
        self.expected_revision: str | None = None
        self.scanned = 0
        self.pages = 0
        self.category_counts: dict[str, int] = {}
        self.groups: dict[str, list[dict[str, Any]]] = {}
        self.state_bytes = 0
        self.calculated_at: float | None = None

    def clear_findings(self) -> None:
        self.category_counts.clear()
        self.groups.clear()
        self.seen_cursors.clear()
        self.seen_memory_ids.clear()
        self.state_bytes = 0


class HygieneScanManager:
    """Resumable, bounded, in-memory hygiene scans over one exact namespace.

    Every scan is scoped to exactly one context (``include_global=False``,
    ``recall_scope="local"``) and one snapshot revision.  Any change of
    revision, malformed page metadata, expired session, or exceeded budget
    fails closed: the session is terminated and can only be restarted.
    """

    def __init__(
        self,
        backend: Any,
        *,
        page_limit: int = DEFAULT_PAGE_LIMIT,
        max_entries_per_scan: int = DEFAULT_MAX_ENTRIES_PER_SCAN,
        max_state_bytes: int = DEFAULT_MAX_STATE_BYTES,
        session_ttl_seconds: float = DEFAULT_SESSION_TTL_SECONDS,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_reported_candidates: int = DEFAULT_MAX_REPORTED_CANDIDATES,
        classify_entry: Callable[[dict[str, Any]], Iterable[str]] | None = None,
        duplicate_key: Callable[[dict[str, Any]], str | None] | None = None,
        survivor_sort_key: Callable[[dict[str, Any]], tuple[Any, ...]] | None = None,
        time_source: Callable[[], float] = time.time,
    ) -> None:
        self._backend = backend
        self._page_limit = max(1, min(int(page_limit), _BACKEND_PAGE_LIMIT_CEILING))
        self._max_entries = max(1, int(max_entries_per_scan))
        self._max_state_bytes = max(1_024, int(max_state_bytes))
        self._ttl = max(1.0, float(session_ttl_seconds))
        self._max_sessions = max(1, int(max_sessions))
        self._max_reported_candidates = max(1, int(max_reported_candidates))
        self._classify_entry = classify_entry
        self._duplicate_key = duplicate_key or default_duplicate_key
        self._survivor_sort_key = survivor_sort_key or default_survivor_sort_key
        self._now = time_source
        self._sessions: dict[str, _ScanSession] = {}
        self._sessions_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_scan(self, *, context_id: str) -> dict[str, Any]:
        """Create a scan session and return its initial report with token."""

        context = self._validated_context(context_id)
        now = float(self._now())
        with self._sessions_lock:
            self._purge_expired_locked(now)
            self._evict_terminal_for_capacity_locked()
            if len(self._sessions) >= self._max_sessions:
                raise HygieneScanError(
                    "too many active hygiene scans; retry after one expires "
                    "or is discarded",
                    code="session-capacity",
                )
            token = secrets.token_urlsafe(32)
            session = _ScanSession(
                token=token,
                context_id=context,
                now=now,
                ttl=self._ttl,
            )
            self._sessions[token] = session
        with session.lock:
            return self._build_report(session)

    def advance_scan(self, *, scan_token: str, context_id: str) -> dict[str, Any]:
        """Fetch and fold in exactly one bounded page, then report progress."""

        session = self._resolve_session(scan_token=scan_token, context_id=context_id)
        if not session.lock.acquire(blocking=False):
            raise HygieneScanError(
                "another advance is already in progress for this scan",
                code="advance-in-progress",
            )
        try:
            self._require_current_session(session)
            if session.state != "running":
                raise HygieneScanError(
                    f"hygiene scan is {session.state} and cannot advance; "
                    "start a new scan",
                    code="scan-not-running",
                    restart_required=session.state == "failed",
                )
            self._advance_locked(session)
            self._require_current_session(session)
            session.expires_at = float(self._now()) + self._ttl
            return self._build_report(session)
        finally:
            session.lock.release()

    def scan_status(self, *, scan_token: str, context_id: str) -> dict[str, Any]:
        """Report current progress without touching the backend."""

        session = self._resolve_session(scan_token=scan_token, context_id=context_id)
        if not session.lock.acquire(blocking=False):
            raise HygieneScanError(
                "another advance is already in progress for this scan",
                code="advance-in-progress",
            )
        try:
            self._require_current_session(session)
            return self._build_report(session)
        finally:
            session.lock.release()

    def discard_scan(self, *, scan_token: str, context_id: str) -> None:
        """Drop a session and all of its derived in-memory state."""

        session = self._resolve_session(scan_token=scan_token, context_id=context_id)
        if not session.lock.acquire(blocking=False):
            raise HygieneScanError(
                "another advance is already in progress for this scan",
                code="advance-in-progress",
            )
        try:
            self._require_current_session(session)
            with self._sessions_lock:
                self._sessions.pop(session.token, None)
            session.clear_findings()
            session.state = "discarded"
        finally:
            session.lock.release()

    # ------------------------------------------------------------------
    # Session resolution and expiry
    # ------------------------------------------------------------------

    def _validated_context(self, context_id: str) -> str:
        context = context_id
        if (
            not isinstance(context, str) or not context
            or context != context.strip() or len(context) > _MAX_CONTEXT_ID_LENGTH
            or any(ord(character) < 32 for character in context)
        ):
            raise HygieneScanError(
                "context_id is required and must be a bounded identifier",
                code="invalid-context",
            )
        return context

    def _resolve_session(self, *, scan_token: str, context_id: str) -> _ScanSession:
        context = self._validated_context(context_id)
        token = scan_token if isinstance(scan_token, str) and len(scan_token) <= 128 else ""
        now = float(self._now())
        with self._sessions_lock:
            self._purge_expired_locked(now)
            session = self._sessions.get(token)
            # Unknown, expired, and wrong-context tokens are one identical
            # failure so a token cannot be probed for another namespace.
            if session is None or session.context_id != context or now >= session.expires_at:
                raise HygieneScanError(
                    _INVALID_TOKEN_MESSAGE,
                    code="invalid-token",
                )
            return session

    def _purge_expired_locked(self, now: float) -> None:
        expired = [
            token
            for token, session in self._sessions.items()
            if now >= session.expires_at
        ]
        for token in expired:
            session = self._sessions[token]
            # A page may be outside this process in the serialized backend.
            # Keep its slot bounded until it returns and can erase its state.
            if not session.lock.acquire(blocking=False):
                continue
            try:
                self._sessions.pop(token)
                session.clear_findings()
                session.state = "expired"
            finally:
                session.lock.release()

    def _evict_terminal_for_capacity_locked(self) -> None:
        # Terminal reports are useful while there is room, but a completed or
        # failed scan must not block an explicit restart for the full TTL.
        for token, session in list(self._sessions.items()):
            if len(self._sessions) < self._max_sessions:
                return
            if session.state not in {"complete", "failed", "truncated"}:
                continue
            if not session.lock.acquire(blocking=False):
                continue
            try:
                self._sessions.pop(token)
                session.clear_findings()
                session.state = "evicted"
            finally:
                session.lock.release()

    def _require_current_session(self, session: _ScanSession) -> None:
        """Recheck after taking the session lock and after each backend page."""
        with self._sessions_lock:
            registered = self._sessions.get(session.token) is session
            expired = float(self._now()) >= session.expires_at
            if registered and expired:
                self._sessions.pop(session.token)
            valid = registered and not expired
        if not valid:
            session.clear_findings()
            session.state = "expired" if expired else "discarded"
            raise HygieneScanError(_INVALID_TOKEN_MESSAGE, code="invalid-token")

    # ------------------------------------------------------------------
    # Advancing
    # ------------------------------------------------------------------

    def _fail(
        self,
        session: _ScanSession,
        *,
        code: str,
        message: str,
        restart_required: bool = False,
    ) -> NoReturn:
        """Terminate the session and drop findings so nothing stale leaks."""

        session.state = "failed"
        session.failure_code = code
        session.clear_findings()
        raise HygieneScanError(message, code=code, restart_required=restart_required)

    def _charge(self, session: _ScanSession, amount: int) -> None:
        session.state_bytes += int(amount)
        if session.state_bytes > self._max_state_bytes:
            self._fail(
                session,
                code="state-budget-exceeded",
                message=(
                    "hygiene scan exceeded its in-memory state budget; "
                    "start a new scan with a smaller entry bound"
                ),
            )

    def _advance_locked(self, session: _ScanSession) -> None:
        remaining_budget = self._max_entries - session.scanned
        request_limit = max(1, min(self._page_limit, remaining_budget))
        try:
            payload = self._backend.list_memory(
                context_id=session.context_id,
                limit=request_limit,
                include_global=False,
                include_vectors=False,
                recall_scope="local",
                cursor=session.cursor,
                response_mode="compact",
            )
        except Exception:
            # Real backends raise (cursor snapshot mismatch, expired cursor,
            # scope revision change) instead of returning a differing
            # revision string; both paths must fail closed identically.
            self._fail(
                session,
                code="restart-required",
                message=(
                    "memory listing failed or the snapshot moved; the scan "
                    "must be restarted"
                ),
                restart_required=True,
            )

        self._require_current_session(session)

        page = payload.get("_retrieval_page") if isinstance(payload, dict) else None
        total = page.get("total") if isinstance(page, dict) else None
        returned = page.get("returned") if isinstance(page, dict) else None
        total_entries = total.get("entries") if isinstance(total, dict) else None
        returned_entries = (
            returned.get("entries") if isinstance(returned, dict) else None
        )
        has_more = page.get("has_more") if isinstance(page, dict) else None
        next_cursor = page.get("next_cursor") if isinstance(page, dict) else None
        revision = page.get("snapshot_revision") if isinstance(page, dict) else None
        if (
            not isinstance(page, dict)
            or page.get("surface") != "memory-list"
            or page.get("response_mode") != "compact"
            or type(total_entries) is not int
            or total_entries < 0
            or type(returned_entries) is not int
            or returned_entries < 0
            or returned_entries > request_limit
            or type(has_more) is not bool
            or not isinstance(revision, str)
            or not revision
            or (has_more and (not isinstance(next_cursor, str) or not next_cursor))
            or (not has_more and next_cursor is not None)
        ):
            self._fail(
                session,
                code="invalid-page",
                message="memory listing page metadata is invalid",
            )

        if session.expected_total is None:
            session.expected_total = total_entries
            session.expected_revision = revision
        elif (
            total_entries != session.expected_total
            or revision != session.expected_revision
        ):
            self._fail(
                session,
                code="restart-required",
                message=(
                    "memory snapshot revision or total changed during the "
                    "scan; the scan must be restarted"
                ),
                restart_required=True,
            )

        raw_entries = payload.get("entries")
        if not isinstance(raw_entries, list) or len(raw_entries) != returned_entries:
            self._fail(
                session,
                code="invalid-page",
                message="memory listing page entry count is inconsistent",
            )

        page_ids: list[str] = []
        for entry in raw_entries:
            if not isinstance(entry, dict):
                self._fail(
                    session,
                    code="invalid-page",
                    message="memory listing entry is invalid",
                )
            memory_id = entry.get("memory_id")
            entry_context = entry.get("context_id")
            if (
                not isinstance(memory_id, str) or not memory_id
                or len(memory_id) > _MAX_SORT_KEY_STRING_LENGTH
                or any(ord(character) < 32 for character in memory_id)
                or not isinstance(entry_context, str) or entry_context != session.context_id
                or not isinstance(entry.get("source_text"), str)
                or not isinstance(entry.get("tag"), str)
                or not isinstance(entry.get("metadata"), dict)
            ):
                self._fail(
                    session,
                    code="invalid-page",
                    message=(
                        "memory listing entry fields are invalid or outside the scan scope"
                    ),
                )
            try:
                json.dumps(entry["metadata"], allow_nan=False)
                for field in ("created_at", "updated_at"):
                    value = entry.get(field)
                    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                        raise ValueError("invalid timestamp")
            except (ValueError, TypeError, OverflowError, RecursionError):
                self._fail(session, code="invalid-page", message="memory listing entry metadata or timestamps are invalid")
            page_ids.append(memory_id)
        if len(page_ids) != len(set(page_ids)) or session.seen_memory_ids.intersection(
            page_ids
        ):
            self._fail(
                session,
                code="invalid-page",
                message="memory listing pagination did not advance",
            )
        for memory_id in page_ids:
            self._charge(session, len(memory_id.encode("utf-8")) + 8)
        session.seen_memory_ids.update(page_ids)

        for entry in raw_entries:
            self._ingest_entry(session, entry)
        session.scanned += returned_entries
        session.pages += 1

        assert session.expected_total is not None
        if session.scanned > session.expected_total:
            self._fail(
                session,
                code="invalid-page",
                message="memory listing returned more entries than its total",
            )
        if session.scanned == session.expected_total:
            if has_more:
                self._fail(
                    session,
                    code="invalid-page",
                    message="memory listing claims more pages beyond its total",
                )
            session.state = "complete"
            session.calculated_at = float(self._now())
            return
        # scanned < expected_total from here on.
        if not has_more or returned_entries == 0:
            self._fail(
                session,
                code="invalid-page",
                message="memory listing pagination ended before its total",
            )
        if session.scanned >= self._max_entries:
            # Entry budget reached with more remaining: terminal, but this
            # partial result must never be mistaken for a full-namespace scan.
            session.state = "truncated"
            return
        assert isinstance(next_cursor, str) and next_cursor
        if next_cursor in session.seen_cursors or next_cursor == session.cursor:
            self._fail(
                session,
                code="invalid-page",
                message="memory listing repeated a pagination cursor",
            )
        self._charge(session, len(next_cursor.encode("utf-8")))
        session.seen_cursors.add(next_cursor)
        session.cursor = next_cursor

    # ------------------------------------------------------------------
    # Entry ingestion (transient raw entry, bounded retained derivation)
    # ------------------------------------------------------------------

    def _ingest_entry(self, session: _ScanSession, entry: dict[str, Any]) -> None:
        if self._classify_entry is not None:
            try:
                categories = list(self._classify_entry(entry))
            except Exception:
                self._fail(
                    session,
                    code="callback-failed",
                    message="entry classifier callback failed",
                )
            for category in categories:
                if (
                    not isinstance(category, str)
                    or not category
                    or len(category) > _MAX_CATEGORY_NAME_LENGTH
                    or category == _DUPLICATE_CATEGORY
                ):
                    self._fail(
                        session,
                        code="callback-failed",
                        message="entry classifier returned an invalid category",
                    )
                if category not in session.category_counts:
                    if len(session.category_counts) >= _MAX_DISTINCT_CATEGORIES:
                        self._fail(
                            session,
                            code="callback-failed",
                            message="entry classifier produced too many categories",
                        )
                    self._charge(session, len(category.encode("utf-8")) + 8)
                    session.category_counts[category] = 0
                session.category_counts[category] += 1

        try:
            group_key = self._duplicate_key(entry)
        except Exception:
            self._fail(
                session,
                code="callback-failed",
                message="duplicate key callback failed",
            )
        if group_key is None:
            return
        if not isinstance(group_key, str) or len(group_key) > _MAX_DUPLICATE_KEY_LENGTH:
            self._fail(
                session,
                code="callback-failed",
                message="duplicate key callback returned an invalid key",
            )

        try:
            sort_key = self._survivor_sort_key(entry)
        except Exception:
            self._fail(
                session,
                code="callback-failed",
                message="survivor sort key callback failed",
            )
        key_cost = self._validated_sort_key_cost(session, sort_key)

        memory_id = str(entry.get("memory_id") or "")
        tag = str(entry.get("tag") or "")[:_MAX_RETAINED_TAG_LENGTH]
        members = session.groups.get(group_key)
        cost = len(memory_id.encode("utf-8")) + len(tag.encode("utf-8")) + key_cost + _RECORD_BYTE_OVERHEAD
        if members is None:
            cost += len(group_key.encode("utf-8"))
        self._charge(session, cost)
        record = {"memory_id": memory_id, "tag": tag, "sort_key": sort_key}
        if members is None:
            session.groups[group_key] = [record]
        else:
            members.append(record)

    def _validated_sort_key_cost(
        self,
        session: _ScanSession,
        sort_key: Any,
    ) -> int:
        valid = isinstance(sort_key, tuple) and 0 < len(sort_key) <= (
            _MAX_SORT_KEY_ELEMENTS
        )
        cost = 0
        if valid:
            for element in sort_key:
                if isinstance(element, str):
                    if len(element) > _MAX_SORT_KEY_STRING_LENGTH:
                        valid = False
                        break
                    cost += len(element.encode("utf-8"))
                elif isinstance(element, bool) or isinstance(element, (int, float)):
                    if isinstance(element, float) and not math.isfinite(element):
                        valid = False
                        break
                    cost += 8
                else:
                    valid = False
                    break
        if not valid:
            self._fail(
                session,
                code="callback-failed",
                message=(
                    "survivor sort key must be a small tuple of bounded "
                    "strings and finite numbers"
                ),
            )
        return cost

    # ------------------------------------------------------------------
    # Reporting (no raw content, no internal content digests)
    # ------------------------------------------------------------------

    def _duplicate_candidates(
        self,
        session: _ScanSession,
    ) -> tuple[list[dict[str, Any]], int]:
        provisional = session.state != "complete"
        candidates: list[dict[str, Any]] = []
        for members in session.groups.values():
            if len(members) < 2:
                continue
            try:
                survivor = min(members, key=lambda member: member["sort_key"])
            except TypeError:
                self._fail(
                    session,
                    code="callback-failed",
                    message="survivor sort keys are not mutually comparable",
                )
            survivor_id = str(survivor["memory_id"])
            # A public group id must derive only from already-public random
            # memory ids, never from the content-derived grouping key, so it
            # cannot act as a raw-content equality oracle.
            member_ids = sorted(str(member["memory_id"]) for member in members)
            group_id = hashlib.sha256(
                ("memory-ids:" + "\0".join(member_ids)).encode("utf-8")
            ).hexdigest()[:12]
            for member in members:
                memory_id = str(member["memory_id"])
                if memory_id == survivor_id:
                    continue
                candidates.append(
                    {
                        "memory_id": memory_id,
                        "duplicate_of_memory_id": survivor_id,
                        "duplicate_of_tag": str(survivor["tag"]),
                        "duplicate_group_id": group_id,
                        "duplicate_group_count": len(members),
                        "duplicate_match": "same-context-normalized-whole-source-text",
                        "provisional": provisional,
                    }
                )
        candidates.sort(
            key=lambda item: (item["duplicate_group_id"], item["memory_id"])
        )
        return candidates[: self._max_reported_candidates], len(candidates)

    def _build_report(self, session: _ScanSession) -> dict[str, Any]:
        complete = session.state == "complete"
        total = session.expected_total
        if total is None:
            fraction = 0.0
        elif total == 0:
            fraction = 1.0
        else:
            fraction = round(min(1.0, session.scanned / total), 6)
        bounded_candidates, candidate_count = self._duplicate_candidates(session)
        category_counts = dict(sorted(session.category_counts.items()))
        if candidate_count:
            category_counts[_DUPLICATE_CATEGORY] = candidate_count
        no_findings = (
            complete
            and candidate_count == 0
            and not any(category_counts.values())
        )
        report: dict[str, Any] = {
            "action": "memory-hygiene-scan",
            "scan_token": session.token,
            "state": session.state,
            "failure_code": session.failure_code,
            "context_id": session.context_id,
            "include_global": False,
            "recall_scope": "local",
            "snapshot_revision": session.expected_revision,
            "scanned_entry_count": session.scanned,
            "total_entry_count": total,
            "scanned_fraction": fraction,
            "scan_complete": complete,
            "provisional": not complete,
            "pages_fetched": session.pages,
            "category_counts": category_counts,
            "duplicate_candidate_count": candidate_count,
            "duplicate_candidates": bounded_candidates,
            "duplicate_candidates_truncated": (
                candidate_count > len(bounded_candidates)
            ),
            "no_findings_in_complete_scan": no_findings,
            "assessment_scope": "configured-entry-checks-and-whole-text-duplicates",
            "entry_classifier_configured": self._classify_entry is not None,
            "core_availability_assessed": False,
            "cleanup_preservation_verified": False,
            "retained_state_estimate_bytes": session.state_bytes,
            "retained_state_budget_bytes": self._max_state_bytes,
            "retained_state_budget_kind": "estimated-payload-and-fixed-record-overhead",
            "expires_at": session.expires_at,
        }
        if complete:
            report["calculated_at"] = session.calculated_at
            report["scope"] = {
                "scan_kind": "exact-namespace",
                "context_id": session.context_id,
                "snapshot_revision": session.expected_revision,
                "include_global": False,
                "recall_scope": "local",
            }
        return report

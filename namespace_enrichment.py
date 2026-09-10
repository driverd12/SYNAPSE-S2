"""Explicit namespace analysis jobs with revision-fenced, bounded caching.

The caller owns backend serialization. In production, calculate uses the
existing authoritative CoreClient; this module never constructs an MLX backend.
"""
from __future__ import annotations

from bisect import bisect_right
from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import quote

from redaction import reject_sensitive_identifier


MAX_EXPIRY_ROWS = 10_000
MAX_RESULT_BYTES = 2 * 1024 * 1024
PROPOSAL_PREFIX = "bridge_governance.proposal.v1."
LINK_PREFIX = "bridge_governance.link.v1."
_CONTEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_REVISION = re.compile(r"[0-9a-f]{64}\Z")


class RevisionUnavailable(RuntimeError):
    """Current namespace revision cannot be established without guessing."""


@dataclass(frozen=True)
class RevisionSnapshot:
    revision: str
    sequence: int
    observed_at: float
    valid_until: float | None


class NamespaceRevisionObserver:
    """Persistent read-only SQLite data_version plus bridge expiry boundaries.

    data_version is meaningful only across reads on the same connection. A random
    connection-lifetime nonce and file identity prevent reopened/replaced databases
    from sharing a cache revision. This observer never writes; every database
    commit, including non-memory metadata changes, conservatively invalidates it.
    """

    def __init__(self, memory_path: str | Path, *, clock: Callable[[], float] = time.time):
        self.path = Path(memory_path).expanduser().absolute()
        self._clock = clock
        self._lock = threading.Lock()
        self._connection: sqlite3.Connection | None = None
        self._identity: tuple[int, int] | None = None
        self._nonce = ""
        self._version: int | None = None
        self._expiries: list[float] = []
        self._sequence = 0
        self._closed = False

    def _file_identity(self) -> tuple[int, int]:
        found = self.path.lstat()
        if not stat.S_ISREG(found.st_mode) or stat.S_ISLNK(found.st_mode):
            raise RevisionUnavailable("namespace revision file is unavailable")
        return found.st_dev, found.st_ino

    def _disconnect(self) -> None:
        if self._connection is not None:
            self._connection.close()
        self._connection = None
        self._identity = None
        self._version = None
        self._expiries = []

    def _connect(self, identity: tuple[int, int]) -> sqlite3.Connection:
        if self._connection is None or identity != self._identity:
            self._disconnect()
            connection = sqlite3.connect(
                f"file:{quote(str(self.path), safe='/')}?mode=ro",
                uri=True, timeout=0.1, isolation_level=None, check_same_thread=False,
            )
            try:
                connection.execute("PRAGMA query_only=ON")
                if self._file_identity() != identity:
                    raise RevisionUnavailable("namespace revision file changed")
            except BaseException:
                connection.close()
                raise
            self._connection = connection
            self._identity = identity
            self._nonce = secrets.token_hex(16)
        return self._connection

    @staticmethod
    def _read_expiries(connection: sqlite3.Connection) -> list[float]:
        # Project scalar timestamps only, never memory text or governance
        # reasons/evidence. Prefix scans are bounded and only repeat on writes.
        rows = connection.execute(
            """
            SELECT key, json_valid(value_json),
                CASE WHEN json_valid(value_json) THEN json_extract(value_json, '$.state') END,
                CASE WHEN json_valid(value_json) THEN json_extract(value_json, '$.proposal_expires_at') END,
                CASE WHEN json_valid(value_json) THEN json_extract(value_json, '$.link_expires_at') END,
                CASE WHEN json_valid(value_json) THEN json_type(value_json, '$.proposal_expires_at') END,
                CASE WHEN json_valid(value_json) THEN json_type(value_json, '$.link_expires_at') END
            FROM store_metadata
            WHERE key GLOB ? OR key GLOB ?
            LIMIT ?
            """,
            (PROPOSAL_PREFIX + "*", LINK_PREFIX + "*", MAX_EXPIRY_ROWS + 1),
        ).fetchall()
        if len(rows) > MAX_EXPIRY_ROWS:
            raise RevisionUnavailable("namespace expiry observation exceeds its bound")
        expiries: list[float] = []
        for key, valid_json, state, proposal_expiry, link_expiry, proposal_type, link_type in rows:
            if valid_json != 1 or state not in {
                "pending", "approved", "rejected", "disabled", "revoked", "expired",
            }:
                raise RevisionUnavailable("namespace expiry metadata is invalid")
            if str(key).startswith(PROPOSAL_PREFIX) and state == "pending" and proposal_expiry is None:
                raise RevisionUnavailable("namespace proposal expiry is missing")
            for expiry, json_type in ((proposal_expiry, proposal_type), (link_expiry, link_type)):
                if expiry is not None:
                    if json_type not in {"integer", "real"} or type(expiry) not in (int, float) or not math.isfinite(expiry) or expiry <= 0:
                        raise RevisionUnavailable("namespace expiry metadata is invalid")
                    expiries.append(float(expiry))
        return sorted(set(expiries))

    def snapshot(self) -> RevisionSnapshot:
        with self._lock:
            if self._closed:
                raise RevisionUnavailable("namespace revision observer is closed")
            try:
                for _ in range(3):
                    identity = self._file_identity()
                    connection = self._connect(identity)
                    version = int(connection.execute("PRAGMA data_version").fetchone()[0])
                    expiries = self._expiries
                    if version != self._version:
                        expiries = self._read_expiries(connection)
                    if self._file_identity() != identity:
                        self._disconnect()
                        continue
                    if int(connection.execute("PRAGMA data_version").fetchone()[0]) != version:
                        continue
                    self._version, self._expiries = version, expiries
                    now = float(self._clock())
                    if not math.isfinite(now):
                        raise RevisionUnavailable("namespace observation clock is invalid")
                    expiry_epoch = bisect_right(expiries, now)
                    seed = json.dumps(
                        [self._nonce, *identity, version, expiry_epoch],
                        separators=(",", ":"),
                    )
                    self._sequence += 1
                    return RevisionSnapshot(
                        revision=hashlib.sha256(seed.encode()).hexdigest(),
                        sequence=self._sequence, observed_at=now,
                        valid_until=expiries[expiry_epoch] if expiry_epoch < len(expiries) else None,
                    )
            except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
                raise RevisionUnavailable("namespace revision is unavailable") from exc
            raise RevisionUnavailable("namespace revision changed while observing")

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._disconnect()


def _options(value: Mapping[str, Any] | None) -> dict[str, Any]:
    defaults = {
        "limit": 500, "include_suggestions": True, "include_density_metrics": True,
        "suggestion_limit": 50, "min_suggestion_score": 0.05,
        "max_visual_phase_delay_ticks": 4,
    }
    if value is not None and (not isinstance(value, Mapping) or set(value) - set(defaults)):
        raise ValueError("namespace enrichment options are invalid")
    defaults.update(value or {})
    for key, low, high in (
        ("limit", 1, 2000), ("suggestion_limit", 0, 100),
        ("max_visual_phase_delay_ticks", 0, 4),
    ):
        item = defaults[key]
        if type(item) is not int or not low <= item <= high:
            raise ValueError(f"{key} is outside the enrichment bound")
    for key in ("include_suggestions", "include_density_metrics"):
        if type(defaults[key]) is not bool:
            raise ValueError(f"{key} must be a boolean")
    score = defaults["min_suggestion_score"]
    if type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1:
        raise ValueError("min_suggestion_score is invalid")
    defaults["min_suggestion_score"] = float(score)
    return defaults


class NamespaceEnrichmentManager:
    """One explicitly started job, bounded cached results, cheap status reads."""

    def __init__(
        self, *, revision_source: Callable[[], RevisionSnapshot],
        calculate: Callable[..., dict[str, Any]],
        close_revision_source: Callable[[], None] | None = None,
        max_cached_entries: int = 8, max_duration_seconds: float = 60.0,
        max_result_bytes: int = MAX_RESULT_BYTES,
        max_revision_age_seconds: float = 15.0,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if type(max_cached_entries) is not int or not 1 <= max_cached_entries <= 32:
            raise ValueError("namespace cache size is invalid")
        if type(max_result_bytes) is not int or not 1 <= max_result_bytes <= MAX_RESULT_BYTES:
            raise ValueError("namespace result size bound is invalid")
        if type(max_duration_seconds) not in (int, float) or not math.isfinite(max_duration_seconds) or not 0 < max_duration_seconds <= 300:
            raise ValueError("namespace duration bound is invalid")
        if type(max_revision_age_seconds) not in (int, float) or not math.isfinite(max_revision_age_seconds) or not 0 < max_revision_age_seconds <= 60:
            raise ValueError("namespace revision age bound is invalid")
        self._revision_source, self._calculate = revision_source, calculate
        self._close_revision_source = close_revision_source
        self._max_cached = max_cached_entries
        self._max_duration = float(max_duration_seconds)
        self._max_bytes = max_result_bytes
        self._max_revision_age = float(max_revision_age_seconds)
        self._clock, self._monotonic = clock, monotonic
        self._lock = threading.Lock()
        self._latest: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()
        self._cache: OrderedDict[tuple[str, str, str], dict[str, Any]] = OrderedDict()
        self._observed: RevisionSnapshot | None = None
        self._revision_unavailable = False
        self._invalidated_at: float | None = None
        self._active: dict[str, Any] | None = None
        self._closed = False

    @staticmethod
    def _request(context_id: str, options: Mapping[str, Any] | None):
        context = reject_sensitive_identifier(context_id, field="context_id")
        if context != context.strip() or (context and _CONTEXT.fullmatch(context) is None):
            raise ValueError("context_id is invalid")
        normalized = _options(options)
        return (context, json.dumps(normalized, sort_keys=True)), normalized

    @staticmethod
    def _validate_snapshot(snapshot: RevisionSnapshot) -> None:
        if not isinstance(snapshot, RevisionSnapshot) or _REVISION.fullmatch(snapshot.revision) is None:
            raise RevisionUnavailable("namespace revision snapshot is invalid")
        if type(snapshot.sequence) is not int or snapshot.sequence < 1 or not math.isfinite(snapshot.observed_at):
            raise RevisionUnavailable("namespace revision snapshot is invalid")
        if snapshot.valid_until is not None and (
            not math.isfinite(snapshot.valid_until) or snapshot.valid_until <= snapshot.observed_at
        ):
            raise RevisionUnavailable("namespace revision validity is invalid")

    def observe_revision(self, snapshot: RevisionSnapshot) -> None:
        self._validate_snapshot(snapshot)
        with self._lock:
            if self._observed is None or snapshot.sequence > self._observed.sequence:
                self._observed = snapshot
                if self._invalidated_at is None or snapshot.observed_at >= self._invalidated_at:
                    self._revision_unavailable = False

    def invalidate_revision(self) -> None:
        """Fail closed when a caller cannot refresh authoritative revision evidence."""
        with self._lock:
            self._revision_unavailable = True
            self._invalidated_at = self._clock()

    def _render(self, job: dict[str, Any]) -> dict[str, Any]:
        result = {key: value for key, value in job.items() if not key.startswith("_")}
        now = self._clock()
        if result["state"] == "ready" and self._revision_unavailable:
            result.update(state="stale", data=None, error_code="revision_unavailable")
        elif result["state"] == "ready" and (
            self._observed is None or self._observed.revision != result["revision"]
            or now < result["calculated_at"]
            or (result["valid_until"] is not None and now >= result["valid_until"])
        ):
            result.update(state="stale", data=None, error_code="revision_changed")
        elif result["state"] == "ready" and (
            now < self._observed.observed_at
            or now - self._observed.observed_at > self._max_revision_age
        ):
            result.update(state="stale", data=None, error_code="revision_stale")
        result["revision_observed_at"] = self._observed.observed_at if self._observed else None
        result["deadline_exceeded"] = bool(
            result["state"] in {"queued", "running"}
            and self._monotonic() - job["_began"] > self._max_duration
        )
        # Detach nested data: response consumers cannot mutate the cache.
        return json.loads(json.dumps(result, allow_nan=False))

    def _empty(self, key, options, *, state="stale", error="not_requested"):
        return {
            "schema": "synapse-s2.namespace-enrichment.v1", "state": state,
            "job_id": None, "context_id": key[0], "options": dict(options),
            "revision": None, "calculated_at": None, "valid_until": None,
            "data": None, "error_code": error, "cache_hit": False,
            "_began": self._monotonic(),
        }

    def status(self, *, context_id: str, options: Mapping[str, Any] | None = None) -> dict[str, Any]:
        key, normalized = self._request(context_id, options)
        with self._lock:
            job = self._latest.get(key) or self._empty(key, normalized)
            return self._render(job)

    def start(self, *, context_id: str, options: Mapping[str, Any] | None = None) -> dict[str, Any]:
        key, normalized = self._request(context_id, options)
        with self._lock:
            if self._closed:
                return self._render(self._empty(key, normalized, state="failed", error="closed"))
            if self._active is not None:
                if self._active["_key"] == key:
                    return self._render(self._active)
                return self._render(self._empty(key, normalized, state="busy", error="another_job_active"))
            job = self._empty(key, normalized, state="queued", error=None)
            job.update(job_id="s2enrich_" + secrets.token_hex(16), _key=key)
            self._active = job
            self._latest[key] = job
            self._latest.move_to_end(key)
            while len(self._latest) > self._max_cached:
                self._latest.popitem(last=False)
            initial = self._render(job)
            thread = threading.Thread(target=self._run, args=(job,), name="namespace-enrichment", daemon=True)
            try:
                thread.start()
            except Exception:
                self._active = None
                job.update(state="failed", error_code="worker_unavailable")
                return self._render(job)
            return initial

    def _run(self, job: dict[str, Any]) -> None:
        state, error = "stale", "revision_unavailable"
        try:
            before = self._revision_source()
            self.observe_revision(before)
            cache_key = (*job["_key"], before.revision)
            with self._lock:
                if self._closed:
                    return
                cached = self._cache.get(cache_key)
                if cached and self._render(cached)["state"] == "ready":
                    job.update({k: v for k, v in cached.items() if not k.startswith("_") and k != "job_id"})
                    job["cache_hit"] = True
                    self._cache.move_to_end(cache_key)
                    return
                job.update(state="running", revision=before.revision)
            state, error = "failed", "enrichment_failed"
            data = self._calculate(context_id=job["context_id"], **job["options"])
            encoded = json.dumps(data, allow_nan=False, separators=(",", ":")).encode()
            if not isinstance(data, dict) or len(encoded) > self._max_bytes:
                error = "result_exceeds_bound"
                return
            if data.get("selected_context_id") != job["context_id"]:
                error = "context_mismatch"
                return
            if self._monotonic() - job["_began"] > self._max_duration:
                error = "duration_exceeded"
                return
            state, error = "stale", "revision_unavailable"
            after = self._revision_source()
            self.observe_revision(after)
            with self._lock:
                if self._closed:
                    return
                if self._revision_unavailable:
                    error = "revision_unavailable"
                    return
                if before.revision != after.revision or self._observed.revision != after.revision:
                    error = "revision_changed"
                    return
                job.update(
                    state="ready", error_code=None, calculated_at=self._clock(),
                    revision=after.revision, valid_until=after.valid_until,
                    data=json.loads(encoded),
                )
                self._cache[cache_key] = dict(job)
                self._cache.move_to_end(cache_key)
                while len(self._cache) > self._max_cached:
                    self._cache.popitem(last=False)
        except Exception:
            # Exception text may contain memory content, credentials or paths.
            if state == "stale" and error == "revision_unavailable":
                self.invalidate_revision()
        finally:
            with self._lock:
                if self._closed:
                    job.update(state="failed", error_code="closed", data=None)
                elif job["state"] in {"queued", "running"}:
                    job.update(state=state, error_code=error, data=None)
                if self._active is job:
                    self._active = None

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._cache.clear()
            self._latest.clear()
        if self._close_revision_source is not None:
            self._close_revision_source()

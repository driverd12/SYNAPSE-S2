from __future__ import annotations

import copy
import fcntl
import json
import math
import os
import secrets
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping


AGGREGATE_SCHEMA = "synapse-s2.impact-metrics.v1"
PROJECTION_SCHEMA = "synapse-s2.impact-projection.v1"
AGGREGATE_VERSION = 1
LATENCY_SAMPLE_LIMIT = 128
STORE_DIRECTORY_NAME = "impact-metrics"
STORE_FILE_NAME = "aggregate.json"
LOCK_FILE_NAME = ".aggregate.lock"
MAX_STORE_BYTES = 64 * 1024
MAX_COUNTER = 9_007_199_254_740_991
MAX_RESULT_COUNT = 1_000_000
MAX_RESPONSE_BYTES = 128 * 1024 * 1024
MAX_LATENCY_MS = 24 * 60 * 60 * 1000
MAX_INPUT_PRICE_PER_MILLION_TOKENS = 1_000_000.0

_COUNTER_FIELDS = (
    "attempt_count",
    "completed_count",
    "error_count",
    "nonempty_result_count",
    "result_count_total",
    "bridge_eligible_count",
    "connected_assist_count",
    "graph_assist_count",
    "response_bytes_total",
    "estimated_tokens_total",
)

_CAVEATS = (
    (
        "Coverage includes only dashboard recall outcomes recorded by this local "
        "aggregate; it is not a count of every SYNAPSE-S2 or MCP operation."
    ),
    (
        "Result yield means a completed retrieval returned at least one item; it "
        "does not measure correctness, relevance, or usefulness."
    ),
    (
        "Connected and graph assists report returned evidence paths; they do not "
        "prove that SYNAPSE-S2 caused a time or money saving."
    ),
    "Estimated tokens use ceil(UTF-8 JSON response bytes / 4).",
    (
        "Model-input-equivalent cost is a what-if shown only when an input-token "
        "price is supplied explicitly. Dashboard responses may never enter a model "
        "context, and local-model use may have no per-token charge."
    ),
    (
        "No savings amount is reported because this aggregate has no measured "
        "no-SYNAPSE counterfactual. A configured response ceiling is not actual savings."
    ),
)


class ImpactMetricsError(RuntimeError):
    """A content-free failure at the private impact-metrics boundary."""

    def __init__(self, code: str = "impact_metrics_invalid") -> None:
        super().__init__(code)
        self.code = code


def _normal_absolute_path(value: str | os.PathLike[str]) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise ImpactMetricsError("impact_metrics_root_invalid") from exc
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ImpactMetricsError("impact_metrics_root_invalid")
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts:
        raise ImpactMetricsError("impact_metrics_root_invalid")
    normalized = Path(os.path.normpath(str(path)))
    if normalized != path or normalized == Path(normalized.anchor):
        raise ImpactMetricsError("impact_metrics_root_invalid")
    return normalized


def _file_identity(value: os.stat_result) -> tuple[int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(stat.S_IFMT(value.st_mode)),
    )


def _validate_private_directory(
    path: Path,
    *,
    expected_identity: tuple[int, int, int] | None = None,
) -> os.stat_result:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise ImpactMetricsError("impact_metrics_root_invalid") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o700
        or (
            expected_identity is not None
            and _file_identity(observed) != expected_identity
        )
    ):
        raise ImpactMetricsError("impact_metrics_root_invalid")
    return observed


def _validate_private_regular_file(
    path: Path,
    observed: os.stat_result,
    *,
    code: str,
) -> None:
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) != 0o600
    ):
        raise ImpactMetricsError(code)


def _bounded_integer(value: Any, *, maximum: int, code: str) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise ImpactMetricsError(code)
    return int(value)


def _bounded_number(value: Any, *, maximum: float, code: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ImpactMetricsError(code)
    number = float(value)
    if not math.isfinite(number) or number < 0.0 or number > maximum:
        raise ImpactMetricsError(code)
    return number


def _checked_increment(current: Any, amount: int, *, code: str) -> int:
    value = _bounded_integer(current, maximum=MAX_COUNTER, code=code)
    increment = _bounded_integer(amount, maximum=MAX_COUNTER, code=code)
    if value > MAX_COUNTER - increment:
        raise ImpactMetricsError(code)
    return value + increment


def _default_aggregate() -> dict[str, Any]:
    return {
        "schema": AGGREGATE_SCHEMA,
        "version": AGGREGATE_VERSION,
        "coverage": {
            "first_recorded_at": None,
            "updated_at": None,
            "latency_sample_limit": LATENCY_SAMPLE_LIMIT,
        },
        "dashboard_recall": {
            **{field: 0 for field in _COUNTER_FIELDS},
            "latency_samples_ms": [],
        },
    }


def _validate_timestamp(value: Any, *, nullable: bool) -> float | None:
    if value is None and nullable:
        return None
    return _bounded_number(
        value,
        maximum=float(MAX_COUNTER),
        code="impact_metrics_store_invalid",
    )


def _validate_aggregate(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "version",
        "coverage",
        "dashboard_recall",
    }:
        raise ImpactMetricsError("impact_metrics_store_invalid")
    if (
        value.get("schema") != AGGREGATE_SCHEMA
        or value.get("version") != AGGREGATE_VERSION
    ):
        raise ImpactMetricsError("impact_metrics_store_invalid")

    coverage = value.get("coverage")
    if not isinstance(coverage, dict) or set(coverage) != {
        "first_recorded_at",
        "updated_at",
        "latency_sample_limit",
    }:
        raise ImpactMetricsError("impact_metrics_store_invalid")
    if coverage.get("latency_sample_limit") != LATENCY_SAMPLE_LIMIT:
        raise ImpactMetricsError("impact_metrics_store_invalid")
    first_recorded_at = _validate_timestamp(
        coverage.get("first_recorded_at"),
        nullable=True,
    )
    updated_at = _validate_timestamp(coverage.get("updated_at"), nullable=True)

    recall = value.get("dashboard_recall")
    if not isinstance(recall, dict) or set(recall) != {
        *_COUNTER_FIELDS,
        "latency_samples_ms",
    }:
        raise ImpactMetricsError("impact_metrics_store_invalid")
    counters = {
        field: _bounded_integer(
            recall.get(field),
            maximum=MAX_COUNTER,
            code="impact_metrics_store_invalid",
        )
        for field in _COUNTER_FIELDS
    }
    samples = recall.get("latency_samples_ms")
    if not isinstance(samples, list) or len(samples) > LATENCY_SAMPLE_LIMIT:
        raise ImpactMetricsError("impact_metrics_store_invalid")
    clean_samples = [
        _bounded_number(
            sample,
            maximum=float(MAX_LATENCY_MS),
            code="impact_metrics_store_invalid",
        )
        for sample in samples
    ]

    attempts = counters["attempt_count"]
    completed = counters["completed_count"]
    errors = counters["error_count"]
    if (
        completed + errors != attempts
        or counters["nonempty_result_count"] > completed
        or counters["bridge_eligible_count"] > completed
        or counters["connected_assist_count"]
        > counters["bridge_eligible_count"]
        or counters["graph_assist_count"] > completed
        or len(clean_samples) > attempts
    ):
        raise ImpactMetricsError("impact_metrics_store_invalid")
    if attempts == 0:
        if first_recorded_at is not None or updated_at is not None or clean_samples:
            raise ImpactMetricsError("impact_metrics_store_invalid")
    elif (
        first_recorded_at is None
        or updated_at is None
        or updated_at < first_recorded_at
    ):
        raise ImpactMetricsError("impact_metrics_store_invalid")

    return {
        "schema": AGGREGATE_SCHEMA,
        "version": AGGREGATE_VERSION,
        "coverage": {
            "first_recorded_at": first_recorded_at,
            "updated_at": updated_at,
            "latency_sample_limit": LATENCY_SAMPLE_LIMIT,
        },
        "dashboard_recall": {
            **counters,
            "latency_samples_ms": clean_samples,
        },
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ImpactMetricsError("impact_metrics_store_invalid")
        result[key] = value
    return result


def _reject_nonfinite_json(_value: str) -> None:
    raise ImpactMetricsError("impact_metrics_store_invalid")


def _safe_ratio(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(float(numerator) / float(denominator), 6)


def _nearest_rank(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return round(float(ordered[index]), 3)


def _latency_projection(samples: list[float]) -> dict[str, Any]:
    if not samples:
        return {
            "sample_count": 0,
            "sample_limit": LATENCY_SAMPLE_LIMIT,
            "p50": None,
            "p95": None,
            "mean": None,
            "minimum": None,
            "maximum": None,
            "bounded_recent_window": True,
        }
    return {
        "sample_count": len(samples),
        "sample_limit": LATENCY_SAMPLE_LIMIT,
        "p50": _nearest_rank(samples, 0.50),
        "p95": _nearest_rank(samples, 0.95),
        "mean": round(sum(samples) / len(samples), 3),
        "minimum": round(min(samples), 3),
        "maximum": round(max(samples), 3),
        "bounded_recent_window": True,
    }


def project_impact_metrics(
    aggregate: Mapping[str, Any],
    *,
    input_price_per_million_tokens: float | None = None,
) -> dict[str, Any]:
    """Project content-free, uncertainty-labelled dashboard impact metrics.

    The optional price produces a what-if model-input equivalent for the observed
    response-token estimate. It is not an observed bill and deliberately does not
    estimate savings: this store has no measured no-SYNAPSE counterfactual, and a
    response budget is only a ceiling.
    """

    canonical = _validate_aggregate(copy.deepcopy(dict(aggregate)))
    if input_price_per_million_tokens is None:
        price = None
    else:
        price = _bounded_number(
            input_price_per_million_tokens,
            maximum=MAX_INPUT_PRICE_PER_MILLION_TOKENS,
            code="impact_metrics_price_invalid",
        )

    coverage = canonical["coverage"]
    recall = canonical["dashboard_recall"]
    attempts = int(recall["attempt_count"])
    completed = int(recall["completed_count"])
    errors = int(recall["error_count"])
    nonempty = int(recall["nonempty_result_count"])
    bridge_eligible = int(recall["bridge_eligible_count"])
    connected_assists = int(recall["connected_assist_count"])
    graph_assists = int(recall["graph_assist_count"])
    estimated_tokens = int(recall["estimated_tokens_total"])
    observed_cost = (
        None
        if price is None
        else round((estimated_tokens * price) / 1_000_000.0, 8)
    )

    return {
        "schema": PROJECTION_SCHEMA,
        "version": 1,
        "coverage": {
            "scope": "dashboard-recall-only",
            "first_recorded_at": coverage["first_recorded_at"],
            "updated_at": coverage["updated_at"],
            "recall_attempt_count": attempts,
            "latency_sample_count": len(recall["latency_samples_ms"]),
            "persistent": True,
            "content_free": True,
        },
        "recall": {
            "attempt_count": attempts,
            "completed_count": completed,
            "error_count": errors,
            "error_rate": _safe_ratio(errors, attempts),
            "nonempty_result_count": nonempty,
            "result_count_total": int(recall["result_count_total"]),
            "result_yield": {
                "numerator": nonempty,
                "denominator": completed,
                "ratio": _safe_ratio(nonempty, completed),
                "semantics": "nonempty completed retrievals, not relevance",
            },
            "mean_results_per_completed_recall": (
                None
                if completed == 0
                else round(int(recall["result_count_total"]) / completed, 3)
            ),
        },
        "assistance": {
            "bridge_eligible_count": bridge_eligible,
            "connected_assist_count": connected_assists,
            "connected_assist_rate": {
                "numerator": connected_assists,
                "denominator": bridge_eligible,
                "ratio": _safe_ratio(connected_assists, bridge_eligible),
                "semantics": "recalls returning an approved bridge evidence path",
            },
            "graph_assist_count": graph_assists,
            "graph_assist_rate": {
                "numerator": graph_assists,
                "denominator": completed,
                "ratio": _safe_ratio(graph_assists, completed),
                "semantics": "completed recalls returning a graph-neighbor result",
            },
        },
        "performance": {
            "latency_ms": _latency_projection(recall["latency_samples_ms"]),
            "latency_scope": "all recorded recall outcomes, including errors",
            "response_bytes_total": int(recall["response_bytes_total"]),
            "estimated_response_tokens_total": estimated_tokens,
            "token_estimate_formula": "ceil(each UTF-8 JSON response byte count / 4)",
        },
        "cost": {
            "enabled": price is not None,
            "input_price_per_million_tokens": price,
            "estimated_model_input_equivalent_cost_usd": observed_cost,
            "basis": (
                "what-if observed dashboard response-token estimate priced as "
                "model input; not an observed bill"
            ),
            "savings_available": False,
            "estimated_input_cost_avoided_usd": None,
            "savings_unavailable_reason": (
                "No measured no-SYNAPSE counterfactual is stored; a configured "
                "response ceiling is not actual savings."
            ),
        },
        "caveats": list(_CAVEATS),
    }


class ImpactMetricsStore:
    """Owner-only aggregate beneath a caller-supplied verified binding data root.

    The caller must pass the absolute ``CoreClientBinding.data_root`` (or an
    equivalently verified owner-only test root). This class never falls back to
    the current working directory, home-directory guesses, or repository-local
    state.
    """

    def __init__(self, data_root: str | os.PathLike[str]) -> None:
        self.data_root = _normal_absolute_path(data_root)
        observed_root = _validate_private_directory(self.data_root)
        self._root_identity = _file_identity(observed_root)
        self.store_directory = self.data_root / STORE_DIRECTORY_NAME
        self.path = self.store_directory / STORE_FILE_NAME
        self.lock_path = self.store_directory / LOCK_FILE_NAME
        self._ensure_layout()

    def _ensure_layout(self) -> None:
        _validate_private_directory(
            self.data_root,
            expected_identity=self._root_identity,
        )
        created = False
        try:
            self.store_directory.mkdir(mode=0o700, parents=False)
            created = True
        except FileExistsError:
            pass
        try:
            observed = self.store_directory.lstat()
        except OSError as exc:
            raise ImpactMetricsError("impact_metrics_layout_invalid") from exc
        if created:
            if (
                stat.S_ISLNK(observed.st_mode)
                or not stat.S_ISDIR(observed.st_mode)
                or observed.st_uid != os.getuid()
            ):
                raise ImpactMetricsError("impact_metrics_layout_invalid")
            os.chmod(self.store_directory, 0o700)
            observed = self.store_directory.lstat()
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o700
        ):
            raise ImpactMetricsError("impact_metrics_layout_invalid")
        _validate_private_directory(
            self.data_root,
            expected_identity=self._root_identity,
        )

    @contextmanager
    def _locked(self, *, exclusive: bool) -> Iterator[None]:
        self._ensure_layout()
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        created = False
        try:
            descriptor = os.open(
                self.lock_path,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            created = True
        except FileExistsError:
            try:
                descriptor = os.open(self.lock_path, flags)
            except OSError as exc:
                raise ImpactMetricsError("impact_metrics_lock_invalid") from exc
        try:
            opened = os.fstat(descriptor)
            if created:
                os.fchmod(descriptor, 0o600)
                opened = os.fstat(descriptor)
            _validate_private_regular_file(
                self.lock_path,
                opened,
                code="impact_metrics_lock_invalid",
            )
            visible = self.lock_path.lstat()
            _validate_private_regular_file(
                self.lock_path,
                visible,
                code="impact_metrics_lock_invalid",
            )
            if _file_identity(visible) != _file_identity(opened):
                raise ImpactMetricsError("impact_metrics_lock_invalid")
            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH,
            )
            held = os.fstat(descriptor)
            visible = self.lock_path.lstat()
            if (
                _file_identity(held) != _file_identity(opened)
                or _file_identity(visible) != _file_identity(opened)
            ):
                raise ImpactMetricsError("impact_metrics_lock_invalid")
            self._ensure_layout()
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _read_unlocked(self) -> dict[str, Any]:
        try:
            observed = self.path.lstat()
        except FileNotFoundError:
            return _default_aggregate()
        except OSError as exc:
            raise ImpactMetricsError("impact_metrics_store_invalid") from exc
        _validate_private_regular_file(
            self.path,
            observed,
            code="impact_metrics_store_invalid",
        )
        if observed.st_size <= 0 or observed.st_size > MAX_STORE_BYTES:
            raise ImpactMetricsError("impact_metrics_store_invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise ImpactMetricsError("impact_metrics_store_invalid") from exc
        try:
            opened = os.fstat(descriptor)
            _validate_private_regular_file(
                self.path,
                opened,
                code="impact_metrics_store_invalid",
            )
            if (
                _file_identity(opened) != _file_identity(observed)
                or opened.st_size <= 0
                or opened.st_size > MAX_STORE_BYTES
            ):
                raise ImpactMetricsError("impact_metrics_store_invalid")
            remaining = int(opened.st_size) + 1
            chunks: list[bytes] = []
            while remaining > 0:
                try:
                    chunk = os.read(descriptor, min(remaining, 16 * 1024))
                except InterruptedError:
                    continue
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            visible = self.path.lstat()
            if (
                len(raw) != int(opened.st_size)
                or _file_identity(after) != _file_identity(opened)
                or _file_identity(visible) != _file_identity(opened)
                or int(after.st_size) != int(opened.st_size)
                or int(after.st_mtime_ns) != int(opened.st_mtime_ns)
            ):
                raise ImpactMetricsError("impact_metrics_store_invalid")
        finally:
            os.close(descriptor)
        try:
            decoded = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_json,
            )
        except ImpactMetricsError:
            raise
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ImpactMetricsError("impact_metrics_store_invalid") from exc
        return _validate_aggregate(decoded)

    def _fsync_store_directory(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.store_directory, flags)
        except OSError as exc:
            raise ImpactMetricsError("impact_metrics_layout_invalid") from exc
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o700
            ):
                raise ImpactMetricsError("impact_metrics_layout_invalid")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _write_unlocked(self, aggregate: Mapping[str, Any]) -> None:
        canonical = _validate_aggregate(copy.deepcopy(dict(aggregate)))
        try:
            payload = (
                json.dumps(
                    canonical,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ImpactMetricsError("impact_metrics_store_invalid") from exc
        if len(payload) > MAX_STORE_BYTES:
            raise ImpactMetricsError("impact_metrics_store_invalid")
        temporary = self.store_directory / (
            f".{STORE_FILE_NAME}.{secrets.token_hex(16)}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(temporary, flags, 0o600)
            os.fchmod(descriptor, 0o600)
            view = memoryview(payload)
            while view:
                try:
                    written = os.write(descriptor, view)
                except InterruptedError:
                    continue
                if written <= 0:
                    raise ImpactMetricsError("impact_metrics_store_invalid")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            try:
                existing = self.path.lstat()
            except FileNotFoundError:
                existing = None
            if existing is not None:
                _validate_private_regular_file(
                    self.path,
                    existing,
                    code="impact_metrics_store_invalid",
                )
            self._ensure_layout()
            os.replace(temporary, self.path)
            published = self.path.lstat()
            _validate_private_regular_file(
                self.path,
                published,
                code="impact_metrics_store_invalid",
            )
            self._fsync_store_directory()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def load(self) -> dict[str, Any]:
        with self._locked(exclusive=False):
            return self._read_unlocked()

    def project(
        self,
        *,
        input_price_per_million_tokens: float | None = None,
    ) -> dict[str, Any]:
        return project_impact_metrics(
            self.load(),
            input_price_per_million_tokens=input_price_per_million_tokens,
        )

    def record_dashboard_recall(
        self,
        *,
        succeeded: bool,
        latency_ms: float,
        result_count: int = 0,
        bridge_eligible: bool = False,
        connected_assist: bool = False,
        graph_assist: bool = False,
        response_bytes: int = 0,
        estimated_tokens: int | None = None,
        recorded_at: float | None = None,
    ) -> dict[str, Any]:
        """Record one content-free dashboard recall outcome.

        ``succeeded`` means a ready retrieval completed, not merely that an HTTP
        response arrived. ``connected_assist`` and ``graph_assist`` are one-per-
        recall evidence flags. ``response_bytes`` is the UTF-8 JSON response-body
        size; no prompt, namespace, memory identifier, excerpt, or result body is
        accepted or persisted by this interface.
        """

        if type(succeeded) is not bool:
            raise ImpactMetricsError("impact_metrics_outcome_invalid")
        latency = _bounded_number(
            latency_ms,
            maximum=float(MAX_LATENCY_MS),
            code="impact_metrics_outcome_invalid",
        )
        results = _bounded_integer(
            result_count,
            maximum=MAX_RESULT_COUNT,
            code="impact_metrics_outcome_invalid",
        )
        response_size = _bounded_integer(
            response_bytes,
            maximum=MAX_RESPONSE_BYTES,
            code="impact_metrics_outcome_invalid",
        )
        calculated_tokens = int(math.ceil(response_size / 4.0))
        if estimated_tokens is None:
            token_estimate = calculated_tokens
        else:
            token_estimate = _bounded_integer(
                estimated_tokens,
                maximum=MAX_RESPONSE_BYTES,
                code="impact_metrics_outcome_invalid",
            )
            if token_estimate != calculated_tokens:
                raise ImpactMetricsError("impact_metrics_outcome_invalid")
        for flag in (bridge_eligible, connected_assist, graph_assist):
            if type(flag) is not bool:
                raise ImpactMetricsError("impact_metrics_outcome_invalid")
        if not succeeded and (
            results > 0 or bridge_eligible or connected_assist or graph_assist
        ):
            raise ImpactMetricsError("impact_metrics_outcome_invalid")
        if connected_assist and (not bridge_eligible or results == 0):
            raise ImpactMetricsError("impact_metrics_outcome_invalid")
        if graph_assist and results == 0:
            raise ImpactMetricsError("impact_metrics_outcome_invalid")
        timestamp = _bounded_number(
            time.time() if recorded_at is None else recorded_at,
            maximum=float(MAX_COUNTER),
            code="impact_metrics_outcome_invalid",
        )

        with self._locked(exclusive=True):
            aggregate = self._read_unlocked()
            coverage = aggregate["coverage"]
            recall = aggregate["dashboard_recall"]
            recall["attempt_count"] = _checked_increment(
                recall["attempt_count"],
                1,
                code="impact_metrics_store_invalid",
            )
            terminal_field = "completed_count" if succeeded else "error_count"
            recall[terminal_field] = _checked_increment(
                recall[terminal_field],
                1,
                code="impact_metrics_store_invalid",
            )
            recall["response_bytes_total"] = _checked_increment(
                recall["response_bytes_total"],
                response_size,
                code="impact_metrics_store_invalid",
            )
            recall["estimated_tokens_total"] = _checked_increment(
                recall["estimated_tokens_total"],
                token_estimate,
                code="impact_metrics_store_invalid",
            )
            if succeeded:
                recall["result_count_total"] = _checked_increment(
                    recall["result_count_total"],
                    results,
                    code="impact_metrics_store_invalid",
                )
                for field, enabled in (
                    ("nonempty_result_count", results > 0),
                    ("bridge_eligible_count", bridge_eligible),
                    ("connected_assist_count", connected_assist),
                    ("graph_assist_count", graph_assist),
                ):
                    if enabled:
                        recall[field] = _checked_increment(
                            recall[field],
                            1,
                            code="impact_metrics_store_invalid",
                        )
            samples = list(recall["latency_samples_ms"])
            samples.append(latency)
            recall["latency_samples_ms"] = samples[-LATENCY_SAMPLE_LIMIT:]
            previous_first = coverage["first_recorded_at"]
            previous_updated = coverage["updated_at"]
            coverage["first_recorded_at"] = (
                timestamp
                if previous_first is None
                else min(float(previous_first), timestamp)
            )
            coverage["updated_at"] = (
                timestamp
                if previous_updated is None
                else max(float(previous_updated), timestamp)
            )
            canonical = _validate_aggregate(aggregate)
            self._write_unlocked(canonical)
            return copy.deepcopy(canonical)


def record_dashboard_recall(
    data_root: str | os.PathLike[str],
    **outcome: Any,
) -> dict[str, Any]:
    """Convenience wrapper requiring an explicit verified binding data root."""

    return ImpactMetricsStore(data_root).record_dashboard_recall(**outcome)


def read_impact_projection(
    data_root: str | os.PathLike[str],
    *,
    input_price_per_million_tokens: float | None = None,
) -> dict[str, Any]:
    """Read the private aggregate and return its public content-free projection."""

    return ImpactMetricsStore(data_root).project(
        input_price_per_million_tokens=input_price_per_million_tokens,
    )

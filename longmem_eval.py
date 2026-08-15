#!/usr/bin/env python3
"""Offline LongMemEval-V2-derived evaluation library for SYNAPSE-S2.

This module implements the LongMemEval-V2 *interaction contract* — sequential
trajectory Insert followed by compact text/image evidence Query — against a
disposable SYNAPSE-S2 store, with deterministic grading over a strictly
versioned corpus.  It is honest about its claim boundary:

* It never downloads anything, never opens the operator's live database, and
  never calls a reader or judge model.
* A passing run is **not** an official LongMemEval-V2 score.  The official
  benchmark uses the released corpus (100/500-trajectory tiers, 451
  questions), a Qwen reader, and a GPT judge; none of those run here.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from typing import Any, Callable, Iterable
from unittest.mock import patch

import memory_store as _memory_store_module
from bridge_governance import BridgeGovernance


CORPUS_SCHEMA = "synapse-s2.longmem-v2.corpus.v1"
FIXTURE_SCHEMA = "synapse-s2.longmem-v2-fixture.v1"
PREPARED_DATASET_SCHEMA = "synapse-s2.longmem-v2-prepared.v1"
REPORT_SCHEMA = "synapse-s2.longmem-v2-eval.v1"
REPORT_VERSION = 1
ADAPTER_PROTOCOL = "longmem-insert-query-v1"

ABILITIES = frozenset(
    {
        "static_state",
        "dynamic_state",
        "workflow",
        "environment_gotchas",
        "premise_awareness",
    }
)
HORIZONS = frozenset({"single-session", "cross-session", "long-horizon"})
TURN_ROLES = frozenset({"user", "assistant", "observation", "system"})
MEMORY_TYPES = frozenset({"text", "image"})
RECALL_SCOPES = frozenset({"local", "connected"})
FORBIDDEN_CONTEXTS = frozenset({"global"})

MEDIA_ID_PATTERN = re.compile(r"s2img_[0-9a-f]{32}")

OFFICIAL_CONTRACT = {
    "benchmark": "LongMemEval-V2",
    "abilities": sorted(ABILITIES),
    "trajectory_tiers": [100, 500],
    "question_count": 451,
    "reader": "official Qwen reader (never run by this harness)",
    "judge": "official GPT judge (never run by this harness)",
}

DERIVED_NOTICE = (
    "This synapse-derived offline fixture exercises the LongMemEval-V2 "
    "insert/query contract and ability categories on a small synthetic "
    "multimodal corpus; passing does not prove retrieval quality on live "
    "data and is not an official LongMemEval-V2 score."
)
PREPARED_NOTICE = (
    "This run consumed an operator-prepared local dataset through the "
    "LongMemEval-V2 adapter contract without the official reader or judge; "
    "the resulting evidence metrics are not an official LongMemEval-V2 score."
)
TOKEN_ESTIMATOR = "ceil(utf8_bytes / 4) heuristic; not a model tokenizer"

# Fixed hard gates.  These constants are the only accepted thresholds: the
# loaders reject any fixture or prepared dataset whose thresholds differ, and
# the acceptance verdict fails closed if handed anything else, so the gates
# cannot be removed or weakened through data.
SAFE_THRESHOLDS = {
    "minimum_graded_macro_recall_at_k": 0.75,
    "minimum_graded_macro_ndcg_at_k": 0.7,
    "minimum_graded_macro_mrr": 0.7,
    "minimum_per_question_graded_recall_at_k": 0.5,
    "maximum_namespace_leakage_count": 0,
    "maximum_scope_provenance_violation_count": 0,
    "maximum_false_premise_qualified_support_count": 0,
    "maximum_abstention_violation_count": 0,
    "maximum_current_over_retired_violation_count": 0,
    "maximum_temporal_evidence_violation_count": 0,
    "maximum_result_contract_violation_count": 0,
    "maximum_answer_decision_violation_count": 0,
    "maximum_deleted_evidence_count": 0,
    "maximum_duplicate_memory_id_count": 0,
    "maximum_duplicate_content_rate": 0.0,
    "maximum_provenance_violation_count": 0,
    "maximum_confidence_violation_count": 0,
    "maximum_tie_ordering_violation_count": 0,
    "maximum_logical_deletion_residue_count": 0,
    "maximum_surface_deletion_residue_count": 0,
    "maximum_media_residue_count": 0,
    "maximum_recovery_residue_count": 0,
    "maximum_replication_residue_count": 0,
    "minimum_image_evidence_hits": 1,
}

_IDENTITY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-/"
)

# Fixed resource bounds, enforced by the loaders before any backend is
# constructed, so an oversized or adversarial dataset can never drive backend
# construction or population.
RESOURCE_BOUNDS = {
    "max_dataset_file_bytes": 16_777_216,
    "max_backend_dimension": 8192,
    "max_backend_num_neurons": 1_048_576,
    # Exact float32 neural topology bytes for one backend:
    # 4 * (dimension*neurons + neurons*neurons + 3*neurons) must fit 384 MiB.
    "max_backend_topology_bytes": 402_653_184,
    "max_backend_default_top_k": 256,
    "max_backend_recall_count": 4096,
    "max_namespaces": 64,
    "max_trajectories": 2048,
    "max_turns": 65536,
    "max_questions": 4096,
    "max_turn_text_bytes": 16_384,
    "max_total_text_bytes": 8_388_608,
    "max_result_limit": 256,
    "max_candidate_limit": 4096,
}

ANSWER_DECISION_RULE = (
    "deterministic evidence rule: 'qualified' iff at least one supporting "
    "item is returned within result_limit (judged-relevant for graded "
    "questions; marker-bearing for false-premise/absent-topic probes), "
    "otherwise 'abstain'; no reader model runs, so this grades the evidence "
    "decision only and does not measure reader-level premise awareness"
)


class EvalError(RuntimeError):
    """The corpus, dataset, or measurement cannot establish its invariants."""


def backend_topology_bytes(backend: dict[str, Any]) -> int:
    """Exact float32 byte size of one backend's neural topology arrays."""

    dimension = int(backend["dimension"])
    neurons = int(backend["num_neurons"])
    return 4 * (dimension * neurons + neurons * neurons + 3 * neurons)


def require_backend_topology(backend: Any, *, owner: str) -> None:
    """Fail closed unless the exact topology byte size fits the fixed bound.

    This runs before any backend arrays are allocated, so an adversarial or
    oversized configuration can never drive the allocation itself.
    """

    if not isinstance(backend, dict):
        raise EvalError(f"{owner} must be an object")
    for field in ("dimension", "num_neurons"):
        if type(backend.get(field)) is not int or int(backend[field]) <= 0:
            raise EvalError(f"{owner} {field} must be a positive exact integer")
    if backend_topology_bytes(backend) > RESOURCE_BOUNDS["max_backend_topology_bytes"]:
        raise EvalError(
            f"{owner} neural topology exceeds the fixed 384 MiB byte bound"
        )


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize one value using the lane's stable JSON wire format."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvalError("value contains non-canonical JSON") from exc


def digest_value(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def bounded_identity(value: str | None, *, field: str) -> str | None:
    if value is None or not str(value).strip():
        return None
    clean = str(value).strip()
    if len(clean) > 160 or any(char not in _IDENTITY_CHARS for char in clean):
        raise EvalError(f"{field} must be a bounded public identifier")
    return clean


def estimate_tokens(byte_count: int) -> int:
    """Deterministic token estimate; documented heuristic, not a tokenizer."""

    return int(math.ceil(max(0, int(byte_count)) / 4))


def _dcg(grades: list[int]) -> float:
    return sum((2**grade - 1) / math.log2(index + 2) for index, grade in enumerate(grades))


def nearest_rank_percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return round(ordered[rank - 1], 6)


def size_summary(values: list[int]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "min": 0, "p50": 0, "p95": 0, "max": 0}
    ordered = sorted(int(value) for value in values)
    return {
        "count": len(ordered),
        "min": ordered[0],
        "p50": nearest_rank_percentile([float(value) for value in ordered], 0.5),
        "p95": nearest_rank_percentile([float(value) for value in ordered], 0.95),
        "max": ordered[-1],
    }


def _require_text(container: dict[str, Any], field: str, *, owner: str) -> str:
    value = container.get(field)
    if type(value) is not str or not value.strip():
        raise EvalError(f"{owner} field {field} must be a non-blank string")
    return value.strip()


def _finite_number(
    value: Any,
    *,
    field: str,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    """Return one exact finite JSON number, excluding booleans.

    Downstream stores and governance surfaces accept floats, so corpus
    validation must reject NaN/Infinity and out-of-range values before any
    backend or mutation object is constructed.
    """

    if type(value) not in (int, float):
        raise EvalError(f"{field} must be a finite number")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise EvalError(f"{field} must be a finite number")
    if minimum is not None and parsed < minimum:
        if maximum is None:
            raise EvalError(f"{field} must be at least {minimum:g}")
        raise EvalError(f"{field} must be between {minimum:g} and {maximum:g}")
    if maximum is not None and parsed > maximum:
        if minimum is None:
            raise EvalError(f"{field} must be at most {maximum:g}")
        raise EvalError(f"{field} must be between {minimum:g} and {maximum:g}")
    return parsed


def _visible_text(turn: dict[str, Any]) -> str:
    return " ".join(
        str(turn.get(field) or "") for field in ("tag", "label", "text")
    ).casefold()


def validate_corpus(corpus: Any) -> dict[str, Any]:
    """Structurally validate one corpus and return its evaluation index.

    The corpus is the normalized form shared by the synapse-derived fixture
    and the prepared-corpus operator dataset: trajectories of sequential
    turns, governed context links, temporal relationships, deletions, and
    graded questions across all five LongMemEval-V2 abilities.
    """

    if not isinstance(corpus, dict) or corpus.get("schema") != CORPUS_SCHEMA:
        raise EvalError("corpus schema is unsupported")
    trajectories = corpus.get("trajectories")
    questions = corpus.get("questions")
    if not isinstance(trajectories, list) or len(trajectories) < 2:
        raise EvalError("corpus requires at least two trajectories")
    if len(trajectories) > RESOURCE_BOUNDS["max_trajectories"]:
        raise EvalError("corpus trajectory count exceeds the fixed resource bound")
    if not isinstance(questions, list) or not questions:
        raise EvalError("corpus questions are required")
    if len(questions) > RESOURCE_BOUNDS["max_questions"]:
        raise EvalError("corpus question count exceeds the fixed resource bound")

    turns: dict[str, dict[str, Any]] = {}
    total_text_bytes = 0
    canonical_order: list[str] = []
    trajectory_ids: list[str] = []
    session_ids: set[str] = set()
    contexts: set[str] = set()
    last_by_context_tag: dict[tuple[str, str], str] = {}
    groups: dict[str, dict[str, list[str]]] = {
        "duplicate_group": defaultdict(list),
        "near_duplicate_group": defaultdict(list),
        "tie_group": defaultdict(list),
    }
    for trajectory in trajectories:
        if not isinstance(trajectory, dict):
            raise EvalError("corpus trajectory must be an object")
        trajectory_id = _require_text(trajectory, "trajectory_id", owner="trajectory")
        context_id = _require_text(trajectory, "context_id", owner="trajectory")
        if trajectory_id in trajectory_ids:
            raise EvalError("corpus trajectory_id values must be unique")
        if context_id in FORBIDDEN_CONTEXTS:
            raise EvalError("corpus must not populate the shared global context")
        trajectory_ids.append(trajectory_id)
        contexts.add(context_id)
        sessions = trajectory.get("sessions")
        if not isinstance(sessions, list) or not sessions:
            raise EvalError("corpus trajectory sessions are required")
        for session in sessions:
            if not isinstance(session, dict):
                raise EvalError("corpus session must be an object")
            session_id = _require_text(session, "session_id", owner="session")
            if session_id in session_ids:
                raise EvalError("corpus session_id values must be unique")
            session_ids.add(session_id)
            session_turns = session.get("turns")
            if not isinstance(session_turns, list) or not session_turns:
                raise EvalError("corpus session turns are required")
            for turn in session_turns:
                if not isinstance(turn, dict):
                    raise EvalError("corpus turn must be an object")
                turn_id = _require_text(turn, "turn_id", owner="turn")
                if turn_id in turns:
                    raise EvalError("corpus turn_id values must be unique")
                if len(turns) >= RESOURCE_BOUNDS["max_turns"]:
                    raise EvalError("corpus turn count exceeds the fixed resource bound")
                tag = _require_text(turn, "tag", owner="turn")
                _require_text(turn, "label", owner="turn")
                turn_text_bytes = len(
                    _require_text(turn, "text", owner="turn").encode("utf-8")
                )
                if turn_text_bytes > RESOURCE_BOUNDS["max_turn_text_bytes"]:
                    raise EvalError(
                        f"turn {turn_id} text exceeds the fixed per-turn byte bound"
                    )
                total_text_bytes += turn_text_bytes
                if total_text_bytes > RESOURCE_BOUNDS["max_total_text_bytes"]:
                    raise EvalError("corpus total text bytes exceed the fixed resource bound")
                role = _require_text(turn, "role", owner="turn")
                memory_type = _require_text(turn, "memory_type", owner="turn")
                if role not in TURN_ROLES:
                    raise EvalError(f"turn {turn_id} role is unsupported")
                if memory_type not in MEMORY_TYPES:
                    raise EvalError(f"turn {turn_id} memory_type is unsupported")
                categories = turn.get("categories")
                if (
                    not isinstance(categories, list)
                    or not categories
                    or any(type(item) is not str or not item.strip() for item in categories)
                ):
                    raise EvalError(f"turn {turn_id} categories are required")
                if memory_type == "image":
                    media_id = turn.get("media_id")
                    if type(media_id) is not str or MEDIA_ID_PATTERN.fullmatch(media_id) is None:
                        raise EvalError(f"image turn {turn_id} media_id is invalid")
                if turn.get("event_time") is not None:
                    _finite_number(
                        turn.get("event_time"),
                        field=f"turn {turn_id} event_time",
                        minimum=0.0,
                    )

                revision = 1
                supersedes = turn.get("supersedes_turn_ref")
                previous_id = last_by_context_tag.get((context_id, tag))
                if previous_id is not None:
                    if supersedes != previous_id:
                        raise EvalError(
                            f"turn {turn_id} reuses tag {tag} without superseding {previous_id}"
                        )
                    previous = turns[previous_id]
                    previous["superseded_by"] = turn_id
                    revision = previous["revision"] + 1
                elif supersedes is not None:
                    raise EvalError(f"turn {turn_id} supersedes an unknown state turn")
                last_by_context_tag[(context_id, tag)] = turn_id

                turns[turn_id] = {
                    "turn": turn,
                    "trajectory_id": trajectory_id,
                    "session_id": session_id,
                    "context_id": context_id,
                    "ordinal": len(canonical_order),
                    "revision": revision,
                    "superseded_by": None,
                }
                canonical_order.append(turn_id)
                for field, grouped in groups.items():
                    group = str(turn.get(field) or "").strip()
                    if group:
                        grouped[group].append(turn_id)
    if len(contexts) < 3:
        raise EvalError("corpus must span at least three namespaces")
    if len(contexts) > RESOURCE_BOUNDS["max_namespaces"]:
        raise EvalError("corpus namespace count exceeds the fixed resource bound")
    for field, grouped in groups.items():
        minimum = 3 if field == "tie_group" else 2
        if not any(len(members) >= minimum for members in grouped.values()):
            raise EvalError(f"corpus requires a multi-member {field}")

    context_links = corpus.get("context_links", [])
    if not isinstance(context_links, list) or not context_links:
        raise EvalError("corpus requires at least one governed context link")
    for link in context_links:
        if not isinstance(link, dict):
            raise EvalError("corpus context link must be an object")
        source = str(link.get("source_context_id") or "")
        target = str(link.get("target_context_id") or "")
        if source not in contexts or target not in contexts:
            raise EvalError("corpus context link references an unknown namespace")
        if source == target:
            raise EvalError("corpus context link namespaces must be distinct")
        if link.get("enabled") is not True:
            raise EvalError("corpus context links must be enabled approvals")
        for field in ("relation_type", "direction", "approved_by"):
            _require_text(link, field, owner="context link")
        if str(link["direction"]) not in {"directed", "bidirectional"}:
            raise EvalError(
                "corpus context link direction must be directed or bidirectional"
            )
        _finite_number(
            link.get("confidence"),
            field="corpus context link confidence",
            minimum=0.0,
            maximum=1.0,
        )

    deletions = corpus.get("deletions", [])
    if not isinstance(deletions, list) or not deletions:
        raise EvalError("corpus requires at least one deletion case")
    deleted_turn_ids: set[str] = set()
    deleted_image = False
    for deletion in deletions:
        if not isinstance(deletion, dict):
            raise EvalError("corpus deletion must be an object")
        turn_ref = _require_text(deletion, "turn_ref", owner="deletion")
        _require_text(deletion, "reason", owner="deletion")
        record = turns.get(turn_ref)
        if record is None or turn_ref in deleted_turn_ids:
            raise EvalError("corpus deletion references an unknown or repeated turn")
        if record["superseded_by"] is not None or record["turn"].get("supersedes_turn_ref"):
            raise EvalError("corpus deletions must target standalone state turns")
        deleted_turn_ids.add(turn_ref)
        if record["turn"]["memory_type"] == "image":
            deleted_image = True
    if not deleted_image:
        raise EvalError("corpus requires at least one deleted image turn")

    relationships = corpus.get("relationships", [])
    if not isinstance(relationships, list):
        raise EvalError("corpus relationships must be a list")
    for relationship in relationships:
        if not isinstance(relationship, dict):
            raise EvalError("corpus relationship must be an object")
        source_ref = str(relationship.get("source_turn_ref") or "")
        target_ref = str(relationship.get("target_turn_ref") or "")
        context_id = str(relationship.get("context_id") or "")
        _require_text(relationship, "relation_type", owner="relationship")
        if source_ref not in turns or target_ref not in turns:
            raise EvalError("corpus relationship references an unknown turn")
        if source_ref in deleted_turn_ids or target_ref in deleted_turn_ids:
            raise EvalError("corpus relationship references a deleted turn")
        if (
            turns[source_ref]["context_id"] != context_id
            or turns[target_ref]["context_id"] != context_id
        ):
            raise EvalError("corpus relationship must stay inside one namespace")
        _finite_number(
            relationship.get("weight"),
            field="corpus relationship weight",
            minimum=0.0,
            maximum=1.0,
        )

    all_visible = [_visible_text(record["turn"]) for record in turns.values()]
    live_visible = [
        _visible_text(record["turn"])
        for turn_id, record in turns.items()
        if turn_id not in deleted_turn_ids
    ]

    question_ids: set[str] = set()
    observed_abilities: set[str] = set()
    observed_horizons: set[str] = set()
    observed_scopes: set[str] = set()
    coverage = Counter()
    for question in questions:
        if not isinstance(question, dict):
            raise EvalError("corpus question must be an object")
        question_id = _require_text(question, "question_id", owner="question")
        if question_id in question_ids:
            raise EvalError("corpus question_id values must be unique")
        question_ids.add(question_id)
        prompt = _require_text(question, "prompt", owner="question")
        ability = _require_text(question, "ability", owner="question")
        horizon = _require_text(question, "horizon", owner="question")
        context_id = _require_text(question, "context_id", owner="question")
        scope = _require_text(question, "recall_scope", owner="question")
        if ability not in ABILITIES:
            raise EvalError(f"question {question_id} ability is unsupported")
        if horizon not in HORIZONS:
            raise EvalError(f"question {question_id} horizon is unsupported")
        if scope not in RECALL_SCOPES:
            raise EvalError(f"question {question_id} recall_scope is unsupported")
        if context_id not in contexts:
            raise EvalError(f"question {question_id} references an unknown context")
        allowed = question.get("allowed_contexts")
        if (
            not isinstance(allowed, list)
            or context_id not in allowed
            or any(str(value) not in contexts for value in allowed)
        ):
            raise EvalError(f"question {question_id} allowed_contexts are invalid")
        for field, bound in (
            ("result_limit", RESOURCE_BOUNDS["max_result_limit"]),
            ("candidate_limit", RESOURCE_BOUNDS["max_candidate_limit"]),
        ):
            if type(question.get(field)) is not int or int(question[field]) <= 0:
                raise EvalError(f"question {question_id} {field} must be a positive integer")
            if int(question[field]) > bound:
                raise EvalError(
                    f"question {question_id} {field} exceeds the fixed resource bound"
                )
        if type(question.get("include_graph_neighbors")) is not bool:
            raise EvalError(f"question {question_id} include_graph_neighbors must be boolean")
        judgments = question.get("judgments")
        if not isinstance(judgments, dict):
            raise EvalError(f"question {question_id} judgments must be an object")
        for turn_ref, grade in judgments.items():
            record = turns.get(str(turn_ref))
            if record is None:
                raise EvalError(f"question {question_id} judges an unknown turn")
            if str(turn_ref) in deleted_turn_ids:
                raise EvalError(f"question {question_id} judges a deleted turn")
            if record["superseded_by"] is not None:
                raise EvalError(f"question {question_id} judges a retired state revision")
            if type(grade) is not int or not 1 <= grade <= 3:
                raise EvalError(f"question {question_id} grades must be integers from 1 to 3")
            if record["context_id"] not in {str(value) for value in allowed}:
                raise EvalError(f"question {question_id} judges a turn outside allowed scope")

        markers = question.get("expected_markers")
        if markers is not None:
            if not isinstance(markers, dict):
                raise EvalError(f"question {question_id} expected_markers must be an object")
            current_ref = str(markers.get("current_turn_ref") or "")
            retired_ref = str(markers.get("retired_turn_ref") or "")
            required_current = _require_text(markers, "required_current", owner="markers")
            forbidden_retired = _require_text(markers, "forbidden_retired", owner="markers")
            current = turns.get(current_ref)
            retired = turns.get(retired_ref)
            if current is None or retired is None:
                raise EvalError(f"question {question_id} markers reference unknown turns")
            if retired["superseded_by"] != current_ref:
                raise EvalError(
                    f"question {question_id} marker turns are not a supersession pair"
                )
            current_text = str(current["turn"]["text"]).casefold()
            retired_text = str(retired["turn"]["text"]).casefold()
            if required_current.casefold() not in current_text:
                raise EvalError(f"question {question_id} current marker is absent")
            if required_current.casefold() in retired_text:
                raise EvalError(f"question {question_id} current marker is not distinctive")
            if forbidden_retired.casefold() not in retired_text:
                raise EvalError(f"question {question_id} retired marker is absent")
            if forbidden_retired.casefold() in current_text:
                raise EvalError(f"question {question_id} retired marker is not distinctive")
            if current_ref not in {str(key) for key in judgments}:
                raise EvalError(f"question {question_id} must judge its current state turn")
            coverage["dynamic_markers"] += 1

        premise_marker = question.get("false_premise_marker")
        if premise_marker is not None:
            marker = str(premise_marker).strip().casefold()
            if not marker or marker not in prompt.casefold():
                raise EvalError(f"question {question_id} premise marker must be in the prompt")
            if any(marker in visible for visible in all_visible):
                raise EvalError(f"question {question_id} premise marker is not absent")
            coverage["premise"] += 1

        if question.get("expects_abstention"):
            marker = str(question.get("absent_marker") or "").strip().casefold()
            if not marker or marker not in prompt.casefold():
                raise EvalError(f"question {question_id} abstention marker must be in the prompt")
            if any(marker in visible for visible in all_visible):
                raise EvalError(f"question {question_id} abstention marker is not absent")
            coverage["abstention"] += 1

        temporal = question.get("temporal_expectation")
        if temporal is not None:
            if not isinstance(temporal, dict):
                raise EvalError(f"question {question_id} temporal_expectation is invalid")
            before_ref = str(temporal.get("before_turn_ref") or "")
            after_ref = str(temporal.get("after_turn_ref") or "")
            relation = str(temporal.get("relation_type") or "")
            matched = any(
                str(rel.get("source_turn_ref")) == before_ref
                and str(rel.get("target_turn_ref")) == after_ref
                and str(rel.get("relation_type")) == relation
                for rel in relationships
            )
            if not matched:
                raise EvalError(
                    f"question {question_id} temporal expectation lacks a corpus relationship"
                )
            before_time = turns[before_ref]["turn"].get("event_time")
            after_time = turns[after_ref]["turn"].get("event_time")
            if (
                not isinstance(before_time, (int, float))
                or not isinstance(after_time, (int, float))
                or not float(before_time) < float(after_time)
            ):
                raise EvalError(f"question {question_id} temporal event times are inconsistent")
            judged = {str(key) for key in judgments}
            if before_ref not in judged or after_ref not in judged:
                raise EvalError(f"question {question_id} must judge both temporal turns")
            coverage["temporal"] += 1

        image_ref = question.get("expected_image_turn_ref")
        if image_ref is not None:
            record = turns.get(str(image_ref))
            if (
                record is None
                or record["turn"]["memory_type"] != "image"
                or str(image_ref) in deleted_turn_ids
            ):
                raise EvalError(f"question {question_id} expected image turn is invalid")
            if str(image_ref) not in {str(key) for key in judgments}:
                raise EvalError(f"question {question_id} must judge its expected image turn")
            coverage["image"] += 1

        probe = question.get("deleted_probe")
        if probe is not None:
            if not isinstance(probe, dict):
                raise EvalError(f"question {question_id} deleted_probe is invalid")
            turn_ref = str(probe.get("turn_ref") or "")
            marker = str(probe.get("marker") or "").strip().casefold()
            if turn_ref not in deleted_turn_ids or not marker:
                raise EvalError(f"question {question_id} deleted_probe must target a deletion")
            if marker not in _visible_text(turns[turn_ref]["turn"]):
                raise EvalError(f"question {question_id} deleted_probe marker is absent")
            if any(marker in visible for visible in live_visible):
                raise EvalError(
                    f"question {question_id} deleted_probe marker survives in live turns"
                )
            coverage["deleted_probe"] += 1

        observed_abilities.add(ability)
        observed_horizons.add(horizon)
        observed_scopes.add(scope)

    if observed_abilities != ABILITIES:
        raise EvalError("corpus questions must cover every LongMemEval-V2 ability")
    if observed_horizons != HORIZONS:
        raise EvalError("corpus questions must cover every horizon")
    if observed_scopes != RECALL_SCOPES:
        raise EvalError("corpus questions must exercise local and connected recall")
    for required in ("dynamic_markers", "premise", "abstention", "temporal", "image", "deleted_probe"):
        if coverage[required] < 1:
            raise EvalError(f"corpus questions must include a {required} case")
    tie_groups = groups["tie_group"]
    tie_judged = any(
        sum(1 for turn_ref in question.get("judgments", {}) if str(turn_ref) in members) >= 2
        for question in questions
        for members in tie_groups.values()
    )
    if not tie_judged:
        raise EvalError("corpus questions must judge at least two members of a tie group")

    return {
        "turns": turns,
        "canonical_order": canonical_order,
        "trajectory_ids": trajectory_ids,
        "contexts": contexts,
        "deleted_turn_ids": deleted_turn_ids,
        "groups": {field: dict(grouped) for field, grouped in groups.items()},
        "context_links": context_links,
        "relationships": relationships,
        "deletions": deletions,
        "questions": questions,
    }


def _validate_common_payload(payload: Any, *, schema: str, owner: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise EvalError(f"{owner} must be a JSON object")
    if payload.get("schema") != schema or payload.get("version") != 1:
        raise EvalError(f"{owner} schema or version is unsupported")
    backend = payload.get("backend")
    if not isinstance(backend, dict) or backend.get("embedding_provider") != "semantic-hash":
        raise EvalError(f"{owner} must use the offline semantic-hash provider")
    for field, bound in (
        ("dimension", RESOURCE_BOUNDS["max_backend_dimension"]),
        ("num_neurons", RESOURCE_BOUNDS["max_backend_num_neurons"]),
        ("default_top_k", RESOURCE_BOUNDS["max_backend_default_top_k"]),
        ("recall_count", RESOURCE_BOUNDS["max_backend_recall_count"]),
    ):
        if type(backend.get(field)) is not int or int(backend[field]) <= 0:
            raise EvalError(f"{owner} backend {field} must be a positive exact integer")
        if int(backend[field]) > bound:
            raise EvalError(f"{owner} backend {field} exceeds the fixed resource bound")
    require_backend_topology(backend, owner=f"{owner} backend")
    _finite_number(
        payload.get("fixed_epoch"),
        field=f"{owner} fixed_epoch",
        minimum=0.0,
    )
    if type(payload.get("random_seed")) is not int:
        raise EvalError(f"{owner} random_seed must be an exact integer")
    if payload.get("thresholds") != SAFE_THRESHOLDS:
        raise EvalError(f"{owner} acceptance thresholds are missing or weakened")
    validate_corpus(payload.get("corpus"))
    return payload


def validate_fixture(payload: Any) -> dict[str, Any]:
    """Validate the version-controlled synapse-derived fixture."""

    return _validate_common_payload(
        payload, schema=FIXTURE_SCHEMA, owner="longmem fixture"
    )


def validate_prepared_dataset(payload: Any) -> dict[str, Any]:
    """Validate an operator-prepared local dataset for prepared-corpus mode.

    The preparation block must be honest: this harness cannot verify official
    reader/judge parity, so any dataset claiming it is rejected outright.
    """

    payload = _validate_common_payload(
        payload, schema=PREPARED_DATASET_SCHEMA, owner="prepared dataset"
    )
    if bounded_identity(payload.get("dataset_label"), field="dataset_label") is None:
        raise EvalError("prepared dataset requires a bounded dataset_label")
    if bounded_identity(payload.get("dataset_version"), field="dataset_version") is None:
        raise EvalError("prepared dataset requires a bounded dataset_version")
    preparation = payload.get("preparation")
    if not isinstance(preparation, dict):
        raise EvalError("prepared dataset preparation provenance is required")
    for field in ("prepared_by", "source_note"):
        if type(preparation.get(field)) is not str or not preparation[field].strip():
            raise EvalError(f"prepared dataset preparation {field} is required")
    if preparation.get("official_reader_parity") not in (None, False):
        raise EvalError(
            "prepared dataset must not claim official reader/judge parity; "
            "this harness cannot verify that claim"
        )
    return payload


class LongMemInsertQueryAdapter:
    """Baseline Insert/Query adapter over one disposable SYNAPSE-S2 backend.

    The class defines the duck-typed protocol an ablation adapter (for
    example a future Memora Shadow build) must satisfy; the measurement
    runner accepts any object with these methods via its adapter factory
    seam, so comparisons never require importing an unmerged branch here.
    """

    label = "synapse-durable-store-baseline"
    protocol = ADAPTER_PROTOCOL

    def __init__(self, backend: Any) -> None:
        self.backend = backend
        self._governance: BridgeGovernance | None = None

    def _spike_indices(self, text: str) -> list[int]:
        spikes = self.backend.encode_to_spikes_top_k(self.backend.embed_text(text))
        values = spikes.tolist() if hasattr(spikes, "tolist") else list(spikes)
        return [index for index, value in enumerate(values) if float(value) > 0.0]

    def insert_turn(
        self,
        *,
        tag: str,
        context_id: str,
        source_text: str,
        embedding_text: str,
        metadata: dict[str, Any],
        timestamp: float,
    ) -> str:
        with patch.object(_memory_store_module.time, "time", return_value=timestamp):
            entry = self.backend.memory_store.upsert_entry(
                tag=tag,
                context_id=context_id,
                source_text=source_text,
                metadata=metadata,
                embedding_dimensions=int(self.backend.dimension),
                spike_indices=self._spike_indices(embedding_text),
                neuron_indices=[],
                registered_at=timestamp,
            )
        return str(entry["memory_id"])

    def approve_context_link(
        self,
        link: dict[str, Any],
        *,
        request_id: str,
        timestamp: float,
    ) -> None:
        if self._governance is None:
            self._governance = BridgeGovernance(
                self.backend.memory_store,
                require_distinct_reviewer=False,
                allow_compatibility_approval=True,
                allow_test_time=True,
            )
        self._governance.approve_namespace_link_compat(
            source_context_id=str(link["source_context_id"]),
            target_context_id=str(link["target_context_id"]),
            relation_type=str(link["relation_type"]),
            direction=str(link["direction"]),
            weight=float(link["confidence"]),
            evidence={"method": "longmem-v2-offline-population"},
            approved_by=str(link["approved_by"]),
            reason="Fixed offline LongMemEval-V2 lane approval.",
            governance_request_id=request_id,
            confirm=True,
            now=timestamp,
        )

    def add_relationship(
        self,
        *,
        context_id: str,
        source_memory_id: str,
        target_memory_id: str,
        relation_type: str,
        weight: float,
        timestamp: float,
    ) -> dict[str, Any]:
        with patch.object(_memory_store_module.time, "time", return_value=timestamp):
            return self.backend.memory_store.upsert_relationship(
                context_id=context_id,
                source_memory_id=source_memory_id,
                target_memory_id=target_memory_id,
                relation_type=relation_type,
                weight=weight,
                evidence={"method": "longmem-v2-offline-population"},
            )

    def delete_memory(
        self,
        *,
        context_id: str,
        memory_id: str,
        reason: str,
        timestamp: float,
    ) -> bool:
        with patch.object(_memory_store_module.time, "time", return_value=timestamp):
            outcome = self.backend.prune_memory(
                context_id=context_id,
                target_type="memory",
                memory_id=memory_id,
                reason=reason,
                source_surface="longmem-v2-fixture",
                publish_audit=False,
                confirm=True,
            )
        return bool(outcome.get("result", {}).get("deleted"))

    def get_entry(self, memory_id: str) -> dict[str, Any] | None:
        return self.backend.memory_store.get_entry(memory_id)

    def query(
        self,
        *,
        prompt: str,
        context_id: str,
        recall_scope: str,
        result_limit: int,
        candidate_limit: int,
        include_graph_neighbors: bool,
    ) -> dict[str, Any]:
        return self.backend.retrieve_text_v2(
            prompt,
            context_id=context_id,
            recall_scope=recall_scope,
            result_limit=result_limit,
            candidate_limit=candidate_limit,
            include_graph_neighbors=include_graph_neighbors,
        )


def populate_corpus(
    adapter: Any,
    corpus: dict[str, Any],
    *,
    fixed_epoch: float,
    trajectory_order: Iterable[str] | None = None,
    image_capturer: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    source_label: str = "longmem-v2-offline-corpus",
    provider_label: str = "semantic-hash",
) -> dict[str, Any]:
    """Insert trajectories sequentially, then apply links/relationships/deletions.

    Timestamps come from each turn's canonical corpus ordinal (or its
    fixed_time_group), never from insertion order, so a seeded shuffle of
    trajectory order must reproduce an identical store.
    """

    index = validate_corpus(corpus)
    fixed_epoch = _finite_number(
        fixed_epoch,
        field="population fixed_epoch",
        minimum=0.0,
    )
    turns = index["turns"]
    ordered_trajectories = list(
        index["trajectory_ids"] if trajectory_order is None else trajectory_order
    )
    if sorted(ordered_trajectories) != sorted(index["trajectory_ids"]):
        raise EvalError("trajectory_order must contain every trajectory exactly once")
    trajectory_by_id = {
        str(item["trajectory_id"]): item for item in corpus["trajectories"]
    }
    tie_time_groups = sorted(
        {
            str(record["turn"].get("fixed_time_group"))
            for record in turns.values()
            if str(record["turn"].get("fixed_time_group") or "").strip()
        }
    )
    group_time = {name: fixed_epoch + 5_000.0 + index_ for index_, name in enumerate(tie_time_groups)}

    memory_ids: dict[str, str] = {}
    media_records: dict[str, dict[str, Any]] = {}
    insertion_order: list[str] = []
    for trajectory_id in ordered_trajectories:
        trajectory = trajectory_by_id[trajectory_id]
        context_id = str(trajectory["context_id"])
        for session in trajectory["sessions"]:
            for turn in session["turns"]:
                turn_id = str(turn["turn_id"])
                record = turns[turn_id]
                fixed_group = str(turn.get("fixed_time_group") or "").strip()
                timestamp = (
                    group_time[fixed_group]
                    if fixed_group
                    else fixed_epoch + float(record["ordinal"])
                )
                metadata: dict[str, Any] = {
                    "display_label": str(turn["label"]),
                    "display_summary": str(turn["text"]),
                    "display_excerpt": str(turn["text"]),
                    "facets": [str(value) for value in turn["categories"]],
                    "memory_type": str(turn["memory_type"]),
                    "source": source_label,
                    "embedding_provider": provider_label,
                    "benchmark_turn_id": turn_id,
                    "trajectory_id": trajectory_id,
                    "session_id": str(record["session_id"]),
                    "role": str(turn["role"]),
                    "revision": int(record["revision"]),
                    "status": "retired" if record["superseded_by"] else "current",
                }
                if turn.get("supersedes_turn_ref"):
                    metadata["supersedes_turn_ref"] = str(turn["supersedes_turn_ref"])
                if isinstance(turn.get("event_time"), (int, float)):
                    metadata["event_time"] = float(turn["event_time"])
                if turn["memory_type"] == "image":
                    if image_capturer is None:
                        raise EvalError("corpus contains images but no image_capturer was given")
                    captured = image_capturer(turn)
                    if captured.get("raw_original_stored") is not False:
                        raise EvalError("image capture must never store the raw original")
                    if str(captured.get("media_id")) != str(turn["media_id"]):
                        raise EvalError("image capture returned a mismatched media_id")
                    metadata["media_id"] = str(turn["media_id"])
                    metadata["image_artifact"] = dict(captured.get("artifact") or {})
                    metadata["description_source"] = "fixture-authored"
                    media_records[turn_id] = {
                        "media_id": str(turn["media_id"]),
                        "raw_original_stored": bool(captured.get("raw_original_stored")),
                    }
                memory_id = adapter.insert_turn(
                    tag=str(turn["tag"]),
                    context_id=context_id,
                    source_text=str(turn["text"]),
                    embedding_text=str(turn.get("embedding_prompt") or turn["text"]),
                    metadata=metadata,
                    timestamp=timestamp,
                )
                supersedes = str(turn.get("supersedes_turn_ref") or "")
                if supersedes:
                    previous = memory_ids.get(supersedes)
                    if previous is None or previous != memory_id:
                        raise EvalError(
                            "stable memory identity changed across revisions"
                        )
                memory_ids[turn_id] = memory_id
                insertion_order.append(turn_id)

    for link_index, link in enumerate(corpus.get("context_links", [])):
        adapter.approve_context_link(
            link,
            request_id=f"longmem-v2-link-{link_index:03d}",
            timestamp=fixed_epoch + 10_000.0 + link_index,
        )
    relationship_records: list[dict[str, Any]] = []
    for rel_index, relationship in enumerate(corpus.get("relationships", [])):
        record = adapter.add_relationship(
            context_id=str(relationship["context_id"]),
            source_memory_id=memory_ids[str(relationship["source_turn_ref"])],
            target_memory_id=memory_ids[str(relationship["target_turn_ref"])],
            relation_type=str(relationship["relation_type"]),
            weight=float(relationship["weight"]),
            timestamp=fixed_epoch + 20_000.0 + rel_index,
        )
        relationship_records.append(
            {
                "source_turn_ref": str(relationship["source_turn_ref"]),
                "target_turn_ref": str(relationship["target_turn_ref"]),
                "relation_type": str(relationship["relation_type"]),
                "relationship_id": str(record.get("relationship_id") or ""),
                "source_memory_id": str(record.get("source_memory_id") or ""),
                "target_memory_id": str(record.get("target_memory_id") or ""),
            }
        )

    deleted: list[dict[str, Any]] = []
    ordered_deletions = sorted(
        corpus.get("deletions", []), key=lambda item: str(item.get("turn_ref"))
    )
    for del_index, deletion in enumerate(ordered_deletions):
        turn_ref = str(deletion["turn_ref"])
        record = turns[turn_ref]
        deleted_flag = adapter.delete_memory(
            context_id=str(record["context_id"]),
            memory_id=memory_ids[turn_ref],
            reason=str(deletion["reason"]),
            timestamp=fixed_epoch + 30_000.0 + del_index,
        )
        if not deleted_flag:
            raise EvalError(f"deletion of turn {turn_ref} did not report success")
        deleted.append(
            {
                "turn_id": turn_ref,
                "memory_id": memory_ids[turn_ref],
                "context_id": str(record["context_id"]),
                "media_id": media_records.get(turn_ref, {}).get("media_id"),
            }
        )

    live_media = [
        {"turn_id": turn_id, **media}
        for turn_id, media in sorted(media_records.items())
        if turn_id not in {item["turn_id"] for item in deleted}
    ]
    return {
        "memory_ids": memory_ids,
        "insertion_order": insertion_order,
        "trajectory_order": ordered_trajectories,
        "relationships": relationship_records,
        "deleted": deleted,
        "live_media": live_media,
    }


def query_call(adapter: Any, question: dict[str, Any]) -> dict[str, Any]:
    return adapter.query(
        prompt=str(question["prompt"]),
        context_id=str(question["context_id"]),
        recall_scope=str(question["recall_scope"]),
        result_limit=int(question["result_limit"]),
        candidate_limit=int(question["candidate_limit"]),
        include_graph_neighbors=bool(question["include_graph_neighbors"]),
    )


def _item_visible(item: dict[str, Any]) -> str:
    return " ".join(
        str(item.get(field) or "") for field in ("tag", "label", "summary", "excerpt")
    ).casefold()


def marker_hits(items: list[dict[str, Any]], marker: str) -> list[str]:
    target = marker.casefold()
    return [
        str(item.get("memory_id") or "")
        for item in items
        if target in _item_visible(item)
    ]


def _stable_context_link(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    keys = (
        "context_link_id",
        "source_context_id",
        "target_context_id",
        "relation_type",
        "direction",
        "confidence",
        "enabled",
        "approved_by",
    )
    return {key: value.get(key) for key in keys}


def _scope_authorized(item: dict[str, Any], question_context: str) -> bool:
    scope = item.get("scope_provenance", {})
    item_context = str(item.get("context_id") or "")
    if str(scope.get("origin_context_id") or "") != question_context:
        return False
    if str(scope.get("resolved_context_id") or "") != item_context:
        return False
    link = scope.get("context_link")
    if item_context == question_context:
        return link is None
    if not isinstance(link, dict) or link.get("enabled") is not True:
        return False
    source = str(link.get("source_context_id") or "")
    target = str(link.get("target_context_id") or "")
    direction = str(link.get("direction") or "")
    if direction == "directed":
        return source == question_context and target == item_context
    if direction == "bidirectional":
        return {source, target} == {question_context, item_context}
    return False


def evaluate_question(
    question: dict[str, Any],
    result: dict[str, Any],
    index: dict[str, Any],
    populate_record: dict[str, Any],
    adapter: Any,
    latency_ms: list[float],
    *,
    provider_label: str = "semantic-hash",
) -> dict[str, Any]:
    """Grade one query result deterministically against the corpus truth."""

    turns = index["turns"]
    memory_ids = populate_record["memory_ids"]
    deleted_memory_ids = {str(item["memory_id"]) for item in populate_record["deleted"]}
    turn_by_memory = {
        memory_id: turn_id
        for turn_id, memory_id in memory_ids.items()
        if turns[turn_id]["superseded_by"] is None
        and turn_id not in index["deleted_turn_ids"]
    }
    judgments = {str(key): int(value) for key, value in question.get("judgments", {}).items()}
    graded = bool(judgments)
    result_limit = int(question["result_limit"])
    items = list(result.get("items", []))
    retrieved_turn_ids = [turn_by_memory.get(str(item.get("memory_id"))) for item in items]
    retrieved_grades = [int(judgments.get(str(turn_id), 0)) for turn_id in retrieved_turn_ids]

    # Result-contract enforcement: the backend must return at most
    # result_limit items with unique, ordered, 1-based ranks.  Grading only
    # ever consumes items[:k] so an over-returning backend cannot inflate
    # recall/nDCG/MRR.
    result_contract_violations: list[dict[str, Any]] = []
    if len(items) > result_limit:
        result_contract_violations.append(
            {
                "reason": "returned-more-than-result-limit",
                "returned": len(items),
                "result_limit": result_limit,
            }
        )
    observed_ranks = [item.get("rank") for item in items]
    if any(type(rank) is not int for rank in observed_ranks) or observed_ranks != list(
        range(1, len(items) + 1)
    ):
        result_contract_violations.append(
            {
                "reason": "ranks-not-unique-ordered-one-based",
                "observed_ranks": [
                    rank if type(rank) is int else str(rank) for rank in observed_ranks
                ],
            }
        )
    graded_turn_ids = retrieved_turn_ids[:result_limit]
    graded_grades = retrieved_grades[:result_limit]

    metrics: dict[str, Any] = {}
    if graded:
        relevant = set(judgments)
        retrieved_relevant = {
            str(turn_id)
            for turn_id, grade in zip(graded_turn_ids, graded_grades)
            if turn_id and grade > 0
        }
        ideal = sorted(judgments.values(), reverse=True)[:result_limit]
        ideal_dcg = _dcg(ideal)
        metrics = {
            "recall_at_k": round(len(retrieved_relevant) / max(1, len(relevant)), 8),
            "ndcg_at_k": round(_dcg(graded_grades) / ideal_dcg if ideal_dcg else 0.0, 8),
            "mrr": round(
                next(
                    (
                        1.0 / rank
                        for rank, grade in enumerate(graded_grades, start=1)
                        if grade > 0
                    ),
                    0.0,
                ),
                8,
            ),
        }

    allowed_contexts = {str(value) for value in question["allowed_contexts"]}
    leakage = [
        {
            "rank": int(item.get("rank") or 0),
            "memory_id": str(item.get("memory_id") or ""),
            "context_id": str(item.get("context_id") or ""),
        }
        for item in items
        if str(item.get("context_id") or "") not in allowed_contexts
    ]

    memory_counts = Counter(str(item.get("memory_id") or "") for item in items)
    duplicate_memory_id_count = sum(max(0, count - 1) for count in memory_counts.values())
    content_counts = Counter(
        digest_value(
            {
                "context_id": item.get("context_id"),
                "label": " ".join(str(item.get("label") or "").casefold().split()),
                "summary": " ".join(str(item.get("summary") or "").casefold().split()),
                "excerpt": " ".join(str(item.get("excerpt") or "").casefold().split()),
            }
        )
        for item in items
    )
    duplicate_content_count = sum(max(0, count - 1) for count in content_counts.values())
    near_groups = Counter(
        str(turns[str(turn_id)]["turn"].get("near_duplicate_group") or "")
        for turn_id in retrieved_turn_ids
        if turn_id and turns[str(turn_id)]["turn"].get("near_duplicate_group")
    )
    near_duplicate_collisions = sum(max(0, count - 1) for count in near_groups.values())

    provenance_violations: list[dict[str, Any]] = []
    confidence_violations: list[dict[str, Any]] = []
    deleted_evidence: list[dict[str, Any]] = []
    compact_items: list[dict[str, Any]] = []
    for position, (item, turn_id, grade) in enumerate(
        zip(items, retrieved_turn_ids, retrieved_grades)
    ):
        memory_id = str(item.get("memory_id") or "")
        if memory_id in deleted_memory_ids:
            deleted_evidence.append({"rank": item.get("rank"), "memory_id": memory_id})
        source_provenance = item.get("source_provenance", {})
        entry = adapter.get_entry(memory_id)
        entry_metadata = (entry or {}).get("metadata") or {}
        provenance_reasons: list[str] = []
        if not str(source_provenance.get("source") or "").strip():
            provenance_reasons.append("missing-source-provenance")
        if entry is None:
            provenance_reasons.append("stored-entry-unavailable")
        elif str(entry_metadata.get("embedding_provider") or "") != provider_label:
            provenance_reasons.append("missing-provider-provenance")
        if not _scope_authorized(item, str(question["context_id"])):
            provenance_reasons.append("scope-provenance-does-not-authorize-result")
        for reason in provenance_reasons:
            provenance_violations.append(
                {"rank": item.get("rank"), "memory_id": memory_id, "reason": reason}
            )
        confidence = item.get("confidence", {})
        if confidence.get("calibrated") is not False or confidence.get("probability") is not None:
            confidence_violations.append(
                {
                    "rank": item.get("rank"),
                    "memory_id": memory_id,
                    "calibrated": confidence.get("calibrated"),
                    "probability": confidence.get("probability"),
                }
            )
        score = item.get("score")
        if (
            not isinstance(score, (int, float))
            or not math.isfinite(float(score))
            or not 0.0 <= float(score) <= 1.0
        ):
            provenance_violations.append(
                {"rank": item.get("rank"), "memory_id": memory_id, "reason": "invalid-score"}
            )
        scope = item.get("scope_provenance", {})
        compact_items.append(
            {
                "rank": int(item.get("rank") or 0),
                "memory_id": memory_id,
                "turn_id": turn_id,
                "context_id": str(item.get("context_id") or ""),
                "tag": str(item.get("tag") or ""),
                "label": str(item.get("label") or ""),
                "relevance_grade": grade,
                "within_result_limit": position < result_limit,
                "score": float(item.get("score") or 0.0),
                "memory_type": str(entry_metadata.get("memory_type") or ""),
                "media_id": entry_metadata.get("media_id"),
                "confidence": {
                    "calibrated": confidence.get("calibrated"),
                    "probability": confidence.get("probability"),
                    "signal": confidence.get("signal"),
                },
                "scope": {
                    "origin_context_id": scope.get("origin_context_id"),
                    "resolved_context_id": scope.get("resolved_context_id"),
                    "context_link": _stable_context_link(scope.get("context_link")),
                },
                "source": str(source_provenance.get("source") or ""),
            }
        )

    ranker_confidence = result.get("ranker", {}).get("confidence_semantics", {})
    if ranker_confidence.get("calibrated") is not False:
        confidence_violations.append(
            {
                "rank": None,
                "memory_id": None,
                "calibrated": ranker_confidence.get("calibrated"),
                "probability": ranker_confidence.get("probability"),
            }
        )

    current_over_retired_violations: list[dict[str, Any]] = []
    markers = question.get("expected_markers")
    marker_evidence: dict[str, Any] = {}
    if markers is not None:
        current_memory = memory_ids[str(markers["current_turn_ref"])]
        retired_memory = memory_ids[str(markers["retired_turn_ref"])]
        current_hits = marker_hits(items, str(markers["required_current"]))
        retired_hits = marker_hits(items, str(markers["forbidden_retired"]))
        stored = adapter.get_entry(current_memory)
        stored_metadata = (stored or {}).get("metadata") or {}
        expected_revision = int(
            index["turns"][str(markers["current_turn_ref"])]["revision"]
        )
        marker_evidence = {
            "stable_memory_id": current_memory == retired_memory,
            "current_marker_hits": current_hits,
            "retired_marker_hits": retired_hits,
            "stored_revision": stored_metadata.get("revision"),
            "stored_status": stored_metadata.get("status"),
        }
        if current_memory not in current_hits:
            current_over_retired_violations.append({"reason": "current-marker-not-returned"})
        if retired_hits:
            current_over_retired_violations.append({"reason": "retired-marker-still-visible"})
        if current_memory != retired_memory:
            current_over_retired_violations.append({"reason": "memory-identity-not-stable"})
        if stored_metadata.get("revision") != expected_revision or stored_metadata.get("status") != "current":
            current_over_retired_violations.append({"reason": "stored-revision-incorrect"})

    false_premise_support: list[str] = []
    if question.get("false_premise_marker") is not None:
        false_premise_support = marker_hits(items, str(question["false_premise_marker"]))

    abstention_violations: list[str] = []
    if question.get("expects_abstention"):
        abstention_violations = marker_hits(items, str(question["absent_marker"]))

    # Explicit deterministic answer decision.  The decision is derived only
    # from supporting evidence inside items[:k]: judged-relevant items for
    # graded questions, marker-bearing items for false-premise/absent-topic
    # probes.  Unrelated retrieval never counts as awareness support.
    answer_decision: dict[str, Any] | None = None
    answer_decision_violations: list[dict[str, Any]] = []
    decision_kind: str | None = None
    expected_decision: str | None = None
    support_ids: list[str] = []
    if question.get("false_premise_marker") is not None:
        decision_kind = "false-premise"
        expected_decision = "abstain"
        support_ids = marker_hits(
            items[:result_limit], str(question["false_premise_marker"])
        )
    elif question.get("expects_abstention"):
        decision_kind = "absent-topic"
        expected_decision = "abstain"
        support_ids = marker_hits(items[:result_limit], str(question["absent_marker"]))
    elif graded:
        decision_kind = "graded-evidence"
        expected_decision = "qualified"
        support_ids = [
            str(item.get("memory_id") or "")
            for item, grade in zip(items[:result_limit], graded_grades)
            if grade > 0
        ]
    if decision_kind is not None:
        observed_decision = "qualified" if support_ids else "abstain"
        answer_decision = {
            "kind": decision_kind,
            "decision": observed_decision,
            "expected_decision": expected_decision,
            "support_memory_ids": support_ids,
            "rule": ANSWER_DECISION_RULE,
        }
        if observed_decision != expected_decision:
            answer_decision_violations.append(
                {
                    "kind": decision_kind,
                    "expected_decision": expected_decision,
                    "observed_decision": observed_decision,
                    "support_memory_ids": support_ids,
                }
            )

    temporal_violations: list[dict[str, Any]] = []
    temporal_evidence: dict[str, Any] = {}
    temporal = question.get("temporal_expectation")
    if temporal is not None:
        before_ref = str(temporal["before_turn_ref"])
        after_ref = str(temporal["after_turn_ref"])
        relationship = next(
            (
                record
                for record in populate_record["relationships"]
                if record["source_turn_ref"] == before_ref
                and record["target_turn_ref"] == after_ref
                and record["relation_type"] == str(temporal["relation_type"])
            ),
            None,
        )
        returned = {str(item.get("memory_id") or "") for item in items}
        before_entry = adapter.get_entry(memory_ids[before_ref]) or {}
        after_entry = adapter.get_entry(memory_ids[after_ref]) or {}
        before_time = (before_entry.get("metadata") or {}).get("event_time")
        after_time = (after_entry.get("metadata") or {}).get("event_time")
        temporal_evidence = {
            "relationship_id": (relationship or {}).get("relationship_id"),
            "before_memory_id": memory_ids[before_ref],
            "after_memory_id": memory_ids[after_ref],
            "before_event_time": before_time,
            "after_event_time": after_time,
        }
        if relationship is None:
            temporal_violations.append({"reason": "temporal-relationship-missing"})
        if memory_ids[before_ref] not in returned or memory_ids[after_ref] not in returned:
            temporal_violations.append({"reason": "temporal-evidence-not-returned"})
        if (
            not isinstance(before_time, (int, float))
            or not isinstance(after_time, (int, float))
            or not float(before_time) < float(after_time)
        ):
            temporal_violations.append({"reason": "stored-event-times-not-ordered"})

    image_hit = None
    image_evidence: dict[str, Any] = {}
    image_ref = question.get("expected_image_turn_ref")
    if image_ref is not None:
        expected_memory = memory_ids[str(image_ref)]
        stored = adapter.get_entry(expected_memory)
        stored_metadata = (stored or {}).get("metadata") or {}
        live_media = {
            item["turn_id"]: item for item in populate_record["live_media"]
        }.get(str(image_ref), {})
        image_hit = bool(
            expected_memory in {str(item.get("memory_id") or "") for item in items}
            and stored_metadata.get("memory_type") == "image"
            and str(stored_metadata.get("media_id") or "")
            == str(index["turns"][str(image_ref)]["turn"]["media_id"])
            and live_media.get("raw_original_stored") is False
        )
        image_evidence = {
            "expected_memory_id": expected_memory,
            "media_id": stored_metadata.get("media_id"),
            "raw_original_stored": live_media.get("raw_original_stored"),
        }

    probe = question.get("deleted_probe")
    if probe is not None:
        probe_hits = marker_hits(items, str(probe["marker"]))
        if probe_hits:
            deleted_evidence.extend(
                {"rank": None, "memory_id": memory_id, "reason": "deleted-marker-visible"}
                for memory_id in probe_hits
            )

    tie_violations: list[dict[str, Any]] = []
    tie_members: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item, turn_id in zip(items, retrieved_turn_ids):
        if not turn_id:
            continue
        tie_group = str(turns[str(turn_id)]["turn"].get("tie_group") or "")
        if tie_group:
            tie_members[tie_group].append(item)
    for group, members in sorted(tie_members.items()):
        by_score: dict[float, list[str]] = defaultdict(list)
        for item in members:
            by_score[float(item.get("score") or 0.0)].append(str(item.get("memory_id") or ""))
        for score, ids in sorted(by_score.items()):
            if len(ids) > 1 and ids != sorted(ids):
                tie_violations.append({"tie_group": group, "score": score, "memory_ids": ids})

    result_bytes = len(canonical_json_bytes(result))
    evidence_bytes = len(canonical_json_bytes(items))
    return {
        "question_id": str(question["question_id"]),
        "ability": str(question["ability"]),
        "horizon": str(question["horizon"]),
        "prompt": str(question["prompt"]),
        "context_id": str(question["context_id"]),
        "recall_scope": str(question["recall_scope"]),
        "k": int(question["result_limit"]),
        "allowed_contexts": sorted(allowed_contexts),
        "graded": graded,
        "judgments": [
            {"turn_id": turn_id, "memory_id": memory_ids[turn_id], "grade": grade}
            for turn_id, grade in sorted(judgments.items())
        ],
        "retrieved": compact_items,
        "metrics": {
            **metrics,
            "namespace_leakage_count": len(leakage),
            "duplicate_memory_id_count": duplicate_memory_id_count,
            "duplicate_content_count": duplicate_content_count,
            "near_duplicate_collision_count": near_duplicate_collisions,
            "source_content_deduplications": int(
                result.get("work", {}).get("candidate_content_deduplications", 0) or 0
            ),
            "result_bytes": result_bytes,
            "evidence_bytes": evidence_bytes,
            "estimated_result_tokens": estimate_tokens(result_bytes),
            "estimated_evidence_tokens": estimate_tokens(evidence_bytes),
        },
        "scope_leakage": leakage,
        "result_contract_violations": result_contract_violations,
        "answer_decision": answer_decision,
        "answer_decision_violations": answer_decision_violations,
        "provenance_violations": provenance_violations,
        "confidence_violations": confidence_violations,
        "current_over_retired_violations": current_over_retired_violations,
        "marker_evidence": marker_evidence,
        "false_premise_qualified_support": false_premise_support,
        "abstention_violations": abstention_violations,
        "temporal_violations": temporal_violations,
        "temporal_evidence": temporal_evidence,
        "image_hit": image_hit,
        "image_evidence": image_evidence,
        "deleted_evidence": deleted_evidence,
        "tie_ordering_violations": tie_violations,
        "latency_ms": {
            "samples": len(latency_ms),
            "p50": nearest_rank_percentile(latency_ms, 0.5),
            "p95": nearest_rank_percentile(latency_ms, 0.95),
            "informational_only": True,
            "excluded_from_acceptance": True,
            "excluded_from_canonical_digest": True,
        },
        "bytes": {
            "result": result_bytes,
            "evidence": evidence_bytes,
            "serializer": "canonical-json-utf8",
            "token_estimator": TOKEN_ESTIMATOR,
        },
    }


def aggregate_questions(question_evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-question evidence into overall and per-slice metrics."""

    graded = [item for item in question_evidence if item["graded"]]
    if not graded:
        raise EvalError("at least one graded question is required")

    def _macro(items: list[dict[str, Any]], key: str) -> float:
        return round(sum(float(item["metrics"][key]) for item in items) / len(items), 8)

    totals = Counter()
    result_bytes: list[int] = []
    evidence_bytes: list[int] = []
    image_hits = 0
    image_questions = 0
    for evidence in question_evidence:
        metrics = evidence["metrics"]
        totals["leakage"] += int(metrics["namespace_leakage_count"])
        totals["duplicate_ids"] += int(metrics["duplicate_memory_id_count"])
        totals["duplicate_content"] += int(metrics["duplicate_content_count"])
        totals["near_duplicates"] += int(metrics["near_duplicate_collision_count"])
        totals["source_deduplications"] += int(metrics["source_content_deduplications"])
        totals["results"] += len(evidence["retrieved"])
        totals["provenance"] += len(evidence["provenance_violations"])
        totals["scope"] += sum(
            1
            for violation in evidence["provenance_violations"]
            if violation.get("reason") == "scope-provenance-does-not-authorize-result"
        )
        totals["confidence"] += len(evidence["confidence_violations"])
        totals["current_retired"] += len(evidence["current_over_retired_violations"])
        totals["false_premise"] += len(evidence["false_premise_qualified_support"])
        totals["abstention"] += len(evidence["abstention_violations"])
        totals["temporal"] += len(evidence["temporal_violations"])
        totals["result_contract"] += len(evidence["result_contract_violations"])
        totals["answer_decision"] += len(evidence["answer_decision_violations"])
        totals["deleted"] += len(evidence["deleted_evidence"])
        totals["tie"] += len(evidence["tie_ordering_violations"])
        result_bytes.append(int(metrics["result_bytes"]))
        evidence_bytes.append(int(metrics["evidence_bytes"]))
        if evidence["image_hit"] is not None:
            image_questions += 1
            image_hits += int(bool(evidence["image_hit"]))

    by_ability: dict[str, dict[str, Any]] = {}
    by_horizon: dict[str, dict[str, Any]] = {}
    for field, sliced in (("ability", by_ability), ("horizon", by_horizon)):
        for evidence in question_evidence:
            slot = sliced.setdefault(
                str(evidence[field]),
                {"questions": 0, "graded_questions": 0, "violation_count": 0, "_graded": []},
            )
            slot["questions"] += 1
            violation_count = (
                len(evidence["provenance_violations"])
                + len(evidence["confidence_violations"])
                + len(evidence["current_over_retired_violations"])
                + len(evidence["false_premise_qualified_support"])
                + len(evidence["abstention_violations"])
                + len(evidence["temporal_violations"])
                + len(evidence["result_contract_violations"])
                + len(evidence["answer_decision_violations"])
                + len(evidence["deleted_evidence"])
                + len(evidence["tie_ordering_violations"])
                + int(evidence["metrics"]["namespace_leakage_count"])
            )
            slot["violation_count"] += violation_count
            if evidence["graded"]:
                slot["graded_questions"] += 1
                slot["_graded"].append(evidence)
        for slot in sliced.values():
            graded_slice = slot.pop("_graded")
            if graded_slice:
                slot["macro_recall_at_k"] = _macro(graded_slice, "recall_at_k")
                slot["macro_ndcg_at_k"] = _macro(graded_slice, "ndcg_at_k")
                slot["macro_mrr"] = _macro(graded_slice, "mrr")
            else:
                slot["macro_recall_at_k"] = None
                slot["macro_ndcg_at_k"] = None
                slot["macro_mrr"] = None

    denominator = max(1, int(totals["results"]))
    return {
        "metrics": {
            "graded_questions": len(graded),
            "ungraded_questions": len(question_evidence) - len(graded),
            "graded_macro_recall_at_k": _macro(graded, "recall_at_k"),
            "graded_macro_ndcg_at_k": _macro(graded, "ndcg_at_k"),
            "graded_macro_mrr": _macro(graded, "mrr"),
            "namespace_leakage_count": int(totals["leakage"]),
            "namespace_leakage_rate": round(totals["leakage"] / denominator, 8),
            "duplicate_memory_id_count": int(totals["duplicate_ids"]),
            "duplicate_content_count": int(totals["duplicate_content"]),
            "duplicate_content_rate": round(totals["duplicate_content"] / denominator, 8),
            "near_duplicate_collision_count": int(totals["near_duplicates"]),
            "source_content_deduplications": int(totals["source_deduplications"]),
            "provenance_violation_count": int(totals["provenance"]),
            "scope_provenance_violation_count": int(totals["scope"]),
            "confidence_violation_count": int(totals["confidence"]),
            "current_over_retired_violation_count": int(totals["current_retired"]),
            "false_premise_qualified_support_count": int(totals["false_premise"]),
            "abstention_violation_count": int(totals["abstention"]),
            "temporal_evidence_violation_count": int(totals["temporal"]),
            "result_contract_violation_count": int(totals["result_contract"]),
            "answer_decision_violation_count": int(totals["answer_decision"]),
            "deleted_evidence_count": int(totals["deleted"]),
            "tie_ordering_violation_count": int(totals["tie"]),
            "image_questions": image_questions,
            "image_evidence_hits": image_hits,
            "retrieved_items": int(totals["results"]),
        },
        "per_question_minimums": {
            "graded_recall_at_k": min(float(item["metrics"]["recall_at_k"]) for item in graded),
            "graded_ndcg_at_k": min(float(item["metrics"]["ndcg_at_k"]) for item in graded),
            "graded_mrr": min(float(item["metrics"]["mrr"]) for item in graded),
        },
        "by_ability": {key: by_ability[key] for key in sorted(by_ability)},
        "by_horizon": {key: by_horizon[key] for key in sorted(by_horizon)},
        "result_sizes_bytes": {
            "result": size_summary(result_bytes),
            "evidence": size_summary(evidence_bytes),
        },
        "estimated_tokens": {
            "result_total": estimate_tokens(sum(result_bytes)),
            "evidence_total": estimate_tokens(sum(evidence_bytes)),
            "estimator": TOKEN_ESTIMATOR,
        },
    }


def canonical_result_projection(
    corpus: dict[str, Any],
    index: dict[str, Any],
    query_results: dict[str, dict[str, Any]],
    memory_ids: dict[str, str],
) -> dict[str, Any]:
    """Project query semantics for digest comparison, excluding volatile data."""

    turn_by_memory = {
        memory_id: turn_id
        for turn_id, memory_id in memory_ids.items()
        if index["turns"][turn_id]["superseded_by"] is None
        and turn_id not in index["deleted_turn_ids"]
    }
    projected: list[dict[str, Any]] = []
    for question in corpus["questions"]:
        question_id = str(question["question_id"])
        result = query_results[question_id]
        projected_items = []
        for item in result.get("items", []):
            breakdown = item.get("score_breakdown", {})
            scope = item.get("scope_provenance", {})
            confidence = item.get("confidence", {})
            projected_items.append(
                {
                    "rank": item.get("rank"),
                    "memory_id": item.get("memory_id"),
                    "turn_id": turn_by_memory.get(str(item.get("memory_id"))),
                    "context_id": item.get("context_id"),
                    "tag": item.get("tag"),
                    "label": item.get("label"),
                    "score": item.get("score"),
                    "signals": breakdown.get("signals"),
                    "contributions": breakdown.get("contributions"),
                    "confidence": {
                        "calibrated": confidence.get("calibrated"),
                        "probability": confidence.get("probability"),
                        "signal": confidence.get("signal"),
                    },
                    "scope": {
                        "origin_context_id": scope.get("origin_context_id"),
                        "resolved_context_id": scope.get("resolved_context_id"),
                        "context_link": _stable_context_link(scope.get("context_link")),
                    },
                }
            )
        projected.append(
            {
                "question_id": question_id,
                "query": {
                    "fingerprint_sha256": result.get("query", {}).get("fingerprint_sha256"),
                    "context_id": result.get("query", {}).get("context_id"),
                    "recall_scope": result.get("query", {}).get("recall_scope"),
                },
                "ranker": result.get("ranker"),
                "items": projected_items,
                "completeness": result.get("completeness"),
            }
        )
    return {
        "schema": REPORT_SCHEMA,
        "corpus_sha256": digest_value(corpus),
        "questions": projected,
    }


def population_summary(corpus: dict[str, Any], index: dict[str, Any]) -> dict[str, Any]:
    turns = index["turns"]
    context_counts = Counter(record["context_id"] for record in turns.values())
    ability_counts = Counter(str(question["ability"]) for question in corpus["questions"])
    horizon_counts = Counter(str(question["horizon"]) for question in corpus["questions"])
    session_count = sum(
        len(trajectory["sessions"]) for trajectory in corpus["trajectories"]
    )
    return {
        "trajectories": len(corpus["trajectories"]),
        "sessions": session_count,
        "turns": len(turns),
        "image_turns": sum(
            1 for record in turns.values() if record["turn"]["memory_type"] == "image"
        ),
        "questions": len(corpus["questions"]),
        "graded_judgments": sum(
            len(question.get("judgments", {})) for question in corpus["questions"]
        ),
        "namespaces": len(context_counts),
        "turns_by_namespace": dict(sorted(context_counts.items())),
        "questions_by_ability": dict(sorted(ability_counts.items())),
        "questions_by_horizon": dict(sorted(horizon_counts.items())),
        "approved_context_links": len(corpus.get("context_links", [])),
        "temporal_relationships": len(corpus.get("relationships", [])),
        "deletions": len(corpus.get("deletions", [])),
        "official_tier_match": (
            len(corpus["trajectories"]) in OFFICIAL_CONTRACT["trajectory_tiers"]
            and len(corpus["questions"]) == OFFICIAL_CONTRACT["question_count"]
        ),
    }

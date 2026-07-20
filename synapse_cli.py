from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

from redaction import reject_sensitive_identifier, safe_public_error
from token_contracts import (
    COMPACT_SOURCE_LIMITS,
    CONTRACT_SCHEMA,
    DEFAULT_RESPONSE_BYTES,
    ResponseContractError,
    compact_agent_event_limit,
    normalize_response_budget,
    normalize_response_mode,
    project_response,
    response_error,
    serialize_response,
)


_STARTUP_IMPORT_ERROR: Exception | None = None
_CONTRACT_COMMAND_SURFACES = {
    "agent-brief": "agent-hydration",
    "list-memory": "memory-list",
    "graph": "memory-graph",
    "cortex-state": "cortex-state",
}
try:
    from capture_daemon import CaptureInboxDaemon, new_capture_id, write_capture_drop
    import mlx_backend
    from mlx_backend import (
        DEFAULT_NUM_NEURONS,
        DEFAULT_RESOURCE_TARGET_MAX_MB,
        DEFAULT_RESOURCE_TARGET_MIN_MB,
    )
    from transcript_capture import TranscriptCaptureManager
    from memory_store import DurableMemoryStore
except Exception as startup_exc:  # pragma: no cover - dependency/environment specific
    _STARTUP_IMPORT_ERROR = startup_exc


class SafeArgumentParseError(ValueError):
    """An argparse failure whose public representation is safe to emit."""

    def __init__(self, *, prog: str, usage: str, message: str) -> None:
        super().__init__(message)
        self.prog = prog
        self.usage = usage


class SafeArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that never writes attacker-controlled values itself."""

    def error(self, message: str) -> None:
        raise SafeArgumentParseError(
            prog=self.prog,
            usage=self.format_usage(),
            message=safe_public_error(message, fallback="invalid command arguments"),
        )


def _json_default(value: Any) -> str:
    return str(value)


def _emit_line(line: str) -> None:
    try:
        print(line)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        finally:
            raise SystemExit(0)


def emit(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        if payload.get("schema") == CONTRACT_SCHEMA:
            _emit_line(serialize_response(payload))
        else:
            _emit_line(json.dumps(payload, sort_keys=True, default=_json_default))
        return

    for key, value in payload.items():
        if isinstance(value, (dict, list)):
            _emit_line(f"{key}: {json.dumps(value, sort_keys=True, default=_json_default)}")
        else:
            _emit_line(f"{key}: {value}")


def parse_vector(raw: str) -> list[float]:
    value = raw.strip()
    if not value:
        raise argparse.ArgumentTypeError("vector must not be empty")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = [part.strip() for part in value.split(",")]
    if not isinstance(parsed, list) or not parsed:
        raise argparse.ArgumentTypeError("vector must be a JSON list or comma-separated floats")
    try:
        return [float(item) for item in parsed]
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("vector values must be floats") from exc


def parse_metadata(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError("metadata must be a JSON object") from exc
    if not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError("metadata must be a JSON object")
    return parsed


def parse_string_list(raw: str | None, *, field_name: str) -> list[str]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"{field_name} must be a JSON list") from exc
    if not isinstance(parsed, list):
        raise argparse.ArgumentTypeError(f"{field_name} must be a JSON list")
    values: list[str] = []
    for item in parsed:
        text = " ".join(str(item or "").split())
        if text:
            values.append(text)
    return values


def _cli_response_options(
    args: argparse.Namespace,
    *,
    surface: str,
    default_mode: str = "compact",
) -> tuple[str, int] | tuple[str, None]:
    requested_mode = str(getattr(args, "response_mode", "") or "").strip()
    if requested_mode.casefold() == "legacy":
        return "legacy", None
    budget = _cli_response_budget(args, surface=surface)
    configured_mode = os.getenv("SYNAPSE_S2_DEFAULT_RESPONSE_MODE", default_mode)
    mode = normalize_response_mode(requested_mode, default=configured_mode)
    return mode, budget


def _cli_response_budget(args: argparse.Namespace, *, surface: str) -> int:
    requested_budget: Any = getattr(args, "max_response_bytes", "")
    if requested_budget in (None, ""):
        requested_budget = os.getenv("SYNAPSE_S2_MAX_RESPONSE_BYTES", "")
    budget = normalize_response_budget(
        requested_budget,
        default_bytes=DEFAULT_RESPONSE_BYTES[surface],
    )
    return budget


def _cli_error_response_budget(*, surface: str) -> int:
    configured_budget: Any = os.getenv("SYNAPSE_S2_MAX_RESPONSE_BYTES", "")
    try:
        return normalize_response_budget(
            configured_budget,
            default_bytes=DEFAULT_RESPONSE_BYTES[surface],
        )
    except ResponseContractError:
        return DEFAULT_RESPONSE_BYTES[surface]


def _add_response_contract_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--response-mode",
        default="",
        help="compact (default), full contract, or legacy unwrapped compatibility output",
    )
    parser.add_argument(
        "--max-response-bytes",
        default="",
        help="UTF-8 JSON byte ceiling from 4096 through 131072",
    )


def _normalize_cli_limit(value: Any, *, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ResponseContractError("limit must be an integer") from exc
    return min(max(parsed, 1), max(1, int(maximum)))


def _optional_public_output_path(value: Any, *, field: str) -> str | None:
    """Reject credential-shaped output paths before runtime initialization."""

    if value is None:
        return None
    raw = str(value)
    reject_sensitive_identifier(raw, field=field)
    return raw


def build_backend(args: argparse.Namespace) -> mlx_backend.SpikingAttentionBackend:
    return mlx_backend.SpikingAttentionBackend(
        dimension=args.dimension,
        num_neurons=args.neurons,
        default_top_k=args.top_k,
        recall_count=args.recall_count,
        quick_pruning_interval_seconds=args.quick_pruning_interval,
        idle_deep_sleep_seconds=args.idle_deep_sleep_seconds,
        compile_graph=not args.no_compile,
        state_path=args.state,
        memory_path=args.memory_db,
        embedding_provider_name=args.embedding_provider,
        require_native=args.require_native_backend,
    )


def dependency_status(module: str) -> dict[str, Any]:
    spec = importlib.util.find_spec(module)
    return {
        "importable": spec is not None,
        "origin": getattr(spec, "origin", None) if spec is not None else None,
    }


def command_status(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.status(context_id=args.context)


def command_enable(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.set_enabled(True, context_id=args.context)


def command_disable(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.set_enabled(False, context_id=args.context)


def command_remember_text(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    registration = backend.register_text_trace(
        tag=args.tag,
        context_id=args.context,
        text=args.text,
        metadata=parse_metadata(args.metadata),
    )
    registration["agent_deployment"] = _publish_cli_deployment(
        backend,
        context_id=args.context,
        event_type="remember-trace",
        summary=f"{registration['tag']} captured and published",
        payload={
            "tag": registration["tag"],
            "memory_id": registration["memory_id"],
            "source_text": args.text,
            "spike_count": registration["spike_count"],
            "neuron_count": registration["neuron_count"],
        },
    )
    return registration


def command_remember_vector(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    registration = backend.register_trace(
        tag=args.tag,
        embedding=parse_vector(args.vector),
        context_id=args.context,
        metadata=parse_metadata(args.metadata),
    )
    registration["agent_deployment"] = _publish_cli_deployment(
        backend,
        context_id=args.context,
        event_type="remember-trace",
        summary=f"{registration['tag']} captured and published",
        payload={
            "tag": registration["tag"],
            "memory_id": registration["memory_id"],
            "spike_count": registration["spike_count"],
            "neuron_count": registration["neuron_count"],
        },
    )
    return registration


def command_query_text(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    embedding = backend.embed_text_payload(args.text)
    return {
        "context_id": mlx_backend.sanitize_context_id(args.context),
        "recall_scope": args.recall_scope,
        "embedding_provider": embedding["provenance"],
        "result": backend.query_text(
            args.text,
            context_id=args.context,
            recall_scope=args.recall_scope,
        ),
    }


def command_query_vector(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return {
        "context_id": mlx_backend.sanitize_context_id(args.context),
        "recall_scope": args.recall_scope,
        "result": backend.query(
            parse_vector(args.vector),
            context_id=args.context,
            recall_scope=args.recall_scope,
        ),
    }


def _text_from_args(args: argparse.Namespace) -> str:
    if getattr(args, "text_file", None):
        return Path(args.text_file).expanduser().read_text(encoding="utf-8")
    return str(getattr(args, "text", "") or "")


def command_ingest_text(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    text = _text_from_args(args).strip()
    if not text:
        raise ValueError("--text or --text-file must provide content")
    ingestion = backend.ingest_text_events(
        text=text,
        context_id=args.context,
        source_tag=args.tag,
        surprise_threshold=args.surprise_threshold,
        min_segment_sentences=args.min_segment_sentences,
        metadata=parse_metadata(args.metadata),
    )
    ingestion["agent_deployment"] = _publish_cli_deployment(
        backend,
        context_id=args.context,
        event_type="ingest-events",
        summary=(
            f"{ingestion['source_tag']} published "
            f"{ingestion['event_count']} event traces"
        ),
        payload={
            "source_tag": ingestion["source_tag"],
            "sequence_id": ingestion["sequence_id"],
            "source_text": text,
            "event_count": ingestion["event_count"],
            "relationship_count": ingestion["relationship_count"],
            "events": ingestion["events"],
            "relationships": ingestion["relationships"],
        },
    )
    return ingestion


def command_capture_session(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    text = _text_from_args(args).strip()
    if not text:
        raise ValueError("--text or --text-file must provide content")
    return backend.capture_conversation(
        text=text,
        context_id=args.context,
        source_tag=args.tag,
        speaker=args.speaker,
        surprise_threshold=args.surprise_threshold,
        min_segment_sentences=args.min_segment_sentences,
        metadata=parse_metadata(args.metadata),
        capture_id=args.capture_id or None,
    )


def command_prune_memory(args: argparse.Namespace) -> dict[str, Any]:
    if not args.confirm:
        raise ValueError("--confirm is required before pruning memory graph data")
    backend = build_backend(args)
    return backend.prune_memory(
        context_id=args.context,
        target_type=args.target_type,
        memory_id=args.memory_id,
        tag=args.tag,
        relationship_id=args.relationship_id,
        event_id=args.event_id,
        reason=args.reason,
        source_surface="cli",
    )


def command_capture_inbox_drop(args: argparse.Namespace) -> dict[str, Any]:
    text = _text_from_args(args).strip()
    if not text:
        raise ValueError("--text or --text-file must provide content")
    capture_id = args.capture_id or new_capture_id()
    drop_path = write_capture_drop(
        root=args.capture_root,
        context_id=args.context,
        source_tag=args.tag,
        speaker=args.speaker,
        text=text,
        metadata=parse_metadata(args.metadata),
        capture_id=capture_id,
    )
    return {
        "action": "capture-inbox-drop",
        "drop_path": str(drop_path),
        "context_id": mlx_backend.sanitize_context_id(args.context),
        "source_tag": mlx_backend.sanitize_tag(args.tag).replace(" ", "-"),
        "speaker": mlx_backend.sanitize_agent_id(args.speaker),
        "capture_id": capture_id,
        "capture_protocol": "capture.v2",
    }


def _capture_daemon_from_args(
    args: argparse.Namespace,
    *,
    require_backend: bool = True,
) -> CaptureInboxDaemon:
    return CaptureInboxDaemon(
        root=args.capture_root,
        backend=build_backend(args) if require_backend else None,
    )


def command_capture_inbox_status(args: argparse.Namespace) -> dict[str, Any]:
    return _capture_daemon_from_args(args, require_backend=False).status()


def command_capture_inbox_process(args: argparse.Namespace) -> dict[str, Any]:
    if args.confirm is not True:
        raise ValueError("--confirm is required to process capture inbox files")
    return _capture_daemon_from_args(args).process_once(max_files=args.max_files)


def command_capture_error_preflight(args: argparse.Namespace) -> dict[str, Any]:
    return _capture_daemon_from_args(
        args,
        require_backend=False,
    ).error_resolution_preflight(
        reason=args.reason,
        include_historical=bool(args.include_historical),
    )


def command_capture_error_resolve(args: argparse.Namespace) -> dict[str, Any]:
    return _capture_daemon_from_args(
        args,
        require_backend=False,
    ).resolve_error_artifacts(
        preflight_token=args.preflight_token,
        reason=args.reason,
        include_historical=bool(args.include_historical),
        confirm=bool(args.confirm),
    )


def _transcript_manager_from_args(args: argparse.Namespace) -> TranscriptCaptureManager:
    return TranscriptCaptureManager(root=args.capture_root, backend=build_backend(args))


def command_transcript_source_add(args: argparse.Namespace) -> dict[str, Any]:
    return _transcript_manager_from_args(args).register_file_source(
        source_id=args.source_id,
        path=args.path,
        context_id=args.context,
        source_tag=args.tag,
        speaker=args.speaker,
        metadata=parse_metadata(args.metadata),
        confirmed=bool(args.confirm),
        start_at_end=not bool(args.start_at_beginning),
        enabled=not bool(args.disabled),
    )


def command_transcript_source_list(args: argparse.Namespace) -> dict[str, Any]:
    return _transcript_manager_from_args(args).list_sources()


def command_transcript_source_poll(args: argparse.Namespace) -> dict[str, Any]:
    return _transcript_manager_from_args(args).poll_sources(
        source_id=args.source_id,
        max_bytes=args.max_bytes,
    )


def command_capture_clipboard(args: argparse.Namespace) -> dict[str, Any]:
    text = _text_from_args(args)
    return _transcript_manager_from_args(args).capture_clipboard_once(
        text=text if text.strip() else None,
        context_id=args.context,
        source_tag=args.tag,
        speaker=args.speaker,
        metadata=parse_metadata(args.metadata),
        capture_id=args.capture_id or None,
    )


def command_app_list(args: argparse.Namespace) -> dict[str, Any]:
    return _transcript_manager_from_args(args).detect_running_apps()


def command_app_connect(args: argparse.Namespace) -> dict[str, Any]:
    return _transcript_manager_from_args(args).connect_running_app(
        app_name=args.app_name,
        bundle_id=args.bundle_id,
        pid=args.pid,
        context_id=args.context,
        source_tag=args.tag,
        speaker=args.speaker,
        metadata=parse_metadata(args.metadata),
        confirmed=bool(args.confirm),
        allow_manual=bool(args.allow_manual),
    )


def command_app_connections(args: argparse.Namespace) -> dict[str, Any]:
    return _transcript_manager_from_args(args).list_app_connections()


def command_app_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    return _transcript_manager_from_args(args).capture_app_snapshot(
        connection_id=args.connection_id,
        confirmed=bool(args.confirm),
        metadata=parse_metadata(args.metadata),
        capture_id=args.capture_id or None,
    )


def command_app_snapshot_preview(args: argparse.Namespace) -> dict[str, Any]:
    return _transcript_manager_from_args(args).preview_app_snapshot(
        connection_id=args.connection_id,
    )


def command_graph(args: argparse.Namespace) -> dict[str, Any]:
    mode, budget = _cli_response_options(args, surface="memory-graph")
    requested_limit = _normalize_cli_limit(args.limit, maximum=500)
    effective_limit = (
        min(requested_limit, COMPACT_SOURCE_LIMITS["memory-graph"])
        if mode == "compact"
        else requested_limit
    )
    backend = build_backend(args)
    payload = backend.list_memory_graph(
        context_id=args.context,
        limit=effective_limit,
    )
    if mode == "legacy":
        return payload
    payload["_response_source"] = {
        "requested_limit": requested_limit,
        "effective_limit": effective_limit,
    }
    return project_response(
        "memory-graph",
        payload,
        mode=mode,
        max_response_bytes=budget,
    )


def command_namespace_map(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.list_namespace_map(
        context_id=args.context,
        limit=args.limit,
        include_suggestions=not bool(args.no_suggestions),
        suggestion_limit=args.suggestion_limit,
        min_suggestion_score=args.min_suggestion_score,
    )


def command_namespace_link(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.approve_namespace_link(
        source_context_id=args.source_context,
        target_context_id=args.target_context,
        relation_type=args.relation_type,
        weight=args.weight,
        evidence=parse_metadata(args.evidence),
        direction=args.direction,
        approved_by=args.approved_by,
        enabled=not bool(args.disabled),
        confirm=bool(args.confirm),
    )


def _publish_cli_deployment(
    backend: mlx_backend.SpikingAttentionBackend,
    *,
    context_id: str,
    event_type: str,
    summary: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    return backend.publish_context_event(
        context_id=context_id,
        source_surface="cli",
        event_type=event_type,
        summary=summary,
        payload=payload,
    )


def command_pull_context(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.lease_context_events(
        context_id=args.context,
        agent_id=args.agent_id,
        consumer_instance_id=(
            args.consumer_instance_id or backend.delivery_instance_id
        ),
        limit=args.limit,
        lease_seconds=args.lease_seconds,
    )


def command_ack_context(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.ack_context_events(
        context_id=args.context,
        agent_id=args.agent_id,
        acknowledgements=[
            {"receipt_id": receipt_id}
            for receipt_id in args.receipt_id
        ],
    )


def command_release_context(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.release_context_events(
        context_id=args.context,
        agent_id=args.agent_id,
        consumer_instance_id=args.consumer_instance_id,
        receipt_ids=args.receipt_id,
    )


def command_dead_letter_context(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.dead_letter_context_delivery(
        context_id=args.context,
        agent_id=args.agent_id,
        delivery_id=args.delivery_id,
        reason=args.reason,
        confirm=bool(args.confirm),
    )


def command_observe_context(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.list_context_events(
        context_id=args.context,
        since_event_id=args.since_event_id,
        before_event_id=args.before_event_id,
        agent_id=args.agent_id,
        order=args.order,
        limit=args.limit,
    )


def command_list_context_cursors(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.list_context_cursors(context_id=args.context, limit=args.limit)


def command_context_delivery_health(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.context_delivery_health(
        context_id=args.context if args.context_only else None
    )


def command_agent_brief(args: argparse.Namespace) -> dict[str, Any]:
    if args.mode == "morning":
        if str(getattr(args, "response_mode", "") or "").strip().casefold() not in {
            "",
            "legacy",
        }:
            raise ResponseContractError(
                "morning mode is an operator receipt; use legacy response mode"
            )
        runtime = _dashboard_runtime_from_args(args)
        payload = runtime.start_work(
            context_id=args.context,
            agent_id=args.agent_id,
            prompt=args.prompt,
            since_event_id=args.since_event_id,
            event_limit=args.limit,
            graph_limit=args.graph_limit,
            claim_events=not args.observe_only,
            consumer_instance_id=(
                args.consumer_instance_id or runtime.backend.delivery_instance_id
            ),
            lease_seconds=args.lease_seconds,
        )
        payload["action"] = "agent-brief-morning"
        payload["mode"] = "morning"
        if isinstance(payload.get("receipt"), dict):
            payload["receipt"]["action"] = "agent-brief-morning"
            payload["receipt"]["title"] = payload["receipt"].get("title") or "Morning brief"
        return payload
    mode, budget = _cli_response_options(args, surface="agent-hydration")
    requested_limit = _normalize_cli_limit(args.limit, maximum=100)
    requested_graph_limit = _normalize_cli_limit(args.graph_limit, maximum=200)
    effective_limit = (
        compact_agent_event_limit(
            requested_limit=requested_limit,
            max_output_bytes=int(budget),
        )
        if mode == "compact"
        else requested_limit
    )
    effective_graph_limit = (
        min(requested_graph_limit, COMPACT_SOURCE_LIMITS["agent-graph"])
        if mode == "compact"
        else requested_graph_limit
    )
    backend = build_backend(args)
    consumer_instance_id = args.consumer_instance_id or backend.delivery_instance_id
    payload = backend.hydrate_agent_context(
        context_id=args.context,
        agent_id=args.agent_id,
        prompt=args.prompt,
        since_event_id=args.since_event_id,
        event_limit=effective_limit,
        graph_limit=effective_graph_limit,
        acknowledge=False,
        claim_events=not args.observe_only,
        consumer_instance_id=consumer_instance_id,
        lease_seconds=args.lease_seconds,
    )
    if mode == "legacy":
        return payload
    payload["_response_source"] = {
        "requested_event_limit": requested_limit,
        "effective_event_limit": effective_limit,
        "requested_graph_limit": requested_graph_limit,
        "effective_graph_limit": effective_graph_limit,
    }
    try:
        return project_response(
            "agent-hydration",
            payload,
            mode=mode,
            max_response_bytes=budget,
        )
    except Exception:
        receipt_ids = [
            str(item.get("receipt_id") or "")
            for item in payload.get("deliveries", [])
            if isinstance(item, dict) and str(item.get("receipt_id") or "")
        ]
        if receipt_ids:
            try:
                backend.release_context_events(
                    context_id=args.context,
                    agent_id=args.agent_id,
                    consumer_instance_id=consumer_instance_id,
                    receipt_ids=receipt_ids,
                )
            except Exception as release_exc:
                raise ResponseContractError(
                    "projection failed and leased receipts could not be released; "
                    "wait for lease expiry before retrying"
                ) from release_exc
        raise


def command_enter_cortex(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.enter_spiking_cortex(
        context_id=args.context,
        agent_id=args.agent_id,
        task=args.task,
        mode=args.mode,
    )


def command_cortex_tick(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    intended_files = [
        *parse_string_list(args.intended_files_json, field_name="--intended-files-json"),
        *(args.intended_file or []),
    ]
    intended_tools = [
        *parse_string_list(args.intended_tools_json, field_name="--intended-tools-json"),
        *(args.intended_tool or []),
    ]
    return backend.cortex_tick(
        context_id=args.context,
        agent_id=args.agent_id,
        session_id=args.session_id,
        observation=args.observation,
        proposed_action=args.proposed_action,
        intended_files=intended_files,
        intended_tools=intended_tools,
        mutation_intent=args.mutation_intent,
        confidence=args.confidence,
    )


def command_close_cortex(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.close_spiking_cortex(
        context_id=args.context,
        agent_id=args.agent_id,
        session_id=args.session_id,
        reason=args.reason,
    )


def command_commit_cortex(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    text = _text_from_args(args).strip()
    if not text:
        raise ValueError("--text or --text-file must provide content")
    return backend.commit_cortical_trace(
        context_id=args.context,
        agent_id=args.agent_id,
        session_id=args.session_id,
        trace_type=args.trace_type,
        truth_posture=args.truth_posture,
        text=text,
        evidence=parse_metadata(args.evidence),
        confidence=args.confidence,
    )


def command_cortex_state(args: argparse.Namespace) -> dict[str, Any]:
    mode, budget = _cli_response_options(args, surface="cortex-state")
    requested_limit = _normalize_cli_limit(args.limit, maximum=500)
    effective_limit = (
        min(requested_limit, COMPACT_SOURCE_LIMITS["cortex-state"])
        if mode == "compact"
        else requested_limit
    )
    backend = build_backend(args)
    payload = backend.get_cortex_state(
        context_id=args.context,
        agent_id=args.agent_id,
        limit=effective_limit,
    )
    if mode == "legacy":
        return payload
    payload["_response_source"] = {
        "requested_limit": requested_limit,
        "effective_limit": effective_limit,
    }
    return project_response(
        "cortex-state",
        payload,
        mode=mode,
        max_response_bytes=budget,
    )


def command_moderate_cortex(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.moderate_cortex_trace(
        context_id=args.context,
        memory_id=args.memory_id,
        action=args.action,
        reason=args.reason,
        source_surface="cli-cortex",
        confirm=args.confirm,
    )


def command_profile(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.resource_profile(
        benchmark_quick_prune=args.benchmark_quick_prune,
        target_min_mb=args.target_min_mb,
        target_max_mb=args.target_max_mb,
    )


def command_provider_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.benchmark_embedding_provider(
        text=args.text,
        runs=args.runs,
        dimensions=args.embedding_dimensions or args.dimension,
    )


def command_monday_readiness(args: argparse.Namespace) -> dict[str, Any]:
    from dashboard_server import DashboardRuntime

    runtime = DashboardRuntime(build_backend(args))
    return runtime.monday_readiness(
        context_id=args.context,
        include_apps=args.include_apps,
    )


def _dashboard_runtime_from_args(args: argparse.Namespace):
    from dashboard_server import DashboardRuntime

    return DashboardRuntime(build_backend(args))


def command_start_work(args: argparse.Namespace) -> dict[str, Any]:
    return _dashboard_runtime_from_args(args).start_work(
        context_id=args.context,
        agent_id=args.agent_id,
        prompt=args.prompt,
        claim_events=False,
    )


def command_context_health(args: argparse.Namespace) -> dict[str, Any]:
    return _dashboard_runtime_from_args(args).context_health(context_id=args.context)


def command_memory_hygiene(args: argparse.Namespace) -> dict[str, Any]:
    return _dashboard_runtime_from_args(args).memory_hygiene(
        context_id=args.context,
        limit=args.limit,
    )


def command_goal_create(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.create_goal(
        context_id=args.context,
        agent_id=args.agent_id,
        title=args.title,
        owner=args.owner,
        state=args.goal_state,
        next_action=args.next_action,
        evidence=args.evidence,
    )


def command_goal_update(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.update_goal(
        context_id=args.context,
        agent_id=args.agent_id,
        goal_id=args.goal_id,
        title=args.title,
        owner=args.owner,
        state=args.goal_state,
        next_action=args.next_action,
        evidence=args.evidence,
    )


def command_goal_list(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.list_goals(
        context_id=args.context,
        limit=args.limit,
    )


def command_wrap_session(args: argparse.Namespace) -> dict[str, Any]:
    text = _text_from_args(args).strip()
    operation_log: list[Any] = []
    if args.operation_log_json:
        try:
            parsed = json.loads(args.operation_log_json)
        except json.JSONDecodeError as exc:
            raise ValueError("--operation-log-json must be a JSON array") from exc
        if not isinstance(parsed, list):
            raise ValueError("--operation-log-json must be a JSON array")
        operation_log = parsed
    payload: dict[str, Any] = {
        "context_id": args.context,
        "agent_id": args.agent_id,
        "text": text,
        "operation_log": operation_log,
    }
    if args.source_tag:
        payload["source_tag"] = args.source_tag
    if args.capture_id:
        payload["capture_id"] = args.capture_id
    if args.preview:
        return _dashboard_runtime_from_args(args).wrap_session_preview(payload)
    if not args.confirm:
        raise ValueError("--confirm is required to write a wrap session; use --preview to inspect first")
    payload["confirm"] = True
    return _dashboard_runtime_from_args(args).wrap_session(payload)


def command_certify_runtime(args: argparse.Namespace) -> dict[str, Any]:
    output_path = _optional_public_output_path(
        args.output,
        field="runtime certification output path",
    )
    backend = build_backend(args)
    return backend.certify_runtime(
        strict_native=args.strict_native,
        require_gpu=args.require_gpu,
        benchmark_quick_prune=args.benchmark_quick_prune,
        require_resource_envelope=args.require_resource_envelope,
        target_min_mb=args.target_min_mb,
        target_max_mb=args.target_max_mb,
        output_path=output_path,
    )


def command_quick_prune(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.run_quick_pruning()


def command_idle_maintenance(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.run_idle_maintenance(force_deep_sleep=args.force_deep_sleep)


def command_sleep(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.run_deep_sleep_consolidation()


def command_list_memory(args: argparse.Namespace) -> dict[str, Any]:
    mode, budget = _cli_response_options(args, surface="memory-list")
    if mode == "compact" and bool(args.include_vectors):
        raise ResponseContractError(
            "compact memory responses do not support vectors; use full or legacy mode"
        )
    requested_limit = _normalize_cli_limit(args.limit, maximum=10_000)
    effective_limit = (
        min(requested_limit, COMPACT_SOURCE_LIMITS["memory-list"])
        if mode == "compact"
        else requested_limit
    )
    backend = build_backend(args)
    payload = backend.list_memory(
        context_id=args.context,
        limit=effective_limit,
        include_vectors=args.include_vectors,
    )
    if mode == "legacy":
        return payload
    payload["_response_source"] = {
        "requested_limit": requested_limit,
        "effective_limit": effective_limit,
    }
    return project_response(
        "memory-list",
        payload,
        mode=mode,
        max_response_bytes=budget,
    )


def command_export_memory(args: argparse.Namespace) -> dict[str, Any]:
    output_path = _optional_public_output_path(
        args.output,
        field="memory export output path",
    )
    backend = build_backend(args)
    return backend.export_memory(path=output_path, context_id=args.context)


def command_backup_memory(args: argparse.Namespace) -> dict[str, Any]:
    output_path = _optional_public_output_path(
        args.output,
        field="memory backup output path",
    )
    backend = build_backend(args)
    return backend.backup_memory(path=output_path)


def command_backup_recovery_bundle(args: argparse.Namespace) -> dict[str, Any]:
    output_path = _optional_public_output_path(
        args.output,
        field="recovery bundle database output path",
    )
    backend = build_backend(args)
    return backend.backup_recovery_bundle(
        path=output_path,
        capture_root=args.capture_root,
        purpose=args.purpose,
        pinned=bool(args.pinned),
        allow_noncanonical_capture_root=bool(
            args.allow_noncanonical_capture_root
        ),
    )


def command_capture_ledger_integrity(args: argparse.Namespace) -> dict[str, Any]:
    from recovery_manager import VerifiedRecoveryManager

    store = DurableMemoryStore.open_existing_for_audit(args.memory_db)
    capture_root = args.capture_root or store.db_path.parent
    manager = VerifiedRecoveryManager(store, capture_root=capture_root)
    if args.repair:
        return manager.repair_capture_ledger(
            confirm=bool(args.confirm),
            expected_revision=args.expected_revision,
            sample_limit=args.sample_limit,
        )
    return manager.audit_capture_ledger(sample_limit=args.sample_limit)


def command_verify_recovery_bundle(args: argparse.Namespace) -> dict[str, Any]:
    receipt_path = _optional_public_output_path(
        args.receipt,
        field="recovery bundle receipt path",
    )
    if receipt_path is None:
        raise ValueError("recovery bundle receipt path is required")
    backend = build_backend(args)
    return backend.verify_recovery_bundle(
        receipt_path,
        capture_root=args.capture_root,
        expected_database_sha256=args.expected_database_sha256,
        expected_capture_sha256=args.expected_capture_sha256,
    )


def command_restore_recovery_bundle(args: argparse.Namespace) -> dict[str, Any]:
    receipt_path = _optional_public_output_path(
        args.receipt,
        field="recovery bundle receipt path",
    )
    output_root = _optional_public_output_path(
        args.output_root,
        field="recovery proof output root",
    )
    if receipt_path is None or output_root is None:
        raise ValueError("receipt and output root are required")
    backend = build_backend(args)
    return backend.restore_recovery_bundle_isolated(
        receipt_path,
        output_root,
        capture_root=args.capture_root,
        expected_database_sha256=args.expected_database_sha256,
        expected_capture_sha256=args.expected_capture_sha256,
        confirm=bool(args.confirm),
    )


def command_plan_recovery_retention(args: argparse.Namespace) -> dict[str, Any]:
    directory = _optional_public_output_path(
        args.directory,
        field="recovery retention directory",
    )
    backend = build_backend(args)
    return backend.plan_recovery_retention(
        directory=directory,
        keep_latest=args.keep_latest,
        max_age_days=args.max_age_days,
    )


def command_apply_recovery_retention(args: argparse.Namespace) -> dict[str, Any]:
    directory = _optional_public_output_path(
        args.directory,
        field="recovery retention directory",
    )
    backend = build_backend(args)
    return backend.apply_recovery_retention(
        plan_token=args.plan_token,
        cutoff_created_at=args.cutoff_created_at,
        directory=directory,
        keep_latest=args.keep_latest,
        max_age_days=args.max_age_days,
        confirm=bool(args.confirm),
    )


def command_restore_retired_recovery(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.restore_retired_recovery(
        plan_token=args.plan_token,
        confirm=bool(args.confirm),
    )


def command_memory_integrity(args: argparse.Namespace) -> dict[str, Any]:
    context_id = str(args.context).strip() if args.context is not None else None
    store = DurableMemoryStore.open_existing_for_audit(args.memory_db)
    if args.repair:
        return store.repair_semantic_indexes(
            context_id=context_id,
            confirm=bool(args.confirm),
            expected_revision=args.expected_revision,
            sample_limit=args.sample_limit,
        )
    return store.audit_semantic_indexes(
        context_id=context_id,
        sample_limit=args.sample_limit,
    )


def command_preflight(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    status = backend.status(context_id=args.context)
    resource_profile = backend.resource_profile(benchmark_quick_prune=False)
    native_certification = (
        backend.certify_runtime(
            strict_native=args.require_native,
            require_gpu=args.require_gpu,
            benchmark_quick_prune=False,
            require_resource_envelope=args.require_resource_envelope,
        )
        if args.require_native or args.require_gpu
        else None
    )
    dependencies = {
        "mlx": dependency_status("mlx"),
        "mlx.core": dependency_status("mlx.core"),
        "mlxsnn": dependency_status("mlxsnn"),
        "fastmcp": dependency_status("fastmcp"),
        "mcp": dependency_status("mcp"),
    }
    launcher_path = Path(args.launcher).expanduser()
    state_path = Path(status["state_path"]).expanduser()
    memory_db_path = Path(status["memory_db_path"]).expanduser()
    query_result = ""
    if args.query_text:
        query_result = backend.query_text(args.query_text, context_id=args.context)

    checks = {
        "dependencies_importable": all(
            dependencies[name]["importable"]
            for name in ("mlx.core", "mlxsnn", "fastmcp", "mcp")
        ),
        "effective_enabled": bool(status["effective_enabled"]),
        "memory_db_exists": memory_db_path.exists(),
        "memory_parent_writable": os.access(memory_db_path.parent, os.W_OK),
        "state_parent_writable": os.access(state_path.parent, os.W_OK),
        "memory_minimum_met": int(status["memory_context_entry_count"]) >= int(args.minimum_memory),
        "relationship_minimum_met": int(
            status["memory_context_relationship_count"]
        )
        >= int(args.minimum_relationships),
        "resource_envelope_met": (
            not bool(args.require_resource_envelope)
            or bool(resource_profile["within_target_envelope"])
        ),
        "launcher_executable": launcher_path.exists() and os.access(launcher_path, os.X_OK),
        "consolidation_lifecycle_declared": status["consolidation_phase_names"]
        == [
            "connection-weight-decay",
            "synaptic-clustering",
            "semantic-merging",
            "threshold-rescoring",
            "trace-promotion",
            "relationship-extraction",
            "neurogenesis",
        ],
        "quick_pruning_interval_configured": float(
            status["quick_pruning_interval_seconds"]
        )
        == 300.0,
    }
    if native_certification is not None:
        checks["native_certification_ready"] = bool(native_certification["ready"])
    if args.query_text:
        checks["query_returned_context"] = (
            bool(query_result)
            and "No high-salience" not in query_result
            and "No registered historical context matched" not in query_result
        )
        checks["query_not_disabled"] = "disabled" not in query_result.lower()

    failed_checks = [name for name, passed in checks.items() if not passed]
    return {
        "ready": not failed_checks,
        "failed_checks": failed_checks,
        "checks": checks,
        "context_id": mlx_backend.sanitize_context_id(args.context),
        "launcher_path": str(launcher_path),
        "state_path": str(state_path),
        "memory_db_path": str(memory_db_path),
        "minimum_memory": int(args.minimum_memory),
        "minimum_relationships": int(args.minimum_relationships),
        "dependencies": dependencies,
        "status": status,
        "resource_profile": resource_profile,
        "native_certification": native_certification,
        "memory_preview": backend.list_memory(
            context_id=args.context,
            limit=args.preview_limit,
            include_vectors=False,
        ),
        "query_result": query_result,
    }


def command_doctor(args: argparse.Namespace) -> dict[str, Any]:
    runtime = _dashboard_runtime_from_args(args)
    payload = runtime.doctor_report(
        context_id=args.context,
        include_apps=bool(args.include_apps),
        repair_plan=bool(args.repair_plan),
        wait_for_semantic_audit=True,
    )
    payload["python"] = sys.version.split()[0]
    payload["executable"] = sys.executable
    payload["cwd"] = str(Path.cwd())
    payload["dependencies"] = {
        "mlx": dependency_status("mlx"),
        "mlx.core": dependency_status("mlx.core"),
        "mlxsnn": dependency_status("mlxsnn"),
        "fastmcp": dependency_status("fastmcp"),
        "mcp": dependency_status("mcp"),
    }
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        prog="synapse_cli.py",
        description="Operate the local SYNAPSE-S2 spiking attention MCP backend.",
    )
    parser.add_argument("--state", default=None, help="Runtime state JSON path.")
    parser.add_argument("--dimension", type=int, default=1024)
    parser.add_argument("--neurons", type=int, default=DEFAULT_NUM_NEURONS)
    parser.add_argument("--top-k", type=int, default=256)
    parser.add_argument("--recall-count", type=int, default=10)
    parser.add_argument("--quick-pruning-interval", type=float, default=300.0)
    parser.add_argument("--idle-deep-sleep-seconds", type=float, default=1800.0)
    parser.add_argument("--no-compile", action="store_true")
    parser.add_argument("--memory-db", default=None, help="Durable SQLite memory path.")
    parser.add_argument(
        "--embedding-provider",
        default=None,
        help=(
            "Text embedding provider: auto, mlx-neural[:model], semantic-hash, "
            "lexical-hash, or python:/path.py:function."
        ),
    )
    parser.add_argument(
        "--require-native-backend",
        action="store_true",
        help="Fail backend startup if native MLX/mlxsnn execution is not available.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_context(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--context", default="default")

    status = subparsers.add_parser("status")
    add_context(status)
    status.set_defaults(func=command_status)

    enable = subparsers.add_parser("enable")
    add_context(enable)
    enable.set_defaults(func=command_enable)

    disable = subparsers.add_parser("disable")
    add_context(disable)
    disable.set_defaults(func=command_disable)

    remember_text = subparsers.add_parser("remember-text")
    add_context(remember_text)
    remember_text.add_argument("--tag", required=True)
    remember_text.add_argument("--text", required=True)
    remember_text.add_argument("--metadata", default=None)
    remember_text.set_defaults(func=command_remember_text)

    remember_vector = subparsers.add_parser("remember-vector")
    add_context(remember_vector)
    remember_vector.add_argument("--tag", required=True)
    remember_vector.add_argument("--vector", required=True)
    remember_vector.add_argument("--metadata", default=None)
    remember_vector.set_defaults(func=command_remember_vector)

    query_text = subparsers.add_parser("query-text")
    add_context(query_text)
    query_text.add_argument("--text", required=True)
    query_text.add_argument(
        "--scope",
        dest="recall_scope",
        choices=("local", "connected", "all"),
        default="local",
        help="Recall only this context, approved one-hop connections, or every context.",
    )
    query_text.set_defaults(func=command_query_text)

    query_vector = subparsers.add_parser("query-vector")
    add_context(query_vector)
    query_vector.add_argument("--vector", required=True)
    query_vector.add_argument(
        "--scope",
        dest="recall_scope",
        choices=("local", "connected", "all"),
        default="local",
        help="Recall only this context, approved one-hop connections, or every context.",
    )
    query_vector.set_defaults(func=command_query_vector)

    ingest_text = subparsers.add_parser("ingest-text")
    add_context(ingest_text)
    ingest_text.add_argument("--tag", required=True)
    ingest_text.add_argument("--text", default="")
    ingest_text.add_argument("--text-file", default=None)
    ingest_text.add_argument("--metadata", default=None)
    ingest_text.add_argument("--surprise-threshold", type=float, default=0.62)
    ingest_text.add_argument("--min-segment-sentences", type=int, default=2)
    ingest_text.set_defaults(func=command_ingest_text)

    capture_session = subparsers.add_parser("capture-session")
    add_context(capture_session)
    capture_session.add_argument("--tag", default="codex-session")
    capture_session.add_argument("--speaker", default="operator")
    capture_session.add_argument("--text", default="")
    capture_session.add_argument("--text-file", default=None)
    capture_session.add_argument("--metadata", default=None)
    capture_session.add_argument(
        "--capture-id",
        default="",
        help="reuse an s2cap_ id only when retrying the same logical capture",
    )
    capture_session.add_argument("--surprise-threshold", type=float, default=0.5)
    capture_session.add_argument("--min-segment-sentences", type=int, default=1)
    capture_session.set_defaults(func=command_capture_session)

    prune_memory = subparsers.add_parser("prune-memory")
    add_context(prune_memory)
    prune_memory.add_argument("--target-type", required=True)
    prune_memory.add_argument("--memory-id", default="")
    prune_memory.add_argument("--tag", default="")
    prune_memory.add_argument("--relationship-id", default="")
    prune_memory.add_argument("--event-id", type=int, default=0)
    prune_memory.add_argument("--reason", default="")
    prune_memory.add_argument("--confirm", action="store_true")
    prune_memory.set_defaults(func=command_prune_memory)

    capture_inbox_drop = subparsers.add_parser("capture-inbox-drop")
    add_context(capture_inbox_drop)
    capture_inbox_drop.add_argument("--tag", default="codex-session")
    capture_inbox_drop.add_argument("--speaker", default="operator")
    capture_inbox_drop.add_argument("--text", default="")
    capture_inbox_drop.add_argument("--text-file", default=None)
    capture_inbox_drop.add_argument("--metadata", default=None)
    capture_inbox_drop.add_argument("--capture-root", default=None)
    capture_inbox_drop.add_argument(
        "--capture-id",
        default="",
        help="reuse an s2cap_ id only when retrying the same logical drop",
    )
    capture_inbox_drop.set_defaults(func=command_capture_inbox_drop)

    capture_inbox_status = subparsers.add_parser("capture-inbox-status")
    capture_inbox_status.add_argument("--capture-root", default=None)
    capture_inbox_status.set_defaults(func=command_capture_inbox_status)

    capture_inbox_process = subparsers.add_parser("capture-inbox-process")
    capture_inbox_process.add_argument("--capture-root", default=None)
    capture_inbox_process.add_argument("--max-files", type=int, default=50)
    capture_inbox_process.add_argument("--confirm", action="store_true")
    capture_inbox_process.set_defaults(func=command_capture_inbox_process)

    capture_error_preflight = subparsers.add_parser("capture-error-preflight")
    capture_error_preflight.add_argument("--capture-root", default=None)
    capture_error_preflight.add_argument("--reason", required=True)
    capture_error_preflight.add_argument(
        "--include-historical",
        action="store_true",
        help="Include sanitized legacy diagnostics in addition to terminal evidence.",
    )
    capture_error_preflight.set_defaults(func=command_capture_error_preflight)

    capture_error_resolve = subparsers.add_parser("capture-error-resolve")
    capture_error_resolve.add_argument("--capture-root", default=None)
    capture_error_resolve.add_argument("--preflight-token", required=True)
    capture_error_resolve.add_argument("--reason", required=True)
    capture_error_resolve.add_argument("--include-historical", action="store_true")
    capture_error_resolve.add_argument("--confirm", action="store_true")
    capture_error_resolve.set_defaults(func=command_capture_error_resolve)

    transcript_source_add = subparsers.add_parser("transcript-source-add")
    add_context(transcript_source_add)
    transcript_source_add.add_argument("--source-id", required=True)
    transcript_source_add.add_argument("--path", required=True)
    transcript_source_add.add_argument("--tag", default="transcript-source")
    transcript_source_add.add_argument("--speaker", default="operator")
    transcript_source_add.add_argument("--metadata", default=None)
    transcript_source_add.add_argument("--capture-root", default=None)
    transcript_source_add.add_argument("--start-at-beginning", action="store_true")
    transcript_source_add.add_argument("--disabled", action="store_true")
    transcript_source_add.add_argument("--confirm", action="store_true")
    transcript_source_add.set_defaults(func=command_transcript_source_add)

    transcript_source_list = subparsers.add_parser("transcript-source-list")
    transcript_source_list.add_argument("--capture-root", default=None)
    transcript_source_list.set_defaults(func=command_transcript_source_list)

    transcript_source_poll = subparsers.add_parser("transcript-source-poll")
    transcript_source_poll.add_argument("--capture-root", default=None)
    transcript_source_poll.add_argument("--source-id", default="")
    transcript_source_poll.add_argument("--max-bytes", type=int, default=256000)
    transcript_source_poll.set_defaults(func=command_transcript_source_poll)

    capture_clipboard = subparsers.add_parser("capture-clipboard")
    add_context(capture_clipboard)
    capture_clipboard.add_argument("--tag", default="frontmost-selection")
    capture_clipboard.add_argument("--speaker", default="operator")
    capture_clipboard.add_argument("--text", default="")
    capture_clipboard.add_argument("--text-file", default=None)
    capture_clipboard.add_argument("--metadata", default=None)
    capture_clipboard.add_argument("--capture-root", default=None)
    capture_clipboard.add_argument(
        "--capture-id",
        default="",
        help="reuse an s2cap_ id only when retrying the same logical capture",
    )
    capture_clipboard.set_defaults(func=command_capture_clipboard)

    app_list = subparsers.add_parser("app-list")
    app_list.add_argument("--capture-root", default=None)
    app_list.set_defaults(func=command_app_list)

    app_connect = subparsers.add_parser("app-connect")
    add_context(app_connect)
    app_connect.add_argument("--app-name", required=True)
    app_connect.add_argument("--bundle-id", default="")
    app_connect.add_argument("--pid", type=int, default=0)
    app_connect.add_argument("--tag", default="app-connect")
    app_connect.add_argument("--speaker", default="operator")
    app_connect.add_argument("--metadata", default=None)
    app_connect.add_argument("--capture-root", default=None)
    app_connect.add_argument("--confirm", action="store_true")
    app_connect.add_argument("--allow-manual", action="store_true")
    app_connect.set_defaults(func=command_app_connect)

    app_connections = subparsers.add_parser("app-connections")
    app_connections.add_argument("--capture-root", default=None)
    app_connections.set_defaults(func=command_app_connections)

    app_snapshot = subparsers.add_parser("app-snapshot")
    app_snapshot.add_argument("--connection-id", required=True)
    app_snapshot.add_argument("--metadata", default=None)
    app_snapshot.add_argument("--capture-root", default=None)
    app_snapshot.add_argument(
        "--capture-id",
        default="",
        help="reuse an s2cap_ id only when retrying the same logical snapshot",
    )
    app_snapshot.add_argument("--confirm", action="store_true")
    app_snapshot.set_defaults(func=command_app_snapshot)

    app_snapshot_preview = subparsers.add_parser("app-snapshot-preview")
    app_snapshot_preview.add_argument("--connection-id", required=True)
    app_snapshot_preview.add_argument("--capture-root", default=None)
    app_snapshot_preview.set_defaults(func=command_app_snapshot_preview)

    graph = subparsers.add_parser("graph")
    add_context(graph)
    graph.add_argument("--limit", type=int, default=100)
    _add_response_contract_args(graph)
    graph.set_defaults(func=command_graph)

    namespace_map = subparsers.add_parser("namespace-map")
    add_context(namespace_map)
    namespace_map.add_argument("--limit", type=int, default=500)
    namespace_map.add_argument("--suggestion-limit", type=int, default=50)
    namespace_map.add_argument("--min-suggestion-score", type=float, default=0.05)
    namespace_map.add_argument("--no-suggestions", action="store_true")
    namespace_map.set_defaults(func=command_namespace_map)

    namespace_link = subparsers.add_parser("namespace-link")
    namespace_link.add_argument("--source-context", required=True)
    namespace_link.add_argument("--target-context", required=True)
    namespace_link.add_argument("--relation-type", default="related")
    namespace_link.add_argument("--weight", type=float, default=1.0)
    namespace_link.add_argument("--evidence", default=None)
    namespace_link.add_argument(
        "--direction",
        choices=("bidirectional", "directed"),
        default="bidirectional",
    )
    namespace_link.add_argument("--approved-by", default="operator")
    namespace_link.add_argument("--disabled", action="store_true")
    namespace_link.add_argument("--confirm", action="store_true")
    namespace_link.set_defaults(func=command_namespace_link)

    pull_context = subparsers.add_parser("pull-context")
    add_context(pull_context)
    pull_context.add_argument("--agent-id", required=True)
    pull_context.add_argument("--consumer-instance-id", default="")
    pull_context.add_argument("--limit", type=int, default=50)
    pull_context.add_argument("--lease-seconds", type=float, default=60.0)
    pull_context.set_defaults(func=command_pull_context)

    observe_context = subparsers.add_parser("observe-context")
    add_context(observe_context)
    observe_context.add_argument("--since-event-id", type=int, default=0)
    observe_context.add_argument("--before-event-id", type=int)
    observe_context.add_argument("--agent-id", default=None)
    observe_context.add_argument("--order", choices=("asc", "desc"), default="asc")
    observe_context.add_argument("--limit", type=int, default=50)
    observe_context.set_defaults(func=command_observe_context)

    ack_context = subparsers.add_parser("ack-context")
    add_context(ack_context)
    ack_context.add_argument("--agent-id", required=True)
    ack_context.add_argument("--receipt-id", action="append", required=True)
    ack_context.set_defaults(func=command_ack_context)

    release_context = subparsers.add_parser("release-context")
    add_context(release_context)
    release_context.add_argument("--agent-id", required=True)
    release_context.add_argument("--consumer-instance-id", required=True)
    release_context.add_argument("--receipt-id", action="append", required=True)
    release_context.set_defaults(func=command_release_context)

    dead_letter_context = subparsers.add_parser("dead-letter-context")
    add_context(dead_letter_context)
    dead_letter_context.add_argument("--agent-id", required=True)
    dead_letter_context.add_argument("--delivery-id", required=True)
    dead_letter_context.add_argument("--reason", required=True)
    dead_letter_context.add_argument("--confirm", action="store_true")
    dead_letter_context.set_defaults(func=command_dead_letter_context)

    list_context_cursors = subparsers.add_parser("list-context-cursors")
    add_context(list_context_cursors)
    list_context_cursors.add_argument("--limit", type=int, default=50)
    list_context_cursors.set_defaults(func=command_list_context_cursors)

    delivery_health = subparsers.add_parser("context-delivery-health")
    add_context(delivery_health)
    delivery_health.add_argument("--context-only", action="store_true")
    delivery_health.set_defaults(func=command_context_delivery_health)

    agent_brief = subparsers.add_parser("agent-brief")
    add_context(agent_brief)
    agent_brief.add_argument("--agent-id", required=True)
    agent_brief.add_argument("--prompt", default="")
    agent_brief.add_argument(
        "--mode",
        default="hydrate",
        choices=("hydrate", "morning"),
        help="Use morning for the operator Start Work brief; hydrate preserves raw MCP hydration.",
    )
    agent_brief.add_argument("--since-event-id", type=int, default=None)
    agent_brief.add_argument("--limit", type=int, default=20)
    agent_brief.add_argument("--graph-limit", type=int, default=30)
    agent_brief.add_argument("--consumer-instance-id", default="")
    agent_brief.add_argument("--lease-seconds", type=float, default=60.0)
    agent_brief.add_argument(
        "--observe-only",
        action="store_true",
        help="Hydrate recall and graph without leasing context events.",
    )
    _add_response_contract_args(agent_brief)
    agent_brief.set_defaults(func=command_agent_brief)

    enter_cortex = subparsers.add_parser("enter-cortex")
    add_context(enter_cortex)
    enter_cortex.add_argument("--agent-id", required=True)
    enter_cortex.add_argument("--task", required=True)
    enter_cortex.add_argument(
        "--mode",
        default="strict",
        choices=["strict", "creative", "operator", "security", "demo"],
    )
    enter_cortex.set_defaults(func=command_enter_cortex)

    cortex_tick = subparsers.add_parser("cortex-tick")
    add_context(cortex_tick)
    cortex_tick.add_argument("--agent-id", required=True)
    cortex_tick.add_argument("--session-id", required=True)
    cortex_tick.add_argument("--observation", default="")
    cortex_tick.add_argument("--proposed-action", default="")
    cortex_tick.add_argument(
        "--intended-file",
        action="append",
        default=[],
        help="File, path, or glob the agent intends to touch; repeatable.",
    )
    cortex_tick.add_argument(
        "--intended-tool",
        action="append",
        default=[],
        help="Tool or command the agent intends to use; repeatable.",
    )
    cortex_tick.add_argument("--intended-files-json", default=None)
    cortex_tick.add_argument("--intended-tools-json", default=None)
    cortex_tick.add_argument("--mutation-intent", action="store_true")
    cortex_tick.add_argument("--confidence", type=float, default=0.5)
    cortex_tick.set_defaults(func=command_cortex_tick)

    close_cortex = subparsers.add_parser("close-cortex")
    add_context(close_cortex)
    close_cortex.add_argument("--agent-id", required=True)
    close_cortex.add_argument("--session-id", required=True)
    close_cortex.add_argument("--reason", default="operator-complete")
    close_cortex.set_defaults(func=command_close_cortex)

    commit_cortex = subparsers.add_parser("commit-cortex")
    add_context(commit_cortex)
    commit_cortex.add_argument("--agent-id", required=True)
    commit_cortex.add_argument("--session-id", default="")
    commit_cortex.add_argument("--type", dest="trace_type", default="")
    commit_cortex.add_argument("--truth-posture", default="observed")
    commit_cortex.add_argument("--text", default="")
    commit_cortex.add_argument("--text-file", default=None)
    commit_cortex.add_argument("--evidence", default=None)
    commit_cortex.add_argument("--confidence", type=float, default=None)
    commit_cortex.set_defaults(func=command_commit_cortex)

    cortex_state = subparsers.add_parser("cortex-state")
    add_context(cortex_state)
    cortex_state.add_argument("--agent-id", default="")
    cortex_state.add_argument("--limit", type=int, default=50)
    _add_response_contract_args(cortex_state)
    cortex_state.set_defaults(func=command_cortex_state)

    moderate_cortex = subparsers.add_parser("moderate-cortex")
    add_context(moderate_cortex)
    moderate_cortex.add_argument("--memory-id", required=True)
    moderate_cortex.add_argument(
        "--action",
        choices=("promote", "demote", "prune"),
        required=True,
    )
    moderate_cortex.add_argument("--reason", default="")
    moderate_cortex.add_argument("--confirm", action="store_true")
    moderate_cortex.set_defaults(func=command_moderate_cortex)

    profile = subparsers.add_parser("profile")
    profile.add_argument("--benchmark-quick-prune", action="store_true")
    profile.add_argument("--target-min-mb", type=float, default=DEFAULT_RESOURCE_TARGET_MIN_MB)
    profile.add_argument("--target-max-mb", type=float, default=DEFAULT_RESOURCE_TARGET_MAX_MB)
    profile.set_defaults(func=command_profile)

    provider_benchmark = subparsers.add_parser("provider-benchmark")
    provider_benchmark.add_argument("--text", required=True)
    provider_benchmark.add_argument("--runs", type=int, default=1)
    provider_benchmark.add_argument("--embedding-dimensions", type=int, default=None)
    provider_benchmark.set_defaults(func=command_provider_benchmark)

    monday_readiness = subparsers.add_parser("monday-readiness")
    add_context(monday_readiness)
    monday_readiness.add_argument("--include-apps", action="store_true")
    monday_readiness.set_defaults(func=command_monday_readiness)

    start_work = subparsers.add_parser("start-work")
    add_context(start_work)
    start_work.add_argument("--agent-id", default="codex-desktop")
    start_work.add_argument("--prompt", default="")
    start_work.set_defaults(func=command_start_work)

    context_health = subparsers.add_parser("context-health")
    add_context(context_health)
    context_health.set_defaults(func=command_context_health)

    memory_hygiene = subparsers.add_parser("memory-hygiene")
    add_context(memory_hygiene)
    memory_hygiene.add_argument("--limit", type=int, default=25)
    memory_hygiene.set_defaults(func=command_memory_hygiene)

    for command_name in ("goal.create", "goal-create"):
        goal_create = subparsers.add_parser(command_name)
        add_context(goal_create)
        goal_create.add_argument("--agent-id", default="codex-desktop")
        goal_create.add_argument("--title", required=True)
        goal_create.add_argument("--owner", default="")
        goal_create.add_argument(
            "--goal-state",
            "--state",
            dest="goal_state",
            default="planned",
            choices=("planned", "in_progress", "blocked", "done", "stale"),
        )
        goal_create.add_argument("--next-action", default="")
        goal_create.add_argument("--evidence", default="")
        goal_create.set_defaults(func=command_goal_create)

    for command_name in ("goal.update", "goal-update"):
        goal_update = subparsers.add_parser(command_name)
        add_context(goal_update)
        goal_update.add_argument("--agent-id", default="codex-desktop")
        goal_update.add_argument("--goal-id", default="")
        goal_update.add_argument("--title", default="")
        goal_update.add_argument("--owner", default="")
        goal_update.add_argument(
            "--goal-state",
            "--state",
            dest="goal_state",
            default="",
            choices=("", "planned", "in_progress", "blocked", "done", "stale"),
        )
        goal_update.add_argument("--next-action", default="")
        goal_update.add_argument("--evidence", default="")
        goal_update.set_defaults(func=command_goal_update)

    for command_name in ("goal.list", "goal-list"):
        goal_list = subparsers.add_parser(command_name)
        add_context(goal_list)
        goal_list.add_argument("--limit", type=int, default=20)
        goal_list.set_defaults(func=command_goal_list)

    wrap_session = subparsers.add_parser("wrap-session")
    add_context(wrap_session)
    wrap_session.add_argument("--agent-id", default="codex-desktop")
    wrap_session.add_argument("--source-tag", default="")
    wrap_session.add_argument("--text", default="")
    wrap_session.add_argument("--text-file", default=None)
    wrap_session.add_argument("--operation-log-json", default="")
    wrap_session.add_argument(
        "--capture-id",
        default="",
        help="reuse an s2cap_ id only when retrying the same logical wrap",
    )
    wrap_session.add_argument("--preview", action="store_true")
    wrap_session.add_argument("--confirm", action="store_true")
    wrap_session.set_defaults(func=command_wrap_session)

    certify_runtime = subparsers.add_parser("certify-runtime")
    certify_runtime.add_argument("--strict-native", action="store_true")
    certify_runtime.add_argument("--require-gpu", action="store_true")
    certify_runtime.add_argument("--benchmark-quick-prune", action="store_true")
    certify_runtime.add_argument("--require-resource-envelope", action="store_true")
    certify_runtime.add_argument("--target-min-mb", type=float, default=DEFAULT_RESOURCE_TARGET_MIN_MB)
    certify_runtime.add_argument("--target-max-mb", type=float, default=DEFAULT_RESOURCE_TARGET_MAX_MB)
    certify_runtime.add_argument("--output", default=None)
    certify_runtime.set_defaults(func=command_certify_runtime)

    quick_prune = subparsers.add_parser("quick-prune")
    quick_prune.set_defaults(func=command_quick_prune)

    idle_maintenance = subparsers.add_parser("idle-maintenance")
    idle_maintenance.add_argument("--force-deep-sleep", action="store_true")
    idle_maintenance.set_defaults(func=command_idle_maintenance)

    sleep = subparsers.add_parser("sleep")
    sleep.set_defaults(func=command_sleep)

    list_memory = subparsers.add_parser("list-memory")
    add_context(list_memory)
    list_memory.add_argument("--limit", type=int, default=50)
    list_memory.add_argument("--include-vectors", action="store_true")
    _add_response_contract_args(list_memory)
    list_memory.set_defaults(func=command_list_memory)

    export_memory = subparsers.add_parser("export-memory")
    add_context(export_memory)
    export_memory.add_argument("--output", default=None)
    export_memory.set_defaults(func=command_export_memory)

    backup_memory = subparsers.add_parser("backup-memory")
    backup_memory.add_argument("--output", default=None)
    backup_memory.set_defaults(func=command_backup_memory)

    capture_ledger = subparsers.add_parser(
        "capture-ledger-integrity",
        help=(
            "Audit processed capture.v2 payloads against the authoritative "
            "SQLite ledger, or apply a reviewed historical reconciliation."
        ),
    )
    capture_ledger.add_argument("--capture-root", default=None)
    capture_ledger.add_argument("--sample-limit", type=int, default=20)
    capture_ledger.add_argument("--repair", action="store_true")
    capture_ledger.add_argument("--confirm", action="store_true")
    capture_ledger.add_argument("--expected-revision", default=None)
    capture_ledger.set_defaults(func=command_capture_ledger_integrity)

    backup_recovery = subparsers.add_parser(
        "backup-recovery",
        help="Create a signed paired database and exactly-once capture recovery bundle.",
    )
    backup_recovery.add_argument("--output", default=None)
    backup_recovery.add_argument("--capture-root", default=None)
    backup_recovery.add_argument("--purpose", default="operator")
    backup_recovery.add_argument("--pinned", action="store_true")
    backup_recovery.add_argument(
        "--allow-noncanonical-capture-root",
        action="store_true",
        help=(
            "Explicitly permit a pre-existing private capture root outside the "
            "memory-store directory; the signed receipt records this exception."
        ),
    )
    backup_recovery.set_defaults(func=command_backup_recovery_bundle)

    verify_recovery = subparsers.add_parser("verify-recovery")
    verify_recovery.add_argument("--receipt", required=True)
    verify_recovery.add_argument("--capture-root", default=None)
    verify_recovery.add_argument("--expected-database-sha256", default=None)
    verify_recovery.add_argument("--expected-capture-sha256", default=None)
    verify_recovery.set_defaults(func=command_verify_recovery_bundle)

    restore_recovery = subparsers.add_parser("restore-recovery-proof")
    restore_recovery.add_argument("--receipt", required=True)
    restore_recovery.add_argument("--output-root", required=True)
    restore_recovery.add_argument("--capture-root", default=None)
    restore_recovery.add_argument("--expected-database-sha256", default=None)
    restore_recovery.add_argument("--expected-capture-sha256", default=None)
    restore_recovery.add_argument("--confirm", action="store_true")
    restore_recovery.set_defaults(func=command_restore_recovery_bundle)

    retention_plan = subparsers.add_parser("recovery-retention-plan")
    retention_plan.add_argument("--directory", default=None)
    retention_plan.add_argument("--keep-latest", type=int, default=7)
    retention_plan.add_argument("--max-age-days", type=float, default=30.0)
    retention_plan.set_defaults(func=command_plan_recovery_retention)

    retention_apply = subparsers.add_parser("recovery-retention-apply")
    retention_apply.add_argument("--directory", default=None)
    retention_apply.add_argument("--keep-latest", type=int, default=7)
    retention_apply.add_argument("--max-age-days", type=float, default=30.0)
    retention_apply.add_argument("--plan-token", required=True)
    retention_apply.add_argument("--cutoff-created-at", type=float, required=True)
    retention_apply.add_argument("--confirm", action="store_true")
    retention_apply.set_defaults(func=command_apply_recovery_retention)

    retention_restore = subparsers.add_parser("recovery-retention-restore")
    retention_restore.add_argument("--plan-token", required=True)
    retention_restore.add_argument("--confirm", action="store_true")
    retention_restore.set_defaults(func=command_restore_retired_recovery)

    memory_integrity = subparsers.add_parser(
        "memory-integrity",
        help="Audit or transactionally repair durable spike and surface-term indexes.",
    )
    memory_integrity.add_argument(
        "--context",
        default=None,
        help="Optional context to audit; omit to verify the entire memory store.",
    )
    memory_integrity.add_argument(
        "--sample-limit",
        type=int,
        default=20,
        help="Maximum mismatch samples and repaired IDs to include in the receipt.",
    )
    memory_integrity.add_argument(
        "--repair",
        action="store_true",
        help="Repair only mismatched durable index rows in one verified transaction.",
    )
    memory_integrity.add_argument(
        "--confirm",
        action="store_true",
        help=(
            "Required together with --repair; audit mode does not change memory "
            "or semantic-index rows."
        ),
    )
    memory_integrity.add_argument(
        "--expected-revision",
        default=None,
        help="Required with --repair; copy audit_revision from the reviewed audit.",
    )
    memory_integrity.set_defaults(func=command_memory_integrity)

    preflight = subparsers.add_parser("preflight")
    add_context(preflight)
    preflight.add_argument(
        "--query-text",
        default="SYNAPSE-S2 durable local memory Apple Silicon MCP recall",
    )
    preflight.add_argument("--minimum-memory", type=int, default=1)
    preflight.add_argument("--minimum-relationships", type=int, default=0)
    preflight.add_argument("--require-resource-envelope", action="store_true")
    preflight.add_argument("--require-native", action="store_true")
    preflight.add_argument("--require-gpu", action="store_true")
    preflight.add_argument("--preview-limit", type=int, default=5)
    preflight.add_argument(
        "--launcher",
        default="/Users/dan.driver/.local/bin/synapse-s2-mcp",
    )
    preflight.set_defaults(func=command_preflight)

    doctor = subparsers.add_parser("doctor")
    add_context(doctor)
    doctor.add_argument("--include-apps", action="store_true")
    doctor.add_argument("--repair-plan", action="store_true")
    doctor.set_defaults(func=command_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if _STARTUP_IMPORT_ERROR is not None:
        emit(
            {
                "error": safe_public_error(
                    _STARTUP_IMPORT_ERROR,
                    fallback="startup import failed",
                )
            },
            as_json="--json" in raw_argv,
        )
        return 1
    parser = build_parser()
    try:
        args = parser.parse_args(raw_argv)
    except SafeArgumentParseError as exc:
        if "--json" in raw_argv:
            emit({"error": str(exc)}, as_json=True)
        else:
            sys.stderr.write(exc.usage)
            sys.stderr.write(f"{exc.prog}: error: {exc}\n")
        return 2
    try:
        payload = args.func(args)
        emit(payload, as_json=args.json)
        return 0
    except Exception as exc:
        surface = _CONTRACT_COMMAND_SURFACES.get(str(getattr(args, "command", "")))
        response_mode = str(getattr(args, "response_mode", "") or "").strip().casefold()
        if surface and response_mode != "legacy" and not (
            getattr(args, "command", "") == "agent-brief"
            and getattr(args, "mode", "") == "morning"
            and response_mode in {"", "legacy"}
        ):
            error_budget: int | None = _cli_error_response_budget(surface=surface)
            try:
                error_budget = _cli_response_budget(args, surface=surface)
            except Exception:
                pass
            emit(
                response_error(
                    operation=surface,
                    error=exc,
                    max_response_bytes=error_budget,
                ),
                as_json=args.json,
            )
        else:
            emit(
                {"error": safe_public_error(exc, fallback="command failed")},
                as_json=args.json,
            )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

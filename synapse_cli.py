from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

from capture_daemon import CaptureInboxDaemon, write_capture_drop
import mlx_backend
from transcript_capture import TranscriptCaptureManager


def _json_default(value: Any) -> str:
    return str(value)


def emit(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True, default=_json_default))
        return

    for key, value in payload.items():
        if isinstance(value, (dict, list)):
            print(f"{key}: {json.dumps(value, sort_keys=True, default=_json_default)}")
        else:
            print(f"{key}: {value}")


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
        "embedding_provider": embedding["provenance"],
        "result": backend.query_text(args.text, context_id=args.context),
    }


def command_query_vector(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return {
        "context_id": mlx_backend.sanitize_context_id(args.context),
        "result": backend.query(parse_vector(args.vector), context_id=args.context),
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
    drop_path = write_capture_drop(
        root=args.capture_root,
        context_id=args.context,
        source_tag=args.tag,
        speaker=args.speaker,
        text=text,
        metadata=parse_metadata(args.metadata),
    )
    return {
        "action": "capture-inbox-drop",
        "drop_path": str(drop_path),
        "context_id": mlx_backend.sanitize_context_id(args.context),
        "source_tag": mlx_backend.sanitize_tag(args.tag).replace(" ", "-"),
        "speaker": mlx_backend.sanitize_agent_id(args.speaker),
    }


def _capture_daemon_from_args(args: argparse.Namespace) -> CaptureInboxDaemon:
    return CaptureInboxDaemon(root=args.capture_root, backend=build_backend(args))


def command_capture_inbox_status(args: argparse.Namespace) -> dict[str, Any]:
    return _capture_daemon_from_args(args).status()


def command_capture_inbox_process(args: argparse.Namespace) -> dict[str, Any]:
    if args.confirm is not True:
        raise ValueError("--confirm is required to process capture inbox files")
    return _capture_daemon_from_args(args).process_once(max_files=args.max_files)


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
    )


def command_graph(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.list_memory_graph(context_id=args.context, limit=args.limit)


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
    return backend.list_context_events(
        context_id=args.context,
        since_event_id=args.since_event_id,
        limit=args.limit,
    )


def command_ack_context(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.ack_context_events(
        context_id=args.context,
        agent_id=args.agent_id,
        last_event_id=args.last_event_id,
    )


def command_list_context_cursors(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.list_context_cursors(context_id=args.context, limit=args.limit)


def command_agent_brief(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.hydrate_agent_context(
        context_id=args.context,
        agent_id=args.agent_id,
        prompt=args.prompt,
        since_event_id=args.since_event_id,
        event_limit=args.limit,
        graph_limit=args.graph_limit,
        acknowledge=not args.no_ack,
    )


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
    backend = build_backend(args)
    return backend.get_cortex_state(
        context_id=args.context,
        agent_id=args.agent_id,
        limit=args.limit,
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


def command_certify_runtime(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.certify_runtime(
        strict_native=args.strict_native,
        require_gpu=args.require_gpu,
        benchmark_quick_prune=args.benchmark_quick_prune,
        require_resource_envelope=args.require_resource_envelope,
        target_min_mb=args.target_min_mb,
        target_max_mb=args.target_max_mb,
        output_path=args.output,
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
    backend = build_backend(args)
    return backend.list_memory(
        context_id=args.context,
        limit=args.limit,
        include_vectors=args.include_vectors,
    )


def command_export_memory(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.export_memory(path=args.output, context_id=args.context)


def command_backup_memory(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.backup_memory(path=args.output)


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
    backend = build_backend(args)
    return {
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "cwd": str(Path.cwd()),
        "environment": {
            "MLX_DEVICE": os.getenv("MLX_DEVICE", ""),
            "SYNAPSE_S2_STATE_PATH": os.getenv("SYNAPSE_S2_STATE_PATH", ""),
            "SYNAPSE_S2_MEMORY_DB": os.getenv("SYNAPSE_S2_MEMORY_DB", ""),
            "SYNAPSE_S2_EXPORT_DIR": os.getenv("SYNAPSE_S2_EXPORT_DIR", ""),
        },
        "dependencies": {
            "mlx": dependency_status("mlx"),
            "mlx.core": dependency_status("mlx.core"),
            "mlxsnn": dependency_status("mlxsnn"),
            "fastmcp": dependency_status("fastmcp"),
            "mcp": dependency_status("mcp"),
        },
        "status": backend.status(context_id=args.context),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="synapse_cli.py",
        description="Operate the local SYNAPSE-S2 spiking attention MCP backend.",
    )
    parser.add_argument("--state", default=None, help="Runtime state JSON path.")
    parser.add_argument("--dimension", type=int, default=1024)
    parser.add_argument("--neurons", type=int, default=5400)
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
    query_text.set_defaults(func=command_query_text)

    query_vector = subparsers.add_parser("query-vector")
    add_context(query_vector)
    query_vector.add_argument("--vector", required=True)
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
    capture_inbox_drop.set_defaults(func=command_capture_inbox_drop)

    capture_inbox_status = subparsers.add_parser("capture-inbox-status")
    capture_inbox_status.add_argument("--capture-root", default=None)
    capture_inbox_status.set_defaults(func=command_capture_inbox_status)

    capture_inbox_process = subparsers.add_parser("capture-inbox-process")
    capture_inbox_process.add_argument("--capture-root", default=None)
    capture_inbox_process.add_argument("--max-files", type=int, default=50)
    capture_inbox_process.add_argument("--confirm", action="store_true")
    capture_inbox_process.set_defaults(func=command_capture_inbox_process)

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
    app_snapshot.add_argument("--confirm", action="store_true")
    app_snapshot.set_defaults(func=command_app_snapshot)

    graph = subparsers.add_parser("graph")
    add_context(graph)
    graph.add_argument("--limit", type=int, default=100)
    graph.set_defaults(func=command_graph)

    pull_context = subparsers.add_parser("pull-context")
    add_context(pull_context)
    pull_context.add_argument("--since-event-id", type=int, default=0)
    pull_context.add_argument("--limit", type=int, default=50)
    pull_context.set_defaults(func=command_pull_context)

    ack_context = subparsers.add_parser("ack-context")
    add_context(ack_context)
    ack_context.add_argument("--agent-id", required=True)
    ack_context.add_argument("--last-event-id", type=int, required=True)
    ack_context.set_defaults(func=command_ack_context)

    list_context_cursors = subparsers.add_parser("list-context-cursors")
    add_context(list_context_cursors)
    list_context_cursors.add_argument("--limit", type=int, default=50)
    list_context_cursors.set_defaults(func=command_list_context_cursors)

    agent_brief = subparsers.add_parser("agent-brief")
    add_context(agent_brief)
    agent_brief.add_argument("--agent-id", required=True)
    agent_brief.add_argument("--prompt", default="")
    agent_brief.add_argument("--since-event-id", type=int, default=None)
    agent_brief.add_argument("--limit", type=int, default=20)
    agent_brief.add_argument("--graph-limit", type=int, default=30)
    agent_brief.add_argument("--no-ack", action="store_true")
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
    profile.add_argument("--target-min-mb", type=float, default=61.0)
    profile.add_argument("--target-max-mb", type=float, default=138.0)
    profile.set_defaults(func=command_profile)

    provider_benchmark = subparsers.add_parser("provider-benchmark")
    provider_benchmark.add_argument("--text", required=True)
    provider_benchmark.add_argument("--runs", type=int, default=1)
    provider_benchmark.add_argument("--embedding-dimensions", type=int, default=None)
    provider_benchmark.set_defaults(func=command_provider_benchmark)

    certify_runtime = subparsers.add_parser("certify-runtime")
    certify_runtime.add_argument("--strict-native", action="store_true")
    certify_runtime.add_argument("--require-gpu", action="store_true")
    certify_runtime.add_argument("--benchmark-quick-prune", action="store_true")
    certify_runtime.add_argument("--require-resource-envelope", action="store_true")
    certify_runtime.add_argument("--target-min-mb", type=float, default=61.0)
    certify_runtime.add_argument("--target-max-mb", type=float, default=138.0)
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
    list_memory.set_defaults(func=command_list_memory)

    export_memory = subparsers.add_parser("export-memory")
    add_context(export_memory)
    export_memory.add_argument("--output", default=None)
    export_memory.set_defaults(func=command_export_memory)

    backup_memory = subparsers.add_parser("backup-memory")
    backup_memory.add_argument("--output", default=None)
    backup_memory.set_defaults(func=command_backup_memory)

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
    doctor.set_defaults(func=command_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        payload = args.func(args)
        emit(payload, as_json=args.json)
        return 0
    except Exception as exc:
        emit({"error": str(exc)}, as_json=args.json)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

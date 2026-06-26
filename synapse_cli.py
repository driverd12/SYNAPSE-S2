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
        "result": backend.query(embedding["embedding"], context_id=args.context),
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
    return _capture_daemon_from_args(args).process_once(max_files=args.max_files)


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
        query_result = backend.query(
            backend.embed_text(args.query_text),
            context_id=args.context,
        )

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
    parser.add_argument("--neurons", type=int, default=5000)
    parser.add_argument("--top-k", type=int, default=150)
    parser.add_argument("--recall-count", type=int, default=5)
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
    capture_inbox_process.set_defaults(func=command_capture_inbox_process)

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

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

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
    return backend.register_trace(
        tag=args.tag,
        embedding=backend.embed_text(args.text),
        context_id=args.context,
        metadata=parse_metadata(args.metadata),
        source_text=args.text,
    )


def command_remember_vector(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return backend.register_trace(
        tag=args.tag,
        embedding=parse_vector(args.vector),
        context_id=args.context,
        metadata=parse_metadata(args.metadata),
    )


def command_query_text(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return {
        "context_id": mlx_backend.sanitize_context_id(args.context),
        "result": backend.query(backend.embed_text(args.text), context_id=args.context),
    }


def command_query_vector(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    return {
        "context_id": mlx_backend.sanitize_context_id(args.context),
        "result": backend.query(parse_vector(args.vector), context_id=args.context),
    }


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
    if args.query_text:
        checks["query_returned_context"] = bool(query_result) and "No high-salience" not in query_result
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
        "dependencies": dependencies,
        "status": status,
        "memory_preview": backend.list_memory(
            context_id=args.context,
            limit=args.preview_limit,
            include_vectors=False,
        ),
        "query_result": query_result,
    }


def command_seed_demo(args: argparse.Namespace) -> dict[str, Any]:
    backend = build_backend(args)
    samples = [
        (
            "executive-briefing",
            "SYNAPSE-S2 reduces context pressure with local spiking associative recall",
        ),
        (
            "metal-runtime",
            "Apple Silicon MLX executes immutable leaky integrate and fire state updates",
        ),
        (
            "ops-toggle",
            "Operators can enable disable inspect and prune the local MCP memory substrate",
        ),
    ]
    registrations = [
        backend.register_trace(
            tag=tag,
            embedding=backend.embed_text(text),
            context_id=args.context,
            metadata={"seed": "demo"},
            source_text=text,
        )
        for tag, text in samples
    ]
    return {
        "context_id": mlx_backend.sanitize_context_id(args.context),
        "registered": registrations,
        "status": backend.status(context_id=args.context),
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

    seed_demo = subparsers.add_parser("seed-demo")
    add_context(seed_demo)
    seed_demo.set_defaults(func=command_seed_demo)

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

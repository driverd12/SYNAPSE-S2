from __future__ import annotations

import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    from fastmcp import FastMCP
except Exception as fastmcp_exc:  # pragma: no cover - host dependent
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[no-redef]
    except Exception as mcp_exc:  # pragma: no cover - host dependent
        FastMCP = None  # type: ignore[assignment,misc]
        _FASTMCP_IMPORT_ERROR: Exception | None = mcp_exc
        _FASTMCP_PRIMARY_ERROR: Exception | None = fastmcp_exc
    else:
        _FASTMCP_IMPORT_ERROR = None
        _FASTMCP_PRIMARY_ERROR = fastmcp_exc
else:
    _FASTMCP_IMPORT_ERROR = None
    _FASTMCP_PRIMARY_ERROR = None

LOGGER = logging.getLogger("synapse_s2.mcp")
logging.basicConfig(
    level=os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper(),
    stream=sys.stderr,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    force=True,
)

MAX_TOOL_EMBEDDING_DIMS = 32_768
CONTEXT_ID_RE = re.compile(r"[^A-Za-z0-9_.:-]+")
AGENT_ID_RE = re.compile(r"[^A-Za-z0-9_.:@-]+")


class _UnavailableMCP:
    def tool(self, *args: Any, **kwargs: Any):
        def decorator(func):
            return func

        if args and callable(args[0]) and not kwargs:
            return args[0]
        return decorator

    def run(self) -> None:
        message = (
            "FastMCP is unavailable. Install dependencies with `uv sync` or "
            "`python -m pip install fastmcp mlx`."
        )
        if _FASTMCP_IMPORT_ERROR is not None:
            message = f"{message} Import error: {_FASTMCP_IMPORT_ERROR}"
        LOGGER.error(message)
        raise SystemExit(1)


mcp = (
    FastMCP(name="SYNAPSE-S2 Spiking Attention MCP Server")
    if FastMCP is not None
    else _UnavailableMCP()
)


def _sanitize_context_id(context_id: str) -> str:
    raw = str(context_id or "default").strip()
    cleaned = CONTEXT_ID_RE.sub("_", raw).strip("._-:")
    return (cleaned or "default")[:128]


def _sanitize_agent_id(agent_id: str) -> str:
    raw = str(agent_id or "").strip()
    cleaned = AGENT_ID_RE.sub("_", raw).strip("._-:@")
    return (cleaned or "unknown-agent")[:128]


def _validate_embedding(prompt_embedding: list[float]) -> list[float]:
    if not isinstance(prompt_embedding, list):
        raise ValueError("prompt_embedding must be a list[float]")
    if not prompt_embedding:
        raise ValueError("prompt_embedding must not be empty")
    if len(prompt_embedding) > MAX_TOOL_EMBEDDING_DIMS:
        raise ValueError(f"prompt_embedding exceeds {MAX_TOOL_EMBEDDING_DIMS} dimensions")

    values: list[float] = []
    for index, value in enumerate(prompt_embedding):
        try:
            numeric = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"prompt_embedding[{index}] is not a float") from exc
        if not (numeric == numeric and abs(numeric) != float("inf")):
            raise ValueError(f"prompt_embedding[{index}] must be finite")
        values.append(numeric)
    return values


def _validate_optional_embedding(prompt_embedding: list[float] | None) -> list[float] | None:
    if prompt_embedding is None:
        return None
    return _validate_embedding(prompt_embedding)


def _validate_text(text: str, *, field_name: str = "text") -> str:
    value = str(text or "").strip()
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    if len(value) > 20_000:
        raise ValueError(f"{field_name} exceeds 20000 characters")
    return value


def _validate_limit(limit: int) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    return min(max(value, 1), 500)


def _optional_output_path(
    output_path: str | None,
    *,
    allowed_suffixes: set[str],
) -> str | None:
    value = str(output_path or "").strip()
    if not value:
        return None
    if len(value) > 4096:
        raise ValueError("output_path exceeds 4096 characters")
    export_root = Path(os.getenv("SYNAPSE_S2_EXPORT_DIR", ".synapse_s2")).expanduser()
    if not export_root.is_absolute():
        export_root = Path.cwd() / export_root
    resolved_root = export_root.resolve()
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    resolved_candidate = candidate.resolve()
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(
            f"output_path must stay within export root {resolved_root}"
        ) from exc
    suffix = resolved_candidate.suffix.lower()
    if suffix not in allowed_suffixes:
        allowed = ", ".join(sorted(allowed_suffixes))
        raise ValueError(f"output_path suffix must be one of: {allowed}")
    return str(resolved_candidate)


def _load_backend():
    import mlx.core as mx
    import mlx_backend

    return mx, mlx_backend


def _publish_tool_deployment(
    mlx_backend_module: Any,
    *,
    context_id: str,
    event_type: str,
    summary: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    return mlx_backend_module.publish_context_event(
        context_id=context_id,
        source_surface="mcp-tool",
        event_type=event_type,
        summary=summary,
        payload=payload,
    )


@mcp.tool(
    annotations={
        "title": "Query Spiking Associative Memory",
        "readOnlyHint": True,
    }
)
def query_spiking_attention(
    prompt_embedding: list[float],
    context_id: str = "default",
) -> str:
    """Return activated historical context tags for a dense prompt embedding."""
    context = _sanitize_context_id(context_id)
    try:
        values = _validate_embedding(prompt_embedding)
        mx, mlx_backend = _load_backend()
        embedding_arr = mx.array(values, dtype=mx.float32)
        return mlx_backend.simulate_spiking_retrieval(
            embedding=embedding_arr,
            context_id=context,
        )
    except ValueError as exc:
        LOGGER.warning("invalid prompt_embedding for context_id=%s: %s", context, exc)
        return f"invalid prompt_embedding: {exc}"
    except Exception as exc:
        LOGGER.exception("spiking attention query failed for context_id=%s", context)
        return f"spiking attention unavailable: {exc}"


@mcp.tool(
    annotations={
        "title": "Query Spiking Associative Memory From Text",
        "readOnlyHint": True,
    }
)
def query_spiking_attention_text(prompt: str, context_id: str = "default") -> str:
    """Return activated context tags using local deterministic text projection."""
    context = _sanitize_context_id(context_id)
    try:
        prompt_text = _validate_text(prompt, field_name="prompt")
        _, mlx_backend = _load_backend()
        return mlx_backend.simulate_spiking_text_retrieval(
            prompt=prompt_text,
            context_id=context,
        )
    except ValueError as exc:
        LOGGER.warning("invalid prompt text for context_id=%s: %s", context, exc)
        return f"invalid prompt: {exc}"
    except Exception as exc:
        LOGGER.exception("text spiking attention query failed for context_id=%s", context)
        return f"spiking attention unavailable: {exc}"


@mcp.tool()
def remember_spiking_context(
    tag: str,
    context_id: str = "default",
    prompt_embedding: list[float] | None = None,
    text: str = "",
    metadata: dict[str, Any] | None = None,
) -> str:
    """Persist a named context trace for future spiking associative recall."""
    context = _sanitize_context_id(context_id)
    try:
        mx, mlx_backend = _load_backend()
        values = _validate_optional_embedding(prompt_embedding)
        source_text = str(text or "").strip()
        if values is None:
            source_text = _validate_text(source_text)
            registration = mlx_backend.register_text_trace(
                tag=tag,
                text=source_text,
                context_id=context,
                metadata=metadata or {},
            )
        else:
            registration = mlx_backend.register_trace(
                tag=tag,
                embedding=mx.array(values, dtype=mx.float32),
                context_id=context,
                metadata=metadata or {},
                source_text=source_text,
            )
        registration["agent_deployment"] = _publish_tool_deployment(
            mlx_backend,
            context_id=context,
            event_type="remember-trace",
            summary=f"{registration['tag']} captured and published",
            payload={
                "tag": registration["tag"],
                "memory_id": registration["memory_id"],
                "source_text": source_text,
                "metadata": metadata or {},
                "spike_count": registration["spike_count"],
                "neuron_count": registration["neuron_count"],
            },
        )
        return json.dumps(registration, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid trace registration for context_id=%s: %s", context, exc)
        return json.dumps({"error": f"invalid trace: {exc}"}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("trace registration failed for context_id=%s", context)
        return json.dumps({"error": f"trace registration failed: {exc}"}, sort_keys=True)


@mcp.tool()
def set_spiking_attention_enabled(enabled: bool, context_id: str = "global") -> str:
    """Enable or disable SYNAPSE-S2 globally or for one context id."""
    context = _sanitize_context_id(context_id)
    try:
        _, mlx_backend = _load_backend()
        status = mlx_backend.set_enabled(bool(enabled), context_id=context)
        return json.dumps(status, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("toggle failed for context_id=%s", context)
        return json.dumps({"error": f"toggle failed: {exc}"}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Get SYNAPSE-S2 Status",
        "readOnlyHint": True,
    }
)
def get_spiking_attention_status(context_id: str = "default") -> str:
    """Return runtime health, toggle state, and memory-store status."""
    context = _sanitize_context_id(context_id)
    try:
        _, mlx_backend = _load_backend()
        status = mlx_backend.get_status(context_id=context)
        return json.dumps(status, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("status check failed for context_id=%s", context)
        return json.dumps({"error": f"status failed: {exc}"}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "List Persisted SYNAPSE-S2 Memory",
        "readOnlyHint": True,
    }
)
def list_spiking_memory(
    context_id: str = "default",
    limit: int = 50,
    include_vectors: bool = False,
) -> str:
    """List persisted local memory entries for a context."""
    context = _sanitize_context_id(context_id)
    try:
        bounded_limit = _validate_limit(limit)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.get_backend().list_memory(
            context_id=context,
            limit=bounded_limit,
            include_vectors=bool(include_vectors),
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid memory list request for context_id=%s: %s", context, exc)
        return json.dumps({"error": f"invalid memory list request: {exc}"}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("memory list failed for context_id=%s", context)
        return json.dumps({"error": f"memory list failed: {exc}"}, sort_keys=True)


@mcp.tool()
def ingest_spiking_memory_text(
    tag: str,
    text: str,
    context_id: str = "default",
    surprise_threshold: float = 0.62,
    min_segment_sentences: int = 2,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Segment long text into event memories and persist graph relationships."""
    context = _sanitize_context_id(context_id)
    try:
        source_text = _validate_text(text)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.ingest_text_events(
            text=source_text,
            context_id=context,
            source_tag=tag,
            surprise_threshold=float(surprise_threshold),
            min_segment_sentences=int(min_segment_sentences),
            metadata=metadata or {},
        )
        payload["agent_deployment"] = _publish_tool_deployment(
            mlx_backend,
            context_id=context,
            event_type="ingest-events",
            summary=(
                f"{payload['source_tag']} published "
                f"{payload['event_count']} event traces"
            ),
            payload={
                "source_tag": payload["source_tag"],
                "sequence_id": payload["sequence_id"],
                "source_text": source_text,
                "event_count": payload["event_count"],
                "relationship_count": payload["relationship_count"],
                "events": payload["events"],
                "relationships": payload["relationships"],
            },
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid event ingestion request for context_id=%s: %s", context, exc)
        return json.dumps({"error": f"invalid event ingestion request: {exc}"}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("event ingestion failed for context_id=%s", context)
        return json.dumps({"error": f"event ingestion failed: {exc}"}, sort_keys=True)


@mcp.tool()
def capture_spiking_conversation(
    text: str,
    context_id: str = "default",
    source_tag: str = "codex-session",
    speaker: str = "operator",
    surprise_threshold: float = 0.5,
    min_segment_sentences: int = 1,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Capture real operator/agent conversation notes as temporal event memories."""
    context = _sanitize_context_id(context_id)
    try:
        source_text = _validate_text(text)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.capture_conversation(
            text=source_text,
            context_id=context,
            source_tag=source_tag,
            speaker=speaker,
            surprise_threshold=float(surprise_threshold),
            min_segment_sentences=int(min_segment_sentences),
            metadata={
                **(metadata or {}),
                "source_surface": "mcp",
            },
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid conversation capture for context_id=%s: %s", context, exc)
        return json.dumps({"error": f"invalid conversation capture: {exc}"}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("conversation capture failed for context_id=%s", context)
        return json.dumps({"error": f"conversation capture failed: {exc}"}, sort_keys=True)


@mcp.tool()
def prune_spiking_memory(
    target_type: str,
    context_id: str = "default",
    memory_id: str = "",
    tag: str = "",
    relationship_id: str = "",
    event_id: int = 0,
    reason: str = "",
) -> str:
    """Prune one SYNAPSE-S2 memory node, edge, relationship mode, or deployment event."""
    context = _sanitize_context_id(context_id)
    try:
        _, mlx_backend = _load_backend()
        payload = mlx_backend.prune_memory(
            context_id=context,
            target_type=target_type,
            memory_id=memory_id,
            tag=tag,
            relationship_id=relationship_id,
            event_id=max(0, int(event_id)),
            reason=reason,
            source_surface="mcp",
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid memory prune for context_id=%s: %s", context, exc)
        return json.dumps({"error": f"invalid memory prune: {exc}"}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("memory prune failed for context_id=%s", context)
        return json.dumps({"error": f"memory prune failed: {exc}"}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "List SYNAPSE-S2 Memory Graph",
        "readOnlyHint": True,
    }
)
def list_spiking_memory_graph(context_id: str = "default", limit: int = 100) -> str:
    """List compact memory entries and their persisted relationship graph."""
    context = _sanitize_context_id(context_id)
    try:
        bounded_limit = _validate_limit(limit)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.list_memory_graph(
            context_id=context,
            limit=bounded_limit,
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid graph list request for context_id=%s: %s", context, exc)
        return json.dumps({"error": f"invalid graph list request: {exc}"}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("memory graph list failed for context_id=%s", context)
        return json.dumps({"error": f"memory graph list failed: {exc}"}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Pull SYNAPSE-S2 Context Deployments",
        "readOnlyHint": True,
    }
)
def pull_spiking_context_deployments(
    context_id: str = "default",
    since_event_id: int = 0,
    limit: int = 50,
) -> str:
    """Pull durable context-bus events published for connected local agents."""
    context = _sanitize_context_id(context_id)
    try:
        bounded_limit = _validate_limit(limit)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.list_context_events(
            context_id=context,
            since_event_id=max(0, int(since_event_id)),
            limit=bounded_limit,
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid context deployment pull for context_id=%s: %s", context, exc)
        return json.dumps({"error": f"invalid context deployment pull: {exc}"}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("context deployment pull failed for context_id=%s", context)
        return json.dumps({"error": f"context deployment pull failed: {exc}"}, sort_keys=True)


@mcp.tool()
def ack_spiking_context_deployments(
    agent_id: str,
    context_id: str = "default",
    last_event_id: int = 0,
) -> str:
    """Record that a local agent consumed context-bus events through last_event_id."""
    context = _sanitize_context_id(context_id)
    agent = _sanitize_agent_id(agent_id)
    try:
        _, mlx_backend = _load_backend()
        payload = mlx_backend.ack_context_events(
            context_id=context,
            agent_id=agent,
            last_event_id=max(0, int(last_event_id)),
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid context deployment ack for context_id=%s: %s", context, exc)
        return json.dumps({"error": f"invalid context deployment ack: {exc}"}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("context deployment ack failed for context_id=%s", context)
        return json.dumps({"error": f"context deployment ack failed: {exc}"}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "List SYNAPSE-S2 Context Deployment Cursors",
        "readOnlyHint": True,
    }
)
def list_spiking_context_cursors(context_id: str = "default", limit: int = 50) -> str:
    """List durable per-agent context-bus delivery cursors."""
    context = _sanitize_context_id(context_id)
    try:
        bounded_limit = _validate_limit(limit)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.list_context_cursors(
            context_id=context,
            limit=bounded_limit,
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid context cursor list for context_id=%s: %s", context, exc)
        return json.dumps({"error": f"invalid context cursor list: {exc}"}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("context cursor list failed for context_id=%s", context)
        return json.dumps({"error": f"context cursor list failed: {exc}"}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Profile SYNAPSE-S2 Runtime Resources",
        "readOnlyHint": False,
    }
)
def profile_spiking_resources(
    benchmark_quick_prune: bool = False,
    target_min_mb: float = 61.0,
    target_max_mb: float = 138.0,
) -> str:
    """Report topology memory estimates and optional quick-pruning timing."""
    try:
        _, mlx_backend = _load_backend()
        payload = mlx_backend.resource_profile(
            benchmark_quick_prune=bool(benchmark_quick_prune),
            target_min_mb=float(target_min_mb),
            target_max_mb=float(target_max_mb),
        )
        return json.dumps(payload, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("resource profile failed")
        return json.dumps({"error": f"resource profile failed: {exc}"}, sort_keys=True)


@mcp.tool()
def export_spiking_memory(
    context_id: str = "default",
    output_path: str = "",
) -> str:
    """Export persisted memory as JSON, optionally writing to output_path."""
    context = _sanitize_context_id(context_id)
    try:
        path = _optional_output_path(output_path, allowed_suffixes={".json"})
        _, mlx_backend = _load_backend()
        payload = mlx_backend.export_memory(path=path, context_id=context)
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid memory export request for context_id=%s: %s", context, exc)
        return json.dumps({"error": f"invalid memory export request: {exc}"}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("memory export failed for context_id=%s", context)
        return json.dumps({"error": f"memory export failed: {exc}"}, sort_keys=True)


@mcp.tool()
def backup_spiking_memory(output_path: str = "") -> str:
    """Create a SQLite backup of the durable SYNAPSE-S2 memory store."""
    try:
        path = _optional_output_path(
            output_path,
            allowed_suffixes={".db", ".sqlite", ".sqlite3"},
        )
        _, mlx_backend = _load_backend()
        payload = mlx_backend.backup_memory(path=path)
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid memory backup request: %s", exc)
        return json.dumps({"error": f"invalid memory backup request: {exc}"}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("memory backup failed")
        return json.dumps({"error": f"memory backup failed: {exc}"}, sort_keys=True)


@mcp.tool()
def trigger_sleep_consolidation() -> str:
    """Run deep-sleep consolidation for local spiking memory state."""
    try:
        _, mlx_backend = _load_backend()
        status = mlx_backend.run_deep_sleep_consolidation()
        return json.dumps(status, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("sleep consolidation failed")
        return f"sleep consolidation failed: {exc}"


@mcp.tool()
def trigger_idle_maintenance(force_deep_sleep: bool = False) -> str:
    """Run due maintenance, or force idle deep-sleep consolidation."""
    try:
        _, mlx_backend = _load_backend()
        status = mlx_backend.run_idle_maintenance(
            force_deep_sleep=bool(force_deep_sleep)
        )
        return json.dumps(status, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("idle maintenance failed")
        return json.dumps({"error": f"idle maintenance failed: {exc}"}, sort_keys=True)


if __name__ == "__main__":
    mcp.run()

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


if __name__ == "__main__":
    mcp.run()

from __future__ import annotations

import json
import logging
import os
import re
import sys
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

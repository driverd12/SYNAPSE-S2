from __future__ import annotations

import json
import logging
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Annotated, Any

from pydantic import BeforeValidator, WithJsonSchema

from redaction import (
    SECRET_SAFE_LOG_FORMAT,
    install_secret_safe_formatters,
    reject_sensitive_identifier,
    safe_public_error,
)
from token_contracts import (
    COMPACT_SOURCE_LIMITS,
    DEFAULT_RESPONSE_BYTES,
    TOKEN_CONTRACT_OUTPUT_SCHEMA,
    ResponseContractError,
    compact_agent_event_limit,
    normalize_response_budget,
    normalize_response_mode,
    project_response,
    response_error,
)

try:
    from fastmcp import FastMCP
    from fastmcp.tools import FunctionTool, ToolResult
    from mcp.types import TextContent
except Exception as fastmcp_exc:  # pragma: no cover - host dependent
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[no-redef]
    except Exception as mcp_exc:  # pragma: no cover - host dependent
        FastMCP = None  # type: ignore[assignment,misc]
        FunctionTool = None  # type: ignore[assignment,misc]
        ToolResult = None  # type: ignore[assignment,misc]
        TextContent = None  # type: ignore[assignment,misc]
        _FASTMCP_IMPORT_ERROR: Exception | None = mcp_exc
        _FASTMCP_PRIMARY_ERROR: Exception | None = fastmcp_exc
    else:
        FunctionTool = None  # type: ignore[assignment,misc]
        ToolResult = None  # type: ignore[assignment,misc]
        TextContent = None  # type: ignore[assignment,misc]
        _FASTMCP_IMPORT_ERROR = None
        _FASTMCP_PRIMARY_ERROR = fastmcp_exc
else:
    _FASTMCP_IMPORT_ERROR = None
    _FASTMCP_PRIMARY_ERROR = None

LOGGER = logging.getLogger("synapse_s2.mcp")
logging.basicConfig(
    level=os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper(),
    stream=sys.stderr,
    format=SECRET_SAFE_LOG_FORMAT,
    force=True,
)
install_secret_safe_formatters(logging.getLogger().handlers)

MAX_TOOL_EMBEDDING_DIMS = 32_768
MCP_DELIVERY_INSTANCE_ID = f"mcp-{os.getpid()}-{uuid.uuid4().hex}"
MCP_COMPACT_SAFETY_SUMMARY_BYTES = 4_096
MCP_FULL_SAFETY_SUMMARY_BYTES = 131_072
MCP_SAFETY_SUMMARY_PREFIX = "SYNAPSE-S2 safety summary: "
CONTEXT_ID_RE = re.compile(r"[^A-Za-z0-9_.:-]+")
AGENT_ID_RE = re.compile(r"[^A-Za-z0-9_.:@-]+")
_SCHEMA_INVALID_STRING = "[INVALID_STRING]"
_SCHEMA_INVALID_INTEGER = "[INVALID_INTEGER]"
_SCHEMA_INVALID_BOOLEAN = "[INVALID_BOOLEAN]"


def _schema_safe_string(value: Any) -> str:
    return value if isinstance(value, str) else _SCHEMA_INVALID_STRING


def _schema_safe_integer(value: Any) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            reject_sensitive_identifier(value, field="integer input")
        except ValueError:
            return _SCHEMA_INVALID_INTEGER
        return value
    return _SCHEMA_INVALID_INTEGER


def _schema_safe_boolean(value: Any) -> bool | str:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            reject_sensitive_identifier(value, field="boolean input")
        except ValueError:
            return _SCHEMA_INVALID_BOOLEAN
        if value.strip().casefold() in {"true", "false"}:
            return value
    return _SCHEMA_INVALID_BOOLEAN


def _schema_safe_response_mode(value: Any) -> str:
    return value if isinstance(value, str) else "[INVALID_RESPONSE_MODE]"


def _schema_safe_response_budget(value: Any) -> int | str:
    if isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    return "[INVALID_RESPONSE_BUDGET]"


ResponseModeInput = Annotated[
    str,
    BeforeValidator(_schema_safe_response_mode),
    WithJsonSchema(
        {
            "type": "string",
            "enum": ["", "compact", "full"],
            "description": "Bounded response profile; empty uses the installed compact default.",
        }
    ),
]
ResponseBudgetInput = Annotated[
    int | str,
    BeforeValidator(_schema_safe_response_budget),
    WithJsonSchema(
        {
            "oneOf": [
                {"type": "integer", "minimum": 4096, "maximum": 131072},
                {"type": "string", "pattern": "^(?:|[0-9]+)$"},
            ],
            "description": "Exact UTF-8 JSON ceiling in bytes; empty uses the installed default.",
        }
    ),
]
ToolStringInput = Annotated[
    str,
    BeforeValidator(_schema_safe_string),
    WithJsonSchema({"type": "string"}),
]
ToolIntegerInput = Annotated[
    int | str,
    BeforeValidator(_schema_safe_integer),
    WithJsonSchema({"type": "integer", "minimum": 1, "maximum": 500}),
]
ToolBooleanInput = Annotated[
    bool | str,
    BeforeValidator(_schema_safe_boolean),
    WithJsonSchema({"type": "boolean"}),
]


_CONTRACT_TOOL_ARGUMENTS: dict[str, frozenset[str]] = {
    "list_spiking_memory": frozenset(
        {
            "context_id",
            "limit",
            "include_vectors",
            "response_mode",
            "max_response_bytes",
        }
    ),
    "list_spiking_memory_graph": frozenset(
        {
            "context_id",
            "limit",
            "response_mode",
            "max_response_bytes",
        }
    ),
    "hydrate_spiking_agent_context": frozenset(
        {
            "agent_id",
            "context_id",
            "prompt",
            "limit",
            "graph_limit",
            "response_mode",
            "max_response_bytes",
        }
    ),
    "get_spiking_cortex_state": frozenset(
        {
            "agent_id",
            "context_id",
            "limit",
            "response_mode",
            "max_response_bytes",
        }
    ),
}
_CONTRACT_TOOL_SURFACES = {
    "list_spiking_memory": "memory-list",
    "list_spiking_memory_graph": "memory-graph",
    "hydrate_spiking_agent_context": "agent-hydration",
    "get_spiking_cortex_state": "cortex-state",
}


def _undeclared_contract_argument_count(
    arguments: Any,
    *,
    allowed: frozenset[str],
) -> int:
    if arguments is None:
        return 0
    if not isinstance(arguments, dict):
        return 1
    return sum(
        1
        for key in arguments
        if not isinstance(key, str) or key not in allowed
    )


if FastMCP is not None:

    class _SecretSafeFastMCP(FastMCP):
        """Reject unknown contract arguments before FastMCP validation can echo them."""

        async def call_tool(
            self,
            name: str,
            arguments: dict[str, Any] | None = None,
            *,
            version: Any = None,
            run_middleware: bool = True,
            task_meta: Any = None,
        ) -> Any:
            allowed = _CONTRACT_TOOL_ARGUMENTS.get(name)
            if allowed is not None:
                invalid_count = _undeclared_contract_argument_count(
                    arguments,
                    allowed=allowed,
                )
                if invalid_count:
                    # Never render the rejected key or value. FastMCP's default
                    # Pydantic error includes the raw input in its warning log.
                    LOGGER.warning(
                        "rejected %d undeclared argument(s) for contracted tool %s",
                        invalid_count,
                        name,
                    )
                    return _contract_prevalidation_error_result(
                        tool_name=name,
                        arguments=arguments,
                    )
            return await super().call_tool(
                name,
                arguments,
                version=version,
                run_middleware=run_middleware,
                task_meta=task_meta,
            )

        async def _call_tool_mcp(self, key: str, arguments: dict[str, Any]) -> Any:
            """Handle the real MCP transport without logging raw tool arguments."""

            import mcp.types as mcp_types
            from fastmcp.exceptions import DisabledError, NotFoundError
            from fastmcp.server.tasks.config import TaskMeta
            from fastmcp.utilities.versions import VersionSpec

            # FastMCP's default handler logs the complete argument mapping at
            # DEBUG before call_tool() or Pydantic validation. Log only a
            # content-free event so debug operation cannot become a secret sink.
            LOGGER.debug("MCP transport tool call received")
            try:
                version_str: str | None = None
                task_meta: TaskMeta | None = None
                try:
                    context = self._mcp_server.request_context
                    if context.meta:
                        meta = context.meta.model_dump(exclude_none=True)
                        version_str = meta.get("fastmcp", {}).get("version")
                    if context.experimental.is_task:
                        mcp_task_meta = context.experimental.task_metadata
                        task_meta_dict = mcp_task_meta.model_dump(exclude_none=True)
                        task_meta = TaskMeta(ttl=task_meta_dict.get("ttl"))
                except (AttributeError, LookupError):
                    pass

                version = VersionSpec(eq=version_str) if version_str else None
                result = await self.call_tool(
                    key,
                    arguments,
                    version=version,
                    task_meta=task_meta,
                )
                if isinstance(result, mcp_types.CreateTaskResult):
                    return result
                return result.to_mcp_result()
            except DisabledError:
                raise NotFoundError("Unknown or disabled tool") from None
            except NotFoundError:
                raise NotFoundError("Unknown or disabled tool") from None


if FunctionTool is not None:

    class _SecretSafeContractFunctionTool(FunctionTool):
        """Keep registry-level tool execution behind the same closed schema."""

        async def run(self, arguments: dict[str, Any]) -> Any:
            allowed = _CONTRACT_TOOL_ARGUMENTS[self.name]
            invalid_count = _undeclared_contract_argument_count(
                arguments,
                allowed=allowed,
            )
            if invalid_count:
                LOGGER.warning(
                    "rejected %d undeclared argument(s) for contracted tool %s",
                    invalid_count,
                    self.name,
                )
                return _contract_prevalidation_error_result(
                    tool_name=self.name,
                    arguments=arguments,
                )
            return await super().run(arguments)


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
            message = (
                f"{message} Import error: "
                f"{safe_public_error(_FASTMCP_IMPORT_ERROR, fallback='dependency import failed')}"
            )
        LOGGER.error(message)
        raise SystemExit(1)


mcp = (
    _SecretSafeFastMCP(name="SYNAPSE-S2 Spiking Attention MCP Server")
    if FastMCP is not None
    else _UnavailableMCP()
)


def _public_error(label: str, error: BaseException) -> str:
    """Preserve the public error label while bounding and redacting details."""

    return f"{label}: {safe_public_error(error, fallback=label)}"


def _token_response_options(
    *,
    surface: str,
    response_mode: Any,
    max_response_bytes: Any,
) -> tuple[str, int]:
    budget = _token_response_budget(
        surface=surface,
        max_response_bytes=max_response_bytes,
    )
    configured_mode = os.getenv("SYNAPSE_S2_DEFAULT_RESPONSE_MODE", "compact")
    mode = normalize_response_mode(response_mode, default=configured_mode)
    return mode, budget


def _token_response_budget(
    *,
    surface: str,
    max_response_bytes: Any,
) -> int:
    configured_budget: Any = os.getenv("SYNAPSE_S2_MAX_RESPONSE_BYTES", "")
    requested_budget = (
        max_response_bytes
        if max_response_bytes not in (None, "")
        else configured_budget
    )
    budget = normalize_response_budget(
        requested_budget,
        default_bytes=DEFAULT_RESPONSE_BYTES[surface],
    )
    return budget


def _token_error_budget(*, surface: str) -> int:
    """Return the installed valid ceiling when a requested ceiling is malformed."""

    configured_budget: Any = os.getenv("SYNAPSE_S2_MAX_RESPONSE_BYTES", "")
    try:
        return normalize_response_budget(
            configured_budget,
            default_bytes=DEFAULT_RESPONSE_BYTES[surface],
        )
    except ResponseContractError:
        return DEFAULT_RESPONSE_BYTES[surface]


def _contract_prevalidation_error_result(
    *,
    tool_name: str,
    arguments: Any,
) -> Any:
    """Build a bounded error without inspecting or reflecting rejected inputs."""

    surface = _CONTRACT_TOOL_SURFACES[tool_name]
    budget = _token_error_budget(surface=surface)
    if isinstance(arguments, dict):
        requested_budget = arguments.get("max_response_bytes", "")
        try:
            budget = min(
                budget,
                normalize_response_budget(
                    requested_budget,
                    default_bytes=budget,
                ),
            )
        except ResponseContractError:
            pass
    return _contract_tool_result(
        _contract_error(
            surface,
            ResponseContractError("request contains undeclared tool arguments"),
            max_response_bytes=budget,
        )
    )


def _contract_error(
    surface: str,
    error: BaseException,
    *,
    max_response_bytes: int | None = None,
) -> dict[str, Any]:
    return response_error(
        operation=surface,
        error=error,
        max_response_bytes=max_response_bytes,
    )


def _summary_text(value: Any, max_characters: int) -> str:
    text = str(value or "")
    if len(text) <= max_characters:
        return text
    if max_characters <= 0:
        return ""
    if max_characters == 1:
        # A one-byte marker keeps the final receipt-decision fallback bounded
        # even when the source evidence is entirely four-byte Unicode.
        return "~"
    return text[: max_characters - 1] + "…"


def _mcp_safety_summary_text(
    summary: dict[str, Any],
    *,
    profile: str,
) -> str:
    ceiling = (
        MCP_FULL_SAFETY_SUMMARY_BYTES
        if profile == "full"
        else MCP_COMPACT_SAFETY_SUMMARY_BYTES
    )
    summary["max_bytes"] = ceiling
    delivery = summary.get("delivery")
    receipts = (
        delivery.get("receipts", [])
        if isinstance(delivery, dict) and isinstance(delivery.get("receipts"), list)
        else []
    )
    original_text = [
        {
            "event_type": str(item.get("event_type") or ""),
            "source_surface": str(item.get("source_surface") or ""),
            "summary": str(item.get("summary") or ""),
        }
        for item in receipts
        if isinstance(item, dict)
    ]
    cap_profiles = (
        (
            (64, 64, 192),
            (48, 48, 128),
            (32, 32, 96),
            (24, 24, 64),
            (16, 16, 48),
            (8, 8, 32),
            (4, 4, 8),
            (2, 2, 4),
            (1, 1, 1),
            (0, 0, 0),
        )
        if profile != "full"
        else (
            (96, 96, 256),
            (64, 64, 192),
            (48, 48, 128),
            (32, 32, 96),
            (16, 16, 48),
            (8, 8, 24),
            (4, 4, 8),
            (2, 2, 4),
            (1, 1, 1),
        )
    )
    if not receipts:
        cap_profiles = ((0, 0, 0),)

    for event_type_cap, source_cap, summary_cap in cap_profiles:
        omitted_characters = 0
        for item, original in zip(receipts, original_text, strict=True):
            for field, cap in (
                ("event_type", event_type_cap),
                ("source_surface", source_cap),
                ("summary", summary_cap),
            ):
                shortened = _summary_text(original[field], cap)
                item[field] = shortened
                omitted_characters += max(0, len(original[field]) - len(shortened))
        if isinstance(delivery, dict):
            delivery["evidence_text_truncated"] = omitted_characters > 0
            delivery["omitted_text_characters"] = omitted_characters
            delivery["receipt_decision_supported"] = all(
                bool(item.get("event_type"))
                and bool(item.get("source_surface"))
                and bool(item.get("summary"))
                for item in receipts
                if isinstance(item, dict)
            )
            if not delivery["receipt_decision_supported"]:
                continue
        rendered = MCP_SAFETY_SUMMARY_PREFIX + json.dumps(
            summary,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        if len(rendered.encode("utf-8")) <= ceiling:
            return rendered

    raise ResponseContractError(
        "MCP safety summary cannot preserve every receipt identity within its byte ceiling"
    )


def _contract_tool_result(payload: dict[str, Any]) -> Any:
    if ToolResult is None or TextContent is None:  # pragma: no cover - legacy fallback
        return payload
    operation = str(payload.get("operation") or "response")
    warnings = [
        {
            "code": _summary_text(item.get("code") or "warning", 96),
            "severity": _summary_text(item.get("severity") or "warning", 24),
            "action_required": bool(item.get("action_required", False)),
        }
        for item in payload.get("warnings", [])
        if isinstance(item, dict)
    ]
    continuation = payload.get("continuation")
    summary: dict[str, Any] = {
        "schema": "synapse-s2.mcp-safety-summary.v1",
        "operation": operation,
        "ok": bool(payload.get("ok")),
        "structuredContent_required": True,
        "warnings": warnings,
        "continuation": {
            key: _summary_text(continuation.get(key), 240)
            for key in ("strategy", "instruction")
            if isinstance(continuation, dict) and continuation.get(key) not in (None, "")
        },
    }
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    profile = str(
        (payload.get("response_contract") or {}).get("profile") or "compact"
    )
    source_data = (
        data.get("payload")
        if profile == "full" and isinstance(data.get("payload"), dict)
        else data
    )
    error = data.get("error") if isinstance(data.get("error"), dict) else None
    if error is not None:
        summary["error"] = {
            "code": _summary_text(error.get("code"), 96),
            "message": _summary_text(error.get("message"), 320),
            "retryable": bool(error.get("retryable", False)),
        }
    if operation == "agent-hydration":
        if profile == "full":
            full_events = {
                int(item.get("event_id") or 0): item
                for item in source_data.get("events", [])
                if isinstance(item, dict)
            }
            deployments = [
                {
                    **item,
                    "event": full_events.get(int(item.get("event_id") or 0), {}),
                }
                for item in source_data.get("deliveries", [])
                if isinstance(item, dict)
            ]
            delivery = {
                "observed": bool(source_data.get("claim_events")),
                "ack_required": bool(source_data.get("ack_required")),
                "has_more": bool(source_data.get("has_more_events")),
                "blocking": source_data.get("blocking_delivery"),
                "deployments": deployments,
            }
        else:
            delivery = (
                source_data.get("delivery")
                if isinstance(source_data.get("delivery"), dict)
                else {}
            )
        summary["delivery"] = {
            "observed": bool(delivery.get("observed")),
            "ack_required": bool(delivery.get("ack_required")),
            "has_more": bool(delivery.get("has_more")),
            "blocking": delivery.get("blocking"),
            "receipts": [
                {
                    "receipt_id": str(item.get("receipt_id") or ""),
                    "event_id": int(item.get("event_id") or 0),
                    "event_type": _summary_text(
                        (item.get("event") or {}).get("event_type") or ""
                        , 512
                    )
                    if isinstance(item.get("event"), dict)
                    else "",
                    "source_surface": _summary_text(
                        (item.get("event") or {}).get("source_surface") or ""
                        , 512
                    )
                    if isinstance(item.get("event"), dict)
                    else "",
                    "summary": _summary_text(
                        (item.get("event") or {}).get("summary") or "", 2_048
                    )
                    if isinstance(item.get("event"), dict)
                    else "",
                    "trust": "untrusted-event-evidence",
                }
                for item in delivery.get("deployments", [])
                if isinstance(item, dict)
            ],
        }
    elif operation == "cortex-state":
        if profile == "full":
            sessions = [
                item
                for item in source_data.get("active_sessions", [])
                if isinstance(item, dict)
            ]
            latest = sessions[0] if sessions else {}
            actionable_codes = sorted(
                {
                    str(warning.get("code") or "cortex-governor-warning")
                    for session in sessions
                    for warning in session.get("last_warnings", [])
                    if isinstance(warning, dict)
                    and (
                        bool(warning.get("action_required"))
                        or str(warning.get("severity") or "").casefold()
                        in {"critical", "high"}
                    )
                }
            )
            summary["governance"] = {
                "latest_decision": _summary_text(latest.get("last_decision"), 160),
                "action_required": bool(actionable_codes),
                "warning_codes": [_summary_text(code, 96) for code in actionable_codes],
            }
        else:
            summary["governance"] = (
                source_data.get("governance")
                if isinstance(source_data.get("governance"), dict)
                else {}
            )
    guidance = _mcp_safety_summary_text(summary, profile=profile)
    return ToolResult(
        content=[TextContent(type="text", text=guidance)],
        structured_content=payload,
    )


def _sanitize_context_id(context_id: str) -> str:
    raw = reject_sensitive_identifier(
        context_id or "default",
        field="context_id",
    ).strip()
    cleaned = CONTEXT_ID_RE.sub("_", raw).strip("._-:")
    return (cleaned or "default")[:128]


def _sanitize_agent_id(agent_id: str) -> str:
    raw = reject_sensitive_identifier(agent_id or "", field="agent_id").strip()
    cleaned = AGENT_ID_RE.sub("_", raw).strip("._-:@")
    return (cleaned or "unknown-agent")[:128]


def _sanitize_delivery_agent_id(agent_id: str) -> str:
    return _sanitize_agent_id(agent_id).casefold()


def _delivery_agent_id(requested_agent_id: str) -> str:
    configured = str(os.getenv("SYNAPSE_S2_CLIENT_AGENT_ID", "") or "").strip()
    requested = str(requested_agent_id or "").strip()
    if configured:
        configured_agent = _sanitize_delivery_agent_id(configured)
        if requested and _sanitize_delivery_agent_id(requested) != configured_agent:
            raise ValueError(
                "agent_id must match the MCP server's configured delivery identity"
            )
        return configured_agent
    if not requested:
        raise ValueError(
            "agent_id is required when SYNAPSE_S2_CLIENT_AGENT_ID is not configured"
        )
    if str(
        os.getenv("SYNAPSE_S2_ALLOW_UNCONFIGURED_DELIVERY_IDENTITY", "") or ""
    ).strip().lower() not in {"1", "true", "yes", "on"}:
        raise ValueError(
            "delivery tools require SYNAPSE_S2_CLIENT_AGENT_ID; "
            "set SYNAPSE_S2_ALLOW_UNCONFIGURED_DELIVERY_IDENTITY=1 only for isolated development"
        )
    return _sanitize_delivery_agent_id(requested)


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


def _validate_tool_string(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or value == _SCHEMA_INVALID_STRING:
        raise ValueError(f"{field_name} must be a string")
    return value


def _validate_tool_boolean(value: Any, *, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value != _SCHEMA_INVALID_BOOLEAN:
        normalized = value.strip().casefold()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    raise ValueError(f"{field_name} must be a boolean")


def _validate_limit(limit: Any) -> int:
    if isinstance(limit, bool) or limit == _SCHEMA_INVALID_INTEGER:
        raise ValueError("limit must be an integer")
    if isinstance(limit, str):
        try:
            reject_sensitive_identifier(limit, field="limit")
        except ValueError as exc:
            raise ValueError("limit must be an integer") from exc
    try:
        value = int(limit)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    return min(max(value, 1), 500)


def _validate_recall_scope(recall_scope: str) -> str:
    normalized = str(recall_scope or "local").strip().lower()
    if normalized == "broad":
        normalized = "all"
    if normalized not in {"local", "connected", "all"}:
        raise ValueError("recall_scope must be local, connected, or all")
    return normalized


def _parse_json_object(raw: str, *, field_name: str) -> dict[str, Any]:
    value = str(raw or "").strip()
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{field_name} must be a JSON object") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{field_name} must be a JSON object")
    return parsed


def _validate_string_list(values: list[str] | None, *, field_name: str) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError(f"{field_name} must be a list of strings")
    cleaned: list[str] = []
    for index, item in enumerate(values):
        text = " ".join(str(item or "").split())
        if not text:
            continue
        if len(text) > 260:
            raise ValueError(f"{field_name}[{index}] exceeds 260 characters")
        cleaned.append(text)
        if len(cleaned) > 24:
            raise ValueError(f"{field_name} exceeds 24 entries")
    return cleaned


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
    value = reject_sensitive_identifier(value, field="output_path")
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


def _required_output_directory(output_path: str | None) -> str:
    value = str(output_path or "").strip()
    if not value:
        raise ValueError("output_directory is required")
    if len(value) > 4096:
        raise ValueError("output_directory exceeds 4096 characters")
    value = reject_sensitive_identifier(value, field="output_directory")
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
            f"output_directory must stay within export root {resolved_root}"
        ) from exc
    if resolved_candidate == resolved_root:
        raise ValueError("output_directory must be a new child of the export root")
    return str(resolved_candidate)


def _load_backend():
    import mlx.core as mx
    import mlx_backend

    return mx, mlx_backend


def _load_capture_daemon():
    import capture_daemon

    return capture_daemon


def _load_transcript_capture():
    import transcript_capture

    return transcript_capture


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
    recall_scope: str = "local",
) -> str:
    """Return context-local, approved connected, or all-context memory matches."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        values = _validate_embedding(prompt_embedding)
        scope = _validate_recall_scope(recall_scope)
        mx, mlx_backend = _load_backend()
        embedding_arr = mx.array(values, dtype=mx.float32)
        return mlx_backend.simulate_spiking_retrieval(
            embedding=embedding_arr,
            context_id=context,
            recall_scope=scope,
        )
    except ValueError as exc:
        LOGGER.warning("invalid prompt_embedding for context_id=%s: %s", context, exc)
        return _public_error("invalid prompt_embedding", exc)
    except Exception as exc:
        LOGGER.exception("spiking attention query failed for context_id=%s", context)
        return _public_error("spiking attention unavailable", exc)


@mcp.tool(
    annotations={
        "title": "Query Spiking Associative Memory From Text",
        "readOnlyHint": True,
    }
)
def query_spiking_attention_text(
    prompt: str,
    context_id: str = "default",
    recall_scope: str = "local",
) -> str:
    """Return scoped context matches using the configured local text embedding provider."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        prompt_text = _validate_text(prompt, field_name="prompt")
        scope = _validate_recall_scope(recall_scope)
        _, mlx_backend = _load_backend()
        return mlx_backend.simulate_spiking_text_retrieval(
            prompt=prompt_text,
            context_id=context,
            recall_scope=scope,
        )
    except ValueError as exc:
        LOGGER.warning("invalid prompt text for context_id=%s: %s", context, exc)
        return _public_error("invalid prompt", exc)
    except Exception as exc:
        LOGGER.exception("text spiking attention query failed for context_id=%s", context)
        return _public_error("spiking attention unavailable", exc)


@mcp.tool(
    annotations={
        "title": "List SYNAPSE-S2 Namespace Galaxy",
        "readOnlyHint": True,
    }
)
def list_spiking_namespace_map(
    context_id: str = "default",
    limit: int = 500,
    include_suggestions: bool = True,
) -> str:
    """List every namespace, approved bridge, and read-only bridge suggestion."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        bounded_limit = _validate_limit(limit)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.list_namespace_map(
            context_id=context,
            limit=bounded_limit,
            include_suggestions=bool(include_suggestions),
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid namespace map request for context_id=%s: %s", context, exc)
        return json.dumps({"error": _public_error("invalid namespace map request", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("namespace map failed for context_id=%s", context)
        return json.dumps({"error": _public_error("namespace map failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Approve SYNAPSE-S2 Namespace Link",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
    }
)
def approve_spiking_namespace_link(
    source_context_id: str,
    target_context_id: str,
    relation_type: str = "related",
    weight: float = 1.0,
    evidence: dict[str, Any] | None = None,
    direction: str = "bidirectional",
    approved_by: str = "operator",
    confirm: bool = False,
) -> str:
    """Persist one typed link after explicit confirmation; never copies memories."""
    source = "unknown"
    target = "unknown"
    try:
        source = _sanitize_context_id(source_context_id)
        target = _sanitize_context_id(target_context_id)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.approve_namespace_link(
            source_context_id=source,
            target_context_id=target,
            relation_type=relation_type,
            weight=float(weight),
            evidence=evidence or {},
            direction=direction,
            approved_by=_sanitize_agent_id(approved_by),
            confirm=bool(confirm),
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid namespace link request for %s -> %s: %s", source, target, exc)
        return json.dumps({"error": _public_error("invalid namespace link request", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("namespace link approval failed for %s -> %s", source, target)
        return json.dumps({"error": _public_error("namespace link approval failed", exc)}, sort_keys=True)


@mcp.tool()
def remember_spiking_context(
    tag: str,
    context_id: str = "default",
    prompt_embedding: list[float] | None = None,
    text: str = "",
    metadata: dict[str, Any] | None = None,
) -> str:
    """Persist a named context trace for future spiking associative recall."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
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
        return json.dumps({"error": _public_error("invalid trace", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("trace registration failed for context_id=%s", context)
        return json.dumps({"error": _public_error("trace registration failed", exc)}, sort_keys=True)


@mcp.tool()
def set_spiking_attention_enabled(enabled: bool, context_id: str = "global") -> str:
    """Enable or disable SYNAPSE-S2 globally or for one context id."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        _, mlx_backend = _load_backend()
        status = mlx_backend.set_enabled(bool(enabled), context_id=context)
        return json.dumps(status, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("toggle failed for context_id=%s", context)
        return json.dumps({"error": _public_error("toggle failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Get SYNAPSE-S2 Status",
        "readOnlyHint": True,
    }
)
def get_spiking_attention_status(context_id: str = "default") -> str:
    """Return runtime health, toggle state, and memory-store status."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        _, mlx_backend = _load_backend()
        status = mlx_backend.get_status(context_id=context)
        return json.dumps(status, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("status check failed for context_id=%s", context)
        return json.dumps({"error": _public_error("status failed", exc)}, sort_keys=True)


@mcp.tool(
    output_schema=TOKEN_CONTRACT_OUTPUT_SCHEMA,
    annotations={
        "title": "List Persisted SYNAPSE-S2 Memory",
        "readOnlyHint": True,
    }
)
def list_spiking_memory(
    context_id: ToolStringInput = "default",
    limit: ToolIntegerInput = 50,
    include_vectors: ToolBooleanInput = False,
    response_mode: ResponseModeInput = "",
    max_response_bytes: ResponseBudgetInput = "",
) -> Any:
    """List persisted memory using a compact or explicitly full response contract."""
    context = "unknown"
    budget: int | None = _token_error_budget(surface="memory-list")
    try:
        budget = _token_response_budget(
            surface="memory-list",
            max_response_bytes=max_response_bytes,
        )
        configured_mode = os.getenv("SYNAPSE_S2_DEFAULT_RESPONSE_MODE", "compact")
        mode = normalize_response_mode(response_mode, default=configured_mode)
        context = _sanitize_context_id(
            _validate_tool_string(context_id, field_name="context_id")
        )
        bounded_limit = _validate_limit(limit)
        include_vector_data = _validate_tool_boolean(
            include_vectors,
            field_name="include_vectors",
        )
        if mode == "compact" and include_vector_data:
            raise ResponseContractError(
                "compact memory responses do not support vectors; use full mode"
            )
        effective_limit = (
            min(bounded_limit, COMPACT_SOURCE_LIMITS["memory-list"])
            if mode == "compact"
            else bounded_limit
        )
        _, mlx_backend = _load_backend()
        payload = mlx_backend.get_backend().list_memory(
            context_id=context,
            limit=effective_limit,
            include_vectors=include_vector_data,
        )
        payload["_response_source"] = {
            "requested_limit": bounded_limit,
            "effective_limit": effective_limit,
        }
        return _contract_tool_result(
            project_response(
                "memory-list",
                payload,
                mode=mode,
                max_response_bytes=budget,
            )
        )
    except ValueError as exc:
        LOGGER.warning("invalid memory list request for context_id=%s: %s", context, exc)
        return _contract_tool_result(
            _contract_error("memory-list", exc, max_response_bytes=budget)
        )
    except Exception as exc:
        LOGGER.exception("memory list failed for context_id=%s", context)
        return _contract_tool_result(
            _contract_error("memory-list", exc, max_response_bytes=budget)
        )


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
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
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
        return json.dumps({"error": _public_error("invalid event ingestion request", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("event ingestion failed for context_id=%s", context)
        return json.dumps({"error": _public_error("event ingestion failed", exc)}, sort_keys=True)


@mcp.tool()
def capture_spiking_conversation(
    text: str,
    context_id: str = "default",
    source_tag: str = "codex-session",
    speaker: str = "operator",
    surprise_threshold: float = 0.5,
    min_segment_sentences: int = 1,
    metadata: dict[str, Any] | None = None,
    capture_id: str = "",
) -> str:
    """Capture real operator/agent conversation notes as temporal event memories."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
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
            capture_id=str(capture_id or "") or None,
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid conversation capture for context_id=%s: %s", context, exc)
        return json.dumps({"error": _public_error("invalid conversation capture", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("conversation capture failed for context_id=%s", context)
        return json.dumps({"error": _public_error("conversation capture failed", exc)}, sort_keys=True)


@mcp.tool()
def drop_spiking_capture_inbox(
    text: str,
    context_id: str = "default",
    source_tag: str = "codex-session",
    speaker: str = "operator",
    metadata: dict[str, Any] | None = None,
    capture_id: str = "",
) -> str:
    """Drop opt-in session text into the local capture inbox for sidecar ingestion."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        source_text = _validate_text(text)
        capture_daemon = _load_capture_daemon()
        resolved_capture_id = str(capture_id or "") or capture_daemon.new_capture_id()
        drop_path = capture_daemon.write_capture_drop(
            context_id=context,
            source_tag=source_tag,
            speaker=speaker,
            text=source_text,
            metadata={
                **(metadata or {}),
                "source_surface": "mcp-inbox",
            },
            capture_id=resolved_capture_id,
        )
        return json.dumps(
            {
                "action": "drop-spiking-capture-inbox",
                "context_id": context,
                "drop_path": str(drop_path),
                "capture_id": resolved_capture_id,
                "capture_protocol": "capture.v2",
            },
            sort_keys=True,
        )
    except ValueError as exc:
        LOGGER.warning("invalid capture inbox drop for context_id=%s: %s", context, exc)
        return json.dumps({"error": _public_error("invalid capture inbox drop", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("capture inbox drop failed for context_id=%s", context)
        return json.dumps({"error": _public_error("capture inbox drop failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Get SYNAPSE-S2 Capture Inbox Status",
        "readOnlyHint": True,
    }
)
def get_spiking_capture_inbox_status() -> str:
    """Return pending/processed/error counts for the local capture inbox sidecar."""
    try:
        capture_daemon = _load_capture_daemon()
        return json.dumps(capture_daemon.CaptureInboxDaemon().status(), sort_keys=True)
    except Exception as exc:
        LOGGER.exception("capture inbox status failed")
        return json.dumps({"error": _public_error("capture inbox status failed", exc)}, sort_keys=True)


@mcp.tool()
def process_spiking_capture_inbox(max_files: int = 50, confirm: bool = False) -> str:
    """Process pending local capture inbox files into the real SYNAPSE-S2 graph."""
    try:
        if confirm is not True:
            raise ValueError("confirm must be true before processing capture inbox files")
        bounded_max = min(max(int(max_files), 1), 250)
        capture_daemon = _load_capture_daemon()
        return json.dumps(
            capture_daemon.CaptureInboxDaemon().process_once(max_files=bounded_max),
            sort_keys=True,
            default=str,
        )
    except ValueError as exc:
        LOGGER.warning("invalid capture inbox process request: %s", exc)
        return json.dumps({"error": _public_error("invalid capture inbox process request", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("capture inbox process failed")
        return json.dumps({"error": _public_error("capture inbox process failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Preflight SYNAPSE-S2 Capture Error Resolution",
        "readOnlyHint": True,
    }
)
def preflight_spiking_capture_error_resolution(
    reason: str,
    include_historical: bool = False,
) -> str:
    """Return a content-free token for a governed capture-error archival scope."""

    try:
        capture_daemon = _load_capture_daemon()
        payload = capture_daemon.CaptureInboxDaemon().error_resolution_preflight(
            reason=reason,
            include_historical=bool(include_historical),
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        return json.dumps(
            {"error": _public_error("invalid capture error preflight", exc)},
            sort_keys=True,
        )
    except Exception as exc:
        LOGGER.exception("capture error resolution preflight failed")
        return json.dumps(
            {"error": _public_error("capture error preflight failed", exc)},
            sort_keys=True,
        )


@mcp.tool()
def resolve_spiking_capture_errors(
    preflight_token: str,
    reason: str,
    include_historical: bool = False,
    confirm: bool = False,
) -> str:
    """Archive reviewed capture-error evidence after an exact preflight."""

    try:
        capture_daemon = _load_capture_daemon()
        payload = capture_daemon.CaptureInboxDaemon().resolve_error_artifacts(
            preflight_token=preflight_token,
            reason=reason,
            include_historical=bool(include_historical),
            confirm=bool(confirm),
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        return json.dumps(
            {"error": _public_error("invalid capture error resolution", exc)},
            sort_keys=True,
        )
    except Exception as exc:
        LOGGER.exception("capture error resolution failed")
        return json.dumps(
            {"error": _public_error("capture error resolution failed", exc)},
            sort_keys=True,
        )


@mcp.tool()
def register_spiking_transcript_source(
    source_id: str,
    path: str,
    context_id: str = "default",
    source_tag: str = "transcript-source",
    speaker: str = "operator",
    metadata: dict[str, Any] | None = None,
    confirmed: bool = False,
    start_at_end: bool = True,
    enabled: bool = True,
) -> str:
    """Register an explicitly approved local transcript file for delta capture."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        transcript_capture = _load_transcript_capture()
        _, mlx_backend = _load_backend()
        manager = transcript_capture.TranscriptCaptureManager(
            backend=mlx_backend.get_backend()
        )
        payload = manager.register_file_source(
            source_id=source_id,
            path=path,
            context_id=context,
            source_tag=source_tag,
            speaker=speaker,
            metadata={
                **(metadata or {}),
                "source_surface": "mcp-transcript-source",
            },
            confirmed=bool(confirmed),
            start_at_end=bool(start_at_end),
            enabled=bool(enabled),
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning("invalid transcript source registration for context_id=%s: %s", context, exc)
        return json.dumps({"error": _public_error("invalid transcript source registration", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("transcript source registration failed for context_id=%s", context)
        return json.dumps({"error": _public_error("transcript source registration failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "List SYNAPSE-S2 Transcript Sources",
        "readOnlyHint": True,
    }
)
def list_spiking_transcript_sources() -> str:
    """List explicitly registered local transcript capture sources."""
    try:
        transcript_capture = _load_transcript_capture()
        _, mlx_backend = _load_backend()
        manager = transcript_capture.TranscriptCaptureManager(
            backend=mlx_backend.get_backend()
        )
        return json.dumps(manager.list_sources(), sort_keys=True, default=str)
    except Exception as exc:
        LOGGER.exception("transcript source list failed")
        return json.dumps({"error": _public_error("transcript source list failed", exc)}, sort_keys=True)


@mcp.tool()
def poll_spiking_transcript_sources(
    source_id: str = "",
    max_bytes: int = 256000,
) -> str:
    """Poll registered transcript source deltas into the SYNAPSE-S2 memory graph."""
    try:
        transcript_capture = _load_transcript_capture()
        _, mlx_backend = _load_backend()
        manager = transcript_capture.TranscriptCaptureManager(
            backend=mlx_backend.get_backend()
        )
        payload = manager.poll_sources(
            source_id=source_id,
            max_bytes=max(1, min(int(max_bytes), 256000)),
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning("invalid transcript source poll request: %s", exc)
        return json.dumps({"error": _public_error("invalid transcript source poll request", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("transcript source poll failed")
        return json.dumps({"error": _public_error("transcript source poll failed", exc)}, sort_keys=True)


@mcp.tool()
def capture_spiking_clipboard(
    text: str = "",
    context_id: str = "default",
    source_tag: str = "frontmost-selection",
    speaker: str = "operator",
    metadata: dict[str, Any] | None = None,
    capture_id: str = "",
) -> str:
    """Capture explicitly selected/copied text as a one-shot transcript payload."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        transcript_capture = _load_transcript_capture()
        _, mlx_backend = _load_backend()
        manager = transcript_capture.TranscriptCaptureManager(
            backend=mlx_backend.get_backend()
        )
        payload = manager.capture_clipboard_once(
            text=str(text or "") if str(text or "").strip() else None,
            context_id=context,
            source_tag=source_tag,
            speaker=speaker,
            metadata={
                **(metadata or {}),
                "source_surface": "mcp-clipboard",
            },
            capture_id=str(capture_id or "") or None,
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning("invalid clipboard capture for context_id=%s: %s", context, exc)
        return json.dumps({"error": _public_error("invalid clipboard capture", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("clipboard capture failed for context_id=%s", context)
        return json.dumps({"error": _public_error("clipboard capture failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "List Local Apps for SYNAPSE-S2 App Connect",
        "readOnlyHint": True,
    }
)
def list_spiking_running_apps() -> str:
    """List locally visible foreground applications that can be explicitly attached."""
    try:
        transcript_capture = _load_transcript_capture()
        _, mlx_backend = _load_backend()
        manager = transcript_capture.TranscriptCaptureManager(
            backend=mlx_backend.get_backend()
        )
        return json.dumps(manager.detect_running_apps(), sort_keys=True, default=str)
    except Exception as exc:
        LOGGER.exception("running app detection failed")
        return json.dumps({"error": _public_error("running app detection failed", exc)}, sort_keys=True)


@mcp.tool()
def connect_spiking_app(
    app_name: str,
    bundle_id: str = "",
    pid: int = 0,
    context_id: str = "default",
    source_tag: str = "app-connect",
    speaker: str = "operator",
    metadata: dict[str, Any] | None = None,
    confirmed: bool = False,
    allow_manual: bool = False,
) -> str:
    """Attach a confirmed local app to SYNAPSE-S2 for explicit snapshot/selection capture."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        transcript_capture = _load_transcript_capture()
        _, mlx_backend = _load_backend()
        manager = transcript_capture.TranscriptCaptureManager(
            backend=mlx_backend.get_backend()
        )
        payload = manager.connect_running_app(
            app_name=app_name,
            bundle_id=bundle_id,
            pid=int(pid or 0),
            context_id=context,
            source_tag=source_tag,
            speaker=speaker,
            metadata={
                **(metadata or {}),
                "source_surface": "mcp-app-connect",
            },
            confirmed=bool(confirmed),
            allow_manual=bool(allow_manual),
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning("invalid app connect request for context_id=%s: %s", context, exc)
        return json.dumps({"error": _public_error("invalid app connect request", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("app connect failed for context_id=%s", context)
        return json.dumps({"error": _public_error("app connect failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "List SYNAPSE-S2 App Connections",
        "readOnlyHint": True,
    }
)
def list_spiking_app_connections() -> str:
    """List local app connections registered with SYNAPSE-S2."""
    try:
        transcript_capture = _load_transcript_capture()
        _, mlx_backend = _load_backend()
        manager = transcript_capture.TranscriptCaptureManager(
            backend=mlx_backend.get_backend()
        )
        return json.dumps(manager.list_app_connections(), sort_keys=True, default=str)
    except Exception as exc:
        LOGGER.exception("app connection list failed")
        return json.dumps({"error": _public_error("app connection list failed", exc)}, sort_keys=True)


@mcp.tool()
def capture_spiking_app_snapshot(
    connection_id: str,
    metadata: dict[str, Any] | None = None,
    confirmed: bool = False,
    capture_id: str = "",
) -> str:
    """Capture a confirmed local app accessibility snapshot into the SYNAPSE-S2 graph."""
    try:
        transcript_capture = _load_transcript_capture()
        _, mlx_backend = _load_backend()
        manager = transcript_capture.TranscriptCaptureManager(
            backend=mlx_backend.get_backend()
        )
        payload = manager.capture_app_snapshot(
            connection_id=connection_id,
            metadata={
                **(metadata or {}),
                "source_surface": "mcp-app-snapshot",
            },
            confirmed=bool(confirmed),
            capture_id=str(capture_id or "") or None,
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning("invalid app snapshot request: %s", exc)
        return json.dumps({"error": _public_error("invalid app snapshot request", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("app snapshot failed")
        return json.dumps({"error": _public_error("app snapshot failed", exc)}, sort_keys=True)


@mcp.tool()
def prune_spiking_memory(
    target_type: str,
    context_id: str = "default",
    memory_id: str = "",
    tag: str = "",
    relationship_id: str = "",
    event_id: int = 0,
    reason: str = "",
    confirm: bool = False,
) -> str:
    """Prune one SYNAPSE-S2 memory node, edge, relationship mode, or deployment event."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        if confirm is not True:
            raise ValueError("confirm must be true before pruning memory graph data")
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
        return json.dumps({"error": _public_error("invalid memory prune", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("memory prune failed for context_id=%s", context)
        return json.dumps({"error": _public_error("memory prune failed", exc)}, sort_keys=True)


@mcp.tool(
    output_schema=TOKEN_CONTRACT_OUTPUT_SCHEMA,
    annotations={
        "title": "List SYNAPSE-S2 Memory Graph",
        "readOnlyHint": True,
    }
)
def list_spiking_memory_graph(
    context_id: ToolStringInput = "default",
    limit: ToolIntegerInput = 100,
    response_mode: ResponseModeInput = "",
    max_response_bytes: ResponseBudgetInput = "",
) -> Any:
    """List memory graph evidence using a bounded structured response contract."""
    context = "unknown"
    budget: int | None = _token_error_budget(surface="memory-graph")
    try:
        budget = _token_response_budget(
            surface="memory-graph",
            max_response_bytes=max_response_bytes,
        )
        configured_mode = os.getenv("SYNAPSE_S2_DEFAULT_RESPONSE_MODE", "compact")
        mode = normalize_response_mode(response_mode, default=configured_mode)
        context = _sanitize_context_id(
            _validate_tool_string(context_id, field_name="context_id")
        )
        bounded_limit = _validate_limit(limit)
        effective_limit = (
            min(bounded_limit, COMPACT_SOURCE_LIMITS["memory-graph"])
            if mode == "compact"
            else bounded_limit
        )
        _, mlx_backend = _load_backend()
        payload = mlx_backend.list_memory_graph(
            context_id=context,
            limit=effective_limit,
        )
        payload["_response_source"] = {
            "requested_limit": bounded_limit,
            "effective_limit": effective_limit,
        }
        return _contract_tool_result(
            project_response(
                "memory-graph",
                payload,
                mode=mode,
                max_response_bytes=budget,
            )
        )
    except ValueError as exc:
        LOGGER.warning("invalid graph list request for context_id=%s: %s", context, exc)
        return _contract_tool_result(
            _contract_error("memory-graph", exc, max_response_bytes=budget)
        )
    except Exception as exc:
        LOGGER.exception("memory graph list failed for context_id=%s", context)
        return _contract_tool_result(
            _contract_error("memory-graph", exc, max_response_bytes=budget)
        )


@mcp.tool(
    annotations={
        "title": "Pull SYNAPSE-S2 Context Deployments",
        "readOnlyHint": False,
    }
)
def pull_spiking_context_deployments(
    agent_id: str = "",
    context_id: str = "default",
    limit: int = 50,
    lease_seconds: float = 60.0,
) -> str:
    """Lease the oldest eligible context events for the configured local agent."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        bounded_limit = _validate_limit(limit)
        agent = _delivery_agent_id(agent_id)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.lease_context_events(
            context_id=context,
            agent_id=agent,
            consumer_instance_id=MCP_DELIVERY_INSTANCE_ID,
            limit=bounded_limit,
            lease_seconds=float(lease_seconds),
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid context deployment pull for context_id=%s: %s", context, exc)
        return json.dumps({"error": _public_error("invalid context deployment pull", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("context deployment pull failed for context_id=%s", context)
        return json.dumps({"error": _public_error("context deployment pull failed", exc)}, sort_keys=True)


@mcp.tool()
def ack_spiking_context_deployments(
    agent_id: str,
    context_id: str = "default",
    receipt_id: str = "",
    receipt_ids: list[str] | None = None,
) -> str:
    """Atomically acknowledge one or more durable receipts after consumption."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        agent = _delivery_agent_id(agent_id)
        requested_receipts: list[str] = []
        if receipt_ids is not None:
            if not isinstance(receipt_ids, list):
                raise ValueError("receipt_ids must be a list")
            requested_receipts.extend(str(value or "").strip() for value in receipt_ids)
        if str(receipt_id or "").strip():
            requested_receipts.append(str(receipt_id).strip())
        requested_receipts = list(dict.fromkeys(value for value in requested_receipts if value))
        if not requested_receipts:
            raise ValueError("receipt_id or receipt_ids is required")
        if len(requested_receipts) > 500:
            raise ValueError("at most 500 receipt_ids may be acknowledged")
        _, mlx_backend = _load_backend()
        payload = mlx_backend.ack_context_events(
            context_id=context,
            agent_id=agent,
            acknowledgements=[
                {"receipt_id": receipt}
                for receipt in requested_receipts
            ],
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid context deployment ack for context_id=%s: %s", context, exc)
        return json.dumps({"error": _public_error("invalid context deployment ack", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("context deployment ack failed for context_id=%s", context)
        return json.dumps({"error": _public_error("context deployment ack failed", exc)}, sort_keys=True)


@mcp.tool()
def release_spiking_context_deployments(
    agent_id: str,
    receipt_ids: list[str],
    context_id: str = "default",
) -> str:
    """Release unconsumed leases so another attempt can retry immediately."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        agent = _delivery_agent_id(agent_id)
        if not isinstance(receipt_ids, list) or not receipt_ids:
            raise ValueError("receipt_ids must be a non-empty list")
        requested_receipts = list(
            dict.fromkeys(str(value or "").strip() for value in receipt_ids)
        )
        if any(not value for value in requested_receipts):
            raise ValueError("receipt_ids must not contain empty values")
        if len(requested_receipts) > 500:
            raise ValueError("at most 500 receipt_ids may be released")
        _, mlx_backend = _load_backend()
        payload = mlx_backend.release_context_events(
            context_id=context,
            agent_id=agent,
            consumer_instance_id=MCP_DELIVERY_INSTANCE_ID,
            receipt_ids=requested_receipts,
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid context deployment release for context_id=%s: %s", context, exc)
        return json.dumps({"error": _public_error("invalid context deployment release", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("context deployment release failed for context_id=%s", context)
        return json.dumps({"error": _public_error("context deployment release failed", exc)}, sort_keys=True)


@mcp.tool()
def dead_letter_spiking_context_delivery(
    agent_id: str,
    delivery_id: str,
    reason: str,
    context_id: str = "default",
    confirm: bool = False,
) -> str:
    """Governedly quarantine one retry-exhausted delivery after lease expiry."""

    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        agent = _delivery_agent_id(agent_id)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.dead_letter_context_delivery(
            context_id=context,
            agent_id=agent,
            delivery_id=str(delivery_id or "").strip(),
            reason=str(reason or "").strip(),
            confirm=bool(confirm),
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning(
            "invalid context delivery dead-letter for context_id=%s: %s",
            context,
            exc,
        )
        return json.dumps(
            {"error": _public_error("invalid context delivery dead-letter", exc)},
            sort_keys=True,
        )
    except Exception as exc:
        LOGGER.exception(
            "context delivery dead-letter failed for context_id=%s",
            context,
        )
        return json.dumps(
            {"error": _public_error("context delivery dead-letter failed", exc)},
            sort_keys=True,
        )


@mcp.tool(
    annotations={
        "title": "List SYNAPSE-S2 Context Deployment Cursors",
        "readOnlyHint": True,
    }
)
def list_spiking_context_cursors(context_id: str = "default", limit: int = 50) -> str:
    """List durable per-agent context-bus delivery cursors."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        bounded_limit = _validate_limit(limit)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.list_context_cursors(
            context_id=context,
            limit=bounded_limit,
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid context cursor list for context_id=%s: %s", context, exc)
        return json.dumps({"error": _public_error("invalid context cursor list", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("context cursor list failed for context_id=%s", context)
        return json.dumps({"error": _public_error("context cursor list failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Audit SYNAPSE-S2 Context Delivery",
        "readOnlyHint": True,
    }
)
def inspect_spiking_context_delivery_health() -> str:
    """Verify normalized routes, delivery rows, receipts, and foreign keys."""
    try:
        _, mlx_backend = _load_backend()
        return json.dumps(
            mlx_backend.get_backend().context_delivery_health(context_id=None),
            sort_keys=True,
        )
    except Exception as exc:
        LOGGER.exception("context delivery health inspection failed")
        return json.dumps(
            {"error": _public_error("context delivery health inspection failed", exc)},
            sort_keys=True,
        )


@mcp.tool(
    output_schema=TOKEN_CONTRACT_OUTPUT_SCHEMA,
    annotations={
        "title": "Hydrate Agent Context From SYNAPSE-S2",
        "readOnlyHint": False,
    }
)
def hydrate_spiking_agent_context(
    agent_id: ToolStringInput,
    context_id: ToolStringInput = "default",
    prompt: ToolStringInput = "",
    limit: ToolIntegerInput = 20,
    graph_limit: ToolIntegerInput = 30,
    response_mode: ResponseModeInput = "",
    max_response_bytes: ResponseBudgetInput = "",
) -> Any:
    """Lease a bounded agent context contract; acknowledge every returned receipt separately."""
    context = "unknown"
    agent = "unknown"
    backend = None
    payload: dict[str, Any] | None = None
    budget: int | None = _token_error_budget(surface="agent-hydration")
    try:
        budget = _token_response_budget(
            surface="agent-hydration",
            max_response_bytes=max_response_bytes,
        )
        configured_mode = os.getenv("SYNAPSE_S2_DEFAULT_RESPONSE_MODE", "compact")
        mode = normalize_response_mode(response_mode, default=configured_mode)
        context = _sanitize_context_id(
            _validate_tool_string(context_id, field_name="context_id")
        )
        agent = _delivery_agent_id(
            _validate_tool_string(agent_id, field_name="agent_id")
        )
        prompt_text = _validate_tool_string(prompt, field_name="prompt").strip()
        if len(prompt_text) > 20_000:
            raise ValueError("prompt exceeds 20000 characters")
        bounded_limit = _validate_limit(limit)
        bounded_graph_limit = _validate_limit(graph_limit)
        effective_limit = (
            compact_agent_event_limit(
                requested_limit=bounded_limit,
                max_output_bytes=budget,
            )
            if mode == "compact"
            else bounded_limit
        )
        effective_graph_limit = (
            min(bounded_graph_limit, COMPACT_SOURCE_LIMITS["agent-graph"])
            if mode == "compact"
            else bounded_graph_limit
        )
        _, mlx_backend = _load_backend()
        backend = mlx_backend.get_backend()
        payload = backend.hydrate_agent_context(
            context_id=context,
            agent_id=agent,
            prompt=prompt_text,
            since_event_id=None,
            event_limit=effective_limit,
            graph_limit=effective_graph_limit,
            acknowledge=False,
            claim_events=True,
            consumer_instance_id=MCP_DELIVERY_INSTANCE_ID,
        )
        payload["_response_source"] = {
            "requested_event_limit": bounded_limit,
            "effective_event_limit": effective_limit,
            "requested_graph_limit": bounded_graph_limit,
            "effective_graph_limit": effective_graph_limit,
        }
        try:
            return _contract_tool_result(
                project_response(
                    "agent-hydration",
                    payload,
                    mode=mode,
                    max_response_bytes=budget,
                )
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
                        context_id=context,
                        agent_id=agent,
                        consumer_instance_id=MCP_DELIVERY_INSTANCE_ID,
                        receipt_ids=receipt_ids,
                    )
                except Exception:
                    LOGGER.exception(
                        "failed to release agent context receipts after projection failure"
                    )
                    raise ResponseContractError(
                        "projection failed and leased receipts could not be released; "
                        "wait for lease expiry before retrying"
                    )
            raise
    except ValueError as exc:
        LOGGER.warning(
            "invalid agent context hydration for context_id=%s agent_id=%s: %s",
            context,
            agent,
            exc,
        )
        return _contract_tool_result(
            _contract_error("agent-hydration", exc, max_response_bytes=budget)
        )
    except Exception as exc:
        LOGGER.exception(
            "agent context hydration failed for context_id=%s agent_id=%s",
            context,
            agent,
        )
        return _contract_tool_result(
            _contract_error("agent-hydration", exc, max_response_bytes=budget)
        )


@mcp.tool(
    annotations={
        "title": "Enter SYNAPSE-S2 Cortex Governor",
        "readOnlyHint": False,
    }
)
def enter_spiking_cortex(
    agent_id: str,
    context_id: str = "default",
    task: str = "",
    mode: str = "strict",
) -> str:
    """Start a governed agent work session with recall, policy, and context-bus deployment."""
    context = "unknown"
    agent = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        agent = _sanitize_agent_id(agent_id)
        task_text = _validate_text(task, field_name="task")
        _, mlx_backend = _load_backend()
        payload = mlx_backend.enter_spiking_cortex(
            context_id=context,
            agent_id=agent,
            task=task_text,
            mode=str(mode or "strict"),
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning(
            "invalid cortex enter for context_id=%s agent_id=%s: %s",
            context,
            agent,
            exc,
        )
        return json.dumps({"error": _public_error("invalid cortex enter", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("cortex enter failed for context_id=%s agent_id=%s", context, agent)
        return json.dumps({"error": _public_error("cortex enter failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Tick SYNAPSE-S2 Cortex Governor",
        "readOnlyHint": False,
    }
)
def tick_spiking_cortex(
    agent_id: str,
    session_id: str,
    context_id: str = "default",
    observation: str = "",
    proposed_action: str = "",
    intended_files: list[str] | None = None,
    intended_tools: list[str] | None = None,
    mutation_intent: bool = False,
    confidence: float = 0.5,
) -> str:
    """Evaluate the current observation/action against governed memory before proceeding."""
    context = "unknown"
    agent = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        agent = _sanitize_agent_id(agent_id)
        clean_session_id = str(session_id or "").strip()
        if not clean_session_id:
            raise ValueError("session_id must not be empty")
        observation_text = str(observation or "").strip()
        proposed_text = str(proposed_action or "").strip()
        if len(observation_text) > 20_000:
            raise ValueError("observation exceeds 20000 characters")
        if len(proposed_text) > 20_000:
            raise ValueError("proposed_action exceeds 20000 characters")
        scoped_files = _validate_string_list(intended_files, field_name="intended_files")
        scoped_tools = _validate_string_list(intended_tools, field_name="intended_tools")
        _, mlx_backend = _load_backend()
        payload = mlx_backend.cortex_tick(
            context_id=context,
            agent_id=agent,
            session_id=clean_session_id,
            observation=observation_text,
            proposed_action=proposed_text,
            intended_files=scoped_files,
            intended_tools=scoped_tools,
            mutation_intent=bool(mutation_intent),
            confidence=float(confidence),
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning(
            "invalid cortex tick for context_id=%s agent_id=%s: %s",
            context,
            agent,
            exc,
        )
        return json.dumps({"error": _public_error("invalid cortex tick", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("cortex tick failed for context_id=%s agent_id=%s", context, agent)
        return json.dumps({"error": _public_error("cortex tick failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Close SYNAPSE-S2 Cortex Governor",
        "readOnlyHint": False,
    }
)
def close_spiking_cortex(
    agent_id: str,
    session_id: str,
    context_id: str = "default",
    reason: str = "operator-complete",
) -> str:
    """End an active governed agent session after verified traces or handoff are captured."""
    context = "unknown"
    agent = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        agent = _sanitize_agent_id(agent_id)
        clean_session_id = str(session_id or "").strip()
        if not clean_session_id:
            raise ValueError("session_id must not be empty")
        _, mlx_backend = _load_backend()
        payload = mlx_backend.close_spiking_cortex(
            context_id=context,
            agent_id=agent,
            session_id=clean_session_id,
            reason=str(reason or "operator-complete"),
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning(
            "invalid cortex close for context_id=%s agent_id=%s: %s",
            context,
            agent,
            exc,
        )
        return json.dumps({"error": _public_error("invalid cortex close", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("cortex close failed for context_id=%s agent_id=%s", context, agent)
        return json.dumps({"error": _public_error("cortex close failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Commit SYNAPSE-S2 Cortical Trace",
        "readOnlyHint": False,
    }
)
def commit_spiking_cortical_trace(
    agent_id: str,
    text: str,
    context_id: str = "default",
    session_id: str = "",
    trace_type: str = "",
    truth_posture: str = "observed",
    evidence_json: str = "",
    confidence: float = -1.0,
) -> str:
    """Persist a typed governed memory trace with truth posture and optional evidence."""
    context = "unknown"
    agent = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        agent = _sanitize_agent_id(agent_id)
        text_value = _validate_text(text, field_name="text")
        evidence = _parse_json_object(evidence_json, field_name="evidence_json")
        confidence_value: float | None = None
        if float(confidence) >= 0.0:
            confidence_value = float(confidence)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.commit_cortical_trace(
            context_id=context,
            agent_id=agent,
            session_id=str(session_id or ""),
            trace_type=str(trace_type or ""),
            truth_posture=str(truth_posture or "observed"),
            text=text_value,
            evidence=evidence,
            confidence=confidence_value,
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning(
            "invalid cortical trace commit for context_id=%s agent_id=%s: %s",
            context,
            agent,
            exc,
        )
        return json.dumps({"error": _public_error("invalid cortical trace commit", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception(
            "cortical trace commit failed for context_id=%s agent_id=%s",
            context,
            agent,
        )
        return json.dumps({"error": _public_error("cortical trace commit failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Moderate SYNAPSE-S2 Cortical Trace",
        "readOnlyHint": False,
    }
)
def moderate_spiking_cortical_trace(
    memory_id: str,
    action: str,
    context_id: str = "default",
    reason: str = "",
    confirm: bool = False,
) -> str:
    """Promote, demote, or prune a Cortex Governor trace by memory id."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        clean_memory_id = str(memory_id or "").strip()
        if not clean_memory_id:
            raise ValueError("memory_id is required")
        _, mlx_backend = _load_backend()
        payload = mlx_backend.moderate_cortex_trace(
            context_id=context,
            memory_id=clean_memory_id,
            action=str(action or ""),
            reason=str(reason or ""),
            source_surface="mcp-cortex",
            confirm=bool(confirm),
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning(
            "invalid cortical trace moderation for context_id=%s memory_id=%s: %s",
            context,
            str(memory_id or "").strip(),
            exc,
        )
        return json.dumps({"error": _public_error("invalid cortical trace moderation", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception(
            "cortical trace moderation failed for context_id=%s memory_id=%s",
            context,
            str(memory_id or "").strip(),
        )
        return json.dumps({"error": _public_error("cortical trace moderation failed", exc)}, sort_keys=True)


@mcp.tool(
    output_schema=TOKEN_CONTRACT_OUTPUT_SCHEMA,
    annotations={
        "title": "Get SYNAPSE-S2 Cortex State",
        "readOnlyHint": True,
    }
)
def get_spiking_cortex_state(
    agent_id: ToolStringInput = "",
    context_id: ToolStringInput = "default",
    limit: ToolIntegerInput = 50,
    response_mode: ResponseModeInput = "",
    max_response_bytes: ResponseBudgetInput = "",
) -> Any:
    """Inspect governed Cortex state through a bounded structured contract."""
    context = "unknown"
    agent = "unknown"
    budget: int | None = _token_error_budget(surface="cortex-state")
    try:
        budget = _token_response_budget(
            surface="cortex-state",
            max_response_bytes=max_response_bytes,
        )
        configured_mode = os.getenv("SYNAPSE_S2_DEFAULT_RESPONSE_MODE", "compact")
        mode = normalize_response_mode(response_mode, default=configured_mode)
        context = _sanitize_context_id(
            _validate_tool_string(context_id, field_name="context_id")
        )
        agent_input = _validate_tool_string(agent_id, field_name="agent_id")
        agent = _sanitize_agent_id(agent_input) if agent_input.strip() else ""
        bounded_limit = _validate_limit(limit)
        effective_limit = (
            min(bounded_limit, COMPACT_SOURCE_LIMITS["cortex-state"])
            if mode == "compact"
            else bounded_limit
        )
        _, mlx_backend = _load_backend()
        payload = mlx_backend.get_cortex_state(
            context_id=context,
            agent_id=agent,
            limit=effective_limit,
        )
        payload["_response_source"] = {
            "requested_limit": bounded_limit,
            "effective_limit": effective_limit,
        }
        return _contract_tool_result(
            project_response(
                "cortex-state",
                payload,
                mode=mode,
                max_response_bytes=budget,
            )
        )
    except ValueError as exc:
        LOGGER.warning(
            "invalid cortex state request for context_id=%s agent_id=%s: %s",
            context,
            agent or "<all>",
            exc,
        )
        return _contract_tool_result(
            _contract_error("cortex-state", exc, max_response_bytes=budget)
        )
    except Exception as exc:
        LOGGER.exception(
            "cortex state request failed for context_id=%s agent_id=%s",
            context,
            agent or "<all>",
        )
        return _contract_tool_result(
            _contract_error("cortex-state", exc, max_response_bytes=budget)
        )


@mcp.tool(
    annotations={
        "title": "Create SYNAPSE-S2 Goal",
        "readOnlyHint": False,
    }
)
def create_spiking_goal(
    title: str,
    agent_id: str = "mcp-client",
    context_id: str = "default",
    owner: str = "",
    state: str = "planned",
    next_action: str = "",
    evidence: str = "",
) -> str:
    """Create a lightweight goal-ledger trace for the active local context."""
    context = "unknown"
    agent = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        agent = _sanitize_agent_id(agent_id)
        clean_title = _validate_text(title, field_name="title")
        _, mlx_backend = _load_backend()
        payload = mlx_backend.create_goal(
            context_id=context,
            agent_id=agent,
            title=clean_title,
            owner=str(owner or ""),
            state=str(state or "planned"),
            next_action=str(next_action or ""),
            evidence=str(evidence or ""),
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning("invalid goal create for context_id=%s agent_id=%s: %s", context, agent, exc)
        return json.dumps({"error": _public_error("invalid goal create", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("goal create failed for context_id=%s agent_id=%s", context, agent)
        return json.dumps({"error": _public_error("goal create failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Update SYNAPSE-S2 Goal",
        "readOnlyHint": False,
    }
)
def update_spiking_goal(
    agent_id: str = "mcp-client",
    context_id: str = "default",
    goal_id: str = "",
    title: str = "",
    owner: str = "",
    state: str = "",
    next_action: str = "",
    evidence: str = "",
) -> str:
    """Append an auditable state update to an existing goal-ledger trace."""
    context = "unknown"
    agent = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        agent = _sanitize_agent_id(agent_id)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.update_goal(
            context_id=context,
            agent_id=agent,
            goal_id=str(goal_id or ""),
            title=str(title or ""),
            owner=str(owner or ""),
            state=str(state or ""),
            next_action=str(next_action or ""),
            evidence=str(evidence or ""),
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning("invalid goal update for context_id=%s agent_id=%s: %s", context, agent, exc)
        return json.dumps({"error": _public_error("invalid goal update", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("goal update failed for context_id=%s agent_id=%s", context, agent)
        return json.dumps({"error": _public_error("goal update failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "List SYNAPSE-S2 Goals",
        "readOnlyHint": True,
    }
)
def list_spiking_goals(context_id: str = "default", limit: int = 20) -> str:
    """List current goal-ledger state for the active local context."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        bounded_limit = _validate_limit(limit)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.list_goals(context_id=context, limit=bounded_limit)
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning("invalid goal list for context_id=%s: %s", context, exc)
        return json.dumps({"error": _public_error("invalid goal list", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("goal list failed for context_id=%s", context)
        return json.dumps({"error": _public_error("goal list failed", exc)}, sort_keys=True)


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
        return json.dumps({"error": _public_error("resource profile failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Benchmark SYNAPSE-S2 Embedding Provider",
        "readOnlyHint": False,
    }
)
def benchmark_spiking_embedding_provider(
    text: str,
    runs: int = 1,
    dimensions: int = 0,
) -> str:
    """Embed text with the configured local provider and report latency/provenance."""
    try:
        prompt = str(text or "").strip()
        if not prompt:
            raise ValueError("text must not be empty")
        if len(prompt) > 20_000:
            raise ValueError("text exceeds 20000 characters")
        bounded_runs = max(1, min(int(runs), 25))
        requested_dimensions = None if int(dimensions) <= 0 else int(dimensions)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.benchmark_embedding_provider(
            text=prompt,
            runs=bounded_runs,
            dimensions=requested_dimensions,
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning("invalid embedding provider benchmark request: %s", exc)
        return json.dumps({"error": _public_error("invalid embedding provider benchmark", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("embedding provider benchmark failed")
        return json.dumps({"error": _public_error("embedding provider benchmark failed", exc)}, sort_keys=True)


@mcp.tool(
    annotations={
        "title": "Certify SYNAPSE-S2 Native Runtime",
        "readOnlyHint": False,
    }
)
def certify_spiking_runtime(
    strict_native: bool = False,
    require_gpu: bool = False,
    benchmark_quick_prune: bool = False,
    require_resource_envelope: bool = False,
    target_min_mb: float = 61.0,
    target_max_mb: float = 138.0,
    output_path: str = "",
) -> str:
    """Emit an auditable local native-runtime certification evidence payload."""
    try:
        path = _optional_output_path(output_path, allowed_suffixes={".json"})
        _, mlx_backend = _load_backend()
        payload = mlx_backend.certify_runtime(
            strict_native=bool(strict_native),
            require_gpu=bool(require_gpu),
            benchmark_quick_prune=bool(benchmark_quick_prune),
            require_resource_envelope=bool(require_resource_envelope),
            target_min_mb=float(target_min_mb),
            target_max_mb=float(target_max_mb),
            output_path=path,
        )
        return json.dumps(payload, sort_keys=True, default=str)
    except ValueError as exc:
        LOGGER.warning("invalid runtime certification request: %s", exc)
        return json.dumps({"error": _public_error("invalid runtime certification request", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("runtime certification failed")
        return json.dumps({"error": _public_error("runtime certification failed", exc)}, sort_keys=True)


@mcp.tool()
def export_spiking_memory(
    context_id: str = "default",
    output_path: str = "",
) -> str:
    """Export persisted memory as JSON, optionally writing to output_path."""
    context = "unknown"
    try:
        context = _sanitize_context_id(context_id)
        path = _optional_output_path(output_path, allowed_suffixes={".json"})
        _, mlx_backend = _load_backend()
        payload = mlx_backend.export_memory(path=path, context_id=context)
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid memory export request for context_id=%s: %s", context, exc)
        return json.dumps({"error": _public_error("invalid memory export request", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("memory export failed for context_id=%s", context)
        return json.dumps({"error": _public_error("memory export failed", exc)}, sort_keys=True)


@mcp.tool()
def backup_spiking_memory(output_path: str = "") -> str:
    """Create a segregated SQLite-only diagnostic, not a recovery point."""
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
        return json.dumps({"error": _public_error("invalid memory backup request", exc)}, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("memory backup failed")
        return json.dumps({"error": _public_error("memory backup failed", exc)}, sort_keys=True)


@mcp.tool()
def audit_capture_ledger_integrity(sample_limit: int = 20) -> str:
    """Audit processed capture.v2 payloads against the authoritative SQLite ledger."""
    try:
        _, mlx_backend = _load_backend()
        payload = mlx_backend.audit_capture_ledger(sample_limit=sample_limit)
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid capture ledger audit request: %s", exc)
        return json.dumps(
            {"error": _public_error("invalid capture ledger audit request", exc)},
            sort_keys=True,
        )
    except Exception as exc:
        LOGGER.exception("capture ledger audit failed")
        return json.dumps(
            {"error": _public_error("capture ledger audit failed", exc)},
            sort_keys=True,
        )


@mcp.tool()
def repair_capture_ledger_integrity(
    expected_revision: str,
    confirm: bool = False,
    sample_limit: int = 20,
) -> str:
    """Apply a reviewed historical ledger projection without replaying captures."""
    try:
        _, mlx_backend = _load_backend()
        payload = mlx_backend.repair_capture_ledger(
            confirm=bool(confirm),
            expected_revision=expected_revision,
            sample_limit=sample_limit,
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid capture ledger repair request: %s", exc)
        return json.dumps(
            {"error": _public_error("invalid capture ledger repair request", exc)},
            sort_keys=True,
        )
    except Exception as exc:
        LOGGER.exception("capture ledger repair failed")
        return json.dumps(
            {"error": _public_error("capture ledger repair failed", exc)},
            sort_keys=True,
        )


@mcp.tool()
def backup_spiking_recovery(
    output_path: str = "",
    purpose: str = "operator",
    pinned: bool = False,
) -> str:
    """Create and verify a signed SQLite plus exactly-once capture recovery bundle."""
    try:
        path = _optional_output_path(
            output_path,
            allowed_suffixes={".db", ".sqlite", ".sqlite3"},
        )
        _, mlx_backend = _load_backend()
        payload = mlx_backend.backup_recovery_bundle(
            path=path,
            purpose=purpose,
            pinned=bool(pinned),
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid recovery backup request: %s", exc)
        return json.dumps(
            {"error": _public_error("invalid recovery backup request", exc)},
            sort_keys=True,
        )
    except Exception as exc:
        LOGGER.exception("recovery backup failed")
        return json.dumps(
            {"error": _public_error("recovery backup failed", exc)},
            sort_keys=True,
        )


@mcp.tool()
def verify_spiking_recovery(
    receipt_path: str,
    expected_database_sha256: str = "",
    expected_capture_sha256: str = "",
) -> str:
    """Cryptographically verify a paired recovery bundle without restoring it."""
    try:
        receipt = _optional_output_path(
            receipt_path,
            allowed_suffixes={".json"},
        )
        if receipt is None:
            raise ValueError("receipt_path is required")
        _, mlx_backend = _load_backend()
        payload = mlx_backend.verify_recovery_bundle(
            receipt,
            expected_database_sha256=expected_database_sha256 or None,
            expected_capture_sha256=expected_capture_sha256 or None,
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid recovery verification request: %s", exc)
        return json.dumps(
            {"error": _public_error("invalid recovery verification request", exc)},
            sort_keys=True,
        )
    except Exception as exc:
        LOGGER.exception("recovery verification failed")
        return json.dumps(
            {"error": _public_error("recovery verification failed", exc)},
            sort_keys=True,
        )


@mcp.tool()
def restore_spiking_recovery_proof(
    receipt_path: str,
    output_directory: str,
    expected_database_sha256: str = "",
    expected_capture_sha256: str = "",
    confirm: bool = False,
) -> str:
    """Materialize an isolated paired restore proof; never overwrite live state."""
    try:
        receipt = _optional_output_path(
            receipt_path,
            allowed_suffixes={".json"},
        )
        if receipt is None:
            raise ValueError("receipt_path is required")
        output_root = _required_output_directory(output_directory)
        _, mlx_backend = _load_backend()
        payload = mlx_backend.restore_recovery_bundle_isolated(
            receipt,
            output_root,
            expected_database_sha256=expected_database_sha256 or None,
            expected_capture_sha256=expected_capture_sha256 or None,
            confirm=bool(confirm),
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid recovery restore request: %s", exc)
        return json.dumps(
            {"error": _public_error("invalid recovery restore request", exc)},
            sort_keys=True,
        )
    except Exception as exc:
        LOGGER.exception("recovery restore failed")
        return json.dumps(
            {"error": _public_error("recovery restore failed", exc)},
            sort_keys=True,
        )


@mcp.tool()
def plan_spiking_recovery_retention(
    keep_latest: int = 7,
    max_age_days: float = 30.0,
) -> str:
    """Plan safe retention for verified default recovery bundles without moving files."""
    try:
        _, mlx_backend = _load_backend()
        payload = mlx_backend.plan_recovery_retention(
            keep_latest=keep_latest,
            max_age_days=max_age_days,
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid recovery retention plan request: %s", exc)
        return json.dumps(
            {"error": _public_error("invalid recovery retention plan request", exc)},
            sort_keys=True,
        )
    except Exception as exc:
        LOGGER.exception("recovery retention planning failed")
        return json.dumps(
            {"error": _public_error("recovery retention planning failed", exc)},
            sort_keys=True,
        )


@mcp.tool()
def apply_spiking_recovery_retention(
    plan_token: str,
    cutoff_created_at: float,
    keep_latest: int = 7,
    max_age_days: float = 30.0,
    confirm: bool = False,
) -> str:
    """Move only a previously planned stale recovery set into signed quarantine."""
    try:
        _, mlx_backend = _load_backend()
        payload = mlx_backend.apply_recovery_retention(
            plan_token=plan_token,
            cutoff_created_at=cutoff_created_at,
            keep_latest=keep_latest,
            max_age_days=max_age_days,
            confirm=bool(confirm),
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid recovery retention apply request: %s", exc)
        return json.dumps(
            {"error": _public_error("invalid recovery retention apply request", exc)},
            sort_keys=True,
        )
    except Exception as exc:
        LOGGER.exception("recovery retention apply failed")
        return json.dumps(
            {"error": _public_error("recovery retention apply failed", exc)},
            sort_keys=True,
        )


@mcp.tool()
def restore_retired_spiking_recovery(
    plan_token: str,
    confirm: bool = False,
) -> str:
    """Restore a quarantined recovery bundle set without overwriting live state."""
    try:
        _, mlx_backend = _load_backend()
        payload = mlx_backend.restore_retired_recovery(
            plan_token=plan_token,
            confirm=bool(confirm),
        )
        return json.dumps(payload, sort_keys=True)
    except ValueError as exc:
        LOGGER.warning("invalid retired recovery restore request: %s", exc)
        return json.dumps(
            {"error": _public_error("invalid retired recovery restore request", exc)},
            sort_keys=True,
        )
    except Exception as exc:
        LOGGER.exception("retired recovery restore failed")
        return json.dumps(
            {"error": _public_error("retired recovery restore failed", exc)},
            sort_keys=True,
        )


@mcp.tool()
def trigger_sleep_consolidation() -> str:
    """Run deep-sleep consolidation for local spiking memory state."""
    try:
        _, mlx_backend = _load_backend()
        status = mlx_backend.run_deep_sleep_consolidation()
        return json.dumps(status, sort_keys=True)
    except Exception as exc:
        LOGGER.exception("sleep consolidation failed")
        return _public_error("sleep consolidation failed", exc)


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
        return json.dumps({"error": _public_error("idle maintenance failed", exc)}, sort_keys=True)


def _install_contract_tool_guards() -> None:
    """Replace contracted registry entries with validation-safe tool objects."""

    if FunctionTool is None:  # pragma: no cover - legacy fallback
        return
    components = tuple(mcp.local_provider._components.values())
    for tool_name in _CONTRACT_TOOL_ARGUMENTS:
        matches = [
            component
            for component in components
            if isinstance(component, FunctionTool) and component.name == tool_name
        ]
        if len(matches) != 1:
            raise RuntimeError(
                "contracted MCP tool registration must resolve exactly once"
            )
        original = matches[0]
        if isinstance(original, _SecretSafeContractFunctionTool):
            continue
        values = {
            field_name: getattr(original, field_name)
            for field_name in FunctionTool.model_fields
        }
        guarded = _SecretSafeContractFunctionTool(**values)
        mcp.local_provider.remove_tool(original.name, original.version)
        mcp.add_tool(guarded)


_install_contract_tool_guards()


if __name__ == "__main__":
    from client_session_bridge import run_with_client_session_bridge

    run_with_client_session_bridge(mcp.run)

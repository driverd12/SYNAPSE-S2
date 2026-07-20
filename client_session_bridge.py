from __future__ import annotations

import hashlib
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

import capture_daemon
import mlx_backend
from redaction import (
    SECRET_SAFE_LOG_FORMAT,
    SecretRedactingFormatter,
    redact_capture_text,
    safe_public_error,
)


LOGGER = logging.getLogger("synapse_s2.client_session_bridge")
if not LOGGER.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(SecretRedactingFormatter(SECRET_SAFE_LOG_FORMAT))
    LOGGER.addHandler(_handler)
LOGGER.setLevel(os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper())
LOGGER.propagate = False


@dataclass(frozen=True)
class ClientSessionBridgeConfig:
    context_id: str = "default"
    agent_id: str = "local-mcp-client"
    startup_prompt: str = ""
    capture_root: Path | None = None
    source_tag: str = "client-session-boundary"
    enabled: bool = True
    cortex_enabled: bool = True
    cortex_mode: str = "strict"
    startup_recall_mode: str = "surface"
    event_limit: int = 20
    graph_limit: int = 30


class ClientSessionBridge:
    """Hydrate a local MCP client, enter Cortex, and capture a boundary note on exit."""

    def __init__(
        self,
        config: ClientSessionBridgeConfig,
        *,
        backend: mlx_backend.SpikingAttentionBackend | None = None,
    ) -> None:
        self.config = config
        self.backend = backend
        # Keep the full 128-bit nonce. This value scopes both the delivery
        # consumer instance and the deterministic session-boundary capture ID;
        # truncating it weakens collision resistance across long-lived clients.
        self.session_id = uuid.uuid4().hex
        self.started_at: float | None = None
        self.hydration: dict[str, Any] | None = None
        self.cortex_session: dict[str, Any] | None = None
        self.start_error: str = ""
        self.cortex_error: str = ""
        self._finished = False

    @classmethod
    def from_environment(
        cls,
        *,
        env: Mapping[str, str] | None = None,
        backend: mlx_backend.SpikingAttentionBackend | None = None,
    ) -> "ClientSessionBridge":
        values = env or os.environ
        agent_id = _resolve_agent_id(values)
        context_id = mlx_backend.sanitize_context_id(
            values.get("SYNAPSE_S2_CONTEXT_ID", "default")
        )
        prompt = values.get("SYNAPSE_S2_CLIENT_STARTUP_PROMPT", "").strip()
        if not prompt:
            prompt = (
                f"Hydrate SYNAPSE-S2 context for {agent_id} local MCP client startup."
            )
        prompt, _ = redact_capture_text(prompt)
        capture_root = values.get("SYNAPSE_S2_CAPTURE_ROOT", "").strip()
        config = ClientSessionBridgeConfig(
            context_id=context_id,
            agent_id=agent_id,
            startup_prompt=prompt,
            capture_root=Path(capture_root) if capture_root else None,
            source_tag=values.get(
                "SYNAPSE_S2_CLIENT_SESSION_SOURCE_TAG",
                "client-session-boundary",
            ),
            enabled=_env_enabled(values.get("SYNAPSE_S2_CLIENT_SESSION_BRIDGE", "1")),
            cortex_enabled=_env_enabled(values.get("SYNAPSE_S2_CLIENT_CORTEX", "1")),
            cortex_mode=values.get("SYNAPSE_S2_CLIENT_CORTEX_MODE", "strict"),
            startup_recall_mode=values.get(
                "SYNAPSE_S2_CLIENT_STARTUP_RECALL_MODE",
                "surface",
            ),
            event_limit=_env_int(values.get("SYNAPSE_S2_CLIENT_EVENT_LIMIT"), default=20),
            graph_limit=_env_int(values.get("SYNAPSE_S2_CLIENT_GRAPH_LIMIT"), default=30),
        )
        return cls(config, backend=backend)

    def start(self) -> dict[str, Any]:
        self.started_at = time.time()
        if not self.config.enabled:
            self.hydration = {
                "action": "client-session-start",
                "enabled": False,
                "context_id": self.config.context_id,
                "agent_id": self.config.agent_id,
            }
            return self.hydration
        try:
            backend = self.backend or mlx_backend.get_control_plane_backend()
            self.hydration = backend.hydrate_agent_context(
                context_id=self.config.context_id,
                agent_id=self.config.agent_id,
                prompt=self.config.startup_prompt,
                event_limit=self.config.event_limit,
                graph_limit=self.config.graph_limit,
                acknowledge=False,
                claim_events=False,
                consumer_instance_id=f"bridge-{self.session_id}",
                recall_mode=self.config.startup_recall_mode,
            )
            LOGGER.info(
                "hydrated SYNAPSE-S2 client session agent_id=%s context_id=%s new_events=%s latest_event_id=%s",
                self.config.agent_id,
                self.config.context_id,
                self.hydration.get("new_event_count"),
                self.hydration.get("latest_event_id"),
            )
            self._enter_cortex_session(backend)
            return self.hydration
        except Exception as exc:
            self.start_error = safe_public_error(
                exc,
                fallback="client session startup failed",
            )
            LOGGER.exception(
                "SYNAPSE-S2 client startup hydration failed agent_id=%s context_id=%s",
                self.config.agent_id,
                self.config.context_id,
            )
            self.hydration = {
                "action": "client-session-start",
                "enabled": True,
                "context_id": self.config.context_id,
                "agent_id": self.config.agent_id,
                "error": safe_public_error(
                    exc,
                    fallback="client session startup failed",
                ),
            }
            return self.hydration

    def finish(self, *, reason: str = "mcp-server-exit", final_note: str = "") -> dict[str, Any]:
        if self._finished:
            return {
                "action": "client-session-finish",
                "dropped": False,
                "reason": "already-finished",
                "session_id": self.session_id,
            }
        self._finished = True
        if not self.config.enabled:
            return {
                "action": "client-session-finish",
                "dropped": False,
                "reason": "disabled",
                "session_id": self.session_id,
            }
        ended_at = time.time()
        text = self._render_boundary_note(reason=reason, ended_at=ended_at, final_note=final_note)
        redacted_text, redaction_count = capture_daemon.redact_capture_text(text)
        capture_id = self._boundary_capture_id()
        try:
            drop_path = capture_daemon.write_capture_drop(
                root=self.config.capture_root,
                context_id=self.config.context_id,
                source_tag=self.config.source_tag,
                speaker=self.config.agent_id,
                text=redacted_text,
                capture_id=capture_id,
                metadata={
                    "client_session_bridge": True,
                    # The capture daemon turns the exactly-once boundary drop
                    # into the durable typed follow-up trace. This keeps MCP
                    # shutdown fast without weakening the Cortex provenance.
                    "cortex_governor": bool(self.cortex_session_id),
                    "trace_type": "follow_up",
                    "cortex_trace_type": "follow_up",
                    "truth_posture": "observed",
                    "confidence": 0.76,
                    "deferred_cortex_commit": bool(self.cortex_session_id),
                    "session_id": self.session_id,
                    "cortex_session_id": self.cortex_session_id,
                    "agent_id": self.config.agent_id,
                    "started_at": self.started_at,
                    "ended_at": ended_at,
                    "duration_seconds": round(ended_at - (self.started_at or ended_at), 3),
                    "redaction_count": int(redaction_count),
                    "startup_error": self.start_error,
                    "cortex_error": self.cortex_error,
                    "startup_latest_event_id": self._hydration_int("latest_event_id"),
                    "startup_new_event_count": self._hydration_int("new_event_count"),
                },
            )
            cortex_result = self._commit_cortex_boundary(
                text=redacted_text,
                reason=reason,
                ended_at=ended_at,
                drop_path=drop_path,
                redaction_count=redaction_count,
            )
            LOGGER.info(
                "dropped SYNAPSE-S2 client session boundary agent_id=%s context_id=%s path=%s",
                self.config.agent_id,
                self.config.context_id,
                drop_path,
            )
            return {
                "action": "client-session-finish",
                "dropped": True,
                "drop_path": str(drop_path),
                "redaction_count": int(redaction_count),
                "session_id": self.session_id,
                "capture_id": capture_id,
                **cortex_result,
            }

        except Exception as exc:
            LOGGER.exception(
                "SYNAPSE-S2 client session boundary capture failed agent_id=%s context_id=%s",
                self.config.agent_id,
                self.config.context_id,
            )
            return {
                "action": "client-session-finish",
                "dropped": False,
                "error": safe_public_error(
                    exc,
                    fallback="client session finish failed",
                ),
                "session_id": self.session_id,
            }

    def _boundary_capture_id(self) -> str:
        payload = "\x1f".join(
            (
                "client-session-boundary.v2",
                self.config.context_id,
                self.config.agent_id,
                self.session_id,
            )
        ).encode("utf-8")
        return "s2cap_" + hashlib.sha256(payload).hexdigest()[:32]

    def _render_boundary_note(
        self,
        *,
        reason: str,
        ended_at: float,
        final_note: str,
    ) -> str:
        duration = round(ended_at - (self.started_at or ended_at), 3)
        hydration = self.hydration or {}
        recall_items = hydration.get("recall_items")
        if not isinstance(recall_items, list):
            recall_items = []
        recall_summary = "; ".join(str(item) for item in recall_items[:3]) or "none"
        return "\n".join(
            line
            for line in (
                "SYNAPSE-S2 MCP client session ended.",
                f"Agent: {self.config.agent_id}",
                f"Context: {self.config.context_id}",
                f"Session ID: {self.session_id}",
                f"Reason: {reason}",
                f"Duration seconds: {duration}",
                f"Startup new deployments: {hydration.get('new_event_count', 0)}",
                f"Startup latest event id: {hydration.get('latest_event_id', 0)}",
                f"Startup recall highlights: {recall_summary}",
                f"Startup error: {self.start_error}" if self.start_error else "",
                f"Final note: {final_note}" if final_note else "",
            )
            if line
        )

    def _hydration_int(self, key: str) -> int:
        try:
            return int((self.hydration or {}).get(key, 0))
        except (TypeError, ValueError):
            return 0

    @property
    def cortex_session_id(self) -> str:
        if isinstance(self.cortex_session, dict):
            return str(self.cortex_session.get("session_id", "") or "")
        return ""

    def _enter_cortex_session(self, backend: mlx_backend.SpikingAttentionBackend) -> None:
        if not self.config.enabled or not self.config.cortex_enabled:
            return
        try:
            session = backend.enter_spiking_cortex(
                context_id=self.config.context_id,
                agent_id=self.config.agent_id,
                task=self.config.startup_prompt,
                mode=self.config.cortex_mode,
                recall_mode=self.config.startup_recall_mode,
            )
            session_id = str(session.get("session_id", "") or "")
            if session_id and session_id in backend.cortex_sessions:
                leased_session = dict(backend.cortex_sessions[session_id])
                leased_session.update(
                    {
                        "client_bridge_session_id": self.session_id,
                        "lease_kind": "mcp-client",
                        "owner_pid": os.getpid(),
                        "owner_ppid": os.getppid(),
                        "owner_started_at": self.started_at or time.time(),
                    }
                )
                backend.cortex_sessions[session_id] = backend._normalize_cortex_session(
                    leased_session
                )
                backend._persist_runtime_state()
                session = dict(session)
                session.update(backend.cortex_sessions[session_id])
            self.cortex_session = session
            if isinstance(self.hydration, dict):
                self.hydration["client_cortex_enabled"] = True
                self.hydration["client_cortex_session_id"] = session_id
                self.hydration["client_cortex_session"] = session
                if session.get("cortex_state"):
                    self.hydration["cortex_state"] = session["cortex_state"]
            LOGGER.info(
                "entered SYNAPSE-S2 Cortex session agent_id=%s context_id=%s session_id=%s",
                self.config.agent_id,
                self.config.context_id,
                session.get("session_id"),
            )
        except Exception as exc:
            self.cortex_error = safe_public_error(
                exc,
                fallback="cortex session enter failed",
            )
            if isinstance(self.hydration, dict):
                self.hydration["client_cortex_enabled"] = True
                self.hydration["client_cortex_error"] = self.cortex_error
            LOGGER.exception(
                "SYNAPSE-S2 Cortex session enter failed agent_id=%s context_id=%s",
                self.config.agent_id,
                self.config.context_id,
            )

    def _commit_cortex_boundary(
        self,
        *,
        text: str,
        reason: str,
        ended_at: float,
        drop_path: Path,
        redaction_count: int,
    ) -> dict[str, Any]:
        if not self.config.enabled or not self.config.cortex_enabled:
            return {"cortex_committed": False, "cortex_reason": "disabled"}
        session_id = self.cortex_session_id
        if not session_id:
            return {
                "cortex_committed": False,
                "cortex_reason": "no-cortex-session",
                "cortex_error": self.cortex_error,
            }
        backend = self.backend or mlx_backend.get_control_plane_backend()
        if backend.control_plane_only:
            self._mark_cortex_session_finished(
                backend,
                reason=reason,
                ended_at=ended_at,
            )
            return {
                "cortex_committed": False,
                "cortex_queued": True,
                "cortex_reason": "exactly-once-capture-queued",
                "cortex_session_id": session_id,
                "cortex_trace_type": "follow_up",
            }
        try:
            commit = backend.commit_cortical_trace(
                context_id=self.config.context_id,
                agent_id=self.config.agent_id,
                session_id=session_id,
                trace_type="follow_up",
                truth_posture="observed",
                text=text,
                confidence=0.76,
                evidence={
                    "client_session_bridge": True,
                    "session_id": self.session_id,
                    "cortex_session_id": session_id,
                    "reason": reason,
                    "ended_at": ended_at,
                    "drop_path": str(drop_path),
                    "redaction_count": int(redaction_count),
                    "startup_error": self.start_error,
                },
            )
            self._mark_cortex_session_finished(backend, reason=reason, ended_at=ended_at)
            return {
                "cortex_committed": True,
                "cortex_session_id": session_id,
                "cortex_memory_id": commit.get("memory_id", ""),
                "cortex_trace_type": commit.get("trace_type", ""),
            }
        except Exception as exc:
            self.cortex_error = safe_public_error(
                exc,
                fallback="cortex boundary commit failed",
            )
            self._mark_cortex_session_finished(backend, reason=reason, ended_at=ended_at)
            LOGGER.exception(
                "SYNAPSE-S2 Cortex boundary commit failed agent_id=%s context_id=%s session_id=%s",
                self.config.agent_id,
                self.config.context_id,
                session_id,
            )
            return {
                "cortex_committed": False,
                "cortex_session_id": session_id,
                "cortex_error": self.cortex_error,
            }

    def _mark_cortex_session_finished(
        self,
        backend: mlx_backend.SpikingAttentionBackend,
        *,
        reason: str,
        ended_at: float,
    ) -> None:
        session_id = self.cortex_session_id
        if not session_id:
            return
        session = backend.cortex_sessions.get(session_id)
        if not isinstance(session, dict):
            return
        finished_session = dict(session)
        finished_session.update(
            {
                "status": "finished",
                "finished_at": ended_at,
                "finish_reason": str(reason or "client-session-finish"),
                "updated_at": ended_at,
            }
        )
        backend.cortex_sessions[session_id] = backend._normalize_cortex_session(finished_session)
        try:
            backend._persist_runtime_state()
        except Exception:
            LOGGER.exception(
                "failed to persist finished Cortex session agent_id=%s context_id=%s session_id=%s",
                self.config.agent_id,
                self.config.context_id,
                session_id,
            )


def run_with_client_session_bridge(run_server: Callable[[], Any]) -> Any:
    bridge = ClientSessionBridge.from_environment()
    bridge.start()
    try:
        return run_server()
    finally:
        bridge.finish(reason="mcp-server-exit")


def _resolve_agent_id(env: Mapping[str, str]) -> str:
    configured = env.get("SYNAPSE_S2_CLIENT_AGENT_ID", "").strip()
    if configured:
        return mlx_backend.sanitize_agent_id(configured)
    if env.get("CODEX_PROJECT_DIR"):
        return "codex-desktop"
    if env.get("CLAUDE_PROJECT_DIR"):
        return "claude-code"
    return "local-mcp-client"


def _env_enabled(raw: str) -> bool:
    return str(raw or "").strip().lower() not in {"0", "false", "no", "off", "disabled"}


def _env_int(raw: str | None, *, default: int) -> int:
    try:
        value = int(str(raw if raw is not None else default).strip())
    except (TypeError, ValueError):
        return int(default)
    return max(1, value)

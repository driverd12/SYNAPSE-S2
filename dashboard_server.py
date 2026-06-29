from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import logging
import os
import platform
import re
import subprocess
import sys
import time
import tomllib
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from capture_daemon import CaptureInboxDaemon
import mlx_backend
from transcript_capture import TranscriptCaptureManager


LOGGER = logging.getLogger("synapse_s2.dashboard")
logging.basicConfig(
    level=os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper(),
    stream=sys.stderr,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    force=True,
)

ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
MAX_JSON_BODY_BYTES = 128 * 1024
MAX_TEXT_BYTES = 64 * 1024
DEFAULT_CONTEXT = os.getenv("SYNAPSE_S2_DASHBOARD_CONTEXT", "default")
CONFIRMATION_TOKEN_TTL_SECONDS = 120.0
MAX_CONFIRMATION_TOKENS = 256
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class DashboardError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class DashboardRuntime:
    """Small request router shared by the HTTP handler and unit tests."""

    def __init__(self, backend: mlx_backend.SpikingAttentionBackend | None = None) -> None:
        self._backend = backend
        self.started_at = time.time()
        self._system_info_cache: dict[str, Any] | None = None
        self._confirmation_tokens: dict[str, dict[str, Any]] = {}

    @property
    def backend(self) -> mlx_backend.SpikingAttentionBackend:
        if self._backend is None:
            self._backend = mlx_backend.get_backend()
        return self._backend

    def capture_daemon(self) -> CaptureInboxDaemon:
        return CaptureInboxDaemon(
            root=os.getenv("SYNAPSE_S2_CAPTURE_ROOT"),
            backend=self.backend,
        )

    def transcript_capture(self) -> TranscriptCaptureManager:
        return TranscriptCaptureManager(
            root=os.getenv("SYNAPSE_S2_CAPTURE_ROOT"),
            backend=self.backend,
        )

    def handle(
        self,
        method: str,
        raw_path: str,
        body: bytes = b"",
    ) -> tuple[int, dict[str, str], bytes]:
        parsed = urlparse(raw_path)
        try:
            if parsed.path.startswith("/api/"):
                return self._handle_api(method.upper(), parsed.path, parsed.query, body)
            if method.upper() != "GET":
                raise DashboardError(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")
            return self._serve_static(parsed.path)
        except DashboardError as exc:
            return self._json_response({"error": exc.message}, status=exc.status)
        except ValueError as exc:
            return self._json_response({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            error_id = f"dash_{uuid.uuid4().hex[:12]}"
            LOGGER.exception("dashboard request failed for %s %s", method, raw_path)
            payload = {"error": "dashboard request failed", "error_id": error_id}
            if self._debug_error_details_enabled():
                payload["detail"] = str(exc)
            return self._json_response(payload, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_api(
        self,
        method: str,
        path: str,
        query: str,
        body: bytes,
    ) -> tuple[int, dict[str, str], bytes]:
        params = parse_qs(query, keep_blank_values=False)
        if method == "GET" and path == "/api/status":
            context = self._context_from_params(params)
            return self._json_response(self.backend.status(context_id=context))
        if method == "GET" and path == "/api/profile":
            benchmark = self._bool_param(params, "benchmark_quick_prune", False)
            return self._json_response(
                self.backend.resource_profile(benchmark_quick_prune=benchmark)
            )
        if method == "GET" and path == "/api/graph":
            context = self._context_from_params(params)
            limit = self._int_param(params, "limit", 50, minimum=1, maximum=500)
            return self._json_response(
                self.backend.list_memory_graph(context_id=context, limit=limit)
            )
        if method == "GET" and path == "/api/context-events":
            context = self._context_from_params(params)
            limit = self._int_param(params, "limit", 50, minimum=1, maximum=500)
            since_event_id = self._int_param(
                params,
                "since_event_id",
                0,
                minimum=0,
                maximum=9_999_999_999,
            )
            return self._json_response(
                self.backend.list_context_events(
                    context_id=context,
                    since_event_id=since_event_id,
                    limit=limit,
                )
            )
        if method == "GET" and path == "/api/context-cursors":
            context = self._context_from_params(params)
            limit = self._int_param(params, "limit", 50, minimum=1, maximum=500)
            return self._json_response(
                self.backend.list_context_cursors(
                    context_id=context,
                    limit=limit,
                )
            )
        if method == "GET" and path == "/api/capture-inbox":
            return self._json_response(self.capture_daemon().status())
        if method == "GET" and path == "/api/apps":
            return self._json_response(self.transcript_capture().detect_running_apps())
        if method == "GET" and path == "/api/app-connections":
            return self._json_response(self.transcript_capture().list_app_connections())
        if method == "GET" and path == "/api/self-test":
            context = self._context_from_params(params)
            include_apps = self._bool_param(params, "include_apps", True)
            return self._json_response(
                self.self_test(context_id=context, include_apps=include_apps)
            )
        if method == "GET" and path == "/api/monday-readiness":
            context = self._context_from_params(params)
            include_apps = self._bool_param(params, "include_apps", True)
            return self._json_response(
                self.monday_readiness(context_id=context, include_apps=include_apps)
            )
        if method == "GET" and path == "/api/context-health":
            context = self._context_from_params(params)
            return self._json_response(self.context_health(context_id=context))
        if method == "GET" and path == "/api/memory-hygiene":
            context = self._context_from_params(params)
            limit = self._int_param(params, "limit", 25, minimum=1, maximum=100)
            return self._json_response(self.memory_hygiene(context_id=context, limit=limit))
        if method == "GET" and path == "/api/doctor":
            context = self._context_from_params(params)
            include_apps = self._bool_param(params, "include_apps", True)
            repair_plan = self._bool_param(params, "repair_plan", True)
            return self._json_response(
                self.doctor_report(
                    context_id=context,
                    include_apps=include_apps,
                    repair_plan=repair_plan,
                )
            )
        if method == "GET" and path == "/api/start-work":
            context = self._context_from_params(params)
            agent_raw = str(params.get("agent_id", ["codex-desktop"])[0] or "codex-desktop")
            prompt = str(params.get("prompt", [""])[0] or "")
            return self._json_response(
                self.start_work(
                    context_id=context,
                    agent_id=mlx_backend.sanitize_agent_id(agent_raw),
                    prompt=prompt,
                )
            )
        if method == "GET" and path == "/api/cortex/state":
            context = self._context_from_params(params)
            agent_raw = str(params.get("agent_id", [""])[0] or "").strip()
            agent_id = mlx_backend.sanitize_agent_id(agent_raw) if agent_raw else ""
            limit = self._int_param(params, "limit", 50, minimum=1, maximum=500)
            return self._json_response(
                self.backend.get_cortex_state(
                    context_id=context,
                    agent_id=agent_id,
                    limit=limit,
                )
            )
        if method == "GET" and path == "/api/snapshot":
            context = self._context_from_params(params)
            limit = self._int_param(params, "limit", 50, minimum=1, maximum=500)
            include_graph = self._bool_param(params, "include_graph", True)
            return self._json_response(
                self.snapshot(context_id=context, limit=limit, include_graph=include_graph)
            )

        if method == "POST" and path == "/api/app-connect/preflight":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            app_target = self._app_connect_target(payload, context_id=context)
            preview = {
                "action": "app-connect-preflight",
                "context_id": context,
                "app_name": app_target["app_name"],
                "bundle_id": app_target["bundle_id"],
                "pid": app_target["pid"],
                "source_tag": app_target["source_tag"],
                "speaker": app_target["speaker"],
                "allow_manual": app_target["allow_manual"],
                "mode": "operator-confirmed-local-app-attach",
            }
            return self._json_response(
                self._issue_confirmation_token(
                    action="app-connect",
                    target=app_target,
                    preview=preview,
                )
            )
        if method == "POST" and path == "/api/app-snapshot/preflight":
            payload = self._parse_json_body(body)
            snapshot_target = self._app_snapshot_target(payload)
            connection = self._connection_preview(snapshot_target["connection_id"])
            preview = {
                "action": "app-snapshot-preflight",
                "connection_id": snapshot_target["connection_id"],
                "connection": connection,
                "mode": "operator-confirmed-local-app-snapshot",
                "preview_note": "snapshot text is harvested only after confirmation",
            }
            return self._json_response(
                self._issue_confirmation_token(
                    action="app-snapshot",
                    target=snapshot_target,
                    preview=preview,
                )
            )
        if method == "POST" and path == "/api/app-snapshot/preview":
            payload = self._parse_json_body(body)
            snapshot_target = self._app_snapshot_target(payload)
            preview = self.transcript_capture().preview_app_snapshot(
                connection_id=snapshot_target["connection_id"],
            )
            preview["receipt"] = self._operation_receipt(
                action="preview-app-snapshot",
                status=str(preview.get("quality_badge", {}).get("status") or "degraded"),
                title=f"{preview.get('app_name', 'App')} snapshot preview",
                summary=(
                    f"{preview.get('snapshot_quality', {}).get('signal_chars', 0)} signal chars; "
                    "no memory write performed"
                ),
                context_id=str(preview.get("context_id") or DEFAULT_CONTEXT),
                source_tag=str(preview.get("source_tag") or "app-connect"),
                quality=str(preview.get("quality_badge", {}).get("label") or "preview"),
                next_action=str(preview.get("quality_badge", {}).get("next_action") or ""),
            )
            return self._json_response(preview)
        if method == "POST" and path == "/api/capture-inbox/preflight":
            payload = self._parse_json_body(body)
            max_files = self._max_files_from_payload(payload)
            preflight = self.capture_daemon().preflight(max_files=max_files)
            target = self._capture_inbox_target(
                max_files=max_files,
                preflight=preflight,
            )
            return self._json_response(
                self._issue_confirmation_token(
                    action="capture-inbox-process",
                    target=target,
                    preview=preflight,
                )
            )

        if method == "POST" and path == "/api/cortex/enter":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            agent_id = mlx_backend.sanitize_agent_id(str(payload.get("agent_id", "dashboard-ui")))
            task = self._text_payload(payload, "task", max_bytes=MAX_TEXT_BYTES)
            return self._json_response(
                self.backend.enter_spiking_cortex(
                    context_id=context,
                    agent_id=agent_id,
                    task=task,
                    mode=str(payload.get("mode", "strict")),
                )
            )
        if method == "POST" and path == "/api/cortex/tick":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            agent_id = mlx_backend.sanitize_agent_id(str(payload.get("agent_id", "dashboard-ui")))
            session_id = self._text_payload(payload, "session_id", max_bytes=512)
            observation = str(payload.get("observation", "") or "").strip()
            proposed_action = str(payload.get("proposed_action", "") or "").strip()
            if len(observation.encode("utf-8")) > MAX_TEXT_BYTES:
                raise DashboardError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "observation is too large")
            if len(proposed_action.encode("utf-8")) > MAX_TEXT_BYTES:
                raise DashboardError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "proposed_action is too large")
            intended_files = self._string_list_payload(payload, "intended_files")
            intended_tools = self._string_list_payload(payload, "intended_tools")
            try:
                confidence = float(payload.get("confidence", 0.5))
            except (TypeError, ValueError) as exc:
                raise DashboardError(HTTPStatus.BAD_REQUEST, "confidence must be numeric") from exc
            return self._json_response(
                self.backend.cortex_tick(
                    context_id=context,
                    agent_id=agent_id,
                    session_id=session_id,
                    observation=observation,
                    proposed_action=proposed_action,
                    intended_files=intended_files,
                    intended_tools=intended_tools,
                    mutation_intent=bool(payload.get("mutation_intent", False)),
                    confidence=confidence,
                )
            )
        if method == "POST" and path == "/api/cortex/close":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            agent_id = mlx_backend.sanitize_agent_id(str(payload.get("agent_id", "dashboard-ui")))
            session_id = self._text_payload(payload, "session_id", max_bytes=512)
            reason = str(payload.get("reason", "operator-ended-dashboard-session") or "").strip()
            return self._json_response(
                self.backend.close_spiking_cortex(
                    context_id=context,
                    agent_id=agent_id,
                    session_id=session_id,
                    reason=reason,
                )
            )
        if method == "POST" and path == "/api/cortex/commit":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            agent_id = mlx_backend.sanitize_agent_id(str(payload.get("agent_id", "dashboard-ui")))
            text = self._text_payload(payload, "text", max_bytes=MAX_TEXT_BYTES)
            evidence = payload.get("evidence", {})
            if evidence is None:
                evidence = {}
            if not isinstance(evidence, dict):
                raise DashboardError(HTTPStatus.BAD_REQUEST, "evidence must be an object")
            confidence_raw = payload.get("confidence", None)
            confidence: float | None = None
            if confidence_raw is not None and confidence_raw != "":
                try:
                    confidence = float(confidence_raw)
                except (TypeError, ValueError) as exc:
                    raise DashboardError(HTTPStatus.BAD_REQUEST, "confidence must be numeric") from exc
            return self._json_response(
                self.backend.commit_cortical_trace(
                    context_id=context,
                    agent_id=agent_id,
                    session_id=str(payload.get("session_id", "") or ""),
                    trace_type=str(payload.get("trace_type", "") or ""),
                    truth_posture=str(payload.get("truth_posture", "observed") or "observed"),
                    text=text,
                    evidence=evidence,
                    confidence=confidence,
                )
            )
        if method == "POST" and path == "/api/cortex/moderate":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            memory_id = self._text_payload(payload, "memory_id", max_bytes=512)
            action = str(payload.get("action", "") or "").strip()
            reason = str(payload.get("reason", "") or "").strip()
            if len(reason.encode("utf-8")) > MAX_TEXT_BYTES:
                raise DashboardError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "reason is too large")
            confirm = False
            if action.strip().lower().replace("-", "_") == "prune":
                confirm = self._required_bool(payload, "confirm")
            return self._json_response(
                self.backend.moderate_cortex_trace(
                    context_id=context,
                    memory_id=memory_id,
                    action=action,
                    reason=reason,
                    source_surface="dashboard-cortex",
                    confirm=confirm,
                )
            )
        if method == "POST" and path == "/api/wrap-session/preview":
            payload = self._parse_json_body(body)
            return self._json_response(self.wrap_session_preview(payload))
        if method == "POST" and path == "/api/wrap-session":
            payload = self._parse_json_body(body)
            return self._json_response(self.wrap_session(payload))
        if method == "POST" and path == "/api/pin-memory":
            payload = self._parse_json_body(body)
            return self._json_response(self.pin_memory(payload))

        if method == "POST" and path == "/api/toggle":
            payload = self._parse_json_body(body)
            enabled = self._required_bool(payload, "enabled")
            context = self._context_from_payload(payload)
            if context == "global":
                context = None
            return self._json_response(self.backend.set_enabled(enabled, context_id=context))
        if method == "POST" and path == "/api/query":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            prompt = self._text_payload(payload, "prompt", max_bytes=MAX_TEXT_BYTES)
            started = time.perf_counter()
            result = self.backend.query_text(prompt, context_id=context)
            elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
            results = self._parse_recall_result(result)
            return self._json_response(
                {
                    "context_id": context,
                    "prompt": prompt,
                    "result": result,
                    "results": results,
                    "latency_ms": elapsed_ms,
                    "diagnostics": {
                        "result_count": len(results),
                        "runtime": "ready" if self.backend.is_enabled(context) else "disabled",
                        "embedding_provider": self.backend.embedding_provider_info(),
                        "memory_entry_revision": self.backend.memory_store.entries_revision(
                            context_id=context,
                            include_global=True,
                        ),
                    },
                    "query_id": self._query_id(context=context),
                }
            )
        if method == "POST" and path == "/api/remember":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            tag = mlx_backend.sanitize_tag(str(payload.get("tag", "")).strip())
            if not tag:
                raise DashboardError(HTTPStatus.BAD_REQUEST, "tag is required")
            text = self._text_payload(payload, "text", max_bytes=MAX_TEXT_BYTES)
            metadata = self._metadata_payload(payload)
            registration = self.backend.register_text_trace(
                tag=tag,
                context_id=context,
                text=text,
                metadata=metadata,
            )
            registration["agent_deployment"] = self._publish_agent_deployment(
                context_id=context,
                source_surface="dashboard",
                event_type="remember-trace",
                summary=f"{registration['tag']} captured and published",
                payload={
                    "tag": registration["tag"],
                    "memory_id": registration["memory_id"],
                    "source_text": text,
                    "metadata": metadata,
                    "spike_count": registration["spike_count"],
                    "neuron_count": registration["neuron_count"],
                },
            )
            return self._json_response(registration)
        if method == "POST" and path == "/api/ingest":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            tag = mlx_backend.sanitize_tag(str(payload.get("tag", "dashboard-brief")).strip())
            text = self._text_payload(payload, "text", max_bytes=MAX_TEXT_BYTES)
            threshold = float(payload.get("surprise_threshold", 0.58))
            min_sentences = int(payload.get("min_segment_sentences", 1))
            ingestion = self.backend.ingest_text_events(
                text=text,
                context_id=context,
                source_tag=tag,
                surprise_threshold=threshold,
                min_segment_sentences=min_sentences,
                metadata={"source": "dashboard"},
            )
            ingestion["agent_deployment"] = self._publish_agent_deployment(
                context_id=context,
                source_surface="dashboard",
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
            return self._json_response(ingestion)
        if method == "POST" and path == "/api/capture-conversation":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            tag = mlx_backend.sanitize_tag(str(payload.get("source_tag", payload.get("tag", "codex-session"))).strip())
            text = self._text_payload(payload, "text", max_bytes=MAX_TEXT_BYTES)
            speaker = mlx_backend.sanitize_agent_id(str(payload.get("speaker", "operator")))
            threshold = float(payload.get("surprise_threshold", 0.5))
            min_sentences = int(payload.get("min_segment_sentences", 1))
            capture = self.backend.capture_conversation(
                text=text,
                context_id=context,
                source_tag=tag,
                speaker=speaker,
                surprise_threshold=threshold,
                min_segment_sentences=min_sentences,
                metadata={
                    **self._metadata_payload(payload),
                    "source_surface": "dashboard",
                },
            )
            return self._json_response(capture)
        if method == "POST" and path == "/api/app-connect":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            app_target = self._app_connect_target(payload, context_id=context)
            self._consume_confirmation_token(
                token=str(payload.get("confirmation_token", "") or ""),
                action="app-connect",
                target=app_target,
            )
            return self._json_response(
                self._with_receipt(
                    self.transcript_capture().connect_running_app(
                    app_name=app_target["app_name"],
                    bundle_id=app_target["bundle_id"],
                    pid=int(app_target["pid"]),
                    context_id=context,
                    source_tag=app_target["source_tag"],
                    speaker=app_target["speaker"],
                    metadata={
                        **app_target["metadata"],
                        "source_surface": "dashboard-app-connect",
                    },
                    confirmed=True,
                    allow_manual=bool(app_target["allow_manual"]),
                    ),
                    action="app-connect",
                    status="ready",
                    title=f"{app_target['app_name']} attached",
                    summary="Local app connection is available for preview, snapshot, and selected-text capture.",
                    context_id=context,
                    source_tag=app_target["source_tag"],
                    next_action="Preview the app snapshot before writing memory.",
                )
            )
        if method == "POST" and path == "/api/app-snapshot":
            payload = self._parse_json_body(body)
            snapshot_target = self._app_snapshot_target(payload)
            self._consume_confirmation_token(
                token=str(payload.get("confirmation_token", "") or ""),
                action="app-snapshot",
                target=snapshot_target,
            )
            return self._json_response(
                self.transcript_capture().capture_app_snapshot(
                    connection_id=snapshot_target["connection_id"],
                    metadata={
                        **snapshot_target["metadata"],
                        "source_surface": "dashboard-app-snapshot",
                    },
                    confirmed=True,
                )
            )
        if method == "POST" and path == "/api/app-selection-capture":
            payload = self._parse_json_body(body)
            if payload.get("confirm") is not True:
                raise DashboardError(
                    HTTPStatus.BAD_REQUEST,
                    "confirm must be true before capturing selected app text",
                )
            return self._json_response(
                self._with_receipt(
                    self.transcript_capture().capture_app_selected_text(
                    connection_id=self._text_payload(
                        payload,
                        "connection_id",
                        max_bytes=512,
                    ),
                    text=self._text_payload(payload, "text", max_bytes=MAX_TEXT_BYTES),
                    metadata={
                        **self._metadata_payload(payload),
                        "source_surface": "dashboard-app-selection-capture",
                    },
                    confirmed=True,
                    ),
                    action="capture-app-selected-text",
                    status="ready",
                    title="Selected app text captured",
                    summary="Exact selected text was redacted and written to memory.",
                    context_id=DEFAULT_CONTEXT,
                    source_tag="app-selected-text",
                    next_action="Use recall to verify the captured content is findable.",
                )
            )
        if method == "POST" and path == "/api/prune-memory":
            payload = self._parse_json_body(body)
            if payload.get("confirm") is not True:
                raise DashboardError(
                    HTTPStatus.BAD_REQUEST,
                    "confirm must be true before pruning memory graph data",
                )
            context = self._context_from_payload(payload)
            try:
                event_id = int(payload.get("event_id", 0) or 0)
            except (TypeError, ValueError) as exc:
                raise DashboardError(HTTPStatus.BAD_REQUEST, "event_id must be an integer") from exc
            prune = self.backend.prune_memory(
                context_id=context,
                target_type=str(payload.get("target_type", "")),
                memory_id=str(payload.get("memory_id", "")),
                tag=str(payload.get("tag", "")),
                relationship_id=str(payload.get("relationship_id", "")),
                event_id=event_id,
                reason=str(payload.get("reason", "")),
                source_surface="dashboard",
            )
            return self._json_response(prune)
        if method == "POST" and path == "/api/context-ack":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            agent_id = mlx_backend.sanitize_agent_id(str(payload.get("agent_id", "")))
            try:
                last_event_id = int(payload.get("last_event_id", 0))
            except (TypeError, ValueError) as exc:
                raise DashboardError(
                    HTTPStatus.BAD_REQUEST,
                    "last_event_id must be an integer",
                ) from exc
            return self._json_response(
                self.backend.ack_context_events(
                    context_id=context,
                    agent_id=agent_id,
                    last_event_id=max(0, last_event_id),
                )
            )
        if method == "POST" and path == "/api/quick-prune":
            return self._json_response(self.backend.run_quick_pruning(trigger="dashboard"))
        if method == "POST" and path == "/api/certify-runtime":
            payload = self._parse_json_body(body)
            output_path = ""
            if payload.get("write_evidence") is True:
                stamp = time.strftime("%Y%m%d-%H%M%S")
                output_path = str(self._export_root() / f"native-certification-{stamp}.json")
            return self._json_response(
                self.backend.certify_runtime(
                    strict_native=bool(payload.get("strict_native", False)),
                    require_gpu=bool(payload.get("require_gpu", False)),
                    benchmark_quick_prune=bool(payload.get("benchmark_quick_prune", False)),
                    require_resource_envelope=bool(
                        payload.get("require_resource_envelope", False)
                    ),
                    target_min_mb=float(
                        payload.get(
                            "target_min_mb",
                            mlx_backend.DEFAULT_RESOURCE_TARGET_MIN_MB,
                        )
                    ),
                    target_max_mb=float(
                        payload.get(
                            "target_max_mb",
                            mlx_backend.DEFAULT_RESOURCE_TARGET_MAX_MB,
                        )
                    ),
                    output_path=output_path or None,
                )
            )
        if method == "POST" and path == "/api/sleep":
            return self._json_response(self.backend.run_deep_sleep_consolidation())
        if method == "POST" and path == "/api/backup":
            export_root = self._export_root()
            stamp = time.strftime("%Y%m%d-%H%M%S")
            backup_path = export_root / f"dashboard-memory-{stamp}.sqlite3"
            return self._json_response(self.backend.backup_memory(path=backup_path))
        if method == "POST" and path == "/api/readiness-audit":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            return self._json_response(self.readiness_audit(context_id=context))
        if method == "POST" and path == "/api/evidence-pack":
            payload = self._parse_json_body(body)
            context = self._context_from_payload(payload)
            return self._json_response(self.evidence_pack(context_id=context))
        if method == "POST" and path == "/api/memory-hygiene/action":
            payload = self._parse_json_body(body)
            return self._json_response(self.memory_hygiene_action(payload))
        if method == "POST" and path == "/api/capture-inbox/process":
            payload = self._parse_json_body(body)
            max_files = self._max_files_from_payload(payload)
            preflight = self.capture_daemon().preflight(max_files=max_files)
            target = self._capture_inbox_target(
                max_files=max_files,
                preflight=preflight,
            )
            self._consume_confirmation_token(
                token=str(payload.get("confirmation_token", "") or ""),
                action="capture-inbox-process",
                target=target,
            )
            return self._json_response(
                self.capture_daemon().process_once(max_files=max_files)
            )

        raise DashboardError(HTTPStatus.NOT_FOUND, "route not found")

    def snapshot(
        self,
        *,
        context_id: str,
        limit: int = 50,
        include_graph: bool = True,
    ) -> dict[str, Any]:
        context = mlx_backend.sanitize_context_id(context_id)
        timings: dict[str, float] = {}
        snapshot_started = time.perf_counter()

        def timed(stage: str, callback: Any) -> Any:
            started = time.perf_counter()
            try:
                return callback()
            finally:
                timings[stage] = round((time.perf_counter() - started) * 1000.0, 3)

        status = timed("status", lambda: self.backend.status(context_id=context))
        profile = timed(
            "profile",
            lambda: self.backend.resource_profile(benchmark_quick_prune=False),
        )
        if include_graph:
            graph = timed("graph", lambda: self.backend.list_memory_graph(context_id=context, limit=limit))
        else:
            timings["graph"] = 0.0
            graph = self._deferred_graph(context=context, status=status)
        system = timed("system", lambda: self._system_info(context_id=context))
        capture_inbox = timed("capture_inbox", lambda: self.capture_daemon().status())
        cortex_state = timed(
            "cortex_state",
            lambda: self.backend.get_cortex_state(context_id=context, limit=limit),
        )
        timings["total"] = round((time.perf_counter() - snapshot_started) * 1000.0, 3)
        return {
            "context_id": context,
            "status": status,
            "profile": profile,
            "graph": graph,
            "system": system,
            "capture_inbox": capture_inbox,
            "cortex_state": cortex_state,
            "timings_ms": timings,
            "generated_at": time.time(),
        }

    def _publish_agent_deployment(
        self,
        *,
        context_id: str,
        source_surface: str,
        event_type: str,
        summary: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self.backend.publish_context_event(
            context_id=context_id,
            source_surface=source_surface,
            event_type=event_type,
            summary=summary,
            payload=payload,
        )

    def _deferred_graph(self, *, context: str, status: dict[str, Any]) -> dict[str, Any]:
        return {
            "context_id": context,
            "deferred": True,
            "entries": [],
            "relationships": [],
            "entry_count": int(status.get("memory_context_entry_count") or 0),
            "relationship_count": int(status.get("memory_context_relationship_count") or 0),
            "relationship_summary": {
                "total": int(status.get("memory_context_relationship_count") or 0),
                "temporal": None,
                "associative": None,
                "other": None,
                "by_type": {},
            },
            "memory_db_path": status.get("memory_db_path"),
        }

    def self_test(
        self,
        *,
        context_id: str,
        include_apps: bool = True,
    ) -> dict[str, Any]:
        context = mlx_backend.sanitize_context_id(context_id)
        started = time.perf_counter()
        components: dict[str, dict[str, Any]] = {}
        recommended_actions: list[str] = []

        def set_component(
            name: str,
            *,
            status: str,
            label: str,
            detail: str,
            **extra: Any,
        ) -> None:
            components[name] = {
                "status": status,
                "label": label,
                "detail": detail,
                **extra,
            }

        try:
            runtime_status = self.backend.status(context_id=context)
            resource_profile = self.backend.resource_profile(benchmark_quick_prune=False)
            runtime_ready = (
                bool(runtime_status.get("effective_enabled"))
                and str(runtime_status.get("runtime") or "").lower() == "ready"
            )
            runtime_detail = (
                f"{runtime_status.get('runtime', 'unknown')} runtime, "
                f"{int(runtime_status.get('num_neurons') or 0)} neurons, "
                f"{resource_profile.get('estimated_total_mb', 0)} MB estimated substrate"
            )
            set_component(
                "runtime",
                status="ready" if runtime_ready else "blocked",
                label="Runtime ready" if runtime_ready else "Runtime disabled",
                detail=runtime_detail,
                effective_enabled=bool(runtime_status.get("effective_enabled")),
                num_neurons=int(runtime_status.get("num_neurons") or 0),
                estimated_total_mb=resource_profile.get("estimated_total_mb"),
            )
            if not runtime_ready:
                recommended_actions.append("Enable the SYNAPSE-S2 core before relying on capture or recall.")

            memory_path = str(runtime_status.get("memory_db_path") or "")
            memory_entries = int(runtime_status.get("memory_context_entry_count") or 0)
            memory_relationships = int(runtime_status.get("memory_context_relationship_count") or 0)
            set_component(
                "memory",
                status="ready" if memory_path else "blocked",
                label="Memory store reachable" if memory_path else "Memory store unavailable",
                detail=(
                    f"{memory_entries} entries and {memory_relationships} relationships "
                    f"in context {context}"
                ),
                entry_count=memory_entries,
                relationship_count=memory_relationships,
                memory_db_path=memory_path,
            )
            if not memory_path:
                recommended_actions.append("Check the SQLite memory store path and local write permissions.")

            provider = dict(runtime_status.get("embedding_provider") or {})
            if not provider:
                provider = self.backend.embedding_provider_info()
            provider_error = str(provider.get("error") or "")
            provider_type = str(provider.get("provider_type") or "")
            embedding_status = (
                "blocked"
                if provider_error or provider_type == "unavailable"
                else "ready"
            )
            provider_id = str(provider.get("provider") or "unknown")
            model_id = str(provider.get("model_id") or provider.get("model") or provider_id)
            set_component(
                "embedding",
                status=embedding_status,
                label="Embedding provider ready"
                if embedding_status == "ready"
                else "Embedding provider blocked",
                detail=provider_error or f"{provider_id} / {model_id}",
                provider=provider_id,
                model_id=model_id,
                provider_type=provider_type,
                semantic=bool(provider.get("semantic")),
                local_only=bool(provider.get("local_only", True)),
            )
            if embedding_status != "ready":
                recommended_actions.append("Resolve the embedding provider load path before trusting semantic recall.")
        except Exception as exc:
            error = str(exc)
            set_component(
                "runtime",
                status="blocked",
                label="Runtime check failed",
                detail=error,
            )
            set_component(
                "memory",
                status="blocked",
                label="Memory check failed",
                detail=error,
                entry_count=0,
                relationship_count=0,
            )
            set_component(
                "embedding",
                status="blocked",
                label="Embedding check failed",
                detail=error,
            )
            recommended_actions.append("Inspect runtime startup logs; the core status call failed.")

        try:
            context_events = self.backend.list_context_events(
                context_id=context,
                since_event_id=0,
                limit=1,
            )
            set_component(
                "context_bus",
                status="ready",
                label="Context bus reachable",
                detail=(
                    f"{context_events.get('delivery_mode', 'polling')} delivery, "
                    f"{int(context_events.get('event_count') or 0)} recent event sample"
                ),
                delivery_mode=context_events.get("delivery_mode"),
                event_count=int(context_events.get("event_count") or 0),
            )
        except Exception as exc:
            set_component(
                "context_bus",
                status="blocked",
                label="Context bus blocked",
                detail=str(exc),
                event_count=0,
            )
            recommended_actions.append("Repair context bus reads before depending on client hydration.")

        try:
            inbox_status = self.capture_daemon().status()
            pending = int(inbox_status.get("pending_file_count") or 0)
            errors = int(inbox_status.get("error_file_count") or 0)
            set_component(
                "capture_inbox",
                status="blocked" if errors else "ready",
                label="Capture inbox ready" if not errors else "Capture inbox has errors",
                detail=(
                    f"{pending} pending files, {errors} error files, "
                    f"root {inbox_status.get('root', '')}"
                ),
                pending_file_count=pending,
                error_file_count=errors,
                root=inbox_status.get("root"),
            )
            if errors:
                recommended_actions.append("Process or clear capture inbox error files before more ingestion.")
        except Exception as exc:
            set_component(
                "capture_inbox",
                status="blocked",
                label="Capture inbox blocked",
                detail=str(exc),
                pending_file_count=0,
                error_file_count=0,
            )
            recommended_actions.append("Check capture inbox root permissions and daemon state.")

        try:
            manager = self.transcript_capture()
            connections = manager.list_app_connections()
            app_payload: dict[str, Any] = {
                "app_count": None,
                "apps": [],
                "warning": "",
            }
            if include_apps:
                app_payload = manager.detect_running_apps()
            app_count_raw = app_payload.get("app_count")
            app_count = int(app_count_raw) if app_count_raw is not None else None
            connection_count = int(connections.get("connection_count") or 0)
            warning = str(app_payload.get("warning") or "")
            app_status = "ready" if connection_count or (app_count or 0) > 0 else "degraded"
            detail = (
                f"{connection_count} attached connection"
                f"{'' if connection_count == 1 else 's'}"
            )
            if app_count is not None:
                detail = f"{app_count} detected app{'' if app_count == 1 else 's'}, {detail}"
            if warning:
                detail = f"{detail}; detection warning: {warning}"
                app_status = "degraded"
            set_component(
                "app_connect",
                status=app_status,
                label="App Connect ready" if app_status == "ready" else "App Connect needs attention",
                detail=detail,
                app_count=app_count,
                connection_count=connection_count,
                mode=app_payload.get("mode", "skipped-app-detection"),
            )
            if app_status != "ready":
                recommended_actions.append(
                    "Use Detect to list running apps, then attach one or use selected-text capture."
                )
        except Exception as exc:
            set_component(
                "app_connect",
                status="blocked",
                label="App Connect blocked",
                detail=str(exc),
                app_count=0,
                connection_count=0,
            )
            recommended_actions.append("Grant local Automation or Accessibility permissions for app snapshots.")

        statuses = [component["status"] for component in components.values()]
        if any(status == "blocked" for status in statuses):
            overall_status = "blocked"
        elif any(status == "degraded" for status in statuses):
            overall_status = "degraded"
        else:
            overall_status = "ready"
        return {
            "action": "self-test",
            "context_id": context,
            "overall_status": overall_status,
            "ready": overall_status == "ready",
            "components": components,
            "recommended_actions": recommended_actions,
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
            "generated_at": time.time(),
        }

    def context_health(self, *, context_id: str) -> dict[str, Any]:
        context = mlx_backend.sanitize_context_id(context_id)
        started = time.perf_counter()
        factors: list[dict[str, Any]] = []
        recommended_actions: list[str] = []
        score = 100

        def add_factor(
            factor_id: str,
            *,
            label: str,
            status: str,
            detail: str,
            points_lost: int = 0,
            action: str = "",
        ) -> None:
            nonlocal score
            clean_status = status if status in {"ready", "degraded", "blocked"} else "blocked"
            loss = max(0, int(points_lost))
            score -= loss
            factors.append(
                {
                    "id": factor_id,
                    "label": label,
                    "status": clean_status,
                    "detail": detail,
                    "points_lost": loss,
                }
            )
            if action and clean_status != "ready":
                recommended_actions.append(action)

        self_test_payload = self.self_test(context_id=context, include_apps=False)
        for component_id, component in self_test_payload.get("components", {}).items():
            status = str(component.get("status") or "blocked")
            if status == "blocked":
                loss = 18 if component_id in {"runtime", "memory", "embedding"} else 10
            elif status == "degraded":
                loss = 6
            else:
                loss = 0
            add_factor(
                f"self_test_{component_id}",
                label=str(component.get("label") or component_id),
                status=status,
                detail=str(component.get("detail") or ""),
                points_lost=loss,
            )

        hygiene = self.memory_hygiene(context_id=context, limit=25)
        hygiene_loss = min(22, int(hygiene.get("backlog_count") or 0) * 4)
        memory_quality_score = max(0, 100 - hygiene_loss)
        add_factor(
            "memory_quality",
            label="Memory quality",
            status="ready"
            if hygiene_loss == 0
            else "degraded"
            if hygiene_loss < 16
            else "blocked",
            detail=(
                f"{hygiene.get('backlog_count', 0)} hygiene review items; "
                f"quality score {memory_quality_score}"
            ),
            points_lost=hygiene_loss,
            action="Review Memory Hygiene before relying on stale or low-signal traces.",
        )

        try:
            profile = self.backend.resource_profile(benchmark_quick_prune=False)
            envelope_ok = bool(profile.get("within_target_envelope"))
            add_factor(
                "resource_envelope",
                label="Resource envelope",
                status="ready" if envelope_ok else "degraded",
                detail=(
                    f"{profile.get('estimated_total_mb', 0)} MB estimated topology memory"
                ),
                points_lost=0 if envelope_ok else 6,
                action="Tune SYNAPSE_S2_NEURONS or resource envelope settings.",
            )
        except Exception as exc:
            add_factor(
                "resource_envelope",
                label="Resource envelope",
                status="blocked",
                detail=str(exc),
                points_lost=10,
                action="Run Doctor and inspect resource profile errors.",
            )

        score = max(0, min(100, score))
        if score >= 86:
            overall_status = "ready"
        elif score >= 60:
            overall_status = "degraded"
        else:
            overall_status = "blocked"
        return {
            "action": "context-health",
            "context_id": context,
            "status": overall_status,
            "score": score,
            "memory_quality_score": memory_quality_score,
            "factors": factors,
            "recommended_actions": self._unique_strings(
                [
                    *recommended_actions,
                    *list(self_test_payload.get("recommended_actions") or []),
                ]
            ),
            "hygiene_summary": hygiene.get("queue_summary", {}),
            "receipt": self._operation_receipt(
                action="context-health",
                status=overall_status,
                title=f"Context health {score}/100",
                summary=f"{len(factors)} factors checked for {context}",
                context_id=context,
                quality=str(memory_quality_score),
                next_action=(
                    "Proceed with Start Work."
                    if overall_status == "ready"
                    else "Resolve degraded factors before depending on recall."
                ),
            ),
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
            "generated_at": time.time(),
        }

    def memory_hygiene(self, *, context_id: str, limit: int = 25) -> dict[str, Any]:
        context = mlx_backend.sanitize_context_id(context_id)
        graph = self.backend.list_memory_graph(context_id=context, limit=250)
        entries = list(graph.get("entries") or [])
        duplicate_seen: dict[str, str] = {}
        review_items: list[dict[str, Any]] = []
        queue_summary: dict[str, int] = {}

        for entry in entries:
            item = self._memory_hygiene_item(entry, duplicate_seen=duplicate_seen)
            if item is None:
                continue
            review_items.append(item)
            for category in item["categories"]:
                queue_summary[category] = queue_summary.get(category, 0) + 1

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        review_items.sort(
            key=lambda item: (
                severity_order.get(str(item.get("severity") or "low"), 3),
                -float(item.get("updated_at") or 0.0),
            )
        )
        bounded_items = review_items[: max(1, min(int(limit), 100))]
        backlog_count = len(review_items)
        status = "ready" if backlog_count == 0 else "degraded" if backlog_count < 8 else "blocked"
        return {
            "action": "memory-hygiene",
            "context_id": context,
            "status": status,
            "backlog_count": backlog_count,
            "review_items": bounded_items,
            "queue_summary": dict(sorted(queue_summary.items())),
            "memory_quality_score": max(0, 100 - min(60, backlog_count * 5)),
            "recommended_actions": self._memory_hygiene_recommendations(queue_summary),
            "receipt": self._operation_receipt(
                action="memory-hygiene",
                status=status,
                title=f"{backlog_count} memory hygiene item{'s' if backlog_count != 1 else ''}",
                summary="Review stale, low-signal, duplicate, or sensitive-looking memory before reuse.",
                context_id=context,
                quality=str(max(0, 100 - min(60, backlog_count * 5))),
                next_action="Open the queue and prune, demote, or recapture flagged memory.",
            ),
            "generated_at": time.time(),
        }

    def memory_hygiene_action(self, payload: dict[str, Any]) -> dict[str, Any]:
        context = self._context_from_payload(payload)
        action = str(payload.get("action", "acknowledge") or "acknowledge").strip().lower()
        memory_id = str(payload.get("memory_id", "") or "").strip()
        reason = str(payload.get("reason", "") or "").strip()
        if action == "prune":
            if payload.get("confirm") is not True:
                raise DashboardError(
                    HTTPStatus.BAD_REQUEST,
                    "confirm must be true before pruning memory from hygiene",
                )
            result = self.backend.prune_memory(
                context_id=context,
                target_type="event",
                memory_id=memory_id,
                reason=reason or "memory hygiene prune",
                source_surface="dashboard-memory-hygiene",
            )
            return {
                "action": "memory-hygiene-action",
                "context_id": context,
                "hygiene_action": "prune",
                "memory_id": memory_id,
                "result": result,
                "receipt": self._operation_receipt(
                    action="memory-hygiene-action",
                    status="ready",
                    title="Memory item pruned",
                    summary=reason or "Memory hygiene removed one graph item.",
                    context_id=context,
                    next_action="Refresh Memory Hygiene.",
                ),
            }

        audit = self.backend.publish_context_event(
            context_id=context,
            source_surface="dashboard-memory-hygiene",
            event_type="memory-hygiene-action",
            summary=f"memory hygiene {action}: {memory_id or 'queue'}",
            payload={
                "hygiene_action": action,
                "memory_id": memory_id,
                "reason": reason,
            },
        )
        return {
            "action": "memory-hygiene-action",
            "context_id": context,
            "hygiene_action": action,
            "memory_id": memory_id,
            "agent_deployment": audit,
            "receipt": self._operation_receipt(
                action="memory-hygiene-action",
                status="ready",
                title=f"Memory hygiene {action}",
                summary=reason or "Hygiene action recorded on the context bus.",
                context_id=context,
                event_count=1,
                next_action="Refresh Memory Hygiene.",
            ),
        }

    def doctor_report(
        self,
        *,
        context_id: str,
        include_apps: bool = True,
        repair_plan: bool = True,
    ) -> dict[str, Any]:
        context = mlx_backend.sanitize_context_id(context_id)
        started = time.perf_counter()
        checks: list[dict[str, Any]] = []

        def add_check(
            check_id: str,
            *,
            label: str,
            status: str,
            detail: str,
            repair: str,
        ) -> None:
            checks.append(
                {
                    "id": check_id,
                    "label": label,
                    "status": status if status in {"ready", "degraded", "blocked"} else "blocked",
                    "detail": detail,
                    "repair": repair,
                }
            )

        status_payload = self.backend.status(context_id=context)
        provider = dict(status_payload.get("embedding_provider") or {})
        memory_path = Path(str(status_payload.get("memory_db_path") or ""))
        add_check(
            "python",
            label="Python runtime",
            status="ready" if sys.executable else "blocked",
            detail=f"{sys.version.split()[0]} at {sys.executable}",
            repair="Run from the project virtualenv or reinstall local launcher.",
        )
        add_check(
            "memory_db",
            label="SQLite memory",
            status="ready" if memory_path else "blocked",
            detail=str(memory_path),
            repair="Set SYNAPSE_S2_MEMORY_DB to a writable local SQLite path.",
        )
        provider_error = str(provider.get("error") or "")
        provider_type = str(provider.get("provider_type") or "")
        add_check(
            "embedding_provider",
            label="Embedding provider",
            status="blocked" if provider_error or provider_type == "unavailable" else "ready",
            detail=provider_error or str(provider.get("provider") or "unknown"),
            repair="Use semantic-hash fallback or resolve the MLX neural model path.",
        )
        for module in ("mlx", "mlx.core", "mlxsnn", "fastmcp", "mcp"):
            dependency = self._dependency_status(module)
            add_check(
                f"dependency_{module.replace('.', '_')}",
                label=f"Dependency {module}",
                status="ready" if dependency["importable"] else "degraded",
                detail=str(dependency.get("origin") or "not importable"),
                repair=f"Install or repair optional dependency {module}.",
            )
        mcp_check = self._mcp_tool_name_check()
        add_check(
            "mcp_tool_names",
            label="MCP tool names",
            status="ready" if not mcp_check["invalid_tool_names"] else "blocked",
            detail=mcp_check["detail"],
            repair="Rename MCP tools to contain only alphanumeric characters and underscores.",
        )
        try:
            inbox = self.capture_daemon().status()
            errors = int(inbox.get("error_file_count") or 0)
            add_check(
                "capture_inbox",
                label="Capture inbox",
                status="ready" if errors == 0 else "degraded",
                detail=f"{inbox.get('pending_file_count', 0)} pending, {errors} errors",
                repair="Process pending drops or inspect error files in the capture root.",
            )
        except Exception as exc:
            add_check(
                "capture_inbox",
                label="Capture inbox",
                status="blocked",
                detail=str(exc),
                repair="Check capture root permissions and daemon configuration.",
            )
        if include_apps:
            try:
                apps = self.transcript_capture().detect_running_apps()
                add_check(
                    "app_connect_detect",
                    label="App Connect detection",
                    status="ready" if int(apps.get("app_count") or 0) > 0 else "degraded",
                    detail=f"{apps.get('app_count', 0)} detected apps",
                    repair="Grant Automation or use manual app connect plus selected-text fallback.",
                )
            except Exception as exc:
                add_check(
                    "app_connect_detect",
                    label="App Connect detection",
                    status="blocked",
                    detail=str(exc),
                    repair="Grant macOS Automation/Accessibility permissions or use selected-text capture.",
                )

        if any(check["status"] == "blocked" for check in checks):
            overall_status = "blocked"
        elif any(check["status"] == "degraded" for check in checks):
            overall_status = "degraded"
        else:
            overall_status = "ready"
        plan = [
            check["repair"]
            for check in checks
            if check["status"] != "ready" and str(check.get("repair") or "").strip()
        ]
        if repair_plan and not plan:
            plan = ["No repair required. Run Start Work and capture a Wrap Session at handoff."]
        return {
            "action": "doctor-report",
            "context_id": context,
            "overall_status": overall_status,
            "checks": checks,
            "repair_plan": self._unique_strings(plan) if repair_plan else [],
            "environment": {
                "MLX_DEVICE": os.getenv("MLX_DEVICE", ""),
                "SYNAPSE_S2_STATE_PATH": os.getenv("SYNAPSE_S2_STATE_PATH", ""),
                "SYNAPSE_S2_MEMORY_DB": os.getenv("SYNAPSE_S2_MEMORY_DB", ""),
                "SYNAPSE_S2_EXPORT_DIR": os.getenv("SYNAPSE_S2_EXPORT_DIR", ""),
            },
            "status": status_payload,
            "receipt": self._operation_receipt(
                action="doctor-report",
                status=overall_status,
                title=f"Doctor {overall_status}",
                summary=f"{len(checks)} checks completed",
                context_id=context,
                next_action=(
                    "No repair required."
                    if overall_status == "ready"
                    else "Apply the repair plan, then rerun Doctor."
                ),
            ),
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
            "generated_at": time.time(),
        }

    def start_work(
        self,
        *,
        context_id: str,
        agent_id: str,
        prompt: str = "",
    ) -> dict[str, Any]:
        context = mlx_backend.sanitize_context_id(context_id)
        agent = mlx_backend.sanitize_agent_id(agent_id or "codex-desktop")
        started = time.perf_counter()
        health = self.context_health(context_id=context)
        hygiene = self.memory_hygiene(context_id=context, limit=8)
        hydrate = self.backend.hydrate_agent_context(
            context_id=context,
            agent_id=agent,
            prompt=prompt,
            event_limit=20,
            graph_limit=30,
            acknowledge=True,
        )
        recipes = self.operator_recipes()
        cortex_state = hydrate.get("cortex_state") if isinstance(hydrate.get("cortex_state"), dict) else {}
        current_objective = (
            str(cortex_state.get("active_goal") or "").strip()
            or str(prompt or "").strip()
            or "No active goal recorded. Define the task in Cortex Governor before mutating files."
        )
        recall_items = list(hydrate.get("recall_items") or [])[:5]
        risks = self._unique_dict_items(
            [
                *list(cortex_state.get("risks") or []),
                *list(cortex_state.get("unverified_assumptions") or []),
                *list(cortex_state.get("stale_or_uncertain_memories") or []),
                *list(cortex_state.get("contradictions") or []),
            ],
            key="memory_id",
        )[:5]
        recent_traces = [
            event
            for event in hydrate.get("events", [])[:10]
            if any(
                token in str(event.get(field, "")).lower()
                for field in ("source_surface", "event_type", "summary")
                for token in ("app", "session", "client", "wrap", "capture")
            )
        ][:5]
        if not recent_traces:
            recent_traces = list(hydrate.get("events", [])[:5])
        next_actions = self._unique_strings(
            [
                *list(health.get("recommended_actions") or []),
                *list(hygiene.get("recommended_actions") or []),
                "Use App Connect Preview before writing app snapshots to memory.",
                "Capture a Wrap Session before switching projects or clients.",
            ]
        )[:8]
        brief_sections = [
            {
                "id": "current_objective",
                "title": "Current objective",
                "status": "ready" if current_objective else "degraded",
                "body": current_objective,
                "items": [{"label": current_objective}],
                "confidence": 0.86 if cortex_state.get("active_goal") else 0.58,
                "source_memories": self._source_memory_refs(cortex_state.get("active_sessions") or []),
            },
            {
                "id": "relevant_memories",
                "title": "Relevant memories",
                "status": "ready" if recall_items else "degraded",
                "body": hydrate.get("recall_result") or "No relevant memories recalled yet; capture or query current context.",
                "items": recall_items,
                "confidence": 0.82 if recall_items else 0.42,
                "source_memories": self._source_memory_refs(recall_items, hydrate.get("graph_entries") or []),
            },
            {
                "id": "open_risks",
                "title": "Open risks",
                "status": "blocked" if cortex_state.get("contradictions") else "degraded" if risks or hygiene.get("backlog_count") else "ready",
                "body": (
                    f"{len(risks)} risks or uncertain traces; {hygiene.get('backlog_count', 0)} hygiene items."
                    if risks or hygiene.get("backlog_count")
                    else "No unresolved risks surfaced in the current context."
                ),
                "items": risks or hygiene.get("review_items", [])[:3],
                "confidence": 0.78 if risks or hygiene.get("backlog_count") else 0.9,
                "source_memories": self._source_memory_refs(risks, hygiene.get("review_items", [])),
            },
            {
                "id": "recent_app_session_traces",
                "title": "Recent app/session traces",
                "status": "ready" if recent_traces else "degraded",
                "body": (
                    f"{len(recent_traces)} recent app, session, capture, or context-bus traces."
                    if recent_traces
                    else "No recent app or session traces for this cursor."
                ),
                "items": recent_traces,
                "confidence": 0.74 if recent_traces else 0.44,
                "source_memories": self._source_memory_refs(recent_traces),
            },
            {
                "id": "recommended_next_actions",
                "title": "Recommended next 3 actions",
                "status": "ready",
                "body": "Follow these before touching code or claiming success.",
                "items": next_actions[:3],
                "confidence": 0.88,
                "source_memories": self._source_memory_refs(
                    health.get("factors", []),
                    hygiene.get("review_items", []),
                ),
            },
            {
                "id": "health",
                "title": "Context health",
                "status": health["status"],
                "body": f"{health['score']}/100 with memory quality {health['memory_quality_score']}/100.",
                "confidence": 0.84,
                "source_memories": [],
            },
            {
                "id": "events",
                "title": "New durable events",
                "status": "ready" if hydrate.get("new_event_count", 0) else "degraded",
                "body": f"{hydrate.get('new_event_count', 0)} new context-bus events since last cursor.",
                "items": hydrate.get("events", [])[:5],
                "confidence": 0.8 if hydrate.get("new_event_count", 0) else 0.55,
                "source_memories": self._source_memory_refs(hydrate.get("events", [])),
            },
            {
                "id": "recall",
                "title": "Recall evidence",
                "status": "ready" if hydrate.get("recall_items") else "degraded",
                "body": hydrate.get("recall_result") or "No prompt recall yet; run Recall or capture current work.",
                "items": hydrate.get("recall_items", [])[:5],
                "confidence": 0.82 if hydrate.get("recall_items") else 0.42,
                "source_memories": self._source_memory_refs(hydrate.get("recall_items", [])),
            },
            {
                "id": "hygiene",
                "title": "Memory hygiene",
                "status": hygiene["status"],
                "body": f"{hygiene['backlog_count']} review items waiting.",
                "items": hygiene.get("review_items", [])[:5],
                "confidence": max(0.35, min(0.95, 1.0 - (int(hygiene.get("backlog_count") or 0) * 0.08))),
                "source_memories": self._source_memory_refs(hygiene.get("review_items", [])),
            },
            {
                "id": "recipes",
                "title": "Recommended recipes",
                "status": "ready",
                "body": "Use the first recipe that matches the current operator moment.",
                "items": recipes[:3],
                "confidence": 0.88,
                "source_memories": [],
            },
        ]
        return {
            "action": "start-work",
            "context_id": context,
            "agent_id": agent,
            "prompt": str(prompt or ""),
            "status": health["status"],
            "score": health["score"],
            "memory_quality_score": health["memory_quality_score"],
            "brief_sections": brief_sections,
            "next_actions": next_actions,
            "recipes": recipes,
            "context_health": health,
            "memory_hygiene": hygiene,
            "agent_brief": hydrate,
            "goals_ledger": cortex_state,
            "receipt": self._operation_receipt(
                action="start-work",
                status=health["status"],
                title=f"Start Work brief for {context}",
                summary=f"{len(brief_sections)} sections generated for {agent}",
                context_id=context,
                next_action=next_actions[0] if next_actions else "Proceed with governed work.",
            ),
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
            "generated_at": time.time(),
        }

    def _source_memory_refs(self, *collections: Any) -> list[dict[str, str]]:
        refs: list[dict[str, str]] = []
        seen: set[str] = set()

        def add_ref(memory_id: str, label: str = "", source: str = "") -> None:
            clean_id = str(memory_id or "").strip()
            if not clean_id or clean_id in seen:
                return
            seen.add(clean_id)
            refs.append(
                {
                    "memory_id": clean_id,
                    "label": self._compact_text(str(label or clean_id), 96),
                    "source": self._compact_text(str(source or "memory"), 48),
                }
            )

        def visit(item: Any, source: str = "") -> None:
            if isinstance(item, dict):
                memory_id = (
                    item.get("memory_id")
                    or item.get("pinned_memory_id")
                    or item.get("source_memory_id")
                    or item.get("target_memory_id")
                )
                label = (
                    item.get("tag")
                    or item.get("label")
                    or item.get("summary")
                    or item.get("excerpt")
                    or item.get("event_type")
                    or memory_id
                )
                if memory_id:
                    add_ref(str(memory_id), str(label or memory_id), source or str(item.get("source_surface") or "memory"))
                for nested_key in ("items", "events", "relationships", "source_memories"):
                    nested = item.get(nested_key)
                    if isinstance(nested, list):
                        visit(nested, source or nested_key)
                return
            if isinstance(item, str):
                for match in re.finditer(r"\bid=([^,\)\s]+)", item):
                    add_ref(match.group(1), item.split("(", 1)[0].strip(), source or "recall")
                return
            if isinstance(item, (list, tuple)):
                for nested_item in item:
                    visit(nested_item, source)

        for collection in collections:
            visit(collection)
        return refs[:8]

    def _unique_dict_items(
        self,
        items: list[Any],
        *,
        key: str,
    ) -> list[dict[str, Any]]:
        unique: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            identity = str(item.get(key) or item.get("tag") or item.get("excerpt") or item)
            if identity in seen:
                continue
            seen.add(identity)
            unique.append(item)
        return unique

    def operator_recipes(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "daily_start",
                "title": "Start daily work",
                "description": "Open the daily trust loop before relying on memory or changing code.",
                "steps": [
                    "Run Start Work.",
                    "Resolve Doctor or Context Health blockers.",
                    "Use Recall for prior decisions before editing.",
                ],
            },
            {
                "id": "resume_work",
                "title": "Resume yesterday's work",
                "description": "Recover objective, risks, and useful traces before continuing.",
                "steps": [
                    "Run Start Work.",
                    "Review recent app/session traces.",
                    "Pin relevant memory into working context.",
                    "Enter Cortex before risky changes.",
                ],
            },
            {
                "id": "app_capture",
                "title": "Capture from an app",
                "description": "Attach a running local app and write only useful, previewed context.",
                "steps": [
                    "Detect apps and connect the target app.",
                    "Preview the app snapshot and inspect the quality badge.",
                    "Snapshot to memory only when the preview contains the intended content.",
                ],
            },
            {
                "id": "selected_text_capture",
                "title": "Capture exact selected text",
                "description": "Use this when Accessibility only exposes window metadata.",
                "steps": [
                    "Select the relevant text in the source app.",
                    "Use the selected-text fallback.",
                    "Confirm the receipt includes the expected source tag.",
                ],
            },
            {
                "id": "verify_before_claim",
                "title": "Verify before claiming success",
                "description": "Turn validation evidence into governed memory.",
                "steps": [
                    "Run Doctor / Repair.",
                    "Run the relevant test or self-test.",
                    "Commit a validation trace or Wrap Session with evidence.",
                ],
            },
            {
                "id": "memory_cleanup",
                "title": "Clean bad memory",
                "description": "Keep the graph useful by removing stale, noisy, or conflicting traces.",
                "steps": [
                    "Run Memory Hygiene.",
                    "Review stale, duplicate, low-confidence, or sensitive-looking items.",
                    "Promote, demote, prune, merge, or mark resolved.",
                ],
            },
            {
                "id": "handoff",
                "title": "Wrap a session",
                "description": "Capture the final verified state before switching tools or people.",
                "steps": [
                    "Summarize decisions, tests, and follow-ups.",
                    "Preview Wrap Session.",
                    "Confirm Wrap Session to persist handoff memory.",
                ],
            },
            {
                "id": "evidence_pack",
                "title": "Create evidence pack",
                "description": "Collect proof before showing the system to someone else.",
                "steps": [
                    "Run Doctor.",
                    "Run Evidence Pack.",
                    "Keep the operation receipt with the backup or report path.",
                ],
            },
        ]

    def wrap_session_preview(self, payload: dict[str, Any]) -> dict[str, Any]:
        context = self._context_from_payload(payload)
        agent_id = mlx_backend.sanitize_agent_id(str(payload.get("agent_id", "codex-desktop")))
        text = str(payload.get("text", "") or "").strip()
        operation_log = payload.get("operation_log", [])
        if not text and not operation_log:
            raise DashboardError(
                HTTPStatus.BAD_REQUEST,
                "text or operation_log is required for wrap session preview",
            )
        preview_text = self._render_wrap_session_text(
            context_id=context,
            agent_id=agent_id,
            text=text,
            operation_log=operation_log,
        )
        source_tag = mlx_backend.sanitize_tag(
            str(payload.get("source_tag", f"wrap-session-{agent_id}") or f"wrap-session-{agent_id}")
        ).replace(" ", "-")
        return {
            "action": "wrap-session-preview",
            "context_id": context,
            "agent_id": agent_id,
            "preview_text": preview_text,
            "proposed_capture": {
                "source_tag": source_tag,
                "speaker": agent_id,
                "metadata": {
                    "source_surface": "dashboard-wrap-session",
                    "operation_log_count": len(operation_log) if isinstance(operation_log, list) else 0,
                },
            },
            "capture_required": True,
            "receipt": self._operation_receipt(
                action="wrap-session-preview",
                status="ready",
                title="Wrap Session preview ready",
                summary=f"{len(preview_text)} preview characters prepared",
                context_id=context,
                source_tag=source_tag,
                next_action="Confirm Wrap Session to write this handoff to memory.",
            ),
        }

    def wrap_session(self, payload: dict[str, Any]) -> dict[str, Any]:
        if payload.get("confirm") is not True:
            raise DashboardError(
                HTTPStatus.BAD_REQUEST,
                "confirm must be true before wrapping a session into memory",
            )
        preview = self.wrap_session_preview(payload)
        capture = self.backend.capture_conversation(
            text=preview["preview_text"],
            context_id=preview["context_id"],
            source_tag=preview["proposed_capture"]["source_tag"],
            speaker=preview["proposed_capture"]["speaker"],
            surprise_threshold=0.5,
            min_segment_sentences=1,
            metadata={
                **preview["proposed_capture"]["metadata"],
                **self._metadata_payload(payload),
                "wrap_session": True,
                "agent_id": preview["agent_id"],
            },
        )
        capture["action"] = "wrap-session"
        capture["receipt"] = self._operation_receipt(
            action="wrap-session",
            status="ready",
            title="Session wrapped into memory",
            summary=(
                f"{capture.get('event_count', 0)} events and "
                f"{capture.get('relationship_count', 0)} relationships captured"
            ),
            context_id=preview["context_id"],
            source_tag=preview["proposed_capture"]["source_tag"],
            event_count=int(capture.get("event_count") or 0),
            relationship_count=int(capture.get("relationship_count") or 0),
            next_action="Run Start Work in the next client or session to hydrate this handoff.",
        )
        return capture

    def pin_memory(self, payload: dict[str, Any]) -> dict[str, Any]:
        context = self._context_from_payload(payload)
        agent_id = mlx_backend.sanitize_agent_id(
            str(payload.get("agent_id", "dashboard-ui") or "dashboard-ui")
        )
        memory_id = str(payload.get("memory_id", "") or "").strip()
        if not memory_id:
            raise DashboardError(HTTPStatus.BAD_REQUEST, "memory_id is required")
        note = str(payload.get("note", "") or "").strip()
        if len(note.encode("utf-8")) > MAX_TEXT_BYTES:
            raise DashboardError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "note is too large")
        entry = self.backend.memory_store.get_entry(memory_id)
        if entry is None:
            raise DashboardError(HTTPStatus.NOT_FOUND, "memory was not found")
        entry_context = str(entry.get("context_id") or "")
        if entry_context not in {context, "global"}:
            raise DashboardError(
                HTTPStatus.NOT_FOUND,
                "memory was not found in the selected context",
            )

        pinned_tag = str(entry.get("tag") or memory_id)
        source_excerpt = self._compact_text(str(entry.get("source_text") or ""), 640)
        note_line = f"Operator note: {note}" if note else "Operator note: none provided."
        trace_text = "\n".join(
            [
                "Feature: Recall result pinned for the current operator task.",
                f"Context: {context}",
                f"Agent: {agent_id}",
                f"Pinned memory: {pinned_tag}",
                f"Pinned memory id: {memory_id}",
                f"Original context: {entry_context}",
                note_line,
                "Evidence excerpt:",
                source_excerpt or "(empty source text)",
            ]
        ).strip()
        commit = self.backend.commit_cortical_trace(
            context_id=context,
            agent_id=agent_id,
            session_id="dashboard-recall-pin",
            trace_type="evidence",
            truth_posture="operator-confirmed",
            text=trace_text,
            evidence={
                "source": "dashboard-recall-pin",
                "pinned_memory_id": memory_id,
                "pinned_tag": pinned_tag,
                "pinned_context_id": entry_context,
                "note_sha256": hashlib.sha256(note.encode("utf-8")).hexdigest()
                if note
                else "",
            },
            confidence=0.9,
        )
        return {
            "action": "pin-memory",
            "context_id": context,
            "agent_id": agent_id,
            "pinned_memory_id": memory_id,
            "pinned_tag": pinned_tag,
            "pinned_context_id": entry_context,
            "trace_type": commit.get("trace_type", "evidence"),
            "truth_posture": commit.get("truth_posture", "operator-confirmed"),
            "confidence": commit.get("confidence"),
            "memory_id": commit.get("memory_id"),
            "tag": commit.get("tag"),
            "agent_deployment": commit.get("agent_deployment"),
            "receipt": self._operation_receipt(
                action="pin-memory",
                status="ready",
                title="Recall pinned to working memory",
                summary=f"{pinned_tag} pinned as operator-confirmed evidence.",
                context_id=context,
                source_tag=str(commit.get("tag") or ""),
                event_count=1,
                quality="operator-confirmed",
                next_action="Use the pinned evidence in Cortex Governor or Wrap Session handoff.",
            ),
        }

    def readiness_audit(self, *, context_id: str) -> dict[str, Any]:
        context = mlx_backend.sanitize_context_id(context_id)
        started = time.perf_counter()
        status = self.backend.status(context_id=context)
        profile = self.backend.resource_profile(benchmark_quick_prune=False)
        graph = self.backend.list_memory_graph(context_id=context, limit=20)
        prompt = self._audit_prompt(graph)
        query_result = ""
        if prompt:
            query_result = self.backend.query_text(prompt, context_id=context)
        target_max = float(
            profile.get("target_envelope_mb", {}).get(
                "max",
                mlx_backend.DEFAULT_RESOURCE_TARGET_MAX_MB,
            )
        )
        estimated_mb = float(profile.get("estimated_total_mb") or 0.0)
        checks = {
            "runtime_ready": bool(status.get("effective_enabled"))
            and str(status.get("runtime", "")).lower() == "ready",
            "mlx_ready": bool(status.get("mlx_available")),
            "mlxsnn_ready": bool(status.get("mlxsnn_available")),
            "memory_ready": int(status.get("memory_context_entry_count") or 0) > 0,
            "graph_ready": int(graph.get("relationship_count") or 0) > 0,
            "resource_ceiling_ok": estimated_mb <= target_max,
            "query_ready": bool(query_result) and "disabled" not in query_result.lower(),
        }
        failed_checks = [name for name, passed in checks.items() if not passed]
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
        return {
            "action": "readiness-audit",
            "audit_id": f"audit_{time.strftime('%Y%m%d_%H%M%S')}_{context}",
            "context_id": context,
            "ready": not failed_checks,
            "checks": checks,
            "failed_checks": failed_checks,
            "elapsed_ms": elapsed_ms,
            "query_prompt": prompt,
            "query_result": query_result,
            "graph_summary": graph.get("relationship_summary", {}),
            "status_summary": {
                "runtime": status.get("runtime"),
                "effective_enabled": status.get("effective_enabled"),
                "memory_context_entry_count": status.get("memory_context_entry_count"),
                "memory_context_relationship_count": status.get(
                    "memory_context_relationship_count"
                ),
                "quick_pruning_interval_seconds": status.get(
                    "quick_pruning_interval_seconds"
                ),
            },
            "resource_summary": {
                "estimated_total_mb": profile.get("estimated_total_mb"),
                "target_envelope_mb": profile.get("target_envelope_mb"),
                "mlx_device": profile.get("mlx_device"),
                "mlxsnn_lif_execution_path": profile.get("mlxsnn_lif_execution_path"),
            },
        }

    def monday_readiness(
        self,
        *,
        context_id: str,
        include_apps: bool = True,
    ) -> dict[str, Any]:
        context = mlx_backend.sanitize_context_id(context_id)
        started = time.perf_counter()
        checks: list[dict[str, Any]] = []
        recommended_actions: list[str] = []
        artifacts: dict[str, Any] = {}

        def add_check(
            check_id: str,
            *,
            label: str,
            status: str,
            detail: str,
            required: bool = True,
            metrics: dict[str, Any] | None = None,
        ) -> None:
            normalized_status = status if status in {"ready", "degraded", "blocked"} else "blocked"
            checks.append(
                {
                    "id": check_id,
                    "label": label,
                    "status": normalized_status,
                    "detail": detail,
                    "required": bool(required),
                    "metrics": metrics or {},
                }
            )

        try:
            self_test = self.self_test(context_id=context, include_apps=include_apps)
            artifacts["self_test"] = self_test
            recommended_actions.extend(self_test.get("recommended_actions", []))
            component_labels = {
                "runtime": "Core runtime",
                "memory": "Memory store",
                "embedding": "Embedding provider",
                "context_bus": "Context bus",
                "capture_inbox": "Capture inbox",
                "app_connect": "App Connect",
            }
            for component_id, label in component_labels.items():
                component = dict(self_test.get("components", {}).get(component_id) or {})
                if not component:
                    add_check(
                        component_id,
                        label=label,
                        status="blocked",
                        detail="component did not report",
                        required=component_id != "app_connect" or include_apps,
                    )
                    continue
                add_check(
                    component_id,
                    label=str(component.get("label") or label),
                    status=str(component.get("status") or "blocked"),
                    detail=str(component.get("detail") or ""),
                    required=component_id != "app_connect" or include_apps,
                    metrics={
                        key: value
                        for key, value in component.items()
                        if key
                        not in {
                            "status",
                            "label",
                            "detail",
                        }
                    },
                )
        except Exception as exc:
            add_check(
                "self_test",
                label="Self test",
                status="blocked",
                detail=str(exc),
                required=True,
            )
            recommended_actions.append("Run Self Test and inspect the failing component before demo use.")

        try:
            profile = self.backend.resource_profile(benchmark_quick_prune=True)
            artifacts["resource_profile"] = profile
            envelope = profile.get("target_envelope_mb") or {}
            estimated_mb = float(profile.get("estimated_total_mb") or 0.0)
            add_check(
                "resource_envelope",
                label="Resource envelope",
                status="ready" if profile.get("within_target_envelope") else "blocked",
                detail=(
                    f"{estimated_mb:.3f} MB estimated substrate inside "
                    f"{envelope.get('min', '?')}-{envelope.get('max', '?')} MB target"
                ),
                required=True,
                metrics={
                    "estimated_total_mb": profile.get("estimated_total_mb"),
                    "target_envelope_mb": envelope,
                    "num_neurons": profile.get("num_neurons"),
                    "dimension": profile.get("dimension"),
                },
            )
            quick = dict(profile.get("quick_pruning") or {})
            quick_ok = bool(quick.get("within_60ms_budget"))
            add_check(
                "quick_prune",
                label="Quick prune budget",
                status="ready" if quick_ok else "blocked",
                detail=(
                    f"{quick.get('elapsed_ms', '?')} ms quick-prune sample"
                    if quick
                    else "quick-prune benchmark did not return a sample"
                ),
                required=True,
                metrics=quick,
            )
            if not profile.get("within_target_envelope"):
                recommended_actions.append("Tune SYNAPSE_S2_NEURONS before demo; the memory substrate is outside target.")
            if not quick_ok:
                recommended_actions.append("Investigate quick-pruning latency before relying on long sessions.")
        except Exception as exc:
            add_check(
                "resource_envelope",
                label="Resource envelope",
                status="blocked",
                detail=str(exc),
                required=True,
            )
            add_check(
                "quick_prune",
                label="Quick prune budget",
                status="blocked",
                detail=str(exc),
                required=True,
            )
            recommended_actions.append("Run the resource profile locally and resolve the reported error.")

        try:
            benchmark = self.backend.benchmark_embedding_provider(
                text="SYNAPSE-S2 Monday readiness embedding warmup",
                runs=1,
            )
            artifacts["embedding_benchmark"] = benchmark
            nonzero = int(benchmark.get("vector_nonzero_count") or 0)
            latency_ms = float(benchmark.get("average_latency_ms") or 0.0)
            add_check(
                "embedding_latency",
                label="Embedding warm path",
                status="ready" if nonzero > 0 else "blocked",
                detail=f"{latency_ms:.3f} ms average embedding latency, {nonzero} nonzero dimensions",
                required=True,
                metrics={
                    "average_latency_ms": benchmark.get("average_latency_ms"),
                    "dimensions": benchmark.get("dimensions"),
                    "provider": benchmark.get("embedding_provider"),
                    "vector_nonzero_count": nonzero,
                },
            )
            if nonzero <= 0:
                recommended_actions.append("Resolve embedding vector generation before trusting recall quality.")
        except Exception as exc:
            add_check(
                "embedding_latency",
                label="Embedding warm path",
                status="blocked",
                detail=str(exc),
                required=True,
            )
            recommended_actions.append("Resolve the embedding provider load path before Monday demo.")

        try:
            audit = self.readiness_audit(context_id=context)
            artifacts["readiness_audit"] = audit
            failed_checks = list(audit.get("failed_checks") or [])
            add_check(
                "recall_audit",
                label="Recall audit",
                status="ready" if audit.get("ready") else "blocked",
                detail=(
                    "query and graph audit passed"
                    if audit.get("ready")
                    else f"failed checks: {', '.join(failed_checks) or 'unknown'}"
                ),
                required=True,
                metrics={
                    "failed_checks": failed_checks,
                    "elapsed_ms": audit.get("elapsed_ms"),
                    "query_prompt": audit.get("query_prompt"),
                },
            )
            if failed_checks:
                recommended_actions.append(
                    f"Fix readiness audit checks before demo: {', '.join(failed_checks)}."
                )
        except Exception as exc:
            add_check(
                "recall_audit",
                label="Recall audit",
                status="blocked",
                detail=str(exc),
                required=True,
            )
            recommended_actions.append("Seed real memory and rerun Readiness Audit before demo use.")

        required_checks = [check for check in checks if check["required"]]
        optional_checks = [check for check in checks if not check["required"]]

        def check_value(check: dict[str, Any]) -> float:
            if check["status"] == "ready":
                return 1.0
            if check["status"] == "degraded":
                return 0.5
            return 0.0

        weighted_total = (len(required_checks) * 2.0) + len(optional_checks)
        weighted_score = (
            sum(check_value(check) * (2.0 if check["required"] else 1.0) for check in checks)
            / weighted_total
            if weighted_total
            else 0.0
        )
        required_failures = [
            check for check in required_checks if check["status"] != "ready"
        ]
        optional_failures = [
            check for check in optional_checks if check["status"] != "ready"
        ]
        if any(check["status"] == "blocked" for check in required_failures):
            overall_status = "blocked"
        elif required_failures or optional_failures:
            overall_status = "degraded"
        else:
            overall_status = "ready"

        unique_actions: list[str] = []
        seen_actions: set[str] = set()
        for action in recommended_actions:
            clean = " ".join(str(action or "").split())
            if clean and clean not in seen_actions:
                seen_actions.add(clean)
                unique_actions.append(clean)

        return {
            "action": "monday-readiness",
            "context_id": context,
            "overall_status": overall_status,
            "demo_ready": not required_failures,
            "score": int(round(weighted_score * 100)),
            "checks": checks,
            "summary": {
                "required_ready": len(required_checks) - len(required_failures),
                "required_total": len(required_checks),
                "optional_ready": len(optional_checks) - len(optional_failures),
                "optional_total": len(optional_checks),
                "blocked": sum(1 for check in checks if check["status"] == "blocked"),
                "degraded": sum(1 for check in checks if check["status"] == "degraded"),
            },
            "critical_failures": [
                {
                    "id": check["id"],
                    "label": check["label"],
                    "detail": check["detail"],
                }
                for check in required_failures
            ],
            "recommended_actions": unique_actions,
            "operator_steps": [
                "Open the LaunchAgent dashboard at http://127.0.0.1:8765/?context_id=default.",
                "Run Monday Readiness and resolve every required failure before demo use.",
                "Use App Connect Detect, attach the target app, then snapshot exposed UI text or use selected-text capture for exact content.",
                "Capture decisions and validation evidence into SYNAPSE-S2 before switching clients.",
                "Generate an Evidence Pack after the demo run or before sharing claims.",
            ],
            "artifacts": artifacts,
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
            "generated_at": time.time(),
        }

    def evidence_pack(self, *, context_id: str) -> dict[str, Any]:
        context = mlx_backend.sanitize_context_id(context_id)
        export_root = self._export_root()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        report_path = export_root / f"evidence-pack-{context}-{stamp}.json"
        backup_path = export_root / f"evidence-memory-{context}-{stamp}.sqlite3"
        snapshot = self.snapshot(context_id=context, limit=250, include_graph=True)
        audit = self.readiness_audit(context_id=context)
        backup = self.backend.backup_memory(path=backup_path)
        payload: dict[str, Any] = {
            "action": "evidence-pack",
            "context_id": context,
            "created_at": time.time(),
            "report_path": str(report_path),
            "snapshot": snapshot,
            "readiness_audit": audit,
            "backup": backup,
        }
        digest_body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        payload["sha256"] = hashlib.sha256(digest_body).hexdigest()
        report_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        return payload

    def _audit_prompt(self, graph: dict[str, Any]) -> str:
        entries = graph.get("entries", [])
        for entry in entries:
            if not entry.get("metadata", {}).get("event_segment"):
                text = str(entry.get("source_text") or entry.get("tag") or "").strip()
                if text:
                    return text
        for entry in entries:
            text = str(entry.get("source_text") or entry.get("tag") or "").strip()
            if text:
                return text
        return "SYNAPSE-S2 local memory readiness"

    def _system_info(self, *, context_id: str) -> dict[str, Any]:
        if self._system_info_cache is None:
            self._system_info_cache = {
                "project_version": self._project_version(),
                "platform": platform.system() or "Darwin",
                "machine": platform.machine(),
                "macos_version": platform.mac_ver()[0],
                "chip": self._chip_label(),
                "pid": os.getpid(),
            }
        info = dict(self._system_info_cache)
        uptime_seconds = max(0.0, time.time() - self.started_at)
        memory_uri = f"s2://local/{mlx_backend.sanitize_context_id(context_id)}"
        provider = self.backend.embedding_provider_info()
        provider_id = str(provider.get("provider") or "embedding-provider")
        model_id = str(provider.get("model_id") or provider_id)
        info.update(
            {
                "started_at": self.started_at,
                "uptime_seconds": round(uptime_seconds, 3),
                "memory_uri": memory_uri,
                "model_uri": f"embedding://{provider_id}/{model_id}",
                "embedding_model_id": model_id,
                "substrate_label": "SNN Memory Context",
                "mode": "LOCAL ONLY",
            }
        )
        return info

    def _project_version(self) -> str:
        try:
            with (ROOT / "pyproject.toml").open("rb") as handle:
                payload = tomllib.load(handle)
            return str(payload.get("project", {}).get("version", "local"))
        except Exception:
            LOGGER.exception("failed to read project version")
            return "local"

    def _chip_label(self) -> str:
        try:
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                check=False,
                capture_output=True,
                text=True,
                timeout=1.0,
            )
            label = result.stdout.strip()
            if label:
                return label
        except Exception:
            LOGGER.debug("failed to read Apple chip label", exc_info=True)
        machine = platform.machine()
        return machine or "unknown"

    def _parse_recall_result(self, result: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for rank, chunk in enumerate(str(result or "").split(" / "), start=1):
            text = chunk.strip()
            if not text:
                continue
            parsed = self._parse_recall_chunk(text)
            parsed["rank"] = rank
            parsed["raw"] = text
            items.append(parsed)
        return items

    def _parse_recall_chunk(self, text: str) -> dict[str, Any]:
        match = re.match(r"^(?P<tag>.+?)\s+\((?P<meta>[^()]*)\)$", text)
        if not match:
            return {
                "kind": "status",
                "tag": text,
                "label": text,
            }
        metadata = self._parse_key_value_pairs(match.group("meta"))
        item: dict[str, Any] = {
            "kind": "linked" if "linked" in metadata else "memory",
            "tag": match.group("tag"),
            "label": match.group("tag"),
            "metadata": metadata,
        }
        if "score" in metadata:
            item["score"] = metadata["score"]
        if "weight" in metadata:
            item["weight"] = metadata["weight"]
        if "context" in metadata:
            item["context_id"] = metadata["context"]
        if "id" in metadata:
            item["memory_id"] = metadata["id"]
        if "linked" in metadata:
            item["relation_type"] = metadata["linked"]
        if "label" in metadata:
            item["label"] = metadata["label"]
        if "facets" in metadata:
            item["facets"] = [
                facet.strip()
                for facet in str(metadata["facets"]).split("|")
                if facet.strip()
            ]
        if "summary" in metadata:
            item["summary"] = metadata["summary"]
        return item

    def _parse_key_value_pairs(self, text: str) -> dict[str, Any]:
        metadata: dict[str, Any] = {}
        for part in text.split(","):
            key, separator, value = part.partition("=")
            if not separator:
                continue
            clean_key = key.strip()
            clean_value = value.strip()
            if clean_key in {"score", "weight"}:
                try:
                    metadata[clean_key] = round(float(clean_value), 6)
                    continue
                except ValueError:
                    pass
            metadata[clean_key] = clean_value
        return metadata

    def _query_id(self, *, context: str) -> str:
        return f"q_{time.strftime('%Y%m%d_%H%M%S')}_{context}"

    def _serve_static(self, path: str) -> tuple[int, dict[str, str], bytes]:
        if path in ("", "/"):
            path = "/index.html"
        decoded = unquote(path).lstrip("/")
        candidate = (WEB_ROOT / decoded).resolve()
        try:
            candidate.relative_to(WEB_ROOT.resolve())
        except ValueError as exc:
            raise DashboardError(HTTPStatus.FORBIDDEN, "static path escapes web root") from exc
        if not candidate.exists() or not candidate.is_file():
            raise DashboardError(HTTPStatus.NOT_FOUND, "static asset not found")
        content_type = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".svg": "image/svg+xml",
        }.get(candidate.suffix.lower(), "application/octet-stream")
        headers = {
            "Content-Type": content_type,
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            **SECURITY_HEADERS,
        }
        return int(HTTPStatus.OK), headers, candidate.read_bytes()

    def _json_response(
        self,
        payload: dict[str, Any],
        *,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> tuple[int, dict[str, str], bytes]:
        body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return int(status), {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            **SECURITY_HEADERS,
        }, body

    def _parse_json_body(self, body: bytes) -> dict[str, Any]:
        if len(body) > MAX_JSON_BODY_BYTES:
            raise DashboardError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "JSON body too large")
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise DashboardError(HTTPStatus.BAD_REQUEST, "invalid JSON body") from exc
        if not isinstance(payload, dict):
            raise DashboardError(HTTPStatus.BAD_REQUEST, "JSON body must be an object")
        return payload

    def _issue_confirmation_token(
        self,
        *,
        action: str,
        target: dict[str, Any],
        preview: dict[str, Any],
    ) -> dict[str, Any]:
        self._purge_confirmation_tokens()
        if len(self._confirmation_tokens) >= MAX_CONFIRMATION_TOKENS:
            oldest = sorted(
                self._confirmation_tokens.items(),
                key=lambda item: float(item[1].get("issued_at", 0.0)),
            )
            for token, _record in oldest[: max(1, len(oldest) - MAX_CONFIRMATION_TOKENS + 1)]:
                self._confirmation_tokens.pop(token, None)
        now = time.time()
        token = uuid.uuid4().hex
        target_hash = self._confirmation_target_hash(target)
        expires_at = now + CONFIRMATION_TOKEN_TTL_SECONDS
        self._confirmation_tokens[token] = {
            "action": str(action),
            "target_hash": target_hash,
            "issued_at": now,
            "expires_at": expires_at,
        }
        return {
            **preview,
            "confirmation_token": token,
            "confirmation_expires_at": expires_at,
            "confirmation_ttl_seconds": CONFIRMATION_TOKEN_TTL_SECONDS,
            "target_hash": target_hash,
            "requires_confirmation_token": True,
        }

    def _consume_confirmation_token(
        self,
        *,
        token: str,
        action: str,
        target: dict[str, Any],
    ) -> None:
        self._purge_confirmation_tokens()
        clean_token = str(token or "").strip()
        if not clean_token:
            raise DashboardError(
                HTTPStatus.BAD_REQUEST,
                f"confirmation_token is required for {action}",
            )
        record = self._confirmation_tokens.pop(clean_token, None)
        if record is None:
            raise DashboardError(
                HTTPStatus.CONFLICT,
                "confirmation_token is missing, expired, or already used",
            )
        if str(record.get("action") or "") != str(action):
            raise DashboardError(HTTPStatus.CONFLICT, "confirmation_token action mismatch")
        if float(record.get("expires_at", 0.0) or 0.0) < time.time():
            raise DashboardError(HTTPStatus.CONFLICT, "confirmation_token expired")
        expected_hash = str(record.get("target_hash") or "")
        actual_hash = self._confirmation_target_hash(target)
        if expected_hash != actual_hash:
            raise DashboardError(HTTPStatus.CONFLICT, "confirmation target changed after preflight")

    def _purge_confirmation_tokens(self) -> None:
        now = time.time()
        expired = [
            token
            for token, record in self._confirmation_tokens.items()
            if float(record.get("expires_at", 0.0) or 0.0) < now
        ]
        for token in expired:
            self._confirmation_tokens.pop(token, None)

    def _confirmation_target_hash(self, target: dict[str, Any]) -> str:
        target_json = json.dumps(target, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(target_json.encode("utf-8")).hexdigest()

    def _max_files_from_payload(self, payload: dict[str, Any]) -> int:
        try:
            max_files = int(payload.get("max_files", 50))
        except (TypeError, ValueError) as exc:
            raise DashboardError(HTTPStatus.BAD_REQUEST, "max_files must be an integer") from exc
        return min(max(max_files, 1), 250)

    def _app_connect_target(self, payload: dict[str, Any], *, context_id: str) -> dict[str, Any]:
        app_name = self._text_payload(payload, "app_name", max_bytes=1024)
        try:
            pid = int(payload.get("pid", 0) or 0)
        except (TypeError, ValueError) as exc:
            raise DashboardError(HTTPStatus.BAD_REQUEST, "pid must be an integer") from exc
        return {
            "context_id": context_id,
            "app_name": app_name,
            "bundle_id": str(payload.get("bundle_id", "") or ""),
            "pid": pid,
            "source_tag": str(payload.get("source_tag", "app-connect") or "app-connect"),
            "speaker": mlx_backend.sanitize_agent_id(str(payload.get("speaker", "operator"))),
            "allow_manual": payload.get("allow_manual") is True,
            "metadata": self._metadata_payload(payload),
        }

    def _app_snapshot_target(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "connection_id": self._text_payload(payload, "connection_id", max_bytes=512),
            "metadata": self._metadata_payload(payload),
        }

    def _connection_preview(self, connection_id: str) -> dict[str, Any]:
        connections = self.transcript_capture().list_app_connections().get("connections", [])
        for connection in connections:
            if str(connection.get("connection_id") or "") == connection_id:
                return {
                    "connection_id": connection_id,
                    "app_name": str(connection.get("app_name") or ""),
                    "bundle_id": str(connection.get("bundle_id") or ""),
                    "pid": int(connection.get("pid") or 0),
                    "context_id": str(connection.get("context_id") or ""),
                    "source_tag": str(connection.get("source_tag") or ""),
                    "speaker": str(connection.get("speaker") or ""),
                }
        raise DashboardError(HTTPStatus.BAD_REQUEST, "app connection was not found")

    def _capture_inbox_target(
        self,
        *,
        max_files: int,
        preflight: dict[str, Any],
    ) -> dict[str, Any]:
        selected_files = preflight.get("selected_files", [])
        if not isinstance(selected_files, list):
            selected_files = []
        return {
            "root": str(preflight.get("root") or ""),
            "max_files": int(max_files),
            "selected_file_count": int(preflight.get("selected_file_count") or 0),
            "selected_files": [
                {
                    "file": str(item.get("file") or ""),
                    "bytes": int(item.get("bytes") or 0),
                    "modified_at": float(item.get("modified_at") or 0.0),
                    "sha256": str(item.get("sha256") or ""),
                }
                for item in selected_files
                if isinstance(item, dict)
            ],
        }

    def _memory_hygiene_item(
        self,
        entry: dict[str, Any],
        *,
        duplicate_seen: dict[str, str],
    ) -> dict[str, Any] | None:
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        source_text = str(entry.get("source_text") or "")
        categories: list[str] = []
        reasons: list[str] = []
        recommended_actions: list[str] = []
        severity = "low"

        snapshot_quality = metadata.get("snapshot_quality")
        if isinstance(snapshot_quality, dict) and bool(snapshot_quality.get("low_signal")):
            categories.append("low_signal_app_capture")
            reasons.append("App snapshot produced low signal text.")
            recommended_actions.append("Recapture from selected text or a richer app view.")
            severity = "medium"

        confidence_raw = metadata.get("confidence")
        try:
            confidence = float(confidence_raw)
        except (TypeError, ValueError):
            confidence = None
        truth_posture = str(metadata.get("truth_posture") or "").lower()
        trace_type = str(metadata.get("trace_type") or "").lower()
        if confidence is not None and confidence < 0.6:
            categories.append("low_confidence_trace")
            reasons.append(f"Confidence is {confidence:.2f}.")
            recommended_actions.append("Promote with evidence, demote, or prune after review.")
            severity = "medium"
        if truth_posture in {"inferred", "stale"} or trace_type in {"assumption", "follow_up"}:
            categories.append("assumption_or_follow_up")
            reasons.append("Trace is an assumption, follow-up, inferred, or stale.")
            recommended_actions.append("Resolve or convert to observed/test-validated memory.")
            if severity == "low":
                severity = "medium"

        normalized = " ".join(source_text.lower().split())[:220]
        if normalized and normalized in duplicate_seen:
            categories.append("duplicate_candidate")
            reasons.append("Source text resembles another memory entry.")
            recommended_actions.append("Prune or merge duplicate memory if it is redundant.")
        elif normalized:
            duplicate_seen[normalized] = str(entry.get("memory_id") or "")

        sensitive_markers = (
            "[redacted_secret]",
            "api_key=",
            "password=",
            "private_key",
            "secret=",
            "sk-",
            "token=",
        )
        lowered = source_text.lower()
        if any(marker in lowered for marker in sensitive_markers):
            categories.append("sensitive_redaction_review")
            reasons.append("Entry contains redacted or sensitive-looking material.")
            recommended_actions.append("Verify redaction and prune if the memory is unnecessary.")
            severity = "high"

        if not categories:
            return None

        return {
            "item_id": f"hygiene_{hashlib.sha256(str(entry.get('memory_id', '')).encode('utf-8')).hexdigest()[:10]}",
            "memory_id": str(entry.get("memory_id") or ""),
            "tag": str(entry.get("tag") or ""),
            "categories": self._unique_strings(categories),
            "category": categories[0],
            "severity": severity,
            "reason": " ".join(reasons),
            "recommended_action": recommended_actions[0],
            "recommended_actions": self._unique_strings(recommended_actions),
            "source_excerpt": self._compact_text(source_text, 220),
            "updated_at": float(entry.get("updated_at") or 0.0),
            "metadata": {
                "trace_type": trace_type,
                "truth_posture": truth_posture,
                "confidence": confidence,
                "adapter_kind": metadata.get("adapter_kind"),
                "snapshot_quality": snapshot_quality if isinstance(snapshot_quality, dict) else {},
            },
        }

    def _memory_hygiene_recommendations(self, queue_summary: dict[str, int]) -> list[str]:
        recommendations: list[str] = []
        if queue_summary.get("low_signal_app_capture"):
            recommendations.append("Recapture low-signal app snapshots using preview or selected-text fallback.")
        if queue_summary.get("low_confidence_trace") or queue_summary.get("assumption_or_follow_up"):
            recommendations.append("Promote supported assumptions or prune stale follow-ups.")
        if queue_summary.get("sensitive_redaction_review"):
            recommendations.append("Review redacted/sensitive-looking entries and prune anything unnecessary.")
        if queue_summary.get("duplicate_candidate"):
            recommendations.append("Prune duplicate memory entries that do not add new evidence.")
        if not recommendations:
            recommendations.append("No hygiene action required.")
        return recommendations

    def _operation_receipt(
        self,
        *,
        action: str,
        status: str,
        title: str,
        summary: str,
        context_id: str,
        source_tag: str = "",
        event_count: int = 0,
        relationship_count: int = 0,
        quality: str = "",
        next_action: str = "",
    ) -> dict[str, Any]:
        normalized_status = status if status in {"ready", "degraded", "blocked"} else "degraded"
        return {
            "receipt_id": f"rcpt_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}",
            "action": str(action),
            "status": normalized_status,
            "title": str(title),
            "summary": str(summary),
            "context_id": mlx_backend.sanitize_context_id(context_id),
            "source_tag": str(source_tag or ""),
            "event_count": int(event_count or 0),
            "relationship_count": int(relationship_count or 0),
            "quality": str(quality or normalized_status),
            "next_action": str(next_action or ""),
            "created_at": time.time(),
        }

    def _with_receipt(
        self,
        payload: dict[str, Any],
        *,
        action: str,
        status: str,
        title: str,
        summary: str,
        context_id: str,
        source_tag: str = "",
        event_count: int | None = None,
        relationship_count: int | None = None,
        quality: str = "",
        next_action: str = "",
    ) -> dict[str, Any]:
        result = dict(payload)
        result["receipt"] = self._operation_receipt(
            action=action,
            status=status,
            title=title,
            summary=summary,
            context_id=str(result.get("context_id") or context_id),
            source_tag=str(result.get("source_tag") or source_tag),
            event_count=int(
                event_count
                if event_count is not None
                else int(result.get("event_count") or 0)
            ),
            relationship_count=int(
                relationship_count
                if relationship_count is not None
                else int(result.get("relationship_count") or 0)
            ),
            quality=quality,
            next_action=next_action,
        )
        return result

    def _dependency_status(self, module: str) -> dict[str, Any]:
        spec = importlib.util.find_spec(module)
        return {
            "importable": spec is not None,
            "origin": getattr(spec, "origin", None) if spec is not None else None,
        }

    def _mcp_tool_name_check(self) -> dict[str, Any]:
        server_path = ROOT / "mcp_server.py"
        invalid: list[str] = []
        tool_names: list[str] = []
        if not server_path.exists():
            return {
                "invalid_tool_names": invalid,
                "tool_names": tool_names,
                "detail": "mcp_server.py not found",
            }
        text = server_path.read_text(encoding="utf-8")
        patterns = [
            re.compile(r"@(?:mcp|server)\.tool\(\s*name\s*=\s*[\"']([^\"']+)[\"']"),
            re.compile(r"@(?:mcp|server)\.tool\(\s*[\"']([^\"']+)[\"']"),
            re.compile(r"name\s*=\s*[\"']([A-Za-z0-9_.:-]+)[\"']"),
        ]
        for pattern in patterns:
            for match in pattern.finditer(text):
                name = match.group(1)
                if name in tool_names:
                    continue
                tool_names.append(name)
                if not re.fullmatch(r"[A-Za-z0-9_]+", name):
                    invalid.append(name)
        return {
            "invalid_tool_names": invalid,
            "tool_names": tool_names,
            "detail": (
                "all declared MCP tool names are client-safe"
                if not invalid
                else f"invalid names: {', '.join(invalid[:8])}"
            ),
        }

    def _unique_strings(self, values: list[Any]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            text = " ".join(str(value or "").split())
            if not text or text in seen:
                continue
            seen.add(text)
            result.append(text)
        return result

    def _compact_text(self, value: str, limit: int) -> str:
        text = " ".join(str(value or "").split())
        if len(text) <= limit:
            return text
        return text[: max(0, limit - 1)].rstrip() + "..."

    def _render_wrap_session_text(
        self,
        *,
        context_id: str,
        agent_id: str,
        text: str,
        operation_log: Any,
    ) -> str:
        lines = [
            f"Context: {context_id}",
            f"Agent: {agent_id}",
            f"Wrapped at: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
            "",
            "Session notes:",
            str(text or "").strip() or "No free-form notes provided.",
        ]
        if isinstance(operation_log, list) and operation_log:
            lines.extend(["", "Operation receipts:"])
            for item in operation_log[-10:]:
                if isinstance(item, dict):
                    action = str(item.get("action") or item.get("title") or "operation")
                    summary = str(item.get("summary") or item.get("detail") or "")
                    status = str(item.get("status") or "")
                    rendered = " - ".join(part for part in (action, status, summary) if part)
                    lines.append(f"- {rendered}")
                else:
                    lines.append(f"- {str(item)}")
        return "\n".join(lines).strip()

    def _debug_error_details_enabled(self) -> bool:
        return os.getenv("SYNAPSE_S2_DASHBOARD_DEBUG_ERRORS", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _context_from_params(self, params: dict[str, list[str]]) -> str:
        value = params.get("context_id", [DEFAULT_CONTEXT])[0]
        return mlx_backend.sanitize_context_id(value)

    def _context_from_payload(self, payload: dict[str, Any]) -> str:
        return mlx_backend.sanitize_context_id(str(payload.get("context_id", DEFAULT_CONTEXT)))

    def _bool_param(
        self,
        params: dict[str, list[str]],
        key: str,
        default: bool,
    ) -> bool:
        value = params.get(key, [str(default)])[0].strip().lower()
        return value in {"1", "true", "yes", "on"}

    def _int_param(
        self,
        params: dict[str, list[str]],
        key: str,
        default: int,
        *,
        minimum: int,
        maximum: int,
    ) -> int:
        try:
            value = int(params.get(key, [str(default)])[0])
        except (TypeError, ValueError) as exc:
            raise DashboardError(HTTPStatus.BAD_REQUEST, f"{key} must be an integer") from exc
        return min(max(value, minimum), maximum)

    def _required_bool(self, payload: dict[str, Any], key: str) -> bool:
        if key not in payload:
            raise DashboardError(HTTPStatus.BAD_REQUEST, f"{key} is required")
        if not isinstance(payload[key], bool):
            raise DashboardError(HTTPStatus.BAD_REQUEST, f"{key} must be a boolean")
        return bool(payload[key])

    def _text_payload(
        self,
        payload: dict[str, Any],
        key: str,
        *,
        max_bytes: int,
    ) -> str:
        text = str(payload.get(key, "")).strip()
        if not text:
            raise DashboardError(HTTPStatus.BAD_REQUEST, f"{key} is required")
        if len(text.encode("utf-8")) > max_bytes:
            raise DashboardError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"{key} is too large")
        return text

    def _metadata_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        metadata = payload.get("metadata", {})
        if metadata is None:
            return {}
        if not isinstance(metadata, dict):
            raise DashboardError(HTTPStatus.BAD_REQUEST, "metadata must be an object")
        return metadata

    def _string_list_payload(self, payload: dict[str, Any], key: str) -> list[str]:
        value = payload.get(key, [])
        if value is None:
            return []
        if isinstance(value, str):
            value = [item.strip() for item in value.splitlines() if item.strip()]
        if not isinstance(value, list):
            raise DashboardError(HTTPStatus.BAD_REQUEST, f"{key} must be a list")
        cleaned: list[str] = []
        for index, item in enumerate(value):
            text = " ".join(str(item or "").split())
            if not text:
                continue
            if len(text) > 260:
                raise DashboardError(
                    HTTPStatus.BAD_REQUEST,
                    f"{key}[{index}] exceeds 260 characters",
                )
            cleaned.append(text)
            if len(cleaned) > 24:
                raise DashboardError(HTTPStatus.BAD_REQUEST, f"{key} exceeds 24 entries")
        return cleaned

    def _export_root(self) -> Path:
        export_root = Path(os.getenv("SYNAPSE_S2_EXPORT_DIR", ROOT / ".synapse_s2")).expanduser()
        if not export_root.is_absolute():
            export_root = ROOT / export_root
        export_root.mkdir(parents=True, exist_ok=True)
        return export_root.resolve()


class SynapseDashboardHandler(BaseHTTPRequestHandler):
    server_version = "SYNAPSE-S2-Dashboard/0.1"

    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_OPTIONS(self) -> None:
        self.send_response(int(HTTPStatus.NO_CONTENT))
        self.send_header("Allow", "GET, POST, OPTIONS")
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        LOGGER.info("%s - %s", self.address_string(), format % args)

    def _dispatch(self) -> None:
        if self.command == "POST" and not self._origin_allowed():
            status, headers, body = self.server.runtime._json_response(  # type: ignore[attr-defined]
                {"error": "origin not allowed"},
                status=HTTPStatus.FORBIDDEN,
            )
            self._write_response(status, headers, body)
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_JSON_BODY_BYTES:
            status, headers, body = self.server.runtime._json_response(  # type: ignore[attr-defined]
                {"error": "request body too large"},
                status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
        else:
            raw_body = self.rfile.read(length) if length else b""
            status, headers, body = self.server.runtime.handle(  # type: ignore[attr-defined]
                self.command,
                self.path,
                raw_body,
            )
        self._write_response(status, headers, body)

    def _origin_allowed(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"}:
            return False
        if parsed.hostname not in LOOPBACK_HOSTS:
            return False
        origin_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return int(origin_port) == int(self.server.server_port)

    def _write_response(
        self,
        status: int,
        headers: dict[str, str],
        body: bytes,
    ) -> None:
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SynapseDashboardServer(HTTPServer):
    request_queue_size = 32

    def __init__(
        self,
        server_address: tuple[str, int],
        runtime: DashboardRuntime,
    ) -> None:
        super().__init__(server_address, SynapseDashboardHandler)
        self.runtime = runtime


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the SYNAPSE-S2 local dashboard.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--context", default=DEFAULT_CONTEXT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.host not in LOOPBACK_HOSTS and os.getenv(
        "SYNAPSE_S2_ALLOW_NON_LOOPBACK_DASHBOARD", ""
    ).strip().lower() not in {"1", "true", "yes", "on"}:
        LOGGER.error(
            "refusing to bind dashboard to non-loopback host %s; set "
            "SYNAPSE_S2_ALLOW_NON_LOOPBACK_DASHBOARD=true only for a controlled LAN demo",
            args.host,
        )
        return 2
    runtime = DashboardRuntime()
    server = SynapseDashboardServer((args.host, args.port), runtime)
    url = f"http://{args.host}:{server.server_port}/?context_id={mlx_backend.sanitize_context_id(args.context)}"
    LOGGER.info("SYNAPSE-S2 dashboard listening on %s", url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("SYNAPSE-S2 dashboard stopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

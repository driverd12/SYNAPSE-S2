from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import re
import subprocess
import sys
import time
import tomllib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from capture_daemon import CaptureInboxDaemon
import mlx_backend


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
        except Exception as exc:
            LOGGER.exception("dashboard request failed for %s %s", method, raw_path)
            return self._json_response(
                {"error": "dashboard request failed", "detail": str(exc)},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

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
                    mutation_intent=bool(payload.get("mutation_intent", False)),
                    confidence=confidence,
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
            result = self.backend.query(
                self.backend.embed_text(prompt),
                context_id=context,
            )
            elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
            return self._json_response(
                {
                    "context_id": context,
                    "prompt": prompt,
                    "result": result,
                    "results": self._parse_recall_result(result),
                    "latency_ms": elapsed_ms,
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
                    target_min_mb=float(payload.get("target_min_mb", 61.0)),
                    target_max_mb=float(payload.get("target_max_mb", 138.0)),
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
        if method == "POST" and path == "/api/capture-inbox/process":
            payload = self._parse_json_body(body)
            try:
                max_files = int(payload.get("max_files", 50))
            except (TypeError, ValueError) as exc:
                raise DashboardError(HTTPStatus.BAD_REQUEST, "max_files must be an integer") from exc
            return self._json_response(
                self.capture_daemon().process_once(max_files=min(max(max_files, 1), 250))
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

    def readiness_audit(self, *, context_id: str) -> dict[str, Any]:
        context = mlx_backend.sanitize_context_id(context_id)
        started = time.perf_counter()
        status = self.backend.status(context_id=context)
        profile = self.backend.resource_profile(benchmark_quick_prune=False)
        graph = self.backend.list_memory_graph(context_id=context, limit=20)
        prompt = self._audit_prompt(graph)
        query_result = ""
        if prompt:
            query_result = self.backend.query(
                self.backend.embed_text(prompt),
                context_id=context,
            )
        target_max = float(profile.get("target_envelope_mb", {}).get("max", 138.0))
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
        info.update(
            {
                "started_at": self.started_at,
                "uptime_seconds": round(uptime_seconds, 3),
                "memory_uri": memory_uri,
                "model_uri": memory_uri,
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
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
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

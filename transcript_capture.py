from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from capture_daemon import redact_capture_text
import mlx_backend


LOGGER = logging.getLogger("synapse_s2.transcript_capture")
if not LOGGER.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    LOGGER.addHandler(_handler)
LOGGER.setLevel(os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper())
LOGGER.propagate = False

MAX_TRANSCRIPT_DELTA_BYTES = 256_000
APP_DETECT_SYSTEM_EVENTS_TIMEOUT_SECONDS = float(
    os.getenv("SYNAPSE_S2_APP_DETECT_TIMEOUT_SECONDS", "12.0")
)
APP_DETECT_PS_TIMEOUT_SECONDS = 2.0
APP_SNAPSHOT_ACCESSIBILITY_TIMEOUT_SECONDS = float(
    os.getenv("SYNAPSE_S2_APP_SNAPSHOT_TIMEOUT_SECONDS", "8.0")
)
CLIPBOARD_READ_TIMEOUT_SECONDS = 5.0
ALLOWED_TRANSCRIPT_SUFFIXES = {
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".txt",
}
SENSITIVE_PATH_FRAGMENTS = {
    ".aws",
    ".gnupg",
    ".ssh",
    ".env",
    "1password",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "keychain",
    "private_key",
    "secret",
    "secrets",
}


def resolve_capture_root(root: str | os.PathLike[str] | None = None) -> Path:
    if root is not None:
        return Path(root).expanduser().resolve()
    configured = os.getenv("SYNAPSE_S2_CAPTURE_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.cwd() / ".synapse_s2").resolve()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8")).hexdigest()


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(str(path).encode("utf-8")).hexdigest()


def _json_safe(value: Any, fallback: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return fallback


class TranscriptCaptureManager:
    """Hardened transcript and local app capture adapters.

    The manager keeps all connectors local and auditable: registered file
    deltas, explicit selected text, and confirmed running-app snapshots.
    """

    def __init__(
        self,
        *,
        root: str | os.PathLike[str] | None = None,
        backend: mlx_backend.SpikingAttentionBackend | None = None,
        running_app_provider: Callable[[], list[dict[str, Any]]] | None = None,
        app_snapshot_provider: Callable[[dict[str, Any]], str] | None = None,
    ) -> None:
        self.root = resolve_capture_root(root)
        self.backend = backend or mlx_backend.get_backend()
        self.running_app_provider = running_app_provider or self._detect_running_apps_macos
        self.app_snapshot_provider = app_snapshot_provider or self._snapshot_app_accessibility

    def paths(self) -> dict[str, Path]:
        return {
            "root": self.root,
            "source_state_path": self.root / "transcript_sources.json",
            "app_state_path": self.root / "app_connections.json",
        }

    def status(self) -> dict[str, Any]:
        sources = self.list_sources()["sources"]
        enabled = [source for source in sources if source.get("enabled")]
        return {
            "root": str(self.root),
            "source_state_path": str(self.paths()["source_state_path"]),
            "source_count": len(sources),
            "enabled_source_count": len(enabled),
            "sources": sources,
            "app_connections": self.list_app_connections()["connections"],
            "mode": "hardened-app-connect",
            "connector_model": {
                "remote_control_plane": False,
                "background_clipboard_monitoring": False,
                "requires_explicit_source_registration": True,
                "redaction_before_ingest": True,
            },
        }

    def detect_running_apps(self) -> dict[str, Any]:
        started = time.perf_counter()
        apps: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        provider_warning = ""
        try:
            raw_apps = list(self.running_app_provider() or [])
        except Exception as exc:
            provider_warning = str(exc.__class__.__name__)
            LOGGER.debug(
                "running app provider failed; falling back to ps: %s",
                str(exc)[:240],
                exc_info=True,
            )
            raw_apps = self._detect_running_apps_ps()
        for raw_app in raw_apps:
            app = self._public_app(raw_app)
            if not app["app_name"]:
                continue
            if app.get("detection") == "ps" and not self._looks_like_attachable_app(app):
                continue
            key = (
                str(app.get("app_name") or "").strip().lower(),
                str(app.get("bundle_id") or "").strip().lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            apps.append(app)
        apps.sort(key=lambda item: (item["app_name"].lower(), int(item.get("pid") or 0)))
        return {
            "action": "detect-running-apps",
            "app_count": len(apps),
            "apps": apps,
            "mode": "local-process-detection",
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "warning": provider_warning,
        }

    def connect_running_app(
        self,
        *,
        app_name: str,
        context_id: str = "default",
        source_tag: str = "app-connect",
        speaker: str = "operator",
        bundle_id: str = "",
        pid: int = 0,
        metadata: dict[str, Any] | None = None,
        confirmed: bool = False,
        allow_manual: bool = False,
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("explicit --confirm is required to connect a local app")
        requested_name = " ".join(str(app_name or "").split())
        if not requested_name:
            raise ValueError("app_name must not be empty")
        detected = self._match_running_app(
            app_name=requested_name,
            bundle_id=str(bundle_id or ""),
            pid=int(pid or 0),
        )
        if detected is None:
            if not allow_manual:
                raise ValueError("app is not currently detected; pass allow_manual only for a verified local app")
            detected = {
                "app_name": requested_name,
                "bundle_id": str(bundle_id or ""),
                "pid": int(pid or 0),
                "detection": "manual-operator-entry",
            }
        state = self._read_app_state()
        connections = state.setdefault("connections", {})
        now = time.time()
        connection_id = self._connection_id(detected)
        record = {
            "connection_id": connection_id,
            "app_name": str(detected.get("app_name") or requested_name),
            "bundle_id": str(detected.get("bundle_id") or bundle_id or ""),
            "pid": int(detected.get("pid") or pid or 0),
            "context_id": mlx_backend.sanitize_context_id(context_id),
            "source_tag": mlx_backend.sanitize_tag(source_tag).replace(" ", "-"),
            "speaker": mlx_backend.sanitize_agent_id(speaker),
            "enabled": True,
            "adapter_kinds": [
                "frontmost-selection",
                "clipboard-once",
                "app-accessibility-snapshot",
                "app-selected-text",
            ],
            "created_at": float(connections.get(connection_id, {}).get("created_at") or now),
            "updated_at": now,
            "metadata": _json_safe(metadata or {}, {}),
            "consent": {
                "operator_confirmed": True,
                "mode": "local-app-connect",
                "attached_at": now,
            },
        }
        connections[connection_id] = record
        self._write_app_state(state)
        return self._public_connection(record)

    def list_app_connections(self) -> dict[str, Any]:
        state = self._read_app_state()
        connections = [
            self._public_connection(connection)
            for connection in state.get("connections", {}).values()
            if isinstance(connection, dict)
        ]
        connections.sort(key=lambda item: (item["app_name"].lower(), item["connection_id"]))
        return {
            "root": str(self.root),
            "app_state_path": str(self.paths()["app_state_path"]),
            "connection_count": len(connections),
            "connections": connections,
        }

    def preview_app_snapshot(
        self,
        *,
        connection_id: str,
    ) -> dict[str, Any]:
        connection = self._get_connection(connection_id)
        try:
            snapshot_text = self._clean_accessibility_snapshot_text(
                str(self.app_snapshot_provider(connection) or "")
            )
        except Exception as exc:
            return self._blocked_app_snapshot_preview(
                connection=connection,
                reason="app snapshot failed; grant Accessibility permission or use selected-text capture",
                error_type=exc.__class__.__name__,
            )
        if not snapshot_text:
            return self._blocked_app_snapshot_preview(
                connection=connection,
                reason="app snapshot did not return text; use selected-text capture",
                error_type="empty-snapshot",
            )
        if len(snapshot_text.encode("utf-8")) > MAX_TRANSCRIPT_DELTA_BYTES:
            snapshot_text = snapshot_text.encode("utf-8")[:MAX_TRANSCRIPT_DELTA_BYTES].decode(
                "utf-8",
                errors="replace",
            )
        redacted_text, redaction_count = redact_capture_text(snapshot_text)
        quality = self._snapshot_quality(snapshot_text)
        badge = self._snapshot_quality_badge(quality)
        preview_text = self._preview_text(redacted_text, limit=1200)
        return {
            "action": "preview-app-snapshot",
            "adapter_kind": "app-accessibility-snapshot",
            "connection_id": connection["connection_id"],
            "app_name": connection["app_name"],
            "bundle_id": connection.get("bundle_id", ""),
            "pid": int(connection.get("pid") or 0),
            "context_id": str(connection.get("context_id") or "default"),
            "source_tag": str(connection.get("source_tag") or "app-connect"),
            "speaker": str(connection.get("speaker") or "operator"),
            "preview_text": preview_text,
            "preview_line_count": len([line for line in preview_text.splitlines() if line.strip()]),
            "redaction_count": int(redaction_count),
            "input_sha256": _sha256_text(snapshot_text),
            "snapshot_quality": quality,
            "quality_badge": badge,
            "capture_guidance": self._app_capture_guidance(
                connection=connection,
                quality=quality,
                badge=badge,
            ),
            "writes_memory": False,
        }

    def _blocked_app_snapshot_preview(
        self,
        *,
        connection: dict[str, Any],
        reason: str,
        error_type: str,
    ) -> dict[str, Any]:
        quality = {
            "line_count": 0,
            "unique_line_count": 0,
            "signal_chars": 0,
            "low_signal": True,
            "repetitive": False,
            "quality": "blocked",
            "blocked_reason": str(reason or "app snapshot unavailable"),
        }
        badge = self._snapshot_quality_badge(quality)
        return {
            "action": "preview-app-snapshot",
            "adapter_kind": "app-accessibility-snapshot",
            "connection_id": connection["connection_id"],
            "app_name": connection["app_name"],
            "bundle_id": connection.get("bundle_id", ""),
            "pid": int(connection.get("pid") or 0),
            "context_id": str(connection.get("context_id") or "default"),
            "source_tag": str(connection.get("source_tag") or "app-connect"),
            "speaker": str(connection.get("speaker") or "operator"),
            "preview_text": "",
            "preview_line_count": 0,
            "redaction_count": 0,
            "input_sha256": "",
            "snapshot_quality": quality,
            "quality_badge": badge,
            "capture_guidance": self._app_capture_guidance(
                connection=connection,
                quality=quality,
                badge=badge,
            ),
            "writes_memory": False,
            "error_type": str(error_type or "snapshot-unavailable"),
            "error": quality["blocked_reason"],
        }

    def capture_app_snapshot(
        self,
        *,
        connection_id: str,
        confirmed: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("explicit confirmation is required to capture an app snapshot")
        connection = self._get_connection(connection_id)
        snapshot_text = self._clean_accessibility_snapshot_text(
            str(self.app_snapshot_provider(connection) or "")
        )
        if not snapshot_text:
            raise ValueError("app snapshot did not return text")
        if len(snapshot_text.encode("utf-8")) > MAX_TRANSCRIPT_DELTA_BYTES:
            snapshot_text = snapshot_text.encode("utf-8")[:MAX_TRANSCRIPT_DELTA_BYTES].decode(
                "utf-8",
                errors="replace",
            )
        snapshot_quality = self._snapshot_quality(snapshot_text)
        quality_badge = self._snapshot_quality_badge(snapshot_quality)
        redacted_text, redaction_count = redact_capture_text(snapshot_text)
        capture = self.backend.capture_conversation(
            text=redacted_text,
            context_id=str(connection.get("context_id") or "default"),
            source_tag=str(connection.get("source_tag") or "app-connect"),
            speaker=str(connection.get("speaker") or "operator"),
            surprise_threshold=0.5,
            min_segment_sentences=1,
            metadata={
                **_json_safe(connection.get("metadata") or {}, {}),
                **_json_safe(metadata or {}, {}),
                "transcript_adapter": True,
                "adapter_kind": "app-accessibility-snapshot",
                "capture_mode": "confirmed-local-app-snapshot",
                "connection_id": connection["connection_id"],
                "app_name": connection["app_name"],
                "bundle_id": connection.get("bundle_id", ""),
                "pid": connection.get("pid", 0),
                "redaction_count": int(redaction_count),
                "input_sha256": _sha256_text(snapshot_text),
                "remote_control_plane": False,
                "snapshot_quality": snapshot_quality,
            },
        )
        return {
            "action": "capture-app-snapshot",
            "adapter_kind": "app-accessibility-snapshot",
            "connection_id": connection["connection_id"],
            "app_name": connection["app_name"],
            "context_id": capture["context_id"],
            "source_tag": capture["source_tag"],
            "speaker": capture.get("speaker"),
            "event_count": capture["event_count"],
            "relationship_count": capture["relationship_count"],
            "agent_deployment": capture.get("agent_deployment"),
            "redaction_count": int(redaction_count),
            "snapshot_quality": snapshot_quality,
            "quality_badge": quality_badge,
            "capture_guidance": self._app_capture_guidance(
                connection=connection,
                quality=snapshot_quality,
                badge=quality_badge,
            ),
            "receipt": {
                "action": "capture-app-snapshot",
                "status": quality_badge["status"],
                "title": f"{connection['app_name']} snapshot captured",
                "summary": (
                    f"{capture['event_count']} events, "
                    f"{capture['relationship_count']} relationships, "
                    f"{snapshot_quality['signal_chars']} signal chars"
                ),
                "context_id": capture["context_id"],
                "source_tag": capture["source_tag"],
                "event_count": capture["event_count"],
                "relationship_count": capture["relationship_count"],
                "quality": quality_badge["label"],
                "next_action": quality_badge["next_action"],
            },
        }

    def capture_app_selected_text(
        self,
        *,
        connection_id: str,
        text: str | None = None,
        confirmed: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("explicit confirmation is required to capture app selected text")
        connection = self._get_connection(connection_id)
        raw_text = self._read_clipboard() if text is None else str(text or "")
        clean_text = raw_text.strip()
        if not clean_text:
            raise ValueError("selected app text must not be empty")
        if len(clean_text.encode("utf-8")) > MAX_TRANSCRIPT_DELTA_BYTES:
            clean_text = clean_text.encode("utf-8")[:MAX_TRANSCRIPT_DELTA_BYTES].decode(
                "utf-8",
                errors="replace",
            )
        redacted_text, redaction_count = redact_capture_text(clean_text)
        capture = self.backend.capture_conversation(
            text=redacted_text,
            context_id=str(connection.get("context_id") or "default"),
            source_tag=str(connection.get("source_tag") or "app-connect"),
            speaker=str(connection.get("speaker") or "operator"),
            surprise_threshold=0.5,
            min_segment_sentences=1,
            metadata={
                **_json_safe(connection.get("metadata") or {}, {}),
                **_json_safe(metadata or {}, {}),
                "transcript_adapter": True,
                "adapter_kind": "app-selected-text",
                "capture_mode": "confirmed-selected-text-fallback",
                "connection_id": connection["connection_id"],
                "app_name": connection["app_name"],
                "bundle_id": connection.get("bundle_id", ""),
                "pid": connection.get("pid", 0),
                "redaction_count": int(redaction_count),
                "input_sha256": _sha256_text(clean_text),
                "remote_control_plane": False,
            },
        )
        return {
            "action": "capture-app-selected-text",
            "adapter_kind": "app-selected-text",
            "connection_id": connection["connection_id"],
            "app_name": connection["app_name"],
            "context_id": capture["context_id"],
            "source_tag": capture["source_tag"],
            "speaker": capture.get("speaker"),
            "event_count": capture["event_count"],
            "relationship_count": capture["relationship_count"],
            "agent_deployment": capture.get("agent_deployment"),
            "redaction_count": int(redaction_count),
        }

    def register_file_source(
        self,
        *,
        source_id: str,
        path: str | os.PathLike[str],
        context_id: str = "default",
        source_tag: str = "transcript-source",
        speaker: str = "operator",
        metadata: dict[str, Any] | None = None,
        confirmed: bool = False,
        start_at_end: bool = True,
        enabled: bool = True,
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("explicit --confirm is required to register a transcript source")
        source = mlx_backend.sanitize_tag(source_id).replace(" ", "-")
        if not source:
            raise ValueError("source_id must not be empty")
        resolved = Path(path).expanduser().resolve()
        self._validate_source_path(resolved)
        state = self._read_state()
        sources = state.setdefault("sources", {})
        cursor = int(resolved.stat().st_size) if start_at_end else 0
        now = time.time()
        record = {
            "source_id": source,
            "kind": "file-tail",
            "path": str(resolved),
            "path_sha256": _sha256_path(resolved),
            "context_id": mlx_backend.sanitize_context_id(context_id),
            "source_tag": mlx_backend.sanitize_tag(source_tag).replace(" ", "-"),
            "speaker": mlx_backend.sanitize_agent_id(speaker),
            "enabled": bool(enabled),
            "cursor": cursor,
            "format": resolved.suffix.lower().lstrip(".") or "text",
            "created_at": float(sources.get(source, {}).get("created_at") or now),
            "updated_at": now,
            "metadata": _json_safe(metadata or {}, {}),
            "consent": {
                "operator_confirmed": True,
                "mode": "explicit-registration",
                "registered_at": now,
            },
        }
        sources[source] = record
        self._write_state(state)
        return self._public_source(record)

    def list_sources(self) -> dict[str, Any]:
        state = self._read_state()
        sources = [
            self._public_source(source)
            for source in state.get("sources", {}).values()
            if isinstance(source, dict)
        ]
        sources.sort(key=lambda item: item["source_id"])
        return {
            "root": str(self.root),
            "source_state_path": str(self.paths()["source_state_path"]),
            "source_count": len(sources),
            "sources": sources,
        }

    def poll_sources(
        self,
        *,
        source_id: str = "",
        max_bytes: int = MAX_TRANSCRIPT_DELTA_BYTES,
    ) -> dict[str, Any]:
        state = self._read_state()
        sources = state.get("sources", {})
        bounded_max = max(1, min(int(max_bytes), MAX_TRANSCRIPT_DELTA_BYTES))
        requested = mlx_backend.sanitize_tag(source_id).replace(" ", "-") if source_id else ""
        selected: list[dict[str, Any]] = []
        if requested:
            source = sources.get(requested)
            if isinstance(source, dict):
                selected.append(source)
            else:
                raise ValueError(f"transcript source not found: {requested}")
        else:
            selected = [
                source
                for source in sources.values()
                if isinstance(source, dict) and bool(source.get("enabled", True))
            ]

        captures: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for source in selected:
            if not bool(source.get("enabled", True)):
                continue
            try:
                capture = self._poll_file_source(source, max_bytes=bounded_max)
                if capture is not None:
                    captures.append(capture)
            except Exception as exc:
                LOGGER.exception("failed to poll transcript source %s", source.get("source_id"))
                errors.append(
                    {
                        "source_id": str(source.get("source_id") or ""),
                        "error": str(exc),
                    }
                )
        self._write_state(state)
        return {
            "action": "poll-transcript-sources",
            "root": str(self.root),
            "source_count": len(selected),
            "captured_source_count": len(captures),
            "captured_event_count": sum(int(item.get("event_count") or 0) for item in captures),
            "captured_relationship_count": sum(
                int(item.get("relationship_count") or 0) for item in captures
            ),
            "captures": captures,
            "errors": errors,
        }

    def capture_clipboard_once(
        self,
        *,
        text: str | None = None,
        context_id: str = "default",
        source_tag: str = "frontmost-selection",
        speaker: str = "operator",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        raw_text = self._read_clipboard() if text is None else str(text or "")
        clean_text = raw_text.strip()
        if not clean_text:
            raise ValueError("clipboard capture text must not be empty")
        redacted_text, redaction_count = redact_capture_text(clean_text)
        capture = self.backend.capture_conversation(
            text=redacted_text,
            context_id=mlx_backend.sanitize_context_id(context_id),
            source_tag=mlx_backend.sanitize_tag(source_tag).replace(" ", "-"),
            speaker=mlx_backend.sanitize_agent_id(speaker),
            surprise_threshold=0.5,
            min_segment_sentences=1,
            metadata={
                **_json_safe(metadata or {}, {}),
                "transcript_adapter": True,
                "adapter_kind": "clipboard-once",
                "capture_mode": "explicit-one-shot",
                "redaction_count": int(redaction_count),
                "input_sha256": _sha256_text(clean_text),
                "remote_control_plane": False,
            },
        )
        return {
            "action": "capture-clipboard-once",
            "adapter_kind": "clipboard-once",
            "context_id": capture["context_id"],
            "source_tag": capture["source_tag"],
            "speaker": capture.get("speaker"),
            "event_count": capture["event_count"],
            "relationship_count": capture["relationship_count"],
            "agent_deployment": capture.get("agent_deployment"),
            "redaction_count": int(redaction_count),
        }

    def _poll_file_source(
        self,
        source: dict[str, Any],
        *,
        max_bytes: int,
    ) -> dict[str, Any] | None:
        path = Path(str(source.get("path") or "")).expanduser().resolve()
        self._validate_source_path(path)
        size = int(path.stat().st_size)
        cursor = max(0, int(source.get("cursor") or 0))
        if size < cursor:
            cursor = 0
        if size <= cursor:
            source["cursor"] = size
            source["updated_at"] = time.time()
            return None
        end = min(size, cursor + max_bytes)
        with path.open("rb") as handle:
            handle.seek(cursor)
            raw = handle.read(end - cursor)
        text = raw.decode("utf-8", errors="replace").strip()
        source["cursor"] = end
        source["updated_at"] = time.time()
        if not text:
            return None
        redacted_text, redaction_count = redact_capture_text(text)
        source_id = str(source.get("source_id") or "")
        capture = self.backend.capture_conversation(
            text=redacted_text,
            context_id=str(source.get("context_id") or "default"),
            source_tag=str(source.get("source_tag") or source_id or "transcript-source"),
            speaker=str(source.get("speaker") or "operator"),
            surprise_threshold=0.5,
            min_segment_sentences=1,
            metadata={
                **_json_safe(source.get("metadata") or {}, {}),
                "transcript_adapter": True,
                "adapter_kind": "file-tail",
                "capture_mode": "registered-file-delta",
                "source_id": source_id,
                "path_sha256": source.get("path_sha256") or _sha256_path(path),
                "path_name": path.name,
                "cursor_start": cursor,
                "cursor_end": end,
                "truncated": end < size,
                "redaction_count": int(redaction_count),
                "input_sha256": _sha256_text(text),
                "remote_control_plane": False,
            },
        )
        return {
            "source_id": source_id,
            "adapter_kind": "file-tail",
            "context_id": capture["context_id"],
            "source_tag": capture["source_tag"],
            "speaker": capture.get("speaker"),
            "cursor_start": cursor,
            "cursor_end": end,
            "bytes_captured": len(raw),
            "truncated": end < size,
            "event_count": capture["event_count"],
            "relationship_count": capture["relationship_count"],
            "redaction_count": int(redaction_count),
            "agent_deployment": capture.get("agent_deployment"),
        }

    def _read_state(self) -> dict[str, Any]:
        path = self.paths()["source_state_path"]
        if not path.exists():
            return {"version": 1, "sources": {}}
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            LOGGER.warning("failed to read transcript source state", exc_info=True)
            return {"version": 1, "sources": {}}
        if not isinstance(parsed, dict):
            return {"version": 1, "sources": {}}
        if not isinstance(parsed.get("sources"), dict):
            parsed["sources"] = {}
        parsed["version"] = 1
        return parsed

    def _write_state(self, state: dict[str, Any]) -> None:
        path = self.paths()["source_state_path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(path.suffix + ".tmp")
        temp_path.write_text(
            json.dumps(state, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        temp_path.replace(path)

    def _read_app_state(self) -> dict[str, Any]:
        path = self.paths()["app_state_path"]
        if not path.exists():
            return {"version": 1, "connections": {}}
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            LOGGER.warning("failed to read app connection state", exc_info=True)
            return {"version": 1, "connections": {}}
        if not isinstance(parsed, dict):
            return {"version": 1, "connections": {}}
        if not isinstance(parsed.get("connections"), dict):
            parsed["connections"] = {}
        parsed["version"] = 1
        return parsed

    def _write_app_state(self, state: dict[str, Any]) -> None:
        path = self.paths()["app_state_path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(path.suffix + ".tmp")
        temp_path.write_text(
            json.dumps(state, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        temp_path.replace(path)

    def _match_running_app(
        self,
        *,
        app_name: str,
        bundle_id: str = "",
        pid: int = 0,
    ) -> dict[str, Any] | None:
        requested_name = " ".join(str(app_name or "").split()).lower()
        requested_bundle = str(bundle_id or "").strip().lower()
        requested_pid = int(pid or 0)
        candidates = [self._public_app(app) for app in self.running_app_provider()]
        if requested_pid > 0:
            for app in candidates:
                if int(app.get("pid") or 0) == requested_pid:
                    candidate_name = str(app.get("app_name") or "").strip().lower()
                    candidate_bundle = str(app.get("bundle_id") or "").strip().lower()
                    if requested_bundle and candidate_bundle == requested_bundle:
                        return app
                    if requested_name and candidate_name == requested_name:
                        return app
        if requested_bundle:
            for app in candidates:
                if str(app.get("bundle_id") or "").strip().lower() == requested_bundle:
                    return app
        if requested_name:
            for app in candidates:
                if str(app.get("app_name") or "").strip().lower() == requested_name:
                    return app
        return None

    def _connection_id(self, app: dict[str, Any]) -> str:
        app_name = " ".join(str(app.get("app_name") or "").split())
        bundle_id = " ".join(str(app.get("bundle_id") or "").split())
        pid = int(app.get("pid") or 0)
        fingerprint = f"{bundle_id}|{app_name}|{pid}"
        return "app_" + _sha256_text(fingerprint)[:16]

    def _get_connection(self, connection_id: str) -> dict[str, Any]:
        requested = str(connection_id or "").strip()
        if not requested:
            raise ValueError("connection_id must not be empty")
        connection = self._read_app_state().get("connections", {}).get(requested)
        if not isinstance(connection, dict):
            raise ValueError(f"app connection not found: {requested}")
        if not bool(connection.get("enabled", True)):
            raise ValueError(f"app connection is disabled: {requested}")
        return connection

    def _validate_source_path(self, path: Path) -> None:
        if not path.exists():
            raise ValueError(f"transcript source path does not exist: {path}")
        if not path.is_file():
            raise ValueError(f"transcript source must be a file: {path}")
        if path.suffix.lower() not in ALLOWED_TRANSCRIPT_SUFFIXES:
            allowed = ", ".join(sorted(ALLOWED_TRANSCRIPT_SUFFIXES))
            raise ValueError(f"transcript source suffix must be one of: {allowed}")
        lowered_parts = {part.lower() for part in path.parts}
        lowered_name = path.name.lower()
        if lowered_parts & SENSITIVE_PATH_FRAGMENTS or any(
            fragment in lowered_name for fragment in SENSITIVE_PATH_FRAGMENTS
        ):
            raise ValueError("refusing to register sensitive-looking path as transcript source")

    def _read_clipboard(self) -> str:
        try:
            result = subprocess.run(
                ["pbpaste"],
                text=True,
                capture_output=True,
                check=True,
                timeout=CLIPBOARD_READ_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            raise ValueError(
                "could not read macOS clipboard; pass explicit text or run from a user session"
            ) from exc
        return result.stdout

    def _detect_visible_application_processes(self) -> list[dict[str, Any]]:
        script = """
        tell application "System Events"
          set appRows to {}
          repeat with proc in (application processes whose visible is true)
            set appName to ""
            set appPid to 0
            set appBundle to ""
            try
              set appName to name of proc as text
            end try
            try
              set appPid to unix id of proc as integer
            end try
            try
              set appBundle to bundle identifier of proc as text
            end try
            if appName is not "" then
              set end of appRows to appName & tab & appPid & tab & appBundle
            end if
          end repeat
          set AppleScript's text item delimiters to linefeed
          return appRows as text
        end tell
        """
        result = subprocess.run(
            ["osascript", "-e", script],
            text=True,
            capture_output=True,
            check=True,
            timeout=APP_DETECT_SYSTEM_EVENTS_TIMEOUT_SECONDS,
        )
        apps: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if not parts or not parts[0].strip():
                continue
            try:
                pid = int(parts[1]) if len(parts) > 1 and parts[1].strip() else 0
            except ValueError:
                pid = 0
            bundle_id = parts[2].strip() if len(parts) > 2 else ""
            apps.append(
                {
                    "app_name": parts[0].strip(),
                    "pid": pid,
                    "bundle_id": "" if bundle_id == "missing value" else bundle_id,
                    "detection": "system-events",
                }
            )
        return apps

    def _detect_running_apps_macos(self) -> list[dict[str, Any]]:
        try:
            return self._detect_visible_application_processes()
        except Exception as exc:
            detail = str(getattr(exc, "stderr", "") or exc.__class__.__name__).strip()
            LOGGER.debug(
                "macOS System Events app detection failed; falling back to ps: %s",
                detail[:240],
            )
            LOGGER.debug("System Events detection failure detail", exc_info=True)
            return self._detect_running_apps_ps()

    def _detect_running_apps_ps(self) -> list[dict[str, Any]]:
        try:
            result = subprocess.run(
                ["ps", "-axo", "pid=,comm="],
                text=True,
                capture_output=True,
                check=True,
                timeout=APP_DETECT_PS_TIMEOUT_SECONDS,
            )
        except Exception:
            LOGGER.warning("ps app detection failed", exc_info=True)
            return []
        apps: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            row = line.strip()
            if not row:
                continue
            pid_text, _, command = row.partition(" ")
            try:
                pid = int(pid_text)
            except ValueError:
                continue
            app_name = Path(command.strip()).name if command.strip() else ""
            if not app_name:
                continue
            apps.append(
                {
                    "app_name": app_name,
                    "pid": pid,
                    "bundle_id": "",
                    "detection": "ps",
                }
            )
        return apps

    def _looks_like_attachable_app(self, app: dict[str, Any]) -> bool:
        name = str(app.get("app_name") or "").strip()
        if not name:
            return False
        lowered = name.lower()
        preferred_exact = {
            "alacritty",
            "chatgpt",
            "chrome",
            "claude",
            "codex",
            "cursor",
            "notes",
            "safari",
            "script editor",
            "slack",
            "terminal",
            "wireshark",
            "windows app",
        }
        if lowered in preferred_exact or (
            lowered.startswith("google chrome")
            and "helper" not in lowered
            and "renderer" not in lowered
        ):
            return True
        noisy_fragments = {
            "agent",
            "assistant",
            "background",
            "browsersupport",
            "center",
            "crashpad",
            "daemon",
            "driver",
            "extension",
            "extractor",
            "helper",
            "notification",
            "launcher",
            "plugin",
            "renderer",
            "registrar",
            "service",
            "spotlight",
            "support",
            "sync",
            "widget",
            "xpc",
            " for chrome",
        }
        if any(fragment in lowered for fragment in noisy_fragments):
            return False
        if lowered in {"sh", "zsh", "-zsh", "bash", "python", "node", "ps", "osascript"}:
            return False
        return " " in name and bool(name[0].isupper())

    def _resolve_accessibility_app_name(self, app: dict[str, Any]) -> str:
        app_name = " ".join(str(app.get("app_name") or "").split())
        if not app_name:
            raise ValueError("app_name must not be empty")
        requested_name = app_name.lower()
        requested_bundle = str(app.get("bundle_id") or "").strip().lower()
        try:
            requested_pid = int(app.get("pid") or 0)
        except (TypeError, ValueError):
            requested_pid = 0
        try:
            candidates = [
                self._public_app(candidate)
                for candidate in self._detect_visible_application_processes()
            ]
        except Exception:
            return app_name
        if requested_pid > 0:
            for candidate in candidates:
                if int(candidate.get("pid") or 0) == requested_pid:
                    return str(candidate.get("app_name") or app_name)
        if requested_bundle:
            for candidate in candidates:
                if str(candidate.get("bundle_id") or "").strip().lower() == requested_bundle:
                    return str(candidate.get("app_name") or app_name)
        for candidate in candidates:
            if str(candidate.get("app_name") or "").strip().lower() == requested_name:
                return str(candidate.get("app_name") or app_name)
        return app_name

    def _clean_accessibility_snapshot_text(self, text: str) -> str:
        lines: list[str] = []
        seen: set[str] = set()
        for raw_line in str(text or "").splitlines():
            line = " ".join(raw_line.split())
            if not line or line.lower() == "missing value":
                continue
            key = line.lower()
            if key in seen:
                continue
            seen.add(key)
            lines.append(line)
        return "\n".join(lines).strip()

    def _snapshot_quality(self, text: str) -> dict[str, Any]:
        lines = [line for line in str(text or "").splitlines() if line.strip()]
        signal_chars = sum(len(line) for line in lines)
        unique_count = len(set(line.lower() for line in lines))
        low_signal = signal_chars < 160 or len(lines) < 4
        repetitive = bool(lines) and unique_count / max(len(lines), 1) < 0.55
        if not lines:
            quality = "blocked"
        elif low_signal:
            quality = "low"
        elif repetitive:
            quality = "degraded"
        else:
            quality = "high"
        return {
            "line_count": len(lines),
            "unique_line_count": unique_count,
            "signal_chars": signal_chars,
            "low_signal": low_signal,
            "repetitive": repetitive,
            "quality": quality,
        }

    def _snapshot_quality_badge(self, quality: dict[str, Any]) -> dict[str, Any]:
        quality_id = str(quality.get("quality") or "low")
        if quality_id == "high":
            return {
                "status": "ready",
                "label": "High signal",
                "detail": "Accessibility returned enough distinct UI text for memory capture.",
                "next_action": "Capture snapshot to memory if this preview matches the intended work.",
            }
        if quality_id == "degraded":
            return {
                "status": "degraded",
                "label": "Repetitive",
                "detail": "The snapshot has enough text, but repeated UI labels may dilute recall value.",
                "next_action": "Prefer selected-text capture for exact content if this preview is mostly chrome.",
            }
        if quality_id == "blocked":
            return {
                "status": "blocked",
                "label": "No text",
                "detail": "The app did not expose readable Accessibility text.",
                "next_action": "Select relevant text in the app and use the selected-text fallback.",
            }
        return {
            "status": "degraded",
            "label": "Low signal",
            "detail": "The snapshot returned only a small amount of app text.",
            "next_action": "Open the relevant app view or use selected-text capture before writing memory.",
        }

    def _app_capture_guidance(
        self,
        *,
        connection: dict[str, Any],
        quality: dict[str, Any],
        badge: dict[str, Any],
    ) -> list[str]:
        app_name = str(connection.get("app_name") or "the app")
        guidance = [
            f"Preview shows locally exposed Accessibility text from {app_name}.",
            str(badge.get("next_action") or "Capture only if the preview matches the intended content."),
        ]
        if bool(quality.get("low_signal")):
            guidance.append("Use selected-text capture for exact content when the preview is short.")
        if int(quality.get("line_count") or 0) <= 2:
            guidance.append("Bring the target window forward and expand the relevant panel before retrying.")
        return guidance

    def _preview_text(self, text: str, *, limit: int) -> str:
        clean = str(text or "").strip()
        if len(clean) <= limit:
            return clean
        return clean[: max(0, limit - 14)].rstrip() + "\n[truncated]"

    def _snapshot_app_accessibility(self, app: dict[str, Any]) -> str:
        app_name = self._resolve_accessibility_app_name(app)
        script = """
        on appendClean(rawValue)
          try
            set textValue to rawValue as text
          on error
            return ""
          end try
          if textValue is "" or textValue is "missing value" then return ""
          return textValue & linefeed
        end appendClean

        on run argv
          set appName to item 1 of argv
          set outputText to "Application: " & appName & linefeed
          tell application "System Events"
            if not (exists process appName) then error "process not found: " & appName
            tell process appName
              try
                set frontmost to true
              end try
              set winIndex to 0
              repeat with win in windows
                set winIndex to winIndex + 1
                try
                  set outputText to outputText & "Window " & winIndex & ": " & (name of win as text) & linefeed
                on error
                  set outputText to outputText & "Window " & winIndex & linefeed
                end try
                try
                  set uiItems to entire contents of win
                  repeat with itemRef in uiItems
                    try
                      set outputText to outputText & my appendClean(name of itemRef)
                    end try
                    try
                      set outputText to outputText & my appendClean(title of itemRef)
                    end try
                    try
                      set outputText to outputText & my appendClean(description of itemRef)
                    end try
                    try
                      set outputText to outputText & my appendClean(value of itemRef)
                    end try
                  end repeat
                end try
              end repeat
            end tell
          end tell
          return outputText
        end run
        """
        try:
            result = subprocess.run(
                ["osascript", "-e", script, app_name],
                text=True,
                capture_output=True,
                check=True,
                timeout=APP_SNAPSHOT_ACCESSIBILITY_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            raise ValueError(
                "app snapshot failed; grant Accessibility permission or use selected-text capture"
            ) from exc
        return self._clean_accessibility_snapshot_text(result.stdout)

    def _public_app(self, app: dict[str, Any]) -> dict[str, Any]:
        try:
            pid = int(app.get("pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        return {
            "app_name": " ".join(str(app.get("app_name") or app.get("name") or "").split()),
            "bundle_id": " ".join(str(app.get("bundle_id") or "").split()),
            "pid": pid,
            "detection": str(app.get("detection") or "provider"),
        }

    def _public_source(self, source: dict[str, Any]) -> dict[str, Any]:
        path = Path(str(source.get("path") or ""))
        return {
            "source_id": str(source.get("source_id") or ""),
            "kind": str(source.get("kind") or "file-tail"),
            "path": str(source.get("path") or ""),
            "path_name": path.name,
            "path_sha256": str(source.get("path_sha256") or ""),
            "context_id": str(source.get("context_id") or "default"),
            "source_tag": str(source.get("source_tag") or ""),
            "speaker": str(source.get("speaker") or "operator"),
            "enabled": bool(source.get("enabled", True)),
            "cursor": int(source.get("cursor") or 0),
            "format": str(source.get("format") or ""),
            "created_at": float(source.get("created_at") or 0.0),
            "updated_at": float(source.get("updated_at") or 0.0),
            "consent": _json_safe(source.get("consent") or {}, {}),
        }

    def _public_connection(self, connection: dict[str, Any]) -> dict[str, Any]:
        return {
            "connection_id": str(connection.get("connection_id") or ""),
            "app_name": str(connection.get("app_name") or ""),
            "bundle_id": str(connection.get("bundle_id") or ""),
            "pid": int(connection.get("pid") or 0),
            "context_id": str(connection.get("context_id") or "default"),
            "source_tag": str(connection.get("source_tag") or "app-connect"),
            "speaker": str(connection.get("speaker") or "operator"),
            "enabled": bool(connection.get("enabled", True)),
            "adapter_kinds": list(connection.get("adapter_kinds") or []),
            "created_at": float(connection.get("created_at") or 0.0),
            "updated_at": float(connection.get("updated_at") or 0.0),
            "metadata": _json_safe(connection.get("metadata") or {}, {}),
            "consent": _json_safe(connection.get("consent") or {}, {}),
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Operate SYNAPSE-S2 transcript capture adapters.")
    parser.add_argument("--capture-root", default=None)
    parser.add_argument("--state", default=None)
    parser.add_argument("--memory-db", default=None)
    parser.add_argument("--dimension", type=int, default=1024)
    parser.add_argument("--neurons", type=int, default=5400)
    parser.add_argument("--top-k", type=int, default=256)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--max-bytes", type=int, default=MAX_TRANSCRIPT_DELTA_BYTES)
    return parser


def backend_from_args(args: argparse.Namespace) -> mlx_backend.SpikingAttentionBackend:
    return mlx_backend.SpikingAttentionBackend(
        dimension=args.dimension,
        num_neurons=args.neurons,
        default_top_k=args.top_k,
        compile_graph=False,
        state_path=args.state,
        memory_path=args.memory_db,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manager = TranscriptCaptureManager(
        root=args.capture_root,
        backend=backend_from_args(args),
    )
    if args.once:
        print(
            json.dumps(
                manager.poll_sources(max_bytes=args.max_bytes),
                sort_keys=True,
                default=str,
            )
        )
        return 0
    LOGGER.info("starting SYNAPSE-S2 transcript capture poller root=%s", manager.root)
    while True:
        manager.poll_sources(max_bytes=args.max_bytes)
        time.sleep(max(0.25, float(args.poll_interval)))


if __name__ == "__main__":
    raise SystemExit(main())

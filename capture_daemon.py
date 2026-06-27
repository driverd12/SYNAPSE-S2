from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any

import mlx_backend
from redaction import redact_capture_text, redact_sensitive_value


LOGGER = logging.getLogger("synapse_s2.capture_daemon")
if not LOGGER.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    LOGGER.addHandler(_handler)
LOGGER.setLevel(os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper())
LOGGER.propagate = False

CAPTURE_SUFFIXES = {".json", ".jsonl", ".txt"}
MAX_CAPTURE_BYTES = 256_000


def resolve_capture_root(root: str | os.PathLike[str] | None = None) -> Path:
    if root is not None:
        return Path(root).expanduser().resolve()
    configured = os.getenv("SYNAPSE_S2_CAPTURE_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.cwd() / ".synapse_s2").resolve()


def _json_safe(value: Any, fallback: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return fallback


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except PermissionError:
        LOGGER.warning("could not chmod private capture directory %s", path)


def _write_private_text(path: Path, text: str) -> None:
    _ensure_private_dir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(text)
        try:
            path.chmod(0o600)
        except PermissionError:
            LOGGER.warning("could not chmod private capture file %s", path)
    finally:
        if fd >= 0:
            os.close(fd)


def write_capture_drop(
    *,
    root: str | os.PathLike[str] | None = None,
    context_id: str = "default",
    source_tag: str = "codex-session",
    speaker: str = "operator",
    text: str,
    metadata: dict[str, Any] | None = None,
) -> Path:
    clean_text = str(text or "").strip()
    if not clean_text:
        raise ValueError("capture drop text must not be empty")
    capture_root = resolve_capture_root(root)
    inbox_dir = capture_root / "capture_inbox"
    _ensure_private_dir(capture_root)
    _ensure_private_dir(inbox_dir)
    context = mlx_backend.sanitize_context_id(context_id)
    tag = mlx_backend.sanitize_tag(source_tag).replace(" ", "-")
    redacted_text, redaction_count = redact_capture_text(clean_text)
    safe_metadata, metadata_redactions = redact_sensitive_value(metadata or {})
    payload = {
        "version": 1,
        "created_at": time.time(),
        "context_id": context,
        "source_tag": tag,
        "speaker": mlx_backend.sanitize_agent_id(speaker),
        "text": redacted_text,
        "metadata": _json_safe(safe_metadata, {}),
        "redaction_count": int(redaction_count + metadata_redactions),
        "input_sha256": _sha256_text(clean_text),
        "raw_text_stored": False,
    }
    digest = _sha256_text(json.dumps(payload, sort_keys=True))[:12]
    filename = f"{time.strftime('%Y%m%d-%H%M%S')}-{tag[:80]}-{digest}.json"
    output_path = inbox_dir / filename
    temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    _write_private_text(
        temp_path,
        json.dumps(payload, indent=2, sort_keys=True),
    )
    temp_path.replace(output_path)
    try:
        output_path.chmod(0o600)
    except PermissionError:
        LOGGER.warning("could not chmod capture drop %s", output_path)
    return output_path


class CaptureInboxDaemon:
    """Process opt-in session capture payloads dropped into a local inbox."""

    def __init__(
        self,
        *,
        root: str | os.PathLike[str] | None = None,
        backend: mlx_backend.SpikingAttentionBackend | None = None,
    ) -> None:
        self.root = resolve_capture_root(root)
        self.backend = backend or mlx_backend.get_backend()

    def paths(self) -> dict[str, Path]:
        return {
            "root": self.root,
            "inbox_dir": self.root / "capture_inbox",
            "processed_dir": self.root / "capture_processed",
            "error_dir": self.root / "capture_errors",
            "state_path": self.root / "capture_daemon_state.json",
        }

    def status(self) -> dict[str, Any]:
        paths = self.paths()
        for key in ("inbox_dir", "processed_dir", "error_dir"):
            _ensure_private_dir(paths[key])
        pending = self._capture_files(paths["inbox_dir"])
        processed = self._capture_files(paths["processed_dir"])
        errors = self._capture_files(paths["error_dir"])
        last_result = self._read_state(paths["state_path"])
        return {
            "root": str(paths["root"]),
            "inbox_dir": str(paths["inbox_dir"]),
            "processed_dir": str(paths["processed_dir"]),
            "error_dir": str(paths["error_dir"]),
            "pending_file_count": len(pending),
            "processed_file_count": len(processed),
            "error_file_count": len(errors),
            "pending_files": [path.name for path in pending[:20]],
            "last_result": last_result,
            "enabled": True,
            "mode": "capture-inbox",
        }

    def process_once(self, *, max_files: int = 50) -> dict[str, Any]:
        paths = self.paths()
        for key in ("inbox_dir", "processed_dir", "error_dir"):
            _ensure_private_dir(paths[key])
        files = self._capture_files(paths["inbox_dir"])[: max(1, int(max_files))]
        captures: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        processed_file_count = 0
        error_file_count = 0
        if not files:
            return {
                "processed_at": time.time(),
                "root": str(self.root),
                "processed_file_count": 0,
                "error_file_count": 0,
                "captured_payload_count": 0,
                "captured_event_count": 0,
                "captured_relationship_count": 0,
                "captures": [],
                "errors": [],
            }

        for path in files:
            try:
                payloads = self._load_payloads(path)
                for payload in payloads:
                    captures.append(self._capture_payload(path=path, payload=payload))
                self._move_file(path, paths["processed_dir"])
                processed_file_count += 1
            except Exception as exc:
                LOGGER.exception("failed to process capture payload %s", path)
                error_payload = {
                    "file": path.name,
                    "error": str(exc),
                    "failed_at": time.time(),
                }
                errors.append(error_payload)
                _write_private_text(
                    paths["error_dir"] / f"{path.name}.error.json",
                    json.dumps(error_payload, indent=2, sort_keys=True),
                )
                self._move_file(path, paths["error_dir"])
                error_file_count += 1

        captured_event_count = sum(int(item.get("event_count") or 0) for item in captures)
        captured_relationship_count = sum(
            int(item.get("relationship_count") or 0) for item in captures
        )
        result = {
            "processed_at": time.time(),
            "root": str(self.root),
            "processed_file_count": processed_file_count,
            "error_file_count": error_file_count,
            "captured_payload_count": len(captures),
            "captured_event_count": captured_event_count,
            "captured_relationship_count": captured_relationship_count,
            "captures": captures,
            "errors": errors,
        }
        _write_private_text(
            paths["state_path"],
            json.dumps(result, indent=2, sort_keys=True, default=str),
        )
        return result

    def _read_state(self, state_path: Path) -> dict[str, Any]:
        if not state_path.exists():
            return {}
        try:
            parsed = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception:
            LOGGER.warning("failed to read capture daemon state", exc_info=True)
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _capture_files(self, directory: Path) -> list[Path]:
        if not directory.exists():
            return []
        files = [
            path
            for path in directory.iterdir()
            if not path.is_symlink()
            and path.is_file()
            and path.suffix.lower() in CAPTURE_SUFFIXES
            and not path.name.startswith(".")
            and not path.name.endswith(".tmp")
        ]
        return sorted(files, key=lambda path: (path.lstat().st_mtime, path.name))

    def _load_payloads(self, path: Path) -> list[dict[str, Any]]:
        raw = self._read_capture_text(path)
        suffix = path.suffix.lower()
        if suffix == ".txt":
            return [{"source_tag": path.stem, "text": raw}]
        if suffix == ".jsonl":
            payloads = []
            for line_number, line in enumerate(raw.splitlines(), start=1):
                if not line.strip():
                    continue
                parsed = json.loads(line)
                if not isinstance(parsed, dict):
                    raise ValueError(f"jsonl line {line_number} must be an object")
                payloads.append(parsed)
            return payloads
        parsed = json.loads(raw or "{}")
        if isinstance(parsed, list):
            if not all(isinstance(item, dict) for item in parsed):
                raise ValueError("capture JSON list items must be objects")
            return parsed
        if not isinstance(parsed, dict):
            raise ValueError("capture JSON must be an object or list of objects")
        return [parsed]

    def _read_capture_text(self, path: Path) -> str:
        if path.is_symlink():
            raise ValueError("capture inbox refuses symlink payloads")
        try:
            path_stat = path.lstat()
        except FileNotFoundError as exc:
            raise ValueError(f"capture file disappeared before processing: {path.name}") from exc
        if not stat.S_ISREG(path_stat.st_mode):
            raise ValueError("capture inbox payload must be a regular file")
        if path_stat.st_size > MAX_CAPTURE_BYTES:
            raise ValueError(f"capture file exceeds {MAX_CAPTURE_BYTES} bytes")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            opened_stat = os.fstat(fd)
            if not stat.S_ISREG(opened_stat.st_mode):
                raise ValueError("capture inbox payload must be a regular file")
            if opened_stat.st_size > MAX_CAPTURE_BYTES:
                raise ValueError(f"capture file exceeds {MAX_CAPTURE_BYTES} bytes")
            raw_bytes = os.read(fd, opened_stat.st_size)
        finally:
            os.close(fd)
        return raw_bytes.decode("utf-8", errors="replace")

    def _capture_payload(self, *, path: Path, payload: dict[str, Any]) -> dict[str, Any]:
        text = str(payload.get("text", "")).strip()
        if not text:
            raise ValueError(f"{path.name} capture payload text must not be empty")
        redacted_text, redaction_count = redact_capture_text(text)
        inherited_redactions = int(payload.get("redaction_count", 0) or 0)
        raw_metadata = payload.get("metadata", {})
        metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
        safe_metadata, metadata_redactions = redact_sensitive_value(metadata)
        source_tag = mlx_backend.sanitize_tag(
            str(payload.get("source_tag") or payload.get("tag") or path.stem)
        ).replace(" ", "-")
        capture = self.backend.capture_conversation(
            text=redacted_text,
            context_id=mlx_backend.sanitize_context_id(
                str(payload.get("context_id") or "default")
            ),
            source_tag=source_tag,
            speaker=mlx_backend.sanitize_agent_id(str(payload.get("speaker") or "capture-daemon")),
            surprise_threshold=float(payload.get("surprise_threshold", 0.5)),
            min_segment_sentences=int(payload.get("min_segment_sentences", 1)),
            metadata={
                **_json_safe(safe_metadata, {}),
                "capture_daemon": True,
                "capture_file": path.name,
                "redaction_count": int(
                    redaction_count + inherited_redactions + metadata_redactions
                ),
                "input_sha256": str(payload.get("input_sha256") or _sha256_text(text)),
                "raw_text_stored": False,
            },
        )
        return {
            "context_id": capture["context_id"],
            "source_tag": capture["source_tag"],
            "speaker": capture.get("speaker"),
            "event_count": capture["event_count"],
            "relationship_count": capture["relationship_count"],
            "agent_deployment": capture.get("agent_deployment"),
            "redaction_count": int(redaction_count + inherited_redactions + metadata_redactions),
        }

    def _move_file(self, path: Path, destination_dir: Path) -> Path:
        _ensure_private_dir(destination_dir)
        destination = destination_dir / path.name
        if destination.exists():
            destination = destination_dir / f"{path.stem}-{int(time.time() * 1000)}{path.suffix}"
        path.replace(destination)
        try:
            destination.chmod(0o600)
        except PermissionError:
            LOGGER.warning("could not chmod moved capture file %s", destination)
        return destination


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the SYNAPSE-S2 capture inbox daemon.")
    parser.add_argument("--capture-root", default=None)
    parser.add_argument("--state", default=None)
    parser.add_argument("--memory-db", default=None)
    parser.add_argument("--dimension", type=int, default=1024)
    parser.add_argument("--neurons", type=int, default=5000)
    parser.add_argument("--top-k", type=int, default=150)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--max-files", type=int, default=50)
    parser.add_argument("--poll-transcript-sources", action="store_true")
    parser.add_argument("--max-transcript-bytes", type=int, default=256_000)
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
    daemon = CaptureInboxDaemon(root=args.capture_root, backend=backend_from_args(args))
    if args.once:
        result = daemon.process_once(max_files=args.max_files)
        if args.poll_transcript_sources:
            result["transcript_sources"] = _poll_transcript_sources(
                root=args.capture_root,
                backend=daemon.backend,
                max_bytes=args.max_transcript_bytes,
            )
        print(json.dumps(result, sort_keys=True, default=str))
        return 0
    LOGGER.info("starting SYNAPSE-S2 capture inbox daemon root=%s", daemon.root)
    while True:
        daemon.process_once(max_files=args.max_files)
        if args.poll_transcript_sources:
            _poll_transcript_sources(
                root=args.capture_root,
                backend=daemon.backend,
                max_bytes=args.max_transcript_bytes,
            )
        time.sleep(max(0.25, float(args.poll_interval)))


def _poll_transcript_sources(
    *,
    root: str | os.PathLike[str] | None,
    backend: mlx_backend.SpikingAttentionBackend,
    max_bytes: int,
) -> dict[str, Any]:
    try:
        import transcript_capture

        return transcript_capture.TranscriptCaptureManager(
            root=root,
            backend=backend,
        ).poll_sources(max_bytes=max_bytes)
    except Exception as exc:
        LOGGER.exception("transcript source polling failed")
        return {"error": str(exc)}


if __name__ == "__main__":
    raise SystemExit(main())

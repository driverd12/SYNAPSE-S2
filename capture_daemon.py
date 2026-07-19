from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import logging
import math
import os
import re
import secrets
import stat
import sys
import time
from pathlib import Path
from typing import Any, Iterator

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
STALE_EMPTY_CLAIM_SECONDS = 60.0
STALE_INBOX_TEMP_SECONDS = 300.0
CAPTURE_PROTOCOL_VERSION = 2
CAPTURE_ID_RE = re.compile(r"^s2cap_[0-9a-f]{32}$")
CLAIM_DIR_RE = re.compile(r"^s2claim_[0-9a-f]{32}$")
LEGACY_INBOX_TEMP_RE = re.compile(r"^.+\.(?:json|jsonl|txt)\.tmp$", re.IGNORECASE)
ATOMIC_INBOX_TEMP_RE = re.compile(
    r"^\..+\.(?:json|jsonl|txt)\.[0-9a-f]{32}\.tmp$",
    re.IGNORECASE,
)
LEGACY_TEXT_IDENTITY_FILE = ".capture-identity.json"
UNTRUSTED_RAW_DIGEST_KEYS = {
    "input_sha256",
    "raw_input_sha256",
    "raw_sha256",
    "raw_text_sha256",
    "payload_sha256",
}
SENSITIVE_METADATA_KEYS = {
    "api_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "token",
    "secret",
    "password",
    "authorization",
    "private_key",
}


class CaptureDeferred(RuntimeError):
    """A capture is owned by another worker and should be retried later."""


class CaptureCleanupPending(RuntimeError):
    """The backend committed, but transport cleanup must be retried."""


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


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_write_private_text(path: Path, text: str) -> None:
    _ensure_private_dir(path.parent)
    temp_path = path.parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(temp_path, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        os.replace(temp_path, path)
        try:
            path.chmod(0o600)
        except PermissionError:
            LOGGER.warning("could not chmod private capture file %s", path)
        _fsync_directory(path.parent)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _canonical_capture_id(value: Any) -> str:
    capture_id = str(value or "").strip()
    if CAPTURE_ID_RE.fullmatch(capture_id) is None:
        raise ValueError(
            "capture_id must use canonical s2cap_<32 lowercase hex> format"
        )
    return capture_id


def new_capture_id() -> str:
    """Return a cryptographically random canonical capture transport identity."""

    return f"s2cap_{secrets.token_hex(16)}"


def write_capture_drop(
    *,
    root: str | os.PathLike[str] | None = None,
    context_id: str = "default",
    source_tag: str = "codex-session",
    speaker: str = "operator",
    text: str,
    metadata: dict[str, Any] | None = None,
    capture_id: str | None = None,
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
    canonical_capture_id = (
        _canonical_capture_id(capture_id)
        if capture_id is not None
        else new_capture_id()
    )
    payload = {
        "version": CAPTURE_PROTOCOL_VERSION,
        "capture_id": canonical_capture_id,
        "created_at": time.time(),
        "context_id": context,
        "source_tag": tag,
        "speaker": mlx_backend.sanitize_agent_id(speaker),
        "text": redacted_text,
        "metadata": _json_safe(safe_metadata, {}),
        "redaction_count": int(redaction_count + metadata_redactions),
        "raw_text_stored": False,
    }
    filename = (
        f"{time.strftime('%Y%m%d-%H%M%S')}-{tag[:80]}-"
        f"{canonical_capture_id}-{secrets.token_hex(6)}.json"
    )
    output_path = inbox_dir / filename
    _atomic_write_private_text(
        output_path,
        json.dumps(payload, indent=2, sort_keys=True),
    )
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
        self._backend = backend

    @property
    def backend(self) -> mlx_backend.SpikingAttentionBackend:
        """Construct the expensive MLX backend only on the ingestion path."""

        if self._backend is None:
            self._backend = mlx_backend.get_backend()
        return self._backend

    def paths(self) -> dict[str, Path]:
        return {
            "root": self.root,
            "inbox_dir": self.root / "capture_inbox",
            "processing_dir": self.root / "capture_processing",
            "processed_dir": self.root / "capture_processed",
            "error_dir": self.root / "capture_errors",
            "receipt_dir": self.root / "capture_receipts",
            "lock_dir": self.root / "capture_locks",
            "state_path": self.root / "capture_daemon_state.json",
        }

    def _ensure_transport_dirs(self, paths: dict[str, Path]) -> None:
        for key in (
            "inbox_dir",
            "processing_dir",
            "processed_dir",
            "error_dir",
            "receipt_dir",
            "lock_dir",
        ):
            _ensure_private_dir(paths[key])

    def status(self) -> dict[str, Any]:
        paths = self.paths()
        self._ensure_transport_dirs(paths)
        pending = self._capture_files(paths["inbox_dir"])
        temp_diagnostics = self._inbox_temp_diagnostics(paths["inbox_dir"])
        processing = self._processing_claims(paths["processing_dir"])
        processing_diagnostics = self._processing_diagnostics(paths["processing_dir"])
        processed = self._capture_files(paths["processed_dir"])
        errors = self._capture_files(paths["error_dir"])
        receipts = self._receipt_files(paths["receipt_dir"])
        last_result = self._read_state(paths["state_path"])
        return {
            "root": str(paths["root"]),
            "inbox_dir": str(paths["inbox_dir"]),
            "processing_dir": str(paths["processing_dir"]),
            "processed_dir": str(paths["processed_dir"]),
            "error_dir": str(paths["error_dir"]),
            "receipt_dir": str(paths["receipt_dir"]),
            "pending_file_count": len(pending),
            "inbox_temp_file_count": temp_diagnostics["total"],
            "fresh_inbox_temp_file_count": temp_diagnostics["fresh"],
            "stale_inbox_temp_file_count": temp_diagnostics["stale"],
            "ignored_inbox_temp_file_count": temp_diagnostics["ignored"],
            "inbox_temp_stale_after_seconds": STALE_INBOX_TEMP_SECONDS,
            "processing_file_count": len(processing),
            "processing_empty_claim_count": processing_diagnostics["empty"],
            "processing_malformed_claim_count": processing_diagnostics["malformed"],
            "processed_file_count": len(processed),
            "error_file_count": len(errors),
            "receipt_count": len(receipts),
            "pending_files": [path.name for path in pending[:20]],
            "processing_files": [path.name for _, path in processing[:20]],
            "last_result": last_result,
            "enabled": True,
            "mode": "capture-inbox",
        }

    def preflight(self, *, max_files: int = 50) -> dict[str, Any]:
        paths = self.paths()
        self._ensure_transport_dirs(paths)
        bounded_max = min(max(int(max_files), 1), 250)
        pending = self._capture_files(paths["inbox_dir"])
        selected = pending[:bounded_max]
        selected_files: list[dict[str, Any]] = []
        selected_total_bytes = 0
        for path in selected:
            try:
                stat_result = path.lstat()
                size = int(stat_result.st_size)
                modified_at = float(stat_result.st_mtime)
            except FileNotFoundError:
                continue
            transport_token = self._preflight_transport_token(
                path=path,
                stat_result=stat_result,
            )
            try:
                request_fingerprint = self._preflight_request_fingerprint(path)
                fingerprint_mode = "post-redaction-request"
            except Exception:
                # Malformed drops still need an operator-confirmable transport
                # identity so processing can quarantine them. The token below
                # contains only file-system metadata, never content bytes.
                request_fingerprint = ""
                fingerprint_mode = "transport-metadata-only"
            selected_total_bytes += size
            selected_files.append(
                {
                    "file": path.name,
                    "bytes": size,
                    "modified_at": modified_at,
                    "transport_token": transport_token,
                    "request_fingerprint": request_fingerprint,
                    "fingerprint_mode": fingerprint_mode,
                }
            )
        return {
            "action": "capture-inbox-preflight",
            "root": str(self.root),
            "inbox_dir": str(paths["inbox_dir"]),
            "pending_file_count": len(pending),
            "selected_file_count": len(selected_files),
            "selected_total_bytes": selected_total_bytes,
            "selected_files": selected_files,
            "max_files": bounded_max,
            "mode": "manual-confirmation-preflight",
        }

    def _preflight_transport_token(
        self,
        *,
        path: Path,
        stat_result: os.stat_result,
    ) -> str:
        metadata = {
            "file": path.name,
            "device": int(stat_result.st_dev),
            "inode": int(stat_result.st_ino),
            "mode": int(stat.S_IMODE(stat_result.st_mode)),
            "bytes": int(stat_result.st_size),
            "modified_ns": int(stat_result.st_mtime_ns),
            "changed_ns": int(stat_result.st_ctime_ns),
        }
        return _sha256_text(
            json.dumps(metadata, sort_keys=True, separators=(",", ":"))
        )

    def _preflight_request_fingerprint(self, path: Path) -> str:
        document_kind, raw_payloads = self._load_payload_document(path)
        requests: list[dict[str, Any]] = []
        for ordinal, raw_payload in enumerate(raw_payloads):
            payload = dict(raw_payload)
            raw_version = payload.get("version", 1)
            if isinstance(raw_version, bool):
                raise ValueError("capture payload version must be 1 or 2")
            version = int(raw_version)
            if version not in (1, CAPTURE_PROTOCOL_VERSION):
                raise ValueError(f"unsupported capture payload version: {version}")
            payload["version"] = version
            if version == CAPTURE_PROTOCOL_VERSION:
                capture_id = _canonical_capture_id(payload.get("capture_id"))
            elif payload.get("capture_id"):
                capture_id = _canonical_capture_id(payload.get("capture_id"))
            else:
                # Preflight must not allocate durable identity. A stable local
                # placeholder lets equivalent legacy requests compare safely;
                # the claimed file receives a random persisted ID before apply.
                capture_id = f"s2cap_{ordinal:032x}"
            payload["capture_id"] = capture_id
            normalized = self._normalize_payload_before_capture(
                path=path,
                payload=payload,
                version=version,
            )
            requests.append(self._canonical_capture_request(normalized))
        safe_contract = {
            "protocol": "capture-preflight.v2",
            "document_kind": document_kind,
            "requests": requests,
        }
        return self._request_fingerprint(safe_contract)

    def _inbox_temp_kind(self, name: str) -> str:
        if ATOMIC_INBOX_TEMP_RE.fullmatch(name) is not None:
            return "atomic-write-temp"
        if LEGACY_INBOX_TEMP_RE.fullmatch(name) is not None:
            return "legacy-write-temp"
        return ""

    def _inbox_temp_artifacts(self, inbox_dir: Path) -> list[dict[str, Any]]:
        try:
            entries = list(inbox_dir.iterdir())
        except FileNotFoundError:
            return []
        now = time.time()
        artifacts: list[dict[str, Any]] = []
        for path in entries:
            temp_kind = self._inbox_temp_kind(path.name)
            if not temp_kind:
                continue
            try:
                path_stat = path.lstat()
            except FileNotFoundError:
                continue
            regular = bool(
                stat.S_ISREG(path_stat.st_mode)
                and not stat.S_ISLNK(path_stat.st_mode)
            )
            newest_change = max(
                float(path_stat.st_mtime),
                float(path_stat.st_ctime),
            )
            age_seconds = max(0.0, now - newest_change)
            state = (
                "ignored"
                if not regular
                else "stale"
                if age_seconds >= STALE_INBOX_TEMP_SECONDS
                else "fresh"
            )
            artifacts.append(
                {
                    "path": path,
                    "kind": temp_kind,
                    "state": state,
                    "age_seconds": age_seconds,
                    "stat": path_stat,
                }
            )
        return sorted(
            artifacts,
            key=lambda item: (float(item["stat"].st_mtime), item["path"].name),
        )

    def _inbox_temp_diagnostics(self, inbox_dir: Path) -> dict[str, int]:
        artifacts = self._inbox_temp_artifacts(inbox_dir)
        return {
            "total": len(artifacts),
            "fresh": sum(1 for item in artifacts if item["state"] == "fresh"),
            "stale": sum(1 for item in artifacts if item["state"] == "stale"),
            "ignored": sum(1 for item in artifacts if item["state"] == "ignored"),
        }

    def _repair_inbox_temp_artifacts(
        self,
        paths: dict[str, Path],
    ) -> dict[str, int]:
        repaired = {
            "quarantined": 0,
            "evidence_errors": 0,
        }
        inbox_dir = paths["inbox_dir"]
        for artifact in self._inbox_temp_artifacts(inbox_dir):
            if artifact["state"] != "stale":
                continue
            path = artifact["path"]
            observed_stat = artifact["stat"]
            observed_identity = (
                int(observed_stat.st_dev),
                int(observed_stat.st_ino),
                int(observed_stat.st_size),
                int(observed_stat.st_mtime_ns),
                int(observed_stat.st_ctime_ns),
            )
            try:
                current_stat = path.lstat()
            except FileNotFoundError:
                continue
            current_identity = (
                int(current_stat.st_dev),
                int(current_stat.st_ino),
                int(current_stat.st_size),
                int(current_stat.st_mtime_ns),
                int(current_stat.st_ctime_ns),
            )
            if (
                current_identity != observed_identity
                or not stat.S_ISREG(current_stat.st_mode)
                or stat.S_ISLNK(current_stat.st_mode)
            ):
                continue
            current_age = max(
                0.0,
                time.time()
                - max(float(current_stat.st_mtime), float(current_stat.st_ctime)),
            )
            if current_age < STALE_INBOX_TEMP_SECONDS:
                continue
            destination = self._unique_destination(
                paths["error_dir"],
                f"stale-temp-{path.name}",
            )
            try:
                os.replace(path, destination)
            except FileNotFoundError:
                continue
            try:
                destination.chmod(0o600)
            except PermissionError:
                LOGGER.warning("could not chmod quarantined temp %s", destination)
            _fsync_directory(inbox_dir)
            _fsync_directory(paths["error_dir"])
            quarantined_at = time.time()
            evidence = {
                "artifact_type": "stale-capture-inbox-temp",
                "original_file": path.name,
                "quarantined_file": destination.name,
                "temp_kind": artifact["kind"],
                "observed_bytes": int(current_stat.st_size),
                "observed_modified_at": float(current_stat.st_mtime),
                "observed_changed_at": float(current_stat.st_ctime),
                "observed_age_seconds": round(current_age, 3),
                "transport_token": self._preflight_transport_token(
                    path=path,
                    stat_result=current_stat,
                ),
                "content_inspected": False,
                "content_digest_recorded": False,
                "quarantined_at": quarantined_at,
                "reason": (
                    "stale capture inbox temp was never eligible for ingestion"
                ),
            }
            evidence_path = self._unique_destination(
                paths["error_dir"],
                f"{destination.name}.evidence.json",
            )
            try:
                _atomic_write_private_text(
                    evidence_path,
                    json.dumps(evidence, indent=2, sort_keys=True),
                )
            except Exception:
                repaired["evidence_errors"] += 1
                LOGGER.exception(
                    "quarantined stale inbox temp but failed to persist evidence %s",
                    evidence_path,
                )
            repaired["quarantined"] += 1
        return repaired

    def process_once(self, *, max_files: int = 50) -> dict[str, Any]:
        paths = self.paths()
        self._ensure_transport_dirs(paths)
        bounded_max = min(max(int(max_files), 1), 250)
        temp_repair = self._repair_inbox_temp_artifacts(paths)
        repair = self._repair_processing_claims(paths)
        claims = self._processing_claims(paths["processing_dir"])[:bounded_max]
        remaining = bounded_max - len(claims)
        if remaining > 0:
            for inbox_path in self._capture_files(paths["inbox_dir"])[:remaining]:
                claimed = self._claim_inbox_file(
                    inbox_path=inbox_path,
                    inbox_dir=paths["inbox_dir"],
                    processing_dir=paths["processing_dir"],
                )
                if claimed is not None:
                    claims.append(claimed)

        captures: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        processed_file_count = 0
        error_file_count = 0
        deferred_file_count = 0
        idempotent_capture_count = 0

        for claim_dir, path in claims:
            outcome = self._process_claim(
                claim_dir=claim_dir,
                path=path,
                paths=paths,
            )
            if outcome is None:
                deferred_file_count += 1
                continue
            captures.extend(outcome["captures"])
            errors.extend(outcome["errors"])
            processed_file_count += int(outcome["processed_file_count"])
            error_file_count += int(outcome["error_file_count"])
            idempotent_capture_count += int(outcome["idempotent_capture_count"])

        captured_event_count = sum(int(item.get("event_count") or 0) for item in captures)
        captured_relationship_count = sum(
            int(item.get("relationship_count") or 0) for item in captures
        )
        temp_diagnostics = self._inbox_temp_diagnostics(paths["inbox_dir"])
        result = {
            "processed_at": time.time(),
            "root": str(self.root),
            "processed_file_count": processed_file_count,
            "error_file_count": error_file_count,
            "deferred_file_count": deferred_file_count,
            "repaired_empty_claim_count": repair["empty_removed"],
            "quarantined_claim_count": repair["malformed_quarantined"],
            "quarantined_stale_temp_count": temp_repair["quarantined"],
            "temp_quarantine_evidence_error_count": temp_repair["evidence_errors"],
            "inbox_temp_file_count": temp_diagnostics["total"],
            "fresh_inbox_temp_file_count": temp_diagnostics["fresh"],
            "stale_inbox_temp_file_count": temp_diagnostics["stale"],
            "ignored_inbox_temp_file_count": temp_diagnostics["ignored"],
            "inbox_temp_stale_after_seconds": STALE_INBOX_TEMP_SECONDS,
            "captured_payload_count": len(captures),
            "idempotent_capture_count": idempotent_capture_count,
            "captured_event_count": captured_event_count,
            "captured_relationship_count": captured_relationship_count,
            "captures": captures,
            "errors": errors,
        }
        if claims or temp_repair["quarantined"]:
            _atomic_write_private_text(
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
        files: list[Path] = []
        try:
            entries = list(directory.iterdir())
        except FileNotFoundError:
            return []
        for path in entries:
            try:
                path_stat = path.lstat()
            except FileNotFoundError:
                continue
            if (
                stat.S_ISREG(path_stat.st_mode)
                and not path.is_symlink()
                and path.suffix.lower() in CAPTURE_SUFFIXES
                and not path.name.startswith(".")
                and not path.name.endswith(".tmp")
            ):
                files.append(path)
        return sorted(files, key=self._path_sort_key)

    def _path_sort_key(self, path: Path) -> tuple[float, str]:
        try:
            modified_at = float(path.lstat().st_mtime)
        except FileNotFoundError:
            modified_at = float("inf")
        return (modified_at, path.name)

    def _receipt_files(self, receipt_dir: Path) -> list[Path]:
        if not receipt_dir.exists():
            return []
        receipts: list[Path] = []
        for path in receipt_dir.iterdir():
            try:
                path_stat = path.lstat()
            except FileNotFoundError:
                continue
            if (
                stat.S_ISREG(path_stat.st_mode)
                and not path.is_symlink()
                and path.suffix == ".json"
                and CAPTURE_ID_RE.fullmatch(path.stem) is not None
            ):
                receipts.append(path)
        return sorted(receipts, key=self._path_sort_key)

    def _processing_claims(self, processing_dir: Path) -> list[tuple[Path, Path]]:
        if not processing_dir.exists():
            return []
        claims: list[tuple[Path, Path]] = []
        for claim_dir in processing_dir.iterdir():
            try:
                claim_stat = claim_dir.lstat()
            except FileNotFoundError:
                continue
            if (
                claim_dir.is_symlink()
                or not stat.S_ISDIR(claim_stat.st_mode)
                or CLAIM_DIR_RE.fullmatch(claim_dir.name) is None
            ):
                continue
            payload_files = self._capture_files(claim_dir)
            if len(payload_files) == 1:
                claims.append((claim_dir, payload_files[0]))
        return sorted(claims, key=lambda item: self._path_sort_key(item[1]))

    def _processing_diagnostics(self, processing_dir: Path) -> dict[str, int]:
        diagnostics = {"empty": 0, "malformed": 0}
        if not processing_dir.exists():
            return diagnostics
        for claim_dir in processing_dir.iterdir():
            try:
                claim_stat = claim_dir.lstat()
            except FileNotFoundError:
                continue
            if (
                claim_dir.is_symlink()
                or not stat.S_ISDIR(claim_stat.st_mode)
                or CLAIM_DIR_RE.fullmatch(claim_dir.name) is None
            ):
                continue
            state = self._claim_state(claim_dir)
            if state["missing"]:
                continue
            if state["malformed"]:
                diagnostics["malformed"] += 1
            elif not state["payloads"]:
                diagnostics["empty"] += 1
        return diagnostics

    def _claim_state(self, claim_dir: Path) -> dict[str, Any]:
        payloads = self._capture_files(claim_dir)
        child_names: list[str] = []
        unknown_names: list[str] = []
        try:
            children = list(claim_dir.iterdir())
        except FileNotFoundError:
            return {
                "payloads": [],
                "child_names": [],
                "unknown_names": [],
                "malformed": False,
                "missing": True,
            }
        for child in children:
            child_names.append(child.name)
            if child.name in {".lock", LEGACY_TEXT_IDENTITY_FILE}:
                continue
            if child in payloads:
                continue
            unknown_names.append(child.name)
        identity_allowed = bool(
            not (claim_dir / LEGACY_TEXT_IDENTITY_FILE).exists()
            or (len(payloads) == 1 and payloads[0].suffix.lower() == ".txt")
            or not payloads
        )
        return {
            "payloads": payloads,
            "child_names": sorted(child_names),
            "unknown_names": sorted(unknown_names),
            "malformed": bool(
                len(payloads) > 1 or unknown_names or not identity_allowed
            ),
            "missing": False,
        }

    def _repair_processing_claims(self, paths: dict[str, Path]) -> dict[str, int]:
        repaired = {"empty_removed": 0, "malformed_quarantined": 0}
        processing_dir = paths["processing_dir"]
        now = time.time()
        for claim_dir in list(processing_dir.iterdir()):
            try:
                claim_stat = claim_dir.lstat()
            except FileNotFoundError:
                continue
            if (
                claim_dir.is_symlink()
                or not stat.S_ISDIR(claim_stat.st_mode)
                or CLAIM_DIR_RE.fullmatch(claim_dir.name) is None
            ):
                continue
            initial_state = self._claim_state(claim_dir)
            if initial_state["missing"]:
                continue
            if initial_state["malformed"]:
                quarantine = False
                with self._exclusive_lock(claim_dir / ".lock") as acquired:
                    if not acquired:
                        continue
                    state = self._claim_state(claim_dir)
                    if state["missing"] or not state["malformed"]:
                        continue
                    destination = self._unique_destination(
                        paths["error_dir"],
                        f"malformed-{claim_dir.name}",
                    )
                    os.replace(claim_dir, destination)
                    _fsync_directory(processing_dir)
                    _fsync_directory(paths["error_dir"])
                    error_payload = {
                        "claim": claim_dir.name,
                        "error": "malformed capture claim quarantined before effect",
                        "children": state["child_names"],
                        "failed_at": time.time(),
                    }
                    _atomic_write_private_text(
                        self._unique_destination(
                            paths["error_dir"],
                            f"{claim_dir.name}.error.json",
                        ),
                        json.dumps(error_payload, indent=2, sort_keys=True),
                    )
                    quarantine = True
                if quarantine:
                    repaired["malformed_quarantined"] += 1
                continue
            if initial_state["payloads"]:
                continue
            newest_mtime = float(claim_stat.st_mtime)
            for child_name in initial_state["child_names"]:
                try:
                    newest_mtime = max(
                        newest_mtime,
                        float((claim_dir / child_name).lstat().st_mtime),
                    )
                except FileNotFoundError:
                    continue
            if now - newest_mtime < STALE_EMPTY_CLAIM_SECONDS:
                continue
            remove_empty = False
            with self._exclusive_lock(claim_dir / ".lock") as acquired:
                if not acquired:
                    continue
                state = self._claim_state(claim_dir)
                remove_empty = bool(
                    not state["missing"]
                    and not state["payloads"]
                    and not state["malformed"]
                )
            if remove_empty:
                self._cleanup_empty_claim(claim_dir)
                if not claim_dir.exists():
                    repaired["empty_removed"] += 1
        return repaired

    def _claim_inbox_file(
        self,
        *,
        inbox_path: Path,
        inbox_dir: Path,
        processing_dir: Path,
    ) -> tuple[Path, Path] | None:
        claim_dir = processing_dir / f"s2claim_{secrets.token_hex(16)}"
        _ensure_private_dir(claim_dir)
        claimed_path = claim_dir / inbox_path.name
        try:
            os.replace(inbox_path, claimed_path)
        except FileNotFoundError:
            self._cleanup_empty_claim(claim_dir)
            return None
        except Exception:
            self._cleanup_empty_claim(claim_dir)
            raise
        try:
            claimed_path.chmod(0o600)
        except PermissionError:
            LOGGER.warning("could not chmod claimed capture file %s", claimed_path)
        _fsync_directory(inbox_dir)
        _fsync_directory(claim_dir)
        _fsync_directory(processing_dir)
        return claim_dir, claimed_path

    @contextlib.contextmanager
    def _exclusive_lock(self, lock_path: Path) -> Iterator[bool]:
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            fd = os.open(lock_path, flags, 0o600)
        except FileNotFoundError:
            yield False
            return
        acquired = False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                acquired = False
            yield acquired
        finally:
            if acquired:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _process_claim(
        self,
        *,
        claim_dir: Path,
        path: Path,
        paths: dict[str, Path],
    ) -> dict[str, Any] | None:
        moved = False
        outcome: dict[str, Any] | None = None
        with self._exclusive_lock(claim_dir / ".lock") as acquired:
            if not acquired:
                return None
            captures: list[dict[str, Any]] = []
            payloads: list[dict[str, Any]] = []
            current_payload: dict[str, Any] | None = None
            current_record_index: int | None = None
            try:
                document_kind, payloads = self._prepare_payload_document(path)
                del document_kind
                for record_index, payload in enumerate(payloads):
                    current_payload = payload
                    current_record_index = record_index
                    captures.append(
                        self._capture_payload_exactly_once(path=path, payload=payload)
                    )
                try:
                    self._move_file(path, paths["processed_dir"])
                except Exception as exc:
                    raise CaptureCleanupPending(
                        f"capture committed but archive cleanup failed for {path.name}"
                    ) from exc
                moved = True
                outcome = {
                    "processed_file_count": 1,
                    "error_file_count": 0,
                    "idempotent_capture_count": sum(
                        1 for item in captures if item.get("idempotent_replay")
                    ),
                    "captures": captures,
                    "errors": [],
                }
            except CaptureCleanupPending:
                LOGGER.warning(
                    "capture commit is durable; cleanup remains pending for %s",
                    path,
                    exc_info=True,
                )
                return None
            except CaptureDeferred:
                return None
            except Exception as exc:
                LOGGER.exception("failed to process capture payload %s", path)
                error_payload = {
                    "file": path.name,
                    "error": str(exc),
                    "failed_at": time.time(),
                    "batch_atomicity": "per-record",
                    "batch_record_count": len(payloads),
                    "failed_record_index": current_record_index,
                    "failed_capture_id": (
                        str(current_payload.get("capture_id") or "")
                        if isinstance(current_payload, dict)
                        else ""
                    ),
                    **self._committed_capture_audit(captures),
                }
                sidecar = self._unique_destination(
                    paths["error_dir"],
                    f"{path.name}.error.json",
                )
                _atomic_write_private_text(
                    sidecar,
                    json.dumps(error_payload, indent=2, sort_keys=True),
                )
                if path.exists():
                    self._move_file(path, paths["error_dir"])
                moved = True
                outcome = {
                    "processed_file_count": 0,
                    "error_file_count": 1,
                    "idempotent_capture_count": sum(
                        1 for item in captures if item.get("idempotent_replay")
                    ),
                    "captures": captures,
                    "errors": [error_payload],
                }
        if moved:
            self._cleanup_empty_claim(claim_dir)
        return outcome

    def _committed_capture_audit(
        self,
        captures: list[dict[str, Any]],
    ) -> dict[str, Any]:
        committed: list[dict[str, Any]] = []
        for capture in captures:
            capture_id = _canonical_capture_id(capture.get("capture_id"))
            committed.append(
                {
                    "capture_id": capture_id,
                    "context_id": str(capture.get("context_id") or "default"),
                    "source_tag": str(capture.get("source_tag") or ""),
                    "event_count": int(capture.get("event_count") or 0),
                    "relationship_count": int(
                        capture.get("relationship_count") or 0
                    ),
                    "idempotent_replay": bool(
                        capture.get("idempotent_replay")
                    ),
                    "receipt_replay": bool(capture.get("receipt_replay")),
                }
            )
        return {
            "committed_capture_count": len(committed),
            "committed_capture_ids": [
                item["capture_id"] for item in committed
            ],
            "committed_event_count": sum(
                int(item["event_count"]) for item in committed
            ),
            "committed_relationship_count": sum(
                int(item["relationship_count"]) for item in committed
            ),
            "idempotent_replay_count": sum(
                1 for item in committed if item["idempotent_replay"]
            ),
            "receipt_replay_count": sum(
                1 for item in committed if item["receipt_replay"]
            ),
            "committed_captures": committed,
        }

    def _load_payload_document(self, path: Path) -> tuple[str, list[dict[str, Any]]]:
        raw = self._read_capture_text(path)
        suffix = path.suffix.lower()
        if suffix == ".txt":
            payload: dict[str, Any] = {
                "version": 1,
                "source_tag": path.stem,
                "text": raw,
            }
            identity_path = path.parent / LEGACY_TEXT_IDENTITY_FILE
            if (
                CLAIM_DIR_RE.fullmatch(path.parent.name) is not None
                and identity_path.exists()
            ):
                try:
                    identity = json.loads(self._read_capture_text(identity_path))
                except Exception as exc:
                    raise ValueError("legacy text capture identity is invalid") from exc
                if not isinstance(identity, dict):
                    raise ValueError("legacy text capture identity must be an object")
                payload.update(identity)
                payload["text"] = raw
            return "txt", [payload]
        if suffix == ".jsonl":
            payloads: list[dict[str, Any]] = []
            for line_number, line in enumerate(raw.splitlines(), start=1):
                if not line.strip():
                    continue
                parsed = json.loads(line)
                if not isinstance(parsed, dict):
                    raise ValueError(f"jsonl line {line_number} must be an object")
                payloads.append(parsed)
            if not payloads:
                raise ValueError("capture JSONL must contain at least one object")
            return "jsonl", payloads
        parsed = json.loads(raw or "{}")
        if isinstance(parsed, list):
            if not all(isinstance(item, dict) for item in parsed):
                raise ValueError("capture JSON list items must be objects")
            if not parsed:
                raise ValueError("capture JSON list must not be empty")
            return "json-list", parsed
        if not isinstance(parsed, dict):
            raise ValueError("capture JSON must be an object or list of objects")
        return "json-object", [parsed]

    def _prepare_payload_document(
        self,
        path: Path,
    ) -> tuple[str, list[dict[str, Any]]]:
        document_kind, raw_payloads = self._load_payload_document(path)
        payloads: list[dict[str, Any]] = []
        changed = False
        capture_ids: set[str] = set()
        for ordinal, raw_payload in enumerate(raw_payloads):
            payload = dict(raw_payload)
            raw_version = payload.get("version", 1)
            if isinstance(raw_version, bool):
                raise ValueError("capture payload version must be 1 or 2")
            try:
                version = int(raw_version)
            except (TypeError, ValueError) as exc:
                raise ValueError("capture payload version must be 1 or 2") from exc
            if version not in (1, CAPTURE_PROTOCOL_VERSION):
                raise ValueError(f"unsupported capture payload version: {version}")
            payload["version"] = version
            if version == CAPTURE_PROTOCOL_VERSION:
                capture_id = _canonical_capture_id(payload.get("capture_id"))
            elif payload.get("capture_id"):
                capture_id = _canonical_capture_id(payload.get("capture_id"))
            else:
                capture_id = new_capture_id()
            payload["capture_id"] = capture_id
            payload.pop("input_sha256", None)
            payload = self._normalize_payload_before_capture(
                path=path,
                payload=payload,
                version=version,
            )
            if capture_id in capture_ids:
                raise ValueError(
                    f"duplicate capture_id within one batch: {capture_id}"
                )
            capture_ids.add(capture_id)
            payloads.append(payload)
            changed = changed or payload != raw_payload

        if document_kind == "txt":
            self._persist_legacy_text_payload(path=path, payload=payloads[0])
        elif changed:
            self._persist_payload_document(
                path=path,
                document_kind=document_kind,
                payloads=payloads,
            )
        return document_kind, payloads

    def _normalize_payload_before_capture(
        self,
        *,
        path: Path,
        payload: dict[str, Any],
        version: int,
    ) -> dict[str, Any]:
        normalized = dict(payload)
        text = str(normalized.get("text") or "").strip()
        if not text:
            raise ValueError(f"{path.name} capture payload text must not be empty")
        redacted_text, text_redactions = redact_capture_text(text)
        inherited_redactions = int(normalized.get("redaction_count", 0) or 0)
        raw_metadata = normalized.get("metadata", {})
        safe_metadata, metadata_redactions = self._safe_capture_metadata(
            raw_metadata if isinstance(raw_metadata, dict) else {}
        )
        source_default = "capture-daemon" if version == 2 else path.stem
        source_tag = mlx_backend.sanitize_tag(
            str(
                normalized.get("source_tag")
                or normalized.get("tag")
                or source_default
            )
        ).replace(" ", "-")
        context_id = mlx_backend.sanitize_context_id(
            str(normalized.get("context_id") or "default")
        )
        speaker = mlx_backend.sanitize_agent_id(
            str(normalized.get("speaker") or "capture-daemon")
        )
        try:
            surprise_threshold = float(normalized.get("surprise_threshold", 0.5))
        except (TypeError, ValueError) as exc:
            raise ValueError("surprise_threshold must be a finite number") from exc
        if not math.isfinite(surprise_threshold):
            raise ValueError("surprise_threshold must be a finite number")
        surprise_threshold = min(max(surprise_threshold, 0.0), 1.0)
        raw_min_sentences = normalized.get("min_segment_sentences", 1)
        if isinstance(raw_min_sentences, bool):
            raise ValueError("min_segment_sentences must be an integer")
        try:
            min_segment_sentences = max(1, int(raw_min_sentences))
        except (TypeError, ValueError) as exc:
            raise ValueError("min_segment_sentences must be an integer") from exc
        normalized.update(
            {
                "text": redacted_text,
                "context_id": context_id,
                "source_tag": source_tag,
                "speaker": speaker,
                "surprise_threshold": surprise_threshold,
                "min_segment_sentences": min_segment_sentences,
                "metadata": safe_metadata,
                "redaction_count": int(
                    inherited_redactions + text_redactions + metadata_redactions
                ),
                "raw_text_stored": False,
            }
        )
        for raw_key in list(normalized):
            folded = str(raw_key).strip().casefold().replace("-", "_")
            if (
                folded in UNTRUSTED_RAW_DIGEST_KEYS
                or (folded.startswith("raw_") and "sha" in folded)
            ):
                normalized.pop(raw_key, None)
        return normalized

    def _safe_capture_metadata(
        self,
        metadata: dict[str, Any],
    ) -> tuple[dict[str, Any], int]:
        redacted_value, value_redactions = redact_sensitive_value(metadata)
        stripped_count = 0

        def strip_sensitive_fields(value: Any) -> Any:
            nonlocal stripped_count
            if isinstance(value, dict):
                clean: dict[str, Any] = {}
                for raw_key, item in value.items():
                    key = str(raw_key)
                    folded = key.strip().casefold().replace("-", "_")
                    compact_key = folded.replace("_", "")
                    if (
                        folded in UNTRUSTED_RAW_DIGEST_KEYS
                        or folded in SENSITIVE_METADATA_KEYS
                        or compact_key
                        in {
                            "apikey",
                            "accesstoken",
                            "refreshtoken",
                            "clientsecret",
                            "privatekey",
                        }
                        or (folded.startswith("raw_") and "sha" in folded)
                    ):
                        stripped_count += 1
                        continue
                    clean[key] = strip_sensitive_fields(item)
                return clean
            if isinstance(value, list):
                return [strip_sensitive_fields(item) for item in value]
            return value

        stripped = strip_sensitive_fields(redacted_value)
        try:
            serialized = json.dumps(
                stripped,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("capture metadata must be finite JSON-safe data") from exc
        safe = json.loads(serialized)
        return (
            safe if isinstance(safe, dict) else {},
            int(value_redactions + stripped_count),
        )

    def _persist_legacy_text_payload(
        self,
        *,
        path: Path,
        payload: dict[str, Any],
    ) -> None:
        _atomic_write_private_text(path, str(payload["text"]))
        identity = {key: value for key, value in payload.items() if key != "text"}
        _atomic_write_private_text(
            path.parent / LEGACY_TEXT_IDENTITY_FILE,
            json.dumps(identity, indent=2, sort_keys=True),
        )

    def _persist_payload_document(
        self,
        *,
        path: Path,
        document_kind: str,
        payloads: list[dict[str, Any]],
    ) -> None:
        if document_kind == "json-object":
            text = json.dumps(payloads[0], indent=2, sort_keys=True)
        elif document_kind == "json-list":
            text = json.dumps(payloads, indent=2, sort_keys=True)
        elif document_kind == "jsonl":
            text = "\n".join(
                json.dumps(payload, sort_keys=True, separators=(",", ":"))
                for payload in payloads
            ) + "\n"
        else:
            return
        _atomic_write_private_text(path, text)

    def _read_capture_text(self, path: Path) -> str:
        return self._read_capture_bytes(path).decode("utf-8", errors="replace")

    def _read_capture_bytes(self, path: Path) -> bytes:
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
            chunks: list[bytes] = []
            remaining = opened_stat.st_size
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw_bytes = b"".join(chunks)
        finally:
            os.close(fd)
        return raw_bytes

    def _canonical_capture_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        capture_id = _canonical_capture_id(payload.get("capture_id"))
        text, text_redactions = redact_capture_text(str(payload.get("text") or "").strip())
        if not text:
            raise ValueError("capture payload text must not be empty")
        raw_metadata = payload.get("metadata", {})
        safe_metadata, metadata_redactions = self._safe_capture_metadata(
            raw_metadata if isinstance(raw_metadata, dict) else {}
        )
        inherited_redactions = int(payload.get("redaction_count", 0) or 0)
        redaction_count = int(
            inherited_redactions + text_redactions + metadata_redactions
        )
        return {
            "capture_id": capture_id,
            "text": text,
            "context_id": mlx_backend.sanitize_context_id(
                str(payload.get("context_id") or "default")
            ),
            "source_tag": mlx_backend.sanitize_tag(
                str(payload.get("source_tag") or "capture-daemon")
            ).replace(" ", "-"),
            "speaker": mlx_backend.sanitize_agent_id(
                str(payload.get("speaker") or "capture-daemon")
            ),
            "surprise_threshold": float(payload.get("surprise_threshold", 0.5)),
            "min_segment_sentences": int(payload.get("min_segment_sentences", 1)),
            "metadata": {
                **safe_metadata,
                "capture_daemon": True,
                "capture_id": capture_id,
                "capture_protocol": "capture.v2",
                "redaction_count": redaction_count,
                "raw_text_stored": False,
            },
        }

    def _request_fingerprint(self, request: dict[str, Any]) -> str:
        canonical = json.dumps(
            _json_safe(request, {}),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return _sha256_text(canonical)

    def _capture_payload_exactly_once(
        self,
        *,
        path: Path,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        capture_id = _canonical_capture_id(payload.get("capture_id"))
        request = self._canonical_capture_request(payload)
        request_fingerprint = self._request_fingerprint(request)
        paths = self.paths()
        lock_path = paths["lock_dir"] / f"{capture_id}.lock"
        with self._exclusive_lock(lock_path) as acquired:
            if not acquired:
                raise CaptureDeferred(f"capture {capture_id} is owned by another worker")
            receipt_path = paths["receipt_dir"] / f"{capture_id}.json"
            receipt_replay = False
            if receipt_path.exists():
                try:
                    receipt = self._read_receipt(receipt_path)
                    receipt_replay = bool(
                        receipt["capture_id"] == capture_id
                        and receipt["request_fingerprint"] == request_fingerprint
                    )
                    if not receipt_replay:
                        self._quarantine_transport_receipt(receipt_path)
                except Exception:
                    LOGGER.warning(
                        "quarantining invalid transport receipt %s",
                        receipt_path,
                        exc_info=True,
                    )
                    self._quarantine_transport_receipt(receipt_path)

            # The SQLite capture_operations ledger is authoritative. Even a
            # matching transport receipt must replay through the backend so a
            # restored database cannot silently lose a capture.
            result = self._capture_payload(
                path=path,
                payload=payload,
                request=request,
            )
            try:
                compact_result = self._compact_capture_result(result)
                receipt_payload = {
                    "version": 1,
                    "capture_id": capture_id,
                    "request_fingerprint": request_fingerprint,
                    "committed_at": time.time(),
                    "result": compact_result,
                }
                _atomic_write_private_text(
                    receipt_path,
                    json.dumps(receipt_payload, indent=2, sort_keys=True),
                )
            except Exception as exc:
                raise CaptureCleanupPending(
                    f"capture {capture_id} committed but receipt persistence failed"
                ) from exc
            compact_result["idempotent_replay"] = bool(
                result.get("idempotent_replay")
            )
            compact_result["receipt_replay"] = receipt_replay
            return compact_result

    def _quarantine_transport_receipt(self, receipt_path: Path) -> None:
        if not receipt_path.exists():
            return
        destination = receipt_path.parent / (
            f"stale-{receipt_path.stem}-{int(time.time() * 1000)}-"
            f"{secrets.token_hex(8)}.json"
        )
        try:
            os.replace(receipt_path, destination)
            _fsync_directory(receipt_path.parent)
        except FileNotFoundError:
            return
        except OSError:
            LOGGER.warning(
                "could not quarantine stale transport receipt %s; it will be replaced after ledger verification",
                receipt_path,
                exc_info=True,
            )

    def _read_receipt(self, receipt_path: Path) -> dict[str, Any]:
        try:
            parsed = json.loads(self._read_capture_text(receipt_path))
        except Exception as exc:
            raise ValueError(f"invalid capture receipt {receipt_path.name}") from exc
        if not isinstance(parsed, dict):
            raise ValueError(f"invalid capture receipt {receipt_path.name}")
        capture_id = _canonical_capture_id(parsed.get("capture_id"))
        request_fingerprint = str(parsed.get("request_fingerprint") or "")
        if re.fullmatch(r"[0-9a-f]{64}", request_fingerprint) is None:
            raise ValueError(f"invalid capture receipt digest for {capture_id}")
        result = parsed.get("result")
        if not isinstance(result, dict):
            raise ValueError(f"invalid capture receipt result for {capture_id}")
        return {
            **parsed,
            "capture_id": capture_id,
            "request_fingerprint": request_fingerprint,
            "result": result,
        }

    def _capture_payload(
        self,
        *,
        path: Path,
        payload: dict[str, Any],
        request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        canonical_request = request or self._canonical_capture_request(payload)
        capture_id = _canonical_capture_id(canonical_request.get("capture_id"))
        capture = self.backend.capture_conversation(**canonical_request)
        return {
            "capture_id": capture_id,
            "context_id": capture.get("context_id") or "default",
            "source_tag": capture.get("source_tag") or canonical_request["source_tag"],
            "speaker": capture.get("speaker"),
            "event_count": int(capture.get("event_count") or 0),
            "relationship_count": int(capture.get("relationship_count") or 0),
            "agent_deployment": capture.get("agent_deployment"),
            "redaction_count": int(
                canonical_request["metadata"].get("redaction_count") or 0
            ),
            "idempotent_replay": bool(capture.get("idempotent_replay")),
        }

    def _compact_capture_result(self, result: dict[str, Any]) -> dict[str, Any]:
        deployment = result.get("agent_deployment")
        compact_deployment: dict[str, Any] | None = None
        if isinstance(deployment, dict):
            compact_deployment = {
                key: _json_safe(deployment[key], None)
                for key in (
                    "action",
                    "context_id",
                    "event_id",
                    "event_type",
                    "published_at",
                )
                if key in deployment
            }
        return {
            "capture_id": _canonical_capture_id(result.get("capture_id")),
            "context_id": str(result.get("context_id") or "default"),
            "source_tag": str(result.get("source_tag") or "capture-daemon"),
            "speaker": result.get("speaker"),
            "event_count": int(result.get("event_count") or 0),
            "relationship_count": int(result.get("relationship_count") or 0),
            "agent_deployment": compact_deployment,
            "redaction_count": int(result.get("redaction_count") or 0),
        }

    def _unique_destination(self, destination_dir: Path, name: str) -> Path:
        _ensure_private_dir(destination_dir)
        destination = destination_dir / name
        if not destination.exists():
            return destination
        candidate = Path(name)
        return destination_dir / (
            f"{candidate.stem}-{int(time.time() * 1000)}-"
            f"{secrets.token_hex(8)}{candidate.suffix}"
        )

    def _move_file(self, path: Path, destination_dir: Path) -> Path:
        destination = self._unique_destination(destination_dir, path.name)
        os.replace(path, destination)
        try:
            destination.chmod(0o600)
        except PermissionError:
            LOGGER.warning("could not chmod moved capture file %s", destination)
        _fsync_directory(path.parent)
        _fsync_directory(destination_dir)
        return destination

    def _cleanup_empty_claim(self, claim_dir: Path) -> None:
        for private_name in (".lock", LEGACY_TEXT_IDENTITY_FILE):
            try:
                (claim_dir / private_name).unlink()
            except FileNotFoundError:
                pass
            except OSError:
                return
        try:
            claim_dir.rmdir()
        except FileNotFoundError:
            pass
        except OSError:
            return
        _fsync_directory(claim_dir.parent)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the SYNAPSE-S2 capture inbox daemon.")
    parser.add_argument("--capture-root", default=None)
    parser.add_argument("--state", default=None)
    parser.add_argument("--memory-db", default=None)
    parser.add_argument("--dimension", type=int, default=1024)
    parser.add_argument("--neurons", type=int, default=5400)
    parser.add_argument("--top-k", type=int, default=256)
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

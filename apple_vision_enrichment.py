from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import math
import os
import platform
import re
import secrets
import stat
import struct
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from core_client_binding import CoreClientBinding, validate_core_client_binding
from redaction import redact_capture_text


APPLE_VISION_ENRICHMENT_SCHEMA = "synapse-s2.apple-vision-enrichment.v1"
APPLE_VISION_HELPER_RESULT_SCHEMA = "synapse-s2.apple-vision-helper-result.v1"
APPLE_VISION_FEATURE_PRINT_SCHEMA = "synapse-s2.apple-vision-feature-print.v1"
APPLE_VISION_FEATURE_PRINT_REFERENCE_SCHEMA = (
    "synapse-s2.apple-vision-feature-print-reference.v1"
)
APPLE_VISION_OCR_SCHEMA = "synapse-s2.apple-vision-ocr.v1"
APPLE_VISION_MODES = frozenset({"off", "feature-print", "ocr", "all"})
APPLE_VISION_INPUT_DERIVATIVES = frozenset(
    {
        "source-transient-downsampled",
        "thumbnail-transient-downsampled",
    }
)
MAX_VISION_EDGE = 2_048
MAX_VISION_OUTPUT_BYTES = 128 * 1024
MAX_VISION_SOURCE_BYTES = 20 * 1024 * 1024
MAX_FEATURE_ELEMENTS = 8_192
MAX_OCR_OBSERVATIONS = 128
MAX_OCR_UTF8_BYTES = 8_192
MAX_HELPER_SOURCE_BYTES = 128 * 1024
MAX_HELPER_BINARY_BYTES = 8 * 1024 * 1024
HELPER_BUILD_TIMEOUT_SECONDS = 120.0
HELPER_RUN_TIMEOUT_SECONDS = 30.0

_HELPER_SOURCE = Path(__file__).resolve().parent / "native" / "apple_vision_enrich.swift"
_HELPER_MANIFEST_SCHEMA = "synapse-s2.apple-vision-helper-cache.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_FAILURE_CODES = frozenset(
    {
        "feature-print-request-failed",
        "no-feature-print",
        "ocr-request-failed",
    }
)


class AppleVisionError(RuntimeError):
    """A content-free Apple Vision boundary failure."""


class AppleVisionUnavailable(AppleVisionError):
    """The optional local Vision helper cannot run on this host."""


VisionEnricher = Callable[[Path, str, str], dict[str, Any]]


def validate_vision_mode(value: Any) -> str:
    mode = str(value or "off").strip().lower()
    if mode not in APPLE_VISION_MODES:
        raise ValueError("vision enrichment must be off, feature-print, ocr, or all")
    return mode


def validate_input_derivative(value: Any) -> str:
    derivative = str(value or "").strip()
    if derivative not in APPLE_VISION_INPUT_DERIVATIVES:
        raise ValueError("vision input derivative is invalid")
    return derivative


def _private_directory(path: Path, *, create: bool) -> os.stat_result:
    if create:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
    try:
        observed = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise AppleVisionUnavailable("Apple Vision helper cache is unavailable") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        raise AppleVisionUnavailable("Apple Vision helper cache is unsafe")
    return observed


def _private_regular(
    path: Path,
    *,
    maximum_bytes: int,
    executable: bool = False,
    allow_empty: bool = False,
) -> os.stat_result:
    try:
        observed = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise AppleVisionUnavailable("Apple Vision helper artifact is unavailable") from exc
    expected_mode = 0o700 if executable else 0o600
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) != expected_mode
        or (observed.st_size <= 0 and not allow_empty)
        or observed.st_size > maximum_bytes
    ):
        raise AppleVisionUnavailable("Apple Vision helper artifact is unsafe")
    return observed


def _read_regular(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        observed = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise AppleVisionUnavailable("Apple Vision helper source is unavailable") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_size <= 0
        or observed.st_size > maximum_bytes
    ):
        raise AppleVisionUnavailable("Apple Vision helper source is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise AppleVisionUnavailable("Apple Vision helper source changed during open")
        data = b""
        remaining = int(opened.st_size)
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            data += chunk
            remaining -= len(chunk)
        if len(data) != int(opened.st_size):
            raise AppleVisionUnavailable("Apple Vision helper source changed during read")
        return data
    finally:
        os.close(descriptor)


def _read_private(
    path: Path,
    *,
    maximum_bytes: int,
    executable: bool = False,
) -> bytes:
    observed = _private_regular(
        path,
        maximum_bytes=maximum_bytes,
        executable=executable,
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise AppleVisionUnavailable("Apple Vision helper artifact changed during open")
        data = b""
        remaining = int(opened.st_size)
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            data += chunk
            remaining -= len(chunk)
        if len(data) != int(opened.st_size):
            raise AppleVisionUnavailable("Apple Vision helper artifact changed during read")
        return data
    finally:
        os.close(descriptor)


def _write_private(path: Path, data: bytes, *, executable: bool = False) -> None:
    mode = 0o700 if executable else 0o600
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise AppleVisionUnavailable("Apple Vision helper publication stalled")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_stage(stage: Path) -> None:
    if not stage.exists() or stage.is_symlink():
        return
    for filename in ("helper", "manifest.json"):
        try:
            (stage / filename).unlink()
        except FileNotFoundError:
            pass
    try:
        stage.rmdir()
    except FileNotFoundError:
        pass


def _remove_corrupt_helper_cache(path: Path) -> None:
    """Remove only one derived digest directory while holding the helper lock."""

    try:
        observed = path.lstat()
    except FileNotFoundError:
        return
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        raise AppleVisionUnavailable("Apple Vision helper cache is unsafe")
    allowed = {"helper", "manifest.json"}
    for child in path.iterdir():
        if child.name not in allowed:
            raise AppleVisionUnavailable("Apple Vision helper cache is inconsistent")
        child_stat = child.lstat()
        if (
            stat.S_ISLNK(child_stat.st_mode)
            or not stat.S_ISREG(child_stat.st_mode)
            or child_stat.st_uid != os.getuid()
            or child_stat.st_nlink != 1
        ):
            raise AppleVisionUnavailable("Apple Vision helper cache is unsafe")
        child.unlink()
    path.rmdir()


def _bounded_utf8(value: str, maximum_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return value, False
    return encoded[:maximum_bytes].decode("utf-8", errors="ignore"), True


def _normalize_ocr(value: Any) -> tuple[str, int, bool]:
    if type(value) is not str or "\x00" in value:
        raise AppleVisionError("Apple Vision OCR output is invalid")
    lines = [" ".join(line.split()) for line in value.splitlines()]
    clean = "\n".join(line for line in lines if line)
    clean_bytes = clean.encode("utf-8")
    if len(clean_bytes) > MAX_VISION_OUTPUT_BYTES:
        raise AppleVisionError("Apple Vision OCR output exceeds the safe bound")
    input_truncated = len(clean_bytes) > MAX_OCR_UTF8_BYTES
    redacted, redaction_count = redact_capture_text(clean)
    safe_lines = [" ".join(line.split()) for line in str(redacted or "").splitlines()]
    safe = "\n".join(line for line in safe_lines if line)
    safe, redaction_truncated = _bounded_utf8(safe, MAX_OCR_UTF8_BYTES)
    return safe, int(redaction_count), bool(input_truncated or redaction_truncated)


def _decode_feature_data(value: Any, *, element_type: str, element_count: int) -> bytes:
    if type(value) is not str:
        raise AppleVisionError("Apple Vision feature-print encoding is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise AppleVisionError("Apple Vision feature-print encoding is invalid") from exc
    width = 4 if element_type == "float32" else 8
    if len(decoded) != element_count * width:
        raise AppleVisionError("Apple Vision feature-print shape is invalid")
    format_code = "<f" if element_type == "float32" else "<d"
    if any(not math.isfinite(item[0]) for item in struct.iter_unpack(format_code, decoded)):
        raise AppleVisionError("Apple Vision feature-print values are invalid")
    return decoded


def validate_vision_enrichment(value: Any, *, requested_mode: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AppleVisionError("Apple Vision enrichment output is invalid")
    mode = validate_vision_mode(value.get("mode"))
    if mode == "off" or (requested_mode is not None and mode != validate_vision_mode(requested_mode)):
        raise AppleVisionError("Apple Vision enrichment mode changed")
    expected_fields = {
        "schema",
        "provider",
        "mode",
        "status",
        "input_derivative",
        "input_dimensions",
    }
    if mode in {"feature-print", "all"}:
        expected_fields.add("feature_print")
    if mode in {"ocr", "all"}:
        expected_fields.add("ocr")
    if frozenset(value) != expected_fields:
        raise AppleVisionError("Apple Vision enrichment contract is invalid")
    derivative = validate_input_derivative(value.get("input_derivative"))
    dimensions = value.get("input_dimensions")
    if (
        not isinstance(dimensions, dict)
        or frozenset(dimensions) != {"width", "height"}
        or type(dimensions.get("width")) is not int
        or type(dimensions.get("height")) is not int
        or not 0 < dimensions["width"] <= MAX_VISION_EDGE
        or not 0 < dimensions["height"] <= MAX_VISION_EDGE
        or dimensions["width"] * dimensions["height"] > MAX_VISION_EDGE**2
    ):
        raise AppleVisionError("Apple Vision input dimensions are invalid")
    if (
        value.get("schema") != APPLE_VISION_ENRICHMENT_SCHEMA
        or value.get("provider") != "apple-vision"
        or value.get("status") not in {"ready", "partial", "failed"}
    ):
        raise AppleVisionError("Apple Vision enrichment contract is invalid")

    clean: dict[str, Any] = {
        "schema": APPLE_VISION_ENRICHMENT_SCHEMA,
        "provider": "apple-vision",
        "mode": mode,
        "status": str(value["status"]),
        "input_derivative": derivative,
        "input_dimensions": {
            "width": int(dimensions["width"]),
            "height": int(dimensions["height"]),
        },
    }
    statuses: list[str] = []
    if mode in {"feature-print", "all"}:
        feature = value.get("feature_print")
        if not isinstance(feature, dict) or feature.get("status") not in {"ready", "failed"}:
            raise AppleVisionError("Apple Vision feature-print contract is invalid")
        if feature["status"] == "failed":
            if (
                frozenset(feature) != {"status", "failure_code"}
                or feature.get("failure_code") not in _ALLOWED_FAILURE_CODES
            ):
                raise AppleVisionError("Apple Vision feature-print failure is invalid")
            clean["feature_print"] = dict(feature)
        else:
            expected_feature_fields = {
                "status",
                "schema",
                "request_revision",
                "element_type",
                "element_count",
                "encoding",
                "data",
            }
            element_type = str(feature.get("element_type") or "")
            element_count = feature.get("element_count")
            if (
                frozenset(feature) != expected_feature_fields
                or feature.get("schema") != APPLE_VISION_FEATURE_PRINT_SCHEMA
                or type(feature.get("request_revision")) is not int
                or feature["request_revision"] not in {1, 2}
                or element_type not in {"float32", "float64"}
                or type(element_count) is not int
                or not 0 < element_count <= MAX_FEATURE_ELEMENTS
                or feature.get("encoding") != "base64-little-endian"
            ):
                raise AppleVisionError("Apple Vision feature-print contract is invalid")
            _decode_feature_data(
                feature.get("data"),
                element_type=element_type,
                element_count=element_count,
            )
            clean["feature_print"] = dict(feature)
        statuses.append(str(feature["status"]))

    if mode in {"ocr", "all"}:
        ocr = value.get("ocr")
        if not isinstance(ocr, dict) or ocr.get("status") not in {"ready", "failed"}:
            raise AppleVisionError("Apple Vision OCR contract is invalid")
        if ocr["status"] == "failed":
            if (
                frozenset(ocr) != {"status", "failure_code"}
                or ocr.get("failure_code") not in _ALLOWED_FAILURE_CODES
            ):
                raise AppleVisionError("Apple Vision OCR failure is invalid")
            clean["ocr"] = dict(ocr)
        else:
            expected_ocr_fields = {
                "status",
                "schema",
                "request_revision",
                "recognition_level",
                "language_correction",
                "automatic_language_detection",
                "observation_count",
                "mean_confidence",
                "text",
                "truncated",
            }
            if "redaction_count" in ocr:
                expected_ocr_fields.add("redaction_count")
            confidence = ocr.get("mean_confidence")
            observation_count = ocr.get("observation_count")
            prior_redaction_count = ocr.get("redaction_count", 0)
            if (
                frozenset(ocr) != expected_ocr_fields
                or ocr.get("schema") != APPLE_VISION_OCR_SCHEMA
                or ocr.get("request_revision") != 3
                or ocr.get("recognition_level") != "accurate"
                or ocr.get("language_correction") is not True
                or ocr.get("automatic_language_detection") is not True
                or type(observation_count) is not int
                or not 0 <= observation_count <= MAX_OCR_OBSERVATIONS
                or type(confidence) not in {int, float}
                or not math.isfinite(float(confidence))
                or not 0.0 <= float(confidence) <= 1.0
                or type(ocr.get("truncated")) is not bool
                or type(prior_redaction_count) is not int
                or not 0 <= prior_redaction_count <= 1_000_000
            ):
                raise AppleVisionError("Apple Vision OCR contract is invalid")
            text, redaction_count, redaction_truncated = _normalize_ocr(ocr.get("text"))
            clean["ocr"] = {
                **ocr,
                "mean_confidence": round(float(confidence), 6),
                "text": text,
                "truncated": bool(ocr["truncated"] or redaction_truncated),
                "redaction_count": prior_redaction_count + redaction_count,
            }
        statuses.append(str(ocr["status"]))

    expected_status = (
        "ready"
        if statuses and all(status == "ready" for status in statuses)
        else "partial"
        if "ready" in statuses
        else "failed"
    )
    if clean["status"] != expected_status:
        raise AppleVisionError("Apple Vision enrichment status is inconsistent")
    return json.loads(json.dumps(clean, sort_keys=True, allow_nan=False))


def ocr_cue_text(value: Any) -> str:
    try:
        enrichment = validate_public_vision_enrichment(value)
    except (AppleVisionError, ValueError):
        return ""
    ocr = enrichment.get("ocr")
    if not isinstance(ocr, dict) or ocr.get("status") != "ready":
        return ""
    return str(ocr.get("text") or "").strip()


def privatize_vision_enrichment(
    value: Any,
) -> tuple[dict[str, Any], bytes | None]:
    """Move learned feature bytes out of durable metadata into the private cache."""

    enrichment = validate_vision_enrichment(value)
    projected = json.loads(json.dumps(enrichment, sort_keys=True, allow_nan=False))
    feature_bytes: bytes | None = None
    feature = projected.get("feature_print")
    if isinstance(feature, dict) and feature.get("status") == "ready":
        element_type = str(feature["element_type"])
        element_count = int(feature["element_count"])
        feature_bytes = _decode_feature_data(
            feature.get("data"),
            element_type=element_type,
            element_count=element_count,
        )
        projected["feature_print"] = {
            "status": "ready",
            "schema": APPLE_VISION_FEATURE_PRINT_REFERENCE_SCHEMA,
            "request_revision": int(feature["request_revision"]),
            "element_type": element_type,
            "element_count": element_count,
            "storage": "private-node-local-media-cache",
            "byte_count": len(feature_bytes),
        }
    return validate_public_vision_enrichment(projected), feature_bytes


def validate_public_vision_enrichment(value: Any) -> dict[str, Any]:
    """Validate the durable-safe reference projection (never learned vector bytes)."""

    if not isinstance(value, dict):
        raise AppleVisionError("Apple Vision public enrichment is invalid")
    mode = validate_vision_mode(value.get("mode"))
    if mode == "off":
        raise AppleVisionError("Apple Vision public enrichment mode is invalid")
    expected_fields = {
        "schema",
        "provider",
        "mode",
        "status",
        "input_derivative",
        "input_dimensions",
    }
    if mode in {"feature-print", "all"}:
        expected_fields.add("feature_print")
    if mode in {"ocr", "all"}:
        expected_fields.add("ocr")
    if frozenset(value) != expected_fields:
        raise AppleVisionError("Apple Vision public enrichment contract is invalid")
    derivative = validate_input_derivative(value.get("input_derivative"))
    dimensions = value.get("input_dimensions")
    if (
        value.get("schema") != APPLE_VISION_ENRICHMENT_SCHEMA
        or value.get("provider") != "apple-vision"
        or value.get("status") not in {"ready", "partial", "failed"}
        or not isinstance(dimensions, dict)
        or frozenset(dimensions) != {"width", "height"}
        or type(dimensions.get("width")) is not int
        or type(dimensions.get("height")) is not int
        or not 0 < dimensions["width"] <= MAX_VISION_EDGE
        or not 0 < dimensions["height"] <= MAX_VISION_EDGE
        or dimensions["width"] * dimensions["height"] > MAX_VISION_EDGE**2
    ):
        raise AppleVisionError("Apple Vision public enrichment contract is invalid")
    clean: dict[str, Any] = {
        "schema": APPLE_VISION_ENRICHMENT_SCHEMA,
        "provider": "apple-vision",
        "mode": mode,
        "status": str(value["status"]),
        "input_derivative": derivative,
        "input_dimensions": dict(dimensions),
    }
    statuses: list[str] = []
    if mode in {"feature-print", "all"}:
        feature = value.get("feature_print")
        if not isinstance(feature, dict) or feature.get("status") not in {"ready", "failed"}:
            raise AppleVisionError("Apple Vision public feature-print is invalid")
        if feature["status"] == "failed":
            if (
                frozenset(feature) != {"status", "failure_code"}
                or feature.get("failure_code") not in _ALLOWED_FAILURE_CODES
            ):
                raise AppleVisionError("Apple Vision public feature-print is invalid")
        else:
            if (
                frozenset(feature)
                != {
                    "status",
                    "schema",
                    "request_revision",
                    "element_type",
                    "element_count",
                    "storage",
                    "byte_count",
                }
                or feature.get("schema")
                != APPLE_VISION_FEATURE_PRINT_REFERENCE_SCHEMA
                or feature.get("request_revision") not in {1, 2}
                or feature.get("element_type") not in {"float32", "float64"}
                or type(feature.get("element_count")) is not int
                or not 0 < feature["element_count"] <= MAX_FEATURE_ELEMENTS
                or feature.get("storage") != "private-node-local-media-cache"
                or type(feature.get("byte_count")) is not int
                or feature["byte_count"]
                != feature["element_count"]
                * (4 if feature["element_type"] == "float32" else 8)
            ):
                raise AppleVisionError("Apple Vision public feature-print is invalid")
        clean["feature_print"] = dict(feature)
        statuses.append(str(feature["status"]))
    if mode in {"ocr", "all"}:
        ocr = value.get("ocr")
        ocr_status = str(ocr.get("status") or "failed") if isinstance(ocr, dict) else "failed"
        ocr_document = {
            "schema": APPLE_VISION_ENRICHMENT_SCHEMA,
            "provider": "apple-vision",
            "mode": "ocr",
            "status": ocr_status,
            "input_derivative": derivative,
            "input_dimensions": dict(dimensions),
            "ocr": ocr,
        }
        clean["ocr"] = validate_vision_enrichment(ocr_document)["ocr"]
        statuses.append(ocr_status)
    expected_status = (
        "ready"
        if statuses and all(status == "ready" for status in statuses)
        else "partial"
        if "ready" in statuses
        else "failed"
    )
    if clean["status"] != expected_status:
        raise AppleVisionError("Apple Vision public enrichment status is inconsistent")
    return json.loads(json.dumps(clean, sort_keys=True, allow_nan=False))


class AppleVisionEnricher:
    """Short-lived, opt-in Vision execution bound to the verified data root."""

    def __init__(
        self,
        binding: CoreClientBinding,
        *,
        helper_source: Path | None = None,
        command_runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
    ) -> None:
        try:
            self.binding = validate_core_client_binding(binding.to_wire())
        except Exception as exc:
            raise AppleVisionError("verified core binding is required") from exc
        self.helper_source = helper_source or _HELPER_SOURCE
        self.root = self.binding.data_root / "vision-helper"
        self.lock_path = self.root / ".helper.lock"
        self.command_runner = command_runner or subprocess.run

    def _validate_data_root(self) -> None:
        try:
            observed = self.binding.data_root.lstat()
        except (FileNotFoundError, OSError) as exc:
            raise AppleVisionUnavailable("bound data root is unavailable") from exc
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) & 0o022
        ):
            raise AppleVisionUnavailable("bound data root is unsafe")

    def _prepare_root(self) -> None:
        self._validate_data_root()
        _private_directory(self.root, create=True)
        try:
            descriptor = os.open(
                self.lock_path,
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except OSError as exc:
            raise AppleVisionUnavailable("Apple Vision helper lock is unavailable") from exc
        try:
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        _private_regular(self.lock_path, maximum_bytes=1, allow_empty=True)

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        self._prepare_root()
        descriptor = os.open(
            self.lock_path,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _cached_helper(self, cache_digest: str, source_digest: str) -> Path | None:
        version_root = self.root / cache_digest
        helper = version_root / "helper"
        manifest_path = version_root / "manifest.json"
        try:
            _private_directory(version_root, create=False)
            binary = _read_private(
                helper,
                maximum_bytes=MAX_HELPER_BINARY_BYTES,
                executable=True,
            )
            manifest = json.loads(
                _read_private(manifest_path, maximum_bytes=4_096).decode("utf-8")
            )
        except (
            AppleVisionUnavailable,
            OSError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return None
        if manifest != {
            "schema": _HELPER_MANIFEST_SCHEMA,
            "source_sha256": source_digest,
            "binary_sha256": hashlib.sha256(binary).hexdigest(),
            "platform": "macos",
        }:
            return None
        return helper

    def _compile_helper(self) -> Path:
        if platform.system() != "Darwin":
            raise AppleVisionUnavailable("Apple Vision enrichment is unavailable on this host")
        source = _read_regular(self.helper_source, maximum_bytes=MAX_HELPER_SOURCE_BYTES)
        source_digest = hashlib.sha256(source).hexdigest()
        cache_digest = hashlib.sha256(
            (_HELPER_MANIFEST_SCHEMA + "\x00").encode("utf-8") + source
        ).hexdigest()
        if (
            _SHA256_RE.fullmatch(source_digest) is None
            or _SHA256_RE.fullmatch(cache_digest) is None
        ):
            raise AppleVisionUnavailable("Apple Vision helper identity is invalid")
        self._prepare_root()
        cached = self._cached_helper(cache_digest, source_digest)
        if cached is not None:
            return cached
        if not Path("/usr/bin/xcrun").is_file():
            raise AppleVisionUnavailable(
                "Apple Vision enrichment needs local Apple developer tools for first use"
            )
        with self._exclusive_lock():
            cached = self._cached_helper(cache_digest, source_digest)
            if cached is not None:
                return cached
            with tempfile.TemporaryDirectory(
                prefix=".vision-build-",
                dir=str(self.binding.data_root),
            ) as work_name:
                work_root = Path(work_name)
                os.chmod(work_root, 0o700)
                binary_path = work_root / "helper"
                copied_source = work_root / "helper.swift"
                _write_private(copied_source, source)
                module_cache = work_root / "module-cache"
                module_cache.mkdir(mode=0o700)
                try:
                    completed = self.command_runner(
                        [
                            "/usr/bin/xcrun",
                            "--sdk",
                            "macosx",
                            "swiftc",
                            "-O",
                            "-module-cache-path",
                            str(module_cache),
                            "-framework",
                            "Vision",
                            "-framework",
                            "ImageIO",
                            "-framework",
                            "CoreGraphics",
                            str(copied_source),
                            "-o",
                            str(binary_path),
                        ],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=HELPER_BUILD_TIMEOUT_SECONDS,
                        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise AppleVisionUnavailable("Apple Vision helper build is unavailable") from exc
                if completed.returncode != 0:
                    raise AppleVisionUnavailable("Apple Vision helper build failed")
                try:
                    observed = binary_path.lstat()
                except (FileNotFoundError, OSError) as exc:
                    raise AppleVisionUnavailable("Apple Vision helper build produced no binary") from exc
                if (
                    stat.S_ISLNK(observed.st_mode)
                    or not stat.S_ISREG(observed.st_mode)
                    or observed.st_size <= 0
                    or observed.st_size > MAX_HELPER_BINARY_BYTES
                ):
                    raise AppleVisionUnavailable("Apple Vision helper build output is unsafe")
                binary = binary_path.read_bytes()
                if binary[:4] not in {
                    b"\xcf\xfa\xed\xfe",
                    b"\xfe\xed\xfa\xcf",
                    b"\xca\xfe\xba\xbe",
                    b"\xbe\xba\xfe\xca",
                }:
                    raise AppleVisionUnavailable("Apple Vision helper build output is invalid")
            stage = Path(
                tempfile.mkdtemp(prefix=f".stage-{cache_digest}-", dir=str(self.root))
            )
            os.chmod(stage, 0o700)
            published = False
            try:
                _write_private(stage / "helper", binary, executable=True)
                manifest = {
                    "schema": _HELPER_MANIFEST_SCHEMA,
                    "source_sha256": source_digest,
                    "binary_sha256": hashlib.sha256(binary).hexdigest(),
                    "platform": "macos",
                }
                _write_private(
                    stage / "manifest.json",
                    (json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8"),
                )
                _fsync_directory(stage)
                destination = self.root / cache_digest
                if destination.exists() or destination.is_symlink():
                    cached = self._cached_helper(cache_digest, source_digest)
                    if cached is not None:
                        return cached
                    _remove_corrupt_helper_cache(destination)
                os.rename(stage, destination)
                _fsync_directory(self.root)
                published = True
                return destination / "helper"
            finally:
                if not published:
                    _remove_stage(stage)

    @staticmethod
    def _source_is_bounded(path: Path) -> None:
        if not path.is_absolute() or "\x00" in str(path):
            raise AppleVisionError("Apple Vision input path is invalid")
        try:
            observed = path.lstat()
        except (FileNotFoundError, OSError) as exc:
            raise AppleVisionError("Apple Vision input is unavailable") from exc
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or observed.st_size <= 0
            or observed.st_size > MAX_VISION_SOURCE_BYTES
        ):
            raise AppleVisionError("Apple Vision input is unsafe")

    def enrich(
        self,
        source_path: Path,
        mode: str,
        input_derivative: str,
    ) -> dict[str, Any]:
        canonical_mode = validate_vision_mode(mode)
        if canonical_mode == "off":
            raise ValueError("Apple Vision enrichment mode must be enabled")
        derivative = validate_input_derivative(input_derivative)
        source = Path(source_path)
        self._source_is_bounded(source)
        helper = self._compile_helper()
        try:
            completed = self.command_runner(
                [
                    str(helper),
                    "--input",
                    str(source),
                    "--mode",
                    canonical_mode,
                    "--max-edge",
                    str(MAX_VISION_EDGE),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=HELPER_RUN_TIMEOUT_SECONDS,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AppleVisionError("Apple Vision enrichment failed") from exc
        output = bytes(completed.stdout or b"")
        if completed.returncode != 0 or not output or len(output) > MAX_VISION_OUTPUT_BYTES:
            raise AppleVisionError("Apple Vision enrichment failed")
        try:
            raw = json.loads(output.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AppleVisionError("Apple Vision enrichment output is invalid") from exc
        if not isinstance(raw, dict) or raw.get("schema") != APPLE_VISION_HELPER_RESULT_SCHEMA:
            raise AppleVisionError("Apple Vision enrichment output is invalid")
        raw = dict(raw)
        raw["schema"] = APPLE_VISION_ENRICHMENT_SCHEMA
        raw["input_derivative"] = derivative
        return validate_vision_enrichment(raw, requested_mode=canonical_mode)


def optional_enrichment_status(
    *,
    mode: str,
    input_derivative: str,
    status: str,
    failure_code: str,
) -> dict[str, Any]:
    """Content-free receipt for a non-required enrichment that could not run."""

    canonical_mode = validate_vision_mode(mode)
    if canonical_mode == "off":
        raise ValueError("Apple Vision enrichment mode must be enabled")
    derivative = validate_input_derivative(input_derivative)
    if status not in {"unavailable", "failed"}:
        raise ValueError("optional enrichment status is invalid")
    if failure_code not in {"helper-unavailable", "enrichment-failed"}:
        raise ValueError("optional enrichment failure code is invalid")
    return validate_optional_enrichment_status(
        {
            "schema": APPLE_VISION_ENRICHMENT_SCHEMA,
            "provider": "apple-vision",
            "mode": canonical_mode,
            "status": status,
            "input_derivative": derivative,
            "failure_code": failure_code,
            "persisted": False,
        }
    )


def validate_optional_enrichment_status(value: Any) -> dict[str, Any]:
    """Validate a content-free receipt for optional enrichment failure."""

    if not isinstance(value, dict) or frozenset(value) != {
        "schema",
        "provider",
        "mode",
        "status",
        "input_derivative",
        "failure_code",
        "persisted",
    }:
        raise AppleVisionError("optional Apple Vision receipt is invalid")
    mode = validate_vision_mode(value.get("mode"))
    if (
        mode == "off"
        or value.get("schema") != APPLE_VISION_ENRICHMENT_SCHEMA
        or value.get("provider") != "apple-vision"
        or value.get("status") not in {"unavailable", "failed"}
        or value.get("failure_code")
        not in {"helper-unavailable", "enrichment-failed"}
        or value.get("persisted") is not False
    ):
        raise AppleVisionError("optional Apple Vision receipt is invalid")
    derivative = validate_input_derivative(value.get("input_derivative"))
    return {
        "schema": APPLE_VISION_ENRICHMENT_SCHEMA,
        "provider": "apple-vision",
        "mode": mode,
        "status": str(value["status"]),
        "input_derivative": derivative,
        "failure_code": str(value["failure_code"]),
        "persisted": False,
    }


__all__ = [
    "APPLE_VISION_ENRICHMENT_SCHEMA",
    "APPLE_VISION_MODES",
    "AppleVisionEnricher",
    "AppleVisionError",
    "AppleVisionUnavailable",
    "VisionEnricher",
    "ocr_cue_text",
    "optional_enrichment_status",
    "privatize_vision_enrichment",
    "validate_input_derivative",
    "validate_optional_enrichment_status",
    "validate_public_vision_enrichment",
    "validate_vision_enrichment",
    "validate_vision_mode",
]

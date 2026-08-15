"""SYNAPSE-S2 memory backend for the official LongMemEval-V2 harness.

Implements the pinned official ``Memory`` contract with ``memory_type``
``synapse_s2``:

* ``insert(trajectory)`` streams one official trajectory (public ``states``
  shape or legacy ``content`` shape) state-by-state into a **disposable**
  SYNAPSE-S2 store under an explicit benchmark namespace with stable,
  deterministic memory identities and idempotent re-insertion.  The stored
  text and the idempotency fingerprint are both derived from the redacted,
  byte-bounded logical payload plus normalized non-path identifiers — never
  from raw text, credential material, screenshot paths, or raw-content
  digests.
* The store's runtime (SQLite, unix socket, media cache) always lives in a
  short, freshly created private ``/private/tmp`` root that is independent of
  the harness workspace, so long or space-containing artifact paths can never
  break the socket path bound.  Every configured root is rejected if any
  component is a symlink or if it overlaps a live SYNAPSE-S2 store.
* ``query(query, query_image=None)`` returns official
  ``{"type": "text"|"image", "value": ...}`` context items; image values are
  existing bounded thumbnail derivative files produced by the SYNAPSE image
  capture path (raw originals are never retained).  When a query image is
  supplied, an owner-private scratch copy is compared transiently against the
  exact authoritative media references in this adapter namespace.  Apple
  Vision feature bytes stay inside the private node-local cache boundary and
  the query scratch is removed in ``finally``; unavailable/incompatible Vision
  degrades honestly to text retrieval rather than manufacturing a durable
  query image.
* ``save_memory``/``_load_backend`` produce and verify a sealed, portable
  benchmark artifact (logical store + media derivatives + the exact referenced
  private media-cache objects needed for transient image similarity + insert
  ledger + digest manifest + executable source manifest + persisted public
  memory config).  Loading performs an exact lstat tree verification (no symlinks,
  devices, hardlinks, or unlisted entries; exact modes and owner), validates
  the SQLite payload (quick/integrity/schema/namespace), and binds every
  ledger row to its exact store row (memory id, tag, state index,
  fingerprint, ordinal timestamp, media id), so a re-signed but internally
  inconsistent ledger fails closed.

The persisted ``memory_config.json`` carries only fixed-schema public fields
(``store_namespace``/``backend``/``retrieval``/``image``/``insert``): no
workspace, runtime, or trajectory absolute paths and no arbitrary provenance.

Nothing here claims an official score; scoring is delegated entirely to the
official harness, reader, and judge.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable, Iterator

from memory_modules.memory import (  # the pinned official contract module
    Memory,
    MemoryContextItem,
    register_memory,
    require,
)

from official_longmem import ADAPTER_VERSION
from official_longmem import bootstrap as _bootstrap
from redaction import redact_capture_text

MEMORY_TYPE = "synapse_s2"
ARTIFACT_SCHEMA = "synapse-s2.longmem-v2-official-memory-artifact.v3"
ARTIFACT_VERSION = 3
FINGERPRINT_SCHEMA = "synapse-s2.longmem-v2-insert-fingerprint.v2"
SOURCE_BUILD_SCHEMA = "synapse-s2.longmem-v2-executable-source-build.v1"
MANIFEST_NAME = "artifact_manifest.json"
MEMORY_CONFIG_NAME = "memory_config.json"
LEDGER_NAME = "insert_ledger.json"
STORE_DIR_NAME = "synapse_store"
STORE_FILE_RELATIVE = f"{STORE_DIR_NAME}/memory.sqlite3"
DERIVATIVES_DIR_NAME = "derivatives"
MEDIA_CACHE_DIR_NAME = "media-cache"
MEDIA_CACHE_OBJECTS_RELATIVE = f"{MEDIA_CACHE_DIR_NAME}/objects"
BENCHMARK_NAMESPACE_DEFAULT = "longmem-v2-official"
FIXED_EPOCH = 1_700_000_000.0

# Fixed adapter-side resource bounds (fail closed; not configurable upward).
MAX_TRAJECTORIES = 16_384
MAX_STATES_PER_TRAJECTORY = 8_192
MAX_STATE_TEXT_BYTES_CEILING = 16_384
MAX_QUERY_BYTES = 4_096
MAX_SCREENSHOT_SOURCE_BYTES = 33_554_432
MAX_THUMBNAIL_FILE_BYTES = 1_048_576
MAX_MEDIA_CACHE_THUMBNAIL_BYTES = 512 * 1024
MAX_MEDIA_CACHE_FEATURE_PRINT_BYTES = 64 * 1024
MAX_MEDIA_CACHE_MANIFEST_BYTES = 64 * 1024
MAX_MEDIA_CACHE_OBJECTS = 10_000
MAX_LEDGER_FILE_BYTES = 67_108_864
MAX_MANIFEST_FILE_BYTES = 16_777_216
MAX_MEMORY_CONFIG_FILE_BYTES = 65_536
MAX_STORE_FILE_BYTES = 1 << 32
MAX_SOURCE_FILE_BYTES = 8_388_608
MAX_RESULT_LIMIT = 256
MAX_CANDIDATE_LIMIT = 4_096
MAX_TEXT_ITEM_BYTES_CEILING = 16_384
MAX_TRAJECTORY_ID_CHARS = 200
MAX_MEMORY_ID_CHARS = 200
MAX_URL_METADATA_BYTES = 512
MAX_SANITIZE_INPUT_CHARS = 1_048_576
MAX_SQLITE_SCHEMA_OBJECTS = 4_096
QUERY_IMAGE_RESULT_LIMIT_CEILING = 50
QUERY_IMAGE_CANDIDATE_LIMIT_CEILING = 512
QUERY_IMAGE_TIME_BUDGET_SECONDS = 2.0
QUERY_IMAGE_INPUT_DERIVATIVE = "source-transient-downsampled"
QUERY_IMAGE_META_SCHEMA = "synapse-s2.longmem-v2-query-image.v1"

_STREAM_CHUNK_BYTES = 1 << 20
_HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ANY_HEX64_PATTERN = re.compile(r"^[0-9A-Fa-f]{64}$")
_MEDIA_ID_PATTERN = re.compile(r"^s2img_[0-9a-f]{32}$")
_RELATIVE_FILE_PATTERN = re.compile(r"^(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$")
_SQL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_]+$")
_CONTEXT_COLUMNS = frozenset({"context_id", "source_context_id", "target_context_id"})

# Injectable seam so tests can exercise the complete-write loop with a
# partial writer; production always uses os.write.
_OS_WRITE = os.write

ARTIFACT_NOTES = (
    "sealed portable LongMemEval-V2 benchmark artifact: logical store, bounded "
    "media derivatives, exact referenced private media-cache objects, and insert "
    "ledger only; raw originals and unreferenced cache objects are excluded, "
    "neural runtime state is derived and machine-local, and no authority or "
    "binding credential is ever copied"
)

# Executable sources bound into (and verified against) every sealed artifact.
EXECUTABLE_SOURCE_MODULES = (
    "memory_modules.memory",
    "evaluation.harness",
    "official_longmem",
    "official_longmem.bootstrap",
    "official_longmem.synapse_s2_memory",
    "longmem_eval",
    "mlx_backend",
    "memory_store",
    "bridge_governance",
    "cortex_contract",
    "core_authority",
    "core_client_binding",
    "core_protocol",
    "core_request_journal",
    "core_runtime_paths",
    "core_path_policy",
    "event_segmenter",
    "harmonic_memory",
    "image_capture",
    "media_similarity",
    "redaction",
    "retrieval_cursor",
    "embedding_providers",
    "apple_vision_enrichment",
)
EXECUTABLE_BUILD_FILES = (
    "native/apple_vision_enrich.swift",
    "pyproject.toml",
    "uv.lock",
)

_DEFAULT_BACKEND = {
    "dimension": 256,
    "num_neurons": 2048,
    "default_top_k": 32,
    "recall_count": 64,
    "embedding_provider": "semantic-hash",
}
_DEFAULT_RETRIEVAL = {
    "result_limit": 8,
    "candidate_limit": 256,
    "include_graph_neighbors": True,
    "max_text_item_bytes": 2048,
}
_DEFAULT_IMAGE = {
    "vision_mode": "off",
    "max_source_bytes": MAX_SCREENSHOT_SOURCE_BYTES,
    "max_thumbnail_bytes": MAX_THUMBNAIL_FILE_BYTES,
}
_DEFAULT_INSERT = {
    "max_state_text_bytes": 8192,
}
PUBLIC_PARAM_KEYS = ("store_namespace", "backend", "retrieval", "image", "insert")
EXPECTED_MANIFEST_SHA256_PARAM = "expected_artifact_manifest_sha256"
RELEASE_AFTER_QUERY_PARAM = "release_after_query"
RUNTIME_ONLY_PARAM_KEYS = frozenset(
    {EXPECTED_MANIFEST_SHA256_PARAM, RELEASE_AFTER_QUERY_PARAM}
)
_ALLOWED_TOP_KEYS = frozenset(
    {
        "workspace_dir",
        "store_namespace",
        "trajectories_root_dir",
        "backend",
        "retrieval",
        "image",
        "insert",
        EXPECTED_MANIFEST_SHA256_PARAM,
        RELEASE_AFTER_QUERY_PARAM,
    }
)
_LEDGER_KEYS = frozenset({"next_ordinal", "trajectories"})
_LEDGER_RECORD_KEYS = frozenset(
    {"fingerprint", "state_count", "ordinal_start", "memory_ids", "media"}
)
_LEDGER_MEDIA_KEYS = frozenset(
    {
        "media_id",
        "state_index",
        "thumbnail_sha256",
        "thumbnail_bytes",
        "media_object_sha256",
    }
)
_MANIFEST_KEYS = frozenset(
    {
        "schema",
        "artifact_version",
        "memory_type",
        "adapter_version",
        "official_commit_pin",
        "memory_config",
        "trajectory_count",
        "media_count",
        "next_ordinal",
        "files",
        "source_manifest",
        "source_build_id",
        "credentials_included",
        "official_score_claimed",
        "notes",
    }
)
_SOURCE_MANIFEST_ENTRY_KEYS = frozenset({"sha256", "bytes", "file"})
_STORE_METADATA_KEYS = frozenset(
    {
        "display_label",
        "display_summary",
        "display_excerpt",
        "memory_type",
        "source",
        "embedding_provider",
        "trajectory_id",
        "state_index",
        "state_url",
        "trajectory_binding",
        "adapter_version",
        "benchmark_namespace",
        "text_truncated",
    }
)


def executable_source_manifest() -> dict[str, dict[str, Any]]:
    """Streamed digests of every executable source module in the fixed set.

    Module files are located via ``find_spec`` (no execution) so optional
    heavy modules are bound without being imported.
    """

    manifest: dict[str, dict[str, Any]] = {}
    for name in EXECUTABLE_SOURCE_MODULES:
        try:
            spec = importlib.util.find_spec(name)
        except (ImportError, ValueError) as exc:
            raise RuntimeError(f"executable source module unresolvable: {name}") from exc
        require(
            spec is not None and isinstance(spec.origin, str) and spec.origin,
            f"executable source module missing: {name}",
        )
        assert spec is not None and spec.origin is not None
        source_path = _bootstrap.require_no_symlink_components(
            Path(spec.origin), owner=f"executable source {name}"
        )
        digest, size = _stream_regular_file(
            source_path,
            owner=f"executable source {name}",
            maximum_bytes=MAX_SOURCE_FILE_BYTES,
        )
        manifest[name] = {
            "sha256": digest,
            "bytes": size,
            "file": source_path.name,
        }
    source_root = Path(__file__).resolve().parents[1]
    for relative in EXECUTABLE_BUILD_FILES:
        source_path = _bootstrap.require_no_symlink_components(
            source_root / relative, owner=f"executable build source {relative}"
        )
        digest, size = _stream_regular_file(
            source_path,
            owner=f"executable build source {relative}",
            maximum_bytes=MAX_SOURCE_FILE_BYTES,
        )
        manifest[f"build:{relative}"] = {
            "sha256": digest,
            "bytes": size,
            "file": relative,
        }
    return manifest


def executable_source_build_id(
    source_manifest: dict[str, dict[str, Any]] | None = None,
) -> str:
    """Bind the complete logical source inventory without persisting paths."""

    manifest = executable_source_manifest() if source_manifest is None else source_manifest
    return "source-" + _sha256_hex(
        _canonical_json_bytes({"schema": SOURCE_BUILD_SCHEMA, "files": manifest})
    )


def _synapse() -> dict[str, Any]:
    """Load the SYNAPSE-S2 runtime modules lazily.

    Registration of the memory type must never require native runtime
    dependencies; they are needed only once a memory instance is built.
    """

    return {
        "longmem_eval": importlib.import_module("longmem_eval"),
        "mlx_backend": importlib.import_module("mlx_backend"),
        "core_client_binding": importlib.import_module("core_client_binding"),
        "image_capture": importlib.import_module("image_capture"),
        "media_similarity": importlib.import_module("media_similarity"),
    }


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _open_regular_readonly(path: Path, *, owner: str) -> int:
    # O_NONBLOCK must be present on the *initial* nofollow open.  Checking the
    # file type only after a blocking open can hang forever on a FIFO and may
    # have device-specific side effects.  Regular-file reads are unaffected.
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{owner} must be an existing local regular file") from exc


def _stream_regular_file(
    path: Path,
    *,
    owner: str,
    maximum_bytes: int,
    sink: Callable[[bytes], None] | None = None,
) -> tuple[str, int]:
    """Bounded fd-streaming digest (and optional copy sink) of a regular file.

    Never materializes the whole file in memory: reads fixed-size chunks
    through an O_NOFOLLOW descriptor with an fstat identity recheck.
    """

    fd = _open_regular_readonly(path, owner=owner)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), f"{owner} must be a regular file")
        require(
            before.st_size <= maximum_bytes,
            f"{owner} exceeds the fixed byte bound",
        )
        digest = hashlib.sha256()
        total = 0
        while True:
            try:
                chunk = os.read(fd, _STREAM_CHUNK_BYTES)
            except OSError as exc:
                raise RuntimeError(f"{owner} could not be read") from exc
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            require(total <= maximum_bytes, f"{owner} exceeds the fixed byte bound")
            if sink is not None:
                sink(chunk)
        after = os.fstat(fd)
        require(
            total == before.st_size
            and (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
            f"{owner} changed while being read",
        )
        return digest.hexdigest(), total
    finally:
        os.close(fd)


def _read_regular_file_bytes(path: Path, *, owner: str, maximum_bytes: int) -> bytes:
    """Bounded whole-content read for small control files (never the store)."""

    chunks: list[bytes] = []
    _stream_regular_file(
        path, owner=owner, maximum_bytes=maximum_bytes, sink=chunks.append
    )
    return b"".join(chunks)


def _complete_write(fd: int, data: bytes) -> None:
    """Write every byte, looping over short writes."""

    view = memoryview(data)
    while len(view) > 0:
        written = _OS_WRITE(fd, view)
        require(
            isinstance(written, int) and written > 0,
            "write could not make progress",
        )
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            _complete_write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    _fsync_directory(path.parent)


def _stream_copy_private(
    source: Path,
    target: Path,
    *,
    owner: str,
    maximum_bytes: int,
) -> dict[str, Any]:
    """fd-streaming private copy with complete-write loop, fsync, and digest."""

    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target.parent, 0o700)
    temporary = target.with_name(target.name + ".tmp")
    try:
        out_fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            digest, size = _stream_regular_file(
                source,
                owner=owner,
                maximum_bytes=maximum_bytes,
                sink=lambda chunk: _complete_write(out_fd, chunk),
            )
            os.fsync(out_fd)
        finally:
            os.close(out_fd)
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    _fsync_directory(target.parent)
    return {"sha256": digest, "bytes": size}


def _require_owner_private_directory(path: Path, *, owner: str) -> None:
    """Require one existing, non-symlink, current-owner 0700 directory."""

    try:
        observed = os.lstat(path)
    except OSError as exc:
        raise RuntimeError(f"{owner} is unavailable") from exc
    require(stat.S_ISDIR(observed.st_mode), f"{owner} must be a directory")
    require(
        observed.st_uid == os.getuid() and stat.S_IMODE(observed.st_mode) == 0o700,
        f"{owner} must be a current-owner 0700 directory",
    )


def _active_run_root(*, owner: str) -> Any:
    run_root = _bootstrap.active_run_root()
    require(
        run_root is not None,
        f"{owner} requires the wrapper-created disposable run contract",
    )
    assert run_root is not None
    _require_owner_private_directory(run_root.base, owner="disposable run root")
    return run_root


def _create_private_directory(path: Path, *, owner: str) -> tuple[Path, Path]:
    """Create a fresh private directory strictly inside the active run root.

    Missing parents are created one component at a time with exact 0700 mode;
    existing components must already be owner-private.  The returned second
    value is the verified cleanup root for :func:`remove_tree_checked`.
    """

    run_root = _active_run_root(owner=owner)
    try:
        candidate = _bootstrap.require_within_active_run_root(path, owner=owner)
    except _bootstrap.BootstrapError as exc:
        raise RuntimeError(f"{owner} failed disposable path validation") from exc
    require(candidate != run_root.base, f"{owner} must be below the disposable run root")
    require(not os.path.lexists(candidate), f"{owner} must be fresh")

    missing: list[Path] = []
    current = candidate
    while not os.path.lexists(current):
        missing.append(current)
        current = current.parent
    require(
        current == run_root.base or current.is_relative_to(run_root.base),
        f"{owner} parent escapes the disposable run root",
    )
    node = current
    while True:
        _require_owner_private_directory(node, owner=f"{owner} parent")
        if node == run_root.base:
            break
        node = node.parent

    first_created: Path | None = None
    try:
        for node in reversed(missing):
            os.mkdir(node, mode=0o700)
            os.chmod(node, 0o700)
            _require_owner_private_directory(node, owner=owner)
            if first_created is None:
                first_created = node
    except BaseException:
        if first_created is not None and os.path.lexists(first_created):
            _bootstrap.remove_tree_checked(
                first_created,
                owner=f"{owner} failed creation",
                safe_root=run_root.base,
            )
        raise
    return candidate, run_root.base


def _mkdtemp_private(*, parent: Path, prefix: str, owner: str) -> tuple[Path, Path]:
    run_root = _active_run_root(owner=owner)
    try:
        parent = _bootstrap.require_within_active_run_root(parent, owner=f"{owner} parent")
    except _bootstrap.BootstrapError as exc:
        raise RuntimeError(f"{owner} parent failed disposable path validation") from exc
    _require_owner_private_directory(parent, owner=f"{owner} parent")
    candidate = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    try:
        os.chmod(candidate, 0o700)
        _bootstrap.require_within_active_run_root(candidate, owner=owner)
        _require_owner_private_directory(candidate, owner=owner)
    except BaseException:
        _bootstrap.remove_tree_checked(
            candidate, owner=f"{owner} failed creation", safe_root=run_root.base
        )
        raise
    return candidate, run_root.base


def _remove_disposable_tree(path: Path, *, safe_root: Path, owner: str) -> None:
    _bootstrap.remove_tree_checked(path, owner=owner, safe_root=safe_root)


def _require_int(value: Any, *, field: str, minimum: int, maximum: int) -> int:
    require(
        type(value) is int and minimum <= value <= maximum,
        f"memory_params {field} must be an integer in [{minimum}, {maximum}]",
    )
    return int(value)


def _artifact_file_limit(relative: str) -> int:
    if relative == MEMORY_CONFIG_NAME:
        return MAX_MEMORY_CONFIG_FILE_BYTES
    if relative == LEDGER_NAME:
        return MAX_LEDGER_FILE_BYTES
    if relative == STORE_FILE_RELATIVE:
        return MAX_STORE_FILE_BYTES
    if relative.startswith(f"{DERIVATIVES_DIR_NAME}/") and relative.endswith(".jpg"):
        return MAX_THUMBNAIL_FILE_BYTES
    media_match = re.fullmatch(
        rf"{re.escape(MEDIA_CACHE_OBJECTS_RELATIVE)}/"
        rf"{_MEDIA_ID_PATTERN.pattern[1:-1]}/"
        r"(manifest\.json|thumbnail\.jpg|feature-print\.bin)",
        relative,
    )
    if media_match is not None:
        filename = media_match.group(1)
        if filename == "manifest.json":
            return MAX_MEDIA_CACHE_MANIFEST_BYTES
        if filename == "thumbnail.jpg":
            return MAX_MEDIA_CACHE_THUMBNAIL_BYTES
        return MAX_MEDIA_CACHE_FEATURE_PRINT_BYTES
    return 0


def _media_cache_relative(media_id: str, filename: str) -> str:
    require(
        _MEDIA_ID_PATTERN.fullmatch(media_id) is not None,
        "media cache object id is invalid",
    )
    require(
        filename in {"manifest.json", "thumbnail.jpg", "feature-print.bin"},
        "media cache object filename is invalid",
    )
    return f"{MEDIA_CACHE_OBJECTS_RELATIVE}/{media_id}/{filename}"


def _media_object_binding_sha256(
    media_id: str,
    artifacts: dict[str, bytes],
) -> str:
    """Bind the exact validated private object bytes without exposing them."""

    require(
        _MEDIA_ID_PATTERN.fullmatch(media_id) is not None,
        "media cache object id is invalid",
    )
    require(
        set(artifacts) in (
            {"manifest.json", "thumbnail.jpg"},
            {"feature-print.bin", "manifest.json", "thumbnail.jpg"},
        )
        and all(isinstance(value, bytes) and value for value in artifacts.values()),
        "media cache object inventory is invalid",
    )
    inventory = {
        filename: {
            "sha256": _sha256_hex(artifacts[filename]),
            "bytes": len(artifacts[filename]),
        }
        for filename in sorted(artifacts)
    }
    return _sha256_hex(
        _canonical_json_bytes(
            {
                "schema": "synapse-s2.longmem-v2-media-object-binding.v1",
                "media_id": media_id,
                "files": inventory,
            }
        )
    )


def _require_media_object_binding(
    *,
    manifest: dict[str, Any],
    artifacts: dict[str, bytes],
    media: dict[str, Any],
) -> str:
    """Bind a MediaObjectReader-validated object to its ledger projection."""

    media_id = str(media.get("media_id") or "")
    thumbnail = artifacts.get("thumbnail.jpg")
    public_metadata = manifest.get("public_metadata")
    require(
        isinstance(thumbnail, bytes)
        and manifest.get("media_id") == media_id
        and manifest.get("thumbnail_sha256") == media.get("thumbnail_sha256")
        and manifest.get("thumbnail_size_bytes") == media.get("thumbnail_bytes")
        and len(thumbnail) == media.get("thumbnail_bytes")
        and secrets.compare_digest(
            _sha256_hex(thumbnail), str(media.get("thumbnail_sha256") or "")
        )
        and isinstance(public_metadata, dict)
        and public_metadata.get("media_id") == media_id
        and public_metadata.get("context_memory_type") == "image",
        "media cache object does not bind to the sealed ledger",
    )
    if "feature-print.bin" in artifacts:
        enrichment = public_metadata.get("vision_enrichment")
        feature = enrichment.get("feature_print") if isinstance(enrichment, dict) else None
        require(
            isinstance(enrichment, dict)
            and enrichment.get("status") == "ready"
            and enrichment.get("input_derivative") == QUERY_IMAGE_INPUT_DERIVATIVE
            and isinstance(feature, dict)
            and feature.get("status") == "ready",
            "media cache feature print is not compatible with transient query input",
        )
    binding = _media_object_binding_sha256(media_id, artifacts)
    require(
        secrets.compare_digest(
            binding, str(media.get("media_object_sha256") or "")
        ),
        "media cache object bytes do not bind to the sealed ledger",
    )
    return binding


def _require_identity(value: Any, *, field: str) -> str:
    require(isinstance(value, str) and value.strip(), f"memory_params {field} is required")
    clean = str(value).strip()
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
    require(
        len(clean) <= 120 and all(char in allowed for char in clean),
        f"memory_params {field} must be a bounded public identifier",
    )
    _redacted, redaction_hits = redact_capture_text(clean)
    require(
        redaction_hits == 0,
        f"memory_params {field} must not contain credential material",
    )
    return clean


def _normalize_trajectory_id(value: Any) -> str:
    """Normalized non-path, non-credential trajectory identifier."""

    require(
        isinstance(value, str) and value.strip(),
        "trajectory must carry a non-empty id",
    )
    clean = str(value).strip()
    require(
        len(clean) <= MAX_TRAJECTORY_ID_CHARS,
        "trajectory id exceeds the fixed length bound",
    )
    require(
        all(char.isprintable() for char in clean),
        "trajectory id must not contain control characters",
    )
    require(
        "/" not in clean and "\\" not in clean and clean not in {".", ".."},
        "trajectory id must be a normalized non-path identifier",
    )
    _, redaction_hits = redact_capture_text(clean)
    require(redaction_hits == 0, "trajectory id must not contain credential material")
    return clean


def _merged_section(
    params: dict[str, Any],
    key: str,
    defaults: dict[str, Any],
) -> dict[str, Any]:
    section = params.get(key, {})
    require(isinstance(section, dict), f"memory_params {key} must be an object")
    unknown = set(section) - set(defaults)
    require(not unknown, f"memory_params {key} has unknown keys: {sorted(unknown)}")
    return {**defaults, **section}


def _iter_states(trajectory: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield normalized states for both official trajectory shapes."""

    states = trajectory.get("states")
    legacy = trajectory.get("content")
    require(
        isinstance(states, list) or isinstance(legacy, list),
        "trajectory must carry a states or content list",
    )
    if isinstance(states, list):
        for index, state in enumerate(states):
            require(isinstance(state, dict), "trajectory state must be an object")
            thought = state.get("thought")
            if thought is None:
                thought = state.get("thoughts")
            text = state.get("accessibility_tree")
            if text is None:
                text = state.get("text")
            yield {
                "state_index": index,
                "url": str(state.get("url") or ""),
                "action": str(state.get("action") or ""),
                "thought": str(thought or ""),
                "text": str(text or ""),
                "screenshot": state.get("screenshot"),
            }
        return
    for index, state in enumerate(legacy):
        require(isinstance(state, dict), "trajectory content state must be an object")
        observation = state.get("observation")
        observation = observation if isinstance(observation, dict) else {}
        yield {
            "state_index": index,
            "url": str(state.get("url") or ""),
            "action": str(state.get("action") or ""),
            "thought": str(state.get("thoughts") or ""),
            "text": str(observation.get("text") or ""),
            "screenshot": observation.get("screenshot"),
        }


def _trajectory_goal(trajectory: dict[str, Any]) -> str:
    goal = trajectory.get("goal")
    if not goal:
        metadata = trajectory.get("metadata")
        if isinstance(metadata, dict):
            goal = metadata.get("original_goal")
    return str(goal or "")


def _truncate_utf8(text: str, maximum_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return text, False
    return encoded[:maximum_bytes].decode("utf-8", errors="ignore"), True


def _sanitize_bounded(text: str, maximum_bytes: int) -> tuple[str, bool]:
    """Redact a bounded-input value before applying the public byte bound.

    Truncating first can cut a credential marker away from its secret and turn
    the remaining prefix into apparently ordinary text.  Inputs above the
    fixed scan ceiling are rejected instead of being partially inspected.
    """

    require(isinstance(text, str), "text payload must be a string")
    require(
        len(text) <= MAX_SANITIZE_INPUT_CHARS,
        "text payload exceeds the fixed sanitization scan bound",
    )
    redacted, _hits = redact_capture_text(text)
    return _truncate_utf8(redacted, maximum_bytes)


def _sqlite_schema_digest(db_path: Path, *, immutable: bool = False) -> str:
    """Stream a deterministic digest of the complete SQLite schema."""

    immutable_query = "&immutable=1" if immutable else ""
    connection = sqlite3.connect(
        f"file:{db_path}?mode=ro{immutable_query}", uri=True
    )
    try:
        connection.execute("PRAGMA query_only = ON")
        digest = hashlib.sha256()
        count = 0
        cursor = connection.execute(
            "SELECT type, name, tbl_name, COALESCE(sql, '') "
            "FROM sqlite_master ORDER BY type, name, tbl_name"
        )
        for row in cursor:
            count += 1
            require(
                count <= MAX_SQLITE_SCHEMA_OBJECTS,
                "SQLite schema exceeds the fixed object bound",
            )
            digest.update(_canonical_json_bytes([str(value) for value in row]))
        require(count > 0, "SQLite schema is empty")
        return digest.hexdigest()
    finally:
        connection.close()


def _stream_sqlite_integrity(connection: sqlite3.Connection, pragma: str) -> None:
    """Consume every integrity result row without materializing the report."""

    count = 0
    for row in connection.execute(f"PRAGMA {pragma}"):
        count += 1
        require(
            count == 1 and len(row) == 1 and row[0] == "ok",
            f"restored store failed the SQLite {pragma}",
        )
    require(count == 1, f"restored store failed the SQLite {pragma}")


class _Runtime:
    """Disposable per-instance SYNAPSE-S2 runtime plus workspace pointers."""

    def __init__(
        self,
        *,
        workspace_dir: Path,
        owns_workspace: bool,
        runtime_root: Path,
        safe_root: Path,
        backend: Any,
        adapter: Any,
        cache: Any,
        binding: Any,
        derivatives_dir: Path,
        ledger_path: Path,
    ) -> None:
        self.workspace_dir = workspace_dir
        self.owns_workspace = owns_workspace
        self.runtime_root = runtime_root
        self.safe_root = safe_root
        self.backend = backend
        self.adapter = adapter
        self.cache = cache
        self.binding = binding
        self.derivatives_dir = derivatives_dir
        self.ledger_path = ledger_path


@register_memory
class SynapseS2Memory(Memory):
    """Official-harness memory backend over a disposable SYNAPSE-S2 store."""

    memory_type = MEMORY_TYPE

    def __init__(self, memory_params: dict[str, object]) -> None:
        super().__init__(memory_params)
        params = dict(memory_params)
        unknown = set(params) - _ALLOWED_TOP_KEYS
        require(not unknown, f"memory_params has unknown keys: {sorted(unknown)}")

        workspace_dir = params.get("workspace_dir")
        require(
            workspace_dir is None or (isinstance(workspace_dir, str) and workspace_dir.strip()),
            "memory_params workspace_dir must be null or a non-empty string",
        )
        self._configured_workspace = (
            Path(str(workspace_dir)).expanduser() if workspace_dir else None
        )
        expected_manifest_sha256 = params.get(EXPECTED_MANIFEST_SHA256_PARAM)
        require(
            expected_manifest_sha256 is None
            or (
                isinstance(expected_manifest_sha256, str)
                and _ANY_HEX64_PATTERN.fullmatch(expected_manifest_sha256) is not None
            ),
            f"memory_params {EXPECTED_MANIFEST_SHA256_PARAM} must be a 64-digit hex digest",
        )
        self._expected_artifact_manifest_sha256 = (
            str(expected_manifest_sha256).lower()
            if expected_manifest_sha256 is not None
            else None
        )
        release_after_query = params.get(RELEASE_AFTER_QUERY_PARAM, False)
        require(
            type(release_after_query) is bool,
            f"memory_params {RELEASE_AFTER_QUERY_PARAM} must be a boolean",
        )
        self._release_after_query = bool(release_after_query)
        self._namespace = _require_identity(
            params.get("store_namespace", BENCHMARK_NAMESPACE_DEFAULT),
            field="store_namespace",
        )
        require(
            self._namespace != "global",
            "memory_params store_namespace must never be the shared global context",
        )
        trajectories_root = params.get("trajectories_root_dir")
        require(
            trajectories_root is None
            or (isinstance(trajectories_root, str) and trajectories_root.strip()),
            "memory_params trajectories_root_dir must be null or a non-empty string",
        )
        self._trajectories_root: Path | None = None
        if trajectories_root:
            try:
                candidate_root = _bootstrap.require_no_symlink_components(
                    Path(str(trajectories_root)).expanduser(),
                    owner="memory_params trajectories_root_dir",
                )
                self._trajectories_root = _bootstrap.require_outside_live_store(
                    candidate_root,
                    owner="memory_params trajectories_root_dir",
                )
            except _bootstrap.BootstrapError as exc:
                raise RuntimeError(
                    "memory_params trajectories_root_dir failed path safety validation"
                ) from exc

        backend = _merged_section(params, "backend", _DEFAULT_BACKEND)
        backend["dimension"] = _require_int(
            backend["dimension"], field="backend.dimension", minimum=8, maximum=8192
        )
        backend["num_neurons"] = _require_int(
            backend["num_neurons"], field="backend.num_neurons", minimum=8, maximum=1_048_576
        )
        backend["default_top_k"] = _require_int(
            backend["default_top_k"], field="backend.default_top_k", minimum=1, maximum=256
        )
        backend["recall_count"] = _require_int(
            backend["recall_count"], field="backend.recall_count", minimum=1, maximum=4096
        )
        require(
            backend["embedding_provider"] == "semantic-hash",
            "memory_params backend.embedding_provider must be the offline "
            "semantic-hash provider; remote embedding endpoints are a run-time "
            "operator decision recorded by the preflight, not a memory_params field",
        )
        self._backend_config = backend

        retrieval = _merged_section(params, "retrieval", _DEFAULT_RETRIEVAL)
        retrieval["result_limit"] = _require_int(
            retrieval["result_limit"],
            field="retrieval.result_limit",
            minimum=1,
            maximum=MAX_RESULT_LIMIT,
        )
        retrieval["candidate_limit"] = _require_int(
            retrieval["candidate_limit"],
            field="retrieval.candidate_limit",
            minimum=retrieval["result_limit"],
            maximum=MAX_CANDIDATE_LIMIT,
        )
        require(
            type(retrieval["include_graph_neighbors"]) is bool,
            "memory_params retrieval.include_graph_neighbors must be a boolean",
        )
        retrieval["max_text_item_bytes"] = _require_int(
            retrieval["max_text_item_bytes"],
            field="retrieval.max_text_item_bytes",
            minimum=256,
            maximum=MAX_TEXT_ITEM_BYTES_CEILING,
        )
        self._retrieval = retrieval

        image = _merged_section(params, "image", _DEFAULT_IMAGE)
        require(
            isinstance(image["vision_mode"], str)
            and image["vision_mode"] in {"off", "feature-print", "ocr", "all"},
            "memory_params image.vision_mode must be off, feature-print, ocr, or all",
        )
        image["max_source_bytes"] = _require_int(
            image["max_source_bytes"],
            field="image.max_source_bytes",
            minimum=1024,
            maximum=MAX_SCREENSHOT_SOURCE_BYTES,
        )
        image["max_thumbnail_bytes"] = _require_int(
            image["max_thumbnail_bytes"],
            field="image.max_thumbnail_bytes",
            minimum=1024,
            maximum=MAX_THUMBNAIL_FILE_BYTES,
        )
        self._image = image

        insert = _merged_section(params, "insert", _DEFAULT_INSERT)
        insert["max_state_text_bytes"] = _require_int(
            insert["max_state_text_bytes"],
            field="insert.max_state_text_bytes",
            minimum=512,
            maximum=MAX_STATE_TEXT_BYTES_CEILING,
        )
        self._insert = insert

        # Exact topology byte bound before any backend arrays can be built.
        longmem_eval = importlib.import_module("longmem_eval")
        longmem_eval.require_backend_topology(
            self._backend_config, owner="memory_params backend"
        )

        self._runtime: _Runtime | None = None
        self._ledger: dict[str, Any] = {"next_ordinal": 0, "trajectories": {}}
        self._content_identities: dict[str, str] = {}
        self._media_reference_index: dict[str, dict[str, Any]] = {}
        self._image_converter: Callable[..., Any] | None = None
        self._vision_enricher: Callable[..., Any] | None = None
        self._query_vision_enricher: Callable[..., Any] | None = None
        self._vision_status: dict[str, Any] = {
            "requested_mode": self._image["vision_mode"],
            "effective_mode": self._image["vision_mode"],
            "reason": None,
        }
        self._query_lock = threading.Lock()
        self._last_query_meta_local = threading.local()
        self._closed = False

    # -- persisted public config -------------------------------------------------

    @property
    def memory_config(self) -> dict[str, Any]:
        """Fixed-schema public config: no paths, no provenance, no runtime state."""

        return {
            "memory_type": MEMORY_TYPE,
            "memory_params": {
                "store_namespace": self._namespace,
                "backend": dict(self._backend_config),
                "retrieval": dict(self._retrieval),
                "image": dict(self._image),
                "insert": dict(self._insert),
            },
        }

    # -- runtime construction -------------------------------------------------

    def configure_runtime(self, **kwargs: object) -> None:
        """Apply non-persisted runtime overrides (test seams included)."""

        converter = kwargs.pop("image_converter", None)
        if converter is not None:
            require(
                self._runtime is None,
                "image_converter must be configured before the store is built",
            )
            require(callable(converter), "image_converter must be callable")
            self._image_converter = converter  # type: ignore[assignment]
        vision_enricher = kwargs.pop("vision_enricher", None)
        if vision_enricher is not None:
            require(
                self._runtime is None,
                "vision_enricher must be configured before the store is built",
            )
            require(callable(vision_enricher), "vision_enricher must be callable")
            self._vision_enricher = vision_enricher  # type: ignore[assignment]
        query_vision_enricher = kwargs.pop("query_vision_enricher", None)
        if query_vision_enricher is not None:
            require(not self._closed, "memory instance is closed")
            require(
                callable(query_vision_enricher),
                "query_vision_enricher must be callable",
            )
            # Query enrichment is transient and cannot mutate capture state, so
            # a pinned artifact may install this process-local seam after load.
            self._query_vision_enricher = query_vision_enricher  # type: ignore[assignment]
        # Any other runtime kwargs from the harness are accepted and ignored.
        return None

    def _resolve_workspace(self) -> tuple[Path, bool, Path]:
        run_root = _active_run_root(owner="memory workspace")
        if self._configured_workspace is not None:
            workspace, safe_root = _create_private_directory(
                self._configured_workspace, owner="memory workspace"
            )
            return workspace, True, safe_root
        workspace, safe_root = _mkdtemp_private(
            parent=run_root.workspace_parent,
            prefix="s2lm-ws-",
            owner="memory workspace",
        )
        return workspace, True, safe_root

    def _resolve_runtime_root(self) -> tuple[Path, Path]:
        """Short private runtime/socket root, independent of the workspace."""

        run_root = _active_run_root(owner="runtime root")
        runtime_root, safe_root = _mkdtemp_private(
            parent=run_root.runtime_parent,
            prefix="s2lm-",
            owner="runtime root",
        )
        try:
            socket_path = runtime_root / "repo" / ".synapse_s2" / "core" / "service.sock"
            require(
                len(str(socket_path).encode("utf-8")) <= 103,
                "runtime socket path exceeds the Darwin bound",
            )
        except BaseException:
            _remove_disposable_tree(
                runtime_root, safe_root=safe_root, owner="runtime root failed creation"
            )
            raise
        return runtime_root, safe_root

    def _binding(self, runtime_root: Path) -> Any:
        """Disposable canonical-layout binding; placeholder identities only.

        The digests below are fixed placeholders for a store that exists only
        for this benchmark run; no operator binding, credential, or live core
        identity is ever read or copied.
        """

        modules = _synapse()
        repo_root, _safe_root = _create_private_directory(
            runtime_root / "repo", owner="runtime repository root"
        )
        # ``require_disposable_root`` deliberately refuses arbitrary paths
        # containing ``.synapse_s2``.  This is the one fixed canonical exception:
        # it is created exclusively beneath the just-created private runtime
        # repository root and never accepts a caller-supplied component.
        data_root = repo_root / ".synapse_s2"
        require(
            data_root.parent == repo_root
            and repo_root.parent == runtime_root
            and not os.path.lexists(data_root),
            "runtime data root is not a fresh canonical child",
        )
        os.mkdir(data_root, mode=0o700)
        os.chmod(data_root, 0o700)
        _require_owner_private_directory(data_root, owner="runtime data root")
        core_root = data_root / "core"
        require(
            not os.path.lexists(core_root),
            "runtime core root is not fresh",
        )
        os.mkdir(core_root, mode=0o700)
        os.chmod(core_root, 0o700)
        _require_owner_private_directory(core_root, owner="runtime core root")
        binding = modules["core_client_binding"].CoreClientBinding(
            repo_root=repo_root,
            data_root=data_root,
            config_path=core_root / "service.json",
            socket_path=core_root / "service.sock",
            state_path=data_root / "runtime_state.json",
            memory_path=data_root / "memory.sqlite3",
            capture_root=data_root,
            export_root=data_root / "exports",
            backup_root=data_root / "backups",
            recovery_root=data_root / "recovery",
            replication_inbox_root=data_root / "replication" / "inbox",
            core_label="longmem-v2-official-adapter",
            config_digest="a" * 64,
            config_fingerprint="b" * 64,
            embedding_space_identity="c" * 64,
            layout="canonical",
            authority_mode="authoritative-core-v6",
        )
        try:
            canonical = modules["core_client_binding"].validate_core_client_binding(
                binding.to_wire()
            )
        except Exception as exc:
            raise RuntimeError("runtime core binding failed validation") from exc
        require(
            canonical.socket_path == core_root / "service.sock"
            and len(str(canonical.socket_path).encode("utf-8")) <= 103,
            "runtime core socket binding is invalid",
        )
        return canonical

    def _build_runtime(self) -> _Runtime:
        require(not self._closed, "memory instance is closed")
        if self._runtime is not None:
            return self._runtime
        modules = _synapse()
        longmem_eval = modules["longmem_eval"]
        longmem_eval.require_backend_topology(
            self._backend_config, owner="memory_params backend"
        )
        workspace, owns_workspace, safe_root = self._resolve_workspace()
        runtime_root: Path | None = None
        try:
            ledger_path = workspace / LEDGER_NAME
            require(
                not os.path.lexists(ledger_path),
                "workspace already contains an insert ledger; use a fresh "
                "workspace or load the sealed artifact instead",
            )
            runtime_root, runtime_safe_root = self._resolve_runtime_root()
            require(runtime_safe_root == safe_root, "disposable runtime roots diverged")
            binding = self._binding(runtime_root)
            data_root = Path(binding.data_root)
            try:
                backend = modules["mlx_backend"].SpikingAttentionBackend(
                    dimension=self._backend_config["dimension"],
                    num_neurons=self._backend_config["num_neurons"],
                    default_top_k=self._backend_config["default_top_k"],
                    recall_count=self._backend_config["recall_count"],
                    compile_graph=False,
                    state_path=data_root / "runtime_state.json",
                    embedding_provider_name=self._backend_config["embedding_provider"],
                )
            except Exception as exc:
                raise RuntimeError("backend construction failed") from exc
            adapter = longmem_eval.LongMemInsertQueryAdapter(backend)
            vision_enricher = self._vision_enricher
            if self._image["vision_mode"] != "off":
                if vision_enricher is None:
                    try:
                        vision_module = importlib.import_module(
                            "apple_vision_enrichment"
                        )
                        vision_enricher = vision_module.AppleVisionEnricher(
                            binding
                        ).enrich
                    except Exception:
                        # Visible degradation: captures proceed with vision off
                        # and the reason is carried into post-query metadata.
                        self._vision_status = {
                            "requested_mode": self._image["vision_mode"],
                            "effective_mode": "off",
                            "reason": "apple vision enrichment unavailable",
                        }
            cache_kwargs: dict[str, Any] = {}
            if self._image_converter is not None:
                cache_kwargs["converter"] = self._image_converter
            if vision_enricher is not None:
                cache_kwargs["vision_enricher"] = vision_enricher
            cache = modules["image_capture"].ImageCaptureCache(binding, **cache_kwargs)
            derivatives_dir, _safe_root = _create_private_directory(
                workspace / DERIVATIVES_DIR_NAME,
                owner="memory derivative directory",
            )
        except BaseException:
            if runtime_root is not None and os.path.lexists(runtime_root):
                _remove_disposable_tree(
                    runtime_root,
                    safe_root=safe_root,
                    owner="failed runtime cleanup",
                )
            if owns_workspace and os.path.lexists(workspace):
                _remove_disposable_tree(
                    workspace,
                    safe_root=safe_root,
                    owner="failed workspace cleanup",
                )
            raise
        self._runtime = _Runtime(
            workspace_dir=workspace,
            owns_workspace=owns_workspace,
            runtime_root=runtime_root,
            safe_root=safe_root,
            backend=backend,
            adapter=adapter,
            cache=cache,
            binding=binding,
            derivatives_dir=derivatives_dir,
            ledger_path=ledger_path,
        )
        return self._runtime

    # -- insert ledger -----------------------------------------------------------

    def _validate_ledger(self, ledger: Any) -> dict[str, Any]:
        """Bounded canonical insert-ledger schema, counts, and ordinal tiling."""

        require(isinstance(ledger, dict), "insert ledger must be an object")
        require(
            set(ledger) == _LEDGER_KEYS,
            "insert ledger must carry exactly next_ordinal and trajectories",
        )
        next_ordinal = ledger["next_ordinal"]
        require(
            type(next_ordinal) is int
            and 0 <= next_ordinal <= MAX_TRAJECTORIES * MAX_STATES_PER_TRAJECTORY,
            "insert ledger next_ordinal is out of bounds",
        )
        trajectories = ledger["trajectories"]
        require(isinstance(trajectories, dict), "insert ledger trajectories must be an object")
        require(
            len(trajectories) <= MAX_TRAJECTORIES,
            "insert ledger trajectory count exceeds the fixed bound",
        )
        spans: list[tuple[int, int]] = []
        seen_memory_ids: set[str] = set()
        seen_media_ids: set[str] = set()
        for trajectory_id, record in trajectories.items():
            require(
                _normalize_trajectory_id(trajectory_id) == trajectory_id,
                f"insert ledger trajectory id is not normalized: {trajectory_id!r}",
            )
            require(isinstance(record, dict), "insert ledger record must be an object")
            require(
                set(record) == _LEDGER_RECORD_KEYS,
                f"insert ledger record schema mismatch for {trajectory_id}",
            )
            fingerprint = record["fingerprint"]
            require(
                isinstance(fingerprint, str) and _HEX64_PATTERN.fullmatch(fingerprint),
                f"insert ledger fingerprint malformed for {trajectory_id}",
            )
            state_count = record["state_count"]
            require(
                type(state_count) is int and 1 <= state_count <= MAX_STATES_PER_TRAJECTORY,
                f"insert ledger state_count out of bounds for {trajectory_id}",
            )
            ordinal_start = record["ordinal_start"]
            require(
                type(ordinal_start) is int and 0 <= ordinal_start <= next_ordinal,
                f"insert ledger ordinal_start out of bounds for {trajectory_id}",
            )
            memory_ids = record["memory_ids"]
            require(
                isinstance(memory_ids, list) and len(memory_ids) == state_count,
                f"insert ledger memory_ids count mismatch for {trajectory_id}",
            )
            for memory_id in memory_ids:
                require(
                    isinstance(memory_id, str)
                    and 0 < len(memory_id) <= MAX_MEMORY_ID_CHARS
                    and all(char.isprintable() for char in memory_id)
                    and memory_id not in seen_memory_ids,
                    f"insert ledger memory id malformed or duplicated for {trajectory_id}",
                )
                seen_memory_ids.add(memory_id)
            media = record["media"]
            require(isinstance(media, list), f"insert ledger media must be a list for {trajectory_id}")
            seen_states: set[int] = set()
            for entry in media:
                require(isinstance(entry, dict), "insert ledger media entry must be an object")
                require(
                    set(entry) == _LEDGER_MEDIA_KEYS,
                    f"insert ledger media schema mismatch for {trajectory_id}",
                )
                state_index = entry["state_index"]
                require(
                    type(state_index) is int
                    and 0 <= state_index < state_count
                    and state_index not in seen_states,
                    f"insert ledger media state_index invalid for {trajectory_id}",
                )
                seen_states.add(state_index)
                media_id = entry["media_id"]
                require(
                    isinstance(media_id, str)
                    and _MEDIA_ID_PATTERN.fullmatch(media_id)
                    and media_id == self._media_id(trajectory_id, state_index)
                    and media_id not in seen_media_ids,
                    f"insert ledger media id does not bind to {trajectory_id} "
                    f"state {state_index}",
                )
                seen_media_ids.add(media_id)
                thumbnail_sha256 = entry["thumbnail_sha256"]
                require(
                    isinstance(thumbnail_sha256, str)
                    and _HEX64_PATTERN.fullmatch(thumbnail_sha256),
                    f"insert ledger thumbnail digest malformed for {trajectory_id}",
                )
                require(
                    type(entry["thumbnail_bytes"]) is int
                    and 1 <= entry["thumbnail_bytes"] <= self._image["max_thumbnail_bytes"],
                    f"insert ledger thumbnail byte count invalid for {trajectory_id}",
                )
                require(
                    isinstance(entry["media_object_sha256"], str)
                    and _HEX64_PATTERN.fullmatch(entry["media_object_sha256"]),
                    f"insert ledger media object binding malformed for {trajectory_id}",
                )
            spans.append((ordinal_start, state_count))
        require(
            len(seen_media_ids) <= MAX_MEDIA_CACHE_OBJECTS,
            "insert ledger media count exceeds the fixed cache object bound",
        )
        spans.sort()
        expected_start = 0
        for start, count in spans:
            require(
                start == expected_start,
                "insert ledger ordinals do not tile the store contiguously",
            )
            expected_start += count
        require(
            expected_start == next_ordinal,
            "insert ledger next_ordinal does not match the ordinal tiling",
        )
        return ledger

    def _persist_ledger(self, runtime: _Runtime) -> None:
        _write_private_file(runtime.ledger_path, _canonical_json_bytes(self._ledger))

    # -- insert ----------------------------------------------------------------

    def _prepared_states(self, trajectory: dict[str, Any], trajectory_id: str) -> list[dict[str, Any]]:
        """Redacted, bounded logical payload per state (single pass, bounded)."""

        goal = _trajectory_goal(trajectory)
        outcome = str(trajectory.get("outcome") or "")
        max_text = int(self._insert["max_state_text_bytes"])
        prepared: list[dict[str, Any]] = []
        for state in _iter_states(trajectory):
            require(
                len(prepared) < MAX_STATES_PER_TRAJECTORY,
                "trajectory state count exceeds the fixed adapter bound",
            )
            state_index = int(state["state_index"])
            parts: list[str] = []
            if goal and state_index == 0:
                parts.append(f"goal: {goal}")
            if outcome and state_index == 0:
                parts.append(f"outcome: {outcome}")
            if state["url"]:
                parts.append(f"url: {state['url']}")
            if state["action"]:
                parts.append(f"action: {state['action']}")
            if state["thought"]:
                parts.append(f"thought: {state['thought']}")
            if state["text"]:
                parts.append(f"observation: {state['text']}")
            text, truncated = _sanitize_bounded("\n".join(parts), max_text)
            if not text.strip():
                text = f"trajectory {trajectory_id} state {state_index} (empty state)"
            url_public, _ = _sanitize_bounded(state["url"], MAX_URL_METADATA_BYTES)
            screenshot = state.get("screenshot")
            has_screenshot = isinstance(screenshot, str) and bool(screenshot.strip())
            prepared.append(
                {
                    "state_index": state_index,
                    "text": text,
                    "truncated": truncated,
                    "url_public": url_public,
                    "screenshot": screenshot if has_screenshot else None,
                }
            )
        require(prepared, "trajectory must carry at least one state")
        return prepared

    def _trajectory_fingerprint(
        self,
        trajectory: dict[str, Any],
        trajectory_id: str,
        prepared: list[dict[str, Any]],
    ) -> str:
        """Ephemeral in-process identity over the redacted logical payload.

        This value supports same-instance idempotency only.  It is never placed
        in the store, ledger, manifest, or any other persisted artifact.  The
        persisted trajectory binding is an independent random capability, so
        sealed artifacts expose no raw- or sanitized-content hash oracle.
        """

        max_text = int(self._insert["max_state_text_bytes"])
        goal_public, _ = _sanitize_bounded(_trajectory_goal(trajectory), max_text)
        outcome_public, _ = _sanitize_bounded(str(trajectory.get("outcome") or ""), max_text)
        digest = hashlib.sha256()
        digest.update(
            _canonical_json_bytes(
                {
                    "schema": FINGERPRINT_SCHEMA,
                    "namespace": self._namespace,
                    "trajectory_id": trajectory_id,
                    "goal": goal_public,
                    "outcome": outcome_public,
                    "state_count": len(prepared),
                }
            )
        )
        for row in prepared:
            digest.update(
                _canonical_json_bytes(
                    {
                        "state_index": row["state_index"],
                        "text": row["text"],
                        "has_image": row["screenshot"] is not None,
                    }
                )
            )
        return digest.hexdigest()

    def _resolve_screenshot(self, value: Any) -> Path:
        require(
            isinstance(value, str) and value.strip(),
            "trajectory screenshot reference must be a non-empty string",
        )
        reference = Path(str(value))
        candidates: list[Path] = []
        if reference.is_absolute():
            candidates.append(reference)
        elif self._trajectories_root is not None:
            candidates.append(self._trajectories_root / reference)
            candidates.append(self._trajectories_root / "screenshots" / reference)
        require(
            bool(candidates),
            "relative screenshot references require memory_params trajectories_root_dir",
        )
        for candidate in candidates:
            try:
                safe_candidate = _bootstrap.require_no_symlink_components(
                    candidate, owner="trajectory screenshot source"
                )
                safe_candidate = _bootstrap.require_outside_live_store(
                    safe_candidate, owner="trajectory screenshot source"
                )
                descriptor = _open_regular_readonly(
                    safe_candidate, owner="trajectory screenshot source"
                )
            except (OSError, RuntimeError, _bootstrap.BootstrapError):
                continue
            try:
                observed = os.fstat(descriptor)
                require(
                    stat.S_ISREG(observed.st_mode)
                    and observed.st_size <= self._image["max_source_bytes"],
                    "trajectory screenshot source exceeds the fixed byte bound",
                )
            finally:
                os.close(descriptor)
            return safe_candidate
        raise RuntimeError("trajectory screenshot source is unavailable")

    def _media_id(self, trajectory_id: str, state_index: int) -> str:
        seed = f"{self._namespace}|{trajectory_id}|{state_index}".encode("utf-8")
        return "s2img_" + hashlib.sha256(seed).hexdigest()[:32]

    def _capture_screenshot(
        self,
        runtime: _Runtime,
        *,
        trajectory_id: str,
        state_index: int,
        source: Path,
    ) -> dict[str, Any]:
        media_id = self._media_id(trajectory_id, state_index)
        captured = runtime.cache.capture_image(
            source,
            media_id=media_id,
            vision_mode=self._vision_status["effective_mode"],
            vision_required=False,
        )
        require(
            captured.get("raw_original_stored") is False,
            "image capture must never store the raw original",
        )
        thumbnail = runtime.cache.get_thumbnail(media_id)
        _cache_manifest, cache_artifacts = (
            runtime.cache.reader.read_object_artifacts(media_id)
        )
        require(
            len(thumbnail.data) <= self._image["max_thumbnail_bytes"],
            "thumbnail derivative exceeds the fixed byte bound",
        )
        require(
            cache_artifacts["thumbnail.jpg"] == thumbnail.data,
            "thumbnail derivative does not match the private media object",
        )
        derivative = runtime.derivatives_dir / f"{media_id}.jpg"
        digest = _sha256_hex(thumbnail.data)
        if derivative.exists():
            existing = _read_regular_file_bytes(
                derivative,
                owner="thumbnail derivative",
                maximum_bytes=self._image["max_thumbnail_bytes"],
            )
            require(
                _sha256_hex(existing) == digest,
                "existing thumbnail derivative does not match the cache thumbnail",
            )
        else:
            _write_private_file(derivative, thumbnail.data)
        return {
            "media_id": media_id,
            "state_index": state_index,
            "thumbnail_sha256": digest,
            "thumbnail_bytes": len(thumbnail.data),
            "media_object_sha256": _media_object_binding_sha256(
                media_id, cache_artifacts
            ),
        }

    def insert(self, trajectory: dict[str, object]) -> None:
        require(isinstance(trajectory, dict), "trajectory must be an object")
        trajectory_id = _normalize_trajectory_id(trajectory.get("id"))
        prepared = self._prepared_states(trajectory, trajectory_id)
        content_identity = self._trajectory_fingerprint(
            trajectory, trajectory_id, prepared
        )
        existing = self._ledger["trajectories"].get(trajectory_id)
        if existing is not None:
            prior_identity = self._content_identities.get(trajectory_id)
            require(
                prior_identity is not None
                and secrets.compare_digest(prior_identity, content_identity),
                f"trajectory {trajectory_id} was already inserted with different content",
            )
            return  # idempotent re-insert of identical content
        # Preflight the complete media delta before constructing a runtime or
        # touching the store/cache. ImageCaptureCache deliberately owns only
        # per-object validation; this adapter owns the official-run inventory
        # ceiling and therefore must enforce existing + incoming atomically.
        # The index is populated only after a trajectory finishes and is
        # rebuilt from a fully validated ledger on restore, making its length
        # the constant-time authoritative in-process media count. Full ledger
        # validation remains at seal/load boundaries to avoid quadratic
        # insertion cost across an official stream.
        existing_media_count = len(self._media_reference_index)
        incoming_media_count = sum(
            row["screenshot"] is not None for row in prepared
        )
        require(
            existing_media_count + incoming_media_count
            <= MAX_MEDIA_CACHE_OBJECTS,
            "trajectory media count exceeds the fixed cache object bound",
        )
        require(
            len(self._ledger["trajectories"]) < MAX_TRAJECTORIES,
            "trajectory count exceeds the fixed adapter bound",
        )
        runtime = self._build_runtime()
        ordinal_start = int(self._ledger["next_ordinal"])
        trajectory_binding = secrets.token_hex(32)
        memory_ids: list[str] = []
        media_records: list[dict[str, Any]] = []
        ordinal = ordinal_start
        for row in prepared:
            state_index = int(row["state_index"])
            text = str(row["text"])
            metadata: dict[str, Any] = {
                "display_label": f"{trajectory_id} state {state_index}",
                "display_summary": text[:240],
                "display_excerpt": text,
                "memory_type": "text",
                "source": "longmem-v2-official-trajectory",
                "embedding_provider": self._backend_config["embedding_provider"],
                "trajectory_id": trajectory_id,
                "state_index": state_index,
                "state_url": row["url_public"],
                "trajectory_binding": trajectory_binding,
                "adapter_version": ADAPTER_VERSION,
                "benchmark_namespace": self._namespace,
                "text_truncated": bool(row["truncated"]),
            }
            if row["screenshot"] is not None:
                source = self._resolve_screenshot(row["screenshot"])
                media = self._capture_screenshot(
                    runtime,
                    trajectory_id=trajectory_id,
                    state_index=state_index,
                    source=source,
                )
                media_records.append(media)
                metadata["memory_type"] = "image"
                metadata["media_id"] = media["media_id"]
                metadata["media_object_sha256"] = media[
                    "media_object_sha256"
                ]
            memory_id = runtime.adapter.insert_turn(
                tag=f"lmv2:{trajectory_id}:{state_index:04d}",
                context_id=self._namespace,
                source_text=text,
                embedding_text=text,
                metadata=metadata,
                timestamp=FIXED_EPOCH + float(ordinal),
            )
            memory_ids.append(str(memory_id))
            ordinal += 1
        self._ledger["trajectories"][trajectory_id] = {
            # Historical field name retained for artifact-schema continuity;
            # this is an opaque random binding, never a content fingerprint.
            "fingerprint": trajectory_binding,
            "state_count": len(prepared),
            "ordinal_start": ordinal_start,
            "memory_ids": memory_ids,
            "media": media_records,
        }
        self._ledger["next_ordinal"] = ordinal
        for media in media_records:
            media_id = str(media["media_id"])
            state_index = int(media["state_index"])
            require(
                media_id not in self._media_reference_index,
                "media reference identity is duplicated",
            )
            self._media_reference_index[media_id] = {
                "trajectory_id": trajectory_id,
                "state_index": state_index,
                "memory_id": memory_ids[state_index],
                "thumbnail_sha256": str(media["thumbnail_sha256"]),
                "thumbnail_bytes": int(media["thumbnail_bytes"]),
                "media_object_sha256": str(media["media_object_sha256"]),
            }
        self._content_identities[trajectory_id] = content_identity
        self._persist_ledger(runtime)

    # -- query -----------------------------------------------------------------

    def _authoritative_media_scope(
        self,
        runtime: _Runtime,
        *,
        maximum_references: int,
    ) -> tuple[list[str], dict[str, Any]]:
        """Resolve exact in-namespace ledger references back to stored rows.

        The private media cache is deliberately not enumerated: orphaned or
        cross-namespace cache objects can therefore never enter the query
        scope.  Query-time row reads stop exactly at ``maximum_references``;
        only fixed-size trajectory headers are examined beyond that prefix so
        the receipt can state whether the deterministic scope was truncated.
        Every selected ID is jointly witnessed by the insert ledger, the
        in-process index built during insert/restore validation, and its exact
        logical store row.
        """

        require(
            type(maximum_references) is int
            and 1 <= maximum_references <= QUERY_IMAGE_CANDIDATE_LIMIT_CEILING,
            "query image scope bound is invalid",
        )
        scope: list[str] = []
        seen: set[str] = set()
        trajectories = self._ledger.get("trajectories")
        require(isinstance(trajectories, dict), "insert ledger is unavailable")
        require(
            len(trajectories) <= MAX_TRAJECTORIES,
            "insert ledger trajectory count exceeds the fixed bound",
        )
        total_references = 0
        for trajectory_id in sorted(trajectories):
            record = trajectories[trajectory_id]
            require(isinstance(record, dict), "insert ledger record is invalid")
            memory_ids = record.get("memory_ids")
            media = record.get("media")
            require(
                isinstance(memory_ids, list) and isinstance(media, list),
                "insert ledger media binding is invalid",
            )
            total_references += len(media)
            if len(scope) >= maximum_references:
                continue
            for reference in media:
                if len(scope) >= maximum_references:
                    break
                require(
                    isinstance(reference, dict),
                    "insert ledger media reference is invalid",
                )
                media_id = str(reference.get("media_id") or "")
                state_index = int(reference.get("state_index"))
                require(
                    _MEDIA_ID_PATTERN.fullmatch(media_id) is not None
                    and 0 <= state_index < len(memory_ids)
                    and media_id not in seen,
                    "insert ledger media reference is invalid",
                )
                indexed = self._media_reference_index.get(media_id)
                require(
                    isinstance(indexed, dict)
                    and indexed.get("trajectory_id") == trajectory_id
                    and indexed.get("state_index") == state_index
                    and indexed.get("memory_id") == str(memory_ids[state_index])
                    and indexed.get("thumbnail_sha256")
                    == reference.get("thumbnail_sha256")
                    and indexed.get("thumbnail_bytes")
                    == reference.get("thumbnail_bytes")
                    and indexed.get("media_object_sha256")
                    == reference.get("media_object_sha256"),
                    "indexed media reference does not bind to the insert ledger",
                )
                entry = runtime.adapter.get_entry(str(memory_ids[state_index]))
                metadata = (entry or {}).get("metadata")
                require(
                    isinstance(metadata, dict)
                    and metadata.get("benchmark_namespace") == self._namespace
                    and metadata.get("trajectory_id") == trajectory_id
                    and metadata.get("state_index") == state_index
                    and metadata.get("media_id") == media_id
                    and metadata.get("memory_type") == "image"
                    and metadata.get("media_object_sha256")
                    == reference.get("media_object_sha256"),
                    "authoritative media reference does not bind to its store row",
                )
                seen.add(media_id)
                scope.append(media_id)
        require(
            total_references == len(self._media_reference_index),
            "media reference index count does not match the insert ledger",
        )
        return scope, {
            "total_reference_count": total_references,
            "selected_reference_count": len(scope),
            "truncated_reference_count": max(0, total_references - len(scope)),
            "complete": total_references <= maximum_references,
            "selection_policy": "sorted-trajectory-ledger-prefix-v1",
            "trajectory_headers_examined": len(trajectories),
        }

    def _media_reference_for_entry(
        self,
        *,
        memory_id: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        media_id = str(metadata.get("media_id") or "")
        trajectory_id = str(metadata.get("trajectory_id") or "")
        state_index = metadata.get("state_index")
        indexed = self._media_reference_index.get(media_id)
        trajectories = self._ledger.get("trajectories")
        record = (
            trajectories.get(trajectory_id)
            if isinstance(trajectories, dict)
            else None
        )
        memory_ids = record.get("memory_ids") if isinstance(record, dict) else None
        require(
            _MEDIA_ID_PATTERN.fullmatch(media_id) is not None
            and type(state_index) is int
            and isinstance(memory_ids, list)
            and 0 <= state_index < len(memory_ids)
            and str(memory_ids[state_index]) == memory_id
            and media_id == self._media_id(trajectory_id, state_index)
            and isinstance(indexed, dict)
            and indexed.get("trajectory_id") == trajectory_id
            and indexed.get("state_index") == state_index
            and indexed.get("memory_id") == memory_id,
            "retrieval media reference does not bind to the insert ledger",
        )
        assert isinstance(indexed, dict)
        return indexed

    def _thumbnail_path(self, runtime: _Runtime, media_id: str) -> Path:
        require(
            _MEDIA_ID_PATTERN.fullmatch(media_id) is not None,
            "thumbnail media reference is invalid",
        )
        derivative = runtime.derivatives_dir / f"{media_id}.jpg"
        try:
            observed = os.lstat(derivative)
        except OSError as exc:
            raise RuntimeError("thumbnail derivative is unavailable") from exc
        require(
            stat.S_ISREG(observed.st_mode)
            and observed.st_uid == os.getuid()
            and observed.st_nlink == 1
            and stat.S_IMODE(observed.st_mode) == 0o600
            and 0 < observed.st_size <= self._image["max_thumbnail_bytes"],
            "thumbnail derivative is not an owner-private bounded regular file",
        )
        # Re-open with O_NOFOLLOW and re-check the fixed byte ceiling so a
        # pathname replacement cannot be returned unchecked.
        digest, size = _stream_regular_file(
            derivative,
            owner="thumbnail derivative",
            maximum_bytes=self._image["max_thumbnail_bytes"],
        )
        indexed = self._media_reference_index.get(media_id)
        require(
            isinstance(indexed, dict)
            and type(indexed.get("thumbnail_bytes")) is int
            and size == indexed["thumbnail_bytes"]
            and isinstance(indexed.get("thumbnail_sha256"), str)
            and secrets.compare_digest(digest, indexed["thumbnail_sha256"]),
            "thumbnail derivative does not match its sealed ledger binding",
        )
        return derivative

    def _query_image_similarity(
        self,
        runtime: _Runtime,
        query_image: str,
        *,
        scope_media_ids: list[str],
        scope_summary: dict[str, Any],
    ) -> tuple[list[str], dict[str, Any]]:
        """Run the optional transient visual lane with a content-free receipt."""

        result_limit = min(
            int(self._retrieval["result_limit"]), QUERY_IMAGE_RESULT_LIMIT_CEILING
        )
        candidate_limit = min(
            int(self._retrieval["candidate_limit"]),
            QUERY_IMAGE_CANDIDATE_LIMIT_CEILING,
        )
        metadata: dict[str, Any] = {
            "schema": QUERY_IMAGE_META_SCHEMA,
            "provided": True,
            "status": "failure",
            "reason_code": "query-image-rejected",
            "result_count": 0,
            "scope_reference_count": len(scope_media_ids),
            "scope_total_reference_count": int(
                scope_summary["total_reference_count"]
            ),
            "scope_truncated_reference_count": int(
                scope_summary["truncated_reference_count"]
            ),
            "scope_complete": bool(scope_summary["complete"]),
            "scope_selection_policy": str(scope_summary["selection_policy"]),
            "scope_trajectory_headers_examined": int(
                scope_summary["trajectory_headers_examined"]
            ),
            "compatible_candidate_count": 0,
            "result_limit": result_limit,
            "candidate_limit": candidate_limit,
            "time_budget_seconds": QUERY_IMAGE_TIME_BUDGET_SECONDS,
            "query_persisted": False,
            "media_cache_written": False,
            "raw_path_returned": False,
            "feature_print_bytes_returned": False,
            "scratch_removed": False,
        }
        scratch_root: Path | None = None
        safe_root = runtime.safe_root
        try:
            try:
                source = _bootstrap.require_no_symlink_components(
                    Path(query_image), owner="query image source"
                )
                source = _bootstrap.require_outside_live_store(
                    source, owner="query image source"
                )
                scratch_root, safe_root = _mkdtemp_private(
                    parent=runtime.runtime_root,
                    prefix=".query-image-",
                    owner="query image scratch",
                )
                suffix = source.suffix.lower()
                if suffix not in {".png", ".jpg", ".jpeg", ".heic"}:
                    suffix = ".image"
                scratch = scratch_root / f"query{suffix}"
                copied = _stream_copy_private(
                    source,
                    scratch,
                    owner="query image source",
                    maximum_bytes=self._image["max_source_bytes"],
                )
                require(
                    int(copied["bytes"]) > 0,
                    "query image source must not be empty",
                )
                modules = _synapse()
                media_similarity = modules["media_similarity"]
                projection = media_similarity.query_similar_media_transient(
                    runtime.binding,
                    scratch,
                    scope_media_ids=scope_media_ids,
                    result_limit=result_limit,
                    candidate_limit=candidate_limit,
                    time_budget_seconds=QUERY_IMAGE_TIME_BUDGET_SECONDS,
                    vision_enricher=(
                        self._query_vision_enricher or self._vision_enricher
                    ),
                    vision_input_derivative=QUERY_IMAGE_INPUT_DERIVATIVE,
                )
                candidate = projection.get("candidate")
                results = projection.get("results")
                require(
                    isinstance(candidate, dict) and isinstance(results, list),
                    "transient image similarity returned an invalid projection",
                )
                compatible_count = int(candidate.get("compatible_count") or 0)
                require(
                    0 <= compatible_count <= candidate_limit
                    and len(results) <= result_limit,
                    "transient image similarity exceeded its fixed bounds",
                )
                selected: list[str] = []
                seen: set[str] = set()
                authorized = set(scope_media_ids)
                for item in results:
                    media_id = str((item or {}).get("media_id") or "")
                    require(
                        media_id in authorized and media_id not in seen,
                        "transient image similarity returned an unauthorized result",
                    )
                    seen.add(media_id)
                    selected.append(media_id)
                scope_complete = bool(scope_summary["complete"])
                metadata.update(
                    {
                        "status": "applied"
                        if compatible_count and scope_complete
                        else "degraded",
                        "reason_code": (
                            None
                            if compatible_count and scope_complete
                            else "authoritative-scope-truncated"
                            if compatible_count
                            else "no-compatible-feature-prints"
                        ),
                        "result_count": len(selected),
                        "compatible_candidate_count": compatible_count,
                    }
                )
                return selected, metadata
            except Exception as exc:
                media_similarity = _synapse()["media_similarity"]
                if isinstance(exc, media_similarity.MediaSimilarityIncompatible):
                    metadata.update(
                        status="degraded",
                        reason_code="query-feature-print-incompatible",
                    )
                elif isinstance(
                    exc, media_similarity.MediaSimilarityIntegrityDrift
                ):
                    metadata.update(
                        status="failure",
                        reason_code="authoritative-media-integrity-drift",
                    )
                elif isinstance(exc, media_similarity.MediaSimilarityError):
                    metadata.update(
                        status="degraded",
                        reason_code="vision-or-similarity-unavailable",
                    )
                elif isinstance(
                    exc,
                    (
                        RuntimeError,
                        ValueError,
                        OSError,
                        _bootstrap.BootstrapError,
                    ),
                ):
                    metadata.update(
                        status="failure",
                        reason_code="query-image-rejected",
                    )
                else:
                    raise
                return [], metadata
        finally:
            if scratch_root is not None and os.path.lexists(scratch_root):
                _remove_disposable_tree(
                    scratch_root,
                    safe_root=safe_root,
                    owner="query image scratch cleanup",
                )
            metadata["scratch_removed"] = scratch_root is None or not os.path.lexists(
                scratch_root
            )

    def query(
        self,
        query: str,
        query_image: str | None = None,
    ) -> list[MemoryContextItem]:
        require(isinstance(query, str) and query.strip(), "query must be a non-empty string")
        runtime = self._build_runtime()
        require(
            bool(self._ledger["trajectories"]),
            "query requires at least one inserted or loaded trajectory",
        )
        bounded_query, query_truncated = _sanitize_bounded(
            query.strip(), MAX_QUERY_BYTES
        )
        if query_image is not None:
            require(
                isinstance(query_image, str) and bool(query_image.strip()),
                "query_image must be null or a non-empty path string",
            )
        with self._query_lock:
            try:
                envelope = runtime.adapter.query(
                    prompt=bounded_query,
                    context_id=self._namespace,
                    recall_scope="local",
                    result_limit=int(self._retrieval["result_limit"]),
                    candidate_limit=int(self._retrieval["candidate_limit"]),
                    include_graph_neighbors=bool(
                        self._retrieval["include_graph_neighbors"]
                    ),
                )
            except ValueError as exc:
                raise RuntimeError("retrieval rejected the query") from exc
        envelope_items = envelope.get("items")
        require(
            isinstance(envelope_items, list)
            and len(envelope_items) <= int(self._retrieval["result_limit"]),
            "retrieval returned an invalid result envelope",
        )

        similar_media_ids: list[str] = []
        query_image_meta: dict[str, Any] | None = None
        if query_image is not None:
            image_candidate_limit = min(
                int(self._retrieval["candidate_limit"]),
                QUERY_IMAGE_CANDIDATE_LIMIT_CEILING,
            )
            authoritative_media, scope_summary = self._authoritative_media_scope(
                runtime,
                maximum_references=image_candidate_limit,
            )
            similar_media_ids, query_image_meta = self._query_image_similarity(
                runtime,
                query_image,
                scope_media_ids=authoritative_media,
                scope_summary=scope_summary,
            )

        text_rows: list[tuple[MemoryContextItem, str]] = []
        seen_memory_ids: set[str] = set()
        max_item_bytes = int(self._retrieval["max_text_item_bytes"])
        for entry in envelope_items:
            require(isinstance(entry, dict), "retrieval result item is invalid")
            memory_id = str(entry.get("memory_id") or "")
            require(
                bool(memory_id) and memory_id not in seen_memory_ids,
                "retrieval returned a missing or duplicate memory identity",
            )
            seen_memory_ids.add(memory_id)
            header = f"[{entry.get('tag')}]"
            body = str(entry.get("excerpt") or entry.get("summary") or entry.get("label") or "")
            text_value, _ = _truncate_utf8(f"{header} {body}".strip(), max_item_bytes)
            stored = runtime.adapter.get_entry(memory_id) if memory_id else None
            metadata = (stored or {}).get("metadata")
            metadata = metadata if isinstance(metadata, dict) else {}
            media_id = str(metadata.get("media_id") or "")
            if media_id:
                self._media_reference_for_entry(
                    memory_id=memory_id,
                    metadata=metadata,
                )
            text_rows.append(({"type": "text", "value": text_value}, media_id))

        # Visual matches lead in their deterministic similarity order; text
        # evidence retains the backend order.  A stored image may be selected
        # by both signals but its thumbnail is returned once only.
        items: list[MemoryContextItem] = []
        seen_images: set[str] = set()
        image_limit = int(self._retrieval["result_limit"])
        for media_id in similar_media_ids:
            if media_id in seen_images or len(seen_images) >= image_limit:
                continue
            derivative = self._thumbnail_path(runtime, media_id)
            seen_images.add(media_id)
            items.append({"type": "image", "value": str(derivative)})
        for text_item, media_id in text_rows:
            items.append(text_item)
            if (
                media_id
                and media_id not in seen_images
                and len(seen_images) < image_limit
            ):
                derivative = self._thumbnail_path(runtime, media_id)
                seen_images.add(media_id)
                items.append({"type": "image", "value": str(derivative)})
        self._last_query_meta_local.value = {
            "adapter": MEMORY_TYPE,
            "adapter_version": ADAPTER_VERSION,
            "benchmark_namespace": self._namespace,
            "result_count": int(envelope.get("result_count") or 0),
            "query_truncated": query_truncated,
            "query_invocation_id": self.get_query_context().get("query_invocation_id"),
            "vision": dict(self._vision_status),
            "query_image": query_image_meta,
            "release_after_query": self._release_after_query,
            "released_after_query": False,
            "release_state": "pending-post-query-hook"
            if self._release_after_query
            else "not-requested",
            "official_score_claimed": False,
        }
        return items

    def post_query_hook(
        self,
        *,
        query: str,
        query_image: str | None,
        memory_context: list[MemoryContextItem],
    ) -> dict[str, object] | None:
        meta = getattr(self._last_query_meta_local, "value", None)
        if isinstance(meta, dict):
            result = dict(meta)
            if self._release_after_query:
                has_image_context = any(
                    isinstance(item, dict) and item.get("type") == "image"
                    for item in memory_context
                )
                if has_image_context:
                    # The pinned harness consumes image paths only *after*
                    # this hook.  Its wrapper-owned per-question finally guard
                    # closes this instance after prompt construction, keeping
                    # the derivatives available for tokenization/data-URL
                    # conversion and still guaranteeing deterministic cleanup.
                    result["released_after_query"] = False
                    result["release_state"] = "deferred-for-image-consumption"
                else:
                    self.close()
                    result["released_after_query"] = True
                    result["release_state"] = "closed-by-post-query-hook"
            return result
        return None

    # -- save / load ------------------------------------------------------------

    def save_memory(self, output_dir: str | Path) -> None:
        """Validate and create a fresh sealed destination before base writes.

        The pinned base class creates and writes ``memory_config.json`` before
        calling ``_save_backend``.  Performing the confinement gate only in
        ``_save_backend`` would therefore be too late.
        """

        require(not self._closed, "memory instance is closed")
        destination, safe_root = _create_private_directory(
            Path(output_dir), owner="artifact destination"
        )
        try:
            super().save_memory(destination)
        except BaseException:
            if os.path.lexists(destination):
                _remove_disposable_tree(
                    destination,
                    safe_root=safe_root,
                    owner="failed artifact cleanup",
                )
            raise

    @classmethod
    def reconcile_loaded_memory_config(cls, saved_config, requested_config):
        """Require an exact public config plus an out-of-band manifest pin."""

        require(
            saved_config["memory_type"] == cls.memory_type,
            "Saved memory config type does not match synapse_s2",
        )
        saved_params = dict(saved_config["memory_params"])
        require(
            set(saved_params) == set(PUBLIC_PARAM_KEYS),
            "sealed artifact memory config must carry exactly the fixed "
            f"public schema fields {sorted(PUBLIC_PARAM_KEYS)}",
        )
        require(
            requested_config is not None,
            "synapse_s2 load requires a caller-supplied requested config with an "
            "out-of-band artifact manifest digest",
        )
        assert requested_config is not None
        require(
            requested_config["memory_type"] == cls.memory_type,
            "Requested memory config type does not match synapse_s2",
        )
        requested_params = dict(requested_config["memory_params"])
        expected_digest = requested_params.pop(EXPECTED_MANIFEST_SHA256_PARAM, None)
        release_after_query = requested_params.pop(RELEASE_AFTER_QUERY_PARAM, False)
        require(
            isinstance(expected_digest, str)
            and _ANY_HEX64_PATTERN.fullmatch(expected_digest) is not None,
            "synapse_s2 load requires expected_artifact_manifest_sha256 as a "
            "64-digit caller-supplied hex digest",
        )
        require(
            type(release_after_query) is bool,
            "synapse_s2 load release_after_query must be a boolean",
        )
        require(
            set(requested_params) == set(PUBLIC_PARAM_KEYS)
            and requested_params == saved_params,
            "synapse_s2 requested public memory config must exactly match the "
            "sealed public memory config",
        )
        effective = {
            **saved_params,
            EXPECTED_MANIFEST_SHA256_PARAM: expected_digest.lower(),
            RELEASE_AFTER_QUERY_PARAM: release_after_query,
        }
        return json.loads(
            json.dumps({"memory_type": cls.memory_type, "memory_params": effective})
        )

    def _save_backend(self, output_dir: Path) -> None:
        runtime = self._runtime
        require(runtime is not None, "save requires a built memory store")
        assert runtime is not None
        output_dir = Path(output_dir)
        try:
            _bootstrap.require_within_active_run_root(
                output_dir, owner="artifact directory"
            )
        except _bootstrap.BootstrapError as exc:
            raise RuntimeError(
                "artifact directory failed disposable path validation"
            ) from exc
        _require_owner_private_directory(output_dir, owner="artifact directory")
        manifest_path = output_dir / MANIFEST_NAME
        require(
            not os.path.lexists(manifest_path),
            "refusing to overwrite an existing sealed artifact",
        )
        existing_names = {entry.name for entry in output_dir.iterdir()}
        require(
            existing_names <= {MEMORY_CONFIG_NAME},
            f"refusing to seal into a non-empty directory: {sorted(existing_names)}",
        )
        os.chmod(output_dir, 0o700)

        self._validate_ledger(self._ledger)

        # Bind the persisted public memory config exactly as written.
        config_path = output_dir / MEMORY_CONFIG_NAME
        config_bytes = _read_regular_file_bytes(
            config_path,
            owner="persisted memory config",
            maximum_bytes=MAX_MEMORY_CONFIG_FILE_BYTES,
        )
        require(
            config_bytes
            == (
                json.dumps(self.memory_config, indent=2, ensure_ascii=True) + "\n"
            ).encode("utf-8"),
            "persisted memory config does not match the public memory config",
        )
        os.chmod(config_path, 0o600)

        files: dict[str, dict[str, Any]] = {
            MEMORY_CONFIG_NAME: {
                "sha256": _sha256_hex(config_bytes),
                "bytes": len(config_bytes),
            }
        }

        store_dir = output_dir / STORE_DIR_NAME
        store_dir.mkdir(mode=0o700)
        db_path = Path(runtime.backend.memory_store.db_path)
        target_db = output_dir / STORE_FILE_RELATIVE
        require(not target_db.exists(), "artifact store file already exists")
        source_connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            target_connection = sqlite3.connect(target_db)
            try:
                source_connection.backup(target_connection)
                target_connection.commit()
                target_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                journal_mode = target_connection.execute(
                    "PRAGMA journal_mode=DELETE"
                ).fetchone()
                require(
                    journal_mode is not None
                    and str(journal_mode[0]).lower() == "delete",
                    "sealed store could not be normalized to a single SQLite file",
                )
                quick = target_connection.execute("PRAGMA quick_check").fetchone()
                require(
                    quick is not None and quick[0] == "ok",
                    "sealed store failed the SQLite quick check",
                )
            finally:
                target_connection.close()
        finally:
            source_connection.close()
        for residue in (f"{target_db}-wal", f"{target_db}-shm", f"{target_db}-journal"):
            residue_path = Path(residue)
            if os.path.lexists(residue_path):
                residue_stat = os.lstat(residue_path)
                require(
                    stat.S_ISREG(residue_stat.st_mode)
                    and residue_stat.st_nlink == 1
                    and (
                        residue_path.name.endswith("-shm")
                        or residue_stat.st_size == 0
                    ),
                    "sealed store produced an unsafe SQLite sidecar",
                )
                residue_path.unlink()
            require(
                not os.path.lexists(residue_path),
                "sealed store retained a SQLite sidecar",
            )
        os.chmod(target_db, 0o600)
        self._validate_restored_store(
            target_db,
            self._ledger,
            expected_schema_digest=_sqlite_schema_digest(db_path),
        )
        store_digest, store_size = _stream_regular_file(
            target_db,
            owner="artifact store file",
            maximum_bytes=MAX_STORE_FILE_BYTES,
        )
        files[STORE_FILE_RELATIVE] = {"sha256": store_digest, "bytes": store_size}

        media_entries = {
            str(media["media_id"]): media
            for record in self._ledger["trajectories"].values()
            for media in record["media"]
        }
        referenced_media = sorted(media_entries)
        require(
            len(referenced_media) <= MAX_MEDIA_CACHE_OBJECTS,
            "artifact media count exceeds the fixed cache object bound",
        )
        media_reader_type = _synapse()["image_capture"].MediaObjectReader
        if referenced_media:
            _create_private_directory(
                output_dir / MEDIA_CACHE_DIR_NAME,
                owner="sealed private media cache",
            )
            _create_private_directory(
                output_dir / MEDIA_CACHE_OBJECTS_RELATIVE,
                owner="sealed private media object inventory",
            )
        artifact_media_reader = media_reader_type(
            output_dir / MEDIA_CACHE_DIR_NAME
        )
        for media_id in referenced_media:
            media = media_entries[media_id]
            cache_manifest, cache_artifacts = (
                runtime.cache.reader.read_object_artifacts(media_id)
            )
            _require_media_object_binding(
                manifest=cache_manifest,
                artifacts=cache_artifacts,
                media=media,
            )
            source = runtime.derivatives_dir / f"{media_id}.jpg"
            relative = f"{DERIVATIVES_DIR_NAME}/{media_id}.jpg"
            files[relative] = _stream_copy_private(
                source,
                output_dir / relative,
                owner="thumbnail derivative",
                maximum_bytes=self._image["max_thumbnail_bytes"],
            )
            require(
                files[relative]["sha256"] == media["thumbnail_sha256"]
                and files[relative]["bytes"] == media["thumbnail_bytes"]
                and cache_artifacts["thumbnail.jpg"]
                == _read_regular_file_bytes(
                    output_dir / relative,
                    owner="sealed thumbnail derivative",
                    maximum_bytes=self._image["max_thumbnail_bytes"],
                ),
                "thumbnail derivative does not bind to its private media object",
            )
            for filename in sorted(cache_artifacts):
                cache_relative = _media_cache_relative(media_id, filename)
                payload = cache_artifacts[filename]
                require(
                    0 < len(payload) <= _artifact_file_limit(cache_relative),
                    "private media object file exceeds its fixed byte bound",
                )
                _write_private_file(output_dir / cache_relative, payload)
                files[cache_relative] = {
                    "sha256": _sha256_hex(payload),
                    "bytes": len(payload),
                }
            sealed_manifest, sealed_artifacts = (
                artifact_media_reader.read_object_artifacts(media_id)
            )
            require(
                sealed_manifest == cache_manifest
                and sealed_artifacts == cache_artifacts,
                "private media object changed while being sealed",
            )
            _require_media_object_binding(
                manifest=sealed_manifest,
                artifacts=sealed_artifacts,
                media=media,
            )

        ledger_bytes = _canonical_json_bytes(self._ledger)
        _write_private_file(output_dir / LEDGER_NAME, ledger_bytes)
        files[LEDGER_NAME] = {
            "sha256": _sha256_hex(ledger_bytes),
            "bytes": len(ledger_bytes),
        }

        source_manifest = executable_source_manifest()
        manifest = {
            "schema": ARTIFACT_SCHEMA,
            "artifact_version": ARTIFACT_VERSION,
            "memory_type": MEMORY_TYPE,
            "adapter_version": ADAPTER_VERSION,
            "official_commit_pin": _bootstrap.OFFICIAL_COMMIT,
            "memory_config": self.memory_config,
            "trajectory_count": len(self._ledger["trajectories"]),
            "media_count": len(referenced_media),
            "next_ordinal": int(self._ledger["next_ordinal"]),
            "files": files,
            "source_manifest": source_manifest,
            "source_build_id": executable_source_build_id(source_manifest),
            "credentials_included": False,
            "official_score_claimed": False,
            "notes": ARTIFACT_NOTES,
        }
        manifest_bytes = _canonical_json_bytes(manifest)
        _write_private_file(manifest_path, manifest_bytes)

        observed_files, observed_directories = self._scan_artifact_tree(output_dir)
        expected_files = set(files) | {MANIFEST_NAME}
        expected_directories = {
            parent.as_posix()
            for relative in expected_files
            for parent in Path(relative).parents
            if parent.as_posix() != "."
        }
        require(
            observed_files == expected_files
            and observed_directories == expected_directories,
            "sealed artifact inventory changed during publication",
        )

    @staticmethod
    def _scan_artifact_tree(root: Path) -> tuple[set[str], set[str]]:
        """Exact lstat walk: only owner-private regular files and directories."""

        uid = os.getuid()
        root_stat = os.lstat(root)
        require(stat.S_ISDIR(root_stat.st_mode), "artifact root must be a directory")
        require(
            stat.S_IMODE(root_stat.st_mode) == 0o700 and root_stat.st_uid == uid,
            "artifact root must be an owner-private 0700 directory",
        )
        files: set[str] = set()
        directories: set[str] = set()
        stack: list[Path] = [root]
        while stack:
            current = stack.pop()
            with os.scandir(current) as entries:
                for entry in entries:
                    entry_path = Path(entry.path)
                    entry_stat = os.lstat(entry_path)
                    relative = entry_path.relative_to(root).as_posix()
                    require(
                        not stat.S_ISLNK(entry_stat.st_mode),
                        f"artifact contains a symlink: {relative}",
                    )
                    if stat.S_ISDIR(entry_stat.st_mode):
                        require(
                            stat.S_IMODE(entry_stat.st_mode) == 0o700
                            and entry_stat.st_uid == uid,
                            f"artifact directory must be owner-private 0700: {relative}",
                        )
                        directories.add(relative)
                        stack.append(entry_path)
                        continue
                    require(
                        stat.S_ISREG(entry_stat.st_mode),
                        f"artifact contains a non-regular file: {relative}",
                    )
                    require(
                        entry_stat.st_nlink == 1,
                        f"artifact contains a hardlinked file: {relative}",
                    )
                    require(
                        stat.S_IMODE(entry_stat.st_mode) == 0o600
                        and entry_stat.st_uid == uid,
                        f"artifact file must be owner-private 0600: {relative}",
                    )
                    files.add(relative)
        return files, directories

    def _validate_restored_store(
        self,
        db_path: Path,
        ledger: dict[str, Any],
        *,
        expected_schema_digest: str,
    ) -> None:
        """Stream integrity and prove ledger plus retrieval-bearing semantics."""

        require(
            _sqlite_schema_digest(db_path, immutable=True) == expected_schema_digest,
            "restored store schema does not match this executable build",
        )
        expected_columns = [
            "memory_id",
            "tag",
            "context_id",
            "source_text",
            "metadata_json",
            "embedding_dimensions",
            "spike_indices_json",
            "neuron_indices_json",
            "created_at",
            "updated_at",
        ]
        expected_rows: dict[str, tuple[str, int, dict[int, dict[str, Any]], dict[str, Any]]] = {}
        for trajectory_id, record in ledger["trajectories"].items():
            media_by_state = {
                int(media["state_index"]): media for media in record["media"]
            }
            for state_index, memory_id in enumerate(record["memory_ids"]):
                tag = f"lmv2:{trajectory_id}:{state_index:04d}"
                stable_id = "s2_" + hashlib.sha256(
                    f"{self._namespace}\x1f{tag}".encode("utf-8")
                ).hexdigest()[:32]
                require(
                    memory_id == stable_id and memory_id not in expected_rows,
                    "sealed ledger contains an invalid or duplicate memory binding",
                )
                expected_rows[memory_id] = (
                    trajectory_id,
                    state_index,
                    media_by_state,
                    record,
                )
        require(
            len(expected_rows) == int(ledger["next_ordinal"]),
            "sealed ledger memory count is internally inconsistent",
        )

        connection = sqlite3.connect(
            f"file:{db_path}?mode=ro&immutable=1", uri=True
        )
        try:
            connection.execute("PRAGMA query_only = ON")
            for pragma in ("quick_check", "integrity_check"):
                _stream_sqlite_integrity(connection, pragma)
            foreign_key_count = 0
            for _row in connection.execute("PRAGMA foreign_key_check"):
                foreign_key_count += 1
                require(False, "restored store failed the SQLite foreign_key_check")
            require(
                foreign_key_count == 0,
                "restored store failed the SQLite foreign_key_check",
            )

            tables: list[str] = []
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            ):
                require(
                    len(tables) < MAX_SQLITE_SCHEMA_OBJECTS,
                    "restored store table count exceeds the fixed bound",
                )
                tables.append(str(row[0]))
            require(
                {"memory_entries", "memory_spikes", "memory_surface_terms", "memory_events"}
                <= set(tables),
                "restored store is missing retrieval-bearing tables",
            )
            observed_columns = [
                str(row[1])
                for row in connection.execute("PRAGMA table_info(memory_entries)")
            ]
            require(
                observed_columns == expected_columns,
                "restored store memory_entries schema does not match this build",
            )
            for table in tables:
                require(
                    _SQL_NAME_PATTERN.fullmatch(table) is not None,
                    "restored store contains an invalid table name",
                )
                columns = {
                    str(row[1])
                    for row in connection.execute(f'PRAGMA table_info("{table}")')
                }
                for column in sorted(columns & _CONTEXT_COLUMNS):
                    for context_row in connection.execute(
                        f'SELECT DISTINCT "{column}" FROM "{table}"'
                    ):
                        require(
                            context_row[0] in (None, self._namespace),
                            "restored store contains a foreign namespace",
                        )

            row_count = 0
            row_cursor = connection.execute(
                "SELECT memory_id, tag, context_id, source_text, metadata_json, "
                "embedding_dimensions, spike_indices_json, neuron_indices_json, "
                "created_at, updated_at FROM memory_entries ORDER BY memory_id"
            )
            for row in row_cursor:
                row_count += 1
                require(
                    row_count <= int(ledger["next_ordinal"]),
                    "restored store contains rows not present in the sealed ledger",
                )
                memory_id = str(row[0])
                expected = expected_rows.pop(memory_id, None)
                require(
                    expected is not None,
                    "restored store row is not present in the sealed ledger",
                )
                assert expected is not None
                trajectory_id, state_index, media_by_state, record = expected
                tag = f"lmv2:{trajectory_id}:{state_index:04d}"
                require(
                    str(row[1]) == tag and str(row[2]) == self._namespace,
                    "restored store row does not bind to its ledger identity",
                )

                source_text = row[3]
                require(
                    isinstance(source_text, str)
                    and bool(source_text.strip())
                    and len(source_text.encode("utf-8"))
                    <= int(self._insert["max_state_text_bytes"]),
                    "restored store source text violates the bounded text contract",
                )
                sanitized_source, sanitized_truncated = _sanitize_bounded(
                    source_text, int(self._insert["max_state_text_bytes"])
                )
                require(
                    not sanitized_truncated and sanitized_source == source_text,
                    "restored store source text is not fully sanitized",
                )

                metadata_raw = row[4]
                try:
                    metadata = json.loads(str(metadata_raw))
                except (TypeError, ValueError):
                    metadata = None
                require(
                    isinstance(metadata, dict),
                    "restored store metadata is malformed",
                )
                assert isinstance(metadata, dict)
                expected_metadata_keys = set(_STORE_METADATA_KEYS)
                if state_index in media_by_state:
                    expected_metadata_keys.update(
                        {"media_id", "media_object_sha256"}
                    )
                require(
                    set(metadata) == expected_metadata_keys,
                    "restored store metadata does not match the fixed schema",
                )
                require(
                    str(metadata_raw)
                    == json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                    "restored store metadata is not canonical",
                )
                require(
                    metadata.get("trajectory_id") == trajectory_id
                    and metadata.get("state_index") == state_index
                    and metadata.get("trajectory_binding") == record["fingerprint"]
                    and metadata.get("benchmark_namespace") == self._namespace
                    and metadata.get("source")
                    == "longmem-v2-official-trajectory"
                    and metadata.get("embedding_provider")
                    == self._backend_config["embedding_provider"]
                    and metadata.get("adapter_version") == ADAPTER_VERSION,
                    "restored store metadata does not bind to the sealed ledger",
                )
                require(
                    metadata.get("display_label")
                    == f"{trajectory_id} state {state_index}"
                    and metadata.get("display_summary") == source_text[:240]
                    and metadata.get("display_excerpt") == source_text
                    and isinstance(metadata.get("state_url"), str)
                    and len(str(metadata["state_url"]).encode("utf-8"))
                    <= MAX_URL_METADATA_BYTES
                    and type(metadata.get("text_truncated")) is bool,
                    "restored store display metadata is inconsistent",
                )
                if state_index in media_by_state:
                    require(
                        metadata.get("memory_type") == "image"
                        and metadata.get("media_id")
                        == media_by_state[state_index]["media_id"]
                        and metadata.get("media_object_sha256")
                        == media_by_state[state_index]["media_object_sha256"],
                        "restored store media binding is inconsistent",
                    )
                else:
                    require(
                        metadata.get("memory_type") == "text",
                        "restored store text row has an invalid memory type",
                    )

                dimensions = row[5]
                require(
                    type(dimensions) is int
                    and dimensions == int(self._backend_config["dimension"]),
                    "restored store embedding dimensions do not match this build",
                )
                try:
                    spike_indices = json.loads(str(row[6]))
                    neuron_indices = json.loads(str(row[7]))
                except ValueError:
                    spike_indices = None
                    neuron_indices = None
                expected_spike_count = min(
                    int(self._backend_config["default_top_k"]), int(dimensions)
                )
                require(
                    isinstance(spike_indices, list)
                    and len(spike_indices) == expected_spike_count
                    and all(type(value) is int for value in spike_indices)
                    and spike_indices == sorted(set(spike_indices))
                    and all(0 <= value < int(dimensions) for value in spike_indices)
                    and neuron_indices == [],
                    "restored store retrieval coordinates are malformed",
                )
                indexed_spikes = [
                    int(spike_row[0])
                    for spike_row in connection.execute(
                        "SELECT spike_index FROM memory_spikes "
                        "WHERE memory_id = ? AND context_id = ? ORDER BY spike_index",
                        (memory_id, self._namespace),
                    )
                ]
                require(
                    indexed_spikes == spike_indices,
                    "restored store spike index does not bind to the entry",
                )
                surface_count = 0
                for surface_row in connection.execute(
                    "SELECT context_id, term, weight FROM memory_surface_terms "
                    "WHERE memory_id = ? ORDER BY term",
                    (memory_id,),
                ):
                    surface_count += 1
                    require(
                        surface_count <= 512
                        and surface_row[0] == self._namespace
                        and isinstance(surface_row[1], str)
                        and bool(surface_row[1])
                        and math.isfinite(float(surface_row[2]))
                        and float(surface_row[2]) > 0.0,
                        "restored store surface index is malformed",
                    )
                require(
                    surface_count > 0,
                    "restored store entry is not surface-retrieval-bearing",
                )

                event_cursor = iter(
                    connection.execute(
                        "SELECT event_type, payload_json, created_at FROM memory_events "
                        "WHERE memory_id = ? ORDER BY event_id LIMIT 2",
                        (memory_id,),
                    )
                )
                event_row = next(event_cursor, None)
                require(
                    event_row is not None
                    and event_row[0] == "upsert"
                    and next(event_cursor, None) is None,
                    "restored store ledger event binding is invalid",
                )
                assert event_row is not None
                try:
                    event_payload = json.loads(str(event_row[1]))
                except ValueError:
                    event_payload = None
                require(
                    event_payload
                    == {
                        "tag": tag,
                        "context_id": self._namespace,
                        "embedding_dimensions": int(dimensions),
                        "spike_count": len(spike_indices),
                    },
                    "restored store ledger event payload is inconsistent",
                )

                expected_created = FIXED_EPOCH + float(
                    int(record["ordinal_start"]) + state_index
                )
                require(
                    math.isfinite(float(row[8]))
                    and math.isfinite(float(row[9]))
                    and abs(float(row[8]) - expected_created) < 1e-6
                    and abs(float(row[9]) - expected_created) < 1e-6
                    and abs(float(event_row[2]) - expected_created) < 1e-6,
                    "restored store ordinal timestamps do not bind to the ledger",
                )
        finally:
            connection.close()

        require(
            row_count == int(ledger["next_ordinal"]) and not expected_rows,
            "restored store entry count does not match the sealed ledger",
        )

    def _load_backend(self, input_dir: Path) -> None:
        require(not self._closed, "memory instance is closed")
        require(self._runtime is None, "load requires an unbuilt memory instance")
        _active_run_root(owner="artifact restore")
        require(
            self._expected_artifact_manifest_sha256 is not None,
            "artifact restore requires a caller-supplied out-of-band manifest digest",
        )
        input_dir = Path(input_dir)
        try:
            input_dir = _bootstrap.require_disposable_root(
                input_dir, owner="artifact directory"
            )
        except _bootstrap.BootstrapError as exc:
            raise RuntimeError("artifact directory failed path safety validation") from exc

        manifest_raw = _read_regular_file_bytes(
            input_dir / MANIFEST_NAME,
            owner="artifact manifest",
            maximum_bytes=MAX_MANIFEST_FILE_BYTES,
        )
        require(
            secrets.compare_digest(
                _sha256_hex(manifest_raw),
                self._expected_artifact_manifest_sha256,
            ),
            "artifact manifest does not match the caller-supplied digest",
        )
        try:
            manifest = json.loads(manifest_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("artifact manifest is not canonical UTF-8 JSON") from exc
        require(isinstance(manifest, dict), "artifact manifest must be an object")
        require(
            set(manifest) == _MANIFEST_KEYS,
            "artifact manifest does not match the fixed public schema",
        )
        require(
            _canonical_json_bytes(manifest) == manifest_raw,
            "artifact manifest is not in canonical form",
        )
        require(
            manifest.get("schema") == ARTIFACT_SCHEMA
            and manifest.get("artifact_version") == ARTIFACT_VERSION
            and manifest.get("memory_type") == MEMORY_TYPE,
            "artifact schema, version, or memory type mismatch",
        )
        require(
            type(manifest.get("trajectory_count")) is int
            and 0 <= manifest["trajectory_count"] <= MAX_TRAJECTORIES
            and type(manifest.get("media_count")) is int
            and 0 <= manifest["media_count"]
            <= MAX_TRAJECTORIES * MAX_STATES_PER_TRAJECTORY
            and type(manifest.get("next_ordinal")) is int
            and 0 <= manifest["next_ordinal"]
            <= MAX_TRAJECTORIES * MAX_STATES_PER_TRAJECTORY,
            "artifact manifest counts are malformed",
        )
        require(
            manifest.get("adapter_version") == ADAPTER_VERSION,
            "artifact adapter_version does not match this adapter build",
        )
        require(
            manifest.get("official_commit_pin") == _bootstrap.OFFICIAL_COMMIT,
            "artifact official commit pin does not match this adapter build",
        )
        require(
            manifest.get("credentials_included") is False,
            "artifact must not carry credentials",
        )
        require(
            manifest.get("official_score_claimed") is False
            and manifest.get("notes") == ARTIFACT_NOTES,
            "artifact public posture does not match this adapter build",
        )
        current_source_manifest = executable_source_manifest()
        source_manifest = manifest.get("source_manifest")
        require(
            isinstance(source_manifest, dict)
            and set(source_manifest) == set(current_source_manifest)
            and all(
                isinstance(entry, dict)
                and set(entry) == _SOURCE_MANIFEST_ENTRY_KEYS
                for entry in source_manifest.values()
            ),
            "artifact executable source manifest schema is invalid",
        )
        require(
            source_manifest == current_source_manifest
            and manifest.get("source_build_id")
            == executable_source_build_id(current_source_manifest),
            "artifact executable source manifest does not match the current "
            "runtime sources",
        )
        saved_public = manifest.get("memory_config")
        require(
            isinstance(saved_public, dict)
            and set(saved_public) == {"memory_type", "memory_params"}
            and saved_public.get("memory_type") == MEMORY_TYPE
            and isinstance(saved_public.get("memory_params"), dict)
            and set(saved_public["memory_params"]) == set(PUBLIC_PARAM_KEYS),
            "artifact manifest memory config must carry exactly the fixed "
            "public schema fields",
        )
        require(
            saved_public == self.memory_config,
            "artifact public memory config does not match this instance",
        )

        files = manifest.get("files")
        require(isinstance(files, dict) and files, "artifact manifest files missing")
        for relative, expected in files.items():
            require(
                isinstance(relative, str)
                and _RELATIVE_FILE_PATTERN.fullmatch(relative) is not None
                and ".." not in Path(relative).parts,
                f"artifact manifest file path is unsafe: {relative!r}",
            )
            require(
                isinstance(expected, dict)
                and set(expected) == {"sha256", "bytes"}
                and isinstance(expected.get("sha256"), str)
                and _HEX64_PATTERN.fullmatch(expected["sha256"]) is not None
                and type(expected.get("bytes")) is int
                and _artifact_file_limit(relative) > 0
                and 0 <= expected["bytes"] <= _artifact_file_limit(relative),
                f"artifact manifest file entry is malformed: {relative}",
            )
        for required in (MEMORY_CONFIG_NAME, LEDGER_NAME, STORE_FILE_RELATIVE):
            require(
                required in files,
                f"artifact manifest must list {required}",
            )

        observed_files, observed_directories = self._scan_artifact_tree(input_dir)
        expected_files = set(files) | {MANIFEST_NAME}
        require(
            observed_files == expected_files,
            "artifact tree does not exactly match the manifest file list: "
            f"unexpected={sorted(observed_files - expected_files)} "
            f"missing={sorted(expected_files - observed_files)}",
        )
        expected_directories = {
            parent.as_posix()
            for relative in expected_files
            for parent in Path(relative).parents
            if parent.as_posix() != "."
        }
        require(
            observed_directories == expected_directories,
            "artifact tree contains unlisted directories: "
            f"{sorted(observed_directories - expected_directories)}",
        )

        for relative, expected in files.items():
            digest, size = _stream_regular_file(
                input_dir / relative,
                owner=f"artifact file {relative}",
                maximum_bytes=_artifact_file_limit(relative),
            )
            require(
                digest == expected["sha256"] and size == expected["bytes"],
                f"artifact file failed digest verification: {relative}",
            )

        config_bytes = _read_regular_file_bytes(
            input_dir / MEMORY_CONFIG_NAME,
            owner="persisted memory config",
            maximum_bytes=MAX_MEMORY_CONFIG_FILE_BYTES,
        )
        require(
            config_bytes
            == (
                json.dumps(self.memory_config, indent=2, ensure_ascii=True) + "\n"
            ).encode("utf-8"),
            "persisted memory config does not match the manifest binding",
        )

        ledger_bytes = _read_regular_file_bytes(
            input_dir / LEDGER_NAME,
            owner="artifact insert ledger",
            maximum_bytes=MAX_LEDGER_FILE_BYTES,
        )
        ledger = json.loads(ledger_bytes.decode("utf-8"))
        ledger = self._validate_ledger(ledger)
        require(
            _canonical_json_bytes(ledger) == ledger_bytes,
            "artifact insert ledger is not in canonical form",
        )
        require(
            manifest.get("trajectory_count") == len(ledger["trajectories"])
            and manifest.get("next_ordinal") == ledger["next_ordinal"],
            "artifact manifest counts do not match the insert ledger",
        )
        media_entries: dict[str, dict[str, Any]] = {}
        loaded_media_index: dict[str, dict[str, Any]] = {}
        for trajectory_id, record in ledger["trajectories"].items():
            for media in record["media"]:
                media_id = str(media["media_id"])
                state_index = int(media["state_index"])
                media_entries[media_id] = media
                loaded_media_index[media_id] = {
                    "trajectory_id": trajectory_id,
                    "state_index": state_index,
                    "memory_id": str(record["memory_ids"][state_index]),
                    "thumbnail_sha256": str(media["thumbnail_sha256"]),
                    "thumbnail_bytes": int(media["thumbnail_bytes"]),
                    "media_object_sha256": str(media["media_object_sha256"]),
                }
        require(
            manifest.get("media_count") == len(media_entries),
            "artifact manifest media count does not match the insert ledger",
        )
        require(
            len(media_entries) <= MAX_MEDIA_CACHE_OBJECTS,
            "artifact media count exceeds the fixed cache object bound",
        )
        media_reader_type = _synapse()["image_capture"].MediaObjectReader
        artifact_media_reader = media_reader_type(
            input_dir / MEDIA_CACHE_DIR_NAME
        )
        require(
            artifact_media_reader.object_ids() == sorted(media_entries),
            "artifact private media object inventory does not match the ledger",
        )
        cache_object_files: set[str] = set()
        for media_id, media in media_entries.items():
            cache_manifest, cache_artifacts = (
                artifact_media_reader.read_object_artifacts(media_id)
            )
            _require_media_object_binding(
                manifest=cache_manifest,
                artifacts=cache_artifacts,
                media=media,
            )
            cache_object_files.update(
                _media_cache_relative(media_id, filename)
                for filename in cache_artifacts
            )
        expected_from_ledger = (
            {MEMORY_CONFIG_NAME, LEDGER_NAME, STORE_FILE_RELATIVE}
            | {
                f"{DERIVATIVES_DIR_NAME}/{media_id}.jpg"
                for media_id in media_entries
            }
            | cache_object_files
        )
        require(
            set(files) == expected_from_ledger,
            "artifact manifest file list does not match the exact ledger media inventory",
        )
        for media_id, media in media_entries.items():
            listed = files[f"{DERIVATIVES_DIR_NAME}/{media_id}.jpg"]
            require(
                listed["sha256"] == media["thumbnail_sha256"]
                and listed["bytes"] == media["thumbnail_bytes"],
                f"artifact media derivative does not bind to the ledger: {media_id}",
            )

        runtime = self._build_runtime()
        try:
            # Restore into the fresh disposable runtime only after all public
            # artifact controls have been verified.  Capture the empty store's
            # executable-build schema before replacement.
            db_path = Path(runtime.backend.memory_store.db_path)
            expected_schema_digest = _sqlite_schema_digest(db_path)
            runtime.backend.memory_store.close()
            for residue in (f"{db_path}-wal", f"{db_path}-shm", f"{db_path}-journal"):
                Path(residue).unlink(missing_ok=True)
            copied = _stream_copy_private(
                input_dir / STORE_FILE_RELATIVE,
                db_path,
                owner="artifact store file",
                maximum_bytes=MAX_STORE_FILE_BYTES,
            )
            require(
                copied["sha256"] == files[STORE_FILE_RELATIVE]["sha256"],
                "artifact store file changed during restore",
            )
            self._validate_restored_store(
                db_path,
                ledger,
                expected_schema_digest=expected_schema_digest,
            )
            modules = _synapse()
            try:
                backend = modules["mlx_backend"].SpikingAttentionBackend(
                    dimension=self._backend_config["dimension"],
                    num_neurons=self._backend_config["num_neurons"],
                    default_top_k=self._backend_config["default_top_k"],
                    recall_count=self._backend_config["recall_count"],
                    compile_graph=False,
                    state_path=db_path.parent / "runtime_state.json",
                    embedding_provider_name=self._backend_config["embedding_provider"],
                )
            except Exception as exc:
                raise RuntimeError("backend restore failed") from exc
            runtime.backend = backend
            runtime.adapter = modules["longmem_eval"].LongMemInsertQueryAdapter(backend)
            for media_id in media_entries:
                relative = f"{DERIVATIVES_DIR_NAME}/{media_id}.jpg"
                copied_derivative = _stream_copy_private(
                    input_dir / relative,
                    runtime.derivatives_dir / f"{media_id}.jpg",
                    owner=f"artifact media derivative {media_id}",
                    maximum_bytes=self._image["max_thumbnail_bytes"],
                )
                require(
                    copied_derivative == files[relative],
                    "artifact media derivative changed during restore",
                )
            if media_entries:
                runtime.cache._prepare_cache()
            for media_id, media in media_entries.items():
                cache_manifest, cache_artifacts = (
                    artifact_media_reader.read_object_artifacts(media_id)
                )
                _require_media_object_binding(
                    manifest=cache_manifest,
                    artifacts=cache_artifacts,
                    media=media,
                )
                object_root = runtime.cache.objects_root / media_id
                require(
                    object_root.parent == runtime.cache.objects_root
                    and not os.path.lexists(object_root),
                    "restored private media object is not a fresh canonical child",
                )
                _require_owner_private_directory(
                    runtime.cache.objects_root,
                    owner="restored private media object parent",
                )
                os.mkdir(object_root, mode=0o700)
                os.chmod(object_root, 0o700)
                _require_owner_private_directory(
                    object_root,
                    owner="restored private media object",
                )
                for filename in sorted(cache_artifacts):
                    _write_private_file(
                        object_root / filename,
                        cache_artifacts[filename],
                    )
                restored_manifest, restored_artifacts = (
                    runtime.cache.reader.read_object_artifacts(media_id)
                )
                require(
                    restored_manifest == cache_manifest
                    and restored_artifacts == cache_artifacts,
                    "private media object changed during restore",
                )
                _require_media_object_binding(
                    manifest=restored_manifest,
                    artifacts=restored_artifacts,
                    media=media,
                )
            if media_entries:
                require(
                    runtime.cache.reader.object_ids() == sorted(media_entries),
                    "restored private media object inventory changed",
                )
            self._ledger = ledger
            self._media_reference_index = loaded_media_index
            self._content_identities.clear()
            self._persist_ledger(runtime)
        except BaseException:
            self.close()
            raise

    # -- teardown ----------------------------------------------------------------

    def close(self) -> None:
        """Deterministically close the store and remove disposable roots."""

        runtime = self._runtime
        if runtime is None:
            self._closed = True
            self._content_identities.clear()
            self._media_reference_index.clear()
            self.clear_query_context()
            return
        failures: list[BaseException] = []
        try:
            runtime.backend.memory_store.close()
        except Exception as exc:
            failures.append(exc)
        for path, owner, enabled in (
            (runtime.runtime_root, "runtime root cleanup", True),
            (runtime.workspace_dir, "memory workspace cleanup", runtime.owns_workspace),
        ):
            if not enabled or not os.path.lexists(path):
                continue
            try:
                _remove_disposable_tree(
                    path,
                    safe_root=runtime.safe_root,
                    owner=owner,
                )
            except BaseException as exc:
                failures.append(exc)
        roots_removed = not os.path.lexists(runtime.runtime_root) and (
            not runtime.owns_workspace or not os.path.lexists(runtime.workspace_dir)
        )
        if roots_removed:
            self._runtime = None
            self._closed = True
            self._content_identities.clear()
            self._media_reference_index.clear()
            self.clear_query_context()
            if hasattr(self._last_query_meta_local, "value"):
                delattr(self._last_query_meta_local, "value")
        if failures:
            raise RuntimeError("memory close could not complete deterministic cleanup") from failures[0]
        require(roots_removed, "memory close left disposable runtime residue")


def build_memory_config(
    *,
    workspace_dir: str | None = None,
    trajectories_root_dir: str | None = None,
    store_namespace: str = BENCHMARK_NAMESPACE_DEFAULT,
    backend: dict[str, Any] | None = None,
    retrieval: dict[str, Any] | None = None,
    image: dict[str, Any] | None = None,
    insert: dict[str, Any] | None = None,
    expected_artifact_manifest_sha256: str | None = None,
    release_after_query: bool | None = None,
) -> dict[str, Any]:
    """Compose the official memory-config JSON object for this memory type."""

    memory_params: dict[str, Any] = {
        "workspace_dir": workspace_dir,
        "trajectories_root_dir": trajectories_root_dir,
        "store_namespace": store_namespace,
    }
    if backend is not None:
        memory_params["backend"] = dict(backend)
    if retrieval is not None:
        memory_params["retrieval"] = dict(retrieval)
    if image is not None:
        memory_params["image"] = dict(image)
    if insert is not None:
        memory_params["insert"] = dict(insert)
    if expected_artifact_manifest_sha256 is not None:
        memory_params[EXPECTED_MANIFEST_SHA256_PARAM] = (
            expected_artifact_manifest_sha256
        )
    if release_after_query is not None:
        memory_params[RELEASE_AFTER_QUERY_PARAM] = release_after_query
    return {"memory_type": MEMORY_TYPE, "memory_params": memory_params}

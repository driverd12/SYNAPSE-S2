from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import stat
import struct
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from core_client_binding import CoreClientBinding, validate_core_client_binding


IMAGE_ARTIFACT_SCHEMA = "synapse-s2.image-artifact.v1"
VISUAL_DESCRIPTOR_SCHEMA = "synapse-s2.visual-descriptor.rgb16-v1"
MEDIA_ID_RE = re.compile(r"^s2img_[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_SOURCE_BYTES = 20 * 1024 * 1024
MAX_SOURCE_PIXELS = 100_000_000
MAX_THUMBNAIL_EDGE = 320
MAX_THUMBNAIL_BYTES = 512 * 1024
MAX_OBJECTS = 10_000
SIPS_TIMEOUT_SECONDS = 20.0

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"
_HEIC_BRANDS = frozenset({b"heic", b"heix", b"hevc", b"hevx"})
_PUBLIC_METADATA_FIELDS = frozenset(
    {
        "schema",
        "context_memory_type",
        "media_id",
        "mime_type",
        "source_dimensions",
        "thumbnail_dimensions",
        "visual_descriptor",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "media_id",
        "source_mime_type",
        "source_size_bytes",
        "source_sha256",
        "thumbnail_sha256",
        "thumbnail_size_bytes",
        "created_at",
        "public_metadata",
    }
)


class ImageCaptureError(RuntimeError):
    """A content-free failure at the local image-cache boundary."""


class ImageCaptureNotFound(ImageCaptureError):
    """The requested node-local derivative does not exist on this Mac."""


@dataclass(frozen=True)
class ConversionResult:
    source_width: int
    source_height: int
    bmp_path: Path
    thumbnail_path: Path


@dataclass(frozen=True)
class ThumbnailResult:
    media_id: str
    content_type: str
    data: bytes


Converter = Callable[[Path, Path], ConversionResult]


def new_media_id() -> str:
    return f"s2img_{secrets.token_hex(16)}"


def validate_media_id(value: Any) -> str:
    if type(value) is not str or MEDIA_ID_RE.fullmatch(value) is None:
        raise ValueError("media_id must use canonical s2img_<32 lowercase hex> format")
    return value


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_directory(path: Path, *, create: bool) -> os.stat_result:
    if create:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
    try:
        observed = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ImageCaptureError("private image cache is unavailable") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        raise ImageCaptureError("private image cache directory is unsafe")
    return observed


def _private_regular(
    path: Path,
    *,
    maximum_bytes: int,
    allow_empty: bool = False,
) -> os.stat_result:
    try:
        observed = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ImageCaptureError("private image cache artifact is unavailable") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) != 0o600
        or (observed.st_size <= 0 and not allow_empty)
        or observed.st_size > maximum_bytes
    ):
        raise ImageCaptureError("private image cache artifact is unsafe")
    return observed


def _read_private_regular(path: Path, *, maximum_bytes: int) -> bytes:
    observed = _private_regular(path, maximum_bytes=maximum_bytes)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise ImageCaptureError("private image cache artifact changed during open")
        chunks: list[bytes] = []
        remaining = int(opened.st_size)
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        current = path.lstat()
        if (
            len(data) != int(opened.st_size)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or current.st_size != opened.st_size
        ):
            raise ImageCaptureError("private image cache artifact changed during read")
        return data
    finally:
        os.close(descriptor)


def _write_private_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise ImageCaptureError("private image cache write made no progress")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _normal_source_path(value: str | os.PathLike[str]) -> Path:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValueError("image source path must be a normal absolute path")
    candidate = Path(raw)
    normalized = Path(os.path.normpath(str(candidate)))
    if (
        not candidate.is_absolute()
        or candidate != normalized
        or ".." in candidate.parts
        or candidate == Path(candidate.anchor)
    ):
        raise ValueError("image source path must be a normal absolute path")
    return candidate


def _source_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


@contextmanager
def _open_source(path: Path) -> Iterator[tuple[int, os.stat_result]]:
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        root_fd = os.open(path.anchor or os.sep, directory_flags)
    except OSError as exc:
        raise ValueError("image source ancestor must be a real directory") from exc
    parent_fd = root_fd
    descriptor = -1
    try:
        for component in path.parent.parts[1:]:
            try:
                next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            except OSError as exc:
                raise ValueError("image source ancestor must be a real directory") from exc
            opened_parent = os.fstat(next_fd)
            if not stat.S_ISDIR(opened_parent.st_mode):
                os.close(next_fd)
                raise ValueError("image source ancestor must be a real directory")
            if parent_fd != root_fd:
                os.close(parent_fd)
            parent_fd = next_fd
        try:
            observed = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise ValueError("image source is unavailable") from exc
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or not (stat.S_IMODE(observed.st_mode) & stat.S_IRUSR)
            or observed.st_size <= 0
            or observed.st_size > MAX_SOURCE_BYTES
        ):
            raise ValueError("image source must be an owner-readable bounded regular file")
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path.name, file_flags, dir_fd=parent_fd)
        except OSError as exc:
            raise ValueError("image source must be a real regular file") from exc
        opened = os.fstat(descriptor)
        if _source_identity(opened) != _source_identity(observed):
            raise ValueError("image source changed between validation and open")
        yield descriptor, opened
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd != root_fd:
            os.close(parent_fd)
        os.close(root_fd)


def _assert_source_unchanged(path: Path, expected: os.stat_result) -> None:
    try:
        current = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ValueError("image source changed during conversion") from exc
    if stat.S_ISLNK(current.st_mode) or _source_identity(current) != _source_identity(expected):
        raise ValueError("image source changed during conversion")


def _hash_source(descriptor: int, expected_size: int) -> tuple[str, bytes]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    prefix = b""
    remaining = int(expected_size)
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            break
        if len(prefix) < 64:
            prefix += chunk[: 64 - len(prefix)]
        digest.update(chunk)
        remaining -= len(chunk)
    if remaining != 0:
        raise ValueError("image source changed while hashing")
    return digest.hexdigest(), prefix


def _mime_from_magic(prefix: bytes) -> str:
    if prefix.startswith(_PNG_MAGIC):
        return "image/png"
    if prefix.startswith(_JPEG_MAGIC):
        return "image/jpeg"
    if len(prefix) >= 16 and prefix[4:8] == b"ftyp":
        brands = {prefix[index : index + 4] for index in range(8, len(prefix) - 3, 4)}
        if brands & _HEIC_BRANDS:
            return "image/heic"
    raise ValueError("image source format is unsupported; expected PNG, JPEG, or HEIC")


def _run_sips(arguments: list[str]) -> str:
    if not Path("/usr/bin/sips").is_file():
        raise ImageCaptureError("macOS image conversion is unavailable")
    try:
        completed = subprocess.run(
            ["/usr/bin/sips", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=SIPS_TIMEOUT_SECONDS,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ImageCaptureError("macOS image conversion failed") from exc
    if completed.returncode != 0:
        raise ImageCaptureError("macOS image conversion failed")
    return completed.stdout


def _sips_dimensions(source_path: Path) -> tuple[int, int]:
    output = _run_sips(
        [
            "-g",
            "pixelWidth",
            "-g",
            "pixelHeight",
            str(source_path),
        ]
    )
    width_match = re.search(r"(?m)^\s*pixelWidth:\s*([0-9]+)\s*$", output)
    height_match = re.search(r"(?m)^\s*pixelHeight:\s*([0-9]+)\s*$", output)
    if width_match is None or height_match is None:
        raise ImageCaptureError("macOS image dimensions are unavailable")
    width = int(width_match.group(1))
    height = int(height_match.group(1))
    if width <= 0 or height <= 0 or width * height > MAX_SOURCE_PIXELS:
        raise ValueError("image source dimensions exceed the safe limit")
    return width, height


def _sips_converter(source_path: Path, work_root: Path) -> ConversionResult:
    source_width, source_height = _sips_dimensions(source_path)
    bmp_path = work_root / "normalized.bmp"
    thumbnail_path = work_root / "thumbnail.jpg"
    _run_sips(
        [
            "-Z",
            str(MAX_THUMBNAIL_EDGE),
            "-s",
            "format",
            "bmp",
            str(source_path),
            "--out",
            str(bmp_path),
        ]
    )
    _run_sips(
        [
            "-s",
            "format",
            "jpeg",
            "-s",
            "formatOptions",
            "70",
            str(bmp_path),
            "--out",
            str(thumbnail_path),
        ]
    )
    for output in (bmp_path, thumbnail_path):
        try:
            observed = output.lstat()
        except (FileNotFoundError, OSError) as exc:
            raise ImageCaptureError("macOS image conversion did not publish output") from exc
        if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
            raise ImageCaptureError("macOS image conversion output is unsafe")
        os.chmod(output, 0o600)
    return ConversionResult(
        source_width=source_width,
        source_height=source_height,
        bmp_path=bmp_path,
        thumbnail_path=thumbnail_path,
    )


def _bmp_pixels(data: bytes) -> tuple[int, int, list[tuple[int, int, int]]]:
    if len(data) < 54 or data[:2] != b"BM":
        raise ImageCaptureError("normalized image is not a supported BMP")
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    dib_size = struct.unpack_from("<I", data, 14)[0]
    if dib_size < 40 or len(data) < 14 + dib_size:
        raise ImageCaptureError("normalized BMP header is invalid")
    width = struct.unpack_from("<i", data, 18)[0]
    signed_height = struct.unpack_from("<i", data, 22)[0]
    planes = struct.unpack_from("<H", data, 26)[0]
    bits_per_pixel = struct.unpack_from("<H", data, 28)[0]
    compression = struct.unpack_from("<I", data, 30)[0]
    if (
        width <= 0
        or signed_height == 0
        or abs(signed_height) > MAX_THUMBNAIL_EDGE
        or width > MAX_THUMBNAIL_EDGE
        or planes != 1
        or bits_per_pixel not in {24, 32}
        or compression != 0
    ):
        raise ImageCaptureError("normalized BMP format is unsupported")
    height = abs(signed_height)
    bytes_per_pixel = bits_per_pixel // 8
    row_stride = ((width * bits_per_pixel + 31) // 32) * 4
    required = pixel_offset + row_stride * height
    if pixel_offset < 14 + dib_size or required > len(data):
        raise ImageCaptureError("normalized BMP pixels are truncated")
    top_down = signed_height < 0
    pixels: list[tuple[int, int, int]] = []
    for output_y in range(height):
        source_y = output_y if top_down else height - output_y - 1
        row_offset = pixel_offset + source_y * row_stride
        for x in range(width):
            offset = row_offset + x * bytes_per_pixel
            blue, green, red = data[offset : offset + 3]
            pixels.append((red, green, blue))
    return width, height, pixels


def _cell_average(
    pixels: list[tuple[int, int, int]],
    *,
    width: int,
    height: int,
    cell_x: int,
    cell_y: int,
    cells: int,
) -> tuple[int, int, int]:
    x0 = min(width - 1, (cell_x * width) // cells)
    x1 = max(x0 + 1, ((cell_x + 1) * width) // cells)
    y0 = min(height - 1, (cell_y * height) // cells)
    y1 = max(y0 + 1, ((cell_y + 1) * height) // cells)
    red = green = blue = count = 0
    for y in range(y0, min(height, y1)):
        for x in range(x0, min(width, x1)):
            pixel = pixels[y * width + x]
            red += pixel[0]
            green += pixel[1]
            blue += pixel[2]
            count += 1
    if count <= 0:
        raise ImageCaptureError("normalized image cell is empty")
    return (
        round(red / count),
        round(green / count),
        round(blue / count),
    )


def _normalize_histogram(values: list[int]) -> bytes:
    total = sum(values)
    if total <= 0:
        return bytes(len(values))
    return bytes(min(255, round(value * 255 / total)) for value in values)


def _visual_descriptor_from_bmp(data: bytes) -> tuple[dict[str, Any], int, int]:
    width, height, pixels = _bmp_pixels(data)
    tensor = bytearray()
    cells: list[tuple[int, int, int]] = []
    for cell_y in range(16):
        for cell_x in range(16):
            pixel = _cell_average(
                pixels,
                width=width,
                height=height,
                cell_x=cell_x,
                cell_y=cell_y,
                cells=16,
            )
            cells.append(pixel)
            tensor.extend(pixel)

    channel_histograms = [[0] * 16 for _ in range(3)]
    for red, green, blue in pixels:
        for channel, value in enumerate((red, green, blue)):
            channel_histograms[channel][min(15, value // 16)] += 1
    histogram = b"".join(_normalize_histogram(values) for values in channel_histograms)

    luminance = [round(0.299 * red + 0.587 * green + 0.114 * blue) for red, green, blue in cells]
    edge_weights = [0] * 8
    for y in range(1, 15):
        for x in range(1, 15):
            dx = luminance[y * 16 + x + 1] - luminance[y * 16 + x - 1]
            dy = luminance[(y + 1) * 16 + x] - luminance[(y - 1) * 16 + x]
            magnitude = int(round(math.hypot(dx, dy)))
            if magnitude <= 0:
                continue
            angle = math.atan2(dy, dx) % math.pi
            bucket = min(7, int(angle * 8 / math.pi))
            edge_weights[bucket] += magnitude
    edge_histogram = _normalize_histogram(edge_weights)

    difference_bits = 0
    for row in range(8):
        y = round(row * 15 / 7)
        samples = [luminance[y * 16 + round(column * 15 / 8)] for column in range(9)]
        for left, right in zip(samples, samples[1:]):
            difference_bits = (difference_bits << 1) | int(left > right)

    descriptor = {
        "schema": VISUAL_DESCRIPTOR_SCHEMA,
        "tensor_shape": [16, 16, 3],
        "tensor_encoding": "base64-u8-rgb",
        "tensor_data": base64.b64encode(bytes(tensor)).decode("ascii"),
        "rgb_histogram_shape": [3, 16],
        "rgb_histogram_encoding": "base64-u8-normalized",
        "rgb_histogram_data": base64.b64encode(histogram).decode("ascii"),
        "edge_histogram_shape": [8],
        "edge_histogram_encoding": "base64-u8-normalized",
        "edge_histogram_data": base64.b64encode(edge_histogram).decode("ascii"),
        "difference_bits_hex": f"{difference_bits:016x}",
    }
    return descriptor, width, height


def _decode_exact_base64(value: Any, *, expected_bytes: int) -> bytes:
    if type(value) is not str:
        raise ImageCaptureError("visual descriptor encoding is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ImageCaptureError("visual descriptor encoding is invalid") from exc
    if len(decoded) != expected_bytes:
        raise ImageCaptureError("visual descriptor shape is invalid")
    return decoded


def _validate_public_metadata(value: Any, *, media_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != _PUBLIC_METADATA_FIELDS:
        raise ImageCaptureError("image public metadata contract is invalid")
    canonical_media_id = validate_media_id(value.get("media_id"))
    if media_id is not None and canonical_media_id != media_id:
        raise ImageCaptureError("image public metadata identity changed")
    if (
        value.get("schema") != IMAGE_ARTIFACT_SCHEMA
        or value.get("context_memory_type") != "image"
        or value.get("mime_type") not in {"image/png", "image/jpeg", "image/heic"}
    ):
        raise ImageCaptureError("image public metadata contract is invalid")
    for field, maximum in (
        ("source_dimensions", MAX_SOURCE_PIXELS),
        ("thumbnail_dimensions", MAX_THUMBNAIL_EDGE),
    ):
        dimensions = value.get(field)
        if (
            not isinstance(dimensions, dict)
            or frozenset(dimensions) != {"width", "height"}
            or type(dimensions.get("width")) is not int
            or type(dimensions.get("height")) is not int
            or int(dimensions["width"]) <= 0
            or int(dimensions["height"]) <= 0
            or int(dimensions["width"]) > maximum
            or int(dimensions["height"]) > maximum
        ):
            raise ImageCaptureError("image dimensions are invalid")
    source_dimensions = value["source_dimensions"]
    if int(source_dimensions["width"]) * int(source_dimensions["height"]) > MAX_SOURCE_PIXELS:
        raise ImageCaptureError("image source dimensions exceed the safe limit")
    descriptor = value.get("visual_descriptor")
    expected_descriptor_fields = {
        "schema",
        "tensor_shape",
        "tensor_encoding",
        "tensor_data",
        "rgb_histogram_shape",
        "rgb_histogram_encoding",
        "rgb_histogram_data",
        "edge_histogram_shape",
        "edge_histogram_encoding",
        "edge_histogram_data",
        "difference_bits_hex",
    }
    if (
        not isinstance(descriptor, dict)
        or frozenset(descriptor) != expected_descriptor_fields
        or descriptor.get("schema") != VISUAL_DESCRIPTOR_SCHEMA
        or descriptor.get("tensor_shape") != [16, 16, 3]
        or descriptor.get("tensor_encoding") != "base64-u8-rgb"
        or descriptor.get("rgb_histogram_shape") != [3, 16]
        or descriptor.get("rgb_histogram_encoding") != "base64-u8-normalized"
        or descriptor.get("edge_histogram_shape") != [8]
        or descriptor.get("edge_histogram_encoding") != "base64-u8-normalized"
        or re.fullmatch(r"[0-9a-f]{16}", str(descriptor.get("difference_bits_hex") or "")) is None
    ):
        raise ImageCaptureError("visual descriptor contract is invalid")
    _decode_exact_base64(descriptor.get("tensor_data"), expected_bytes=16 * 16 * 3)
    _decode_exact_base64(descriptor.get("rgb_histogram_data"), expected_bytes=3 * 16)
    _decode_exact_base64(descriptor.get("edge_histogram_data"), expected_bytes=8)
    return json.loads(json.dumps(value, sort_keys=True, allow_nan=False))


class ImageCaptureCache:
    """Private thumbnail cache plus durable-safe visual metadata builder.

    The returned public metadata is suitable for the existing SQLite metadata
    field. The original image, source path, source digest, thumbnail bytes, and
    thumbnail digest never appear in that projection.
    """

    def __init__(
        self,
        binding: CoreClientBinding,
        *,
        converter: Converter | None = None,
    ) -> None:
        try:
            canonical = validate_core_client_binding(binding.to_wire())
        except Exception as exc:
            raise ImageCaptureError("verified core binding is required") from exc
        self.binding = canonical
        self.root = canonical.data_root / "media-cache"
        self.objects_root = self.root / "objects"
        self.lock_path = self.root / ".media-cache.lock"
        self.converter = converter or _sips_converter

    def _validate_data_root(self) -> None:
        try:
            observed = self.binding.data_root.lstat()
        except (FileNotFoundError, OSError) as exc:
            raise ImageCaptureError("bound data root is unavailable") from exc
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) & 0o022
        ):
            raise ImageCaptureError("bound data root is unsafe")

    def _prepare_cache(self) -> None:
        self._validate_data_root()
        _private_directory(self.root, create=True)
        _private_directory(self.objects_root, create=True)
        try:
            descriptor = os.open(
                self.lock_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except OSError as exc:
            raise ImageCaptureError("image cache lock is unavailable") from exc
        try:
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        _private_regular(self.lock_path, maximum_bytes=1, allow_empty=True)

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        self._prepare_cache()
        descriptor = os.open(
            self.lock_path,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.getuid()
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o600
            ):
                raise ImageCaptureError("image cache lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _object_path(self, media_id: str) -> Path:
        return self.objects_root / validate_media_id(media_id)

    def _capture_projection(
        self,
        *,
        manifest: dict[str, Any],
        thumbnail: bytes,
        idempotent_replay: bool,
    ) -> dict[str, Any]:
        media_id = validate_media_id(manifest.get("media_id"))
        public_metadata = _validate_public_metadata(
            manifest.get("public_metadata"),
            media_id=media_id,
        )
        return {
            "action": "capture-image-cache",
            "media_id": media_id,
            "cache_ready": True,
            "thumbnail_size_bytes": len(thumbnail),
            "public_metadata": public_metadata,
            "idempotent_replay": bool(idempotent_replay),
            "raw_original_stored": False,
            "source_path_stored": False,
            "public_digest_stored": False,
        }

    def capture_image(
        self,
        source_path: str | os.PathLike[str],
        *,
        media_id: str | None = None,
    ) -> dict[str, Any]:
        source = _normal_source_path(source_path)
        canonical_media_id = validate_media_id(media_id) if media_id is not None else new_media_id()
        self._prepare_cache()
        with _open_source(source) as (source_fd, source_stat):
            source_sha256, prefix = _hash_source(source_fd, int(source_stat.st_size))
            source_mime_type = _mime_from_magic(prefix)
            _assert_source_unchanged(source, source_stat)
            destination = self._object_path(canonical_media_id)
            if destination.exists() or destination.is_symlink():
                existing_manifest, existing_thumbnail = self._read_object(
                    canonical_media_id
                )
                if not secrets.compare_digest(
                    str(existing_manifest.get("source_sha256") or ""),
                    source_sha256,
                ):
                    raise ValueError(
                        "media_id is already present for a different image derivative"
                    )
                return self._capture_projection(
                    manifest=existing_manifest,
                    thumbnail=existing_thumbnail,
                    idempotent_replay=True,
                )
            with tempfile.TemporaryDirectory(
                prefix=".image-work-",
                dir=str(self.binding.data_root),
            ) as work_name:
                work_root = Path(work_name)
                os.chmod(work_root, 0o700)
                conversion = self.converter(source, work_root)
                _assert_source_unchanged(source, source_stat)
                if (
                    type(conversion.source_width) is not int
                    or type(conversion.source_height) is not int
                    or conversion.source_width <= 0
                    or conversion.source_height <= 0
                    or conversion.source_width * conversion.source_height > MAX_SOURCE_PIXELS
                ):
                    raise ImageCaptureError("converted image dimensions are invalid")
                bmp_bytes = self._read_conversion_output(
                    conversion.bmp_path,
                    work_root=work_root,
                    maximum_bytes=MAX_THUMBNAIL_EDGE * MAX_THUMBNAIL_EDGE * 4 + 64 * 1024,
                )
                descriptor, thumbnail_width, thumbnail_height = _visual_descriptor_from_bmp(
                    bmp_bytes
                )
                thumbnail_bytes = self._read_conversion_output(
                    conversion.thumbnail_path,
                    work_root=work_root,
                    maximum_bytes=MAX_THUMBNAIL_BYTES,
                )
                if not thumbnail_bytes.startswith(_JPEG_MAGIC):
                    raise ImageCaptureError("thumbnail conversion did not produce JPEG")
                public_metadata = _validate_public_metadata(
                    {
                        "schema": IMAGE_ARTIFACT_SCHEMA,
                        "context_memory_type": "image",
                        "media_id": canonical_media_id,
                        "mime_type": source_mime_type,
                        "source_dimensions": {
                            "width": conversion.source_width,
                            "height": conversion.source_height,
                        },
                        "thumbnail_dimensions": {
                            "width": thumbnail_width,
                            "height": thumbnail_height,
                        },
                        "visual_descriptor": descriptor,
                    },
                    media_id=canonical_media_id,
                )
                manifest = {
                    "schema": IMAGE_ARTIFACT_SCHEMA,
                    "media_id": canonical_media_id,
                    "source_mime_type": source_mime_type,
                    "source_size_bytes": int(source_stat.st_size),
                    "source_sha256": source_sha256,
                    "thumbnail_sha256": hashlib.sha256(thumbnail_bytes).hexdigest(),
                    "thumbnail_size_bytes": len(thumbnail_bytes),
                    "created_at": time.time(),
                    "public_metadata": public_metadata,
                }
                try:
                    self._publish_object(
                        media_id=canonical_media_id,
                        thumbnail_bytes=thumbnail_bytes,
                        manifest=manifest,
                    )
                except ValueError:
                    # A concurrent retry may have published the same deterministic
                    # derivative first. Accept only an exact private source-digest
                    # match; a conflicting media ID remains fail-closed.
                    existing_manifest, existing_thumbnail = self._read_object(
                        canonical_media_id
                    )
                    if not secrets.compare_digest(
                        str(existing_manifest.get("source_sha256") or ""),
                        source_sha256,
                    ):
                        raise
                    return self._capture_projection(
                        manifest=existing_manifest,
                        thumbnail=existing_thumbnail,
                        idempotent_replay=True,
                    )
        return self._capture_projection(
            manifest=manifest,
            thumbnail=thumbnail_bytes,
            idempotent_replay=False,
        )

    @staticmethod
    def _read_conversion_output(
        path: Path,
        *,
        work_root: Path,
        maximum_bytes: int,
    ) -> bytes:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = work_root / candidate
        try:
            candidate.relative_to(work_root)
        except ValueError as exc:
            raise ImageCaptureError("image converter output escaped its private workspace") from exc
        try:
            observed = candidate.lstat()
        except (FileNotFoundError, OSError) as exc:
            raise ImageCaptureError("image converter output is missing") from exc
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or observed.st_size <= 0
            or observed.st_size > maximum_bytes
        ):
            raise ImageCaptureError("image converter output is unsafe")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino):
                raise ImageCaptureError("image converter output changed during open")
            data = b""
            remaining = int(opened.st_size)
            while remaining:
                chunk = os.read(descriptor, min(remaining, 64 * 1024))
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)
            if len(data) != int(opened.st_size):
                raise ImageCaptureError("image converter output changed during read")
            return data
        finally:
            os.close(descriptor)

    def _publish_object(
        self,
        *,
        media_id: str,
        thumbnail_bytes: bytes,
        manifest: dict[str, Any],
    ) -> None:
        stage = Path(tempfile.mkdtemp(prefix=f".stage-{media_id}-", dir=str(self.root)))
        os.chmod(stage, 0o700)
        published = False
        try:
            _write_private_exclusive(stage / "thumbnail.jpg", thumbnail_bytes)
            manifest_bytes = (
                json.dumps(
                    manifest,
                    sort_keys=True,
                    indent=2,
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
            _write_private_exclusive(stage / "manifest.json", manifest_bytes)
            _fsync_directory(stage)
            with self._exclusive_lock():
                destination = self._object_path(media_id)
                if destination.exists() or destination.is_symlink():
                    raise ValueError("media_id is already present in the image cache")
                os.rename(stage, destination)
                _fsync_directory(self.objects_root)
                published = True
        finally:
            if not published and stage.exists() and not stage.is_symlink():
                for filename in ("thumbnail.jpg", "manifest.json"):
                    try:
                        (stage / filename).unlink()
                    except FileNotFoundError:
                        pass
                try:
                    stage.rmdir()
                except FileNotFoundError:
                    pass

    def _read_object(self, media_id: str) -> tuple[dict[str, Any], bytes]:
        canonical_media_id = validate_media_id(media_id)
        if not self.root.exists() or not self.objects_root.exists():
            raise ImageCaptureNotFound("image cache object is unavailable")
        _private_directory(self.root, create=False)
        _private_directory(self.objects_root, create=False)
        object_root = self._object_path(canonical_media_id)
        try:
            _private_directory(object_root, create=False)
        except ImageCaptureError as exc:
            try:
                object_root.lstat()
            except FileNotFoundError:
                raise ImageCaptureNotFound(
                    "image cache object is unavailable"
                ) from exc
            except OSError:
                pass
            raise
        names = sorted(path.name for path in object_root.iterdir())
        if names != ["manifest.json", "thumbnail.jpg"]:
            raise ImageCaptureError("image cache object inventory is invalid")
        manifest_bytes = _read_private_regular(
            object_root / "manifest.json",
            maximum_bytes=64 * 1024,
        )
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ImageCaptureError("image cache manifest is malformed") from exc
        thumbnail = _read_private_regular(
            object_root / "thumbnail.jpg",
            maximum_bytes=MAX_THUMBNAIL_BYTES,
        )
        self._validate_manifest(manifest, media_id=canonical_media_id, thumbnail=thumbnail)
        return manifest, thumbnail

    @staticmethod
    def _validate_manifest(
        value: Any,
        *,
        media_id: str,
        thumbnail: bytes,
    ) -> dict[str, Any]:
        if not isinstance(value, dict) or frozenset(value) != _MANIFEST_FIELDS:
            raise ImageCaptureError("image cache manifest contract is invalid")
        if (
            value.get("schema") != IMAGE_ARTIFACT_SCHEMA
            or value.get("media_id") != media_id
            or value.get("source_mime_type") not in {"image/png", "image/jpeg", "image/heic"}
            or type(value.get("source_size_bytes")) is not int
            or not 0 < int(value["source_size_bytes"]) <= MAX_SOURCE_BYTES
            or SHA256_RE.fullmatch(str(value.get("source_sha256") or "")) is None
            or SHA256_RE.fullmatch(str(value.get("thumbnail_sha256") or "")) is None
            or type(value.get("thumbnail_size_bytes")) is not int
            or int(value["thumbnail_size_bytes"]) != len(thumbnail)
            or not isinstance(value.get("created_at"), (int, float))
            or isinstance(value.get("created_at"), bool)
            or not math.isfinite(float(value["created_at"]))
            or hashlib.sha256(thumbnail).hexdigest() != value["thumbnail_sha256"]
            or not thumbnail.startswith(_JPEG_MAGIC)
        ):
            raise ImageCaptureError("image cache manifest verification failed")
        public_metadata = _validate_public_metadata(value.get("public_metadata"), media_id=media_id)
        if public_metadata.get("mime_type") != value.get("source_mime_type"):
            raise ImageCaptureError("image cache manifest MIME binding changed")
        return dict(value)

    def get_thumbnail(self, media_id: str) -> ThumbnailResult:
        _manifest, thumbnail = self._read_object(media_id)
        return ThumbnailResult(
            media_id=validate_media_id(media_id),
            content_type="image/jpeg",
            data=thumbnail,
        )

    def get_public_metadata(self, media_id: str) -> dict[str, Any]:
        """Return only the durable-safe metadata projection for one cache object."""

        manifest, _thumbnail = self._read_object(media_id)
        return _validate_public_metadata(
            manifest.get("public_metadata"),
            media_id=validate_media_id(media_id),
        )

    def audit(
        self,
        *,
        referenced_media_ids: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        references_provided = referenced_media_ids is not None
        references = self._normalize_references(referenced_media_ids or [])
        stored: list[str] = []
        valid: list[str] = []
        corrupt: list[str] = []
        invalid_entry_count = 0
        if self.root.exists() or self.root.is_symlink():
            _private_directory(self.root, create=False)
            _private_directory(self.objects_root, create=False)
            entries = sorted(self.objects_root.iterdir(), key=lambda path: path.name)
            if len(entries) > MAX_OBJECTS:
                raise ImageCaptureError("image cache object bound exceeded")
            for entry in entries:
                name = entry.name
                if MEDIA_ID_RE.fullmatch(name) is None:
                    invalid_entry_count += 1
                    corrupt.append(f"invalid-entry-{invalid_entry_count:04d}")
                    continue
                stored.append(name)
                try:
                    self._read_object(name)
                except (ImageCaptureError, ValueError, OSError):
                    corrupt.append(name)
                else:
                    valid.append(name)
        missing = sorted(references - set(valid)) if references_provided else []
        orphaned = sorted(set(valid) - references) if references_provided else []
        revision_payload = {
            "stored": stored,
            "valid": valid,
            "corrupt": corrupt,
            "references": sorted(references) if references_provided else None,
            "missing": missing,
            "orphaned": orphaned,
        }
        revision = hashlib.sha256(
            json.dumps(
                revision_payload,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        return {
            "action": "image-cache-audit",
            "healthy": not corrupt and not missing,
            "reference_set_provided": references_provided,
            "stored_count": len(stored),
            "valid_count": len(valid),
            "corrupt_count": len(corrupt),
            "invalid_entry_count": invalid_entry_count,
            "missing_count": len(missing),
            "orphan_count": len(orphaned),
            "corrupt_ids": corrupt,
            "missing_ids": missing,
            "orphan_ids": orphaned,
            "revision": revision,
            "content_free_revision": True,
        }

    @staticmethod
    def _normalize_references(values: Iterable[str]) -> set[str]:
        if isinstance(values, (str, bytes, dict)):
            raise ValueError("referenced_media_ids must be an iterable of media IDs")
        references: set[str] = set()
        for value in values:
            references.add(validate_media_id(value))
            if len(references) > MAX_OBJECTS:
                raise ValueError("referenced_media_ids exceeds the safe bound")
        return references

    def prune_orphans(
        self,
        *,
        referenced_media_ids: Iterable[str],
        expected_revision: str,
        confirm: bool,
    ) -> dict[str, Any]:
        if confirm is not True:
            raise ValueError("confirm must be true before pruning image cache objects")
        if type(expected_revision) is not str or SHA256_RE.fullmatch(expected_revision) is None:
            raise ValueError("expected_revision must be a canonical SHA-256 revision")
        references = self._normalize_references(referenced_media_ids)
        with self._exclusive_lock():
            audit = self.audit(referenced_media_ids=references)
            if not secrets.compare_digest(str(audit["revision"]), expected_revision):
                raise ValueError("image cache prune revision is stale")
            if audit["corrupt_count"]:
                raise ImageCaptureError("corrupt image cache objects require manual review")
            removed: list[str] = []
            for media_id in audit["orphan_ids"]:
                self._remove_valid_object(media_id)
                removed.append(media_id)
            _fsync_directory(self.objects_root)
        after = self.audit(referenced_media_ids=references)
        return {
            "action": "image-cache-prune-orphans",
            "removed_count": len(removed),
            "removed_ids": removed,
            "before_revision": expected_revision,
            "after_revision": after["revision"],
            "remaining_orphan_count": after["orphan_count"],
            "cache_only": True,
            "raw_original_stored": False,
        }

    def _remove_valid_object(self, media_id: str) -> None:
        self._read_object(media_id)
        object_root = self._object_path(media_id)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        descriptor = os.open(object_root, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o700
            ):
                raise ImageCaptureError("image cache object changed before prune")
            os.unlink("thumbnail.jpg", dir_fd=descriptor)
            os.unlink("manifest.json", dir_fd=descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rmdir(object_root)


__all__ = [
    "ConversionResult",
    "IMAGE_ARTIFACT_SCHEMA",
    "ImageCaptureCache",
    "ImageCaptureError",
    "ImageCaptureNotFound",
    "MAX_SOURCE_BYTES",
    "MAX_THUMBNAIL_EDGE",
    "ThumbnailResult",
    "VISUAL_DESCRIPTOR_SCHEMA",
    "new_media_id",
    "validate_media_id",
]

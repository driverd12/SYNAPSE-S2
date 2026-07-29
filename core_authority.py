from __future__ import annotations

import fcntl
import math
import os
import re
import stat
import time
import uuid
import weakref
from dataclasses import dataclass
from pathlib import Path


CORE_AUTHORITY_METADATA_KEY = "core_authority"
CORE_AUTHORITY_SCHEMA_VERSION = 1
CORE_AUTHORITY_INSTANCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
CORE_AUTHORITY_LOCK_GENERATION_RE = re.compile(
    r"(?:lockfs-v1-[0-9a-f]{1,32}-[0-9a-f]{1,32}"
    r"|lockfs-v2-[0-9a-f]{1,32}-[0-9a-f]{1,32})"
)
CORE_AUTHORITY_LOCK_TRANSITION_SCHEMA = (
    "synapse-s2.authority-lock-generation-transition.v1"
)
CORE_AUTHORITY_LOCK_TIMESTAMP_TOLERANCE_SECONDS = 1.0

_CORE_AUTHORITY_LOCK_V1_RE = re.compile(
    r"lockfs-v1-(?P<device>[0-9a-f]{1,32})-(?P<inode>[0-9a-f]{1,32})"
)
_CORE_AUTHORITY_LOCK_V2_RE = re.compile(
    r"lockfs-v2-(?P<inode>[0-9a-f]{1,32})-(?P<birthtime_ns>[0-9a-f]{1,32})"
)


class CoreAuthorityError(RuntimeError):
    """Raised when backend ownership violates the authoritative-core fence."""


_LIVE_LEASES: "weakref.WeakSet[CoreAuthorityLease]" = weakref.WeakSet()


def _invalidate_in_forked_child() -> None:
    """A child may never reuse its parent's process-lifetime authority."""

    for lease in list(_LIVE_LEASES):
        lease._invalidate_after_fork()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_invalidate_in_forked_child)


def _private_mode(mode: int) -> int:
    return stat.S_IMODE(mode)


def _nanoseconds_from_seconds(value: object, *, field: str) -> int:
    """Round a finite positive POSIX timestamp to integer nanoseconds."""

    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise CoreAuthorityError(f"{field} is invalid")
    nanoseconds = int(round(float(value) * 1_000_000_000))
    if nanoseconds <= 0:
        raise CoreAuthorityError(f"{field} is invalid")
    return nanoseconds


def _lock_birthtime_ns(identity: os.stat_result) -> int | None:
    """Return rounded inode birth time where the platform exposes it.

    macOS exposes ``st_birthtime`` but not a portable ``st_birthtime_ns``.
    Converting the reported POSIX timestamp once and encoding the rounded
    nanoseconds makes the generation independent of mount-assigned device IDs.
    A platform that advertises an unusable birth time fails closed instead of
    silently falling back to the weaker legacy identity.
    """

    if not hasattr(identity, "st_birthtime"):
        return None
    return _nanoseconds_from_seconds(
        getattr(identity, "st_birthtime"),
        field="authoritative core lock birthtime",
    )


def _parse_lock_generation_id(generation_id: object) -> tuple[str, int, int]:
    """Parse one closed lock-generation identifier without filesystem access."""

    if not isinstance(generation_id, str):
        raise CoreAuthorityError("authoritative core lock generation is invalid")
    legacy = _CORE_AUTHORITY_LOCK_V1_RE.fullmatch(generation_id)
    if legacy is not None:
        return (
            "v1",
            int(legacy.group("inode"), 16),
            int(legacy.group("device"), 16),
        )
    current = _CORE_AUTHORITY_LOCK_V2_RE.fullmatch(generation_id)
    if current is not None:
        return (
            "v2",
            int(current.group("inode"), 16),
            int(current.group("birthtime_ns"), 16),
        )
    raise CoreAuthorityError("authoritative core lock generation is invalid")


def _validated_legacy_lock_generation_transition(
    *,
    legacy_generation_id: object,
    current_generation_id: object,
    lock_inode: object,
    lock_birthtime_ns: object,
    durable_claimed_at: object,
    timestamp_tolerance_seconds: object,
) -> dict[str, object]:
    """Purely validate the single admissible legacy-v1 to v2 transition."""

    if type(lock_inode) is not int or lock_inode <= 0:
        raise CoreAuthorityError("authoritative core lock inode is invalid")
    if type(lock_birthtime_ns) is not int or lock_birthtime_ns <= 0:
        raise CoreAuthorityError("authoritative core lock birthtime is invalid")
    if (
        type(timestamp_tolerance_seconds) not in {int, float}
        or not math.isfinite(float(timestamp_tolerance_seconds))
        or float(timestamp_tolerance_seconds) < 0.0
        or float(timestamp_tolerance_seconds)
        > CORE_AUTHORITY_LOCK_TIMESTAMP_TOLERANCE_SECONDS
    ):
        raise CoreAuthorityError(
            "authoritative core lock timestamp tolerance is invalid"
        )

    predecessor_version, predecessor_inode, _predecessor_device = (
        _parse_lock_generation_id(legacy_generation_id)
    )
    current_version, current_inode, current_birthtime_ns = (
        _parse_lock_generation_id(current_generation_id)
    )
    if predecessor_version != "v1" or current_version != "v2":
        raise CoreAuthorityError(
            "authoritative core lock generation transition is invalid"
        )
    if predecessor_inode != lock_inode or current_inode != lock_inode:
        raise CoreAuthorityError(
            "authoritative core lock generation transition changed inode"
        )
    if current_birthtime_ns != lock_birthtime_ns:
        raise CoreAuthorityError(
            "authoritative core lock generation birthtime is inconsistent"
        )

    claimed_at_ns = _nanoseconds_from_seconds(
        durable_claimed_at,
        field="durable core authority claimed_at",
    )
    tolerance_ns = int(
        round(float(timestamp_tolerance_seconds) * 1_000_000_000)
    )
    if lock_birthtime_ns > claimed_at_ns + tolerance_ns:
        raise CoreAuthorityError(
            "authoritative core lock was created after the durable claim"
        )

    return {
        "schema": CORE_AUTHORITY_LOCK_TRANSITION_SCHEMA,
        "predecessor_generation_id": legacy_generation_id,
        "current_generation_id": current_generation_id,
        "lock_inode": lock_inode,
        "lock_birthtime_ns": lock_birthtime_ns,
    }


def _lock_generation_id(identity: os.stat_result) -> str:
    """Return the non-copyable filesystem generation of one held lock inode.

    A pathname can be unlinked while an old process still holds its descriptor.
    On macOS, binding the marker to inode plus birth time prevents a replacement
    pathname from being mistaken for the old generation without depending on a
    mount-assigned device number that can change across a reboot.  Platforms
    without inode birth time retain the legacy device/inode identity.  The old
    inode cannot be reused while its descriptor remains open.
    """

    birthtime_ns = _lock_birthtime_ns(identity)
    if birthtime_ns is None:
        generation = (
            f"lockfs-v1-{int(identity.st_dev):x}-{int(identity.st_ino):x}"
        )
    else:
        generation = f"lockfs-v2-{int(identity.st_ino):x}-{birthtime_ns:x}"
    if CORE_AUTHORITY_LOCK_GENERATION_RE.fullmatch(generation) is None:
        raise CoreAuthorityError("authoritative core lock generation is invalid")
    return generation


def _ensure_private_directory(path: Path) -> None:
    """Create only the service-owned leaf and reject unsafe path identities."""

    try:
        current = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(mode=0o700, parents=False)
        except FileExistsError:
            pass
        current = path.lstat()
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
        raise CoreAuthorityError("authoritative core directory must be a real directory")
    if current.st_uid != os.getuid():
        raise CoreAuthorityError("authoritative core directory has an unexpected owner")
    if _private_mode(current.st_mode) != 0o700:
        raise CoreAuthorityError("authoritative core directory must have mode 0700")


def _open_private_lock(path: Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise CoreAuthorityError(
                "authoritative core lock could not be opened safely"
            ) from exc
    except OSError as exc:
        raise CoreAuthorityError(
            "authoritative core lock could not be created safely"
        ) from exc
    try:
        current = os.fstat(descriptor)
        if created:
            # The leaf belongs to this invocation, so normalizing a restrictive
            # process umask is safe.  Existing filesystem evidence is never
            # repaired in place: an unsafe pre-existing lock must fail closed.
            os.fchmod(descriptor, 0o600)
            current = os.fstat(descriptor)
        if not stat.S_ISREG(current.st_mode):
            raise CoreAuthorityError("authoritative core lock must be a regular file")
        if current.st_uid != os.getuid():
            raise CoreAuthorityError("authoritative core lock has an unexpected owner")
        if current.st_nlink != 1:
            raise CoreAuthorityError("authoritative core lock must not be hard linked")
        if _private_mode(current.st_mode) != 0o600:
            raise CoreAuthorityError("authoritative core lock must have mode 0600")
        visible = path.lstat()
        if (
            stat.S_ISLNK(visible.st_mode)
            or not stat.S_ISREG(visible.st_mode)
            or visible.st_uid != current.st_uid
            or visible.st_dev != current.st_dev
            or visible.st_ino != current.st_ino
        ):
            raise CoreAuthorityError("authoritative core lock path changed during open")
        return descriptor, current
    except BaseException:
        os.close(descriptor)
        raise


@dataclass(eq=False)
class CoreAuthorityLease:
    """Process-bound filesystem and durable-database authority identity."""

    db_path: Path
    descriptor: int
    lock_path: Path
    role: str
    owner_pid: int
    lock_device: int
    lock_inode: int
    lock_generation_id: str
    instance_id: str
    database_device: int | None = None
    database_inode: int | None = None
    durable_epoch: int | None = None
    durable_schema_version: int | None = None
    config_fingerprint: str | None = None
    build_id: str | None = None
    protocol_version: str | None = None
    _closed: bool = False
    _fork_invalidated: bool = False

    @classmethod
    def acquire_local(cls, db_path: str | os.PathLike[str]) -> "CoreAuthorityLease":
        return cls._acquire(db_path=db_path, role="local", timeout_seconds=0.0)

    @classmethod
    def acquire_core(
        cls,
        db_path: str | os.PathLike[str],
        *,
        timeout_seconds: float = 15.0,
        instance_id: str | None = None,
    ) -> "CoreAuthorityLease":
        clean_instance_id = str(instance_id or f"core-{uuid.uuid4().hex}").strip()
        if not CORE_AUTHORITY_INSTANCE_RE.fullmatch(clean_instance_id):
            raise CoreAuthorityError("authoritative core instance_id is invalid")
        return cls._acquire(
            db_path=db_path,
            role="core",
            timeout_seconds=timeout_seconds,
            instance_id=clean_instance_id,
        )

    @classmethod
    def _acquire(
        cls,
        *,
        db_path: str | os.PathLike[str],
        role: str,
        timeout_seconds: float,
        instance_id: str | None = None,
    ) -> "CoreAuthorityLease":
        resolved_db = Path(db_path).expanduser().resolve()
        parent = resolved_db.parent
        if not parent.is_dir():
            raise CoreAuthorityError(
                "memory-store parent must exist before acquiring core authority"
            )
        core_dir = parent / "core"
        _ensure_private_directory(core_dir)
        lock_path = core_dir / "authority.lock"
        descriptor, identity = _open_private_lock(lock_path)
        mode = fcntl.LOCK_EX if role == "core" else fcntl.LOCK_SH
        deadline = time.monotonic() + max(0.0, float(timeout_seconds))
        lease: CoreAuthorityLease | None = None
        while True:
            try:
                fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
                lease = cls(
                    db_path=resolved_db,
                    descriptor=descriptor,
                    lock_path=lock_path,
                    role=role,
                    owner_pid=os.getpid(),
                    lock_device=int(identity.st_dev),
                    lock_inode=int(identity.st_ino),
                    lock_generation_id=_lock_generation_id(identity),
                    instance_id=str(instance_id or f"local-{os.getpid()}-{uuid.uuid4().hex}"),
                )
                lease.assert_active_for(resolved_db)
                if resolved_db.exists():
                    lease.bind_database_identity(resolved_db)
                _LIVE_LEASES.add(lease)
                return lease
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    os.close(descriptor)
                    if role == "core":
                        raise CoreAuthorityError(
                            "authoritative core startup is fenced by an active local backend"
                        ) from exc
                    raise CoreAuthorityError(
                        "authoritative core service is active; route through the core client"
                    ) from exc
                time.sleep(0.02)
            except BaseException:
                if lease is not None:
                    lease._closed = True
                    lease.descriptor = -1
                os.close(descriptor)
                raise

    def _invalidate_after_fork(self) -> None:
        if self._closed:
            return
        self._fork_invalidated = True
        self._closed = True
        descriptor = self.descriptor
        self.descriptor = -1
        try:
            os.close(descriptor)
        except OSError:
            pass

    def assert_active_for(self, db_path: str | os.PathLike[str]) -> None:
        if self._closed or self._fork_invalidated:
            raise CoreAuthorityError("core authority lease is not active")
        if self.owner_pid != os.getpid():
            raise CoreAuthorityError("core authority lease belongs to another process")
        if Path(db_path).expanduser().resolve() != self.db_path:
            raise CoreAuthorityError("core authority lease does not match the memory store")
        try:
            held = os.fstat(self.descriptor)
            visible = self.lock_path.lstat()
            core_dir = self.lock_path.parent.lstat()
        except OSError as exc:
            raise CoreAuthorityError("core authority lock identity is unavailable") from exc
        if (
            not stat.S_ISREG(held.st_mode)
            or held.st_uid != os.getuid()
            or held.st_nlink != 1
            or _private_mode(held.st_mode) != 0o600
            or int(held.st_dev) != self.lock_device
            or int(held.st_ino) != self.lock_inode
            or _lock_generation_id(held) != self.lock_generation_id
        ):
            raise CoreAuthorityError("held core authority lock identity is invalid")
        if (
            stat.S_ISLNK(visible.st_mode)
            or not stat.S_ISREG(visible.st_mode)
            or visible.st_uid != os.getuid()
            or visible.st_nlink != 1
            or _private_mode(visible.st_mode) != 0o600
            or int(visible.st_dev) != self.lock_device
            or int(visible.st_ino) != self.lock_inode
        ):
            raise CoreAuthorityError("core authority lock path was replaced")
        if (
            stat.S_ISLNK(core_dir.st_mode)
            or not stat.S_ISDIR(core_dir.st_mode)
            or core_dir.st_uid != os.getuid()
            or _private_mode(core_dir.st_mode) != 0o700
        ):
            raise CoreAuthorityError("authoritative core directory identity is invalid")
        if self.database_device is not None or self.database_inode is not None:
            try:
                database = self.db_path.lstat()
            except OSError as exc:
                raise CoreAuthorityError(
                    "authoritative memory database identity is unavailable"
                ) from exc
            if (
                stat.S_ISLNK(database.st_mode)
                or not stat.S_ISREG(database.st_mode)
                or database.st_uid != os.getuid()
                or database.st_nlink != 1
                or int(database.st_dev) != self.database_device
                or int(database.st_ino) != self.database_inode
            ):
                raise CoreAuthorityError(
                    "authoritative memory database path was replaced"
                )

    def bind_database_identity(self, db_path: str | os.PathLike[str]) -> None:
        """Bind this process lease to one exact, owner-controlled database inode."""

        self.assert_active_for(db_path)
        try:
            database = self.db_path.lstat()
        except OSError as exc:
            raise CoreAuthorityError(
                "authoritative memory database identity is unavailable"
            ) from exc
        if (
            stat.S_ISLNK(database.st_mode)
            or not stat.S_ISREG(database.st_mode)
            or database.st_uid != os.getuid()
            or database.st_nlink != 1
        ):
            raise CoreAuthorityError(
                "authoritative memory database must be one owner-controlled regular file"
            )
        identity = (int(database.st_dev), int(database.st_ino))
        current = (self.database_device, self.database_inode)
        if current != (None, None) and current != identity:
            raise CoreAuthorityError(
                "authoritative memory database path was replaced"
            )
        self.database_device, self.database_inode = identity
        self.assert_active_for(db_path)

    def assert_core_for(self, db_path: str | os.PathLike[str]) -> None:
        self.assert_active_for(db_path)
        if self.role != "core":
            raise CoreAuthorityError("authoritative core lease is not active")

    def validate_legacy_lock_generation_transition(
        self,
        *,
        legacy_generation_id: str,
        durable_claimed_at: float,
        timestamp_tolerance_seconds: float = 1.0,
    ) -> dict[str, object]:
        """Validate a one-time same-inode migration from lockfs-v1 to v2.

        This compatibility proof is intentionally narrow: the caller must hold
        the active exclusive core lease, the descriptor and visible pathname
        must still identify the same private zero-byte lock, and the lock's
        birth time may not postdate the durable authority claim.  At most one
        second of tolerance is allowed for filesystem timestamp rounding.
        Nothing is mutated; callers may use the closed result as evidence for a
        separately governed durable-marker transition.
        """

        self.assert_core_for(self.db_path)
        try:
            held = os.fstat(self.descriptor)
            visible = self.lock_path.lstat()
        except OSError as exc:
            raise CoreAuthorityError(
                "core authority lock identity is unavailable"
            ) from exc
        if (
            not stat.S_ISREG(held.st_mode)
            or held.st_uid != os.getuid()
            or held.st_nlink != 1
            or _private_mode(held.st_mode) != 0o600
            or int(held.st_size) != 0
            or int(held.st_dev) != self.lock_device
            or int(held.st_ino) != self.lock_inode
        ):
            raise CoreAuthorityError(
                "held core authority lock is not a private zero-byte file"
            )
        if (
            stat.S_ISLNK(visible.st_mode)
            or not stat.S_ISREG(visible.st_mode)
            or visible.st_uid != os.getuid()
            or visible.st_nlink != 1
            or _private_mode(visible.st_mode) != 0o600
            or int(visible.st_size) != 0
            or int(visible.st_dev) != self.lock_device
            or int(visible.st_ino) != self.lock_inode
        ):
            raise CoreAuthorityError(
                "visible core authority lock is not the held private zero-byte file"
            )

        held_birthtime_ns = _lock_birthtime_ns(held)
        visible_birthtime_ns = _lock_birthtime_ns(visible)
        if (
            held_birthtime_ns is None
            or visible_birthtime_ns is None
            or held_birthtime_ns != visible_birthtime_ns
        ):
            raise CoreAuthorityError(
                "authoritative core lock birthtime identity is unavailable"
            )
        current_generation_id = _lock_generation_id(held)
        if (
            current_generation_id != self.lock_generation_id
            or _lock_generation_id(visible) != self.lock_generation_id
        ):
            raise CoreAuthorityError(
                "authoritative core lock generation identity changed"
            )

        result = _validated_legacy_lock_generation_transition(
            legacy_generation_id=legacy_generation_id,
            current_generation_id=current_generation_id,
            lock_inode=self.lock_inode,
            lock_birthtime_ns=held_birthtime_ns,
            durable_claimed_at=durable_claimed_at,
            timestamp_tolerance_seconds=timestamp_tolerance_seconds,
        )
        self.assert_core_for(self.db_path)
        return result

    def bind_durable_authority(
        self,
        *,
        epoch: int,
        config_fingerprint: str,
        build_id: str,
        protocol_version: str,
        schema_version: int = CORE_AUTHORITY_SCHEMA_VERSION,
    ) -> None:
        self.assert_core_for(self.db_path)
        if type(epoch) is not int or epoch <= 0:
            raise CoreAuthorityError("authoritative core epoch is invalid")
        if schema_version != CORE_AUTHORITY_SCHEMA_VERSION:
            raise CoreAuthorityError("authoritative core schema version is unsupported")
        if self.durable_epoch is not None and (
            self.durable_epoch != epoch
            or self.durable_schema_version != schema_version
            or self.config_fingerprint != config_fingerprint
            or self.build_id != build_id
            or self.protocol_version != protocol_version
        ):
            raise CoreAuthorityError("authoritative core lease is already bound")
        self.durable_epoch = epoch
        self.durable_schema_version = schema_version
        self.config_fingerprint = config_fingerprint
        self.build_id = build_id
        self.protocol_version = protocol_version

    @property
    def active(self) -> bool:
        try:
            self.assert_active_for(self.db_path)
        except CoreAuthorityError:
            return False
        return True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        descriptor = self.descriptor
        self.descriptor = -1
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def __enter__(self) -> "CoreAuthorityLease":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - process teardown fallback
        try:
            self.close()
        except Exception:
            pass

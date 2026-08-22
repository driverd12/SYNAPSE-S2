#!/usr/bin/env python3
"""Incumbent-only release provenance verifier.

This tool runs exclusively as the *currently deployed* (incumbent) verifier
against local, pre-distributed documents.  It never executes or imports
candidate code, never imports live-store or recovery modules, never opens a
socket, database, or subprocess, and never touches recovery keys or live
state.  Its only write, ever, is the atomic fsynced replacement of the
operator-owned release floor file performed by the two explicitly confirmed
mutation commands; ``verify-release`` performs no write of any kind.

Bootstrap non-claim: the release base (commit f739) cannot use a candidate
verifier to authenticate itself — a verifier delivered inside a release
could vouch for exactly the release that delivered it.  The first trust
root and the first verifier distribution are therefore necessarily
out-of-band; this tool only ever extends trust already installed.

Closed canonical document schemas, all parsed from exact canonical JSON
bytes (sorted keys, compact separators, ASCII, no trailing newline) with
duplicate keys, unknown or missing fields, floats, booleans-as-integers,
non-canonical encodings, and out-of-bounds values all rejected:

- ``synapse-s2.release-root.v1`` — the out-of-band trust anchor: an ed25519
  root key id and raw public key (hex).  The key id is ``ed25519-`` plus
  the SHA-256 of a domain-separated payload over the raw public key.
- ``synapse-s2.release-trust-bundle.v1`` — root-signed: a monotonic trust
  generation, validity times, per-channel minimum sequences, a bounded list
  of delegated release keys (role, channels, validity window, inclusive
  ``sequence_minimum``/``sequence_maximum`` bounds), a bounded revocation
  list, and the root signature over the domain-separated canonical
  unsigned document.
- ``synapse-s2.release-trust-bundle.v2`` — identical fields and bounds,
  signed over its own ``v2`` domain (a v1 signature can never verify a v2
  bundle or vice versa), with a closed two-role delegation vocabulary:
  ``release`` (signs envelopes) and ``compatibility-review`` (signs
  build-compatibility tickets, verified by the separate dormant
  ``release_compatibility`` tool).  A key id may appear in at most one
  delegation, so no key can hold both roles; envelopes signed by a
  non-release delegation are blocked (``delegation-role-mismatch``).
  Every v1 document, signature, and behavior is unchanged.
- ``synapse-s2.release-envelope.v1`` — signed by a delegated release key:
  channel, version, monotonic sequence, source SHA (40 hex), product
  schema, inventory policy id, product id, the trust generation it was
  issued under, validity times, signing key id, and signature.
- ``synapse-s2.release-floor.v1`` — the local, owner-only, unsigned
  monotonic floor stored outside ``.synapse_s2``: the accepted root key,
  trust generation and bundle digest, per-channel minimum and installed
  sequence plus the installed envelope/source/policy/product identities,
  the cumulative sorted list of every committed revoked key id, and the
  committed clock.

Monotonic floor semantics: a lower trust generation or release sequence is
blocked; an equal trust generation requires the exact accepted bundle
digest; an equal installed sequence requires the exact installed envelope
digest and identities (idempotency); a higher sequence verifies without
advancing the floor until ``record-installed-release``; a higher trust
generation is only committed by ``accept-trust-bundle``.  A system clock
behind the committed floor clock is blocked.  Trust rotation invalidates
envelopes that were not re-signed: an envelope's trust generation must
equal the presented bundle's generation exactly.  Revocations are
cumulative: a bundle that omits a previously committed revocation, or
delegates a previously revoked key, is blocked regardless of generation.

The root key signs trust bundles only; delegated release keys sign
envelopes only, within their delegated role, channels, validity window,
inclusive sequence bounds, and subject to revocation.  A delegation only
verifies while the current time is inside its validity window and the
envelope's whole issued_at/expires_at validity is contained in it.  A
bundle delegating or revoking its own root key is malformed.

Output is one bounded, deterministic, redacted JSON line: status tokens
and document identities only — never filesystem paths, key material,
signatures, or exception text.  ``apply_supported`` and ``apply_performed``
are always false.  Exit codes: 0 verified/idempotent success, 3
stale/rollback/equivocation/revoked/expired/identity mismatch, 2
malformed/unsafe/raced/unsupported.  A mutation whose commit cannot be
proven either way reports ``outcome_unknown:<token>`` (exit 2) and the
next confirmed call reconciles idempotently.

Import hardening: before any non-builtin import, ``sys.path`` is rebuilt
using builtins only — PYTHONPATH, cwd, and repository entries are dropped;
only the interpreter's stdlib locations plus the isolated trusted
environment's own site-packages (for ``cryptography`` 49) are retained,
with stdlib entries first so nothing in site-packages can shadow the
stdlib.  The imported ``cryptography`` must be version 49.0.0 exactly and
must, after symlink resolution, originate from within that admitted
site-packages directory, or every command fails closed.  No repository or candidate module is ever imported.  The
hardened operator invocation is ``python -I trusted/scripts/release_provenance.py``
from the isolated trusted environment; isolated mode closes the
interpreter-startup window this module cannot control.
"""

import sys

# Preserve the caller's process-global state exactly so importing this
# verifier as an API cannot perturb a long-lived test or operator process.
_ORIGINAL_SYS_PATH = list(sys.path)
_ORIGINAL_DONT_WRITE_BYTECODE = sys.dont_write_bytecode

# No bytecode caching for any import this module performs.
sys.dont_write_bytecode = True

_TRUSTED_SITE_PACKAGES: str | None = None


def _sanitize_sys_path() -> None:
    """Rebuild sys.path using builtins only, before any non-builtin import.
    Admitted entries are exactly the startup-loaded stdlib directory, its
    lib-dynload directory, the versioned stdlib zip, and — last, so it can
    never shadow the stdlib — the running trusted environment's own
    site-packages directory, which is the only permitted origin for
    ``cryptography``.  No repository path is admitted and no import-hijack
    lane is created: PYTHONPATH, cwd, and user site never survive."""
    global _TRUSTED_SITE_PACKAGES

    def _clean(entry: object) -> bool:
        return (
            isinstance(entry, str)
            and entry.startswith("/")
            and "\x00" not in entry
            and not any(
                part in ("", ".", "..") for part in entry.split("/")[1:]
            )
        )

    os_file = getattr(sys.modules.get("os"), "__file__", None)
    if not (
        isinstance(os_file, str)
        and _clean(os_file)
        and "/" in os_file[1:]
    ):
        raise ImportError("untrusted standard library location")
    stdlib_dir = os_file.rsplit("/", 1)[0]
    stdlib_parent = stdlib_dir.rsplit("/", 1)[0]
    versioned_zip = (
        stdlib_parent
        + "/python"
        + str(sys.version_info.major)
        + str(sys.version_info.minor)
        + ".zip"
    )
    prefix = sys.prefix
    if not _clean(prefix):
        raise ImportError("untrusted interpreter prefix")
    site_packages = (
        prefix
        + "/lib/python"
        + str(sys.version_info.major)
        + "."
        + str(sys.version_info.minor)
        + "/site-packages"
    )
    sanitized: list[str] = []
    for entry in (
        versioned_zip,
        stdlib_dir,
        stdlib_dir + "/lib-dynload",
        site_packages,
    ):
        if not _clean(entry):
            continue
        if entry not in sanitized:
            sanitized.append(entry)
    if len(sanitized) != 4:
        raise ImportError("untrusted standard library location")
    _TRUSTED_SITE_PACKAGES = site_packages
    sys.path[:] = sanitized


_sanitize_sys_path()

import argparse
import hashlib
import json
import os
import re
import stat
import time

try:
    import fcntl
except Exception:  # pragma: no cover - platform gate refuses instead
    fcntl = None


def _import_trusted_cryptography():
    """Import Ed25519 primitives from the isolated trusted environment only.
    Any import failure, a version other than exactly 49.0.0, or a
    symlink-resolved on-disk origin outside the admitted site-packages
    returns None and every command fails closed; nothing else is ever
    imported."""
    admitted = _TRUSTED_SITE_PACKAGES
    if not isinstance(admitted, str):
        return None
    try:
        import cryptography
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except Exception:
        return None
    version = getattr(cryptography, "__version__", None)
    if not (isinstance(version, str) and version == "49.0.0"):
        return None
    admitted_real = os.path.realpath(admitted)
    for module in (cryptography, ed25519):
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str):
            return None
        if not os.path.realpath(origin).startswith(admitted_real + "/"):
            return None
    return ed25519


_ED25519 = _import_trusted_cryptography()

# CLI execution keeps the hardened import policy for the process lifetime.
# API imports restore the caller's exact process-global state; no further
# dynamic import happens below.
if __name__ != "__main__":
    sys.path[:] = _ORIGINAL_SYS_PATH
    sys.dont_write_bytecode = _ORIGINAL_DONT_WRITE_BYTECODE

RESULT_SCHEMA = "synapse-s2.release-provenance-result.v1"
RESULT_MODE = "incumbent-release-provenance"

ROOT_SCHEMA = "synapse-s2.release-root.v1"
BUNDLE_SCHEMA = "synapse-s2.release-trust-bundle.v1"
BUNDLE_SCHEMA_V2 = "synapse-s2.release-trust-bundle.v2"
ENVELOPE_SCHEMA = "synapse-s2.release-envelope.v1"
FLOOR_SCHEMA = "synapse-s2.release-floor.v1"
PRODUCT_SCHEMA = "synapse-s2.product-release-plan.v1"

# Closed per-schema delegation role vocabularies.  The v1 vocabulary is
# frozen forever; v2 adds exactly one further role.  A key id may appear
# in at most one delegation, so no single key can ever hold both roles.
DELEGATION_ROLE_RELEASE = "release"
DELEGATION_ROLE_COMPATIBILITY = "compatibility-review"
_BUNDLE_ROLES_BY_SCHEMA = {
    BUNDLE_SCHEMA: (DELEGATION_ROLE_RELEASE,),
    BUNDLE_SCHEMA_V2: (
        DELEGATION_ROLE_COMPATIBILITY,
        DELEGATION_ROLE_RELEASE,
    ),
}

COMMAND_VERIFY = "verify-release"
COMMAND_ACCEPT = "accept-trust-bundle"
COMMAND_RECORD = "record-installed-release"

STATUS_VERIFIED = "verified"
STATUS_ACCEPTED = "accepted"
STATUS_RECORDED = "recorded"

_SUCCESS_STATUSES = frozenset(
    (STATUS_VERIFIED, STATUS_ACCEPTED, STATUS_RECORDED)
)

RESULT_NONCLAIMS = (
    "bootstrap-trust-out-of-band",
    "no-apply",
    "no-candidate-execution",
    "no-live-state-access",
    "no-recovery-access",
)

# Domain separation: a signature or digest computed for one purpose can
# never verify for another.
_KEY_ID_DOMAIN = b"SYNAPSE-S2\x00ED25519-PUBLIC-KEY\x00v1\x00"
_BUNDLE_SIGNING_DOMAIN = b"SYNAPSE-S2\x00RELEASE-TRUST-BUNDLE\x00v1\x00"
_BUNDLE_SIGNING_DOMAIN_V2 = b"SYNAPSE-S2\x00RELEASE-TRUST-BUNDLE\x00v2\x00"
_ENVELOPE_SIGNING_DOMAIN = b"SYNAPSE-S2\x00RELEASE-ENVELOPE\x00v1\x00"

_BUNDLE_DOMAINS_BY_SCHEMA = {
    BUNDLE_SCHEMA: _BUNDLE_SIGNING_DOMAIN,
    BUNDLE_SCHEMA_V2: _BUNDLE_SIGNING_DOMAIN_V2,
}

# Hard bounds, enforced before the offending byte or entry is consumed.
MAX_DOCUMENT_BYTES = 64 * 1024
MAX_RESULT_BYTES = 4096
MAX_PATH_BYTES = 4096
MAX_DELEGATIONS = 16
MAX_BUNDLE_CHANNELS = 16
MAX_FLOOR_CHANNELS = 64
MAX_REVOCATIONS = 64
MAX_INT = 2**53

_KEY_ID_RE = re.compile(r"ed25519-[0-9a-f]{64}")
_HEX_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}")
_PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{64}")
_SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}")
_PRODUCT_ID_RE = re.compile(r"product-[0-9a-f]{64}")
_POLICY_ID_RE = re.compile(r"inventory-policy-[0-9a-f]{64}")
_CHANNEL_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,63}")

# Path components that must never appear in any operand path (compared
# case-insensitively: hostile paths on case-insensitive filesystems must
# not slip past): the live store, every recovery location, and the
# updater's own state live under these names.
_FORBIDDEN_PATH_COMPONENTS = frozenset(
    (".synapse_s2", "recovery", "updater-state")
)

_GROUP_OR_WORLD_WRITE = 0o022
_FLOOR_LOCK_SUFFIX = ".lock"

_O_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", None)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", None)

_DIR_OPEN_FLAGS = (
    os.O_RDONLY | (_O_DIRECTORY or 0) | (_O_NOFOLLOW or 0) | (_O_CLOEXEC or 0)
)
# O_NONBLOCK: a document swapped to a FIFO between the no-follow stat and
# the open can never block; for regular files it is a no-op.
_FILE_OPEN_FLAGS = (
    os.O_RDONLY
    | (_O_NOFOLLOW or 0)
    | (_O_CLOEXEC or 0)
    | (_O_NONBLOCK or 0)
)

_PLATFORM_SUPPORTED = (
    None not in (_O_DIRECTORY, _O_NOFOLLOW, _O_CLOEXEC, _O_NONBLOCK)
    and fcntl is not None
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.rename in os.supports_dir_fd
    and os.unlink in os.supports_dir_fd
    and hasattr(os, "fchmod")
)


class _Refusal(Exception):
    """Exit 2: malformed, unsafe, raced, or unsupported."""

    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


class _Blocked(Exception):
    """Exit 3: stale, rollback, equivocation, revoked, expired, or an
    identity mismatch discovered across verified documents."""

    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


class _OutcomeUnknown(Exception):
    """Exit 2 with an ``outcome_unknown:`` status: the floor mutation may
    or may not have committed durably.  The previous floor is never
    corrupted; the next confirmed call reconciles idempotently."""

    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


class _CliArgumentError(Exception):
    pass


def _now() -> int:
    return int(time.time())


def canonical_bytes(document) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _reject_float(value: str):
    raise _Refusal("document-float")


def _reject_constant(value: str):
    raise _Refusal("document-nonfinite")


def _reject_duplicate_keys(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise _Refusal("document-duplicate-key")
    return dict(pairs)


def parse_canonical_document(data: bytes) -> dict:
    """Strict parse: UTF-8 (in fact ASCII), no floats, no NaN/Infinity, no
    duplicate keys, top-level object, and the input must be byte-identical
    to the canonical re-encoding with no trailing newline: what is signed
    is exactly what is stored."""
    if not isinstance(data, bytes):
        raise _Refusal("document-malformed")
    if len(data) > MAX_DOCUMENT_BYTES:
        raise _Refusal("document-oversize")
    try:
        text = data.decode("utf-8")
    except Exception:
        raise _Refusal("document-encoding")
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except _Refusal:
        raise
    except Exception:
        raise _Refusal("document-malformed")
    if not isinstance(document, dict):
        raise _Refusal("document-malformed")
    if data != canonical_bytes(document):
        raise _Refusal("document-noncanonical")
    return document


def _require_exact_fields(
    document: dict, fields: tuple[str, ...], token: str
) -> None:
    if set(document) != set(fields):
        raise _Refusal(token)


def _string(value, token: str, pattern: re.Pattern | None = None) -> str:
    if type(value) is not str:
        raise _Refusal(token)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise _Refusal(token)
    return value


def _integer(
    value, token: str, minimum: int = 0, maximum: int = MAX_INT
) -> int:
    # bool is an int subclass; ``type is int`` rejects booleans-as-integers.
    if type(value) is not int:
        raise _Refusal(token)
    if not minimum <= value <= maximum:
        raise _Refusal(token)
    return value


def key_id_for_public_key(public_key_hex: str) -> str:
    raw = bytes.fromhex(public_key_hex)
    return (
        "ed25519-"
        + hashlib.sha256(_KEY_ID_DOMAIN + raw).hexdigest()
    )


def _unsigned_signing_payload(document: dict, domain: bytes) -> bytes:
    unsigned = {
        key: value for key, value in document.items() if key != "signature"
    }
    return domain + canonical_bytes(unsigned)


def _signature_valid(
    public_key_hex: str, signature_hex: str, payload: bytes
) -> bool:
    if _ED25519 is None:
        raise _Refusal("crypto-unavailable")
    try:
        public = _ED25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(public_key_hex)
        )
        public.verify(bytes.fromhex(signature_hex), payload)
    except Exception:
        return False
    return True


def _validate_root_document(document: dict) -> tuple[str, str]:
    token = "root-invalid"
    _require_exact_fields(
        document, ("schema", "root_key_id", "root_public_key"), token
    )
    if document["schema"] != ROOT_SCHEMA:
        raise _Refusal(token)
    public_key = _string(document["root_public_key"], token, _PUBLIC_KEY_RE)
    key_id = _string(document["root_key_id"], token, _KEY_ID_RE)
    if key_id != key_id_for_public_key(public_key):
        raise _Refusal(token)
    return key_id, public_key


_BUNDLE_FIELDS = (
    "schema",
    "root_key_id",
    "generation",
    "issued_at",
    "expires_at",
    "channel_minimum_sequences",
    "delegations",
    "revoked_key_ids",
    "signature",
)

_DELEGATION_FIELDS = (
    "key_id",
    "public_key",
    "role",
    "channels",
    "not_before",
    "not_after",
    "sequence_minimum",
    "sequence_maximum",
)


def _validate_bundle_syntax(document: dict) -> None:
    """Single-document checks only: exact fields, closed vocabularies,
    bounds, internal consistency.  Cross-document and signature checks
    happen in _verify_bundle."""
    token = "bundle-invalid"
    _require_exact_fields(document, _BUNDLE_FIELDS, token)
    schema = document["schema"]
    allowed_roles = (
        _BUNDLE_ROLES_BY_SCHEMA.get(schema) if type(schema) is str else None
    )
    if allowed_roles is None:
        raise _Refusal(token)
    bundle_root_key_id = _string(document["root_key_id"], token, _KEY_ID_RE)
    _integer(document["generation"], token, minimum=1)
    issued_at = _integer(document["issued_at"], token)
    expires_at = _integer(document["expires_at"], token)
    if expires_at <= issued_at:
        raise _Refusal(token)
    minima = document["channel_minimum_sequences"]
    if not isinstance(minima, dict) or not (
        1 <= len(minima) <= MAX_BUNDLE_CHANNELS
    ):
        raise _Refusal(token)
    for channel, minimum in minima.items():
        _string(channel, token, _CHANNEL_RE)
        _integer(minimum, token)
    delegations = document["delegations"]
    if not isinstance(delegations, list) or len(delegations) > MAX_DELEGATIONS:
        raise _Refusal(token)
    seen_key_ids: set[str] = set()
    seen_roles: set[str] = set()
    for delegation in delegations:
        if not isinstance(delegation, dict):
            raise _Refusal(token)
        _require_exact_fields(delegation, _DELEGATION_FIELDS, token)
        public_key = _string(delegation["public_key"], token, _PUBLIC_KEY_RE)
        key_id = _string(delegation["key_id"], token, _KEY_ID_RE)
        if key_id != key_id_for_public_key(public_key):
            raise _Refusal(token)
        if delegation["role"] not in allowed_roles:
            raise _Refusal(token)
        seen_roles.add(delegation["role"])
        # The root key signs bundles only; a bundle delegating its own
        # root key as a release key is malformed on its face.
        if key_id == bundle_root_key_id:
            raise _Refusal("bundle-root-delegated")
        if key_id in seen_key_ids:
            raise _Refusal(token)
        seen_key_ids.add(key_id)
        channels = delegation["channels"]
        if not isinstance(channels, list) or not (
            1 <= len(channels) <= MAX_BUNDLE_CHANNELS
        ):
            raise _Refusal(token)
        if channels != sorted(set(channels), key=str):
            raise _Refusal(token)
        for channel in channels:
            _string(channel, token, _CHANNEL_RE)
            if channel not in minima:
                raise _Refusal(token)
        not_before = _integer(delegation["not_before"], token)
        not_after = _integer(delegation["not_after"], token)
        if not_after <= not_before:
            raise _Refusal(token)
        sequence_minimum = _integer(
            delegation["sequence_minimum"], token, minimum=1
        )
        sequence_maximum = _integer(
            delegation["sequence_maximum"], token, minimum=1
        )
        if sequence_maximum < sequence_minimum:
            raise _Refusal(token)
    if document["schema"] == BUNDLE_SCHEMA_V2 and seen_roles != set(
        _BUNDLE_ROLES_BY_SCHEMA[BUNDLE_SCHEMA_V2]
    ):
        # A v2 bundle exists to carry the two-role vocabulary: both role
        # sets must be nonempty (each on a distinct key id, enforced by the
        # duplicate-key check above).  v1 bundles are unchanged.
        raise _Refusal(token)
    revoked = document["revoked_key_ids"]
    if not isinstance(revoked, list) or len(revoked) > MAX_REVOCATIONS:
        raise _Refusal(token)
    if revoked != sorted(set(revoked), key=str):
        raise _Refusal(token)
    for key_id in revoked:
        _string(key_id, token, _KEY_ID_RE)
        if key_id == bundle_root_key_id:
            raise _Refusal("bundle-root-revoked")
    _string(document["signature"], token, _SIGNATURE_RE)


def _verify_bundle(
    document: dict, root_key_id: str, root_public_key: str, now: int
) -> None:
    """Cross-document verification of an already syntax-valid bundle.
    The signing domain is selected by the bundle schema, so a v1
    signature can never verify a v2 bundle or vice versa."""
    if document["root_key_id"] != root_key_id:
        raise _Blocked("bundle-root-mismatch")
    if not _signature_valid(
        root_public_key,
        document["signature"],
        _unsigned_signing_payload(
            document, _BUNDLE_DOMAINS_BY_SCHEMA[document["schema"]]
        ),
    ):
        raise _Blocked("bundle-signature-invalid")
    if now < document["issued_at"]:
        raise _Blocked("bundle-not-yet-valid")
    if now >= document["expires_at"]:
        raise _Blocked("bundle-expired")


_ENVELOPE_FIELDS = (
    "schema",
    "channel",
    "version",
    "sequence",
    "source_sha",
    "product_schema",
    "inventory_policy_id",
    "product_id",
    "trust_generation",
    "issued_at",
    "expires_at",
    "key_id",
    "signature",
)


def _validate_envelope_syntax(document: dict) -> None:
    token = "envelope-invalid"
    _require_exact_fields(document, _ENVELOPE_FIELDS, token)
    if document["schema"] != ENVELOPE_SCHEMA:
        raise _Refusal(token)
    _string(document["channel"], token, _CHANNEL_RE)
    _string(document["version"], token, _VERSION_RE)
    _integer(document["sequence"], token, minimum=1)
    _string(document["source_sha"], token, _SOURCE_SHA_RE)
    if document["product_schema"] != PRODUCT_SCHEMA:
        raise _Refusal(token)
    _string(document["inventory_policy_id"], token, _POLICY_ID_RE)
    _string(document["product_id"], token, _PRODUCT_ID_RE)
    _integer(document["trust_generation"], token, minimum=1)
    issued_at = _integer(document["issued_at"], token)
    expires_at = _integer(document["expires_at"], token)
    if expires_at <= issued_at:
        raise _Refusal(token)
    _string(document["key_id"], token, _KEY_ID_RE)
    _string(document["signature"], token, _SIGNATURE_RE)


def _verify_envelope(
    envelope: dict, bundle: dict, root_key_id: str, now: int
) -> None:
    """Cross-document verification of an already syntax-valid envelope
    against an already verified bundle."""
    key_id = envelope["key_id"]
    if key_id == root_key_id:
        # The root key never signs envelopes.
        raise _Blocked("root-signed-envelope")
    if key_id in bundle["revoked_key_ids"]:
        raise _Blocked("key-revoked")
    delegation = None
    for candidate in bundle["delegations"]:
        if candidate["key_id"] == key_id:
            delegation = candidate
            break
    if delegation is None:
        raise _Blocked("delegation-unknown")
    if delegation["role"] != DELEGATION_ROLE_RELEASE:
        # Role confusion: only a release-role delegation signs envelopes.
        # Every v1 delegation is release-role, so v1 behavior is unchanged.
        raise _Blocked("delegation-role-mismatch")
    if envelope["channel"] not in delegation["channels"]:
        raise _Blocked("channel-not-delegated")
    if not (
        delegation["not_before"]
        <= envelope["issued_at"]
        < delegation["not_after"]
    ):
        raise _Blocked("delegation-window")
    if envelope["expires_at"] > delegation["not_after"]:
        # The envelope's whole validity must be contained in the
        # delegation's: a delegate cannot mint trust outliving its grant.
        raise _Blocked("delegation-window")
    if now < delegation["not_before"]:
        raise _Blocked("delegation-not-yet-valid")
    if now >= delegation["not_after"]:
        raise _Blocked("delegation-expired")
    if envelope["trust_generation"] != bundle["generation"]:
        raise _Blocked("trust-generation-mismatch")
    minimum = bundle["channel_minimum_sequences"].get(envelope["channel"])
    if minimum is None:
        raise _Blocked("channel-unknown")
    if envelope["sequence"] < minimum:
        raise _Blocked("sequence-below-minimum")
    if not (
        delegation["sequence_minimum"]
        <= envelope["sequence"]
        <= delegation["sequence_maximum"]
    ):
        raise _Blocked("sequence-outside-delegation")
    if not _signature_valid(
        delegation["public_key"],
        envelope["signature"],
        _unsigned_signing_payload(envelope, _ENVELOPE_SIGNING_DOMAIN),
    ):
        raise _Blocked("envelope-signature-invalid")
    if now < envelope["issued_at"]:
        raise _Blocked("envelope-not-yet-valid")
    if now >= envelope["expires_at"]:
        raise _Blocked("envelope-expired")


_FLOOR_FIELDS = (
    "schema",
    "root_key_id",
    "trust_generation",
    "trust_bundle_sha256",
    "committed_at",
    "revoked_key_ids",
    "channels",
)

_FLOOR_CHANNEL_FIELDS = ("minimum_sequence", "installed")

_FLOOR_INSTALLED_FIELDS = (
    "sequence",
    "envelope_sha256",
    "source_sha",
    "inventory_policy_id",
    "product_id",
)


def _validate_floor_syntax(document: dict) -> None:
    token = "floor-invalid"
    _require_exact_fields(document, _FLOOR_FIELDS, token)
    if document["schema"] != FLOOR_SCHEMA:
        raise _Refusal(token)
    _string(document["root_key_id"], token, _KEY_ID_RE)
    _integer(document["trust_generation"], token, minimum=1)
    _string(document["trust_bundle_sha256"], token, _HEX_SHA256_RE)
    _integer(document["committed_at"], token)
    revoked = document["revoked_key_ids"]
    if not isinstance(revoked, list) or len(revoked) > MAX_REVOCATIONS:
        raise _Refusal(token)
    if revoked != sorted(set(revoked), key=str):
        raise _Refusal(token)
    for key_id in revoked:
        _string(key_id, token, _KEY_ID_RE)
    channels = document["channels"]
    if not isinstance(channels, dict) or len(channels) > MAX_FLOOR_CHANNELS:
        raise _Refusal(token)
    for channel, state in channels.items():
        _string(channel, token, _CHANNEL_RE)
        if not isinstance(state, dict):
            raise _Refusal(token)
        _require_exact_fields(state, _FLOOR_CHANNEL_FIELDS, token)
        _integer(state["minimum_sequence"], token)
        installed = state["installed"]
        if installed is None:
            continue
        if not isinstance(installed, dict):
            raise _Refusal(token)
        _require_exact_fields(installed, _FLOOR_INSTALLED_FIELDS, token)
        _integer(installed["sequence"], token, minimum=1)
        _string(installed["envelope_sha256"], token, _HEX_SHA256_RE)
        _string(installed["source_sha"], token, _SOURCE_SHA_RE)
        _string(installed["inventory_policy_id"], token, _POLICY_ID_RE)
        _string(installed["product_id"], token, _PRODUCT_ID_RE)


def _check_floor_trust(
    floor: dict, root_key_id: str, bundle: dict, bundle_sha256: str, now: int
) -> None:
    """Monotonic floor checks shared by every command that sees a floor."""
    if floor["root_key_id"] != root_key_id:
        raise _Blocked("floor-root-mismatch")
    if now < floor["committed_at"]:
        raise _Blocked("clock-before-floor")
    if bundle["generation"] < floor["trust_generation"]:
        raise _Blocked("trust-generation-stale")
    if (
        bundle["generation"] == floor["trust_generation"]
        and bundle_sha256 != floor["trust_bundle_sha256"]
    ):
        raise _Blocked("trust-bundle-equivocation")
    # Revocations are cumulative: whatever the generation, a presented
    # bundle must retain every committed revocation and must not delegate
    # a committed-revoked key.
    floor_revoked = frozenset(floor["revoked_key_ids"])
    if not floor_revoked <= frozenset(bundle["revoked_key_ids"]):
        raise _Blocked("revocation-forgotten")
    for delegation in bundle["delegations"]:
        if delegation["key_id"] in floor_revoked:
            raise _Blocked("revoked-key-redelegated")


def _check_floor_release(
    floor: dict, envelope: dict, envelope_sha256: str
) -> bool:
    """Sequence checks of a verified envelope against the floor.  Returns
    True when the envelope is exactly the recorded installed release."""
    state = floor["channels"].get(envelope["channel"])
    if state is None:
        return False
    if envelope["sequence"] < state["minimum_sequence"]:
        raise _Blocked("sequence-below-floor")
    installed = state["installed"]
    if installed is None:
        return False
    if envelope["sequence"] < installed["sequence"]:
        raise _Blocked("sequence-rollback")
    if envelope["sequence"] == installed["sequence"]:
        if (
            envelope_sha256 != installed["envelope_sha256"]
            or envelope["source_sha"] != installed["source_sha"]
            or envelope["inventory_policy_id"]
            != installed["inventory_policy_id"]
            or envelope["product_id"] != installed["product_id"]
        ):
            raise _Blocked("release-equivocation")
        return True
    return False


def _check_expected_identities(
    envelope: dict,
    expected_source_sha: str | None,
    expected_inventory_policy_id: str | None,
    expected_product_id: str | None,
) -> None:
    if (
        expected_source_sha is not None
        and envelope["source_sha"] != expected_source_sha
    ):
        raise _Blocked("expected-source-sha-mismatch")
    if (
        expected_inventory_policy_id is not None
        and envelope["inventory_policy_id"] != expected_inventory_policy_id
    ):
        raise _Blocked("expected-inventory-policy-mismatch")
    if (
        expected_product_id is not None
        and envelope["product_id"] != expected_product_id
    ):
        raise _Blocked("expected-product-id-mismatch")


def _validate_path_argument(value, forbid_components: bool = True) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise _Refusal("invalid-arguments")
    if "\x00" in value or len(value.encode("utf-8", "replace")) > MAX_PATH_BYTES:
        raise _Refusal("invalid-arguments")
    parts = value.split("/")[1:]
    if any(part in ("", ".", "..") for part in parts):
        raise _Refusal("invalid-arguments")
    if forbid_components and any(
        part.lower() in _FORBIDDEN_PATH_COMPONENTS for part in parts
    ):
        raise _Refusal("forbidden-path")
    return value


def _fingerprint(observed: os.stat_result) -> tuple:
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_mode,
        observed.st_uid,
        observed.st_nlink,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
    )


def _screen_regular_file(
    observed: os.stat_result, owner_only: bool
) -> None:
    if not stat.S_ISREG(observed.st_mode):
        raise _Refusal("unsafe-file")
    if observed.st_nlink != 1:
        raise _Refusal("unsafe-file")
    if observed.st_uid != os.geteuid():
        raise _Refusal("unsafe-file")
    mode = stat.S_IMODE(observed.st_mode)
    if owner_only:
        if mode not in (0o600, 0o400):
            raise _Refusal("unsafe-file")
    elif mode & _GROUP_OR_WORLD_WRITE:
        raise _Refusal("unsafe-file")


def _screen_directory(observed: os.stat_result) -> None:
    if not stat.S_ISDIR(observed.st_mode):
        raise _Refusal("unsafe-path")


def _walk_to_parent(
    path: str, fds: list[int]
) -> tuple[int, str, list[tuple[int, str, int]]]:
    """Open every ancestor of ``path`` dir_fd-relative with a no-follow
    stat plus O_DIRECTORY|O_NOFOLLOW open anchored at ``/``, so no ancestor
    symlink is ever followed and no pathname is re-resolved.  Returns the
    held parent descriptor, the leaf name, and one (parent_fd, name,
    child_fd) step per component so callers can re-prove, after their
    reads and before success, that every held directory is still the one
    visible under its name."""
    parts = path.split("/")[1:]
    directory_fd = os.open("/", _DIR_OPEN_FLAGS)
    fds.append(directory_fd)
    steps: list[tuple[int, str, int]] = []
    for name in parts[:-1]:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _screen_directory(before)
        child_fd = os.open(name, _DIR_OPEN_FLAGS, dir_fd=directory_fd)
        fds.append(child_fd)
        after = os.fstat(child_fd)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise _Refusal("validation-race")
        steps.append((directory_fd, name, child_fd))
        directory_fd = child_fd
    return directory_fd, parts[-1], steps


def _verify_visible_steps(steps) -> None:
    """Prove that every held directory of a completed walk is still the
    component visible under its name in its held parent: the identity
    actually used is the identity finally visible on the path."""
    for parent_fd, name, child_fd in steps:
        held = os.fstat(child_fd)
        try:
            visible = os.stat(
                name, dir_fd=parent_fd, follow_symlinks=False
            )
        except OSError:
            raise _Refusal("validation-race")
        if (held.st_dev, held.st_ino) != (visible.st_dev, visible.st_ino):
            raise _Refusal("validation-race")


def _read_document_at(
    directory_fd: int,
    leaf: str,
    owner_only: bool,
    missing_ok: bool,
    steps=(),
) -> tuple[bytes, os.stat_result] | None:
    """Race-checked read of one document.  After all reads it re-proves
    the walk steps and the leaf's finally visible identity, so the bytes
    returned are the bytes of the file visible at the path at the end.
    Returns (data, fstat-after-read) or None when missing_ok."""
    try:
        before = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            _verify_visible_steps(steps)
            return None
        raise _Refusal("file-missing")
    _screen_regular_file(before, owner_only)
    if before.st_size > MAX_DOCUMENT_BYTES:
        raise _Refusal("document-oversize")
    file_fd = os.open(leaf, _FILE_OPEN_FLAGS, dir_fd=directory_fd)
    try:
        during = os.fstat(file_fd)
        if _fingerprint(before) != _fingerprint(during):
            raise _Refusal("validation-race")
        chunks: list[bytes] = []
        remaining = MAX_DOCUMENT_BYTES + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(file_fd)
        if _fingerprint(during) != _fingerprint(after):
            raise _Refusal("validation-race")
        if len(data) != before.st_size:
            raise _Refusal("validation-race")
        _verify_visible_steps(steps)
        try:
            visible = os.stat(
                leaf, dir_fd=directory_fd, follow_symlinks=False
            )
        except OSError:
            raise _Refusal("validation-race")
        if (visible.st_dev, visible.st_ino) != (after.st_dev, after.st_ino):
            raise _Refusal("validation-race")
        if _fingerprint(visible) != _fingerprint(after):
            raise _Refusal("validation-race")
        return data, after
    finally:
        os.close(file_fd)


def _read_safe_document(
    path: str, owner_only: bool = False, missing_ok: bool = False
) -> bytes | None:
    fds: list[int] = []
    try:
        try:
            directory_fd, leaf, steps = _walk_to_parent(path, fds)
            result = _read_document_at(
                directory_fd, leaf, owner_only, missing_ok, steps=steps
            )
            return None if result is None else result[0]
        except (_Refusal, _Blocked):
            raise
        except OSError:
            raise _Refusal("file-unreadable")
    finally:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _build_result(
    command: str,
    status: str,
    *,
    channel=None,
    version=None,
    sequence=None,
    trust_generation=None,
    source_sha=None,
    inventory_policy_id=None,
    product_id=None,
    bundle_sha256=None,
    envelope_sha256=None,
    floor_present=None,
    floor_advanced: bool = False,
    idempotent: bool = False,
) -> dict:
    return {
        "schema": RESULT_SCHEMA,
        "mode": RESULT_MODE,
        "command": command,
        "status": status,
        "apply_supported": False,
        "apply_performed": False,
        "channel": channel,
        "version": version,
        "sequence": sequence,
        "trust_generation": trust_generation,
        "source_sha": source_sha,
        "inventory_policy_id": inventory_policy_id,
        "product_id": product_id,
        "bundle_sha256": bundle_sha256,
        "envelope_sha256": envelope_sha256,
        "floor_present": floor_present,
        "floor_advanced": floor_advanced,
        "idempotent": idempotent,
        "nonclaims": list(RESULT_NONCLAIMS),
    }


def render_result(result: dict) -> str:
    line = json.dumps(
        result,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    if len(line.encode("utf-8")) > MAX_RESULT_BYTES:
        return json.dumps(
            _build_result(
                str(result.get("command", "")),
                "unsupported:output-oversize",
            ),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    return line


def provenance_exit_code(result: dict) -> int:
    status = str(result.get("status"))
    if status in _SUCCESS_STATUSES:
        return 0
    if status.startswith("blocked:"):
        return 3
    return 2


def _guard(command: str, work) -> dict:
    """Run ``work`` and collapse every failure to the deterministic
    redacted result contract: tokens only, never exception text."""
    try:
        try:
            return work()
        except (_Refusal, _Blocked, _OutcomeUnknown):
            raise
        except Exception:
            raise _Refusal("internal-error")
    except _Blocked as blocked:
        return _build_result(command, "blocked:" + blocked.token)
    except _OutcomeUnknown as unknown:
        return _build_result(command, "outcome_unknown:" + unknown.token)
    except _Refusal as refusal:
        return _build_result(command, "unsupported:" + refusal.token)


def _require_supported() -> None:
    if not _PLATFORM_SUPPORTED:
        raise _Refusal("platform-unsupported")
    if _ED25519 is None:
        raise _Refusal("crypto-unavailable")


def _load_chain(
    root_path: str, bundle_path: str, envelope_path: str, now: int
) -> tuple[str, dict, str, dict, str]:
    """Read and fully verify root -> bundle -> envelope.  Returns the root
    key id, bundle document and digest, envelope document and digest."""
    root_bytes = _read_safe_document(root_path)
    bundle_bytes = _read_safe_document(bundle_path)
    envelope_bytes = _read_safe_document(envelope_path)
    root_key_id, root_public_key = _validate_root_document(
        parse_canonical_document(root_bytes)
    )
    bundle = parse_canonical_document(bundle_bytes)
    _validate_bundle_syntax(bundle)
    _verify_bundle(bundle, root_key_id, root_public_key, now)
    envelope = parse_canonical_document(envelope_bytes)
    _validate_envelope_syntax(envelope)
    _verify_envelope(envelope, bundle, root_key_id, now)
    return (
        root_key_id,
        bundle,
        hashlib.sha256(bundle_bytes).hexdigest(),
        envelope,
        hashlib.sha256(envelope_bytes).hexdigest(),
    )


def _load_floor(
    floor_path: str,
) -> dict | None:
    floor_bytes = _read_safe_document(
        floor_path, owner_only=True, missing_ok=True
    )
    if floor_bytes is None:
        return None
    floor = parse_canonical_document(floor_bytes)
    _validate_floor_syntax(floor)
    return floor


def verify_release(
    root_path,
    bundle_path,
    envelope_path,
    floor_path,
    expected_source_sha=None,
    expected_inventory_policy_id=None,
    expected_product_id=None,
) -> dict:
    """Read-only chain verification; never writes anything anywhere."""

    def work() -> dict:
        _require_supported()
        root_file = _validate_path_argument(root_path)
        bundle_file = _validate_path_argument(bundle_path)
        envelope_file = _validate_path_argument(envelope_path)
        floor_file = _validate_path_argument(floor_path)
        for expected, pattern in (
            (expected_source_sha, _SOURCE_SHA_RE),
            (expected_inventory_policy_id, _POLICY_ID_RE),
            (expected_product_id, _PRODUCT_ID_RE),
        ):
            if expected is not None:
                _string(expected, "invalid-arguments", pattern)
        now = _now()
        (
            root_key_id,
            bundle,
            bundle_sha256,
            envelope,
            envelope_sha256,
        ) = _load_chain(root_file, bundle_file, envelope_file, now)
        floor = _load_floor(floor_file)
        idempotent = False
        if floor is not None:
            _check_floor_trust(floor, root_key_id, bundle, bundle_sha256, now)
            idempotent = _check_floor_release(floor, envelope, envelope_sha256)
        _check_expected_identities(
            envelope,
            expected_source_sha,
            expected_inventory_policy_id,
            expected_product_id,
        )
        return _build_result(
            COMMAND_VERIFY,
            STATUS_VERIFIED,
            channel=envelope["channel"],
            version=envelope["version"],
            sequence=envelope["sequence"],
            trust_generation=bundle["generation"],
            source_sha=envelope["source_sha"],
            inventory_policy_id=envelope["inventory_policy_id"],
            product_id=envelope["product_id"],
            bundle_sha256=bundle_sha256,
            envelope_sha256=envelope_sha256,
            floor_present=floor is not None,
            floor_advanced=False,
            idempotent=idempotent,
        )

    return _guard(COMMAND_VERIFY, work)


def _screen_floor_parent(directory_fd: int) -> None:
    """The floor's direct parent must be a stable, owner-only directory
    owned by the invoking user: no other principal may create, replace, or
    remove entries within it."""
    observed = os.fstat(directory_fd)
    if not stat.S_ISDIR(observed.st_mode):
        raise _Refusal("unsafe-parent")
    if observed.st_uid != os.geteuid():
        raise _Refusal("unsafe-parent")
    if stat.S_IMODE(observed.st_mode) & 0o077:
        raise _Refusal("unsafe-parent")


def _verify_lock_identity(
    directory_fd: int, lock_leaf: str, lock_fd: int
) -> None:
    """The held, flocked descriptor must still be the file visible under
    the lock name; a lock file unlinked or replaced underneath the
    descriptor excludes nobody."""
    held = os.fstat(lock_fd)
    try:
        visible = os.stat(
            lock_leaf, dir_fd=directory_fd, follow_symlinks=False
        )
    except OSError:
        raise _Refusal("floor-lock-replaced")
    if (held.st_dev, held.st_ino) != (visible.st_dev, visible.st_ino):
        raise _Refusal("floor-lock-replaced")


def _acquire_floor_lock(
    directory_fd: int, lock_leaf: str, fds: list[int]
) -> int:
    """Owner-only advisory exclusive lock next to the floor file.  A held
    lock means another mutation is racing: refuse, never wait.  The exact
    0600 mode is forced with fchmod (a hostile umask must not widen a
    freshly created lock) and the lock's visible identity is proven after
    flock succeeds."""
    lock_fd = os.open(
        lock_leaf,
        os.O_RDWR
        | os.O_CREAT
        | (_O_NOFOLLOW or 0)
        | (_O_CLOEXEC or 0)
        | (_O_NONBLOCK or 0),
        0o600,
        dir_fd=directory_fd,
    )
    fds.append(lock_fd)
    observed = os.fstat(lock_fd)
    if not stat.S_ISREG(observed.st_mode):
        raise _Refusal("unsafe-file")
    if observed.st_nlink != 1:
        raise _Refusal("unsafe-file")
    if observed.st_uid != os.geteuid():
        raise _Refusal("unsafe-file")
    os.fchmod(lock_fd, 0o600)
    if stat.S_IMODE(os.fstat(lock_fd).st_mode) != 0o600:
        raise _Refusal("unsafe-file")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise _Refusal("floor-locked")
    _verify_lock_identity(directory_fd, lock_leaf, lock_fd)
    return lock_fd


def _floor_temp_leaf(floor_leaf: str) -> str:
    return (
        "."
        + floor_leaf
        + ".tmp-"
        + str(os.getpid())
        + "-"
        + os.urandom(8).hex()
    )


def _cas_floor(directory_fd: int, floor_leaf: str, expected) -> None:
    """Compare-and-swap guard immediately before the rename: the visible
    floor must still be exactly the one this mutation was computed from —
    absent when ``expected`` is None, otherwise matching both the captured
    stat fingerprint and the captured content digest."""
    try:
        visible = os.stat(
            floor_leaf, dir_fd=directory_fd, follow_symlinks=False
        )
    except FileNotFoundError:
        visible = None
    except OSError:
        raise _Refusal("floor-raced")
    if expected is None:
        if visible is not None:
            raise _Refusal("floor-raced")
        return
    expected_fingerprint, expected_sha256 = expected
    if visible is None or _fingerprint(visible) != expected_fingerprint:
        raise _Refusal("floor-raced")
    try:
        check_fd = os.open(floor_leaf, _FILE_OPEN_FLAGS, dir_fd=directory_fd)
    except OSError:
        raise _Refusal("floor-raced")
    try:
        held = os.fstat(check_fd)
        if _fingerprint(held) != expected_fingerprint:
            raise _Refusal("floor-raced")
        chunks: list[bytes] = []
        remaining = MAX_DOCUMENT_BYTES + 1
        while remaining > 0:
            chunk = os.read(check_fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if hashlib.sha256(b"".join(chunks)).hexdigest() != expected_sha256:
            raise _Refusal("floor-raced")
    finally:
        os.close(check_fd)


def _remove_owned_temp(
    directory_fd: int, temp_leaf: str, temp_fd: int
) -> None:
    """Unlink the temp name only while it provably still names this call's
    own temp file (same device and inode as the held descriptor).  A file
    someone else linked under the name is never deleted."""
    try:
        held = os.fstat(temp_fd)
        visible = os.stat(
            temp_leaf, dir_fd=directory_fd, follow_symlinks=False
        )
        if (held.st_dev, held.st_ino) == (visible.st_dev, visible.st_ino):
            os.unlink(temp_leaf, dir_fd=directory_fd)
    except OSError:
        pass


def _write_floor_atomically(
    directory_fd: int,
    floor_leaf: str,
    document: dict,
    steps,
    lock_fd: int,
    lock_leaf: str,
    expected,
) -> None:
    """Unique exclusive same-directory temp, full write with a
    zero-progress guard, exact fchmod 0600, fstat verification, temp
    fsync; then — with the parent, walk, lock identity, and floor CAS all
    re-proven immediately before the commit point — atomic rename over the
    floor, directory fsync, and a final visible-identity verification.
    After the rename the commit is re-proven end to end: a held read of
    the published floor's exact bytes, a post-read fstat with full
    fingerprint equality, a re-proof of every visible ancestor step, and
    a reopen/stat/read of the requested visible leaf proving the same
    identity, bytes, mode, owner, and link count, then a post-reread
    fstat with full fingerprint equality, one more re-proof of every
    visible ancestor step, and a final no-follow stat of the visible
    leaf proving the identity and fingerprint of the re-read file — the
    requested path must still name exactly the committed floor at the
    moment of success.
    Any pre-rename failure removes only this call's own temp and leaves
    the previous floor untouched; any post-rename ambiguity is reported as
    outcome-unknown, never as clean failure or success."""
    data = canonical_bytes(document)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise _Refusal("floor-oversize")
    temp_leaf = _floor_temp_leaf(floor_leaf)
    create_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | (_O_NOFOLLOW or 0)
        | (_O_CLOEXEC or 0)
    )
    try:
        temp_fd = os.open(temp_leaf, create_flags, 0o600, dir_fd=directory_fd)
    except FileExistsError:
        # A file this call did not create is never deleted, whatever it is.
        raise _Refusal("temp-exists")
    renamed = False
    try:
        try:
            written = 0
            while written < len(data):
                count = os.write(temp_fd, data[written:])
                if type(count) is not int or count <= 0:
                    raise _Refusal("floor-write-failed")
                written += count
            os.fchmod(temp_fd, 0o600)
            temp_stat = os.fstat(temp_fd)
            if not (
                stat.S_ISREG(temp_stat.st_mode)
                and stat.S_IMODE(temp_stat.st_mode) == 0o600
                and temp_stat.st_uid == os.geteuid()
                and temp_stat.st_nlink == 1
                and temp_stat.st_size == len(data)
            ):
                raise _Refusal("floor-write-failed")
            os.fsync(temp_fd)
            # Pre-publish: every identity the rename relies on is
            # re-proven under the lock, immediately before the commit.
            _screen_floor_parent(directory_fd)
            _verify_visible_steps(steps)
            _verify_lock_identity(directory_fd, lock_leaf, lock_fd)
            _cas_floor(directory_fd, floor_leaf, expected)
            os.rename(
                temp_leaf,
                floor_leaf,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            renamed = True
            os.fsync(directory_fd)
            visible = os.stat(
                floor_leaf, dir_fd=directory_fd, follow_symlinks=False
            )
            if not (
                (visible.st_dev, visible.st_ino)
                == (temp_stat.st_dev, temp_stat.st_ino)
                and stat.S_IMODE(visible.st_mode) == 0o600
                and visible.st_uid == os.geteuid()
                and visible.st_nlink == 1
                and visible.st_size == len(data)
            ):
                raise _Refusal("floor-write-failed")
            # Post-publish: hold the published floor open, prove its
            # exact bytes, then prove nothing moved during the read.
            check_fd = os.open(
                floor_leaf, _FILE_OPEN_FLAGS, dir_fd=directory_fd
            )
            try:
                held = os.fstat(check_fd)
                if (held.st_dev, held.st_ino) != (
                    visible.st_dev,
                    visible.st_ino,
                ):
                    raise _Refusal("floor-write-failed")
                committed = b""
                while len(committed) <= len(data):
                    chunk = os.read(check_fd, 65536)
                    if not chunk:
                        break
                    committed += chunk
                if committed != data:
                    raise _Refusal("floor-write-failed")
                final_held = os.fstat(check_fd)
                if not (
                    _fingerprint(final_held) == _fingerprint(held)
                    and stat.S_ISREG(final_held.st_mode)
                    and stat.S_IMODE(final_held.st_mode) == 0o600
                    and final_held.st_uid == os.geteuid()
                    and final_held.st_nlink == 1
                    and final_held.st_size == len(data)
                ):
                    raise _Refusal("floor-write-failed")
            finally:
                try:
                    os.close(check_fd)
                except OSError:
                    pass
            # The requested path must still reach exactly the committed
            # floor: re-prove every visible ancestor step, then reopen
            # the visible leaf and prove the same identity and bytes.
            _verify_visible_steps(steps)
            try:
                final_visible = os.stat(
                    floor_leaf, dir_fd=directory_fd, follow_symlinks=False
                )
            except OSError:
                raise _Refusal("floor-write-failed")
            if not (
                (final_visible.st_dev, final_visible.st_ino)
                == (final_held.st_dev, final_held.st_ino)
                and _fingerprint(final_visible) == _fingerprint(final_held)
            ):
                raise _Refusal("floor-write-failed")
            reopen_fd = os.open(
                floor_leaf, _FILE_OPEN_FLAGS, dir_fd=directory_fd
            )
            try:
                reopened = os.fstat(reopen_fd)
                if _fingerprint(reopened) != _fingerprint(final_held):
                    raise _Refusal("floor-write-failed")
                reread = b""
                while len(reread) <= len(data):
                    chunk = os.read(reopen_fd, 65536)
                    if not chunk:
                        break
                    reread += chunk
                if reread != data:
                    raise _Refusal("floor-write-failed")
                # Post-reread: prove nothing moved during the re-read
                # either — the reopened floor must still be the same
                # untouched regular owner-only file.
                final_reopened = os.fstat(reopen_fd)
                if not (
                    _fingerprint(final_reopened) == _fingerprint(reopened)
                    and stat.S_ISREG(final_reopened.st_mode)
                    and stat.S_IMODE(final_reopened.st_mode) == 0o600
                    and final_reopened.st_uid == os.geteuid()
                    and final_reopened.st_nlink == 1
                    and final_reopened.st_size == len(data)
                ):
                    raise _Refusal("floor-write-failed")
            finally:
                try:
                    os.close(reopen_fd)
                except OSError:
                    pass
            # The requested path must still reach exactly the re-read
            # floor at the moment of success: re-prove every visible
            # ancestor step once more, then prove the visible leaf is
            # the very file the re-read proved.
            _verify_visible_steps(steps)
            try:
                last_visible = os.stat(
                    floor_leaf, dir_fd=directory_fd, follow_symlinks=False
                )
            except OSError:
                raise _Refusal("floor-write-failed")
            if not (
                (last_visible.st_dev, last_visible.st_ino)
                == (final_reopened.st_dev, final_reopened.st_ino)
                and _fingerprint(last_visible) == _fingerprint(final_reopened)
            ):
                raise _Refusal("floor-write-failed")
        except (_Refusal, _Blocked, _OutcomeUnknown):
            raise
        except Exception:
            raise _Refusal("floor-write-failed")
    except _OutcomeUnknown:
        raise
    except (_Refusal, _Blocked):
        if renamed:
            # The new floor was renamed into place but its durability or
            # final visibility is unproven: neither clean failure nor
            # success may be claimed.
            raise _OutcomeUnknown("floor-commit")
        raise
    finally:
        if not renamed:
            _remove_owned_temp(directory_fd, temp_leaf, temp_fd)
        try:
            os.close(temp_fd)
        except OSError:
            pass


def accept_trust_bundle(
    root_path, bundle_path, floor_path, confirm: bool = False
) -> dict:
    """Advance the floor's accepted trust generation.  The only command
    that commits a higher trust generation."""

    def work() -> dict:
        _require_supported()
        if confirm is not True:
            raise _Refusal("confirm-required")
        root_file = _validate_path_argument(root_path)
        bundle_file = _validate_path_argument(bundle_path)
        floor_file = _validate_path_argument(floor_path)
        fds: list[int] = []
        try:
            try:
                directory_fd, floor_leaf, steps = _walk_to_parent(
                    floor_file, fds
                )
                _screen_floor_parent(directory_fd)
                lock_leaf = floor_leaf + _FLOOR_LOCK_SUFFIX
                lock_fd = _acquire_floor_lock(directory_fd, lock_leaf, fds)
            except (_Refusal, _Blocked):
                raise
            except OSError:
                raise _Refusal("file-unreadable")
            # Everything is (re-)read and reverified under the owner lock:
            # nothing captured before the lock is trusted for the mutation.
            now = _now()
            root_bytes = _read_safe_document(root_file)
            bundle_bytes = _read_safe_document(bundle_file)
            root_key_id, root_public_key = _validate_root_document(
                parse_canonical_document(root_bytes)
            )
            bundle = parse_canonical_document(bundle_bytes)
            _validate_bundle_syntax(bundle)
            _verify_bundle(bundle, root_key_id, root_public_key, now)
            bundle_sha256 = hashlib.sha256(bundle_bytes).hexdigest()
            floor = None
            expected = None
            floor_read = _read_document_at(
                directory_fd,
                floor_leaf,
                owner_only=True,
                missing_ok=True,
                steps=steps,
            )
            if floor_read is not None:
                floor_bytes, floor_stat = floor_read
                expected = (
                    _fingerprint(floor_stat),
                    hashlib.sha256(floor_bytes).hexdigest(),
                )
                floor = parse_canonical_document(floor_bytes)
                _validate_floor_syntax(floor)
                _check_floor_trust(
                    floor, root_key_id, bundle, bundle_sha256, now
                )
                if bundle["generation"] == floor["trust_generation"]:
                    # Exact digest equality was established above; this is
                    # the idempotent re-accept of the committed bundle.
                    return _build_result(
                        COMMAND_ACCEPT,
                        STATUS_ACCEPTED,
                        trust_generation=floor["trust_generation"],
                        bundle_sha256=bundle_sha256,
                        floor_present=True,
                        floor_advanced=False,
                        idempotent=True,
                    )
            channels: dict[str, dict] = {}
            previous_channels = floor["channels"] if floor is not None else {}
            for channel, minimum in bundle[
                "channel_minimum_sequences"
            ].items():
                previous = previous_channels.get(channel)
                if previous is not None:
                    if minimum < previous["minimum_sequence"]:
                        # A newer bundle may never lower a committed
                        # channel minimum.
                        raise _Blocked("minimum-rollback")
                    installed = previous["installed"]
                else:
                    installed = None
                channels[channel] = {
                    "minimum_sequence": minimum,
                    "installed": installed,
                }
            # Channels absent from the new bundle keep their committed
            # state; the floor never forgets an installed release.
            for channel, previous in previous_channels.items():
                if channel not in channels:
                    channels[channel] = previous
            if len(channels) > MAX_FLOOR_CHANNELS:
                raise _Refusal("floor-oversize")
            new_floor = {
                "schema": FLOOR_SCHEMA,
                "root_key_id": root_key_id,
                "trust_generation": bundle["generation"],
                "trust_bundle_sha256": bundle_sha256,
                "committed_at": now,
                # The floor trust check above proved the bundle's list is a
                # superset of every committed revocation, so committing it
                # keeps the floor's revocation set cumulative.
                "revoked_key_ids": list(bundle["revoked_key_ids"]),
                "channels": channels,
            }
            _validate_floor_syntax(new_floor)
            _write_floor_atomically(
                directory_fd,
                floor_leaf,
                new_floor,
                steps,
                lock_fd,
                lock_leaf,
                expected,
            )
            return _build_result(
                COMMAND_ACCEPT,
                STATUS_ACCEPTED,
                trust_generation=bundle["generation"],
                bundle_sha256=bundle_sha256,
                floor_present=floor is not None,
                floor_advanced=True,
                idempotent=False,
            )
        finally:
            for fd in reversed(fds):
                try:
                    os.close(fd)
                except OSError:
                    pass

    return _guard(COMMAND_ACCEPT, work)


def record_installed_release(
    root_path,
    bundle_path,
    envelope_path,
    floor_path,
    confirm: bool = False,
    expected_source_sha=None,
    expected_inventory_policy_id=None,
    expected_product_id=None,
) -> dict:
    """Record a verified envelope as the installed release for its channel.
    Requires the presented bundle to already be the committed floor trust;
    never advances the trust generation itself."""

    def work() -> dict:
        _require_supported()
        if confirm is not True:
            raise _Refusal("confirm-required")
        root_file = _validate_path_argument(root_path)
        bundle_file = _validate_path_argument(bundle_path)
        envelope_file = _validate_path_argument(envelope_path)
        floor_file = _validate_path_argument(floor_path)
        for expected, pattern in (
            (expected_source_sha, _SOURCE_SHA_RE),
            (expected_inventory_policy_id, _POLICY_ID_RE),
            (expected_product_id, _PRODUCT_ID_RE),
        ):
            if expected is not None:
                _string(expected, "invalid-arguments", pattern)
        fds: list[int] = []
        try:
            try:
                directory_fd, floor_leaf, steps = _walk_to_parent(
                    floor_file, fds
                )
                _screen_floor_parent(directory_fd)
                lock_leaf = floor_leaf + _FLOOR_LOCK_SUFFIX
                lock_fd = _acquire_floor_lock(directory_fd, lock_leaf, fds)
            except (_Refusal, _Blocked):
                raise
            except OSError:
                raise _Refusal("file-unreadable")
            # Full chain re-read and reverified under the owner lock.
            now = _now()
            (
                root_key_id,
                bundle,
                bundle_sha256,
                envelope,
                envelope_sha256,
            ) = _load_chain(root_file, bundle_file, envelope_file, now)
            _check_expected_identities(
                envelope,
                expected_source_sha,
                expected_inventory_policy_id,
                expected_product_id,
            )
            floor_read = _read_document_at(
                directory_fd,
                floor_leaf,
                owner_only=True,
                missing_ok=True,
                steps=steps,
            )
            if floor_read is None:
                raise _Blocked("trust-not-accepted")
            floor_bytes, floor_stat = floor_read
            expected = (
                _fingerprint(floor_stat),
                hashlib.sha256(floor_bytes).hexdigest(),
            )
            floor = parse_canonical_document(floor_bytes)
            _validate_floor_syntax(floor)
            _check_floor_trust(floor, root_key_id, bundle, bundle_sha256, now)
            if (
                bundle["generation"] != floor["trust_generation"]
                or bundle_sha256 != floor["trust_bundle_sha256"]
            ):
                # Installation is only recorded under the exact committed
                # trust; accept the newer bundle first.
                raise _Blocked("trust-not-accepted")
            channel = envelope["channel"]
            state = floor["channels"].get(channel)
            if state is None:
                raise _Blocked("channel-not-accepted")
            already_installed = _check_floor_release(
                floor, envelope, envelope_sha256
            )
            if already_installed:
                return _build_result(
                    COMMAND_RECORD,
                    STATUS_RECORDED,
                    channel=channel,
                    version=envelope["version"],
                    sequence=envelope["sequence"],
                    trust_generation=bundle["generation"],
                    source_sha=envelope["source_sha"],
                    inventory_policy_id=envelope["inventory_policy_id"],
                    product_id=envelope["product_id"],
                    bundle_sha256=bundle_sha256,
                    envelope_sha256=envelope_sha256,
                    floor_present=True,
                    floor_advanced=False,
                    idempotent=True,
                )
            channels = {
                name: {
                    "minimum_sequence": value["minimum_sequence"],
                    "installed": value["installed"],
                }
                for name, value in floor["channels"].items()
            }
            channels[channel] = {
                "minimum_sequence": state["minimum_sequence"],
                "installed": {
                    "sequence": envelope["sequence"],
                    "envelope_sha256": envelope_sha256,
                    "source_sha": envelope["source_sha"],
                    "inventory_policy_id": envelope["inventory_policy_id"],
                    "product_id": envelope["product_id"],
                },
            }
            new_floor = {
                "schema": FLOOR_SCHEMA,
                "root_key_id": floor["root_key_id"],
                "trust_generation": floor["trust_generation"],
                "trust_bundle_sha256": floor["trust_bundle_sha256"],
                "committed_at": now,
                "revoked_key_ids": list(floor["revoked_key_ids"]),
                "channels": channels,
            }
            _validate_floor_syntax(new_floor)
            _write_floor_atomically(
                directory_fd,
                floor_leaf,
                new_floor,
                steps,
                lock_fd,
                lock_leaf,
                expected,
            )
            return _build_result(
                COMMAND_RECORD,
                STATUS_RECORDED,
                channel=channel,
                version=envelope["version"],
                sequence=envelope["sequence"],
                trust_generation=bundle["generation"],
                source_sha=envelope["source_sha"],
                inventory_policy_id=envelope["inventory_policy_id"],
                product_id=envelope["product_id"],
                bundle_sha256=bundle_sha256,
                envelope_sha256=envelope_sha256,
                floor_present=True,
                floor_advanced=True,
                idempotent=False,
            )
        finally:
            for fd in reversed(fds):
                try:
                    os.close(fd)
                except OSError:
                    pass

    return _guard(COMMAND_RECORD, work)


class _ProvenanceArgumentParser(argparse.ArgumentParser):
    """Rejected command lines must yield the deterministic unsupported JSON
    contract on stdout, never argparse usage text on stderr.  Help output
    is untouched."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise _CliArgumentError()


def _emit(result: dict) -> int:
    sys.stdout.write(render_result(result) + "\n")
    return provenance_exit_code(result)


_BOOTSTRAP_NONCLAIM_HELP = (
    "Incumbent-only release provenance verifier over local canonical "
    "documents; read-only except the confirmed atomic floor update. "
    "Bootstrap non-claim: the release base (commit f739) cannot use a "
    "candidate verifier to authenticate itself; the first trust root and "
    "verifier distribution is necessarily out-of-band."
)


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:]) if argv is None else list(argv)
    command = raw_argv[0] if raw_argv else ""
    if command not in (COMMAND_VERIFY, COMMAND_ACCEPT, COMMAND_RECORD):
        command = COMMAND_VERIFY
    parser = _ProvenanceArgumentParser(
        prog="release_provenance",
        allow_abbrev=False,
        description=_BOOTSTRAP_NONCLAIM_HELP,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def _add_common(subparser, with_envelope: bool, with_expected: bool):
        subparser.add_argument(
            "--root-file",
            required=True,
            help="Absolute path of the out-of-band release-root document.",
        )
        subparser.add_argument(
            "--trust-bundle",
            required=True,
            help="Absolute path of the root-signed trust-bundle document.",
        )
        if with_envelope:
            subparser.add_argument(
                "--envelope",
                required=True,
                help="Absolute path of the release-envelope document.",
            )
        subparser.add_argument(
            "--floor",
            required=True,
            help=(
                "Absolute path of the owner-only release floor file, "
                "outside any live-state or recovery directory."
            ),
        )
        if with_expected:
            subparser.add_argument(
                "--expected-source-sha",
                default=None,
                help="Optional expected source SHA (40 hex).",
            )
            subparser.add_argument(
                "--expected-inventory-policy-id",
                default=None,
                help="Optional expected inventory policy id.",
            )
            subparser.add_argument(
                "--expected-product-id",
                default=None,
                help="Optional expected product id (product-<64 hex>).",
            )

    verify_parser = subparsers.add_parser(
        COMMAND_VERIFY,
        help="Read-only verification of root -> bundle -> envelope.",
    )
    _add_common(verify_parser, with_envelope=True, with_expected=True)

    accept_parser = subparsers.add_parser(
        COMMAND_ACCEPT,
        help="Commit a verified, newer trust bundle to the floor.",
    )
    _add_common(accept_parser, with_envelope=False, with_expected=False)
    accept_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Required explicit confirmation for the floor mutation.",
    )

    record_parser = subparsers.add_parser(
        COMMAND_RECORD,
        help="Record a verified envelope as installed for its channel.",
    )
    _add_common(record_parser, with_envelope=True, with_expected=True)
    record_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Required explicit confirmation for the floor mutation.",
    )

    try:
        args = parser.parse_args(raw_argv)
    except _CliArgumentError:
        return _emit(
            _build_result(command, "unsupported:invalid-arguments")
        )
    if args.command == COMMAND_VERIFY:
        result = verify_release(
            args.root_file,
            args.trust_bundle,
            args.envelope,
            args.floor,
            args.expected_source_sha,
            args.expected_inventory_policy_id,
            args.expected_product_id,
        )
    elif args.command == COMMAND_ACCEPT:
        result = accept_trust_bundle(
            args.root_file,
            args.trust_bundle,
            args.floor,
            confirm=args.confirm,
        )
    else:
        result = record_installed_release(
            args.root_file,
            args.trust_bundle,
            args.envelope,
            args.floor,
            confirm=args.confirm,
            expected_source_sha=args.expected_source_sha,
            expected_inventory_policy_id=args.expected_inventory_policy_id,
            expected_product_id=args.expected_product_id,
        )
    return _emit(result)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Offline release signer, separate from the verifier by design.

This tool runs on an offline signing host only.  It never opens a socket,
database, or subprocess, never imports repository or candidate modules,
and never touches live state or recovery paths.  Raw Ed25519 private keys
live only in absolute, owner-only, mode 0600, single-hard-link, exactly
32-byte files — key material never passes through argv, environment
variables, or stdin.

Every command requires ``--signing-root``: an existing directory that is
owned by the invoking user, mode-masked owner-only (no group or world
bits), not inside any repository (a ``.git`` entry in the root or any of
its ancestors fails closed), and — like every operand path — free of the
forbidden ``.synapse_s2``, ``recovery``, and ``updater-state`` components,
compared case-insensitively.  Every private key read or written and every
output the signer produces must live strictly beneath the signing root.

Every output is published exclusively — no overwrite, ever — via a
uniquely named same-directory temp file that is fully written (zero-write
progress guard), fchmod-ed to its exact mode regardless of umask,
fstat-verified, fsynced, hard-linked to its final name (link fails if the
name exists), directory-fsynced, and finally verified byte-for-byte and
identity-for-identity at its visible path.  Only a temp file this call
itself created is ever cleaned up; unknown files are never deleted.  A
failure after the final name exists is reported as
``outcome_unknown:<token>`` (exit 2) — neither clean failure nor success
is ever claimed for an ambiguous publish.

Commands:

- ``keygen root|release|compatibility-review`` — generate a fresh Ed25519
  keypair.  Both output
  names must be absent beforehand; the public document is published first
  and rolled back if the private key cannot then be published, so a failed
  keygen never leaves an orphaned secret.  The private key is written raw
  (32 bytes, 0600, exclusive, owner-only parent).  For the root role the
  public side is a canonical ``synapse-s2.release-root.v1`` document; for
  the release and compatibility-review roles a canonical
  ``synapse-s2.release-key.v1`` document carrying that role.
- ``sign-trust-bundle`` — sign an unsigned canonical trust-bundle document
  with the root key.  The signer refuses unless the document schema is
  ``synapse-s2.release-trust-bundle.v1`` or
  ``synapse-s2.release-trust-bundle.v2`` (each signed over its own exact
  schema-selected domain), the document carries no
  signature yet, the complete unsigned schema (fields, vocabularies,
  bounds, delegation windows and inclusive sequence bounds, sorted
  revocations) validates, the signing key is exactly the root key named by
  both the document and the out-of-band root document, and its own
  freshly produced signature verifies.  A v2 bundle must additionally
  carry both the release and compatibility-review role sets, each
  nonempty on distinct non-root, nonrevoked key ids; v1 bundles are
  unchanged.
- ``sign-release`` — sign an unsigned canonical release-envelope document
  with a delegated release key.  The signer refuses unless the document
  schema is ``synapse-s2.release-envelope.v1``, it carries no signature
  yet, the complete unsigned schema validates, the envelope's ``key_id``
  matches the signing key, and the signing key is *not* the root key (the
  root signs bundles only), and its own signature verifies.
- ``sign-compatibility-ticket`` — sign an unsigned canonical
  build-compatibility ticket with a delegated compatibility-review key.
  The signer refuses unless the root document validates, the supplied v2
  trust bundle is canonical, syntax-valid, and root-signed over the v2
  domain, the ticket names that exact bundle hash and generation plus the
  signing key's own id, the bundle grants that key a nonrevoked
  compatibility-review delegation whose channel, inclusive sequence
  bounds, and validity window contain the ticket's, the complete unsigned
  ticket schema (pinned profile, schemas, policies, exactly the thirteen
  surface digests, equal dependency component ids) validates, and its own
  freshly produced signature over the ticket domain verifies.  Offline
  signing never consults the wall clock; current-time validity is the
  verifier's judgment alone.

Canonical documents are exact canonical JSON bytes with no trailing
newline: what is signed is exactly what is stored.

Real keys must never be generated outside disposable test fixtures until
this tool itself has shipped through the governed release process.

Output is one bounded, deterministic, redacted JSON line: status tokens,
key ids, and document digests only — never filesystem paths, private key
material, signatures, or exception text.  Exit codes: 0 success, 2
anything else (including ``outcome_unknown``).

Import hardening matches the verifier: ``sys.path`` is rebuilt with
builtins only before any non-builtin import — stdlib locations first,
then the isolated trusted environment's own site-packages as the only
permitted origin for ``cryptography`` — so no PYTHONPATH, cwd, or
repository entry survives and no import-hijack lane exists.  The imported
``cryptography`` must be version 49.0.0 exactly and must, after symlink
resolution, originate from within that admitted site-packages directory,
or every command fails closed.  The hardened invocation is
``python -I trusted/scripts/sign_release_provenance.py``.
"""

import sys

_ORIGINAL_SYS_PATH = list(sys.path)
_ORIGINAL_DONT_WRITE_BYTECODE = sys.dont_write_bytecode

sys.dont_write_bytecode = True

_TRUSTED_SITE_PACKAGES: str | None = None


def _sanitize_sys_path() -> None:
    """Rebuild sys.path using builtins only, before any non-builtin import.
    Identical policy to the verifier: exactly the stdlib zip, stdlib
    directory, lib-dynload, and — last — the trusted environment's own
    site-packages."""
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


def _import_trusted_cryptography():
    """Import Ed25519 primitives from the isolated trusted environment
    only.  Any import failure, a version other than exactly 49.0.0, or a
    symlink-resolved on-disk origin outside the admitted site-packages
    means every command fails closed."""
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

if __name__ != "__main__":
    sys.path[:] = _ORIGINAL_SYS_PATH
    sys.dont_write_bytecode = _ORIGINAL_DONT_WRITE_BYTECODE

RESULT_SCHEMA = "synapse-s2.release-signing-result.v1"
RESULT_MODE = "offline-release-signer"

ROOT_SCHEMA = "synapse-s2.release-root.v1"
KEY_SCHEMA = "synapse-s2.release-key.v1"
BUNDLE_SCHEMA = "synapse-s2.release-trust-bundle.v1"
BUNDLE_SCHEMA_V2 = "synapse-s2.release-trust-bundle.v2"
ENVELOPE_SCHEMA = "synapse-s2.release-envelope.v1"
PRODUCT_SCHEMA = "synapse-s2.product-release-plan.v1"
TICKET_SCHEMA = "synapse-s2.build-compatibility-ticket.v1"

# Ticket vocabulary restated byte-for-byte from the verifier
# (scripts/release_compatibility.py); this tool never imports it.
COMPATIBILITY_OBSERVATION_SCHEMA = "synapse-s2.compatibility-observation.v1"
LAYOUT_SCHEMA = "synapse-s2.installed-layout-contract.v1"
HOST_EVIDENCE_RECEIPT_SCHEMA = "synapse-s2.host-evidence-receipt.v1"

DELEGATION_ROLE_RELEASE = "release"
DELEGATION_ROLE_COMPATIBILITY = "compatibility-review"
_BUNDLE_ROLES_BY_SCHEMA = {
    BUNDLE_SCHEMA: (DELEGATION_ROLE_RELEASE,),
    BUNDLE_SCHEMA_V2: (
        DELEGATION_ROLE_COMPATIBILITY,
        DELEGATION_ROLE_RELEASE,
    ),
}

# Pinned ticket policy claims restated from the verifier: the compatibility
# ticket's exact-build-only surface profile, host evidence deferred to a later
# lane, migration and downgrade blocked outright.  This profile-version
# namespace is independent of the dormant activation-contract profile.
SURFACE_MODE = "exact-build-only"
PROFILE_VERSION = 3
HOST_EVIDENCE_POLICY = "required-later"
MIGRATION_POLICY = "blocked"
DOWNGRADE_POLICY = "blocked"
EXPECTED_LAYOUT_CONTRACT_MODE = "inactive-versioned-v1"
EXPECTED_LAYOUT_CONTRACT_ID = (
    "layout-contract-"
    "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada"
)

# The closed compatibility surface vocabulary: exactly these thirteen
# sorted names, restated from the verifier.
COMPATIBILITY_SURFACES = (
    "authority-runtime",
    "capture",
    "context-delivery",
    "core-config",
    "disk-safety",
    "embedding-space",
    "installed-layout",
    "platform-runtime",
    "readiness-quiescence",
    "recovery",
    "replication",
    "request-journal",
    "store-schema",
)

COMMAND_KEYGEN = "keygen"
COMMAND_SIGN_BUNDLE = "sign-trust-bundle"
COMMAND_SIGN_RELEASE = "sign-release"
COMMAND_SIGN_TICKET = "sign-compatibility-ticket"

STATUS_GENERATED = "generated"
STATUS_SIGNED = "signed"

_SUCCESS_STATUSES = frozenset((STATUS_GENERATED, STATUS_SIGNED))

RESULT_NONCLAIMS = (
    "no-key-material-in-output",
    "no-live-state-access",
    "no-network",
    "no-recovery-access",
    "offline-only",
)

_KEY_ID_DOMAIN = b"SYNAPSE-S2\x00ED25519-PUBLIC-KEY\x00v1\x00"
_BUNDLE_SIGNING_DOMAIN = b"SYNAPSE-S2\x00RELEASE-TRUST-BUNDLE\x00v1\x00"
_BUNDLE_SIGNING_DOMAIN_V2 = b"SYNAPSE-S2\x00RELEASE-TRUST-BUNDLE\x00v2\x00"
_ENVELOPE_SIGNING_DOMAIN = b"SYNAPSE-S2\x00RELEASE-ENVELOPE\x00v1\x00"
_TICKET_SIGNING_DOMAIN = b"SYNAPSE-S2\x00BUILD-COMPATIBILITY-TICKET\x00v1\x00"

_BUNDLE_DOMAINS_BY_SCHEMA = {
    BUNDLE_SCHEMA: _BUNDLE_SIGNING_DOMAIN,
    BUNDLE_SCHEMA_V2: _BUNDLE_SIGNING_DOMAIN_V2,
}

MAX_DOCUMENT_BYTES = 64 * 1024
MAX_RESULT_BYTES = 4096
MAX_PATH_BYTES = 4096
PRIVATE_KEY_BYTES = 32
MAX_DELEGATIONS = 16
MAX_BUNDLE_CHANNELS = 16
MAX_REVOCATIONS = 64
MAX_INT = 2**53

_KEY_ID_RE = re.compile(r"ed25519-[0-9a-f]{64}")
_PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{64}")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}")
_HEX_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}")
_BUILD_ID_RE = re.compile(r"source-[0-9a-f]{24}")
_PRODUCT_ID_RE = re.compile(r"product-[0-9a-f]{64}")
_COMPONENT_ID_RE = re.compile(r"component-[0-9a-f]{64}")
_POLICY_ID_RE = re.compile(r"inventory-policy-[0-9a-f]{64}")
_CHANNEL_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,63}")
_LAYOUT_CONTRACT_ID_RE = re.compile(r"layout-contract-[0-9a-f]{64}")

# Compared case-insensitively so hostile paths on case-insensitive
# filesystems cannot slip past.
_FORBIDDEN_PATH_COMPONENTS = frozenset(
    (".synapse_s2", "recovery", "updater-state")
)

_O_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", None)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", None)

_DIR_OPEN_FLAGS = (
    os.O_RDONLY | (_O_DIRECTORY or 0) | (_O_NOFOLLOW or 0) | (_O_CLOEXEC or 0)
)
_FILE_OPEN_FLAGS = (
    os.O_RDONLY
    | (_O_NOFOLLOW or 0)
    | (_O_CLOEXEC or 0)
    | (_O_NONBLOCK or 0)
)
_CREATE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | (_O_NOFOLLOW or 0)
    | (_O_CLOEXEC or 0)
)

_PLATFORM_SUPPORTED = (
    None not in (_O_DIRECTORY, _O_NOFOLLOW, _O_CLOEXEC, _O_NONBLOCK)
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.link in os.supports_dir_fd
    and os.unlink in os.supports_dir_fd
    and hasattr(os, "fchmod")
)


class _Refusal(Exception):
    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


class _OutcomeUnknown(Exception):
    """Exit 2 with an ``outcome_unknown:`` status: an output reached its
    final name but its durability or final verification is unproven.
    Nothing pre-existing was overwritten; the operator must inspect the
    named output before retrying."""

    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


class _CliArgumentError(Exception):
    pass


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


def key_id_for_public_key(public_key_hex: str) -> str:
    raw = bytes.fromhex(public_key_hex)
    return (
        "ed25519-"
        + hashlib.sha256(_KEY_ID_DOMAIN + raw).hexdigest()
    )


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


_UNSIGNED_BUNDLE_FIELDS = (
    "schema",
    "root_key_id",
    "generation",
    "issued_at",
    "expires_at",
    "channel_minimum_sequences",
    "delegations",
    "revoked_key_ids",
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

_UNSIGNED_ENVELOPE_FIELDS = (
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
)


def _validate_unsigned_bundle(document: dict) -> None:
    """The complete unsigned trust-bundle schema — the same closed fields,
    vocabularies, and bounds the verifier enforces, minus the signature —
    validated before anything is signed.  The signer never signs a
    document the verifier would refuse to parse.  The allowed delegation
    roles are selected by the exact bundle schema: v1 carries release
    only; v2 must carry both the release and compatibility-review role
    sets, each nonempty on distinct non-root, nonrevoked key ids."""
    token = "bundle-invalid"
    _require_exact_fields(document, _UNSIGNED_BUNDLE_FIELDS, token)
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
    delegated_roles: list[tuple[str, object]] = []
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
        if key_id == bundle_root_key_id:
            raise _Refusal("bundle-root-delegated")
        if key_id in seen_key_ids:
            raise _Refusal(token)
        seen_key_ids.add(key_id)
        delegated_roles.append((key_id, delegation["role"]))
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
    revoked = document["revoked_key_ids"]
    if not isinstance(revoked, list) or len(revoked) > MAX_REVOCATIONS:
        raise _Refusal(token)
    if revoked != sorted(set(revoked), key=str):
        raise _Refusal(token)
    for key_id in revoked:
        _string(key_id, token, _KEY_ID_RE)
        if key_id == bundle_root_key_id:
            raise _Refusal("bundle-root-revoked")
    if schema == BUNDLE_SCHEMA_V2:
        # A v2 bundle exists to carry the two-role vocabulary: both role
        # sets must remain nonempty after revocations (each role on a
        # distinct key id, enforced by the duplicate-key check above).
        revoked_set = set(revoked)
        if seen_key_ids & revoked_set:
            # A v2 role grant and revocation are mutually exclusive.
            # Refuse the contradictory bundle outright rather than
            # signing a document whose authority depends on which list a
            # later consumer happens to consult first.  v1 remains
            # byte-for-byte and behaviorally unchanged.
            raise _Refusal(token)
        live_roles = {
            role
            for delegated_key_id, role in delegated_roles
            if delegated_key_id not in revoked_set
        }
        if live_roles != set(_BUNDLE_ROLES_BY_SCHEMA[BUNDLE_SCHEMA_V2]):
            raise _Refusal(token)


def _validate_unsigned_envelope(document: dict) -> None:
    """The complete unsigned release-envelope schema, validated with the
    verifier's own bounds before anything is signed."""
    token = "envelope-invalid"
    _require_exact_fields(document, _UNSIGNED_ENVELOPE_FIELDS, token)
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


_UNSIGNED_TICKET_FIELDS = (
    "schema",
    "profile",
    "profile_version",
    "compatibility_observation_schema",
    "product_schema",
    "channel",
    "version",
    "sequence",
    "source_sha",
    "current_source_build_id",
    "candidate_source_build_id",
    "current_product_id",
    "candidate_product_id",
    "inventory_policy_id",
    "current_dependency_component_id",
    "candidate_dependency_component_id",
    "surface_digests",
    "surfaces_digest",
    "layout_schema",
    "layout_mode",
    "layout_contract_id",
    "trust_generation",
    "trust_bundle_sha256",
    "envelope_sha256",
    "host_evidence_receipt_schema",
    "host_evidence_policy",
    "migration",
    "downgrade",
    "issued_at",
    "expires_at",
    "key_id",
)


def _validate_unsigned_ticket(document: dict) -> None:
    """The complete unsigned build-compatibility-ticket schema — the same
    closed fields, pinned vocabularies, and bounds the verifier enforces,
    minus the signature — validated before anything is signed: pinned
    exact-build-only profile, pinned schemas and policies, exactly the
    thirteen surface digests, and equal dependency component ids."""
    token = "ticket-invalid"
    _require_exact_fields(document, _UNSIGNED_TICKET_FIELDS, token)
    if document["schema"] != TICKET_SCHEMA:
        raise _Refusal(token)
    if document["profile"] != SURFACE_MODE:
        raise _Refusal(token)
    if (
        _integer(document["profile_version"], token, minimum=1)
        != PROFILE_VERSION
    ):
        raise _Refusal(token)
    if (
        document["compatibility_observation_schema"]
        != COMPATIBILITY_OBSERVATION_SCHEMA
    ):
        raise _Refusal(token)
    if document["product_schema"] != PRODUCT_SCHEMA:
        raise _Refusal(token)
    _string(document["channel"], token, _CHANNEL_RE)
    _string(document["version"], token, _VERSION_RE)
    _integer(document["sequence"], token, minimum=1)
    _string(document["source_sha"], token, _SOURCE_SHA_RE)
    _string(document["current_source_build_id"], token, _BUILD_ID_RE)
    _string(document["candidate_source_build_id"], token, _BUILD_ID_RE)
    _string(document["current_product_id"], token, _PRODUCT_ID_RE)
    _string(document["candidate_product_id"], token, _PRODUCT_ID_RE)
    _string(document["inventory_policy_id"], token, _POLICY_ID_RE)
    _string(
        document["current_dependency_component_id"], token, _COMPONENT_ID_RE
    )
    _string(
        document["candidate_dependency_component_id"], token, _COMPONENT_ID_RE
    )
    if (
        document["current_dependency_component_id"]
        != document["candidate_dependency_component_id"]
    ):
        # Exact-build-only tickets claim one unchanged dependency
        # component; a ticket claiming a dependency change is never signed.
        raise _Refusal(token)
    surface_digests = document["surface_digests"]
    if type(surface_digests) is not dict:
        raise _Refusal(token)
    if set(surface_digests) != set(COMPATIBILITY_SURFACES):
        raise _Refusal(token)
    for digest in surface_digests.values():
        _string(digest, token, _HEX_SHA256_RE)
    _string(document["surfaces_digest"], token, _HEX_SHA256_RE)
    if document["layout_schema"] != LAYOUT_SCHEMA:
        raise _Refusal(token)
    if document["layout_mode"] != EXPECTED_LAYOUT_CONTRACT_MODE:
        raise _Refusal(token)
    if (
        _string(document["layout_contract_id"], token, _LAYOUT_CONTRACT_ID_RE)
        != EXPECTED_LAYOUT_CONTRACT_ID
    ):
        # The verifier pins one reviewed host-independent contract.  The
        # signer must never mint a well-shaped ticket that Phase A will
        # reject as a different layout contract.
        raise _Refusal(token)
    _integer(document["trust_generation"], token, minimum=1)
    _string(document["trust_bundle_sha256"], token, _HEX_SHA256_RE)
    _string(document["envelope_sha256"], token, _HEX_SHA256_RE)
    if (
        document["host_evidence_receipt_schema"]
        != HOST_EVIDENCE_RECEIPT_SCHEMA
    ):
        raise _Refusal(token)
    if document["host_evidence_policy"] != HOST_EVIDENCE_POLICY:
        raise _Refusal(token)
    if document["migration"] != MIGRATION_POLICY:
        raise _Refusal(token)
    if document["downgrade"] != DOWNGRADE_POLICY:
        raise _Refusal(token)
    issued_at = _integer(document["issued_at"], token)
    expires_at = _integer(document["expires_at"], token)
    if expires_at <= issued_at:
        raise _Refusal(token)
    _string(document["key_id"], token, _KEY_ID_RE)


def _validate_path_argument(value) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise _Refusal("invalid-arguments")
    if "\x00" in value or len(value.encode("utf-8", "replace")) > MAX_PATH_BYTES:
        raise _Refusal("invalid-arguments")
    parts = value.split("/")[1:]
    if any(part in ("", ".", "..") for part in parts):
        raise _Refusal("invalid-arguments")
    if any(part.lower() in _FORBIDDEN_PATH_COMPONENTS for part in parts):
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


def _walk_to_parent(
    path: str, fds: list[int]
) -> tuple[int, str, list[tuple[int, str, int]]]:
    """Open every ancestor of ``path`` dir_fd-relative with a no-follow
    stat plus O_DIRECTORY|O_NOFOLLOW open anchored at ``/``.  Returns the
    held parent descriptor, the leaf name, and one (parent_fd, name,
    child_fd) step per component so callers can re-prove, after their
    reads or writes, that every held directory is still the one visible
    under its name."""
    parts = path.split("/")[1:]
    directory_fd = os.open("/", _DIR_OPEN_FLAGS)
    fds.append(directory_fd)
    steps: list[tuple[int, str, int]] = []
    for name in parts[:-1]:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise _Refusal("unsafe-path")
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
    component visible under its name in its held parent."""
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


def _read_exact_file(
    path: str,
    *,
    private_key: bool,
) -> bytes:
    """Held-descriptor read with the same no-follow, fingerprint-checked
    discipline as the verifier, plus a final visible-identity proof of
    every walk component and the leaf itself after all reads.
    ``private_key`` demands exactly mode 0600, one hard link, exactly 32
    bytes, owned by the caller."""
    fds: list[int] = []
    try:
        try:
            directory_fd, leaf, steps = _walk_to_parent(path, fds)
            before = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                raise _Refusal("unsafe-file")
            if before.st_nlink != 1:
                raise _Refusal("unsafe-file")
            if before.st_uid != os.geteuid():
                raise _Refusal("unsafe-file")
            mode = stat.S_IMODE(before.st_mode)
            if private_key:
                if mode != 0o600:
                    raise _Refusal("private-key-unsafe")
                if before.st_size != PRIVATE_KEY_BYTES:
                    raise _Refusal("private-key-unsafe")
            else:
                if mode & 0o022:
                    raise _Refusal("unsafe-file")
                if before.st_size > MAX_DOCUMENT_BYTES:
                    raise _Refusal("document-oversize")
            file_fd = os.open(leaf, _FILE_OPEN_FLAGS, dir_fd=directory_fd)
            fds.append(file_fd)
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
            if (visible.st_dev, visible.st_ino) != (
                after.st_dev,
                after.st_ino,
            ):
                raise _Refusal("validation-race")
            if _fingerprint(visible) != _fingerprint(after):
                raise _Refusal("validation-race")
            return data
        except _Refusal:
            raise
        except OSError:
            raise _Refusal("file-unreadable")
    finally:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _require_signing_root(signing_root) -> str:
    """Validate the mandatory signing root: an existing directory owned by
    the invoking user with no group/world mode bits, reached through a
    no-follow walk, with no ``.git`` entry in the root itself or any held
    ancestor (a signing root inside a repository — where checked-in or
    synced content could alias key material — fails closed)."""
    root_path = _validate_path_argument(signing_root)
    fds: list[int] = []
    try:
        try:
            directory_fd, leaf, steps = _walk_to_parent(root_path, fds)
            before = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise _Refusal("signing-root-unsafe")
            root_fd = os.open(leaf, _DIR_OPEN_FLAGS, dir_fd=directory_fd)
            fds.append(root_fd)
            held = os.fstat(root_fd)
            if (before.st_dev, before.st_ino) != (
                held.st_dev,
                held.st_ino,
            ):
                raise _Refusal("validation-race")
            if held.st_uid != os.geteuid():
                raise _Refusal("signing-root-unsafe")
            if stat.S_IMODE(held.st_mode) & 0o077:
                raise _Refusal("signing-root-unsafe")
            for held_dir_fd in fds:
                try:
                    os.stat(
                        ".git", dir_fd=held_dir_fd, follow_symlinks=False
                    )
                except FileNotFoundError:
                    continue
                except OSError:
                    # Cannot prove the absence of a repository: fail closed.
                    raise _Refusal("repository-path")
                raise _Refusal("repository-path")
            return root_path
        except _Refusal:
            raise
        except OSError:
            raise _Refusal("signing-root-unsafe")
    finally:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _require_within_signing_root(path: str, signing_root: str) -> str:
    if not path.startswith(signing_root + "/"):
        raise _Refusal("outside-signing-root")
    return path


def _path_exists_no_follow(path: str) -> bool:
    fds: list[int] = []
    try:
        try:
            directory_fd, leaf, _steps = _walk_to_parent(path, fds)
            os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False
        except _Refusal:
            raise
        except OSError:
            raise _Refusal("file-unreadable")
    finally:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _output_temp_leaf(leaf: str) -> str:
    return (
        "."
        + leaf
        + ".tmp-"
        + str(os.getpid())
        + "-"
        + os.urandom(8).hex()
    )


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


def _publish_exclusive(
    path: str, data: bytes, mode: int, parent_owner_only: bool
) -> tuple[int, int]:
    """Exclusive no-clobber publish: uniquely named same-directory temp,
    full write with a zero-progress guard, exact fchmod despite umask,
    fstat verification, temp fsync, walk re-proof, then a hard link to the
    final name — which fails if anything already bears the name — temp
    unlink, directory fsync, and a final visible verification of identity,
    mode, link count, size, and exact bytes.  After the verification read
    the publish is re-proven end to end: a post-read fstat of the held
    descriptor, a re-proof of every visible ancestor step, and a final
    visible leaf stat must all agree on identity and full fingerprint —
    the requested path must still name exactly the published bytes at the
    moment of success.  Returns the published file's (st_dev, st_ino).
    Any failure after the final name exists raises _OutcomeUnknown;
    earlier failures clean up only this call's own temp and leave
    everything else untouched."""
    fds: list[int] = []
    directory_fd = -1
    temp_fd = -1
    temp_leaf: str | None = None
    published = False
    try:
        try:
            try:
                directory_fd, leaf, steps = _walk_to_parent(path, fds)
                parent = os.fstat(directory_fd)
                if not stat.S_ISDIR(parent.st_mode):
                    raise _Refusal("unsafe-parent")
                if parent.st_uid != os.geteuid():
                    raise _Refusal("unsafe-parent")
                forbidden = 0o077 if parent_owner_only else 0o022
                if stat.S_IMODE(parent.st_mode) & forbidden:
                    raise _Refusal("unsafe-parent")
                try:
                    os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise _Refusal("output-exists")
                candidate_leaf = _output_temp_leaf(leaf)
                try:
                    temp_fd = os.open(
                        candidate_leaf,
                        _CREATE_FLAGS,
                        0o600,
                        dir_fd=directory_fd,
                    )
                except FileExistsError:
                    # A file this call did not create is never deleted.
                    raise _Refusal("temp-exists")
                fds.append(temp_fd)
                temp_leaf = candidate_leaf
                written = 0
                while written < len(data):
                    count = os.write(temp_fd, data[written:])
                    if type(count) is not int or count <= 0:
                        raise _Refusal("output-write-failed")
                    written += count
                os.fchmod(temp_fd, mode)
                temp_stat = os.fstat(temp_fd)
                if not (
                    stat.S_ISREG(temp_stat.st_mode)
                    and stat.S_IMODE(temp_stat.st_mode) == mode
                    and temp_stat.st_uid == os.geteuid()
                    and temp_stat.st_nlink == 1
                    and temp_stat.st_size == len(data)
                ):
                    raise _Refusal("output-write-failed")
                os.fsync(temp_fd)
                _verify_visible_steps(steps)
                try:
                    os.link(
                        temp_leaf,
                        leaf,
                        src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd,
                    )
                except FileExistsError:
                    raise _Refusal("output-exists")
                published = True
                os.unlink(temp_leaf, dir_fd=directory_fd)
                temp_leaf = None
                os.fsync(directory_fd)
                visible = os.stat(
                    leaf, dir_fd=directory_fd, follow_symlinks=False
                )
                if not (
                    (visible.st_dev, visible.st_ino)
                    == (temp_stat.st_dev, temp_stat.st_ino)
                    and stat.S_IMODE(visible.st_mode) == mode
                    and visible.st_uid == os.geteuid()
                    and visible.st_nlink == 1
                    and visible.st_size == len(data)
                ):
                    raise _Refusal("output-unverified")
                check_fd = os.open(
                    leaf, _FILE_OPEN_FLAGS, dir_fd=directory_fd
                )
                try:
                    held = os.fstat(check_fd)
                    if (held.st_dev, held.st_ino) != (
                        visible.st_dev,
                        visible.st_ino,
                    ):
                        raise _Refusal("output-unverified")
                    chunks: list[bytes] = []
                    remaining = len(data) + 1
                    while remaining > 0:
                        chunk = os.read(check_fd, min(remaining, 65536))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    if b"".join(chunks) != data:
                        raise _Refusal("output-unverified")
                    # Post-read re-proof: the held descriptor must still
                    # be the exact file that was verified, byte for byte
                    # and attribute for attribute.
                    final_held = os.fstat(check_fd)
                    if _fingerprint(final_held) != _fingerprint(held):
                        raise _Refusal("output-unverified")
                    if not (
                        stat.S_ISREG(final_held.st_mode)
                        and stat.S_IMODE(final_held.st_mode) == mode
                        and final_held.st_uid == os.geteuid()
                        and final_held.st_nlink == 1
                        and final_held.st_size == len(data)
                    ):
                        raise _Refusal("output-unverified")
                    # The requested absolute path must still resolve
                    # through the identical ancestor chain that was
                    # proven before the link.
                    _verify_visible_steps(steps)
                    # And the visible leaf under that chain must be the
                    # verified file itself, not a substitute.
                    try:
                        final_visible = os.stat(
                            leaf,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                    except OSError:
                        raise _Refusal("output-unverified")
                    if (final_visible.st_dev, final_visible.st_ino) != (
                        final_held.st_dev,
                        final_held.st_ino,
                    ):
                        raise _Refusal("output-unverified")
                    if _fingerprint(final_visible) != _fingerprint(
                        final_held
                    ):
                        raise _Refusal("output-unverified")
                finally:
                    os.close(check_fd)
                return (temp_stat.st_dev, temp_stat.st_ino)
            except (_Refusal, _OutcomeUnknown):
                raise
            except OSError:
                raise _Refusal("output-write-failed")
        except _OutcomeUnknown:
            raise
        except _Refusal:
            if published:
                # The final name exists but the publish is unproven:
                # neither clean failure nor success may be claimed.
                raise _OutcomeUnknown("output-publish")
            raise
    finally:
        if temp_leaf is not None and temp_fd >= 0:
            _remove_owned_temp(directory_fd, temp_leaf, temp_fd)
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _unpublish_exact(path: str, identity: tuple[int, int]) -> bool:
    """Roll back exactly the file this call published — unlink only while
    the visible file still has the published (st_dev, st_ino).  Returns
    True when the name no longer exists afterwards."""
    fds: list[int] = []
    try:
        directory_fd, leaf, _steps = _walk_to_parent(path, fds)
        try:
            visible = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return True
        if (visible.st_dev, visible.st_ino) != identity:
            return False
        os.unlink(leaf, dir_fd=directory_fd)
        os.fsync(directory_fd)
        return True
    except (_Refusal, OSError):
        return False
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
    key_role=None,
    key_id=None,
    document_schema=None,
    document_sha256=None,
) -> dict:
    return {
        "schema": RESULT_SCHEMA,
        "mode": RESULT_MODE,
        "command": command,
        "status": status,
        "key_role": key_role,
        "key_id": key_id,
        "document_schema": document_schema,
        "document_sha256": document_sha256,
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


def signing_exit_code(result: dict) -> int:
    return 0 if str(result.get("status")) in _SUCCESS_STATUSES else 2


def _guard(command: str, work) -> dict:
    try:
        try:
            return work()
        except (_Refusal, _OutcomeUnknown):
            raise
        except Exception:
            raise _Refusal("internal-error")
    except _OutcomeUnknown as unknown:
        return _build_result(command, "outcome_unknown:" + unknown.token)
    except _Refusal as refusal:
        return _build_result(command, "unsupported:" + refusal.token)


def _require_supported() -> None:
    if not _PLATFORM_SUPPORTED:
        raise _Refusal("platform-unsupported")
    if _ED25519 is None:
        raise _Refusal("crypto-unavailable")


def _load_private_key(path: str):
    raw = _read_exact_file(path, private_key=True)
    if len(raw) != PRIVATE_KEY_BYTES:
        raise _Refusal("private-key-unsafe")
    try:
        return _ED25519.Ed25519PrivateKey.from_private_bytes(raw)
    except Exception:
        raise _Refusal("private-key-invalid")


def _public_key_hex(private_key) -> str:
    return private_key.public_key().public_bytes_raw().hex()


def _load_root_document(root_path: str) -> tuple[str, str]:
    document = parse_canonical_document(
        _read_exact_file(root_path, private_key=False)
    )
    token = "root-invalid"
    if set(document) != {"schema", "root_key_id", "root_public_key"}:
        raise _Refusal(token)
    if document["schema"] != ROOT_SCHEMA:
        raise _Refusal(token)
    public_key = document["root_public_key"]
    key_id = document["root_key_id"]
    if type(public_key) is not str or not _PUBLIC_KEY_RE.fullmatch(
        public_key
    ):
        raise _Refusal(token)
    if type(key_id) is not str or not _KEY_ID_RE.fullmatch(key_id):
        raise _Refusal(token)
    if key_id != key_id_for_public_key(public_key):
        raise _Refusal(token)
    return key_id, public_key


def _load_root_key_id(root_path: str) -> str:
    return _load_root_document(root_path)[0]


def _load_signed_bundle_v2(
    bundle_path: str, root_key_id: str, root_public_key: str
) -> tuple[dict, str]:
    """Load, canonically parse, syntax-validate, and root-verify a signed
    v2 trust bundle over the v2 signing domain only.  No wall-clock
    checks: the offline signer proves the chain of custody; the verifier
    alone judges current time.  Returns the bundle document and the
    sha256 of its exact canonical bytes."""
    data = _read_exact_file(bundle_path, private_key=False)
    document = parse_canonical_document(data)
    if document.get("schema") != BUNDLE_SCHEMA_V2:
        raise _Refusal("document-type-mismatch")
    token = "bundle-invalid"
    if "signature" not in document:
        raise _Refusal(token)
    signature = _string(document["signature"], token, _SIGNATURE_RE)
    unsigned = {
        key: value for key, value in document.items() if key != "signature"
    }
    _validate_unsigned_bundle(unsigned)
    if document["root_key_id"] != root_key_id:
        raise _Refusal("bundle-root-mismatch")
    payload = _BUNDLE_SIGNING_DOMAIN_V2 + canonical_bytes(unsigned)
    try:
        public = _ED25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(root_public_key)
        )
        public.verify(bytes.fromhex(signature), payload)
    except Exception:
        raise _Refusal("bundle-signature-invalid")
    return document, hashlib.sha256(data).hexdigest()


def _check_delegation_grant_offline(
    delegation: dict,
    bundle: dict,
    channel: str,
    sequence: int,
    issued_at: int,
    expires_at: int,
) -> None:
    """The verifier's delegation-grant checks minus its wall-clock checks:
    channel grant, validity-window containment, channel minimum, and
    inclusive sequence bounds."""
    if channel not in delegation["channels"]:
        raise _Refusal("channel-not-delegated")
    if not (
        delegation["not_before"] <= issued_at < delegation["not_after"]
    ):
        raise _Refusal("delegation-window")
    if expires_at > delegation["not_after"]:
        # The document's whole validity must be contained in the
        # delegation's: a delegate cannot mint trust outliving its grant.
        raise _Refusal("delegation-window")
    minimum = bundle["channel_minimum_sequences"].get(channel)
    if minimum is None:
        raise _Refusal("channel-unknown")
    if sequence < minimum:
        raise _Refusal("sequence-below-minimum")
    if not (
        delegation["sequence_minimum"]
        <= sequence
        <= delegation["sequence_maximum"]
    ):
        raise _Refusal("sequence-outside-delegation")


def _verify_own_signature(
    public_key_hex: str, signature_hex: str, payload: bytes
) -> None:
    try:
        public = _ED25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(public_key_hex)
        )
        public.verify(bytes.fromhex(signature_hex), payload)
    except Exception:
        raise _Refusal("self-verification-failed")


def keygen(role, private_key_out, public_out, signing_root) -> dict:
    def work() -> dict:
        _require_supported()
        if role not in (
            "root",
            DELEGATION_ROLE_RELEASE,
            DELEGATION_ROLE_COMPATIBILITY,
        ):
            raise _Refusal("invalid-arguments")
        root = _require_signing_root(signing_root)
        private_path = _require_within_signing_root(
            _validate_path_argument(private_key_out), root
        )
        public_path = _require_within_signing_root(
            _validate_path_argument(public_out), root
        )
        if private_path == public_path:
            raise _Refusal("invalid-arguments")
        # Preflight both names before any key material exists: a rerun
        # after any earlier outcome must refuse, never silently pair a new
        # document with an old key or vice versa.
        if _path_exists_no_follow(private_path) or _path_exists_no_follow(
            public_path
        ):
            raise _Refusal("output-exists")
        private_key = _ED25519.Ed25519PrivateKey.generate()
        raw = private_key.private_bytes_raw()
        if len(raw) != PRIVATE_KEY_BYTES:
            raise _Refusal("keygen-failed")
        public_hex = _public_key_hex(private_key)
        key_id = key_id_for_public_key(public_hex)
        if role == "root":
            public_document = {
                "schema": ROOT_SCHEMA,
                "root_key_id": key_id,
                "root_public_key": public_hex,
            }
        else:
            public_document = {
                "schema": KEY_SCHEMA,
                "key_id": key_id,
                "public_key": public_hex,
                "role": role,
            }
        public_bytes = canonical_bytes(public_document)
        # The public document lands first; if the private key then fails
        # to publish, the public document is rolled back so the keygen
        # transaction never leaves an orphaned artifact — and in no branch
        # does a secret exist on disk without this call knowing its state.
        public_identity = _publish_exclusive(
            public_path, public_bytes, 0o644, parent_owner_only=False
        )
        try:
            _publish_exclusive(
                private_path, raw, 0o600, parent_owner_only=True
            )
        except _OutcomeUnknown:
            # The private key may exist: rolling back the public document
            # could orphan a real secret, so keep both and report.
            raise
        except _Refusal:
            _unpublish_exact(public_path, public_identity)
            raise
        return _build_result(
            COMMAND_KEYGEN,
            STATUS_GENERATED,
            key_role=role,
            key_id=key_id,
            document_schema=public_document["schema"],
            document_sha256=hashlib.sha256(public_bytes).hexdigest(),
        )

    return _guard(COMMAND_KEYGEN, work)


def sign_trust_bundle(
    private_key_path, root_path, unsigned_path, output_path, signing_root
) -> dict:
    def work() -> dict:
        _require_supported()
        root = _require_signing_root(signing_root)
        key_file = _require_within_signing_root(
            _validate_path_argument(private_key_path), root
        )
        root_file = _validate_path_argument(root_path)
        unsigned_file = _validate_path_argument(unsigned_path)
        output_file = _require_within_signing_root(
            _validate_path_argument(output_path), root
        )
        private_key = _load_private_key(key_file)
        public_hex = _public_key_hex(private_key)
        key_id = key_id_for_public_key(public_hex)
        root_key_id = _load_root_key_id(root_file)
        # Key role check: only the out-of-band root key signs bundles.
        if key_id != root_key_id:
            raise _Refusal("key-role-mismatch")
        unsigned = parse_canonical_document(
            _read_exact_file(unsigned_file, private_key=False)
        )
        # Product type check: refuse to sign anything but a complete,
        # bound-checked unsigned trust bundle naming this exact root key.
        # The signing domain is selected by the exact bundle schema, so a
        # v1 signature can never verify a v2 bundle or vice versa.
        schema = unsigned.get("schema")
        if type(schema) is not str or schema not in _BUNDLE_DOMAINS_BY_SCHEMA:
            raise _Refusal("document-type-mismatch")
        if "signature" in unsigned:
            raise _Refusal("document-already-signed")
        _validate_unsigned_bundle(unsigned)
        if unsigned["root_key_id"] != root_key_id:
            raise _Refusal("bundle-root-mismatch")
        payload = _BUNDLE_DOMAINS_BY_SCHEMA[schema] + canonical_bytes(unsigned)
        signature_hex = private_key.sign(payload).hex()
        if not _SIGNATURE_RE.fullmatch(signature_hex):
            raise _Refusal("signing-failed")
        _verify_own_signature(public_hex, signature_hex, payload)
        signed = dict(unsigned)
        signed["signature"] = signature_hex
        signed_bytes = canonical_bytes(signed)
        if len(signed_bytes) > MAX_DOCUMENT_BYTES:
            raise _Refusal("document-oversize")
        _publish_exclusive(
            output_file, signed_bytes, 0o644, parent_owner_only=False
        )
        return _build_result(
            COMMAND_SIGN_BUNDLE,
            STATUS_SIGNED,
            key_role="root",
            key_id=key_id,
            document_schema=schema,
            document_sha256=hashlib.sha256(signed_bytes).hexdigest(),
        )

    return _guard(COMMAND_SIGN_BUNDLE, work)


def sign_release(
    private_key_path, root_path, unsigned_path, output_path, signing_root
) -> dict:
    def work() -> dict:
        _require_supported()
        root = _require_signing_root(signing_root)
        key_file = _require_within_signing_root(
            _validate_path_argument(private_key_path), root
        )
        root_file = _validate_path_argument(root_path)
        unsigned_file = _validate_path_argument(unsigned_path)
        output_file = _require_within_signing_root(
            _validate_path_argument(output_path), root
        )
        private_key = _load_private_key(key_file)
        public_hex = _public_key_hex(private_key)
        key_id = key_id_for_public_key(public_hex)
        root_key_id = _load_root_key_id(root_file)
        # Key role check: the root key never signs envelopes.
        if key_id == root_key_id:
            raise _Refusal("key-role-mismatch")
        unsigned = parse_canonical_document(
            _read_exact_file(unsigned_file, private_key=False)
        )
        if unsigned.get("schema") != ENVELOPE_SCHEMA:
            raise _Refusal("document-type-mismatch")
        if "signature" in unsigned:
            raise _Refusal("document-already-signed")
        _validate_unsigned_envelope(unsigned)
        # The envelope must name the key actually signing it.
        if unsigned["key_id"] != key_id:
            raise _Refusal("envelope-key-mismatch")
        payload = _ENVELOPE_SIGNING_DOMAIN + canonical_bytes(unsigned)
        signature_hex = private_key.sign(payload).hex()
        if not _SIGNATURE_RE.fullmatch(signature_hex):
            raise _Refusal("signing-failed")
        _verify_own_signature(public_hex, signature_hex, payload)
        signed = dict(unsigned)
        signed["signature"] = signature_hex
        signed_bytes = canonical_bytes(signed)
        if len(signed_bytes) > MAX_DOCUMENT_BYTES:
            raise _Refusal("document-oversize")
        _publish_exclusive(
            output_file, signed_bytes, 0o644, parent_owner_only=False
        )
        return _build_result(
            COMMAND_SIGN_RELEASE,
            STATUS_SIGNED,
            key_role="release",
            key_id=key_id,
            document_schema=ENVELOPE_SCHEMA,
            document_sha256=hashlib.sha256(signed_bytes).hexdigest(),
        )

    return _guard(COMMAND_SIGN_RELEASE, work)


def sign_compatibility_ticket(
    private_key_path,
    root_path,
    trust_bundle_path,
    unsigned_path,
    output_path,
    signing_root,
) -> dict:
    def work() -> dict:
        _require_supported()
        root = _require_signing_root(signing_root)
        key_file = _require_within_signing_root(
            _validate_path_argument(private_key_path), root
        )
        root_file = _validate_path_argument(root_path)
        bundle_file = _validate_path_argument(trust_bundle_path)
        unsigned_file = _validate_path_argument(unsigned_path)
        output_file = _require_within_signing_root(
            _validate_path_argument(output_path), root
        )
        private_key = _load_private_key(key_file)
        public_hex = _public_key_hex(private_key)
        key_id = key_id_for_public_key(public_hex)
        root_key_id, root_public_key = _load_root_document(root_file)
        # Key role check: the root key never signs tickets.
        if key_id == root_key_id:
            raise _Refusal("key-role-mismatch")
        bundle, bundle_sha256 = _load_signed_bundle_v2(
            bundle_file, root_key_id, root_public_key
        )
        unsigned = parse_canonical_document(
            _read_exact_file(unsigned_file, private_key=False)
        )
        if unsigned.get("schema") != TICKET_SCHEMA:
            raise _Refusal("document-type-mismatch")
        if "signature" in unsigned:
            raise _Refusal("document-already-signed")
        _validate_unsigned_ticket(unsigned)
        # The ticket must name the key actually signing it.
        if unsigned["key_id"] != key_id:
            raise _Refusal("ticket-key-mismatch")
        if key_id in bundle["revoked_key_ids"]:
            raise _Refusal("key-revoked")
        delegation = None
        for candidate in bundle["delegations"]:
            if candidate["key_id"] == key_id:
                delegation = candidate
                break
        if delegation is None:
            raise _Refusal("delegation-unknown")
        # Role check: a release (or any other) delegation never signs
        # tickets — role confusion is exactly the cross-lane forgery the
        # compatibility lane exists to prevent.
        if delegation["role"] != DELEGATION_ROLE_COMPATIBILITY:
            raise _Refusal("delegation-role-mismatch")
        if unsigned["trust_generation"] != bundle["generation"]:
            raise _Refusal("trust-generation-mismatch")
        if unsigned["trust_bundle_sha256"] != bundle_sha256:
            raise _Refusal("ticket-bundle-mismatch")
        _check_delegation_grant_offline(
            delegation,
            bundle,
            unsigned["channel"],
            unsigned["sequence"],
            unsigned["issued_at"],
            unsigned["expires_at"],
        )
        # The ticket's whole validity window must fit inside the bundle's.
        if (
            unsigned["issued_at"] < bundle["issued_at"]
            or unsigned["expires_at"] > bundle["expires_at"]
        ):
            raise _Refusal("lifetime-outside-trust")
        payload = _TICKET_SIGNING_DOMAIN + canonical_bytes(unsigned)
        signature_hex = private_key.sign(payload).hex()
        if not _SIGNATURE_RE.fullmatch(signature_hex):
            raise _Refusal("signing-failed")
        _verify_own_signature(public_hex, signature_hex, payload)
        signed = dict(unsigned)
        signed["signature"] = signature_hex
        signed_bytes = canonical_bytes(signed)
        if len(signed_bytes) > MAX_DOCUMENT_BYTES:
            raise _Refusal("document-oversize")
        _publish_exclusive(
            output_file, signed_bytes, 0o644, parent_owner_only=False
        )
        return _build_result(
            COMMAND_SIGN_TICKET,
            STATUS_SIGNED,
            key_role=DELEGATION_ROLE_COMPATIBILITY,
            key_id=key_id,
            document_schema=TICKET_SCHEMA,
            document_sha256=hashlib.sha256(signed_bytes).hexdigest(),
        )

    return _guard(COMMAND_SIGN_TICKET, work)


class _SignerArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise _CliArgumentError()


def _emit(result: dict) -> int:
    sys.stdout.write(render_result(result) + "\n")
    return signing_exit_code(result)


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:]) if argv is None else list(argv)
    command = raw_argv[0] if raw_argv else ""
    if command not in (
        COMMAND_KEYGEN,
        COMMAND_SIGN_BUNDLE,
        COMMAND_SIGN_RELEASE,
        COMMAND_SIGN_TICKET,
    ):
        command = COMMAND_KEYGEN
    parser = _SignerArgumentParser(
        prog="sign_release_provenance",
        allow_abbrev=False,
        description=(
            "Offline release signer: keys and documents live in local "
            "files only; key material never passes through argv, "
            "environment, or stdin, and no output is ever overwritten. "
            "All private keys and outputs live beneath the mandatory "
            "owner-only --signing-root, outside any repository."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def _add_signing_root_argument(subparser):
        subparser.add_argument(
            "--signing-root",
            required=True,
            help=(
                "Absolute path of the owner-only signing root directory; "
                "every private key and output must live beneath it, and "
                "it must not be inside any repository."
            ),
        )

    keygen_parser = subparsers.add_parser(
        COMMAND_KEYGEN, help="Generate a fresh Ed25519 keypair."
    )
    keygen_parser.add_argument(
        "role",
        choices=("root", "release", "compatibility-review"),
        help=(
            "Key role: root signs trust bundles, release signs envelopes, "
            "compatibility-review signs build-compatibility tickets."
        ),
    )
    keygen_parser.add_argument(
        "--private-key-out",
        required=True,
        help="Absolute path for the raw 32-byte private key (0600, new).",
    )
    keygen_parser.add_argument(
        "--public-out",
        required=True,
        help="Absolute path for the canonical public document (new).",
    )
    _add_signing_root_argument(keygen_parser)

    def _add_sign_arguments(subparser):
        subparser.add_argument(
            "--private-key",
            required=True,
            help="Absolute path of the raw 0600 32-byte private key file.",
        )
        subparser.add_argument(
            "--root-file",
            required=True,
            help="Absolute path of the out-of-band release-root document.",
        )
        subparser.add_argument(
            "--input",
            required=True,
            help="Absolute path of the unsigned canonical document.",
        )
        subparser.add_argument(
            "--output",
            required=True,
            help="Absolute path for the signed document (never overwritten).",
        )
        _add_signing_root_argument(subparser)

    bundle_parser = subparsers.add_parser(
        COMMAND_SIGN_BUNDLE,
        help="Sign an unsigned trust bundle with the root key.",
    )
    _add_sign_arguments(bundle_parser)

    release_parser = subparsers.add_parser(
        COMMAND_SIGN_RELEASE,
        help="Sign an unsigned release envelope with a delegated key.",
    )
    _add_sign_arguments(release_parser)

    ticket_parser = subparsers.add_parser(
        COMMAND_SIGN_TICKET,
        allow_abbrev=False,
        help=(
            "Sign an unsigned build-compatibility ticket with a delegated "
            "compatibility-review key."
        ),
    )
    ticket_parser.add_argument(
        "--trust-bundle",
        required=True,
        help=(
            "Absolute path of the root-signed canonical v2 trust bundle "
            "the ticket binds by exact hash and generation."
        ),
    )
    _add_sign_arguments(ticket_parser)

    try:
        args = parser.parse_args(raw_argv)
    except _CliArgumentError:
        return _emit(
            _build_result(command, "unsupported:invalid-arguments")
        )
    if args.command == COMMAND_KEYGEN:
        result = keygen(
            args.role,
            args.private_key_out,
            args.public_out,
            args.signing_root,
        )
    elif args.command == COMMAND_SIGN_BUNDLE:
        result = sign_trust_bundle(
            args.private_key,
            args.root_file,
            args.input,
            args.output,
            args.signing_root,
        )
    elif args.command == COMMAND_SIGN_TICKET:
        result = sign_compatibility_ticket(
            args.private_key,
            args.root_file,
            args.trust_bundle,
            args.input,
            args.output,
            args.signing_root,
        )
    else:
        result = sign_release(
            args.private_key,
            args.root_file,
            args.input,
            args.output,
            args.signing_root,
        )
    return _emit(result)


if __name__ == "__main__":
    sys.exit(main())

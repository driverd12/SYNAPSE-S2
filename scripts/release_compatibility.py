#!/usr/bin/env python3
"""Dormant source-backed exact-build-only build-compatibility verifier.

This tool is dormant by construction: it verifies documents plus the exact
source bytes of two installed roots, and reports.  It never applies,
activates, migrates, downgrades, installs, or executes anything; it never
imports repository or candidate modules, never opens a socket, database,
or subprocess, never mutates the floor, and never accesses live-state or
recovery content (exact safe-listed live-state entries at the current root
receive bounded no-follow metadata screening only, never an open or
descent).  Once loaded by the documented CLI, or imported by an API caller
running Python with ``-B``, verifier logic never writes filesystem content;
its only output is JSON on stdout, and there is no mutation command at all.
``apply``/``activation``/``migration``/``downgrade`` support and
host-evidence use are hard-false in every result.

A build-compatibility ticket is a second, independent signature lane over
an exact pair of builds.  The release lane (a delegated ``release`` key
signing the release envelope) asserts what the candidate build *is*; the
compatibility lane (a distinct delegated ``compatibility-review`` key
signing this ticket) asserts that a named review found that exact
current-to-candidate pair compatible, surface by surface, in
``exact-build-only`` mode: the claim holds for precisely the bound bytes
and identities and for no other build, version range, or migration path.
Both roles are delegated by the same root-signed
``synapse-s2.release-trust-bundle.v2`` document, which must delegate both
roles (each to a distinct key id — a key id may appear in at most one
delegation), and each document kind verifies only over its own signing
domain.

Source-backed verification: the verifier takes the absolute current root
and candidate root, opens one descriptor-anchored snapshot per root, and
reads every inventoried file exactly once per root into one shared
payload-plus-stat cache.  From those same held bytes — never a second
pathname resolution, never a separate planner — it derives, per root: the
TRUSTED_MANIFEST ``source_build_id`` (including the AST proof that
``core_service.py`` binds ``BUILD_SOURCE_MANIFEST`` exactly once to the
trusted literal), the full product identity records
``(component, role, path, mode, size, sha256)``, the ``product_id``, the
``inventory_policy_id``, the ``dependencies`` component identity, and the
thirteen closed compatibility-surface digests over the exact stable
records of both roots.  Only after every derivation are both held chains
rechecked, the floor reread (byte-identical or the run fails closed), and
every time window re-evaluated at a fresh clock reading — so a
revocation, floor advance, or expiry during the scan can never yield
``verified``.  Candidate code is never executed or imported: sources are
bytes, screened at most by ``ast.parse``.

Closed canonical document schemas (exact canonical JSON bytes — sorted
keys, compact separators, ASCII, no trailing newline; duplicate keys,
unknown or missing fields, floats, booleans-as-integers, non-canonical
encodings, and out-of-bounds values all rejected):

- ``synapse-s2.release-root.v1`` — the out-of-band trust anchor.
- ``synapse-s2.release-trust-bundle.v2`` — root-signed over the ``v2``
  domain; delegation roles are exactly ``release`` and
  ``compatibility-review`` and both must be present.  A v1 bundle is
  refused: the ticket lane requires the two-role vocabulary.
- ``synapse-s2.release-envelope.v1`` — signed by a delegated release key;
  a ticket only verifies against a fully verified envelope, and both the
  envelope's and the ticket's whole validity windows must be contained in
  the bundle's window and in *both* delegations' windows.
- ``synapse-s2.release-floor.v1`` — the local owner-only monotonic floor.
  The presented bundle must be *accepted exactly* and the floor must
  carry an installed record for the envelope's channel; the observed
  current root must equal that installed record's product identity and
  inventory policy, and the candidate sequence must be strictly greater
  than the installed sequence.
- ``synapse-s2.build-compatibility-ticket.v1`` — signed by a delegated
  compatibility-review key over the domain
  ``SYNAPSE-S2\\x00BUILD-COMPATIBILITY-TICKET\\x00v1\\x00``.  The ticket
  uniquely signs, by exact equality: the current and candidate
  ``source_build_id`` and ``product_id``, the inventory policy id, the
  current and candidate ``dependencies`` component identities, all
  thirteen surface digests and the global surfaces digest, the ticket
  schema and ``exact-build-only`` profile and version and product schema,
  the host-independent inactive installed-layout contract id pinned
  below, the trust bundle and envelope digests, the ``required-later``
  host-evidence policy, and the ``blocked`` migration and downgrade
  policies.  ``source_build_id`` is not the envelope's ``source_sha``;
  no host layout id or host path ever enters the ticket.

The expected layout contract id is the host-independent
``layout_contract_id`` of the reviewed ``inactive-versioned-v1`` installed
layout contract (restated here as a byte-pinned constant — this tool never
imports the sibling module).  TRUSTED_MANIFEST, the product inventory,
and the inventory policy are likewise reviewed byte-pinned restatements;
the tests pin them against the sibling planner.

Output is one bounded, deterministic, redacted JSON line: status tokens
and document/build identities only — never filesystem paths, key
material, signatures, or exception text.  Exit codes: 0 verified, 3
blocked (stale/rollback/equivocation/revoked/expired/role or identity
mismatch), 2 malformed/unsafe/raced/unsupported.

Bootstrap non-claim: a compatibility ticket cannot vouch for the verifier
that checks it; the first trust root and verifier distribution are
necessarily out-of-band.

Import hardening matches the release verifier: ``sys.path`` is rebuilt
with builtins only before any non-builtin import — stdlib locations
first, then the isolated trusted environment's own site-packages as the
only permitted origin for ``cryptography`` — so no PYTHONPATH, cwd, or
repository entry survives and no import-hijack lane exists.  The imported
``cryptography`` must be version 49.0.0 exactly and must, after symlink
resolution, originate from within that admitted site-packages directory,
or every command fails closed.  The hardened invocation is
``python -I -B trusted/scripts/release_compatibility.py``.  API callers must
likewise use ``-B`` for the no-filesystem-write guarantee because Python's
import machinery runs before this module can suppress its own bytecode file.
"""

import sys

# Preserve the caller's process-global state exactly so importing this
# verifier as an API cannot perturb a long-lived test or operator process.
_ORIGINAL_SYS_PATH = list(sys.path)
_ORIGINAL_DONT_WRITE_BYTECODE = sys.dont_write_bytecode

sys.dont_write_bytecode = True

_TRUSTED_SITE_PACKAGES: str | None = None


def _sanitize_sys_path() -> None:
    """Rebuild sys.path using builtins only, before any non-builtin import.
    Identical policy to the release verifier: exactly the stdlib zip, the
    stdlib directory, lib-dynload, and — last — the trusted environment's
    own site-packages."""
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
import ast
import errno
import hashlib
import io
import json
import os
import re
import stat
import time
import tokenize


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

# CLI execution keeps the hardened import policy for the process lifetime.
# API imports restore the caller's exact process-global state; no further
# dynamic import happens below.
if __name__ != "__main__":
    sys.path[:] = _ORIGINAL_SYS_PATH
    sys.dont_write_bytecode = _ORIGINAL_DONT_WRITE_BYTECODE

RESULT_SCHEMA = "synapse-s2.build-compatibility-result.v1"
RESULT_MODE = "dormant-build-compatibility-ticket"

# Sibling schemas restated byte-for-byte (never imported); the tests pin
# them against the sibling modules.
ROOT_SCHEMA = "synapse-s2.release-root.v1"
BUNDLE_SCHEMA_V2 = "synapse-s2.release-trust-bundle.v2"
ENVELOPE_SCHEMA = "synapse-s2.release-envelope.v1"
FLOOR_SCHEMA = "synapse-s2.release-floor.v1"
PRODUCT_SCHEMA = "synapse-s2.product-release-plan.v1"
TICKET_SCHEMA = "synapse-s2.build-compatibility-ticket.v1"

DELEGATION_ROLE_RELEASE = "release"
DELEGATION_ROLE_COMPATIBILITY = "compatibility-review"
_BUNDLE_ROLES_V2 = (
    DELEGATION_ROLE_COMPATIBILITY,
    DELEGATION_ROLE_RELEASE,
)

COMMAND_VERIFY_TICKET = "verify-compatibility-ticket"

STATUS_VERIFIED = "verified"

_SUCCESS_STATUSES = frozenset((STATUS_VERIFIED,))

RESULT_NONCLAIMS = (
    "bootstrap-trust-out-of-band",
    "exact-build-only",
    "host-evidence-not-verified",
    "host-evidence-required-later",
    "no-activation",
    "no-apply",
    "no-candidate-execution",
    "no-candidate-import",
    "no-downgrade",
    "no-floor-mutation",
    "no-live-state-content-access",
    "no-migration",
    "no-network",
    "no-recovery-access",
)

# Domain separation: a signature or digest computed for one purpose can
# never verify for another.  The v1 domains are restated byte-for-byte;
# the ticket and surface domains belong to this lane alone.
_KEY_ID_DOMAIN = b"SYNAPSE-S2\x00ED25519-PUBLIC-KEY\x00v1\x00"
_BUNDLE_SIGNING_DOMAIN_V2 = b"SYNAPSE-S2\x00RELEASE-TRUST-BUNDLE\x00v2\x00"
_ENVELOPE_SIGNING_DOMAIN = b"SYNAPSE-S2\x00RELEASE-ENVELOPE\x00v1\x00"
_TICKET_SIGNING_DOMAIN = b"SYNAPSE-S2\x00BUILD-COMPATIBILITY-TICKET\x00v1\x00"
_SURFACE_DIGEST_DOMAIN = b"SYNAPSE-S2\x00COMPATIBILITY-SURFACE\x00v1\x00"
_SURFACES_DIGEST_DOMAIN = b"SYNAPSE-S2\x00COMPATIBILITY-SURFACES\x00v1\x00"

# The closed compatibility surface vocabulary: exactly these thirteen
# sorted names, each reviewed in exact-build-only mode.  Adding, removing,
# or renaming a surface is a new reviewed vocabulary (and a new ticket
# review), never an in-place edit.
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

SURFACE_MODE = "exact-build-only"

# Closed per-surface file sets: the exact inventory-relative source files
# whose stable records (path, mode, size, sha256) each surface digest
# binds, for both roots.  Reviewed verbatim; the tests pin these sets.
SURFACE_FILES = {
    "authority-runtime": (
        "core_authority.py",
        "core_client_binding.py",
        "core_service.py",
        "memory_store.py",
    ),
    "capture": (
        "capture_daemon.py",
        "transcript_capture.py",
        "memory_store.py",
        "mlx_backend.py",
        "replacement_policy.py",
        "core_service.py",
        "scripts/core_agent_installer.py",
    ),
    "context-delivery": (
        "memory_store.py",
        "mlx_backend.py",
        "core_service.py",
        "core_protocol.py",
        "mcp_server.py",
    ),
    "core-config": (
        "core_protocol.py",
        "core_service.py",
        "core_client_binding.py",
        "client_config.py",
        "scripts/core_agent_installer.py",
        "scripts/core_cutover_preflight.py",
    ),
    "disk-safety": ("core_path_policy.py",),
    "store-schema": (
        "memory_store.py",
        "core_service.py",
        "scripts/core_agent_installer.py",
    ),
    "embedding-space": (
        "embedding_providers.py",
        "mlx_backend.py",
        "core_service.py",
    ),
    "installed-layout": (
        "scripts/installed_layout.py",
        "scripts/release_activation_journal.py",
        "scripts/release_stage.py",
        "scripts/release_update_plan.py",
        "core_client_binding.py",
        "client_config.py",
        "scripts/core_agent_installer.py",
    ),
    "platform-runtime": (
        "core_protocol.py",
        "core_runtime_paths.py",
        "scripts/release_stage.py",
        "pyproject.toml",
        "uv.lock",
    ),
    "readiness-quiescence": (
        "operator_readiness_contract.py",
        "scripts/operator_readiness_certify.py",
        "scripts/core_cutover_preflight.py",
        "scripts/core_agent_installer.py",
    ),
    "recovery": (
        "recovery_manager.py",
        "memory_store.py",
        "core_request_journal.py",
        "capture_daemon.py",
        "scripts/release_activation_journal.py",
        "scripts/repair_torn_core_adoption.py",
        "scripts/core_agent_installer.py",
        "scripts/core_cutover_preflight.py",
    ),
    "replication": (
        "replication_protocol.py",
        "replication_store.py",
        "replication_manager.py",
    ),
    "request-journal": (
        "core_request_journal.py",
        "core_service.py",
        "recovery_manager.py",
    ),
}

# Pinned ticket policy claims: host evidence is deferred to a later,
# separate lane; migration and downgrade are blocked outright in
# exact-build-only mode.
HOST_EVIDENCE_POLICY = "required-later"
MIGRATION_POLICY = "blocked"
DOWNGRADE_POLICY = "blocked"

# Integer version of the compatibility ticket's exact-build-only surface
# profile; any semantic change to what a surface digest or the global digest
# covers is a new version.  This namespace is independent of the separately
# versioned dormant activation-contract profile.
PROFILE_VERSION = 2

# Closed schema of the per-root compatibility observation whose records
# the surface digests bind; hashed into the global digest.
COMPATIBILITY_OBSERVATION_SCHEMA = "synapse-s2.compatibility-observation.v1"

# Fixed installed-layout contract schema bound by the ticket and hashed
# into the global digest; host-independent by construction.
LAYOUT_SCHEMA = "synapse-s2.installed-layout-contract.v1"

# Fixed schema of the *later* host-evidence receipt lane the ticket
# points at without claiming: host evidence is required later and is not
# verified here, under any status.
HOST_EVIDENCE_RECEIPT_SCHEMA = "synapse-s2.host-evidence-receipt.v1"

# Host-independent installed-layout binding: the layout_contract_id of the
# reviewed inactive-versioned-v1 contract projection from
# scripts/installed_layout.py, restated as a byte-pinned constant (this
# tool never imports the sibling module).  The tests recompute it from the
# sibling; any layout contract change forces a reviewed re-pin here.
EXPECTED_LAYOUT_CONTRACT_MODE = "inactive-versioned-v1"
EXPECTED_LAYOUT_CONTRACT_ID = (
    "layout-contract-"
    "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada"
)

# Reviewed byte-pinned restatement of the planner's trusted copy of
# core_service.BUILD_SOURCE_MANIFEST.  The tests pin exact tuple parity
# with scripts/release_update_plan.py, so manifest evolution fails closed
# until this verifier is deliberately updated in the same release.
TRUSTED_MANIFEST = (
    "apple_vision_enrichment.py",
    "backend_router.py",
    "bridge_governance.py",
    "capture_daemon.py",
    "client_config.py",
    "core_authority.py",
    "core_client_binding.py",
    "core_client.py",
    "core_path_policy.py",
    "core_protocol.py",
    "core_request_journal.py",
    "core_runtime_paths.py",
    "core_service.py",
    "cortex_contract.py",
    "embedding_providers.py",
    "event_segmenter.py",
    "harmonic_memory.py",
    "image_capture.py",
    "media_similarity.py",
    "memora_governance.py",
    "memora_shadow.py",
    "memory_store.py",
    "mlx_backend.py",
    "native/apple_vision_enrich.swift",
    "operator_readiness_contract.py",
    "recovery_manager.py",
    "redaction.py",
    "replication_manager.py",
    "replication_protocol.py",
    "replication_store.py",
    "replacement_policy.py",
    "retrieval_cursor.py",
    "scripts/core_cutover_preflight.py",
    "transcript_capture.py",
    "pyproject.toml",
    "uv.lock",
)

_MANIFEST_NAME = "BUILD_SOURCE_MANIFEST"

# Bounds on candidate core_service.py analysis, with generous headroom
# over the trusted source (restated from the planner).
MAX_MANIFEST_SOURCE_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_SOURCE_TOKENS = 160_000

_DYNAMIC_NAMESPACE_BUILTINS = frozenset(
    (
        "exec",
        "eval",
        "globals",
        "locals",
        "vars",
        "__import__",
        "setattr",
        "delattr",
    )
)

_PYTHON_ENCODING_COOKIE_RE = re.compile(
    br"^[ \t\f]*#.*?coding[:=][ \t]*[-_.a-zA-Z0-9]+"
)

# Product identity vocabulary, restated byte-for-byte from the planner;
# the tests pin every constant and the derived inventory_policy_id.
_PRODUCT_ID_DOMAIN = "synapse-s2.product-identity.v1"
_PRODUCT_COMPONENT_ID_DOMAIN = "synapse-s2.component-identity.v1"
INVENTORY_POLICY_SCHEMA = "synapse-s2.product-inventory-policy.v1"
INVENTORY_POLICY_CANDIDATE_LAYOUT = "closed-exact-v1"
INVENTORY_POLICY_RECORD_FIELDS = (
    "component",
    "role",
    "path",
    "mode",
    "size",
    "sha256",
)
_INVENTORY_POLICY_ID_DOMAIN = "SYNAPSE-S2\x00PRODUCT-INVENTORY-POLICY\x00v1\x00"

DEPENDENCY_COMPONENT = "dependencies"

# Reviewed byte-pinned restatement of the planner's component-tagged
# product inventory; nothing is derived at runtime and git is never
# invoked.  The tests pin exact tuple parity with the planner.
PRODUCT_INVENTORY = (
    ("repo-config", "vcs-config", ".gitattributes"),
    ("repo-config", "vcs-config", ".gitignore"),
    ("config-template", "config-template", ".mcp.json.example"),
    ("repo-config", "agent-doc", "AGENTS.md"),
    ("operator-docs", "policy-doc", "README.md"),
    ("core", "code", "apple_vision_enrichment.py"),
    ("core", "code", "backend_router.py"),
    ("core", "code", "bridge_governance.py"),
    ("core", "code", "capture_daemon.py"),
    ("core", "code", "client_config.py"),
    ("mcp", "code", "client_session_bridge.py"),
    ("core", "code", "core_authority.py"),
    ("core", "code", "core_client.py"),
    ("core", "code", "core_client_binding.py"),
    ("core", "code", "core_path_policy.py"),
    ("core", "code", "core_protocol.py"),
    ("core", "code", "core_request_journal.py"),
    ("core", "code", "core_runtime_paths.py"),
    ("core", "code", "core_service.py"),
    ("core", "code", "cortex_contract.py"),
    ("dashboard", "code", "dashboard_server.py"),
    ("operator-docs", "policy-doc", "docs/AUTHORITATIVE_CORE_OPERATIONS.md"),
    ("operator-docs", "policy-doc", "docs/BRIDGE_GOVERNANCE.md"),
    ("operator-docs", "doc", "docs/CURRENT_STATUS.md"),
    ("operator-docs", "policy-doc", "docs/EXACTLY_ONCE_CAPTURE.md"),
    ("operator-docs", "doc", "docs/FRONTIER_ENHANCEMENTS.md"),
    ("operator-docs", "doc", "docs/HARMONIC_MEMORY.md"),
    ("operator-docs", "doc", "docs/LONGMEM_V2_EVALUATION.md"),
    ("operator-docs", "doc", "docs/MEMORA_SHADOW.md"),
    ("operator-docs", "doc", "docs/MEMORY_CONFIDENCE_GATE.md"),
    ("operator-docs", "policy-doc", "docs/MULTI_MAC_REPLICATION.md"),
    (
        "operator-docs",
        "doc",
        "docs/Neuromorphic-Attention-Plugin-Development-Plan.md",
    ),
    (
        "operator-docs",
        "doc",
        "docs/Neuromorphic-Attention-Plugin-Development-Plan.pdf",
    ),
    (
        "operator-docs",
        "policy-doc",
        "docs/OPERATOR_READINESS_CERTIFICATION.md",
    ),
    ("operator-docs", "doc", "docs/PRODUCTION_GAP_AUDIT.md"),
    ("operator-docs", "doc", "docs/PROPOSAL_COMPLIANCE.md"),
    ("operator-docs", "doc", "docs/RETRIEVAL_V2_VALIDATION.md"),
    ("operator-docs", "doc", "docs/TOKEN_CONTRACTS.md"),
    ("operator-docs", "doc", "docs/TOMORROW_RUNBOOK.md"),
    (
        "operator-docs",
        "evidence",
        "docs/evidence/phase6-token-contract-acceptance.json",
    ),
    (
        "operator-docs",
        "evidence",
        "docs/evidence/phase8-retrieval-v2-acceptance.json",
    ),
    (
        "operator-docs",
        "evidence",
        "docs/evidence/phase9-replication-acceptance.json",
    ),
    ("operator-docs", "doc", "docs/source-prompt-and-plan.txt"),
    (
        "operator-docs",
        "doc",
        "docs/superpowers/plans/2026-06-26-large-neural-embedding-provider.md",
    ),
    (
        "operator-docs",
        "doc",
        "docs/superpowers/plans/2026-06-27-synapse-s2-reliability-usability.md",
    ),
    (
        "operator-docs",
        "doc",
        "docs/superpowers/plans/2026-06-29-operator-readiness-certification.md",
    ),
    ("core", "code", "embedding_providers.py"),
    ("core", "code", "event_segmenter.py"),
    ("core", "code", "harmonic_memory.py"),
    ("core", "code", "image_capture.py"),
    ("core", "code", "impact_metrics.py"),
    ("support-tools", "support-tool", "longmem_eval.py"),
    ("mcp", "code", "mcp_client_wrapper.py"),
    ("mcp", "code", "mcp_server.py"),
    ("core", "code", "media_similarity.py"),
    ("core", "code", "memora_governance.py"),
    ("core", "code", "memora_shadow.py"),
    ("core", "code", "memory_store.py"),
    ("core", "code", "mlx_backend.py"),
    ("native", "native-source", "native/apple_vision_enrich.swift"),
    ("official-longmem", "eval-adapter", "official_longmem/__init__.py"),
    ("official-longmem", "eval-adapter", "official_longmem/bootstrap.py"),
    (
        "official-longmem",
        "eval-adapter",
        "official_longmem/synapse_s2_memory.py",
    ),
    ("core", "code", "operator_readiness_contract.py"),
    (
        "operator-manual",
        "manual-asset",
        "output/manual/SYNAPSE-S2_Quick_Reference.png",
    ),
    (
        "operator-manual",
        "manual-asset",
        "output/manual/SYNAPSE-S2_Visual_User_Manual.md",
    ),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-01.png"),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-02.png"),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-03.png"),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-04.png"),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-05.png"),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-06.png"),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-07.png"),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-08.png"),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-09.png"),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-10.png"),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-11.png"),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-12.png"),
    ("operator-manual", "manual-asset", "output/manual/plates/manual-13.png"),
    (
        "operator-manual",
        "manual-asset",
        "output/pdf/SYNAPSE-S2_Quick_Reference.pdf",
    ),
    (
        "operator-manual",
        "manual-asset",
        "output/pdf/SYNAPSE-S2_Visual_User_Manual.pdf",
    ),
    ("dependencies", "packaging", "pyproject.toml"),
    ("core", "code", "recovery_manager.py"),
    ("core", "code", "redaction.py"),
    ("core", "code", "replacement_policy.py"),
    ("core", "code", "replication_manager.py"),
    ("core", "code", "replication_protocol.py"),
    ("core", "code", "replication_store.py"),
    ("core", "code", "retrieval_cursor.py"),
    (
        "operator-scripts",
        "operator-script",
        "scripts/capture_frontmost_selection.sh",
    ),
    ("operator-scripts", "operator-script", "scripts/core_agent_installer.py"),
    (
        "operator-scripts",
        "operator-script",
        "scripts/core_cutover_preflight.py",
    ),
    (
        "operator-scripts",
        "operator-script",
        "scripts/core_cutover_preflight.sh",
    ),
    (
        "operator-scripts",
        "operator-script",
        "scripts/install_capture_daemon.sh",
    ),
    (
        "operator-scripts",
        "operator-script",
        "scripts/install_client_configs.py",
    ),
    ("operator-scripts", "operator-script", "scripts/install_core_agent.sh"),
    (
        "operator-scripts",
        "operator-script",
        "scripts/install_dashboard_agent.sh",
    ),
    (
        "operator-scripts",
        "operator-script",
        "scripts/install_local_launcher.sh",
    ),
    ("operator-scripts", "operator-script", "scripts/installed_layout.py"),
    ("support-tools", "support-tool", "scripts/measure_longmem_v2.py"),
    ("support-tools", "support-tool", "scripts/measure_memory_confidence.py"),
    ("support-tools", "support-tool", "scripts/measure_retrieval_v2.py"),
    ("support-tools", "support-tool", "scripts/measure_token_contracts.py"),
    ("operator-scripts", "operator-script", "scripts/open_dashboard.py"),
    (
        "operator-scripts",
        "operator-script",
        "scripts/operator_readiness_certify.py",
    ),
    ("operator-scripts", "operator-script", "scripts/prep_tomorrow.sh"),
    ("operator-scripts", "operator-script", "scripts/purge_namespaces.py"),
    (
        "operator-scripts",
        "operator-script",
        "scripts/release_activation_journal.py",
    ),
    (
        "operator-scripts",
        "operator-script",
        "scripts/release_compatibility.py",
    ),
    ("operator-scripts", "operator-script", "scripts/release_provenance.py"),
    ("operator-scripts", "operator-script", "scripts/release_stage.py"),
    ("operator-scripts", "operator-script", "scripts/release_update_plan.py"),
    (
        "operator-scripts",
        "operator-script",
        "scripts/repair_torn_core_adoption.py",
    ),
    ("support-tools", "support-tool", "scripts/run_longmem_v2_official.py"),
    (
        "operator-scripts",
        "operator-script",
        "scripts/secure_installer_support.py",
    ),
    (
        "operator-scripts",
        "operator-script",
        "scripts/sign_release_provenance.py",
    ),
    ("operator-scripts", "operator-script", "scripts/smoke_dashboard.py"),
    (
        "operator-scripts",
        "operator-script",
        "scripts/synapse_status_report.py",
    ),
    ("cli", "code", "synapse_cli.py"),
    ("tests", "fixture", "tests/fixtures/longmem_v2/benchmark_v1.json"),
    ("tests", "fixture", "tests/fixtures/memory_confidence/benchmark_v1.json"),
    ("tests", "fixture", "tests/fixtures/retrieval_v2/benchmark_v1.json"),
    ("tests", "test", "tests/test_apple_vision_enrichment.py"),
    ("tests", "test", "tests/test_argparse_security.py"),
    ("tests", "test", "tests/test_backend.py"),
    ("tests", "test", "tests/test_backend_routing.py"),
    ("tests", "test", "tests/test_backup_recovery.py"),
    ("tests", "test", "tests/test_bridge_governance.py"),
    ("tests", "test", "tests/test_capture_daemon.py"),
    ("tests", "test", "tests/test_capture_ledger_reconciliation.py"),
    ("tests", "test", "tests/test_cli.py"),
    ("tests", "test", "tests/test_client_config.py"),
    ("tests", "test", "tests/test_client_session_bridge.py"),
    ("tests", "test", "tests/test_context_event_delivery.py"),
    ("tests", "test", "tests/test_core_adoption_repair.py"),
    ("tests", "test", "tests/test_core_authority.py"),
    ("tests", "test", "tests/test_core_client_binding.py"),
    ("tests", "test", "tests/test_core_cutover_preflight_finite.py"),
    ("tests", "test", "tests/test_core_installer.py"),
    ("tests", "test", "tests/test_core_operational_routes.py"),
    ("tests", "test", "tests/test_core_path_policy.py"),
    ("tests", "test", "tests/test_core_protocol.py"),
    ("tests", "test", "tests/test_core_recovery_routes.py"),
    ("tests", "test", "tests/test_core_request_journal.py"),
    ("tests", "test", "tests/test_core_service.py"),
    ("tests", "test", "tests/test_dashboard_memora.py"),
    ("tests", "test", "tests/test_dashboard_open.py"),
    ("tests", "test", "tests/test_dashboard_server.py"),
    ("tests", "test", "tests/test_dashboard_smoke.py"),
    ("tests", "test", "tests/test_documentation.py"),
    ("tests", "test", "tests/test_embedding_providers.py"),
    ("tests", "test", "tests/test_event_segmenter.py"),
    ("tests", "test", "tests/test_harmonic_memory.py"),
    ("tests", "test", "tests/test_image_capture.py"),
    ("tests", "test", "tests/test_impact_metrics.py"),
    ("tests", "test", "tests/test_installed_layout.py"),
    ("tests", "test", "tests/test_launch_agent_installers.py"),
    ("tests", "test", "tests/test_longmem_eval.py"),
    ("tests", "test", "tests/test_longmem_v2_measurement.py"),
    ("tests", "test", "tests/test_mcp_client_wrapper.py"),
    ("tests", "test", "tests/test_mcp_server.py"),
    ("tests", "test", "tests/test_measure_token_contracts.py"),
    ("tests", "test", "tests/test_media_similarity.py"),
    ("tests", "test", "tests/test_memora_governance.py"),
    ("tests", "test", "tests/test_memora_retrieval.py"),
    ("tests", "test", "tests/test_memora_shadow.py"),
    ("tests", "test", "tests/test_memora_surfaces.py"),
    ("tests", "test", "tests/test_memory_confidence_measurement.py"),
    ("tests", "test", "tests/test_memory_store.py"),
    ("tests", "test", "tests/test_memory_store_atomicity.py"),
    ("tests", "test", "tests/test_official_longmem_adapter.py"),
    ("tests", "test", "tests/test_official_longmem_runner_stage1a.py"),
    ("tests", "test", "tests/test_operational_scripts.py"),
    ("tests", "test", "tests/test_operator_readiness_certifier.py"),
    ("tests", "test", "tests/test_purge_namespaces.py"),
    ("tests", "test", "tests/test_recovery_route_surfaces.py"),
    ("tests", "test", "tests/test_redaction.py"),
    ("tests", "test", "tests/test_release_activation_journal.py"),
    ("tests", "test", "tests/test_release_compatibility.py"),
    ("tests", "test", "tests/test_release_provenance.py"),
    ("tests", "test", "tests/test_release_stage.py"),
    ("tests", "test", "tests/test_release_update_orchestrator.py"),
    ("tests", "test", "tests/test_release_update_plan.py"),
    ("tests", "test", "tests/test_replacement_admission.py"),
    ("tests", "test", "tests/test_replication.py"),
    ("tests", "test", "tests/test_response_contract.py"),
    ("tests", "test", "tests/test_retrieval_cursor.py"),
    ("tests", "test", "tests/test_retrieval_pages.py"),
    ("tests", "test", "tests/test_retrieval_pagination_integration.py"),
    ("tests", "test", "tests/test_retrieval_v2.py"),
    ("tests", "test", "tests/test_retrieval_v2_contract.py"),
    ("tests", "test", "tests/test_retrieval_v2_measurement.py"),
    ("tests", "test", "tests/test_retrieval_v2_surfaces.py"),
    ("tests", "test", "tests/test_status_report.py"),
    ("tests", "test", "tests/test_transcript_capture.py"),
    ("core", "code", "token_contracts.py"),
    ("core", "code", "transcript_capture.py"),
    ("dependencies", "dependency-lock", "uv.lock"),
    ("dashboard", "web-asset", "web/app.js"),
    ("dashboard", "web-asset", "web/index.html"),
    ("dashboard", "web-asset", "web/styles.css"),
)

# Root-local live-state directories the *current* (incumbent) root may
# contain without failing verification.  They are exempted only at the
# root, only by exact name, and only when they are real directories after
# no-follow screening; there are no nested or basename exemptions, and the
# candidate root gets no exemption at all.  Restated byte-for-byte from
# the reviewed planner.
PRODUCT_CURRENT_ROOT_IGNORED_DIRS = frozenset(
    (
        ".cache",
        ".claude",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".synapse_s2",
        ".uv-cache",
        ".venv",
        "__pycache__",
    )
)

# Host configuration artifacts the *current* (incumbent) root may carry at
# its top level: exact regular-file names plus a strict, bounded, ASCII
# rotation pattern for timestamped ``.mcp.json`` backups.  Each is
# type-screened with a no-follow stat, checked for safe ownership, link
# count, and mode, and never opened; the candidate root gets no such
# exemption and rejects every one of these names.
PRODUCT_CURRENT_ROOT_IGNORED_FILES = frozenset(
    (
        ".DS_Store",
        ".mcp.json",
        "..mcp.json.synapse-config.lock",
    )
)
_PRODUCT_CURRENT_BACKUP_RE = re.compile(
    r"\.mcp\.json\.bak-[0-9]{8}-[0-9]{6}(?:-[0-9a-f]{8,32})?"
)

# Bytecode cache directories tolerated (never opened) inside the *current*
# root, by exact inventory-relative path only.  There is no basename-wide
# exemption, and the candidate root rejects these paths too.
PRODUCT_CURRENT_CACHE_DIR_PATHS = frozenset(
    (
        "official_longmem/__pycache__",
        "scripts/__pycache__",
        "tests/__pycache__",
    )
)

# Basenames that can never legitimately appear anywhere in the inventory.
_PRODUCT_CACHE_BASENAMES = frozenset(("__pycache__", ".pytest_cache"))

# VCS metadata tolerated (never read) in either root after no-follow type
# screening: a directory in a primary checkout, a regular file in a linked
# worktree; anything else (symlink, special file) fails closed.
_PRODUCT_VCS_METADATA_NAMES = frozenset((".git",))

# Hard bounds, enforced before the offending byte or entry is consumed.
MAX_DOCUMENT_BYTES = 64 * 1024
MAX_RESULT_BYTES = 8192
MAX_PATH_BYTES = 4096
MAX_DELEGATIONS = 16
MAX_BUNDLE_CHANNELS = 16
MAX_FLOOR_CHANNELS = 64
MAX_REVOCATIONS = 64
MAX_INT = 2**53
MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
# Planner-parity aggregate budgets (restated from the reviewed planner):
# one logical product-byte budget shared across both roots, and one
# independent budget for the cached TRUSTED_MANIFEST payload lengths,
# likewise shared across both roots.
MAX_TOTAL_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_PRODUCT_TOTAL_BYTES = 2 * MAX_TOTAL_MANIFEST_BYTES
MAX_PRODUCT_INVENTORY_ENTRIES = 512
MAX_PRODUCT_DIRECTORY_ENTRIES = 512
MAX_PRODUCT_NAME_BYTES = 255
MAX_PRODUCT_PATH_BYTES = 512
MAX_PRODUCT_SCANNED_NAME_BYTES = 512 * 1024
_READ_CHUNK_BYTES = 1024 * 1024

_KEY_ID_RE = re.compile(r"ed25519-[0-9a-f]{64}")
_HEX_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}")
_PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{64}")
_SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}")
_BUILD_ID_RE = re.compile(r"source-[0-9a-f]{24}")
_PRODUCT_ID_RE = re.compile(r"product-[0-9a-f]{64}")
_COMPONENT_ID_RE = re.compile(r"component-[0-9a-f]{64}")
_POLICY_ID_RE = re.compile(r"inventory-policy-[0-9a-f]{64}")
_CHANNEL_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,63}")
_LAYOUT_CONTRACT_ID_RE = re.compile(r"layout-contract-[0-9a-f]{64}")

# Path components that must never appear in any operand path (compared
# case-insensitively).
_FORBIDDEN_PATH_COMPONENTS = frozenset(
    (".synapse_s2", "recovery", "updater-state")
)

_GROUP_OR_WORLD_WRITE = 0o022

_O_DIRECTORY = getattr(os, "O_DIRECTORY", None)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", None)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", None)

_DIR_OPEN_FLAGS = (
    os.O_RDONLY | (_O_DIRECTORY or 0) | (_O_NOFOLLOW or 0) | (_O_CLOEXEC or 0)
)
# O_NONBLOCK guarantees that an entry swapped to a FIFO between the
# no-follow stat and the open cannot block the verifier; for regular files
# it is a no-op.
_FILE_OPEN_FLAGS = (
    os.O_RDONLY
    | (_O_NOFOLLOW or 0)
    | (_O_CLOEXEC or 0)
    | (_O_NONBLOCK or 0)
)

_PLATFORM_SUPPORTED = (
    None not in (_O_DIRECTORY, _O_NOFOLLOW, _O_CLOEXEC, _O_NONBLOCK)
    and callable(getattr(os, "pread", None))
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
)


class _Refusal(Exception):
    """Exit 2: malformed, unsafe, raced, or unsupported."""

    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


class _Blocked(Exception):
    """Exit 3: stale, rollback, equivocation, revoked, expired, or a role
    or identity mismatch discovered across verified documents and
    observed roots."""

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
    """Strict parse: what is signed is exactly what is stored."""
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


def _validate_bundle_v2_syntax(document: dict) -> None:
    """Single-document checks of a v2 trust bundle.  A v1 bundle is
    refused outright: the ticket lane requires the two-role vocabulary,
    and both role sets must be nonempty (each role on a distinct key id —
    a key id may appear in at most one delegation)."""
    token = "bundle-invalid"
    _require_exact_fields(document, _BUNDLE_FIELDS, token)
    if document["schema"] != BUNDLE_SCHEMA_V2:
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
        if delegation["role"] not in _BUNDLE_ROLES_V2:
            raise _Refusal(token)
        seen_roles.add(delegation["role"])
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
    if seen_roles != set(_BUNDLE_ROLES_V2):
        # Both role sets must be nonempty: the compatibility lane cannot
        # exist without the release lane it cross-checks, and vice versa.
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


def _verify_bundle_v2(
    document: dict, root_key_id: str, root_public_key: str, now: int
) -> None:
    """Cross-document verification of an already syntax-valid v2 bundle
    over the v2 signing domain only."""
    if document["root_key_id"] != root_key_id:
        raise _Blocked("bundle-root-mismatch")
    if not _signature_valid(
        root_public_key,
        document["signature"],
        _unsigned_signing_payload(document, _BUNDLE_SIGNING_DOMAIN_V2),
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


def _find_delegation(bundle: dict, key_id: str) -> dict:
    for candidate in bundle["delegations"]:
        if candidate["key_id"] == key_id:
            return candidate
    raise _Blocked("delegation-unknown")


def _check_delegation_grant(
    delegation: dict,
    bundle: dict,
    channel: str,
    sequence: int,
    issued_at: int,
    expires_at: int,
    now: int,
) -> None:
    """Shared delegation checks: channel grant, validity containment,
    current-time window, channel minimum, and inclusive sequence bounds."""
    if channel not in delegation["channels"]:
        raise _Blocked("channel-not-delegated")
    if not (
        delegation["not_before"] <= issued_at < delegation["not_after"]
    ):
        raise _Blocked("delegation-window")
    if expires_at > delegation["not_after"]:
        # The document's whole validity must be contained in the
        # delegation's: a delegate cannot mint trust outliving its grant.
        raise _Blocked("delegation-window")
    if now < delegation["not_before"]:
        raise _Blocked("delegation-not-yet-valid")
    if now >= delegation["not_after"]:
        raise _Blocked("delegation-expired")
    minimum = bundle["channel_minimum_sequences"].get(channel)
    if minimum is None:
        raise _Blocked("channel-unknown")
    if sequence < minimum:
        raise _Blocked("sequence-below-minimum")
    if not (
        delegation["sequence_minimum"]
        <= sequence
        <= delegation["sequence_maximum"]
    ):
        raise _Blocked("sequence-outside-delegation")


def _verify_envelope(
    envelope: dict, bundle: dict, root_key_id: str, now: int
) -> dict:
    """Cross-document verification of an already syntax-valid envelope
    against an already verified v2 bundle; only a release-role delegation
    signs envelopes.  Returns the signing delegation."""
    key_id = envelope["key_id"]
    if key_id == root_key_id:
        raise _Blocked("root-signed-envelope")
    if key_id in bundle["revoked_key_ids"]:
        raise _Blocked("key-revoked")
    delegation = _find_delegation(bundle, key_id)
    if delegation["role"] != DELEGATION_ROLE_RELEASE:
        raise _Blocked("delegation-role-mismatch")
    if envelope["trust_generation"] != bundle["generation"]:
        raise _Blocked("trust-generation-mismatch")
    _check_delegation_grant(
        delegation,
        bundle,
        envelope["channel"],
        envelope["sequence"],
        envelope["issued_at"],
        envelope["expires_at"],
        now,
    )
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
    return delegation


_TICKET_FIELDS = (
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
    "signature",
)


def _validate_ticket_syntax(document: dict) -> None:
    """Single-document checks of a build-compatibility ticket: exact
    fields, closed vocabularies, pinned policy claims, exactly the
    thirteen surface digests in exact-build-only profile.  A ticket
    claiming any other profile or policy is not a document this verifier
    accepts at all."""
    token = "ticket-invalid"
    _require_exact_fields(document, _TICKET_FIELDS, token)
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
        # component; a ticket claiming a dependency change is not a
        # document this verifier accepts at all.
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
    _string(document["layout_contract_id"], token, _LAYOUT_CONTRACT_ID_RE)
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
    _string(document["signature"], token, _SIGNATURE_RE)


def _verify_ticket(
    ticket: dict, bundle: dict, root_key_id: str, now: int
) -> dict:
    """Cross-document verification of an already syntax-valid ticket
    against an already verified v2 bundle; only a compatibility-review
    delegation signs tickets, over the ticket domain only.  Returns the
    signing delegation."""
    key_id = ticket["key_id"]
    if key_id == root_key_id:
        # The root key never signs tickets.
        raise _Blocked("root-signed-ticket")
    if key_id in bundle["revoked_key_ids"]:
        raise _Blocked("key-revoked")
    delegation = _find_delegation(bundle, key_id)
    if delegation["role"] != DELEGATION_ROLE_COMPATIBILITY:
        # Role confusion: a release key vouching for compatibility is
        # exactly the cross-lane forgery this lane exists to prevent.
        raise _Blocked("delegation-role-mismatch")
    if ticket["trust_generation"] != bundle["generation"]:
        raise _Blocked("trust-generation-mismatch")
    _check_delegation_grant(
        delegation,
        bundle,
        ticket["channel"],
        ticket["sequence"],
        ticket["issued_at"],
        ticket["expires_at"],
        now,
    )
    if not _signature_valid(
        delegation["public_key"],
        ticket["signature"],
        _unsigned_signing_payload(ticket, _TICKET_SIGNING_DOMAIN),
    ):
        raise _Blocked("ticket-signature-invalid")
    if now < ticket["issued_at"]:
        raise _Blocked("ticket-not-yet-valid")
    if now >= ticket["expires_at"]:
        raise _Blocked("ticket-expired")
    return delegation


def _check_lifetime_containment(
    document: dict,
    bundle: dict,
    release_delegation: dict,
    compatibility_delegation: dict,
) -> None:
    """The document's whole validity window must fit inside the bundle's
    window and inside *both* delegations' windows: neither lane may hold a
    claim alive after the other lane's grant has lapsed."""
    issued_at = document["issued_at"]
    expires_at = document["expires_at"]
    if issued_at < bundle["issued_at"] or expires_at > bundle["expires_at"]:
        raise _Blocked("lifetime-outside-trust")
    for delegation in (release_delegation, compatibility_delegation):
        if (
            issued_at < delegation["not_before"]
            or expires_at > delegation["not_after"]
        ):
            raise _Blocked("lifetime-outside-trust")


def _check_ticket_binding(
    ticket: dict,
    envelope: dict,
    bundle_sha256: str,
    envelope_sha256: str,
) -> None:
    """Exact document-level cross-binding: the ticket names one bundle,
    one envelope, one channel/sequence/version, one inventory policy, one
    candidate product, and one layout contract — all by exact equality, or
    the ticket binds nothing.  Source-observation bindings are checked
    separately after the scan."""
    if ticket["trust_bundle_sha256"] != bundle_sha256:
        raise _Blocked("ticket-bundle-mismatch")
    if ticket["envelope_sha256"] != envelope_sha256:
        raise _Blocked("ticket-envelope-mismatch")
    if ticket["channel"] != envelope["channel"]:
        raise _Blocked("ticket-channel-mismatch")
    if ticket["sequence"] != envelope["sequence"]:
        raise _Blocked("ticket-sequence-mismatch")
    if ticket["version"] != envelope["version"]:
        raise _Blocked("ticket-version-mismatch")
    if ticket["source_sha"] != envelope["source_sha"]:
        raise _Blocked("ticket-source-mismatch")
    if ticket["inventory_policy_id"] != envelope["inventory_policy_id"]:
        raise _Blocked("ticket-policy-mismatch")
    if ticket["candidate_product_id"] != envelope["product_id"]:
        raise _Blocked("ticket-product-mismatch")
    if ticket["layout_contract_id"] != EXPECTED_LAYOUT_CONTRACT_ID:
        raise _Blocked("layout-contract-mismatch")
    # The ticket's whole validity window must also fit inside the
    # envelope's window: a compatibility claim may never outlive (or
    # predate) the release claim it vouches for.
    if (
        ticket["issued_at"] < envelope["issued_at"]
        or ticket["expires_at"] > envelope["expires_at"]
    ):
        raise _Blocked("lifetime-outside-envelope")


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
    """Monotonic floor checks, then the *exact acceptance* requirement:
    the presented bundle must be the committed floor trust itself."""
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
    floor_revoked = frozenset(floor["revoked_key_ids"])
    if not floor_revoked <= frozenset(bundle["revoked_key_ids"]):
        raise _Blocked("revocation-forgotten")
    for delegation in bundle["delegations"]:
        if delegation["key_id"] in floor_revoked:
            raise _Blocked("revoked-key-redelegated")
    if (
        bundle["generation"] != floor["trust_generation"]
        or bundle_sha256 != floor["trust_bundle_sha256"]
    ):
        # A ticket only verifies under the exact committed trust; accept
        # the newer bundle first.
        raise _Blocked("trust-not-accepted")


def _check_floor_release(floor: dict, envelope: dict) -> dict:
    """Channel checks of a verified envelope against the accepted floor:
    the channel must exist with an installed record, the candidate must
    clear the committed minimum, and the candidate sequence must be
    strictly greater than the installed sequence — an equal sequence is a
    re-signing, not an update, and never yields a compatibility claim.
    Returns the installed record for post-scan identity checks."""
    state = floor["channels"].get(envelope["channel"])
    if state is None:
        raise _Blocked("channel-not-accepted")
    if envelope["sequence"] < state["minimum_sequence"]:
        raise _Blocked("sequence-below-floor")
    installed = state["installed"]
    if installed is None:
        raise _Blocked("channel-not-installed")
    if envelope["sequence"] <= installed["sequence"]:
        raise _Blocked("sequence-not-advancing")
    return installed


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


def _identity(observed: os.stat_result) -> tuple[int, int, int]:
    # Shared ancestors (e.g. /, /Users, /tmp) legitimately change mtime as
    # unrelated processes work inside them; their swap detection needs only
    # device, inode, and file type.
    return (observed.st_dev, observed.st_ino, stat.S_IFMT(observed.st_mode))


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


def _walk_to_parent(
    path: str, fds: list[int]
) -> tuple[int, str, list[tuple[int, str, int]]]:
    """Open every ancestor of ``path`` dir_fd-relative with a no-follow
    stat plus O_DIRECTORY|O_NOFOLLOW open anchored at ``/``, so no ancestor
    symlink is ever followed and no pathname is re-resolved."""
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


def _read_safe_document(
    path: str, owner_only: bool = False, missing_ok: bool = False
) -> bytes | None:
    """Race-checked read of one document: fingerprint equality before,
    during, and after the read, then a re-proof of every walk step and of
    the leaf's finally visible identity."""
    fds: list[int] = []
    try:
        try:
            directory_fd, leaf, steps = _walk_to_parent(path, fds)
            try:
                before = os.stat(
                    leaf, dir_fd=directory_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                if missing_ok:
                    _verify_visible_steps(steps)
                    return None
                raise _Refusal("file-missing")
            _screen_regular_file(before, owner_only)
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


class _HeldFloorDocument:
    """Race-checked floor read that retains every walk descriptor, the
    final parent descriptor, and the floor leaf descriptor from the
    initial read until the verifier's outer finally, so the recheck
    proves the same held inode and bytes — a close-and-reopen recheck
    would let an A-B-A replacement of the floor escape byte comparison."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._fds: list[int] = []
        self._steps: list[tuple[int, str, int]] = []
        self._parent_fd = -1
        self._leaf = ""
        self._file_fd = -1
        self._leaf_fingerprint: tuple | None = None
        self._parent_fingerprint: tuple | None = None

    def open_and_read(self, owner_only: bool) -> bytes | None:
        try:
            directory_fd, leaf, steps = _walk_to_parent(
                self.path, self._fds
            )
            self._steps = steps
            self._parent_fd = directory_fd
            self._leaf = leaf
            try:
                before = os.stat(
                    leaf, dir_fd=directory_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                _verify_visible_steps(steps)
                return None
            _screen_regular_file(before, owner_only)
            if before.st_size > MAX_DOCUMENT_BYTES:
                raise _Refusal("document-oversize")
            file_fd = os.open(leaf, _FILE_OPEN_FLAGS, dir_fd=directory_fd)
            self._fds.append(file_fd)
            self._file_fd = file_fd
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
            held = os.fstat(file_fd)
            if _fingerprint(during) != _fingerprint(held):
                raise _Refusal("validation-race")
            if len(data) != before.st_size:
                raise _Refusal("validation-race")
            try:
                visible = os.stat(
                    leaf, dir_fd=directory_fd, follow_symlinks=False
                )
            except OSError:
                raise _Refusal("validation-race")
            if _fingerprint(visible) != _fingerprint(held):
                raise _Refusal("validation-race")
            _verify_visible_steps(steps)
            self._leaf_fingerprint = _fingerprint(held)
            # Captured only after the leaf and ancestor proofs: an atomic
            # A-B-A rename back into place must move the parent's ctime,
            # so the recheck pins the parent's full fingerprint too.
            self._parent_fingerprint = _fingerprint(os.fstat(directory_fd))
            return data
        except (_Refusal, _Blocked):
            raise
        except OSError:
            raise _Refusal("file-unreadable")

    def recheck_bytes(self, initial_bytes: bytes) -> None:
        token = "floor-raced"
        try:
            _verify_visible_steps(self._steps)
            parent = os.fstat(self._parent_fd)
            if _fingerprint(parent) != self._parent_fingerprint:
                raise _Refusal(token)
            held = os.fstat(self._file_fd)
            visible = os.stat(
                self._leaf, dir_fd=self._parent_fd, follow_symlinks=False
            )
            if _fingerprint(held) != self._leaf_fingerprint:
                raise _Refusal(token)
            if _fingerprint(visible) != self._leaf_fingerprint:
                raise _Refusal(token)
            chunks: list[bytes] = []
            offset = 0
            remaining = MAX_DOCUMENT_BYTES + 1
            while remaining > 0:
                chunk = os.pread(
                    self._file_fd, min(remaining, 65536), offset
                )
                if not chunk:
                    break
                chunks.append(chunk)
                offset += len(chunk)
                remaining -= len(chunk)
            if b"".join(chunks) != initial_bytes:
                raise _Refusal(token)
            if _fingerprint(os.fstat(self._file_fd)) != (
                self._leaf_fingerprint
            ):
                raise _Refusal(token)
            visible_again = os.stat(
                self._leaf, dir_fd=self._parent_fd, follow_symlinks=False
            )
            if _fingerprint(visible_again) != self._leaf_fingerprint:
                raise _Refusal(token)
            if _fingerprint(os.fstat(self._parent_fd)) != (
                self._parent_fingerprint
            ):
                raise _Refusal(token)
            _verify_visible_steps(self._steps)
        except (_Refusal, OSError):
            raise _Refusal(token) from None

    def close(self) -> None:
        for fd in reversed(self._fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _validate_directory_stat(observed: os.stat_result, token: str) -> None:
    if (
        not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.geteuid()
        or observed.st_mode & _GROUP_OR_WORLD_WRITE
    ):
        raise _Refusal(token)


class _RootSnapshot:
    """Holds descriptors for the complete absolute chain of a root — from
    the filesystem anchor ``/`` through every ancestor — plus every
    traversed inventory directory, so all reads and rechecks happen
    against captured identities, never re-resolved pathnames.  Restated
    from the reviewed planner; the tests pin behavioral parity."""

    def __init__(self, root: str) -> None:
        self.root = root
        self._descriptors: list[int] = []
        self._anchor_fd = -1
        self._anchor_identity: tuple | None = None
        # (held parent fd, component name, held fd, identity fingerprint)
        self._ancestors: list[tuple[int, str, int, tuple]] = []
        self._root_parent_fd = -1
        self._root_name = ""
        self._root_fd = -1
        self._root_fingerprint: tuple | None = None
        self._directories: dict[tuple[str, ...], tuple[int, tuple]] = {}
        self._files: list[tuple[tuple[str, ...], str, tuple]] = []

    def open_root(self) -> None:
        components = tuple(self.root.split("/")[1:])
        if not components:
            raise _Refusal("root-unsafe")
        try:
            anchor = os.open("/", _DIR_OPEN_FLAGS)
        except OSError:
            raise _Refusal("root-unsafe") from None
        self._descriptors.append(anchor)
        self._anchor_fd = anchor
        self._anchor_identity = _identity(os.fstat(anchor))
        parent = anchor
        last_index = len(components) - 1
        for index, name in enumerate(components):
            try:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except OSError:
                raise _Refusal("root-unsafe") from None
            # A symlink (or anything but a directory) anywhere in the
            # chain, ancestors included, is rejected outright.
            if not stat.S_ISDIR(before.st_mode):
                raise _Refusal("root-unsafe")
            try:
                held = os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent)
            except OSError:
                raise _Refusal("root-unsafe") from None
            self._descriptors.append(held)
            observed = os.fstat(held)
            if index == last_index:
                if _fingerprint(observed) != _fingerprint(before):
                    raise _Refusal("validation-race")
                _validate_directory_stat(observed, "root-unsafe")
                self._root_parent_fd = parent
                self._root_name = name
                self._root_fd = held
                self._root_fingerprint = _fingerprint(observed)
            else:
                if _identity(observed) != _identity(before):
                    raise _Refusal("validation-race")
                self._ancestors.append(
                    (parent, name, held, _identity(observed))
                )
            parent = held

    def _directory_fd(self, key: tuple[str, ...]) -> int:
        descriptor = self._root_fd
        for depth in range(len(key)):
            prefix = key[: depth + 1]
            entry = self._directories.get(prefix)
            if entry is None:
                name = key[depth]
                try:
                    before = os.stat(
                        name, dir_fd=descriptor, follow_symlinks=False
                    )
                except OSError:
                    raise _Refusal("root-unsafe") from None
                _validate_directory_stat(before, "root-unsafe")
                try:
                    child = os.open(name, _DIR_OPEN_FLAGS, dir_fd=descriptor)
                except OSError:
                    raise _Refusal("root-unsafe") from None
                self._descriptors.append(child)
                held = os.fstat(child)
                if _fingerprint(held) != _fingerprint(before):
                    raise _Refusal("validation-race")
                _validate_directory_stat(held, "root-unsafe")
                entry = (child, _fingerprint(held))
                self._directories[prefix] = entry
            descriptor = entry[0]
        return descriptor

    def read_file_with_stat(
        self, name: str, budget: dict[str, int]
    ) -> tuple[bytes, os.stat_result]:
        components = tuple(name.split("/"))
        directory_key = components[:-1]
        leaf = components[-1]
        parent = self._directory_fd(directory_key)
        try:
            before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except OSError as exc:
            token = (
                "file-missing" if exc.errno == errno.ENOENT else "file-unsafe"
            )
            raise _Refusal(token) from None
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_mode & _GROUP_OR_WORLD_WRITE
        ):
            raise _Refusal("file-unsafe")
        if before.st_size > MAX_SOURCE_FILE_BYTES:
            raise _Refusal("file-oversize")
        # The aggregate budget is enforced before the open so no byte
        # beyond the invocation limit is ever read.
        if before.st_size > budget["remaining"]:
            raise _Refusal("total-oversize")
        try:
            descriptor = os.open(leaf, _FILE_OPEN_FLAGS, dir_fd=parent)
        except OSError as exc:
            token = (
                "file-missing" if exc.errno == errno.ENOENT else "file-unsafe"
            )
            raise _Refusal(token) from None
        try:
            opened = os.fstat(descriptor)
            if _fingerprint(opened) != _fingerprint(before):
                raise _Refusal("validation-race")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining > 0:
                chunk = os.read(descriptor, min(remaining, _READ_CHUNK_BYTES))
                if not chunk:
                    raise _Refusal("validation-race")
                chunks.append(chunk)
                remaining -= len(chunk)
            # No trailing EOF probe: it could return bytes appended after
            # the budget check, pushing aggregate reads past the cap.
            # Growth or any other mutation is caught by the immediate
            # post-read fstat below and by the full held-vs-visible
            # recheck.
            after = os.fstat(descriptor)
            if _fingerprint(after) != _fingerprint(before):
                raise _Refusal("validation-race")
        finally:
            os.close(descriptor)
        payload = b"".join(chunks)
        budget["remaining"] -= len(payload)
        self._files.append((directory_key, leaf, _fingerprint(before)))
        return payload, before

    def recheck(self) -> None:
        try:
            if _identity(os.fstat(self._anchor_fd)) != self._anchor_identity:
                raise _Refusal("validation-race")
            for parent, name, held, identity in self._ancestors:
                if _identity(os.fstat(held)) != identity:
                    raise _Refusal("validation-race")
                visible = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(visible.st_mode)
                    or _identity(visible) != identity
                ):
                    raise _Refusal("validation-race")
            held_root = os.fstat(self._root_fd)
            visible_root = os.stat(
                self._root_name,
                dir_fd=self._root_parent_fd,
                follow_symlinks=False,
            )
        except OSError:
            raise _Refusal("validation-race") from None
        if (
            _fingerprint(held_root) != self._root_fingerprint
            or _fingerprint(visible_root) != self._root_fingerprint
        ):
            raise _Refusal("validation-race")
        for key, (descriptor, fingerprint) in self._directories.items():
            parent = (
                self._root_fd
                if len(key) == 1
                else self._directories[key[:-1]][0]
            )
            try:
                held = os.fstat(descriptor)
                visible = os.stat(
                    key[-1], dir_fd=parent, follow_symlinks=False
                )
            except OSError:
                raise _Refusal("validation-race") from None
            if (
                _fingerprint(held) != fingerprint
                or _fingerprint(visible) != fingerprint
            ):
                raise _Refusal("validation-race")
        for directory_key, leaf, fingerprint in self._files:
            parent = (
                self._root_fd
                if not directory_key
                else self._directories[directory_key][0]
            )
            try:
                visible = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            except OSError:
                raise _Refusal("validation-race") from None
            if _fingerprint(visible) != fingerprint:
                raise _Refusal("validation-race")

    def close(self) -> None:
        while self._descriptors:
            descriptor = self._descriptors.pop()
            try:
                os.close(descriptor)
            except OSError:
                pass


def _extract_manifest(source: bytes) -> tuple[str, tuple[str, ...] | None]:
    """Return ("ok", tuple) only when the source binds BUILD_SOURCE_MANIFEST
    exactly once, at top level, to a literal tuple of strings.  Any further
    store, delete, rebind, mutation, aliasing import, or shadowing binding —
    nested scopes included — is ambiguous.  Restated from the reviewed
    planner; parsing never executes the candidate."""
    # Bound work before parsing: a hostile candidate could otherwise submit
    # pathological source engineered against the parser.  The token ceiling
    # streams via tokenize and aborts early, so no huge AST is ever built.
    # Decode with the one fixed admitted codec before tokenization: the
    # bytes-oriented tokenizer would honor a candidate PEP 263 cookie by
    # consulting process-global codec hooks.  Cookies fail closed before
    # fixed UTF-8 decoding; ``generate_tokens`` then consumes only a string.
    if len(source) > MAX_MANIFEST_SOURCE_BYTES:
        return ("complexity", None)
    if source.startswith(b"\xef\xbb\xbf"):
        return ("missing", None)
    if any(
        _PYTHON_ENCODING_COOKIE_RE.match(line)
        for line in source.split(b"\n", 2)[:2]
    ):
        return ("missing", None)
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError:
        return ("missing", None)
    # The previous bytes tokenizer emitted one ENCODING token.  Seed the
    # count at one so the reviewed ceiling is byte-for-byte behaviorally
    # unchanged for all ordinary UTF-8 source.
    token_count = 1
    try:
        for _ in tokenize.generate_tokens(io.StringIO(text).readline):
            token_count += 1
            if token_count > MAX_MANIFEST_SOURCE_TOKENS:
                return ("complexity", None)
    except (
        tokenize.TokenError,
        IndentationError,
        SyntaxError,
        ValueError,
        UnicodeDecodeError,
    ):
        return ("missing", None)
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, UnicodeDecodeError):
        return ("missing", None)

    def _touches_manifest(node: ast.AST) -> bool:
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            if (
                isinstance(node, ast.Attribute)
                and node.attr == _MANIFEST_NAME
            ):
                return True
            node = node.value
        return isinstance(node, ast.Name) and node.id == _MANIFEST_NAME

    type_parameter_nodes = tuple(
        node_type
        for node_type in (
            getattr(ast, "TypeVar", None),
            getattr(ast, "ParamSpec", None),
            getattr(ast, "TypeVarTuple", None),
        )
        if isinstance(node_type, type)
    )
    bindings = 0
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id == _MANIFEST_NAME
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            bindings += 1
        elif isinstance(node, ast.alias) and _MANIFEST_NAME in (
            node.name.split(".")[0],
            node.asname,
        ):
            return ("ambiguous", None)
        elif (
            isinstance(node, (ast.Global, ast.Nonlocal))
            and _MANIFEST_NAME in node.names
        ):
            return ("ambiguous", None)
        elif isinstance(node, ast.ExceptHandler) and node.name == _MANIFEST_NAME:
            return ("ambiguous", None)
        elif isinstance(node, ast.arg) and node.arg == _MANIFEST_NAME:
            return ("ambiguous", None)
        elif (
            isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
            and node.name == _MANIFEST_NAME
        ):
            return ("ambiguous", None)
        elif (
            isinstance(node, (ast.MatchAs, ast.MatchStar))
            and node.name == _MANIFEST_NAME
        ):
            return ("ambiguous", None)
        elif isinstance(node, ast.MatchMapping) and node.rest == _MANIFEST_NAME:
            return ("ambiguous", None)
        elif isinstance(node, ast.ImportFrom) and any(
            alias.name == "*" for alias in node.names
        ):
            return ("ambiguous", None)
        elif (
            isinstance(node, (ast.Attribute, ast.Subscript))
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and _touches_manifest(node)
        ):
            return ("ambiguous", None)
        elif (
            type_parameter_nodes
            and isinstance(node, type_parameter_nodes)
            and node.name == _MANIFEST_NAME
        ):
            return ("ambiguous", None)
        elif (
            isinstance(node, ast.Name)
            and node.id in _DYNAMIC_NAMESPACE_BUILTINS
        ):
            return ("ambiguous", None)
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and _MANIFEST_NAME in node.value
        ):
            # Any string mention of the manifest name outside its literal
            # binding (e.g. a globals()/setattr key) is ambiguous.
            return ("ambiguous", None)
    if bindings == 0:
        return ("missing", None)
    if bindings > 1:
        return ("ambiguous", None)
    assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == _MANIFEST_NAME
    ]
    if len(assignments) != 1:
        # The single binding is not a plain top-level assignment (AnnAssign,
        # AugAssign, walrus, loop target, tuple unpack, nested scope, ...).
        return ("ambiguous", None)
    value = assignments[0].value
    if not isinstance(value, ast.Tuple):
        return ("missing", None)
    entries: list[str] = []
    for element in value.elts:
        if not isinstance(element, ast.Constant) or not isinstance(
            element.value, str
        ):
            return ("missing", None)
        entries.append(element.value)
    return ("ok", tuple(entries))


def _product_directory_map() -> dict[
    tuple[str, ...], tuple[frozenset[str], frozenset[str]]
]:
    """Recursive closure of every inventoried directory: for each directory
    key, the exact expected file leaves and expected subdirectory names.
    Any other entry found there is an anomaly, whatever its suffix.
    Restated from the reviewed planner."""
    files: dict[tuple[str, ...], set[str]] = {(): set()}
    subdirs: dict[tuple[str, ...], set[str]] = {(): set()}
    for _, _, path in PRODUCT_INVENTORY:
        parts = tuple(path.split("/"))
        for depth in range(len(parts) - 1):
            parent = parts[:depth]
            files.setdefault(parent, set())
            subdirs.setdefault(parent, set()).add(parts[depth])
            child = parts[: depth + 1]
            files.setdefault(child, set())
            subdirs.setdefault(child, set())
        files.setdefault(parts[:-1], set()).add(parts[-1])
        subdirs.setdefault(parts[:-1], set())
    return {
        key: (frozenset(files[key]), frozenset(subdirs[key]))
        for key in files
    }


def _scan_product_directory(
    snapshot: "_RootSnapshot",
    key: tuple[str, ...],
    expected_files: frozenset[str],
    expected_subdirs: frozenset[str],
    allow_root_state: bool,
    name_budget: dict[str, int],
    ignored_registry: list[tuple[tuple[str, ...], str, str, tuple]],
) -> None:
    """Closed-tree scan of one inventoried directory: every entry must be
    an expected file, an expected subdirectory, or (current root only) an
    exactly named, safety-screened ignored entry recorded for the final
    recheck.  Everything else — extra files or directories,
    ``sitecustomize.py``, casefold collisions, symlinks, hardlinks, FIFOs,
    and every other special file — fails closed.  Restated from the
    reviewed planner."""
    descriptor = snapshot._directory_fd(key)
    names: list[str] = []
    folded: set[str] = set()
    try:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                # Incremental bounds: the entry count, per-name bytes, and
                # aggregate scanned-name budget are all enforced before the
                # name is kept, so a hostile directory cannot balloon
                # memory.
                if len(names) >= MAX_PRODUCT_DIRECTORY_ENTRIES:
                    raise _Refusal("directory-oversize")
                name = entry.name
                if (
                    not isinstance(name, str)
                    or not name
                    or "\x00" in name
                    or not name.isascii()
                ):
                    # Only ASCII entry names are supported: Unicode
                    # normalization collisions cannot exist within ASCII
                    # and the remaining aliasing risk (case) is rejected
                    # below.
                    raise _Refusal("name-unsafe")
                encoded_length = len(name.encode("ascii"))
                if encoded_length > MAX_PRODUCT_NAME_BYTES:
                    raise _Refusal("name-oversize")
                if encoded_length > name_budget["remaining"]:
                    raise _Refusal("scan-oversize")
                name_budget["remaining"] -= encoded_length
                fold = name.casefold()
                if fold in folded:
                    raise _Refusal("name-collision")
                folded.add(fold)
                names.append(name)
    except OSError:
        raise _Refusal("validation-race") from None
    listing = frozenset(names)
    if not expected_files <= listing or not expected_subdirs <= listing:
        raise _Refusal("file-missing")
    # Expected files are fully screened by the read phase and expected
    # subdirectories by the held-descriptor open; only the residue is
    # classified here, and everything unknown fails closed.
    for name in sorted(listing - expected_files - expected_subdirs):
        try:
            observed = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            raise _Refusal("validation-race") from None
        mode = observed.st_mode
        if not key and name in _PRODUCT_VCS_METADATA_NAMES:
            if stat.S_ISDIR(mode):
                if (
                    observed.st_uid != os.geteuid()
                    or mode & _GROUP_OR_WORLD_WRITE
                ):
                    raise _Refusal("root-unsafe")
                ignored_registry.append((key, name, "dir", _identity(observed)))
                continue
            if stat.S_ISREG(mode):
                if (
                    observed.st_nlink != 1
                    or observed.st_uid != os.geteuid()
                    or mode & _GROUP_OR_WORLD_WRITE
                ):
                    raise _Refusal("file-unsafe")
                ignored_registry.append(
                    (key, name, "file", _fingerprint(observed))
                )
                continue
            raise _Refusal("special-file")
        if (
            allow_root_state
            and not key
            and name in PRODUCT_CURRENT_ROOT_IGNORED_DIRS
            and stat.S_ISDIR(mode)
        ):
            # Root-local live-state directories: tolerated only as safe
            # real directories owned by the invoking user, never descended
            # into.
            if observed.st_uid != os.geteuid() or mode & _GROUP_OR_WORLD_WRITE:
                raise _Refusal("root-unsafe")
            ignored_registry.append((key, name, "dir", _identity(observed)))
            continue
        if (
            allow_root_state
            and not key
            and (
                name in PRODUCT_CURRENT_ROOT_IGNORED_FILES
                or _PRODUCT_CURRENT_BACKUP_RE.fullmatch(name) is not None
            )
        ):
            # Host configuration artifacts: tolerated only as safe regular
            # files owned by the invoking user, and never opened.
            if stat.S_ISREG(mode):
                if (
                    observed.st_nlink != 1
                    or observed.st_uid != os.geteuid()
                    or mode & _GROUP_OR_WORLD_WRITE
                ):
                    raise _Refusal("file-unsafe")
                ignored_registry.append(
                    (key, name, "file", _fingerprint(observed))
                )
                continue
            if stat.S_ISDIR(mode):
                raise _Refusal("unexpected-entry")
            raise _Refusal("special-file")
        if (
            allow_root_state
            and key
            and "/".join(key + (name,)) in PRODUCT_CURRENT_CACHE_DIR_PATHS
            and stat.S_ISDIR(mode)
        ):
            # Nested bytecode caches: exact inventory-relative paths, safe
            # real directories only, never descended into.
            if observed.st_uid != os.geteuid() or mode & _GROUP_OR_WORLD_WRITE:
                raise _Refusal("root-unsafe")
            ignored_registry.append((key, name, "dir", _identity(observed)))
            continue
        if not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
            raise _Refusal("special-file")
        raise _Refusal("unexpected-entry")


def _recheck_ignored_entries(
    snapshot: "_RootSnapshot",
    ignored_registry: list[tuple[tuple[str, ...], str, str, tuple]],
) -> None:
    """Final held-descriptor recheck of every entry the scan ignored.

    Regular ignored files must still match their full scan-time fingerprint
    (device, inode, owner, link count, mode, size, times).  Ignored
    directories may drift in content and times — live state keeps moving —
    but must keep the same device, inode, and type and must still be owned
    by the invoking user with no group/world write.  Restated from the
    reviewed planner."""
    for key, name, kind, recorded in ignored_registry:
        descriptor = snapshot._directory_fd(key)
        try:
            observed = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            raise _Refusal("validation-race") from None
        if kind == "file":
            if _fingerprint(observed) != recorded:
                raise _Refusal("validation-race")
            continue
        if _identity(observed) != recorded:
            raise _Refusal("validation-race")
        if (
            observed.st_uid != os.geteuid()
            or observed.st_mode & _GROUP_OR_WORLD_WRITE
        ):
            raise _Refusal("root-unsafe")


def _validate_static_vocabulary() -> None:
    """Internal consistency of the reviewed byte-pinned vocabulary: the
    inventory is a closed set of unique safe paths, the trusted manifest
    and every surface file set are subsets of it, the dependencies
    component is present, and the surface map covers exactly the thirteen
    closed surface names."""
    token = "static-vocabulary-invalid"
    if (
        not isinstance(PRODUCT_INVENTORY, tuple)
        or not PRODUCT_INVENTORY
        or len(PRODUCT_INVENTORY) > MAX_PRODUCT_INVENTORY_ENTRIES
    ):
        raise _Refusal(token)
    seen_paths: set[str] = set()
    components: set[str] = set()
    for entry in PRODUCT_INVENTORY:
        if (
            not isinstance(entry, tuple)
            or len(entry) != 3
            or not all(
                isinstance(field, str) and field and field.isascii()
                for field in entry
            )
        ):
            raise _Refusal(token)
        component, role, path = entry
        if any("\x00" in field or "\\" in field for field in entry):
            raise _Refusal(token)
        if len(path.encode("ascii")) > MAX_PRODUCT_PATH_BYTES:
            raise _Refusal(token)
        parts = path.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise _Refusal(token)
        if any(
            len(part.encode("ascii")) > MAX_PRODUCT_NAME_BYTES
            for part in parts
        ):
            raise _Refusal(token)
        if (
            parts[0] in PRODUCT_CURRENT_ROOT_IGNORED_DIRS
            or parts[0] in _PRODUCT_VCS_METADATA_NAMES
            or parts[0] in PRODUCT_CURRENT_ROOT_IGNORED_FILES
            or _PRODUCT_CURRENT_BACKUP_RE.fullmatch(parts[0]) is not None
        ):
            raise _Refusal(token)
        if any(part in _PRODUCT_CACHE_BASENAMES for part in parts):
            raise _Refusal(token)
        if any(
            path == cache or path.startswith(cache + "/")
            for cache in PRODUCT_CURRENT_CACHE_DIR_PATHS
        ):
            raise _Refusal(token)
        if path in seen_paths:
            raise _Refusal(token)
        seen_paths.add(path)
        components.add(component)
    if DEPENDENCY_COMPONENT not in components:
        raise _Refusal(token)
    for files, subdirs in _product_directory_map().values():
        if files & subdirs:
            raise _Refusal(token)
        folded: set[str] = set()
        for name in list(files) + list(subdirs):
            fold = name.casefold()
            if fold in folded:
                raise _Refusal(token)
            folded.add(fold)
    if (
        not isinstance(TRUSTED_MANIFEST, tuple)
        or not TRUSTED_MANIFEST
        or len(set(TRUSTED_MANIFEST)) != len(TRUSTED_MANIFEST)
        or "core_service.py" not in TRUSTED_MANIFEST
        or not set(TRUSTED_MANIFEST) <= seen_paths
    ):
        raise _Refusal(token)
    if (
        not isinstance(SURFACE_FILES, dict)
        or set(SURFACE_FILES) != set(COMPATIBILITY_SURFACES)
        or list(COMPATIBILITY_SURFACES)
        != sorted(set(COMPATIBILITY_SURFACES))
    ):
        raise _Refusal(token)
    for files in SURFACE_FILES.values():
        if (
            not isinstance(files, tuple)
            or not files
            or len(set(files)) != len(files)
            or not set(files) <= seen_paths
        ):
            raise _Refusal(token)


def _product_digest(
    domain: str, records: list[tuple[str, str, str, str, int, str]]
) -> str:
    """Full SHA-256 over a domain-separated canonical payload binding the
    inventory schema and, per record, component, role, path, the exact
    permission mode, size, and content digest.  Byte-identical to the
    reviewed planner's digest; the tests pin parity."""
    hasher = hashlib.sha256()
    hasher.update(
        "\x00".join((domain, PRODUCT_SCHEMA, str(len(records)))).encode(
            "ascii"
        )
        + b"\n"
    )
    for component, role, path, mode, size, digest in sorted(records):
        hasher.update(
            "\x00".join(
                (component, role, path, mode, str(size), digest)
            ).encode("ascii")
            + b"\n"
        )
    return hasher.hexdigest()


def _inventory_policy_id() -> str:
    """Domain-separated SHA-256 over the canonical (sorted-key, compact,
    ASCII) JSON encoding of the closed inventory policy; byte-identical to
    the reviewed planner's identifier."""
    payload = json.dumps(
        {
            "schema": INVENTORY_POLICY_SCHEMA,
            "product_schema": PRODUCT_SCHEMA,
            "record_fields": list(INVENTORY_POLICY_RECORD_FIELDS),
            "candidate_layout": INVENTORY_POLICY_CANDIDATE_LAYOUT,
            "entries": [list(entry) for entry in sorted(PRODUCT_INVENTORY)],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    hasher = hashlib.sha256()
    hasher.update(_INVENTORY_POLICY_ID_DOMAIN.encode("ascii"))
    hasher.update(payload.encode("ascii"))
    return "inventory-policy-" + hasher.hexdigest()


def _capture_root_observation(
    snapshot: _RootSnapshot,
    budget: dict[str, int],
    manifest_budget: dict[str, int],
    name_budget: dict[str, int],
    allow_root_state: bool,
    ignored_registry: list[tuple[tuple[str, ...], str, str, tuple]],
) -> dict:
    """Open the root chain, read every inventoried file exactly once into
    one shared payload-plus-stat cache, then scan the complete closed
    directory tree; derive every identity from those same held bytes.
    Logical product bytes are charged against the caller's shared product
    budget and cached TRUSTED_MANIFEST payload lengths against the
    caller's independent manifest budget — both spanning both roots.  The
    caller rechecks ignored entries and the snapshot only after every
    derivation of both roots is complete."""
    snapshot.open_root()
    payload_by_path: dict[str, bytes] = {}
    records: list[tuple[str, str, str, str, int, str]] = []
    for component, role, path in PRODUCT_INVENTORY:
        payload, observed = snapshot.read_file_with_stat(path, budget)
        payload_by_path[path] = payload
        records.append(
            (
                component,
                role,
                path,
                format(stat.S_IMODE(observed.st_mode), "04o"),
                observed.st_size,
                hashlib.sha256(payload).hexdigest(),
            )
        )
    directory_map = _product_directory_map()
    for key in sorted(directory_map):
        expected_files, expected_subdirs = directory_map[key]
        _scan_product_directory(
            snapshot,
            key,
            expected_files,
            expected_subdirs,
            allow_root_state,
            name_budget,
            ignored_registry,
        )
    build_digest = hashlib.sha256()
    for name in TRUSTED_MANIFEST:
        payload = payload_by_path[name]
        # Cached manifest lengths are charged against the independent
        # manifest budget before the bytes are consumed by the digest.
        if len(payload) > manifest_budget["remaining"]:
            raise _Refusal("manifest-total-oversize")
        manifest_budget["remaining"] -= len(payload)
        encoded_name = name.encode("utf-8")
        build_digest.update(len(encoded_name).to_bytes(4, "big"))
        build_digest.update(encoded_name)
        build_digest.update(len(payload).to_bytes(8, "big"))
        build_digest.update(payload)
    status, literal = _extract_manifest(payload_by_path["core_service.py"])
    if status == "complexity":
        raise _Refusal("manifest-complexity")
    if status == "missing":
        raise _Refusal("manifest-missing")
    if status == "ambiguous" or literal != TRUSTED_MANIFEST:
        raise _Refusal("manifest-drift")
    record_by_path = {record[2]: record for record in records}
    dependency_rows = [
        record for record in records if record[0] == DEPENDENCY_COMPONENT
    ]
    surface_records = {
        surface: tuple(
            (record[2], record[3], record[4], record[5])
            for record in (
                record_by_path[path] for path in sorted(SURFACE_FILES[surface])
            )
        )
        for surface in COMPATIBILITY_SURFACES
    }
    return {
        "source_build_id": "source-" + build_digest.hexdigest()[:24],
        "product_id": "product-"
        + _product_digest(_PRODUCT_ID_DOMAIN, records),
        "dependency_component_id": "component-"
        + _product_digest(_PRODUCT_COMPONENT_ID_DOMAIN, dependency_rows),
        "surface_records": surface_records,
    }


def _surface_digests(observation: dict) -> dict[str, str]:
    """Independent per-root, per-surface domain-separated digests over the
    surface name, its exact-build-only mode, its closed file set, and the
    exact stable records (path, mode, size, sha256) of that one root.  The
    record schema is identical for both roots, so two digests are equal
    exactly when the underlying surface bytes and stable metadata are —
    the equality the exact-build profile requires surface by surface."""
    digests: dict[str, str] = {}
    for surface in COMPATIBILITY_SURFACES:
        payload = canonical_bytes(
            {
                "surface": surface,
                "mode": SURFACE_MODE,
                "files": sorted(SURFACE_FILES[surface]),
                "records": [
                    list(record)
                    for record in observation["surface_records"][surface]
                ],
            }
        )
        digests[surface] = hashlib.sha256(
            _SURFACE_DIGEST_DOMAIN + payload
        ).hexdigest()
    return digests


def _surfaces_digest(
    digests: dict[str, str], dependency_component_id: str
) -> str:
    """One global domain-separated digest over a canonical closed
    projection: the compatibility observation schema, the exact-build-only
    profile plus its integer version, the installed-layout contract schema
    and mode, the host-independent layout contract id, the one unchanged
    dependency component id, and the common thirteen-digest surface map.
    No host path or host layout id is ever hashed."""
    payload = canonical_bytes(
        {
            "compatibility_observation_schema": (
                COMPATIBILITY_OBSERVATION_SCHEMA
            ),
            "profile": SURFACE_MODE,
            "profile_version": PROFILE_VERSION,
            "layout_schema": LAYOUT_SCHEMA,
            "layout_mode": EXPECTED_LAYOUT_CONTRACT_MODE,
            "layout_contract_id": EXPECTED_LAYOUT_CONTRACT_ID,
            "dependency_component_id": dependency_component_id,
            "surface_digests": dict(digests),
        }
    )
    return hashlib.sha256(_SURFACES_DIGEST_DOMAIN + payload).hexdigest()


def _recheck_time_windows(
    now: int,
    bundle: dict,
    release_delegation: dict,
    compatibility_delegation: dict,
    envelope: dict,
    ticket: dict,
    floor: dict,
) -> None:
    """Second wall-clock evaluation after the source scan: expiry can
    arrive while megabytes are read, and a claim that lapsed mid-scan must
    never surface as verified.  Every window proven open at the first
    instant must still be open at the second."""
    if now < bundle["issued_at"]:
        raise _Blocked("bundle-not-yet-valid")
    if now >= bundle["expires_at"]:
        raise _Blocked("bundle-expired")
    for delegation in (release_delegation, compatibility_delegation):
        if now < delegation["not_before"]:
            raise _Blocked("delegation-not-yet-valid")
        if now >= delegation["not_after"]:
            raise _Blocked("delegation-expired")
    if now < envelope["issued_at"]:
        raise _Blocked("envelope-not-yet-valid")
    if now >= envelope["expires_at"]:
        raise _Blocked("envelope-expired")
    if now < ticket["issued_at"]:
        raise _Blocked("ticket-not-yet-valid")
    if now >= ticket["expires_at"]:
        raise _Blocked("ticket-expired")
    if now < floor["committed_at"]:
        raise _Blocked("clock-before-floor")


def _check_observations(
    ticket: dict,
    envelope: dict,
    installed: dict,
    current_observation: dict,
    candidate_observation: dict,
    current_digests: dict[str, str],
    candidate_digests: dict[str, str],
    policy_id: str,
) -> str:
    """Exact-build equality first, then binding of the signed claims to
    the observed source bytes.  Every one of the thirteen independently
    derived surface digests must be equal between the roots, and the one
    dependency component identity must be unchanged — otherwise the pair
    is not an exact build and no ticket comparison happens at all.  Then
    the verifier's own inventory policy, the floor's installed identity,
    both source build ids, both product ids, the dependency component id,
    the common thirteen-digest map, and the global digest over the
    canonical closed projection are each checked by exact equality, or the
    ticket claims nothing about these roots.  Returns the common global
    digest."""
    if policy_id != envelope["inventory_policy_id"]:
        raise _Blocked("policy-mismatch")
    if installed["inventory_policy_id"] != policy_id:
        raise _Blocked("installed-policy-mismatch")
    if installed["product_id"] != current_observation["product_id"]:
        # The current root must be the very product the floor records as
        # installed; anything else is a claim about someone else's disk.
        raise _Blocked("installed-product-mismatch")
    if (
        current_observation["dependency_component_id"]
        != candidate_observation["dependency_component_id"]
    ):
        # Dependencies are a separately signed compatibility premise.
        # Check them before the overlapping platform-runtime surface so a
        # dependency drift has one stable, specific refusal token.
        raise _Blocked("dependency-changed")
    for surface in COMPATIBILITY_SURFACES:
        if current_digests[surface] != candidate_digests[surface]:
            raise _Blocked("surface-changed")
    dependency_component_id = current_observation["dependency_component_id"]
    if (
        ticket["current_source_build_id"]
        != current_observation["source_build_id"]
        or ticket["candidate_source_build_id"]
        != candidate_observation["source_build_id"]
    ):
        raise _Blocked("source-build-mismatch")
    if (
        ticket["current_product_id"] != current_observation["product_id"]
        or ticket["candidate_product_id"]
        != candidate_observation["product_id"]
    ):
        raise _Blocked("product-identity-mismatch")
    if (
        ticket["current_dependency_component_id"] != dependency_component_id
        or ticket["candidate_dependency_component_id"]
        != dependency_component_id
    ):
        raise _Blocked("dependency-mismatch")
    for surface in COMPATIBILITY_SURFACES:
        if ticket["surface_digests"][surface] != current_digests[surface]:
            raise _Blocked("surface-mismatch")
    surfaces_digest = _surfaces_digest(
        current_digests, dependency_component_id
    )
    if ticket["surfaces_digest"] != surfaces_digest:
        raise _Blocked("surfaces-digest-mismatch")
    return surfaces_digest


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
    current_source_build_id=None,
    candidate_source_build_id=None,
    current_product_id=None,
    candidate_product_id=None,
    current_dependency_component_id=None,
    candidate_dependency_component_id=None,
    bundle_sha256=None,
    envelope_sha256=None,
    ticket_sha256=None,
    surfaces_digest=None,
    layout_contract_id=None,
    floor_present=None,
) -> dict:
    return {
        "schema": RESULT_SCHEMA,
        "mode": RESULT_MODE,
        "command": command,
        "status": status,
        # Hard non-claims: this verifier never applies, activates,
        # migrates, downgrades, checks host evidence, or confers live
        # authority — under any status, including verified.
        "apply_supported": False,
        "apply_performed": False,
        "activation_authorized": False,
        "migration_authorized": False,
        "downgrade_authorized": False,
        "host_evidence_verified": False,
        "live_authority": False,
        "channel": channel,
        "version": version,
        "sequence": sequence,
        "trust_generation": trust_generation,
        "source_sha": source_sha,
        "inventory_policy_id": inventory_policy_id,
        "current_source_build_id": current_source_build_id,
        "candidate_source_build_id": candidate_source_build_id,
        "current_product_id": current_product_id,
        "candidate_product_id": candidate_product_id,
        "current_dependency_component_id": current_dependency_component_id,
        "candidate_dependency_component_id": candidate_dependency_component_id,
        "bundle_sha256": bundle_sha256,
        "envelope_sha256": envelope_sha256,
        "ticket_sha256": ticket_sha256,
        "surfaces_digest": surfaces_digest,
        "layout_contract_id": layout_contract_id,
        "surface_mode": SURFACE_MODE,
        "surface_count": len(COMPATIBILITY_SURFACES),
        "floor_present": floor_present,
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


def compatibility_exit_code(result: dict) -> int:
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
        except (_Refusal, _Blocked):
            raise
        except Exception:
            raise _Refusal("internal-error")
    except _Blocked as blocked:
        return _build_result(command, "blocked:" + blocked.token)
    except _Refusal as refusal:
        return _build_result(command, "unsupported:" + refusal.token)


def _require_supported() -> None:
    if not _PLATFORM_SUPPORTED:
        raise _Refusal("platform-unsupported")
    if _ED25519 is None:
        raise _Refusal("crypto-unavailable")


def verify_compatibility_ticket(
    root_path,
    bundle_path,
    envelope_path,
    ticket_path,
    floor_path,
    current_root,
    candidate_root,
) -> dict:
    """Read-only source-backed verification of one build-compatibility
    ticket against the trust chain, the committed floor, and the exact
    bytes of both roots; after a ``python -B`` API import, this logic never
    writes filesystem content and never imports or executes anything from
    either root.  JSON returned here may be emitted on stdout by the CLI."""
    held_resources: list[_RootSnapshot | _HeldFloorDocument] = []

    def work() -> dict:
        _require_supported()
        _validate_static_vocabulary()
        root_file = _validate_path_argument(root_path)
        bundle_file = _validate_path_argument(bundle_path)
        envelope_file = _validate_path_argument(envelope_path)
        ticket_file = _validate_path_argument(ticket_path)
        floor_file = _validate_path_argument(floor_path)
        current_dir = _validate_path_argument(current_root)
        candidate_dir = _validate_path_argument(candidate_root)

        first_now = _now()
        root_bytes = _read_safe_document(root_file)
        bundle_bytes = _read_safe_document(bundle_file)
        envelope_bytes = _read_safe_document(envelope_file)
        ticket_bytes = _read_safe_document(ticket_file)
        floor_document = _HeldFloorDocument(floor_file)
        held_resources.append(floor_document)
        floor_bytes = floor_document.open_and_read(owner_only=True)
        if floor_bytes is None:
            # No committed floor means no accepted trust: a ticket cannot
            # bootstrap the trust it needs to be verified under.
            raise _Blocked("trust-not-accepted")

        root_document = parse_canonical_document(root_bytes)
        root_key_id, root_public_key = _validate_root_document(root_document)
        bundle = parse_canonical_document(bundle_bytes)
        _validate_bundle_v2_syntax(bundle)
        _verify_bundle_v2(bundle, root_key_id, root_public_key, first_now)
        bundle_sha256 = hashlib.sha256(bundle_bytes).hexdigest()
        envelope = parse_canonical_document(envelope_bytes)
        _validate_envelope_syntax(envelope)
        release_delegation = _verify_envelope(
            envelope, bundle, root_key_id, first_now
        )
        envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
        ticket = parse_canonical_document(ticket_bytes)
        _validate_ticket_syntax(ticket)
        compatibility_delegation = _verify_ticket(
            ticket, bundle, root_key_id, first_now
        )
        ticket_sha256 = hashlib.sha256(ticket_bytes).hexdigest()
        _check_lifetime_containment(
            envelope, bundle, release_delegation, compatibility_delegation
        )
        _check_lifetime_containment(
            ticket, bundle, release_delegation, compatibility_delegation
        )
        floor = parse_canonical_document(floor_bytes)
        _validate_floor_syntax(floor)
        _check_floor_trust(
            floor, root_key_id, bundle, bundle_sha256, first_now
        )
        installed = _check_floor_release(floor, envelope)
        _check_ticket_binding(ticket, envelope, bundle_sha256, envelope_sha256)

        # Source scan: one snapshot, one read per inventoried file, and
        # one closed-tree directory scan per root, all identities derived
        # from the same held bytes.  One logical product-byte budget and
        # one independent manifest-byte budget span both roots, as does
        # the scanned-name budget; only the current root may carry the
        # exact safe ignored root entries, each recorded for the final
        # recheck.
        product_budget = {"remaining": MAX_PRODUCT_TOTAL_BYTES}
        manifest_budget = {"remaining": MAX_TOTAL_MANIFEST_BYTES}
        name_budget = {"remaining": MAX_PRODUCT_SCANNED_NAME_BYTES}
        current_ignored: list[tuple[tuple[str, ...], str, str, tuple]] = []
        candidate_ignored: list[tuple[tuple[str, ...], str, str, tuple]] = []
        current_snapshot = _RootSnapshot(current_dir)
        held_resources.append(current_snapshot)
        current_observation = _capture_root_observation(
            current_snapshot,
            product_budget,
            manifest_budget,
            name_budget,
            True,
            current_ignored,
        )
        candidate_snapshot = _RootSnapshot(candidate_dir)
        held_resources.append(candidate_snapshot)
        candidate_observation = _capture_root_observation(
            candidate_snapshot,
            product_budget,
            manifest_budget,
            name_budget,
            False,
            candidate_ignored,
        )
        current_digests = _surface_digests(current_observation)
        candidate_digests = _surface_digests(candidate_observation)
        policy_id = _inventory_policy_id()

        # Post-scan closure, in order after all derivation: every ignored
        # current-root entry (and any candidate-root VCS metadata) must
        # still match its scan-time identity, both snapshots must still
        # hold exactly what was read, the floor must not have moved by a
        # single byte, and every trust window must still be open at a
        # fresh clock reading no earlier than the first — so neither a
        # race nor a mid-scan revocation commit nor a mid-scan expiry nor
        # a clock step can yield verified.
        _recheck_ignored_entries(current_snapshot, current_ignored)
        _recheck_ignored_entries(candidate_snapshot, candidate_ignored)
        current_snapshot.recheck()
        candidate_snapshot.recheck()
        floor_document.recheck_bytes(floor_bytes)
        final_now = _now()
        if final_now < first_now:
            raise _Refusal("clock-regression")
        _recheck_time_windows(
            final_now,
            bundle,
            release_delegation,
            compatibility_delegation,
            envelope,
            ticket,
            floor,
        )

        surfaces_digest = _check_observations(
            ticket,
            envelope,
            installed,
            current_observation,
            candidate_observation,
            current_digests,
            candidate_digests,
            policy_id,
        )

        return _build_result(
            COMMAND_VERIFY_TICKET,
            STATUS_VERIFIED,
            channel=envelope["channel"],
            version=envelope["version"],
            sequence=envelope["sequence"],
            trust_generation=bundle["generation"],
            source_sha=envelope["source_sha"],
            inventory_policy_id=policy_id,
            current_source_build_id=current_observation["source_build_id"],
            candidate_source_build_id=candidate_observation[
                "source_build_id"
            ],
            current_product_id=current_observation["product_id"],
            candidate_product_id=candidate_observation["product_id"],
            current_dependency_component_id=current_observation[
                "dependency_component_id"
            ],
            candidate_dependency_component_id=candidate_observation[
                "dependency_component_id"
            ],
            bundle_sha256=bundle_sha256,
            envelope_sha256=envelope_sha256,
            ticket_sha256=ticket_sha256,
            surfaces_digest=surfaces_digest,
            layout_contract_id=EXPECTED_LAYOUT_CONTRACT_ID,
            floor_present=True,
        )

    try:
        return _guard(COMMAND_VERIFY_TICKET, work)
    finally:
        for resource in held_resources:
            resource.close()


class _CompatibilityArgumentParser(argparse.ArgumentParser):
    """Rejected command lines must yield the deterministic unsupported JSON
    contract on stdout, never argparse usage text on stderr.  Help output
    is untouched."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise _CliArgumentError()


def _emit(result: dict) -> int:
    sys.stdout.write(render_result(result) + "\n")
    return compatibility_exit_code(result)


_VERIFIER_NONCLAIM_HELP = (
    "Source-backed exact-build compatibility verification over local "
    "canonical documents and two dormant source roots; strictly "
    "read-only, never imports or executes candidate code, never mutates "
    "the floor, and in this documented -B invocation never writes "
    "filesystem content (JSON is emitted on stdout), and never accesses "
    "live-state or recovery content "
    "(exact safe-listed current-root live-state entries receive bounded "
    "no-follow metadata screening only).  A verified result is a dormant "
    "review artifact only: it authorizes no apply, activation, "
    "migration, or downgrade."
)


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:]) if argv is None else list(argv)
    parser = _CompatibilityArgumentParser(
        prog="release_compatibility",
        allow_abbrev=False,
        description=_VERIFIER_NONCLAIM_HELP,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser(
        COMMAND_VERIFY_TICKET,
        help=(
            "Read-only source-backed verification of one "
            "build-compatibility ticket over two dormant roots."
        ),
    )
    verify_parser.add_argument(
        "--root-file",
        required=True,
        help="Absolute path of the out-of-band release-root document.",
    )
    verify_parser.add_argument(
        "--trust-bundle",
        required=True,
        help="Absolute path of the root-signed v2 trust-bundle document.",
    )
    verify_parser.add_argument(
        "--envelope",
        required=True,
        help="Absolute path of the release-envelope document.",
    )
    verify_parser.add_argument(
        "--ticket",
        required=True,
        help="Absolute path of the build-compatibility-ticket document.",
    )
    verify_parser.add_argument(
        "--floor",
        required=True,
        help=(
            "Absolute path of the owner-only release floor file, outside "
            "any live-state or recovery directory (never mutated here)."
        ),
    )
    verify_parser.add_argument(
        "--current-root",
        required=True,
        help="Absolute path of the currently installed dormant source root.",
    )
    verify_parser.add_argument(
        "--candidate-root",
        required=True,
        help="Absolute path of the staged candidate dormant source root.",
    )
    try:
        args = parser.parse_args(raw_argv)
    except _CliArgumentError:
        return _emit(
            _build_result(
                COMMAND_VERIFY_TICKET, "unsupported:invalid-arguments"
            )
        )
    result = verify_compatibility_ticket(
        args.root_file,
        args.trust_bundle,
        args.envelope,
        args.ticket,
        args.floor,
        args.current_root,
        args.candidate_root,
    )
    return _emit(result)


if __name__ == "__main__":
    sys.exit(main())

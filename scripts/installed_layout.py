#!/usr/bin/env python3
"""Dormant installed-layout contract for SYNAPSE-S2 safe updates.

This module is a *pure description layer*: it computes, from caller-supplied
values only, where a SYNAPSE-S2 installation keeps its code, environment,
durable data, and updater state — without ever touching that installation.
It performs no filesystem, network, process, database, environment-variable,
or live-service access of any kind; its only imports are ``hashlib``,
``json``, ``posixpath``, and ``re``.  Every checked value must be an exact
builtin type (``type(x) is str/dict/list/bool``): lookalike subclasses could
smuggle impure behaviour through comparison hooks and are rejected.  Nothing
here activates, applies, migrates, selects, or wires anything: every plan it
emits reports ``activation_supported``, ``apply_supported``,
``apply_performed``, ``live_state_modified``,
``physical_separation_verified``, and ``provenance_verified`` as ``false``.

Closed schema ``synapse-s2.installed-layout-plan.v1`` with two modes:

- ``legacy-checkout-v1`` exactly models the current live layout — code at
  the checkout root, the virtual environment at ``<checkout>/.venv``, and
  all durable data embedded at ``<checkout>/.synapse_s2``.  Because data
  lives inside the code tree, this mode is *never* activation or apply
  eligible (``activation_eligibility`` is ``never``); it exists only so the
  incumbent layout has an honest, hashable description.

- ``inactive-versioned-v1`` binds the ``install_root`` plus four mutually
  disjoint roots: an exact, derived
  ``release_root = <install_root>/releases/<product-id>`` (matching the
  inactive destination the incumbent stager publishes to, and the *sole*
  intentional descendant of ``install_root``), an ``environment_root``, a
  *retained* ``data_root``, and an ``updater_state_root``.  The
  ``install_root`` must itself be disjoint from the legacy checkout and
  from the environment, data, and updater-state roots.  Canonical legacy
  data is preserved in place while every new root lives elsewhere: the
  only permitted containment anywhere is
  ``data_root == <legacy_checkout_root>/.synapse_s2`` exactly — any other
  spelling that touches the legacy checkout fails closed.  Because the
  live legacy checkout contains ``.synapse_s2``, any staged source must
  come from a clean incumbent source snapshot; the plan states this as
  the requirement token ``clean-incumbent-source-snapshot``.

A fixed adapter table maps every consumer — python interpreter, core
service, MCP installed entrypoint (``mcp_client_wrapper.py``) and MCP
server module (``mcp_server.py``), dashboard server and its auth secret,
memory store, runtime state, core request journal, client-config
publication journal, and readiness evidence — onto exactly one of those
roots, so the legacy plan reproduces today's paths byte-for-byte and the
versioned plan is a complete, deterministic relocation contract.  Every
*derived* path (the release root and each adapter binding) is revalidated
against the same canonical-path rules, including the 4096-byte bound.
Each plan is identified by a domain-separated ``layout-<sha256>`` over its
canonical binding payload; associating a stage result never changes the
``layout_id``.

All separation guarantees are **lexical only**: paths are compared as
canonical strings (casefold-insensitively) and no symlink, mount, hardlink,
or device identity is ever resolved — ``physical_separation_verified`` is
always false and ``no-physical-alias-resolution`` is a standing nonclaim.
As a partial mitigation for the one aliasing family this module can see
lexically, Darwin's ``/tmp``, ``/var``, and ``/etc`` symlinks into
``/private``, any root whose first component is one of those names is
rejected: the ``/private/...`` spelling must be used.

A successful release-stage result may optionally be *associated* with an
``inactive-versioned-v1`` plan.  Association is shape-only and confers no
authority: the result must match the closed
``synapse-s2.release-stage-result.v1`` key set; carry exactly one of the
two completed outcomes the incumbent stager emits — status ``staged`` with
reason ``source-staged-inactive`` and ``resumed`` false, or status
``already-staged`` with reason ``identity-already-staged`` and ``resumed``
true — with ``source_staged``, ``identity_pin_verified``, and
``journal_committed`` all true; claim no environment build, activation, or
live-state effect; and name the exact product and inventory-policy
identities being planned.  Incomplete, failed, unsupported,
``outcome_unknown``, or activation-claiming results are rejected; even an
accepted result is recorded only as ``shape-only-untrusted`` and never
flips any verification flag or perturbs the ``layout_id``.

Every plan also carries a host-independent ``layout_contract_id``
(``layout-contract-<sha256>``), computed by
``installed_layout_contract_projection(mode)`` over the contract itself —
schema, mode, root roles, adapters, mode policies, and nonclaims, plus
three closed behavioural policy blocks restated from this module's actual
enforcement constants: ``path_policy`` (byte bound, normalization and
control-rejection rules, casefold/ancestor overlap rule, the forbidden
active/selector/Darwin-aliased components, the exact canonical legacy-data
exception, and the release-root derivation), ``identity_policy`` (the
product and inventory-policy identity grammars, hash domains, and
canonicalization rules), and ``stage_result_policy`` (the exact stage
schema, key set, accepted status/reason/resumed outcomes, required flags,
and nonclaims).  Never any host path — so compatibility tickets can bind
the *contract* an installation follows rather than one host's concrete
``layout_id``, and any change to an enforcement constant changes the
contract identity.  The contract identity is folded into each
``layout_id`` payload: a host layout identity commits to the exact
contract it instantiates.

Rejected everywhere, fail closed: non-absolute, non-normal, traversal,
control-character (C0, DEL, and C1 ``U+0080``–``U+009F``), root ("/"), or
oversized paths (inputs and derivations
alike); casefold aliases and ancestor/descendant overlaps between roots;
``current``/``latest`` path components (no selector may ever be modeled);
``.synapse_s2``, ``recovery``, ``launchagents``, and ``launchdaemons``
components inside code/environment/install/updater roots; Darwin-aliased
``/tmp``, ``/var``, ``/etc`` spellings; non-canonical legacy-data
containment; and malformed product or inventory-policy identities.
"""

import hashlib
import json
import posixpath
import re

SCHEMA = "synapse-s2.installed-layout-plan.v1"

MODE_LEGACY_CHECKOUT = "legacy-checkout-v1"
MODE_INACTIVE_VERSIONED = "inactive-versioned-v1"

STATUS_PLANNED = "planned"
STATUS_UNSUPPORTED = "unsupported"

ACTIVATION_ELIGIBILITY_NEVER = "never"
ACTIVATION_ELIGIBILITY_GOVERNED = "requires-future-governed-activation"

REQUIREMENT_CLEAN_SNAPSHOT = "clean-incumbent-source-snapshot"

STAGE_ASSOCIATION_SHAPE_ONLY = "shape-only-untrusted"

RELEASES_DIRECTORY_NAME = "releases"
LEGACY_ENVIRONMENT_DIRECTORY = ".venv"
LEGACY_DATA_DIRECTORY = ".synapse_s2"

MAX_PATH_BYTES = 4096

# Adapter table: (adapter name, root kind, path relative to that root).
# ``code`` resolves under the code root (the checkout in legacy mode, the
# immutable release root in versioned mode), ``environment`` under the
# virtual-environment root, and ``data`` under the retained data root.
# The MCP installed entrypoint (the wrapper clients launch) is bound
# separately from the MCP server module it fronts.
ADAPTERS = (
    ("python-interpreter", "environment", "bin/python"),
    ("core-service", "code", "core_service.py"),
    ("mcp-entrypoint", "code", "mcp_client_wrapper.py"),
    ("mcp-server", "code", "mcp_server.py"),
    ("dashboard-server", "code", "dashboard_server.py"),
    ("dashboard-auth", "data", "dashboard-auth.json"),
    ("memory-store", "data", "memory.sqlite3"),
    ("runtime-state", "data", "runtime_state.json"),
    ("core-request-journal", "data", "core/requests.sqlite3"),
    (
        "client-config-journal",
        "data",
        "client-config-publication.journal.json",
    ),
    ("readiness-evidence", "data", "evidence_packs"),
)

NONCLAIMS = (
    "no-activation",
    "no-apply",
    "no-current-or-latest-selector",
    "no-filesystem-access",
    "no-live-state-access",
    "no-migration",
    "no-physical-alias-resolution",
    "no-physical-separation-verification",
    "no-provenance-verification",
    "no-stage-result-authority",
)

# The closed shape of the sibling stager's result document, restated here
# byte-for-byte rather than imported: importing scripts/release_stage.py
# would execute its os-level module machinery and break this module's
# purity guarantee.  tests/test_installed_layout.py pins these constants
# against the real stager.
STAGE_RESULT_SCHEMA = "synapse-s2.release-stage-result.v1"
STAGE_RESULT_MODE = "incumbent-inactive-source-stage"
STAGE_STATUS_STAGED = "staged"
STAGE_STATUS_ALREADY_STAGED = "already-staged"
STAGE_STATUS_OUTCOME_UNKNOWN = "outcome_unknown"
STAGE_REASON_STAGED = "source-staged-inactive"
STAGE_REASON_ALREADY_STAGED = "identity-already-staged"

STAGE_NONCLAIMS = (
    "no-activation",
    "no-current-or-latest-selector",
    "no-environment-build",
    "no-data-root-access",
    "no-live-state-access",
    "no-migration",
    "no-provenance-authentication-inside-stager",
    "no-post-stage-immutability-claim",
    "no-orphan-operation-reclamation",
)

STAGE_RESULT_KEYS = frozenset(
    (
        "schema",
        "mode",
        "status",
        "reason",
        "product_id",
        "inventory_policy_id",
        "source_staged",
        "identity_pin_verified",
        "journal_committed",
        "resumed",
        "reconciled",
        "environment_stage_supported",
        "environment_built",
        "activation_supported",
        "activation_performed",
        "live_state_modified",
        "nonclaims",
    )
)

_STAGE_RESULT_STRING_KEYS = (
    "schema",
    "mode",
    "status",
    "reason",
    "product_id",
    "inventory_policy_id",
)

# Flags a completed stage result must pin exactly True (work performed)
# and exactly False (dormancy preserved).  The validator and the contract
# projection share these tuples so the contract identity binds the very
# constants the validator enforces.
_STAGE_REQUIRED_TRUE_KEYS = (
    "source_staged",
    "identity_pin_verified",
    "journal_committed",
)

_STAGE_REQUIRED_FALSE_KEYS = (
    "environment_stage_supported",
    "environment_built",
    "activation_supported",
    "activation_performed",
    "live_state_modified",
)

_PRODUCT_ID_RE = re.compile(r"\Aproduct-[0-9a-f]{64}\Z")
_POLICY_ID_RE = re.compile(r"\Ainventory-policy-[0-9a-f]{64}\Z")

_LAYOUT_ID_DOMAIN = b"SYNAPSE-S2\x00INSTALLED-LAYOUT-PLAN\x00v1\x00"

CONTRACT_SCHEMA = "synapse-s2.installed-layout-contract.v1"

CONTRACT_STATUS_PROJECTED = "projected"

_LAYOUT_CONTRACT_ID_DOMAIN = (
    b"SYNAPSE-S2\x00INSTALLED-LAYOUT-CONTRACT\x00v1\x00"
)

# Root roles each mode binds, in plan order.  Role names only, never host
# paths: the contract projection must hash identically on every machine.
_MODE_ROOT_ROLES = {
    MODE_LEGACY_CHECKOUT: (
        "code_root",
        "environment_root",
        "data_root",
        "legacy_checkout_root",
    ),
    MODE_INACTIVE_VERSIONED: (
        "install_root",
        "code_root",
        "environment_root",
        "data_root",
        "release_root",
        "updater_state_root",
        "legacy_checkout_root",
    ),
}

# Flags every plan pins to False; the contract projection restates them so
# the contract identity commits to the dormancy guarantees themselves.
_ALWAYS_FALSE_FLAGS = (
    "activation_supported",
    "apply_supported",
    "apply_performed",
    "live_state_modified",
    "physical_separation_verified",
    "provenance_verified",
)

# Components that may never appear inside a code, environment, install, or
# updater-state root: live data, recovery material, and launchd namespaces.
_FORBIDDEN_ACTIVE_COMPONENTS = frozenset(
    (".synapse_s2", "recovery", "launchagents", "launchdaemons")
)

# Mutable selector names are rejected as path components everywhere: this
# contract only ever describes immutable, identity-addressed locations.
_FORBIDDEN_SELECTOR_COMPONENTS = frozenset(("current", "latest"))

# Darwin symlinks these top-level names into /private, so a lexical
# comparison cannot tell /tmp/x from /private/tmp/x.  Roots must use the
# /private/... spelling; the aliased spellings fail closed.
_DARWIN_ALIASED_FIRST_COMPONENTS = frozenset(("tmp", "var", "etc"))


class _Unsupported(Exception):
    """Internal fail-closed rejection carrying only a fixed public token."""

    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


def _canonical_absolute_path(raw: object, token: str) -> str:
    """Admit exactly one canonical spelling of one absolute directory path."""

    if type(raw) is not str or not raw:
        raise _Unsupported(token)
    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError:
        raise _Unsupported(token) from None
    if len(encoded) > MAX_PATH_BYTES:
        raise _Unsupported(token)
    if any(
        ord(character) < 32 or 127 <= ord(character) <= 159
        for character in raw
    ):
        raise _Unsupported(token)
    if not raw.startswith("/") or raw.startswith("//") or raw == "/":
        raise _Unsupported(token)
    if posixpath.normpath(raw) != raw:
        raise _Unsupported(token)
    components = raw.split("/")[1:]
    if any(component in ("", ".", "..") for component in components):
        raise _Unsupported(token)
    return raw


def _reject_components(
    path: str, forbidden: frozenset, token: str
) -> None:
    for component in path.split("/")[1:]:
        if component.casefold() in forbidden:
            raise _Unsupported(token)


def _reject_aliased_spelling(path: str, token: str) -> None:
    if path.split("/")[1].casefold() in _DARWIN_ALIASED_FIRST_COMPONENTS:
        raise _Unsupported(token)


def _components_casefold(path: str) -> tuple:
    return tuple(part.casefold() for part in path.split("/")[1:])


def _overlaps(first: str, second: str) -> bool:
    """True when the two paths are equal, casefold aliases, or nested.

    Comparison is casefold-insensitive so a case-insensitive filesystem
    cannot alias two "distinct" roots onto one directory.  This is a
    lexical judgement only: physical aliasing via symlinks, mounts, or
    hardlinks is explicitly out of scope (``no-physical-alias-resolution``).
    """

    left = _components_casefold(first)
    right = _components_casefold(second)
    shorter = min(len(left), len(right))
    return left[:shorter] == right[:shorter]


def _derived(path: str) -> str:
    """Revalidate a path this module built by concatenation."""

    return _canonical_absolute_path(path, "derived-path-invalid")


def _bind_adapters(
    code_root: str, environment_root: str, data_root: str
) -> dict:
    roots = {
        "code": code_root,
        "environment": environment_root,
        "data": data_root,
    }
    return {
        name: _derived(roots[kind] + "/" + relative)
        for name, kind, relative in ADAPTERS
    }


def _contract_policies(mode: str) -> dict:
    """Fresh per-call policy document for one mode; no shared references."""

    if mode == MODE_LEGACY_CHECKOUT:
        return {
            "activation_eligibility": ACTIVATION_ELIGIBILITY_NEVER,
            "requirements": [],
            "stage_association_policy": "not-applicable",
            "data_root_policy": "embedded-under-legacy-checkout",
            "release_root_policy": "not-modeled",
            "separation_policy": "lexical-only",
        }
    return {
        "activation_eligibility": ACTIVATION_ELIGIBILITY_GOVERNED,
        "requirements": [REQUIREMENT_CLEAN_SNAPSHOT],
        "stage_association_policy": STAGE_ASSOCIATION_SHAPE_ONLY,
        "data_root_policy": "retained-canonical-legacy-data-or-disjoint",
        "release_root_policy": "sole-install-root-descendant",
        "separation_policy": "lexical-only",
    }


def _contract_path_policy() -> dict:
    """Fresh host-independent restatement of every path-admission rule.

    Reads the enforcement constants from module globals at call time so the
    contract identity tracks the constants the validators actually apply:
    perturbing any of them perturbs ``layout_contract_id``.  Role names and
    templates only — no value may ever begin with ``/``.
    """

    return {
        "max_path_bytes": MAX_PATH_BYTES,
        "encoding": "utf-8",
        "absolute_paths_only": True,
        "bare_root_rejected": True,
        "leading_double_slash_rejected": True,
        "normalization_rule": "posixpath.normpath-fixed-point",
        "empty_dot_dotdot_components_rejected": True,
        "rejected_codepoint_ranges": [[0, 31], [127, 159]],
        "component_comparison_rule": "casefold",
        "overlap_rule": "casefold-equal-alias-or-ancestor-descendant",
        "derived_paths_revalidated": True,
        "forbidden_active_components": sorted(
            _FORBIDDEN_ACTIVE_COMPONENTS
        ),
        "forbidden_selector_components": sorted(
            _FORBIDDEN_SELECTOR_COMPONENTS
        ),
        "darwin_aliased_first_components": sorted(
            _DARWIN_ALIASED_FIRST_COMPONENTS
        ),
        "releases_directory_name": RELEASES_DIRECTORY_NAME,
        "legacy_environment_directory": LEGACY_ENVIRONMENT_DIRECTORY,
        "legacy_data_directory": LEGACY_DATA_DIRECTORY,
        "legacy_data_exception": (
            "data_root == <legacy_checkout_root>/" + LEGACY_DATA_DIRECTORY
        ),
        "release_root_derivation": (
            "<install_root>/" + RELEASES_DIRECTORY_NAME + "/<product_id>"
        ),
    }


def _contract_identity_policy() -> dict:
    """Fresh restatement of the identity grammars and hashing rules."""

    return {
        "product_id_grammar": _PRODUCT_ID_RE.pattern,
        "product_id_grammar_flags": int(_PRODUCT_ID_RE.flags),
        "inventory_policy_id_grammar": _POLICY_ID_RE.pattern,
        "inventory_policy_id_grammar_flags": int(_POLICY_ID_RE.flags),
        "layout_id_form": "layout-<sha256-hex>",
        "layout_contract_id_form": "layout-contract-<sha256-hex>",
        "layout_id_domain": _LAYOUT_ID_DOMAIN.decode("ascii"),
        "layout_contract_id_domain": (
            _LAYOUT_CONTRACT_ID_DOMAIN.decode("ascii")
        ),
        "hash_algorithm": "sha256",
        "canonicalization_rule": "json-sorted-keys-compact-ascii",
        "exact_builtin_types_required": True,
    }


def _contract_stage_result_policy() -> dict:
    """Fresh restatement of the exact stage-result acceptance shape."""

    return {
        "schema": STAGE_RESULT_SCHEMA,
        "mode": STAGE_RESULT_MODE,
        "keys": sorted(STAGE_RESULT_KEYS),
        "string_keys": list(_STAGE_RESULT_STRING_KEYS),
        "accepted_outcomes": [
            {
                "status": STAGE_STATUS_STAGED,
                "reason": STAGE_REASON_STAGED,
                "resumed": False,
            },
            {
                "status": STAGE_STATUS_ALREADY_STAGED,
                "reason": STAGE_REASON_ALREADY_STAGED,
                "resumed": True,
            },
        ],
        "rejected_statuses": [STAGE_STATUS_OUTCOME_UNKNOWN],
        "required_true_keys": list(_STAGE_REQUIRED_TRUE_KEYS),
        "required_false_keys": list(_STAGE_REQUIRED_FALSE_KEYS),
        "nonclaims": list(STAGE_NONCLAIMS),
        "association_policy": STAGE_ASSOCIATION_SHAPE_ONLY,
        "identity_match_required": True,
    }


def _layout_contract_id(mode: str) -> str:
    payload = {
        "schema": CONTRACT_SCHEMA,
        "plan_schema": SCHEMA,
        "mode": mode,
        "root_roles": list(_MODE_ROOT_ROLES[mode]),
        "adapters": [list(entry) for entry in ADAPTERS],
        "policies": _contract_policies(mode),
        "path_policy": _contract_path_policy(),
        "identity_policy": _contract_identity_policy(),
        "stage_result_policy": _contract_stage_result_policy(),
        "always_false_flags": list(_ALWAYS_FALSE_FLAGS),
        "nonclaims": list(NONCLAIMS),
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    digest = hashlib.sha256(
        _LAYOUT_CONTRACT_ID_DOMAIN + canonical.encode("ascii")
    ).hexdigest()
    return "layout-contract-" + digest


def installed_layout_contract_projection(mode: object) -> dict:
    """Project the host-independent layout contract for one mode.

    The projection binds schema, mode, root roles, adapters, mode policies,
    the behavioural ``path_policy``/``identity_policy``/
    ``stage_result_policy`` blocks, and nonclaims — never a host path — so
    its ``layout_contract_id`` is stable across machines yet changes
    whenever any enforcement constant changes.  Compatibility tickets bind
    this contract identity, not any single host's ``layout_id``.
    """

    # Exact-type check before the membership lookup: a str-subclass mode
    # must never reach the dict lookup, where its overridden
    # __hash__/__eq__ would execute.
    if type(mode) is not str or mode not in _MODE_ROOT_ROLES:
        return {
            "schema": CONTRACT_SCHEMA,
            "plan_schema": SCHEMA,
            "status": STATUS_UNSUPPORTED,
            "reason": "unsupported:mode-invalid",
            "layout_contract_id": None,
            "mode": None,
            "root_roles": None,
            "adapters": None,
            "policies": None,
            "path_policy": None,
            "identity_policy": None,
            "stage_result_policy": None,
            "always_false_flags": list(_ALWAYS_FALSE_FLAGS),
            "nonclaims": list(NONCLAIMS),
        }
    return {
        "schema": CONTRACT_SCHEMA,
        "plan_schema": SCHEMA,
        "status": CONTRACT_STATUS_PROJECTED,
        "reason": "projected:host-independent-contract",
        "layout_contract_id": _layout_contract_id(mode),
        "mode": mode,
        "root_roles": list(_MODE_ROOT_ROLES[mode]),
        "adapters": [list(entry) for entry in ADAPTERS],
        "policies": _contract_policies(mode),
        "path_policy": _contract_path_policy(),
        "identity_policy": _contract_identity_policy(),
        "stage_result_policy": _contract_stage_result_policy(),
        "always_false_flags": list(_ALWAYS_FALSE_FLAGS),
        "nonclaims": list(NONCLAIMS),
    }


def _layout_id(binding: dict) -> str:
    canonical = json.dumps(
        binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    digest = hashlib.sha256(
        _LAYOUT_ID_DOMAIN + canonical.encode("ascii")
    ).hexdigest()
    return "layout-" + digest


def _result(
    mode: str,
    *,
    status: str,
    reason: str,
    layout_id: str | None = None,
    layout_contract_id: str | None = None,
    product_id: str | None = None,
    inventory_policy_id: str | None = None,
    install_root: str | None = None,
    code_root: str | None = None,
    environment_root: str | None = None,
    data_root: str | None = None,
    release_root: str | None = None,
    updater_state_root: str | None = None,
    legacy_checkout_root: str | None = None,
    data_root_retained_under_legacy_checkout: bool | None = None,
    adapters: dict | None = None,
    activation_eligibility: str | None = None,
    requirements: tuple = (),
    stage_associated: bool = False,
    stage_association: str | None = None,
) -> dict:
    return {
        "schema": SCHEMA,
        "mode": mode,
        "status": status,
        "reason": reason,
        "layout_id": layout_id,
        "layout_contract_id": layout_contract_id,
        "product_id": product_id,
        "inventory_policy_id": inventory_policy_id,
        "install_root": install_root,
        "code_root": code_root,
        "environment_root": environment_root,
        "data_root": data_root,
        "release_root": release_root,
        "updater_state_root": updater_state_root,
        "legacy_checkout_root": legacy_checkout_root,
        "data_root_retained_under_legacy_checkout": (
            data_root_retained_under_legacy_checkout
        ),
        "adapters": adapters,
        "activation_eligibility": activation_eligibility,
        "requirements": list(requirements),
        "stage_associated": stage_associated,
        "stage_association": stage_association,
        "activation_supported": False,
        "apply_supported": False,
        "apply_performed": False,
        "live_state_modified": False,
        "physical_separation_verified": False,
        "provenance_verified": False,
        "nonclaims": list(NONCLAIMS),
    }


def _unsupported(mode: str, token: str) -> dict:
    return _result(
        mode,
        status=STATUS_UNSUPPORTED,
        reason="unsupported:" + token,
    )


def _validate_identity(
    value: object, pattern: re.Pattern, token: str
) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise _Unsupported(token)
    return value


def _validate_stage_result(
    stage_result: object, product_id: str, inventory_policy_id: str
) -> None:
    """Shape-validate one completed inactive stage result; confer nothing.

    Acceptance means only that the document is the exact closed shape a
    successful incumbent stage emits for these identities.  It is never
    treated as authenticated, verified, or authoritative, and it never
    perturbs the layout identity.
    """

    if type(stage_result) is not dict:
        raise _Unsupported("stage-result-shape")
    # Cardinality gate before any key access: len() on an exact dict never
    # touches keys, so an oversized or undersized document is rejected
    # without scanning a single entry.
    if len(stage_result) != len(STAGE_RESULT_KEYS):
        raise _Unsupported("stage-result-shape")
    # Key gate before set()/lookups: plain iteration never hashes or
    # rich-compares keys, so a str-subclass key cannot execute overridden
    # __hash__/__eq__ before its type is rejected here.
    for key in stage_result:
        if type(key) is not str:
            raise _Unsupported("stage-result-shape")
    if set(stage_result) != STAGE_RESULT_KEYS:
        raise _Unsupported("stage-result-shape")
    for key in _STAGE_RESULT_STRING_KEYS:
        if type(stage_result[key]) is not str:
            raise _Unsupported("stage-result-shape")
    if stage_result["schema"] != STAGE_RESULT_SCHEMA:
        raise _Unsupported("stage-result-schema")
    if stage_result["mode"] != STAGE_RESULT_MODE:
        raise _Unsupported("stage-result-schema")
    status = stage_result["status"]
    if status == STAGE_STATUS_OUTCOME_UNKNOWN:
        raise _Unsupported("stage-result-outcome-unknown")
    if status not in (STAGE_STATUS_STAGED, STAGE_STATUS_ALREADY_STAGED):
        raise _Unsupported("stage-result-not-successful")
    # Exactly the two completed outcomes the incumbent stager can emit:
    # a fresh stage is never resumed; an idempotent re-stage always is.
    if status == STAGE_STATUS_STAGED:
        if stage_result["reason"] != STAGE_REASON_STAGED:
            raise _Unsupported("stage-result-inconsistent")
        if stage_result["resumed"] is not False:
            raise _Unsupported("stage-result-inconsistent")
    else:
        if stage_result["reason"] != STAGE_REASON_ALREADY_STAGED:
            raise _Unsupported("stage-result-inconsistent")
        if stage_result["resumed"] is not True:
            raise _Unsupported("stage-result-inconsistent")
    for key in _STAGE_REQUIRED_TRUE_KEYS:
        if stage_result[key] is not True:
            raise _Unsupported("stage-result-incomplete")
    for key in _STAGE_REQUIRED_FALSE_KEYS:
        if stage_result[key] is not False:
            raise _Unsupported("stage-result-claims-live-effect")
    if type(stage_result["reconciled"]) is not bool:
        raise _Unsupported("stage-result-shape")
    if stage_result["product_id"] != product_id:
        raise _Unsupported("stage-result-identity-mismatch")
    if stage_result["inventory_policy_id"] != inventory_policy_id:
        raise _Unsupported("stage-result-identity-mismatch")
    nonclaims = stage_result["nonclaims"]
    if type(nonclaims) is not list:
        raise _Unsupported("stage-result-nonclaims")
    # Length gate before any item access: an arbitrarily long list is
    # rejected without scanning a single entry.
    if len(nonclaims) != len(STAGE_NONCLAIMS):
        raise _Unsupported("stage-result-nonclaims")
    for expected, actual in zip(STAGE_NONCLAIMS, nonclaims):
        # Exact-str check before equality so a str-subclass entry never
        # has its overridden __eq__ consulted.
        if type(actual) is not str or actual != expected:
            raise _Unsupported("stage-result-nonclaims")


def plan_legacy_checkout_layout(
    checkout_root: object, *, stage_result: object = None
) -> dict:
    """Model the current live checkout layout exactly; never eligible.

    The returned plan reproduces today's paths byte-for-byte: code at the
    checkout root, the environment at ``<checkout>/.venv``, and durable
    data at ``<checkout>/.synapse_s2``.  Because data is embedded inside
    the code tree, no stage result may be associated and the plan is never
    activation or apply eligible.
    """

    try:
        if stage_result is not None:
            raise _Unsupported("stage-association-not-applicable")
        checkout = _canonical_absolute_path(
            checkout_root, "checkout-root-invalid"
        )
        _reject_components(
            checkout,
            _FORBIDDEN_ACTIVE_COMPONENTS,
            "checkout-root-forbidden-component",
        )
        _reject_components(
            checkout,
            _FORBIDDEN_SELECTOR_COMPONENTS,
            "checkout-root-selector-component",
        )
        _reject_aliased_spelling(checkout, "checkout-root-aliased-spelling")
        environment_root = _derived(
            checkout + "/" + LEGACY_ENVIRONMENT_DIRECTORY
        )
        data_root = _derived(checkout + "/" + LEGACY_DATA_DIRECTORY)
        adapters = _bind_adapters(checkout, environment_root, data_root)
    except _Unsupported as rejection:
        return _unsupported(MODE_LEGACY_CHECKOUT, rejection.token)
    layout_contract_id = _layout_contract_id(MODE_LEGACY_CHECKOUT)
    layout_id = _layout_id(
        {
            "schema": SCHEMA,
            "mode": MODE_LEGACY_CHECKOUT,
            "layout_contract_id": layout_contract_id,
            "product_id": None,
            "inventory_policy_id": None,
            "install_root": None,
            "code_root": checkout,
            "environment_root": environment_root,
            "data_root": data_root,
            "release_root": None,
            "updater_state_root": None,
            "legacy_checkout_root": checkout,
            "adapters": adapters,
        }
    )
    return _result(
        MODE_LEGACY_CHECKOUT,
        status=STATUS_PLANNED,
        reason="planned:legacy-checkout-modeled",
        layout_id=layout_id,
        layout_contract_id=layout_contract_id,
        code_root=checkout,
        environment_root=environment_root,
        data_root=data_root,
        legacy_checkout_root=checkout,
        data_root_retained_under_legacy_checkout=True,
        adapters=adapters,
        activation_eligibility=ACTIVATION_ELIGIBILITY_NEVER,
    )


def plan_inactive_versioned_layout(
    *,
    install_root: object,
    environment_root: object,
    data_root: object,
    updater_state_root: object,
    legacy_checkout_root: object,
    product_id: object,
    inventory_policy_id: object,
    stage_result: object = None,
) -> dict:
    """Bind one inactive, versioned layout; describe, never touch.

    ``release_root`` is derived — never chosen — as
    ``<install_root>/releases/<product-id>``, the exact inactive
    destination the incumbent stager publishes to and the sole intentional
    descendant of ``install_root``.  The retained ``data_root`` may be
    exactly ``<legacy_checkout_root>/.synapse_s2`` and nothing else inside
    the old checkout; every root is otherwise mutually disjoint with no
    casefold aliasing, judged lexically only.
    """

    try:
        product = _validate_identity(
            product_id, _PRODUCT_ID_RE, "product-id-invalid"
        )
        policy = _validate_identity(
            inventory_policy_id,
            _POLICY_ID_RE,
            "inventory-policy-id-invalid",
        )
        install = _canonical_absolute_path(
            install_root, "install-root-invalid"
        )
        environment = _canonical_absolute_path(
            environment_root, "environment-root-invalid"
        )
        data = _canonical_absolute_path(data_root, "data-root-invalid")
        updater_state = _canonical_absolute_path(
            updater_state_root, "updater-state-root-invalid"
        )
        legacy = _canonical_absolute_path(
            legacy_checkout_root, "legacy-checkout-root-invalid"
        )
        for path, token in (
            (install, "install-root-forbidden-component"),
            (environment, "environment-root-forbidden-component"),
            (updater_state, "updater-state-root-forbidden-component"),
            (legacy, "legacy-checkout-root-forbidden-component"),
        ):
            _reject_components(
                path, _FORBIDDEN_ACTIVE_COMPONENTS, token
            )
        for path, token in (
            (install, "install-root-selector-component"),
            (environment, "environment-root-selector-component"),
            (data, "data-root-selector-component"),
            (updater_state, "updater-state-root-selector-component"),
            (legacy, "legacy-checkout-root-selector-component"),
        ):
            _reject_components(
                path, _FORBIDDEN_SELECTOR_COMPONENTS, token
            )
        for path, token in (
            (install, "install-root-aliased-spelling"),
            (environment, "environment-root-aliased-spelling"),
            (data, "data-root-aliased-spelling"),
            (updater_state, "updater-state-root-aliased-spelling"),
            (legacy, "legacy-checkout-root-aliased-spelling"),
        ):
            _reject_aliased_spelling(path, token)
        release = _derived(
            install + "/" + RELEASES_DIRECTORY_NAME + "/" + product
        )
        # The install root owns exactly one descendant: the derived
        # release root.  Every other root — and the legacy checkout —
        # must be lexically disjoint from it.
        if _overlaps(install, legacy):
            raise _Unsupported("legacy-checkout-overlap")
        for other in (environment, data, updater_state):
            if _overlaps(install, other):
                raise _Unsupported("install-root-overlap")
        bound_roots = (release, environment, data, updater_state)
        for index, first in enumerate(bound_roots):
            for second in bound_roots[index + 1:]:
                if _overlaps(first, second):
                    raise _Unsupported("root-overlap")
        for new_root in (release, environment, updater_state):
            if _overlaps(new_root, legacy):
                raise _Unsupported("legacy-checkout-overlap")
        # The single permitted containment: the retained data root is
        # exactly the legacy checkout's embedded data directory.
        canonical_retained = legacy + "/" + LEGACY_DATA_DIRECTORY
        data_retained = data == canonical_retained
        if _overlaps(data, legacy) and not data_retained:
            raise _Unsupported("legacy-data-root-not-canonical")
        adapters = _bind_adapters(release, environment, data)
        if stage_result is not None:
            _validate_stage_result(stage_result, product, policy)
    except _Unsupported as rejection:
        return _unsupported(MODE_INACTIVE_VERSIONED, rejection.token)
    layout_contract_id = _layout_contract_id(MODE_INACTIVE_VERSIONED)
    layout_id = _layout_id(
        {
            "schema": SCHEMA,
            "mode": MODE_INACTIVE_VERSIONED,
            "layout_contract_id": layout_contract_id,
            "product_id": product,
            "inventory_policy_id": policy,
            "install_root": install,
            "code_root": release,
            "environment_root": environment,
            "data_root": data,
            "release_root": release,
            "updater_state_root": updater_state,
            "legacy_checkout_root": legacy,
            "adapters": adapters,
        }
    )
    return _result(
        MODE_INACTIVE_VERSIONED,
        status=STATUS_PLANNED,
        reason="planned:inactive-versioned-layout-bound",
        layout_id=layout_id,
        layout_contract_id=layout_contract_id,
        product_id=product,
        inventory_policy_id=policy,
        install_root=install,
        code_root=release,
        environment_root=environment,
        data_root=data,
        release_root=release,
        updater_state_root=updater_state,
        legacy_checkout_root=legacy,
        data_root_retained_under_legacy_checkout=data_retained,
        adapters=adapters,
        activation_eligibility=ACTIVATION_ELIGIBILITY_GOVERNED,
        requirements=(REQUIREMENT_CLEAN_SNAPSHOT,),
        stage_associated=stage_result is not None,
        stage_association=(
            STAGE_ASSOCIATION_SHAPE_ONLY
            if stage_result is not None
            else None
        ),
    )

"""Adversarial tests for the dormant installed-layout contract."""

from __future__ import annotations

import ast
import builtins
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


layout = _load(
    "test_installed_layout_module", ROOT / "scripts/installed_layout.py"
)

LEGACY_CHECKOUT = "/Users/operator/SYNAPSE-S2"
PRODUCT_ID = "product-" + hashlib.sha256(b"layout-product").hexdigest()
POLICY_ID = (
    "inventory-policy-" + hashlib.sha256(b"layout-policy").hexdigest()
)
INSTALL_ROOT = "/opt/synapse-s2"
ENVIRONMENT_ROOT = "/opt/synapse-s2-environments/" + PRODUCT_ID
RETAINED_DATA_ROOT = LEGACY_CHECKOUT + "/.synapse_s2"
EXTERNAL_DATA_ROOT = "/private/var/synapse-s2/data"
UPDATER_STATE_ROOT = "/opt/synapse-s2-updater-state"

FALSE_FLAGS = (
    "activation_supported",
    "apply_supported",
    "apply_performed",
    "live_state_modified",
    "physical_separation_verified",
    "provenance_verified",
)


def _plan_inactive(**overrides) -> dict:
    arguments = {
        "install_root": INSTALL_ROOT,
        "environment_root": ENVIRONMENT_ROOT,
        "data_root": RETAINED_DATA_ROOT,
        "updater_state_root": UPDATER_STATE_ROOT,
        "legacy_checkout_root": LEGACY_CHECKOUT,
        "product_id": PRODUCT_ID,
        "inventory_policy_id": POLICY_ID,
    }
    arguments.update(overrides)
    return layout.plan_inactive_versioned_layout(**arguments)


def _stage_result(**overrides) -> dict:
    result = {
        "schema": "synapse-s2.release-stage-result.v1",
        "mode": "incumbent-inactive-source-stage",
        "status": "staged",
        "reason": "source-staged-inactive",
        "product_id": PRODUCT_ID,
        "inventory_policy_id": POLICY_ID,
        "source_staged": True,
        "identity_pin_verified": True,
        "journal_committed": True,
        "resumed": False,
        "reconciled": False,
        "environment_stage_supported": False,
        "environment_built": False,
        "activation_supported": False,
        "activation_performed": False,
        "live_state_modified": False,
        "nonclaims": [
            "no-activation",
            "no-current-or-latest-selector",
            "no-environment-build",
            "no-data-root-access",
            "no-live-state-access",
            "no-migration",
            "no-provenance-authentication-inside-stager",
            "no-post-stage-immutability-claim",
            "no-orphan-operation-reclamation",
        ],
    }
    result.update(overrides)
    return result


def _already_staged_result(**overrides) -> dict:
    result = _stage_result(
        status="already-staged",
        reason="identity-already-staged",
        resumed=True,
    )
    result.update(overrides)
    return result


class LegacyCheckoutParityTests(unittest.TestCase):
    def test_legacy_plan_models_current_paths_exactly(self) -> None:
        plan = layout.plan_legacy_checkout_layout(LEGACY_CHECKOUT)
        self.assertEqual(plan["schema"], "synapse-s2.installed-layout-plan.v1")
        self.assertEqual(plan["mode"], "legacy-checkout-v1")
        self.assertEqual(plan["status"], "planned")
        self.assertIsNone(plan["install_root"])
        self.assertEqual(plan["code_root"], LEGACY_CHECKOUT)
        self.assertEqual(
            plan["environment_root"], LEGACY_CHECKOUT + "/.venv"
        )
        self.assertEqual(
            plan["data_root"], LEGACY_CHECKOUT + "/.synapse_s2"
        )
        self.assertEqual(plan["legacy_checkout_root"], LEGACY_CHECKOUT)
        self.assertEqual(
            plan["adapters"],
            {
                "python-interpreter": (
                    LEGACY_CHECKOUT + "/.venv/bin/python"
                ),
                "core-service": LEGACY_CHECKOUT + "/core_service.py",
                "mcp-entrypoint": (
                    LEGACY_CHECKOUT + "/mcp_client_wrapper.py"
                ),
                "mcp-server": LEGACY_CHECKOUT + "/mcp_server.py",
                "dashboard-server": (
                    LEGACY_CHECKOUT + "/dashboard_server.py"
                ),
                "dashboard-auth": (
                    LEGACY_CHECKOUT + "/.synapse_s2/dashboard-auth.json"
                ),
                "memory-store": (
                    LEGACY_CHECKOUT + "/.synapse_s2/memory.sqlite3"
                ),
                "runtime-state": (
                    LEGACY_CHECKOUT + "/.synapse_s2/runtime_state.json"
                ),
                "core-request-journal": (
                    LEGACY_CHECKOUT + "/.synapse_s2/core/requests.sqlite3"
                ),
                "client-config-journal": (
                    LEGACY_CHECKOUT
                    + "/.synapse_s2/client-config-publication.journal.json"
                ),
                "readiness-evidence": (
                    LEGACY_CHECKOUT + "/.synapse_s2/evidence_packs"
                ),
            },
        )

    def test_legacy_core_journal_matches_runtime_path_derivation(self) -> None:
        runtime_paths = _load(
            "test_installed_layout_runtime_paths",
            ROOT / "core_runtime_paths.py",
        )
        plan = layout.plan_legacy_checkout_layout(LEGACY_CHECKOUT)
        derived = (
            runtime_paths.durable_core_root(plan["adapters"]["memory-store"])
            / "requests.sqlite3"
        )
        self.assertEqual(
            plan["adapters"]["core-request-journal"], str(derived)
        )

    def test_mcp_entrypoint_and_server_are_distinct_real_files(self) -> None:
        plan = layout.plan_legacy_checkout_layout(str(ROOT))
        entrypoint = plan["adapters"]["mcp-entrypoint"]
        server = plan["adapters"]["mcp-server"]
        self.assertNotEqual(entrypoint, server)
        self.assertTrue(entrypoint.endswith("/mcp_client_wrapper.py"))
        self.assertTrue(server.endswith("/mcp_server.py"))
        self.assertTrue(Path(entrypoint).is_file())
        self.assertTrue(Path(server).is_file())

    def test_legacy_plan_is_never_activation_or_apply_eligible(self) -> None:
        plan = layout.plan_legacy_checkout_layout(LEGACY_CHECKOUT)
        self.assertEqual(plan["activation_eligibility"], "never")
        self.assertIsNone(plan["release_root"])
        self.assertIsNone(plan["updater_state_root"])
        self.assertIsNone(plan["install_root"])
        self.assertIsNone(plan["product_id"])
        self.assertIsNone(plan["inventory_policy_id"])
        self.assertTrue(plan["data_root_retained_under_legacy_checkout"])
        for flag in FALSE_FLAGS:
            self.assertIs(plan[flag], False)

    def test_legacy_plan_rejects_stage_association(self) -> None:
        plan = layout.plan_legacy_checkout_layout(
            LEGACY_CHECKOUT, stage_result=_stage_result()
        )
        self.assertEqual(plan["status"], "unsupported")
        self.assertEqual(
            plan["reason"], "unsupported:stage-association-not-applicable"
        )
        self.assertIsNone(plan["layout_id"])
        self.assertIsNone(plan["adapters"])

    def test_legacy_plan_is_deterministic(self) -> None:
        first = layout.plan_legacy_checkout_layout(LEGACY_CHECKOUT)
        second = layout.plan_legacy_checkout_layout(LEGACY_CHECKOUT)
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )


class InactiveVersionedLayoutTests(unittest.TestCase):
    def test_release_root_is_derived_from_install_and_product(self) -> None:
        plan = _plan_inactive()
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["mode"], "inactive-versioned-v1")
        self.assertEqual(plan["install_root"], INSTALL_ROOT)
        self.assertEqual(
            plan["release_root"],
            INSTALL_ROOT + "/releases/" + PRODUCT_ID,
        )
        self.assertEqual(plan["code_root"], plan["release_root"])
        self.assertEqual(plan["environment_root"], ENVIRONMENT_ROOT)
        self.assertEqual(plan["data_root"], RETAINED_DATA_ROOT)
        self.assertEqual(plan["updater_state_root"], UPDATER_STATE_ROOT)
        self.assertEqual(plan["product_id"], PRODUCT_ID)
        self.assertEqual(plan["inventory_policy_id"], POLICY_ID)

    def test_adapters_bind_under_their_roots(self) -> None:
        plan = _plan_inactive()
        adapters = plan["adapters"]
        self.assertEqual(
            adapters["python-interpreter"],
            ENVIRONMENT_ROOT + "/bin/python",
        )
        for name in (
            "core-service",
            "mcp-entrypoint",
            "mcp-server",
            "dashboard-server",
        ):
            self.assertTrue(
                adapters[name].startswith(plan["release_root"] + "/")
            )
        for name in (
            "dashboard-auth",
            "memory-store",
            "runtime-state",
            "core-request-journal",
            "client-config-journal",
            "readiness-evidence",
        ):
            self.assertTrue(
                adapters[name].startswith(RETAINED_DATA_ROOT + "/")
            )
        self.assertEqual(len(adapters), 11)
        self.assertNotEqual(
            adapters["mcp-entrypoint"], adapters["mcp-server"]
        )

    def test_retained_data_root_may_stay_under_old_checkout(self) -> None:
        plan = _plan_inactive(data_root=RETAINED_DATA_ROOT)
        self.assertEqual(plan["status"], "planned")
        self.assertTrue(plan["data_root_retained_under_legacy_checkout"])

    def test_external_data_root_is_supported_and_not_retained(self) -> None:
        plan = _plan_inactive(data_root=EXTERNAL_DATA_ROOT)
        self.assertEqual(plan["status"], "planned")
        self.assertIs(
            plan["data_root_retained_under_legacy_checkout"], False
        )
        self.assertEqual(plan["data_root"], EXTERNAL_DATA_ROOT)

    def test_clean_incumbent_snapshot_is_a_stated_requirement(self) -> None:
        plan = _plan_inactive()
        self.assertEqual(
            plan["requirements"], ["clean-incumbent-source-snapshot"]
        )
        self.assertEqual(
            plan["activation_eligibility"],
            "requires-future-governed-activation",
        )

    def test_all_authority_flags_stay_false(self) -> None:
        for plan in (
            _plan_inactive(),
            _plan_inactive(stage_result=_stage_result()),
            layout.plan_legacy_checkout_layout(LEGACY_CHECKOUT),
            _plan_inactive(product_id="bogus"),
        ):
            for flag in FALSE_FLAGS:
                self.assertIs(plan[flag], False)
            self.assertEqual(plan["nonclaims"], list(layout.NONCLAIMS))
        self.assertIn("no-activation", layout.NONCLAIMS)
        self.assertIn("no-stage-result-authority", layout.NONCLAIMS)
        self.assertIn("no-current-or-latest-selector", layout.NONCLAIMS)
        self.assertIn("no-physical-alias-resolution", layout.NONCLAIMS)

    def test_layout_id_is_deterministic_and_domain_separated(self) -> None:
        identity = re.compile(r"\Alayout-[0-9a-f]{64}\Z")
        inactive = _plan_inactive()
        legacy = layout.plan_legacy_checkout_layout(LEGACY_CHECKOUT)
        self.assertRegex(inactive["layout_id"], identity)
        self.assertRegex(legacy["layout_id"], identity)
        self.assertEqual(_plan_inactive(), inactive)
        self.assertNotEqual(inactive["layout_id"], legacy["layout_id"])

    def test_layout_id_binds_every_root_and_identity(self) -> None:
        base = _plan_inactive()["layout_id"]
        changed = (
            _plan_inactive(install_root="/opt/synapse-s2-b"),
            _plan_inactive(
                environment_root="/opt/synapse-s2-environments/other"
            ),
            _plan_inactive(data_root=EXTERNAL_DATA_ROOT),
            _plan_inactive(
                updater_state_root="/opt/synapse-s2-updater-state-b"
            ),
            _plan_inactive(
                data_root="/Users/operator/OLD/.synapse_s2",
                legacy_checkout_root="/Users/operator/OLD",
            ),
            _plan_inactive(
                product_id="product-" + "0" * 64,
            ),
            _plan_inactive(
                inventory_policy_id="inventory-policy-" + "1" * 64,
            ),
        )
        identifiers = {plan["layout_id"] for plan in changed}
        for plan in changed:
            self.assertEqual(plan["status"], "planned")
        self.assertNotIn(base, identifiers)
        self.assertEqual(len(identifiers), len(changed))

    def test_stage_association_is_shape_only_and_untrusted(self) -> None:
        plan = _plan_inactive(stage_result=_stage_result())
        self.assertEqual(plan["status"], "planned")
        self.assertIs(plan["stage_associated"], True)
        self.assertEqual(plan["stage_association"], "shape-only-untrusted")
        self.assertIs(plan["provenance_verified"], False)
        self.assertIs(plan["physical_separation_verified"], False)

    def test_stage_association_never_changes_the_layout_id(self) -> None:
        bare = _plan_inactive()
        associated = _plan_inactive(stage_result=_stage_result())
        resumed = _plan_inactive(stage_result=_already_staged_result())
        self.assertIs(bare["stage_associated"], False)
        self.assertIsNone(bare["stage_association"])
        self.assertEqual(bare["layout_id"], associated["layout_id"])
        self.assertEqual(bare["layout_id"], resumed["layout_id"])
        self.assertEqual(
            bare["layout_contract_id"], associated["layout_contract_id"]
        )
        self.assertEqual(
            bare["layout_contract_id"], resumed["layout_contract_id"]
        )


class PathAndIdentityRejectionTests(unittest.TestCase):
    def _assert_rejected(self, plan: dict, token: str) -> None:
        self.assertEqual(plan["status"], "unsupported")
        self.assertEqual(plan["reason"], "unsupported:" + token)
        self.assertIsNone(plan["layout_id"])
        self.assertIsNone(plan["adapters"])
        self.assertIsNone(plan["release_root"])
        self.assertIsNone(plan["install_root"])
        for flag in FALSE_FLAGS:
            self.assertIs(plan[flag], False)

    def test_malformed_paths_fail_closed(self) -> None:
        for bad in (
            "relative/path",
            "",
            "/",
            "//opt/synapse-s2",
            "/opt/../synapse-s2",
            "/opt/./synapse-s2",
            "/opt//synapse-s2",
            "/opt/synapse-s2/",
            "/opt/syn\x00apse",
            "/opt/syn\napse",
            "/opt/syn\x7fapse",
            "/opt/syn\x80apse",
            "/opt/syn\x85apse",
            "/opt/syn\x9fapse",
            "/" + "a" * layout.MAX_PATH_BYTES,
            None,
            7,
            b"/opt/synapse-s2",
            ["/opt/synapse-s2"],
        ):
            self._assert_rejected(
                _plan_inactive(install_root=bad), "install-root-invalid"
            )
            legacy = layout.plan_legacy_checkout_layout(bad)
            self.assertEqual(legacy["status"], "unsupported")
            self.assertEqual(
                legacy["reason"], "unsupported:checkout-root-invalid"
            )

    def test_c1_controls_are_rejected_and_nbsp_is_not(self) -> None:
        # C1 boundary pin: U+0080 and U+009F fail closed on every root
        # (input and derived alike); U+00A0 sits just past the C1 range
        # and stays accepted.
        for control in ("\u0080", "\u0085", "\u009f"):
            bad = "/opt/synapse" + control + "dir"
            self._assert_rejected(
                _plan_inactive(install_root=bad), "install-root-invalid"
            )
            self._assert_rejected(
                _plan_inactive(environment_root=bad),
                "environment-root-invalid",
            )
            self._assert_rejected(
                _plan_inactive(data_root=bad), "data-root-invalid"
            )
            self._assert_rejected(
                _plan_inactive(updater_state_root=bad),
                "updater-state-root-invalid",
            )
            legacy = layout.plan_legacy_checkout_layout(bad)
            self.assertEqual(
                legacy["reason"], "unsupported:checkout-root-invalid"
            )
        nbsp = _plan_inactive(install_root="/opt/synapse\u00a0install")
        self.assertEqual(nbsp["status"], "planned")

    def test_str_subclasses_are_rejected_as_impure(self) -> None:
        class SneakyPath(str):
            pass

        self._assert_rejected(
            _plan_inactive(install_root=SneakyPath(INSTALL_ROOT)),
            "install-root-invalid",
        )
        self._assert_rejected(
            _plan_inactive(product_id=SneakyPath(PRODUCT_ID)),
            "product-id-invalid",
        )
        legacy = layout.plan_legacy_checkout_layout(
            SneakyPath(LEGACY_CHECKOUT)
        )
        self.assertEqual(
            legacy["reason"], "unsupported:checkout-root-invalid"
        )

    def test_each_root_is_validated_with_its_own_token(self) -> None:
        for override, token in (
            ({"environment_root": "env"}, "environment-root-invalid"),
            ({"data_root": "data"}, "data-root-invalid"),
            (
                {"updater_state_root": "state"},
                "updater-state-root-invalid",
            ),
            (
                {"legacy_checkout_root": "old"},
                "legacy-checkout-root-invalid",
            ),
        ):
            self._assert_rejected(_plan_inactive(**override), token)

    def test_bad_identities_fail_closed(self) -> None:
        for bad in (
            "product-" + "g" * 64,
            "product-" + "A" * 64,
            "product-" + "0" * 63,
            "component-" + "0" * 64,
            "product-",
            "",
            None,
            17,
        ):
            self._assert_rejected(
                _plan_inactive(product_id=bad), "product-id-invalid"
            )
        for bad in (
            "inventory-policy-" + "0" * 63,
            "inventory-policy-" + "A" * 64,
            "policy",
            None,
        ):
            self._assert_rejected(
                _plan_inactive(inventory_policy_id=bad),
                "inventory-policy-id-invalid",
            )

    def test_forbidden_active_components_are_rejected(self) -> None:
        self._assert_rejected(
            _plan_inactive(install_root="/opt/recovery/synapse"),
            "install-root-forbidden-component",
        )
        self._assert_rejected(
            _plan_inactive(
                environment_root="/opt/other/.synapse_s2/env"
            ),
            "environment-root-forbidden-component",
        )
        self._assert_rejected(
            _plan_inactive(
                updater_state_root="/opt/LaunchAgents/updater"
            ),
            "updater-state-root-forbidden-component",
        )
        self._assert_rejected(
            _plan_inactive(
                legacy_checkout_root="/Users/operator/LaunchDaemons"
            ),
            "legacy-checkout-root-forbidden-component",
        )
        legacy = layout.plan_legacy_checkout_layout(
            "/Users/operator/.synapse_s2/checkout"
        )
        self.assertEqual(
            legacy["reason"],
            "unsupported:checkout-root-forbidden-component",
        )

    def test_selector_components_are_rejected_everywhere(self) -> None:
        self._assert_rejected(
            _plan_inactive(install_root="/opt/current"),
            "install-root-selector-component",
        )
        self._assert_rejected(
            _plan_inactive(environment_root="/opt/envs/latest"),
            "environment-root-selector-component",
        )
        self._assert_rejected(
            _plan_inactive(data_root="/private/var/Current/data"),
            "data-root-selector-component",
        )
        self._assert_rejected(
            _plan_inactive(updater_state_root="/opt/state/LATEST"),
            "updater-state-root-selector-component",
        )
        legacy = layout.plan_legacy_checkout_layout("/Users/op/current")
        self.assertEqual(
            legacy["reason"], "unsupported:checkout-root-selector-component"
        )

    def test_darwin_aliased_spellings_are_rejected(self) -> None:
        self._assert_rejected(
            _plan_inactive(install_root="/tmp/synapse-install"),
            "install-root-aliased-spelling",
        )
        self._assert_rejected(
            _plan_inactive(environment_root="/var/synapse-env"),
            "environment-root-aliased-spelling",
        )
        self._assert_rejected(
            _plan_inactive(data_root="/etc/synapse-data"),
            "data-root-aliased-spelling",
        )
        self._assert_rejected(
            _plan_inactive(updater_state_root="/TMP/updater"),
            "updater-state-root-aliased-spelling",
        )
        legacy = layout.plan_legacy_checkout_layout("/tmp/checkout")
        self.assertEqual(
            legacy["reason"], "unsupported:checkout-root-aliased-spelling"
        )
        # The unambiguous /private/... spellings stay accepted.
        self.assertEqual(
            _plan_inactive(data_root=EXTERNAL_DATA_ROOT)["status"],
            "planned",
        )

    def test_install_root_owns_only_the_release_root(self) -> None:
        self._assert_rejected(
            _plan_inactive(environment_root=INSTALL_ROOT + "/env"),
            "install-root-overlap",
        )
        self._assert_rejected(
            _plan_inactive(environment_root=INSTALL_ROOT + "/releases"),
            "install-root-overlap",
        )
        self._assert_rejected(
            _plan_inactive(data_root="/opt/Synapse-S2"),
            "install-root-overlap",
        )
        self._assert_rejected(
            _plan_inactive(updater_state_root=INSTALL_ROOT + "/state"),
            "install-root-overlap",
        )
        self._assert_rejected(
            _plan_inactive(updater_state_root="/opt"),
            "install-root-overlap",
        )

    def test_root_overlaps_and_aliases_fail_closed(self) -> None:
        self._assert_rejected(
            _plan_inactive(
                updater_state_root=ENVIRONMENT_ROOT + "/state"
            ),
            "root-overlap",
        )
        self._assert_rejected(
            _plan_inactive(
                data_root=EXTERNAL_DATA_ROOT,
                updater_state_root="/private/VAR/synapse-s2/DATA",
            ),
            "root-overlap",
        )
        self._assert_rejected(
            _plan_inactive(
                environment_root="/opt/Synapse-S2-Updater-State"
            ),
            "root-overlap",
        )

    def test_new_roots_may_never_touch_the_legacy_checkout(self) -> None:
        self._assert_rejected(
            _plan_inactive(
                environment_root=LEGACY_CHECKOUT + "/env"
            ),
            "legacy-checkout-overlap",
        )
        self._assert_rejected(
            _plan_inactive(
                updater_state_root="/users/OPERATOR/synapse-s2/state",
            ),
            "legacy-checkout-overlap",
        )
        self._assert_rejected(
            _plan_inactive(install_root=LEGACY_CHECKOUT + "/install"),
            "legacy-checkout-overlap",
        )
        # Even an install root that merely contains the old checkout is
        # rejected: install_root must be fully disjoint from legacy.
        self._assert_rejected(
            _plan_inactive(install_root="/Users/operator"),
            "legacy-checkout-overlap",
        )
        sibling = _plan_inactive(install_root="/Users/operator-installs")
        self.assertEqual(sibling["status"], "planned")

    def test_retained_data_root_must_be_exactly_dot_synapse_s2(self) -> None:
        for bad in (
            LEGACY_CHECKOUT,
            "/Users/operator",
            LEGACY_CHECKOUT + "/.synapse_s2/memory",
            LEGACY_CHECKOUT + "/data",
            "/users/operator/synapse-s2/.synapse_s2",
            LEGACY_CHECKOUT + "/.SYNAPSE_S2",
        ):
            self._assert_rejected(
                _plan_inactive(data_root=bad),
                "legacy-data-root-not-canonical",
            )

    def test_oversized_derived_paths_fail_closed(self) -> None:
        long_install = "/" + "a" * 4090
        self._assert_rejected(
            _plan_inactive(install_root=long_install),
            "derived-path-invalid",
        )
        long_checkout = "/" + "a" * 4090
        legacy = layout.plan_legacy_checkout_layout(long_checkout)
        self.assertEqual(
            legacy["reason"], "unsupported:derived-path-invalid"
        )


class StageResultShapeTests(unittest.TestCase):
    def _assert_rejected(self, stage_result: object, token: str) -> None:
        plan = _plan_inactive(stage_result=stage_result)
        self.assertEqual(plan["status"], "unsupported")
        self.assertEqual(plan["reason"], "unsupported:" + token)
        self.assertIs(plan["stage_associated"], False)

    def test_non_dict_and_open_keyset_fail_closed(self) -> None:
        self._assert_rejected("staged", "stage-result-shape")
        self._assert_rejected(12, "stage-result-shape")
        extra = _stage_result()
        extra["trusted"] = True
        self._assert_rejected(extra, "stage-result-shape")
        missing = _stage_result()
        del missing["journal_committed"]
        self._assert_rejected(missing, "stage-result-shape")

    def test_dict_subclasses_are_rejected_as_impure(self) -> None:
        class SneakyResult(dict):
            pass

        self._assert_rejected(
            SneakyResult(_stage_result()), "stage-result-shape"
        )

    def test_str_subclass_keys_never_execute_hooks(self) -> None:
        # A str-subclass key must be rejected by exact-type iteration
        # before any set()/lookup can invoke its overridden
        # __hash__/__eq__ — those hooks would be arbitrary code running
        # inside the pure planner.
        invocations: list[str] = []

        class SneakyKey(str):
            def __hash__(self):
                invocations.append("hash")
                return str.__hash__(self)

            def __eq__(self, other):
                invocations.append("eq")
                return str.__eq__(self, other)

        doc = _stage_result()
        del doc["reconciled"]
        doc[SneakyKey("reconciled")] = False
        invocations.clear()
        self._assert_rejected(doc, "stage-result-shape")
        self.assertEqual(invocations, [])

    def test_wrong_schema_or_mode_fails_closed(self) -> None:
        self._assert_rejected(
            _stage_result(schema="synapse-s2.release-stage-result.v2"),
            "stage-result-schema",
        )
        self._assert_rejected(
            _stage_result(mode="candidate-active-stage"),
            "stage-result-schema",
        )

    def test_unsuccessful_statuses_fail_closed(self) -> None:
        self._assert_rejected(
            _stage_result(status="outcome_unknown"),
            "stage-result-outcome-unknown",
        )
        self._assert_rejected(
            _stage_result(status="unsupported"),
            "stage-result-not-successful",
        )
        self._assert_rejected(
            _stage_result(status="active"), "stage-result-not-successful"
        )
        self._assert_rejected(
            _stage_result(status=None), "stage-result-shape"
        )

    def test_already_staged_is_an_accepted_completed_status(self) -> None:
        plan = _plan_inactive(stage_result=_already_staged_result())
        self.assertEqual(plan["status"], "planned")
        self.assertIs(plan["stage_associated"], True)

    def test_status_reason_resumed_triples_are_exact(self) -> None:
        self._assert_rejected(
            _stage_result(reason="identity-already-staged"),
            "stage-result-inconsistent",
        )
        self._assert_rejected(
            _stage_result(reason="source-staged-inactive:extra"),
            "stage-result-inconsistent",
        )
        self._assert_rejected(
            _stage_result(reason=""), "stage-result-inconsistent"
        )
        self._assert_rejected(
            _stage_result(reason=None), "stage-result-shape"
        )
        self._assert_rejected(
            _stage_result(resumed=True), "stage-result-inconsistent"
        )
        self._assert_rejected(
            _already_staged_result(resumed=False),
            "stage-result-inconsistent",
        )
        self._assert_rejected(
            _already_staged_result(reason="source-staged-inactive"),
            "stage-result-inconsistent",
        )
        self._assert_rejected(
            _stage_result(resumed=1), "stage-result-inconsistent"
        )

    def test_incomplete_stage_fails_closed(self) -> None:
        for key in (
            "source_staged",
            "identity_pin_verified",
            "journal_committed",
        ):
            self._assert_rejected(
                _stage_result(**{key: False}), "stage-result-incomplete"
            )
            self._assert_rejected(
                _stage_result(**{key: 1}), "stage-result-incomplete"
            )

    def test_stage_claiming_live_effect_fails_closed(self) -> None:
        for key in (
            "environment_stage_supported",
            "environment_built",
            "activation_supported",
            "activation_performed",
            "live_state_modified",
        ):
            self._assert_rejected(
                _stage_result(**{key: True}),
                "stage-result-claims-live-effect",
            )
            self._assert_rejected(
                _stage_result(**{key: 0}),
                "stage-result-claims-live-effect",
            )

    def test_identity_mismatch_fails_closed(self) -> None:
        self._assert_rejected(
            _stage_result(product_id="product-" + "2" * 64),
            "stage-result-identity-mismatch",
        )
        self._assert_rejected(
            _stage_result(
                inventory_policy_id="inventory-policy-" + "3" * 64
            ),
            "stage-result-identity-mismatch",
        )

    def test_tampered_nonclaims_fail_closed(self) -> None:
        shrunk = _stage_result()
        shrunk["nonclaims"] = shrunk["nonclaims"][:-1]
        self._assert_rejected(shrunk, "stage-result-nonclaims")
        reordered = _stage_result()
        reordered["nonclaims"] = list(reversed(reordered["nonclaims"]))
        self._assert_rejected(reordered, "stage-result-nonclaims")
        tupled = _stage_result()
        tupled["nonclaims"] = tuple(tupled["nonclaims"])
        self._assert_rejected(tupled, "stage-result-nonclaims")
        self._assert_rejected(
            _stage_result(reconciled=1), "stage-result-shape"
        )

    def test_oversized_documents_trip_the_cardinality_gate(self) -> None:
        # The validator checks len(document) == len(STAGE_RESULT_KEYS)
        # before touching a single key, so an arbitrarily bloated
        # document is rejected without being scanned.
        bloated = _stage_result()
        for index in range(10_000):
            bloated["padding-" + str(index)] = False
        self._assert_rejected(bloated, "stage-result-shape")
        # Same cardinality, wrong keyset: the exact-set gate still fires.
        swapped = _stage_result()
        del swapped["reconciled"]
        swapped["trusted"] = True
        self._assert_rejected(swapped, "stage-result-shape")

    def test_oversized_documents_never_execute_key_hooks(self) -> None:
        invocations: list[str] = []

        class SneakyKey(str):
            def __hash__(self):
                invocations.append("hash")
                return str.__hash__(self)

            def __eq__(self, other):
                invocations.append("eq")
                return str.__eq__(self, other)

        bloated = _stage_result()
        for index in range(1_000):
            bloated[SneakyKey("padding-" + str(index))] = False
        invocations.clear()
        self._assert_rejected(bloated, "stage-result-shape")
        self.assertEqual(invocations, [])

    def test_oversized_nonclaims_trip_the_length_gate(self) -> None:
        # The validator checks len(nonclaims) == len(STAGE_NONCLAIMS)
        # before comparing a single entry.
        padded = _stage_result()
        padded["nonclaims"] = padded["nonclaims"] + ["no-extra"] * 10_000
        self._assert_rejected(padded, "stage-result-nonclaims")
        # Same length, duplicated entry: per-item equality still fires.
        duplicated = _stage_result()
        duplicated["nonclaims"] = (
            duplicated["nonclaims"][:-1] + [duplicated["nonclaims"][0]]
        )
        self._assert_rejected(duplicated, "stage-result-nonclaims")

    def test_str_subclass_nonclaims_never_execute_hooks(self) -> None:
        invocations: list[str] = []

        class SneakyClaim(str):
            def __hash__(self):
                invocations.append("hash")
                return str.__hash__(self)

            def __eq__(self, other):
                invocations.append("eq")
                return str.__eq__(self, other)

        doc = _stage_result()
        claims = list(doc["nonclaims"])
        claims[0] = SneakyClaim(claims[0])
        doc["nonclaims"] = claims
        invocations.clear()
        self._assert_rejected(doc, "stage-result-nonclaims")
        self.assertEqual(invocations, [])


class PurityAndVocabularyTests(unittest.TestCase):
    def test_module_imports_only_pure_stdlib(self) -> None:
        source = (ROOT / "scripts/installed_layout.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, ast.ImportFrom)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name)
            if isinstance(node, ast.Call) and isinstance(
                node.func, ast.Name
            ):
                self.assertNotIn(
                    node.func.id,
                    ("open", "eval", "exec", "compile", "__import__"),
                )
        self.assertEqual(
            imported, {"hashlib", "json", "posixpath", "re"}
        )

    def test_module_namespace_holds_no_io_machinery(self) -> None:
        for name in (
            "os",
            "sys",
            "socket",
            "subprocess",
            "sqlite3",
            "pathlib",
            "tempfile",
            "shutil",
            "open",
        ):
            self.assertFalse(hasattr(layout, name))

    def test_planning_performs_zero_io(self) -> None:
        blocked = AssertionError("forbidden side effect")

        class _Poisoned(dict):
            def __getitem__(self, key):
                raise blocked

            def get(self, key, default=None):
                raise blocked

        with (
            mock.patch.object(builtins, "open", side_effect=blocked),
            mock.patch.object(os, "open", side_effect=blocked),
            mock.patch.object(os, "stat", side_effect=blocked),
            mock.patch.object(os, "lstat", side_effect=blocked),
            mock.patch.object(os, "listdir", side_effect=blocked),
            mock.patch.object(os, "scandir", side_effect=blocked),
            mock.patch.object(os, "mkdir", side_effect=blocked),
            mock.patch.object(os, "environ", new=_Poisoned()),
            mock.patch.object(socket, "socket", side_effect=blocked),
            mock.patch.object(subprocess, "Popen", side_effect=blocked),
            mock.patch.object(subprocess, "run", side_effect=blocked),
            mock.patch.object(sqlite3, "connect", side_effect=blocked),
        ):
            self.assertEqual(
                layout.plan_legacy_checkout_layout(LEGACY_CHECKOUT)[
                    "status"
                ],
                "planned",
            )
            self.assertEqual(_plan_inactive()["status"], "planned")
            self.assertEqual(
                _plan_inactive(stage_result=_stage_result())["status"],
                "planned",
            )
            self.assertEqual(
                _plan_inactive(product_id="bogus")["status"],
                "unsupported",
            )
            self.assertEqual(
                layout.plan_legacy_checkout_layout("relative")["status"],
                "unsupported",
            )
            self.assertEqual(
                layout.installed_layout_contract_projection(
                    layout.MODE_INACTIVE_VERSIONED
                )["status"],
                "projected",
            )
            self.assertEqual(
                layout.installed_layout_contract_projection(None)[
                    "status"
                ],
                "unsupported",
            )

    def test_no_current_or_latest_selector_is_ever_modeled(self) -> None:
        plans = (
            layout.plan_legacy_checkout_layout(LEGACY_CHECKOUT),
            _plan_inactive(),
            _plan_inactive(stage_result=_stage_result()),
        )
        for plan in plans:
            values = list(plan.values()) + list(
                (plan["adapters"] or {}).values()
            )
            for value in values:
                if not isinstance(value, str):
                    continue
                for component in value.split("/"):
                    self.assertNotIn(
                        component.casefold(), ("current", "latest")
                    )
        source = (ROOT / "scripts/installed_layout.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('"/current"', source)
        self.assertNotIn('"/latest"', source)

    def test_result_keyset_is_closed_and_stable(self) -> None:
        legacy = layout.plan_legacy_checkout_layout(LEGACY_CHECKOUT)
        inactive = _plan_inactive()
        rejected = _plan_inactive(product_id="bogus")
        self.assertEqual(set(legacy), set(inactive))
        self.assertEqual(set(legacy), set(rejected))
        self.assertIn("install_root", legacy)
        self.assertIn("layout_contract_id", legacy)


PROJECTION_KEYS = frozenset(
    (
        "schema",
        "plan_schema",
        "status",
        "reason",
        "layout_contract_id",
        "mode",
        "root_roles",
        "adapters",
        "policies",
        "path_policy",
        "identity_policy",
        "stage_result_policy",
        "always_false_flags",
        "nonclaims",
    )
)


class ContractProjectionTests(unittest.TestCase):
    def test_projection_is_deterministic_and_well_formed(self) -> None:
        identity = re.compile(r"\Alayout-contract-[0-9a-f]{64}\Z")
        for mode in (
            layout.MODE_LEGACY_CHECKOUT,
            layout.MODE_INACTIVE_VERSIONED,
        ):
            first = layout.installed_layout_contract_projection(mode)
            second = layout.installed_layout_contract_projection(mode)
            self.assertEqual(first, second)
            self.assertIsNot(first, second)
            self.assertEqual(set(first), set(PROJECTION_KEYS))
            self.assertEqual(
                first["schema"], "synapse-s2.installed-layout-contract.v1"
            )
            self.assertEqual(
                first["plan_schema"],
                "synapse-s2.installed-layout-plan.v1",
            )
            self.assertEqual(first["status"], "projected")
            self.assertRegex(first["layout_contract_id"], identity)
            self.assertEqual(
                first["policies"]["separation_policy"], "lexical-only"
            )
            self.assertEqual(
                first["always_false_flags"], list(FALSE_FLAGS)
            )
            self.assertEqual(first["nonclaims"], list(layout.NONCLAIMS))
            # Mutating one returned document must not leak into the next.
            first["adapters"].append(["evil", "code", "evil.py"])
            first["policies"]["separation_policy"] = "physical"
            first["path_policy"]["max_path_bytes"] = 1
            first["stage_result_policy"]["nonclaims"].append("no-honesty")
            third = layout.installed_layout_contract_projection(mode)
            self.assertEqual(third, second)

    def test_projection_policy_blocks_restate_the_real_constants(self) -> None:
        projection = layout.installed_layout_contract_projection(
            layout.MODE_INACTIVE_VERSIONED
        )
        path_policy = projection["path_policy"]
        self.assertEqual(
            path_policy["max_path_bytes"], layout.MAX_PATH_BYTES
        )
        self.assertEqual(path_policy["max_path_bytes"], 4096)
        self.assertEqual(
            path_policy["rejected_codepoint_ranges"],
            [[0, 31], [127, 159]],
        )
        self.assertEqual(
            path_policy["forbidden_active_components"],
            sorted(layout._FORBIDDEN_ACTIVE_COMPONENTS),
        )
        self.assertEqual(
            path_policy["forbidden_selector_components"],
            ["current", "latest"],
        )
        self.assertEqual(
            path_policy["darwin_aliased_first_components"],
            ["etc", "tmp", "var"],
        )
        self.assertEqual(
            path_policy["legacy_data_exception"],
            "data_root == <legacy_checkout_root>/"
            + layout.LEGACY_DATA_DIRECTORY,
        )
        self.assertEqual(
            path_policy["release_root_derivation"],
            "<install_root>/"
            + layout.RELEASES_DIRECTORY_NAME
            + "/<product_id>",
        )
        self.assertEqual(
            path_policy["legacy_environment_directory"],
            layout.LEGACY_ENVIRONMENT_DIRECTORY,
        )
        self.assertIs(path_policy["derived_paths_revalidated"], True)
        identity_policy = projection["identity_policy"]
        self.assertEqual(
            identity_policy["product_id_grammar"],
            layout._PRODUCT_ID_RE.pattern,
        )
        self.assertEqual(
            identity_policy["inventory_policy_id_grammar"],
            layout._POLICY_ID_RE.pattern,
        )
        for flags_key, live_pattern in (
            ("product_id_grammar_flags", layout._PRODUCT_ID_RE),
            ("inventory_policy_id_grammar_flags", layout._POLICY_ID_RE),
        ):
            bound_flags = identity_policy[flags_key]
            self.assertIs(type(bound_flags), int)
            self.assertEqual(bound_flags, int(live_pattern.flags))
            # Case-sensitive grammar: only the automatic UNICODE flag.
            self.assertEqual(bound_flags, int(re.UNICODE))
            self.assertEqual(bound_flags & re.IGNORECASE, 0)
        self.assertEqual(identity_policy["hash_algorithm"], "sha256")
        self.assertEqual(
            identity_policy["layout_contract_id_domain"],
            "SYNAPSE-S2\x00INSTALLED-LAYOUT-CONTRACT\x00v1\x00",
        )
        self.assertEqual(
            identity_policy["layout_id_domain"],
            "SYNAPSE-S2\x00INSTALLED-LAYOUT-PLAN\x00v1\x00",
        )
        stage_policy = projection["stage_result_policy"]
        self.assertEqual(
            stage_policy["schema"], layout.STAGE_RESULT_SCHEMA
        )
        self.assertEqual(stage_policy["mode"], layout.STAGE_RESULT_MODE)
        self.assertEqual(
            stage_policy["keys"], sorted(layout.STAGE_RESULT_KEYS)
        )
        self.assertEqual(
            stage_policy["string_keys"],
            list(layout._STAGE_RESULT_STRING_KEYS),
        )
        self.assertEqual(
            stage_policy["accepted_outcomes"],
            [
                {
                    "status": "staged",
                    "reason": "source-staged-inactive",
                    "resumed": False,
                },
                {
                    "status": "already-staged",
                    "reason": "identity-already-staged",
                    "resumed": True,
                },
            ],
        )
        self.assertEqual(
            stage_policy["rejected_statuses"], ["outcome_unknown"]
        )
        self.assertEqual(
            stage_policy["required_true_keys"],
            list(layout._STAGE_REQUIRED_TRUE_KEYS),
        )
        self.assertEqual(
            stage_policy["required_false_keys"],
            list(layout._STAGE_REQUIRED_FALSE_KEYS),
        )
        self.assertEqual(
            stage_policy["nonclaims"], list(layout.STAGE_NONCLAIMS)
        )
        self.assertEqual(
            stage_policy["association_policy"], "shape-only-untrusted"
        )
        legacy = layout.installed_layout_contract_projection(
            layout.MODE_LEGACY_CHECKOUT
        )
        versioned = layout.installed_layout_contract_projection(
            layout.MODE_INACTIVE_VERSIONED
        )
        self.assertNotEqual(
            legacy["layout_contract_id"], versioned["layout_contract_id"]
        )
        self.assertEqual(
            legacy["root_roles"],
            [
                "code_root",
                "environment_root",
                "data_root",
                "legacy_checkout_root",
            ],
        )
        self.assertEqual(
            versioned["root_roles"],
            [
                "install_root",
                "code_root",
                "environment_root",
                "data_root",
                "release_root",
                "updater_state_root",
                "legacy_checkout_root",
            ],
        )

    def test_projection_contains_no_host_paths(self) -> None:
        def _walk(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict):
                for key, item in value.items():
                    yield from _walk(key)
                    yield from _walk(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    yield from _walk(item)

        for mode in (
            layout.MODE_LEGACY_CHECKOUT,
            layout.MODE_INACTIVE_VERSIONED,
        ):
            projection = layout.installed_layout_contract_projection(mode)
            for text in _walk(projection):
                self.assertFalse(text.startswith("/"))
            dumped = json.dumps(projection)
            for host_path in (
                LEGACY_CHECKOUT,
                INSTALL_ROOT,
                ENVIRONMENT_ROOT,
                UPDATER_STATE_ROOT,
            ):
                self.assertNotIn(host_path, dumped)

    def test_plans_carry_the_matching_contract_id(self) -> None:
        legacy_projection = layout.installed_layout_contract_projection(
            layout.MODE_LEGACY_CHECKOUT
        )
        versioned_projection = layout.installed_layout_contract_projection(
            layout.MODE_INACTIVE_VERSIONED
        )
        legacy_plan = layout.plan_legacy_checkout_layout(LEGACY_CHECKOUT)
        self.assertEqual(
            legacy_plan["layout_contract_id"],
            legacy_projection["layout_contract_id"],
        )
        for plan in (
            _plan_inactive(),
            _plan_inactive(data_root=EXTERNAL_DATA_ROOT),
            _plan_inactive(install_root="/opt/synapse-s2-b"),
        ):
            self.assertEqual(
                plan["layout_contract_id"],
                versioned_projection["layout_contract_id"],
            )
        # Host-independence: entirely different host roots, same contract.
        other_host = layout.plan_legacy_checkout_layout(
            "/Users/someone-else/Checkouts/SYNAPSE-S2"
        )
        self.assertEqual(
            other_host["layout_contract_id"],
            legacy_projection["layout_contract_id"],
        )
        self.assertNotEqual(
            other_host["layout_id"], legacy_plan["layout_id"]
        )

    def test_layout_id_binds_the_contract_id(self) -> None:
        # Recompute the legacy layout identity by hand: the binding
        # payload must include the contract identity, so a compatibility
        # ticket bound to the contract survives host renames while the
        # host layout_id still commits to the exact contract.
        plan = layout.plan_legacy_checkout_layout(LEGACY_CHECKOUT)
        binding = {
            "schema": "synapse-s2.installed-layout-plan.v1",
            "mode": "legacy-checkout-v1",
            "layout_contract_id": plan["layout_contract_id"],
            "product_id": None,
            "inventory_policy_id": None,
            "install_root": None,
            "code_root": LEGACY_CHECKOUT,
            "environment_root": LEGACY_CHECKOUT + "/.venv",
            "data_root": LEGACY_CHECKOUT + "/.synapse_s2",
            "release_root": None,
            "updater_state_root": None,
            "legacy_checkout_root": LEGACY_CHECKOUT,
            "adapters": plan["adapters"],
        }
        canonical = json.dumps(
            binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        expected = "layout-" + hashlib.sha256(
            b"SYNAPSE-S2\x00INSTALLED-LAYOUT-PLAN\x00v1\x00"
            + canonical.encode("ascii")
        ).hexdigest()
        self.assertEqual(plan["layout_id"], expected)

    def test_unsupported_plans_carry_no_contract_id(self) -> None:
        rejected = _plan_inactive(product_id="bogus")
        self.assertEqual(rejected["status"], "unsupported")
        self.assertIsNone(rejected["layout_contract_id"])
        legacy = layout.plan_legacy_checkout_layout("relative")
        self.assertIsNone(legacy["layout_contract_id"])

    def test_invalid_modes_fail_closed_without_hook_execution(self) -> None:
        invocations: list[str] = []

        class SneakyMode(str):
            def __hash__(self):
                invocations.append("hash")
                return str.__hash__(self)

            def __eq__(self, other):
                invocations.append("eq")
                return str.__eq__(self, other)

        for bad in (
            None,
            7,
            b"legacy-checkout-v1",
            "legacy-checkout-v2",
            "",
            SneakyMode("legacy-checkout-v1"),
        ):
            projection = layout.installed_layout_contract_projection(bad)
            self.assertEqual(set(projection), set(PROJECTION_KEYS))
            self.assertEqual(projection["status"], "unsupported")
            self.assertEqual(
                projection["reason"], "unsupported:mode-invalid"
            )
            self.assertIsNone(projection["layout_contract_id"])
            self.assertIsNone(projection["mode"])
            self.assertIsNone(projection["root_roles"])
            self.assertIsNone(projection["adapters"])
            self.assertIsNone(projection["policies"])
            self.assertIsNone(projection["path_policy"])
            self.assertIsNone(projection["identity_policy"])
            self.assertIsNone(projection["stage_result_policy"])
            self.assertEqual(
                projection["always_false_flags"], list(FALSE_FLAGS)
            )
            self.assertEqual(
                projection["nonclaims"], list(layout.NONCLAIMS)
            )
        self.assertEqual(invocations, [])


class ContractBindingMutationTests(unittest.TestCase):
    """Every enforcement constant must perturb layout_contract_id.

    Each case loads a private copy of the module, monkeypatches exactly
    one constant, and proves the contract identity moves in both modes:
    the id binds the behavioural constants themselves, not labels.
    """

    MUTATIONS = (
        ("MAX_PATH_BYTES", 1024),
        (
            "ADAPTERS",
            (("python-interpreter", "environment", "bin/python"),),
        ),
        ("NONCLAIMS", ("no-activation",)),
        ("_ALWAYS_FALSE_FLAGS", ("activation_supported",)),
        (
            "_FORBIDDEN_ACTIVE_COMPONENTS",
            frozenset((".synapse_s2", "recovery", "launchagents")),
        ),
        (
            "_FORBIDDEN_SELECTOR_COMPONENTS",
            frozenset(("current", "latest", "stable")),
        ),
        ("_DARWIN_ALIASED_FIRST_COMPONENTS", frozenset(("tmp", "var"))),
        ("RELEASES_DIRECTORY_NAME", "channels"),
        ("LEGACY_ENVIRONMENT_DIRECTORY", ".virtualenv"),
        ("LEGACY_DATA_DIRECTORY", ".synapse_s2_data"),
        ("STAGE_RESULT_SCHEMA", "synapse-s2.release-stage-result.v2"),
        ("STAGE_RESULT_MODE", "candidate-active-stage"),
        ("STAGE_STATUS_STAGED", "staged-v2"),
        ("STAGE_STATUS_ALREADY_STAGED", "already-staged-v2"),
        ("STAGE_STATUS_OUTCOME_UNKNOWN", "unknown"),
        ("STAGE_REASON_STAGED", "source-staged-active"),
        ("STAGE_REASON_ALREADY_STAGED", "identity-re-staged"),
        ("STAGE_NONCLAIMS", ("no-activation",)),
        ("STAGE_RESULT_KEYS", frozenset(("schema",))),
        ("_STAGE_RESULT_STRING_KEYS", ("schema",)),
        ("_STAGE_REQUIRED_TRUE_KEYS", ("source_staged",)),
        ("_STAGE_REQUIRED_FALSE_KEYS", ("environment_built",)),
        ("STAGE_ASSOCIATION_SHAPE_ONLY", "shape-only-trusted"),
        ("_PRODUCT_ID_RE", re.compile(r"\Aproduct-[0-9a-f]{32}\Z")),
        (
            "_POLICY_ID_RE",
            re.compile(r"\Ainventory-policy-[0-9a-f]{32}\Z"),
        ),
        (
            "_PRODUCT_ID_RE",
            re.compile(r"\Aproduct-[0-9a-f]{64}\Z", re.IGNORECASE),
        ),
        (
            "_POLICY_ID_RE",
            re.compile(
                r"\Ainventory-policy-[0-9a-f]{64}\Z", re.IGNORECASE
            ),
        ),
    )

    MODES = ("legacy-checkout-v1", "inactive-versioned-v1")

    def _canonical_ids(self) -> dict:
        return {
            mode: layout.installed_layout_contract_projection(mode)[
                "layout_contract_id"
            ]
            for mode in self.MODES
        }

    def test_pristine_reload_reproduces_the_canonical_ids(self) -> None:
        # Determinism control: an unmutated private copy of the module
        # must reproduce the shared module's contract ids exactly.
        pristine = _load(
            "test_installed_layout_pristine_copy",
            ROOT / "scripts/installed_layout.py",
        )
        for mode, canonical in self._canonical_ids().items():
            self.assertEqual(
                pristine.installed_layout_contract_projection(mode)[
                    "layout_contract_id"
                ],
                canonical,
            )

    def test_every_enforcement_constant_perturbs_the_contract_id(
        self,
    ) -> None:
        canonical_ids = self._canonical_ids()
        for attribute, mutated in self.MUTATIONS:
            with self.subTest(attribute=attribute):
                private = _load(
                    "test_installed_layout_mutated_copy",
                    ROOT / "scripts/installed_layout.py",
                )
                # The mutation must actually change the constant.
                self.assertNotEqual(getattr(private, attribute), mutated)
                setattr(private, attribute, mutated)
                for mode, canonical in canonical_ids.items():
                    perturbed = (
                        private.installed_layout_contract_projection(mode)
                    )
                    self.assertEqual(perturbed["status"], "projected")
                    self.assertNotEqual(
                        perturbed["layout_contract_id"], canonical
                    )

    def test_contract_ids_are_stable_across_hash_seeds(self) -> None:
        # Frozensets feed the hashed payload only through sorted();
        # recompute the ids in child interpreters under two different
        # fixed hash seeds to prove no set-iteration order leaks in.
        code = (
            "import importlib.util, sys\n"
            "spec = importlib.util.spec_from_file_location("
            "'il', sys.argv[1])\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "for mode in sys.argv[2:]:\n"
            "    print(module.installed_layout_contract_projection("
            "mode)['layout_contract_id'])\n"
        )
        expected = [self._canonical_ids()[mode] for mode in self.MODES]
        for seed in ("0", "1"):
            environment = dict(os.environ)
            environment["PYTHONHASHSEED"] = seed
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    code,
                    str(ROOT / "scripts/installed_layout.py"),
                    *self.MODES,
                ],
                capture_output=True,
                text=True,
                env=environment,
                check=True,
            )
            self.assertEqual(completed.stdout.split(), expected)


class PlannerAndStageCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.planner = _load(
            "test_installed_layout_planner",
            ROOT / "scripts/release_update_plan.py",
        )
        cls.stage = _load(
            "test_installed_layout_stage",
            ROOT / "scripts/release_stage.py",
        )

    def test_stage_shape_constants_match_the_real_stager(self) -> None:
        self.assertEqual(
            layout.STAGE_RESULT_SCHEMA, self.stage.RESULT_SCHEMA
        )
        self.assertEqual(layout.STAGE_RESULT_MODE, self.stage.RESULT_MODE)
        self.assertEqual(
            layout.STAGE_STATUS_STAGED, self.stage.STATUS_STAGED
        )
        self.assertEqual(
            layout.STAGE_STATUS_ALREADY_STAGED,
            self.stage.STATUS_ALREADY_STAGED,
        )
        self.assertEqual(
            layout.STAGE_STATUS_OUTCOME_UNKNOWN,
            self.stage.STATUS_OUTCOME_UNKNOWN,
        )
        self.assertEqual(
            tuple(layout.STAGE_NONCLAIMS), tuple(self.stage.NONCLAIMS)
        )
        stage_source = (ROOT / "scripts/release_stage.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"' + layout.STAGE_REASON_STAGED + '"', stage_source)
        self.assertIn(
            '"' + layout.STAGE_REASON_ALREADY_STAGED + '"', stage_source
        )

    def test_real_stager_success_documents_associate(self) -> None:
        staged = self.stage._result(
            self.stage.STATUS_STAGED,
            layout.STAGE_REASON_STAGED,
            PRODUCT_ID,
            POLICY_ID,
            source_staged=True,
            journal_committed=True,
        )
        self.assertEqual(set(staged), set(layout.STAGE_RESULT_KEYS))
        plan = _plan_inactive(stage_result=staged)
        self.assertEqual(plan["status"], "planned")
        self.assertIs(plan["stage_associated"], True)
        self.assertEqual(plan["stage_association"], "shape-only-untrusted")
        resumed = self.stage._result(
            self.stage.STATUS_ALREADY_STAGED,
            layout.STAGE_REASON_ALREADY_STAGED,
            PRODUCT_ID,
            POLICY_ID,
            source_staged=True,
            resumed=True,
            journal_committed=True,
        )
        plan = _plan_inactive(stage_result=resumed)
        self.assertEqual(plan["status"], "planned")
        self.assertIs(plan["stage_associated"], True)

    def test_real_stager_failure_documents_never_associate(self) -> None:
        unsupported = self.stage._result(
            self.stage.STATUS_UNSUPPORTED,
            "unsupported:activation-requested",
            None,
            None,
        )
        plan = _plan_inactive(stage_result=unsupported)
        self.assertEqual(plan["status"], "unsupported")
        unknown = self.stage._result(
            self.stage.STATUS_OUTCOME_UNKNOWN,
            "outcome_unknown:journal-append",
            PRODUCT_ID,
            POLICY_ID,
        )
        plan = _plan_inactive(stage_result=unknown)
        self.assertEqual(
            plan["reason"], "unsupported:stage-result-outcome-unknown"
        )

    def test_release_root_matches_stager_publish_destination(self) -> None:
        plan = _plan_inactive()
        self.assertEqual(layout.RELEASES_DIRECTORY_NAME, "releases")
        self.assertEqual(
            plan["release_root"],
            INSTALL_ROOT + "/releases/" + PRODUCT_ID,
        )
        stage_source = (ROOT / "scripts/release_stage.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('install_path + "/releases/" + product_id', stage_source)

    def test_planner_inventory_binds_the_layout_contract(self) -> None:
        self.assertIn(
            (
                "operator-scripts",
                "operator-script",
                "scripts/installed_layout.py",
            ),
            self.planner.PRODUCT_INVENTORY,
        )
        self.assertIn(
            ("tests", "test", "tests/test_installed_layout.py"),
            self.planner.PRODUCT_INVENTORY,
        )
        self.assertIn(
            ("mcp", "code", "mcp_client_wrapper.py"),
            self.planner.PRODUCT_INVENTORY,
        )
        self.assertIn(
            ("mcp", "code", "mcp_server.py"),
            self.planner.PRODUCT_INVENTORY,
        )

    def test_planned_roots_pass_the_real_stagers_separation_gate(self) -> None:
        # Direct composition against the trusted stager's lexical
        # separation validator: a plan's roots, together with clean
        # incumbent/candidate source snapshots, must be accepted as-is.
        # This pins planner and stager against drifting apart.
        plan = _plan_inactive()
        self.assertEqual(plan["status"], "planned")
        current = "/Users/operator/synapse-s2-current-snapshot"
        candidate = "/Users/operator/synapse-s2-candidate-snapshot"
        self.stage._validate_separation(
            (
                current,
                candidate,
                plan["install_root"],
                plan["environment_root"],
                plan["data_root"],
                plan["updater_state_root"],
            )
        )
        # Counterexample documenting the clean-snapshot requirement: the
        # live legacy checkout as current source overlaps the retained
        # data root and the stager fails closed.
        with self.assertRaises(self.stage._Blocked):
            self.stage._validate_separation(
                (
                    LEGACY_CHECKOUT,
                    candidate,
                    plan["install_root"],
                    plan["environment_root"],
                    plan["data_root"],
                    plan["updater_state_root"],
                )
            )

    def test_layout_accepts_the_planners_inventory_policy_id(self) -> None:
        policy = self.planner._inventory_policy_id()
        plan = _plan_inactive(
            inventory_policy_id=policy,
            stage_result=_stage_result(inventory_policy_id=policy),
        )
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["inventory_policy_id"], policy)


if __name__ == "__main__":
    unittest.main()

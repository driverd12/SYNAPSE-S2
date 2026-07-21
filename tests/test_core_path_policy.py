from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from core_path_policy import CorePathPolicy, CorePathPolicyError


class CorePathPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.roots: dict[str, Path] = {}
        for name in ("export", "backup", "recovery", "capture"):
            root = self.base / name
            root.mkdir(mode=0o700)
            root.chmod(0o700)
            self.roots[name] = root
        self.policy = CorePathPolicy(
            export_root=self.roots["export"],
            backup_root=self.roots["backup"],
            recovery_root=self.roots["recovery"],
            capture_root=self.roots["capture"],
        )

    @staticmethod
    def private_file(path: Path, payload: bytes = b"evidence") -> Path:
        path.write_bytes(payload)
        path.chmod(0o600)
        return path

    def test_existing_private_input_is_canonical_bounded_and_revalidatable(self) -> None:
        directory = self.roots["recovery"] / "bundle"
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
        receipt = self.private_file(directory / "receipt.json")

        authorization = self.policy.authorize_recovery_input(receipt)

        self.assertEqual(authorization.path, receipt)
        self.assertEqual(os.fspath(authorization), str(receipt))
        self.assertTrue(authorization.target_exists)
        authorization.assert_stable()

    def test_existing_input_rejects_escape_symlinks_hardlinks_and_public_mode(self) -> None:
        outside = self.private_file(self.base / "outside.json")
        with self.assertRaises(CorePathPolicyError):
            self.policy.authorize_recovery_input(outside)
        with self.assertRaises(CorePathPolicyError):
            self.policy.authorize_recovery_input(
                self.roots["recovery"] / ".." / "outside.json"
            )

        private = self.private_file(self.roots["recovery"] / "private.json")
        hardlink = self.roots["recovery"] / "hardlink.json"
        os.link(private, hardlink)
        with self.assertRaises(CorePathPolicyError):
            self.policy.authorize_recovery_input(private)

        public = self.private_file(self.roots["recovery"] / "public.json")
        public.chmod(0o644)
        with self.assertRaises(CorePathPolicyError):
            self.policy.authorize_recovery_input(public)

        real_directory = self.roots["recovery"] / "real"
        real_directory.mkdir(mode=0o700)
        real_directory.chmod(0o700)
        nested = self.private_file(real_directory / "nested.json")
        linked_directory = self.roots["recovery"] / "linked"
        linked_directory.symlink_to(real_directory, target_is_directory=True)
        with self.assertRaises(CorePathPolicyError):
            self.policy.authorize_recovery_input(linked_directory / nested.name)

    def test_future_output_allows_one_missing_leaf_without_creating_it(self) -> None:
        directory = self.roots["export"] / "daily"
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
        output = directory / "memory.json"

        authorization = self.policy.authorize_export_output(output)

        self.assertEqual(authorization.path, output)
        self.assertEqual(authorization.existing_ancestor, directory)
        self.assertFalse(authorization.target_exists)
        self.assertFalse(output.exists())
        authorization.assert_stable()

    def test_future_output_rejects_missing_parent_components(self) -> None:
        output = self.roots["export"] / "missing" / "memory.json"

        with self.assertRaises(CorePathPolicyError):
            self.policy.authorize_export_output(output)

        self.assertFalse(output.parent.exists())

    def test_future_output_requires_lexical_containment(self) -> None:
        with self.assertRaises(CorePathPolicyError):
            self.policy.authorize_export_output(self.base / "outside.json")
        with self.assertRaises(CorePathPolicyError):
            self.policy.authorize_export_output(
                self.roots["export"] / ".." / "outside.json"
            )

    def test_future_output_rejects_replacement_by_default(self) -> None:
        output = self.private_file(self.roots["backup"] / "memory.sqlite3")

        with self.assertRaises(CorePathPolicyError):
            self.policy.authorize_backup_output(output)

        governed = self.policy.authorize_backup_output(
            output,
            allow_replacement=True,
        )
        self.assertTrue(governed.target_exists)
        self.assertTrue(governed.replacement_allowed)
        governed.assert_stable()

    def test_future_output_rejects_existing_symlink_component(self) -> None:
        real_directory = self.roots["export"] / "real"
        real_directory.mkdir(mode=0o700)
        real_directory.chmod(0o700)
        linked_directory = self.roots["export"] / "linked"
        linked_directory.symlink_to(real_directory, target_is_directory=True)

        with self.assertRaises(CorePathPolicyError):
            self.policy.authorize_export_output(linked_directory / "memory.json")

    def test_authorization_detects_replaced_existing_ancestor(self) -> None:
        directory = self.roots["recovery"] / "restore"
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
        output = directory / "memory.sqlite3"
        authorization = self.policy.authorize_recovery_output(output)

        retired = self.roots["recovery"] / "restore-retired"
        directory.rename(retired)
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)

        with self.assertRaises(CorePathPolicyError):
            authorization.assert_stable()

    def test_existing_input_fd_remains_bound_after_leaf_replacement(self) -> None:
        receipt = self.private_file(
            self.roots["recovery"] / "receipt.json",
            b"trusted-receipt",
        )
        authorization = self.policy.authorize_recovery_input(receipt)

        retired = receipt.with_name("receipt.retired.json")
        receipt.rename(retired)
        self.private_file(receipt, b"attacker-replacement")

        with self.assertRaises(CorePathPolicyError):
            authorization.assert_stable()
        descriptor = authorization.duplicate_target_fd()
        try:
            self.assertEqual(os.read(descriptor, 1024), b"trusted-receipt")
        finally:
            os.close(descriptor)
        self.assertEqual(receipt.read_bytes(), b"attacker-replacement")

    def test_existing_input_rejects_leaf_swap_during_descriptor_capture(self) -> None:
        receipt = self.private_file(
            self.roots["recovery"] / "receipt.json",
            b"trusted-receipt",
        )
        retired = receipt.with_name("receipt.retired.json")
        original_open = os.open
        replaced = False

        def racing_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal replaced
            if path == receipt.name and dir_fd is not None and not replaced:
                replaced = True
                receipt.rename(retired)
                replacement_fd = original_open(
                    receipt,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    os.write(replacement_fd, b"attacker-replacement")
                finally:
                    os.close(replacement_fd)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("core_path_policy.os.open", side_effect=racing_open):
            with self.assertRaises(CorePathPolicyError):
                self.policy.authorize_recovery_input(receipt)

        self.assertTrue(replaced)
        self.assertEqual(retired.read_bytes(), b"trusted-receipt")
        self.assertEqual(receipt.read_bytes(), b"attacker-replacement")

    def test_future_output_parent_fd_defeats_directory_replacement(self) -> None:
        directory = self.roots["export"] / "daily"
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
        output = directory / "memory.json"
        authorization = self.policy.authorize_export_output(output)

        retired = self.roots["export"] / "daily-retired"
        directory.rename(retired)
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)

        with self.assertRaises(CorePathPolicyError):
            authorization.assert_stable()
        parent_fd = authorization.duplicate_parent_fd()
        try:
            output_fd = os.open(
                authorization.leaf_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
            try:
                os.write(output_fd, b"anchored-output")
            finally:
                os.close(output_fd)
        finally:
            os.close(parent_fd)

        self.assertEqual((retired / "memory.json").read_bytes(), b"anchored-output")
        self.assertFalse(output.exists())

    def test_closed_capability_cannot_duplicate_descriptors(self) -> None:
        receipt = self.private_file(self.roots["recovery"] / "receipt.json")
        authorization = self.policy.authorize_recovery_input(receipt)

        authorization.close()
        authorization.close()

        self.assertTrue(authorization.closed)
        with self.assertRaises(CorePathPolicyError):
            authorization.duplicate_parent_fd()
        with self.assertRaises(CorePathPolicyError):
            authorization.duplicate_target_fd()

    def test_capture_root_is_server_owned_and_client_overrides_are_rejected(self) -> None:
        authorization = self.policy.authorize_capture_root()
        self.assertEqual(authorization.path, self.roots["capture"])
        authorization.assert_stable()

        for override in (self.roots["capture"], self.roots["recovery"]):
            with self.subTest(override=override), self.assertRaises(
                CorePathPolicyError
            ):
                self.policy.authorize_capture_root(override)

    def test_policy_rejects_noncanonical_or_nonprivate_root(self) -> None:
        linked = self.base / "linked-export"
        linked.symlink_to(self.roots["export"], target_is_directory=True)
        with self.assertRaises(CorePathPolicyError):
            CorePathPolicy(
                export_root=linked,
                backup_root=self.roots["backup"],
                recovery_root=self.roots["recovery"],
                capture_root=self.roots["capture"],
            )

        self.roots["export"].chmod(0o755)
        with self.assertRaises(CorePathPolicyError):
            CorePathPolicy(
                export_root=self.roots["export"],
                backup_root=self.roots["backup"],
                recovery_root=self.roots["recovery"],
                capture_root=self.roots["capture"],
            )

    def test_policy_detects_configured_root_replacement(self) -> None:
        original = self.roots["export"]
        retired = self.base / "export-retired"
        original.rename(retired)
        original.mkdir(mode=0o700)
        original.chmod(0o700)

        with self.assertRaises(CorePathPolicyError):
            self.policy.configured_root("export")

    def test_rejections_are_content_free(self) -> None:
        canary = self.roots["export"] / "sk-secret-canary-1234567890123456"
        canary.mkdir(mode=0o700)
        canary.chmod(0o700)
        target = canary / "already-there.json"
        self.private_file(target)

        with self.assertRaises(CorePathPolicyError) as raised:
            self.policy.authorize_export_output(target)

        self.assertEqual(str(raised.exception), "path_not_authorized")
        self.assertNotIn(str(canary), repr(raised.exception))


if __name__ == "__main__":
    unittest.main()

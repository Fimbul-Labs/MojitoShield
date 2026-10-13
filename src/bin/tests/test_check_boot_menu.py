"""Tests for check: Boot menu protection (`boot-menu`), following docs/check-contracts.md."""

import os
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from mojitoshield.checks import boot_menu
from mojitoshield.results import Status
from support import CheckTestCase, completed


class BootMenuTests(CheckTestCase):
    PASSWORD = 'cat << EOF\nset superusers="admin"\npassword_pbkdf2 admin grub.pbkdf2.sha512.10000.ABC\nEOF\n'

    def setUp(self):
        super().setUp()
        self.grub_config = self.path(boot_menu, "GRUB_CONFIG", "boot/grub/grub.cfg")
        self.path(boot_menu, "GRUB_CUSTOM_CONFIG", "boot/grub/custom.cfg")
        self.scripts = self.path(boot_menu, "GRUB_SCRIPTS", "etc/grub.d")
        self.write("boot/grub/grub.cfg", "")
        self.script("10_linux", "echo menuentry\n")

    def script(
        self, name: str, contents: str, *, executable: bool = True, age_days: float | None = None
    ):
        path = self.write(f"etc/grub.d/{name}", contents)
        path.chmod(0o755 if executable else 0o644)
        if age_days is not None:
            moment = (datetime.now() - timedelta(days=age_days)).timestamp()
            os.utime(path, (moment, moment))
        return path

    def generated(self, age_days: float):
        moment = (datetime.now() - timedelta(days=age_days)).timestamp()
        os.utime(self.grub_config, (moment, moment))

    def unencrypted(self):
        self.commands(
            {
                ("findmnt",): completed('SOURCE="/dev/sda2" FSTYPE="ext4"\n'),
                ("lsblk",): completed("part\ndisk\n"),
            }
        )

    def test_encryption_protects_the_boot_menu(self):
        self.commands(
            {
                ("findmnt",): completed('SOURCE="/dev/mapper/vgmint-root" FSTYPE="ext4"\n'),
                ("lsblk",): completed("lvm\ncrypt\npart\ndisk\n"),
            }
        )
        self.assertOutcome(boot_menu.check, Status.OK, "boot_menu.protected_by_encryption")

    def test_no_password_and_no_encryption(self):
        self.unencrypted()
        self.assertOutcome(boot_menu.check, Status.WARNING, "boot_menu.no_password")

    def test_password_active_when_the_menu_was_generated_afterwards(self):
        self.unencrypted()
        self.script("40_custom", self.PASSWORD, age_days=10)
        self.generated(age_days=2)
        self.assertOutcome(boot_menu.check, Status.OK, "boot_menu.password_active")

    def test_password_added_after_the_menu_was_generated_needs_confirmation(self):
        self.unencrypted()
        self.generated(age_days=10)
        self.script("40_custom", self.PASSWORD, age_days=1)
        self.assertOutcome(
            boot_menu.check, Status.AUTH_REQUIRED, "boot_menu.password_not_confirmed"
        )

    def test_superuser_and_password_may_be_in_different_scripts(self):
        self.unencrypted()
        self.script("01_users", 'cat << EOF\nset superusers="admin"\nEOF\n', age_days=10)
        self.script("02_password", "cat << EOF\npassword admin secret\nEOF\n", age_days=10)
        self.generated(age_days=1)
        self.assertOutcome(boot_menu.check, Status.OK, "boot_menu.password_active")

    def test_commented_or_non_executable_settings_do_not_count(self):
        self.unencrypted()
        self.script("40_custom", '# set superusers="admin"\n# password_pbkdf2 admin x\n')
        self.script("50_disabled", self.PASSWORD, executable=False)
        self.assertOutcome(boot_menu.check, Status.WARNING, "boot_menu.no_password")

    def test_password_in_custom_cfg_is_active_at_once(self):
        self.unencrypted()
        self.write("boot/grub/custom.cfg", 'set superusers="admin"\npassword_pbkdf2 admin x\n')
        self.assertOutcome(boot_menu.check, Status.OK, "boot_menu.password_active")

    def test_unreadable_custom_cfg_needs_the_extended_scan(self):
        self.unencrypted()
        self.write("boot/grub/custom.cfg", "")
        original = Path.read_text

        def read_text(path, *args, **kwargs):
            if path.name == "custom.cfg":
                raise PermissionError
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_text", read_text):
            self.assertOutcome(
                boot_menu.check, Status.AUTH_REQUIRED, "boot_menu.authorization_required"
            )

    def test_grub_not_used(self):
        self.unencrypted()
        self.grub_config.unlink()
        self.assertOutcome(boot_menu.check, Status.UNKNOWN, "boot_menu.grub_not_used")

    def test_unknown_encryption_without_password(self):
        self.commands({})
        self.assertOutcome(boot_menu.check, Status.UNKNOWN, "boot_menu.status_unknown")


if __name__ == "__main__":
    unittest.main()

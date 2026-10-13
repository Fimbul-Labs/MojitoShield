"""Tests for check: System up to date (`updates`), following docs/check-contracts.md."""

import gzip
import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from mojitoshield.checks import updates
from mojitoshield.results import Status
from support import NOW, CheckTestCase, completed


class UpdatesTests(CheckTestCase):
    def setUp(self):
        super().setUp()
        self.path(updates, "APT_AUTO_UPGRADES", "apt/20auto-upgrades")
        self.path(updates, "MINTUPDATE_AUTOMATION_SCRIPT", "mintupdate/automatic_upgrades.py")
        self.path(updates, "MINTUPDATE_UPGRADE_FLAG", "lib/upgrades-enabled")
        self.reboot_file = self.path(updates, "REBOOT_REQUIRED", "run/reboot-required")
        self.start(
            patch.object(
                updates,
                "APT_HISTORY_LOGS",
                (
                    self.root / "log/history.log",
                    self.root / "log/history.log.1.gz",
                ),
            )
        )
        self.commands({("systemctl", "is-enabled"): completed("disabled\n", 1)})

    def history(self, *entries: tuple[datetime, bool]) -> str:
        lines = []
        for started, upgraded in entries:
            lines += ["", f"Start-Date: {started:%Y-%m-%d  %H:%M:%S}", "Commandline: apt"]
            lines.append(
                "Upgrade: libc6:amd64 (2.39-0, 2.39-1)" if upgraded else "Install: foo:amd64 (1.0)"
            )
            lines.append(f"End-Date: {started:%Y-%m-%d  %H:%M:%S}")
        return "\n".join(lines) + "\n"

    def test_recently_installed_updates(self):
        self.write("log/history.log", self.history((NOW - timedelta(days=3), True)))
        outcome = self.assertOutcome(updates.check, Status.OK, "updates.recently_installed")
        self.assertEqual(outcome.data, {"days": "3"})

    def test_old_updates(self):
        self.write(
            "log/history.log",
            self.history(
                (NOW - timedelta(days=45), True),
                (NOW - timedelta(days=2), False),
            ),
        )
        outcome = self.assertOutcome(
            updates.check, Status.WARNING, "updates.not_installed_recently"
        )
        self.assertEqual(outcome.data, {"days": "45"})

    def test_rotated_history_is_used_when_the_current_log_has_no_upgrade(self):
        self.write("log/history.log", self.history((NOW - timedelta(days=1), False)))
        self.write(
            "log/history.log.1.gz",
            gzip.compress(self.history((NOW - timedelta(days=10), True)).encode()),
        )
        self.assertOutcome(updates.check, Status.OK, "updates.recently_installed")

    def test_automatic_updates(self):
        self.write(
            "apt/20auto-upgrades",
            'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n',
        )
        self.assertOutcome(updates.check, Status.OK, "updates.automatic")

    def test_update_manager_automation_needs_flag_and_timer(self):
        self.write("mintupdate/automatic_upgrades.py", "")
        self.write("lib/upgrades-enabled", "")
        self.commands({("systemctl", "is-enabled"): completed("enabled\n")})
        self.assertOutcome(updates.check, Status.OK, "updates.automatic")

    def test_pending_reboot_for_over_a_week(self):
        self.write("run/reboot-required", "*** System restart required ***\n")
        old = (NOW - timedelta(days=9)).timestamp()
        os.utime(self.reboot_file, (old, old))
        outcome = self.assertOutcome(updates.check, Status.WARNING, "updates.reboot_pending")
        self.assertEqual(outcome.data, {"days": "9"})

    def test_recent_pending_reboot_is_not_a_warning(self):
        self.write("run/reboot-required", "")
        recent = (NOW - timedelta(days=1)).timestamp()
        os.utime(self.reboot_file, (recent, recent))
        self.write("log/history.log", self.history((NOW - timedelta(days=1), True)))
        self.assertOutcome(updates.check, Status.OK, "updates.recently_installed")

    def test_no_history(self):
        self.assertOutcome(updates.check, Status.UNKNOWN, "updates.history_unavailable")


class AptSettingsTests(unittest.TestCase):
    def test_enabled_settings_are_detected(self):
        contents = (
            'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
        )
        self.assertIs(updates.parse_apt_auto_updates(contents), True)

    def test_disabled_setting_is_detected(self):
        contents = (
            'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "0";\n'
        )
        self.assertIs(updates.parse_apt_auto_updates(contents), False)

    def test_incomplete_settings_are_not_assumed_safe(self):
        self.assertIsNone(
            updates.parse_apt_auto_updates('APT::Periodic::Update-Package-Lists "1";')
        )


if __name__ == "__main__":
    unittest.main()

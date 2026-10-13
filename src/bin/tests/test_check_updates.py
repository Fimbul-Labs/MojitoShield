"""Tests for check: System up to date (`updates`), following docs/check-contracts.md."""

import gzip
import os
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import patch

from mojitoshield.checks import updates
from mojitoshield.results import Status
from support import NOW, CheckTestCase, completed

# The history a fresh Mint 22.3 install writes: the ISO build, then the installer
# (no command line) upgrading a few packages while it adds language packs.
FRESH_INSTALL_HISTORY = """
Start-Date: 2026-01-08  18:43:35
Commandline: apt-get remove --purge -f -q -y ubuntu-pro-client
Purge: ubuntu-pro-client-l10n:amd64 (37.1ubuntu0~24.04)
End-Date: 2026-01-08  18:43:37

Start-Date: 2026-10-10  11:15:26
Requested-By: mint (1000)
Install: libsasl2-modules-gssapi-mit:amd64 (2.1.28+dfsg1-5ubuntu3.1, automatic)
Upgrade: udev:amd64 (255.4-1ubuntu8.12, 255.4-1ubuntu8.17)
End-Date: 2026-10-10  11:16:12

Start-Date: 2026-10-10  16:26:26
Commandline: /usr/bin/apt install /mnt/mojitoshield/mojitoshield_0.1.2_all.deb
Requested-By: tester (1000)
Install: mojitoshield:amd64 (0.1.2)
End-Date: 2026-10-10  16:26:28
"""

SECURITY_UPDATE = (
    "Inst udev [255.4-1ubuntu8.12] (255.4-1ubuntu8.17 Ubuntu:24.04/noble-updates, "
    "Ubuntu:24.04/noble-security [amd64])"
)
OTHER_UPDATE = "Inst mintupdate [7.0.0] (7.0.1 linuxmint:22.3/zena [all])"


class UpdatesTests(CheckTestCase):
    def setUp(self):
        super().setUp()
        self.path(updates, "APT_AUTO_UPGRADES", "apt/20auto-upgrades")
        self.path(updates, "MINTUPDATE_AUTOMATION_SCRIPT", "mintupdate/automatic_upgrades.py")
        self.path(updates, "MINTUPDATE_UPGRADE_FLAG", "lib/upgrades-enabled")
        self.reboot_file = self.path(updates, "REBOOT_REQUIRED", "run/reboot-required")
        self.path(updates, "APT_LISTS", "lists")
        self.installer_logs = self.path(updates, "INSTALLER_LOGS", "log/installer")
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
        self.security_list(NOW - timedelta(hours=5))
        self.pending()

    def security_list(self, published: datetime) -> None:
        # format_datetime always writes English names, whatever the locale.
        date = format_datetime(published.astimezone(timezone.utc), usegmt=True)
        self.write(
            "lists/security.ubuntu.com_ubuntu_dists_noble-security_InRelease",
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
            f"Origin: Ubuntu\nSuite: noble-security\nDate: {date}\n",
        )

    def pending(self, *lines: str, returncode: int = 0) -> None:
        self.commands(
            {
                ("systemctl", "is-enabled"): completed("disabled\n", 1),
                ("apt-get", "-s", "dist-upgrade"): completed(
                    "NOTE: This is only a simulation!\n" + "".join(f"{line}\n" for line in lines),
                    returncode,
                ),
            }
        )

    def installed(self, moment: datetime) -> None:
        self.installer_logs.mkdir(parents=True)
        os.utime(self.installer_logs, (moment.timestamp(), moment.timestamp()))

    def history(self, started: datetime, commandline: str | None) -> str:
        lines = ["", f"Start-Date: {started:%Y-%m-%d  %H:%M:%S}"]
        if commandline is not None:
            lines.append(f"Commandline: {commandline}")
        lines += [
            "Upgrade: libc6:amd64 (2.39-0, 2.39-1)",
            f"End-Date: {started:%Y-%m-%d  %H:%M:%S}",
        ]
        return "\n".join(lines) + "\n"

    def test_fresh_install_with_pending_security_updates(self):
        self.installed(datetime(2026, 10, 10, 11, 20))
        self.write("log/history.log", FRESH_INSTALL_HISTORY)
        self.pending(SECURITY_UPDATE, SECURITY_UPDATE, OTHER_UPDATE)
        outcome = self.assertOutcome(
            updates.check, Status.WARNING, "updates.security_updates_pending_no_update"
        )
        self.assertEqual(outcome.data, {"count": "2"})

    def test_installing_one_package_is_not_a_full_update(self):
        self.write("log/history.log", self.history(NOW - timedelta(days=1), "apt install ./x.deb"))
        self.pending(SECURITY_UPDATE)
        self.assertOutcome(
            updates.check, Status.WARNING, "updates.security_updates_pending_no_update"
        )

    def test_no_pending_security_updates(self):
        self.pending(OTHER_UPDATE)
        self.assertOutcome(updates.check, Status.OK, "updates.no_security_updates_pending")

    def test_recent_update_manager_run_allows_new_security_updates(self):
        self.write(
            "log/history.log",
            self.history(NOW - timedelta(days=3), "aptkit role='role-install-packages'"),
        )
        self.pending(SECURITY_UPDATE)
        outcome = self.assertOutcome(updates.check, Status.OK, "updates.security_updates_recent")
        self.assertEqual(outcome.data, {"count": "1", "days": "3"})

    def test_old_full_update_with_pending_security_updates(self):
        self.write("log/history.log", self.history(NOW - timedelta(days=20), "apt full-upgrade"))
        self.pending(SECURITY_UPDATE)
        outcome = self.assertOutcome(
            updates.check, Status.WARNING, "updates.security_updates_pending"
        )
        self.assertEqual(outcome.data, {"count": "1", "days": "20"})

    def test_entry_without_command_line_counts_after_installation(self):
        self.installed(NOW - timedelta(days=100))
        self.write("log/history.log", self.history(NOW - timedelta(days=2), None))
        self.pending(SECURITY_UPDATE)
        self.assertOutcome(updates.check, Status.OK, "updates.security_updates_recent")

    def test_entry_without_command_line_does_not_count_without_installation_date(self):
        self.write("log/history.log", self.history(NOW - timedelta(days=2), None))
        self.pending(SECURITY_UPDATE)
        self.assertOutcome(
            updates.check, Status.WARNING, "updates.security_updates_pending_no_update"
        )

    def test_rotated_history_is_used(self):
        self.write(
            "log/history.log.1.gz",
            gzip.compress(self.history(NOW - timedelta(days=10), "apt-get upgrade").encode()),
        )
        self.pending(SECURITY_UPDATE)
        self.assertOutcome(updates.check, Status.OK, "updates.security_updates_recent")

    def test_old_package_lists(self):
        self.security_list(NOW - timedelta(days=20))
        outcome = self.assertOutcome(updates.check, Status.WARNING, "updates.lists_outdated")
        self.assertEqual(outcome.data, {"days": "20"})

    def test_missing_package_lists(self):
        (self.root / "lists/security.ubuntu.com_ubuntu_dists_noble-security_InRelease").unlink()
        self.assertOutcome(updates.check, Status.UNKNOWN, "updates.lists_unavailable")

    def test_simulation_failure_is_not_assumed_safe(self):
        self.pending(returncode=100)
        self.assertOutcome(updates.check, Status.UNKNOWN, "updates.pending_unavailable")

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
        self.assertOutcome(updates.check, Status.OK, "updates.no_security_updates_pending")


class PendingUpdateParsingTests(unittest.TestCase):
    def test_debian_security_archive_is_recognized(self):
        line = "Inst libc6 [2.41-11] (2.41-12 Debian-Security:13/stable-security [amd64])"
        self.assertEqual(updates.count_pending_security_updates(line), 1)

    def test_configure_lines_are_not_counted_twice(self):
        output = f"{SECURITY_UPDATE}\nConf udev (255.4-1ubuntu8.17 Ubuntu:24.04/noble-security)"
        self.assertEqual(updates.count_pending_security_updates(output), 1)

    def test_full_update_programs(self):
        self.assertTrue(
            updates.is_full_update("aptkit role='role-install-packages' sender=':1.2'")
        )
        self.assertTrue(updates.is_full_update("/usr/bin/apt-get -y dist-upgrade"))
        self.assertFalse(updates.is_full_update("/usr/bin/apt install virt-manager"))
        self.assertFalse(updates.is_full_update(None))

    def test_unsigned_release_date(self):
        published = updates.release_date("Origin: Ubuntu\nDate: Tue, 13 Oct 2026 10:10:30 UTC\n")
        self.assertEqual(published.astimezone(timezone.utc).hour, 10)


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

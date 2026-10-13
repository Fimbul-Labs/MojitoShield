"""Tests for check: Firewall (`firewall`), following docs/check-contracts.md."""

import unittest
from pathlib import Path
from unittest.mock import patch

from mojitoshield.checks import firewall
from mojitoshield.results import Status
from support import CheckTestCase, completed


class FirewallTests(CheckTestCase):
    def setUp(self):
        super().setUp()
        self.path(firewall, "UFW_CONFIG", "ufw/ufw.conf")

    def test_enabled_and_running(self):
        self.write("ufw/ufw.conf", "# comment\nENABLED=yes\nLOGLEVEL=low\n")
        self.commands({("systemctl", "is-active", "ufw"): completed("active\n")})
        self.assertOutcome(firewall.check, Status.OK, "firewall.enabled")

    def test_disabled(self):
        self.write("ufw/ufw.conf", "ENABLED=no\n")
        self.commands({})
        self.assertOutcome(firewall.check, Status.WARNING, "firewall.disabled")

    def test_enabled_but_not_running_needs_the_live_status(self):
        self.write("ufw/ufw.conf", "ENABLED=yes\n")
        self.commands({("systemctl", "is-active", "ufw"): completed("inactive\n", 3)})
        self.assertOutcome(firewall.check, Status.AUTH_REQUIRED, "firewall.service_not_confirmed")

    def test_unreadable_settings_need_the_live_status(self):
        self.write("ufw/ufw.conf", "ENABLED=yes\n")
        with patch.object(Path, "read_text", side_effect=PermissionError):
            self.assertOutcome(
                firewall.check, Status.AUTH_REQUIRED, "firewall.authorization_required"
            )

    def test_ufw_not_installed(self):
        self.assertOutcome(firewall.check, Status.UNKNOWN, "firewall.ufw_not_installed")

    def test_last_enabled_value_wins(self):
        self.assertIs(firewall.parse_ufw_enabled('ENABLED=yes\nENABLED="no"\n'), False)
        self.assertIsNone(firewall.parse_ufw_enabled("LOGLEVEL=low\n"))


if __name__ == "__main__":
    unittest.main()

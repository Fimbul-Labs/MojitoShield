"""Tests for check: AppArmor (`apparmor`), following docs/check-contracts.md."""

import unittest

from mojitoshield.checks import apparmor
from mojitoshield.results import Status
from support import CheckTestCase


class AppArmorTests(CheckTestCase):
    def setUp(self):
        super().setUp()
        self.path(apparmor, "APPARMOR_ENABLED", "apparmor/enabled")

    def test_states(self):
        for value, status, message_id in (
            ("Y\n", Status.OK, "apparmor.enabled"),
            ("N\n", Status.WARNING, "apparmor.disabled"),
            ("?\n", Status.UNKNOWN, "apparmor.unrecognized_status"),
        ):
            with self.subTest(value=value):
                self.write("apparmor/enabled", value)
                self.assertOutcome(apparmor.check, status, message_id)

    def test_not_available(self):
        self.assertOutcome(apparmor.check, Status.UNKNOWN, "apparmor.not_available")


if __name__ == "__main__":
    unittest.main()

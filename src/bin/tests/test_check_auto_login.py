"""Tests for check: Automatic login (`auto-login`), following docs/check-contracts.md."""

import unittest
from unittest.mock import patch

from mojitoshield.checks import auto_login
from mojitoshield.results import Status
from support import CheckTestCase


class AutoLoginTests(CheckTestCase):
    def setUp(self):
        super().setUp()
        self.path(auto_login, "DISPLAY_MANAGER_FILE", "X11/default-display-manager")
        self.start(
            patch.object(
                auto_login,
                "LIGHTDM_CONFIG_SOURCES",
                (
                    self.root / "share/lightdm.conf.d",
                    self.root / "etc/lightdm.conf.d",
                    self.root / "etc/lightdm.conf",
                ),
            )
        )
        self.write("X11/default-display-manager", "/usr/sbin/lightdm\n")
        self.write(
            "share/lightdm.conf.d/50-greeter.conf", "[Seat:*]\ngreeter-session=slick-greeter\n"
        )

    def test_no_automatic_login(self):
        self.write("etc/lightdm.conf.d/70-linuxmint.conf", "[Seat:*]\nuser-session=cinnamon\n")
        self.assertOutcome(auto_login.check, Status.OK, "auto_login.disabled")

    def test_automatic_login_does_not_reveal_the_user_name(self):
        self.write("etc/lightdm.conf", "[Seat:*]\nautologin-user=someone\n")
        outcome = self.assertOutcome(auto_login.check, Status.WARNING, "auto_login.enabled")
        self.assertNotIn("someone", repr(outcome))

    def test_later_file_overrides_earlier_one(self):
        self.write("etc/lightdm.conf.d/60-auto.conf", "[SeatDefaults]\nautologin-user=someone\n")
        self.write("etc/lightdm.conf", "[Seat:*]\nautologin-user=\n")
        self.assertOutcome(auto_login.check, Status.OK, "auto_login.disabled")

    def test_broken_file_is_skipped_like_login_window_does(self):
        self.write("etc/lightdm.conf.d/10-broken.conf", "autologin-user=someone\n")
        self.assertOutcome(auto_login.check, Status.OK, "auto_login.disabled")

    def test_other_display_manager(self):
        self.write("X11/default-display-manager", "/usr/sbin/gdm3\n")
        outcome = self.assertOutcome(
            auto_login.check, Status.UNKNOWN, "auto_login.display_manager_not_supported"
        )
        self.assertEqual(outcome.data, {"display_manager": "gdm3"})

    def test_unknown_display_manager(self):
        (self.root / "X11/default-display-manager").unlink()
        self.assertOutcome(auto_login.check, Status.UNKNOWN, "auto_login.display_manager_unknown")


if __name__ == "__main__":
    unittest.main()

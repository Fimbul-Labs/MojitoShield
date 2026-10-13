"""Tests for check: Screen lock (`screen-lock`), following docs/check-contracts.md."""

import unittest
from unittest.mock import patch

from mojitoshield.checks import screen_lock
from mojitoshield.results import Status
from support import CheckTestCase, completed


class ScreenLockTests(CheckTestCase):
    def use_desktop(self, value: str):
        self.start(patch.dict("os.environ", {"XDG_CURRENT_DESKTOP": value}))

    def test_desktop_detection(self):
        for value, desktop in (
            ("X-Cinnamon", "cinnamon"),
            ("MATE", "mate"),
            ("XFCE", "xfce"),
            ("ubuntu:GNOME", None),
            ("", None),
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    screen_lock.current_desktop({"XDG_CURRENT_DESKTOP": value}), desktop
                )

    def test_cinnamon_locks_after_delay(self):
        self.use_desktop("X-Cinnamon")
        self.commands(
            {
                ("gsettings", "get", "org.cinnamon.desktop.screensaver"): completed("true\n"),
                ("gsettings", "get", "org.cinnamon.desktop.session"): completed("uint32 900\n"),
            }
        )
        outcome = self.assertOutcome(screen_lock.check, Status.OK, "screen_lock.enabled")
        self.assertEqual(outcome.data, {"desktop": "Cinnamon", "minutes": "15"})

    def test_mate_delay_is_in_minutes(self):
        self.use_desktop("MATE")
        self.commands(
            {
                ("gsettings", "get", "org.mate.screensaver", "lock-enabled"): completed("true\n"),
                ("gsettings", "get", "org.mate.screensaver", "idle-activation-enabled"): completed(
                    "true\n"
                ),
                ("gsettings", "get", "org.mate.session"): completed("5\n"),
            }
        )
        outcome = self.assertOutcome(screen_lock.check, Status.OK, "screen_lock.enabled")
        self.assertEqual(outcome.data["minutes"], "5")

    def test_lock_disabled(self):
        self.use_desktop("X-Cinnamon")
        self.commands(
            {("gsettings", "get", "org.cinnamon.desktop.screensaver"): completed("false\n")}
        )
        self.assertOutcome(screen_lock.check, Status.WARNING, "screen_lock.disabled")

    def test_zero_idle_delay_never_locks_automatically(self):
        self.use_desktop("X-Cinnamon")
        self.commands(
            {
                ("gsettings", "get", "org.cinnamon.desktop.screensaver"): completed("true\n"),
                ("gsettings", "get", "org.cinnamon.desktop.session"): completed("uint32 0\n"),
            }
        )
        self.assertOutcome(screen_lock.check, Status.WARNING, "screen_lock.never_automatic")

    def test_xfce_screensaver_turned_off_never_locks_automatically(self):
        self.use_desktop("XFCE")
        self.commands(
            {
                (
                    "xfconf-query",
                    "--channel",
                    "xfce4-screensaver",
                    "--property",
                    "/lock/enabled",
                ): completed("true\n"),
                (
                    "xfconf-query",
                    "--channel",
                    "xfce4-screensaver",
                    "--property",
                    "/saver/enabled",
                ): completed("false\n"),
            }
        )
        self.assertOutcome(screen_lock.check, Status.WARNING, "screen_lock.never_automatic")

    def test_unreadable_idle_delay(self):
        self.use_desktop("X-Cinnamon")
        self.commands(
            {("gsettings", "get", "org.cinnamon.desktop.screensaver"): completed("true\n")}
        )
        self.assertOutcome(screen_lock.check, Status.UNKNOWN, "screen_lock.idle_delay_unavailable")

    def test_unsupported_desktop_is_not_guessed(self):
        self.use_desktop("KDE")
        self.commands({})
        self.assertOutcome(screen_lock.check, Status.UNKNOWN, "screen_lock.desktop_not_supported")


if __name__ == "__main__":
    unittest.main()

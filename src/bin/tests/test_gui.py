"""GTK smoke tests; skipped when no display is available."""

import threading
import time
import unittest
from unittest.mock import patch

from mojitoshield_core import CHECKS, CheckResult, Status

try:
    import gi

    gi.require_version("Gtk", "3.0")
    from gi.repository import Gio, Gtk

    GTK_AVAILABLE = Gtk.init_check(None)[0]
except (ImportError, ValueError):
    GTK_AVAILABLE = False

if GTK_AVAILABLE:
    import mojitoshield as gui


def fake_results(auth_required: frozenset[str] = frozenset()) -> tuple[CheckResult, ...]:
    return tuple(
        CheckResult(
            check_id=definition.check_id,
            level=definition.level,
            status=Status.AUTH_REQUIRED if definition.check_id in auth_required else Status.OK,
            message_id=(
                "firewall.authorization_required"
                if definition.check_id in auth_required
                else "firewall.active"
            ),
        )
        for definition in CHECKS
    )


def wait_until(condition, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)
        if condition():
            return True
        time.sleep(0.01)
    return False


@unittest.skipUnless(GTK_AVAILABLE, "GTK display not available")
class WindowSmokeTests(unittest.TestCase):
    application = None

    @classmethod
    def setUpClass(cls):
        # A process can only register one anonymous application on the session bus.
        if WindowSmokeTests.application is None:
            WindowSmokeTests.application = Gtk.Application(flags=Gio.ApplicationFlags.NON_UNIQUE)
            WindowSmokeTests.application.register(None)

    def open_window(self, results: tuple[CheckResult, ...], release=None):
        application = self.application

        def run_checks():
            if release is not None:
                release.wait(5)
            return results

        patches = (
            patch("mojitoshield_core.run_checks", side_effect=run_checks),
            patch("mojitoshield.privileged_helper_available", return_value=False),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

        window = gui.MojitoShieldWindow(application)
        self.addCleanup(window.destroy)
        return window

    def scan_finished(self, window) -> bool:
        return window._refresh_action.get_enabled()

    def test_window_lists_all_checks_in_one_keyboard_navigable_list(self):
        window = self.open_window(fake_results())
        self.assertTrue(wait_until(lambda: self.scan_finished(window)))

        rows = window.check_list.get_children()
        self.assertEqual(len(rows), 9)
        self.assertEqual([row.check.level for row in rows], [1] * 7 + [2] * 2)
        headers = [row.get_header() for row in rows if row.get_header() is not None]
        self.assertEqual(
            [header.get_text() for header in headers],
            ["Level 1: everyday protection", "Level 2: physical access"],
        )
        self.assertEqual(window.check_list.get_selected_row().check.check_id, "firewall")
        self.assertEqual(window.detail_title.get_text(), "Firewall")
        self.assertEqual(rows[0].get_accessible().get_name(), "Firewall: OK")

    def test_rows_show_checking_until_results_arrive(self):
        release = threading.Event()
        window = self.open_window(fake_results(), release)
        wait_until(lambda: False, timeout=0.1)

        first_row = window.check_list.get_children()[0]
        self.assertEqual(first_row.status_label.get_text(), "Checking…")
        self.assertFalse(self.scan_finished(window))

        release.set()
        self.assertTrue(wait_until(lambda: self.scan_finished(window)))
        self.assertEqual(first_row.status_label.get_text(), "OK")

    def test_scan_is_not_called_complete_while_permission_is_missing(self):
        window = self.open_window(fake_results(frozenset({"firewall"})))
        self.assertTrue(wait_until(lambda: self.scan_finished(window)))

        summary = window.summary_label.get_text()
        self.assertIn("not complete", summary)
        self.assertNotIn("Scan complete", summary)
        self.assertTrue(window.extended_button.get_visible())
        self.assertFalse(window.extended_button.get_sensitive())
        self.assertEqual(window.extended_button.get_label(), "Extended scan (not installed)")

    def test_wide_window_keeps_list_width_and_readable_detail_lines(self):
        window = self.open_window(fake_results())
        window.resize(1600, 900)
        self.assertTrue(wait_until(lambda: window.main_paned.get_allocated_width() > 1000))
        wait_until(lambda: False, timeout=0.1)

        self.assertEqual(window.main_paned.get_orientation(), Gtk.Orientation.HORIZONTAL)
        self.assertEqual(window.main_paned.get_position(), gui.LIST_WIDTH)
        self.assertEqual(
            window.detail_explanation.get_max_width_chars(), gui.DETAIL_MAX_WIDTH_CHARS
        )

    def test_complete_scan_hides_extended_scan(self):
        window = self.open_window(fake_results())
        self.assertTrue(wait_until(lambda: self.scan_finished(window)))

        self.assertTrue(window.summary_label.get_text().startswith("Scan complete"))
        self.assertFalse(window.extended_button.get_visible())


if __name__ == "__main__":
    unittest.main()

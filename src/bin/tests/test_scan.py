"""Tests for the list of checks and running a whole scan."""

import unittest
from unittest.mock import patch

from mojitoshield.results import Status
from mojitoshield.scan import CHECKS, run_checks


class ScanTests(unittest.TestCase):
    def test_nine_checks_in_two_levels(self):
        self.assertEqual(
            [(definition.check_id, definition.level) for definition in CHECKS],
            [
                ("firewall", 1),
                ("updates", 1),
                ("screen-lock", 1),
                ("auto-login", 1),
                ("timeshift", 1),
                ("network-services", 1),
                ("apparmor", 1),
                ("disk-encryption", 2),
                ("boot-menu", 2),
            ],
        )

    def test_a_failing_check_does_not_stop_the_scan(self):
        with (
            patch("mojitoshield.system.run_command", side_effect=OSError("boom")),
            self.assertLogs("mojitoshield.scan", level="WARNING") as logs,
        ):
            results = run_checks()

        self.assertEqual(len(results), 9)
        failed = [
            result for result in results if result.outcome.message_id == "check.unexpected_error"
        ]
        self.assertTrue(failed)
        self.assertTrue(all(result.outcome.status is Status.UNKNOWN for result in failed))
        self.assertTrue(all("boom" not in line for line in logs.output))


if __name__ == "__main__":
    unittest.main()

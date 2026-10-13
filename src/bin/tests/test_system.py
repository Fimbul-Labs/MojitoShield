"""Tests for the shared system access: commands run with a language-neutral locale."""

import unittest
from unittest.mock import patch

from mojitoshield import system


class RunCommandTests(unittest.TestCase):
    def test_commands_are_run_with_language_neutral_locale(self):
        with (
            patch("mojitoshield.system.shutil.which", return_value="/usr/bin/systemctl"),
            patch("mojitoshield.system.subprocess.run") as run,
        ):
            system.run_command(["systemctl", "is-active", "ssh.service"])

        environment = run.call_args.kwargs["env"]
        self.assertEqual(
            (environment["LANG"], environment["LC_ALL"], environment["LANGUAGE"]), ("C", "C", "C")
        )

    def test_missing_program_gives_none(self):
        with patch("mojitoshield.system.shutil.which", return_value=None):
            self.assertIsNone(system.run_command(["no-such-program"]))


if __name__ == "__main__":
    unittest.main()

import json
import unittest
from unittest.mock import patch

from mojitoshield_core import (
    PRIVILEGED_CHECK_IDS,
    PrivilegedScanFailed,
    Status,
    _parse_privileged_output,
    _run_command,
    identify_distribution,
    parse_apt_auto_updates,
    run_privileged_checks,
)
from mojitoshield_i18n import translate


class DistributionTests(unittest.TestCase):
    def test_identifies_linux_mint(self):
        release = {"ID": "linuxmint", "PRETTY_NAME": "Linux Mint 22"}

        self.assertTrue(identify_distribution(release))

    def test_identifies_lmde_by_name(self):
        release = {"ID": "debian", "PRETTY_NAME": "LMDE 6 Faye"}

        self.assertTrue(identify_distribution(release))

    def test_does_not_treat_every_debian_derivative_as_mint(self):
        release = {"ID": "ubuntu", "ID_LIKE": "linuxmint", "NAME": "Ubuntu"}

        self.assertFalse(identify_distribution(release))


class AptSettingsTests(unittest.TestCase):
    def test_enabled_settings_are_detected(self):
        contents = (
            'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
        )

        self.assertIs(parse_apt_auto_updates(contents), True)

    def test_disabled_setting_is_detected(self):
        contents = (
            'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "0";\n'
        )

        self.assertIs(parse_apt_auto_updates(contents), False)

    def test_incomplete_settings_are_not_assumed_safe(self):
        self.assertIsNone(parse_apt_auto_updates('APT::Periodic::Update-Package-Lists "1";'))


class ResultTests(unittest.TestCase):
    def test_commands_are_run_with_language_neutral_locale(self):
        with (
            patch("mojitoshield_core.shutil.which", return_value="/usr/bin/systemctl"),
            patch("mojitoshield_core.subprocess.run") as run,
        ):
            _run_command(["systemctl", "is-active", "ssh.service"])

        self.assertEqual(run.call_args.kwargs["env"]["LANG"], "C")
        self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")
        self.assertEqual(run.call_args.kwargs["env"]["LANGUAGE"], "C")

    def test_helper_response_contains_language_neutral_codes(self):
        output = json.dumps(
            {
                "version": 1,
                "results": [
                    {
                        "check_id": "firewall",
                        "status": "ok",
                        "message_id": "firewall.active",
                        "evidence": "status: active",
                    }
                ],
            }
        )

        (result,) = _parse_privileged_output(("firewall",), output)

        self.assertEqual(result.message_id, "firewall.active")
        self.assertIs(result.status, Status.OK)
        self.assertFalse(hasattr(result, "summary"))

    def test_helper_response_cannot_return_an_unrequested_check(self):
        output = json.dumps(
            {
                "version": 1,
                "results": [
                    {
                        "check_id": "timeshift",
                        "status": "unknown",
                        "message_id": "timeshift.path_unreadable",
                    }
                ],
            }
        )

        with self.assertRaises(PrivilegedScanFailed):
            _parse_privileged_output(("firewall",), output)

    def test_unallowlisted_check_is_rejected_before_authentication(self):
        self.assertEqual(PRIVILEGED_CHECK_IDS, {"firewall", "boot-menu"})
        with patch("mojitoshield_core.privileged_helper_available") as is_available:
            with self.assertRaises(ValueError):
                run_privileged_checks(("run-arbitrary-command",))
        is_available.assert_not_called()

    def test_status_presentation_is_selected_outside_the_analysis_core(self):
        self.assertEqual(translate("status.auth_required"), "Requires extended permission")
        self.assertEqual(translate("unknown.message_id"), "unknown.message_id")


if __name__ == "__main__":
    unittest.main()

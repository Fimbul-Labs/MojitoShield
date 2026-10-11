import unittest
import json
import subprocess
from unittest.mock import patch

from mojitoshield_core import (
    CHECKS,
    PRIVILEGED_CHECK_IDS,
    PrivilegedScanFailed,
    Status,
    _parse_privileged_output,
    _run_command,
    identify_distribution,
    parse_apt_auto_updates,
    run_privileged_checks,
)
from mojitoshield_i18n import language_from_locale, translate


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
            'APT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "1";\n'
        )

        self.assertIs(parse_apt_auto_updates(contents), True)

    def test_disabled_setting_is_detected(self):
        contents = (
            'APT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "0";\n'
        )

        self.assertIs(parse_apt_auto_updates(contents), False)

    def test_incomplete_settings_are_not_assumed_safe(self):
        self.assertIsNone(parse_apt_auto_updates('APT::Periodic::Update-Package-Lists "1";'))


class ResultTests(unittest.TestCase):
    def test_all_original_topics_are_present_in_two_levels(self):
        self.assertEqual(len(CHECKS), 11)
        self.assertEqual([check.level for check in CHECKS].count(1), 8)
        self.assertEqual([check.level for check in CHECKS].count(2), 3)

    def test_unavailable_ufw_is_not_assumed_to_require_root(self):
        firewall_check = next(check for check in CHECKS if check.check_id == "firewall")

        with patch("mojitoshield_core._run_command", return_value=None):
            result = firewall_check.run(firewall_check)

        self.assertIs(result.status, Status.UNKNOWN)
        self.assertEqual(result.message_id, "firewall.command_unavailable")

    def test_ufw_root_requirement_does_not_depend_on_error_language(self):
        firewall_check = next(check for check in CHECKS if check.check_id == "firewall")
        error_texts = (
            "ERROR: Du måste vara root för att köra detta skript",
            "ERROR: You need to be root to run this script",
            "ERREUR : vous devez être root pour exécuter ce script",
            "FEHLER: Dieses Skript muss als root ausgeführt werden",
        )

        for error_text in error_texts:
            command = subprocess.CompletedProcess(
                args=["ufw", "status"],
                returncode=1,
                stdout="",
                stderr=error_text,
            )
            with self.subTest(error_text=error_text), patch(
                "mojitoshield_core._run_command", return_value=command
            ):
                result = firewall_check.run(firewall_check)

            self.assertIs(result.status, Status.AUTH_REQUIRED)
            self.assertEqual(result.message_id, "firewall.authorization_required")

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
        self.assertEqual(PRIVILEGED_CHECK_IDS, {"firewall", "timeshift", "access-control"})
        with patch("mojitoshield_core.privileged_helper_available") as is_available:
            with self.assertRaises(ValueError):
                run_privileged_checks(("run-arbitrary-command",))
        is_available.assert_not_called()

    def test_status_presentation_is_selected_outside_the_analysis_core(self):
        self.assertEqual(translate("status.auth_required", "sv"), "Kräver utökad behörighet")
        self.assertEqual(translate("status.auth_required", "en"), "Requires extended permission")

    def test_desktop_locale_selects_language_and_has_english_fallback(self):
        self.assertEqual(language_from_locale("sv_SE.UTF-8"), "sv")
        self.assertEqual(language_from_locale("ar_EG.UTF-8"), "ar")
        self.assertEqual(language_from_locale("de_DE.UTF-8"), "en")

if __name__ == "__main__":
    unittest.main()
import json
import os
import stat
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

import mojitoshield_privileged as helper
from mojitoshield_core import (
    PKEXEC_PATH,
    PRIVILEGED_HELPER_PATH,
    PrivilegedHelperUnavailable,
    PrivilegedScanCancelled,
    PrivilegedScanFailed,
    _is_trusted_system_path,
    run_privileged_checks,
)


def _fake_stat(file_mode: int, file_uid: int = 0, directory_mode: int = 0o755):
    """Return a Path.stat replacement for a single file in root-owned directories."""

    def fake(path: Path, *args, **kwargs) -> os.stat_result:
        if path.name == "target":
            return os.stat_result((stat.S_IFREG | file_mode, 0, 0, 1, file_uid, 0, 0, 0, 0, 0))
        return os.stat_result((stat.S_IFDIR | directory_mode, 0, 0, 1, 0, 0, 0, 0, 0, 0))

    return fake


class TrustedPathTests(unittest.TestCase):
    path = Path("/usr/share/example/target")

    def _is_trusted(self, *, executable: bool, **stat_options) -> bool:
        with (
            patch.object(Path, "resolve", lambda path, strict=False: path),
            patch.object(Path, "stat", _fake_stat(**stat_options)),
        ):
            return _is_trusted_system_path(self.path, executable=executable)

    def test_root_owned_policy_file_is_trusted_without_execute_bit(self):
        self.assertTrue(self._is_trusted(executable=False, file_mode=0o644))

    def test_root_owned_helper_must_be_executable(self):
        self.assertTrue(self._is_trusted(executable=True, file_mode=0o755))
        self.assertFalse(self._is_trusted(executable=True, file_mode=0o644))

    def test_user_owned_or_writable_files_are_not_trusted(self):
        self.assertFalse(self._is_trusted(executable=False, file_mode=0o644, file_uid=1000))
        self.assertFalse(self._is_trusted(executable=False, file_mode=0o664))
        self.assertFalse(self._is_trusted(executable=False, file_mode=0o646))

    def test_writable_parent_directory_is_not_trusted(self):
        self.assertFalse(self._is_trusted(executable=False, file_mode=0o644, directory_mode=0o777))

    def test_missing_file_is_not_trusted(self):
        self.assertFalse(
            _is_trusted_system_path(Path("/nonexistent/mojitoshield"), executable=False)
        )


class PrivilegedHelperTests(unittest.TestCase):
    def test_helper_refuses_to_run_without_root(self):
        with patch("mojitoshield_privileged.os.geteuid", return_value=1000):
            self.assertEqual(helper.main(["firewall"]), 2)

    def test_helper_rejects_unknown_checks_before_running_anything(self):
        with (
            patch("mojitoshield_privileged.os.geteuid", return_value=0),
            patch("mojitoshield_privileged._firewall") as firewall_check,
        ):
            self.assertEqual(helper.main(["arbitrary-command"]), 2)
        firewall_check.assert_not_called()

    def test_helper_only_runs_the_allowlisted_requested_check(self):
        with (
            patch("mojitoshield_privileged.os.geteuid", return_value=0),
            patch(
                "mojitoshield_privileged._firewall",
                return_value={
                    "check_id": "firewall",
                    "status": "ok",
                    "message_id": "firewall.active",
                },
            ),
            patch("mojitoshield_privileged.sys.stdout") as stdout,
        ):
            self.assertEqual(helper.main(["firewall"]), 0)

        payload = json.loads("".join(call.args[0] for call in stdout.write.call_args_list))
        self.assertEqual(payload["results"][0]["check_id"], "firewall")

    def test_firewall_helper_uses_fixed_binary_and_c_locale(self):
        command = subprocess.CompletedProcess(
            args=["/usr/sbin/ufw", "status"],
            returncode=0,
            stdout="Status: active\n",
            stderr="",
        )
        with (
            patch("mojitoshield_privileged.UFW_EXECUTABLE") as ufw_executable,
            patch("mojitoshield_privileged.subprocess.run", return_value=command) as run,
        ):
            ufw_executable.is_file.return_value = True
            ufw_executable.__str__.return_value = "/usr/sbin/ufw"
            result = helper._firewall()

        self.assertEqual(run.call_args.args[0], ["/usr/sbin/ufw", "status"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")
        self.assertEqual(run.call_args.kwargs["env"]["LANGUAGE"], "C")
        self.assertEqual(result["message_id"], "firewall.active")

    def test_pkexec_receives_only_fixed_helper_and_allowlisted_check_ids(self):
        response = json.dumps(
            {
                "version": 1,
                "results": [
                    {
                        "check_id": "firewall",
                        "status": "ok",
                        "message_id": "firewall.active",
                    }
                ],
            }
        )
        process = subprocess.CompletedProcess([], 0, response, "")

        with (
            patch("mojitoshield_core.privileged_helper_available", return_value=True),
            patch("mojitoshield_core.subprocess.run", return_value=process) as run,
        ):
            (result,) = run_privileged_checks(("firewall",))

        self.assertEqual(
            run.call_args.args[0],
            [str(PKEXEC_PATH), str(PRIVILEGED_HELPER_PATH), "firewall"],
        )
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(result.message_id, "firewall.active")

    def test_helper_and_app_agree_on_grub_passwords(self):
        from mojitoshield_core import grub_password_configured

        samples = (
            'set superusers="admin"\npassword_pbkdf2 admin grub.pbkdf2.sha512.10000.ABC',
            "set superusers=admin\npassword admin secret",
            '# set superusers="admin"\n# password_pbkdf2 admin x',
            'set superusers=""\npassword_pbkdf2 admin x',
            'set superusers="admin"',
            "",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(
                    helper._grub_password_configured(sample), grub_password_configured(sample)
                )

    def test_boot_menu_helper_returns_only_a_conclusion(self):
        with tempfile.TemporaryDirectory() as directory:
            grub_config = Path(directory) / "grub.cfg"
            grub_config.write_text(
                'set superusers="admin"\npassword_pbkdf2 admin grub.pbkdf2.SECRET\n'
            )
            with patch.object(
                helper, "GRUB_CONFIGS", (grub_config, Path(directory) / "custom.cfg")
            ):
                result = helper._boot_menu()
                grub_config.write_text("menuentry 'Linux Mint' {}\n")
                missing = helper._boot_menu()

        self.assertEqual(
            result,
            {"check_id": "boot-menu", "status": "ok", "message_id": "boot_menu.password_active"},
        )
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertEqual(missing["message_id"], "boot_menu.password_not_active")

    def test_dismissed_authorization_dialog_is_reported_as_cancelled(self):
        process = subprocess.CompletedProcess([], 126, "", "")
        with (
            patch("mojitoshield_core.privileged_helper_available", return_value=True),
            patch("mojitoshield_core.subprocess.run", return_value=process),
        ):
            with self.assertRaises(PrivilegedScanCancelled):
                run_privileged_checks(("firewall",))

    def test_helper_failure_and_timeout_are_reported_as_failed(self):
        failures = (
            {"return_value": subprocess.CompletedProcess([], 1, "", "")},
            {"side_effect": subprocess.TimeoutExpired("pkexec", 30)},
            {"side_effect": OSError()},
        )
        for failure in failures:
            with (
                self.subTest(failure=failure),
                patch("mojitoshield_core.privileged_helper_available", return_value=True),
                patch("mojitoshield_core.subprocess.run", **failure),
            ):
                with self.assertRaises(PrivilegedScanFailed):
                    run_privileged_checks(("firewall",))

    def test_missing_helper_is_detected_before_pkexec_starts(self):
        with (
            patch("mojitoshield_core.privileged_helper_available", return_value=False),
            patch("mojitoshield_core.subprocess.run") as run,
        ):
            with self.assertRaises(PrivilegedHelperUnavailable):
                run_privileged_checks(("firewall",))
        run.assert_not_called()

    def test_policy_action_points_to_the_fixed_helper_and_does_not_cache_auth(self):
        policy_path = (
            Path(__file__).parents[1] / "data/polkit/org.mojitoshield.privileged-check.policy"
        )
        policy = ET.parse(policy_path).getroot()
        action = policy.find("action")

        self.assertIsNotNone(action)
        assert action is not None
        self.assertEqual(action.attrib["id"], "org.mojitoshield.privileged-check")
        annotations = {
            annotation.attrib["key"]: annotation.text for annotation in action.findall("annotate")
        }
        self.assertEqual(
            annotations["org.freedesktop.policykit.exec.path"],
            str(PRIVILEGED_HELPER_PATH),
        )
        self.assertFalse(
            any(
                "auth_admin_keep" in (element.text or "")
                for element in action.findall("defaults/*")
            )
        )


if __name__ == "__main__":
    unittest.main()

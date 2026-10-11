import json
import subprocess
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

import mojitoshield_privileged as helper
from mojitoshield_core import (
    PKEXEC_PATH,
    PRIVILEGED_HELPER_PATH,
    PrivilegedScanFailed,
    run_privileged_checks,
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

    def test_policy_action_points_to_the_fixed_helper_and_does_not_cache_auth(self):
        policy_path = (
            Path(__file__).parents[1]
            / "data/polkit/org.mojitoshield.privileged-check.policy"
        )
        policy = ET.parse(policy_path).getroot()
        action = policy.find("action")

        self.assertIsNotNone(action)
        assert action is not None
        self.assertEqual(action.attrib["id"], "org.mojitoshield.privileged-check")
        annotations = {
            annotation.attrib["key"]: annotation.text
            for annotation in action.findall("annotate")
        }
        self.assertEqual(
            annotations["org.freedesktop.policykit.exec.path"],
            str(PRIVILEGED_HELPER_PATH),
        )
        self.assertFalse(any("auth_admin_keep" in (element.text or "") for element in action.findall("defaults/*")))


if __name__ == "__main__":
    unittest.main()
import re
import shutil
import subprocess
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from mojitoshield_core import PRIVILEGED_HELPER_PATH, PRIVILEGED_POLICY_PATH


SOURCE_ROOT = Path(__file__).parents[1]


class DebianPackagingTests(unittest.TestCase):
    def _install_entries(self) -> list[tuple[str, str]]:
        manifest = SOURCE_ROOT / "debian/mojitoshield.install"
        return [
            tuple(line.split())
            for line in manifest.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_every_installed_source_file_exists(self):
        for source, _destination in self._install_entries():
            with self.subTest(source=source):
                self.assertTrue((SOURCE_ROOT / source).is_file())

    def test_install_destinations_are_directories(self):
        # dh_install cannot rename files; a destination is always a directory.
        for _source, destination in self._install_entries():
            with self.subTest(destination=destination):
                self.assertTrue(destination.endswith("/"))

    def test_policy_is_installed_where_the_app_trusts_it(self):
        destinations = {
            "/" + destination + Path(source).name
            for source, destination in self._install_entries()
        }
        self.assertIn(str(PRIVILEGED_POLICY_PATH), destinations)

    def test_rules_install_the_helper_at_the_fixed_path(self):
        rules = (SOURCE_ROOT / "debian/rules").read_text(encoding="utf-8")
        self.assertIn("mojitoshield_privileged.py", rules)
        self.assertIn(f"debian/mojitoshield{PRIVILEGED_HELPER_PATH}", rules)

    def test_launcher_runs_the_installed_application(self):
        launcher = (SOURCE_ROOT / "mojitoshield").read_text(encoding="utf-8")
        destinations = {
            "/" + destination + Path(source).name
            for source, destination in self._install_entries()
        }
        installed_app = next(
            path for path in destinations if path.endswith("/mojitoshield.py")
        )
        self.assertIn(installed_app, launcher)

    def test_package_requires_the_python_version_the_code_uses(self):
        # platform.freedesktop_os_release and runtime "X | Y" unions need Python 3.10.
        control = (SOURCE_ROOT / "debian/control").read_text(encoding="utf-8")
        self.assertRegex(control, r"(?m)^Depends:.*\bpython3 \(>= 3\.10\)")

    def test_helper_runs_python_in_isolated_mode(self):
        helper = SOURCE_ROOT / "mojitoshield_privileged.py"
        first_line = helper.read_text(encoding="utf-8").splitlines()[0]
        self.assertEqual(first_line, "#!/usr/bin/python3 -I")


class ApplicationIdentityTests(unittest.TestCase):
    def application_id(self) -> str:
        gui_source = (SOURCE_ROOT / "mojitoshield.py").read_text(encoding="utf-8")
        return re.search(r'^APPLICATION_ID = "([^"]+)"$', gui_source, re.M).group(1)

    def test_desktop_entry_metainfo_and_icon_share_the_application_id(self):
        application_id = self.application_id()
        data = SOURCE_ROOT / "data"
        self.assertTrue((data / f"applications/{application_id}.desktop").is_file())
        self.assertTrue(
            (data / f"icons/hicolor/scalable/apps/{application_id}.svg").is_file()
        )

        metainfo = ET.parse(data / f"metainfo/{application_id}.metainfo.xml").getroot()
        self.assertEqual(metainfo.findtext("id"), application_id)
        self.assertEqual(metainfo.findtext("launchable"), f"{application_id}.desktop")

        desktop = (data / f"applications/{application_id}.desktop").read_text(encoding="utf-8")
        self.assertIn(f"\nIcon={application_id}\n", desktop)

    def test_metainfo_and_icon_are_packaged(self):
        manifest = (SOURCE_ROOT / "debian/mojitoshield.install").read_text(encoding="utf-8")
        self.assertIn("usr/share/metainfo/", manifest)
        self.assertIn("usr/share/icons/hicolor/scalable/apps/", manifest)


@unittest.skipIf(shutil.which("appstreamcli") is None, "appstreamcli missing")
class MetainfoTests(unittest.TestCase):
    def test_metainfo_has_no_validation_errors(self):
        (metainfo,) = (SOURCE_ROOT / "data/metainfo").glob("*.metainfo.xml")
        result = subprocess.run(
            ["appstreamcli", "validate", "--no-net", "--no-color", str(metainfo)],
            capture_output=True,
            text=True,
            check=False,
            env={"LC_ALL": "C", "LANGUAGE": "C", "PATH": "/usr/bin:/bin"},
        )
        errors = [line for line in result.stdout.splitlines() if line.startswith("E:")]
        self.assertEqual(errors, [], result.stdout)


@unittest.skipIf(shutil.which("desktop-file-validate") is None, "desktop-file-validate missing")
class DesktopEntryTests(unittest.TestCase):
    def test_desktop_entry_is_valid(self):
        (desktop_file,) = (SOURCE_ROOT / "data/applications").glob("*.desktop")
        result = subprocess.run(
            ["desktop-file-validate", str(desktop_file)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

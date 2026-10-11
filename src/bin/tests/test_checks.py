"""Outcome tests for each of the 11 checks, using fake local system data."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import mojitoshield_core as core
from mojitoshield_core import CHECKS, Status


def check(check_id: str):
    return next(definition for definition in CHECKS if definition.check_id == check_id)


def run(check_id: str):
    definition = check(check_id)
    return definition.run(definition)


def completed(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout, "")


def fake_commands(responses: dict[tuple[str, ...], subprocess.CompletedProcess | None]):
    """Answer _run_command by the longest matching argument prefix."""

    def run_command(arguments: list[str]):
        for length in range(len(arguments), 0, -1):
            key = tuple(arguments[:length])
            if key in responses:
                return responses[key]
        return None

    return patch("mojitoshield_core._run_command", side_effect=run_command)


class TemporaryFilesTestCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def write(self, relative: str, contents: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def patch_path(self, name: str, relative: str) -> Path:
        path = self.root / relative
        patcher = patch.object(core, name, path)
        patcher.start()
        self.addCleanup(patcher.stop)
        return path


class DistributionTests(unittest.TestCase):
    def test_supported_and_unsupported_distributions(self):
        cases = (
            ({"ID": "linuxmint", "NAME": "Linux Mint"}, True),
            ({"ID": "debian", "NAME": "LMDE", "PRETTY_NAME": "LMDE 6 (faye)"}, True),
            ({"ID": "debian", "PRETTY_NAME": "Linux Mint Debian Edition 6"}, True),
            ({"ID": "ubuntu", "ID_LIKE": "debian", "NAME": "Ubuntu"}, False),
            ({"ID": "debian", "NAME": "Debian GNU/Linux"}, False),
            ({"ID": "fedora", "NAME": "Fedora Linux"}, False),
            ({}, False),
        )
        for release, supported in cases:
            with self.subTest(release=release):
                self.assertIs(core.identify_distribution(release), supported)

    def test_missing_os_release_is_reported_as_unknown_distribution(self):
        with patch("mojitoshield_core.platform.freedesktop_os_release", side_effect=OSError):
            self.assertEqual(core.current_distribution(), (False, None))

    def test_current_distribution_returns_display_name(self):
        release = {"ID": "linuxmint", "NAME": "Linux Mint", "PRETTY_NAME": "Linux Mint 22.2"}
        with patch("mojitoshield_core.platform.freedesktop_os_release", return_value=release):
            self.assertEqual(core.current_distribution(), (True, "Linux Mint 22.2"))


class FirewallTests(unittest.TestCase):
    def test_active_and_inactive_ufw(self):
        for output, status, message_id in (
            ("Status: active\n\nTo Action From\n", Status.OK, "firewall.active"),
            ("Status: inactive\n", Status.WARNING, "firewall.inactive"),
            ("Something else\n", Status.UNKNOWN, "firewall.unrecognized_status"),
        ):
            with self.subTest(output=output), fake_commands({("ufw",): completed(output)}):
                result = run("firewall")
            self.assertIs(result.status, status)
            self.assertEqual(result.message_id, message_id)


class AutomaticUpdatesTests(TemporaryFilesTestCase):
    ENABLED = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
    DISABLED = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "0";\n'

    def setUp(self):
        super().setUp()
        self.apt_file = self.patch_path("APT_AUTO_UPGRADES", "apt/20auto-upgrades")
        self.script = self.patch_path("MINTUPDATE_AUTOMATION_SCRIPT", "mintupdate/automatic_upgrades.py")
        self.flag = self.patch_path("MINTUPDATE_UPGRADE_FLAG", "lib/upgrades-enabled")

    def install_mintupdate(self, *, flag: bool, timer_state: str):
        self.write("mintupdate/automatic_upgrades.py", "")
        if flag:
            self.write("lib/upgrades-enabled", "")
        return fake_commands({("systemctl", "is-enabled"): completed(timer_state + "\n")})

    def test_apt_unattended_upgrades_enabled(self):
        self.write("apt/20auto-upgrades", self.ENABLED)
        result = run("updates")
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.message_id, "updates.enabled")

    def test_apt_unattended_upgrades_disabled_without_mintupdate(self):
        self.write("apt/20auto-upgrades", self.DISABLED)
        result = run("updates")
        self.assertIs(result.status, Status.WARNING)
        self.assertEqual(result.message_id, "updates.disabled")

    def test_incomplete_apt_settings_are_not_assumed_safe(self):
        self.write("apt/20auto-upgrades", 'APT::Periodic::Update-Package-Lists "1";\n')
        result = run("updates")
        self.assertIs(result.status, Status.UNKNOWN)
        self.assertEqual(result.message_id, "updates.settings_unparseable")

    def test_missing_settings_without_mintupdate_cannot_be_determined(self):
        result = run("updates")
        self.assertIs(result.status, Status.UNKNOWN)
        self.assertEqual(result.message_id, "updates.settings_unreadable")

    def test_update_manager_automation_enabled(self):
        with self.install_mintupdate(flag=True, timer_state="enabled"):
            result = run("updates")
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.message_id, "updates.mintupdate_automation_enabled")

    def test_update_manager_automation_needs_both_flag_and_timer(self):
        for flag, timer_state in ((False, "enabled"), (True, "disabled"), (False, "disabled")):
            with self.subTest(flag=flag, timer_state=timer_state):
                self.flag.unlink(missing_ok=True)
                with self.install_mintupdate(flag=flag, timer_state=timer_state):
                    result = run("updates")
                self.assertIs(result.status, Status.WARNING)
                self.assertEqual(result.message_id, "updates.mintupdate_automation_disabled")

    def test_apt_unattended_upgrades_count_even_when_update_manager_automation_is_off(self):
        self.write("apt/20auto-upgrades", self.ENABLED)
        with self.install_mintupdate(flag=False, timer_state="disabled"):
            result = run("updates")
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.message_id, "updates.enabled")


class TimeshiftTests(TemporaryFilesTestCase):
    ROOT_UUID = "11111111-2222-3333-4444-555555555555"

    def setUp(self):
        super().setUp()
        self.patch_path("TIMESHIFT_CONFIG", "etc/timeshift.json")
        self.snapshots = self.patch_path("TIMESHIFT_SNAPSHOTS", "timeshift/snapshots")
        commands = fake_commands({("findmnt",): completed(self.ROOT_UUID + "\n")})
        commands.start()
        self.addCleanup(commands.stop)

    def write_settings(self, **overrides: str):
        settings = {
            "backup_device_uuid": self.ROOT_UUID,
            "do_first_run": "false",
            "btrfs_mode": "false",
            "schedule_monthly": "true",
            "schedule_weekly": "false",
            "schedule_daily": "false",
            "schedule_hourly": "false",
            "schedule_boot": "false",
        }
        settings.update(overrides)
        self.write("etc/timeshift.json", json.dumps(settings))

    def test_no_result_claims_timeshift_is_verified(self):
        self.write_settings()
        (self.snapshots / "2026-10-02_22-07-41").mkdir(parents=True)
        result = run("timeshift")
        self.assertIs(result.status, Status.UNKNOWN)
        self.assertEqual(result.message_id, "timeshift.snapshots_found")
        self.assertEqual(dict(result.data), {"count": "1"})

    def test_not_configured(self):
        for overrides in ({"backup_device_uuid": ""}, {"do_first_run": "true"}):
            with self.subTest(overrides=overrides):
                self.write_settings(**overrides)
                self.assertEqual(run("timeshift").message_id, "timeshift.not_configured")

    def test_configured_without_schedule(self):
        self.write_settings(schedule_monthly="false")
        self.assertEqual(run("timeshift").message_id, "timeshift.configured_without_schedule")

    def test_btrfs_snapshots_are_not_counted(self):
        self.write_settings(btrfs_mode="true")
        self.assertEqual(run("timeshift").message_id, "timeshift.btrfs_scheduled")

    def test_snapshots_on_separate_device(self):
        self.write_settings(backup_device_uuid="99999999-0000-0000-0000-000000000000")
        self.assertEqual(run("timeshift").message_id, "timeshift.scheduled_on_separate_device")

    def test_same_device_without_snapshots(self):
        self.write_settings()
        self.snapshots.mkdir(parents=True)
        self.assertEqual(run("timeshift").message_id, "timeshift.no_snapshots_at_default_path")

    def test_missing_settings_fall_back_to_snapshot_directory(self):
        result = run("timeshift")
        self.assertIs(result.status, Status.UNKNOWN)
        self.assertEqual(result.message_id, "timeshift.path_unreadable")

    def test_corrupt_settings_fall_back_to_snapshot_directory(self):
        self.write("etc/timeshift.json", "{not json")
        self.assertEqual(run("timeshift").message_id, "timeshift.path_unreadable")

    def test_unreadable_snapshot_directory_requires_permission(self):
        with patch.object(Path, "iterdir", side_effect=PermissionError):
            result = run("timeshift")
        self.assertIs(result.status, Status.AUTH_REQUIRED)


class AccessControlTests(TemporaryFilesTestCase):
    def setUp(self):
        super().setUp()
        self.patch_path("SELINUX_ENFORCE", "selinux/enforce")
        self.patch_path("APPARMOR_ENABLED", "apparmor/enabled")
        self.patch_path("APPARMOR_PROFILES", "apparmor/profiles")

    def test_selinux_modes(self):
        for value, status in (("1", Status.OK), ("0", Status.WARNING)):
            with self.subTest(value=value):
                self.write("selinux/enforce", value)
                self.assertIs(run("access-control").status, status)

    def test_apparmor_enforcing_profiles(self):
        self.write("apparmor/enabled", "Y\n")
        self.write("apparmor/profiles", "/usr/bin/man (enforce)\nlsb_release (enforce)\nfoo (complain)\n")
        result = run("access-control")
        self.assertIs(result.status, Status.OK)
        self.assertEqual(dict(result.data), {"count": "2"})

    def test_apparmor_disabled(self):
        self.write("apparmor/enabled", "N\n")
        self.write("apparmor/profiles", "")
        self.assertIs(run("access-control").status, Status.WARNING)

    def test_apparmor_enabled_without_enforcing_profiles_is_unconfirmed(self):
        self.write("apparmor/enabled", "Y\n")
        self.write("apparmor/profiles", "foo (complain)\n")
        self.assertEqual(run("access-control").message_id, "access_control.apparmor_unconfirmed")

    def test_missing_security_module_data(self):
        self.assertEqual(run("access-control").message_id, "access_control.status_unreadable")


class SshAndClamAvTests(unittest.TestCase):
    def test_ssh_states(self):
        for states, status in (
            ({"ssh.service": "inactive", "sshd.service": "inactive", "ssh.socket": "inactive"}, Status.OK),
            ({"ssh.service": "inactive", "sshd.service": "inactive", "ssh.socket": "active"}, Status.WARNING),
        ):
            responses = {
                ("systemctl", "is-active", unit): completed(state + "\n", 0 if state == "active" else 3)
                for unit, state in states.items()
            }
            with self.subTest(states=states), fake_commands(responses):
                self.assertIs(run("ssh").status, status)

    def test_ssh_without_systemctl(self):
        with fake_commands({}):
            self.assertEqual(run("ssh").message_id, "ssh.status_unavailable")

    def test_clamav_is_never_a_warning(self):
        for state in ("active", "inactive"):
            with self.subTest(state=state), fake_commands(
                {("systemctl", "is-active"): completed(state + "\n")}
            ):
                result = run("clamav")
            self.assertIsNot(result.status, Status.WARNING)


class ScreenLockTests(unittest.TestCase):
    def test_desktop_detection(self):
        for value, desktop in (
            ("X-Cinnamon", "cinnamon"),
            ("MATE", "mate"),
            ("XFCE", "xfce"),
            ("ubuntu:GNOME", None),
            ("", None),
        ):
            with self.subTest(value=value):
                self.assertEqual(core.current_desktop({"XDG_CURRENT_DESKTOP": value}), desktop)

    def test_each_mint_desktop_uses_its_own_setting(self):
        for desktop, command in (
            ("X-Cinnamon", ("gsettings", "get", "org.cinnamon.desktop.screensaver")),
            ("MATE", ("gsettings", "get", "org.mate.screensaver")),
            ("XFCE", ("xfconf-query", "--channel", "xfce4-screensaver")),
        ):
            for output, status in (("true\n", Status.OK), ("false\n", Status.WARNING)):
                with (
                    self.subTest(desktop=desktop, output=output),
                    patch.dict("os.environ", {"XDG_CURRENT_DESKTOP": desktop}),
                    fake_commands({command: completed(output)}),
                ):
                    result = run("screen-lock")
                self.assertIs(result.status, status)
                self.assertIn("desktop", dict(result.data))

    def test_unsupported_desktop_is_not_guessed(self):
        with patch.dict("os.environ", {"XDG_CURRENT_DESKTOP": "KDE"}), fake_commands({}) as command:
            result = run("screen-lock")
        self.assertEqual(result.message_id, "screen_lock.desktop_not_supported")
        command.assert_not_called()

    def test_failing_settings_query(self):
        with (
            patch.dict("os.environ", {"XDG_CURRENT_DESKTOP": "X-Cinnamon"}),
            fake_commands({("gsettings",): completed("", 1)}),
        ):
            self.assertEqual(run("screen-lock").message_id, "screen_lock.settings_unavailable")


class BluetoothTests(TemporaryFilesTestCase):
    def setUp(self):
        super().setUp()
        self.patch_path("RFKILL_DIRECTORY", "rfkill")

    def add_radio(self, name: str, kind: str, soft: str, hard: str = "0"):
        self.write(f"rfkill/{name}/type", kind + "\n")
        self.write(f"rfkill/{name}/soft", soft + "\n")
        self.write(f"rfkill/{name}/hard", hard + "\n")

    def test_unblocked_bluetooth_is_not_a_warning(self):
        self.add_radio("rfkill0", "bluetooth", "0")
        result = run("bluetooth")
        self.assertIs(result.status, Status.UNKNOWN)
        self.assertEqual(result.message_id, "bluetooth.unblocked_is_not_proof_of_risk")

    def test_all_blocked_bluetooth(self):
        self.add_radio("rfkill0", "bluetooth", "1")
        self.add_radio("rfkill1", "bluetooth", "0", hard="1")
        self.add_radio("rfkill2", "wlan", "0")
        self.assertIs(run("bluetooth").status, Status.OK)

    def test_no_bluetooth_radio(self):
        self.add_radio("rfkill0", "wlan", "0")
        self.assertEqual(run("bluetooth").message_id, "bluetooth.no_radio_found")


class RootShellTests(unittest.TestCase):
    def test_undefined_check_never_claims_a_result(self):
        result = run("root-shell")
        self.assertIs(result.status, Status.UNKNOWN)
        self.assertEqual(result.message_id, "root_shell.check_not_implemented")


class EncryptionTests(unittest.TestCase):
    def commands(self, source: str, fstype: str, lsblk_types: str | None):
        responses = {
            ("findmnt",): completed(f'SOURCE="{source}" FSTYPE="{fstype}"\n'),
        }
        if lsblk_types is not None:
            device = core.block_device_from_mount_source(source)
            responses[("lsblk", "--inverse", "--noheadings", "--output", "TYPE", device)] = (
                completed(lsblk_types)
            )
        return fake_commands(responses)

    def test_root_on_crypt_mapping(self):
        with self.commands("/dev/mapper/vgmint-root", "ext4", "lvm\ncrypt\npart\ndisk\n"):
            result = run("full-disk-encryption")
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.evidence, "/dev/mapper/vgmint-root")

    def test_root_without_crypt_mapping(self):
        with self.commands("/dev/nvme0n1p2", "ext4", "part\ndisk\n"):
            self.assertIs(run("full-disk-encryption").status, Status.WARNING)

    def test_btrfs_subvolume_source_is_resolved_to_its_device(self):
        with self.commands("/dev/mapper/luks-abc[/@]", "btrfs", "crypt\npart\ndisk\n"):
            self.assertIs(run("full-disk-encryption").status, Status.OK)

    def test_unreadable_mount_source(self):
        with fake_commands({}):
            result = run("full-disk-encryption")
        self.assertIs(result.status, Status.UNKNOWN)

    def test_home_on_crypt_mapping(self):
        with self.commands("/dev/mapper/home", "ext4", "crypt\npart\ndisk\n"):
            self.assertEqual(run("home-encryption").message_id, "encryption.home_crypt_mapping")

    def test_ecryptfs_home_does_not_reveal_the_home_path(self):
        with self.commands("/home/.ecryptfs/someone/.Private", "ecryptfs", None):
            result = run("home-encryption")
        self.assertIs(result.status, Status.OK)
        self.assertEqual(result.message_id, "encryption.home_ecryptfs")
        self.assertNotIn("someone", result.evidence)

    def test_home_without_encryption(self):
        with self.commands("/dev/sda2", "ext4", "part\ndisk\n"):
            self.assertIs(run("home-encryption").status, Status.WARNING)


class ScanResilienceTests(unittest.TestCase):
    def test_a_failing_check_does_not_stop_the_scan(self):
        with (
            patch("mojitoshield_core._run_command", side_effect=OSError("boom")),
            self.assertLogs("mojitoshield_core", level="WARNING") as logs,
        ):
            results = core.run_checks()

        self.assertTrue(all("boom" not in line for line in logs.output))

        self.assertEqual(len(results), 11)
        failed = [result for result in results if result.message_id == "check.unexpected_error"]
        self.assertTrue(failed)
        self.assertTrue(all(result.status is Status.UNKNOWN for result in failed))
        self.assertTrue(all("boom" not in result.evidence for result in failed))

    def test_results_follow_the_fixed_check_order(self):
        with fake_commands({}):
            results = core.run_checks()
        self.assertEqual(
            [result.check_id for result in results],
            [definition.check_id for definition in CHECKS],
        )


if __name__ == "__main__":
    unittest.main()

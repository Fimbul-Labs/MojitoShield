"""Outcome tests for each of the 9 checks, following docs/check-contracts.md."""

import gzip
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import mojitoshield_core as core
from mojitoshield_core import CHECKS, Status

NOW = datetime(2026, 10, 11, 12, 0, 0)


def run(check_id: str):
    definition = next(check for check in CHECKS if check.check_id == check_id)
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


class CheckTestCase(unittest.TestCase):
    """Gives each test a temporary root, a fixed clock and no real commands."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.start(patch("mojitoshield_core._now", return_value=NOW))

    def start(self, patcher):
        patched = patcher.start()
        self.addCleanup(patcher.stop)
        return patched

    def commands(self, responses):
        self.start(fake_commands(responses))

    def path(self, name: str, relative: str) -> Path:
        path = self.root / relative
        self.start(patch.object(core, name, path))
        return path

    def write(self, relative: str, contents: str | bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contents, bytes):
            path.write_bytes(contents)
        else:
            path.write_text(contents, encoding="utf-8")
        return path

    def assertResult(self, check_id: str, status: Status, message_id: str):
        result = run(check_id)
        self.assertEqual((result.status, result.message_id), (status, message_id))
        return result


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


class FirewallTests(CheckTestCase):
    def setUp(self):
        super().setUp()
        self.path("UFW_CONFIG", "ufw/ufw.conf")

    def test_enabled_and_running(self):
        self.write("ufw/ufw.conf", "# comment\nENABLED=yes\nLOGLEVEL=low\n")
        self.commands({("systemctl", "is-active", "ufw"): completed("active\n")})
        self.assertResult("firewall", Status.OK, "firewall.enabled")

    def test_disabled(self):
        self.write("ufw/ufw.conf", "ENABLED=no\n")
        self.commands({})
        self.assertResult("firewall", Status.WARNING, "firewall.disabled")

    def test_enabled_but_not_running_needs_the_live_status(self):
        self.write("ufw/ufw.conf", "ENABLED=yes\n")
        self.commands({("systemctl", "is-active", "ufw"): completed("inactive\n", 3)})
        self.assertResult("firewall", Status.AUTH_REQUIRED, "firewall.service_not_confirmed")

    def test_unreadable_settings_need_the_live_status(self):
        self.write("ufw/ufw.conf", "ENABLED=yes\n")
        with patch.object(Path, "read_text", side_effect=PermissionError):
            self.assertResult("firewall", Status.AUTH_REQUIRED, "firewall.authorization_required")

    def test_ufw_not_installed(self):
        self.assertResult("firewall", Status.UNKNOWN, "firewall.ufw_not_installed")

    def test_last_enabled_value_wins(self):
        self.assertIs(core.parse_ufw_enabled('ENABLED=yes\nENABLED="no"\n'), False)
        self.assertIsNone(core.parse_ufw_enabled("LOGLEVEL=low\n"))


class UpdatesTests(CheckTestCase):
    def setUp(self):
        super().setUp()
        self.path("APT_AUTO_UPGRADES", "apt/20auto-upgrades")
        self.path("MINTUPDATE_AUTOMATION_SCRIPT", "mintupdate/automatic_upgrades.py")
        self.path("MINTUPDATE_UPGRADE_FLAG", "lib/upgrades-enabled")
        self.reboot_file = self.path("REBOOT_REQUIRED", "run/reboot-required")
        self.start(
            patch.object(
                core,
                "APT_HISTORY_LOGS",
                (
                    self.root / "log/history.log",
                    self.root / "log/history.log.1.gz",
                ),
            )
        )
        self.commands({("systemctl", "is-enabled"): completed("disabled\n", 1)})

    def history(self, *entries: tuple[datetime, bool]) -> str:
        lines = []
        for started, upgraded in entries:
            lines += ["", f"Start-Date: {started:%Y-%m-%d  %H:%M:%S}", "Commandline: apt"]
            lines.append(
                "Upgrade: libc6:amd64 (2.39-0, 2.39-1)" if upgraded else "Install: foo:amd64 (1.0)"
            )
            lines.append(f"End-Date: {started:%Y-%m-%d  %H:%M:%S}")
        return "\n".join(lines) + "\n"

    def test_recently_installed_updates(self):
        self.write("log/history.log", self.history((NOW - timedelta(days=3), True)))
        result = self.assertResult("updates", Status.OK, "updates.recently_installed")
        self.assertEqual(dict(result.data), {"days": "3"})

    def test_old_updates(self):
        self.write(
            "log/history.log",
            self.history(
                (NOW - timedelta(days=45), True),
                (NOW - timedelta(days=2), False),
            ),
        )
        result = self.assertResult("updates", Status.WARNING, "updates.not_installed_recently")
        self.assertEqual(dict(result.data), {"days": "45"})

    def test_rotated_history_is_used_when_the_current_log_has_no_upgrade(self):
        self.write("log/history.log", self.history((NOW - timedelta(days=1), False)))
        self.write(
            "log/history.log.1.gz",
            gzip.compress(self.history((NOW - timedelta(days=10), True)).encode()),
        )
        self.assertResult("updates", Status.OK, "updates.recently_installed")

    def test_automatic_updates(self):
        self.write(
            "apt/20auto-upgrades",
            'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n',
        )
        self.assertResult("updates", Status.OK, "updates.automatic")

    def test_update_manager_automation_needs_flag_and_timer(self):
        self.write("mintupdate/automatic_upgrades.py", "")
        self.write("lib/upgrades-enabled", "")
        self.commands({("systemctl", "is-enabled"): completed("enabled\n")})
        self.assertResult("updates", Status.OK, "updates.automatic")

    def test_pending_reboot_for_over_a_week(self):
        self.write("run/reboot-required", "*** System restart required ***\n")
        old = (NOW - timedelta(days=9)).timestamp()
        os.utime(self.reboot_file, (old, old))
        result = self.assertResult("updates", Status.WARNING, "updates.reboot_pending")
        self.assertEqual(dict(result.data), {"days": "9"})

    def test_recent_pending_reboot_is_not_a_warning(self):
        self.write("run/reboot-required", "")
        recent = (NOW - timedelta(days=1)).timestamp()
        os.utime(self.reboot_file, (recent, recent))
        self.write("log/history.log", self.history((NOW - timedelta(days=1), True)))
        self.assertResult("updates", Status.OK, "updates.recently_installed")

    def test_no_history(self):
        self.assertResult("updates", Status.UNKNOWN, "updates.history_unavailable")


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
                self.assertEqual(core.current_desktop({"XDG_CURRENT_DESKTOP": value}), desktop)

    def test_cinnamon_locks_after_delay(self):
        self.use_desktop("X-Cinnamon")
        self.commands(
            {
                ("gsettings", "get", "org.cinnamon.desktop.screensaver"): completed("true\n"),
                ("gsettings", "get", "org.cinnamon.desktop.session"): completed("uint32 900\n"),
            }
        )
        result = self.assertResult("screen-lock", Status.OK, "screen_lock.enabled")
        self.assertEqual(dict(result.data), {"desktop": "Cinnamon", "minutes": "15"})

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
        result = self.assertResult("screen-lock", Status.OK, "screen_lock.enabled")
        self.assertEqual(dict(result.data)["minutes"], "5")

    def test_lock_disabled(self):
        self.use_desktop("X-Cinnamon")
        self.commands(
            {("gsettings", "get", "org.cinnamon.desktop.screensaver"): completed("false\n")}
        )
        self.assertResult("screen-lock", Status.WARNING, "screen_lock.disabled")

    def test_zero_idle_delay_never_locks_automatically(self):
        self.use_desktop("X-Cinnamon")
        self.commands(
            {
                ("gsettings", "get", "org.cinnamon.desktop.screensaver"): completed("true\n"),
                ("gsettings", "get", "org.cinnamon.desktop.session"): completed("uint32 0\n"),
            }
        )
        self.assertResult("screen-lock", Status.WARNING, "screen_lock.never_automatic")

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
        self.assertResult("screen-lock", Status.WARNING, "screen_lock.never_automatic")

    def test_unreadable_idle_delay(self):
        self.use_desktop("X-Cinnamon")
        self.commands(
            {("gsettings", "get", "org.cinnamon.desktop.screensaver"): completed("true\n")}
        )
        self.assertResult("screen-lock", Status.UNKNOWN, "screen_lock.idle_delay_unavailable")

    def test_unsupported_desktop_is_not_guessed(self):
        self.use_desktop("KDE")
        self.commands({})
        self.assertResult("screen-lock", Status.UNKNOWN, "screen_lock.desktop_not_supported")


class AutoLoginTests(CheckTestCase):
    def setUp(self):
        super().setUp()
        self.path("DISPLAY_MANAGER_FILE", "X11/default-display-manager")
        self.start(
            patch.object(
                core,
                "LIGHTDM_CONFIG_SOURCES",
                (
                    self.root / "share/lightdm.conf.d",
                    self.root / "etc/lightdm.conf.d",
                    self.root / "etc/lightdm.conf",
                ),
            )
        )
        self.write("X11/default-display-manager", "/usr/sbin/lightdm\n")
        self.write(
            "share/lightdm.conf.d/50-greeter.conf", "[Seat:*]\ngreeter-session=slick-greeter\n"
        )

    def test_no_automatic_login(self):
        self.write("etc/lightdm.conf.d/70-linuxmint.conf", "[Seat:*]\nuser-session=cinnamon\n")
        self.assertResult("auto-login", Status.OK, "auto_login.disabled")

    def test_automatic_login_does_not_reveal_the_user_name(self):
        self.write("etc/lightdm.conf", "[Seat:*]\nautologin-user=someone\n")
        result = self.assertResult("auto-login", Status.WARNING, "auto_login.enabled")
        self.assertNotIn("someone", repr(result))

    def test_later_file_overrides_earlier_one(self):
        self.write("etc/lightdm.conf.d/60-auto.conf", "[SeatDefaults]\nautologin-user=someone\n")
        self.write("etc/lightdm.conf", "[Seat:*]\nautologin-user=\n")
        self.assertResult("auto-login", Status.OK, "auto_login.disabled")

    def test_broken_file_is_skipped_like_login_window_does(self):
        self.write("etc/lightdm.conf.d/10-broken.conf", "autologin-user=someone\n")
        self.assertResult("auto-login", Status.OK, "auto_login.disabled")

    def test_other_display_manager(self):
        self.write("X11/default-display-manager", "/usr/sbin/gdm3\n")
        result = self.assertResult(
            "auto-login", Status.UNKNOWN, "auto_login.display_manager_not_supported"
        )
        self.assertEqual(dict(result.data), {"display_manager": "gdm3"})

    def test_unknown_display_manager(self):
        (self.root / "X11/default-display-manager").unlink()
        self.assertResult("auto-login", Status.UNKNOWN, "auto_login.display_manager_unknown")


class TimeshiftTests(CheckTestCase):
    ROOT_UUID = "11111111-2222-3333-4444-555555555555"

    def setUp(self):
        super().setUp()
        self.executable = self.path("TIMESHIFT_EXECUTABLE", "bin/timeshift")
        self.path("TIMESHIFT_CONFIG", "etc/timeshift.json")
        self.snapshots = self.path("TIMESHIFT_SNAPSHOTS", "timeshift/snapshots")
        self.write("bin/timeshift", "")
        self.commands({("findmnt",): completed(self.ROOT_UUID + "\n")})

    def settings(self, **overrides: str):
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

    def snapshot(self, age_days: float):
        (self.snapshots / f"{NOW - timedelta(days=age_days):%Y-%m-%d_%H-%M-%S}").mkdir(
            parents=True
        )

    def test_recent_snapshot(self):
        self.settings()
        self.snapshot(60)
        self.snapshot(8)
        result = self.assertResult("timeshift", Status.OK, "timeshift.recent_snapshot")
        self.assertEqual(dict(result.data), {"days": "8", "limit": "40"})

    def test_snapshot_older_than_the_limit(self):
        self.settings()
        self.snapshot(41)
        self.assertResult("timeshift", Status.WARNING, "timeshift.snapshot_too_old")

    def test_limit_follows_the_schedule(self):
        self.settings(schedule_monthly="false", schedule_weekly="true")
        self.snapshot(15)
        result = self.assertResult("timeshift", Status.WARNING, "timeshift.snapshot_too_old")
        self.assertEqual(dict(result.data)["limit"], "14")

    def test_age_limit_bounds(self):
        self.assertEqual(core.timeshift_age_limit_days(("hourly",)), 7)
        self.assertEqual(core.timeshift_age_limit_days(("daily", "monthly")), 7)
        self.assertEqual(core.timeshift_age_limit_days(("weekly",)), 14)
        self.assertEqual(core.timeshift_age_limit_days(("monthly",)), 40)
        self.assertEqual(core.timeshift_age_limit_days(("boot",)), 40)
        self.assertEqual(core.timeshift_age_limit_days(()), 40)

    def test_set_up_without_snapshots(self):
        self.settings()
        self.snapshots.mkdir(parents=True)
        (self.snapshots / "not-a-snapshot").mkdir()
        self.assertResult("timeshift", Status.WARNING, "timeshift.no_snapshots")

    def test_never_set_up(self):
        self.assertResult("timeshift", Status.WARNING, "timeshift.not_set_up")
        for overrides in ({"backup_device_uuid": ""}, {"do_first_run": "true"}):
            with self.subTest(overrides=overrides):
                self.settings(**overrides)
                self.assertResult("timeshift", Status.WARNING, "timeshift.not_set_up")

    def test_not_installed(self):
        self.executable.unlink()
        self.assertResult("timeshift", Status.UNKNOWN, "timeshift.not_installed")

    def test_snapshots_that_cannot_be_seen(self):
        self.settings(btrfs_mode="true")
        self.assertResult("timeshift", Status.UNKNOWN, "timeshift.btrfs_mode")
        self.settings(backup_device_uuid="99999999-0000-0000-0000-000000000000")
        self.assertResult("timeshift", Status.UNKNOWN, "timeshift.separate_device")

    def test_corrupt_settings(self):
        self.write("etc/timeshift.json", "{not json")
        self.assertResult("timeshift", Status.UNKNOWN, "timeshift.settings_unreadable")

    def test_unreadable_snapshot_folder(self):
        self.settings()
        with patch.object(Path, "iterdir", side_effect=PermissionError):
            self.assertResult("timeshift", Status.UNKNOWN, "timeshift.snapshots_unreadable")


class NetworkServicesTests(CheckTestCase):
    HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

    def setUp(self):
        super().setUp()
        self.start(
            patch.object(
                core,
                "PROC_NET_TCP",
                (
                    (self.root / "net/tcp", False),
                    (self.root / "net/tcp6", True),
                ),
            )
        )
        self.path("SSH_CONFIG", "ssh/sshd_config")
        self.path("SYS_CLASS_NET", "sys/net")
        self.commands({("ip", "-json"): completed("[]")})

    def listen(self, *sockets: str, ipv6: str = ""):
        rows = [
            f"   0: {socket} 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 1 1\n"
            for socket in sockets
        ]
        self.write("net/tcp", self.HEADER + "".join(rows))
        if ipv6:
            self.write(
                "net/tcp6",
                self.HEADER
                + f"   0: {ipv6} 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0\n",
            )

    def test_only_loopback_services(self):
        # 127.0.0.1:631 (CUPS), 127.0.0.53:53 (resolver), [::1]:631
        self.listen("0100007F:0277", "3500007F:0035", ipv6="00000000000000000000000001000000:0277")
        self.assertResult("network-services", Status.OK, "network_services.none")

    def test_remote_desktop(self):
        self.listen("00000000:0D3D")  # 0.0.0.0:3389
        result = self.assertResult(
            "network-services", Status.WARNING, "network_services.remote_desktop"
        )
        self.assertEqual(dict(result.data), {"ports": "3389"})

    def test_ssh_with_password_login(self):
        self.listen("00000000:0016")
        self.write(
            "ssh/sshd_config",
            "Include "
            + str(self.root / "ssh/sshd_config.d/*.conf")
            + "\nKbdInteractiveAuthentication no\n",
        )
        self.assertResult(
            "network-services", Status.WARNING, "network_services.ssh_password_login"
        )

    def test_ssh_with_key_login_only_from_a_drop_in(self):
        self.listen("00000000:0016")
        self.write("ssh/sshd_config.d/10-keys.conf", "PasswordAuthentication no\n")
        self.write(
            "ssh/sshd_config",
            "Include "
            + str(self.root / "ssh/sshd_config.d/*.conf")
            + "\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\n",
        )
        self.assertResult("network-services", Status.OK, "network_services.ssh_key_only")

    def test_ssh_root_login(self):
        self.listen("00000000:0016")
        self.write(
            "ssh/sshd_config",
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\n",
        )
        self.assertResult(
            "network-services", Status.WARNING, "network_services.ssh_password_login"
        )

    def test_match_blocks_do_not_change_global_settings(self):
        self.assertFalse(
            core.ssh_allows_password_or_root_login(
                [
                    "PasswordAuthentication no",
                    "KbdInteractiveAuthentication=no",
                    "Match User guest",
                    "PasswordAuthentication yes",
                ]
            )
        )

    def test_other_ports_cannot_be_judged(self):
        self.listen("00000000:01BD")  # 0.0.0.0:445
        result = self.assertResult(
            "network-services", Status.UNKNOWN, "network_services.other_ports"
        )
        self.assertEqual(dict(result.data), {"ports": "445"})

    def test_services_on_internal_virtual_bridges_are_ignored(self):
        self.listen("017AA8C0:0035")  # 192.168.122.1:53 on virbr0
        (self.root / "sys/net/virbr0/bridge").mkdir(parents=True)
        (self.root / "sys/net/virbr0/brif/vnet0").mkdir(parents=True)
        (self.root / "sys/net/vnet0").mkdir(parents=True)
        self.commands(
            {
                ("ip", "-json"): completed(
                    json.dumps(
                        [
                            {"ifname": "virbr0", "addr_info": [{"local": "192.168.122.1"}]},
                        ]
                    )
                )
            }
        )
        self.assertResult("network-services", Status.OK, "network_services.none")

    def test_bridge_with_a_real_network_card_still_counts(self):
        self.listen("017AA8C0:0035")
        (self.root / "sys/net/br0/bridge").mkdir(parents=True)
        (self.root / "sys/net/br0/brif/enp2s0").mkdir(parents=True)
        (self.root / "sys/net/enp2s0/device").mkdir(parents=True)
        self.commands(
            {
                ("ip", "-json"): completed(
                    json.dumps(
                        [
                            {"ifname": "br0", "addr_info": [{"local": "192.168.122.1"}]},
                        ]
                    )
                )
            }
        )
        self.assertResult("network-services", Status.UNKNOWN, "network_services.other_ports")

    def test_unreadable_connection_list(self):
        self.assertResult("network-services", Status.UNKNOWN, "network_services.status_unreadable")


class AppArmorTests(CheckTestCase):
    def setUp(self):
        super().setUp()
        self.path("APPARMOR_ENABLED", "apparmor/enabled")

    def test_states(self):
        for value, status, message_id in (
            ("Y\n", Status.OK, "apparmor.enabled"),
            ("N\n", Status.WARNING, "apparmor.disabled"),
            ("?\n", Status.UNKNOWN, "apparmor.unrecognized_status"),
        ):
            with self.subTest(value=value):
                self.write("apparmor/enabled", value)
                self.assertResult("apparmor", status, message_id)

    def test_not_available(self):
        self.assertResult("apparmor", Status.UNKNOWN, "apparmor.not_available")


class DiskEncryptionTests(CheckTestCase):
    def setUp(self):
        super().setUp()
        self.path("CHASSIS_TYPE", "dmi/chassis_type")
        self.start(patch.object(Path, "home", return_value=Path("/home/someone")))

    def mounts(self, root: tuple[str, str, str], home: tuple[str, str, str] | None = None):
        home = home or root
        responses = {}
        for target, (source, fstype, types) in (("/", root), ("/home/someone", home)):
            responses[("findmnt", "--target", target)] = completed(
                f'SOURCE="{source}" FSTYPE="{fstype}"\n'
            )
            if types is not None:
                device = core.block_device_from_mount_source(source)
                responses[("lsblk", "--inverse", "--noheadings", "--output", "TYPE", device)] = (
                    completed(types)
                )
        self.commands(responses)

    def test_system_encrypted(self):
        self.mounts(("/dev/mapper/vgmint-root", "ext4", "lvm\ncrypt\npart\ndisk\n"))
        self.assertResult("disk-encryption", Status.OK, "disk_encryption.system_encrypted")

    def test_btrfs_subvolume_source_is_resolved_to_its_device(self):
        self.mounts(("/dev/mapper/luks-abc[/@]", "btrfs", "crypt\npart\ndisk\n"))
        self.assertResult("disk-encryption", Status.OK, "disk_encryption.system_encrypted")

    def test_only_home_encrypted(self):
        self.mounts(
            ("/dev/sda2", "ext4", "part\ndisk\n"), ("/dev/mapper/home", "ext4", "crypt\npart\n")
        )
        self.assertResult("disk-encryption", Status.OK, "disk_encryption.home_only")

    def test_ecryptfs_home_does_not_reveal_the_home_path(self):
        self.mounts(
            ("/dev/sda2", "ext4", "part\ndisk\n"),
            ("/home/.ecryptfs/someone/.Private", "ecryptfs", None),
        )
        result = self.assertResult("disk-encryption", Status.OK, "disk_encryption.home_only")
        self.assertNotIn("someone", result.evidence)

    def test_one_warning_for_an_unencrypted_desktop_computer(self):
        self.write("dmi/chassis_type", "3\n")
        self.mounts(("/dev/sda2", "ext4", "part\ndisk\n"))
        self.assertResult("disk-encryption", Status.WARNING, "disk_encryption.not_encrypted")

    def test_stronger_text_for_an_unencrypted_laptop(self):
        self.write("dmi/chassis_type", "10\n")
        self.mounts(("/dev/nvme0n1p2", "ext4", "part\ndisk\n"))
        self.assertResult(
            "disk-encryption", Status.WARNING, "disk_encryption.not_encrypted_portable"
        )

    def test_unreadable_devices(self):
        self.commands({})
        self.assertResult("disk-encryption", Status.UNKNOWN, "disk_encryption.status_unknown")


class BootMenuTests(CheckTestCase):
    PASSWORD = 'cat << EOF\nset superusers="admin"\npassword_pbkdf2 admin grub.pbkdf2.sha512.10000.ABC\nEOF\n'

    def setUp(self):
        super().setUp()
        self.grub_config = self.path("GRUB_CONFIG", "boot/grub/grub.cfg")
        self.path("GRUB_CUSTOM_CONFIG", "boot/grub/custom.cfg")
        self.scripts = self.path("GRUB_SCRIPTS", "etc/grub.d")
        self.write("boot/grub/grub.cfg", "")
        self.script("10_linux", "echo menuentry\n")

    def script(
        self, name: str, contents: str, *, executable: bool = True, age_days: float | None = None
    ):
        path = self.write(f"etc/grub.d/{name}", contents)
        path.chmod(0o755 if executable else 0o644)
        if age_days is not None:
            moment = (datetime.now() - timedelta(days=age_days)).timestamp()
            os.utime(path, (moment, moment))
        return path

    def generated(self, age_days: float):
        moment = (datetime.now() - timedelta(days=age_days)).timestamp()
        os.utime(self.grub_config, (moment, moment))

    def unencrypted(self):
        self.commands(
            {
                ("findmnt",): completed('SOURCE="/dev/sda2" FSTYPE="ext4"\n'),
                ("lsblk",): completed("part\ndisk\n"),
            }
        )

    def test_encryption_protects_the_boot_menu(self):
        self.commands(
            {
                ("findmnt",): completed('SOURCE="/dev/mapper/vgmint-root" FSTYPE="ext4"\n'),
                ("lsblk",): completed("lvm\ncrypt\npart\ndisk\n"),
            }
        )
        self.assertResult("boot-menu", Status.OK, "boot_menu.protected_by_encryption")

    def test_no_password_and_no_encryption(self):
        self.unencrypted()
        self.assertResult("boot-menu", Status.WARNING, "boot_menu.no_password")

    def test_password_active_when_the_menu_was_generated_afterwards(self):
        self.unencrypted()
        self.script("40_custom", self.PASSWORD, age_days=10)
        self.generated(age_days=2)
        self.assertResult("boot-menu", Status.OK, "boot_menu.password_active")

    def test_password_added_after_the_menu_was_generated_needs_confirmation(self):
        self.unencrypted()
        self.generated(age_days=10)
        self.script("40_custom", self.PASSWORD, age_days=1)
        self.assertResult("boot-menu", Status.AUTH_REQUIRED, "boot_menu.password_not_confirmed")

    def test_superuser_and_password_may_be_in_different_scripts(self):
        self.unencrypted()
        self.script("01_users", 'cat << EOF\nset superusers="admin"\nEOF\n', age_days=10)
        self.script("02_password", "cat << EOF\npassword admin secret\nEOF\n", age_days=10)
        self.generated(age_days=1)
        self.assertResult("boot-menu", Status.OK, "boot_menu.password_active")

    def test_commented_or_non_executable_settings_do_not_count(self):
        self.unencrypted()
        self.script("40_custom", '# set superusers="admin"\n# password_pbkdf2 admin x\n')
        self.script("50_disabled", self.PASSWORD, executable=False)
        self.assertResult("boot-menu", Status.WARNING, "boot_menu.no_password")

    def test_password_in_custom_cfg_is_active_at_once(self):
        self.unencrypted()
        self.write("boot/grub/custom.cfg", 'set superusers="admin"\npassword_pbkdf2 admin x\n')
        self.assertResult("boot-menu", Status.OK, "boot_menu.password_active")

    def test_unreadable_custom_cfg_needs_the_extended_scan(self):
        self.unencrypted()
        self.write("boot/grub/custom.cfg", "")
        original = Path.read_text

        def read_text(path, *args, **kwargs):
            if path.name == "custom.cfg":
                raise PermissionError
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_text", read_text):
            self.assertResult(
                "boot-menu", Status.AUTH_REQUIRED, "boot_menu.authorization_required"
            )

    def test_grub_not_used(self):
        self.unencrypted()
        self.grub_config.unlink()
        self.assertResult("boot-menu", Status.UNKNOWN, "boot_menu.grub_not_used")

    def test_unknown_encryption_without_password(self):
        self.commands({})
        self.assertResult("boot-menu", Status.UNKNOWN, "boot_menu.status_unknown")


class ScanTests(unittest.TestCase):
    def test_nine_checks_in_two_levels(self):
        self.assertEqual(
            [(check.check_id, check.level) for check in CHECKS],
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
            patch("mojitoshield_core._run_command", side_effect=OSError("boom")),
            self.assertLogs("mojitoshield_core", level="WARNING") as logs,
        ):
            results = core.run_checks()

        self.assertEqual(len(results), 9)
        failed = [result for result in results if result.message_id == "check.unexpected_error"]
        self.assertTrue(failed)
        self.assertTrue(all(result.status is Status.UNKNOWN for result in failed))
        self.assertTrue(all("boom" not in line for line in logs.output))


if __name__ == "__main__":
    unittest.main()

"""Read-only checks used by MojitoShield.

Each check follows its contract in docs/check-contracts.md.
"""

from __future__ import annotations

import configparser
import glob
import gzip
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence


LOGGER = logging.getLogger(__name__)

# Firewall
UFW_CONFIG = Path("/etc/ufw/ufw.conf")

# System up to date
APT_AUTO_UPGRADES = Path("/etc/apt/apt.conf.d/20auto-upgrades")
APT_HISTORY_LOGS = (
    Path("/var/log/apt/history.log"),
    Path("/var/log/apt/history.log.1.gz"),
)
MINTUPDATE_AUTOMATION_SCRIPT = Path("/usr/lib/linuxmint/mintUpdate/automatic_upgrades.py")
MINTUPDATE_UPGRADE_FLAG = Path("/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled")
MINTUPDATE_UPGRADE_TIMER = "mintupdate-automation-upgrade.timer"
REBOOT_REQUIRED = Path("/var/run/reboot-required")
UPDATES_MAX_AGE_DAYS = 30
REBOOT_PENDING_MAX_DAYS = 7

# Automatic login
DISPLAY_MANAGER_FILE = Path("/etc/X11/default-display-manager")
# Read in this order, later values winning, as Mint's Login Window tool does.
LIGHTDM_CONFIG_SOURCES = (
    Path("/usr/share/lightdm/lightdm.conf.d"),
    Path("/etc/lightdm/lightdm.conf.d"),
    Path("/etc/lightdm/lightdm.conf"),
)
LIGHTDM_SEAT_GROUPS = ("SeatDefaults", "Seat:*", "Seat:seat0")

# Timeshift
TIMESHIFT_EXECUTABLE = Path("/usr/bin/timeshift")
TIMESHIFT_CONFIG = Path("/etc/timeshift/timeshift.json")
TIMESHIFT_SNAPSHOTS = Path("/timeshift/snapshots")
TIMESHIFT_SCHEDULES = ("monthly", "weekly", "daily", "hourly", "boot")
TIMESHIFT_SCHEDULE_DAYS = {"hourly": 1 / 24, "daily": 1, "weekly": 7, "monthly": 30}
TIMESHIFT_MIN_AGE_LIMIT_DAYS = 7
TIMESHIFT_MAX_AGE_LIMIT_DAYS = 40

# Network services
PROC_NET_TCP = ((Path("/proc/net/tcp"), False), (Path("/proc/net/tcp6"), True))
TCP_LISTEN_STATE = "0A"
SSH_PORT = 22
REMOTE_DESKTOP_PORTS = frozenset({23, 3389, *range(5900, 6000)})
SSH_CONFIG = Path("/etc/ssh/sshd_config")
SYS_CLASS_NET = Path("/sys/class/net")

# AppArmor
APPARMOR_ENABLED = Path("/sys/module/apparmor/parameters/enabled")

# Disk encryption
CHASSIS_TYPE = Path("/sys/class/dmi/id/chassis_type")
# SMBIOS chassis types for portable computers.
PORTABLE_CHASSIS_TYPES = frozenset({8, 9, 10, 11, 14, 30, 31, 32})


@dataclass(frozen=True)
class ScreenLockSettings:
    name: str
    lock_query: list[str]
    idle_delay_query: list[str]
    idle_delay_unit_seconds: int
    idle_enabled_query: list[str] | None = None


SCREEN_LOCK_SETTINGS = {
    "cinnamon": ScreenLockSettings(
        name="Cinnamon",
        lock_query=["gsettings", "get", "org.cinnamon.desktop.screensaver", "lock-enabled"],
        idle_delay_query=["gsettings", "get", "org.cinnamon.desktop.session", "idle-delay"],
        idle_delay_unit_seconds=1,
    ),
    "mate": ScreenLockSettings(
        name="MATE",
        lock_query=["gsettings", "get", "org.mate.screensaver", "lock-enabled"],
        idle_delay_query=["gsettings", "get", "org.mate.session", "idle-delay"],
        idle_delay_unit_seconds=60,
        idle_enabled_query=[
            "gsettings", "get", "org.mate.screensaver", "idle-activation-enabled",
        ],
    ),
    "xfce": ScreenLockSettings(
        name="Xfce",
        lock_query=[
            "xfconf-query", "--channel", "xfce4-screensaver", "--property", "/lock/enabled",
        ],
        idle_delay_query=[
            "xfconf-query", "--channel", "xfce4-screensaver",
            "--property", "/saver/idle-activation/delay",
        ],
        idle_delay_unit_seconds=60,
        idle_enabled_query=[
            "xfconf-query", "--channel", "xfce4-screensaver", "--property", "/saver/enabled",
        ],
    ),
}


class Status(str, Enum):
    OK = "ok"
    WARNING = "warning"
    UNKNOWN = "unknown"
    AUTH_REQUIRED = "auth_required"


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    level: int
    status: Status
    message_id: str
    evidence: str = ""
    data: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class CheckDefinition:
    check_id: str
    level: int
    run: Callable[[CheckDefinition], CheckResult]


def identify_distribution(release: Mapping[str, str]) -> bool:
    """Return whether os-release data identifies Mint or LMDE."""
    distribution_id = release.get("ID", "").lower()
    name = release.get("NAME", "").lower()
    pretty_name = release.get("PRETTY_NAME", "").lower()

    if distribution_id == "linuxmint":
        return True

    return "lmde" in name or "lmde" in pretty_name or (
        "linux mint debian edition" in pretty_name
    )


def current_distribution() -> tuple[bool, str | None]:
    """Read the local os-release data and identify supported systems."""
    try:
        release = platform.freedesktop_os_release()
    except (AttributeError, OSError):
        return False, None

    name = release.get("PRETTY_NAME") or release.get("NAME")
    return identify_distribution(release), name


def _now() -> datetime:
    return datetime.now()


def _days_since(moment: datetime) -> float:
    return max(0.0, (_now() - moment).total_seconds() / 86400)


def _result(
    check: CheckDefinition,
    status: Status,
    message_id: str,
    evidence: str = "",
    data: Mapping[str, str] | None = None,
) -> CheckResult:
    return CheckResult(
        check_id=check.check_id,
        level=check.level,
        status=status,
        message_id=message_id,
        evidence=evidence,
        data=tuple(sorted((data or {}).items())),
    )


def _run_command(arguments: list[str]) -> subprocess.CompletedProcess[str] | None:
    executable = shutil.which(arguments[0])
    if executable is None:
        return None

    try:
        return subprocess.run(
            [executable, *arguments[1:]],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "LANG": "C", "LC_ALL": "C", "LANGUAGE": "C"},
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return None


# 1. Firewall


def parse_ufw_enabled(contents: str) -> bool | None:
    """Return the ENABLED value of ufw.conf; the file is a shell fragment, so the last one wins."""
    enabled = None
    for line in contents.splitlines():
        match = re.match(r'^\s*ENABLED\s*=\s*["\']?(yes|no)["\']?\s*$', line, re.IGNORECASE)
        if match:
            enabled = match.group(1).lower() == "yes"
    return enabled


def _check_firewall(check: CheckDefinition) -> CheckResult:
    try:
        contents = UFW_CONFIG.read_text(encoding="utf-8")
    except FileNotFoundError:
        return _result(check, Status.UNKNOWN, "firewall.ufw_not_installed")
    except (OSError, UnicodeError):
        return _result(check, Status.AUTH_REQUIRED, "firewall.authorization_required")

    enabled = parse_ufw_enabled(contents)
    if enabled is False:
        return _result(check, Status.WARNING, "firewall.disabled", str(UFW_CONFIG))
    if enabled is None:
        return _result(check, Status.AUTH_REQUIRED, "firewall.authorization_required")

    service = _run_command(["systemctl", "is-active", "ufw"])
    if service is not None and service.stdout.strip() == "active":
        return _result(check, Status.OK, "firewall.enabled", str(UFW_CONFIG))
    return _result(check, Status.AUTH_REQUIRED, "firewall.service_not_confirmed")


# 2. System up to date


def parse_apt_auto_updates(contents: str) -> bool | None:
    """Parse the two APT periodic settings relevant to automatic updates."""
    keys = {
        "Update-Package-Lists": None,
        "Unattended-Upgrade": None,
    }
    pattern = re.compile(
        r'^\s*APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)'
        r'\s+["\']?([01])["\']?\s*;'
    )

    for line in contents.splitlines():
        match = pattern.match(line)
        if match:
            keys[match.group(1)] = match.group(2) == "1"

    if any(value is None for value in keys.values()):
        return None
    return all(keys.values())


def latest_upgrade_time(history: str) -> datetime | None:
    """Return the start time of the newest APT history entry that upgraded packages."""
    latest = None
    started = None
    for line in history.splitlines():
        if line.startswith("Start-Date:"):
            try:
                started = datetime.strptime(
                    " ".join(line.split(":", 1)[1].split()), "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                started = None
        elif line.startswith("Upgrade:") and started is not None:
            if latest is None or started > latest:
                latest = started
    return latest


def _read_apt_history() -> list[str]:
    histories = []
    for path in APT_HISTORY_LOGS:
        try:
            raw = path.read_bytes()
            if path.suffix == ".gz":
                raw = gzip.decompress(raw)
        except (OSError, EOFError, gzip.BadGzipFile):
            continue
        histories.append(raw.decode("utf-8", errors="replace"))
    return histories


def _mintupdate_automation_enabled() -> bool | None:
    """Return whether Update Manager's automatic upgrades run, or None if unknown."""
    if not MINTUPDATE_AUTOMATION_SCRIPT.is_file():
        return None
    try:
        flag_present = MINTUPDATE_UPGRADE_FLAG.exists()
    except OSError:
        return None
    command = _run_command(["systemctl", "is-enabled", MINTUPDATE_UPGRADE_TIMER])
    if command is None:
        return None

    # The timer starts the upgrade script, and the script exits unless the flag exists.
    return flag_present and command.stdout.strip() == "enabled"


def _automatic_updates_source() -> str | None:
    """Return what installs updates automatically, if anything does."""
    try:
        if parse_apt_auto_updates(APT_AUTO_UPGRADES.read_text(encoding="utf-8")):
            return str(APT_AUTO_UPGRADES)
    except (OSError, UnicodeError):
        pass
    if _mintupdate_automation_enabled():
        return MINTUPDATE_UPGRADE_TIMER
    return None


def _reboot_pending_days() -> float | None:
    try:
        modified = REBOOT_REQUIRED.stat().st_mtime
    except OSError:
        return None
    return _days_since(datetime.fromtimestamp(modified))


def _check_updates(check: CheckDefinition) -> CheckResult:
    reboot_days = _reboot_pending_days()
    if reboot_days is not None and reboot_days > REBOOT_PENDING_MAX_DAYS:
        return _result(
            check, Status.WARNING, "updates.reboot_pending", str(REBOOT_REQUIRED),
            {"days": str(int(reboot_days))},
        )

    source = _automatic_updates_source()
    if source is not None:
        return _result(check, Status.OK, "updates.automatic", source)

    upgrade_times = [
        moment
        for history in _read_apt_history()
        if (moment := latest_upgrade_time(history)) is not None
    ]
    if not upgrade_times:
        return _result(check, Status.UNKNOWN, "updates.history_unavailable")

    days = _days_since(max(upgrade_times))
    data = {"days": str(int(days))}
    evidence = str(APT_HISTORY_LOGS[0])
    if days <= UPDATES_MAX_AGE_DAYS:
        return _result(check, Status.OK, "updates.recently_installed", evidence, data)
    return _result(check, Status.WARNING, "updates.not_installed_recently", evidence, data)


# 3. Screen lock


def current_desktop(environment: Mapping[str, str] | None = None) -> str | None:
    """Return the supported Mint desktop named by XDG_CURRENT_DESKTOP."""
    if environment is None:
        environment = os.environ
    desktops = environment.get("XDG_CURRENT_DESKTOP", "").lower().split(":")
    for desktop in SCREEN_LOCK_SETTINGS:
        if desktop in desktops or f"x-{desktop}" in desktops:
            return desktop
    return None


def _setting(arguments: list[str]) -> str | None:
    command = _run_command(arguments)
    if command is None or command.returncode != 0:
        return None
    return command.stdout.strip().lower()


def parse_setting_number(value: str | None) -> int | None:
    """Parse gsettings or xfconf numbers such as 'uint32 900' or '5'."""
    if not value:
        return None
    try:
        return int(value.split()[-1])
    except ValueError:
        return None


def _check_screen_lock(check: CheckDefinition) -> CheckResult:
    desktop = current_desktop()
    if desktop is None:
        return _result(check, Status.UNKNOWN, "screen_lock.desktop_not_supported")

    settings = SCREEN_LOCK_SETTINGS[desktop]
    data = {"desktop": settings.name}
    lock_enabled = _setting(settings.lock_query)
    if lock_enabled is None:
        return _result(check, Status.UNKNOWN, "screen_lock.settings_unavailable", data=data)
    if lock_enabled == "false":
        return _result(check, Status.WARNING, "screen_lock.disabled", data=data)
    if lock_enabled != "true":
        return _result(check, Status.UNKNOWN, "screen_lock.unrecognized_result", data=data)

    if settings.idle_enabled_query is not None:
        if _setting(settings.idle_enabled_query) == "false":
            return _result(check, Status.WARNING, "screen_lock.never_automatic", data=data)

    idle_delay = parse_setting_number(_setting(settings.idle_delay_query))
    if idle_delay is None:
        return _result(check, Status.UNKNOWN, "screen_lock.idle_delay_unavailable", data=data)
    if idle_delay == 0:
        return _result(check, Status.WARNING, "screen_lock.never_automatic", data=data)

    minutes = max(1, round(idle_delay * settings.idle_delay_unit_seconds / 60))
    return _result(check, Status.OK, "screen_lock.enabled", data={**data, "minutes": str(minutes)})


# 4. Automatic login


def lightdm_autologin_user(config_texts: Iterable[str]) -> str:
    """Return the effective autologin-user from LightDM files read in priority order."""
    user = ""
    for text in config_texts:
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(text)
        except configparser.Error:
            # Login Window skips files it cannot parse, and so does LightDM.
            continue
        for group in LIGHTDM_SEAT_GROUPS:
            if parser.has_option(group, "autologin-user"):
                user = parser.get(group, "autologin-user").strip()
    return user


def _lightdm_config_files() -> list[Path]:
    files = []
    for source in LIGHTDM_CONFIG_SOURCES:
        if source.is_dir():
            files.extend(sorted(source.glob("*.conf")))
        elif source.is_file():
            files.append(source)
    return files


def _check_auto_login(check: CheckDefinition) -> CheckResult:
    try:
        display_manager = Path(
            DISPLAY_MANAGER_FILE.read_text(encoding="utf-8").strip()
        ).name
    except (OSError, UnicodeError):
        return _result(check, Status.UNKNOWN, "auto_login.display_manager_unknown")
    if display_manager != "lightdm":
        return _result(
            check, Status.UNKNOWN, "auto_login.display_manager_not_supported",
            data={"display_manager": display_manager[:40]},
        )

    try:
        texts = [path.read_text(encoding="utf-8") for path in _lightdm_config_files()]
    except (OSError, UnicodeError):
        return _result(check, Status.UNKNOWN, "auto_login.settings_unreadable")

    # The user name is personal data, so it is never part of the result.
    if lightdm_autologin_user(texts):
        return _result(check, Status.WARNING, "auto_login.enabled")
    return _result(check, Status.OK, "auto_login.disabled")


# 5. Timeshift


@dataclass(frozen=True)
class TimeshiftSettings:
    configured: bool
    btrfs_mode: bool
    schedules: tuple[str, ...]
    backup_device_uuid: str


def parse_timeshift_settings(contents: str) -> TimeshiftSettings | None:
    """Parse the Timeshift settings that tell where and when snapshots are made."""
    try:
        settings = json.loads(contents)
    except json.JSONDecodeError:
        return None
    if not isinstance(settings, dict):
        return None

    backup_device_uuid = settings.get("backup_device_uuid", "")
    if not isinstance(backup_device_uuid, str):
        return None

    def enabled(key: str) -> bool:
        # Timeshift stores booleans as the strings "true" and "false".
        return str(settings.get(key, "")).lower() == "true"

    return TimeshiftSettings(
        configured=bool(backup_device_uuid.strip()) and not enabled("do_first_run"),
        btrfs_mode=enabled("btrfs_mode"),
        schedules=tuple(name for name in TIMESHIFT_SCHEDULES if enabled(f"schedule_{name}")),
        backup_device_uuid=backup_device_uuid.strip(),
    )


def timeshift_age_limit_days(schedules: Sequence[str]) -> float:
    """Allow twice the most frequent schedule, within fixed bounds."""
    intervals = [TIMESHIFT_SCHEDULE_DAYS[name] for name in schedules if name in TIMESHIFT_SCHEDULE_DAYS]
    if not intervals:
        return TIMESHIFT_MAX_AGE_LIMIT_DAYS
    return min(
        max(2 * min(intervals), TIMESHIFT_MIN_AGE_LIMIT_DAYS),
        TIMESHIFT_MAX_AGE_LIMIT_DAYS,
    )


def newest_snapshot_time(names: Iterable[str]) -> datetime | None:
    """Return the newest time among snapshot folder names like 2026-10-02_22-07-41."""
    times = []
    for name in names:
        try:
            times.append(datetime.strptime(name, "%Y-%m-%d_%H-%M-%S"))
        except ValueError:
            continue
    return max(times, default=None)


def _root_filesystem_uuid() -> str | None:
    command = _run_command(["findmnt", "--noheadings", "--output", "UUID", "--target", "/"])
    if command is None or command.returncode != 0:
        return None
    return command.stdout.strip() or None


def _check_timeshift(check: CheckDefinition) -> CheckResult:
    try:
        settings = parse_timeshift_settings(TIMESHIFT_CONFIG.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if TIMESHIFT_EXECUTABLE.is_file():
            return _result(check, Status.WARNING, "timeshift.not_set_up")
        return _result(check, Status.UNKNOWN, "timeshift.not_installed")
    except (OSError, UnicodeError):
        settings = None
    if settings is None:
        return _result(check, Status.UNKNOWN, "timeshift.settings_unreadable", str(TIMESHIFT_CONFIG))

    if not settings.configured:
        return _result(check, Status.WARNING, "timeshift.not_set_up", str(TIMESHIFT_CONFIG))
    if settings.btrfs_mode:
        # Btrfs snapshots are only mounted while Timeshift runs.
        return _result(check, Status.UNKNOWN, "timeshift.btrfs_mode", str(TIMESHIFT_CONFIG))
    root_uuid = _root_filesystem_uuid()
    if root_uuid is not None and root_uuid != settings.backup_device_uuid:
        return _result(check, Status.UNKNOWN, "timeshift.separate_device", str(TIMESHIFT_CONFIG))

    try:
        names = [path.name for path in TIMESHIFT_SNAPSHOTS.iterdir() if path.is_dir()]
    except FileNotFoundError:
        names = []
    except OSError:
        return _result(check, Status.UNKNOWN, "timeshift.snapshots_unreadable", str(TIMESHIFT_SNAPSHOTS))

    newest = newest_snapshot_time(names)
    if newest is None:
        return _result(check, Status.WARNING, "timeshift.no_snapshots", str(TIMESHIFT_SNAPSHOTS))

    age_days = _days_since(newest)
    limit_days = timeshift_age_limit_days(settings.schedules)
    data = {"days": str(int(age_days)), "limit": str(int(limit_days))}
    if age_days <= limit_days:
        return _result(check, Status.OK, "timeshift.recent_snapshot", str(TIMESHIFT_SNAPSHOTS), data)
    return _result(check, Status.WARNING, "timeshift.snapshot_too_old", str(TIMESHIFT_SNAPSHOTS), data)


# 6. Network services


def _proc_net_address(hex_address: str, ipv6: bool) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    raw = bytes.fromhex(hex_address)
    # The kernel prints each 32-bit word in host (little-endian) byte order.
    words = b"".join(raw[index:index + 4][::-1] for index in range(0, len(raw), 4))
    return ipaddress.IPv6Address(words) if ipv6 else ipaddress.IPv4Address(words)


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def listening_sockets(proc_net_text: str, ipv6: bool) -> set[tuple[IPAddress, int]]:
    """Return non-loopback (address, port) pairs of TCP sockets in the listening state."""
    sockets = set()
    for line in proc_net_text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] != TCP_LISTEN_STATE:
            continue
        hex_address, _, hex_port = fields[1].partition(":")
        try:
            address = _proc_net_address(hex_address, ipv6)
            port = int(hex_port, 16)
        except ValueError:
            continue
        mapped = getattr(address, "ipv4_mapped", None)
        if address.is_loopback or (mapped is not None and mapped.is_loopback):
            continue
        sockets.add((address, port))
    return sockets


def _is_internal_bridge(name: str) -> bool:
    """Return whether an interface is a bridge whose ports are all virtual, like virbr0."""
    if not re.fullmatch(r"[\w.@-]{1,32}", name):
        return False
    bridge = SYS_CLASS_NET / name
    if not (bridge / "bridge").is_dir():
        return False
    try:
        ports = list((bridge / "brif").iterdir())
    except OSError:
        return False
    # A port with a device link is a real network card, reachable from other computers.
    return not any((SYS_CLASS_NET / port.name / "device").exists() for port in ports)


def parse_interface_addresses(ip_json: str) -> dict[str, set[IPAddress]]:
    """Parse `ip -json address show` into addresses per interface name."""
    try:
        interfaces = json.loads(ip_json)
    except json.JSONDecodeError:
        return {}
    addresses: dict[str, set[IPAddress]] = {}
    for interface in interfaces if isinstance(interfaces, list) else ():
        name = interface.get("ifname") if isinstance(interface, dict) else None
        if not isinstance(name, str):
            continue
        for info in interface.get("addr_info", ()):
            try:
                addresses.setdefault(name, set()).add(ipaddress.ip_address(info.get("local", "")))
            except (AttributeError, ValueError):
                continue
    return addresses


def _internal_bridge_addresses() -> set[IPAddress]:
    command = _run_command(["ip", "-json", "address", "show"])
    if command is None or command.returncode != 0:
        return set()
    return {
        address
        for name, addresses in parse_interface_addresses(command.stdout).items()
        if _is_internal_bridge(name)
        for address in addresses
    }


def _ssh_config_lines(path: Path, depth: int = 0) -> list[str]:
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        include = re.match(r"(?i)^include\s+(.+)$", stripped)
        if include is None:
            lines.append(stripped)
            continue
        if depth >= 3:
            continue
        for pattern in include.group(1).split():
            if not pattern.startswith("/"):
                pattern = str(SSH_CONFIG.parent / pattern)
            for included in sorted(glob.glob(pattern)):
                lines.extend(_ssh_config_lines(Path(included), depth + 1))
    return lines


def ssh_allows_password_or_root_login(lines: Iterable[str]) -> bool:
    """Apply sshd's first-value-wins rule to the global login options."""
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[\s=]+", line, maxsplit=1)
        key = parts[0].lower()
        if key == "match":
            break
        if len(parts) == 2 and key not in values:
            values[key] = parts[1].strip().lower()

    password = values.get("passwordauthentication", "yes") == "yes"
    keyboard_interactive = values.get("kbdinteractiveauthentication", "yes") == "yes"
    root = values.get("permitrootlogin", "prohibit-password") == "yes"
    return password or keyboard_interactive or root


def _check_network_services(check: CheckDefinition) -> CheckResult:
    sockets: set[tuple[IPAddress, int]] = set()
    readable = False
    for path, ipv6 in PROC_NET_TCP:
        try:
            sockets |= listening_sockets(path.read_text(encoding="ascii"), ipv6)
            readable = True
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError):
            return _result(check, Status.UNKNOWN, "network_services.status_unreadable")
    if not readable:
        return _result(check, Status.UNKNOWN, "network_services.status_unreadable")

    # Services only on internal bridges are reachable from local virtual machines, not other computers.
    internal = _internal_bridge_addresses() if sockets else set()
    ports = {port for address, port in sockets if address not in internal}
    if not ports:
        return _result(check, Status.OK, "network_services.none")

    evidence = "TCP " + ", ".join(str(port) for port in sorted(ports))
    remote_desktop = sorted(ports & REMOTE_DESKTOP_PORTS)
    if remote_desktop:
        return _result(
            check, Status.WARNING, "network_services.remote_desktop", evidence,
            {"ports": ", ".join(str(port) for port in remote_desktop)},
        )

    if SSH_PORT in ports:
        try:
            risky = ssh_allows_password_or_root_login(_ssh_config_lines(SSH_CONFIG))
        except (OSError, UnicodeError):
            return _result(check, Status.UNKNOWN, "network_services.ssh_settings_unreadable", evidence)
        if risky:
            return _result(check, Status.WARNING, "network_services.ssh_password_login", evidence)

    other_ports = sorted(ports - {SSH_PORT})
    if other_ports:
        return _result(
            check, Status.UNKNOWN, "network_services.other_ports", evidence,
            {"ports": ", ".join(str(port) for port in other_ports[:20])},
        )
    return _result(check, Status.OK, "network_services.ssh_key_only", evidence)


# 7. AppArmor


def _check_apparmor(check: CheckDefinition) -> CheckResult:
    try:
        enabled = APPARMOR_ENABLED.read_text(encoding="ascii").strip().upper()
    except FileNotFoundError:
        return _result(check, Status.UNKNOWN, "apparmor.not_available")
    except (OSError, UnicodeError):
        return _result(check, Status.UNKNOWN, "apparmor.status_unreadable")

    if enabled == "Y":
        return _result(check, Status.OK, "apparmor.enabled", str(APPARMOR_ENABLED))
    if enabled == "N":
        return _result(check, Status.WARNING, "apparmor.disabled", str(APPARMOR_ENABLED))
    return _result(check, Status.UNKNOWN, "apparmor.unrecognized_status")


# 8. Disk encryption


def parse_findmnt_pairs(output: str) -> dict[str, str]:
    """Parse one line of `findmnt --pairs` output."""
    return dict(re.findall(r'([A-Z]+)="([^"]*)"', output))


def block_device_from_mount_source(source: str) -> str:
    """Drop the btrfs subvolume suffix, as in /dev/sda2[/@home]."""
    return re.sub(r"\[[^\]]*\]$", "", source)


@dataclass(frozen=True)
class MountEncryption:
    crypt_mapping: bool | None
    source: str
    filesystem_type: str = ""


def _mount_encryption(target: str) -> MountEncryption:
    mount = _run_command(
        ["findmnt", "--target", target, "--noheadings", "--pairs", "--output", "SOURCE,FSTYPE"]
    )
    fields = parse_findmnt_pairs(mount.stdout) if mount and mount.returncode == 0 else {}
    source = fields.get("SOURCE", "")
    filesystem_type = fields.get("FSTYPE", "").lower()
    if not source:
        return MountEncryption(None, "mount_source_unreadable")

    device = block_device_from_mount_source(source)
    block_types = _run_command(
        ["lsblk", "--inverse", "--noheadings", "--output", "TYPE", device]
    )
    if block_types is None or block_types.returncode != 0:
        return MountEncryption(None, source, filesystem_type)

    types = {line.strip().lower() for line in block_types.stdout.splitlines()}
    return MountEncryption("crypt" in types, source, filesystem_type)


def _is_portable_computer() -> bool:
    try:
        return int(CHASSIS_TYPE.read_text(encoding="ascii").strip()) in PORTABLE_CHASSIS_TYPES
    except (OSError, UnicodeError, ValueError):
        return False


def _check_disk_encryption(check: CheckDefinition) -> CheckResult:
    system = _mount_encryption("/")
    if system.crypt_mapping:
        return _result(check, Status.OK, "disk_encryption.system_encrypted", system.source)

    # The home path is not used as evidence because it contains the user name.
    home = _mount_encryption(str(Path.home()))
    if home.filesystem_type == "ecryptfs":
        return _result(check, Status.OK, "disk_encryption.home_only", "ecryptfs")
    if home.crypt_mapping:
        return _result(check, Status.OK, "disk_encryption.home_only", home.source)

    if system.crypt_mapping is None or home.crypt_mapping is None:
        return _result(check, Status.UNKNOWN, "disk_encryption.status_unknown")
    message_id = (
        "disk_encryption.not_encrypted_portable"
        if _is_portable_computer()
        else "disk_encryption.not_encrypted"
    )
    return _result(check, Status.WARNING, message_id, system.source)


# 9. Boot menu protection


def _check_boot_menu(check: CheckDefinition) -> CheckResult:
    # See docs/root-shell-check-proposal.md; this stays undecided until it is approved.
    return _result(check, Status.UNKNOWN, "boot_menu.check_not_defined")


CHECKS = (
    CheckDefinition("firewall", 1, _check_firewall),
    CheckDefinition("updates", 1, _check_updates),
    CheckDefinition("screen-lock", 1, _check_screen_lock),
    CheckDefinition("auto-login", 1, _check_auto_login),
    CheckDefinition("timeshift", 1, _check_timeshift),
    CheckDefinition("network-services", 1, _check_network_services),
    CheckDefinition("apparmor", 1, _check_apparmor),
    CheckDefinition("disk-encryption", 2, _check_disk_encryption),
    CheckDefinition("boot-menu", 2, _check_boot_menu),
)


def run_checks() -> tuple[CheckResult, ...]:
    """Run each read-only check and keep one failure from stopping the scan."""
    results = []
    for check in CHECKS:
        try:
            results.append(check.run(check))
        except (OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
            LOGGER.warning("Check %s could not complete (%s).", check.check_id, type(error).__name__)
            results.append(
                _result(
                    check,
                    Status.UNKNOWN,
                    "check.unexpected_error",
                    type(error).__name__,
                )
            )
    return tuple(results)


PRIVILEGED_CHECK_IDS = frozenset({"firewall"})
PRIVILEGED_HELPER_PATH = Path("/usr/libexec/mojitoshield/privileged-check")
PRIVILEGED_POLICY_PATH = Path(
    "/usr/share/polkit-1/actions/org.mojitoshield.privileged-check.policy"
)
PKEXEC_PATH = Path("/usr/bin/pkexec")
MAX_PRIVILEGED_OUTPUT_BYTES = 16_384


class PrivilegedScanError(Exception):
    """Base exception for the optional privileged scan."""


class PrivilegedHelperUnavailable(PrivilegedScanError):
    """Raised when the trusted packaged helper cannot be used."""


class PrivilegedScanCancelled(PrivilegedScanError):
    """Raised when the user cancels the system authorization dialog."""


class PrivilegedScanFailed(PrivilegedScanError):
    """Raised when the helper fails or returns an invalid response."""


def _is_trusted_system_path(path: Path, *, executable: bool) -> bool:
    try:
        resolved = path.resolve(strict=True)
        file_info = resolved.stat()
    except OSError:
        return False

    if (
        not stat.S_ISREG(file_info.st_mode)
        or file_info.st_uid != 0
        or file_info.st_mode & 0o022
        or (executable and not file_info.st_mode & 0o111)
    ):
        return False

    parent = resolved.parent
    while parent != parent.parent:
        try:
            directory_info = parent.stat()
        except OSError:
            return False
        if directory_info.st_uid != 0 or directory_info.st_mode & 0o022:
            return False
        parent = parent.parent

    return True


def privileged_helper_available() -> bool:
    return (
        _is_trusted_system_path(PKEXEC_PATH, executable=True)
        and _is_trusted_system_path(PRIVILEGED_HELPER_PATH, executable=True)
        and _is_trusted_system_path(PRIVILEGED_POLICY_PATH, executable=False)
    )


def _parse_privileged_output(
    requested_ids: tuple[str, ...], output: str
) -> tuple[CheckResult, ...]:
    if len(output.encode("utf-8")) > MAX_PRIVILEGED_OUTPUT_BYTES:
        raise PrivilegedScanFailed("helper_response_too_large")

    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise PrivilegedScanFailed("helper_response_invalid_json") from error

    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise PrivilegedScanFailed("helper_response_unknown_version")

    entries = payload.get("results")
    if not isinstance(entries, list) or len(entries) != len(requested_ids):
        raise PrivilegedScanFailed("helper_response_missing_results")

    definitions = {check.check_id: check for check in CHECKS}
    allowed_statuses = {
        "ok": Status.OK,
        "warning": Status.WARNING,
        "unknown": Status.UNKNOWN,
    }
    results: dict[str, CheckResult] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise PrivilegedScanFailed("helper_response_invalid_result")

        check_id = entry.get("check_id")
        if check_id not in requested_ids or check_id in results:
            raise PrivilegedScanFailed("helper_response_unexpected_check")

        status = allowed_statuses.get(entry.get("status"))
        message_id = entry.get("message_id")
        evidence = entry.get("evidence", "")
        data = entry.get("data", {})
        if (
            status is None
            or not isinstance(message_id, str)
            or not re.fullmatch(r"[a-z0-9_.]+", message_id)
            or not isinstance(evidence, str)
            or len(evidence) > 300
            or not isinstance(data, dict)
            or any(
                not isinstance(key, str)
                or not isinstance(value, (str, int))
                or len(str(value)) > 100
                for key, value in data.items()
            )
        ):
            raise PrivilegedScanFailed("helper_response_invalid_fields")

        definition = definitions[check_id]
        results[check_id] = _result(
            definition,
            status,
            message_id,
            evidence,
            {key: str(value) for key, value in data.items()},
        )

    if set(results) != set(requested_ids):
        raise PrivilegedScanFailed("helper_response_missing_check")

    return tuple(results[check_id] for check_id in requested_ids)


def run_privileged_checks(check_ids: Sequence[str]) -> tuple[CheckResult, ...]:
    """Run only fixed, allowlisted checks through the packaged PolicyKit helper."""
    requested_ids = tuple(check_ids)
    if (
        not requested_ids
        or len(set(requested_ids)) != len(requested_ids)
        or not set(requested_ids).issubset(PRIVILEGED_CHECK_IDS)
    ):
        raise ValueError("privileged_check_not_allowlisted")
    if not privileged_helper_available():
        raise PrivilegedHelperUnavailable("privileged_helper_not_trusted_or_missing")

    try:
        process = subprocess.run(
            [str(PKEXEC_PATH), str(PRIVILEGED_HELPER_PATH), *requested_ids],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as error:
        raise PrivilegedScanFailed("privileged_scan_timeout") from error
    except OSError as error:
        raise PrivilegedScanFailed("privileged_scan_could_not_start") from error

    if process.returncode == 126:
        raise PrivilegedScanCancelled("privileged_scan_cancelled")
    if process.returncode != 0:
        raise PrivilegedScanFailed("privileged_scan_failed")

    return _parse_privileged_output(requested_ids, process.stdout)
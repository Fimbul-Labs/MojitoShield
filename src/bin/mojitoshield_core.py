"""Read-only checks used by the MojitoShield prototype."""

from __future__ import annotations

import logging
import json
import os
import platform
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Sequence


LOGGER = logging.getLogger(__name__)


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


def _check_firewall(check: CheckDefinition) -> CheckResult:
    command = _run_command(["ufw", "status"])
    if command is None:
        return _result(check, Status.UNKNOWN, "firewall.command_unavailable")
    if command.returncode != 0:
        return _result(check, Status.AUTH_REQUIRED, "firewall.authorization_required")

    status_line = next(
        (line.strip().lower() for line in command.stdout.splitlines()
         if line.strip().lower().startswith("status:")),
        "",
    )
    if status_line == "status: active":
        return _result(check, Status.OK, "firewall.active", status_line)
    if status_line == "status: inactive":
        return _result(
            check,
            Status.WARNING,
            "firewall.inactive",
            status_line,
        )
    return _result(check, Status.UNKNOWN, "firewall.unrecognized_status")


def _check_automatic_updates(check: CheckDefinition) -> CheckResult:
    settings_file = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    try:
        contents = settings_file.read_text(encoding="utf-8")
    except PermissionError:
        return _result(check, Status.AUTH_REQUIRED, "updates.authorization_required")
    except (OSError, UnicodeError):
        return _result(check, Status.UNKNOWN, "updates.settings_unreadable")

    enabled = parse_apt_auto_updates(contents)
    if enabled is None:
        return _result(
            check,
            Status.UNKNOWN,
            "updates.settings_unparseable",
            str(settings_file),
        )
    if enabled:
        return _result(
            check,
            Status.OK,
            "updates.enabled",
            str(settings_file),
        )
    return _result(
        check,
        Status.WARNING,
        "updates.disabled",
        str(settings_file),
    )


def _check_timeshift(check: CheckDefinition) -> CheckResult:
    snapshots = Path("/timeshift/snapshots")
    try:
        snapshot_count = sum(path.is_dir() for path in snapshots.iterdir())
    except PermissionError:
        return _result(check, Status.AUTH_REQUIRED, "timeshift.authorization_required", str(snapshots))
    except OSError:
        return _result(
            check,
            Status.UNKNOWN,
            "timeshift.path_unreadable",
            str(snapshots),
        )

    if snapshot_count:
        return _result(
            check,
            Status.UNKNOWN,
            "timeshift.snapshots_found",
            str(snapshots),
            {"count": str(snapshot_count)},
        )
    return _result(
        check,
        Status.UNKNOWN,
        "timeshift.no_snapshots_at_default_path",
        str(snapshots),
    )


def _check_access_control(check: CheckDefinition) -> CheckResult:
    selinux_enforce = Path("/sys/fs/selinux/enforce")
    try:
        selinux_state = selinux_enforce.read_text(encoding="ascii").strip()
    except PermissionError:
        return _result(check, Status.AUTH_REQUIRED, "access_control.authorization_required")
    except OSError:
        selinux_state = ""

    if selinux_state == "1":
        return _result(check, Status.OK, "access_control.selinux_enforcing", str(selinux_enforce))
    if selinux_state == "0":
        return _result(check, Status.WARNING, "access_control.selinux_permissive", str(selinux_enforce))

    apparmor_enabled = Path("/sys/module/apparmor/parameters/enabled")
    apparmor_profiles = Path("/sys/kernel/security/apparmor/profiles")
    try:
        enabled = apparmor_enabled.read_text(encoding="ascii").strip().upper()
        profiles = apparmor_profiles.read_text(encoding="utf-8")
    except PermissionError:
        return _result(check, Status.AUTH_REQUIRED, "access_control.authorization_required")
    except (OSError, UnicodeError):
        return _result(
            check,
            Status.UNKNOWN,
            "access_control.status_unreadable",
        )

    enforced_count = sum("(enforce)" in line for line in profiles.splitlines())
    if enabled == "Y" and enforced_count:
        return _result(
            check,
            Status.OK,
            "access_control.apparmor_enforcing",
            str(apparmor_profiles),
            {"count": str(enforced_count)},
        )
    if enabled == "N":
        return _result(check, Status.WARNING, "access_control.apparmor_disabled")
    return _result(
        check,
        Status.UNKNOWN,
        "access_control.apparmor_unconfirmed",
        str(apparmor_profiles),
    )


def _systemd_unit_active(units: tuple[str, ...]) -> bool | None:
    known_states = {"active", "inactive", "failed", "activating", "deactivating"}
    found_unit = False

    for unit in units:
        command = _run_command(["systemctl", "is-active", unit])
        if command is None:
            return None
        state = command.stdout.strip().lower()
        if state == "active":
            return True
        if state in known_states:
            found_unit = True

    return False if found_unit else None


def _check_ssh(check: CheckDefinition) -> CheckResult:
    active = _systemd_unit_active(("ssh.service", "sshd.service", "ssh.socket"))
    if active is None:
        return _result(check, Status.UNKNOWN, "ssh.status_unavailable")
    if active:
        return _result(
            check,
            Status.WARNING,
            "ssh.active",
        )
    return _result(check, Status.OK, "ssh.inactive")


def _check_clamav(check: CheckDefinition) -> CheckResult:
    active = _systemd_unit_active(("clamav-daemon.service",))
    if active:
        return _result(
            check,
            Status.OK,
            "clamav.active_limited",
        )
    return _result(
        check,
        Status.UNKNOWN,
        "clamav.not_a_universal_requirement",
    )


def _check_screen_lock(check: CheckDefinition) -> CheckResult:
    command = _run_command(
        ["gsettings", "get", "org.cinnamon.desktop.screensaver", "lock-enabled"]
    )
    if command is None or command.returncode != 0:
        return _result(
            check,
            Status.UNKNOWN,
            "screen_lock.settings_unavailable",
        )

    value = command.stdout.strip().lower()
    if value == "true":
        return _result(check, Status.OK, "screen_lock.enabled")
    if value == "false":
        return _result(check, Status.WARNING, "screen_lock.disabled")
    return _result(check, Status.UNKNOWN, "screen_lock.unrecognized_result")


def _check_bluetooth(check: CheckDefinition) -> CheckResult:
    rfkill_directory = Path("/sys/class/rfkill")
    try:
        devices = list(rfkill_directory.glob("rfkill*"))
    except OSError:
        return _result(check, Status.UNKNOWN, "bluetooth.status_unavailable")

    bluetooth_devices: list[tuple[bool, bool]] = []
    for device in devices:
        try:
            device_type = (device / "type").read_text(encoding="ascii").strip()
            if device_type != "bluetooth":
                continue
            soft_blocked = (device / "soft").read_text(encoding="ascii").strip() == "1"
            hard_blocked = (device / "hard").read_text(encoding="ascii").strip() == "1"
            bluetooth_devices.append((soft_blocked, hard_blocked))
        except (OSError, UnicodeError):
            return _result(check, Status.UNKNOWN, "bluetooth.device_unreadable")

    if not bluetooth_devices:
        return _result(check, Status.UNKNOWN, "bluetooth.no_radio_found")
    if all(soft or hard for soft, hard in bluetooth_devices):
        return _result(check, Status.OK, "bluetooth.all_radios_blocked")
    return _result(
        check,
        Status.UNKNOWN,
        "bluetooth.unblocked_is_not_proof_of_risk",
    )


def _check_root_shell(check: CheckDefinition) -> CheckResult:
    return _result(
        check,
        Status.UNKNOWN,
        "root_shell.check_not_implemented",
    )


def _encrypted_mount(mountpoint: str) -> tuple[bool | None, str]:
    mount = _run_command(
        ["findmnt", "--target", mountpoint, "--noheadings", "--output", "SOURCE"]
    )
    if mount is None or mount.returncode != 0 or not mount.stdout.strip():
        return None, "mount_source_unreadable"

    source = mount.stdout.strip()
    block_types = _run_command(
        ["lsblk", "--inverse", "--noheadings", "--output", "TYPE", source]
    )
    if block_types is None or block_types.returncode != 0:
        return None, source

    types = {line.strip().lower() for line in block_types.stdout.splitlines()}
    return "crypt" in types, source


def _check_full_disk_encryption(check: CheckDefinition) -> CheckResult:
    encrypted, source = _encrypted_mount("/")
    if encrypted is None:
        return _result(check, Status.UNKNOWN, "encryption.root_status_unknown", source)
    if encrypted:
        return _result(check, Status.OK, "encryption.root_crypt_mapping", source)
    return _result(
        check,
        Status.WARNING,
        "encryption.root_crypt_mapping_not_found",
        source,
    )


def _check_home_encryption(check: CheckDefinition) -> CheckResult:
    encrypted, source = _encrypted_mount("/home")
    if encrypted is None:
        return _result(check, Status.UNKNOWN, "encryption.home_status_unknown", source)
    if encrypted:
        return _result(check, Status.OK, "encryption.home_crypt_mapping", source)
    return _result(
        check,
        Status.WARNING,
        "encryption.home_crypt_mapping_not_found",
        source,
    )


CHECKS = (
    CheckDefinition("firewall", 1, _check_firewall),
    CheckDefinition("updates", 1, _check_automatic_updates),
    CheckDefinition("timeshift", 1, _check_timeshift),
    CheckDefinition("access-control", 1, _check_access_control),
    CheckDefinition("ssh", 1, _check_ssh),
    CheckDefinition("clamav", 1, _check_clamav),
    CheckDefinition("screen-lock", 1, _check_screen_lock),
    CheckDefinition("bluetooth", 1, _check_bluetooth),
    CheckDefinition("root-shell", 2, _check_root_shell),
    CheckDefinition("full-disk-encryption", 2, _check_full_disk_encryption),
    CheckDefinition("home-encryption", 2, _check_home_encryption),
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


PRIVILEGED_CHECK_IDS = frozenset({"firewall", "timeshift", "access-control"})
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
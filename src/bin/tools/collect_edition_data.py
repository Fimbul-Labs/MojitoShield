"""Print, as JSON, what MojitoShield's checks read on this system.

Run it once on each Linux Mint edition and save the output as test data:

    cd src/bin
    python3 -m tools.collect_edition_data > tests/data/editions/NAME.json

NAME is the edition, for example mint-22.3-xfce. The output only contains
system facts that are the same for every user of an edition: os-release
fields, the desktop, settings values, command results and which files exist.
For the planned "System up to date" rules it also records the pending
upgrades, the package lists' dates and a summary of each APT history entry.
It never contains user names, file contents, addresses or device names.
"""

from __future__ import annotations

import json
import os
import platform
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from mojitoshield import system
from mojitoshield.checks import (
    apparmor,
    auto_login,
    boot_menu,
    firewall,
    network_services,
    screen_lock,
    timeshift,
    updates,
)

FORMAT_VERSION = 2
APT_LISTS = Path("/var/lib/apt/lists")
RELEASE_FIELDS = ("Origin", "Suite", "Date")
HISTORY_COUNTED_ACTIONS = ("Install", "Upgrade", "Remove", "Purge")
OS_RELEASE_FIELDS = ("ID", "ID_LIKE", "NAME", "PRETTY_NAME", "VERSION_ID", "VERSION_CODENAME")

# The checks decide from whether these exist, not from what they contain.
PRESENCE_PATHS = (
    firewall.UFW_CONFIG,
    updates.APT_AUTO_UPGRADES,
    updates.MINTUPDATE_AUTOMATION_SCRIPT,
    updates.MINTUPDATE_UPGRADE_FLAG,
    auto_login.DISPLAY_MANAGER_FILE,
    *auto_login.LIGHTDM_CONFIG_SOURCES,
    timeshift.TIMESHIFT_EXECUTABLE,
    timeshift.TIMESHIFT_CONFIG,
    network_services.SSH_CONFIG,
    apparmor.APPARMOR_ENABLED,
    boot_menu.GRUB_SCRIPTS,
)


def screen_lock_commands() -> list[list[str]]:
    """Every screen-lock query, for all desktops, so one file covers what any desktop would read."""
    commands = []
    for settings in screen_lock.SCREEN_LOCK_SETTINGS.values():
        commands.extend([settings.lock_query, settings.idle_delay_query])
        if settings.idle_enabled_query is not None:
            commands.append(settings.idle_enabled_query)
    return commands


def service_commands() -> list[list[str]]:
    return [
        ["systemctl", "is-active", "ufw"],
        ["systemctl", "is-enabled", updates.MINTUPDATE_UPGRADE_TIMER],
        # Simulated: lists pending upgrades and their archives without changing anything.
        ["apt-get", "-s", "dist-upgrade"],
    ]


def command_record(arguments: list[str]) -> dict[str, object]:
    # The same runner as the checks, so the output has the same C locale.
    command = system.run_command(arguments)
    if command is None:
        return {"arguments": arguments, "available": False}
    return {
        "arguments": arguments,
        "available": True,
        "returncode": command.returncode,
        "stdout": command.stdout,
    }


def os_release_fields() -> dict[str, str]:
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        return {}
    return {field: release[field] for field in OS_RELEASE_FIELDS if field in release}


def display_manager() -> str | None:
    try:
        return Path(auto_login.DISPLAY_MANAGER_FILE.read_text(encoding="utf-8").strip()).name
    except (OSError, UnicodeError):
        return None


def apparmor_enabled() -> str | None:
    try:
        return apparmor.APPARMOR_ENABLED.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return None


def package_lists() -> dict[str, dict[str, str]]:
    """The date fields of each repository's Release file, and when it changed on disk."""
    lists = {}
    for path in sorted(APT_LISTS.glob("*Release")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        except OSError:
            continue
        if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
            # A signed InRelease file: the fields start after the signature header.
            text = text.partition("\n\n")[2]
        fields = {}
        for line in text.splitlines():
            if not line.strip() or line.startswith(" "):
                break
            name, _, value = line.partition(":")
            if name in RELEASE_FIELDS:
                fields[name] = value.strip()
        fields["modified"] = modified.isoformat(timespec="seconds")
        lists[path.name] = fields
    return lists


def history_entries() -> list[dict[str, object]]:
    """One summary per APT history entry: when, which tool, and how many packages changed.

    Only the first two words of the command line are kept, so local file paths
    and user names in Requested-By never leave the system.
    """
    entries = []
    for history in updates._read_apt_history():
        for block in re.split(r"\n\s*\n", history):
            fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
            if "Start-Date" not in fields:
                continue
            entries.append(
                {
                    "start": " ".join(fields["Start-Date"].split()),
                    "command": " ".join(fields.get("Commandline", "").split()[:2]),
                    "requested_by_user": "Requested-By" in fields,
                    **{
                        action.lower(): len(re.findall(r"\)(?:, |$)", fields[action]))
                        for action in HISTORY_COUNTED_ACTIONS
                        if action in fields
                    },
                }
            )
    return sorted(entries, key=lambda entry: entry["start"])


def collect() -> dict[str, object]:
    return {
        "format": FORMAT_VERSION,
        "collected": date.today().isoformat(),
        "os_release": os_release_fields(),
        "xdg_current_desktop": os.environ.get("XDG_CURRENT_DESKTOP", ""),
        "display_manager": display_manager(),
        "apparmor_enabled": apparmor_enabled(),
        "files_present": {str(path): path.exists() for path in PRESENCE_PATHS},
        "commands": [
            command_record(arguments)
            for arguments in [*screen_lock_commands(), *service_commands()]
        ],
        "package_lists": package_lists(),
        "apt_history": history_entries(),
    }


def main() -> int:
    json.dump(collect(), sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

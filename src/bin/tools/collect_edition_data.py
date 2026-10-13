"""Print, as JSON, what MojitoShield's checks read on this system.

Run it once on each Linux Mint edition and save the output as test data:

    cd src/bin
    python3 -m tools.collect_edition_data > tests/data/editions/NAME.json

NAME is the edition, for example mint-22.3-xfce. The output only contains
system facts that are the same for every user of an edition: os-release
fields, the desktop, settings values, command results and which files exist.
It never contains user names, file contents, addresses or device names.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from datetime import date
from pathlib import Path

import mojitoshield_core as core


FORMAT_VERSION = 1
OS_RELEASE_FIELDS = ("ID", "ID_LIKE", "NAME", "PRETTY_NAME", "VERSION_ID", "VERSION_CODENAME")

# The checks decide from whether these exist, not from what they contain.
PRESENCE_PATHS = (
    core.UFW_CONFIG,
    core.APT_AUTO_UPGRADES,
    core.MINTUPDATE_AUTOMATION_SCRIPT,
    core.MINTUPDATE_UPGRADE_FLAG,
    core.DISPLAY_MANAGER_FILE,
    *core.LIGHTDM_CONFIG_SOURCES,
    core.TIMESHIFT_EXECUTABLE,
    core.TIMESHIFT_CONFIG,
    core.SSH_CONFIG,
    core.APPARMOR_ENABLED,
    core.GRUB_SCRIPTS,
)


def screen_lock_commands() -> list[list[str]]:
    """Every screen-lock query, for all desktops, so one file covers what any desktop would read."""
    commands = []
    for settings in core.SCREEN_LOCK_SETTINGS.values():
        commands.extend([settings.lock_query, settings.idle_delay_query])
        if settings.idle_enabled_query is not None:
            commands.append(settings.idle_enabled_query)
    return commands


def service_commands() -> list[list[str]]:
    return [
        ["systemctl", "is-active", "ufw"],
        ["systemctl", "is-enabled", core.MINTUPDATE_UPGRADE_TIMER],
    ]


def command_record(arguments: list[str]) -> dict[str, object]:
    # The same runner as the checks, so the output has the same C locale.
    command = core._run_command(arguments)
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
        return Path(core.DISPLAY_MANAGER_FILE.read_text(encoding="utf-8").strip()).name
    except (OSError, UnicodeError):
        return None


def apparmor_enabled() -> str | None:
    try:
        return core.APPARMOR_ENABLED.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return None


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
    }


def main() -> int:
    json.dump(collect(), sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

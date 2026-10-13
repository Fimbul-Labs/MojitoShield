"""Check 3, Screen lock: does the screen lock by itself after a while without use?"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from mojitoshield import system
from mojitoshield.results import Outcome, Status


@dataclass(frozen=True)
class ScreenLockSettings:
    """Where one desktop keeps its screen-lock settings.

    Attributes:
        name: The desktop's name as shown to the user.
        lock_query: Command that prints whether locking is on.
        idle_delay_query: Command that prints the delay before the screen locks.
        idle_delay_unit_seconds: Seconds per unit of that delay (1 or 60).
        idle_enabled_query: Command that prints whether the screensaver starts
            by itself, for desktops that have a separate switch for it.
    """

    name: str
    lock_query: list[str]
    idle_delay_query: list[str]
    idle_delay_unit_seconds: int
    idle_enabled_query: list[str] | None = None


def _xfconf_query(property_name: str) -> list[str]:
    return ["xfconf-query", "--channel", "xfce4-screensaver", "--property", property_name]


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
        idle_enabled_query=["gsettings", "get", "org.mate.screensaver", "idle-activation-enabled"],
    ),
    "xfce": ScreenLockSettings(
        name="Xfce",
        lock_query=_xfconf_query("/lock/enabled"),
        idle_delay_query=_xfconf_query("/saver/idle-activation/delay"),
        idle_delay_unit_seconds=60,
        idle_enabled_query=_xfconf_query("/saver/enabled"),
    ),
}


def current_desktop(environment: Mapping[str, str] | None = None) -> str | None:
    """Find which of Mint's desktops is running, from XDG_CURRENT_DESKTOP.

    Args:
        environment: Environment variables to read; the process's own by default.

    Returns:
        "cinnamon", "mate" or "xfce", or None for any other desktop.

    Examples:
        >>> current_desktop({"XDG_CURRENT_DESKTOP": "X-Cinnamon"})
        'cinnamon'
        >>> current_desktop({"XDG_CURRENT_DESKTOP": "GNOME"}) is None
        True
    """
    if environment is None:
        environment = os.environ
    desktops = environment.get("XDG_CURRENT_DESKTOP", "").lower().split(":")
    for desktop in SCREEN_LOCK_SETTINGS:
        if desktop in desktops or f"x-{desktop}" in desktops:
            return desktop
    return None


def _setting(arguments: list[str]) -> str | None:
    command = system.run_command(arguments)
    if command is None or command.returncode != 0:
        return None
    return command.stdout.strip().lower()


def parse_setting_number(value: str | None) -> int | None:
    """Read a number printed by gsettings or xfconf-query.

    Args:
        value: The printed setting, such as "uint32 900" or "5", or None.

    Returns:
        The number, or None when there is no value or it is not a number.

    Examples:
        >>> parse_setting_number("uint32 900")
        900
        >>> parse_setting_number("5")
        5
        >>> parse_setting_number("") is None
        True
    """
    if not value:
        return None
    try:
        return int(value.split()[-1])
    except ValueError:
        return None


def check() -> Outcome:
    """Check whether the screen locks by itself after a while without use.

    Returns:
        OK with the delay in minutes, Warning when locking is off or never
        starts by itself, or Could not determine on other desktops or when a
        setting cannot be read.
    """
    desktop = current_desktop()
    if desktop is None:
        return Outcome(Status.UNKNOWN, "screen_lock.desktop_not_supported")

    settings = SCREEN_LOCK_SETTINGS[desktop]
    data = {"desktop": settings.name}
    lock_enabled = _setting(settings.lock_query)
    if lock_enabled is None:
        return Outcome(Status.UNKNOWN, "screen_lock.settings_unavailable", data=data)
    if lock_enabled == "false":
        return Outcome(Status.WARNING, "screen_lock.disabled", data=data)
    if lock_enabled != "true":
        return Outcome(Status.UNKNOWN, "screen_lock.unrecognized_result", data=data)

    idle_enabled_query = settings.idle_enabled_query
    if idle_enabled_query is not None and _setting(idle_enabled_query) == "false":
        return Outcome(Status.WARNING, "screen_lock.never_automatic", data=data)

    idle_delay = parse_setting_number(_setting(settings.idle_delay_query))
    if idle_delay is None:
        return Outcome(Status.UNKNOWN, "screen_lock.idle_delay_unavailable", data=data)
    if idle_delay == 0:
        return Outcome(Status.WARNING, "screen_lock.never_automatic", data=data)

    minutes = max(1, round(idle_delay * settings.idle_delay_unit_seconds / 60))
    return Outcome(Status.OK, "screen_lock.enabled", data={**data, "minutes": str(minutes)})

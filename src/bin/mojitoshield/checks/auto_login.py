"""Check 4, Automatic login: does an account log in without a password at startup?"""

from __future__ import annotations

import configparser
from collections.abc import Iterable
from pathlib import Path

from mojitoshield.results import Outcome, Status

DISPLAY_MANAGER_FILE = Path("/etc/X11/default-display-manager")
# Read in this order, later values winning, as Mint's Login Window tool does.
LIGHTDM_CONFIG_SOURCES = (
    Path("/usr/share/lightdm/lightdm.conf.d"),
    Path("/etc/lightdm/lightdm.conf.d"),
    Path("/etc/lightdm/lightdm.conf"),
)
LIGHTDM_SEAT_GROUPS = ("SeatDefaults", "Seat:*", "Seat:seat0")


def lightdm_autologin_user(config_texts: Iterable[str]) -> str:
    r"""Find the account LightDM logs in automatically, as Mint's Login Window does.

    Args:
        config_texts: The texts of the LightDM settings files, in the order
            LightDM reads them; a later value replaces an earlier one. Files
            that cannot be parsed are skipped, as LightDM skips them.

    Returns:
        The user name, or an empty string when no account logs in by itself.
        The name is only used to decide; it is never shown or stored.

    Examples:
        >>> lightdm_autologin_user(["[Seat:*]\nautologin-user=\n"])
        ''
        >>> lightdm_autologin_user(["[Seat:*]\nautologin-user=alex\n"])
        'alex'
    """
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


def check() -> Outcome:
    """Check whether an account logs in at startup without a password.

    Returns:
        OK when no account logs in automatically, Warning when one does, or
        Could not determine when the login screen is not LightDM or its
        settings cannot be read.
    """
    try:
        display_manager = Path(DISPLAY_MANAGER_FILE.read_text(encoding="utf-8").strip()).name
    except (OSError, UnicodeError):
        return Outcome(Status.UNKNOWN, "auto_login.display_manager_unknown")
    if display_manager != "lightdm":
        return Outcome(
            Status.UNKNOWN,
            "auto_login.display_manager_not_supported",
            data={"display_manager": display_manager[:40]},
        )

    try:
        texts = [path.read_text(encoding="utf-8") for path in _lightdm_config_files()]
    except (OSError, UnicodeError):
        return Outcome(Status.UNKNOWN, "auto_login.settings_unreadable")

    # The user name is personal data, so it is never part of the result.
    if lightdm_autologin_user(texts):
        return Outcome(Status.WARNING, "auto_login.enabled")
    return Outcome(Status.OK, "auto_login.disabled")

"""Recognise Linux Mint and LMDE, the systems MojitoShield is made for."""

from __future__ import annotations

import platform
from collections.abc import Mapping


def identify_distribution(release: Mapping[str, str]) -> bool:
    """Return whether os-release data identifies Linux Mint or LMDE.

    Args:
        release: Fields from /etc/os-release, such as ID, NAME and PRETTY_NAME.

    Returns:
        True for Linux Mint and LMDE, False for anything else.

    Examples:
        >>> identify_distribution({"ID": "linuxmint", "NAME": "Linux Mint"})
        True
        >>> identify_distribution({"ID": "debian", "PRETTY_NAME": "LMDE 7 (gigi)"})
        True
        >>> identify_distribution({"ID": "ubuntu", "NAME": "Ubuntu"})
        False
    """
    distribution_id = release.get("ID", "").lower()
    name = release.get("NAME", "").lower()
    pretty_name = release.get("PRETTY_NAME", "").lower()

    if distribution_id == "linuxmint":
        return True

    return "lmde" in name or "lmde" in pretty_name or "linux mint debian edition" in pretty_name


def current_distribution() -> tuple[bool, str | None]:
    """Identify the running system from /etc/os-release.

    Returns:
        Whether the system is Linux Mint or LMDE, and its display name, or
        None when os-release cannot be read or names nothing.
    """
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        return False, None

    name = release.get("PRETTY_NAME") or release.get("NAME")
    return identify_distribution(release), name

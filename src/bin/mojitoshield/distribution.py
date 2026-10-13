"""Recognise Linux Mint and LMDE, the systems MojitoShield is made for."""

from __future__ import annotations

import platform
from collections.abc import Mapping


def identify_distribution(release: Mapping[str, str]) -> bool:
    """Return whether os-release data identifies Mint or LMDE."""
    distribution_id = release.get("ID", "").lower()
    name = release.get("NAME", "").lower()
    pretty_name = release.get("PRETTY_NAME", "").lower()

    if distribution_id == "linuxmint":
        return True

    return "lmde" in name or "lmde" in pretty_name or "linux mint debian edition" in pretty_name


def current_distribution() -> tuple[bool, str | None]:
    """Return whether this system is supported, and its name if it has one."""
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        return False, None

    name = release.get("PRETTY_NAME") or release.get("NAME")
    return identify_distribution(release), name

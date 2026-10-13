"""Check 1, Firewall: is UFW turned on and running?"""

from __future__ import annotations

import re
from pathlib import Path

from mojitoshield import system
from mojitoshield.results import Outcome, Status

UFW_CONFIG = Path("/etc/ufw/ufw.conf")


def parse_ufw_enabled(contents: str) -> bool | None:
    r"""Read the ENABLED setting from the text of /etc/ufw/ufw.conf.

    The file is a shell fragment, so when ENABLED appears more than once, the
    last one wins.

    Args:
        contents: The text of ufw.conf.

    Returns:
        True for ENABLED=yes, False for ENABLED=no, or None if the setting is
        missing or has another value.

    Examples:
        >>> parse_ufw_enabled("ENABLED=yes\n")
        True
        >>> parse_ufw_enabled('ENABLED=no\nENABLED="yes"\n')
        True
        >>> parse_ufw_enabled("# ENABLED=yes\n") is None
        True
    """
    enabled = None
    for line in contents.splitlines():
        match = re.match(r'^\s*ENABLED\s*=\s*["\']?(yes|no)["\']?\s*$', line, re.IGNORECASE)
        if match:
            enabled = match.group(1).lower() == "yes"
    return enabled


def check() -> Outcome:
    """Check whether the UFW firewall is turned on and was started.

    Returns:
        OK when it is on and its service is active, Warning when it is turned
        off, and Requires extended permission when the readable settings cannot
        confirm it.
    """
    try:
        contents = UFW_CONFIG.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Outcome(Status.UNKNOWN, "firewall.ufw_not_installed")
    except (OSError, UnicodeError):
        return Outcome(Status.AUTH_REQUIRED, "firewall.authorization_required")

    enabled = parse_ufw_enabled(contents)
    if enabled is False:
        return Outcome(Status.WARNING, "firewall.disabled", str(UFW_CONFIG))
    if enabled is None:
        return Outcome(Status.AUTH_REQUIRED, "firewall.authorization_required")

    service = system.run_command(["systemctl", "is-active", "ufw"])
    if service is not None and service.stdout.strip() == "active":
        return Outcome(Status.OK, "firewall.enabled", str(UFW_CONFIG))
    return Outcome(Status.AUTH_REQUIRED, "firewall.service_not_confirmed")

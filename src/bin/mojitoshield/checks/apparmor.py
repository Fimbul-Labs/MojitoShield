"""Check 7, AppArmor: is AppArmor turned on?"""

from __future__ import annotations

from pathlib import Path

from mojitoshield.results import Outcome, Status

APPARMOR_ENABLED = Path("/sys/module/apparmor/parameters/enabled")


def check() -> Outcome:
    try:
        enabled = APPARMOR_ENABLED.read_text(encoding="ascii").strip().upper()
    except FileNotFoundError:
        return Outcome(Status.UNKNOWN, "apparmor.not_available")
    except (OSError, UnicodeError):
        return Outcome(Status.UNKNOWN, "apparmor.status_unreadable")

    if enabled == "Y":
        return Outcome(Status.OK, "apparmor.enabled", str(APPARMOR_ENABLED))
    if enabled == "N":
        return Outcome(Status.WARNING, "apparmor.disabled", str(APPARMOR_ENABLED))
    return Outcome(Status.UNKNOWN, "apparmor.unrecognized_status")

"""The list of checks, in the order and levels shown to the user, and running them."""

from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from mojitoshield.checks import (
    apparmor,
    auto_login,
    boot_menu,
    disk_encryption,
    firewall,
    network_services,
    screen_lock,
    timeshift,
    updates,
)
from mojitoshield.results import CheckResult, Outcome, Status

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CheckDefinition:
    """One entry in the list of checks.

    Attributes:
        check_id: Stable identifier, also used in the text catalog and by the
            Extended scan.
        level: 1 for everyday protection, 2 for protection against someone
            with the computer in hand.
        run: The check's function, which returns an Outcome and never raises.
    """

    check_id: str
    level: int
    run: Callable[[], Outcome]

    def result(self, outcome: Outcome) -> CheckResult:
        """Label an outcome with this check's ID and level."""
        return CheckResult(self.check_id, self.level, outcome)


CHECKS = (
    CheckDefinition("firewall", 1, firewall.check),
    CheckDefinition("updates", 1, updates.check),
    CheckDefinition("screen-lock", 1, screen_lock.check),
    CheckDefinition("auto-login", 1, auto_login.check),
    CheckDefinition("timeshift", 1, timeshift.check),
    CheckDefinition("network-services", 1, network_services.check),
    CheckDefinition("apparmor", 1, apparmor.check),
    CheckDefinition("disk-encryption", 2, disk_encryption.check),
    CheckDefinition("boot-menu", 2, boot_menu.check),
)


def run_check(definition: CheckDefinition) -> CheckResult:
    """Run one check, turning an unexpected error into Could not determine.

    Checks handle the errors they expect themselves. This is the safety net
    for the rest, so one broken check never stops the scan.

    Args:
        definition: The check to run.

    Returns:
        The check's result, or Could not determine with the error type as
        evidence if the check raised.
    """
    try:
        outcome = definition.run()
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        # Only the error type is logged; its message may contain paths with the user name.
        LOGGER.warning(
            "Check %s could not complete (%s).", definition.check_id, type(error).__name__
        )
        outcome = Outcome(Status.UNKNOWN, "check.unexpected_error", type(error).__name__)
    return definition.result(outcome)


def run_checks() -> tuple[CheckResult, ...]:
    """Run every check in the order shown to the user."""
    return tuple(run_check(definition) for definition in CHECKS)

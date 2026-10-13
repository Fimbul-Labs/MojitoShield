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
    check_id: str
    level: int
    run: Callable[[], Outcome]

    def result(self, outcome: Outcome) -> CheckResult:
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
    """Run one check; an unexpected error gives Could not determine instead of stopping the scan."""
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
    return tuple(run_check(definition) for definition in CHECKS)

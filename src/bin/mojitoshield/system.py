"""Shared access to the local system: running read-only commands and reading the clock.

Checks call these through the module (system.run_command, system.now), so tests
can replace them in one place.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime

COMMAND_TIMEOUT_SECONDS = 3


def run_command(
    arguments: list[str], timeout: float = COMMAND_TIMEOUT_SECONDS
) -> subprocess.CompletedProcess[str] | None:
    """Run a read-only command and capture its output.

    The command runs with the C locale, so its output is in English and can be
    parsed the same way whatever language the user has chosen.

    Args:
        arguments: The program name followed by its arguments. The program is
            looked up on PATH; nothing is passed through a shell.
        timeout: Seconds to wait before giving up.

    Returns:
        The finished process, whatever its exit code, or None if the program
        is not installed, could not start or did not finish in time.
    """
    executable = shutil.which(arguments[0])
    if executable is None:
        return None

    try:
        return subprocess.run(
            [executable, *arguments[1:]],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "LANG": "C", "LC_ALL": "C", "LANGUAGE": "C"},
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def now() -> datetime:
    """Return the current local time; tests replace this to fix the clock."""
    return datetime.now()


def days_since(moment: datetime) -> float:
    """Return how many days ago a local time was, never less than zero.

    Args:
        moment: A local time without a time zone, like the ones now() returns.

    Returns:
        The age in days, including fractions; 0.0 for times in the future.
    """
    return max(0.0, (now() - moment).total_seconds() / 86400)

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


def run_command(arguments: list[str]) -> subprocess.CompletedProcess[str] | None:
    """Run a read-only command and return its result, or None if it could not run.

    The C locale keeps the output in English, so parsing it does not depend on
    the user's language.
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
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def now() -> datetime:
    return datetime.now()


def days_since(moment: datetime) -> float:
    return max(0.0, (now() - moment).total_seconds() / 86400)

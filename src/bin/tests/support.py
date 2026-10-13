"""Shared helpers for the check tests: a temporary folder, a fixed clock and fake commands."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from mojitoshield.results import Outcome, Status

NOW = datetime(2026, 10, 11, 12, 0, 0)

CommandResponses = dict[tuple[str, ...], "subprocess.CompletedProcess[str] | None"]


def completed(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    """Return what a finished command with this output looks like."""
    return subprocess.CompletedProcess([], returncode, stdout, "")


def fake_commands(responses: CommandResponses):
    """Answer system.run_command by the longest matching argument prefix; others give None."""

    def run_command(arguments: list[str], timeout: float | None = None):
        for length in range(len(arguments), 0, -1):
            key = tuple(arguments[:length])
            if key in responses:
                return responses[key]
        return None

    return patch("mojitoshield.system.run_command", side_effect=run_command)


class CheckTestCase(unittest.TestCase):
    """Gives each test a temporary folder, a fixed clock and no real commands."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.start(patch("mojitoshield.system.now", return_value=NOW))
        self.commands({})

    def start(self, patcher):
        """Start a patch and stop it again when the test ends."""
        patched = patcher.start()
        self.addCleanup(patcher.stop)
        return patched

    def commands(self, responses: CommandResponses) -> None:
        self.start(fake_commands(responses))

    def path(self, module: ModuleType, name: str, relative: str) -> Path:
        """Point a path constant of a check module into the temporary folder."""
        path = self.root / relative
        self.start(patch.object(module, name, path))
        return path

    def write(self, relative: str, contents: str | bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contents, bytes):
            path.write_bytes(contents)
        else:
            path.write_text(contents, encoding="utf-8")
        return path

    def assertOutcome(
        self, check: Callable[[], Outcome], status: Status, message_id: str
    ) -> Outcome:
        outcome = check()
        self.assertEqual((outcome.status, outcome.message_id), (status, message_id))
        return outcome

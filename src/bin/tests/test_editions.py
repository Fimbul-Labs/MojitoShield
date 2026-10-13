"""Replay data collected on real Linux Mint editions through the checks.

Each file in tests/data/editions was written by tools/collect_edition_data.py
on one edition. EXPECTED holds the result a person confirmed on that system,
so new data cannot be added without deciding what the right result is.
"""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from mojitoshield.checks import screen_lock
from mojitoshield.distribution import identify_distribution
from mojitoshield.results import Status
from support import CheckTestCase, completed

EDITIONS = Path(__file__).parent / "data/editions"

# Edition file name: the screen-lock result confirmed on that system.
EXPECTED = {
    # Fresh install: Cinnamon's default locks after 15 minutes.
    "mint-22.3-cinnamon": (Status.OK, "screen_lock.enabled", "15"),
}


def load_editions() -> dict[str, dict]:
    return {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(EDITIONS.glob("*.json"))
    }


class EditionDataTests(CheckTestCase):
    def replay(self, edition: dict):
        """Answer the checks' commands with the recorded results."""
        responses = {
            tuple(record["arguments"]): (
                completed(record["stdout"], record["returncode"]) if record["available"] else None
            )
            for record in edition["commands"]
        }
        self.start(
            patch(
                "mojitoshield.system.run_command",
                side_effect=lambda arguments: responses.get(tuple(arguments)),
            )
        )
        self.start(
            patch.dict("os.environ", {"XDG_CURRENT_DESKTOP": edition["xdg_current_desktop"]})
        )

    def test_every_edition_has_a_confirmed_result(self):
        self.assertEqual(set(load_editions()), set(EXPECTED))

    def test_every_edition_is_identified_as_mint(self):
        for name, edition in load_editions().items():
            with self.subTest(edition=name):
                self.assertTrue(identify_distribution(edition["os_release"]))

    def test_screen_lock_matches_the_confirmed_result(self):
        for name, edition in load_editions().items():
            with self.subTest(edition=name):
                self.replay(edition)
                outcome = screen_lock.check()
                status, message_id, minutes = EXPECTED[name]
                self.assertEqual((outcome.status, outcome.message_id), (status, message_id))
                self.assertEqual(outcome.data.get("minutes"), minutes)


if __name__ == "__main__":
    unittest.main()

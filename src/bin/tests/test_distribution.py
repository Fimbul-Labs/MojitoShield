"""Tests for recognising Linux Mint and LMDE from os-release data."""

import unittest
from unittest.mock import patch

from mojitoshield.distribution import current_distribution, identify_distribution


class DistributionTests(unittest.TestCase):
    def test_supported_and_unsupported_distributions(self):
        cases = (
            ({"ID": "linuxmint", "NAME": "Linux Mint"}, True),
            ({"ID": "debian", "NAME": "LMDE", "PRETTY_NAME": "LMDE 6 (faye)"}, True),
            ({"ID": "debian", "PRETTY_NAME": "Linux Mint Debian Edition 6"}, True),
            ({"ID": "ubuntu", "ID_LIKE": "debian", "NAME": "Ubuntu"}, False),
            # A derivative that mentions Mint in ID_LIKE is still not Mint.
            ({"ID": "ubuntu", "ID_LIKE": "linuxmint", "NAME": "Ubuntu"}, False),
            ({"ID": "debian", "NAME": "Debian GNU/Linux"}, False),
            ({"ID": "fedora", "NAME": "Fedora Linux"}, False),
            ({}, False),
        )
        for release, supported in cases:
            with self.subTest(release=release):
                self.assertIs(identify_distribution(release), supported)

    def test_missing_os_release_is_reported_as_unknown_distribution(self):
        with patch(
            "mojitoshield.distribution.platform.freedesktop_os_release", side_effect=OSError
        ):
            self.assertEqual(current_distribution(), (False, None))

    def test_current_distribution_returns_display_name(self):
        release = {"ID": "linuxmint", "NAME": "Linux Mint", "PRETTY_NAME": "Linux Mint 22.2"}
        with patch(
            "mojitoshield.distribution.platform.freedesktop_os_release", return_value=release
        ):
            self.assertEqual(current_distribution(), (True, "Linux Mint 22.2"))


if __name__ == "__main__":
    unittest.main()

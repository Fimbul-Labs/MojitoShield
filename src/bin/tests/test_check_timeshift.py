"""Tests for check: Timeshift (`timeshift`), following docs/check-contracts.md."""

import json
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from mojitoshield.checks import timeshift
from mojitoshield.results import Status
from support import NOW, CheckTestCase, completed


class TimeshiftTests(CheckTestCase):
    ROOT_UUID = "11111111-2222-3333-4444-555555555555"

    def setUp(self):
        super().setUp()
        self.executable = self.path(timeshift, "TIMESHIFT_EXECUTABLE", "bin/timeshift")
        self.path(timeshift, "TIMESHIFT_CONFIG", "etc/timeshift.json")
        self.snapshots = self.path(timeshift, "TIMESHIFT_SNAPSHOTS", "timeshift/snapshots")
        self.write("bin/timeshift", "")
        self.commands({("findmnt",): completed(self.ROOT_UUID + "\n")})

    def settings(self, **overrides: str):
        settings = {
            "backup_device_uuid": self.ROOT_UUID,
            "do_first_run": "false",
            "btrfs_mode": "false",
            "schedule_monthly": "true",
            "schedule_weekly": "false",
            "schedule_daily": "false",
            "schedule_hourly": "false",
            "schedule_boot": "false",
        }
        settings.update(overrides)
        self.write("etc/timeshift.json", json.dumps(settings))

    def snapshot(self, age_days: float):
        (self.snapshots / f"{NOW - timedelta(days=age_days):%Y-%m-%d_%H-%M-%S}").mkdir(
            parents=True
        )

    def test_recent_snapshot(self):
        self.settings()
        self.snapshot(60)
        self.snapshot(8)
        outcome = self.assertOutcome(timeshift.check, Status.OK, "timeshift.recent_snapshot")
        self.assertEqual(outcome.data, {"days": "8", "limit": "40"})

    def test_snapshot_older_than_the_limit(self):
        self.settings()
        self.snapshot(41)
        self.assertOutcome(timeshift.check, Status.WARNING, "timeshift.snapshot_too_old")

    def test_limit_follows_the_schedule(self):
        self.settings(schedule_monthly="false", schedule_weekly="true")
        self.snapshot(15)
        outcome = self.assertOutcome(timeshift.check, Status.WARNING, "timeshift.snapshot_too_old")
        self.assertEqual(outcome.data["limit"], "14")

    def test_age_limit_bounds(self):
        self.assertEqual(timeshift.timeshift_age_limit_days(("hourly",)), 7)
        self.assertEqual(timeshift.timeshift_age_limit_days(("daily", "monthly")), 7)
        self.assertEqual(timeshift.timeshift_age_limit_days(("weekly",)), 14)
        self.assertEqual(timeshift.timeshift_age_limit_days(("monthly",)), 40)
        self.assertEqual(timeshift.timeshift_age_limit_days(("boot",)), 40)
        self.assertEqual(timeshift.timeshift_age_limit_days(()), 40)

    def test_set_up_without_snapshots(self):
        self.settings()
        self.snapshots.mkdir(parents=True)
        (self.snapshots / "not-a-snapshot").mkdir()
        self.assertOutcome(timeshift.check, Status.WARNING, "timeshift.no_snapshots")

    def test_never_set_up(self):
        self.assertOutcome(timeshift.check, Status.WARNING, "timeshift.not_set_up")
        for overrides in ({"backup_device_uuid": ""}, {"do_first_run": "true"}):
            with self.subTest(overrides=overrides):
                self.settings(**overrides)
                self.assertOutcome(timeshift.check, Status.WARNING, "timeshift.not_set_up")

    def test_not_installed(self):
        self.executable.unlink()
        self.assertOutcome(timeshift.check, Status.UNKNOWN, "timeshift.not_installed")

    def test_snapshots_that_cannot_be_seen(self):
        self.settings(btrfs_mode="true")
        self.assertOutcome(timeshift.check, Status.UNKNOWN, "timeshift.btrfs_mode")
        self.settings(backup_device_uuid="99999999-0000-0000-0000-000000000000")
        self.assertOutcome(timeshift.check, Status.UNKNOWN, "timeshift.separate_device")

    def test_corrupt_settings(self):
        self.write("etc/timeshift.json", "{not json")
        self.assertOutcome(timeshift.check, Status.UNKNOWN, "timeshift.settings_unreadable")

    def test_unreadable_snapshot_folder(self):
        self.settings()
        with patch.object(Path, "iterdir", side_effect=PermissionError):
            self.assertOutcome(timeshift.check, Status.UNKNOWN, "timeshift.snapshots_unreadable")


if __name__ == "__main__":
    unittest.main()

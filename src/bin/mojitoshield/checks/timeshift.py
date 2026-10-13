"""Check 5, Timeshift: is there a recent system snapshot?"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from mojitoshield import system
from mojitoshield.results import Outcome, Status

TIMESHIFT_EXECUTABLE = Path("/usr/bin/timeshift")
TIMESHIFT_CONFIG = Path("/etc/timeshift/timeshift.json")
TIMESHIFT_SNAPSHOTS = Path("/timeshift/snapshots")
TIMESHIFT_SCHEDULES = ("monthly", "weekly", "daily", "hourly", "boot")
TIMESHIFT_SCHEDULE_DAYS = {"hourly": 1 / 24, "daily": 1, "weekly": 7, "monthly": 30}
TIMESHIFT_MIN_AGE_LIMIT_DAYS = 7
TIMESHIFT_MAX_AGE_LIMIT_DAYS = 40


@dataclass(frozen=True)
class TimeshiftSettings:
    configured: bool
    btrfs_mode: bool
    schedules: tuple[str, ...]
    backup_device_uuid: str


def parse_timeshift_settings(contents: str) -> TimeshiftSettings | None:
    """Parse the Timeshift settings that tell where and when snapshots are made."""
    try:
        settings = json.loads(contents)
    except json.JSONDecodeError:
        return None
    if not isinstance(settings, dict):
        return None

    backup_device_uuid = settings.get("backup_device_uuid", "")
    if not isinstance(backup_device_uuid, str):
        return None

    def enabled(key: str) -> bool:
        # Timeshift stores booleans as the strings "true" and "false".
        return str(settings.get(key, "")).lower() == "true"

    return TimeshiftSettings(
        configured=bool(backup_device_uuid.strip()) and not enabled("do_first_run"),
        btrfs_mode=enabled("btrfs_mode"),
        schedules=tuple(name for name in TIMESHIFT_SCHEDULES if enabled(f"schedule_{name}")),
        backup_device_uuid=backup_device_uuid.strip(),
    )


def timeshift_age_limit_days(schedules: Sequence[str]) -> float:
    """Allow twice the most frequent schedule, within fixed bounds."""
    intervals = [
        TIMESHIFT_SCHEDULE_DAYS[name] for name in schedules if name in TIMESHIFT_SCHEDULE_DAYS
    ]
    if not intervals:
        return TIMESHIFT_MAX_AGE_LIMIT_DAYS
    return min(
        max(2 * min(intervals), TIMESHIFT_MIN_AGE_LIMIT_DAYS),
        TIMESHIFT_MAX_AGE_LIMIT_DAYS,
    )


def newest_snapshot_time(names: Iterable[str]) -> datetime | None:
    """Return the newest time among snapshot folder names like 2026-10-02_22-07-41."""
    times = []
    for name in names:
        try:
            times.append(datetime.strptime(name, "%Y-%m-%d_%H-%M-%S"))
        except ValueError:
            continue
    return max(times, default=None)


def _root_filesystem_uuid() -> str | None:
    command = system.run_command(["findmnt", "--noheadings", "--output", "UUID", "--target", "/"])
    if command is None or command.returncode != 0:
        return None
    return command.stdout.strip() or None


def check() -> Outcome:
    try:
        settings = parse_timeshift_settings(TIMESHIFT_CONFIG.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if TIMESHIFT_EXECUTABLE.is_file():
            return Outcome(Status.WARNING, "timeshift.not_set_up")
        return Outcome(Status.UNKNOWN, "timeshift.not_installed")
    except (OSError, UnicodeError):
        settings = None
    if settings is None:
        return Outcome(Status.UNKNOWN, "timeshift.settings_unreadable", str(TIMESHIFT_CONFIG))

    if not settings.configured:
        return Outcome(Status.WARNING, "timeshift.not_set_up", str(TIMESHIFT_CONFIG))
    if settings.btrfs_mode:
        # Btrfs snapshots are only mounted while Timeshift runs.
        return Outcome(Status.UNKNOWN, "timeshift.btrfs_mode", str(TIMESHIFT_CONFIG))
    root_uuid = _root_filesystem_uuid()
    if root_uuid is not None and root_uuid != settings.backup_device_uuid:
        return Outcome(Status.UNKNOWN, "timeshift.separate_device", str(TIMESHIFT_CONFIG))

    try:
        names = [path.name for path in TIMESHIFT_SNAPSHOTS.iterdir() if path.is_dir()]
    except FileNotFoundError:
        names = []
    except OSError:
        return Outcome(Status.UNKNOWN, "timeshift.snapshots_unreadable", str(TIMESHIFT_SNAPSHOTS))

    newest = newest_snapshot_time(names)
    if newest is None:
        return Outcome(Status.WARNING, "timeshift.no_snapshots", str(TIMESHIFT_SNAPSHOTS))

    age_days = system.days_since(newest)
    limit_days = timeshift_age_limit_days(settings.schedules)
    data = {"days": str(int(age_days)), "limit": str(int(limit_days))}
    if age_days <= limit_days:
        return Outcome(Status.OK, "timeshift.recent_snapshot", str(TIMESHIFT_SNAPSHOTS), data)
    return Outcome(Status.WARNING, "timeshift.snapshot_too_old", str(TIMESHIFT_SNAPSHOTS), data)

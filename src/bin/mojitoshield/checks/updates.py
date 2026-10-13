"""Check 2, System up to date: are updates installed, automatically or recently?"""

from __future__ import annotations

import gzip
import re
from datetime import datetime
from pathlib import Path

from mojitoshield import system
from mojitoshield.results import Outcome, Status

APT_AUTO_UPGRADES = Path("/etc/apt/apt.conf.d/20auto-upgrades")
APT_HISTORY_LOGS = (
    Path("/var/log/apt/history.log"),
    Path("/var/log/apt/history.log.1.gz"),
)
MINTUPDATE_AUTOMATION_SCRIPT = Path("/usr/lib/linuxmint/mintUpdate/automatic_upgrades.py")
MINTUPDATE_UPGRADE_FLAG = Path("/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled")
MINTUPDATE_UPGRADE_TIMER = "mintupdate-automation-upgrade.timer"
REBOOT_REQUIRED = Path("/var/run/reboot-required")
UPDATES_MAX_AGE_DAYS = 30
REBOOT_PENDING_MAX_DAYS = 7


def parse_apt_auto_updates(contents: str) -> bool | None:
    """Parse the two APT periodic settings relevant to automatic updates."""
    keys = {
        "Update-Package-Lists": None,
        "Unattended-Upgrade": None,
    }
    pattern = re.compile(
        r"^\s*APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)"
        r'\s+["\']?([01])["\']?\s*;'
    )

    for line in contents.splitlines():
        match = pattern.match(line)
        if match:
            keys[match.group(1)] = match.group(2) == "1"

    if any(value is None for value in keys.values()):
        return None
    return all(keys.values())


def latest_upgrade_time(history: str) -> datetime | None:
    """Return the start time of the newest APT history entry that upgraded packages."""
    latest = None
    started = None
    for line in history.splitlines():
        if line.startswith("Start-Date:"):
            try:
                started = datetime.strptime(
                    " ".join(line.split(":", 1)[1].split()), "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                started = None
        elif (
            line.startswith("Upgrade:")
            and started is not None
            and (latest is None or started > latest)
        ):
            latest = started
    return latest


def _read_apt_history() -> list[str]:
    histories = []
    for path in APT_HISTORY_LOGS:
        try:
            raw = path.read_bytes()
            if path.suffix == ".gz":
                raw = gzip.decompress(raw)
        except (OSError, EOFError, gzip.BadGzipFile):
            continue
        histories.append(raw.decode("utf-8", errors="replace"))
    return histories


def _mintupdate_automation_enabled() -> bool | None:
    """Return whether Update Manager's automatic upgrades run, or None if unknown."""
    if not MINTUPDATE_AUTOMATION_SCRIPT.is_file():
        return None
    try:
        flag_present = MINTUPDATE_UPGRADE_FLAG.exists()
    except OSError:
        return None
    command = system.run_command(["systemctl", "is-enabled", MINTUPDATE_UPGRADE_TIMER])
    if command is None:
        return None

    # The timer starts the upgrade script, and the script exits unless the flag exists.
    return flag_present and command.stdout.strip() == "enabled"


def _automatic_updates_source() -> str | None:
    """Return what installs updates automatically, if anything does."""
    try:
        if parse_apt_auto_updates(APT_AUTO_UPGRADES.read_text(encoding="utf-8")):
            return str(APT_AUTO_UPGRADES)
    except (OSError, UnicodeError):
        pass
    if _mintupdate_automation_enabled():
        return MINTUPDATE_UPGRADE_TIMER
    return None


def _reboot_pending_days() -> float | None:
    try:
        modified = REBOOT_REQUIRED.stat().st_mtime
    except OSError:
        return None
    return system.days_since(datetime.fromtimestamp(modified))


def check() -> Outcome:
    reboot_days = _reboot_pending_days()
    if reboot_days is not None and reboot_days > REBOOT_PENDING_MAX_DAYS:
        return Outcome(
            Status.WARNING,
            "updates.reboot_pending",
            str(REBOOT_REQUIRED),
            {"days": str(int(reboot_days))},
        )

    source = _automatic_updates_source()
    if source is not None:
        return Outcome(Status.OK, "updates.automatic", source)

    upgrade_times = [
        moment
        for history in _read_apt_history()
        if (moment := latest_upgrade_time(history)) is not None
    ]
    if not upgrade_times:
        return Outcome(Status.UNKNOWN, "updates.history_unavailable")

    days = system.days_since(max(upgrade_times))
    data = {"days": str(int(days))}
    evidence = str(APT_HISTORY_LOGS[0])
    if days <= UPDATES_MAX_AGE_DAYS:
        return Outcome(Status.OK, "updates.recently_installed", evidence, data)
    return Outcome(Status.WARNING, "updates.not_installed_recently", evidence, data)

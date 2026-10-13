"""Check 2, System up to date: are security updates installed, automatically or in time?"""

from __future__ import annotations

import gzip
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

from mojitoshield import system
from mojitoshield.results import Outcome, Status

APT_AUTO_UPGRADES = Path("/etc/apt/apt.conf.d/20auto-upgrades")
APT_HISTORY_LOGS = (
    Path("/var/log/apt/history.log"),
    Path("/var/log/apt/history.log.1.gz"),
)
APT_LISTS = Path("/var/lib/apt/lists")
# Written when the installer finishes; APT history from before then is the installation.
INSTALLER_LOGS = Path("/var/log/installer")
MINTUPDATE_AUTOMATION_SCRIPT = Path("/usr/lib/linuxmint/mintUpdate/automatic_upgrades.py")
MINTUPDATE_UPGRADE_FLAG = Path("/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled")
MINTUPDATE_UPGRADE_TIMER = "mintupdate-automation-upgrade.timer"
REBOOT_REQUIRED = Path("/var/run/reboot-required")
# Simulates a full upgrade: lists what is pending without changing anything.
PENDING_UPGRADES_COMMAND = ["apt-get", "-s", "dist-upgrade"]
PENDING_UPGRADES_TIMEOUT_SECONDS = 60
# Cyber Essentials asks for security updates within 14 days of release.
SECURITY_UPDATES_MAX_AGE_DAYS = 14
LISTS_MAX_AGE_DAYS = 14
REBOOT_PENDING_MAX_DAYS = 7
# History entries from these programs that upgrade packages are full updates:
# Update Manager (aptkit, earlier aptdaemon) and unattended-upgrades.
FULL_UPDATE_PROGRAMS = ("aptkit", "aptdaemon", "unattended-upgrade")
APT_PROGRAMS = ("apt", "apt-get")
APT_UPGRADE_COMMANDS = ("upgrade", "full-upgrade", "dist-upgrade")


def parse_apt_auto_updates(contents: str) -> bool | None:
    r"""Tell whether APT settings turn on automatic updates.

    Args:
        contents: The text of /etc/apt/apt.conf.d/20auto-upgrades.

    Returns:
        True when both Update-Package-Lists and Unattended-Upgrade are "1",
        False when either is "0", or None when either is missing.

    Examples:
        >>> parse_apt_auto_updates('APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";')
        True
        >>> parse_apt_auto_updates('APT::Periodic::Update-Package-Lists "1";') is None
        True
    """
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


def is_full_update(commandline: str | None) -> bool:
    """Tell whether an APT history command line updated the whole system.

    Update Manager (aptkit, earlier aptdaemon), unattended-upgrades and
    `apt`/`apt-get` with upgrade, full-upgrade or dist-upgrade count;
    installing a single program with `apt install` does not.

    Args:
        commandline: The Commandline field of a history entry, or None. An
            entry without one comes from Synaptic, an older Update Manager or
            the installer; the caller decides whether to trust it.

    Returns:
        True for a whole-system update.

    Examples:
        >>> is_full_update("aptkit role='role-install-packages' sender=':1.98'")
        True
        >>> is_full_update("/usr/bin/apt install ./mojitoshield_0.1.3_all.deb")
        False
    """
    words = (commandline or "").split()
    if not words:
        return False
    program = Path(words[0]).name
    if program in FULL_UPDATE_PROGRAMS:
        return True
    return program in APT_PROGRAMS and any(word in APT_UPGRADE_COMMANDS for word in words[1:])


def latest_full_update(history: str, installed: datetime | None) -> datetime | None:
    """Find when the last whole-system update started.

    Args:
        history: The text of an APT history log.
        installed: When the installation finished, or None if unknown.
            Entries without a command line only count after it, because the
            installer also upgrades a few packages and records no command line.

    Returns:
        The start of the newest entry that upgraded packages as a full
        update, or None when there is none.
    """
    latest = None
    for block in re.split(r"\n\s*\n", history):
        fields = dict(line.split(":", 1) for line in block.splitlines() if ":" in line)
        if "Upgrade" not in fields or "Start-Date" not in fields:
            continue
        try:
            started = datetime.strptime(
                " ".join(fields["Start-Date"].split()), "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            continue
        commandline = fields.get("Commandline")
        if commandline is None:
            counts = installed is not None and started > installed
        else:
            counts = is_full_update(commandline)
        if counts and (latest is None or started > latest):
            latest = started
    return latest


def count_pending_security_updates(simulation: str) -> int:
    r"""Count the pending updates that come from a security archive.

    Args:
        simulation: Output of `apt-get -s dist-upgrade`, which lists each
            package it would install on an "Inst" line with its archives.

    Returns:
        The number of packages offered by an archive whose name ends in
        "-security", such as Ubuntu's noble-security or Debian's stable-security.

    Examples:
        >>> count_pending_security_updates(
        ...     "Inst libc6 [2.39-0] (2.39-1 Ubuntu:24.04/noble-security [amd64])\n"
        ...     "Conf libc6 (2.39-1 Ubuntu:24.04/noble-security [amd64])\n"
        ...     "Inst mintupdate [7.0.0] (7.0.1 linuxmint:22.3/zena [all])\n"
        ... )
        1
    """
    return sum(
        1
        for line in simulation.splitlines()
        if line.startswith("Inst ") and re.search(r"/\S*-security\b", line)
    )


def release_fields(text: str) -> dict[str, str]:
    r"""Read the header fields of a Release or InRelease file.

    Args:
        text: The file's text; a signed InRelease file is handled too.

    Returns:
        The single-line fields by name, such as {"Suite": "noble-security"}.

    Examples:
        >>> release_fields("Origin: Ubuntu\nSuite: noble-security\nSHA256:\n abc 1 x\n")
        {'Origin': 'Ubuntu', 'Suite': 'noble-security'}
    """
    if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        # A signed InRelease file: the fields start after the signature header.
        text = text.partition("\n\n")[2]
    fields = {}
    for line in text.splitlines():
        # The header ends at the first blank line or the first multi-line field.
        if not line.strip() or line.startswith(" "):
            break
        name, _, value = line.partition(":")
        # A multi-line field, such as SHA256, has nothing after its colon.
        if value.strip():
            fields[name] = value.strip()
    return fields


def release_date(text: str) -> datetime | None:
    """Read when a package list was published.

    Args:
        text: The text of a Release or InRelease file.

    Returns:
        Its Date field as local time without a time zone, like system.now(),
        or None when the field is missing or not a date.
    """
    try:
        published = parsedate_to_datetime(release_fields(text)["Date"])
    except (KeyError, TypeError, ValueError):
        return None
    # As naive local time, like system.now().
    return datetime.fromtimestamp(published.timestamp())


def read_apt_history() -> list[str]:
    """Return the text of the current and the previous APT history log, where readable."""
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


def _security_lists_date() -> datetime | None:
    """Return when the newest security package list was published.

    The files keep the server's date, not the download time. Security archives
    are republished several times a day, so an old date means an old download.
    """
    newest = None
    try:
        paths = sorted(APT_LISTS.glob("*-security_*Release"))
    except OSError:
        return None
    for path in paths:
        try:
            published = release_date(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if published is not None and (newest is None or published > newest):
            newest = published
    return newest


def installation_finished() -> datetime | None:
    """Return when the installer finished, from the time of its log folder."""
    try:
        return datetime.fromtimestamp(INSTALLER_LOGS.stat().st_mtime)
    except OSError:
        return None


def check() -> Outcome:
    """Check whether security updates are installed in time.

    Returns:
        OK with automatic updates, with no pending security updates, or when a
        full update ran within 14 days; Warning when security updates have
        waited longer, the package lists are old, or a restart has waited more
        than 7 days; Could not determine when the lists cannot be read.
    """
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

    lists_date = _security_lists_date()
    if lists_date is None:
        return Outcome(Status.UNKNOWN, "updates.lists_unavailable", str(APT_LISTS))
    lists_days = system.days_since(lists_date)
    if lists_days > LISTS_MAX_AGE_DAYS:
        return Outcome(
            Status.WARNING,
            "updates.lists_outdated",
            str(APT_LISTS),
            {"days": str(int(lists_days))},
        )

    simulation = system.run_command(
        PENDING_UPGRADES_COMMAND, timeout=PENDING_UPGRADES_TIMEOUT_SECONDS
    )
    if simulation is None or simulation.returncode != 0:
        return Outcome(Status.UNKNOWN, "updates.pending_unavailable")
    pending = count_pending_security_updates(simulation.stdout)
    evidence = " ".join(PENDING_UPGRADES_COMMAND)
    if pending == 0:
        return Outcome(Status.OK, "updates.no_security_updates_pending", evidence)

    installed = installation_finished()
    update_times = [
        moment
        for history in read_apt_history()
        if (moment := latest_full_update(history, installed)) is not None
    ]
    if not update_times:
        return Outcome(
            Status.WARNING,
            "updates.security_updates_pending_no_update",
            evidence,
            {"count": str(pending)},
        )
    days = int(system.days_since(max(update_times)))
    data = {"count": str(pending), "days": str(days)}
    if days <= SECURITY_UPDATES_MAX_AGE_DAYS:
        return Outcome(Status.OK, "updates.security_updates_recent", evidence, data)
    return Outcome(Status.WARNING, "updates.security_updates_pending", evidence, data)

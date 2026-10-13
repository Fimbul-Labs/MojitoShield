"""Check 8, Disk encryption: is the system disk or the home directory encrypted?"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from mojitoshield import system
from mojitoshield.results import Outcome, Status

CHASSIS_TYPE = Path("/sys/class/dmi/id/chassis_type")
# SMBIOS chassis types for portable computers.
PORTABLE_CHASSIS_TYPES = frozenset({8, 9, 10, 11, 14, 30, 31, 32})


@dataclass(frozen=True)
class MountEncryption:
    """Whether a mounted filesystem lies on an encrypted (dm-crypt) device.

    crypt_mapping is None when it could not be determined.
    """

    crypt_mapping: bool | None
    source: str
    filesystem_type: str = ""


def parse_findmnt_pairs(output: str) -> dict[str, str]:
    """Parse one line of `findmnt --pairs` output."""
    return dict(re.findall(r'([A-Z]+)="([^"]*)"', output))


def block_device_from_mount_source(source: str) -> str:
    """Drop the btrfs subvolume suffix, as in /dev/sda2[/@home]."""
    return re.sub(r"\[[^\]]*\]$", "", source)


def mount_encryption(target: str) -> MountEncryption:
    """Return whether the filesystem holding target lies on an encrypted device."""
    mount = system.run_command(
        ["findmnt", "--target", target, "--noheadings", "--pairs", "--output", "SOURCE,FSTYPE"]
    )
    fields = parse_findmnt_pairs(mount.stdout) if mount and mount.returncode == 0 else {}
    source = fields.get("SOURCE", "")
    filesystem_type = fields.get("FSTYPE", "").lower()
    if not source:
        return MountEncryption(None, "")

    device = block_device_from_mount_source(source)
    # lsblk --inverse lists the device and every device below it, such as LVM, crypt and disk.
    block_types = system.run_command(
        ["lsblk", "--inverse", "--noheadings", "--output", "TYPE", device]
    )
    if block_types is None or block_types.returncode != 0:
        return MountEncryption(None, source, filesystem_type)

    types = {line.strip().lower() for line in block_types.stdout.splitlines()}
    return MountEncryption("crypt" in types, source, filesystem_type)


def _is_portable_computer() -> bool:
    try:
        return int(CHASSIS_TYPE.read_text(encoding="ascii").strip()) in PORTABLE_CHASSIS_TYPES
    except (OSError, UnicodeError, ValueError):
        return False


def check() -> Outcome:
    system_disk = mount_encryption("/")
    if system_disk.crypt_mapping:
        return Outcome(Status.OK, "disk_encryption.system_encrypted", system_disk.source)

    # The home path is not used as evidence because it contains the user name.
    home = mount_encryption(str(Path.home()))
    if home.filesystem_type == "ecryptfs":
        return Outcome(Status.OK, "disk_encryption.home_only", "ecryptfs")
    if home.crypt_mapping:
        return Outcome(Status.OK, "disk_encryption.home_only", home.source)

    if system_disk.crypt_mapping is None or home.crypt_mapping is None:
        return Outcome(Status.UNKNOWN, "disk_encryption.status_unknown")
    message_id = (
        "disk_encryption.not_encrypted_portable"
        if _is_portable_computer()
        else "disk_encryption.not_encrypted"
    )
    return Outcome(Status.WARNING, message_id, system_disk.source)

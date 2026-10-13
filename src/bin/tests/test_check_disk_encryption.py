"""Tests for check: Disk encryption (`disk-encryption`), following docs/check-contracts.md."""

import unittest
from pathlib import Path
from unittest.mock import patch

from mojitoshield.checks import disk_encryption
from mojitoshield.results import Status
from support import CheckTestCase, completed


class DiskEncryptionTests(CheckTestCase):
    def setUp(self):
        super().setUp()
        self.path(disk_encryption, "CHASSIS_TYPE", "dmi/chassis_type")
        self.start(patch.object(Path, "home", return_value=Path("/home/someone")))

    def mounts(self, root: tuple[str, str, str], home: tuple[str, str, str] | None = None):
        home = home or root
        responses = {}
        for target, (source, fstype, types) in (("/", root), ("/home/someone", home)):
            responses[("findmnt", "--target", target)] = completed(
                f'SOURCE="{source}" FSTYPE="{fstype}"\n'
            )
            if types is not None:
                device = disk_encryption.block_device_from_mount_source(source)
                responses[("lsblk", "--inverse", "--noheadings", "--output", "TYPE", device)] = (
                    completed(types)
                )
        self.commands(responses)

    def test_system_encrypted(self):
        self.mounts(("/dev/mapper/vgmint-root", "ext4", "lvm\ncrypt\npart\ndisk\n"))
        self.assertOutcome(disk_encryption.check, Status.OK, "disk_encryption.system_encrypted")

    def test_btrfs_subvolume_source_is_resolved_to_its_device(self):
        self.mounts(("/dev/mapper/luks-abc[/@]", "btrfs", "crypt\npart\ndisk\n"))
        self.assertOutcome(disk_encryption.check, Status.OK, "disk_encryption.system_encrypted")

    def test_only_home_encrypted(self):
        self.mounts(
            ("/dev/sda2", "ext4", "part\ndisk\n"), ("/dev/mapper/home", "ext4", "crypt\npart\n")
        )
        self.assertOutcome(disk_encryption.check, Status.OK, "disk_encryption.home_only")

    def test_ecryptfs_home_does_not_reveal_the_home_path(self):
        self.mounts(
            ("/dev/sda2", "ext4", "part\ndisk\n"),
            ("/home/.ecryptfs/someone/.Private", "ecryptfs", None),
        )
        outcome = self.assertOutcome(disk_encryption.check, Status.OK, "disk_encryption.home_only")
        self.assertNotIn("someone", outcome.evidence)

    def test_one_warning_for_an_unencrypted_desktop_computer(self):
        self.write("dmi/chassis_type", "3\n")
        self.mounts(("/dev/sda2", "ext4", "part\ndisk\n"))
        self.assertOutcome(disk_encryption.check, Status.WARNING, "disk_encryption.not_encrypted")

    def test_stronger_text_for_an_unencrypted_laptop(self):
        self.write("dmi/chassis_type", "10\n")
        self.mounts(("/dev/nvme0n1p2", "ext4", "part\ndisk\n"))
        self.assertOutcome(
            disk_encryption.check, Status.WARNING, "disk_encryption.not_encrypted_portable"
        )

    def test_unreadable_devices(self):
        self.commands({})
        self.assertOutcome(disk_encryption.check, Status.UNKNOWN, "disk_encryption.status_unknown")


if __name__ == "__main__":
    unittest.main()

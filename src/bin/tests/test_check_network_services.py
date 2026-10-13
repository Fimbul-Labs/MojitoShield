"""Tests for check: Network services (`network-services`), following docs/check-contracts.md."""

import json
import unittest
from unittest.mock import patch

from mojitoshield.checks import network_services
from mojitoshield.results import Status
from support import CheckTestCase, completed


class NetworkServicesTests(CheckTestCase):
    HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

    def setUp(self):
        super().setUp()
        self.start(
            patch.object(
                network_services,
                "PROC_NET_TCP",
                (
                    (self.root / "net/tcp", False),
                    (self.root / "net/tcp6", True),
                ),
            )
        )
        self.path(network_services, "SSH_CONFIG", "ssh/sshd_config")
        self.path(network_services, "SYS_CLASS_NET", "sys/net")
        self.commands({("ip", "-json"): completed("[]")})

    def listen(self, *sockets: str, ipv6: str = ""):
        rows = [
            f"   0: {socket} 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 1 1\n"
            for socket in sockets
        ]
        self.write("net/tcp", self.HEADER + "".join(rows))
        if ipv6:
            self.write(
                "net/tcp6",
                self.HEADER
                + f"   0: {ipv6} 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0\n",
            )

    def test_only_loopback_services(self):
        # 127.0.0.1:631 (CUPS), 127.0.0.53:53 (resolver), [::1]:631
        self.listen("0100007F:0277", "3500007F:0035", ipv6="00000000000000000000000001000000:0277")
        self.assertOutcome(network_services.check, Status.OK, "network_services.none")

    def test_remote_desktop(self):
        self.listen("00000000:0D3D")  # 0.0.0.0:3389
        outcome = self.assertOutcome(
            network_services.check, Status.WARNING, "network_services.remote_desktop"
        )
        self.assertEqual(outcome.data, {"ports": "3389"})

    def test_ssh_with_password_login(self):
        self.listen("00000000:0016")
        self.write(
            "ssh/sshd_config",
            "Include "
            + str(self.root / "ssh/sshd_config.d/*.conf")
            + "\nKbdInteractiveAuthentication no\n",
        )
        self.assertOutcome(
            network_services.check, Status.WARNING, "network_services.ssh_password_login"
        )

    def test_ssh_with_key_login_only_from_a_drop_in(self):
        self.listen("00000000:0016")
        self.write("ssh/sshd_config.d/10-keys.conf", "PasswordAuthentication no\n")
        self.write(
            "ssh/sshd_config",
            "Include "
            + str(self.root / "ssh/sshd_config.d/*.conf")
            + "\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\n",
        )
        self.assertOutcome(network_services.check, Status.OK, "network_services.ssh_key_only")

    def test_ssh_root_login(self):
        self.listen("00000000:0016")
        self.write(
            "ssh/sshd_config",
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\n",
        )
        self.assertOutcome(
            network_services.check, Status.WARNING, "network_services.ssh_password_login"
        )

    def test_match_blocks_do_not_change_global_settings(self):
        self.assertFalse(
            network_services.ssh_allows_password_or_root_login(
                [
                    "PasswordAuthentication no",
                    "KbdInteractiveAuthentication=no",
                    "Match User guest",
                    "PasswordAuthentication yes",
                ]
            )
        )

    def test_other_ports_cannot_be_judged(self):
        self.listen("00000000:01BD")  # 0.0.0.0:445
        outcome = self.assertOutcome(
            network_services.check, Status.UNKNOWN, "network_services.other_ports"
        )
        self.assertEqual(outcome.data, {"ports": "445"})

    def test_services_on_internal_virtual_bridges_are_ignored(self):
        self.listen("017AA8C0:0035")  # 192.168.122.1:53 on virbr0
        (self.root / "sys/net/virbr0/bridge").mkdir(parents=True)
        (self.root / "sys/net/virbr0/brif/vnet0").mkdir(parents=True)
        (self.root / "sys/net/vnet0").mkdir(parents=True)
        self.commands(
            {
                ("ip", "-json"): completed(
                    json.dumps(
                        [
                            {"ifname": "virbr0", "addr_info": [{"local": "192.168.122.1"}]},
                        ]
                    )
                )
            }
        )
        self.assertOutcome(network_services.check, Status.OK, "network_services.none")

    def test_bridge_with_a_real_network_card_still_counts(self):
        self.listen("017AA8C0:0035")
        (self.root / "sys/net/br0/bridge").mkdir(parents=True)
        (self.root / "sys/net/br0/brif/enp2s0").mkdir(parents=True)
        (self.root / "sys/net/enp2s0/device").mkdir(parents=True)
        self.commands(
            {
                ("ip", "-json"): completed(
                    json.dumps(
                        [
                            {"ifname": "br0", "addr_info": [{"local": "192.168.122.1"}]},
                        ]
                    )
                )
            }
        )
        self.assertOutcome(network_services.check, Status.UNKNOWN, "network_services.other_ports")

    def test_unreadable_connection_list(self):
        self.assertOutcome(
            network_services.check, Status.UNKNOWN, "network_services.status_unreadable"
        )


if __name__ == "__main__":
    unittest.main()

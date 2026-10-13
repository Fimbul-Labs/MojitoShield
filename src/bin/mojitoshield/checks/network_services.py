"""Check 6, Network services: do programs accept connections from other computers?"""

from __future__ import annotations

import glob
import ipaddress
import json
import re
from collections.abc import Iterable
from pathlib import Path

from mojitoshield import system
from mojitoshield.results import Outcome, Status

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

PROC_NET_TCP = ((Path("/proc/net/tcp"), False), (Path("/proc/net/tcp6"), True))
TCP_LISTEN_STATE = "0A"
SSH_PORT = 22
REMOTE_DESKTOP_PORTS = frozenset({23, 3389, *range(5900, 6000)})
SSH_CONFIG = Path("/etc/ssh/sshd_config")
SSH_INCLUDE_MAX_DEPTH = 3
SYS_CLASS_NET = Path("/sys/class/net")


def _proc_net_address(hex_address: str, ipv6: bool) -> IPAddress:
    raw = bytes.fromhex(hex_address)
    # The kernel prints each 32-bit word in host (little-endian) byte order.
    words = b"".join(raw[index : index + 4][::-1] for index in range(0, len(raw), 4))
    return ipaddress.IPv6Address(words) if ipv6 else ipaddress.IPv4Address(words)


def listening_sockets(proc_net_text: str, ipv6: bool) -> set[tuple[IPAddress, int]]:
    r"""Find the TCP sockets that wait for connections, from /proc/net/tcp or tcp6.

    Sockets on loopback addresses only accept connections from the computer
    itself, so they are left out.

    Args:
        proc_net_text: The text of /proc/net/tcp or /proc/net/tcp6.
        ipv6: Whether the text is from tcp6.

    Returns:
        (address, port) pairs of listening sockets on other addresses.

    Examples:
        >>> header = "sl local_address rem_address st\n"
        >>> listening_sockets(header + "0: 00000000:0016 00000000:0000 0A\n", ipv6=False)
        {(IPv4Address('0.0.0.0'), 22)}
        >>> listening_sockets(header + "0: 0100007F:0277 00000000:0000 0A\n", ipv6=False)
        set()
    """
    sockets = set()
    for line in proc_net_text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] != TCP_LISTEN_STATE:
            continue
        hex_address, _, hex_port = fields[1].partition(":")
        try:
            address = _proc_net_address(hex_address, ipv6)
            port = int(hex_port, 16)
        except ValueError:
            continue
        mapped = getattr(address, "ipv4_mapped", None)
        if address.is_loopback or (mapped is not None and mapped.is_loopback):
            continue
        sockets.add((address, port))
    return sockets


def _is_internal_bridge(name: str) -> bool:
    """Return whether an interface is a bridge whose ports are all virtual, like virbr0."""
    if not re.fullmatch(r"[\w.@-]{1,32}", name):
        return False
    bridge = SYS_CLASS_NET / name
    if not (bridge / "bridge").is_dir():
        return False
    try:
        ports = list((bridge / "brif").iterdir())
    except OSError:
        return False
    # A port with a device link is a real network card, reachable from other computers.
    return not any((SYS_CLASS_NET / port.name / "device").exists() for port in ports)


def parse_interface_addresses(ip_json: str) -> dict[str, set[IPAddress]]:
    """Group the addresses from `ip -json address show` by network interface.

    Args:
        ip_json: The command's JSON output.

    Returns:
        Addresses by interface name, such as {"virbr0": {192.168.122.1}};
        empty when the output is not the expected JSON.
    """
    try:
        interfaces = json.loads(ip_json)
    except json.JSONDecodeError:
        return {}
    addresses: dict[str, set[IPAddress]] = {}
    for interface in interfaces if isinstance(interfaces, list) else ():
        name = interface.get("ifname") if isinstance(interface, dict) else None
        if not isinstance(name, str):
            continue
        for info in interface.get("addr_info", ()):
            try:
                addresses.setdefault(name, set()).add(ipaddress.ip_address(info.get("local", "")))
            except (AttributeError, ValueError):
                continue
    return addresses


def _internal_bridge_addresses() -> set[IPAddress]:
    command = system.run_command(["ip", "-json", "address", "show"])
    if command is None or command.returncode != 0:
        return set()
    return {
        address
        for name, addresses in parse_interface_addresses(command.stdout).items()
        if _is_internal_bridge(name)
        for address in addresses
    }


def _ssh_config_lines(path: Path, depth: int = 0) -> list[str]:
    """Return the lines of an sshd config file, with Include files read in their place."""
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        include = re.match(r"(?i)^include\s+(.+)$", stripped)
        if include is None:
            lines.append(stripped)
            continue
        if depth >= SSH_INCLUDE_MAX_DEPTH:
            continue
        for pattern in include.group(1).split():
            # Relative Include paths are relative to /etc/ssh, as in sshd.
            absolute = pattern if pattern.startswith("/") else str(SSH_CONFIG.parent / pattern)
            for included in sorted(glob.glob(absolute)):
                lines.extend(_ssh_config_lines(Path(included), depth + 1))
    return lines


def ssh_allows_password_or_root_login(lines: Iterable[str]) -> bool:
    """Tell whether an SSH server allows password or root login.

    Follows sshd: the first value of an option wins, and settings after the
    first Match block only apply to some connections, so they are ignored.

    Args:
        lines: The lines of sshd_config, with Include files already read in.

    Returns:
        True when password, keyboard-interactive or root login is allowed,
        including when the defaults allow it.

    Examples:
        >>> ssh_allows_password_or_root_login(["PasswordAuthentication no", "KbdInteractiveAuthentication no"])
        False
        >>> ssh_allows_password_or_root_login(["PermitRootLogin no"])
        True
    """
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[\s=]+", line, maxsplit=1)
        key = parts[0].lower()
        if key == "match":
            break
        if len(parts) == 2 and key not in values:
            values[key] = parts[1].strip().lower()

    password = values.get("passwordauthentication", "yes") == "yes"
    keyboard_interactive = values.get("kbdinteractiveauthentication", "yes") == "yes"
    root = values.get("permitrootlogin", "prohibit-password") == "yes"
    return password or keyboard_interactive or root


def _listening_ports() -> set[int] | None:
    """Return the ports reachable from other computers, or None if they cannot be read."""
    sockets: set[tuple[IPAddress, int]] = set()
    readable = False
    for path, ipv6 in PROC_NET_TCP:
        try:
            sockets |= listening_sockets(path.read_text(encoding="ascii"), ipv6)
            readable = True
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError):
            return None
    if not readable:
        return None

    # Services only on internal bridges are reachable from local virtual machines,
    # not from other computers.
    internal = _internal_bridge_addresses() if sockets else set()
    return {port for address, port in sockets if address not in internal}


def _port_list(ports: Iterable[int]) -> str:
    return ", ".join(str(port) for port in sorted(ports))


def check() -> Outcome:
    """Check whether programs accept connections from other computers.

    Returns:
        OK when nothing listens, or only SSH with key login; Warning for remote
        desktop, VNC, Telnet or SSH with password login; Could not determine
        for other ports, which are often deliberate.
    """
    ports = _listening_ports()
    if ports is None:
        return Outcome(Status.UNKNOWN, "network_services.status_unreadable")
    if not ports:
        return Outcome(Status.OK, "network_services.none")

    evidence = "TCP " + _port_list(ports)
    remote_desktop = ports & REMOTE_DESKTOP_PORTS
    if remote_desktop:
        return Outcome(
            Status.WARNING,
            "network_services.remote_desktop",
            evidence,
            {"ports": _port_list(remote_desktop)},
        )

    if SSH_PORT in ports:
        try:
            risky = ssh_allows_password_or_root_login(_ssh_config_lines(SSH_CONFIG))
        except (OSError, UnicodeError):
            return Outcome(Status.UNKNOWN, "network_services.ssh_settings_unreadable", evidence)
        if risky:
            return Outcome(Status.WARNING, "network_services.ssh_password_login", evidence)

    other_ports = sorted(ports - {SSH_PORT})
    if other_ports:
        return Outcome(
            Status.UNKNOWN,
            "network_services.other_ports",
            evidence,
            {"ports": _port_list(other_ports[:20])},
        )
    return Outcome(Status.OK, "network_services.ssh_key_only", evidence)

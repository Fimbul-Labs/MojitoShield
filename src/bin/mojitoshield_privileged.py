#!/usr/bin/python3 -I
"""Fixed read-only checks launched by pkexec after system authorization.

Installed as /usr/libexec/mojitoshield/privileged-check and run as root. It
accepts only known check IDs as arguments, prints one JSON answer and never
prints file contents or error details.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

UFW_EXECUTABLE = Path("/usr/sbin/ufw")
UFW_TIMEOUT_SECONDS = 5
GRUB_CONFIGS = (Path("/boot/grub/grub.cfg"), Path("/boot/grub/custom.cfg"))
MAX_EVIDENCE_LENGTH = 120
# Below the app's limit (privileged.MAX_HELPER_OUTPUT_BYTES), so a valid answer always fits.
MAX_OUTPUT_BYTES = 12_000


def _result(check_id: str, status: str, message_id: str, evidence: str = "") -> dict[str, object]:
    """Build one result in the form the app expects, with shortened evidence."""
    result: dict[str, object] = {"check_id": check_id, "status": status, "message_id": message_id}
    if evidence:
        result["evidence"] = evidence[:MAX_EVIDENCE_LENGTH]
    return result


def _firewall() -> dict[str, object]:
    """Ask UFW itself whether the firewall is active."""
    if not UFW_EXECUTABLE.is_file():
        return _result("firewall", "unknown", "firewall.command_unavailable")

    try:
        command = subprocess.run(
            [str(UFW_EXECUTABLE), "status"],
            check=False,
            capture_output=True,
            text=True,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "LANGUAGE": "C",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            },
            timeout=UFW_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return _result("firewall", "unknown", "firewall.status_unavailable")

    status_line = next(
        (
            line.strip().lower()
            for line in command.stdout.splitlines()
            if line.strip().lower().startswith("status:")
        ),
        "",
    )
    if command.returncode == 0 and status_line == "status: active":
        return _result("firewall", "ok", "firewall.active", status_line)
    if command.returncode == 0 and status_line == "status: inactive":
        return _result("firewall", "warning", "firewall.inactive", status_line)
    return _result("firewall", "unknown", "firewall.unrecognized_status", status_line)


def _grub_password_configured(text: str) -> bool:
    """Tell whether GRUB settings set both a superuser and a password."""
    # Same rule as mojitoshield.checks.boot_menu.grub_password_configured;
    # the helper deliberately imports nothing from the app.
    lines = [line.strip() for line in text.splitlines() if not line.lstrip().startswith("#")]
    superusers = any(
        re.match(r"""^set\s+superusers\s*=\s*["']?[^"'\s]+""", line) for line in lines
    )
    password = any(re.match(r"^password(_pbkdf2)?\s+\S+\s+\S+", line) for line in lines)
    return superusers and password


def _boot_menu() -> dict[str, object]:
    """Read the generated boot menu to see whether its password is active."""
    texts = []
    for path in GRUB_CONFIGS:
        try:
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
        except FileNotFoundError:
            continue
        except OSError:
            return _result("boot-menu", "unknown", "boot_menu.config_unreadable")

    if not texts:
        return _result("boot-menu", "unknown", "boot_menu.grub_not_used")
    # Only the conclusion leaves the helper, never lines from the boot configuration.
    if _grub_password_configured("\n".join(texts)):
        return _result("boot-menu", "ok", "boot_menu.password_active")
    return _result("boot-menu", "warning", "boot_menu.password_not_active")


CHECKS: dict[str, Callable[[], dict[str, object]]] = {
    "firewall": _firewall,
    "boot-menu": _boot_menu,
}


def main(arguments: list[str]) -> int:
    """Run the requested checks and print their results as JSON.

    Args:
        arguments: Check IDs from the command line, such as ["firewall"].

    Returns:
        The exit code: 0 on success, 1 if a check failed, and 2 if the helper
        is not running as root or an argument is not a known check ID.
    """
    if os.geteuid() != 0 or not arguments or len(set(arguments)) != len(arguments):
        return 2
    if any(check_id not in CHECKS for check_id in arguments):
        return 2

    try:
        results = [CHECKS[check_id]() for check_id in arguments]
        output = json.dumps({"version": 1, "results": results}, ensure_ascii=False)
    except Exception:  # noqa: BLE001
        # Running as root, the helper reports only "failed", never error details.
        return 1

    if len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
        return 1
    sys.stdout.write(output + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

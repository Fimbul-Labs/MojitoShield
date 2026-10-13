#!/usr/bin/python3 -I
"""Fixed read-only checks launched by pkexec after system authorization."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

UFW_EXECUTABLE = Path("/usr/sbin/ufw")
GRUB_CONFIGS = (Path("/boot/grub/grub.cfg"), Path("/boot/grub/custom.cfg"))


def _firewall() -> dict[str, object]:
    if not UFW_EXECUTABLE.is_file():
        return {
            "check_id": "firewall",
            "status": "unknown",
            "message_id": "firewall.command_unavailable",
        }

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
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return {
            "check_id": "firewall",
            "status": "unknown",
            "message_id": "firewall.status_unavailable",
        }

    status_line = next(
        (
            line.strip().lower()
            for line in command.stdout.splitlines()
            if line.strip().lower().startswith("status:")
        ),
        "",
    )
    if command.returncode == 0 and status_line == "status: active":
        status = "ok"
        message_id = "firewall.active"
    elif command.returncode == 0 and status_line == "status: inactive":
        status = "warning"
        message_id = "firewall.inactive"
    else:
        status = "unknown"
        message_id = "firewall.unrecognized_status"

    return {
        "check_id": "firewall",
        "status": status,
        "message_id": message_id,
        "evidence": status_line[:120],
    }


def _grub_password_configured(text: str) -> bool:
    # Same rule as mojitoshield.checks.boot_menu.grub_password_configured; the helper imports nothing from the app.
    lines = [line.strip() for line in text.splitlines() if not line.lstrip().startswith("#")]
    superusers = any(
        re.match(r"""^set\s+superusers\s*=\s*["']?[^"'\s]+""", line) for line in lines
    )
    password = any(re.match(r"^password(_pbkdf2)?\s+\S+\s+\S+", line) for line in lines)
    return superusers and password


def _boot_menu() -> dict[str, object]:
    texts = []
    for path in GRUB_CONFIGS:
        try:
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
        except FileNotFoundError:
            continue
        except OSError:
            return {
                "check_id": "boot-menu",
                "status": "unknown",
                "message_id": "boot_menu.config_unreadable",
            }

    if not texts:
        return {
            "check_id": "boot-menu",
            "status": "unknown",
            "message_id": "boot_menu.grub_not_used",
        }
    # Only the conclusion leaves the helper, never lines from the boot configuration.
    if _grub_password_configured("\n".join(texts)):
        return {"check_id": "boot-menu", "status": "ok", "message_id": "boot_menu.password_active"}
    return {
        "check_id": "boot-menu",
        "status": "warning",
        "message_id": "boot_menu.password_not_active",
    }


CHECKS: dict[str, Callable[[], dict[str, object]]] = {
    "firewall": _firewall,
    "boot-menu": _boot_menu,
}


def main(arguments: list[str]) -> int:
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

    if len(output.encode("utf-8")) > 12_000:
        return 1
    sys.stdout.write(output + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

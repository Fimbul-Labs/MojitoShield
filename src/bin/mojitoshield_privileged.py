#!/usr/bin/python3 -I
"""Fixed read-only checks launched by pkexec after system authorization."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable


UFW_EXECUTABLE = Path("/usr/sbin/ufw")


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


CHECKS: dict[str, Callable[[], dict[str, object]]] = {
    "firewall": _firewall,
}


def main(arguments: list[str]) -> int:
    if os.geteuid() != 0 or not arguments or len(set(arguments)) != len(arguments):
        return 2
    if any(check_id not in CHECKS for check_id in arguments):
        return 2

    try:
        results = [CHECKS[check_id]() for check_id in arguments]
        output = json.dumps({"version": 1, "results": results}, ensure_ascii=False)
    except Exception:
        return 1

    if len(output.encode("utf-8")) > 12_000:
        return 1
    sys.stdout.write(output + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
#!/usr/bin/python3
"""Fixed read-only checks launched by pkexec after system authorization."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable


SNAPSHOT_DIRECTORY = Path("/timeshift/snapshots")
SELINUX_ENFORCE = Path("/sys/fs/selinux/enforce")
APPARMOR_ENABLED = Path("/sys/module/apparmor/parameters/enabled")
APPARMOR_PROFILES = Path("/sys/kernel/security/apparmor/profiles")
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


def _timeshift() -> dict[str, object]:
    try:
        snapshot_count = sum(path.is_dir() for path in SNAPSHOT_DIRECTORY.iterdir())
    except FileNotFoundError:
        return {
            "check_id": "timeshift",
            "status": "unknown",
            "message_id": "timeshift.path_unreadable",
            "evidence": str(SNAPSHOT_DIRECTORY),
        }
    except OSError:
        return {
            "check_id": "timeshift",
            "status": "unknown",
            "message_id": "timeshift.path_unreadable",
            "evidence": str(SNAPSHOT_DIRECTORY),
        }

    return {
        "check_id": "timeshift",
        "status": "unknown",
        "message_id": (
            "timeshift.snapshots_found" if snapshot_count else "timeshift.no_snapshots_at_default_path"
        ),
        "evidence": str(SNAPSHOT_DIRECTORY),
        "data": {"count": snapshot_count},
    }


def _access_control() -> dict[str, object]:
    try:
        selinux_state = SELINUX_ENFORCE.read_text(encoding="ascii").strip()
        if selinux_state == "1":
            return {
                "check_id": "access-control",
                "status": "ok",
                "message_id": "access_control.selinux_enforcing",
                "evidence": str(SELINUX_ENFORCE),
            }
        if selinux_state == "0":
            return {
                "check_id": "access-control",
                "status": "warning",
                "message_id": "access_control.selinux_permissive",
                "evidence": str(SELINUX_ENFORCE),
            }
    except OSError:
        pass

    try:
        enabled = APPARMOR_ENABLED.read_text(encoding="ascii").strip().upper()
        profiles = APPARMOR_PROFILES.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return {
            "check_id": "access-control",
            "status": "unknown",
            "message_id": "access_control.status_unreadable",
        }

    enforced_count = sum("(enforce)" in line for line in profiles.splitlines())
    if enabled == "Y" and enforced_count:
        status = "ok"
        message_id = "access_control.apparmor_enforcing"
    elif enabled == "N":
        status = "warning"
        message_id = "access_control.apparmor_disabled"
    else:
        status = "unknown"
        message_id = "access_control.apparmor_unconfirmed"

    return {
        "check_id": "access-control",
        "status": status,
        "message_id": message_id,
        "evidence": str(APPARMOR_PROFILES),
        "data": {"count": enforced_count},
    }


CHECKS: dict[str, Callable[[], dict[str, object]]] = {
    "firewall": _firewall,
    "timeshift": _timeshift,
    "access-control": _access_control,
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
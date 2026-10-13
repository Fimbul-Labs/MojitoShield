"""The Extended scan: run fixed checks through the packaged PolicyKit helper.

The helper (mojitoshield_privileged.py, installed as PRIVILEGED_HELPER_PATH)
runs as root after the system's password dialog. This module only starts it
with allowlisted check IDs, and accepts only a small, validated JSON answer.
"""

from __future__ import annotations

import json
import re
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path

from mojitoshield.results import CheckResult, Outcome, Status
from mojitoshield.scan import CHECKS

PRIVILEGED_CHECK_IDS = frozenset({"firewall", "boot-menu"})
PRIVILEGED_HELPER_PATH = Path("/usr/libexec/mojitoshield/privileged-check")
PRIVILEGED_POLICY_PATH = Path(
    "/usr/share/polkit-1/actions/org.mojitoshield.privileged-check.policy"
)
PKEXEC_PATH = Path("/usr/bin/pkexec")
PKEXEC_DISMISSED_EXIT_CODE = 126
HELPER_TIMEOUT_SECONDS = 30
MAX_HELPER_OUTPUT_BYTES = 16_384
MAX_EVIDENCE_LENGTH = 300
MAX_DATA_VALUE_LENGTH = 100
HELPER_STATUSES = {"ok": Status.OK, "warning": Status.WARNING, "unknown": Status.UNKNOWN}


class PrivilegedScanError(Exception):
    """Base exception for the optional privileged scan."""


class PrivilegedHelperUnavailable(PrivilegedScanError):
    """Raised when the trusted packaged helper cannot be used."""


class PrivilegedScanCancelled(PrivilegedScanError):
    """Raised when the user cancels the system authorization dialog."""


class PrivilegedScanFailed(PrivilegedScanError):
    """Raised when the helper fails or returns an invalid response."""


def is_trusted_system_path(path: Path, *, executable: bool) -> bool:
    """Return whether only root can have changed this file or any folder above it."""
    try:
        resolved = path.resolve(strict=True)
        file_info = resolved.stat()
    except OSError:
        return False

    if (
        not stat.S_ISREG(file_info.st_mode)
        or file_info.st_uid != 0
        or file_info.st_mode & 0o022
        or (executable and not file_info.st_mode & 0o111)
    ):
        return False

    parent = resolved.parent
    while parent != parent.parent:
        try:
            directory_info = parent.stat()
        except OSError:
            return False
        if directory_info.st_uid != 0 or directory_info.st_mode & 0o022:
            return False
        parent = parent.parent

    return True


def privileged_helper_available() -> bool:
    return (
        is_trusted_system_path(PKEXEC_PATH, executable=True)
        and is_trusted_system_path(PRIVILEGED_HELPER_PATH, executable=True)
        and is_trusted_system_path(PRIVILEGED_POLICY_PATH, executable=False)
    )


def _valid_helper_entry(entry: dict) -> bool:
    message_id = entry.get("message_id")
    evidence = entry.get("evidence", "")
    data = entry.get("data", {})
    return (
        entry.get("status") in HELPER_STATUSES
        and isinstance(message_id, str)
        and re.fullmatch(r"[a-z0-9_.]+", message_id) is not None
        and isinstance(evidence, str)
        and len(evidence) <= MAX_EVIDENCE_LENGTH
        and isinstance(data, dict)
        and all(
            isinstance(key, str)
            and isinstance(value, (str, int))
            and len(str(value)) <= MAX_DATA_VALUE_LENGTH
            for key, value in data.items()
        )
    )


def parse_helper_output(requested_ids: tuple[str, ...], output: str) -> tuple[CheckResult, ...]:
    """Turn the helper's JSON answer into results, or raise PrivilegedScanFailed."""
    if len(output.encode("utf-8")) > MAX_HELPER_OUTPUT_BYTES:
        raise PrivilegedScanFailed("helper_response_too_large")

    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise PrivilegedScanFailed("helper_response_invalid_json") from error

    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise PrivilegedScanFailed("helper_response_unknown_version")

    entries = payload.get("results")
    if not isinstance(entries, list) or len(entries) != len(requested_ids):
        raise PrivilegedScanFailed("helper_response_missing_results")

    definitions = {definition.check_id: definition for definition in CHECKS}
    results: dict[str, CheckResult] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise PrivilegedScanFailed("helper_response_invalid_result")

        check_id = entry.get("check_id")
        if check_id not in requested_ids or check_id in results:
            raise PrivilegedScanFailed("helper_response_unexpected_check")
        if not _valid_helper_entry(entry):
            raise PrivilegedScanFailed("helper_response_invalid_fields")

        outcome = Outcome(
            HELPER_STATUSES[entry["status"]],
            entry["message_id"],
            entry.get("evidence", ""),
            {key: str(value) for key, value in entry.get("data", {}).items()},
        )
        results[check_id] = definitions[check_id].result(outcome)

    if set(results) != set(requested_ids):
        raise PrivilegedScanFailed("helper_response_missing_check")

    return tuple(results[check_id] for check_id in requested_ids)


def run_privileged_checks(check_ids: Sequence[str]) -> tuple[CheckResult, ...]:
    """Run only fixed, allowlisted checks through the packaged PolicyKit helper."""
    requested_ids = tuple(check_ids)
    if (
        not requested_ids
        or len(set(requested_ids)) != len(requested_ids)
        or not set(requested_ids).issubset(PRIVILEGED_CHECK_IDS)
    ):
        raise ValueError("privileged_check_not_allowlisted")
    if not privileged_helper_available():
        raise PrivilegedHelperUnavailable("privileged_helper_not_trusted_or_missing")

    try:
        process = subprocess.run(
            [str(PKEXEC_PATH), str(PRIVILEGED_HELPER_PATH), *requested_ids],
            check=False,
            capture_output=True,
            text=True,
            timeout=HELPER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise PrivilegedScanFailed("privileged_scan_timeout") from error
    except OSError as error:
        raise PrivilegedScanFailed("privileged_scan_could_not_start") from error

    if process.returncode == PKEXEC_DISMISSED_EXIT_CODE:
        raise PrivilegedScanCancelled("privileged_scan_cancelled")
    if process.returncode != 0:
        raise PrivilegedScanFailed("privileged_scan_failed")

    return parse_helper_output(requested_ids, process.stdout)

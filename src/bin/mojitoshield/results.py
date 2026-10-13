"""The results that checks report, in language-independent codes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    OK = "ok"
    WARNING = "warning"
    UNKNOWN = "unknown"
    AUTH_REQUIRED = "auth_required"


@dataclass(frozen=True)
class Outcome:
    """What one check found.

    The message ID selects the text shown to the user, and data fills in that
    text's placeholders. Evidence names the source the conclusion is based on.
    """

    status: Status
    message_id: str
    evidence: str = ""
    data: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CheckResult:
    """The outcome of one check, labelled with the check it belongs to."""

    check_id: str
    level: int
    outcome: Outcome

"""Check 9, Boot menu protection: can someone change the boot options without a password?

Disk encryption or an active GRUB password protects the boot menu.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from mojitoshield.checks.disk_encryption import mount_encryption
from mojitoshield.results import Outcome, Status

GRUB_CONFIG = Path("/boot/grub/grub.cfg")
GRUB_CUSTOM_CONFIG = Path("/boot/grub/custom.cfg")
GRUB_SCRIPTS = Path("/etc/grub.d")


def grub_password_configured(text: str) -> bool:
    r"""Tell whether GRUB settings set both a superuser and a password.

    Comment lines are ignored. The root helper has its own copy of this rule,
    because it imports nothing from the app.

    Args:
        text: GRUB configuration or the text of /etc/grub.d scripts.

    Returns:
        True only when both `set superusers=` and a `password` or
        `password_pbkdf2` line are present.

    Examples:
        >>> grub_password_configured('set superusers="admin"\npassword_pbkdf2 admin grub.pbkdf2.x')
        True
        >>> grub_password_configured('# set superusers="admin"\npassword admin secret')
        False
    """
    lines = [line.strip() for line in text.splitlines() if not line.lstrip().startswith("#")]
    superusers = any(
        re.match(r"""^set\s+superusers\s*=\s*["']?[^"'\s]+""", line) for line in lines
    )
    password = any(re.match(r"^password(_pbkdf2)?\s+\S+\s+\S+", line) for line in lines)
    return superusers and password


@dataclass(frozen=True)
class GrubScriptsPassword:
    """Whether the scripts in /etc/grub.d set a password.

    Attributes:
        configured: Whether the executable scripts together set one.
        changed: Modification time of the newest script that mentions a
            password, as a Unix timestamp; 0.0 when none does.
    """

    configured: bool
    changed: float


def _grub_scripts_password() -> GrubScriptsPassword:
    # update-grub only runs executable scripts.
    scripts = {
        path: path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(GRUB_SCRIPTS.iterdir())
        if path.is_file() and path.stat().st_mode & 0o111
    }
    changed = max(
        (
            path.stat().st_mtime
            for path, text in scripts.items()
            if "superusers" in text or "password" in text
        ),
        default=0.0,
    )
    return GrubScriptsPassword(grub_password_configured("\n".join(scripts.values())), changed)


def check() -> Outcome:
    """Check whether someone at the computer can change the boot options without a password.

    Returns:
        OK when the disk is encrypted or a GRUB password is active, Warning
        when neither protects the boot menu, Requires extended permission when
        a new password may not be active yet, and Could not determine when GRUB
        is not used or its files cannot be read.
    """
    system_disk = mount_encryption("/")
    if system_disk.crypt_mapping:
        return Outcome(Status.OK, "boot_menu.protected_by_encryption", system_disk.source)

    try:
        generated = GRUB_CONFIG.stat().st_mtime
    except FileNotFoundError:
        return Outcome(Status.UNKNOWN, "boot_menu.grub_not_used")
    except OSError:
        return Outcome(Status.UNKNOWN, "boot_menu.config_unreadable")

    # GRUB reads custom.cfg directly at boot, so a password there is active at once.
    try:
        if grub_password_configured(GRUB_CUSTOM_CONFIG.read_text(encoding="utf-8")):
            return Outcome(Status.OK, "boot_menu.password_active", str(GRUB_CUSTOM_CONFIG))
    except FileNotFoundError:
        pass
    except (OSError, UnicodeError):
        return Outcome(Status.AUTH_REQUIRED, "boot_menu.authorization_required")

    try:
        scripts = _grub_scripts_password()
    except OSError:
        return Outcome(Status.UNKNOWN, "boot_menu.config_unreadable")

    if scripts.configured:
        # A password in /etc/grub.d is only active once update-grub has regenerated grub.cfg.
        if scripts.changed <= generated:
            return Outcome(Status.OK, "boot_menu.password_active", str(GRUB_SCRIPTS))
        return Outcome(Status.AUTH_REQUIRED, "boot_menu.password_not_confirmed", str(GRUB_SCRIPTS))
    if system_disk.crypt_mapping is None:
        return Outcome(Status.UNKNOWN, "boot_menu.status_unknown")
    return Outcome(Status.WARNING, "boot_menu.no_password", str(GRUB_SCRIPTS))

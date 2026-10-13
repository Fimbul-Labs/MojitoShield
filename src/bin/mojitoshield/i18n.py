"""Presentation text catalog; diagnostic results use stable language-free IDs.

The interface is English only for now. Keeping texts here, keyed by message ID,
leaves room to add translated catalogs later without touching the checks.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Plural:
    """Text that depends on a number: `one` when the value named `count` is 1, else `other`."""

    count: str
    one: str
    other: str


ENGLISH: dict[str, str | Plural] = {
    "app.title": "MojitoShield",
    "app.unknown_distribution": "an unknown distribution",
    "app.unsupported.title": "MojitoShield is designed for Linux Mint",
    "app.unsupported.body": "The system was identified as {distribution}. Checks may be inaccurate or not applicable. Continue anyway?",
    "app.abort": "Quit",
    "app.continue": "Continue anyway",
    "app.refresh": "Scan again",
    "app.extended_scan": "Extended scan",
    "app.extended_scan_missing": "Extended scan (not installed)",
    "app.extended_scan_missing_tip": "Install MojitoShield from its Debian package to enable privileged checks.",
    "app.scanning": "Checking {count} items locally…",
    "app.extended_scanning": "Checking items requiring administrator permission…",
    "app.extended_cancelled": "Extended scan was cancelled. Those checks remain incomplete.",
    "app.extended_failed": "Extended scan failed. Those checks remain incomplete.",
    "app.scan_failed": "The scan could not be completed. Try again.",
    "app.summary": "Scan complete. OK: {ok}, Warning: {warning}, Could not determine: {unknown}.",
    "app.summary_incomplete": "Basic scan finished, but not complete. OK: {ok}, Warning: {warning}, Could not determine: {unknown}, Requires extended permission: {auth}.",
    "app.check_list": "Security checks",
    "app.footer": "MojitoShield performs local read-only checks. Results are guidance, not a complete security audit.",
    "app.details": "What is checked?",
    "app.select_check": "Select a check to see its result and details.",
    "app.evidence": "Evidence: {evidence}",
    "level.1": "Level 1: everyday protection",
    "level.2": "Level 2: physical access",
    "status.ok": "OK",
    "status.warning": "Warning",
    "status.unknown": "Could not determine",
    "status.auth_required": "Requires extended permission",
    "status.pending": "Checking…",
    "scan.pending": "Waiting for this check.",
    "check.firewall.title": "Firewall",
    "check.firewall.description": "Reads whether the UFW firewall is turned on and running. It does not show which connections the firewall rules allow, and firewalls managed by other tools are not assessed.",
    "check.updates.title": "System up to date",
    "check.updates.description": "Checks whether security updates are waiting to be installed, using the list of updates the computer last downloaded. Automatic updates, or a full update within the last 14 days, count as up to date. It also checks whether a restart is waiting.",
    "check.screen-lock.title": "Screen lock",
    "check.screen-lock.description": "Checks that the screen locks by itself after a period without use, in Cinnamon, MATE or Xfce. Programs that keep the screen awake, such as video players, are not taken into account.",
    "check.auto-login.title": "Automatic login",
    "check.auto-login.description": "Reads the login screen settings to see whether an account is logged in without a password at startup.",
    "check.timeshift.title": "Timeshift",
    "check.timeshift.description": "Looks for a recent Timeshift system snapshot. A snapshot does not prove that a restore will work, and Timeshift does not back up personal files by default.",
    "check.network-services.title": "Network services",
    "check.network-services.description": "Lists programs that accept connections from other computers, and checks SSH login settings. It cannot see which program owns a port, or whether the firewall blocks it.",
    "check.apparmor.title": "AppArmor",
    "check.apparmor.description": "Checks that AppArmor, which limits what programs are allowed to do, is turned on. It does not count which programs have AppArmor profiles.",
    "check.disk-encryption.title": "Disk encryption",
    "check.disk-encryption.description": "Checks whether the system disk or your home directory is encrypted, so that data stays protected if the computer is lost or stolen. Hardware and firmware encryption are not checked.",
    "check.boot-menu.title": "Boot menu protection",
    "check.boot-menu.description": "Checks whether someone at the computer during startup can change the boot options to get administrator access. Disk encryption or a GRUB password prevents this. Firmware (BIOS) passwords cannot be read.",
    "firewall.ufw_not_installed": "The UFW firewall is not installed. Other firewall tools are not assessed.",
    "firewall.disabled": "The firewall is turned off. You can turn it on in Firewall Configuration, as Linux Mint's Welcome screen recommends.",
    "firewall.enabled": "The firewall is turned on and was started with the system.",
    "firewall.authorization_required": "The firewall settings could not be read. The extended scan can check the live status.",
    "firewall.service_not_confirmed": "The firewall is set to be on, but it could not be confirmed that it is running. The extended scan can check the live status.",
    "firewall.command_unavailable": "UFW could not be started; it may be missing or unavailable.",
    "firewall.status_unavailable": "UFW status could not be read.",
    "firewall.active": "UFW reports that the firewall is active.",
    "firewall.inactive": "UFW reports that the firewall is inactive. You can turn it on in Firewall Configuration.",
    "firewall.unrecognized_status": "UFW returned an unrecognized status.",
    "updates.reboot_pending": "Updates were installed, but a restart has been waiting for {days} days. Restart the computer so that the fixes take effect.",
    "updates.automatic": "Updates are installed automatically.",
    "updates.lists_unavailable": "The list of available updates could not be found, so missing security updates cannot be seen. Open Update Manager and click Refresh.",
    "updates.lists_outdated": "The computer has not looked for updates for {days} days, so missing security updates cannot be seen. Connect to the internet, open Update Manager and click Refresh.",
    "updates.pending_unavailable": "The list of waiting updates could not be read.",
    "updates.no_security_updates_pending": "No security updates are waiting to be installed.",
    "updates.security_updates_recent": Plural(
        "count",
        "1 security update is waiting. The last full update was less than 14 days ago, so this is normal; Update Manager will offer it.",
        "{count} security updates are waiting. The last full update was less than 14 days ago, so this is normal; Update Manager will offer them.",
    ),
    "updates.security_updates_pending": Plural(
        "count",
        "1 security update is waiting, and the last full update was {days} days ago. Open Update Manager and install the updates, or turn on automatic updates in its preferences.",
        "{count} security updates are waiting, and the last full update was {days} days ago. Open Update Manager and install the updates, or turn on automatic updates in its preferences.",
    ),
    "updates.security_updates_pending_no_update": Plural(
        "count",
        "1 security update is waiting, and no full update has been recorded. Open Update Manager and install the updates, or turn on automatic updates in its preferences.",
        "{count} security updates are waiting, and no full update has been recorded. Open Update Manager and install the updates, or turn on automatic updates in its preferences.",
    ),
    "screen_lock.desktop_not_supported": "The desktop environment could not be identified as Cinnamon, MATE or Xfce.",
    "screen_lock.settings_unavailable": "The screen lock could not be checked through {desktop} settings.",
    "screen_lock.disabled": "{desktop} is set not to lock the screen. You can turn on locking in the screensaver settings.",
    "screen_lock.unrecognized_result": "{desktop} returned an unrecognized screen-lock value.",
    "screen_lock.never_automatic": "{desktop} only locks the screen when you lock it yourself. You can set a delay in the screensaver settings.",
    "screen_lock.idle_delay_unavailable": "Locking is turned on in {desktop}, but the delay before it locks could not be read.",
    "screen_lock.enabled": Plural(
        "minutes",
        "{desktop} locks the screen after 1 minute without use.",
        "{desktop} locks the screen after {minutes} minutes without use.",
    ),
    "auto_login.display_manager_unknown": "The login screen in use could not be identified.",
    "auto_login.display_manager_not_supported": "The login screen ({display_manager}) is not LightDM, so its settings are not checked.",
    "auto_login.settings_unreadable": "The login screen settings could not be read.",
    "auto_login.enabled": "An account is logged in automatically at startup. Anyone who turns on the computer gets into that account, and the screen lock does not help after a restart. You can turn this off in Login Window.",
    "auto_login.disabled": "A password is needed to log in at startup.",
    "timeshift.not_installed": "Timeshift is not installed. Other snapshot or backup tools are not assessed.",
    "timeshift.settings_unreadable": "Timeshift's settings could not be read.",
    "timeshift.not_set_up": "System snapshots are not set up. You can set up Timeshift from Linux Mint's Welcome screen, so you can go back if an update or change breaks the system.",
    "timeshift.btrfs_mode": "Timeshift uses Btrfs snapshots, which are only visible while Timeshift runs, so their age was not checked.",
    "timeshift.separate_device": "Timeshift saves snapshots on another device, which was not inspected.",
    "timeshift.snapshots_unreadable": "The Timeshift snapshot folder could not be read.",
    "timeshift.no_snapshots": "Timeshift is set up but has no snapshots. Open Timeshift and create one, or check that scheduled snapshots are turned on.",
    "timeshift.recent_snapshot": Plural(
        "days",
        "The newest system snapshot is 1 day old. A restore has not been tested, and personal files are not included by default.",
        "The newest system snapshot is {days} days old. A restore has not been tested, and personal files are not included by default.",
    ),
    "timeshift.snapshot_too_old": "The newest system snapshot is {days} days old, longer than the expected {limit} days. Open Timeshift and check that scheduled snapshots work.",
    "network_services.status_unreadable": "The list of network connections could not be read.",
    "network_services.none": "No programs accept connections from other computers.",
    "network_services.remote_desktop": "Remote desktop or Telnet accepts connections on port {ports}. Turn the service off if you do not use it.",
    "network_services.ssh_settings_unreadable": "An SSH server accepts connections, but its settings could not be read.",
    "network_services.ssh_password_login": "An SSH server accepts connections and allows password or root login. Use key login only, or turn off the SSH server if you do not use it.",
    "network_services.other_ports": "Programs accept connections from other computers on port {ports}. This is often deliberate, such as file sharing; check that you use them.",
    "network_services.ssh_key_only": "Only an SSH server accepts connections, and it does not allow password or root login.",
    "apparmor.not_available": "AppArmor is not available in the running kernel.",
    "apparmor.status_unreadable": "AppArmor status could not be read.",
    "apparmor.enabled": "AppArmor is turned on.",
    "apparmor.disabled": "AppArmor is turned off, although it is on by default in Linux Mint. Remove apparmor=0 from the boot settings, or ask for help on the Linux Mint forums.",
    "apparmor.unrecognized_status": "AppArmor returned an unrecognized status.",
    "disk_encryption.system_encrypted": "The system disk is encrypted.",
    "disk_encryption.home_only": "Your home directory is encrypted. The rest of the system is not.",
    "disk_encryption.status_unknown": "Disk encryption could not be determined.",
    "disk_encryption.not_encrypted": "The disk is not encrypted, so someone with the computer in hand can read its files. Encryption is chosen when installing Linux Mint; keep it in mind for the next installation, and keep backups of important files.",
    "disk_encryption.not_encrypted_portable": "This laptop's disk is not encrypted, so anyone who finds or steals it can read its files. Encryption is chosen when installing Linux Mint; keep it in mind for the next installation, and keep backups of important files.",
    "boot_menu.protected_by_encryption": "The system disk is encrypted, so changing the boot options gives no access without the encryption passphrase.",
    "boot_menu.password_active": "The boot menu requires a password before boot options can be changed.",
    "boot_menu.password_not_confirmed": "A boot-menu password is set up, but it could not be confirmed that the boot menu was updated afterwards. The extended scan can check it.",
    "boot_menu.password_not_active": "A boot-menu password is set up but not active, because the boot menu was not updated afterwards. Running sudo update-grub in a terminal activates it.",
    "boot_menu.no_password": "The boot options can be changed without a password, and the system disk is not encrypted, so anyone at the computer during startup can get administrator access. Disk encryption, chosen when installing Linux Mint, protects against this. A boot-menu password is an advanced alternative; ask on the Linux Mint forums before setting one, since a mistake can stop the computer from starting.",
    "boot_menu.grub_not_used": "GRUB is not used as the boot menu, so this check does not apply.",
    "boot_menu.config_unreadable": "The boot menu settings could not be read.",
    "boot_menu.authorization_required": "Part of the boot menu settings needs administrator permission to read. The extended scan can check it.",
    "boot_menu.status_unknown": "Boot menu protection could not be determined.",
    "check.unexpected_error": "The check could not be completed.",
}


def translate(message_id: str, **values: str) -> str:
    """Return the English text for a message ID, with its placeholders filled in.

    Args:
        message_id: A key in the catalog, such as "firewall.enabled".
        **values: Values for the placeholders, such as days="3". For a Plural
            text, the value it counts by chooses between its two forms.

    Returns:
        The finished text. An unknown ID is returned as it is, and a text
        with missing values is returned unfilled, so the window never fails
        because of a text.

    Examples:
        >>> translate("timeshift.recent_snapshot", days="1")[:36]
        'The newest system snapshot is 1 day '
        >>> translate("no.such.message")
        'no.such.message'
    """
    template = ENGLISH.get(message_id, message_id)
    if isinstance(template, Plural):
        template = template.one if values.get(template.count) == "1" else template.other
    try:
        return template.format(**values)
    except (KeyError, ValueError):
        return template

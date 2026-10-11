# Check contracts

Each check answers one question, from local, read-only sources. The rules below apply to all of them.

## Rules for every check

1. **Measure the outcome, not only the setting.**
2. **OK requires positive evidence.** Not finding a problem is not proof that things are fine.
3. **Warning requires a concrete deviation that applies to almost every Mint desktop user.**
4. **Every Warning gives a next step a beginner can take.** If the only fix is a reinstall, say so gently.
5. **Do not warn twice about the same root cause.**
6. **When in doubt, Could not determine**, with what the user can check themselves.
7. **Prefer evidence a normal user can read** before asking for a password.

Statuses: **OK**, **Warning**, **Could not determine**, **Requires extended permission**.

---

## Level 1: everyday protection

### 1. Firewall (`firewall`)

- **Question:** Is the firewall turned on?
- **Reads:** `ENABLED=` in `/etc/ufw/ufw.conf` (world-readable) and `systemctl is-active ufw`.
- **Result:**
  - `ENABLED=yes` and the service is active → **OK**. UFW loaded its rules at startup.
  - `ENABLED=no` → **Warning**. Next step: turn on the firewall in *Firewall Configuration* (Mint's Welcome screen recommends this).
  - `ENABLED=yes` but the service is not active, or the file cannot be read → **Requires extended permission**. The extended scan reads the live status with `ufw status`.
  - UFW is not installed → **Could not determine**. Other firewall tools are not assessed.
- **Cannot conclude:** which ports the rules allow (`/etc/ufw/user.rules` is root-only), or whether rules were changed by hand after startup.

### 2. System up to date (`updates`)

- **Question:** Are updates actually being installed?
- **Reads:**
  - Update Manager automation: the flag `/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled` plus `systemctl is-enabled mintupdate-automation-upgrade.timer`.
  - APT unattended-upgrades: `/etc/apt/apt.conf.d/20auto-upgrades`.
  - The date of the latest entry with `Upgrade:` in `/var/log/apt/history.log`, falling back to `history.log.1.gz` (both world-readable).
  - `/var/run/reboot-required` and its modification time.
- **Result:**
  - A reboot has been pending for more than 7 days → **Warning**. Next step: restart the computer so installed fixes take effect.
  - Automatic updates are on → **OK**.
  - Updates were installed within the last 30 days → **OK**.
  - Updates were last installed more than 30 days ago → **Warning**. Next step: open Update Manager and install the updates, or turn on automatic updates in its preferences.
  - No update history can be read → **Could not determine**.
- **Cannot conclude:** whether all available security updates are installed. Checking that would need a fresh package list, and the app works offline.

### 3. Screen lock (`screen-lock`)

- **Question:** Does the screen lock by itself when the computer is left alone?
- **Reads:** for the current desktop (from `XDG_CURRENT_DESKTOP`):
  - Cinnamon: `org.cinnamon.desktop.screensaver lock-enabled` and `org.cinnamon.desktop.session idle-delay` (seconds).
  - MATE: `org.mate.screensaver lock-enabled` and `org.mate.session idle-delay` (minutes).
  - Xfce: `xfce4-screensaver` `/lock/enabled` and `/saver/idle-activation/delay` (minutes).
- **Result:**
  - Locking is on and the idle delay is above 0 → **OK**, showing the delay in minutes.
  - Locking is off → **Warning**. Next step: turn on locking in the screensaver settings.
  - The idle delay is 0 (never) → **Warning**: the screen only locks when locked by hand.
  - Another desktop, or a setting cannot be read → **Could not determine**.
- **Cannot conclude:** whether programs block the screensaver (for example video players).

### 4. Automatic login (`auto-login`)

- **Question:** Does the computer log in to an account without a password at startup?
- **Reads:** `autologin-user` in the `[Seat:*]`, `[Seat:seat0]` and `[SeatDefaults]` groups of `/usr/share/lightdm/lightdm.conf.d/*.conf`, `/etc/lightdm/lightdm.conf.d/*.conf` and `/etc/lightdm/lightdm.conf`, in that order, the later value winning. This is the same logic as Mint's *Login Window* tool. The display manager comes from `/etc/X11/default-display-manager`.
- **Result:**
  - No `autologin-user` is set → **OK**.
  - An `autologin-user` is set → **Warning**. Anyone who turns on the computer gets into the account, which also makes the screen lock useless after a restart. Next step: turn off automatic login in *Login Window*. The user name is never shown.
  - The display manager is not LightDM, or the files cannot be read → **Could not determine**.

### 5. Timeshift (`timeshift`)

- **Question:** Is there a recent system snapshot to go back to?
- **Reads:** `/etc/timeshift/timeshift.json` (world-readable) and the snapshot folder names in `/timeshift/snapshots`, which are timestamps such as `2026-10-02_22-07-41`. The root filesystem's UUID is read with `findmnt`.
- **Age limit:** twice the most frequent enabled schedule (hourly, daily, weekly or monthly), never below 7 days (the computer may be turned off) and never above 40 days. With only a boot schedule, or none, the limit is 40 days.
- **Result:**
  - The newest snapshot is within the limit → **OK**, with its age. The message also says that a restore has not been tested and that personal files are not included by default.
  - The newest snapshot is older than the limit → **Warning**. Next step: open Timeshift and check that scheduled snapshots work.
  - Set up, but no snapshots → **Warning**.
  - Never set up (no settings, or no snapshot device chosen) while Timeshift is installed → **Warning**. Next step: set up system snapshots from the Welcome screen.
  - Snapshots on another device, or btrfs mode → **Could not determine**. Looking would require mounting, which counts as changing the system.
  - Timeshift is not installed, or the snapshot folder cannot be read → **Could not determine**.
- **Cannot conclude:** that a restore works, or anything about backups of personal files.

### 6. Network services (`network-services`)

- **Question:** Do programs accept connections from other computers?
- **Reads:** TCP sockets in the listening state in `/proc/net/tcp` and `/proc/net/tcp6` (world-readable), ignoring loopback addresses. For SSH: `PasswordAuthentication` and `PermitRootLogin` in `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/*.conf` (first value wins, as in sshd).
- **Result:**
  - Nothing listens outside the computer → **OK**.
  - Remote desktop (port 3389), VNC (5900–5999) or Telnet (23) listens → **Warning**. Next step: turn off the service if it is not needed.
  - SSH (port 22) listens and allows password login or root login → **Warning**. Next step: use key login only, or turn off the SSH server if it is not needed.
  - SSH listens with key login only → **OK**.
  - Other ports listen → **Could not determine**, listing the ports. Many such programs are deliberate (file sharing, games).
- **Cannot conclude:** which program owns a port (that needs root), or whether the firewall blocks it (its rules are root-only).

### 7. AppArmor (`apparmor`)

- **Question:** Is AppArmor, which limits what programs may do, turned on?
- **Reads:** `/sys/module/apparmor/parameters/enabled` (world-readable).
- **Result:**
  - `Y` → **OK**.
  - `N` → **Warning**. AppArmor is on by default in Mint, so it was turned off on purpose or by mistake. Next step: remove `apparmor=0` from the boot settings, or ask for help on the Mint forums.
  - The file is missing or unreadable → **Could not determine**.
- **Cannot conclude:** how many programs have profiles, or whether they are enforced.

---

## Level 2: physical access

### 8. Disk encryption (`disk-encryption`)

- **Question:** Is data on the disk protected if the computer is lost or stolen?
- **Reads:** the block devices under `/` and under the user's home directory (`findmnt`, `lsblk`), whether the home directory uses eCryptfs, and `/sys/class/dmi/id/chassis_type` to tell laptops from desktop computers.
- **Result:**
  - The root filesystem is behind a crypt mapping → **OK**.
  - Only the home directory is encrypted (crypt mapping or eCryptfs) → **OK**, saying that the rest of the system is not.
  - Nothing is encrypted → **Warning**. The text is stronger on laptops, which are more often lost or stolen. Next step: encryption has to be chosen when installing Mint, so keep it in mind for the next installation and keep backups of important files.
  - The devices cannot be read → **Could not determine**.
- **Cannot conclude:** hardware (self-encrypting) or firmware encryption, or encrypted folders inside the home directory.

### 9. Boot menu protection (`boot-menu`)

- **Question:** Can someone at the computer during startup change the boot options to get administrator access, without a password?
- **Reads:**
  - Whether the root filesystem is behind a crypt mapping (as in *Disk encryption*).
  - Whether GRUB is the boot menu: `/boot/grub/grub.cfg` exists. Its contents are root-only, but its modification time is readable.
  - GRUB password settings (`set superusers=` together with a `password` or `password_pbkdf2` line) in the executable scripts in `/etc/grub.d` (world-readable) and in `/boot/grub/custom.cfg`, which GRUB reads directly at boot. Comment lines are ignored, and non-executable scripts are ignored because `update-grub` skips them.
- **Result:**
  - The system disk is encrypted → **OK**. Changing boot options gives nothing without the encryption passphrase.
  - A password is set in `custom.cfg` → **OK**.
  - A password is set in `/etc/grub.d`, and `grub.cfg` was generated after those scripts were last changed → **OK**.
  - A password is set in `/etc/grub.d`, but `grub.cfg` is older → **Requires extended permission**. The extended scan reads `grub.cfg`: password present → **OK**; missing → **Warning** with the next step `sudo update-grub`.
  - No password and no encryption → **Warning**. Next step: disk encryption at the next installation; a boot-menu password is an advanced alternative, and a mistake can stop the computer from starting, so ask on the Linux Mint forums first. On unencrypted computers this is a second Warning next to *Disk encryption*; that was a deliberate decision (2026-10-11).
  - GRUB is not used → **Could not determine**.
  - Encryption state unknown and no password, or files unreadable → **Could not determine**.
- **Cannot conclude:** firmware (BIOS/UEFI) passwords, Secure Boot or boot order. Whether boot entries are marked `--unrestricted` is not checked; that only affects starting an entry, not changing its options.
- **Not checked (decided 2026-10-11):** the root account's password state and recovery-mode behaviour (`sulogin`). The earlier, wider proposal is kept in `docs/root-shell-check-proposal.md` for reference.

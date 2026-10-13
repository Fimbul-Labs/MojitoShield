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

- **Question:** Are security updates installed in time? (An earlier rule, any upgrade in the APT history within 30 days, gave OK on a fresh installation with 197 pending updates.)
- **Reads** (all world-readable, no network):
  - Update Manager automation: the flag `/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled` plus `systemctl is-enabled mintupdate-automation-upgrade.timer`.
  - APT unattended-upgrades: `/etc/apt/apt.conf.d/20auto-upgrades`.
  - The `Date:` field of the security archive's package list, `/var/lib/apt/lists/*-security_*Release`. The files keep the server's date, not the download time; security archives are republished several times a day, so an old date means an old download.
  - Pending upgrades from `apt-get -s dist-upgrade` (a simulation that changes nothing). An `Inst` line counts as a security update when one of its archives ends in `-security` (Ubuntu `noble-security`, Debian `stable-security`).
  - The newest **full update** in `/var/log/apt/history.log`, falling back to `history.log.1.gz`: an entry with `Upgrade:` whose command is Update Manager (`aptkit`, earlier `aptdaemon`), `unattended-upgrade`, or `apt`/`apt-get` with `upgrade`, `full-upgrade` or `dist-upgrade`. `apt install` does not count, even when it upgrades a package. An entry without a command line (Synaptic, older Update Manager) counts only after the installation finished, read from the time of `/var/log/installer`, because the installer also upgrades a few packages and records no command line.
  - `/var/run/reboot-required` and its modification time.
- **Result:**
  - A reboot has been pending for more than 7 days → **Warning**. Next step: restart the computer so installed fixes take effect.
  - Automatic updates are on → **OK**.
  - No security package list is found → **Could not determine**. Next step: open Update Manager and click Refresh.
  - The security list was published more than 14 days ago → **Warning**: the computer has not looked for updates. Next step: connect to the internet, open Update Manager and click Refresh.
  - The simulation fails → **Could not determine**.
  - No security updates are pending → **OK**.
  - Security updates are pending and a full update ran within 14 days → **OK**: they are at most about 14 days old.
  - Security updates are pending and no full update within 14 days, or none recorded → **Warning**, with the number. Next step: open Update Manager and install the updates, or turn on automatic updates.
- **Why 14 days:** Cyber Essentials requires critical and high security updates within 14 days of release. Only security updates count, so the Warning stays rare and important.
- **Cannot conclude:** how long a pending update has been available (the lists have no per-package dates), whether an update the user deselected matters, or whether an `aptkit` entry was Software Manager installing a program rather than Update Manager.

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
  - No password and no encryption → **Warning**. Next step: disk encryption at the next installation; a boot-menu password is an advanced alternative, and a mistake can stop the computer from starting, so ask on the Linux Mint forums first. On unencrypted computers this is a second Warning next to *Disk encryption*, on purpose: they are different risks with different fixes.
  - GRUB is not used → **Could not determine**.
  - Encryption state unknown and no password, or files unreadable → **Could not determine**.
- **Cannot conclude:** firmware (BIOS/UEFI) passwords, Secure Boot or boot order. Whether boot entries are marked `--unrestricted` is not checked; that only affects starting an entry, not changing its options.
- **Not checked:** the root account's password state and recovery-mode behaviour (`sulogin`).

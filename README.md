# MojitoShield

MojitoShield looks over the basic security settings of a Linux Mint computer and explains what it finds in plain language. It only reads. It never changes anything, and it works without an internet connection.

This is an early version. Treat the results as a helpful second opinion, not a full security audit.

## Vision

Most Mint users never open the firewall settings or wonder whether their disk is encrypted, and they shouldn't have to. MojitoShield is for them. It tells you what it checked, what deserves a look, and, just as honestly, what it couldn't find out. It shouldn't scare anyone, and it shouldn't promise more safety than it can give.

## Quick start

1. Download the newest `mojitoshield_…_all.deb` from the [Releases page](https://github.com/Fimbul-Labs/MojitoShield/releases).
2. Double-click the file. Mint opens the Package Installer. Click **Install Package** and type your password.
3. Open the menu, search for **MojitoShield** and start it.

The checks run by themselves and take a few seconds. Click a check in the list to see what was found and what you can do about it.

Every check ends with one of four results:

- **OK:** the protection is in place.
- **Warning:** something specific needs your attention. The text tells you what to do.
- **Could not determine:** MojitoShield couldn't find out. This is neither a warning nor an all-clear.
- **Requires extended permission:** the check needs administrator access. Click **Extended scan** and type your password if you want it to run. Saying no is fine.

To remove MojitoShield, run `sudo apt remove mojitoshield` in a terminal.

## What it checks

Everyday protection:

- **Firewall:** is it turned on?
- **System up to date:** have security updates been waiting for more than 14 days?
- **Screen lock:** does the screen lock by itself when you leave the computer?
- **Automatic login:** does the computer log in without a password?
- **Timeshift:** is there a recent system snapshot to go back to?
- **Network services:** can other computers connect to yours?
- **AppArmor:** is it turned on?

If someone gets hold of the computer:

- **Disk encryption:** are your files encrypted?
- **Boot menu protection:** can the startup options be changed without a password?

How each check reaches its result is described in [docs/check-contracts.md](docs/check-contracts.md).

## What it never does

- Change settings, install anything or connect to the internet.
- Ask for, read or store passwords. The password window for the extended scan is Mint's own.
- Give you an overall security score, or save or send a report.

The extended scan uses a small helper that can only run two fixed, read-only checks.

## Tested editions

| Edition | Status |
|---|---|
| Linux Mint 22.3 Cinnamon | Tested on a fresh installation (version 0.1.2) and in daily use |
| Linux Mint 22.3 Xfce | Not tested yet |
| Linux Mint 22.3 MATE | Not tested yet |
| LMDE 7 | Not tested yet |
| Linux Mint 21.x | Should work, not tested yet |
| Linux Mint 20 and older | Not supported (needs Python 3.10) |

On a fresh Xfce installation the screen-lock check may say *Could not determine*, because Xfce only saves settings you have changed.

### Help with testing

If you use Xfce, MATE, LMDE or Mint 21, a test run would help a lot. It takes about an hour in a virtual machine and changes nothing on your own computer. [docs/testing.md](docs/testing.md) walks you through it. Please share what you find as an [issue](https://github.com/Fimbul-Labs/MojitoShield/issues).

## For developers

The code is in `src/bin`. On Mint, Python 3, PyGObject and GTK 3 are already installed, so you can run it from there:

```sh
cd src/bin
python3 -m mojitoshield      # start the app
python3 -m unittest discover -s tests   # run the tests
```

The extended scan only works from the installed package, because its helper must be owned by root. [docs/testing.md](docs/testing.md) shows how to build the package.

- `mojitoshield/checks/` has one module per check.
- `mojitoshield/app.py` is the window, and `mojitoshield/i18n.py` holds all the texts.
- `mojitoshield_privileged.py` is the root helper. It imports nothing from the app on purpose.
- `debian/` holds the packaging.

Code style is set in `ruff.toml`; run `ruff check` and `ruff format` before committing.

When you change a check, update its contract in `docs/check-contracts.md` first. A Warning needs concrete evidence and a next step a beginner can follow; when in doubt, use *Could not determine*. Please keep the app offline and read-only.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE). The AppStream metadata is CC0-1.0.

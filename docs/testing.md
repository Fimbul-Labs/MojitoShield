# Testing MojitoShield on Linux Mint editions

This guide tests MojitoShield on fresh installations of each Linux Mint edition, using virtual machines (VMs) on the development computer. A VM is a complete computer simulated inside a window, so tests never touch the real system.

Each edition is tested twice:

- **Collected data** goes into the automatic tests, so later code changes are checked against real Xfce, MATE and LMDE systems without starting a VM.
- **A manual test** checks that the installed app works and shows correct results.

## Editions

| Edition | Download | When to test |
|---|---|---|
| Linux Mint 22.3 Cinnamon | https://linuxmint.com/download.php | Before every release |
| LMDE 7 Cinnamon | https://linuxmint.com/download_lmde.php | Before every release |
| Linux Mint 22.3 Xfce | https://linuxmint.com/download.php | Before bigger releases |
| Linux Mint 22.3 MATE | https://linuxmint.com/download.php | Before bigger releases |

Start with Mint 22.3 Cinnamon, then LMDE 7 and Xfce. MATE can wait.

## One-time preparation on the development computer

virt-manager (the program that runs the VMs) is already installed. Two more things are needed.

**1. The shared-folder helper.** It lets a VM and the development computer share one folder:

```sh
sudo apt install virtiofsd
```

**2. The shared folder,** with the package and the source code in it. Run this from the project folder, and again whenever the code has changed:

```sh
mkdir -p ~/mojitoshield-vm
git archive HEAD:src/bin --prefix=mojitoshield-source/ --output ~/mojitoshield-vm/mojitoshield-source.tar.gz
```

Then build the package from a clean copy, so no build files end up in the project folder (this needs `sudo apt install debhelper`), and copy it into the shared folder:

```sh
mkdir -p /tmp/mojitoshield-build
git archive HEAD:src/bin --prefix=mojitoshield/ | tar -x -C /tmp/mojitoshield-build
(cd /tmp/mojitoshield-build/mojitoshield && dpkg-buildpackage -us -uc -b)
cp /tmp/mojitoshield-build/mojitoshield_*_all.deb ~/mojitoshield-vm/
```

## Creating a VM (once per edition)

**1. Download the image.** On the download page, choose a mirror and download the `.iso` file and `sha256sum.txt` from the same folder. Then check that the download is not damaged. In the download folder:

```sh
sha256sum --check --ignore-missing sha256sum.txt
```

The line for your `.iso` must end with `OK`.

**2. Create the VM.** Open virt-manager and click *Create a new virtual machine*:

1. *Local install media*, then *Browse* and *Browse Local* to choose the `.iso`. If the operating system is not detected, untick *Automatically detect* and type `ubuntu24.04` (Mint 22.3) or `debian13` (LMDE 7).
2. Memory **4096** MB, CPUs **2**.
3. Disk **25** GB.
4. Name the VM after the edition, for example `mint-22.3-xfce`, and click *Finish*.

**3. Install Mint in the VM.** Double-click *Install Linux Mint* on the desktop and use the defaults: **no** disk encryption, **no** automatic login. Use the same simple user name and password in every VM, for example `tester`. Restart when asked, then log in once.

Do not install updates. The test is about what a fresh installation looks like.

**4. Shut the VM down** from the Mint menu.

**5. Add the shared folder.** In virt-manager, open the VM and choose *View → Details* (in some versions a light-bulb or "i" icon in the toolbar):

1. *Memory*: tick **Enable shared memory**, then *Apply*.
2. *Add Hardware* → *Filesystem*: Driver **virtiofs**, Source path `/home/YOUR-USER-NAME/mojitoshield-vm`, Target path `mojitoshield`. Click *Finish*.

**6. Take a snapshot.** A snapshot saves the VM's state, so every test can start from the same fresh system. With the VM still shut down, choose *View → Snapshots* (or the last icon in the toolbar), then *+*, and name it `fresh-install`.

Always take and restore snapshots while the VM is shut down; a running VM with a shared folder cannot be snapshotted.

## Test run (once per edition and release)

First restore the fresh system: with the VM shut down, choose *View → Snapshots*, select `fresh-install` and click *Run selected snapshot* (the ▶ button under the list). If the VM does not start by itself, click *Power on*. Log in and open a terminal.

**1. Open the shared folder:**

```sh
sudo mkdir -p /mnt/mojitoshield
sudo mount -t virtiofs mojitoshield /mnt/mojitoshield
ls /mnt/mojitoshield
```

The last command should list the `.deb` file and `mojitoshield-source.tar.gz`.

**2. Collect the data.** Replace `NAME` with the VM's name, for example `mint-22.3-xfce`:

```sh
cd ~
tar -xzf /mnt/mojitoshield/mojitoshield-source.tar.gz
cd mojitoshield-source
python3 -m tools.collect_edition_data | sudo tee /mnt/mojitoshield/NAME.json > /dev/null
```

`sudo tee` writes the file as the administrator, because the VM's user may not write to the shared folder. No output means it worked. The file is now in `~/mojitoshield-vm` on the development computer.

**3. Write down the real screen-lock setting.** Open the desktop's screensaver settings (Cinnamon: *Menu → Screensaver*; MATE: *Control Center → Screensaver*; Xfce: *Settings → Xfce Screensaver*). Note whether the computer locks itself and after how many minutes. This is what MojitoShield should report.

**4. Install MojitoShield:**

```sh
sudo apt install /mnt/mojitoshield/mojitoshield_*_all.deb
```

A note that the download "is performed unsandboxed as root" is harmless.

**5. Start MojitoShield from the menu.** There must be **no** "unsupported distribution" warning.

**6. Compare each result with the real system,** using the table below. Copy it into your notes for this edition.

| Check | Where to see the real state | MojitoShield shows | Correct? |
|---|---|---|---|
| Firewall | *Menu → Firewall Configuration*, the Status switch | | |
| System up to date | *Menu → Update Manager* | | |
| Screen lock | What you wrote down in step 3 | | |
| Automatic login | *Menu → Login Window → Users* | | |
| Timeshift | *Menu → Timeshift* | | |
| Network services | A fresh install runs none | | |
| AppArmor | `sudo aa-status`, first line | | |
| Disk encryption | You chose no encryption | | |
| Boot menu protection | A fresh install has no GRUB password | | |

A *Warning* is correct when the real system really has that problem; on a fresh install, several Warnings are normal. *Could not determine* is acceptable only when the text explains why.

**7. Use only the keyboard.** Move through the list with the arrow keys and Tab. The details should follow the selected check.

**8. Test the Extended scan.** Make the firewall settings unreadable, which forces the app to ask for permission:

```sh
sudo chmod 600 /etc/ufw/ufw.conf
```

Close and start MojitoShield again. *Firewall* should show *Requires extended permission* and an **Extended scan** button.

- Click **Extended scan** and enter the password. Firewall should now show a result.
- Restart the app, click **Extended scan** again and click **Cancel**. Firewall should keep *Requires extended permission*, and the summary must not say the scan is complete.

**9. Test without network.** In virt-manager, choose *View → Details*, then the network card (*NIC*), untick **Link state: active** and click *Apply*. (Turning off networking inside the VM works too.) Restart MojitoShield: it should work as before.

**10. Finish.** Shut the VM down. The next test run starts by restoring the snapshot, so the changes from this run disappear.

## After the test

Open an issue at https://github.com/Fimbul-Labs/MojitoShield/issues with:

- the edition and version, and the MojitoShield version;
- the results table from step 6, and anything that looked wrong in the other steps;
- the `.json` file from step 2 and the real screen-lock setting from step 3. The file only holds system facts (see the top of `src/bin/tools/collect_edition_data.py`); read it before attaching it if you want to be sure.

The file is then added to `src/bin/tests/data/editions/`, with the confirmed result in `EXPECTED` in `src/bin/tests/test_editions.py`, so later changes are checked against that edition.

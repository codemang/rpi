# Raspberry Pi hardening

`harden.sh` secures a Raspberry Pi running Home Assistant Container (Docker) on Raspberry Pi OS or Debian. It's safe to re-run. It won't work on Home Assistant OS.

It sets up:

- A firewall that only allows the needed ports from the home network, including a block on non-LAN access to published Docker ports
- Key-only SSH with no root login, plus `fail2ban`
- Automatic security updates
- Kernel hardening and persistent, size-capped logs

## Before you start

- Log in over SSH with a key, as your normal user. Don't use a root shell.
- Don't run this while you need Home Assistant to be available. The initial update can restart Docker, which restarts HA.
- Keep your phone nearby to test HA and Apple Home.

## Running it

```bash
ssh -i ~/.ssh/id_rpi USER@PI

sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/codemang/rpi.git
cd rpi

sudo bash harden.sh --dry-run   # shows the plan, changes nothing
sudo bash harden.sh
```

In the dry run, check that the trusted LAN is correct and that the Home Assistant container was found.

To re-run later, use `git pull` first.

## Recommended prompt answers

These are for this Pi, based on its dry run. The script only asks about ports that are listening and not already allowed, so the list can change as integrations are added.

### Ports

| Prompt | Answer | Why |
|---|---|---|
| `111/tcp` (rpcbind) | **n** | Only used for NFS, and should stay closed. |
| `111/udp` (rpcbind) | **n** | Same as above. |
| `1400/tcp` (python3) | **y** | Home Assistant, almost certainly its Sonos integration receiving speaker updates. |
| `18555/tcp` (go2rtc) | **y** if you view cameras in HA, otherwise **n** | HA's built-in camera streaming. Without it, live views may fail or fall back to something slower. |

For any other port, `python`, `hass`, `mosquitto`, `node` and `zigbee2mqtt` processes default to yes and everything else defaults to no. Those defaults are reasonable if you don't recognise the port.

### Services

| Prompt | Answer | Why |
|---|---|---|
| `Disable rpcbind?` | **y** if `findmnt -t nfs,nfs4` prints nothing, otherwise **n** | It's only needed for NFS mounts. |
| `Disable rpcbind.socket?` | Same as `rpcbind` | Otherwise it can start `rpcbind` again. |
| `Disable cups?` | **y** unless you print through this Pi | Linux printing service. HA doesn't need it, and printing straight to a printer from a Mac or phone isn't affected. |
| `Disable cups-browsed?` | Same as `cups` | Finds network printers for CUPS. |
| Any other service, such as VNC | **y** unless you use it | Undo with `sudo systemctl enable --now SERVICE`. |

### Sudo password

This only appears if your account can use sudo with no password. Answer **y** only if you know the account's password.

## Lockout protection

SSH and firewall changes revert automatically unless you type `keep`. The prompt gives you **about 9 minutes**.

**Don't reboot the Pi before typing `keep`.** A reboot cancels the timer, and the changes stay in place without the undo.

Keep the original SSH window open, and do these checks in order.

### Must pass

1. **New SSH login:** in a new terminal on your Mac, run the exact command the script prints. If it fails, stop and don't type `keep`.
2. **Sudo:** in that new session, run `sudo -k && sudo true`.
3. **Home Assistant:** open `http://PI:8123` on your phone over Wi-Fi.
4. **Apple Home:** with your phone on Wi-Fi, close and reopen the Home app, then toggle an accessory. "No Response" means something is blocked.
5. **Zigbee:** toggle a Zigbee device from Home Assistant.

### Worth checking

- **Sonos:** change the volume in the Sonos app and confirm HA shows the new level within a few seconds.
- **Cameras:** if you allowed 18555, open a live view in HA.
- **Other devices:** look for newly unavailable Wi-Fi devices under **Settings > Devices & services**. Some take a few minutes to drop off, so check again later.

From the new SSH session:

```bash
# All containers should still be running
docker ps

# Firewall should be active, and sshd should appear as a jail
sudo ufw status verbose
sudo fail2ban-client status sshd

# Shows what the firewall blocked
sudo journalctl -k --since "10 min ago" | grep "UFW BLOCK" | tail -20
```

In the blocked list, `SRC` is the sender and `DPT` is the port it tried to reach. Ignore entries from outside your network. One of your devices appearing repeatedly means that port may need allowing.

### Decide

- **Everything works:** type `keep` in the original window, in lowercase.
- **SSH fails:** type anything else, or wait for it to revert. Then try logging in again.
- **One device is blocked:** allow its port from the new session, re-test, then type `keep`. Use your own network and port, and swap `tcp` for `udp` if that's what the log shows:

  ```bash
  sudo ufw allow proto tcp from 192.168.1.0/24 to any port 1883
  ```

Reverting only undoes the SSH, firewall, `fail2ban` and sudo changes. Updates, automatic updates, kernel settings, log settings, disabled services and the root password lock all stay in place.

## After `keep`

1. Read the "Things to review yourself" list.
2. If it says a reboot is needed, run `sudo reboot`.
3. After rebooting, check SSH, Home Assistant and Apple Home again.
4. Run `docker ps` and look for missing containers. Containers without a restart policy don't come back after a reboot, so add `restart: unless-stopped` to their config.

## Options

| Option | Use |
|---|---|
| `--dry-run` | Show the plan without changing anything. |
| `--lan CIDR` | Set the trusted network, instead of auto-detecting it. Repeat it to add an IoT VLAN. |
| `--allow-port 1883/tcp` | Allow another port from the LAN. Repeatable. |
| `--vpn-iface tailscale0` | Allow SSH and HA over a VPN interface. Repeatable. |
| `--auto-reboot` | Reboot at 04:00 when security updates need it. |
| `--strict-udp` | Don't allow UDP replies to ephemeral ports. Tighter, but some IoT discovery stops working. |

Re-run the script after adding a Docker network, so that containers on it can reach services on the Pi.

## Undoing changes

Each run saves a backup in `/var/backups/rpi-harden/`. To undo that run's SSH, firewall, `fail2ban` and sudo changes:

```bash
sudo bash /var/backups/rpi-harden/TIMESTAMP/rollback.sh
```

If you get locked out, connect a monitor and keyboard to the Pi and run the same command, using the newest folder.

## What it deliberately leaves alone

Changing any of these would break this setup:

| Setting | Reason |
|---|---|
| IP forwarding | Docker networking needs it. |
| IPv6 | HomeKit and Matter rely on it. |
| `avahi-daemon` | Provides `hostname.local` and mDNS. |
| Bluetooth | Used by HA Bluetooth integrations. |
| USB lockdown | The Zigbee dongle needs to keep working. |
| `/etc/docker/daemon.json` | Changing it restarts HA and can break containers. |

## Remote access with Tailscale

`setup-tailscale.sh` puts the Pi on your Tailscale network, so you can reach SSH and Home Assistant from anywhere without opening ports on your router. Like `harden.sh`, it's safe to re-run.

```bash
sudo bash setup-tailscale.sh --dry-run   # shows the plan, changes nothing
sudo bash setup-tailscale.sh             # add --mosh for mosh support
```

On the first run it prints a login URL. Open it and sign in, and the script continues.

It does the following:

- Installs Tailscale from Tailscale's apt repo, so it's updated along with everything else.
- Turns off Tailscale SSH and Tailscale DNS. SSH keeps going through the hardened `sshd` and `fail2ban`.
- Allows SSH (22) and HA (8123) in on `tailscale0` only, and lets `tailscale0` through the Docker firewall.

Then, once, by hand:

1. Install Tailscale on your Mac and phone, and sign in with the same account.
2. In the [Tailscale admin console](https://login.tailscale.com/admin/machines), disable key expiry for the Pi.
3. In the HA Companion app, set the External URL to the address the script prints.

**If you re-run `harden.sh` later, add `--vpn-iface tailscale0`.** Without it, `harden.sh` removes the Docker firewall exception.

## Testing

`harden.sh` was tested end to end on Debian 12 and 13 x86 containers with a stand-in Home Assistant, covering rollback, `keep`, the firewall and a reboot. The dropped-connection timer, outside-network blocking, `fail2ban` bans and re-runs were tested on Debian 12 only. It hasn't been tested against real HomeKit, Zigbee or Raspberry Pi hardware, which is why the manual checks above matter.

`setup-tailscale.sh` was tested on a Debian 13 container with the real Tailscale apt repo, ufw and Docker firewall block. The `tailscale` CLI and systemd were stand-ins, so the login and real tailnet traffic haven't been tested.

#!/usr/bin/env bash
#
# harden.sh - security hardening for a Raspberry Pi running Home Assistant
# Container (Docker) on Raspberry Pi OS / Debian.
#
# Safe to re-run. Run it with --dry-run first to see what it detects.
#
# Lockout protection: before SSH and firewall changes are applied, a systemd
# timer is armed that undoes them after 10 minutes. It is only cancelled once
# you confirm that a NEW ssh session works. If your connection drops, wait for
# the timer and the Pi returns to its previous SSH/firewall state.
#
# Deliberately left alone, because each would break this setup:
#   - net.ipv4.ip_forward    Docker networking needs it
#   - IPv6                   HomeKit and Matter rely on it
#   - avahi-daemon           provides hostname.local and mDNS
#   - bluetooth              HA Bluetooth integrations
#   - USB lockdown           the Zigbee dongle needs to keep working
#   - /etc/docker/daemon.json  changing it restarts HA and can break containers

set -Eeuo pipefail

readonly SCRIPT_VERSION="1.0"
readonly ROLLBACK_SECONDS=600
readonly ROLLBACK_UNIT="rpi-harden-rollback"
readonly BACKUP_ROOT="/var/backups/rpi-harden"
readonly SSHD_DROPIN="/etc/ssh/sshd_config.d/00-rpi-harden.conf"
readonly F2B_JAIL="/etc/fail2ban/jail.d/rpi-harden.local"
readonly SYSCTL_FILE="/etc/sysctl.d/99-rpi-harden.conf"
readonly UFW_AFTER="/etc/ufw/after.rules"
readonly DOCKER_BEGIN="# BEGIN rpi-harden docker"
readonly DOCKER_END="# END rpi-harden docker"

DRY_RUN=0
AUTO_REBOOT=0
STRICT_UDP=0
LANS=()
EXTRA_PORTS=()
VPN_IFACES=()

# Set during preflight.
ADMIN_USER=""
SSH_USERS=()
FW_SOURCES=()
V6_SOURCES=()
DOCKER_SUBNETS=()
SSH_PEERS=()
OUTSIDE_PEERS=()
HAS_DOCKER=0
HA_CONTAINER=""
HA_NETWORK=""
REQUIRE_SUDO_PASSWORD=0
UFW_WAS_ACTIVE=0
F2B_WAS_ACTIVE=0
BACKUP_DIR=""
IN_RISKY_SECTION=0

# Base firewall rules, as proto:port. Allowed from the LAN only.
#   8123         Home Assistant web UI
#   5353         mDNS (Apple Home / HomeKit discovery)
#   1900         SSDP (UPnP device discovery)
#   21063:21070  HomeKit Bridge
PORT_RULES=("tcp:8123" "udp:5353" "udp:1900" "tcp:21063:21070")

# Many IoT devices answer broadcast discovery by unicast to an ephemeral port.
# Connection tracking can't match those replies to the broadcast that caused
# them, so without this rule the devices silently disappear from HA.
readonly EPHEMERAL_UDP="udp:32768:60999"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ok\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !!\033[0m %s\n' "$*" >&2; }
die() {
  printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2
  ((IN_RISKY_SECTION)) && rollback_now
  exit 1
}

usage() {
  cat <<'EOF'
Usage: sudo ./harden.sh [options]

  --dry-run            Run the checks and print the plan. Changes nothing.
  --lan CIDR           LAN to trust (repeatable). Auto-detected by default.
                       Add your IoT VLAN here if you have one.
  --allow-port P/PROTO Also allow a port from the LAN, e.g. 1883/tcp (repeatable).
  --vpn-iface IFACE    Allow SSH and HA over a VPN interface, e.g. tailscale0
                       or wg0 (repeatable). Use this if you add a VPN later.
  --auto-reboot        Reboot at 04:00 when security updates need it.
  --strict-udp         Don't allow LAN UDP replies to ephemeral ports. Tighter,
                       but some IoT device discovery will stop working.
  -h, --help           Show this help.
EOF
}

parse_args() {
  while (($#)); do
    case "$1" in
      --dry-run)     DRY_RUN=1 ;;
      --auto-reboot) AUTO_REBOOT=1 ;;
      --strict-udp)  STRICT_UDP=1 ;;
      --lan)         [[ $# -ge 2 ]] || die "--lan needs a value"; LANS+=("$2"); shift ;;
      --vpn-iface)   [[ $# -ge 2 ]] || die "--vpn-iface needs a value"; VPN_IFACES+=("$2"); shift ;;
      --allow-port)
        [[ $# -ge 2 ]] || die "--allow-port needs a value"
        [[ "$2" =~ ^([0-9]+)/(tcp|udp)$ ]] || die "--allow-port must look like 1883/tcp, got: $2"
        EXTRA_PORTS+=("${BASH_REMATCH[2]}:${BASH_REMATCH[1]}")
        shift ;;
      -h|--help)     usage; exit 0 ;;
      *)             usage >&2; die "Unknown option: $1" ;;
    esac
    shift
  done
}

# ask "question" y|n -> returns 0 for yes. Second argument is the default.
ask() {
  local prompt="$1" default="${2:-n}" reply hint="[y/N]"
  [[ "$default" == y ]] && hint="[Y/n]"
  read -r -p "$prompt $hint " reply </dev/tty || reply=""
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy] ]]
}

# ---------------------------------------------------------------- preflight

# Addresses currently connected to sshd. `ss` is used because sudo strips
# SSH_CONNECTION from the environment.
list_ssh_peers() {
  ss -Htn state established '( sport = :22 )' 2>/dev/null \
    | awk '{print $4}' \
    | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//; s/^::ffff://; s/%.*$//' \
    | sort -u
}

# ip_in_nets IP CIDR... -> returns 0 if IP is inside any of the networks.
ip_in_nets() {
  python3 - "$@" <<'PY'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
sys.exit(0 if any(ip in ipaddress.ip_network(n, strict=False) for n in sys.argv[2:]) else 1)
PY
}

is_private_net() {
  python3 - "$1" <<'PY'
import ipaddress, sys
sys.exit(0 if ipaddress.ip_network(sys.argv[1], strict=False).is_private else 1)
PY
}

preflight() {
  info "Running checks"

  [[ $EUID -eq 0 ]] || die "Run this with sudo: sudo ./harden.sh"
  ADMIN_USER="${SUDO_USER:-}"
  [[ -n "$ADMIN_USER" && "$ADMIN_USER" != root ]] \
    || die "Run this via sudo from your normal user, not from a root shell. The script needs to know which account's SSH key to protect."

  [[ -r /etc/os-release ]] || die "/etc/os-release not found."
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" == "haos" ]] || grep -qi "home assistant" /etc/os-release; then
    die "This is Home Assistant OS, which can't be hardened with this script."
  fi
  [[ "${ID:-}" == debian || "${ID:-}" == raspbian || "${ID_LIKE:-}" == *debian* ]] \
    || die "Unsupported OS: ${PRETTY_NAME:-unknown}. This script needs Debian or Raspberry Pi OS."
  ok "OS: ${PRETTY_NAME:-unknown}"

  local cmd
  for cmd in python3 ss ip systemctl systemd-run tar; do
    command -v "$cmd" >/dev/null || die "Required command not found: $cmd"
  done
  [[ -x /usr/sbin/sshd ]] || die "OpenSSH server isn't installed."
  if ((DRY_RUN == 0)); then
    { : </dev/tty; } 2>/dev/null || die "This script needs an interactive terminal."
  fi

  systemctl is-active --quiet fail2ban && F2B_WAS_ACTIVE=1
  check_authorized_keys
  detect_ssh_users
  detect_network
  detect_docker
  scan_listening_ports
}

# Password login gets disabled, so a usable key has to exist first.
check_authorized_keys() {
  local home keys
  home="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
  keys="$home/.ssh/authorized_keys"
  [[ -s "$keys" ]] || die "$keys is missing or empty. From your Mac run: ssh-copy-id -i ~/.ssh/id_rpi.pub $ADMIN_USER@<pi-address>"
  grep -qE '^[^#]*(ssh-ed25519|ssh-rsa|ecdsa-sha2-|sk-ssh-ed25519|sk-ecdsa-)' "$keys" \
    || die "$keys contains no valid public keys."
  ok "SSH key found for $ADMIN_USER"
}

# Keep access for every account that already has keys, not only the current one.
detect_ssh_users() {
  local file user
  SSH_USERS=("$ADMIN_USER")
  for file in /home/*/.ssh/authorized_keys; do
    [[ -s "$file" ]] || continue
    user="$(basename "$(dirname "$(dirname "$file")")")"
    [[ "$user" == "$ADMIN_USER" ]] && continue
    id "$user" >/dev/null 2>&1 && SSH_USERS+=("$user")
  done
  ok "SSH will be limited to: ${SSH_USERS[*]}"
}

detect_network() {
  local iface lan
  if ((${#LANS[@]} == 0)); then
    iface="$(ip -4 route show default | awk '{print $5; exit}')"
    [[ -n "$iface" ]] || die "No default route found. Pass your network with --lan 192.168.1.0/24"
    lan="$(ip -4 route show dev "$iface" proto kernel scope link | awk '$1 ~ /\// {print $1; exit}')"
    [[ -n "$lan" ]] || die "Couldn't detect the LAN on $iface. Pass it with --lan 192.168.1.0/24"
    LANS=("$lan")
  fi
  for lan in "${LANS[@]}"; do
    is_private_net "$lan" || die "$lan isn't a private network. Refusing to treat it as a trusted LAN."
  done
  ok "Trusted LAN: ${LANS[*]}"

  if grep -q '^IPV6=yes' /etc/default/ufw 2>/dev/null || [[ ! -e /etc/default/ufw ]]; then
    V6_SOURCES=("fe80::/10" "fd00::/8")
  fi

  # Connected clients outside the LAN (for example on another VLAN, or over
  # IPv6 via hostname.local) need their own rule to keep working.
  local peer
  mapfile -t SSH_PEERS < <(list_ssh_peers)
  for peer in "${SSH_PEERS[@]}"; do
    [[ -n "$peer" ]] || continue
    ip_in_nets "$peer" "${LANS[@]}" ${V6_SOURCES[@]+"${V6_SOURCES[@]}"} || OUTSIDE_PEERS+=("$peer")
  done
  if ((${#OUTSIDE_PEERS[@]})); then
    warn "Connected from outside the LAN, will add an SSH rule for: ${OUTSIDE_PEERS[*]}"
  fi
}

detect_docker() {
  if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
    warn "Docker isn't running, so the Docker steps will be skipped."
    return 0
  fi
  HAS_DOCKER=1

  # Bridge networks count as trusted sources, or a bridged container (such as
  # Zigbee2MQTT) would lose access to services on the host.
  local subnet
  while read -r subnet; do
    [[ "$subnet" == *.* ]] && DOCKER_SUBNETS+=("$subnet")
  done < <(docker network ls -q --filter driver=bridge \
             | xargs -r docker network inspect -f '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' \
             | sed '/^$/d')

  HA_CONTAINER="$(docker ps --format '{{.Names}} {{.Image}}' \
                    | awk 'tolower($2) ~ /home-?assistant/ {print $1; exit}')"
  if [[ -z "$HA_CONTAINER" ]]; then
    warn "No running Home Assistant container found."
    return 0
  fi
  HA_NETWORK="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$HA_CONTAINER")"
  ok "Home Assistant container: $HA_CONTAINER (network: $HA_NETWORK)"
  if [[ "$HA_NETWORK" != host ]]; then
    warn "HA isn't using host networking, so HomeKit and mDNS discovery likely won't work."
  fi
}

# rule_covers proto port -> returns 0 if an existing rule already includes it.
rule_covers() {
  local proto="$1" port="$2" spec range low high
  local specs=("${PORT_RULES[@]}" ${EXTRA_PORTS[@]+"${EXTRA_PORTS[@]}"})
  ((STRICT_UDP)) || specs+=("$EPHEMERAL_UDP")
  for spec in "${specs[@]}"; do
    [[ "${spec%%:*}" == "$proto" ]] || continue
    range="${spec#*:}"
    low="${range%%:*}"
    high="${range##*:}"
    ((port >= low && port <= high)) && return 0
  done
  return 1
}

# Allow what is really in use. You weren't sure which integrations need the
# network, and HA runs on the host network, so this is the reliable source.
scan_listening_ports() {
  info "Checking which ports are listening"
  local proto port process default rows
  rows="$(ss -H -tulpn 2>/dev/null \
    | awk '{print $1, $5, $NF}' \
    | grep -vE ' (127\.[0-9.]+|\[::1\]|[^ ]*%lo):[0-9]+ ' \
    | sed -E 's/^([a-z]+) [^ ]*:([0-9]+) /\1 \2 /; s/users:\(\("([^"]+)".*/\1/' \
    | sort -u || true)"

  while read -r proto port process; do
    [[ "${port:-}" =~ ^[0-9]+$ ]] || continue
    # 22 has its own rule. 67/68/546/547 are DHCP client traffic.
    case "$port" in 22|67|68|546|547) continue ;; esac
    # Published Docker ports skip ufw and are handled by DOCKER-USER instead.
    [[ "$process" == docker-proxy ]] && continue
    rule_covers "$proto" "$port" && continue

    # HA and the usual IoT services default to yes, so nothing breaks.
    # Anything unrecognised defaults to closed.
    default=n
    case "$process" in
      python*|hass*|mosquitto*|node*|zigbee2mqtt*) default=y ;;
    esac

    if ((DRY_RUN)); then
      printf '     %s/%s (%s): would ask, default %s\n' "$port" "$proto" "$process" "$default"
    elif ask "  Allow $port/$proto ($process) from the LAN?" "$default"; then
      EXTRA_PORTS+=("$proto:$port")
    fi
  done <<<"$rows"
}

show_plan() {
  local spec
  echo
  info "Plan"
  cat <<EOF
  Packages       install ufw, fail2ban, unattended-upgrades, lynis; apply updates
  Auto updates   daily security updates (auto reboot: $( ((AUTO_REBOOT)) && echo yes || echo no ))
  Kernel         network and memory sysctl hardening (IP forwarding stays on)
  Logging        persistent journal, capped at 200 MB to spare the SD card
  SSH            key-only, no root, users: ${SSH_USERS[*]}
  fail2ban       ban SSH abusers for 1 hour, escalating for repeat offenders
  Firewall       deny all inbound by default, then allow from ${LANS[*]}:
EOF
  printf '                   tcp:22 (rate limited)\n'
  for spec in "${PORT_RULES[@]}" ${EXTRA_PORTS[@]+"${EXTRA_PORTS[@]}"}; do
    printf '                   %s\n' "$spec"
  done
  ((STRICT_UDP)) || printf '                   %s (IoT discovery replies)\n' "$EPHEMERAL_UDP"
  ((${#DOCKER_SUBNETS[@]})) && printf '                 also trusted: Docker networks %s\n' "${DOCKER_SUBNETS[*]}"
  ((${#V6_SOURCES[@]})) && printf '                 also trusted: IPv6 %s\n' "${V6_SOURCES[*]}"
  ((${#VPN_IFACES[@]})) && printf '                 VPN (SSH and HA only): %s\n' "${VPN_IFACES[*]}"
  ((HAS_DOCKER)) && printf '  Docker         block non-LAN access to published container ports\n'
  echo
}

# ---------------------------------------------------- low-risk changes

install_packages() {
  info "Installing packages and applying updates"
  export DEBIAN_FRONTEND=noninteractive
  local opts=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
  apt-get update
  apt-get "${opts[@]}" upgrade
  apt-get "${opts[@]}" install ufw fail2ban python3-systemd unattended-upgrades lynis
  ok "Packages up to date"
}

configure_auto_updates() {
  info "Configuring automatic security updates"
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  local reboot=false
  ((AUTO_REBOOT)) && reboot=true
  cat >/etc/apt/apt.conf.d/52rpi-harden-unattended <<EOF
// Managed by harden.sh. Docker's repo isn't listed, so Docker upgrades
// never restart Home Assistant unattended.
Unattended-Upgrade::Origins-Pattern {
  "origin=Debian,codename=\${distro_codename},label=Debian-Security";
  "origin=Debian,codename=\${distro_codename}-security,label=Debian-Security";
  "origin=Raspbian,codename=\${distro_codename},label=Raspbian";
  "origin=Raspberry Pi Foundation,codename=\${distro_codename},label=Raspberry Pi Foundation";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "$reboot";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  ok "Automatic updates enabled"
}

configure_sysctl() {
  info "Applying kernel hardening"
  # rp_filter is 2 (loose) because strict mode drops valid traffic when
  # Ethernet and Wi-Fi are both connected to the same network.
  # log_martians stays off because IoT traffic would flood the SD card.
  cat >"$SYSCTL_FILE" <<'EOF'
# Managed by harden.sh
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF
  # -e skips any key this kernel doesn't have.
  sysctl -e -q -p "$SYSCTL_FILE" || warn "Some sysctl values couldn't be applied."
  printf '* hard core 0\n' >/etc/security/limits.d/99-rpi-harden.conf
  ok "Kernel settings applied"
}

configure_journald() {
  info "Configuring persistent logs"
  mkdir -p /etc/systemd/journald.conf.d
  cat >/etc/systemd/journald.conf.d/99-rpi-harden.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=200M
EOF
  systemctl restart systemd-journald
  ok "Logs persist across reboots"
}

# None of these are needed for HA. Each is confirmed, since you may use one.
disable_unused_services() {
  info "Checking for unneeded services"
  local unit found=0
  for unit in cups cups-browsed triggerhappy rpcbind rpcbind.socket \
              vncserver-x11-serviced wayvnc xrdp telnet.socket ModemManager; do
    systemctl is-enabled --quiet "$unit" 2>/dev/null || continue
    found=1
    if ask "  Disable $unit?" y; then
      systemctl disable --now "$unit" >/dev/null 2>&1 || warn "Couldn't disable $unit."
      ok "Disabled $unit (undo: sudo systemctl enable --now $unit)"
    fi
  done
  ((found)) || ok "None found"
}

lock_root_account() {
  if [[ "$(passwd -S root | awk '{print $2}')" != L ]]; then
    passwd -l root >/dev/null
    ok "Root password login locked"
  fi
}

fix_ssh_permissions() {
  local home group
  home="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
  group="$(id -gn "$ADMIN_USER")"
  chown "$ADMIN_USER:$group" "$home/.ssh" "$home/.ssh/authorized_keys"
  chmod 700 "$home/.ssh"
  chmod 600 "$home/.ssh/authorized_keys"
}

# ------------------------------------- changes that could lock you out

ask_sudo_password() {
  local status
  status="$(passwd -S "$ADMIN_USER" | awk '{print $2}')"
  grep -lsE "^\s*$ADMIN_USER\s.*NOPASSWD" /etc/sudoers.d/* >/dev/null || return 0
  echo
  warn "$ADMIN_USER can use sudo with no password, so anyone who gets into that account gets root."
  if [[ "$status" != P ]]; then
    warn "$ADMIN_USER has no password set, so this stays as it is. Set one with 'passwd', then re-run."
    return 0
  fi
  if ask "  Require a password for sudo? Only say yes if you know $ADMIN_USER's password." n; then
    REQUIRE_SUDO_PASSWORD=1
  fi
}

take_snapshot() {
  BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_ROOT" "$BACKUP_DIR"
  tar -czpf "$BACKUP_DIR/snapshot.tgz" -C / \
    etc/ssh/sshd_config etc/ssh/sshd_config.d etc/ufw etc/default/ufw etc/sudoers.d etc/fail2ban
  ufw status 2>/dev/null | grep -q '^Status: active' && UFW_WAS_ACTIVE=1

  cat >"$BACKUP_DIR/rollback.sh" <<EOF
#!/bin/bash
# Generated by harden.sh. Restores SSH, firewall, fail2ban and sudoers.
exec >>"$BACKUP_DIR/rollback.log" 2>&1
echo "Rollback started: \$(date)"
systemctl stop $ROLLBACK_UNIT.timer 2>/dev/null
fail2ban-client unban --all 2>/dev/null
rm -f "$SSHD_DROPIN" "$F2B_JAIL"
tar -xzpf "$BACKUP_DIR/snapshot.tgz" -C /
systemctl reload ssh
iptables -F DOCKER-USER 2>/dev/null
ufw --force disable
[ "$UFW_WAS_ACTIVE" = 1 ] && ufw --force enable
if [ "$F2B_WAS_ACTIVE" = 1 ]; then systemctl restart fail2ban; else systemctl disable --now fail2ban; fi
echo "Rollback finished: \$(date)"
EOF
  chmod 700 "$BACKUP_DIR/rollback.sh"
  ok "Backup saved to $BACKUP_DIR"
}

arm_rollback() {
  systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
  systemctl reset-failed "$ROLLBACK_UNIT.service" 2>/dev/null || true
  systemd-run --quiet --unit="$ROLLBACK_UNIT" --on-active="$ROLLBACK_SECONDS" \
    --timer-property=AccuracySec=1s /bin/bash "$BACKUP_DIR/rollback.sh"
  IN_RISKY_SECTION=1
  ok "Safety timer armed: changes revert in $((ROLLBACK_SECONDS / 60)) minutes unless confirmed"
}

rollback_now() {
  IN_RISKY_SECTION=0
  warn "Reverting SSH and firewall changes..."
  bash "$BACKUP_DIR/rollback.sh" || true
  warn "Reverted. Log: $BACKUP_DIR/rollback.log"
}

configure_ssh() {
  info "Hardening SSH"
  # The filename sorts first because sshd uses the first value it finds. That
  # beats files like 50-cloud-init.conf, which can turn passwords back on.
  #
  # MaxAuthTries is 4 rather than 2-3 because every key your SSH client offers
  # counts as a try, and you have several keys on your Mac.
  # AllowTcpForwarding is "local" so ssh -L and VS Code Remote keep working.
  cat >"$SSHD_DROPIN" <<EOF
# Managed by harden.sh
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AuthenticationMethods publickey
AllowUsers ${SSH_USERS[*]}
MaxAuthTries 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding local
PermitTunnel no
LogLevel VERBOSE
EOF
  chmod 644 "$SSHD_DROPIN"
  mkdir -p /run/sshd
  /usr/sbin/sshd -t || die "The new SSH config is invalid."

  # Confirm the settings really took effect, in case a config overrides them.
  local effective
  effective="$(/usr/sbin/sshd -T -C "user=$ADMIN_USER,host=localhost,addr=127.0.0.1")"
  grep -qx 'passwordauthentication no' <<<"$effective" || die "SSH password login is still on after the change."
  grep -qx 'permitrootlogin no' <<<"$effective" || die "SSH root login is still on after the change."
  systemctl reload ssh
  ok "SSH is key-only"
}

configure_fail2ban() {
  info "Configuring fail2ban"
  # The LAN isn't ignored, because a compromised IoT device is one of the more
  # likely attackers. Your current address is, so a ban can't hit this session.
  local ignore="127.0.0.1/8 ::1"
  ((${#SSH_PEERS[@]})) && ignore+=" ${SSH_PEERS[*]}"
  cat >"$F2B_JAIL" <<EOF
# Managed by harden.sh
[DEFAULT]
ignoreip = $ignore
bantime = 1h
bantime.increment = true
bantime.maxtime = 1w
findtime = 10m
maxretry = 5
banaction = iptables-multiport
banaction_allports = iptables-allports

[sshd]
enabled = true
backend = systemd
EOF
  systemctl enable fail2ban >/dev/null 2>&1
  systemctl restart fail2ban
  ok "fail2ban is protecting SSH"
}

configure_docker_firewall() {
  ((HAS_DOCKER)) || return 0
  info "Restricting published Docker ports"
  # Docker publishes ports through its own rules, which skip ufw entirely. This
  # adds the LAN restriction in DOCKER-USER, the chain Docker keeps for this.
  # Containers on host networking, likely including HA, use the ufw rules.
  local tmp lan iface
  tmp="$(mktemp)"
  sed "/^$DOCKER_BEGIN\$/,/^$DOCKER_END\$/d" "$UFW_AFTER" >"$tmp"
  {
    echo "$DOCKER_BEGIN"
    echo "*filter"
    echo ":DOCKER-USER - [0:0]"
    echo "-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"
    echo "-A DOCKER-USER -i docker+ -j RETURN"
    echo "-A DOCKER-USER -i br-+ -j RETURN"
    for lan in "${LANS[@]}"; do
      echo "-A DOCKER-USER -s $lan -j RETURN"
    done
    for iface in ${VPN_IFACES[@]+"${VPN_IFACES[@]}"}; do
      echo "-A DOCKER-USER -i $iface -j RETURN"
    done
    echo "-A DOCKER-USER -j DROP"
    echo "COMMIT"
    echo "$DOCKER_END"
  } >>"$tmp"
  cat "$tmp" >"$UFW_AFTER"
  rm -f "$tmp"
}

allow_from() {
  local source="$1" spec proto port
  ufw limit proto tcp from "$source" to any port 22 comment 'SSH' >/dev/null
  for spec in "${PORT_RULES[@]}" ${EXTRA_PORTS[@]+"${EXTRA_PORTS[@]}"}; do
    proto="${spec%%:*}"
    port="${spec#*:}"
    ufw allow proto "$proto" from "$source" to any port "$port" comment 'harden.sh' >/dev/null
  done
  if ((STRICT_UDP == 0)); then
    ufw allow proto udp from "$source" to any port "${EPHEMERAL_UDP#*:}" comment 'IoT discovery' >/dev/null
  fi
}

configure_firewall() {
  info "Configuring firewall"
  FW_SOURCES=("${LANS[@]}" ${DOCKER_SUBNETS[@]+"${DOCKER_SUBNETS[@]}"} ${V6_SOURCES[@]+"${V6_SOURCES[@]}"})

  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  ufw default deny routed >/dev/null
  ufw logging low >/dev/null

  # SSH rules go in before the firewall is switched on.
  local source peer iface
  for source in "${FW_SOURCES[@]}"; do
    allow_from "$source"
  done
  for peer in ${OUTSIDE_PEERS[@]+"${OUTSIDE_PEERS[@]}"}; do
    ufw allow proto tcp from "$peer" to any port 22 comment 'current SSH client' >/dev/null
  done
  for iface in ${VPN_IFACES[@]+"${VPN_IFACES[@]}"}; do
    ufw allow in on "$iface" to any port 22 proto tcp comment 'VPN SSH' >/dev/null
    ufw allow in on "$iface" to any port 8123 proto tcp comment 'VPN HA' >/dev/null
  done

  configure_docker_firewall
  ufw --force enable >/dev/null
  ufw reload >/dev/null
  ok "Firewall is on"
}

apply_sudo_password() {
  ((REQUIRE_SUDO_PASSWORD)) || return 0
  local file
  while read -r file; do
    rm -f "$file"
    ok "Removed $file"
  done < <(grep -lsE "^\s*$ADMIN_USER\s.*NOPASSWD" /etc/sudoers.d/* || true)
  visudo -c >/dev/null || die "The sudoers config is invalid."
}

confirm_access() {
  local address reply="" remaining=$((ROLLBACK_SECONDS - 60))
  address="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')"
  cat <<EOF

================================================================
  Keep this window open and test from a NEW terminal on your Mac:

    ssh -i ~/.ssh/id_rpi -o IdentitiesOnly=yes $ADMIN_USER@${address:-<pi-address>}
EOF
  ((REQUIRE_SUDO_PASSWORD)) && printf '\n  Then check sudo there:  sudo -k && sudo true\n'
  cat <<EOF

  Also check that these still work:
    - Home Assistant in a browser (port 8123)
    - An accessory in the Apple Home app
    - A Zigbee device

  Type "keep" to save the changes. Anything else reverts them.
  Reverting automatically in about $((remaining / 60)) minutes.
================================================================
EOF
  read -r -t "$remaining" -p "> " reply </dev/tty || true
  if [[ "$reply" != keep ]]; then
    rollback_now
    exit 1
  fi
  systemctl stop "$ROLLBACK_UNIT.timer"
  IN_RISKY_SECTION=0
  ok "Changes saved, safety timer cancelled"
}

# --------------------------------------------------------------- report

# Things only you can decide. These are reported, not changed.
report() {
  echo
  info "Things to review yourself"
  local any=0 members name config

  if [[ "$ADMIN_USER" == pi ]]; then
    warn "You're using the well-known 'pi' username. A custom username is safer."
    any=1
  fi

  if ((HAS_DOCKER)); then
    members="$(getent group docker | cut -d: -f4)"
    if [[ -n "$members" ]]; then
      warn "The docker group ($members) is effectively root on this machine."
      any=1
    fi
    while read -r name; do
      [[ -n "$name" ]] || continue
      if [[ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$name")" == true ]]; then
        warn "Container $name runs privileged. For the Zigbee dongle, passing only the device (devices: /dev/serial/by-id/...) is safer, though HA Bluetooth may need extra setup."
        any=1
      fi
    done < <(docker ps --format '{{.Names}}')

    if [[ -n "$HA_CONTAINER" ]]; then
      config="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/config"}}{{.Source}}{{end}}{{end}}' "$HA_CONTAINER")"
      if [[ -n "$config" && -f "$config/secrets.yaml" ]] \
         && [[ -n "$(find "$config/secrets.yaml" -perm /o+r)" ]]; then
        warn "$config/secrets.yaml is world-readable. Fix with: sudo chmod 600 '$config/secrets.yaml'"
        any=1
      fi
    fi
    if ss -Htln 2>/dev/null | grep -qE ':(2375|2376)\b'; then
      warn "The Docker API is listening on the network, which gives root access. Turn it off."
      any=1
    fi
  fi

  if [[ -f /var/run/reboot-required ]]; then
    warn "A reboot is needed to finish updates: sudo reboot"
    any=1
  fi
  ((any)) || ok "Nothing to flag"

  cat <<EOF

Done. Useful commands:
  sudo ufw status numbered            firewall rules
  sudo fail2ban-client status sshd    current bans
  sudo lynis audit system             full security audit
  sudo bash $BACKUP_DIR/rollback.sh
                                      undo the SSH and firewall changes
EOF
}

on_error() {
  local rc=$? line=$1
  warn "Failed at line $line (exit $rc)."
  ((IN_RISKY_SECTION)) && rollback_now
  exit "$rc"
}

on_interrupt() {
  ((IN_RISKY_SECTION)) && rollback_now
  exit 130
}

main() {
  parse_args "$@"
  trap 'on_error $LINENO' ERR
  trap on_interrupt INT TERM

  echo "harden.sh v$SCRIPT_VERSION"
  preflight
  show_plan

  if ((DRY_RUN)); then
    info "Dry run finished. Nothing was changed."
    exit 0
  fi
  ask "Apply these changes?" n || { echo "Cancelled."; exit 0; }
  ask_sudo_password

  install_packages
  configure_auto_updates
  configure_sysctl
  configure_journald
  disable_unused_services
  lock_root_account
  fix_ssh_permissions

  take_snapshot
  arm_rollback
  configure_ssh
  configure_fail2ban
  configure_firewall
  apply_sudo_password
  confirm_access

  report
}

main "$@"

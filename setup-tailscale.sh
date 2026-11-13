#!/usr/bin/env bash
#
# setup-tailscale.sh - install Tailscale on the Pi and open SSH and Home
# Assistant to the tailnet only.
#
# Safe to re-run. Each step checks the current state first and only changes
# what differs. Run it with --dry-run to see what it would do.
#
# What it does:
#   - Adds Tailscale's apt repo and installs tailscale, so it gets updated with
#     the rest of the system (including by unattended-upgrades' normal runs)
#   - Logs the Pi into your tailnet, or updates its settings if already logged in
#   - Allows SSH (22) and HA (8123) in on tailscale0, matching harden.sh's
#     --vpn-iface rules, and lets tailscale0 through harden.sh's Docker block
#
# Settings it applies, and why:
#   --ssh=false          Keep using OpenSSH, so harden.sh's key-only sshd
#                        config and fail2ban still apply.
#   --accept-dns=false   The Pi doesn't need to resolve tailnet names. Leaving
#                        DNS alone stops Tailscale rewriting /etc/resolv.conf,
#                        which Docker containers copy.

set -Eeuo pipefail

readonly IFACE="tailscale0"
readonly KEYRING="/usr/share/keyrings/tailscale-archive-keyring.gpg"
readonly APT_LIST="/etc/apt/sources.list.d/tailscale.list"
readonly UFW_AFTER="/etc/ufw/after.rules"
readonly DOCKER_BEGIN="# BEGIN rpi-harden docker"
readonly DOCKER_END="# END rpi-harden docker"
readonly DOCKER_RULE="-A DOCKER-USER -i $IFACE -j RETURN"
readonly MOSH_PORTS="60000:61000"

DRY_RUN=0
MOSH=0
TS_HOSTNAME=""
REPO_URL=""
CHANGED=0

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ok\033[0m %s\n' "$*"; }
todo() { printf '\033[1;33m ->\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: sudo ./setup-tailscale.sh [options]

  --dry-run          Show what would change. Changes nothing.
  --hostname NAME    Name of the Pi on the tailnet. Defaults to its hostname.
  --mosh             Also install mosh and allow its UDP ports on tailscale0.
  -h, --help         Show this help.
EOF
}

parse_args() {
  while (($#)); do
    case "$1" in
      --dry-run)  DRY_RUN=1 ;;
      --mosh)     MOSH=1 ;;
      --hostname) [[ $# -ge 2 ]] || die "--hostname needs a value"; TS_HOSTNAME="$2"; shift ;;
      -h|--help)  usage; exit 0 ;;
      *)          usage >&2; die "Unknown option: $1" ;;
    esac
    shift
  done
  TS_HOSTNAME="${TS_HOSTNAME:-$(hostname -s)}"
  [[ "$TS_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] \
    || die "Hostname must be letters, digits and dashes, got: $TS_HOSTNAME"
}

# changing "description" -> returns 0 if the change should be applied now.
# In a dry run it only prints the change.
changing() {
  CHANGED=1
  if ((DRY_RUN)); then
    todo "Would $1"
    return 1
  fi
  info "${1^}"
}

preflight() {
  ((EUID == 0)) || die "Run this with sudo."
  command -v systemctl >/dev/null || die "systemd is required."
  command -v python3 >/dev/null || die "python3 is required."

  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    debian|raspbian|ubuntu) ;;
    *) die "Unsupported OS: ${ID:-unknown}. Expected Debian or Raspberry Pi OS." ;;
  esac
  [[ -n "${VERSION_CODENAME:-}" ]] || die "Can't tell the OS release from /etc/os-release."
  REPO_URL="https://pkgs.tailscale.com/stable/$ID/$VERSION_CODENAME"
}

# --------------------------------------------------------------- install

install_repo() {
  if ! command -v curl >/dev/null; then
    if changing "install curl"; then
      apt-get update >/dev/null
      apt-get install -y curl >/dev/null
    else
      todo "Would add the Tailscale apt repo ($REPO_URL)"
      return 0
    fi
  fi

  local tmp
  tmp="$(mktemp -d)"
  if ! curl -fsSL "$REPO_URL.noarmor.gpg" -o "$tmp/key" \
    || ! curl -fsSL "$REPO_URL.tailscale-keyring.list" -o "$tmp/list"; then
    rm -rf "$tmp"
    die "Couldn't download Tailscale's apt repo files from $REPO_URL"
  fi

  if cmp -s "$tmp/key" "$KEYRING" && cmp -s "$tmp/list" "$APT_LIST"; then
    ok "Tailscale apt repo is set up"
  elif changing "add the Tailscale apt repo ($REPO_URL)"; then
    install -m 0644 "$tmp/key" "$KEYRING"
    install -m 0644 "$tmp/list" "$APT_LIST"
    apt-get update >/dev/null
  fi
  rm -rf "$tmp"
}

install_packages() {
  local pkgs=(tailscale) missing=() pkg
  ((MOSH)) && pkgs+=(mosh)
  for pkg in "${pkgs[@]}"; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed' \
      || missing+=("$pkg")
  done
  if ((${#missing[@]} == 0)); then
    ok "Installed: ${pkgs[*]}"
    return 0
  fi
  if changing "install ${missing[*]}"; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}" >/dev/null
  fi
}

enable_service() {
  if systemctl is-enabled --quiet tailscaled 2>/dev/null \
    && systemctl is-active --quiet tailscaled; then
    ok "tailscaled is running"
    return 0
  fi
  if changing "enable and start tailscaled"; then
    systemctl enable --now tailscaled >/dev/null 2>&1
  fi
}

# ----------------------------------------------------------------- login

# ts_field FIELD -> prints a value from `tailscale status --json`, or nothing.
ts_field() {
  tailscale status --json 2>/dev/null | python3 -c '
import json, sys
try:
    s = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
self = s.get("Self") or {}
v = {
    "state": s.get("BackendState", ""),
    "dns": (self.get("DNSName") or "").rstrip("."),
    "ip4": next((ip for ip in self.get("TailscaleIPs") or [] if "." in ip), ""),
}[sys.argv[1]]
print(v)
' "$1" || true
}

# pref NAME -> prints a value from `tailscale debug prefs`, or nothing.
pref() {
  tailscale debug prefs 2>/dev/null \
    | python3 -c 'import json, sys; print(str(json.load(sys.stdin).get(sys.argv[1], "")).lower())' "$1" \
    2>/dev/null || true
}

log_in() {
  if ! command -v tailscale >/dev/null; then
    ((DRY_RUN)) && todo "Would connect to Tailscale as $TS_HOSTNAME"
    return 0
  fi

  local state
  state="$(ts_field state)"
  if [[ "$state" != Running ]]; then
    if changing "connect to Tailscale as $TS_HOSTNAME"; then
      echo "    Open the URL below in a browser and sign in. This waits until you do."
      tailscale up --hostname="$TS_HOSTNAME" --ssh=false --accept-dns=false
    fi
    return 0
  fi
  ok "Logged in to Tailscale"

  # Already up: correct any settings that drifted. `tailscale set` changes
  # only the named settings, unlike `tailscale up`, which resets the rest.
  local args=()
  [[ "$(pref Hostname)" == "$(tr '[:upper:]' '[:lower:]' <<<"$TS_HOSTNAME")" ]] \
    || args+=(--hostname="$TS_HOSTNAME")
  [[ "$(pref RunSSH)" == false ]] || args+=(--ssh=false)
  [[ "$(pref CorpDNS)" == false ]] || args+=(--accept-dns=false)
  if ((${#args[@]} == 0)); then
    ok "Tailscale settings are correct"
    return 0
  fi
  if changing "update Tailscale settings: ${args[*]}"; then
    tailscale set "${args[@]}"
  fi
}

# -------------------------------------------------------------- firewall

ufw_active() {
  command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'
}

# ufw_allow PORT PROTO COMMENT -> adds an allow rule on tailscale0 if missing.
ufw_allow() {
  local port="$1" proto="$2" comment="$3"
  if ufw show added 2>/dev/null \
    | grep -qE "^ufw allow in on $IFACE to any port $port proto $proto( |$)"; then
    ok "Firewall allows $port/$proto on $IFACE"
    return 0
  fi
  if changing "allow $port/$proto in on $IFACE"; then
    ufw allow in on "$IFACE" to any port "$port" proto "$proto" comment "$comment" >/dev/null
  fi
}

configure_firewall() {
  if ! ufw_active; then
    warn "ufw isn't active, so the firewall was skipped. Run harden.sh with --vpn-iface $IFACE."
    return 0
  fi

  # Same rules and comments as harden.sh --vpn-iface, so the two don't duplicate.
  ufw_allow 22 tcp 'VPN SSH'
  ufw_allow 8123 tcp 'VPN HA'
  ((MOSH)) && ufw_allow "$MOSH_PORTS" udp 'VPN mosh'

  # harden.sh blocks non-LAN access to published Docker ports. Let tailscale0
  # through, the same way harden.sh does with --vpn-iface. Containers on host
  # networking, likely including HA, only need the ufw rules above.
  if ! grep -qxF "$DOCKER_BEGIN" "$UFW_AFTER" 2>/dev/null; then
    ok "No harden.sh Docker block to update"
  elif sed -n "/^$DOCKER_BEGIN\$/,/^$DOCKER_END\$/p" "$UFW_AFTER" | grep -qxF -- "$DOCKER_RULE"; then
    ok "Docker firewall lets $IFACE through"
  elif changing "let $IFACE through the Docker firewall"; then
    sed -n "/^$DOCKER_BEGIN\$/,/^$DOCKER_END\$/p" "$UFW_AFTER" \
      | grep -qxF -- "-A DOCKER-USER -j DROP" \
      || die "The Docker block in $UFW_AFTER doesn't look like harden.sh's. Re-run harden.sh with --vpn-iface $IFACE."
    cp -p "$UFW_AFTER" "$UFW_AFTER.bak-tailscale"
    sed -i "/^$DOCKER_BEGIN\$/,/^$DOCKER_END\$/ s/^-A DOCKER-USER -j DROP\$/$DOCKER_RULE\n&/" "$UFW_AFTER"
    ufw reload >/dev/null
  fi
}

# ---------------------------------------------------------------- report

report() {
  echo
  if ((DRY_RUN)); then
    ((CHANGED)) && info "Dry run finished. Nothing was changed." \
      || info "Dry run finished. Everything is already set up."
    return 0
  fi
  ((CHANGED)) || info "Everything was already set up. Nothing changed."

  local dns ip4 user
  dns="$(ts_field dns)"
  ip4="$(ts_field ip4)"
  user="${SUDO_USER:-$(id -un)}"
  [[ -n "$dns" ]] || { warn "Tailscale isn't logged in yet. Re-run this script."; return 0; }

  cat <<EOF

================================================================
  The Pi is on your tailnet as $dns ($ip4)

  From a device signed in to Tailscale:
    ssh -i ~/.ssh/id_rpi $user@$TS_HOSTNAME
    http://$TS_HOSTNAME:8123
EOF
  ((MOSH)) && printf '    mosh --ssh="ssh -i ~/.ssh/id_rpi" %s@%s\n' "$user" "$TS_HOSTNAME"
  cat <<EOF

  Short names like "$TS_HOSTNAME" need MagicDNS. If they don't resolve, use
  $dns, or $ip4.

  Do these once, by hand:
    1. Disable key expiry for this Pi, or it drops off the tailnet in
       180 days: https://login.tailscale.com/admin/machines
    2. In the HA Companion app, set the External URL to
       http://$dns:8123

  If you re-run harden.sh, pass --vpn-iface $IFACE. Without it the
  Docker firewall stops letting $IFACE through.
================================================================
EOF
}

main() {
  parse_args "$@"
  trap 'die "Failed on line $LINENO."' ERR
  preflight
  ((DRY_RUN)) && info "Dry run: checking only"

  info "Installing Tailscale"
  install_repo
  install_packages
  enable_service

  info "Connecting to the tailnet"
  log_in

  info "Configuring firewall"
  configure_firewall

  report
}

main "$@"

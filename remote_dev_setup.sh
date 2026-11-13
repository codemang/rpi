#!/usr/bin/env bash
#
# remote_dev_setup.sh - set up the Pi as a Claude Code dev box you can drive
# from your phone: Claude Code, tmux, and Moshi's moshi-hook.
#
# Run it as your normal user, not with sudo. It asks for sudo itself for the
# few steps that need it. Safe to re-run: each step checks first and skips
# what's already done. Run with --dry-run to see what it would do.
#
# What it does:
#   - Installs git, tmux and curl from apt
#   - Installs Claude Code with Anthropic's native installer into ~/.local/bin.
#     Native installs update themselves in the background.
#   - Installs moshi-hook into ~/.local/bin, adds its hooks to Claude Code
#     only, and runs it as a systemd user service. With --pair, it pairs it
#     with the app and turns on end-to-end encryption for what it sends to
#     Moshi's server (encryption needs pairing first).
#   - Turns on systemd lingering for your user, so the moshi-hook service
#     runs after a reboot without anyone logging in
#
# moshi-hook also updates itself. Turn that off with: moshi-hook set auto-update off
#
# What moshi-hook sends off the Pi: short summaries (up to 200 characters of
# each prompt, 80 of each response, 256 of each approval request) plus
# metadata such as project names. End-to-end encryption hides the text from
# Moshi's server. Full transcripts and code stay on the Pi.
#
# Mosh itself is installed by: sudo bash setup-tailscale.sh --mosh

set -Eeuo pipefail

readonly CLAUDE_INSTALLER="https://claude.ai/install.sh"
readonly MOSHI_INSTALLER="https://getmoshi.app/install.sh"
readonly CLAUDE_SETTINGS="$HOME/.claude/settings.json"
readonly MOSHI_SERVICE="moshi-hook.service"
readonly BIN_DIR="$HOME/.local/bin"
readonly APT_PACKAGES=(git tmux curl python3)

DRY_RUN=0
SKIP_MOSHI=0
PAIR=0
CHANGED=0
TMP_DIR=""

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ok\033[0m %s\n' "$*"; }
todo() { printf '\033[1;33m ->\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: ./remote_dev_setup.sh [options]     (as your normal user, not sudo)

  --dry-run           Show what would change. Changes nothing.
  --pair              Pair moshi-hook with the Moshi app, then turn on
                      end-to-end encryption. Asks for the pairing token from
                      the app's settings (under Integrations or Hooks).
  --no-moshi          Only install Claude Code and tmux.
  -h, --help          Show this help.
EOF
}

parse_args() {
  while (($#)); do
    case "$1" in
      --dry-run)    DRY_RUN=1 ;;
      --no-moshi)   SKIP_MOSHI=1 ;;
      --pair)       PAIR=1 ;;
      -h|--help)    usage; exit 0 ;;
      *)            usage >&2; die "Unknown option: $1" ;;
    esac
    shift
  done
}

# changing "description" -> returns 0 if the change should be applied now.
# In a dry run it only prints the change.
changing() {
  CHANGED=1
  if ((DRY_RUN)); then
    todo "Would ${1,}"
    return 1
  fi
  info "$1"
}

cleanup() { [[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"; }

preflight() {
  ((EUID != 0)) || die "Run this as your normal user, not with sudo. It installs into your home directory."
  [[ "$(uname -s)" == Linux ]] || die "This script is for the Pi (Linux)."
  command -v systemctl >/dev/null || die "systemd is required."
  command -v sudo >/dev/null || die "sudo is required."

  case "$(uname -m)" in
    aarch64|arm64|x86_64) ;;
    *) die "Claude Code needs a 64-bit OS (ARM64 or x64), but this is $(uname -m). Use 64-bit Raspberry Pi OS." ;;
  esac

  local mem_kb
  mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  if ((mem_kb < 3500000)); then
    warn "This Pi has $((mem_kb / 1024)) MB of RAM. Claude Code recommends 4 GB or more."
  fi

  TMP_DIR="$(mktemp -d)"
  trap cleanup EXIT

  # Installers put binaries here. Debian's ~/.profile adds it to PATH at
  # login once it exists. Add it now so this run can find them.
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) export PATH="$BIN_DIR:$PATH" ;;
  esac
}

# download URL FILE -> downloads over HTTPS, or dies.
download() {
  curl -fsSL --proto '=https' --tlsv1.2 "$1" -o "$2" || die "Couldn't download $1"
}

# ------------------------------------------------------------------- apt

install_apt_packages() {
  local missing=() pkg
  for pkg in "${APT_PACKAGES[@]}"; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed' \
      || missing+=("$pkg")
  done
  if ((${#missing[@]} == 0)); then
    ok "Installed: ${APT_PACKAGES[*]}"
    return 0
  fi
  if changing "Install ${missing[*]}"; then
    sudo apt-get update >/dev/null
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}" >/dev/null
  fi
}

# ----------------------------------------------------------- Claude Code

install_claude() {
  if command -v claude >/dev/null; then
    ok "Claude Code is installed ($(claude --version 2>/dev/null | head -1)). It updates itself."
    return 0
  fi
  if ! changing "Install Claude Code"; then
    return 0
  fi
  # Download first rather than piping into bash, so a cut-off download can't
  # run as a partial script.
  download "$CLAUDE_INSTALLER" "$TMP_DIR/claude-install.sh"
  bash "$TMP_DIR/claude-install.sh"
  hash -r
  command -v claude >/dev/null || die "Claude Code installed, but 'claude' isn't in $BIN_DIR."
  ok "Installed $(claude --version | head -1)"
}

# ------------------------------------------------------------ moshi-hook

install_moshi_hook() {
  if command -v moshi-hook >/dev/null; then
    ok "moshi-hook is installed ($(moshi-hook version 2>/dev/null | head -1))"
    return 0
  fi
  if ! changing "Install moshi-hook"; then
    return 0
  fi
  download "$MOSHI_INSTALLER" "$TMP_DIR/moshi-install.sh"
  # The service is started later, after lingering is on.
  INSTALL_DIR="$BIN_DIR" MOSHI_HOOK_SKIP_SERVICE=1 sh "$TMP_DIR/moshi-install.sh"
  hash -r
  command -v moshi-hook >/dev/null || die "moshi-hook installed, but it isn't in $BIN_DIR."
}

install_moshi_claude_hooks() {
  if ! command -v moshi-hook >/dev/null; then
    ((DRY_RUN)) && todo "Would add moshi-hook's hooks to Claude Code"
    return 0
  fi
  if grep -qs 'moshi-hook' "$CLAUDE_SETTINGS"; then
    ok "Claude Code has moshi-hook's hooks"
    return 0
  fi
  # Claude Code only. Without --target it also writes hooks for every other
  # agent it supports.
  if changing "Add moshi-hook's hooks to Claude Code ($CLAUDE_SETTINGS)"; then
    moshi-hook install --target claude
  fi
}

enable_linger() {
  if [[ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" == yes ]]; then
    ok "User services keep running without a login"
    return 0
  fi
  if changing "Let $USER's user services run without a login (loginctl enable-linger)"; then
    sudo loginctl enable-linger "$USER"
  fi
}

install_moshi_service() {
  if systemctl --user is-enabled --quiet "$MOSHI_SERVICE" 2>/dev/null \
    && systemctl --user is-active --quiet "$MOSHI_SERVICE" 2>/dev/null; then
    ok "moshi-hook service is running"
    return 0
  fi
  if ! command -v moshi-hook >/dev/null; then
    ((DRY_RUN)) && todo "Would install and start the moshi-hook service"
    return 0
  fi
  if changing "Install and start the moshi-hook service"; then
    moshi-hook service install
  fi
}

# moshi_status FIELD -> prints "paired" (true/false) or "e2ee" (off/on/...)
# from `moshi-hook status --json`, or nothing if it can't be read.
moshi_status() {
  moshi-hook status --json 2>/dev/null | python3 -c '
import json, sys
try:
    s = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
v = {"paired": str(s.get("paired", "")).lower(),
     "e2ee": (s.get("e2ee") or {}).get("policy", "")}[sys.argv[1]]
print(v)
' "$1" || true
}

pair_moshi() {
  if ! command -v moshi-hook >/dev/null; then
    ((DRY_RUN && PAIR)) && todo "Would pair moshi-hook with the Moshi app"
    return 0
  fi
  if [[ "$(moshi_status paired)" == true ]]; then
    ok "moshi-hook is paired with the Moshi app"
    return 0
  fi
  if ((PAIR == 0)); then
    warn "moshi-hook isn't paired yet. Re-run with --pair when you have the token."
    return 0
  fi
  if changing "Pair moshi-hook with the Moshi app"; then
    local token=""
    # Read without echo, so the token stays off the screen and out of history.
    read -r -s -p "    Paste the pairing token from Moshi's settings: " token </dev/tty || true
    echo
    [[ -n "$token" ]] || die "No token entered."
    moshi-hook pair --token "$token" --store file
  fi
}

enable_moshi_e2ee() {
  if ! command -v moshi-hook >/dev/null || [[ "$(moshi_status paired)" != true ]]; then
    ((DRY_RUN && PAIR)) && todo "Would turn on moshi-hook end-to-end encryption after pairing"
    return 0
  fi
  local policy
  policy="$(moshi_status e2ee)"
  if [[ -n "$policy" && "$policy" != off ]]; then
    ok "moshi-hook end-to-end encryption is on"
    return 0
  fi
  if changing "Turn on moshi-hook end-to-end encryption"; then
    moshi-hook e2ee enable
  fi
}

# ---------------------------------------------------------------- report

report() {
  echo
  if ((DRY_RUN)); then
    if ((CHANGED)); then
      info "Dry run finished. Nothing was changed."
    else
      info "Dry run finished. Everything is already set up."
    fi
    return 0
  fi
  ((CHANGED)) || info "Everything was already set up. Nothing changed."

  cat <<EOF

================================================================
  Next steps, by hand:

  1. Sign in to Claude Code once:
       tmux new -A -s claude
       claude            then /login, and open the URL on any device
EOF
  if ((SKIP_MOSHI == 0)); then
    if ((PAIR == 0)); then
      cat <<EOF

  2. Pair moshi-hook with your phone. Copy the pairing token from
     Moshi's settings (under Integrations or Hooks), then run:
       ./remote_dev_setup.sh --pair
     This also turns on end-to-end encryption.
EOF
    fi
    cat <<EOF

  Check moshi-hook any time with:
       moshi-hook status
       moshi-hook doctor
EOF
  fi
  cat <<EOF

  In Moshi, add the Pi with New Connection (not Easy Pair). See
  "Claude Code from your phone with Moshi" in the README.
================================================================
EOF
}

main() {
  parse_args "$@"
  trap 'die "Failed on line $LINENO."' ERR
  preflight
  ((DRY_RUN)) && info "Dry run: checking only"

  info "Installing packages"
  install_apt_packages

  info "Installing Claude Code"
  install_claude

  if ((SKIP_MOSHI == 0)); then
    info "Setting up moshi-hook"
    install_moshi_hook
    install_moshi_claude_hooks
    enable_linger
    install_moshi_service
    pair_moshi
    enable_moshi_e2ee
  fi

  report
}

main "$@"

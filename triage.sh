#!/usr/bin/env bash
# triage.sh — real-time diagnostic capture for an AI agent (or you) to analyse
# Supports: Arch Linux, Debian/Ubuntu, macOS (Intel + Apple Silicon)
# Run on any machine mid-install, post-install, or during troubleshooting
#
# Usage:
#   bash triage.sh              — full snapshot
#   bash triage.sh --boot       — boot/init failures only
#   bash triage.sh --net        — network only
#   bash triage.sh --disk       — disk/partition only
#   bash triage.sh --packages   — package manager only
#
# Linux — mount USB so regular user can write reports:
#   sudo mount -o uid=$(id -u),gid=$(id -g) /dev/sdX1 /mnt/usb
#
# macOS — USB mounts automatically; run directly:
#   bash /Volumes/USB/usb-triage/triage.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="${SCRIPT_DIR}/reports"
OS_TYPE="$(uname)"  # Linux or Darwin

# Create reports dir — try directly, fall back to sudo (Linux FAT32 mounted as root)
mkdir -p "$REPORT_DIR" 2>/dev/null || sudo mkdir -p "$REPORT_DIR" 2>/dev/null || true

HOSTNAME_STR=$(hostname 2>/dev/null | sed 's/\.local//' || echo "unknown")
TIMESTAMP=$(date '+%Y-%m-%dT%H-%M-%S')
REPORT_FILE="${REPORT_DIR}/${HOSTNAME_STR}-${TIMESTAMP}.txt"

# ── Formatting ────────────────────────────────────────────────────────────────
BOLD='\033[1m'; CYAN='\033[0;36m'; RED='\033[0;31m'
YELLOW='\033[0;33m'; GREEN='\033[0;32m'; DIM='\033[2m'; RESET='\033[0m'

output=""
section() {
  local title="$1"
  echo -e "\n${BOLD}${CYAN}━━━ $title ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  output+=$'\n'"### $title"$'\n'
}
cap() {
  local out
  out=$(eval "$1" 2>&1 || true)
  echo -e "${DIM}${out}${RESET}"
  output+="$out"$'\n'
}
note() { echo -e "  ${YELLOW}⚠${RESET}  $1"; output+="[NOTE] $1"$'\n'; }
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; output+="[OK] $1"$'\n'; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; output+="[ERR] $1"$'\n'; }

# ── Header ────────────────────────────────────────────────────────────────────
print_header() {
  echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════════╗"
  echo -e "║  USB TRIAGE — ${TIMESTAMP}  ║"
  echo -e "╚══════════════════════════════════════════════╝${RESET}"
  echo -e "  OS: ${OS_TYPE} | Host: ${HOSTNAME_STR}\n"
  output+="USB TRIAGE — ${HOSTNAME_STR} — ${TIMESTAMP} — ${OS_TYPE}"$'\n'
}

# ── SYSTEM ────────────────────────────────────────────────────────────────────
section_system() {
  section "SYSTEM"
  cap "uname -a"
  cap "uptime"
  cap "whoami && id"

  if [[ "$OS_TYPE" == "Darwin" ]]; then
    cap "sw_vers"
    local mem_bytes chip
    mem_bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
    chip=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || \
           system_profiler SPHardwareDataType 2>/dev/null | grep "Chip\|Processor" | head -2 || echo "unknown")
    echo -e "  ${DIM}Memory: $((mem_bytes / 1024 / 1024)) MB total${RESET}"
    echo -e "  ${DIM}CPU: ${chip}${RESET}"
    output+="Memory: $((mem_bytes / 1024 / 1024)) MB | CPU: ${chip}"$'\n'
  else
    cap "cat /etc/os-release 2>/dev/null | grep -E '^(NAME|VERSION|ID)=' || echo 'no os-release'"
    local mem_total mem_free
    mem_total=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}') || mem_total="?"
    mem_free=$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2}') || mem_free="?"
    echo -e "  ${DIM}Memory: ${mem_free}kB free / ${mem_total}kB total${RESET}"
    output+="Memory: ${mem_free}kB free / ${mem_total}kB total"$'\n'
  fi
}

# ── BOOT ─────────────────────────────────────────────────────────────────────
section_boot() {
  if [[ "$OS_TYPE" == "Darwin" ]]; then
    section "BOOT & SECURITY (macOS)"

    # SIP
    section "SYSTEM INTEGRITY PROTECTION (SIP)"
    cap "csrutil status 2>/dev/null || echo 'csrutil not available'"

    # Secure Boot / Apple Silicon
    section "SECURE BOOT"
    if [[ "$(uname -m)" == "arm64" ]]; then
      cap "bputil -d 2>/dev/null || echo 'bputil not available (may need recovery mode)'"
    else
      note "Intel Mac — Secure Boot managed via Startup Security Utility in Recovery"
    fi

    # Gatekeeper
    section "GATEKEEPER"
    cap "spctl --status 2>/dev/null || echo 'spctl not available'"

    # FileVault
    section "FILEVAULT"
    cap "fdesetup status 2>/dev/null || echo 'fdesetup not available (try sudo)'"

    # Firewall
    section "APPLICATION FIREWALL"
    cap "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo 'firewall status unavailable'"

    # Recent errors
    section "RECENT ERRORS (system log)"
    cap "log show --last 10m --predicate 'messageType == fault or messageType == error' --style compact 2>/dev/null | tail -40 || echo 'log not accessible'"

    # Failed launch agents
    section "FAILED LAUNCH DAEMONS"
    cap "launchctl print-disabled system 2>/dev/null | grep -i 'true' | head -20 || echo 'none or not accessible'"

  else
    section "BOOT & FAILED SERVICES (Linux)"

    # Failed systemd units
    if command -v systemctl &>/dev/null; then
      local failed
      failed=$(systemctl --failed --no-pager --no-legend 2>/dev/null || echo "")
      if [[ -z "$failed" ]]; then
        ok "No failed systemd units"
      else
        err "Failed units detected:"
        cap "systemctl --failed --no-pager 2>/dev/null"
      fi
    else
      note "systemctl not available (live env?)"
    fi

    # Recent errors
    section "RECENT ERRORS (journal)"
    if command -v journalctl &>/dev/null; then
      local jerr
      jerr=$(journalctl -p err..emerg -b --no-pager -n 40 2>/dev/null || \
             journalctl -p err..emerg --no-pager -n 40 2>/dev/null || echo "")
      if [[ -z "$jerr" ]]; then
        ok "No errors in journal"
      else
        cap "journalctl -p err..emerg -b --no-pager -n 40 2>/dev/null || journalctl -p err..emerg --no-pager -n 40 2>/dev/null"
      fi
    else
      note "journalctl not available — trying dmesg"
      cap "dmesg --level=err,crit,alert,emerg 2>/dev/null | tail -30 || dmesg 2>/dev/null | grep -iE 'error|fail|panic|oops' | tail -30"
    fi

    # Bootloader
    section "BOOTLOADER"
    if [[ -f /etc/default/limine ]]; then
      ok "Limine detected"
      cap "cat /etc/default/limine 2>/dev/null"
    elif [[ -d /boot/loader ]]; then
      ok "systemd-boot detected"
      cap "bootctl status 2>/dev/null | head -30"
    elif command -v grub-install &>/dev/null; then
      ok "GRUB detected"
      cap "grub-install --version 2>/dev/null"
    else
      note "No bootloader detected in standard paths"
    fi

    # Secure Boot
    section "SECURE BOOT"
    if command -v sbctl &>/dev/null; then
      cap "sbctl status 2>/dev/null"
    elif [[ -d /sys/firmware/efi ]]; then
      cap "mokutil --sb-state 2>/dev/null || echo 'mokutil not available'"
    else
      note "Not booted in EFI mode — Secure Boot N/A"
    fi
  fi
}

# ── DISK ──────────────────────────────────────────────────────────────────────
section_disk() {
  if [[ "$OS_TYPE" == "Darwin" ]]; then
    section "DISK & PARTITIONS (macOS)"
    cap "diskutil list 2>/dev/null"

    section "DISK SPACE"
    cap "df -h 2>/dev/null | grep -v devfs | grep -v map"

    section "MOUNTS"
    cap "mount | grep -v 'devfs\|map\|com.apple' | sort"

    section "FILEVAULT STATUS"
    cap "fdesetup status 2>/dev/null || echo 'run with sudo for full status'"

  else
    section "DISK & PARTITIONS (Linux)"
    cap "lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT 2>/dev/null"

    section "MOUNTS"
    cap "mount | grep -v 'cgroup\|proc\|sys\|dev\|run\|snap' | sort"

    section "DISK SPACE"
    cap "df -h 2>/dev/null | grep -v tmpfs | grep -v devtmpfs"

    section "LUKS"
    if command -v cryptsetup &>/dev/null; then
      local luks_devs
      luks_devs=$(lsblk -o NAME,TYPE 2>/dev/null | grep crypt || echo "")
      if [[ -n "$luks_devs" ]]; then
        ok "LUKS device(s) active"
        cap "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null | grep -A2 crypt"
      else
        note "No active LUKS devices"
      fi
      cap "cat /etc/crypttab 2>/dev/null || echo 'no crypttab'"
    else
      note "cryptsetup not installed"
    fi

    section "FSTAB"
    cap "cat /etc/fstab 2>/dev/null || echo 'no fstab'"
  fi
}

# ── NETWORK ───────────────────────────────────────────────────────────────────
section_network() {
  section "NETWORK"

  if [[ "$OS_TYPE" == "Darwin" ]]; then
    cap "ifconfig 2>/dev/null | grep -E '(^[a-z]|inet |status)'"

    section "ROUTES"
    cap "netstat -rn 2>/dev/null | head -30"

    section "DNS"
    cap "scutil --dns 2>/dev/null | grep nameserver | head -10"

    section "WIFI"
    cap "networksetup -getairportnetwork en0 2>/dev/null || echo 'no wifi / en0 not found'"

  else
    cap "ip addr 2>/dev/null || ifconfig 2>/dev/null || echo 'no ip/ifconfig'"

    section "ROUTES"
    cap "ip route 2>/dev/null || route -n 2>/dev/null || echo 'no route info'"

    section "DNS"
    cap "cat /etc/resolv.conf 2>/dev/null || echo 'no resolv.conf'"
  fi

  section "CONNECTIVITY"
  if ping -c1 -W2 8.8.8.8 &>/dev/null 2>&1 || ping -c1 -t2 8.8.8.8 &>/dev/null 2>&1; then
    ok "Internet reachable (8.8.8.8)"
  else
    err "No internet connectivity"
  fi

  if command -v wg &>/dev/null; then
    section "WIREGUARD"
    cap "sudo wg show 2>/dev/null || wg show 2>/dev/null || echo 'wg not accessible without sudo'"
  fi

  section "LISTENING PORTS"
  if [[ "$OS_TYPE" == "Darwin" ]]; then
    cap "netstat -an 2>/dev/null | grep LISTEN | head -30"
  else
    cap "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo 'no ss/netstat'"
  fi
}

# ── PACKAGES ──────────────────────────────────────────────────────────────────
section_packages() {
  section "PACKAGE MANAGER"

  if [[ "$OS_TYPE" == "Darwin" ]]; then
    if command -v brew &>/dev/null; then
      ok "Homebrew"
      cap "brew --version 2>/dev/null"
      cap "brew list 2>/dev/null | wc -l | xargs -I{} echo '{} Homebrew packages installed'"
      cap "brew list --cask 2>/dev/null | wc -l | xargs -I{} echo '{} casks installed'"
      section "RECENT BREW ACTIVITY"
      cap "brew log 2>/dev/null | head -20 || echo 'no brew log'"
      section "OUTDATED"
      cap "brew outdated 2>/dev/null | head -20 || echo 'all up to date'"
    else
      note "Homebrew not installed"
    fi

  elif command -v pacman &>/dev/null; then
    ok "pacman (Arch)"
    cap "pacman -Qe 2>/dev/null | wc -l | xargs -I{} echo '{} explicit packages'"
    cap "pacman -Qm 2>/dev/null | wc -l | xargs -I{} echo '{} AUR/foreign packages'"
    section "RECENT PACMAN ACTIVITY"
    cap "grep -E '\[ALPM\] (installed|upgraded|removed)' /var/log/pacman.log 2>/dev/null | tail -20 || echo 'no pacman log'"

  elif command -v apt &>/dev/null; then
    ok "apt (Debian/Ubuntu)"
    cap "dpkg -l 2>/dev/null | grep '^ii' | wc -l | xargs -I{} echo '{} installed packages'"
    cap "tail -20 /var/log/apt/history.log 2>/dev/null || echo 'no apt log'"

  else
    note "No recognised package manager"
  fi
}

# ── SERVICES ──────────────────────────────────────────────────────────────────
section_services() {
  section "KEY SERVICES"

  if [[ "$OS_TYPE" == "Darwin" ]]; then
    # macOS — check via launchctl
    local macos_services=(
      "com.openssh.sshd:SSH"
      "com.apple.security.syspolicy:Gatekeeper"
      "com.apple.alf:App Firewall"
      "com.apple.fdesetup:FileVault"
    )
    for entry in "${macos_services[@]}"; do
      local svc="${entry%%:*}" label="${entry##*:}"
      if launchctl list "$svc" &>/dev/null 2>&1; then
        ok "$label ($svc): running"
      else
        note "$label ($svc): not running"
      fi
    done

    section "RUNNING USER AGENTS (sample)"
    cap "launchctl list 2>/dev/null | grep -v '^-' | head -20"

  else
    local services=(sshd NetworkManager systemd-resolved nftables hardened-api docker wg-quick@wg0 apparmor)
    for svc in "${services[@]}"; do
      if systemctl is-active --quiet "$svc" 2>/dev/null; then
        ok "$svc: active"
      elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        note "$svc: enabled but not active"
      else
        echo -e "  ${DIM}$svc: inactive/not found${RESET}"
        output+="[DIM] $svc: inactive"$'\n'
      fi
    done
  fi
}

# ── RECENT LOGS ───────────────────────────────────────────────────────────────
section_recent_logs() {
  section "RECENT SYSTEM LOG"
  if [[ "$OS_TYPE" == "Darwin" ]]; then
    cap "log show --last 5m --style compact 2>/dev/null | tail -30 || echo 'log not accessible'"
  else
    cap "journalctl -b --no-pager -n 30 2>/dev/null || dmesg 2>/dev/null | tail -30"
  fi
}

# ── SAVE REPORT ───────────────────────────────────────────────────────────────
save_report() {
  local saved=0

  if echo "$output" > "$REPORT_FILE" 2>/dev/null; then
    saved=1
  elif echo "$output" | sudo tee "$REPORT_FILE" >/dev/null 2>&1; then
    saved=1
  fi

  # Guaranteed fallback to /tmp
  local tmp_report="/tmp/${HOSTNAME_STR}-${TIMESTAMP}.txt"
  echo "$output" > "$tmp_report" 2>/dev/null || true

  echo ""
  if [[ $saved -eq 1 ]]; then
    echo -e "${BOLD}Report saved to:${RESET} ${REPORT_FILE}"
  else
    echo -e "${YELLOW}⚠${RESET}  Could not write to USB — saved to: ${tmp_report}"
    REPORT_FILE="$tmp_report"
  fi

  echo ""
  echo "━━━ PASTE THIS TO YOUR AGENT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Machine : ${HOSTNAME_STR}"
  echo "OS      : ${OS_TYPE} $(uname -r 2>/dev/null || sw_vers -productVersion 2>/dev/null || echo '')"
  echo "Time    : $(date)"
  echo "Report  : ${REPORT_FILE}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ── DISPATCH ──────────────────────────────────────────────────────────────────
print_header

case "${1:-}" in
  --boot)     section_system; section_boot ;;
  --disk)     section_system; section_disk ;;
  --net)      section_system; section_network ;;
  --packages) section_system; section_packages ;;
  ""|--full)
    section_system
    section_boot
    section_disk
    section_network
    section_packages
    section_services
    section_recent_logs
    ;;
  *)
    echo "Usage: triage.sh [--full | --boot | --disk | --net | --packages]"
    exit 1
    ;;
esac

save_report

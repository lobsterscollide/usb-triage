#!/usr/bin/env bash
# mac-audit.sh — macOS security audit
# Runs without root. Items needing sudo are flagged with [SUDO].
# Tested: macOS Ventura, Sonoma, Sequoia — Intel + Apple Silicon
#
# Usage:
#   bash mac-audit.sh              — full audit, saves report
#   bash mac-audit.sh --summary    — summary only (no raw output)
#
# From USB:
#   bash /Volumes/USB/usb-triage/mac-audit.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="${SCRIPT_DIR}/reports"
mkdir -p "$REPORT_DIR" 2>/dev/null || true

HOSTNAME_STR=$(hostname 2>/dev/null | sed 's/\.local//' || echo "unknown")
TIMESTAMP=$(date '+%Y-%m-%dT%H-%M-%S')
REPORT_FILE="${REPORT_DIR}/${HOSTNAME_STR}-audit-${TIMESTAMP}.txt"

# ── Formatting ────────────────────────────────────────────────────────────────
BOLD='\033[1m'; CYAN='\033[0;36m'; RED='\033[0;31m'
YELLOW='\033[0;33m'; GREEN='\033[0;32m'; DIM='\033[2m'; RESET='\033[0m'

output=""
pass_count=0; warn_count=0; fail_count=0; info_count=0

_log() { output+="$1"$'\n'; }

pass() { echo -e "  ${GREEN}[PASS]${RESET} $1"; _log "[PASS] $1"; ((pass_count++)); }
warn() { echo -e "  ${YELLOW}[WARN]${RESET} $1"; _log "[WARN] $1"; ((warn_count++)); }
fail() { echo -e "  ${RED}[FAIL]${RESET} $1"; _log "[FAIL] $1"; ((fail_count++)); }
info() { echo -e "  ${DIM}[INFO]${RESET} $1"; _log "[INFO] $1"; ((info_count++)); }
sudo_note() { echo -e "  ${CYAN}[SUDO]${RESET} $1 — run with sudo for full check"; _log "[SUDO] $1"; }

section() {
  echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  _log ""
  _log "### $1"
}

raw() {
  local out
  out=$(eval "$1" 2>&1 || true)
  if [[ "${SUMMARY_ONLY:-}" != "1" ]]; then
    echo -e "${DIM}${out}${RESET}"
  fi
  _log "$out"
}

# ── HEADER ────────────────────────────────────────────────────────────────────
ARCH=$(uname -m)
MACOS_VER=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
MACOS_BUILD=$(sw_vers -buildVersion 2>/dev/null || echo "")
CHIP=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || \
       system_profiler SPHardwareDataType 2>/dev/null | grep -E "Chip|Processor Name" | head -1 | awk -F': ' '{print $2}' || echo "unknown")

echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════════════╗"
echo -e "║  USB MAC AUDIT — ${TIMESTAMP}  ║"
echo -e "╚══════════════════════════════════════════════════╝${RESET}"
echo -e "  Host: ${HOSTNAME_STR} | macOS ${MACOS_VER} (${MACOS_BUILD}) | ${ARCH}"
echo -e "  Chip: ${CHIP}\n"

_log "USB MAC AUDIT — ${HOSTNAME_STR} — ${TIMESTAMP}"
_log "macOS ${MACOS_VER} (${MACOS_BUILD}) | ${ARCH} | ${CHIP}"

# ── 1. OS VERSION ─────────────────────────────────────────────────────────────
section "1. OS VERSION"
# Extract major version for comparison
MACOS_MAJOR=$(echo "$MACOS_VER" | cut -d. -f1)

if [[ "$MACOS_MAJOR" -ge 15 ]]; then
  pass "macOS ${MACOS_VER} — Sequoia (current)"
elif [[ "$MACOS_MAJOR" -eq 14 ]]; then
  pass "macOS ${MACOS_VER} — Sonoma (supported)"
elif [[ "$MACOS_MAJOR" -eq 13 ]]; then
  warn "macOS ${MACOS_VER} — Ventura (check for security updates)"
else
  fail "macOS ${MACOS_VER} — unsupported, upgrade required"
fi

# Check for pending updates
pending=$(softwareupdate -l 2>/dev/null | grep -i "recommended\|required" | wc -l | tr -d ' ')
if [[ "$pending" -gt 0 ]]; then
  warn "$pending pending software update(s) — run: softwareupdate -ia"
else
  pass "No pending software updates"
fi

# ── 2. DISK ENCRYPTION ────────────────────────────────────────────────────────
section "2. DISK ENCRYPTION (FileVault)"
fv_status=$(fdesetup status 2>/dev/null || echo "")
if echo "$fv_status" | grep -qi "FileVault is On"; then
  pass "FileVault: Enabled"
elif echo "$fv_status" | grep -qi "FileVault is Off"; then
  fail "FileVault: DISABLED — disk is not encrypted"
else
  sudo_note "FileVault status requires sudo or System Preferences check"
fi

# ── 3. SYSTEM INTEGRITY PROTECTION ───────────────────────────────────────────
section "3. SYSTEM INTEGRITY PROTECTION (SIP)"
sip=$(csrutil status 2>/dev/null || echo "")
if echo "$sip" | grep -qi "enabled"; then
  pass "SIP: Enabled"
elif echo "$sip" | grep -qi "disabled"; then
  fail "SIP: DISABLED — system protections are off"
else
  warn "SIP: status unclear — ${sip}"
fi

# ── 4. GATEKEEPER ─────────────────────────────────────────────────────────────
section "4. GATEKEEPER"
gk=$(spctl --status 2>/dev/null || echo "")
if echo "$gk" | grep -qi "enabled\|assessments enabled"; then
  pass "Gatekeeper: Enabled"
else
  fail "Gatekeeper: DISABLED — unsigned apps run without warning"
fi

# ── 5. SECURE BOOT ────────────────────────────────────────────────────────────
section "5. SECURE BOOT"
if [[ "$ARCH" == "arm64" ]]; then
  # Apple Silicon — check via bputil if available (needs recoveryOS for full check)
  sb=$(bputil -d 2>/dev/null || echo "")
  if echo "$sb" | grep -qi "full security"; then
    pass "Secure Boot: Full Security (Apple Silicon)"
  elif echo "$sb" | grep -qi "reduced security"; then
    warn "Secure Boot: Reduced Security — kernel extensions may be unsigned"
  elif echo "$sb" | grep -qi "no security"; then
    fail "Secure Boot: No Security — boot integrity not verified"
  else
    info "Secure Boot: check in System Settings → Privacy & Security → Security (Apple Silicon)"
  fi
else
  info "Intel Mac: Secure Boot managed in Startup Security Utility (Recovery Mode)"
  info "To verify: hold Cmd+R on boot → Utilities → Startup Security Utility → Full Security"
fi

# ── 6. APPLICATION FIREWALL ───────────────────────────────────────────────────
section "6. APPLICATION FIREWALL"
fw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "")
if echo "$fw" | grep -qi "enabled"; then
  pass "Application Firewall: Enabled"
  stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "")
  if echo "$stealth" | grep -qi "enabled"; then
    pass "Stealth Mode: Enabled (no response to ping)"
  else
    warn "Stealth Mode: Disabled — machine responds to network probes"
  fi
else
  fail "Application Firewall: DISABLED"
fi

# ── 7. AUTOMATIC UPDATES ──────────────────────────────────────────────────────
section "7. AUTOMATIC UPDATES"
auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "unknown")
auto_dl=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null || echo "unknown")
auto_install=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "unknown")
critical=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "unknown")

[[ "$auto_check" == "1" ]] && pass "Auto-check for updates: On" || warn "Auto-check for updates: Off"
[[ "$auto_dl" == "1" ]] && pass "Auto-download updates: On" || warn "Auto-download updates: Off"
[[ "$critical" == "1" ]] && pass "Critical security responses: On" || warn "Critical security responses: Off"
[[ "$auto_install" == "1" ]] && info "macOS auto-install: On (optional)" || info "macOS auto-install: Off (manual)"

# ── 8. SCREEN LOCK ────────────────────────────────────────────────────────────
section "8. SCREEN LOCK & LOGIN"
# Check require password immediately after sleep
req_pwd=$(defaults read com.apple.screensaver askForPassword 2>/dev/null || echo "unknown")
req_delay=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null || echo "unknown")

if [[ "$req_pwd" == "1" ]]; then
  if [[ "$req_delay" == "0" ]]; then
    pass "Screen lock: Password required immediately"
  else
    warn "Screen lock: Password required after ${req_delay}s delay — set to 0"
  fi
else
  fail "Screen lock: No password required after sleep"
fi

# Check disable automatic login
auto_login=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "none")
if [[ "$auto_login" == "none" ]] || [[ -z "$auto_login" ]]; then
  pass "Auto-login: Disabled"
else
  fail "Auto-login: ENABLED as '${auto_login}' — disable in System Settings"
fi

# ── 9. SSH ────────────────────────────────────────────────────────────────────
section "9. SSH"
ssh_status=$(launchctl list com.openssh.sshd 2>/dev/null && echo "running" || echo "not running")
if echo "$ssh_status" | grep -qi "not running"; then
  pass "SSH (Remote Login): Disabled"
else
  warn "SSH: Enabled — verify this is intentional"
  raw "cat /etc/ssh/sshd_config 2>/dev/null | grep -Ev '^#|^$' | head -30"
fi

# ── 10. REMOTE ACCESS ─────────────────────────────────────────────────────────
section "10. REMOTE ACCESS"
# Screen Sharing
if launchctl list com.apple.screensharing &>/dev/null 2>&1; then
  warn "Screen Sharing: ENABLED — disable unless actively needed"
else
  pass "Screen Sharing: Disabled"
fi

# Remote Management (ARD)
if launchctl list com.apple.RemoteDesktop.agent &>/dev/null 2>&1; then
  warn "Remote Management (ARD): ENABLED"
else
  pass "Remote Management: Disabled"
fi

# AirDrop
info "AirDrop: check manually — System Settings → General → AirDrop (should be 'Contacts Only' or 'Off')"

# ── 11. USER ACCOUNTS ─────────────────────────────────────────────────────────
section "11. USER ACCOUNTS"
# List all users with UID >= 500 (real users)
raw "dscl . list /Users UniqueID 2>/dev/null | awk '\$2 >= 500 {print \$1, \$2}'"

# List admin users
admins=$(dscl . read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //')
info "Admin users: ${admins}"
admin_count=$(echo "$admins" | wc -w | tr -d ' ')
if [[ "$admin_count" -gt 2 ]]; then
  warn "Multiple admin users (${admin_count}) — review if all are needed"
else
  pass "Admin user count: ${admin_count}"
fi

# Guest account
guest=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo "0")
if [[ "$guest" == "1" ]]; then
  warn "Guest account: ENABLED — disable unless needed"
else
  pass "Guest account: Disabled"
fi

# ── 12. LOGIN ITEMS & LAUNCH AGENTS ──────────────────────────────────────────
section "12. LOGIN ITEMS & PERSISTENCE"
info "User launch agents:"
raw "ls ~/Library/LaunchAgents/ 2>/dev/null | head -30 || echo 'none'"

info "System launch daemons (non-Apple):"
raw "ls /Library/LaunchDaemons/ 2>/dev/null | grep -v 'com.apple' | head -20 || echo 'none'"

info "System launch agents (non-Apple):"
raw "ls /Library/LaunchAgents/ 2>/dev/null | grep -v 'com.apple' | head -20 || echo 'none'"

login_items=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "")
if [[ -n "$login_items" ]]; then
  info "Login items: ${login_items}"
else
  info "Login items: none detected via osascript"
fi

# ── 13. LISTENING PORTS ───────────────────────────────────────────────────────
section "13. LISTENING PORTS"
raw "netstat -an 2>/dev/null | grep LISTEN | grep -v '127.0.0.1\|::1' | head -20"
ext_ports=$(netstat -an 2>/dev/null | grep LISTEN | grep -v '127.0.0.1\|::1\|\.0\.1' | wc -l | tr -d ' ')
if [[ "$ext_ports" -gt 0 ]]; then
  warn "${ext_ports} port(s) listening on non-localhost — review above"
else
  pass "No externally listening ports (all on localhost)"
fi

# ── 14. PRIVACY & LOCATION ───────────────────────────────────────────────────
section "14. PRIVACY & LOCATION"
loc=$(defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled 2>/dev/null || echo "unknown")
if [[ "$loc" == "0" ]]; then
  info "Location Services: Disabled (privacy win, but maps/Find My won't work)"
elif [[ "$loc" == "1" ]]; then
  info "Location Services: Enabled — review which apps have access in System Settings"
else
  info "Location Services: status unknown — check System Settings → Privacy & Security"
fi

# Analytics
analytics=$(defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit 2>/dev/null || echo "unknown")
[[ "$analytics" == "0" ]] && pass "Analytics/diagnostics sharing: Disabled" || warn "Analytics/diagnostics: may be enabled — check System Settings → Privacy → Analytics"

# ── 15. NETWORK & DNS ─────────────────────────────────────────────────────────
section "15. NETWORK & DNS"
dns=$(scutil --dns 2>/dev/null | grep nameserver | awk '{print $3}' | sort -u | head -5)
info "DNS servers: $(echo $dns | tr '\n' ' ')"

# Check for ISP default DNS (common ones)
isp_dns=0
for d in $dns; do
  case "$d" in
    192.168.*|10.*|172.16.*|172.17.*|172.18.*|172.19.*|172.2*|172.3*)
      ((isp_dns++)) ;;
  esac
done
if [[ "$isp_dns" -gt 0 ]]; then
  warn "Using local/ISP DNS — consider NextDNS or Cloudflare (1.1.1.1)"
else
  pass "DNS not using raw ISP resolver"
fi

# VPN
vpn_active=$(ifconfig 2>/dev/null | grep -E '^(utun|ppp)' | head -3)
if [[ -n "$vpn_active" ]]; then
  pass "VPN interface detected: $(echo $vpn_active | awk '{print $1}' | tr -d ':')"
else
  warn "No VPN interface detected — traffic may be unencrypted on untrusted networks"
fi

# ── 16. AGENT-SPECIFIC CHECKS ────────────────────────────────────────────────
section "16. AGENT / CLAUDE CODE"
# Check for Claude Code
claude_path=$(which claude 2>/dev/null || which claude-code 2>/dev/null || echo "")
if [[ -n "$claude_path" ]]; then
  pass "Claude Code: found at ${claude_path}"
  raw "${claude_path} --version 2>/dev/null | head -3"
else
  info "Claude Code: not found in PATH"
fi

# Check for OpenClaw
openclaw_path=$(which openclaw 2>/dev/null || ls ~/.local/bin/openclaw 2>/dev/null || echo "")
if [[ -n "$openclaw_path" ]]; then
  info "OpenClaw: found at ${openclaw_path}"
fi

# Check for API keys accidentally in common locations
api_key_hits=$(grep -r "sk-ant-" ~/Library/Preferences/ ~/Library/Application\ Support/ ~/.config/ ~/.env* 2>/dev/null | grep -v ".git" | wc -l | tr -d ' ')
if [[ "$api_key_hits" -gt 0 ]]; then
  fail "Possible API key(s) found in plain text files — ${api_key_hits} hit(s). Check output above."
  raw "grep -rl 'sk-ant-' ~/Library/Preferences/ ~/Library/Application\ Support/ ~/.config/ ~/.env* 2>/dev/null | head -10"
else
  pass "No API keys found in common plain text locations"
fi

# Check .env files in home
env_files=$(find ~ -maxdepth 3 -name ".env" -o -name ".env.local" -o -name "*.env" 2>/dev/null | grep -v ".git" | head -10)
if [[ -n "$env_files" ]]; then
  warn ".env file(s) found — verify no secrets:"
  echo "$env_files" | while read -r f; do info "  $f"; done
  _log "$env_files"
else
  pass "No .env files in home (top 3 levels)"
fi

# ── 17. HOMEBREW PACKAGES ────────────────────────────────────────────────────
section "17. HOMEBREW"
if command -v brew &>/dev/null; then
  brew_ver=$(brew --version 2>/dev/null | head -1)
  pass "Homebrew: ${brew_ver}"
  outdated=$(brew outdated 2>/dev/null | wc -l | tr -d ' ')
  [[ "$outdated" -gt 0 ]] && warn "${outdated} outdated Homebrew package(s)" || pass "All Homebrew packages up to date"
  raw "brew list 2>/dev/null"
else
  info "Homebrew: not installed"
fi

# ── 18. INSTALLED APPS (non-Apple spotlight) ─────────────────────────────────
section "18. INSTALLED APPLICATIONS"
raw "ls /Applications/ 2>/dev/null | sort"
app_count=$(ls /Applications/ 2>/dev/null | wc -l | tr -d ' ')
info "${app_count} apps in /Applications/"

# ── 19. BLUETOOTH ─────────────────────────────────────────────────────────────
section "19. BLUETOOTH"
bt=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null || echo "unknown")
[[ "$bt" == "0" ]] && info "Bluetooth: Off" || warn "Bluetooth: On — disable when not in use"

# ── 20. TIME MACHINE ──────────────────────────────────────────────────────────
section "20. TIME MACHINE"
tm_dest=$(tmutil destinationinfo 2>/dev/null | grep Name | head -1 || echo "no destination")
if tmutil destinationinfo &>/dev/null 2>&1; then
  info "Time Machine destination: ${tm_dest}"
  warn "Verify Time Machine backup is encrypted: tmutil destinationinfo | grep Encrypted"
else
  info "Time Machine: no backup destination configured"
fi

# ── SUMMARY ───────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}${CYAN}━━━ AUDIT SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${GREEN}[PASS]${RESET} ${pass_count}   ${YELLOW}[WARN]${RESET} ${warn_count}   ${RED}[FAIL]${RESET} ${fail_count}   ${DIM}[INFO]${RESET} ${info_count}"
echo ""

if [[ "$fail_count" -gt 0 ]]; then
  echo -e "  ${RED}${BOLD}CRITICAL items need attention before this machine is trusted.${RESET}"
elif [[ "$warn_count" -gt 3 ]]; then
  echo -e "  ${YELLOW}${BOLD}Several warnings — review before using on untrusted networks.${RESET}"
else
  echo -e "  ${GREEN}${BOLD}Looking good — review warnings above.${RESET}"
fi

_log ""
_log "SUMMARY: PASS=${pass_count} WARN=${warn_count} FAIL=${fail_count} INFO=${info_count}"

# ── SAVE ──────────────────────────────────────────────────────────────────────
if echo "$output" > "$REPORT_FILE" 2>/dev/null; then
  echo -e "\n  Report saved: ${REPORT_FILE}"
else
  REPORT_FILE="/tmp/${HOSTNAME_STR}-audit-${TIMESTAMP}.txt"
  (umask 077; echo "$output" > "$REPORT_FILE")
  echo -e "\n  ${YELLOW}USB write failed — saved to: ${REPORT_FILE}${RESET}"
fi

echo ""
echo "━━━ PASTE THIS TO YOUR AGENT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Machine : ${HOSTNAME_STR}"
echo "macOS   : ${MACOS_VER} (${MACOS_BUILD}) | ${ARCH} | ${CHIP}"
echo "Result  : PASS=${pass_count} WARN=${warn_count} FAIL=${fail_count}"
echo "Report  : ${REPORT_FILE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

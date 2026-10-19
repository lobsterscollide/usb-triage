# USB Triage — Agent Instructions

You are an AI coding agent (e.g. Claude Code) running on a machine that has this
USB kit mounted. Your job: run the audit, read the report, and produce a
prioritised hardening checklist. Do not skip steps, and do not change anything
without the user's confirmation.

---

## Step 1 — Run the audit

| OS | Command | Privileges |
|----|---------|------------|
| Linux | `bash triage.sh` (or `--boot`, `--net`, `--disk`, `--packages`) | Normal user; prompts for `sudo` where needed |
| macOS | `bash mac-audit.sh` | Normal user; items needing `sudo` are flagged `[SUDO]` |
| Windows | `run-audit.bat`, or in an elevated PowerShell: `powershell -ExecutionPolicy Bypass -File .\windows-audit.ps1` | Administrator — BitLocker, Defender and Security log checks are incomplete without it |

Run from the kit's own directory. On Linux, if the USB is mounted root-only,
remount it so your user can write: `sudo mount -o uid=$(id -u),gid=$(id -g) /dev/sdX1 /mnt/usb`.

The report is saved to `reports/<hostname>-<timestamp>.txt` on the USB. If the
USB isn't writable, Linux retries with `sudo`, and macOS/Windows fall back to the
system temp directory — the script prints the path either way.

---

## Step 2 — Read the report

Read the full report file the script printed (not just the on-screen summary).

---

## Step 3 — Classify every finding

| Bucket | Criteria |
|--------|----------|
| **CRITICAL** | Active attack surface or data-loss risk: disk encryption off, Secure Boot disabled, remote access exposed without strong auth, firewall off, SMBv1 enabled |
| **HIGH** | Significant hardening gap: stale malware signatures, password SSH login, pending security updates, unsigned/unknown startup items |
| **LOW** | Best-practice gaps: AutoRun not disabled, verbose services, old patches |

Quick reference — good vs bad states:

| Area | Linux | macOS | Windows |
|------|-------|-------|---------|
| Disk encryption | LUKS on root | FileVault On | BitLocker C: protected, 100% |
| Boot integrity | Secure Boot on (`sbctl status`) | — | Secure Boot ENABLED |
| Firewall | nftables/ufw active, default drop | Application firewall + stealth on | All profiles ON, inbound Block |
| Remote access | sshd off, or key-only + no root | Remote Login / Screen Sharing off | RDP off, or NLA=1; RemoteRegistry stopped |
| Malware/AV | rkhunter/ClamAV present and current | Gatekeeper + SIP enabled | Defender real-time on, sigs < 7 days |
| Updates | No pending security updates | Software Update current | Recent hotfixes |
| Privilege | No unexpected sudoers/UID 0 | Admin accounts reviewed | UAC on (`EnableLUA=1`) |

---

## Step 4 — Produce the hardening checklist

For each CRITICAL and HIGH finding, give the exact command to fix it (or the
settings path if there is no command), in the machine's own shell:

```
[CRITICAL] SMBv1 is enabled
  Fix: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

[HIGH] SSH allows password login
  Fix: echo 'PasswordAuthentication no' | sudo tee /etc/ssh/sshd_config.d/10-no-passwords.conf && sudo systemctl reload sshd
```

---

## Step 5 — Apply fixes (with confirmation)

Before applying any fix:

- Say what the command does and what it changes.
- Ask the user to confirm, unless they have told you to proceed automatically.
- After applying, re-check the relevant setting to confirm the fix took effect.
- Batch anything that needs a reboot so the user reboots once.

---

## Rules

- Reports stay on the USB under `reports/` — do not copy them elsewhere unless
  the user asks. They contain sensitive details about this machine.
- If you see anything suspicious outside these checks (unknown startup entries,
  unrecognised scheduled tasks or launch agents, odd listening ports), flag it
  to the user before taking any action.

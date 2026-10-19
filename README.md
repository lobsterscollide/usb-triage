# usb-triage

> A run-from-USB security audit kit for Linux, macOS and Windows that produces a report an AI agent can turn into a fix list.

[![CI](https://github.com/lobsterscollide/usb-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/lobsterscollide/usb-triage/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## The idea

Checking a new or unfamiliar machine shouldn't need anything installed on it. Copy this folder to a
USB stick, plug it in, run one script: you get a plain-text report of the machine's security posture
saved back to the stick, plus a short summary block. Paste that summary — or point an agent such as
Claude Code at the report — and [`AGENT.md`](AGENT.md) tells it how to classify the findings and
propose fixes, asking before it changes anything.

## What's inside

| Path | What it is |
|------|------------|
| `triage.sh` | Linux (Arch, Debian/Ubuntu) diagnostic snapshot; also runs on macOS |
| `mac-audit.sh` | macOS security audit — no root needed, `[SUDO]` items flagged |
| `windows-audit.ps1` | Windows audit (Secure Boot, BitLocker, Defender, UAC, firewall, SMB, RDP, …) |
| `run-audit.bat` | Double-click Windows launcher; elevates and runs the PowerShell audit |
| `AGENT.md` | Instructions for an AI agent: run, read, classify, propose, confirm |
| `reports/` | Where reports are written (git-ignored) |

## Quick start

```sh
# Linux
bash triage.sh                 # or: --boot | --net | --disk | --packages

# macOS
bash mac-audit.sh              # or: --summary

# Windows: double-click run-audit.bat, or in an elevated PowerShell:
powershell -ExecutionPolicy Bypass -File .\windows-audit.ps1   # or: --boot | --disk | --net | --packages
```

On Linux, if the stick is mounted root-only: `sudo mount -o uid=$(id -u),gid=$(id -g) /dev/sdX1 /mnt/usb`.

## How it works

Each script runs a fixed list of read-only commands, prints coloured results, and writes the full
output to `reports/<hostname>-<timestamp>.txt`. At the end it prints a **PASTE THIS TO YOUR AGENT**
block with the headline numbers. If the stick isn't writable, Linux retries with `sudo` and
macOS/Windows save to the system temp directory instead (owner-only), printing the path.

## Requirements

- Linux or macOS: `bash`. Windows: PowerShell 5.1+ and an Administrator account.
- Nothing to install on the target machine.

## Security notes

- The audit only **reads**. The only file it writes is the report.
- Reports contain sensitive details about the audited machine (hostname, users, network
  configuration, installed software, open ports). Treat the stick as sensitive, wipe old reports,
  and never commit them.
- `run-audit.bat` runs PowerShell with `-ExecutionPolicy Bypass` for that one process only; read
  `windows-audit.ps1` before running it elevated.

## Status

Complete and shared as a reference; not actively maintained.

## Part of a set

| Project | What it is |
|---------|------------|
| [railed](https://github.com/lobsterscollide/railed) | Operating discipline for AI agents with real tool access, built from documented failures |
| [hardened-api](https://github.com/lobsterscollide/hardened-api) | Linux hardening checks and fixes as an API an agent can drive |
| **usb-triage** | Run-from-USB security audit for Linux, macOS and Windows |
| [workstation-scripts](https://github.com/lobsterscollide/workstation-scripts) | Daily → quarterly security routine for an Arch workstation |
| [a2a-schemas](https://github.com/lobsterscollide/a2a-schemas) | Permission boundaries and handoffs between a "build" agent and an "apply" agent |

## License

[MIT](LICENSE)

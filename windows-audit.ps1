#Requires -Version 5.1
# windows-audit.ps1 — USB Triage for Windows
# Mirrors triage.sh output format — paste the summary block to your AI agent when done.
#
# Usage (run as Administrator for full output):
#   Right-click → "Run with PowerShell"
#   powershell -ExecutionPolicy Bypass -File .\windows-audit.ps1
#   powershell -ExecutionPolicy Bypass -File .\windows-audit.ps1 --boot
#   powershell -ExecutionPolicy Bypass -File .\windows-audit.ps1 --disk
#   powershell -ExecutionPolicy Bypass -File .\windows-audit.ps1 --net
#   powershell -ExecutionPolicy Bypass -File .\windows-audit.ps1 --packages
#
# Reports saved to: .\reports\<hostname>-<timestamp>.txt

param(
    [Parameter(Position=0)]
    [ValidateSet('--boot','--disk','--net','--packages','--full','')]
    [string]$Mode = ''
)

$ErrorActionPreference = 'SilentlyContinue'

# ── Paths ─────────────────────────────────────────────────────────────────────
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ReportDir  = Join-Path $ScriptDir 'reports'
$Timestamp  = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
$HostStr    = $env:COMPUTERNAME
$ReportFile = Join-Path $ReportDir "$HostStr-$Timestamp.txt"

if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}

# ── Output Helpers ────────────────────────────────────────────────────────────
$script:Output = [System.Text.StringBuilder]::new()

function Section([string]$Title) {
    $line = "`n━━━ $Title ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    Write-Host $line -ForegroundColor Cyan
    [void]$script:Output.AppendLine("`n### $Title")
}

function Cap([scriptblock]$Block) {
    try {
        $out = & $Block 2>&1 | Out-String
        Write-Host $out.Trim() -ForegroundColor DarkGray
        [void]$script:Output.AppendLine($out.Trim())
    } catch {
        [void]$script:Output.AppendLine("[error: $($_.Exception.Message)]")
    }
}

function OK([string]$Msg)   { Write-Host "  ✓  $Msg" -ForegroundColor Green;  [void]$script:Output.AppendLine("[OK] $Msg") }
function NOTE([string]$Msg) { Write-Host "  ⚠  $Msg" -ForegroundColor Yellow; [void]$script:Output.AppendLine("[NOTE] $Msg") }
function ERR([string]$Msg)  { Write-Host "  ✗  $Msg" -ForegroundColor Red;    [void]$script:Output.AppendLine("[ERR] $Msg") }

function IsAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ── SYSTEM ────────────────────────────────────────────────────────────────────
function Section-System {
    Section "SYSTEM"

    Cap { $os = Get-CimInstance Win32_OperatingSystem
          "OS      : $($os.Caption) Build $($os.BuildNumber)"
          "Version : $($os.Version)"
          "Arch    : $env:PROCESSOR_ARCHITECTURE"
          "Host    : $env:COMPUTERNAME"
          "User    : $env:USERNAME  (Admin: $(IsAdmin))"
    }

    Cap { $os = Get-CimInstance Win32_OperatingSystem
          $uptime = (Get-Date) - $os.LastBootUpTime
          "Uptime  : $([int]$uptime.TotalDays)d $($uptime.Hours)h $($uptime.Minutes)m (last boot: $($os.LastBootUpTime))"
    }

    Cap { $cs = Get-CimInstance Win32_ComputerSystem
          $mem = [math]::Round($cs.TotalPhysicalMemory/1GB, 1)
          $free = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1MB, 1)
          "Memory  : ${free}GB free / ${mem}GB total"
    }

    Cap { $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
          "CPU     : $($cpu.Name)  ($($cpu.NumberOfCores) cores / $($cpu.NumberOfLogicalProcessors) logical)"
    }
}

# ── BOOT & SECURITY ───────────────────────────────────────────────────────────
function Section-Boot {
    Section "SECURE BOOT"
    try {
        $sb = Confirm-SecureBootUEFI
        if ($sb) { OK "Secure Boot: ENABLED" } else { ERR "Secure Boot: DISABLED" }
    } catch {
        NOTE "Secure Boot: cannot query (non-UEFI or missing permission)"
    }

    Section "BITLOCKER"
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        Cap { Get-BitLockerVolume | ForEach-Object {
            $status = if ($_.ProtectionStatus -eq 'On') { '[PROTECTED]' } else { '[UNPROTECTED]' }
            "$($_.MountPoint)  $status  $($_.VolumeStatus)  EncryptionPct:$($_.EncryptionPercentage)%"
        }}
    } else {
        NOTE "Get-BitLockerVolume not available (run as admin or on Pro/Enterprise)"
    }

    Section "WINDOWS DEFENDER"
    Cap { $def = Get-MpComputerStatus
          "RealTimeProtection : $($def.RealTimeProtectionEnabled)"
          "AntivirusEnabled   : $($def.AntivirusEnabled)"
          "LastScanTime       : $($def.QuickScanAge) days ago"
          "DefinitionAge      : $($def.AntivirusSignatureAge) days"
          "TamperProtection   : $($def.IsTamperProtected)"
    }

    Section "USER ACCOUNT CONTROL (UAC)"
    Cap { $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          $level = $uac.ConsentPromptBehaviorAdmin
          $desc = switch ($level) {
              0 { "DISABLED — elevates without prompting (DANGEROUS)" }
              1 { "Prompt for credentials on secure desktop" }
              2 { "Prompt for consent on secure desktop" }
              3 { "Prompt for credentials" }
              4 { "Prompt for consent for non-Windows binaries" }
              5 { "Default — prompt for consent for non-Windows binaries" }
              default { "Unknown level $level" }
          }
          "ConsentPromptBehaviorAdmin : $level — $desc"
          "EnableLUA                  : $($uac.EnableLUA)  (0=UAC off, 1=UAC on)"
    }

    Section "WINDOWS FIREWALL"
    Cap { Get-NetFirewallProfile | ForEach-Object {
        $state = if ($_.Enabled) { 'ON' } else { 'OFF' }
        "$($_.Name.PadRight(10)) : $state  DefaultInbound:$($_.DefaultInboundAction)  DefaultOutbound:$($_.DefaultOutboundAction)"
    }}

    Section "POWERSHELL EXECUTION POLICY"
    Cap { Get-ExecutionPolicy -List | Format-Table -AutoSize | Out-String }

    Section "WINDOWS UPDATE"
    Cap { $wu = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
          "Last 5 hotfixes:"
          $wu | ForEach-Object { "  $($_.HotFixID)  $($_.InstalledOn)  $($_.Description)" }
    }

    Section "SMBv1 STATUS"
    Cap { try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol 2>$null
        if ($smb1) {
            if ($smb1.State -eq 'Enabled') { "SMBv1: ENABLED (EternalBlue risk — disable this)" }
            else { "SMBv1: Disabled" }
        } else {
            $smb1srv = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
            if ($smb1srv.EnableSMB1Protocol) { "SMBv1 Server: ENABLED" } else { "SMBv1 Server: Disabled" }
        }
    } catch { "SMBv1: could not query — run as admin" }}

    Section "REMOTE DESKTOP (RDP)"
    Cap { $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
          if ($rdp.fDenyTSConnections -eq 0) { "RDP: ENABLED" } else { "RDP: Disabled" }
          $nla = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication
          "NLA (Network Level Auth): $($nla.UserAuthentication)  (1=required, 0=disabled)"
    }

    Section "AUTORUN / AUTOPLAY"
    Cap { $ar = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue
          if ($ar) { "NoDriveTypeAutoRun: $($ar.NoDriveTypeAutoRun)  (0xFF=all disabled)" }
          else { "NoDriveTypeAutoRun: not set (AutoRun may be active)" }
    }

    Section "LOCAL ADMINS"
    Cap { Get-LocalGroupMember -Group 'Administrators' 2>$null | ForEach-Object {
        "  $($_.ObjectClass.PadRight(8))  $($_.Name)"
    }}

    Section "LOCAL USERS"
    Cap { Get-LocalUser | ForEach-Object {
        $status = if ($_.Enabled) { 'enabled' } else { 'disabled' }
        "  $($_.Name.PadRight(20)) $status  LastLogon:$($_.LastLogon)"
    }}
}

# ── DISK ──────────────────────────────────────────────────────────────────────
function Section-Disk {
    Section "DISK & VOLUMES"
    Cap { Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        $used = [math]::Round(($_.Used)/1GB, 1)
        $free = [math]::Round(($_.Free)/1GB, 1)
        $total = $used + $free
        "$($_.Name):  ${used}GB used / ${free}GB free / ${total}GB total  $($_.Root)"
    }}

    Section "PARTITIONS"
    Cap { Get-Partition | ForEach-Object {
        "Disk$($_.DiskNumber)  Part$($_.PartitionNumber)  $([math]::Round($_.Size/1GB,1))GB  $($_.Type)  $($_.DriveLetter)"
    }}

    Section "PHYSICAL DISKS"
    Cap { Get-PhysicalDisk | ForEach-Object {
        "$($_.DeviceId)  $($_.FriendlyName)  $([math]::Round($_.Size/1GB,0))GB  $($_.MediaType)  Health:$($_.HealthStatus)"
    }}
}

# ── NETWORK ───────────────────────────────────────────────────────────────────
function Section-Network {
    Section "NETWORK INTERFACES"
    Cap { Get-NetIPAddress | Where-Object { $_.AddressFamily -in 'IPv4','IPv6' -and $_.IPAddress -notmatch '^(127\.|::1)' } |
          ForEach-Object { "$($_.InterfaceAlias.PadRight(25)) $($_.AddressFamily)  $($_.IPAddress)/$($_.PrefixLength)" }
    }

    Section "ROUTES"
    Cap { Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.RouteMetric -lt 300 } |
          Sort-Object RouteMetric | Select-Object -First 20 |
          ForEach-Object { "$($_.DestinationPrefix.PadRight(20)) via $($_.NextHop.PadRight(16)) metric $($_.RouteMetric)" }
    }

    Section "DNS"
    Cap { Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } |
          ForEach-Object { "$($_.InterfaceAlias.PadRight(25)) $($_.ServerAddresses -join ', ')" }
    }

    Section "CONNECTIVITY"
    $probeHost = "8.8.8.8"  # public DNS, used only as a reachability probe
    $ping = Test-NetConnection -ComputerName $probeHost -WarningAction SilentlyContinue
    if ($ping.PingSucceeded) { OK "Internet reachable (8.8.8.8)" } else { ERR "No internet connectivity" }

    Section "LISTENING PORTS"
    Cap { Get-NetTCPConnection -State Listen |
          Select-Object LocalAddress, LocalPort, OwningProcess |
          Sort-Object LocalPort |
          ForEach-Object {
            $proc = try { (Get-Process -Id $_.OwningProcess).Name } catch { "pid:$($_.OwningProcess)" }
            "$($_.LocalAddress.PadRight(20)):$($_.LocalPort.ToString().PadRight(6)) $proc"
          }
    }

    Section "WIREGUARD"
    $wg = Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue
    if ($wg) {
        Cap { $wg | ForEach-Object { "$($_.Name)  $($_.Status)" } }
    } else {
        NOTE "WireGuard service not found"
    }
}

# ── PACKAGES ──────────────────────────────────────────────────────────────────
function Section-Packages {
    Section "INSTALLED SOFTWARE (winget)"
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Cap { winget list 2>&1 | Select-Object -Skip 3 | Select-Object -First 50 }
    } else {
        NOTE "winget not available"
    }

    Section "INSTALLED SOFTWARE (choco)"
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Cap { choco list --local-only 2>&1 | Select-Object -First 50 }
    } else {
        NOTE "Chocolatey not installed"
    }

    Section "RECENT INSTALLS (Event Log)"
    Cap { Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1033,11707,11724} -MaxEvents 20 -ErrorAction SilentlyContinue |
          ForEach-Object {
            $msg = ($_.Message -replace '\s+', ' ')
            if ($msg.Length -gt 100) { $msg = $msg.Substring(0, 100) }
            "$($_.TimeCreated)  $msg"
          }
    }

    Section "STARTUP PROGRAMS"
    Cap { Get-CimInstance Win32_StartupCommand | ForEach-Object {
        "  [$($_.Location)]  $($_.Name.PadRight(30)) $($_.Command)"
    }}

    Section "SCHEDULED TASKS (non-Microsoft)"
    Cap { Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' } |
          Select-Object -First 30 |
          ForEach-Object { "  $($_.TaskName.PadRight(40)) $($_.State)  $($_.TaskPath)" }
    }
}

# ── KEY SERVICES ──────────────────────────────────────────────────────────────
function Section-Services {
    Section "KEY SERVICES"

    $check = @(
        'wuauserv',    # Windows Update
        'WinDefend',   # Windows Defender
        'mpssvc',      # Windows Firewall
        'sshd',        # OpenSSH Server
        'TermService', # Remote Desktop
        'RemoteRegistry',
        'WSearch',     # Windows Search (indexing)
        'w32tm',       # Windows Time
        'EventLog'
    )

    foreach ($svc in $check) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            if ($s.Status -eq 'Running') { OK "$svc ($($s.DisplayName)): Running" }
            else { NOTE "$svc ($($s.DisplayName)): $($s.Status)" }
        } else {
            Write-Host "  -  $svc : not installed" -ForegroundColor DarkGray
            [void]$script:Output.AppendLine("[DIM] $svc : not installed")
        }
    }

    Section "REMOTE REGISTRY WARNING"
    $rr = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
    if ($rr -and $rr.Status -eq 'Running') {
        ERR "RemoteRegistry is RUNNING — allows remote registry reads/writes"
    } elseif ($rr) {
        OK "RemoteRegistry is $($rr.Status) (not a live risk)"
    }
}

# ── RECENT LOGS ───────────────────────────────────────────────────────────────
function Section-Logs {
    Section "RECENT SYSTEM ERRORS (Event Log)"
    Cap { Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 20 -ErrorAction SilentlyContinue |
          ForEach-Object {
            $msg = ($_.Message -replace '\s+', ' ')
            if ($msg.Length -gt 120) { $msg = $msg.Substring(0, 120) }
            "$($_.TimeCreated)  [$($_.Id)]  $($_.ProviderName)  $msg"
          }
    }

    Section "RECENT SECURITY EVENTS (sample)"
    Cap { Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648,4720,4728,4732} -MaxEvents 15 -ErrorAction SilentlyContinue |
          ForEach-Object {
            $msg = ($_.Message -replace '\s+', ' ')
            if ($msg.Length -gt 100) { $msg = $msg.Substring(0, 100) }
            "$($_.TimeCreated)  EventId:$($_.Id)  $msg"
          }
    }
}

# ── SAVE REPORT ───────────────────────────────────────────────────────────────
function Save-Report {
    $content = $script:Output.ToString()

    try {
        $content | Out-File -FilePath $ReportFile -Encoding utf8 -Force
        Write-Host "`nReport saved to: $ReportFile" -ForegroundColor Green
    } catch {
        $tmp = "$env:TEMP\$HostStr-$Timestamp.txt"
        $content | Out-File -FilePath $tmp -Encoding utf8 -Force
        NOTE "Could not write to USB — saved to: $tmp"
    }

    Write-Host ""
    Write-Host "━━━ PASTE THIS TO YOUR AGENT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "Machine : $HostStr"
    Write-Host "OS      : $((Get-CimInstance Win32_OperatingSystem).Caption)"
    Write-Host "Time    : $(Get-Date)"
    Write-Host "Report  : $ReportFile"
    Write-Host "Admin   : $(IsAdmin)"
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
}

# ── HEADER ────────────────────────────────────────────────────────────────────
Write-Host "`n╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  USB TRIAGE (Windows) — $Timestamp  ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "  Host: $HostStr  |  User: $env:USERNAME  |  Admin: $(IsAdmin)`n"

[void]$script:Output.AppendLine("USB TRIAGE (Windows) — $HostStr — $Timestamp")

if (-not (IsAdmin)) {
    NOTE "Not running as Administrator — some checks will be incomplete (BitLocker, Defender details, Event Log security)"
    Write-Host ""
}

# ── DISPATCH ──────────────────────────────────────────────────────────────────
switch ($Mode) {
    '--boot'     { Section-System; Section-Boot }
    '--disk'     { Section-System; Section-Disk }
    '--net'      { Section-System; Section-Network }
    '--packages' { Section-System; Section-Packages }
    default {
        Section-System
        Section-Boot
        Section-Disk
        Section-Network
        Section-Packages
        Section-Services
        Section-Logs
    }
}

Save-Report

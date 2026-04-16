#Requires -RunAsAdministrator
# ThreatClaw Agent Installer for Windows
# Usage (one-liner):
#   $env:TC_URL='https://TC_IP:8445'; $env:TC_TOKEN='TOKEN'; irm get.threatclaw.io/agent/windows | iex
#
# Or manual:
#   .\install-agent.ps1 -Url https://TC_IP:8445 -Token TOKEN
#
# Installs osquery, configures scheduled queries, creates sync task (5min).

param(
    [string]$Url     = $env:TC_URL,
    [string]$Token   = $env:TC_TOKEN,
    [string]$AgentId = ""
)

$ErrorActionPreference = "Stop"
$OsqueryVersion = "5.12.1"
$SyncInterval   = 5  # minutes

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-TC {
    param([string]$Msg, [string]$Color = "Green")
    Write-Host "[ThreatClaw Agent] " -ForegroundColor $Color -NoNewline
    Write-Host $Msg
}

function Write-TCError {
    param([string]$Msg)
    Write-Host "[ThreatClaw Agent] " -ForegroundColor Red -NoNewline
    Write-Host $Msg
    exit 1
}

# ── Banner ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  +==========================================+" -ForegroundColor Cyan
Write-Host "  |       ThreatClaw Agent Installer          |" -ForegroundColor Cyan
Write-Host "  |   Endpoint Security - Windows Edition     |" -ForegroundColor Cyan
Write-Host "  +==========================================+" -ForegroundColor Cyan
Write-Host ""

# ── Validate params ──────────────────────────────────────────────────────────

if (-not $Url) {
    Write-TCError "Missing -Url (or set env:TC_URL before running)"
}
if (-not $Token) {
    Write-TCError "Missing -Token (or set env:TC_TOKEN). Get it from ThreatClaw Dashboard > Skills > Osquery."
}

# Generate agent ID from hostname if not provided
if (-not $AgentId) {
    try {
        $serial = (Get-CimInstance Win32_ComputerSystemProduct).UUID.Substring(0, 8)
    } catch {
        $serial = [System.Environment]::TickCount.ToString().Substring(0, 8)
    }
    $AgentId = "agent-$($env:COMPUTERNAME.ToLower())-$serial"
}

Write-TC "TC URL:    $Url"
Write-TC "Agent ID:  $AgentId"
Write-Host ""

# ── 1. Install osquery ──────────────────────────────────────────────────────

$OsqueryBin = "C:\Program Files\osquery\osqueryd\osqueryd.exe"
$OsqueryI   = "C:\Program Files\osquery\osqueryi.exe"

if (Test-Path $OsqueryBin) {
    Write-TC "osquery already installed"
} else {
    Write-TC "Installing osquery $OsqueryVersion..."

    $msiUrl  = "https://pkg.osquery.io/windows/osquery-$OsqueryVersion.msi"
    $msiPath = Join-Path $env:TEMP "osquery.msi"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
    } catch {
        Write-TCError "Failed to download osquery from $msiUrl"
    }

    Write-TC "Running MSI installer (silent)..."
    $proc = Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /qn /norestart" -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-TCError "osquery MSI install failed (exit code $($proc.ExitCode))"
    }
    Remove-Item $msiPath -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $OsqueryBin)) {
        Write-TCError "osquery binary not found after install at $OsqueryBin"
    }
    Write-TC "osquery installed successfully"
}

# ── 2. Configure osquery ────────────────────────────────────────────────────

$ConfDir  = "C:\Program Files\osquery"
$ConfFile = Join-Path $ConfDir "osquery.conf"

Write-TC "Writing osquery configuration..."

$osqueryConf = @'
{
  "options": {
    "logger_plugin": "filesystem",
    "logger_path": "C:\\Program Files\\osquery\\log",
    "disable_events": "false",
    "events_expiry": "3600",
    "schedule_splay_percent": "10",
    "host_identifier": "hostname",
    "windows_event_channels": "System,Application,Security,Microsoft-Windows-Sysmon/Operational"
  },
  "schedule": {
    "software_windows": {
      "query": "SELECT name, version, install_date FROM programs;",
      "interval": 3600,
      "description": "Software inventory (hourly)"
    },
    "process_connections": {
      "query": "SELECT p.name, p.path, s.remote_address, s.remote_port, s.local_port, s.state FROM process_open_sockets s JOIN processes p ON s.pid = p.pid WHERE s.remote_address != '' AND s.remote_address != '127.0.0.1' AND s.remote_address != '::1' AND s.state = 'ESTABLISHED';",
      "interval": 300,
      "description": "Active network connections (5min)"
    },
    "listening_ports": {
      "query": "SELECT l.port, l.protocol, l.address, p.name as process_name, p.path FROM listening_ports l LEFT JOIN processes p ON l.pid = p.pid;",
      "interval": 300,
      "description": "Listening ports (5min)"
    },
    "logged_in_users": {
      "query": "SELECT user, tty, host, type, time FROM logged_in_users;",
      "interval": 300,
      "description": "Currently logged in users (5min)"
    },
    "scheduled_tasks": {
      "query": "SELECT name, action, path, enabled, last_run_time, next_run_time FROM scheduled_tasks WHERE enabled = 1 AND name NOT LIKE '\\Microsoft%';",
      "interval": 3600,
      "description": "Windows scheduled tasks (hourly)"
    },
    "services": {
      "query": "SELECT name, display_name, service_type, start_type, path, user_account FROM services WHERE start_type = 'AUTO_START';",
      "interval": 3600,
      "description": "Auto-start services (hourly)"
    },
    "os_version": {
      "query": "SELECT name, version, major, minor, build, platform FROM os_version;",
      "interval": 86400,
      "description": "OS version (daily)"
    },
    "system_info": {
      "query": "SELECT hostname, cpu_brand, cpu_physical_cores, physical_memory, hardware_vendor, hardware_model FROM system_info;",
      "interval": 86400,
      "description": "Hardware info (daily)"
    },
    "users": {
      "query": "SELECT uid, gid, username, directory, type FROM users;",
      "interval": 3600,
      "description": "Local users (hourly)"
    },
    "patches": {
      "query": "SELECT hotfix_id, description, installed_on FROM patches;",
      "interval": 86400,
      "description": "Windows patches/KBs (daily)"
    },
    "dns_cache": {
      "query": "SELECT name, type, answer FROM dns_cache;",
      "interval": 300,
      "description": "DNS resolver cache (5min)"
    },
    "autoexec": {
      "query": "SELECT name, path, source FROM autoexec;",
      "interval": 3600,
      "description": "Autostart entries (hourly)"
    },
    "windows_security_events": {
      "query": "SELECT datetime, source, provider_name, eventid, task, level, data FROM windows_eventlog WHERE channel = 'Security' AND eventid IN (4624,4625,4648,4672,4720,4726,4732,4756,1102) AND datetime > datetime('now', '-6 minutes');",
      "interval": 300,
      "description": "Security events - logon, privilege, account changes (5min)"
    },
    "powershell_events": {
      "query": "SELECT datetime, source, eventid, data FROM windows_eventlog WHERE channel = 'Microsoft-Windows-PowerShell/Operational' AND eventid IN (4103,4104) AND datetime > datetime('now', '-6 minutes');",
      "interval": 300,
      "description": "PowerShell script block logging (5min)"
    }
  }
}
'@

Set-Content -Path $ConfFile -Value $osqueryConf -Encoding UTF8
Write-TC "osquery configuration written"

# Start osqueryd service
if (Get-Service osqueryd -ErrorAction SilentlyContinue) {
    Restart-Service osqueryd -Force
    Write-TC "osqueryd service restarted"
} else {
    Write-TC "osqueryd service not found - will start after reboot" -Color Yellow
}

# ── 3. Create sync script ───────────────────────────────────────────────────

$SyncDir    = "C:\ProgramData\ThreatClaw"
$SyncScript = Join-Path $SyncDir "agent-sync.ps1"
$LogFile    = Join-Path $SyncDir "agent-sync.log"

New-Item -ItemType Directory -Path $SyncDir -Force | Out-Null

Write-TC "Creating sync script..."

# Use single-quoted heredoc (no interpolation), then replace tokens
$syncTemplate = @'
# ThreatClaw Agent Sync
# Collects osquery results and sends to ThreatClaw core

$ErrorActionPreference = "SilentlyContinue"
$TC_URL   = "%%TC_URL%%"
$TC_TOKEN = "%%TC_TOKEN%%"
$AGENT_ID = "%%AGENT_ID%%"
$OsqueryI = "C:\Program Files\osquery\osqueryi.exe"
$LogFile  = "C:\ProgramData\ThreatClaw\agent-sync.log"

function Run-Query {
    param([string]$Query)
    try {
        $result = & $OsqueryI --json $Query 2>$null
        if ($result) { return $result } else { return "[]" }
    } catch { return "[]" }
}

function Write-Log {
    param([string]$Msg)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$ts] $Msg" | Out-File -Append -FilePath $LogFile
}

# Collect data
$software   = Run-Query "SELECT name, version, install_date FROM programs;"
$sockets    = Run-Query "SELECT p.name, p.path, s.remote_address, s.remote_port, s.local_port, s.state FROM process_open_sockets s JOIN processes p ON s.pid = p.pid WHERE s.remote_address != '' AND s.remote_address != '127.0.0.1' AND s.state = 'ESTABLISHED';"
$ports      = Run-Query "SELECT l.port, l.protocol, l.address, p.name FROM listening_ports l LEFT JOIN processes p ON l.pid = p.pid;"
$users      = Run-Query "SELECT uid, gid, username, directory, type FROM users;"
$logins     = Run-Query "SELECT user, tty, host, type FROM logged_in_users;"
$tasks      = Run-Query "SELECT name, action, path, enabled FROM scheduled_tasks WHERE enabled = 1 AND name NOT LIKE '\Microsoft%';"
$services   = Run-Query "SELECT name, display_name, start_type, path, user_account FROM services WHERE start_type = 'AUTO_START';"
$dns        = Run-Query "SELECT name, type, answer FROM dns_cache LIMIT 200;"
$autoexec   = Run-Query "SELECT name, path, source FROM autoexec;"
$patches    = Run-Query "SELECT hotfix_id, description, installed_on FROM patches;"
$osVer      = Run-Query "SELECT name, version, build, platform FROM os_version;"
$ifaces     = Run-Query "SELECT i.interface, i.mac, a.address as ip FROM interface_details i JOIN interface_addresses a ON i.interface = a.interface WHERE i.mac != '00:00:00:00:00:00' AND a.address NOT LIKE '127.%' AND a.address NOT LIKE 'fe80%';"
$secEvents  = Run-Query "SELECT datetime, eventid, data FROM windows_eventlog WHERE channel = 'Security' AND eventid IN (4624,4625,4648,4672,4720,4726,4732,4756,1102) AND datetime > datetime('now', '-6 minutes') LIMIT 100;"
$psEvents   = Run-Query "SELECT datetime, eventid, data FROM windows_eventlog WHERE channel = 'Microsoft-Windows-PowerShell/Operational' AND eventid IN (4103,4104) AND datetime > datetime('now', '-6 minutes') LIMIT 50;"

# Parse JSON safely
function Safe-Parse { param([string]$Json) try { $Json | ConvertFrom-Json } catch { @() } }

# Build payload
$payload = @{
    hostname             = $env:COMPUTERNAME
    agent_id             = $AGENT_ID
    platform             = "windows"
    software             = Safe-Parse $software
    process_open_sockets = Safe-Parse $sockets
    listening_ports      = Safe-Parse $ports
    users                = Safe-Parse $users
    logged_in_users      = Safe-Parse $logins
    scheduled_tasks      = Safe-Parse $tasks
    services             = Safe-Parse $services
    dns_cache            = Safe-Parse $dns
    autoexec             = Safe-Parse $autoexec
    patches              = Safe-Parse $patches
    os_version           = Safe-Parse $osVer
    interface_details    = Safe-Parse $ifaces
    windows_security_events = Safe-Parse $secEvents
    powershell_events    = Safe-Parse $psEvents
} | ConvertTo-Json -Depth 4 -Compress

# Skip cert validation for self-signed TLS
Add-Type -ErrorAction SilentlyContinue -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TcCertPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TcCertPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Send to ThreatClaw
try {
    $headers = @{
        "Content-Type"    = "application/json"
        "X-Webhook-Token" = $TC_TOKEN
    }
    $uri = "${TC_URL}/api/tc/webhook/ingest/osquery?token=${TC_TOKEN}"
    Invoke-RestMethod -Uri $uri -Method POST -Body $payload -Headers $headers -TimeoutSec 30 | Out-Null
    Write-Log "Sync OK - $AGENT_ID"
    Write-Output "Sync OK"
} catch {
    Write-Log "Sync FAILED - $_"
    Write-Output "Sync FAILED - $_"
}
'@

# Replace tokens with actual values
$syncContent = $syncTemplate -replace '%%TC_URL%%', $Url -replace '%%TC_TOKEN%%', $Token -replace '%%AGENT_ID%%', $AgentId

Set-Content -Path $SyncScript -Value $syncContent -Encoding UTF8
Write-TC "Sync script created at $SyncScript"

# ── 4. Create Scheduled Task ────────────────────────────────────────────────

$TaskName = "ThreatClaw Agent Sync"

Write-TC "Creating scheduled task ($SyncInterval min interval)..."

# Remove existing task if present
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$SyncScript`""

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes $SyncInterval) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

Register-ScheduledTask -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "ThreatClaw endpoint agent - syncs osquery telemetry every $SyncInterval minutes" | Out-Null

Write-TC "Scheduled task created: '$TaskName' (every ${SyncInterval}min as SYSTEM)"

# ── 5. First sync ───────────────────────────────────────────────────────────

Write-Host ""
Write-TC "Running first sync..."
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $SyncScript
} catch {
    Write-TC "First sync failed (ThreatClaw may not be reachable yet)" -Color Yellow
}

# ── Done ─────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  +==========================================+" -ForegroundColor Green
Write-Host "  |       Installation complete!              |" -ForegroundColor Green
Write-Host "  +==========================================+" -ForegroundColor Green
Write-Host ""
Write-TC "Agent ID:  $AgentId"
Write-TC "Sync:      every ${SyncInterval} minutes (Scheduled Task as SYSTEM)"
Write-TC "Config:    $SyncScript"
Write-TC "Osquery:   $ConfFile"
Write-TC "Log:       $LogFile"
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor Cyan
Write-Host "    Check status:   Get-ScheduledTask -TaskName 'ThreatClaw Agent Sync'"
Write-Host "    Manual sync:    powershell -File C:\ProgramData\ThreatClaw\agent-sync.ps1"
Write-Host "    View logs:      Get-Content C:\ProgramData\ThreatClaw\agent-sync.log"
Write-Host "    Uninstall:      Unregister-ScheduledTask -TaskName 'ThreatClaw Agent Sync'"
Write-Host ""

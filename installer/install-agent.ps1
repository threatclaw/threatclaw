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

# Unzip that also works on Windows PowerShell 3.0/4.0 (Server 2012/R2), where
# Expand-Archive (PS 5.0+) does not exist. Falls back to .NET 4.5 then the
# Shell.Application COM object so extraction never hard-fails on an old host.
function Expand-ZipCompat {
    param([string]$Zip, [string]$Dest)
    if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
        Expand-Archive -Path $Zip -DestinationPath $Dest -Force
        return
    }
    if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force -ErrorAction SilentlyContinue }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        [System.IO.Compression.ZipFile]::ExtractToDirectory($Zip, $Dest)
    } catch {
        New-Item -ItemType Directory -Path $Dest -Force | Out-Null
        $shell = New-Object -ComObject Shell.Application
        $shell.NameSpace($Dest).CopyHere($shell.NameSpace($Zip).Items(), 0x14)
    }
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

# ── 0. Pre-flight ────────────────────────────────────────────────────────────
# Verify the server is reachable AND the token is valid BEFORE touching the
# system. Fail fast with a clear message so a wrong URL/port (often :8445, not
# 443) or a bad token never leaves a half-configured agent that silently fails.
Write-TC "Pre-flight: checking connection and token at $Url ..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Self-signed cert: skip validation for the check (same policy as the sync script).
try {
    Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TcPreflightCertPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
} catch { }
try { [Net.ServicePointManager]::CertificatePolicy = New-Object TcPreflightCertPolicy } catch { }

$tcReachable = $false
$tcBody = ""
if ($env:TC_SKIP_PREFLIGHT) {
    # Escape hatch: bypass the pre-flight entirely (e.g. an unusual proxy the
    # check can't see through). The first sync remains the real test.
    Write-TC "Pre-flight SKIPPED (TC_SKIP_PREFLIGHT set) - proceeding without checking" -Color Yellow
    $tcReachable = $true
} else {
    try {
        $r = Invoke-WebRequest -Uri "$Url/api/tc/webhook/ping/osquery" -Method Post `
            -Headers @{ "X-Webhook-Token" = $Token } -TimeoutSec 10 -UseBasicParsing
        $tcReachable = $true
        $tcBody = "$($r.Content)"
    } catch {
        # A thrown HTTP response (401/403/404/5xx...) still means the server is
        # reachable — read its body so we can look for our marker.
        if ($_.Exception.Response) {
            $tcReachable = $true
            try {
                $tcReader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $tcBody = $tcReader.ReadToEnd()
            } catch { }
        }
    }
}
if ($env:TC_DEBUG) { Write-TC ("DEBUG pre-flight: reachable={0} body={1}" -f $tcReachable, $tcBody) -Color Cyan }
# Decide ONLY on our `tc_preflight` body marker, never on the HTTP status — auth
# middleware, proxies and WAFs inject their own codes (a server without this
# endpoint returns 401; a WAF may return 403). Only an explicit 'bad_token' from
# our endpoint aborts on the token; only total unreachability aborts on connectivity.
if ($tcBody -match 'bad_token') {
    Write-TCError "Server reachable but the webhook token is INVALID. Check TC_TOKEN (Dashboard > Skills > Osquery). Nothing was installed."
} elseif (-not $tcReachable) {
    Write-TCError "Cannot reach ThreatClaw at $Url. Check the URL and PORT (often :8445, not 443) and any firewall between this host and the server. Nothing was installed."
} elseif ($tcBody -match '"tc_preflight":"ok"') {
    Write-TC "Pre-flight OK - server reachable and token valid"
} else {
    Write-TC "Pre-flight: server reachable; token check inconclusive - proceeding" -Color Yellow
}
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

# --- 1b. Install Sysmon ---
#
# Sysmon turns Windows from "I see processes start" into a real EDR signal
# source: process tree with hashes, network connections per process,
# CreateRemoteThread, LSASS access, file create. The osquery agent picks
# up the Sysmon channel automatically via the server-pushed manifest, so
# this install is a one-shot prerequisite - no further config touchpoint
# on the endpoint after deployment.

$SysmonBin    = "C:\Windows\Sysmon64.exe"
$SysmonConf   = "C:\ProgramData\ThreatClaw\sysmon-config.xml"
$SysmonZipUrl = "https://download.sysinternals.com/files/Sysmon.zip"
# Reference SwiftOnSecurity baseline — vendored at install time. If raw
# github is unreachable from the endpoint, the install still proceeds
# with the minimal config below.
$SysmonConfUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$SysmonMinConfig = @'
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <ProcessCreate onmatch="exclude"/>
    <NetworkConnect onmatch="exclude"/>
    <ImageLoad onmatch="include"><ImageLoaded condition="image">mimikatz</ImageLoaded></ImageLoad>
    <CreateRemoteThread onmatch="exclude"/>
    <ProcessAccess onmatch="include"><TargetImage condition="image">lsass.exe</TargetImage></ProcessAccess>
    <FileCreate onmatch="exclude"/>
    <DnsQuery onmatch="exclude"/>
  </EventFiltering>
</Sysmon>
'@

# Always (re)fetch the config — this is just a file write, safe on reinstall.
New-Item -ItemType Directory -Path (Split-Path $SysmonConf) -Force | Out-Null
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $SysmonConfUrl -OutFile $SysmonConf -UseBasicParsing -TimeoutSec 30
    Write-TC "Fetched Sysmon config (SwiftOnSecurity)"
} catch {
    Write-TC "Could not fetch upstream Sysmon config, using minimal embedded config" -Color Yellow
    Set-Content -Path $SysmonConf -Value $SysmonMinConfig -Encoding UTF8
}

# Detect an existing Sysmon: the service is named Sysmon64 (x64) or Sysmon
# (x86), and on a reinstall the binary at $SysmonBin is LOCKED by the running
# service. In that case we must NOT overwrite it (Copy-Item would fail with
# "file in use") — just refresh the config in place with `-c`.
$sysmonSvc = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sysmonSvc -or (Test-Path $SysmonBin)) {
    Write-TC "Sysmon already installed - updating config"
    $proc = Start-Process -FilePath $SysmonBin -ArgumentList "-accepteula -c `"$SysmonConf`"" -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        Write-TC "Sysmon config update returned exit $($proc.ExitCode) - check manually" -Color Yellow
    }
} else {
    Write-TC "Installing Sysmon..."
    $zipPath = Join-Path $env:TEMP "Sysmon.zip"
    $extractDir = Join-Path $env:TEMP "Sysmon"
    try {
        Invoke-WebRequest -Uri $SysmonZipUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec 60
    } catch {
        Write-TC "Failed to download Sysmon from $SysmonZipUrl - skipping (re-run installer later)" -Color Yellow
        $zipPath = $null
    }

    if ($zipPath -and (Test-Path $zipPath)) {
        # Sysmon is an enhancement; osquery (the core agent) is already installed
        # above. Never let a Sysmon hiccup fail the whole agent install.
        try {
            Expand-ZipCompat -Zip $zipPath -Dest $extractDir
            $sysmonExe = Join-Path $extractDir "Sysmon64.exe"
            if (Test-Path $sysmonExe) {
                Copy-Item $sysmonExe $SysmonBin -Force
                $proc = Start-Process -FilePath $SysmonBin -ArgumentList "-accepteula -i `"$SysmonConf`"" -Wait -PassThru -NoNewWindow
                if ($proc.ExitCode -eq 0) {
                    Write-TC "Sysmon installed and running"
                } else {
                    Write-TC "Sysmon install returned exit $($proc.ExitCode) - check manually" -Color Yellow
                }
            }
        } catch {
            Write-TC "Sysmon setup skipped ($($_.Exception.Message)) - osquery agent is installed and active; re-run later to add Sysmon" -Color Yellow
        }
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ── 1b. Advanced audit policy (Phase 3 — Windows coverage) ──────────────────
# Windows does not GENERATE most ATT&CK-relevant Security events unless the
# matching advanced-audit subcategory is enabled — collecting them is useless if
# they never fire. Enable the subcategories that feed the win-auth detections
# (logon, account/group management, Kerberos, credential validation, process
# creation) and turn on command-line capture in 4688.
#
# Subcategories are addressed by GUID, NOT by name: the names are localised
# (a French DC rejects English names), the GUIDs are stable across locales.
# Idempotent (auditpol /set just re-asserts) and non-fatal (an enhancement, like
# Sysmon — never fail the whole agent install over it).
try {
    $auditSubcats = [ordered]@{
        '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Logon'                          # 4624/4625
        '{0CCE9216-69AE-11D9-BED3-505054503030}' = 'Logoff'                         # 4634
        '{0CCE921B-69AE-11D9-BED3-505054503030}' = 'Special Logon'                  # 4672
        '{0CCE923F-69AE-11D9-BED3-505054503030}' = 'Credential Validation'          # 4776
        '{0CCE9242-69AE-11D9-BED3-505054503030}' = 'Kerberos Authentication Service' # 4768
        '{0CCE9240-69AE-11D9-BED3-505054503030}' = 'Kerberos Service Ticket Ops'    # 4769
        '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'User Account Management'        # 4720/4726
        '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'Security Group Management'      # 4728/4732/4756
        '{0CCE9236-69AE-11D9-BED3-505054503030}' = 'Computer Account Management'    # 4741
        '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'Process Creation'              # 4688
    }
    $auditOk = 0
    foreach ($guid in $auditSubcats.Keys) {
        $p = Start-Process -FilePath 'auditpol.exe' `
            -ArgumentList "/set /subcategory:`"$guid`" /success:enable /failure:enable" `
            -Wait -PassThru -NoNewWindow -ErrorAction Stop
        if ($p.ExitCode -eq 0) { $auditOk++ }
    }
    # Capture the process command line in Event 4688 (T1059 visibility).
    $audKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    New-Item -Path $audKey -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path $audKey -Name 'ProcessCreationIncludeCmdLine_Enabled' `
        -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
    Write-TC "Advanced audit policy applied ($auditOk/$($auditSubcats.Count) subcategories + cmdline in 4688)"
} catch {
    Write-TC "Audit policy setup skipped ($($_.Exception.Message)) - agent is active; re-run later" -Color Yellow
}
# NOTE Phase 3: Directory Service Access (4662, DCSync detection / win-auth-003)
# needs the DS Access subcategory {0CCE923B-...} AND a SACL on the domain object;
# DC-specific + high volume → handled separately when the event-id set is frozen.

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
        # osqueryi emits prettified JSON across multiple lines; PowerShell's
        # ConvertFrom-Json refuses an array of strings, so join into one.
        $result = & $OsqueryI --json $Query 2>$null
        if ($result) {
            if ($result -is [array]) { return ($result -join "`n") } else { return $result }
        } else { return "[]" }
    } catch { return "[]" }
}

# Rotate the agent log if it has grown past TC_LOG_MAX_BYTES (default
# 5 MB). One rotation slot — agent-sync.log.1 — is kept; the previous
# slot is discarded. Linux ships log to journald which handles
# rotation at the OS level, so this only matters on Windows. Run once
# at the top of the sync rather than per-line to keep Write-Log
# constant-cost.
$LogMaxBytes = 5MB
try {
    if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt $LogMaxBytes)) {
        $rotated = "$LogFile.1"
        if (Test-Path $rotated) { Remove-Item -Path $rotated -Force -ErrorAction SilentlyContinue }
        Move-Item -Path $LogFile -Destination $rotated -Force -ErrorAction SilentlyContinue
    }
} catch { }

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
$ifaces     = Run-Query "SELECT i.interface, i.mac, a.address as ip FROM interface_details i JOIN interface_addresses a ON i.interface = a.interface WHERE i.mac != '00:00:00:00:00:00' AND a.address NOT LIKE '127.%' AND a.address NOT LIKE 'fe80%' AND i.description NOT LIKE 'Hyper-V%' AND i.description NOT LIKE 'WSL%' AND i.description NOT LIKE 'vEthernet%' AND i.description NOT LIKE 'TAP-Windows%';"
# Security + PowerShell events are collected by CURSOR further down (after the
# delta state is loaded), not by a fixed -6min window — so a missed sync never
# drops events. Same event-id set as before (coverage extension is a later phase).

# PowerShell's pipeline behaviour around arrays makes ConvertTo-Json wrap
# inner arrays as `{"value":[...]}` whenever the array transits through a
# function return. We bypass that entirely by assembling the JSON payload
# as a string template — each $X holds the *raw* JSON string returned by
# osqueryi, so there's no parse/re-serialize round-trip and arrays stay
# arrays. JsonChunk sanitises empty/null inputs into "[]" / "{}".
function JsonChunk {
    param([string]$Raw, [string]$Default = "[]")
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $Default }
    $t = $Raw.Trim()
    if ($t -eq "null" -or $t.Length -eq 0) { return $Default }
    return $t
}

function JsonString {
    param([string]$S)
    if ($null -eq $S) { return '""' }
    return '"' + ($S -replace '\\','\\\\' -replace '"','\\"') + '"'
}

# os_version is the only field TC expects as a single object rather than
# an array. Fall back to "{}" when the query returned an empty list.
function FirstObject {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return "{}" }
    try {
        $arr = $Raw | ConvertFrom-Json
        if ($null -eq $arr) { return "{}" }
        if ($arr -is [array]) {
            if ($arr.Count -eq 0) { return "{}" }
            return ($arr[0] | ConvertTo-Json -Compress -Depth 4)
        }
        return ($arr | ConvertTo-Json -Compress -Depth 4)
    } catch { return "{}" }
}

# ── Delta-sync state (Phase 1 transport) ────────────────────────────────────
# Persisted between cycles so the agent ships only what changed: a hash per
# inventory section, a datetime cursor per event source, and the last full
# refresh time. Lives next to the sync script.
$StateFile = "C:\ProgramData\ThreatClaw\state.json"
function Get-State {
    if (Test-Path $StateFile) {
        try { return (Get-Content $StateFile -Raw | ConvertFrom-Json) } catch { }
    }
    return [pscustomobject]@{ hashes = [pscustomobject]@{}; cursors = [pscustomobject]@{}; last_full = 0 }
}
function Save-State($state) {
    try { $state | ConvertTo-Json -Depth 6 | Set-Content $StateFile -Encoding UTF8 } catch { }
}
function Get-SectionHash([string]$json) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-","")
}
# GzipStream ships with .NET 4.5+ (present on Server 2012R2 and up). Callers wrap
# this in try/catch so a host without it falls back to an uncompressed POST.
function Compress-Gzip([byte[]]$bytes) {
    $ms = New-Object IO.MemoryStream
    $gz = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Compress)
    $gz.Write($bytes, 0, $bytes.Length); $gz.Close()
    # Leading comma: stop PowerShell from UNROLLING the byte[] on return. Without
    # it the caller gets an object[] of bytes, and Invoke-RestMethod then sends the
    # body as the decimal string "31 139 8 0 ..." instead of raw gzip bytes — the
    # server sees a bogus gzip header and rejects the payload.
    return ,$ms.ToArray()
}

$hostnameJson = JsonString $env:COMPUTERNAME
$agentIdJson  = JsonString $AGENT_ID

# ── Load delta state + decide on a periodic full refresh ────────────────────
$state = Get-State
# Unix time, culture-invariant (avoid Get-Date -UFormat %s + [double]::Parse,
# which misreads the decimal under fr-FR and breaks the refresh math) and
# .NET 4.5-safe (no DateTimeOffset.ToUnixTimeSeconds, which needs 4.6).
$epoch = New-Object DateTime(1970,1,1,0,0,0,[System.DateTimeKind]::Utc)
$now = [int64]([DateTime]::UtcNow - $epoch).TotalSeconds
$fullRefresh = ($now - [int64]$state.last_full) -gt 86400   # force a full snapshot 1x/day (self-heal)

# Inventory delta: include a section only when its canonical JSON hash changed
# (or on the daily full refresh). The queries above still run every cycle (so
# the collected set is unchanged); we only decide what to PUT ON THE WIRE here.
$invParts = @()
function Add-Section($name, $rawJson) {
    $clean = (JsonChunk $rawJson)
    $h = Get-SectionHash $clean
    $prev = $state.hashes.$name
    if ($fullRefresh -or $prev -ne $h) {
        $script:invParts += ('"' + $name + '":' + $clean)
        $state.hashes | Add-Member -NotePropertyName $name -NotePropertyValue $h -Force
    }
}
Add-Section "software"          $software
Add-Section "patches"           $patches
Add-Section "services"          $services
Add-Section "scheduled_tasks"   $tasks
Add-Section "users"             $users
Add-Section "autoexec"          $autoexec
Add-Section "interface_details" $ifaces
Add-Section "logged_in_users"   $logins
# os_version is a single object (FirstObject), not an array — same hash gate.
$osRaw = (FirstObject $osVer)
$osH = Get-SectionHash $osRaw
if ($fullRefresh -or $state.hashes.os_version -ne $osH) {
    $invParts += ('"os_version":' + $osRaw)
    $state.hashes | Add-Member -NotePropertyName os_version -NotePropertyValue $osH -Force
}
if ($fullRefresh) { $state.last_full = $now }

# Events by cursor: ship only events newer than the last datetime we synced OK,
# ordered, capped. A missed/failed sync is caught up next cycle from the cursor
# (no fixed-window hole). If the cap is hit we flag truncation so the server can
# surface a possible log-flood/evasion instead of silently losing events.
$cap = 10000
function Collect-Events($name, $channel, $eventFilter) {
    $cur = $state.cursors.$name
    if ([string]::IsNullOrEmpty($cur)) { $cur = (Get-Date).AddMinutes(-6).ToString("yyyy-MM-dd HH:mm:ss") }
    $q = "SELECT datetime, eventid, data FROM windows_eventlog WHERE channel = '$channel' AND $eventFilter AND datetime >= '$cur' ORDER BY datetime ASC LIMIT $cap;"
    $raw = Run-Query $q
    $arr = @(); try { $arr = @($raw | ConvertFrom-Json) } catch { }
    $truncated = ($arr.Count -ge $cap)
    if ($arr.Count -gt 0) {
        $maxDt = ($arr | Select-Object -Last 1).datetime
        $state.cursors | Add-Member -NotePropertyName $name -NotePropertyValue $maxDt -Force
    }
    return [pscustomobject]@{ raw = (JsonChunk $raw); truncated = $truncated }
}
# Phase 3: event-id set aligned with the rewritten win-auth detections (the server
# emits every Security event generically, so the rule's channel+eventid match drives
# detection). Added: 4624 (PtH/RDP), 4662 (DCSync), 4728 (priv-group add), 4768/4769
# (Kerberos/Kerberoasting), 4776 (NTLM cred validation). 4688/4672 left OUT on
# purpose (very high volume, no rule consumes them yet — audit policy enables them
# so they can be added later without re-rolling the host).
$sec = Collect-Events "windows_security_events" "Security" "eventid IN (4624,4625,4662,4720,4726,4728,4732,4756,4768,4769,4776,1102)"
$ps  = Collect-Events "powershell_events" "Microsoft-Windows-PowerShell/Operational" "eventid IN (4103,4104)"

# Skip cert validation for self-signed TLS (also needed for the manifest call below)
Add-Type -ErrorAction SilentlyContinue -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TcCertPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TcCertPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Server-driven extra queries (Brique 2) ---
# Fetch the agent manifest. The server returns a list of extra osquery
# queries (e.g. Sysmon channel, Windows Firewall log, future additions).
# Running them here means we can add a new detection source by editing one
# Rust file on the server - never the 200+ endpoints. Manifest fetch
# failure is non-fatal: we just sync without the extras this cycle.
$manifestExtras = ""
$acceptsGzip = $false   # only gzip if the server advertised it (version-skew safe)
try {
    $manifestUri = "${TC_URL}/api/tc/agent/manifest?platform=windows&token=${TC_TOKEN}"
    $manifest = Invoke-RestMethod -Uri $manifestUri -Method GET -Headers @{"X-Webhook-Token" = $TC_TOKEN} -TimeoutSec 10
    if ($manifest) { $acceptsGzip = [bool]$manifest.accepts_gzip }
    if ($manifest -and $manifest.queries) {
        Write-Log "Manifest fetched, version=$($manifest.version), $($manifest.queries.Count) extra queries"
        $parts = @()
        foreach ($q in $manifest.queries) {
            $raw = Run-Query $q.query
            $parts += '"' + $q.name + '":' + (JsonChunk $raw)
        }
        if ($parts.Count -gt 0) { $manifestExtras = "," + ($parts -join ",") }
    }
} catch {
    Write-Log "Manifest fetch failed - $_ (continuing without extras)"
}

# Assemble payload. hostname/agent_id/ts are ALWAYS present = heartbeat (a quiet
# host stays distinguishable from a dead one). Volatile detection inputs
# (sockets, listening ports, dns) are ALWAYS shipped — they must be re-checked
# against threat intel every cycle, so they are never delta'd. Inventory
# ($invStr) is delta. Events come from the cursor. Truncation flags ride along.
$truncFlags = @()
if ($sec.truncated) { $truncFlags += '"windows_security_events_truncated":true' }
if ($ps.truncated)  { $truncFlags += '"powershell_events_truncated":true' }
$invStr = ""
if ($invParts.Count -gt 0) { $invStr = "," + ($invParts -join ",") }
$truncStr = ""
if ($truncFlags.Count -gt 0) { $truncStr = "," + ($truncFlags -join ",") }
$payload = @"
{"hostname":$hostnameJson,"agent_id":$agentIdJson,"platform":"windows","ts":$now,"process_open_sockets":$(JsonChunk $sockets),"listening_ports":$(JsonChunk $ports),"dns_cache":$(JsonChunk $dns),"windows_security_events":$($sec.raw),"powershell_events":$($ps.raw)$invStr$truncStr$manifestExtras}
"@

# Send to ThreatClaw — gzip only if the server advertised it (negotiated via the
# manifest accepts_gzip flag), with a clear fallback to plaintext if compression
# is unavailable. State (cursors/hashes/last_full) is saved ONLY after a 200, so
# a failed sync re-sends the exact same delta next cycle (no lost events).
try {
    $headers = @{
        "Content-Type"    = "application/json"
        "X-Webhook-Token" = $TC_TOKEN
    }
    $uri = "${TC_URL}/api/tc/webhook/ingest/osquery?token=${TC_TOKEN}"
    $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
    $useGzip = $false
    if ($acceptsGzip) {
        try { [byte[]]$bytes = Compress-Gzip $bytes; $headers["Content-Encoding"] = "gzip"; $useGzip = $true } catch { }
    }
    Invoke-RestMethod -Uri $uri -Method POST -Body $bytes -Headers $headers -TimeoutSec 120 | Out-Null
    Save-State $state
    Write-Log ("Sync OK - $AGENT_ID (gzip=$useGzip, inv=" + $invParts.Count + " sections)")
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
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

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
Write-Host "    Uninstall:      irm get.threatclaw.io/agent/uninstall/windows | iex"
Write-Host "                    (removes the scheduled task, Sysmon, osquery, and C:\ProgramData\ThreatClaw)"
Write-Host "                    add -KeepSysmon / -KeepOsquery to keep either component"
Write-Host ""

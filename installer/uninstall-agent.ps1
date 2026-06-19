# ThreatClaw endpoint agent — Windows uninstaller.
#
# Run as Administrator (or via the one-liner served by the gateway):
#   irm get.threatclaw.io/agent/uninstall | iex
#
# Removes everything install-agent.ps1 deployed: the scheduled task,
# the Sysmon service + driver, the osquery MSI, and the entire
# `C:\ProgramData\ThreatClaw\` directory (which carries the webhook
# token in clear text). Anything missing is treated as "already gone"
# and reported as a skip, so the script is idempotent.
#
# Flags:
#   -KeepSysmon   Leave Sysmon installed (some sites share Sysmon
#                 across multiple SOC products).
#   -KeepOsquery  Leave osquery installed (same reason).

[CmdletBinding()]
param(
    [switch]$KeepSysmon,
    [switch]$KeepOsquery
)

$ErrorActionPreference = 'Continue'

function Write-TC([string]$Msg, [ConsoleColor]$Color = 'Cyan') {
    Write-Host "[ThreatClaw] $Msg" -ForegroundColor $Color
}
function Write-Step([string]$Msg) { Write-Host "  → $Msg" -ForegroundColor White }
function Write-Skip([string]$Msg) { Write-Host "  · $Msg" -ForegroundColor DarkGray }
function Write-Done([string]$Msg) { Write-Host "  ✓ $Msg" -ForegroundColor Green }
function Write-Warn2([string]$Msg) { Write-Host "  ! $Msg" -ForegroundColor Yellow }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ThreatClaw] Administrator privileges required. Right-click PowerShell -> Run as administrator." -ForegroundColor Red
    exit 1
}

Write-TC "Uninstalling ThreatClaw endpoint agent..."

# ── 1. Scheduled task ──────────────────────────────────────────────
$taskName = 'ThreatClaw Agent Sync'
Write-Step "Scheduled task '$taskName'"
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    try {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        Write-Done "removed"
    } catch {
        Write-Warn2 "could not remove ($($_.Exception.Message))"
    }
} else {
    Write-Skip "not present"
}

# ── 2. Sysmon service + driver ─────────────────────────────────────
if ($KeepSysmon) {
    Write-Step "Sysmon — kept (-KeepSysmon)"
} else {
    Write-Step "Sysmon service + kernel driver"
    $sysmonSvc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if (-not $sysmonSvc) { $sysmonSvc = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue }
    if ($sysmonSvc) {
        $sysmonBin = "C:\Windows\Sysmon64.exe"
        if (-not (Test-Path $sysmonBin)) { $sysmonBin = "C:\Windows\Sysmon.exe" }
        if (Test-Path $sysmonBin) {
            try {
                $proc = Start-Process -FilePath $sysmonBin -ArgumentList "-u force" -Wait -PassThru -NoNewWindow -ErrorAction Stop
                if ($proc.ExitCode -eq 0) {
                    Write-Done "uninstalled (driver unloaded)"
                } else {
                    Write-Warn2 "Sysmon -u returned exit code $($proc.ExitCode); attempting sc delete fallback"
                    & sc.exe delete $sysmonSvc.Name | Out-Null
                    Write-Done "service removed via sc.exe"
                }
            } catch {
                Write-Warn2 "Sysmon -u failed: $($_.Exception.Message); attempting sc delete"
                & sc.exe delete $sysmonSvc.Name | Out-Null
            }
            Remove-Item -Path $sysmonBin -Force -ErrorAction SilentlyContinue
        } else {
            Write-Warn2 "service present but binary missing — running sc delete"
            & sc.exe delete $sysmonSvc.Name | Out-Null
        }
    } else {
        Write-Skip "not present"
    }
}

# ── 3. osquery MSI ─────────────────────────────────────────────────
if ($KeepOsquery) {
    Write-Step "osquery — kept (-KeepOsquery)"
} else {
    Write-Step "osquery"
    # Look up the product code from the registry so we can call msiexec /x
    # without the user having to guess the GUID. Stop the daemon first to
    # avoid the MSI prompting for a reboot.
    Stop-Service -Name 'osqueryd' -Force -ErrorAction SilentlyContinue
    $uninstallKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $osqueryFound = $false
    foreach ($k in $uninstallKeys) {
        $entries = Get-ChildItem -Path $k -ErrorAction SilentlyContinue |
            Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like 'osquery*' }
        foreach ($e in $entries) {
            $osqueryFound = $true
            if ($e.UninstallString) {
                Write-Step "uninstalling $($e.DisplayName) [$($e.PSChildName)]"
                # PSChildName is usually the MSI product code in {GUID} form
                $msiArgs = "/x $($e.PSChildName) /qn /norestart"
                try {
                    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
                    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 1605) {
                        Write-Done "removed"
                    } else {
                        Write-Warn2 "msiexec returned $($proc.ExitCode) — check Programs & Features manually"
                    }
                } catch {
                    Write-Warn2 "msiexec failed: $($_.Exception.Message)"
                }
            }
        }
    }
    if (-not $osqueryFound) { Write-Skip "not present" }
}

# ── 4. ProgramData directory (contains the webhook token in clear) ──
$dir = "C:\ProgramData\ThreatClaw"
Write-Step "$dir"
if (Test-Path $dir) {
    try {
        Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
        Write-Done "removed"
    } catch {
        Write-Warn2 "could not remove ($($_.Exception.Message)) — try closing any open log viewer and re-running"
    }
} else {
    Write-Skip "not present"
}

# ── 5. Token reminder ──────────────────────────────────────────────
Write-Host ""
Write-TC "Done." 'Green'
Write-Host ""
Write-Host "    Important: the webhook token that was embedded in this host's" -ForegroundColor Yellow
Write-Host "    agent-sync.ps1 is now off the disk but the gateway still accepts" -ForegroundColor Yellow
Write-Host "    it. Revoke it from the dashboard:" -ForegroundColor Yellow
Write-Host "        Skills -> Osquery -> Revoke / regenerate webhook token" -ForegroundColor Yellow
Write-Host ""

# ThreatClaw Installer for Windows
# Usage: irm https://get.threatclaw.io/windows | iex
# Or:    .\get-threatclaw.ps1
#
# This script:
# 1. Downloads the latest ThreatClaw binary from GitHub Releases
# 2. Verifies the SHA-256 checksum
# 3. Installs to %LOCALAPPDATA%\ThreatClaw
# 4. Adds to PATH

$ErrorActionPreference = "Stop"

$Repo = "threatclaw/threatclaw"
$InstallDir = "$env:LOCALAPPDATA\ThreatClaw"
$ConfigDir = "$env:USERPROFILE\.threatclaw"
$BinaryName = "threatclaw-windows-amd64.exe"

function Write-TC {
    param([string]$Message, [string]$Color = "Green")
    Write-Host "[ThreatClaw] " -ForegroundColor $Color -NoNewline
    Write-Host $Message
}

function Write-TCError {
    param([string]$Message)
    Write-Host "[ThreatClaw] " -ForegroundColor Red -NoNewline
    Write-Host $Message
    exit 1
}

# ── Banner ──
Write-Host ""
Write-Host "  +========================================+" -ForegroundColor Cyan
Write-Host "  |         ThreatClaw Installer            |" -ForegroundColor Cyan
Write-Host "  |   Autonomous Cybersecurity Agent        |" -ForegroundColor Cyan
Write-Host "  +========================================+" -ForegroundColor Cyan
Write-Host ""

# ── Get latest version ──
Write-TC "Checking latest version..."
try {
    $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
    $Version = $releases.tag_name
} catch {
    try {
        $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases" -UseBasicParsing
        $Version = $releases[0].tag_name
    } catch {
        Write-TCError "Could not determine latest version. Check https://github.com/$Repo/releases"
    }
}
Write-TC "Version: $Version"

# ── Download ──
$DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$BinaryName"
$ChecksumUrl = "https://github.com/$Repo/releases/download/$Version/$BinaryName.sha256"

$TmpDir = Join-Path $env:TEMP "threatclaw-install"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null
$TmpBin = Join-Path $TmpDir "threatclaw.exe"

Write-TC "Downloading $BinaryName..."
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TmpBin -UseBasicParsing
} catch {
    Write-TCError "Download failed. Is the release public?"
}

# ── Verify checksum ──
Write-TC "Verifying checksum..."
try {
    $checksumFile = Join-Path $TmpDir "threatclaw.sha256"
    Invoke-WebRequest -Uri $ChecksumUrl -OutFile $checksumFile -UseBasicParsing
    $Expected = (Get-Content $checksumFile).Split(" ")[0].Trim()
    $Actual = (Get-FileHash $TmpBin -Algorithm SHA256).Hash.ToLower()
    if ($Expected -ne $Actual) {
        Remove-Item -Recurse -Force $TmpDir
        Write-TCError "Checksum mismatch!`n  Expected: $Expected`n  Got:      $Actual`n`nThe binary may be corrupted or tampered with."
    }
    Write-TC "Checksum verified"
} catch {
    Write-TC "Checksum file not found - skipping verification" -Color Yellow
}

# ── Install ──
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null

$TargetBin = Join-Path $InstallDir "threatclaw.exe"
Move-Item -Path $TmpBin -Destination $TargetBin -Force
Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue

Write-TC "Installed to $TargetBin"

# ── Add to PATH ──
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-TC "Added $InstallDir to PATH"
} else {
    Write-TC "Already in PATH"
}

# ── Create default config ──
$EnvFile = Join-Path $ConfigDir ".env"
if (-not (Test-Path $EnvFile)) {
    $DbPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
    @"
DATABASE_URL=postgres://threatclaw:${DbPassword}@127.0.0.1:5432/threatclaw
REDIS_URL=redis://127.0.0.1:6379/0
LLM_BACKEND=ollama
TC_PERMISSION_LEVEL=ALERT_ONLY
TC_INSTANCE_NAME=threatclaw
RUST_LOG=info
TC_DB_PASSWORD=${DbPassword}
"@ | Set-Content -Path $EnvFile
    Write-TC "Configuration written to $EnvFile"
} else {
    Write-TC "Existing configuration preserved at $EnvFile"
}

# ── Check Docker ──
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-TC "Docker detected"
} else {
    Write-TC "Docker not found. Install Docker Desktop: https://www.docker.com/products/docker-desktop/" -Color Yellow
}

# ── Check Ollama ──
if (Get-Command ollama -ErrorAction SilentlyContinue) {
    Write-TC "Ollama detected"
} else {
    Write-TC "Ollama not found. Install it for local AI: https://ollama.com/download/windows" -Color Yellow
}

# ── Next steps ──
Write-Host ""
Write-TC "Installation complete!"
Write-Host ""
Write-Host "  Next steps:"
Write-Host "  1. Install Docker Desktop (if not already)"
Write-Host "  2. Start infrastructure:  cd $ConfigDir && docker compose -f docker-compose.core.yml up -d"
Write-Host "  3. Start ThreatClaw:      threatclaw run"
Write-Host "  4. Open dashboard:        http://localhost:3001"
Write-Host ""
Write-Host "  Or run the setup wizard:  threatclaw onboard"
Write-Host ""

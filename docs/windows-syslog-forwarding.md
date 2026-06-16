# Forwarding Windows event logs to ThreatClaw via syslog

When the endpoint agent is not an option (locked-down hosts, third-party security software conflict, faster fleet rollout needed), Windows event logs can be forwarded to the ThreatClaw syslog endpoint instead. Each host that sends its first event lands in the inventory automatically; nothing else needs to be configured server-side.

This guide uses **NXLog Community Edition**, the most widely deployed Windows-to-syslog forwarder. The same outcome can be reached with winlogbeat or syslog-ng for Windows, but NXLog has the lowest configuration surface.

## What ThreatClaw expects on the wire

The bundled fluent-bit instance listens on the gateway host for syslog over both UDP and TCP, on the standard port:

| Port      | Protocol | Format    | Use it when                                     |
|-----------|----------|-----------|-------------------------------------------------|
| `514/tcp` | TCP      | RFC 3164  | Default. Reliable delivery, ordered, ack'd.     |
| `514/udp` | UDP      | RFC 3164  | Lossy networks; fire-and-forget.                |

TCP is the default recommendation: a single dropped UDP packet on a saturated link silently loses the event, while TCP retransmits.

## Endpoint setup, single host

1. Download **NXLog Community Edition** from the official site and run the installer with default options. The service installs into `C:\Program Files\nxlog`.

2. Replace `C:\Program Files\nxlog\conf\nxlog.conf` with the file below. Two values need to match your deployment:
   - `<THREATCLAW_HOST>` — the IP or hostname the agents reach you on
   - `<THREATCLAW_PORT>` — `514` unless you customised it

3. Restart the service:

   ```powershell
   Restart-Service nxlog
   ```

4. Within a minute the host appears in Inventory on the dashboard. If it does not, tail `C:\Program Files\nxlog\data\nxlog.log` and look for a TCP connection error.

## nxlog.conf template

```nxlog
define ROOT C:\Program Files\nxlog
Moduledir   %ROOT%\modules
CacheDir    %ROOT%\data
Pidfile     %ROOT%\data\nxlog.pid
SpoolDir    %ROOT%\data
LogFile     %ROOT%\data\nxlog.log
LogLevel    INFO

<Extension _syslog>
    Module xm_syslog
</Extension>

# ── INPUT: Windows event channels worth forwarding ──
# Security      — logons, account changes, privilege use, audit-log clear
# System        — service / driver / boot events
# Application   — keep Error/Warning/Info only (skip Verbose to stay quiet)
# PowerShell    — script-block logging (requires Group Policy Object enable
#                 under: Computer Configuration > Administrative Templates >
#                 Windows Components > Windows PowerShell)
# Sysmon        — optional; only carries events if Sysmon is installed
<Input eventlog>
    Module im_msvistalog
    Query <QueryList>\
            <Query Id="0">\
                <Select Path="Security">*</Select>\
                <Select Path="System">*</Select>\
                <Select Path="Application">*[System[(Level=1 or Level=2 or Level=3)]]</Select>\
                <Select Path="Microsoft-Windows-PowerShell/Operational">*</Select>\
                <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>\
            </Query>\
          </QueryList>
</Input>

# ── OUTPUT: syslog to ThreatClaw over TCP ──
# Facility local0 is the convention for application-pushed events.
# to_syslog_bsd() emits RFC 3164, which is what the gateway parses.
<Output threatclaw>
    Module om_tcp
    Host <THREATCLAW_HOST>
    Port <THREATCLAW_PORT>
    Exec $SyslogFacilityValue = 16;
    Exec $SyslogSeverityValue = 5;
    Exec to_syslog_bsd();
</Output>

<Route eventlog_to_threatclaw>
    Path eventlog => threatclaw
</Route>
```

## Fleet rollout via GPO

Two pieces ship to every Windows host: the MSI installer and the `nxlog.conf` file. The cleanest pattern is a computer-scoped startup script that does both idempotently.

### 1. Host the installer and config on an internal share

```
\\fileserver\threatclaw\
    nxlog-ce-3.2.2329.msi
    nxlog.conf
```

The `nxlog.conf` on the share is the template above, with `<THREATCLAW_HOST>` and `<THREATCLAW_PORT>` already filled in.

### 2. Startup script (PowerShell, computer scope)

Save the script below under the GPO at `Computer Configuration > Policies > Windows Settings > Scripts (Startup/Shutdown) > Startup`.

```powershell
# install-nxlog-threatclaw.ps1
# Idempotent: re-runs are no-ops once the service is installed and the
# config matches the share.

$share       = '\\fileserver\threatclaw'
$msiName     = 'nxlog-ce-3.2.2329.msi'
$confName    = 'nxlog.conf'
$installPath = 'C:\Program Files\nxlog'
$confPath    = Join-Path $installPath 'conf\nxlog.conf'

# 1. Install NXLog if it is not already present
if (-not (Test-Path "$installPath\nxlog.exe")) {
    Start-Process msiexec.exe `
        -ArgumentList "/i `"$share\$msiName`" /qn /norestart" `
        -Wait
}

# 2. Push the config if its hash does not match the share copy
$srcHash = Get-FileHash "$share\$confName" -Algorithm SHA256
$dstHash = if (Test-Path $confPath) {
    Get-FileHash $confPath -Algorithm SHA256
} else { $null }

if ($null -eq $dstHash -or $srcHash.Hash -ne $dstHash.Hash) {
    Copy-Item "$share\$confName" $confPath -Force
    Restart-Service nxlog -ErrorAction SilentlyContinue
}

# 3. Make sure the service is set to auto-start and running
Set-Service nxlog -StartupType Automatic
if ((Get-Service nxlog).Status -ne 'Running') {
    Start-Service nxlog
}
```

After the GPO applies (next reboot, or `gpupdate /force` on demand), every domain-joined Windows host starts forwarding its event logs to the gateway. Each new host appears in Inventory on first event.

## Verifying

On the gateway, the syslog ingest path stamps every event with a hostname. The fastest check is the **Hunt** page:

1. Open `/hunt` on the dashboard.
2. Set the hostname filter to the Windows host you just configured.
3. Events should appear within one minute of NXLog starting.

If nothing arrives:
- Confirm the host reaches the gateway: `Test-NetConnection <THREATCLAW_HOST> -Port <THREATCLAW_PORT>` should return `TcpTestSucceeded : True`.
- Tail `C:\Program Files\nxlog\data\nxlog.log` — connection errors land there in plain text.
- Confirm the firewall on the Windows host allows the NXLog service outbound: by default Defender allows it, but a third-party endpoint security suite may quarantine new services on first run.

## Sizing note

A single Windows host with the channel selection above ships roughly **150 to 400 events per minute** during business hours, dropping to 20 to 50 at night. The gateway sizes its ingest path for 10 000 events per minute per source by default; the 60-event-per-minute per-host rate limit applies to webhook ingest only, not syslog.

# Endpoint Agent

The ThreatClaw endpoint agent is what lets the platform see what is
happening **inside** each monitored host — beyond what a network
firewall or syslog forwarder can offer. It runs on Linux and Windows
and reports back over HTTPS to your ThreatClaw gateway.

## What it does

On every sync cycle (default: 5 minutes) the agent collects:

- **Software inventory** — installed packages with versions, used by
  the vulnerability matcher to surface CVEs that affect this host.
- **Running processes, listening ports, scheduled tasks**, persistence
  hooks (services, cron, crontab on Linux; services, scheduled tasks
  and run-keys on Windows).
- **User and group changes** since the last sync.
- **Recent security events** — Sysmon process telemetry on Windows,
  auditd / journald entries on Linux.

Everything is pushed as a single signed payload to
`/api/tc/webhook/ingest/osquery` authenticated by a per-source webhook
token. The agent never opens an inbound port and never accepts
commands from the gateway — the model is "the host pushes, the
gateway reads".

Under the hood the agent leverages:

- **osquery** as the data-collection engine (queries listed in
  `installer/install-agent.sh` and embedded in the Windows
  installer).
- **Sysmon** with a curated config on Windows for process /
  network / image-load telemetry.
- A small `agent-sync` script (PowerShell on Windows, POSIX shell on
  Linux) glued to the OS scheduler (Task Scheduler / systemd timer).

## Install

The dashboard's **Setup → Endpoints** page gives you copy-paste
commands with the gateway URL and the webhook token already filled
in. The general shapes are:

### Linux

```bash
curl -fsSL https://get.threatclaw.io/agent | \
  sudo bash -s -- --url https://your-tc-server --token <WEBHOOK_TOKEN>
```

Or, keeping the token out of `ps`/shell history:

```bash
echo '<WEBHOOK_TOKEN>' > /run/tc-token && chmod 600 /run/tc-token
curl -fsSL https://get.threatclaw.io/agent | \
  sudo bash -s -- --url https://your-tc-server --token-file /run/tc-token
```

Supported distributions: Debian 12+, Ubuntu 22.04+, RHEL 9+, Fedora.
macOS is best-effort via Homebrew.

### Windows

PowerShell as Administrator:

```powershell
$env:TC_URL='https://your-tc-server'
$env:TC_TOKEN='<WEBHOOK_TOKEN>'
irm https://get.threatclaw.io/agent/windows | iex
```

The installer registers a scheduled task `ThreatClaw Agent Sync` that
runs every 5 minutes as `SYSTEM`.

### Pre-flight check

Before touching the host, the installer probes the gateway and the
token. A clear failure aborts the install with an actionable message
rather than leaving a half-configured agent behind. If you need to
skip the check (for example to install against a gateway whose
network path is only reachable via a jump host), set
`TC_SKIP_PREFLIGHT=1` for the duration of the install.

## Verify the install

Three checks, fastest first:

1. **Dashboard**: open **Setup → Endpoints**. The new host appears
   with its hostname and a recent `last_sync` timestamp.
2. **Local logs**: the agent writes one log line per sync.
   - Windows: `Get-Content C:\ProgramData\ThreatClaw\agent-sync.log`
   - Linux:   `journalctl -u threatclaw-agent.service -n 50`
3. **Manual sync** to force a cycle now:
   - Windows: `powershell -File C:\ProgramData\ThreatClaw\agent-sync.ps1`
   - Linux:   `sudo /usr/local/bin/threatclaw-agent-sync`

## Operate

Useful day-to-day commands:

| Action          | Windows                                                                  | Linux                                          |
|-----------------|--------------------------------------------------------------------------|------------------------------------------------|
| Check status    | `Get-ScheduledTask -TaskName 'ThreatClaw Agent Sync'`                    | `systemctl status threatclaw-agent.timer`      |
| Trigger now     | `Start-ScheduledTask -TaskName 'ThreatClaw Agent Sync'`                  | `sudo systemctl start threatclaw-agent.service` |
| Tail the log    | `Get-Content C:\ProgramData\ThreatClaw\agent-sync.log -Tail 20 -Wait`    | `journalctl -u threatclaw-agent -f`            |
| Stop temporarily| `Disable-ScheduledTask -TaskName 'ThreatClaw Agent Sync'`                | `sudo systemctl stop threatclaw-agent.timer`   |
| Re-enable       | `Enable-ScheduledTask -TaskName 'ThreatClaw Agent Sync'`                 | `sudo systemctl start threatclaw-agent.timer`  |

## Uninstall

Cleanest path — a single one-liner served by your gateway, the same
way the installer is served:

### Windows

```powershell
irm https://get.threatclaw.io/agent/uninstall/windows | iex
```

Removes the scheduled task, Sysmon (service + kernel driver), the
osquery MSI, and the entire `C:\ProgramData\ThreatClaw\` directory
(which carries the webhook token in clear text). Add `-KeepSysmon`
or `-KeepOsquery` to leave either component in place — useful if you
share Sysmon or osquery with another SOC product on the same host.

### Linux

```bash
curl -fsSL https://get.threatclaw.io/agent/uninstall | sudo bash
```

Removes the systemd timer + service, `/usr/local/bin/threatclaw-agent-sync`
(which carries the webhook token in clear text), the osquery package,
and osquery's own logs under `/var/log/osquery/`. Set
`TC_KEEP_OSQUERY=1` before the pipe to keep osquery installed.

### Finish the cleanup on the gateway

Both uninstallers remind you of this at the end — once the host is
clean, **revoke the webhook token** so a leaked copy can no longer
push to your gateway: **Skills → Osquery → Revoke / regenerate
webhook token**.

## Troubleshooting

- **The agent is registered but `last_sync` is stale.** Check the
  agent log on the host. The most common causes are: the gateway URL
  is no longer reachable (firewall change, TLS expiry, port mapping
  rotation), the webhook token was revoked, or osquery itself failed
  to start.
- **A reinstall on top of an existing host fails.** Run the
  uninstaller first, then reinstall — the installer is idempotent
  for the scheduled task and the agent script but not for the Sysmon
  driver or the osquery MSI.
- **The agent is shipping but the host does not appear in
  Inventory.** Make sure the asset was not previously merged into a
  canonical (status `merged` hides it from the default view).

## Security model

- Outbound HTTPS only. No inbound port, no listener.
- One webhook token per ingest source (configured under **Skills →
  Osquery**). Revoking it terminates every host that uses it.
- The token is stored on disk inside the agent script (so the OS
  scheduler can run unattended). Treat the host as authoritative —
  if it is compromised, rotate the token on the dashboard.
- All collected data stays inside your ThreatClaw deployment. The
  agent never reaches an Anthropic / CyberConsulting endpoint
  directly.

## Related

- [Getting started](getting-started.md) — the abridged install flow.
- [Configuration](configuration.md) — gateway URL, TLS, ports.
- [API reference](api.md) — every endpoint the agent talks to.

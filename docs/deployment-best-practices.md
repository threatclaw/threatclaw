# Deployment best practices

This page is the short version of "what do I activate on my hosts to
get the most out of ThreatClaw without producing duplicate work or
useless traffic". Read it once before the first round of agents go
out — it answers the four questions every operator asks during their
first month.

Audience: SOC operator or sysadmin running the rollout.

## TL;DR — the priority list

1. **Linux fleet**: install the agent, leave rsyslog forwarding off (the
   agent already covers it). Add the auditd module only if you need
   forensic depth on a hardened set of hosts.
2. **Windows fleet**: install the agent. Install Sysmon with a public
   community config (SwiftOnSecurity is the standard). Enable
   PowerShell Script Block Logging via Group Policy. **Do not** point
   the Windows Event Forwarder at us in addition — the agent already
   reads the local Security log.
3. **Firewalls / network appliances**: connect them through the
   built-in connector for OPNsense / FortiGate / Proxmox. **Do not**
   install the agent on the firewall itself. There is no separate
   firewall skill to install on a Linux or Windows host.
4. **Endpoints behind a NAT**: same agent, no extra configuration —
   the agent reaches the platform outbound, not the other way around.

The rest of this page explains why each of those answers is what it is.

## Linux fleet

### What the agent already covers

The agent reads the standard Linux log surfaces on its own:

- `auth.log` / `secure` — sshd, sudo, su, useradd, usermod, groupadd
- `messages` / `syslog` — kernel, daemons, cron sessions
- `journal` — anything written through journald that does not also
  go to file
- the systemd journal for short-lived units that never reach disk

Once the agent is running, every detection rule that matches Linux
host activity (SSH brute force, privilege escalation, persistence,
log tampering, sensitive file access, etc.) has the events it needs.

### Should I also forward rsyslog over the network?

No. If you point rsyslog at the platform on top of the agent, every
matched event lands twice — once through the agent, once through the
forwarder. The detection engine does deduplicate identical rows at
the alert level, but the cost of carrying duplicate volume is paid
upstream of that dedup. There is no detection coverage you gain by
running both.

Where rsyslog forwarding does make sense: an appliance you can't put
the agent on (an old firewall, a printer, a managed switch). For
those, the rsyslog stream stands alone and there is nothing to
duplicate.

### What about auditd?

auditd produces a stream that is strictly richer than syslog (every
`execve`, every file open, every kernel syscall on a watch list).
ThreatClaw consumes it when the agent's auditd module is enabled —
the same agent process, so no second binary to manage.

Recommendation: enable it on the small set of hosts where you want
forensic depth (a domain controller equivalent, a build server, a
finance app server). Do not blanket-enable it on every laptop — the
volume is significant and the marginal detection value on a workstation
is low.

If you do enable it: the same agent will start emitting auditd
records. The detection engine already routes them into the right
rule pack.

## Windows fleet

### What the agent already covers

The agent reads the local Security event log directly — the same
channel that a Domain Controller writes to when a user authenticates,
when an account is created, when a Kerberos ticket is requested,
etc. So out of the box the agent already feeds:

- 4624 / 4625 (logon success / failure)
- 4768 / 4769 (Kerberos TGT / TGS request)
- 4720 / 4732 (account / group changes)
- 1102 (security log cleared)
- the standard authentication and account-management surface

A typical Windows host with **only the agent installed** is enough
to catch every Windows detection rule that targets the Security
channel.

### What you should add: Sysmon

Sysmon is the missing layer on every Windows host. It enriches process
creation, network connections, registry edits and image loads with
information the Security log does not carry (parent process, hashes,
command line, signature checks).

Recommendation: install Sysmon on every Windows host you instrument
and load a community baseline configuration — SwiftOnSecurity's
config is the de-facto standard and matches what the bundled detection
rules expect.

Why it matters: ~80 % of the bundled Windows detection rules are
written against the Sysmon process-creation surface (LOLBins,
PowerShell obfuscation, lateral movement primitives, credential
theft patterns like LSASS dump or NTDS extraction). Without Sysmon
those rules never fire.

The agent will pick up the Sysmon stream automatically — no second
agent to install. Sysmon writes to its own dedicated event log channel,
the agent reads from there.

### What you should add: PowerShell logging

Three Group Policy settings, in order of value:

1. **Script Block Logging** (`Turn on PowerShell Script Block
   Logging`) — captures the actual script content even when it is
   obfuscated or built dynamically with `Invoke-Expression`. This is
   what catches `IEX`, `Invoke-WebRequest`, base64-encoded
   commands, mimikatz scripts.
2. **Module Logging** (`Turn on Module Logging`) — captures which
   PowerShell modules were loaded.
3. **Transcription** (`Turn on PowerShell Transcription`) — optional,
   produces a per-session transcript file. Useful for forensic
   replay but not required for detection.

Without Script Block Logging, every PowerShell-themed detection rule
in the bundle silently misses. With it, the same rules surface every
obfuscated download cradle, every LOLBin chain, every fileless
loader. **Activate it before the first round of red-team-style
tests.**

The agent picks up the PowerShell channel automatically once the
events start flowing.

### Should I also forward the Windows Event Log over WEF?

No. The agent already reads the local channels. Pointing the Windows
Event Forwarder at the platform on top of the agent produces the
same duplicate-volume problem as rsyslog above, with no detection
benefit.

### What about EDR?

If you already have an EDR (CrowdStrike, SentinelOne, Microsoft
Defender for Endpoint, ESET, etc.) leave it on. ThreatClaw does not
replace the EDR's prevention layer — they cover different ground.
The EDR blocks known-malicious behaviour at runtime; ThreatClaw
correlates the surrounding context, runs the detection layer over
the forensic timeline, and orchestrates the human-in-the-loop
response. Both can run on the same host without interfering.

## Network appliances (firewalls, IDS, proxies)

The supported integrations today are: **OPNsense**, **FortiGate** and
**Proxmox**. Each one has a dedicated connector in the platform —
the connector pulls the appliance's syslog / API stream and routes
it into the detection engine without you having to forward anything
manually.

### Should I install the agent on the firewall?

No. The firewall is not a host you want to instrument the way you
instrument a Linux or Windows server — and the supported connectors
already do the work over the network. Putting the agent on the
firewall adds maintenance with no detection gain.

### Is there a separate "firewall skill" to install on a Linux or Windows host?

No. The firewall integration runs entirely from the platform side
through the dedicated connector. The host-side agent does not need
a plug-in for it.

### What about firewall types we do not list?

The framework is open: a new connector for Cisco ASA / Palo Alto /
Juniper / Stormshield can be added under the marketplace. If your
fleet has one of those, mention it during the deployment review and
the priority list moves up accordingly.

## Recommended activation order

For a fresh install — first the platform, then this order on the
fleet:

1. Linux hosts: install the agent (one liner from `/setup`).
2. Windows hosts: install the agent, Sysmon (SwiftOnSecurity config),
   PowerShell Script Block Logging GPO.
3. Firewall(s): enable the OPNsense / FortiGate / Proxmox connector
   from `Skills`, paste the credentials.
4. (Optional) auditd on the hardened subset of Linux hosts.
5. (Optional) EDR connector if you have one — the platform will
   correlate EDR detections with the Sigma alerts on the same host.

After step 3 you already have full coverage on the standard kill
chain (initial access, persistence, lateral movement, credential
theft, defense evasion). Steps 4–5 add forensic depth and EDR
correlation but are not required to survive a routine red-team
audit.

## What "full coverage" looks like once everything is on

A representative end-to-end attack — initial brute force, privilege
escalation, log tampering, credential dump, lateral movement, data
exfil — surfaces as a sequence of incidents on the dashboard:

- one incident per pattern observed (one for the brute force, one
  for the privilege escalation, one for the credential dump, etc.),
  each titled after the actual detection
- proposed remediation actions next to each, gated behind a human
  approval click
- a deep narrative under each incident that describes what was
  observed in plain language and lists the linked alerts and
  findings
- a single asset view that lets you see the full sequence in
  chronological order

If a deployment is missing the Sysmon step or the Script Block
Logging step, expect the kill chain to surface only in fragments —
the brute force and the privilege escalation will still trigger,
but the credential dump and the lateral movement will silently drop
out of the timeline.

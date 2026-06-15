# Sigma Rules

This page covers the detection rule catalog, how rules are evaluated,
the promotion ladder that controls how a match surfaces, the
exception system that suppresses false positives, and the importer
that brings upstream SigmaHQ rules into ThreatClaw.

If you only want to act on a rule, jump to *Tuning a noisy rule*
below.

## Catalog at a glance

ThreatClaw v1.0.32-beta+ ships with **1095 rules** loaded by default,
split across four ingestion channels:

| Channel | Rule count | Source |
|---------|------------|--------|
| `osquery.sysmon` (Windows process / file / network / registry / image_load / DNS / pipe / remote_thread / driver) | ~890 | First-party + bulk import from SigmaHQ critical+high |
| `osquery.powershell` (PowerShell script block) | ~60 | Same |
| `syslog.tcp.*` (Linux sshd, sudo, cron, FIM, nft) | ~30 | Same |
| Other (firewall, m365, Sysmon-driven APT TTPs) | ~115 | First-party packs |

Browse them from the dashboard at `/sigma`. Each rule card shows its
id, title, level, ATT&CK technique, current disposition, and a fire
count over the last 7 days.

## How a match becomes signal

A sigma rule is evaluated against every log event matching its
`logsource` filter. When the rule's `detection.condition` is true,
the engine writes a `sigma_alert` row. From there, three knobs
control what happens next:

### Disposition — what the alert *does*

| Disposition | Effect |
|-------------|--------|
| `detect` | Promote the alert to a finding when severity criteria are met (critical / high → always; medium → only if corroborated by ≥ 1 other signal on the same asset in the last hour). |
| `monitor` | The alert is downgraded to `informational` and tagged with a `_disposition: monitor` marker. It surfaces on the dashboard for audit but never promotes to a finding. |
| `block` | Same promotion as `detect`, plus the alert carries a `_disposition: block` marker that authorizes the HITL panel to propose a blocking action without delay. |

`monitor` is the right disposition for an imported rule you have not
reviewed yet, or for a rule whose fires you want to keep visible
without paging the operator. `detect` is the default for any rule
you trust.

### Tier — *where* the alert lands

| Tier | Effect |
|------|--------|
| `page` | The alert is treated as a high-priority signal — promotes immediately and is surfaced at the top of the operator queue. |
| `queue` (default) | Normal promotion with the regular operator queue. |
| `rba_only` | The alert never paginates on its own. It only contributes to a Risk-Based Aggregation score on the affected asset, which can promote a separate "risk threshold reached" incident. |

### Status — *whether* the rule is on the production catalog

| Status | Effect |
|--------|--------|
| `experimental` | The rule is wired but not battle-tested. Counted on the audit page; expected to be reviewed. |
| `test` | Under active tuning. |
| `stable` | The rule is reliable and the team trusts it. |
| `deprecated` | The rule is disabled and excluded from compile-time aggregation. |

In practice, a fresh import lands in `disposition: monitor`, `tier:
queue`, `status: experimental`. As you confirm the rule is useful and
not noisy, you promote it through the ladder using the dashboard.

## The dashboard pages

### `/sigma` — catalog

A table of every active rule. Filterable by level, by ATT&CK
technique, by disposition, and by fire count. Each row links to the
detail page.

### `/sigma/[ruleId]` — rule detail

For a single rule: the YAML source, the active exceptions, recent
matches (with the events that triggered them), and four action
buttons:

- **Promote** — move the disposition up the ladder (`monitor → detect
  → block`).
- **Demote** — move down (`block → detect → monitor`).
- **Disable** — flip `enabled = false` without removing the rule.
- **Add exception** — open the exception form.

### `/sigma/coverage` — ATT&CK Navigator layer

Renders the catalog as an ATT&CK matrix. Each technique cell is
colored by how many active rules cover it; clicking a cell lists the
matching rules. Exportable as a Navigator JSON v4.5 layer you can
share or overlay on a customer's framework.

### `/sigma/audit` — health view

Summary counters: rules with zero fires in 30 days (candidates for
demotion), rules with > 1k fires in 7 days (candidates for an
exception), rules in `experimental` for more than 30 days (review
needed). The page is the operational checklist; visit it weekly.

## Tuning a noisy rule

Two paths, depending on how broad the noise is:

### Path A — exception for a specific scope

If only one asset, one source IP, or one username produces the FP:

1. Open the rule detail at `/sigma/[ruleId]`.
2. Click **Add exception**.
3. Pick a scope (`hostname` / `source_ip` / `username` / `tag`) and
   a value. Wildcards on the trailing character are supported
   (e.g. `srv-prod-*`).
4. Save. Future matches inside that scope are written to the audit
   log but never promote.

Exceptions are live — no restart needed.

### Path B — demote the disposition

If the rule itself is over-eager and the noise is across many
scopes:

1. Open the rule detail.
2. Click **Demote**. The disposition moves one notch down (typically
   `detect → monitor`).
3. The rule keeps firing but lands as `informational`, so it stays
   visible on the dashboard for review without paging anyone.

If after a week the rule never produces a useful signal, click
**Disable**.

### Path C — the rule itself is broken

If the rule never fires when you expect it to, check the
[`internal sigma audit`] on the dashboard at `/sigma/audit`. The
most common cause is a `logsource` that does not match any active
tag on the install — see the field mapping reference below.

## Field mapping by source

ThreatClaw routes a rule to a source by substring-matching the
rule's `logsource.category` and `logsource.product` against the log
tag. If either substring is absent in the tag, the rule never sees
the event.

| Sigma logsource | ThreatClaw `logsource` | Tag matched on a default install | Field paths |
|-----------------|------------------------|----------------------------------|-------------|
| `windows process_creation` (Sysmon) | `category: osquery, product: sysmon` | `osquery.sysmon` | `data.CommandLine`, `data.Image`, `data.ParentImage`, `data.User`, `data.ProcessId`, `data.Hashes` |
| `windows powershell` | `category: osquery, product: powershell` | `osquery.powershell` | `data.ScriptBlockText`, `data.Path` |
| `linux syslog` (sshd, sudo, cron) | `category: syslog` | `syslog.tcp.*` | `message` (top-level — body scan fallback works) |
| `firewall opnsense / fortinet` | `product: opnsense` / `fortinet` | `opnsense.*` / `fortinet.*` | `action`, `src`, `dst`, `dst_port`, `proto` |
| `m365` cloud identity | `category: m365, product: entra` | `m365.*` (Microsoft Graph connector) | `operationName`, `userPrincipalName`, `ipAddress` |

If a custom rule does not fire, the most common cause is a mismatch
between its logsource and the receiving tag. The `/sigma/audit` page
flags rules in this state.

## Engine capabilities

The native engine implements the SigmaHQ specification subset listed
below. Sigma 2.0 value modifiers landed on 2026-06-15 — anything in
the table below can be used directly in a rule and is also accepted
by the converter.

### Match operators

| Modifier | Semantics | Example |
|----------|-----------|---------|
| (default) | case-insensitive equality | `User: alice` |
| `\|contains` | substring anywhere in the field | `commandline\|contains: powershell` |
| `\|startswith` | substring at the start of the field | `Image\|startswith: 'C:\Windows\'` |
| `\|endswith` | substring at the end of the field | `Image\|endswith: .exe` |
| `\|all` (chained with the above) | every value must match (vs default OR) | `CommandLine\|contains\|all: [' -hp', ' a ']` |
| `\|cased` (chained with the above) | case-sensitive variant | `User\|cased: Administrator` |

### Value transformers

| Modifier | What it does |
|----------|--------------|
| `\|re` | PCRE-style regex. Use `\|re\|i` for an explicit case-insensitive flag. |
| `\|cidr` | Field is parsed as an IPv4 or IPv6 address and tested against the supplied CIDR. |
| `\|windash` | Expands the value into every dash variant (`-`, `/`, `–`, `—`, `―`) so a single rule covers all five forms. |
| `\|base64` | Encodes the value as Base64 at compile time so a Contains match catches it inside an EncodedCommand. |
| `\|base64offset` | Emits the three shift-aligned Base64 variants — useful when the substring's byte alignment in the parent buffer is not known. |
| `\|utf16le`, `\|utf16be`, `\|wide`, `\|utf16` (with BOM) | Encodes the value as UTF-16 bytes rendered into a lossy substring so PowerShell EncodedCommand-style payloads are reachable. |
| `\|fieldref` | Compares two fields in the same event — the anti-evasion idiom for parent/child self-spawn patterns. |
| `\|exists: true\|false` | Field-presence check, regardless of value. |
| `\|lt`, `\|lte`, `\|gt`, `\|gte` | Numeric comparison against the field, coerced from string if needed. |

### Conditions

- `selection`, `X and Y`, `X or Y`, `not X`, `X and not Y`
- `1 of <pattern>`, `all of <pattern>` where `<pattern>` is a prefix
  (`selection_*`), suffix (`*_filter`), or the literal `them`
- the `logsource` substring filter described in the previous section

### Strict field matching (2026-06-15)

When a rule targets a real field — `commandline`, `data.Image`,
`channel`, etc. — the engine honours that field strictly. A missing
key means no match, a present-but-different key means no match. Earlier
builds fell back to scanning the whole serialized event whenever the
key was absent, which let a rule looking for `commandline\|contains:
"RDP"` accidentally match a port number stored in `data.SourcePort`.

Symbolic body aliases (`full_log`, `raw_log`, `message`, `body`, `log`,
`log_text`, `raw_text`) keep the whole-event fallback because legacy
syslog rules use them as a stand-in for the raw log line.

### Still out of scope

- Aggregations (`count() > N over window`, `near`).
- Parenthesized condition grouping (`(X or Y) and Z`).
- Sigma correlation rules (the 2.1.0 metrics / value_sum family).

## Importing upstream SigmaHQ rules

The repository ships a converter at
[`tools/sigma_convert.py`](https://github.com/threatclaw/threatclaw/blob/main/tools/sigma_convert.py)
that turns an upstream SigmaHQ rule file into the ThreatClaw shape.

```bash
# Clone SigmaHQ
git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma

# Convert a pack to a local directory
python3 tools/sigma_convert.py \
  /tmp/sigma/rules/windows/process_creation \
  --out rules/imported/windows-procs \
  --report internal/import-report.md
```

What the converter does:

- remaps `logsource` (upstream `windows process_creation` →
  ThreatClaw `osquery + sysmon`, etc.)
- rewrites field names per source (Sysmon `CommandLine` →
  `data.CommandLine`, PowerShell `ScriptBlockText` →
  `data.ScriptBlockText`)
- rejects rules that use features the engine still doesn't handle
  (parenthesized conditions, aggregations, correlation rules) with a
  logged reason in the report. Sigma 2.0 value modifiers (`|re`,
  `|cidr`, `|windash`, `|base64`/`|base64offset`, `|utf16*`,
  `|fieldref`, `|exists`, `|lt|lte|gt|gte`) now pass through cleanly.

On the upstream catalog of 3133 rules the converter accepts about
2857 rules (91%) on the pre-2026-06-15 modifier scope. The set
of Sigma 2.0 value modifiers added on that date raises the ceiling
further — re-run the converter on the same upstream snapshot to see
the new acceptance count. The report lists the rejections so you
can decide which to rewrite by hand.

Imported rules land with `disposition: monitor` by default so they
surface as informational signal without auto-promoting findings
until you review them.

## Writing a custom rule

A rule lives on disk under `rules/<pack>/<id>.yaml` and gets loaded
into the database at every core boot. The file format is the
SigmaHQ YAML schema with the ThreatClaw-tuned `logsource` block.

Minimal example:

```yaml
title: My internal SSH brute force
id: lnx-ssh-internal-brute
status: stable
description: |
  Detect repeated failed sshd auth from a non-RFC1918 source against
  an internal asset.
references:
  - https://attack.mitre.org/techniques/T1110/
author: Acme SOC
date: 2026-06-15
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  category: syslog
detection:
  selection:
    'message|contains':
      - 'Failed password'
      - 'sshd'
  condition: selection
falsepositives:
  - Internal automation using ssh key-based auth (should not appear with this filter)
level: high
```

Each rule should have a companion `<id>.test.yaml` with at least one
positive and one negative event fixture so the test runner can
verify the rule does what its title claims:

```yaml
rule: lnx-ssh-internal-brute
title: My internal SSH brute force
positive:
  - description: failed password against root from external
    tag: syslog.tcp.*
    event:
      message: "sshd[12345]: Failed password for root from 203.0.113.5 port 22 ssh2"
negative:
  - description: successful login should not match
    tag: syslog.tcp.*
    event:
      message: "sshd[12345]: Accepted publickey for alice from 10.0.0.5 port 22 ssh2"
```

Run `cargo test --test sigma_rules` to verify. Drop the two files
into `rules/<pack>/`, commit, and the next core start picks them up.

## Useful commands

```bash
# How many rules in each disposition
docker compose -f /opt/threatclaw/docker-compose.yml exec -T threatclaw-db \
  psql -U threatclaw -d threatclaw -c \
  "SELECT disposition, COUNT(*) FROM sigma_rules WHERE enabled GROUP BY disposition;"

# Top-firing rules in the last 7 days
docker compose -f /opt/threatclaw/docker-compose.yml exec -T threatclaw-db \
  psql -U threatclaw -d threatclaw -c \
  "SELECT rule_id, COUNT(*) FROM sigma_alerts \
   WHERE matched_at > NOW() - INTERVAL '7 days' \
   GROUP BY rule_id ORDER BY 2 DESC LIMIT 10;"

# Force-reload the on-disk rules without restarting the core
curl -X POST -H "Authorization: Bearer $TC_TOKEN" \
  http://localhost:3000/api/tc/sigma/reload
```

## Next reads

- [`operator-handbook.md`](operator-handbook.md) — the three-layer
  detection model
- [`inventory-gate.md`](inventory-gate.md) — why some sigma alerts
  do not produce incidents
- [`hitl-workflow.md`](hitl-workflow.md) — how an alert promotes to
  an actionable HITL panel

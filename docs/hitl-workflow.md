# HITL Workflow

ThreatClaw never executes a remediation action on its own (in the
default mode). Every proposed action — block an IP, isolate a host,
disable a user account, kill a process, reset a Kerberos
distribution key — goes through a Human-In-The-Loop approval step.

This page explains the approval surfaces, what each action does,
and how to harden the workflow for production.

## Where actions appear

### Inside an incident

Open any incident at `/incidents/<id>`. The right-hand panel labeled
**Propose Actions** lists every action the agent has derived from
the dossier:

| Action | Effect | Requires |
|--------|--------|----------|
| `block_ip` | Push a deny rule on the firewall for the external source IP. | A firewall connector (`skill-opnsense`, `skill-fortinet`, `skill-pfsense`, `skill-mikrotik`). |
| `isolate_host` | Cut the asset off the network at the EDR layer. | An EDR connector (`skill-edr-velociraptor`, `skill-edr-crowdstrike`, ...). |
| `disable_user` | Disable the user account in the directory. | An IAM connector (`skill-active-directory`, `skill-okta`). |
| `kill_process` | Terminate a specific PID on the asset. | EDR connector with a remote kill capability. |
| `reset_krbtgt` | Rotate the Kerberos ticket-granting account twice (kills every existing TGT). | Active Directory connector. |
| `collect_artifacts` | Trigger a forensic collection plan on the asset (memory, logs, autoruns, sysmon). | EDR connector with a hunt capability. |
| `manual` | Description-only — the agent suggests what to do; the operator does it by hand because no skill is connected. | None. |

Each row carries a rationale (why the agent proposes it) and two
buttons:

- **Approve** — execute through the matched skill. The resulting
  receipt (firewall rule id, EDR ticket, ...) is attached to the
  incident as a `remediation_executed` step in the Investigation
  Timeline.
- **Reject** — drop the proposal. The agent will not re-propose the
  same action on the same incident.

A third optional input — **Note** — records a free-text comment
attached to the action and visible on every channel.

### From a notification channel

If a channel is wired (see `configuration.md` for credentials), the
same action panel arrives as an interactive message:

- **Slack / Discord** — the message has inline buttons (Approve /
  Reject). The reply mirrors back to the dashboard in real time.
- **Telegram** — same pattern, inline keyboard.
- **WhatsApp** — text replies (`approve` / `reject` plus the
  incident id).
- **Email** — links to the dashboard for the actual action; no
  one-click approval over email by design.
- **Webhook** — JSON payload, your downstream tool (PagerDuty,
  Opsgenie, ServiceNow) decides what to do.

All channels are bidirectional: a decision made anywhere updates
every other surface.

## Agent modes — who can approve, when

The agent's permission level controls whether actions are *proposed
only* or *can self-execute*. Change it from `Config > General > Agent
mode`:

| Mode | Behaviour | When to use |
|------|-----------|-------------|
| **Investigator** (default) | The agent scans, correlates, proposes. It never executes — even with credentials wired. | Pre-production, audit-only deployments, customers who want full operator control. |
| **Responder** | The agent proposes; actions execute only after a human approval on any channel. | Most production deployments. The sweet spot of automation + control. |
| **Autonomous Low** | The agent auto-executes actions tagged `low_risk` (e.g. add a single IP to a firewall deny list). Everything else still needs HITL. | Customers with a 24/7 high-volume SOC who want common low-risk actions to clear without paging. |
| **Analyst** | A fixed pipeline with no AI decisions. The dashboard remains operational but no remediation panel is exposed. | Regulated environments where the AI must not gate any decision (some compliance frameworks require it). |

A mode change is logged in the immutable audit trail
(`audit_log` table, see `telemetry.md`).

## The ClawShield safety layer

Every action — whether human-approved or self-executed — passes
through a guard layer before reaching the skill. The guard checks:

- **Scope sanity** — refuse to block `0.0.0.0/0`, refuse to disable a
  user named in the customer's `protected_users` setting, refuse to
  isolate a host tagged `do_not_isolate`.
- **Skill capability** — confirm the action type is in the skill's
  declared capabilities. A firewall skill cannot be tricked into
  triggering a process kill.
- **Time-of-day policy** — refuse to execute outside the configured
  maintenance window (per-skill, optional).
- **Throttle** — refuse to push more than N actions per minute per
  skill (default 10/min, configurable).

A guard refusal is recorded with the reason and surfaces on the
incident as a `remediation_refused` step.

## Recovery actions — how to undo

Every executed action returns a receipt the skill knows how to
reverse. The incident detail page shows an **Undo** button next to
the receipt:

| Action | Undo |
|--------|------|
| `block_ip` | Remove the deny rule (skill-side API call). |
| `isolate_host` | Re-attach the asset to the network. |
| `disable_user` | Re-enable the account. The previous password is **not** restored — the user must reset it. |
| `kill_process` | No undo (the process is gone). The button is disabled. |
| `reset_krbtgt` | No undo by design. The action is two-step on purpose, and the audit trail records both rotations. |
| `collect_artifacts` | No undo — the artifacts are read-only collection. The button is disabled. |

Undo passes through the same ClawShield guard layer.

## Pre-flight checklist before turning on Responder mode

The first time you enable actual execution (mode = Responder), walk
through this checklist:

1. **Test the action panel in dry-run** — Investigator mode shows
   every proposed action without executing. Spend a week here and
   make sure the proposals match what an experienced operator would
   do.
2. **Wire one skill at a time** — start with the firewall (lowest
   blast radius). Wait a week before adding EDR. Wait another week
   before adding IAM.
3. **Confirm the `protected_users` list** is populated — at minimum
   the IAM `admin`/`root`/break-glass account and any service
   account that would brick the deployment if disabled.
4. **Confirm the firewall deny list has a max size** — most
   appliances have an undocumented hard limit (typically 1k-10k
   entries). Set a throttle low enough to not hit it.
5. **Enable a notification channel** so an out-of-hours operator
   sees the proposed action even when the dashboard is closed.
6. **Walk through one full HITL flow end-to-end** in production:
   trigger a known-safe rule (a syslog test from a declared internal
   host), watch the action surface, approve, watch the firewall
   apply, click Undo, watch the rule disappear.

## API surface for scripted integration

The same HITL surface is available over REST for SOAR integrations:

```bash
# List pending actions on an incident
curl -H "Authorization: Bearer $TC_TOKEN" \
  http://localhost:3000/api/tc/incidents/<id>/hitl

# Approve an action by its cmd_id
curl -X POST -H "Authorization: Bearer $TC_TOKEN" \
  -d '{"cmd_id":"opnsense_block_ip", "params":{"ip":"203.0.113.5"}}' \
  http://localhost:3000/api/tc/incidents/<id>/execute-action

# Reject
curl -X POST -H "Authorization: Bearer $TC_TOKEN" \
  -d '{"cmd_id":"opnsense_block_ip", "decision":"reject"}' \
  http://localhost:3000/api/tc/incidents/<id>/execute-action
```

A SOAR can stream incidents via the standard list endpoint and act
on them when its own workflow approves. The decision still updates
every surface in real time.

## Common questions

**Can the agent escalate to a different operator if the first one
does not respond?**

Yes — set `escalation.timeout_min` and `escalation.next_channel` in
`Config > Channels`. The agent re-broadcasts the action to the next
channel after N minutes without a decision.

**What if I approve by accident?**

Click Undo on the receipt. If the action is non-undoable (kill,
krbtgt), the audit trail records both the original decision and the
operator's mistake. There is no silent recovery.

**Can I require two approvals for some actions?**

Set `two_person_rule = true` on a per-skill basis. The action
remains in `pending_second_approval` until a different account
approves it. Useful for `disable_user` and `reset_krbtgt` in
regulated environments.

## Next reads

- [`operator-handbook.md`](operator-handbook.md) — the three-layer
  detection model and the dashboard tour
- [`sigma-rules.md`](sigma-rules.md) — how an alert reaches the HITL
  panel
- [`configuration.md`](configuration.md) — channel credentials and
  env vars

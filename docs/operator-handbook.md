# Operator Handbook

This handbook is the page to bookmark once ThreatClaw is installed
and reporting in. It walks through the dashboard, explains how the
detection pipeline is layered, and answers the questions every new
operator asks in their first week.

If you have not installed yet, start with
[`getting-started.md`](getting-started.md).

## The three-layer detection model

Most "why don't I see this alert?" questions come from confusing
three views the product keeps deliberately separate. Each view
answers a different question and shows a different count:

| Layer | What you see | What it answers |
|-------|--------------|-----------------|
| **Engine log** (Console, bottom strip) | Every raw event the engine writes — sigma alert created, scan finished, agent synced, model loaded | "Is the engine alive and matching?" |
| **Incidents** (Incidents page) | Correlated subsets of those raw alerts, grouped per asset and attack pattern | "What is actually under attack right now?" |
| **Attack Timeline** (inside an incident detail page) | The alerts attached to that one incident, sorted chronologically | "What evidence do we have on this specific case?" |

Numbers across the three views never match exactly, and that is the
intended behaviour:

- The engine log might show `ALERT sigma_alerts +35 · total=35`. That
  is the raw stream: thirty-five matches written to the database.
- The Incidents page might show one card with `5 alerts`. The
  Intelligence Engine runs every five minutes, groups alerts by
  asset and attack pattern, deduplicates them in a rolling one-hour
  window, and promotes the group as a single incident with the
  surviving alerts attached.
- The Attack Timeline inside that incident shows the same five — not
  the thirty-five.

The other thirty alerts are not lost. They are one of:

- on a different asset (they live in a different incident, or in
  none yet);
- duplicates of an alert already in the incident (dropped by the
  one-hour dedup so the timeline stays readable);
- below the promotion threshold (a single medium-severity hit
  without corroborating signal is kept as raw evidence but does not
  open an incident on its own);
- filtered by the inventory gate — see
  [`inventory-gate.md`](inventory-gate.md) for why an external
  scanner does not flood your queue.

If you want to see the raw stream, the **Hunt** page lets you filter
by tag (`sigma_alerts`, `osquery.sysmon`, `syslog.tcp.*`, ...) over
any time window. That is the right place when you suspect an alert
exists but does not show on a card.

### The 5-minute cadence

The Intelligence Engine cycle is the heartbeat of the product. It
runs every five minutes by default and, in one pass, it:

1. Reads the recent log batch (per-tag quota, last 5 minutes).
2. Matches every active sigma rule against every event.
3. Inserts the matches as raw `sigma_alerts`.
4. Groups them per asset and attack pattern.
5. Decides which groups deserve to be promoted to an incident.
6. Triggers the L2 forensic enricher on confirmed incidents.

The engine log shows every step in near-real-time (the raw alert
appears within a second of the matching event), but the consolidated
incident card only appears at the end of the cycle. Expect up to a
five-minute delay between an attack and its appearance on the
Incidents page.

This is also why a single short attack and a long sustained one
produce different incident shapes: a short burst leaves one
incident with a few alerts; a sustained brute force grows the same
incident over many cycles, with the dedup keeping the alert list
clean.

## Tour of the dashboard

### Console

The default page. Six panels stacked left to right:

- **Posture** — confirmed incidents, raw alerts, current security
  score, badges (`engine: live`, current model, error rate).
- **Agent cycle** — the four steps the agent runs every cycle
  (Observe, Correlate, Enrich, Decide) with a green dot for the
  active step. Useful to confirm the engine is alive even when
  nothing is firing.
- **Assets at risk** — the top hosts ranked by current risk score,
  with a click-through to the asset page.
- **Recent incidents** — the latest incident cards, severity badge,
  open/closed status.
- **Pending incident** — the next incident waiting on operator
  action.
- **Engine log** — the live stream described above.

### Incidents

The Incidents page is the operator queue. Each row is one incident
card with severity badge, asset, alert count, age, and an
**Investigate** button. Click it to open the incident detail page:

- **Header** — incident id, severity, status, asset, age,
  confirmation badge.
- **AI verdict** — confirmed / inconclusive, confidence score, the
  forensic narrative produced by the L2 model.
- **Attack Timeline** — the chronological view of the alerts
  attached to this incident. This is the view that often differs
  from the engine log count, see above.
- **HITL panel** — proposed actions: block IP, isolate host, disable
  user, reset krbtgt, collect artifacts. Each action has a rationale
  and an Approve / Reject button. Nothing executes without operator
  approval unless the agent is in Autonomous mode.
- **Investigation Timeline** — collapsed by default. Every skill
  call, every LLM call, every graph step. Useful for auditing how
  the agent reached its verdict.
- **MITRE techniques** — the attack pattern, with links to the
  technique page.

### Inventory

The Inventory page is your source of truth on what the deployment
protects. Filters: All / Unknown, billing status (All / Billable /
Observed / Probable duplicates / Inactive). Each asset card carries:

- Hostname, IP addresses, OS, status badge (in observation,
  billable, ...).
- Security score (0-100, derived from CVE findings, attack-path
  exposure, recent incidents).
- A click-through to the asset detail page, with full inventory
  (software, ports, users, scheduled tasks, SSH keys) and the
  per-asset findings list.

The asset's billing status changes how the asset is treated by the
inventory gate — see [`inventory-gate.md`](inventory-gate.md).

### Hunt

The Hunt page is the log lake. It exposes the raw log payload for
free-text investigation. Filters: hostname, source tag, time range
(15 min to 30 d, custom window), substring search over the JSON
payload. Results paginate with a stable cursor.

Use Hunt when:

- a card mentions an alert and you want to see the underlying raw
  event;
- you suspect an alert exists somewhere but no card shows it;
- you need to investigate a host that is not yet an asset (the
  Inventory page does not list it but the Hunt page can search by
  hostname anyway).

The incident detail page has a **Hunt panel** button that opens Hunt
pre-filtered to the asset hostname and a ±10 min window around the
attack events.

### Investigation

The Investigation page is a free-form chat with the agent over the
current incident dossier. Useful for "explain what happened" or
"what would happen if I blocked this IP" questions. The agent
answers from the dossier only — it does not make up evidence.

### Skills

The Skills page is the catalog of connectors and intelligence
modules. Each skill is a sandboxed module that extends the agent's
capabilities — sources, enrichments, or actions. See
[`skills.md`](skills.md) for the list and the sandbox model.

### Reports

The Reports page generates PDF / JSON deliverables: NIS2, RGPD, ISO
27001, NIST, STIX 2.1, MISP. Each report is composed from the
findings, incidents and inventory at the time it is generated. PDF
exports use Typst on the server side.

### Config

The Config page exposes every setting per category: general
(language, time zone), logs (retention, ingestion rate), AI
(model selection, cloud LLM credentials), inventory gate, channels
(Slack, Telegram, Discord, ...), and integrations.

## Common operator workflows

### Confirm an incident is real

1. Open the incident detail page.
2. Read the AI verdict and the Attack Timeline.
3. Cross-check the source IP reputation (the AttackTimeline panel
   shows it automatically).
4. If the asset matters and the timeline is consistent, the incident
   is real — approve the proposed actions.

### Tune down a false-positive rule

1. Open the incident detail page.
2. Look at the rule id of the alert that fired
   (`/sigma/<rule_id>`).
3. From the Sigma page, click **Add exception**: scope it to the
   asset or the source IP that produces the FP.
4. Future matches against the same scope land in the audit log but
   do not promote to an incident.

### Investigate a host not yet declared

1. Open the Hunt page.
2. Type the hostname in the hostname filter (combobox accepts free
   text for hosts not yet enrolled).
3. Set a wide time range and search the JSON payload.
4. Once you confirm the host is internal, declare it in Inventory.

### Force a model re-pull

If the L2 forensic timeline reports a 404 on the
`threatclaw-forensic` model:

```bash
docker exec threatclaw-ollama-1 ollama list
docker exec threatclaw-ollama-1 ollama pull \
  hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF
docker compose restart threatclaw-core
```

Since v1.0.33-beta the entrypoint retries this automatically with
clear logs in `docker logs threatclaw-threatclaw-core-1`.

### Switch the report language

The forensic narrative responds in the language of your choice:

```bash
# Edit /opt/threatclaw/.env
TC_REPORT_LANG=French   # English by default; any natural language name accepted
```

Then restart: `docker compose restart threatclaw-core`.

This setting only affects the LLM narrative. The dashboard UI
language is set independently in **Config > General > Language**.

(*Available from v1.0.34-beta.*)

## Offline / air-gapped installs

If the deployment cannot reach Hugging Face on the boot network, the
local AI models can be shipped as a tarball.

1. Pull the tarball over a one-time link we provide.
2. Place it under `/opt/threatclaw/models/`.
3. Restart the core: `docker compose restart threatclaw-core`.
4. The entrypoint detects the tarball, imports it into Ollama, and
   skips the hf.co download step.

Contact the team for the link.

## Where to look when something is off

| Symptom | First step | Then |
|---------|------------|------|
| Asset not in Inventory | Check **Setup > Endpoints** that the agent registered | Check `docker logs threatclaw-threatclaw-core-1 \| grep OSQUERY` for the sync line |
| Incident count flat for hours | Confirm the IE is running: `docker logs ... \| grep "INTELLIGENCE: Score"` | If silent, restart the core; if alive, check the inventory gate |
| L2 forensic shows 404 | `docker exec threatclaw-ollama-1 ollama list` | If the alias is missing, see "Force a model re-pull" above |
| Dashboard says "no asset" while logs are flowing | Open the Hunt page and confirm the logs are arriving | If they are, declare the asset manually in Inventory |
| Engine log noisy but no incidents | Check **Inventory gate** doctrine; declare an internal CIDR if the source is internal | See [`inventory-gate.md`](inventory-gate.md) |

## Next reads

- [`inventory-gate.md`](inventory-gate.md) — what the inventory gate
  filters and why
- [`attack-prediction.md`](attack-prediction.md) — predicted attack
  paths
- [`configuration.md`](configuration.md) — every environment
  variable
- [`api.md`](api.md) — REST endpoints for SIEM pivot or scripted
  integration

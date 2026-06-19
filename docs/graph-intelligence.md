# Graph Intelligence

Detection produces a flat stream of alerts. The graph is what turns
that stream into context: which IPs touch which assets, which CVEs
affect which hosts, where credential reuse opens lateral pivots,
which assets sit at the choke points between an external entry and a
critical target.

This page is the operator-facing tour of what the graph models and
how the dashboard surfaces it.

If you want the predictive view (attack-paths and choke points), read
[`attack-prediction.md`](attack-prediction.md).
If you want the doctrine (why noise from external scanners doesn't
flood the graph), read [`inventory-gate.md`](inventory-gate.md).

## What the graph models

ThreatClaw runs Apache AGE on top of PostgreSQL, so the graph and the
relational data share one database. Five node families and five edge
families are enough to express the security context:

### Nodes

| Node | What it represents |
|------|--------------------|
| `Asset` | A host, container, network device or service in the customer inventory |
| `IP` | A network address seen in logs (internal or external) |
| `CVE` | A vulnerability published in the NVD / KEV catalog |
| `Technique` | A MITRE ATT&CK technique linked to a sigma rule |
| `CourseOfAction` | A remediation action proposed by the agent (block, isolate, disable, …) |

### Edges

| Edge | What it captures |
|------|------------------|
| `OBSERVED` | An IP appeared as the source of a sigma alert or firewall event toward an asset. Carries `severity_rank`, `internal`, `first_seen`, `last_seen`. |
| `AFFECTS` | A CVE affects an asset (the asset's software inventory matches the CVE's affected products). |
| `LATERAL_PATH` | Two assets share a successful authentication by the same user account within the last 30 days — credential reuse opens a pivot path. |
| `USES_TECHNIQUE` | An alert on an asset matches a sigma rule mapped to a MITRE technique. |
| `REMEDIATES` | A course of action proposed for an incident. Materialised when the agent suggests a remediation. |

## The OBSERVED edge — what changed in v1.0.48

Before v1.0.48 the graph used a label called `ATTACKS` for the IP →
asset relationship. The name was misleading: the pipeline created an
edge for **every** sigma alert with a source IP, including legitimate
LAN traffic (admin tooling, DC chatter, scanner sweeps). A single
chatty internal peer could surface as "4268 attackers" on the asset
detail page when in reality it was one neighbour communicating
normally.

The label was renamed to `OBSERVED` and three new properties were
added on the edge:

- **`severity`** — the sigma alert level (info / low / medium / high
  / critical) verbatim.
- **`severity_rank`** — the same value as a number 1-5, so Cypher's
  `MAX()` returns a meaningful "worst severity" per IP without
  alphabetic surprises.
- **`internal`** — `true` when the source IP is a known internal
  asset of the customer, `false` when it is external.

The `sync_graph_from_db` cycle now **silently drops internal
observations below medium severity** — those are benign LAN chatter
and inflated the counter without adding signal. External sources are
always recorded; internal medium+ stays so genuine lateral-movement
candidates remain visible.

`find_observed_sources` aggregates by IP with `COUNT(r)`, `MAX(rank)`,
`MIN/MAX(seen)`, so the dashboard renders one badge per distinct IP
with `× event_count` instead of one badge per edge.

A one-shot migration runs on the first sync after the upgrade: it
drops every legacy `ATTACKS` edge, guarded by a setting flag so it
never runs twice. Operators on existing installs get a clean
inventory of observed sources without any manual step.

## What you see on the asset detail page

Open any asset and scroll to **Intelligence Graph**. The pane stays
hidden when none of the three sections has any data — that is the
normal state on a host that nobody talks to, not a bug.

| Section | What it shows |
|---------|---------------|
| **Sources observées** / **Observed sources** | Number of distinct IPs that appeared as the source of an event toward this asset. The list below shows one badge per IP with `× event_count` and a colour reflecting the worst severity seen and whether the source is internal or external (red for external or critical/high, amber for medium, muted for low/internal). |
| **CVEs affectant** / **Affecting CVEs** | Count of CVEs whose affected-product list matches the asset's software inventory. |
| **Indice de confiance** / **Confidence score** | Composite score (0-100) derived from how many independent sources confirm the asset's identity. Low values invite the operator to enable additional sources (AD, pfSense, nmap) to enrich the row. |

## Where the graph is queried

Most operator-facing views are graph queries under the hood:

- **Attack-path prediction** — solves shortest paths from `OBSERVED`
  edges (external sources) through assets exposed to a CVE in KEV to
  any asset flagged `critical`. See
  [`attack-prediction.md`](attack-prediction.md).
- **Choke points** — assets that lie on the most predicted paths;
  hardening one breaks multiple paths at once.
- **Lateral movement detection** — `LATERAL_PATH` edges expose hosts
  that share an authenticated session, so a single credential-theft
  alert can be expanded into "which hosts would the attacker reach
  next?".
- **Campaign correlation** — multiple IPs from the same country or
  ASN hitting many assets cluster together as a single campaign
  rather than N independent incidents.

## Where it lives in the code

| Concern | File |
|---------|------|
| Edge creation (filtered) | `src/graph/threat_graph.rs` (function `record_observation`, called from `sync_graph_from_db`) |
| Per-asset query (dedup + COUNT) | `src/graph/threat_graph.rs` (function `find_observed_sources`) |
| Lateral movement | `src/graph/lateral.rs` |
| Campaign clustering | `src/graph/campaign.rs` |
| Attack paths | `src/graph/attack_path.rs` |
| Blast radius | `src/graph/blast_radius.rs` |
| Dashboard render | `dashboard/src/components/assets/sections.tsx` (component `GraphIntelSection`) |

The graph itself is rebuilt incrementally on every IE cycle, with a
full rescan triggered automatically when the resolver detects the
graph went stale.

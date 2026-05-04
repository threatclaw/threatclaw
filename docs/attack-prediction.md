# Attack Prediction

ThreatClaw's prediction page (**Inventaire → Prédiction d'attaque**)
shows the most likely paths an attacker would take to reach the
customer's critical assets, and which fixes break the most paths.

## Two views

The page has two tabs answering two different questions :

### Prédiction (default)

> *"If an attacker tries now, where do they pass ?"*

Static analysis based on the inventory + CVE findings + criticality.
It computes paths in three families :

1. **External → Vulnerable → Critical** : an external entry point
   reaches a publicly exposed asset that has at least one CVE, which
   in turn connects to an asset flagged `critical`.
2. **CVE chain** : an asset with a high CVSS score (or a CVE listed
   on the CISA Known Exploited Vulnerabilities catalog) is on the
   shortest network path to a critical asset.
3. **Direct exposure** : a critical asset is itself reachable from
   the perimeter without any pivot.

This view works **as soon as you have inventory + CVE findings + at
least one critical asset declared**. It does not need any observed
attack history, which makes it the day-one value of the product —
useful for onboarding, weekly patch planning and exposure reporting.

### Activité observée

> *"What lateral movement has actually happened ?"*

Graph-walker that traverses edges derived from observed events :

- `LATERAL_PATH` : two hosts share a successful login by the same
  user account in the last 30 days, so credential reuse opens a
  practical pivot path between them.
- `ATTACKS` : a sigma alert flagged a source-to-destination pattern
  that matches a known attack technique.

This view is empty when the underlying telemetry is missing
(authentication logs not yet ingested, no sigma alerts firing). It
becomes more useful over time as the deployment ingests AD events,
endpoint logs and IDS signatures.

## Required data

| To get | You need |
|---|---|
| At least one path in the **Prédiction** tab | One asset with `criticality = critical`, plus CVE findings on assets that connect to it. The endpoint agent populates the inventory and CVE findings automatically. |
| At least one path in the **Activité observée** tab | Authentication events ingested (AD, Windows Event 4624, sshd accepted) so the engine can derive `LATERAL_PATH` edges, **or** sigma alerts that produce `ATTACKS` edges. |
| A meaningful exposure score | The `exposure_class` field on assets : `internet`, `dmz`, `lan`, `vlan_dev`. The default heuristic uses the IP range; declared values take precedence. |

## Per-path information

Each path card shows :

- **Risk badge** : critical, high, medium, low — derived from the
  worst CVE on the path and from the target's criticality.
- **Exploitability score (0-100)** : weighted aggregate of CVE EPSS
  scores, KEV listing, exposure of entry point, distance to target.
- **Path chain** : entry point → pivots → target. Each node shows
  hostname, max CVSS observed, and a `KEV` flag when one of the CVEs
  is in the CISA Known Exploited Vulnerabilities catalog.
- **CVE list** : up to six CVEs involved. Click an asset in the
  chain (assets UI) to see all of them and the recommended patches.
- **MITRE ATT&CK tags** : techniques that an attacker would chain to
  walk the path.

## Recompute

The prediction is recomputed every 6 hours by a background task.
You can force a recompute from the dashboard's **Recalculer** button
or :

```bash
curl -X POST -H "Authorization: Bearer $TC_TOKEN" \
  https://your-tc-server/api/tc/security/attack-paths/recompute
```

Recompute is cheap (under a second on a typical SMB topology).

## Choke points

The **Activité observée** tab also surfaces the top assets whose
hardening would break the largest number of predicted paths. Patch a
choke point and many downstream paths disappear in the next cycle —
this is the "biggest bang for the buck" ranking.

## Common reasons for an empty page

- **No critical asset declared**. Without a target, the predictor has
  nothing to converge to.
- **No CVE findings on monitored assets**. Roll out the endpoint
  agent on at least a couple of hosts ; CVE auto-correlation kicks
  in within minutes.
- **All assets are flagged `internal` only**. The `External →
  Vulnerable → Critical` family needs at least one entry point with
  exposure to the perimeter.
- **The graph topology is empty** in the **Activité observée** tab.
  This is normal until the deployment starts ingesting authentication
  events from AD or sigma alerts from network sensors.

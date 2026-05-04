# Inventory Gate — Doctrine

> ThreatClaw protects **declared assets**, not log observations.

This page explains why ThreatClaw refuses to escalate every IP that
appears in a log into an incident, and how to configure the gate so
your operator queue stays signal-rich.

## The problem

A perimeter network typically receives thousands of unsolicited
connection attempts every day — port scans, SSH brute-force probes,
exposed-service enumeration by botnets, vulnerability scrapers. The
firewall blocks them, but the underlying log entries are still
ingested by every observability tool sitting downstream.

Without a gate, every one of those entries can :

- Create a row in the asset inventory under the attacker's IP
- Get scored by the behavioural model
- Trigger an incident that the operator must triage
- Dilute the real signal in a sea of noise

A client looking at a console saturated with `5 signals high on
80.95.194.124` (an external scanner that the firewall already
neutralised) loses confidence in the product.

## The doctrine

A finding becomes an **incident** only when its asset resolves to
something the customer asked us to monitor.

Resolution order :

1. **Declared in the `assets` table** — by id, hostname, FQDN or any
   of the listed `ip_addresses`. This is the authoritative inventory.
2. **Inside a declared `internal_networks` CIDR** — for subnets that
   represent fleets of similar hosts the operator hasn't enumerated
   one by one (workstation VLAN, container subnet, …).
3. **RFC1918 fallback** — `10.0.0.0/8`, `172.16.0.0/12`,
   `192.168.0.0/16`. Universal default so fresh installs work without
   any setup; replaced by the explicit declarations as soon as they
   exist.

Anything else is an **external observation** : the underlying finding
is preserved for forensic, audit and pattern-mining, but no incident
is created and no LLM cycle is spent on it.

## Configuring the gate for your environment

### Declare your internal networks

```sql
INSERT INTO internal_networks (cidr, label, zone) VALUES
  ('10.42.0.0/16', 'Office LAN',     'lan'),
  ('172.20.0.0/24', 'DMZ',           'dmz'),
  ('203.0.113.0/29', 'Public servers','public');
```

Public IPs that you own are perfectly valid here — declare them
explicitly so attacks against your own internet-facing assets stay in
scope.

### Declare crown-jewel assets

For assets that warrant the strictest monitoring (domain controller,
file server, finance database, …), use the assets UI or :

```sql
UPDATE assets
   SET criticality   = 'critical',
       user_modified = ARRAY['criticality']
 WHERE hostname = 'srv-01-dom';
```

The `user_modified` flag prevents subsequent endpoint-agent syncs
from resetting the criticality to the auto-detected default.

### Adopt the endpoint agent

The endpoint agent reports the host's identity (hostname, IPs, MAC,
OS, software inventory) on every cycle, which is what populates the
`assets` table for hosts that aren't yet declared. Once the agent
runs on a machine, it counts as monitored.

## What the gate does NOT do

- It does **not** disable detection. Sigma rules, IDS signatures,
  authentication anomaly detection and threat-intel correlation
  still run on every event regardless of the asset's status.
- It does **not** silently delete external observations. They are
  written to the findings table with their full context and remain
  available for retrospective queries.
- It does **not** prevent firewall-block events from being logged.
  Those are still ingested ; they just don't surface as incidents
  the operator has to act on.

## Risks and mitigations

| Scenario | Risk | Mitigation |
|---|---|---|
| A real public-facing asset isn't in `assets` and isn't in `internal_networks` | Attacks against it are dropped to forensic, never escalated | Declare every public-facing asset during onboarding. The `assets` table accepts public IPs. |
| Two genuinely distinct hosts share a hostname | They get merged into a single asset | The assets UI exposes a manual `unmerge` action. The merge is logged in the audit trail. |
| Outbound exfil from a compromised internal host | Auto-archived as "perimeter mitigated" | Suppression rules distinguish source direction — outbound from a private host stays escalated even when blocked at the perimeter. |

## Where the rule lives

- Helper : `classify_asset()` in `src/agent/intelligence_engine.rs`
  with `cidr_contains_ipv4` and `is_rfc1918` predicates.
- Loaded once per intelligence cycle and applied before incident
  creation.
- The same predicate gates the behavioural-clustering pool in the ML
  engine (`ml-engine/src/features.py`) so cluster baselines are built
  from monitored assets only, not polluted by external scanner noise.

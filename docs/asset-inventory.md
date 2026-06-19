# Asset Inventory

The asset inventory is the spine of ThreatClaw. Detection runs against
log streams, but **escalation, scoring, attack-path prediction and
billing all flow through the assets table**. This page covers how
assets enter the inventory, how the platform avoids duplicate rows,
how to merge or split rows manually, and what the operator can
override.

If you want the doctrine — "why ThreatClaw only escalates on declared
assets" — read [`inventory-gate.md`](inventory-gate.md). This page
is the operator-facing companion.

## How an asset enters the inventory

There is a **single resolver** behind every discovery source:
`resolve_asset` in `src/graph/asset_resolution.rs`. Every connector
that learns about a host (endpoint agent, nmap discovery, AD, GLPI,
firewall logs, Sysmon telemetry, syslog forwarder, etc.) feeds a
`DiscoveredAsset` payload through this single entry point.

The resolver matches against existing rows in priority order:

1. **MAC address** — most reliable, survives DHCP changes.
2. **Hostname** — the strongest signal in an AD environment. The
   PostgreSQL row wins over the graph node when both exist so the
   observe-and-enrol paths (osquery and syslog) converge on the same
   row.
3. **FQDN** — fallback when the short hostname is ambiguous.
4. **IP address** — least reliable: only accepted as a match if the
   existing asset was last seen within 24 h, otherwise the resolver
   assumes DHCP reuse and creates a new row.

When the resolver finds a match it **enriches** the existing row
(IPs, MAC, FQDN, OS, ports, services, criticality, sources list) — it
never overwrites a value the operator manually set (the
`user_modified` column tracks which fields the human owns).

When no row matches and the source IP is internal, the resolver
creates a fresh row with a generated asset id (`asset-<n>` or
`syslog-observed-<hostname>` depending on the path).

External IPs (Internet scanners, public IPs that aren't owned by the
customer) are intentionally **not** enrolled — they live in the IP
graph for forensic context but never reach the assets table.

## Inventory views

The **Inventory → Assets** page shows the active inventory. Five
tabs filter by lifecycle bucket:

| Tab | Meaning |
|-----|---------|
| **Tous** / **All** | Every active asset, including ones still in the observation window |
| **Facturables** / **Billable** | Assets that count against the tier quota: declared, observed-persistent, or transient with ≥ 3 distinct days in the last 30 |
| **En observation** / **In observation** | Transient assets (seen < 3 distinct days) — kept visible so the operator can promote or merge them before they age out |
| **Doublons probables** / **Probable duplicates** | Rows flagged by the resolver as possible duplicates of an existing asset (cross-source MAC vs hostname mismatch, IP collision, …) |
| **Inactifs** / **Inactive** | Assets the resolver has not seen for a while — kept for audit but excluded from the default views |

A separate **status='merged'** marker hides aliases that were folded
into a canonical row by a manual merge. They never appear in the list
even though their underlying row stays in the database so historical
findings keep resolving.

## Manual merge

When the resolver creates two rows for what the operator knows is the
same machine (different hostname casing, observe-vs-declared race,
legacy import, …) the inventory page lets you merge them by hand.

1. Click **Fusion** in the toolbar. Each row gains a checkbox.
2. Pick exactly two rows for the side-by-side wizard, or pick three or
   more for a quick canonical-only merge.
3. The wizard opens.

### The 2-asset side-by-side wizard

When exactly two assets are selected, the merge dialog renders a
**side-by-side picker** for the descriptive fields (name, category,
sub-category, role, criticality, owner, location, URL, OS). Click a
cell to choose the value the canonical row will keep.

Identity fields are **always unioned server-side** regardless of
which side the operator clicks: `hostname`, `mac_address`, `fqdn`,
`ip_addresses`, `services` and `tags`. This is what guarantees the
auto-resolver keeps matching either side after the merge — the alias
row remains in the database with `status='merged'`, so any future
sync of either hostname or MAC still finds the right canonical.

The wizard also requires a free-text **reason** so the merge is
auditable (`merge_aliases` row with `merged_by`, `merged_at`,
`reason`).

### N-asset simple merge

When more than two rows are selected, the wizard skips the picker
(four columns of fields would not fit). The operator picks the
canonical row and supplies a reason; every other row is marked
`status='merged'` and the canonical is left untouched. Useful when an
operator already declared the canonical and just wants to absorb the
N observed shadows.

### Reverting a merge

Every merge stays in `merge_aliases` for 30 days. The asset detail
page exposes an **Unmerge** button on the canonical row that restores
each alias to `status='active'` and drops the mapping. Past that
window the aliases stay merged.

## Keep-separate

When the resolver flags two rows as **probable duplicates** but the
operator knows they are genuinely distinct hosts (a hostname reused
by a legitimate twin, two routers with the same MAC vendor pattern,
…), click **Keep separate** in the flag banner. The two assets are
recorded as a "do not merge" pair in `asset_keep_separate` and the
resolver stops flagging them. Manual merge from the operator still
works — the pair is only a hint to the auto-merger.

## Excluding an asset

Some hosts are visible on the network but the customer does not want
them counted or analysed (a partner's machine on the LAN, a noisy
sensor, a honeypot, an asset in transition). The asset detail page
exposes **Exclure cet asset** / **Exclude this asset** which:

- Removes the asset from the billable count.
- Stops the analysis pipeline for this asset (no new sigma alert is
  promoted to incident, no ML score, no graph edges).
- Keeps the row visible under the dedicated tab for audit.

The exclusion requires a reason (auditable) and is reversible from
the same panel.

## Critical assets

Attack-path prediction needs at least one asset flagged as
`criticality = 'critical'`. The asset detail page exposes the
criticality dropdown directly; setting it from the UI also flips the
`user_modified.criticality` flag so subsequent agent syncs do not
reset it to the auto-detected value.

The dashboard accepts five levels (`low`, `medium`, `high`,
`critical` and an `unknown` placeholder for fresh discoveries).
Anything at `critical` becomes a target for the predictive path
solver and a higher-priority alert in the operator queue.

## Where it lives in the code

| Concern | File |
|---------|------|
| Auto-merge resolver | `src/graph/asset_resolution.rs` (function `resolve_asset`) |
| Inventory listing | `src/db/pg_threatclaw.rs` (function `list_assets`) — excludes `status='merged'` by default |
| Manual merge handler | `src/channels/web/handlers/threatclaw_api.rs` (function `asset_merge_handler`) |
| 2-asset wizard | `dashboard/src/app/assets/page.tsx` (the `mergePatch` state and the side-by-side modal) |
| Inventory gate (escalation predicate) | `src/agent/intelligence_engine.rs` (function `classify_asset`) |

The schema lives across migrations V67 (billable persistence),
V68 (merge aliases), V83/V84/V85 (observed-asset dedup). See
`migrations/` for the full history.

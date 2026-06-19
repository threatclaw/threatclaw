# Hunt — The Log Lake

The Hunt page (labelled **Recherche logs** / **Log search** in the
sidebar) exposes the raw log payload for free-text investigation. It
is the right tool when:

- a card mentions an alert and you want to see the underlying raw
  event,
- you suspect an alert exists somewhere but no card surfaces it,
- you need to investigate a host that is not yet declared as an
  asset (the Inventory page would not list it; Hunt can search by
  hostname anyway),
- you want to pivot from an incident to "what else happened around
  that timestamp on that host?".

## Where it sits

The dashboard menu carries a **Recherche logs** / **Log search**
entry under the **Investigation** section. The page itself lives at
`/hunt`. From any incident detail page, the **Voir les logs** /
**View logs** button pivots into this page with the hostname and a
±10 min window around the incident pre-filled.

## Filters

The filter bar at the top stacks five inputs. They AND together;
each one narrows the result set.

### Hostname

A combobox seeded from the inventory. Type to filter; the dropdown
shows the matching asset hostnames first. You can also type a
free-text hostname for hosts not yet enrolled — useful for
investigating a machine that just appeared in the logs but is not
declared yet. The free-text value is highlighted so you know you
are searching outside the inventory.

### Source tag

The set of tags is built dynamically from the recent log stream, so
the dropdown only offers tags that have actually emitted events in
the active time range. Common values: `sigma_alerts`,
`osquery.sysmon`, `osquery.powershell`, `syslog.tcp.*`,
`osquery.users`, `osquery.ports`. Picking a tag scopes every
subsequent column read to that ingestion channel.

### Time range

Seven presets (15 min, 1 h, 6 h, 24 h, 3 d, 7 d, 30 d) plus a
**Custom** option that opens a date-range picker. The custom range
accepts ISO 8601 timestamps via the URL too, so you can share a
specific window by link.

### Free-text search

A substring search over the JSON payload of each event. The match
is case-insensitive and looks at every value in the payload — no
need to know the field path. Common patterns:

- `203.0.113.5` to find every event mentioning a source IP
- `MiniDump` to find every commandline mentioning the LSASS dump
  technique
- `krbtgt` to find every event referring to the Kerberos
  distribution account

A leading `!` negates the substring — useful to exclude noise:
`Failed password !root` returns failed authentication that did not
target `root`.

### Refresh

The page does not auto-poll by default. Click the refresh button
when you want the result set to update; the URL captures the active
filters so a refresh keeps the query stable.

## Results

A virtualized table of matching events. Each row shows:

- the event timestamp (with a tooltip for the precise ISO),
- the tag,
- the hostname,
- a one-line preview of the payload,
- an expand button that shows the full JSON.

The footer reports the cursor (event id + time) of the last
displayed row, plus the count of TimescaleDB chunks the query
scanned. The chunk count is the early-warning signal that the time
range is too wide — if it climbs past ~20 chunks, narrow the
window before paginating.

## Saved queries

The right-hand sidebar lists named presets. Click **Save current
query** to record the active filter set with a name; clicking the
chip later restores it. Useful for repeatable hunts:

- *"Outbound from staging-* "* — hostname pattern + 24 h window +
  tag `osquery.sysmon` + substring `connect`
- *"Sudo failures on prod"* — hostname pattern `srv-prod-*` + tag
  `syslog.tcp.*` + substring `sudo: authentication failure`
- *"Last week LSASS access"* — 7 d window + substring `lsass.dmp`

Saved queries are scoped to your account by default. Share a query
by clicking the link icon — the URL encodes every filter.

## Pivoting from an incident

The incident detail page has a **Hunt** button next to the action
panel. Clicking it opens Hunt pre-filtered to:

- the incident's asset hostname,
- a ±10 minute window around the earliest and latest events on the
  card,
- the most informative tag from the linked sigma alerts (typically
  `osquery.sysmon` when the alerts come from the endpoint, or
  `syslog.tcp.*` when they come from the agent's rsyslog
  forwarder).

This is the canonical "what else happened" pivot — it surfaces the
raw events the cards summarized, and lets you broaden the time range
from there.

## A few worked examples

### Confirm the SSH brute force you observed

1. Hostname = the targeted asset.
2. Tag = `syslog.tcp.*`.
3. Time range = 1 h around the alert.
4. Substring = `Failed password`.

Expect a flat list of `Failed password for <user> from <ip>` lines
with the timestamp pattern of an automated bruteforcer (one per
second or burstier).

### Hunt for credential dumping signs

1. Tag = `osquery.sysmon`.
2. Time range = 24 h.
3. Substring = `comsvcs OR MiniDump OR lsass.dmp`.

The three alternatives cover the three most common LSASS dump
patterns. Even rule-bypassing variants tend to leave one of these in
the commandline.

### Find every login on a critical asset over the week

1. Hostname = the critical asset.
2. Tag = `syslog.tcp.*`.
3. Time range = 7 d.
4. Substring = `Accepted publickey OR Accepted password`.

Returns every successful login. Save the query as
*"<asset>-logins-7d"* and refresh it weekly for an audit trail.

## REST equivalent

The same query lives behind a single endpoint:

```bash
curl -G \
  -H "Authorization: Bearer $TC_TOKEN" \
  --data-urlencode "hostname=srv-prod-01" \
  --data-urlencode "tag=syslog.tcp.*" \
  --data-urlencode "from=2026-06-15T00:00:00Z" \
  --data-urlencode "to=2026-06-15T23:59:59Z" \
  --data-urlencode "q=Failed password" \
  http://localhost:3000/api/tc/logs/search
```

The response is JSON: an array of events plus a `cursor` field for
pagination. Pass `cursor=...` on the next call to get the next
page.

## Performance notes

The underlying storage is a TimescaleDB hypertable on the `logs`
table. Queries are fast (under a second on a typical 100 k events/h
deployment) when the time range scopes naturally to a small number
of chunks. The page reports the chunk count to help you tune; if
you find yourself pushing past ~20 chunks regularly, consider
narrowing the time range or filtering by hostname first.

Retention is 90 days by default (configurable in `threatclaw.toml`),
so anything older than that has been compressed and may not respond
to substring search at the same speed.

## Next reads

- [`operator-handbook.md`](operator-handbook.md) — the three-layer
  detection model, the dashboard tour
- [`sigma-rules.md`](sigma-rules.md) — how the events you see in
  Hunt become sigma alerts
- [`api.md`](api.md) — the full REST reference

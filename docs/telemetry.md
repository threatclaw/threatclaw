# Telemetry

ThreatClaw sends one anonymous ping per install, every seven days, so
we can answer the basic question "how many ThreatClaws are out there
and which versions are they running?" — and so we can tell our actual
users from a rate-limit-busting bot scraping the installer.

This page describes exactly what we collect, why, and how to turn it
off. It is the canonical reference; if any other doc disagrees, this
page wins.

## What we collect

| Field | Example | Why |
|---|---|---|
| `install_id` | `tc-d49c18eb-a967-…` | Random UUID generated on first boot, persisted to `~/.threatclaw/licensing/install_id`. Used to count distinct installs without identifying the operator. |
| `version` | `1.0.16-beta` | So we can tell who is on which release and prioritise upgrade nudges. |
| `tier` | `free` / `starter` / `pro` / `business` / `trial` / `enterprise` | Tells us the free/paid mix. |
| `asset_count` | a number, e.g. `42` | Sent exact, **bucketed server-side** to one of `0-50` / `51-200` / `201-500` / `501-1500` / `1500+`. The exact value is never persisted. |
| Country code | `FR` | Derived **server-side** from the request IP (Cloudflare's `CF-IPCountry` header), then the IP itself is discarded. We never store IP addresses. |

## What we do NOT collect

- No email, no operator name, no organisation name.
- No hostname, no internal asset names, no IP addresses (yours or your assets').
- No path on disk, no installation tree contents.
- No usage information: we don't track which features you click on, which alerts you triage, which incidents you investigate, which connectors you've configured.
- No content of your security data: alerts, findings, incidents, logs — none of that ever leaves your install.
- Nothing about your licence key. Telemetry is a separate channel from licensing; the two never share a payload.

## How to turn it off

Set this in your `.env` (next to your other ThreatClaw settings):

```
TC_TELEMETRY_DISABLED=1
```

Restart the agent. From that point on, no telemetry ping is sent. The
agent does not retry once disabled, and disabling it has no effect on
licensing, scanning, alerting, or any other functionality.

If you re-enable it later (remove the line, restart), pings resume on
the normal seven-day cadence.

## Why an anonymous ping at all

ThreatClaw is open source. Anyone can run the one-line installer
without registering. Without a single signal back from running
installs we have no way to:

- Know how many installations exist.
- Tell apart a real user from a bot scraping `get.threatclaw.io`.
- Spot a regression that only happens on a specific OS or CPU profile.
- Prioritise security patches for the versions that are actually
  deployed (vs. ancient versions nobody uses any more).

The minimum collection above is the smallest signal that answers
those questions. It's an industry-standard trade-off — Plausible
self-hosted, Cal.com, GitLab self-managed and Sentry self-hosted all
do something similar.

## Where the data lives

- **Transit**: TLS 1.2/1.3 to `license.threatclaw.io` (Cloudflare Worker).
- **At rest**: Cloudflare D1 database in EU West region. Each row is
  the schema described above — five fields plus first-seen and
  last-seen timestamps, nothing more.
- **Retention**: pings are kept while the install is active (last seen
  within 14 days). Beyond that the row is left as a historical record
  for trend analysis. We do not enrich it, share it with third
  parties, or use it for marketing.

## Audit-friendly summary

For a CISO reviewing this:

- Outbound traffic: HTTPS POST to `license.threatclaw.io` every seven
  days. Roughly 200 bytes per ping.
- Sensitive data leaving the perimeter: none beyond the country code
  derived from the public IP.
- Data subjects (GDPR sense): none. The payload contains no personal
  data — `install_id` is a system-generated UUID, the bucket is a
  range, and the country is derived from a public network attribute.
- Opt-out: a single environment variable, no operator support call
  required.

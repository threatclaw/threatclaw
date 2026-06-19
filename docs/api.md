# API Reference

ThreatClaw exposes a REST API on port 3000 (configurable). All endpoints require Bearer token authentication.

> **The authoritative endpoint list is the runtime OpenAPI 3.1 spec at
> `/api/tc/openapi.json`.** This page describes the families of endpoints,
> their authentication model, and the integration entry points an
> external system is most likely to talk to. The dashboard renders the
> same spec in a browsable form under **Settings → API**.

## Authentication

Every call carries an `Authorization: Bearer <token>` header:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:3000/api/tc/health
```

The token is generated at first boot and stored in `/opt/threatclaw/.env`
(or wherever the install script wrote it). It can also be set via the
`GATEWAY_AUTH_TOKEN` environment variable.

Two endpoint families bypass the gateway token:

- `/api/tc/webhook/ingest/<source>` accepts a per-source webhook token
  (via the `X-Webhook-Token` header). Endpoint agents push data here.
- `/api/tc/agent/{install,uninstall}.{sh,ps1}` and `/api/tc/agent/manifest`
  serve installer scripts and the agent's query manifest. They are
  unauthenticated because the install one-liner runs before the host has
  any credential, and the manifest is authenticated by the webhook token
  the agent already has.

## Endpoint families

| Family | Path prefix | What it does |
|---|---|---|
| **System** | `/api/tc/health`, `/api/tc/version`, `/api/tc/pause` | Liveness, version, kill switch |
| **Findings** | `/api/tc/findings*` | Vulnerability findings: list, count, get, status updates |
| **Alerts** | `/api/tc/alerts*` | SOC alerts list and per-level counts |
| **Sigma** | `/api/tc/sigma*` | Rule catalog, per-rule stats, exception ladder, audit log, MITRE coverage matrix |
| **Incidents** | `/api/tc/incidents*` | Incidents and operator decisions: resolve, false-positive, accept-risk, snooze, archive, reinvestigate, notes, HITL action queue |
| **Assets** | `/api/tc/assets*` | Inventory: list, get, full detail, security view, criticality override, exclude, merge / unmerge, keep-separate |
| **Hunt (log lake)** | `/api/tc/logs/search`, `/api/tc/hunt/saved*` | Free-text search over recent logs + saved searches |
| **Skills & config** | `/api/tc/skills/catalog`, `/api/tc/config/<skill_id>` | Skill catalog (reads `skill.json` files) and per-skill configuration |
| **Graph & prediction** | `/api/tc/graph*`, `/api/tc/security/attack-paths*`, `/api/tc/security/choke-points` | Observed sources, lateral-movement candidates, CVE-chain attack paths, choke-point ranking |
| **Endpoint agents** | `/api/tc/endpoint-agents`, `/api/tc/webhook/*`, `/api/tc/agent/*` | Registered hosts, webhook token management, install / uninstall script delivery, agent manifest |
| **Metrics** | `/api/tc/metrics` | Dashboard summary (open incidents, pending findings, agent freshness…) |
| **OpenAI-compatible** | `/v1/chat/completions`, `/v1/models` | Direct LLM access in OpenAI format for tooling that already speaks the protocol |

Sigma, asset and incident families changed substantially across recent
releases. Use the runtime OpenAPI spec for the exact request and
response shapes — the spec is regenerated from the route registry on
every build, so it is always in sync with the deployed binary.

## Agent control routes

Agent control routes (mode, audit, HITL callback, integrity verification,
remediation actions) are authenticated and documented in the runtime
OpenAPI spec once logged in. They are not enumerated here to keep the
attack surface description small for unauthenticated readers.

## Python SDK

```python
from threatclaw_sdk import ThreatClawClient, Finding, Severity

client = ThreatClawClient(api_url="http://localhost:3000", api_token="<token>")

# Submit a finding
client.report_finding(Finding(
    skill_id="my-skill",
    title="Issue detected",
    severity=Severity.HIGH,
    asset="192.168.1.10",
))

# Get metrics
metrics = client.get_dashboard_metrics()
```

The SDK wraps the same endpoints described above with idiomatic types.
For a one-off integration that does not justify the SDK, the REST
endpoints are accessible from anything that can sign a header and POST
JSON.

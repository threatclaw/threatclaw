# API Reference

ThreatClaw exposes a REST API on port 3000 (configurable). All endpoints require Bearer token authentication.

The full OpenAPI 3.1 specification is available to authenticated users via the dashboard.

## Authentication

```bash
curl -H "Authorization: Bearer <token>" http://localhost:3000/api/tc/health
```

The token is displayed at startup or set via `GATEWAY_AUTH_TOKEN`.

## Endpoints

### System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/tc/health` | System health, version, LLM status |
| GET | `/api/tc/openapi.json` | OpenAPI specification (authenticated) |

### Findings

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/tc/findings` | List findings (filter by severity, status, skill) |
| POST | `/api/tc/findings` | Create a finding |
| GET | `/api/tc/findings/counts` | Count findings by severity |
| GET | `/api/tc/findings/{id}` | Get finding details |
| PUT | `/api/tc/findings/{id}/status` | Update finding status |

### Alerts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/tc/alerts` | List SOC alerts |
| GET | `/api/tc/alerts/counts` | Count alerts by level |

### Skills & Config

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/tc/skills/catalog` | List all skills (reads skill.json files) |
| GET | `/api/tc/config/{skill_id}` | Get skill configuration |
| POST | `/api/tc/config/{skill_id}` | Set skill configuration |
| GET | `/api/tc/metrics` | Dashboard metrics |

### Agent Control

Agent control routes (mode, audit, HITL callback, integrity verification) are authenticated and documented in the runtime OpenAPI spec once logged in. They are not listed here to reduce unauthorized enumeration.

### Endpoint Agents

| Method | Path | Description |
|--------|------|-------------|
| GET  | `/api/tc/endpoint-agents` | List registered endpoint agents (id, hostname, last_seen) |
| POST | `/api/tc/webhook/token/{source}` | Generate a webhook token for a source (e.g. `osquery`, `zeek`, `suricata`) |
| GET  | `/api/tc/webhook/token/{source}` | Read the existing token without regenerating |
| POST | `/api/tc/webhook/ingest/{source}` | Endpoint agents POST inventory snapshots here. Auth via `X-Webhook-Token` header. |

### Incidents — bulk operations

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/tc/incidents/bulk-archive-stale` | Archive open incidents in `pending` verdict older than 24h (legacy artefacts) |
| POST | `/api/tc/incidents/bulk-archive-perimeter-mitigated` | Archive open incidents whose evidence is fully blocked at the firewall. Add `?dry_run=true` to preview the count without mutating. |
| POST | `/api/tc/incidents/{id}/archive` | Archive a single incident |
| POST | `/api/tc/incidents/archive-resolved` | Archive every incident in resolved/closed/false_positive verdict |

### Attack Prediction

| Method | Path | Description |
|--------|------|-------------|
| GET  | `/api/tc/graph/attack-paths` | CVE-chain analyzer — paths from external IPs through vulnerable pivots to critical assets, derived from inventory + CVE findings |
| GET  | `/api/tc/security/attack-paths` | Graph-walker — paths derived from observed authentication and detection events (LATERAL_PATH / ATTACKS edges) |
| POST | `/api/tc/security/attack-paths/recompute` | Trigger a new computation cycle synchronously |
| GET  | `/api/tc/security/choke-points` | Top assets whose hardening would break the most predicted paths |

### Infrastructure

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/tc/targets` | List configured targets |
| POST | `/api/tc/targets` | Add a target |
| DELETE | `/api/tc/targets/{id}` | Remove a target |

### OpenAI-Compatible

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/chat/completions` | Send a message (OpenAI format) |
| GET | `/v1/models` | List available models |

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

# API Reference

ThreatClaw exposes a REST API on port 3000 (configurable). All endpoints require Bearer token authentication.

The full OpenAPI 3.1 specification is available at `GET /api/tc/openapi.json`.

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
| GET | `/api/tc/openapi.json` | OpenAPI specification |

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

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/tc/agent/mode` | Current mode + available modes |
| POST | `/api/tc/agent/mode` | Change agent mode |
| GET | `/api/tc/agent/kill-switch` | Kill switch status |
| POST | `/api/tc/agent/kill-switch` | Trigger emergency stop |
| GET | `/api/tc/agent/soul` | Verify agent soul integrity |
| GET | `/api/tc/agent/audit` | Audit log entries |
| POST | `/api/tc/agent/react-cycle` | Trigger a ReAct analysis cycle |
| POST | `/api/tc/agent/hitl-callback` | HITL approval callback |

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

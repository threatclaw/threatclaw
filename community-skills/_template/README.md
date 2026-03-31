# skill-CHANGEME

> One-line description of what this skill does.

## What it does

Explain clearly what this skill checks, what API it uses, and what findings it produces.

## Prerequisites

- A free/paid API key from [Example Service](https://example.com)
- Targets configured in ThreatClaw dashboard

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `api_key` | Yes | API key from example.com |
| `targets` | Yes | Comma-separated list of domains/IPs to check |

Configure in: **Dashboard > Skills > skill-CHANGEME > Configure**

## Findings produced

| Title | Severity | When |
|-------|----------|------|
| "Issue detected: {target}" | HIGH | Risk score > 70 |

## Example output

```json
{
  "skill_id": "skill-CHANGEME",
  "title": "Issue detected: suspicious.example.com",
  "severity": "HIGH",
  "category": "monitoring",
  "asset": "suspicious.example.com",
  "source": "example-api",
  "metadata": {"risk_score": 85}
}
```

## Development

```bash
# Run tests
python3 -m pytest tests/ -v

# Run locally
export THREATCLAW_API_URL="http://localhost:3000"
python3 main.py

# Run in Docker (production mode)
docker build -t skill-CHANGEME .
docker run --rm --network none --memory 256m --read-only --tmpfs /tmp:size=64m skill-CHANGEME
```

## License

Apache-2.0

# Configuration

## Environment Variables

Set in `/opt/threatclaw/.env` (Docker install) or `.env` in project root (source install):

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | PostgreSQL connection string |
| `TC_DB_PASSWORD` | (required) | Database password — must be set, weak values rejected |
| `TC_CORE_PORT` | `3000` | API port |
| `TC_DASHBOARD_PORT` | `3001` | Dashboard port |
| `TC_AUTH_TOKEN` | auto-generated | Gateway auth token |
| `RUST_LOG` | `info` | Log level (trace, debug, info, warn, error) |

### LLM

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_BACKEND` | `ollama` | Provider: `ollama`, `mistral`, `anthropic`, `openai_compatible` |
| `OLLAMA_MODEL` | (configurable) | Model name for local LLM backend |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama server URL |
| `MISTRAL_API_KEY` | — | Mistral AI API key |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |

### Agent

| Variable | Default | Description |
|----------|---------|-------------|
| `TC_PERMISSION_LEVEL` | `ALERT_ONLY` | Default mode |
| `TC_INSTANCE_NAME` | `threatclaw` | Instance name |
| `GATEWAY_HOST` | `127.0.0.1` | Gateway bind address |
| `GATEWAY_PORT` | `3000` | Gateway port |
| `WASM_ENABLED` | `true` | Enable WASM tool loading |
| `WASM_CHANNELS_ENABLED` | `true` | Enable WASM channel loading |
| `EMBEDDING_ENABLED` | `false` | Enable vector embeddings |
| `EMBEDDING_PROVIDER` | `ollama` | Embedding provider |
| `HEARTBEAT_ENABLED` | `false` | Enable proactive monitoring |
| `HEARTBEAT_INTERVAL_SECS` | `1800` | Heartbeat interval (seconds) |

## Channels

### Slack

1. Create a [Slack App](https://api.slack.com/apps)
2. Under **OAuth & Permissions**, get the Bot Token (`xoxb-...`)
3. Under **Basic Information**, get the Signing Secret
4. Configure in the setup wizard or store as secrets:
   ```bash
   threatclaw secret set slack_bot_token xoxb-...
   threatclaw secret set slack_signing_secret ...
   ```

### Telegram

1. Talk to [@BotFather](https://t.me/BotFather) to create a bot
2. Copy the bot token
3. Configure in the setup wizard

### Discord

1. Create an app in the [Discord Developer Portal](https://discord.com/developers/applications)
2. Under **Bot**, copy the token
3. Under **General Information**, copy the Public Key

### WhatsApp

1. Set up [WhatsApp Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api) on Meta Developer Portal
2. Get a permanent access token and phone number ID

## Data Retention

Configure in `threatclaw.toml`:

```toml
[retention]
syslog_days = 30        # Raw syslog logs
alerts_days = 90        # SOC alerts
findings_days = 365     # Vulnerability findings
audit_log = -1          # Never delete (legal requirement)
```

## Inventory & monitored scope

ThreatClaw escalates an event to an incident **only** when its asset
matches the customer inventory. Out-of-scope events (random Internet
scanners hitting the perimeter, threat actors hammering blocked ports,
…) are kept as forensic findings but never reach the operator queue.
The match works in this order :

1. The asset string is a known entry in the `assets` table (by id,
   hostname, FQDN, or any of the listed `ip_addresses`).
2. The asset string parses as an IPv4 inside one of the customer-
   declared CIDRs in the `internal_networks` table.
3. The asset string parses as an IPv4 in RFC1918 (`10.0.0.0/8`,
   `172.16.0.0/12`, `192.168.0.0/16`) — universal fallback for fresh
   installs that haven't filled `internal_networks` yet.

Anything else is treated as an external observation.

### Declare an internal network

```bash
psql -U threatclaw -d threatclaw -c \
  "INSERT INTO internal_networks (cidr, label, zone) VALUES \
   ('10.42.0.0/16', 'Office LAN', 'lan'), \
   ('172.20.0.0/24', 'DMZ', 'dmz');"
```

### Declare a critical asset

Attack-path prediction needs at least one asset flagged as `critical`
(domain controller, file server, production database, …). Use the
dashboard's asset detail page or :

```bash
psql -U threatclaw -d threatclaw -c \
  "UPDATE assets SET criticality='critical', user_modified=ARRAY['criticality'] \
   WHERE hostname='srv-01-dom';"
```

The `user_modified` flag prevents subsequent endpoint-agent syncs from
resetting the field to its auto-detected default.

## Agent Modes

| Mode | Description | Requires permissions |
|------|-------------|---------------------|
| **Investigator** (default) | Scans, correlates, proposes. Never executes. | No |
| **Responder** | Proposes + executes after approval (Slack/dashboard) | Yes |
| **Autonomous Low** | Auto-executes low-risk actions | Yes |
| **Analyst** | Fixed pipeline, no AI decisions | No |

Change mode via the dashboard or API:
```bash
curl -X POST http://localhost:3000/api/tc/agent/mode \
  -H "Authorization: Bearer <token>" \
  -d '{"mode": "investigator"}'
```

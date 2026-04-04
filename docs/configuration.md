# Configuration

## Environment Variables

Set in `/opt/threatclaw/.env` (Docker install) or `.env` in project root (source install):

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | PostgreSQL connection string |
| `TC_DB_PASSWORD` | `threatclaw` | Database password |
| `TC_CORE_PORT` | `3000` | API port |
| `TC_DASHBOARD_PORT` | `3001` | Dashboard port |
| `TC_AUTH_TOKEN` | auto-generated | Gateway auth token |
| `RUST_LOG` | `info` | Log level (trace, debug, info, warn, error) |

### LLM

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_BACKEND` | `ollama` | Provider: `ollama`, `mistral`, `anthropic`, `openai_compatible` |
| `OLLAMA_MODEL` | `qwen3:14b` | Model name for Ollama |
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

# Getting Started

## Requirements

- **OS**: Linux (Debian 12+, Ubuntu 22.04+)
- **Rust**: 1.90+ with `wasm32-wasip2` target
- **Docker**: Docker Engine 24+ and Docker Compose v2
- **RAM**: 8GB minimum, 16GB+ recommended for local LLM
- **Disk**: 20GB minimum, 50GB+ if using Ollama models

## Installation

### 1. Clone and build

```bash
git clone https://github.com/threatclaw/threatclaw.git
cd threatclaw
cargo build --release
```

### 2. Start infrastructure

```bash
docker compose -f docker/docker-compose.core.yml up -d
```

This starts PostgreSQL, Redis, and Fluent Bit.

### 3. Install a local LLM (recommended)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:14b    # for 16-32GB RAM
# or
ollama pull qwen3:8b     # for 8-16GB RAM
```

### 4. Run ThreatClaw

```bash
./target/release/threatclaw run
```

On first run, ThreatClaw will:
- Apply database migrations
- Load WASM skills from `~/.threatclaw/tools/`
- Load WASM channels from `~/.threatclaw/channels/`
- Start the web gateway on port 3000

### 5. Open the dashboard

Start the dashboard:

```bash
cd dashboard
npm install
PORT=3001 npm run dev
```

Open `http://localhost:3001` and follow the setup wizard.

## Configuration

ThreatClaw reads configuration from:

1. `~/.threatclaw/.env` — environment variables (DATABASE_URL, LLM_BACKEND, etc.)
2. `~/.threatclaw/settings.json` — persistent settings
3. `threatclaw.toml` — project configuration (optional)

### Minimal `.env`

```bash
DATABASE_URL=postgres://threatclaw:PASSWORD@127.0.0.1:5432/threatclaw
LLM_BACKEND=ollama
OLLAMA_MODEL=qwen3:14b
OLLAMA_BASE_URL=http://127.0.0.1:11434
```

## Sending logs to ThreatClaw

ThreatClaw receives logs via Fluent Bit on port 514 (syslog).

| Source | Configuration |
|--------|--------------|
| **Linux** | Add `*.* @@threatclaw-ip:514` to `/etc/rsyslog.conf` |
| **Windows** | Install [NXLog CE](https://nxlog.co/products/nxlog-community-edition) (free) |
| **pfSense** | Status > System Logs > Settings > Enable Remote Logging |
| **FortiGate** | `config log syslogd setting` → set server IP |
| **Docker** | `--log-driver=fluentd --log-opt fluentd-address=threatclaw-ip:24224` |

## Next steps

- [Configure communication channels](configuration.md#channels) (Slack, Telegram, Discord)
- [Browse available skills](skills.md)
- [Read the API documentation](api.md)

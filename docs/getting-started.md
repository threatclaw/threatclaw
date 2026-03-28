# Getting Started

## Requirements

- **OS**: Linux (Debian 12+, Ubuntu 22.04+)
- **Docker**: Docker Engine 24+ with Compose plugin
- **RAM**: 16GB minimum (32GB+ recommended for AI models)
- **Disk**: 30GB minimum (AI models download ~18GB on first boot)
- **Network**: Internet access for initial model download

## Installation

### One-line install (recommended)

```bash
curl -fsSL https://get.threatclaw.io | sudo bash
```

This will:
1. Install Docker if not present
2. Download all configuration files
3. Generate a secure database password and auth token
4. Pull Docker images from `ghcr.io/threatclaw/`
5. Start all services
6. Download AI models in the background (~18GB, takes 10-15 min)

Open `http://your-server:3001` and create your admin account.

### Docker Compose (manual)

```bash
git clone https://github.com/threatclaw/threatclaw.git
cd threatclaw/docker
cp .env.example .env
# Edit .env to set your password and ports
docker compose up -d
```

### From source (developers only)

```bash
git clone https://github.com/threatclaw/threatclaw.git && cd threatclaw
cargo build --release
./target/release/threatclaw run
# Dashboard: cd dashboard && npm install && npm run build && npx next start -p 3001
```

Requires: Rust 1.90+, PostgreSQL 16 with pgvector + Apache AGE, Ollama.

## First boot

On first boot, ThreatClaw will:
1. Create the database schema (28 migrations)
2. Download AI models: L1 Triage (5GB), L2 Reasoning (8.5GB), L3 Instruct (5GB)
3. Start the Intelligence Engine (cycle every 5 min)
4. Start the dashboard on port 3001

**First access:** Open `http://your-server:3001` → Create your admin account → Follow the onboarding wizard.

## Configuration

### Ports

Edit `.env` before starting:
```bash
TC_DASHBOARD_PORT=3001    # Dashboard (default: 3001)
TC_CORE_PORT=3000         # API (default: 3000)
TC_SYSLOG_PORT=514        # Syslog receiver (default: 514)
```

### Database password

```bash
TC_DB_PASSWORD=your-secure-password
```

The installer generates a random password automatically.

### Cloud LLM (optional)

Add a cloud LLM for enhanced conversation quality:
```bash
ANTHROPIC_API_KEY=sk-ant-...    # Claude
MISTRAL_API_KEY=...              # Mistral AI
```

ThreatClaw works 100% locally without cloud. Cloud LLM is optional.

## Sending logs to ThreatClaw

ThreatClaw receives logs via Fluent Bit on port 514 (syslog).

| Source | Configuration |
|--------|--------------|
| **Linux** | Add `*.* @@threatclaw-ip:514` to `/etc/rsyslog.conf` |
| **Windows** | Install [NXLog CE](https://nxlog.co/products/nxlog-community-edition) |
| **pfSense** | Status > System Logs > Settings > Enable Remote Logging |
| **FortiGate** | `config log syslogd setting` → set server IP |
| **Docker** | `--log-driver=fluentd --log-opt fluentd-address=threatclaw-ip:24224` |

## Troubleshooting

### Change port
Edit `/opt/threatclaw/.env`, then: `docker compose down && docker compose up -d`

### Change data directory
Before first install: set `TC_DIR=/your/path` when running the installer.

### Clean reinstall
```bash
cd /opt/threatclaw && docker compose down -v --rmi all
rm -rf /opt/threatclaw
curl -fsSL https://get.threatclaw.io | sudo bash
```

### Check service status
```bash
cd /opt/threatclaw && docker compose ps
docker compose logs -f threatclaw-core    # Core logs
docker compose logs -f ollama             # AI model logs
```

### AI models not downloading
Ollama needs internet access. Check: `docker compose logs ollama | grep error`

## Next steps

- [Configuration options](configuration.md) — All settings
- [Available skills](skills.md) — Connectors, Intelligence, Actions
- [API documentation](api.md) — REST API endpoints
- [Skill Development Guide](SKILL_DEVELOPMENT_GUIDE.md) — Build custom skills

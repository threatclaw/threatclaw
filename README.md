<p align="center">
  <h1 align="center">ThreatClaw</h1>
  <p align="center"><strong>Autonomous cybersecurity agent for businesses of all sizes</strong></p>
  <p align="center">Self-hosted · AI-powered · OWASP ASI 2026 compliant · 100% on-premise</p>
</p>

---

## What is ThreatClaw?

ThreatClaw is a **self-hosted, AI-powered cybersecurity agent** that monitors, detects, correlates, and proposes remediations. Built on [IronClaw](https://github.com/nearai/ironclaw) with a **Zero Trust Agent** architecture.

All data stays on your infrastructure. No cloud dependency required.

## Quick Start

```bash
git clone https://github.com/threatclaw/threatclaw.git && cd threatclaw
docker compose -f docker/docker-compose.core.yml up -d
cargo build --release
./target/release/threatclaw run
```

Dashboard: `http://localhost:3001` · Requirements: Rust 1.90+, Docker, 8GB+ RAM

## Features

- **AI Agent** — ReAct loop with 3-level escalation (local → enriched → cloud anonymized)
- **4 Modes** — Investigator (default, read-only) → Responder (HITL) → Autonomous Low
- **10 WASM Skills** — Email audit, CrowdSec CTI, AbuseIPDB, HIBP, Compliance, Wazuh, VirusTotal, Shodan, Reports
- **5 Channels** — Slack, Telegram, Discord, WhatsApp, Signal
- **5 Security Pillars** — Soul hash, Command whitelist, XML wrapper, Memory HMAC, Kill switch
- **OWASP ASI 2026** — 9/9 applicable risks mitigated
- **Multi-target** — Per-server mode and permissions (SSH, WinRM, API)
- **Log pipeline** — Fluent Bit on port 514 (syslog) for Linux, Windows, firewalls, Docker
- **Compliance ready** — NIS2 and ISO 27001 mapping skills included

## Documentation

| Doc | Description |
|-----|-------------|
| [User Guide (FR)](docs/USER_GUIDE.md) | Guide utilisateur complet |
| [Architecture](docs/ARCHITECTURE.md) | System design |
| [V2 Architecture](docs/THREATCLAW_V2_ARCHITECTURE.md) | Multi-target, credentials |
| [Skills Reference](docs/SKILLS_REFERENCE.md) | All skills detailed |
| [Skill Development](docs/SKILL_DEVELOPMENT_GUIDE.md) | Build your own |
| [Security Policy](SECURITY.md) | Vulnerability reporting |

## License

[Apache License 2.0](LICENSE) · Built by [CyberConsulting.fr](https://cyberconsulting.fr)

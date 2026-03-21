<h1 align="center">ThreatClaw</h1>
<p align="center">
  <img src="docs/THREATCLAW-3.png" alt="ThreatClaw" width="300">
</p>
<p align="center"><strong>Autonomous cybersecurity agent</strong></p>
<p align="center">Self-hosted · AI-powered · WASM-sandboxed · 100% on-premise</p>

---

## What is ThreatClaw?

ThreatClaw is a **self-hosted, AI-powered cybersecurity agent** that monitors, detects, correlates, and proposes remediations for security threats. Built on [IronClaw](https://github.com/nearai/ironclaw) with a **Zero Trust Agent** architecture.

All data stays on your infrastructure. No cloud dependency required.

## Quick Start

**Linux / macOS:**
```bash
curl -fsSL https://get.threatclaw.io | sh
```

**Windows (PowerShell):**
```powershell
irm https://get.threatclaw.io/windows | iex
```

**From source:**
```bash
git clone https://github.com/threatclaw/threatclaw.git && cd threatclaw
docker compose -f docker/docker-compose.core.yml up -d
cargo build --release
./target/release/threatclaw run
```

See [Getting Started](docs/getting-started.md) for detailed instructions.

## Features

- **AI Agent** — ReAct reasoning loop with 3-level escalation (local → enriched → anonymized cloud)
- **4 Modes** — Investigator (read-only) → Responder (human approval) → Autonomous Low
- **10 WASM Skills** — Email audit, CrowdSec, AbuseIPDB, HIBP, Wazuh, VirusTotal, Shodan, compliance, reports
- **5 Channels** — Slack, Telegram, Discord, WhatsApp, Signal
- **Security** — Immutable soul, command whitelist, injection defense, HMAC memory, kill switch
- **Multi-target** — Per-server mode and permissions
- **Log pipeline** — Syslog on port 514 for Linux, Windows, firewalls, Docker

## Documentation

- [Getting Started](docs/getting-started.md) — Installation and first setup
- [Configuration](docs/configuration.md) — Environment variables, channels, modes
- [Skills](docs/skills.md) — Available skills and how to build your own
- [API Reference](docs/api.md) — REST API endpoints and Python SDK
- [Skill Development](docs/SKILL_DEVELOPMENT_GUIDE.md) — Build official (Rust/WASM) or community (Python/Docker) skills
- [Security Policy](SECURITY.md) — Vulnerability reporting
- [Contributing](CONTRIBUTING.md) — How to contribute

## Support ThreatClaw

ThreatClaw is and will remain open source. If this project is useful to you, you can support its development:

[![Sponsor](https://img.shields.io/badge/Sponsor-ThreatClaw-red?logo=github-sponsors)](https://github.com/sponsors/0xyli)

## License

[Apache License 2.0](LICENSE)

---

Built by [CyberConsulting.fr](https://cyberconsulting.fr)

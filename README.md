<h1 align="center">ThreatClaw</h1>
<p align="center">
  <img src="docs/THREATCLAW-3.png" alt="ThreatClaw" width="300">
</p>
<p align="center"><em>"They use AI to attack. We use AI to fight back."</em></p>
<p align="center"><strong>Autonomous cybersecurity agent for SMBs</strong></p>
<p align="center">Self-hosted · AI-powered · ML behavioral analysis · 100% on-premise</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.2.0--beta-red" alt="Version">
  <img src="https://img.shields.io/badge/license-AGPL_v3-blue" alt="License">
  <img src="https://img.shields.io/badge/status-BETA-orange" alt="Status">
  <img src="https://img.shields.io/badge/pricing-Free_&_Unlimited-brightgreen" alt="Free">
</p>

> **BETA** — ThreatClaw is in active development. Core features are functional and tested, but the product is not yet production-hardened.

---

## What is ThreatClaw?

ThreatClaw is a **self-hosted, AI-powered cybersecurity agent** that monitors, detects, correlates, and proposes remediations for security threats. It has been built for **autonomous SOC operations** targeting SMBs.

**All data stays on your infrastructure.** No cloud dependency required. No asset limits. Free and unlimited.

### 3 layers of detection

```
Layer 1 — Signature-based   → "I know this attack"
Layer 2 — Behavioral ML     → "This behavior is abnormal"
Layer 3 — AI Analysis       → "Here's what's happening and what to do"
```

## Quick Start

**One-line install (recommended):**
```bash
curl -fsSL https://get.threatclaw.io | sudo bash
```
This installs Docker (if needed), downloads all services, and starts ThreatClaw. Open `http://your-server:3001` to create your admin account.

**Docker Compose (manual):**
```bash
git clone https://github.com/threatclaw/threatclaw.git
cd threatclaw/docker
cp .env.example .env
docker compose up -d
```

**From source (developers):**
```bash
git clone https://github.com/threatclaw/threatclaw.git && cd threatclaw
cargo build --release
./target/release/threatclaw run
```

## Screenshots

<p align="center">
  <img src="docs/screenshots/dash.png" alt="Dashboard — Security score, ML detection, infrastructure status" width="800">
  <br><em>Dashboard — Real-time security score, ML behavioral detection, infrastructure health</em>
</p>

<p align="center">
  <img src="docs/screenshots/graph.png" alt="Graph Intelligence — Attack paths, threat actors, lateral movement" width="800">
  <br><em>Graph Intelligence — STIX 2.1 attack graph, threat actors (APT attribution), lateral movement detection</em>
</p>

<p align="center">
  <img src="docs/screenshots/export.png" alt="Reports & Exports — NIS2, RGPD, ISO 27001, STIX/MISP" width="800">
  <br><em>Reports & Exports — NIS2, RGPD/CNIL, ISO 27001, NIST, STIX 2.1, MISP (PDF + JSON)</em>
</p>

## Features

### Multi-level AI Architecture
ThreatClaw uses a multi-level AI system that keeps 95% of decisions local and private. Cloud escalation is optional, always anonymized.

### Core engine (Rust)
- **Intelligence Engine** — Automated threat correlation and scoring
- **Incidents** — Synthesized view with AI verdict, HITL buttons, remediation tracking
- **Graph Intelligence** — STIX 2.1 attack graph: attack paths, lateral movement, campaigns
- **Asset Management** — Auto-discovery, classification, fingerprinting
- **Dashboard Authentication** — Login, sessions, brute force protection
- **10 notification channels** — Telegram, Slack, Discord, Mattermost, Ntfy, Gotify, Email, Signal, WhatsApp, Olvid

### ClawSuite — Detection & Response
- **ClawMatch** — Real-time IoC matching across millions of indicators
- **ClawTrace** — Network threat detection (TLS fingerprints, C2 beacons, certificate anomalies)
- **ClawHunt** — Autonomous AI investigation on confirmed threats
- **ClawStrike** — Guarded remediation (block IP, disable account, create ticket) with HITL
- **ClawShield** — 5-layer protection preventing unauthorized remediation
- **ClawVault** — Encrypted credential storage for all integrations

### Behavioral Intelligence (ML)
- **Per-asset anomaly detection** — Baseline learning over 14 days
- **Peer Analysis** — Behavioral grouping, outlier detection ("the black sheep")
- **DNS Threat Analyzer** — Malicious domain detection (C2, DGA patterns)
- **Company Context** — Sector, business hours, geo scope adjust sensitivity

### Integrations (26 enrichments + 15 connectors)

**Enrichment (automatic, zero config):**
NVD, CISA KEV, EPSS, MITRE ATT&CK, CERT-FR, GreyNoise, CrowdSec, AbuseIPDB, Shodan, VirusTotal, HIBP, and 15 more.

**Connectors (plug your existing tools):**
Active Directory/LDAP, pfSense/OPNsense, Fortinet, Proxmox, GLPI, Wazuh, Nmap, Zeek, Suricata, Pi-hole, UniFi, and more.

### Dashboard (Next.js 14)
- Dark glass design, responsive, bilingual (FR/EN)
- Onboarding wizard
- Real-time security score, ML status, server health
- Skills marketplace (Connectors / Intelligence / Actions)
- Live system logs

### PDF Reports
- NIS2 (Early Warning 24h, Intermediate 72h, Final, Article 21)
- RGPD Article 33, ISO 27001, NIST SP 800-61r3
- Executive & Technical reports, Audit trail

## Pricing

**ThreatClaw is free and unlimited.** No asset limits. No feature gating.

Future premium skills will be available on the marketplace (hub.threatclaw.io).

## Architecture

```
Sources → Database → ML Engine → Intelligence Engine → Graph → AI → User
```

**Stack:** Rust (backend) · PostgreSQL (DB) · Python (ML) · Next.js 14 (dashboard) · Local LLM

## Documentation

- [Getting Started](docs/getting-started.md) — Installation and first steps
- [Configuration](docs/configuration.md) — All settings and options
- [API Reference](docs/api.md) — REST API endpoints
- [Skill Development](docs/SKILL_DEVELOPMENT_GUIDE.md) — Build custom skills
- [Security Policy](SECURITY.md) — Vulnerability reporting
- [Contributing](CONTRIBUTING.md) — How to contribute
- [Changelog](CHANGELOG.md) — Version history

## Community & Support

| Need | Where to go |
|------|-------------|
| 🐛 Bug report | [GitHub Issues](https://github.com/threatclaw/threatclaw/issues/new?template=bug_report.yml) |
| 💡 Feature request | [GitHub Issues](https://github.com/threatclaw/threatclaw/issues/new?template=feature_request.yml) |
| ❓ Question / Support | [GitHub Discussions](https://github.com/threatclaw/threatclaw/discussions) |
| 🔒 Security vulnerability | [Security Advisories](https://github.com/threatclaw/threatclaw/security/advisories) (private) |
| 📧 Commercial / Licensing | [contact@threatclaw.io](mailto:contact@threatclaw.io) |

## Support ThreatClaw

ThreatClaw is and will remain open source. If this project is useful to you:

[![Sponsor](https://img.shields.io/badge/Sponsor-ThreatClaw-red?logo=github-sponsors)](https://github.com/sponsors/0xyli)

## License

**AGPL v3 + Commercial dual-license.**

- Install on your own servers ✅
- Monitor your own infrastructure ✅
- Modify for your own use ✅
- MSSP deploying for clients ✅ (with commercial license)

> 99% of users are not affected by AGPL restrictions.

- Open source: [AGPL-3.0-or-later](LICENSE)
- Commercial: [Commercial License](LICENSE-COMMERCIAL.md) — contact commercial@threatclaw.io

---

Built by [CyberConsulting.fr](https://cyberconsulting.fr) — Cybersecurity consulting for SMBs

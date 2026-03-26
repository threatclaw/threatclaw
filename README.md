<h1 align="center">ThreatClaw</h1>
<p align="center">
  <img src="docs/THREATCLAW-3.png" alt="ThreatClaw" width="300">
</p>
<p align="center"><em>"They use AI to attack. We use AI to fight back."</em></p>
<p align="center"><strong>Autonomous cybersecurity agent for SMBs</strong></p>
<p align="center">Self-hosted · AI-powered · ML behavioral analysis · 100% on-premise</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0--beta-red" alt="Version">
  <img src="https://img.shields.io/badge/tests-3579_passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/license-AGPL_v3-blue" alt="License">
  <img src="https://img.shields.io/badge/status-BETA-orange" alt="Status">
</p>

> **BETA** — ThreatClaw is in active development. Features are functional and tested, but the product is not yet production-hardened. Use in test/lab environments.

---

## What is ThreatClaw?

ThreatClaw is a **self-hosted, AI-powered cybersecurity agent** that monitors, detects, correlates, and proposes remediations for security threats. Originally forked from [IronClaw](https://github.com/nearai/ironclaw), it has been extensively rebuilt for **autonomous SOC operations** targeting SMBs.

**All data stays on your infrastructure.** No cloud dependency required. NIS2-ready.

### 3 layers of detection

```
Layer 1 — Sigma Rules        → "I know this attack" (signatures)
Layer 2 — ML Isolation Forest → "This behavior is abnormal" (anomaly detection)
Layer 3 — LLM Analysis       → "Here's what's happening and what to do" (explanation)
```

## Quick Start

> The one-line installer (`get.threatclaw.io`) is available but not yet publicly tested. Use Docker Compose for now.

**Docker Compose (recommended):**
```bash
git clone https://github.com/threatclaw/threatclaw.git
cd threatclaw
docker compose -f docker/docker-compose.yml up -d
```

**From source:**
```bash
git clone https://github.com/threatclaw/threatclaw.git && cd threatclaw
cargo build --release
./target/release/threatclaw run
# Dashboard: cd dashboard && npm install && npm run build && npx next start -p 3001
```

Open `http://localhost:3001` — the onboarding wizard guides you through setup.

## Features

### Core engine (Rust)
- **AI Agent** — ReAct reasoning loop with 3-level escalation (local L1 → enriched L2 → anonymized cloud)
- **Intelligence Engine** — Runs every 5 min, collects alerts/findings, scores assets, decides notifications
- **Graph Intelligence** — Apache AGE (STIX 2.1): attack paths, lateral movement, campaigns, threat actors
- **Asset Management** — 10 categories, auto-discovery, IP classification (internal/external/unknown), fingerprinting
- **9 Test Scenarios** — APT multi-target, ransomware spread, WordPress compromise, SSH brute force, Log4Shell, C2, phishing, lateral movement, full intrusion

### ML Engine (Python)
- **Isolation Forest** — Per-asset behavioral baseline (14 days), anomaly score 0-1
- **DGA Detection** — Random Forest on DNS domain names, detects C2 algorithmically-generated domains
- **DBSCAN Clustering** — Groups assets by behavior, detects "black sheep" outliers
- **Company Context** — Sector, business hours, geo scope adjust ML sensitivity
- **Daemon mode** — Scores every 5 min, retrains nightly at 03:00

### Integrations (26 enrichments + 15 connectors)

**Enrichment (automatic, zero config):**
NVD, CISA KEV, EPSS, MITRE ATT&CK, CERT-FR, GreyNoise, IPinfo, OpenPhish, ThreatFox, MalwareBazaar, URLhaus, CrowdSec, OTX, Shodan, VirusTotal, HIBP, AbuseIPDB, Google Safe Browsing, SSL Labs, Mozilla Observatory, crt.sh, URLScan.io, WPScan, Wordfence Intelligence, PhishTank, Spamhaus DNSBL, SecurityTrails

**Connectors (client plugs their existing tools):**
Active Directory/LDAP, pfSense/OPNsense, Fortinet, Proxmox, GLPI, Wazuh SIEM, DefectDojo, Nmap, Cloudflare WAF, CrowdSec LAPI, UptimeRobot, Pi-hole, UniFi, Zeek, Suricata

**Webhook receiver** — Generic endpoint with 8 parsers (Cloudflare, CrowdSec, Fail2ban, UptimeRobot, Uptime Kuma, Wordfence, Graylog, ChangeDetection)

### Dashboard (Next.js 14)
- 9 pages: Status, Assets, Findings, Alerts, Intelligence, Agent, Skills, Test, Config
- Neumorphic design (NeuCard), dark/light theme
- Onboarding wizard with company profile
- Real-time security score, ML status, server health

### Security
- 5 security pillars: Immutable Soul, Command Whitelist, XML Injection Defense, HMAC Memory, Kill Switch
- WASM sandbox (BLAKE3-signed skills)
- 4 agent modes: Investigator (read-only) → Responder (HITL) → Autonomous Low → Autonomous High
- Human-in-the-loop on ALL write actions
- Gateway auth (constant-time token comparison)
- SQL injection protection (parameterized queries)
- Cypher injection protection (input validation)

### NACE/NAF Threat Profiles
9 sector-specific profiles (healthcare, finance, industry, retail, government, energy, transport, education, services) with:
- MITRE ATT&CK technique mapping (Enterprise + ICS)
- Compliance framework mapping (NIS2, HIPAA, PCI-DSS, IEC 62443, DORA, RGS)
- Sensitivity multipliers per sector

## Pricing

| | Community | Pro | Enterprise | MSSP |
|---|-----------|-----|------------|------|
| **Assets** | 150 free | 500 | Unlimited | Unlimited |
| **Price** | Free | 49 EUR/month | 299 EUR/month | 800 EUR/month |
| **ML Engine** | Included | Included | Included | Included |
| **Support** | Community | Email | Priority | Dedicated |
| **Updates** | Community | Auto | Auto | Auto + custom |

## Architecture

```
Sources → PostgreSQL → ML Engine (5min) → Intelligence Engine → Graph AGE → LLM → RSSI
                            ↑                       ↑
                    Isolation Forest          Asset correlation
                    DGA Detection            IP classification
                    DBSCAN Clustering        Fingerprinting
```

- **Backend**: Rust (tokio async, axum HTTP, deadpool-postgres)
- **Database**: PostgreSQL + Apache AGE (graph) + pgvector (future)
- **ML**: Python (scikit-learn, pandas) in Docker container
- **Dashboard**: Next.js 14 (React, TypeScript)
- **LLM**: Ollama (local) or Anthropic/Mistral/OpenAI (cloud, anonymized)

## Documentation

- [Architecture v2](docs/ARCHITECTURE_V2_INTELLIGENCE.md) — Full system design (ML, assets, pipeline)
- [Skills Integrations](docs/SKILLS_V2_INTEGRATIONS.md) — All 26 enrichment + 15 connector API specs
- [Skill Development](docs/SKILL_DEVELOPMENT_GUIDE.md) — Build official (Rust/WASM) or community (Python/Docker) skills
- [Security Policy](SECURITY.md) — Vulnerability reporting
- [Contributing](CONTRIBUTING.md) — How to contribute
- [Changelog](CHANGELOG.md) — Version history

## Support ThreatClaw

ThreatClaw is and will remain open source. If this project is useful to you:

[![Sponsor](https://img.shields.io/badge/Sponsor-ThreatClaw-red?logo=github-sponsors)](https://github.com/sponsors/0xyli)

## License

**AGPL v3 + Commercial dual-license.**

**You are NOT affected by AGPL if you:**
- Install ThreatClaw on your own servers ✅
- Use it to monitor your own infrastructure ✅
- Modify it for your own use ✅
- Are an MSSP deploying it for clients ✅ (with a commercial license)

**You ARE affected by AGPL if you:**
- Build a SaaS product on top of ThreatClaw without publishing your modifications
- Embed ThreatClaw in a commercial product you sell without a commercial license

> 99% of users are in the first category.

- Open source: [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-or-later)
- Commercial: [Commercial License](LICENSE-COMMERCIAL.md) — contact commercial@threatclaw.io
- Third-party: [NOTICE](NOTICE) — IronClaw (Apache 2.0), Apache AGE, MITRE ATT&CK

---

Built by [CyberConsulting.fr](https://cyberconsulting.fr) — RSSI as a Service for French SMBs

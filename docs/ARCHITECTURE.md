# ThreatClaw Architecture

> Technical architecture document for developers and contributors.

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Component Descriptions](#component-descriptions)
3. [Data Flow](#data-flow)
4. [Security Model](#security-model)
5. [API Reference](#api-reference)
6. [Development Setup](#development-setup)

---

## System Architecture

ThreatClaw is a three-layer autonomous cybersecurity agent built in Rust, forked from [IronClaw](https://github.com/nearai/ironclaw) (Near AI). It orchestrates open-source security tools via sandboxed WASM skills, a configurable LLM backend, and a Docker-based service stack.

### High-Level Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│    EXTERNAL INTERFACES                                                      │
│    ──────────────────                                                        │
│    Dashboard (Next.js :3000)    Slack/Email Notifications    LLM Cloud      │
│         │                              │                        │           │
│         │ HTTP                         │ Webhooks            │ HTTPS      │
│         │                              │                     │ (anonymized)│
├─────────┼──────────────────────────────┼─────────────────────┼─────────────┤
│         │              LAYER 1: CORE (Rust)                  │             │
│         │                                                     │             │
│         v                                                     v             │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐     │
│  │  REST API   │  │  Scheduler   │  │  LLM Router │  │  Anonymizer  │     │
│  │  :18789     │  │  (cron-based)│  │  local/cloud │  │  (reversible)│     │
│  └──────┬──────┘  └──────┬───────┘  └──────┬──────┘  └──────┬───────┘     │
│         │                │                  │                 │             │
│  ┌──────┴──────┐  ┌──────┴───────┐  ┌──────┴──────┐  ┌──────┴───────┐     │
│  │ Permission  │  │   Sigma      │  │  Skill      │  │  Notification│     │
│  │   Engine    │  │   Engine     │  │  Selector   │  │  Dispatcher  │     │
│  └─────────────┘  └──────────────┘  └─────────────┘  └──────────────┘     │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                    LAYER 2: SKILLS (WASM Sandboxed)                         │
│                                                                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │ vuln-scan   │ │  secrets    │ │  phishing   │ │  darkweb    │          │
│  │ Nuclei+Grype│ │  Gitleaks   │ │  GoPhish    │ │  HIBP API   │          │
│  │ EPSS+NVD    │ │             │ │  LLM tmpl   │ │             │          │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │ email-audit │ │ soc-monitor │ │ cloud-post  │ │ report-gen  │          │
│  │ checkdmarc  │ │ FluentBit   │ │  Prowler    │ │  LLM + PDF  │          │
│  │             │ │ Sigma+Falco │ │             │ │             │          │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘          │
│  ┌─────────────┐ ┌─────────────┐                                           │
│  │ compliance  │ │ compliance  │                                           │
│  │   NIS2      │ │  ISO 27001  │                                           │
│  └─────────────┘ └─────────────┘                                           │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                    LAYER 3: DOCKER SERVICES                                 │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │  threatclaw-internal (isolated bridge, no internet)              │       │
│  │                                                                  │       │
│  │  ┌──────────┐ ┌───────┐ ┌────────┐ ┌───────┐ ┌───────┐        │       │
│  │  │PostgreSQL│ │ Redis │ │ Nuclei │ │ Trivy │ │ Grype │        │       │
│  │  │+pgvector │ │7-alpin│ │        │ │       │ │       │        │       │
│  │  │  :5432   │ │ :6379 │ │        │ │ :4954 │ │       │        │       │
│  │  └──────────┘ └───────┘ └────────┘ └───────┘ └───────┘        │       │
│  │  ┌──────────┐ ┌────────┐ ┌────────┐ ┌──────────┐              │       │
│  │  │ Gitleaks │ │Prowler │ │ Falco  │ │FluentBit │              │       │
│  │  │          │ │        │ │ :8765  │ │:5140/24224│              │       │
│  │  └──────────┘ └────────┘ └────────┘ └──────────┘              │       │
│  └──────────────────────────────────────────────────────────────────┘       │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │  threatclaw-frontend (bridge, can reach external)               │       │
│  │                                                                  │       │
│  │  ┌──────────────┐  ┌───────────────┐  ┌───────────┐            │       │
│  │  │ThreatClaw    │  │  Dashboard    │  │  GoPhish  │            │       │
│  │  │Core :18789   │  │  :3000        │  │  :3333    │            │       │
│  │  └──────────────┘  └───────────────┘  └───────────┘            │       │
│  └──────────────────────────────────────────────────────────────────┘       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Network Architecture

```
                   Internet
                      │
                      │ HTTPS (optional, via reverse proxy)
                      │
              ┌───────┴───────┐
              │ NGINX Reverse │
              │   Proxy       │
              │ (optional)    │
              └───────┬───────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
    :3000 (dashboard) │       :3333 (gophish)
         │            │            │
┌────────┴────────────┴────────────┴────────────┐
│            threatclaw-frontend                 │
│                                                │
│  Dashboard ←─── Core (:18789) ───→ GoPhish    │
│                   │                             │
└───────────────────┼─────────────────────────────┘
                    │
┌───────────────────┼─────────────────────────────┐
│            threatclaw-internal                   │
│           (no internet access)                   │
│                                                  │
│  PostgreSQL  Redis  Nuclei  Trivy  Grype        │
│  Gitleaks  Prowler  Falco  Fluent Bit           │
│                                                  │
└──────────────────────────────────────────────────┘
```

---

## Component Descriptions

### Layer 1: Core (Rust)

The core is a Rust binary (MSRV 1.92, edition 2024) that orchestrates all cybersecurity operations.

| Component | Source Path | Description |
|---|---|---|
| **REST API** | `src/app.rs` | HTTP server on port 18789. Serves the dashboard API, health checks, and metrics. |
| **Scheduler** | `src/orchestrator/` | Cron-based scheduler that triggers skills at configured intervals. Uses standard 5-field cron syntax. |
| **LLM Router** | `src/llm/` | Routes LLM requests to local (Ollama) or cloud (Mistral, Anthropic) backends. Supports smart routing based on task type and a declarative provider registry. |
| **Anonymizer** | `src/anonymizer/` | Intercepts data bound for cloud LLMs and replaces sensitive tokens (IPs, hostnames, credentials, etc.) with numbered placeholders. Returns a reverse mapping for de-anonymization. |
| **Permission Engine** | `src/safety/` | Enforces the 4-level permission model (READ_ONLY, ALERT_ONLY, REMEDIATE_WITH_APPROVAL, FULL_AUTO). Gates skill actions based on trust level. |
| **Sigma Engine** | `src/integrations/` | Applies Sigma detection rules to collected logs. Generates alerts for matching patterns. |
| **Skill Selector** | `src/skills/` | Matches user intents and scheduler events to the appropriate skill using keyword scoring, regex patterns, and exclude keywords. |
| **Notification Dispatcher** | `src/channels/` | Sends alerts via Slack webhooks and/or SMTP email. Supports HITL (Human-In-The-Loop) approval via Slack buttons. |
| **Safety Crate** | `crates/threatclaw_safety/` | Standalone crate for input validation, command injection detection, shell env scrubbing, and secret scanning. |

### Layer 2: Skills (WASM)

Each skill is a self-contained cybersecurity capability, defined by a `SKILL.md` manifest with activation keywords, patterns, permissions, and NIS2 article mappings.

| Skill | Directory | Tool(s) | NIS2 Articles |
|---|---|---|---|
| `skill-vuln-scan` | `skills/skill-vuln-scan/` | Nuclei, Grype, EPSS API, NVD API | Art.21 §2a, §2b |
| `skill-secrets` | `skills/skill-secrets/` | Gitleaks | Art.21 §2h, §2i |
| `skill-email-audit` | `skills/skill-email-audit/` | checkdmarc (DNS) | Art.21 §2e |
| `skill-darkweb` | `skills/skill-darkweb/` | HIBP API v3 | Art.21 §2b, §2i |
| `skill-phishing` | `skills/skill-phishing/` | GoPhish REST API, LLM | Art.21 §2g |
| `skill-soc-monitor` | `skills/skill-soc-monitor/` | Fluent Bit, Falco, Sigma | Art.21 §2b, §2c |
| `skill-cloud-posture` | `skills/skill-cloud-posture/` | Prowler | Art.21 §2a, §2e |
| `skill-report-gen` | `skills/skill-report-gen/` | LLM + PDF generation | Art.21 §1, Art.23 |
| `skill-compliance-nis2` | `skills/skill-compliance-nis2/` | Internal rules engine | Art.21 §2a-§2j |
| `skill-compliance-iso27001` | `skills/skill-compliance-iso27001/` | Internal rules engine | Art.21 §2a, §2e, §2f |

**Skill activation flow:**

```
User input / Scheduler event
        │
        v
┌───────────────┐    keyword match     ┌──────────────┐
│ Skill Selector│───────────────────>  │  Best skill  │
│  (scoring)    │    regex match        │  activated   │
│               │    exclude check      │              │
└───────────────┘                       └──────┬───────┘
                                               │
                                               v
                                        ┌──────────────┐
                                        │ WASM Sandbox │
                                        │  (isolated)  │
                                        │  Permissions │
                                        │  checked     │
                                        └──────────────┘
```

### Layer 3: Docker Services

12 containerized services, all configured with resource limits, health checks, and log rotation.

| Service | Image | Port(s) | Memory Limit | Role |
|---|---|---|---|---|
| `threatclaw-core` | `threatclaw/core:latest` | 18789 | 256M | Agent core |
| `threatclaw-db` | `pgvector/pgvector:pg16` | 5432 | 512M | Primary database |
| `threatclaw-dashboard` | `threatclaw/dashboard:latest` | 3000 | 256M | RSSI dashboard |
| `redis` | `redis:7-alpine` | 6379 | 192M | Cache & rate limiting |
| `nuclei` | `projectdiscovery/nuclei:latest` | - | 128M | CVE scanner |
| `trivy` | `aquasec/trivy:latest` | 4954 | 128M | Container scanner |
| `grype` | `anchore/grype:latest` | - | 128M | Image vuln scanner |
| `gitleaks` | `zricethezav/gitleaks:latest` | - | 64M | Secret detection |
| `gophish` | `gophish/gophish:latest` | 3333, 8083 | 64M | Phishing simulation |
| `prowler` | `prowlercloud/prowler:latest` | - | 128M | Cloud security audit |
| `falco` | `falcosecurity/falco-no-driver:latest` | 8765 | 128M | Runtime anomaly detection |
| `fluent-bit` | `fluent/fluent-bit:latest` | 5140/udp, 24224, 8888 | 64M | Log collector |

**Total baseline memory**: ~1.6 GB (all services idle)

---

## Data Flow

### Log Collection Pipeline

```
┌─────────────────┐
│  System Syslog  │──UDP:5140──┐
│  (/var/log/*)   │            │
└─────────────────┘            │
                               v
┌─────────────────┐     ┌───────────┐     ┌─────────────┐     ┌──────────┐
│  Docker Logs    │─TCP:│ Fluent Bit│────>│ PostgreSQL  │────>│  Sigma   │
│  (containers)   │24224│           │     │   (logs     │     │  Engine  │
└─────────────────┘     │  Filters: │     │    table)   │     │          │
                        │  - parse  │     └─────────────┘     └────┬─────┘
┌─────────────────┐     │  - enrich │                              │
│  Auth Logs      │─tail│  - grep   │                              v
│  (/var/log/     │─────│    (sec   │                        ┌──────────┐
│   auth.log)     │     │    events)│                        │  Alerts  │
└─────────────────┘     └───────────┘                        │  Queue   │
                              ^                              └────┬─────┘
┌─────────────────┐           │                                   │
│  Falco Alerts   │─HTTP:8888─┘                                   v
│  (runtime)      │                                         ┌──────────┐
└─────────────────┘                                         │  LLM     │
                                                            │  Triage  │
                                                            └────┬─────┘
                                                                 │
                                                 ┌───────────────┼──────────┐
                                                 v               v          v
                                           ┌──────────┐  ┌──────────┐ ┌────────┐
                                           │Dashboard │  │  Slack   │ │ Email  │
                                           │  (UI)    │  │  Webhook │ │  SMTP  │
                                           └──────────┘  └──────────┘ └────────┘
```

### Vulnerability Scan Pipeline

```
Scheduler trigger (cron: "0 2 * * *")
        │
        v
┌───────────────┐      ┌──────────┐
│ skill-vuln-   │─exec─│  Nuclei  │──scan──> targets
│ scan          │      └────┬─────┘
│               │           │ JSON results
│               │      ┌────v─────┐
│               │─exec─│  Grype   │──scan──> Docker images
│               │      └────┬─────┘
│               │           │ JSON results
│               │      ┌────v─────┐
│               │─HTTP─│ EPSS API │──enrich──> CVSS*EPSS priority
│               │      └────┬─────┘
│               │           │
│               │      ┌────v─────┐
│               │─HTTP─│ NVD API  │──enrich──> Full CVE details
│               │      └──────────┘
│               │
│  Prioritized  │
│  findings     │──────> PostgreSQL (findings table)
│               │──────> Dashboard (score update)
│               │──────> Slack/Email (critical alerts)
└───────────────┘
```

### LLM Request Flow (with Anonymization)

```
┌──────────────┐        ┌──────────────┐
│  Raw data    │        │  LLM Routing │
│  from skill  │───────>│  Decision    │
└──────────────┘        └──────┬───────┘
                               │
                    ┌──────────┼──────────┐
                    │          │          │
                    v          │          v
             local_only?       │     cloud_allowed?
                    │          │          │
                    v          │          v
             ┌──────────┐     │   ┌──────────────┐
             │  Ollama   │     │   │  Anonymizer  │
             │  (local)  │     │   │  strip IPs   │
             │  No anon  │     │   │  strip hosts │
             └──────────┘     │   │  strip creds │
                               │   │  strip emails│
                               │   └──────┬───────┘
                               │          │
                               │          v
                               │   ┌──────────────┐
                               │   │  Cloud LLM   │
                               │   │  (Mistral /  │
                               │   │   Anthropic) │
                               │   └──────┬───────┘
                               │          │
                               │          v
                               │   ┌──────────────┐
                               │   │ De-anonymize │
                               │   │  response    │
                               │   └──────────────┘
                               │          │
                               └──────────┘
                                     │
                                     v
                              ┌──────────────┐
                              │  Skill gets  │
                              │  LLM output  │
                              └──────────────┘
```

---

## Security Model

### Defense in Depth

```
┌─────────────────────────────────────────────┐
│  Layer 1: Network Isolation                 │
│  - Docker bridge networks (internal/front)  │
│  - No internet on internal network          │
│  - Localhost-bound ports only               │
├─────────────────────────────────────────────┤
│  Layer 2: WASM Sandboxing                   │
│  - Each skill runs in isolated WASM VM      │
│  - Declared permissions only                │
│  - No filesystem access (except declared)   │
├─────────────────────────────────────────────┤
│  Layer 3: Permission Engine                 │
│  - 4 trust levels gate all actions          │
│  - HITL approval for remediation            │
│  - Audit trail in PostgreSQL                │
├─────────────────────────────────────────────┤
│  Layer 4: Data Anonymization               │
│  - All cloud-bound data is anonymized      │
│  - Reversible placeholders                  │
│  - Configurable per data category           │
├─────────────────────────────────────────────┤
│  Layer 5: Input Validation                 │
│  - Command injection detection             │
│  - Shell env scrubbing                      │
│  - Secret scanning on inbound messages     │
│  - Path traversal prevention               │
└─────────────────────────────────────────────┘
```

### Permission Levels

| Level | Scan | Alert | Remediate (w/ approval) | Auto-remediate |
|---|---|---|---|---|
| `READ_ONLY` | Yes | No | No | No |
| `ALERT_ONLY` | Yes | Yes | No | No |
| `REMEDIATE_WITH_APPROVAL` | Yes | Yes | Yes | No |
| `FULL_AUTO` | Yes | Yes | Yes | Yes (reversible only) |

### Data Classification

| Classification | Description | Cloud LLM | Storage |
|---|---|---|---|
| `public` | Non-sensitive data | Allowed (raw) | PostgreSQL |
| `internal` | Findings, scan results | Allowed (anonymized) | PostgreSQL |
| `sensitive` | Secrets, credentials, raw logs | **Never sent to cloud** | PostgreSQL (encrypted) |

### Anonymizer Patterns

The anonymizer uses compiled regex patterns (via `LazyLock<Regex>`) for thread-safe, zero-cost initialization:

| Pattern | Category | Placeholder Format | Example |
|---|---|---|---|
| RFC-1918 IPv4 | IP | `[IP_1]`, `[IP_2]`... | `192.168.1.42` |
| IPv6 ULA (fd00::/8) | IPV6 | `[IPV6_1]`... | `fd12:3456::1` |
| Email addresses | EMAIL | `[EMAIL_1]`... | `user@corp.fr` |
| Internal hostnames | HOST | `[HOST_1]`... | `srv01.corp` |
| Credential key=value | CRED | `[CRED_1]`... | `password=secret` |
| SSH private keys | SSH_KEY | `[SSH_KEY_1]`... | `-----BEGIN RSA...` |
| AWS access keys | AWS_KEY | `[AWS_KEY_1]`... | `AKIA...` |
| GCP API keys | GCP_KEY | `[GCP_KEY_1]`... | `AIza...` |
| Azure conn strings | AZURE | `[AZURE_1]`... | `AccountKey=...` |
| French SIRET/SIREN | SIRET | `[SIRET_1]`... | Business IDs |
| MAC addresses | MAC | `[MAC_1]`... | `AA:BB:CC:DD:EE:FF` |
| French phone numbers | PHONE | `[PHONE_1]`... | `+33 6 12 34 56 78` |

---

## API Reference

### Base URL

```
http://localhost:18789
```

### Health & Status

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check. Returns `200 OK` if the core is running. |
| `GET` | `/metrics` | Prometheus-format metrics. |
| `GET` | `/api/status` | System status: services, uptime, version, permission level. |

### Scans

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scans/trigger` | Manually trigger a skill scan. |
| `GET` | `/api/scans` | List all scan executions. |
| `GET` | `/api/scans/:id` | Get scan details and results. |

**POST /api/scans/trigger** request body:
```json
{
  "skill": "skill-vuln-scan",
  "targets": ["192.168.1.0/24"],
  "options": {
    "scan_type": "quick",
    "severity_filter": "critical,high"
  }
}
```

### Findings

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/findings` | List all findings. Supports query params: `severity`, `skill`, `status`, `limit`, `offset`. |
| `GET` | `/api/findings/:id` | Get finding details. |
| `PATCH` | `/api/findings/:id` | Update finding status (`new`, `acknowledged`, `resolved`, `false_positive`). |

### Alerts

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/alerts` | List alerts. Supports query params: `severity`, `source`, `status`, `since`, `limit`. |
| `GET` | `/api/alerts/:id` | Get alert details. |
| `POST` | `/api/alerts/:id/approve` | Approve a remediation action (requires `REMEDIATE_WITH_APPROVAL`). |
| `POST` | `/api/alerts/:id/reject` | Reject a remediation action. |

### Compliance

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/compliance/nis2` | Get NIS2 compliance scores (overall + per article). |
| `GET` | `/api/compliance/iso27001` | Get ISO 27001 compliance scores (overall + per category). |
| `GET` | `/api/compliance/gaps` | Get compliance gaps (articles/controls below threshold). |

### Reports

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/reports/generate` | Generate a new report. |
| `GET` | `/api/reports` | List generated reports. |
| `GET` | `/api/reports/:id/download` | Download a report PDF. |

**POST /api/reports/generate** request body:
```json
{
  "report_type": "compliance",
  "framework": "nis2",
  "period": "2026-03",
  "include_recommendations": true
}
```

### Configuration

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/config` | Get current configuration (secrets redacted). |
| `GET` | `/api/config/scheduler` | Get scheduler configuration and next run times. |

### Chat Completions (OpenAI-compatible)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/chat/completions` | OpenAI-compatible chat completions API. Supports model override. |
| `GET` | `/v1/models` | List available LLM models. |

---

## Development Setup

### Prerequisites

- **Rust** 1.92+ (edition 2024)
- **Docker Engine** + Compose v2
- **Node.js** 18+ (for dashboard development)
- **PostgreSQL 16** with pgvector extension (or use Docker)

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/threatclaw/threatclaw.git
cd threatclaw

# Start development database
docker compose up -d

# Build the core
cargo build

# Run tests
cargo test

# Run with release optimizations
cargo build --release
```

### Project Structure

```
threatclaw/
├── Cargo.toml                 # Workspace root
├── Cargo.lock
├── src/                       # Core Rust source
│   ├── main.rs                # Entry point
│   ├── app.rs                 # HTTP server (REST API)
│   ├── lib.rs                 # Library root
│   ├── agent/                 # Agent loop and orchestration
│   ├── anonymizer/            # LLM data anonymization
│   │   ├── mod.rs
│   │   ├── patterns.rs        # Regex patterns for PII
│   │   └── transformer.rs     # Anonymize/de-anonymize logic
│   ├── channels/              # Notification channels (Slack, email)
│   ├── cli/                   # CLI interface
│   ├── config/                # Configuration loading (TOML)
│   ├── db/                    # Database layer (PostgreSQL, libSQL)
│   ├── extensions/            # WASM extension management
│   ├── hooks/                 # Lifecycle hooks
│   ├── llm/                   # LLM provider abstraction
│   ├── observability/         # Metrics, tracing
│   ├── orchestrator/          # Scheduler and job dispatch
│   ├── safety/                # Input validation, permission engine
│   ├── sandbox/               # Docker sandbox for shell commands
│   ├── secrets/               # Secret management
│   ├── skills/                # Skill selector and registry
│   ├── tools/                 # Built-in tools
│   ├── webhooks/              # Webhook handlers
│   └── workspace/             # Workspace and document management
├── crates/
│   └── threatclaw_safety/     # Standalone safety crate
├── skills/                    # Skill definitions (SKILL.md + src/ + tests/)
│   ├── skill-vuln-scan/
│   ├── skill-secrets/
│   ├── skill-email-audit/
│   ├── skill-darkweb/
│   ├── skill-phishing/
│   ├── skill-soc-monitor/
│   ├── skill-cloud-posture/
│   ├── skill-report-gen/
│   ├── skill-compliance-nis2/
│   └── skill-compliance-iso27001/
├── dashboard/                 # Next.js RSSI dashboard
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx       # Main page (security score)
│   │   │   ├── alerts/        # SOC alerts page
│   │   │   ├── compliance/    # NIS2/ISO compliance page
│   │   │   └── reports/       # Reports page
│   │   ├── components/        # Shared UI components
│   │   └── lib/               # Utilities and API client
│   ├── package.json
│   ├── next.config.js
│   └── tailwind.config.ts
├── docker/                    # Docker configuration
│   ├── docker-compose.yml     # Production stack (12 services)
│   ├── docker-compose.dev.yml # Development stack
│   ├── fluent-bit/            # Fluent Bit configuration
│   │   ├── fluent-bit.conf
│   │   └── parsers.conf
│   ├── nginx/                 # NGINX reverse proxy
│   └── sandbox.Dockerfile     # Sandbox worker image
├── installer/                 # One-liner installer
├── migrations/                # PostgreSQL migrations
├── tests/                     # Integration tests
├── benches/                   # Benchmarks
├── fuzz/                      # Fuzz testing
├── wit/                       # WASM Interface Types
├── config/                    # Default configurations
├── threatclaw.toml            # Default client configuration
├── Dockerfile                 # Core image
├── Dockerfile.worker          # Sandbox worker image
├── Dockerfile.test            # Test image
└── docker-compose.yml         # Dev database (root level)
```

### Running Tests

```bash
# All unit tests
cargo test

# Tests with specific features
cargo test --features bedrock

# Integration tests only
cargo test --test '*'

# With coverage
cargo llvm-cov --html

# Dashboard tests
cd dashboard && npm test
```

### Development Workflow

```bash
# 1. Start dev database
docker compose up -d

# 2. Run migrations
cargo run -- migrate

# 3. Start the core in development mode
RUST_LOG=debug cargo run

# 4. In another terminal, start the dashboard
cd dashboard
npm install
npm run dev

# 5. Access:
#    - Dashboard: http://localhost:3000
#    - Core API:  http://localhost:18789
#    - Health:    http://localhost:18789/health
```

### Adding a New Skill

1. Create a new directory under `skills/`:
   ```bash
   mkdir -p skills/skill-my-new-skill/{src,tests}
   ```

2. Create `skills/skill-my-new-skill/SKILL.md` with the skill manifest (activation keywords, patterns, permissions, NIS2 mapping).

3. Implement the skill logic in `skills/skill-my-new-skill/src/`.

4. Add tests in `skills/skill-my-new-skill/tests/`.

5. Register the skill in the skill catalog (`src/skills/catalog.rs`).

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://threatclaw:threatclaw@localhost:5432/threatclaw` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `RUST_LOG` | Log level | `info` |
| `TC_PERMISSION_LEVEL` | Permission level override | `ALERT_ONLY` |
| `TC_INSTANCE_NAME` | Instance name override | `threatclaw-default` |
| `SLACK_WEBHOOK_URL` | Slack notification webhook | - |
| `ANTHROPIC_API_KEY` | Anthropic API key | - |
| `MISTRAL_API_KEY` | Mistral API key | - |
| `HIBP_API_KEY` | HaveIBeenPwned API key | - |
| `GOPHISH_API_KEY` | GoPhish API key | - |
| `LLM_REQUEST_TIMEOUT_SECS` | LLM request timeout | `120` |
| `THREATCLAW_BASE_DIR` | Base directory override | `~/.threatclaw` |

---

*ThreatClaw v0.1.0 -- Apache 2.0 License -- Fork of IronClaw (Near AI)*

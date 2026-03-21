# Changelog

All notable changes to ThreatClaw are documented here.

## [0.2.1-beta] — 2026-03-21

### Security
- Patch 10 CVEs — 0 known CVE in default binary
- Upgrade `wasmtime` 28 → 36.0.6 (4 CVEs fixed)
- Upgrade `aws-lc-sys` 0.38.0 → 0.39.0 (2 CVEs fixed, including HIGH 7.4)
- Upgrade `rustls-webpki` 0.103.9 → 0.103.10 (1 CVE fixed)
- Replace `serde_yml` with `serde_yaml_ng` (unsound crate eliminated)
- Remove unused `testcontainers-modules` (eliminates `tokio-tar` CVE)
- Remove `libsql` from default features (CVE no longer in binary)

### Added
- **Cloud anonymization** — data is anonymized before sending to any cloud LLM provider (user-controlled flag)
- **CLI wizard: Cloud Fallback step** — separate Primary AI and IA de secours configuration
- **Multi-platform installers** — Linux, macOS (launchd), Windows (PowerShell + PATH)
- **Dashboard anonymization toggle** — "Do your data leave your infrastructure?" on setup

### Changed
- Wizard step count: 9 → 10 (added cloud fallback step)
- `LlmRouterConfig` now has `anonymize_primary` flag instead of backend-guessing

## [0.2.0-beta] — 2026-03-20

### Added
- **Zero Trust Agent Architecture** — 5 immutable security pillars (OWASP ASI 2026)
- **ReAct reasoning loop** with 3-level AI escalation (local → enriched → cloud anonymized)
- **10 official WASM skills** — email audit, CrowdSec CTI, AbuseIPDB, HIBP, NIS2, ISO 27001, reports, Wazuh, VirusTotal, Shodan
- **4 communication channels** — Slack, Telegram, Discord, WhatsApp (WASM sandboxed)
- **Dashboard** — Chrome embossed design, 6 pages, real-time data
- **Scanner abstraction** — 3 modes (Docker / local binary / remote API) for Nuclei and Trivy
- **Multi-target infrastructure** — per-server mode and permissions
- **Credential vault** — AES-256-GCM + HKDF + Argon2id master password
- **HITL** — Human-in-the-Loop via Slack with nonce anti-replay
- **Heartbeat** — proactive monitoring every 30 minutes
- **Fluent Bit** — syslog port 514 (Linux, Windows, firewalls)
- **Data retention** — configurable per table, NIS2-compliant audit log
- **OpenAI-compatible API** — /v1/chat/completions endpoint
- **MCP security hardening** — input validation, recursion limits
- **CI/CD** — upstream monitoring, cargo audit, Dependabot
- **597 Rust tests**, 5 Playwright e2e tests, 19 SQL migrations

### Security
- Soul hash SHA-256 compiled into binary (tampering detection)
- Command whitelist with anti-injection (12 commands, forbidden targets)
- XML wrapper on all tool outputs (25+ cyber injection patterns)
- Memory HMAC integrity verification
- Kill switch with 8 automatic triggers
- DM pairing for channel security

## [0.1.0] — 2026-03-18

### Added
- Initial fork from IronClaw v0.19.0
- Rebranding (binary, configs, docs)
- 10 Python skill prototypes with tests
- Docker composition (13 services)
- Installer script

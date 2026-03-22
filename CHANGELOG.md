# Changelog

All notable changes to ThreatClaw are documented here.

## [0.3.0-beta] — 2026-03-22

### Added — Config Bridge (Axe 1)
- **LLM config from DB** — `LlmRouterConfig::from_db_settings()` reads `tc_config_llm` and `tc_config_cloud` from settings table at each ReAct cycle; env vars still override
- **NVD API key from DB** — `NvdConfig::from_db()` reads from `tc_config_general.nvdApiKey`; enables 50 req/30s rate limit
- **Channel token bridge** — `config_set_handler` writes channel tokens as process env vars for immediate credential injection
- **Telegram direct API** — `POST /api/tc/telegram/send`, `POST /api/tc/telegram/poll`, `GET /api/tc/telegram/status` endpoints reading token from DB config
- **NVD API key field** in dashboard General config (was non-functional placeholder before)

### Added — Dashboard Redesign (Axe 2)
- **Dark glass theme** — new design system: `#0a0a0f` base, glass cards with `backdrop-blur`, `#d03020` red accent, gradient overlay
- **Tab-based config** — 5 dedicated tabs (Général, IA/LLM, Canaux, Sécurité, Anonymisation) replacing accordion layout
- **Connectivity indicator** — nav bar shows Full/Degraded/Offline status with 30s auto-refresh
- **LLM model status** — shows loaded models with L1/L2 badges and sizes in the IA/LLM tab
- **Telegram integration panel** — bot status indicator, test message sending, Chat ID field in Channels tab
- **Scrollable anonymizer** — `maxHeight: 400px` scrollable list for 50+ rules
- **Sticky save bar** — bottom-fixed save button with glass backdrop
- **Updated glass components** — `ChromeInsetCard`, `ChromeButton` (primary/glass/danger variants), `ChromeEmbossedText` adapted for dark theme

### Changed
- `run_react_cycle()` now reloads LLM config from DB at each cycle start (dynamic config without restart)
- `cve_lookup_handler()` now reads NVD config from DB store
- Home page redesigned: 3-column service grid, dark theme, prominent CTA
- TopNav: red shield logo, glass indicator pills
- Max layout width: 900px → 1100px

### Fixed
- NVD API key input was bound to `general.language` instead of `general.nvdApiKey` (non-functional)
- Test assertions for `LlmRouterConfig::default()` and `ReactRunnerConfig::default()` now match actual defaults

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
- **Whitelist upgrade** — 12 → 22 commands: anti-exfiltration (outbound IP block, DNS sinkhole),
  forensics (SHA-256 hash, lsof, quarantine copy, network snapshot), services (systemctl stop/disable),
  files (quarantine move, chattr immutable), SSH key revocation
- **International anonymizer** — 17 pattern categories + custom RSSI rules via API
- **FAQ page** — 17 questions/réponses bilingues FR/EN pour RSSI

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
- Command whitelist with anti-injection (22 commands, forbidden targets)
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

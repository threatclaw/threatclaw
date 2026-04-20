# Changelog

All notable changes to ThreatClaw are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/)

Versioning: [Semantic Versioning](https://semver.org/) starting with `v1.0.0-beta`.
Earlier `v0.x` entries below reflect pre-public internal development and are kept for transparency.

## [1.0.8-dev] — Unreleased

> **Sprint scope** — v1.0.8 ships 5 features consolidating ThreatClaw into a
> production-grade SOC-in-a-box: auto blast-radius on sensitive incidents,
> a normalized typed graph, first-class suppression rules with TTL +
> audit trail, CISA-KEV time-to-alert telemetry, and an LLM-narrated
> monthly RSSI PDF report. Full rationale: `internal/feature-roadmap.md`
> and ADR-045…049.

### Planned — Graph storage normalisé (ADR-045)

- **Migration V42** — `graph_nodes`, `graph_edges`, `graph_edge_catalog`
  replace ad-hoc joins across AD / Azure / AWS / Cloudflare / Proxmox.
  Typed edge kinds, Dijkstra-ready weights, provenance per skill.
- **`src/graph/`** refactor split into `node.rs`, `edge.rs`, `storage.rs`,
  `query.rs`, `cache.rs`. `petgraph` in-memory cache refreshed via
  `LISTEN graph_update` DB triggers.

### Planned — Blast radius automatique (ADR-048)

- Auto-triggered on `phishing | credential_theft | malware_execution |
  privilege_escalation | lateral_movement | data_exfiltration`.
- Deterministic 0-100 score, cached JSONB snapshot, identity enrichment
  (AD groups, MFA, admin flags) via `skill-active-directory`.
- `BlastRadiusCard` React component at the top of `IncidentDetailPage`.

### Planned — Suppression rules v1 (ADR-047)

- **Migration V44** — `suppression_rules` with **mandatory 90-day TTL**,
  required justification (≥10 chars), full audit trail in
  `suppression_audit`.
- CEL-based predicates via `cel-interpreter` crate.
- Wizard UI from any incident card: click → pre-filled predicate →
  **14-day dry-run preview** → create. Pattern inspired by CrowdStrike
  Falcon "affected threats preview".

### Planned — KEV time-to-alert telemetry

- **Migration V45** — `cve_exposure_alerts` with `GENERATED` columns
  `tta_ingest_sec` and `tta_alert_sec`.
- Dashboard widget exposing P50/P95 time from CISA KEV publication to
  ThreatClaw alert on affected assets.

### Planned — Rapport mensuel RSSI

- **Migration V46** — `monthly_rssi_summary` materialized view refreshed
  hourly via `pg_cron`.
- Single-page A4 PDF via `skill-report-gen` (Typst). NIS2 Article 21 §2
  control coverage mapping. LLM-generated narrative (grounded per
  v1.0.7 citations layer).
- `GET /api/tc/reports/monthly/:yyyy-mm.pdf` + dashboard home widget.

### Planned — Infrastructure

- **ADR-045** — Graph storage normalisé
- **ADR-046** — Rules engine (Cedar authz + CEL predicates)
- **ADR-047** — Suppression rules TTL + audit
- **ADR-048** — Blast radius auto-trigger

---

## [1.0.7-beta] — 2026-04-20

### Added — Shadow AI detection (Zeek-based, passive, 0 MITM)

ThreatClaw detects unauthorized usage of commercial LLM APIs (ChatGPT,
Claude, Gemini, Mistral, Copilot, Perplexity, DeepSeek, Cursor, GitHub
Copilot, Codeium, Tabnine…) and of self-hosted LLM runtimes (Ollama,
vLLM, LM Studio, Jan.ai, GPT4All, Text Generation WebUI) from the
network traffic already observed by Zeek — **no TLS decryption, no
endpoint agent**.

- **Migration `V40__shadow_ai_detection.sql`** — new `llm_endpoint_feed`
  table (fqdn / port / url_pattern) with 70+ seeded entries across
  7 tiers (commercial mainstream, aggregators, hubs, gateways,
  hyperscalers, self-hosted ports & paths, coding assistants).
- **4 Sigma rules** `shadow-ai-001..004` over Zeek `ssl.log` /
  `dns.log` / `conn.log` / `http.log`.
- **`skill-shadow-ai-monitor`** — native Rust pipeline in
  `src/agent/shadow_ai.rs`. Parses matched fields, classifies
  provider + category, creates findings with `category=AI_USAGE_POLICY`
  and rich metadata (provider, endpoint, policy_decision,
  regulatory_flags), upserts the `ai_systems` inventory, marks the
  alert `investigating` to avoid double-qualification.
- **5-minute cron** — `spawn_qualify_cron(db, DEFAULT_QUALIFY_INTERVAL)`
  launched from `app.rs` right after DB init. Fire-and-forget
  `tokio::spawn` with `tokio::time::interval(300s)` + first tick
  skipped. `tracing::info!` on cycles with activity, `tracing::debug!`
  on empty cycles.

### Added — AI governance dashboard (new tab `/governance`)

New top-nav entry between `Intelligence` and `Reports`, with 4 live
cards consuming real API endpoints:

- **Shadow AI live** — open `AI_USAGE_POLICY` findings count + 8
  latest violations with severity + policy decision badges.
- **AI System Inventory** — by-status breakdown (detected / declared /
  assessed / retired / total) + per-system row with one-click
  "declare" button (PATCH `/ai-systems/{id}`).
- **Compliance posture** — radar for 4 frameworks (NIS2 / ISO 27001 /
  ISO 42001 / NIST AI RMF) with expand-collapse per article + score
  bar + critical/high/medium hits + top recommendation.
- **Evidence & audit** — critical/high findings counters + direct link
  to the immutable V16 audit trail (hash-chained via plpgsql trigger).

### Added — Compliance native Rust evaluators (`src/compliance/`)

Four frameworks evaluated live from findings/alerts/assets, no Python
runtime, no skills-dependent:

- **NIS2 Art.21 §2 (a→j)** — 10 mandatory security measures, keyword
  mapping extracted from the legacy Python skill.
- **ISO/IEC 27001:2022** — 4 Annex A themes (A.5 Organizational /
  A.6 People / A.7 Physical / A.8 Technological).
- **ISO/IEC 42001:2023** — 8 Annex A controls (A.2, A.4–A.10). AI
  policy, life cycle, data, transparency, usage, third-party.
- **NIST AI RMF 1.0 (2025 revision)** — 4 functions (Govern / Map /
  Measure / Manage). The 2025 update explicitly names *shadow AI* in
  the inventory control (MAP) — cited verbatim in the generated PDF.

Each article / control → score 0..=100 (`100 - 15*crit - 8*high -
3*med`, clamp [0, 100]). No evidence → score = 50 (neutral, flagged
for review). 11 unit tests covering empty input, targeted hits, shadow
AI → supply-chain / organizational mapping.

### Added — 4 AI governance report templates (Typst)

- **`templates/eu-ai-act-report.typ`** (5-6 p) — EU AI Act (UE 2024/1689)
  compliance: high-risk inventory + Art.12 logging + gaps + priority
  actions + reminder on 2026-08-02 deadline + up to 35 M€ / 7% penalty.
- **`templates/iso42001-assessment.typ`** (6-8 p) — ISO 42001 AI
  Management System: control-by-control score + hits breakdown +
  evidence index section pointing to the audit trail V16 + citations
  V39.
- **`templates/nist-ai-rmf-governance.typ`** (5-6 p) — NIST AI RMF 4
  functions with dedicated shadow-AI block citing the 2025 revision
  verbatim.
- **`templates/whitepaper-ai-governance.typ`** (12-15 p) — corporate
  whitepaper aggregating shadow AI + AI inventory + 4-framework
  compliance posture + 3-6-12 month remediation roadmap. Ready for
  procurement bids or ISO 42001 pre-certification.

### Added — API surface

New endpoints under `/api/tc/`:

- `GET  /governance/summary` — single-shot payload for the /governance
  page (compliance reports + ai_systems counts + shadow-ai findings
  count).
- `GET  /governance/ai-systems?status=&limit=` — inventory listing.
- `POST /governance/ai-systems` — upsert (CISO declares or adds).
- `PATCH /governance/ai-systems/{id}` — status promotion with
  risk_level + declared_by.
- `GET  /governance/shadow-ai-findings` — findings filtered to
  `category LIKE 'AI_%'`.
- `POST /governance/qualify-shadow-ai` — manual trigger (in addition
  to the 5-minute cron).
- `POST /exports/eu-ai-act` — PDF / JSON.
- `POST /exports/iso42001` — PDF / JSON.
- `POST /exports/nist-ai-rmf` — PDF / JSON.
- `POST /exports/whitepaper-ai-governance` — PDF / JSON.

### Added — Exports page refactor (dashboard)

- 4 usage-oriented sections instead of the previous 3 tier-based
  (Incident & Breach Response / Compliance & Audit / Threat Intel &
  CTI / Operations & Inventory).
- **`ExportModal`** — contextual parameters per export: date range
  picker with presets (today / 7d / 30d / 90d / this-month / last-
  month), incident selector (dropdown + auto-generate fallback),
  GDPR override (auto / force-yes / force-no), max records slider.
- **Visible legal badges** — `LEGAL 24h / 72h / 30d` (red) on NIS2 /
  GDPR, `MONTHLY` / `ANNUAL` / `REAL-TIME` on others, `INCIDENT REQ.`
  on the 3 NIS2 reports.
- The 4 new AI governance reports show up in the Compliance & Audit
  section, filtered by region (EU / US / intl).

### Added — Exports backend parameters

`export_report_handler` now accepts four optional body fields
(backward-compatible):

- `incident_id` — chains the early → intermediate → final NIS2
  reports on the same incident (replaces the synthetic
  `TC-INC-YYYYMMDD-001` that collided across same-day incidents).
- `date_range.{start,end}` — RFC3339 or `YYYY-MM-DD`, filters
  `alerts` and `findings` in-memory (period-bound reports).
- `gdpr_override: bool` — CISO forces `gdpr_required = yes/no` on
  Article 33 report when the auto-detection is wrong.
- `max_records: 100..=10000` — cap for raw-data exports.

### Added — Real immutable audit trail export

`export_report_handler` for `audit-trail` now returns actual entries
from `agent_audit_log` (V16, plpgsql-triggered append-only table)
instead of the previous `entries: []` stub. Respects `date_range`,
exposes `row_hash` + `previous_hash` for the hash-chain integrity,
emits `journal_hash = sha256:<latest-row-hash>`.

### Added — AI System Inventory table (V41)

New migration `V41__governance_ai_systems.sql`:

- `ai_systems` table — unified inventory (declared + shadow-detected
  AI) with lifecycle status (`detected` → `declared` → `assessed` →
  `retired`), risk level (`high` / `medium` / `low` per EU AI Act
  Annex III), assessment status, metadata JSONB. `UNIQUE(category,
  provider, endpoint)` + expression + GIN indexes.
- `findings.compliance_metadata` JSONB column — schema-documented
  in `internal/governance-roadmap.md §7.2` (regulatory_framework +
  regulatory_reference + evidence_ids + compliance_status + risk_level
  + remediation_action).
- `ai_systems_stats` view for the governance dashboard counters.

### Added — Documentation

- `internal/shadow-ai-detection-v1.md` — design spec for the shadow
  AI layer (gitignored, local-only per project convention).
- `internal/governance-roadmap.md` — export taxonomy, 4-axes model,
  scenarios, v1.2 / v1.3 / v2.0 plan (gitignored).

### Changed — Installer UX (carried over from mid-April work)

- `installer/get-threatclaw.{sh,ps1}` — detects existing installations
  and auto-restarts the systemd unit / LaunchAgent / Windows process
  on update. Preserves `.env`, `docker-compose.core.yml` and the
  systemd unit. Message differentiates between "Update complete" and
  "Installation complete".

### Changed — Skills manifests audit

- `docs(skills)` — UX + security refresh across the 25 skill manifests
  flagged as problematic by the April audit.

### Fixed — Docker build

- `fix(docker)` — `wasm-tools` pinned to `1.240.0` in the root
  Dockerfile too (and not only the builder sub-image) for Rust 1.94
  compatibility.

### Regulatory alignment

This release materializes ThreatClaw's posture for **EU AI Act Art.12
(logging)**, **NIS2 Art.21 §2(d-e) (supply chain + secure
development)**, **ISO/IEC 42001:2023 A.5.2 / A.6.2.2 / A.10**, and
**NIST AI RMF 2025** (which now explicitly covers shadow AI in the
inventory control). The 2026-08-02 EU AI Act high-risk obligations
are the rationale for shipping now — customers gain 3 months of lead
time before audit pressure.

## [1.0.6-beta] — 2026-04-19

### Added — Grounding layer (infrastructure, **off by default**)

A full anti-hallucination layer for the LLM verdict pipeline is now
shipped. Activation is opt-in via the `tc_config_llm_validation_mode`
DB setting (`off` | `lenient` | `strict`). Off by default so existing
installations are unaffected until an operator flips the switch.

**Five layers** stacked between the LLM output and the final verdict:

1. **Ollama structured outputs** (`format: <JSON Schema>`) — the
   FSM-constrained sampler guarantees enum / type / length compliance
   at inference time. Regex patterns deliberately NOT included in the
   schema (see `docs/MODEL_COMPATIBILITY.md`) because the llama.cpp
   grammar compiler segfaults on them; Phase 2 validators compensate.
2. **Typed Rust validators** — MITRE / CVE / IoC / hash format
   enforcement in `src/agent/validators/`. Invalid identifiers are
   collected in a `ValidationReport` consumed downstream.
3. **Verdict reconciler** (`src/agent/verdict_reconciler.rs`) — 5
   business rules (A/B/C/D/E, priority D>E>A>B>C) that downgrade or
   upgrade LLM verdicts based on deterministic signals (global_score,
   ML anomaly, Sigma alerts, CISA KEV).
4. **Evidence citations** — migration `V39__evidence_citations.sql`
   adds a JSONB column; LLM verdicts must cite concrete alert / finding
   IDs. Fabricated citations (IDs absent from the dossier) trigger
   rule E and downgrade `confirmed` to `inconclusive` in strict mode.
5. **Structured telemetry** — `src/telemetry/` emits OTel-compatible
   events (`threatclaw.llm_call`, `.reconciler`, `.citations`) for
   audit and observability. Ready for Langfuse / Phoenix / Loki
   ingestion without code change.

### Added — Public benchmark

`cargo test --test grounding_benchmark` runs 6 deterministic fixtures
covering every rule branch. Current v1.0.6 results: **rule match
accuracy 100%**, **reconciliation agreement 100%**. See
`docs/BENCHMARK_RESULTS.md` for reproduction.

### Added — Migrations

- `V38__llm_validation_mode.sql` — seeds the validation mode setting.
- `V39__evidence_citations.sql` — JSONB column + GIN index on
  `incidents` for citation persistence.

### Added — Documentation

- `docs/BENCHMARK_RESULTS.md` — benchmark methodology + current metrics.
- `docs/OBSERVABILITY.md` — structured tracing fields + ingestion recipes.
- `docs/MODEL_COMPATIBILITY.md` — Ollama structured-outputs compatibility
  notes for common GGUF models.

### Changed — Schema ingestion for all five LLM call sites

The L1 triage + the three L2 forensic call sites now pass a JSON
Schema to `format`. `call_ollama` is retained as a thin wrapper for
non-JSON callers (shift_report).

### Fixed

- `llm_json` fallback path guards against over-eager repair (bare
  strings, nulls): requires the repaired value to be an object with at
  least a `verdict` or `analysis` field.
- Parser deduplication: `strip_markdown_fences` + `parse_or_repair`
  live in `src/agent/llm_parsing.rs` and are shared between
  `investigation.rs` and the reconciler.

### Operator notes

- **Upgrade path**: no manual migration required — running the new
  binary applies V38 + V39 automatically via refinery.
- **Activating the grounding layer**: set
  `tc_config_llm_validation_mode` to `"lenient"` in the DB to observe
  without modifying verdicts, or `"strict"` to apply downgrades. The
  default `"off"` keeps pre-v1.0.6 behavior.
- **Observed model compatibility** (Ollama 0.20.4 + schema FSM):
  qwen3:14b, qwen2.5:7b-instruct, mistral-small:24b, and
  Foundation-Sec-8B-Reasoning all work after our schema simplification.
  See `docs/MODEL_COMPATIBILITY.md` for details.

## [1.0.5-beta] — 2026-04-17

### Security
- **Dashboard — 0 CVE** — Next.js 14.2.35 → 16.2.4 patches 5 high-severity advisories (GHSA-9g9p-9gw9-jx7f, GHSA-h25m-26qc-wcjf, GHSA-ggv3-7p47-pfv8, GHSA-3x4c-7xq6-9pq8, GHSA-q4gf-8mx6-v5v3). `npm audit` reports 0 vulnerabilities.
- **Rust default build — 0 active CVE** — `rustls-webpki` 0.103.10 → 0.103.12 (RUSTSEC-2026-0049/0098/0099), `rand` 0.8.5 → 0.8.6 (RUSTSEC-2026-0097). `cargo audit` exit 0.
- **libsql** 0.6.0 → 0.9.30 (optional `libsql`/`import` features)
- Documented transitive advisories in optional features (`bedrock`, `libsql`) via `.cargo/audit.toml` with rationale — none affect the default production binary

### Changed
- **React 18 → 19** — enables new Server Components features for future work
- **Node.js 20 → 22** on Docker images (Node 20 EOL April 2026)
- **Turbopack** now default for Next.js builds (~2-5× faster Docker builds)
- **Docker base images aligned and bumped** :
  - `rust:1.92-slim-bookworm` → `rust:1.94-bookworm` (cloud Dockerfile — aligns with docker/Dockerfile)
  - `ollama/ollama:0.20.2` → `0.21.0`
  - `fluent/fluent-bit:3.2` → `4.2`
  - `nginx:1.27.4-alpine` → `1.30.0-alpine`
- `src/middleware.ts` renamed to `src/proxy.ts` (Next.js 16 convention)

### Fixed
- **Syslog ingestion from LAN devices now works** — fluent-bit was attached only to the `threatclaw-internal` network (declared `internal: true`), which caused Docker to silently drop port publishing for 514/udp, 514/tcp and 5140/udp. External syslog sources (pfSense, FortiGate, Linux rsyslog, network switches) could not reach the collector. Added a dedicated `threatclaw-ingest` network (non-internal) so fluent-bit can accept log traffic from the host network while keeping DB access via `threatclaw-internal`.
- `lucide-react` 0.303 → 0.545 for React 19 peer dependency compatibility

---

## [1.0.4-beta] — 2026-04-17

### Added
- **Systemd service** — auto-start ThreatClaw on reboot (`systemctl enable/disable/status threatclaw`)
- **FHS-standard symlink** — `/etc/threatclaw` points to `/opt/threatclaw` for sysadmin discoverability
- **Log persistence directory** — `/var/log/threatclaw/` created with logrotate config (14 days retention, daily, compressed)

### Changed
- Installer success message now shows systemctl commands and log paths
- Uninstall cleans up systemd service, logrotate config, `/etc/threatclaw` symlink, and `/var/log/threatclaw/`

---

## [1.0.3-beta] — 2026-04-17

### Added
- **Demo isolation** — all simulation data tagged `demo=true` with unique session UUID, auto-cleanup after 1h
- **Cleanup API** — `POST /api/tc/test/cleanup` to purge demo data, `GET /api/tc/test/status` for demo data counts
- **Badge [DEMO]** — notifications on Telegram/Slack/Discord show `[DEMO - SIMULATION]` banner with disclaimer
- **Dashboard Simulation page** — renamed Tests to Simulation, added isolation banner, demo data counter, cleanup button, full i18n FR/EN

### Fixed
- Simulation scenarios no longer pollute production graph, ML baseline, findings, or compliance reports
- Demo findings prefixed with `[DEMO]` in title for visibility

---

## [1.0.2-beta] — 2026-04-16

### Added
- **ThreatClaw Agent Windows** — PowerShell installer (`install-agent.ps1`): installs osquery (MSI silent), configures 14 collection queries (software, connections, event log, PowerShell logging, patches, services, autoexec), creates Scheduled Task (5 min sync as SYSTEM)
- **One-liner Windows** — `$env:TC_URL='...'; $env:TC_TOKEN='...'; irm get.threatclaw.io/agent/windows | iex`
- **Dashboard: Agent tab in Config** — new tab with: editable server URL (auto-detected), token generation, Linux/Windows install tabs with pre-filled one-liners, registered agents table with last-sync status
- **API: GET /api/tc/webhook/token/{source}** — read existing webhook token without regenerating
- **API: GET /api/tc/endpoint-agents** — list registered osquery agents with server IP

### Changed
- Home page: replaced large agent install block with compact link to Config > Agent tab
- Agent descriptions clarified: the agent collects telemetry (read-only), it does not perform actions on endpoints

### Fixed
- Cloudflare Worker routes updated: `/agent/windows` serves `install-agent.ps1`

---

## [1.0.1-beta] — 2026-04-16

Post-launch quality release. No new features — security, stability, hygiene.

### Security
- **Dependabot sweep** — wasmtime 36.0.7, tar 0.4.45, rand 0.9.3, next 14.2.35, picomatch 4.0.4
- **Supply chain note** — documented upstream `nearai/threatclaw` WASM dependency in `registry/README.md` ahead of v2.0.0 re-host & re-sign plan

### Fixed
- **Test suite** — recovered 51 failing lib tests (env mutex poison cascade via `env_lock()` helper, sandbox tests, backend tests)
- **Installer** — bumped core readiness timeout from 120s to 180s to accommodate slower cold-start VMs
- **Dashboard i18n drift** — patched the most visible pages (Status, About, Login, Skills) so FR/EN parity matches shipped UI
- **Dashboard** — missing `locale` hook in `AssetFindings` component
- **CHANGELOG rename bug** — `scripts/sync-version.sh` was rewriting the top section header instead of inserting a new one

### Added
- **`docs/adr-index.md`** — 44 Architecture Decision Records indexed with one-line summaries
- **`scripts/sync-version.sh`** — single source of truth version propagation (Cargo.toml → README, docker-compose, installer, dashboard, issue templates)
- **`scripts/check-consistency.sh`** — repo-wide drift check (version strings, i18n parity, dashboard endpoints, migration fields, skill catalog, Dockerfile COPY coverage)

---

## [1.0.0-beta] — 2026-04-14

First public beta release of ThreatClaw — autonomous cybersecurity agent for SMBs.
Self-hosted, AI-powered, WASM-sandboxed skills.

### Highlights

- **5-level LLM architecture** — L0 conversational (Gemma 4 / Mistral Small / Qwen3), L1 triage, L2 forensic (Foundation-Sec Reasoning), L2.5 instruct, L3 cloud escalation with anonymization
- **Tool calling** — L0 bot with 6 DB tools (native Ollama tool calling, validated on Gemma 4 26B MoE)
- **Intelligence Engine** — Dynamic cycle (30s attack / 5min calm), verdict-based notifications, incident deduplication, kill chain correlation
- **Incident management V1** — Structured L2 forensic parsing (IOCs, MITRE, proposed actions), notes, reinvestigate, fallback actions, archive/soft-delete
- **NDR v2** — DNS tunneling, JA4/HASSH fingerprinting, SNI typosquatting, RITA-style beaconing (4-score), ransomware heuristics, PowerShell obfuscation rules, CTI feed unified (OpenPhish, ThreatFox, URLhaus, MalwareBazaar)
- **ML Engine** — Python Isolation Forest anomaly detection, DGA detection (dual backend RF + LSTM ONNX, 96% accuracy), DBSCAN clustering
- **Graph Intelligence** — Apache AGE, asset resolution pipeline (MAC > hostname > IP), STIX 2.1 export, kill chain reconstruction
- **Multi-channel HITL** — Telegram, Slack, Mattermost, Discord, Ntfy with text-rich Option A (no blind buttons), bidirectional conversational bot on all channels
- **Remediation engine** — Real HITL-approved actions (block IP pfSense/OPNsense, disable AD account, GLPI ticket), boot-locked protected infrastructure, CSPRNG nonce, rate limits, LDAP injection escaping
- **Backups** — Daily automatic backups with retention, manual trigger, download, external path for NAS
- **Anti-spam notifications** — 12 configurable parameters (cooldowns per severity, quiet hours, daily digest, escalation bypass), reduced notification noise by 80%
- **57 skills** — Connectors (pfSense, OPNsense, UniFi, MikroTik, Wazuh, Elastic SIEM, Graylog, Proxmox, Proxmox Backup, Veeam, Active Directory, Keycloak, Authentik, GLPI, TheHive, DFIR-IRIS, Shuffle, Freebox, Zeek, Suricata, Pi-hole, Osquery, Cloudflare, Fortinet, Olvid channel, ...), Enrichment (NVD, CISA KEV, EPSS, MITRE ATT&CK, CERT-FR, VirusTotal, Shodan, AbuseIPDB, CrowdSec, HIBP, Phishtank, URLhaus, Safe Browsing, ...), Tools (Nmap, Semgrep, Checkov, Trufflehog, Syft, Grype, ZAP, Strelka)
- **Dashboard** — Next.js 14, dark glass theme, i18n FR/EN, 10 pages (Status, Incidents, Findings, Alerts, Assets, Sources, Intelligence, Skills, Config, Exports)
- **Compliance reports** — NIS2, ISO 27001, NIST (Typst-based PDF generation)
- **Asset intelligence** — Auto-discovery, fingerprinting, software inventory via Osquery, auto-CVE correlation (CISA KEV × NVD)
- **Offline mode** — Full / Degraded / Offline / AirGap with bundle for air-gapped environments
- **Docker plug-and-play** — 13 services, one-liner installer, auto-pull models, auth token auto-generation, TLS certs auto-generated
- **ThreatClaw Agent** — Osquery-based endpoint agent (Linux/macOS), auto-CVE correlation, FIM, process events, systemd timer
- **Anonymizer** — 17 international categories, custom RSSI rules API, cloud LLM anonymization before escalation
- **Security hardening** — HTTPS everywhere (TLS 1.2/1.3), HSTS preload, CSP, Docker `cap_drop: ALL` + `no-new-privileges` + `read_only`, WASM sandbox BLAKE3 signed, 0 CVE in binary

### Note on version numbering

Prior `v0.x` entries in this changelog reflect the internal development history before
the first public release. They are retained for transparency but should be read as
pre-v1.0.0 preview iterations. `v1.0.0-beta` is the first release intended for public
consumption.

---

## [0.2.0.1-beta] — 2026-03-30

### Security
- **HTTPS reverse proxy** — Nginx devant le core et le dashboard, single entry point port 443
- **TLS hardened** — TLS 1.2/1.3 uniquement, AEAD ciphers, session tickets désactivés, ECDH secp384r1
- **Security headers** — HSTS preload, CSP, Permissions-Policy, X-Frame-Options, X-Content-Type-Options
- **Docker hardening** — `cap_drop: ALL` + `no-new-privileges` + `read_only` filesystem + `ipc: private` sur tous les containers
- **Network isolation** — Isolated Docker networks (defense-in-depth)
- **Image pinning** — Docker images pinned to specific versions (anti supply chain)
- **Ollama port fermé** — plus exposé sur l'hôte, accessible uniquement via réseau interne Docker
- **Session cookie** — `HttpOnly; Secure; SameSite=Strict`, meurt à la fermeture du navigateur
- **Inactivity timeout** — session expiry with sliding window
- **Reinforced tokens** — cryptographic strength upgraded
- **Rate limiting** — anti brute force on auth endpoints, per-endpoint throttling
- **Weak password rejection** — core refuses to start with default/weak credentials
- **WAF protections** — common attack patterns and sensitive path access blocked

### Added
- **Pipeline SOC Intelligence V3** — Automated investigation with verdict-based notifications
- **Investigation autonome** — AI-powered incident investigation with enrichment
- **Verdict-based notification** — Only confirmed incidents reach the RSSI (no alert spam)
- **Delta re-notification** — Re-notifies only when verdict changes
- **Error pages branded** — pages d'erreur dark theme ThreatClaw (400, 401, 403, 404, 429, 500, 502, 503, 504)
- **Page 404 dashboard** — full-screen avec Nedry GIF
- **Certificats TLS auto-générés** — CA + server cert avec SAN (hostname + localhost + IP), 10 ans
- **Installer proxy detection** — détecte si port 443 occupé, propose 3 modes (standalone/external-proxy/custom-port)
- **Installer `--hostname`** — nom d'hôte configurable pour le certificat TLS

### Changed
- Core et dashboard ne sont plus exposés directement (ports internes uniquement, nginx proxy)
- Fluent-bit ne monte plus `/var/log` de l'hôte (risque de fuite — les logs arrivent via syslog)
- Réseau Ollama dédié (seuls core et dashboard y accèdent)
- Healthchecks en `CMD` exec form (au lieu de `CMD-SHELL`, anti injection)

### Fixed
- Fluent-bit crash en `read_only` (ajout tmpfs pour SQLite DB)
- Dashboard healthcheck (`wget` au lieu de `curl`, `127.0.0.1` au lieu de `localhost`)
- Nginx `chown` bloqué par `cap_drop ALL` (ajout `CHOWN/SETUID/SETGID`)
- HTTP sur port HTTPS affichait page blanche nginx (page 400 branded)

## [0.2.0-beta] — 2026-03-29

### Added
- **L0 Conversationnel** — Chatbot Telegram/Dashboard avec tool calling (6 outils DB)
- **Skills Marketplace** — 49 skills (connectors, enrichment, actions) installables depuis le dashboard
- **Skills éphémères** — Nuclei, Trivy, ZAP, Subfinder, httpx en containers Docker on-demand
- **Wazuh OpenSearch** — Import alertes via indexer (fallback Wazuh 4.x)
- **Finding deduplication** — Clé unique (skill+title+asset), auto-close au re-scan
- **Exports PDF multilingues** — Templates Typst FR/EN/DE/ES
- **i18n Dashboard** — FR/EN complet, détection langue navigateur
- **One-liner installer** — Détection LVM, `--docker-data`, uninstall robuste
- **Dark glass theme** — design system `#0a0a0f`, glass cards, `#d03020` accent
- **Config tabs** — 5 onglets (Général, IA/LLM, Canaux, Sécurité, Anonymisation)
- **LLM config dynamique** — rechargée depuis DB à chaque cycle ReAct (pas de restart)
- **Telegram direct API** — send, poll, status endpoints
- **Cloud anonymization** — 17 catégories, avant envoi vers tout LLM cloud
- **Multi-platform installers** — Linux, macOS (launchd), Windows (PowerShell)
- **ML Engine** — Behavioral Intelligence, DNS Threat Analyzer, Peer Analysis
- **Graph Intelligence** — STIX 2.1, kill chain, lateral movement, campaigns
- **ReAct reasoning loop** — escalade 3 niveaux (local → enriched → cloud anonymized)
- **10 templates PDF** — NIS2 (24h, 72h, final), RGPD Art.33, NIST, ISO 27001, exécutif, technique, audit
- **26 enrichissements** — NVD, CISA KEV, EPSS, CERT-FR, MITRE ATT&CK, GreyNoise, CrowdSec, etc.
- **15 connecteurs** — Wazuh, Pi-hole, UniFi, Freebox, Cloudflare WAF, Proxmox, GLPI, etc.
- **ClawVault** — Encrypted credential vault
- **HITL** — Human-in-the-Loop via Telegram/Slack avec nonce anti-replay
- **3 568+ tests Rust**, 9 scénarios d'attaque end-to-end

### Security
- 0 CVE dans le binaire (cargo audit clean)
- Multi-layered agent security architecture (OWASP ASI 2026)

## [0.1.0] — 2026-03-18

### Added
- Fork initial depuis IronClaw v0.19.0
- Rebranding complet (binaire, configs, docs)
- 10 skills Python prototypes avec tests
- Docker composition (13 services)
- Installer script

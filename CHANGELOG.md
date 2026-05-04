# Changelog

All notable changes to ThreatClaw are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/)

Versioning: [Semantic Versioning](https://semver.org/) starting with `v1.0.0-beta`.
Earlier `v0.x` entries below cover pre-public internal development and are kept for transparency.

## [1.0.24-beta] — 2026-05-04

### Fixed
- ml-engine release publication: the image declares its source repository so the GitHub Container Registry can create the package the first time the workflow pushes (1.0.23-beta failed to publish for this reason).

### Documentation
- New "Endpoint Agents", "CVE & Attack Prediction" and "Inventory Gate" sections in the README.
- New `docs/inventory-gate.md` and `docs/attack-prediction.md` reference pages.
- Getting-started walks through agent install on Linux and Windows and how to declare a critical asset.
- API reference lists endpoint-agent webhook routes, bulk archive operations and both attack-prediction endpoints.

## [1.0.23-beta] — 2026-05-04

### Added
- Endpoint inventory: hardened agent installer for Debian 13 (apt-key removed in trixie) and for Windows hosts with multi-NIC layouts. The agent now filters virtual / Docker / WSL interfaces so a single host no longer surfaces as multiple assets.
- ml-engine ships a reproducible Docker image: training corpora and DGA models are rebuilt from public sources (Tranco + synthetic) at image build time, with a SHA256 provenance sidecar. No customer or telemetry data ever enters the image.
- Attack-prediction page now exposes two tabs: a static CVE-chain analyzer that works as soon as inventory + CVE + one critical asset exist, and the existing graph-walker for analyst drill-down.
- CVE auto-correlation list extended with Windows server stack, Microsoft desktop apps, virtualization platforms and common security/monitoring tools so Windows inventories trigger NVD lookups too.

### Changed
- Asset resolution merges discoveries that share a hostname even when their MACs differ (Docker bridges, virtual NICs). Prevents phantom assets on every osquery sync.
- IDS findings route to the destination internal asset, with a fallback to the source IP when both ends are external. The firewall hostname is no longer used as the asset for traffic it merely observed.
- Generic operator labels across the UI and back-office prompts where the audience may be a CISO, DSI, MSP analyst or internal IT lead.

### Fixed
- Network page IDS card no longer scrolls horizontally when an IDS snippet is wide.

## [1.0.22-beta] — 2026-05-04

Major signal-to-noise rework. The console now stays quiet on a healthy
infrastructure and only escalates events that touch monitored assets.

### Changed
- **Inventory gate**: incidents are escalated only when the asset matches a declared entry (`assets` table or `internal_networks` CIDR), with RFC1918 as a universal fallback. External IPs are kept as forensic findings but never spawn incidents.
- **ML clustering and anomaly detection** now build their behavioural baseline from monitored assets only. Cluster membership is no longer polluted by Internet scanners.
- IDS findings route to the destination asset when private; outbound flags from a private host still surface that host as the asset.

### Fixed
- L1 prompt no longer copies a hardcoded SSH brute-force example into unrelated incident titles.

### Note
- 1.0.21-beta is deprecated — its perimeter-mitigated bulk-archive query was inert. Skip directly to 1.0.22-beta.

## [1.0.21-beta] — 2026-05-04

### Changed
- Perimeter-mitigated rule now also recognises firewall events that arrive as findings (direct-API connectors), not only rows in the legacy firewall events table.

### Added
- `POST /api/tc/incidents/bulk-archive-perimeter-mitigated` with `?dry_run=true` preview. Backfills the rule across existing open incidents.
- Dashboard maintenance: two-step button to preview then archive perimeter-mitigated incidents from the console.

## [1.0.20-beta] — 2026-05-03

### Added
- Attack timeline on the incident report — alerts and findings shown in chronological order.
- `POST /api/tc/incidents/bulk-archive-stale` — archive open+pending incidents older than 24h.
- Perimeter-mitigated rule — drop dossiers whose evidence is fully blocked at the firewall.

### Changed
- Incident report page is the single triage destination — no more inline expansion.

### Fixed
- CI: install missing protobuf dev headers so the proto build stage succeeds in GitHub Actions.
- Align version strings across the Cargo manifest, README badge and installer script.

## [1.0.19-beta] — 2026-05-03

Investigation graphs now ship inside the release image and are downloaded automatically
by the installer, so a clean install via one-liner or release download is fully operational.

### Fixed
- **Investigation graphs missing from release image** — the 51 CACAO investigation graphs
  are now bundled in the `ghcr.io/threatclaw/core` image and used automatically when the
  host `graphs/sigma/` bind-mount is empty.
- **Investigation graphs not downloaded by installer** — `install.sh` now downloads the
  full graph library on first install and on `--update`, so the bind-mount is populated
  immediately without manual steps.

## [1.0.18-beta] — 2026-05-02

Fix clean-install reliability: investigation graphs and AI models now work out of the box
without cloning the repository.

### Fixed
- **CACAO graphs not loading on release installs** — investigation graphs bundled in the
  Docker image are now used automatically when the host `graphs/sigma/` directory is empty
  (bind-mount fallback via entrypoint). Previously, any install that did not include a full
  git clone had zero graphs and fell back entirely to ReAct.
- **AI models not created on fresh installs** — the triage and forensic analysis models
  are now created automatically on first boot. Fresh installs no longer produce errors on
  every investigation and loop on pending incidents.
- **Forensic section stuck in spinner** — `forensic_enriched_at` was missing from the
  `get_incident` SQL query; the dashboard incident page now renders the L2 forensic
  narrative correctly once enrichment completes.

### Added
- **Anti-hallucination gate** in forensic enricher — incidents with fewer than 2 alerts
  and no evidence citations skip the LLM call and store an explicit "insufficient data"
  message instead of risking fabricated MITRE techniques.
- **Forensic L2 section in incident report** — dedicated panel shows the async narrative,
  MITRE ATT&CK tags, and evidence citations; a spinner indicates enrichment in progress.
- **HITL actions panel** in incident report — proposed remediation actions with
  approve/reject controls, shown only when actionable commands are present.
- **Auto-load related incidents** — correlation panel loads automatically on page open.

### Changed
- **Graph-first mode is now the default** — the investigation engine delegates to
  deterministic graphs when a matching rule exists; unmatched dossiers still fall back
  to the reasoning engine. Can be overridden in `.env`.

## [1.0.17-beta] — 2026-05-02

Two-speed AI pipeline, 13 new investigation graphs, and investigation workspace.

### Added
- **Two-speed AI pipeline** — triage runs synchronously on a cyber-specialized model
  (`threatclaw-primary`); forensic enrichment runs asynchronously after confirmation,
  one incident at a time, without blocking the detection pipeline.
- **Async forensic enricher** — background scheduler produces a detailed RSSI-readable
  narrative with MITRE mapping and evidence citations. Idempotent: a crash mid-analysis
  is recovered cleanly on the next cycle.
- **13 CACAO investigation graphs** — deterministic verdict paths for lab rule IDs
  not previously covered; wired into the full pipeline alongside the LLM path.
- **Investigation workspace** — `/incidents/:id/investigate` page with an interactive
  agent workspace, IP enrichment, and L1 analysis runner.
- **Incident full-detail API** — `GET /incidents/:id/full`, `POST /investigate`,
  `GET /incidents/:id/related`, `POST /incidents/:id/report`.
- **Continuous monitoring** — post-graph L1 trigger with 15-minute re-evaluation window.

### Changed
- **Verdict summaries** — ML internals (anomaly scores, cluster IDs) removed from
  RSSI-facing text; summaries now read as plain-language security analysis.
- **Investigation page** — redesigned incidents table and investigation workspace.

### Fixed
- Reinvestigate endpoint now correctly parses the LLM JSON response instead of
  converting it to display text before parsing (systematic silent failure).
- Reconciler: alert ID column type mismatch corrected, preventing dropped alerts on high-volume rules.
- Reconciler: ML anomaly score, Sigma alerts, and lateral paths properly wired
  into the verdict context.
- Nginx header buffer size corrected, fixing intermittent navigation failures.

---

## [1.0.16-beta] — 2026-04-29

Asset accounting tightened. Operators can now merge duplicate rows
and retire an asset from billing and monitoring with a single toggle.

### Added
- **Manual merge** — select two or more rows in `/assets`, click *Fusionner*; aliases
  redirect to the canonical asset for 30 days (undoable).
- **Single exclusion toggle** — one switch removes an asset from both the billable count
  and the detection pipeline, with a typed reason and an automatic 90-day expiry.
- **Proxmox VM enrichment** — connector now fetches MAC and primary IP per VM, fixing
  duplicate inventory when the same machine is also seen by the firewall or DHCP.

### Changed
- **Billable count** — assets are billable when they show recurring presence (declared
  inventory or three distinct days of activity in the last 30), not because a finding
  fired. Quiet legitimate hosts no longer drop off the bill mid-month.

---

## [1.0.15-beta] — 2026-04-29

Phase G ships. ThreatClaw now decides on known attack patterns through deterministic
investigation playbooks, and falls back to AI reasoning only on the ambiguous branches.
Pricing pivots to an asset-tiered model with HITL included on every tier.

### Added
- **Investigation playbooks (CACAO v2 standard)** — deterministic decisions on common attack scenarios (SSH/RDP brute force, honeypot touches, file-integrity, AD events, EDR responses, firewall events, shadow AI), with a traceable, reproducible path under 100 ms.
- **Predictive Threat Map** — top attack paths populated, including lateral paths inferred from logon events.
- **LLM-assisted graph authoring** — the operator can draft a CACAO v2 playbook from a Sigma rule, with parse + compile validation before save.
- **Manual asset criticality** — operator can override an asset's criticality from the dashboard.
- **Phase G readiness gauge** — live ratio of incidents covered by a proposed HITL action.

### Changed
- **Pricing model** — HITL actions are free on every tier. The paid lever is the cap on monitored assets per tier, see [threatclaw.io/pricing](https://threatclaw.io/pricing). Functionality is identical across tiers.
- **L2 timeouts** downgrade verdicts to `Inconclusive` instead of poisoning incidents with `Error`.
- Threat-map empty state explains the actual cause instead of a generic message.

---

## [1.0.14-beta] — 2026-04-27

Pipeline refoundation: alerts, findings and incidents are wired the way a real SOC expects.
FortiGate becomes a first-class SIEM source. The L2 verdict is grounded against the asset
graph. The operator sees an "act now" zone with prominent HITL buttons on every incident.

### Added
- **FortiGate full ingestion** — full SOC posture in one cycle, no syslog forwarding required. Sigma starter pack ships for FortiGate auth and config events.
- **OPNsense full-API ingestion** — eight log scopes via REST. Sigma rules ship for OPNsense auth, IDS, and DNS-resolver events.
- **Sigma rule promotion** — corroborated signals become findings; lone medium/low alerts stay as alerts. Stops the noise.
- **Asset normalization in Sigma matches** — raw hostnames are resolved to the canonical asset before insert.
- **Human incident titles** — readable summaries based on the top finding instead of cryptic dossier identifiers.
- **Adaptive LLM prompt** — the prompt now lists only the skills actually configured and enabled, so the model doesn't hallucinate sources that aren't installed.
- **Impossible-travel detection** in the identity graph.
- **Firewall and FortiGate baseline drift findings** — catches rule wipes, rogue APs, deauth attacks.
- **`/network` page** — single pane of glass for connected firewalls, blocked sources, identity anomalies, IDS alerts, admin events.
- **Action-first incident detail UI** — large HITL buttons surfaced at the top.

### Changed
- HITL license enforced uniformly on every destructive route, including channel callbacks.
- New connectors: FortiGate webfilter URL block, OPNsense MAC quarantine.
- LLM timeout calibrated for CPU-only inference.

### Fixed
- Sigma rules with array `contains` modifier now fire correctly.
- OPNsense audit-log ingestion path corrected.
- Docker build dependencies fixed.

---

## [1.0.13-beta] — 2026-04-26

OPNsense promoted to a real SIEM source. Three new detectors cover network and endpoint.
Introduces the original HITL license model (subsequently superseded by the asset-tiered
pricing announced in v1.0.15).

### Added
- **HITL license model** — every destructive action gated behind a license check. License page rebuilt; HTTP 402 returned when missing.
- **Endpoint remediation trio (Velociraptor)** — quarantine endpoint, kill process, isolate host. Ships a custom Velociraptor artifact in-tree.
- **OPNsense as a SIEM source** — multiple REST endpoints consumed, rolling firewall events table.
- **Aggregate firewall detector** — port-scan and brute-force aggregation with severity escalation when source is internal.
- **Sigma firewall starter pack** — backdoor port hits, RDP/SMB inbound, UDP amplification, cryptomining proxy ports.
- **Dedicated `/scans` page** — four tabs, nine scan types, real scheduler.
- **Skill catalogue redesign** — single grouped feed per category, "Installed" badge, HITL panel with separate privileged credential fields.

### Fixed
- OPNsense firewall events were silently dropped at insert.

---

## [1.0.12-beta] — 2026-04-25

Velociraptor connector hardened end-to-end. Wazuh agent telemetry wired into the user
behaviour graph. Dashboard navigation unified across every page.

### Added
- **`/users` page** — list and detail of every observed identity, with asset cross-reference, login history, escalation edges, UBA anomalies, honeypot hits.
- **Wazuh → identity graph bridge** — Windows logon events emit identity edges so the user page surfaces real activity.

### Changed
- **skill-velociraptor** rewritten on native gRPC + mTLS (the previous REST path was a dead end).
- **Dashboard navigation unified** — single sidebar across all sectioned pages. Reports gain dedicated routes per category.
- **AD connector** — service-account detection (svc-/srv- prefix or trailing `$`) and French admin-group recognition.

### Fixed
- Asset sources accumulate properly across all resolution paths.
- Identity graph events stop overwriting authoritative `is_admin` and `is_service_account` flags.
- osquery webhook payload size raised so a domain-controller snapshot is no longer rejected.

---

## [1.0.11-beta] — 2026-04-24

Two new connectors for the two vectors that dominate SMB incidents: compromised endpoints
and compromised cloud-identity tenants.

### Added
- **skill-velociraptor** — hunt-result ingestion into the asset graph, plus four read-only tools exposed to the L2 forensic assistant. mTLS, cursor-based sync.
- **skill-microsoft-graph** — full M365 / Entra ID tenant ingestion via OAuth app-only. Pulls sign-ins, audits, users, devices, Conditional Access, Defender alerts, Identity Protection. Detects mail auto-forward rules, illicit OAuth consent, impossible travel, MFA fatigue, Global Admin assignment.
- **Feature probe matrix** on the M365 skill — reports which detections are available on the tenant's licence tier.
- **Identity graph bridging** for cloud sign-ins.

### Changed
- Connector sync gains cursor persistence on both new skills, so restarts never replay.

---

## [1.0.10-beta] — 2026-04-22

Wazuh connector hardened for real customer traffic.

### Added
- Wazuh noise filter — Docker veth and auditd promisc events silenced by default.
- Cursor-based pagination — no event loss when the source fires faster than a sync cycle.
- Attack-scenario harness with CI workflow.

### Fixed
- Log and Sigma alert ingestion no longer fails silently on edge-case payloads.
- Wazuh agent re-enrollment no longer creates duplicate assets.

### Changed
- Local LLM default capacity reduced to fit a typical SMB host without swap thrash.

---

## [1.0.9-beta] — 2026-04-22

Conversational chat lands in the dashboard, grounded LLM by default, and a
Linux/Wazuh Sigma starter pack so fresh installs catch things in the first hour.
Dashboard redesigned as a full SOC console.

### Added
- **Dashboard chat** — same conversational assistant as Slack/Telegram, with thread history and tool-call citations.
- **Grounding strict by default** — every LLM answer is cited against a database source or refused.
- **Sigma starter pack** — MITRE-tagged rules covering SSH brute force, privilege escalation, credential theft, audit tampering.
- **Home KPI strip** — open incidents, severity distribution, top-risk asset, alert volume.

### Changed
- Dashboard redesigned as a SOC operator console — dense, sober, red reserved for urgency.
- ML engine state shows "learning · N/14 d" during bootstrap instead of "offline".
- Per-section save buttons, restart wizard moved out of the global footer.

### Fixed
- Graph layer no longer mistakes hostnames for IP addresses.
- ML engine state read from health endpoint.
- Version badge drift blocked at CI.

### Infrastructure
- Staging pipeline: every push to `main` builds, deploys, and rolls back the database if anything fails.
- Release workflow time roughly halved.

---

## [1.0.8-beta] — 2026-04-21

Five features that consolidate ThreatClaw into a SOC-in-a-box of production-grade quality:
auto blast-radius on sensitive incidents, a normalized typed asset graph, suppression rules
with TTL and audit, time-to-alert telemetry on KEV exposure, and a monthly CISO PDF report.

### Added
- **Auto blast radius** — score 0-100, top assets impacted, manual recompute. Triggers on lateral-risk MITRE categories at high severity or above.
- **Normalized typed asset graph** — replaces ad-hoc joins. AD, Azure AD, AWS, Cloudflare, Proxmox, network and data edges, all weighted for shortest-path queries.
- **Suppression rules v1** — TTL-bounded, audit-trailed, hot-reload-safe. Wizard surfaces a 14-day dry-run before save and warns when confirmed incidents would have been suppressed.
- **CISA KEV time-to-alert telemetry** — measures the gap between a CVE being added to KEV and the first asset match locally.
- **Monthly CISO PDF report** — KPIs, MTTR, blast-radius distribution, top-three risks of the month.

### Community & Governance
- **CLA v1.1** — patent grant + retaliation, French moral-rights compatible, governing law clause.
- **CLA Assistant bot** active on every PR.
- **Code of Conduct** — Contributor Covenant 3.0 with sections specific to weaponised disclosure, credential leakage, offensive-security showcasing.
- **Security policy refresh** — supported versions, scope, safe-harbor clause, SLAs, PGP workflow.
- **Domain alignment** — product addresses migrated to `@threatclaw.io`.

---

## [1.0.7-beta] — 2026-04-20

Shadow AI detection, an AI governance dashboard, and four AI compliance report templates.
Detects unauthorized usage of commercial LLM APIs and self-hosted LLM runtimes from
network traffic — no TLS decryption, no endpoint agent.

### Added
- **Shadow AI detection** — passive detection of commercial LLM APIs and self-hosted LLM runtimes, by network fingerprint. Findings carry `category=AI_USAGE_POLICY` with provider, endpoint and policy decision metadata.
- **AI governance dashboard** (`/governance`) — Shadow AI live, AI System Inventory, four-framework compliance posture (NIS2 / ISO 27001 / ISO 42001 / NIST AI RMF), evidence and audit trail.
- **Native compliance evaluators** — NIS2 Article 21 §2(a-j), ISO 27001:2022 Annex A, ISO 42001:2023 Annex A, NIST AI RMF 1.0 (2025 revision).
- **Four AI governance report templates** — EU AI Act, ISO 42001 assessment, NIST AI RMF, AI governance whitepaper. Targets the 2026-08-02 EU AI Act high-risk obligations.
- **Real audit trail export** — append-only audit table, hash-chained, with verifiable journal hash.

### Changed
- Exports page redesigned around four usage-oriented sections with contextual parameters per export, visible legal badges, regional filtering.

---

## [1.0.6-beta] — 2026-04-19

A full anti-hallucination layer for the LLM verdict pipeline lands as opt-in
infrastructure. Off by default; existing installations are unaffected until an operator
flips the switch.

### Added
- **Grounding layer** — multi-stage validation between LLM output and final verdict, modes `off / lenient / strict`. Off by default.
- **Evidence citations** — verdicts must cite concrete alert and finding identifiers from the dossier.
- **Public benchmark** — deterministic regression run, reproducible from `cargo test`.

### Changed
- Schema-constrained ingestion adopted across all LLM call sites.

### Fixed
- LLM JSON repair path no longer over-eagerly accepts bare strings or nulls.
- Parser deduplication: shared between investigation and reconciler.

---

## [1.0.5-beta] — 2026-04-17

### Security
- Dashboard, zero CVE — Next.js bumped (5 high-severity advisories patched). `npm audit` clean.
- Rust default build, zero active CVE — `cargo audit` clean.
- Transitive advisories under optional features documented with rationale.

### Changed
- React 18 → 19 (enables newer Server Components features).
- Node.js 20 → 22 on Docker images (Node 20 EOL April 2026).
- Turbopack now default for dashboard builds.
- Docker base images bumped and aligned.

### Fixed
- LAN syslog ingestion — collector network reconfigured so external syslog sources can reach it while database access remains internal.

---

## [1.0.4-beta] — 2026-04-17

### Added
- **systemd service** — auto-start on reboot.
- **FHS-standard symlink** — `/etc/threatclaw` for sysadmin discoverability.
- **Log persistence** — `/var/log/threatclaw/` with logrotate (14-day retention, daily, compressed).

### Changed
- Installer success message now shows `systemctl` commands and log paths.
- Uninstall cleans up systemd unit, logrotate config, symlink, and log directory.

---

## [1.0.3-beta] — 2026-04-17

### Added
- **Demo isolation** — every simulation tagged, scoped to a unique session, auto-cleanup after one hour.
- **Cleanup API** — purge demo data on demand.
- **Visible `[DEMO]` banner** on simulation notifications across every channel.

### Fixed
- Simulation scenarios no longer pollute production graph, ML baseline, findings, or compliance reports.

---

## [1.0.2-beta] — 2026-04-16

### Added
- **ThreatClaw Agent — Windows** — PowerShell installer, telemetry collection (read-only), scheduled-task sync.
- **One-liner Windows install** via `irm | iex`.
- **Agent tab in dashboard Config** — token generation, Linux / Windows install snippets, registered-agents table with last-sync status.

### Changed
- Home page agent block replaced with a compact link to Config → Agent.
- Agent description clarifies it collects telemetry only — it does not act on endpoints.

---

## [1.0.1-beta] — 2026-04-16

Post-launch quality release. Security, stability, hygiene.

### Security
- **Dependabot sweep** across the binary and the dashboard.
- Upstream WASM-dependency provenance documented.

### Fixed
- Test suite — recovered failing lib tests on environment-mutex cascades.
- Installer — core readiness timeout adjusted for slower cold-start hosts.
- Dashboard internationalization parity restored on visible pages.

### Added
- Single source-of-truth version-propagation script.
- Repo-wide drift check (versions, internationalization, dashboard endpoints, migration fields, skill catalog, Dockerfile coverage).

---

## [1.0.0-beta] — 2026-04-14

First public beta of ThreatClaw — autonomous cybersecurity agent for SMBs.
Self-hosted, AI-powered, sandboxed skills.

### Highlights
- **Multi-level local LLM stack** — conversational, triage, forensic, instruct, with optional anonymized cloud escalation.
- **Conversational tool calling** — bot answers operator questions against the local database.
- **Intelligence Engine** — dynamic correlation cycle, verdict-based notifications, incident deduplication, kill-chain reconstruction.
- **Incident management** — structured forensic parsing (IOCs, MITRE, proposed actions), notes, re-investigate, fallback actions.
- **Network detection** — DNS tunneling, TLS-fingerprint analysis, beaconing detection, ransomware heuristics, threat-feed correlation.
- **ML engine** — anomaly detection, DGA detection, behavioral clustering.
- **Graph Intelligence** — typed asset graph with priority-ranked resolution, STIX 2.1 export, kill-chain reconstruction.
- **Multi-channel HITL** — Telegram, Slack, Discord, Signal, WhatsApp, Mattermost, Ntfy, web. Bidirectional conversational bot.
- **Remediation engine** — HITL-approved actions (firewall block, account disable, ticket creation), boot-locked protected infrastructure, anti-replay protection, rate limits.
- **Backups** — daily automatic backups with retention, manual trigger, external path.
- **Notification anti-spam** — configurable cooldowns, quiet hours, daily digest, escalation bypass.
- **Skill catalogue** — connectors, enrichments and tools across firewall / SIEM / EDR / DFIR / ticketing / scanning / cloud.
- **Dashboard** — bilingual (FR/EN) console with real-time KPIs.
- **Compliance reports** — NIS2, ISO 27001, NIST.
- **Asset intelligence** — auto-discovery, fingerprinting, software inventory, automatic CVE correlation.
- **Offline mode** — full / degraded / offline / air-gap, with bundle delivery for air-gapped sites.
- **Docker plug-and-play** — one-liner installer, auto model pull, auto-generated TLS certificates.
- **Anonymizer** — international PII categories with custom rules, applied before any cloud LLM escalation.
- **Hardening** — TLS 1.2/1.3 only, HSTS preload, CSP, container isolation, signed sandboxed skill runtime.

### Note on version numbering
Pre-`v1.0.0` entries reflect the internal development history before the first public
release. They are retained for transparency but should be read as preview iterations.

---

## [0.x-beta] — March 2026

Pre-public development releases. Two snapshots are kept for transparency:

- **0.2.0-beta** (2026-03-29) — conversational layer, skill marketplace foundation, ephemeral skill containers, Wazuh import, finding deduplication, multilingual exports, dark glass dashboard, native multi-platform installers, ML engine, graph intelligence, ReAct reasoning loop, encrypted credential vault, anti-replay HITL.
- **0.2.0.1-beta** (2026-03-30) — security hardening pass: nginx reverse proxy, TLS 1.2/1.3 only, HSTS / CSP / Permissions-Policy, container isolation, image pinning, session-cookie hardening, brute-force throttling, weak-password rejection at boot.
- **0.1.0** (2026-03-18) — initial fork and rebranding, first prototype skills, Docker composition, installer.

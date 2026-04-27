# Changelog

All notable changes to ThreatClaw are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/)

Versioning: [Semantic Versioning](https://semver.org/) starting with `v1.0.0-beta`.
Earlier `v0.x` entries below reflect pre-public internal development and are kept for transparency.

## [1.0.14-beta] — 2026-04-27

Pipeline refoundation: alerts, findings and incidents are now wired the
way a real SOC expects — corroboration before escalation, human-readable
incident titles, status='open' with a B3 fallback so an incident is never
silently buried in `error`. FortiGate becomes a first-class SIEM source
on par with OPNsense, the LLM grounds its verdicts against the asset
graph, and the RSSI sees an "act now" zone with prominent HITL buttons
when opening any incident.

### Added
- **FortiGate full SOC ingestion** — 25 endpoints consumed in one cycle:
  ARP / DHCP / interfaces / addresses / policies / system status, SSL VPN
  sessions (with identity-graph LOGGED_IN edges), IPsec tunnels, local
  users + firewall-auth users, FortiAP managed list + Wi-Fi clients,
  rogue APs (CRITICAL finding when present), FortiSwitch detected
  devices, HA cluster status, license expiry, four UTM log scopes
  (virus / IPS / webfilter / app-ctrl) with per-subtype cursors. Plug
  the firewall, no syslog forwarding required. V58 ships 5 Sigma rules
  on `fortinet.event.user/system` (auth failed, admin login, config
  change, policy disable, admin user added).
- **OPNsense full-API ingestion** — 8 log scopes via
  `POST /api/diagnostics/log/core/<scope>` (audit, system, filter,
  suricata, configd, dnsmasq, wireguard, resolver). No more syslog
  forwarding requirement. V59 ships 6 Sigma rules on `opnsense.*`
  (auth failed, admin login, sensitive admin action, IDS alert, kernel
  critical event, MAC migration). V60 adds 7 DNS rules on
  `opnsense.dnsmasq` + `opnsense.resolver` (unbound unwanted reply,
  DNSSEC failure, blacklist, restart, DHCP starvation, DNS rebind,
  rate-limit).
- **Sigma engine `*Any` matchers** — `field|contains: [a, b, c]` arrays
  used to be compiled to exact-match `AnyOf` (the modifier was silently
  dropped on arrays). Most V58 / V59 / V60 rules with array contains
  never fired. Fix: `ContainsAny / StartsWithAny / EndsWithAny` apply
  the modifier to each element. Validated on lab brute force: 0 matches
  before fix, opnsense-001 fires post-fix.
- **Sigma → finding auto-promotion** — sigma_engine creates a
  `sigma:<rule>` finding after each match when level is high/critical
  OR level=medium AND ≥1 other independent signal exists on the same
  asset within 1 h. Stops the noise: low / lone-medium alerts stay as
  alerts, only corroborated signals become findings.
- **Asset normalization in sigma matches** — raw hostname is resolved
  via `find_asset_by_ip / find_asset_by_hostname` before insert, so the
  Intelligence Engine doesn't split signals between `10.77.0.1`,
  `OPNsense.internal`, and `opnsense-firewall`.
- **Human incident titles at creation** — `humanize_incident_title`
  produces readable titles based on the top finding (brute force,
  admin login, sensitive admin action, IDS alert, port scan, rogue AP,
  DNS anomaly) instead of the cryptic
  `Dossier {uuid} — asset=... findings=N alerts=M score=K level=Alert`.
- **Status='open' on L2 failure** — `update_incident_verdict` no longer
  routes verdict='error' to status='error'. The incident keeps
  status='open' so the RSSI sees it in the regular queue, with the
  rules-based title intact. V61 reclassifies the 56 incidents
  historically stuck in `error`.
- **Adaptive LLM prompt** — the L1/L2 prompt now lists the skills the
  operator has actually configured + enabled so the model doesn't
  hallucinate "I checked Wazuh" when Wazuh isn't installed (the common
  PME single-skill deployment).
- **Pre-resolved graph context per dossier** — Cypher query for the
  primary asset (criticality, lateral_paths, linked_cves, recent
  users) is injected in the dossier and surfaced in the prompt's
  CONTEXTE GRAPH ASSET block.
- **Reconciler rule F: confirmed_but_isolated_graph** — downgrades a
  Confirmed verdict to Inconclusive (confidence × 0.7) when the graph
  shows zero lateral paths, zero linked CVEs, and zero sigma critical
  on the asset. Catches the LLM hallucinating a kill chain that the
  topology doesn't support.
- **Impossible-travel detection** in the identity graph — flags a user
  with two successful logins from different /16 subnets within 5 min.
  Network-distance proxy in lieu of an embedded GeoIP DB.
- **Baseline drift findings** — pf/OPNsense detect ±25 % delta on
  `firewall_rules` or `aliases_count` between cycles; FortiGate
  detects ±30 % on `managed_aps` / `wifi_clients`, ±25 % on
  `firewall_policies`. Catches defense-evasion (rule wipe), rogue AP
  appearance, deauth attacks. Stored under `_baseline` settings — no
  migration needed.
- **`/network` page** in the dashboard sidebar (Inventaire ▸ Réseau).
  Single pane of glass exposing data the connectors collect but
  nothing else surfaces: connected firewalls, top blocked sources
  (24 h), identity anomalies (incl. impossible-travel), recent IDS /
  IPS alerts, recent admin/audit events. Empty state with CTA to
  `/skills?cat=network` when no firewall is configured. Backed by
  `GET /api/tc/network/overview`.
- **Action-first incident detail UI** — clicking an incident now
  surfaces a prominent red "Que faire maintenant" hero block with
  large HITL buttons (Bloquer IP / Désactiver compte / Isoler
  endpoint), then context (blast radius, IOCs, MITRE), then triage
  buttons (false positive / re-investigate / ignore pattern) at the
  bottom. The proposed actions are the same path as before, just
  visually surfaced.
- **Sidebar tooltips on the incidents/findings/alerts triptych** —
  "Menaces confirmées et corroborées — tu dois agir." / "Observations
  à revoir — pas urgentes, revue hebdo." / "Signal brut — matière
  première du moteur." Disambiguates the three levels.

### Changed
- **License gate plumbed on every destructive route** — the direct API
  paths `/api/tc/remediation/block-ip`,
  `/api/tc/remediation/disable-account` previously bypassed the
  Action Pack check. They now call `check_tool_license` and return
  HTTP 402 + audit log when the license is missing. Two new gated
  endpoints: `/api/tc/remediation/block-url` (FortiGate webfilter) and
  `/api/tc/remediation/quarantine-mac` (OPNsense alias). Slack /
  Mattermost / Ntfy approval callbacks also gated.
- `fortinet::block_ip` rewritten to use FortiGate's native banned-IP
  endpoint (`/api/v2/monitor/user/banned/add_users`) — instant block,
  no policy plumbing required. Address object still created as a
  paper-trail entry.
- `fortinet::block_url` (new) — manages a `TC-URL-BLOCKLIST` urlfilter
  list (auto-create, idempotent append). Surfaces a hint when the
  list isn't yet attached to a webfilter profile.
- `opnsense_quarantine_mac` (new) — drives a `TC_QUARANTINE_MACS`
  firewall alias via `/api/firewall/alias/{getAliasUUID,addItem,
  setItem,reconfigure}`. Auto-create + idempotent append.
- `remediation_engine::load_firewall_config` now also reads
  `skill-fortinet` config so incident-driven `block_ip` dispatches to
  FortiGate, not just pf/OPNsense.
- skill-fortinet manifest gains a `hitl_actions` block declaring
  `fortinet_block_ip` + `fortinet_block_url` (was missing).
- Intelligence Engine escalation seuil revisited: 1 high finding plus
  any corroboration (active attack, active alert, or a medium on the
  same asset) → Alert. Two high findings without qualifier → Alert.
  Two medium with corroboration → Alert. Anything weaker stays as a
  finding visible in `/findings`.
- Sigma + finding dedup window 15 min → 1 h on `(rule_id, asset)`.
- Per-call LLM timeout calibrated for CPU-only Ollama: 600 s (was
  900 s nominal but never enforced; my first cut at 60-180 s was too
  tight for qwen3:8b on CPU + heavy prompt). Total ReAct loop 900 s.
- Findings cap in dossier 10 → 5 — keeps the prompt manageable for
  qwen3:8b, the 5 most-severe still cover triage.
- sigma_alerts retention 365 d → 30 d (V61). The previous 365 d
  accumulated 74 k rows nobody queried.

### Fixed
- Sigma engine never fired any rule with array `|contains` modifier
  (V58 / V59 / V60 dead until 92d7449). See "Added" section above for
  the *Any matcher fix.
- `docker/Dockerfile` was missing both `COPY proto/` (Velociraptor
  proto tree required by `tonic-build`) and `libprotobuf-dev` (ships
  the `google.protobuf.*` well-known types protoc resolves at compile
  time). Builds were silently failing on `google.protobuf.Empty is not
  defined` even though the host build worked.
- skill-opnsense audit log ingestion was calling
  `/api/diagnostics/log/audit?limit=200` (GET) which silently returns
  `[]`. The correct path is `POST /api/diagnostics/log/core/audit`
  with a bootstrap-table body — wired in the new full-API loop.

---

## [1.0.13-beta] — 2026-04-26

Full rework of the HITL commercial model and OPNsense promoted to a
real SIEM source. All destructive actions now sit behind a single
"Action Pack" license, and three new detectors (volumetric, single-shot
Sigma, Velociraptor EDR) cover both the network and the endpoint.

### Added
- **"Action Pack" doctrine** — one license (199 €/year) unlocks every
  HITL destructive action across every skill. `/licensing` page
  rebuilt; license gate enforced on every execution path
  (`/api/tc/incidents/{id}/execute-action` dashboard handler,
  Slack/Telegram bridges); HTTP 402 returned when missing.
- **Velociraptor HITL trio** — `quarantine_endpoint`, `kill_process`,
  `isolate_host`. Separate mTLS channel for an administrator-role
  api_client. Custom artifact `ThreatClaw.Remediation.ProcessKill`
  shipped in-tree (Velociraptor 0.76 has no upstream ProcessKill).
- **OPNsense as a SIEM source** — 12 REST endpoints consumed
  (firewall log, PF states, OpenVPN/WireGuard/IPsec sessions, audit,
  gateway, aliases, system info), 24 h rolling `firewall_events`
  table, pfSense / OPNsense manifests split.
- **Aggregate firewall detector** — port scan (25+ ports or 10+ hosts
  in 5 min from one external IP) and SSH/RDP/SMB brute force (30+
  blocks). CRITICAL when the source is internal (lateral movement).
- **5 Sigma firewall rules** (V56) — backdoor port hits (4444, 31337,
  6667, 23, 1337), RDP/SMB inbound, UDP amplification, cryptomining
  proxy ports. Match against `firewall_events` mirrored into `logs`.
- **Dedicated `/scans` page** — 4 tabs (Launch / History / Scheduled
  / Library), 9 scan types (nmap, trivy, syft, lynis, docker_bench,
  semgrep, checkov, trufflehog, zap), real V52 scheduler.
- **WordPress-style skill catalogue** — single grouped feed per
  category, "Installed" badge instead of appearance/disappearance,
  HITL panel with separate privileged credential fields.

### Changed
- `tool_calling.rs` refactor: replaced `tool_required_skill`
  (per-skill) with `tool_requires_hitl` (boolean).
  `LicenseManager.allows_hitl()` recognizes both the modern `hitl`
  marker and legacy `skill-*-actions` tokens for the transition.
- `extract_compromised_user` wired onto `AlertRecord.username`
  (decoded Wazuh Windows logon events) — unblocks
  `disable_account` and `reset_password`.

### Fixed
- `insert_firewall_events` (PG) was using the default trait impl
  (`Ok(0)`) — events ingested from OPNsense were silently dropped.
- Stripe live mode: webhook secret pushed to the Cloudflare Worker,
  marketing site now points at the production Payment Link.

---

## [1.0.12-beta] — 2026-04-25

Iteration focused on three things: making the Velociraptor connector
actually work end-to-end, wiring Wazuh agent telemetry into the user
behaviour graph, and giving the dashboard one consistent navigation
shell across every page.

### Added
- **Users page** (`/users`) — list and detail view of every identity
  the agent has observed, with asset × user cross-reference, login
  history per asset, escalation edges, and UBA anomalies. Surfaces
  honeypot account hits as critical incidents.
- **Wazuh → identity graph bridge** — Windows logon events
  (4624/4625/4634/4648/4768/4769/4771/4776) decoded from the
  eventchannel payload and emitted as `LOGGED_IN` edges so the user
  page actually fills with real activity instead of just AD profiles.
- **Premium-skill licensing foundation** — Ed25519 offline cert
  verification, 90-day grace, optional site-fingerprint pinning,
  three-tier `SkillTier` (Free / Premium / BetaPremium) defaulting
  to Free. Inert until a public key is provisioned; ships only the
  plumbing for the future `hub.threatclaw.io` marketplace.

### Changed
- **skill-velociraptor rewritten on tonic gRPC + mTLS** — the
  previous REST path was a dead end (Velociraptor's port 8001 is
  pure gRPC, not a grpc-gateway). Vendored proto tree compiled at
  build time, identity pinned to the Velociraptor CA, server SAN
  forced to `VelociraptorServer`. All four read-only L2 tools and
  the periodic sync now talk to a real server.
- **Dashboard navigation unified** — single left sidebar rendered by
  the root layout for every sectioned page (Inventaire, Investigation,
  Skills, Rapports, Incidents, Config). Sources tab removed in favour
  of the unified Skills catalogue. Reports gain dedicated routes per
  category instead of an URL filter.
- **AD connector** — service-account detection (svc-/srv- prefix or
  trailing `$`) and French admin-group recognition (Admins du domaine,
  Administrateurs de l'entreprise, ...) so a freshly-installed FR DC
  classifies users correctly without waiting for SDProp.

### Fixed
- Asset sources list no longer collapses to the last writer — every
  resolution path (AD + Wazuh + osquery + Velociraptor) now
  accumulates into the asset's `sources` array, restoring the
  confidence-by-source-count signal used by /assets.
- Identity graph events stop overwriting authoritative `is_admin`
  and `is_service_account` flags set by the AD/M365 connectors.
- Webhook ingest accepts 16 MB payloads on the osquery path so a
  domain controller's full snapshot stops getting rejected.

---

## [1.0.11-beta] — 2026-04-24

Two new connectors land: **Velociraptor** for endpoint DFIR and
**Microsoft 365 / Entra ID** for the SaaS side. Together they cover
the two vectors that dominate SMB incidents — compromised endpoints
and compromised M365 accounts.

### Added
- **skill-velociraptor** — ingestion of Velociraptor hunt results
  into ThreatClaw's graph, plus four read-only tools exposed to the
  L2 forensic assistant (list clients, run VQL query with read-only
  enforcement, list hunts, collect a single client). mTLS against
  Velociraptor's gRPC gateway. Cursor-based sync keeps last hunt
  completion across restarts.
- **skill-microsoft-graph** — full M365 / Entra ID tenant ingestion
  via OAuth app-only (certificate or secret). Pulls sign-ins,
  directory audits, users (delta), devices (delta), Intune managed
  devices, Conditional Access policies, Defender unified alerts,
  Identity Protection risky users, and risk detections. Detects the
  five top SMB compromise signals: mail auto-forward rule, illicit
  OAuth consent, impossible travel / high-risk sign-in, MFA fatigue,
  and Global Admin role assignment. Degrades silently per endpoint
  when a licence is missing, so a Business Premium tenant still
  benefits from what it covers.
- Feature probe matrix on the M365 skill — one probe per endpoint
  reports `ok` / `unlicensed` / `consent_missing` so the dashboard
  can tell the operator exactly which licence tier their tenant
  needs for the remaining detections.
- Identity graph bridging — every successful M365 sign-in now emits
  a `LOGGED_IN` edge (User → Asset(m365:tenant)), and `/users/delta`
  upserts `Identity` nodes with department + UPN so on-prem / SaaS
  UBA can correlate across sources.

### Changed
- Connector sync scheduler gains cursor persistence for both new
  skills — restarts never replay already-ingested events.

---

## [1.0.10-beta] — 2026-04-22

Wazuh connector hardened for real customer traffic — noise filter,
cursor-based pagination, native-type database binding, hostname dedup.
Every install now picks up real detections out of the box instead of
drowning in Docker veth noise.

### Added
- Wazuh connector noise filter — Docker veth and auditd promisc events
  silenced by default, extendable via skill config.
- Cursor-based pagination on the Wazuh connector — no event loss when
  the source fires faster than a sync cycle.
- `log_db_write` helper across the connector layer: every DB error
  logged with context instead of silently dropped.
- Attack scenario harness (`scripts/test-attacks/run.sh`) + Forgejo
  workflow — real probes against the TARS lab, verified detection.

### Changed
- Dashboard Wazuh modal surfaces the built-in noise filter and adds a
  sync-cursor reset button.
- Ollama default capacity dropped to 1 loaded model — fits a 32 GB SMB
  host without swap thrash.

### Fixed
- `insert_log` and `insert_sigma_alert` silently failed serialisation
  for weeks on OpenCanary-shaped payloads; bound now as native JSONB
  `Value` / `IpAddr` instead of `::jsonb` / `::inet` casts.
- Wazuh agent re-enrollment no longer creates a duplicate asset
  (hostname-based match + migration V50 purges historical duplicates).

### Infrastructure
- New consistency check flags any reintroduction of the silent
  `let _ = store.*` pattern in connectors.

---

## [1.0.9-beta] — 2026-04-22

Conversational chat lands in the dashboard, grounded LLM by default, and
12 day-zero Sigma rules so fresh installs start catching things within
the first hour. Dashboard redesigned as a full SOC console.

### Added
- Web chat pane in the dashboard — same L0 assistant as Slack/Telegram,
  with thread history, tool-call citations, and auto-resume on crash.
- Grounding Strict on by default: every LLM answer is cited against a
  database source, or the handler refuses to serve it.
- Linux/Wazuh Sigma starter pack — 12 MITRE-tagged rules covering SSH
  brute force, privilege escalation, credential theft, audit tampering.
- Home KPI strip — open incidents, findings by severity, top-risk
  asset, 24 h alert volume, one click per tile to the relevant page.
- Console log tail wired to live backend signals (sources, health,
  IE cycle, incidents) so the operator sees the system moving.

### Changed
- Dashboard redesigned as a SOC operator console — dense layout,
  sober palette, red reserved for urgency, full viewport.
- `/status` split from home: home is the operator console,
  `/status` is the health of the deployment.
- Config page reorganised: vertical sidebar, per-section save
  buttons, restart-wizard moved out of the global footer.
- CpuCard on /status now wires all 8 slots live (PostgreSQL, Intel
  Engine, Channels, Logs, AI, ML, Skills, Dashboard).
- ML engine state shown as "learning · N/14 d" during bootstrap
  instead of "offline".
- Sources / Intelligence / Governance / Exports pages unified on the
  console palette — decorative per-service brand colours dropped.

### Fixed
- Graph layer no longer treats Wazuh hostnames as IP addresses —
  kill-chain correlation and blast radius operational again.
- Dashboard was polling a non-existent ML endpoint and showing the
  engine offline. State now read from `/api/tc/health`.
- Version badge and installer kept drifting after version bumps;
  CI consistency gate blocks drift before merge.

### Infrastructure
- Staging pipeline: every push on `main` builds, deploys to CASE,
  runs smoke tests, and rolls back the database if anything fails.
- Release workflow cut from ~55 min to ~30 min (dropped the duplicate
  Rust build).
- Installer survives minimal Debian / Ubuntu images (wget fallback
  when curl is missing).
- Webhook server honours `HTTP_HOST` / `HTTP_PORT` env vars before
  the hardcoded default.

### Security
- GitHub Actions workflows routed every `${{ … }}` expression through
  `env:` to prevent shell injection via tag names.

---

## [1.0.8-beta] — 2026-04-21

> ThreatClaw v1.0.8 livre 5 features qui consolident la plateforme en
> SOC-in-a-box de niveau production : blast radius automatique sur
> incidents sensibles, graph d'assets typé normalisé, règles de
> suppression avec TTL et audit trail, télémétrie time-to-alert CISA
> KEV, et rapport mensuel RSSI PDF. Rationale complète dans
> `internal/feature-roadmap.md` et ADR-045…048.

### Added — Blast radius automatique (ADR-048)

- **Migration V43** — colonnes `blast_radius_snapshot JSONB`,
  `blast_radius_computed_at` et `blast_radius_score SMALLINT (0-100)`
  sur `incidents`, avec index partiel sur le score pour tri/Top N.
- Déclenchement auto après `update_incident_verdict` pour les
  catégories à risque latéral (T1566 phishing, T1078 valid accounts,
  T1003 credential dumping, T1068 privesc, T1021 lateral movement,
  T1041/T1567 exfiltration, T1486 ransomware impact, T1098 account
  manipulation) au niveau de sévérité HIGH ou supérieur.
- Score déterministe 0-100 : `min(100, Σ(criticality × 10 / (hop+1)))`
  pondéré par la criticity de chaque asset atteint dans les 3 sauts.
- Endpoint `POST /api/tc/incidents/{id}/blast-radius/recompute` pour
  rafraîchir un snapshot à la main.
- Composant React `BlastRadiusCard` en tête du détail incident : score
  coloré, libellé humain localisé, top 10 assets impactés avec icône
  par type (user/host/database/app/vm…), criticité et nombre de sauts,
  bouton « Recalculer ».

### Added — Graph storage normalisé (ADR-045)

- **Migration V42** — `graph_nodes`, `graph_edges`, `graph_edge_catalog`
  remplacent les jointures ad-hoc sur `assets`/`identities`/`sessions`.
  Edges typés avec poids Dijkstra-ready ; 24 kinds pré-seedés couvrant
  AD (MemberOf, AdminTo, HasSession, GenericAll, CanRDP…), Azure AD
  (AZOwns, AZContributor…), AWS (AssumeRole, S3Access), Cloudflare
  (ZeroTrustAccess), Proxmox (HypervisorOf, VMConsole), réseau
  (ReachableOn, ResolvesTo), data (Stores).
- Provenance par skill + TTL optionnel par edge (sessions,
  lease DHCP éphémères).
- `pg_notify('graph_update', …)` via trigger AFTER INSERT/UPDATE/DELETE
  pour invalidation incrémentale du cache in-memory.
- Cache `petgraph::DiGraph` derrière `tokio::sync::RwLock` initialisé
  au boot depuis `graph::normalized::global::init(pool)`, exposé via
  `global::get() -> Option<Arc<GraphCache>>`.
- Algos : BFS borné (blast radius), Dijkstra pondéré (`shortest_path`),
  reconstruction de chemin `Vec<PathStep>` avec `edge_kind` + weight.
- Nouvelle dépendance : `petgraph = "0.6"`.

### Added — Suppression rules v1 (ADR-046, ADR-047)

- **Migration V44** — `suppression_rules` avec TTL obligatoire 90 j
  par défaut (`expires_at NOT NULL`), raison ≥ 10 caractères
  (contrainte CHECK SQL), catalog d'actions `drop|downgrade|tag`,
  scope `global|skill:*|asset_group:*`, traçabilité source
  `manual|suggested|imported_sigma`.
- Table `suppression_audit` séparée avec audit trigger auto
  (created/updated/enabled/disabled/expired/matched_milestone) et
  diff JSONB des champs clés.
- Predicats CEL (Common Expression Language) compilés via la crate
  `cel-interpreter = "0.10"`. Wrap `std::panic::catch_unwind` sur
  `Program::compile` pour neutraliser le bug connu antlr4rust sur
  input malformé (bug upstream documenté).
- `SuppressionEngine` thread-safe (RwLock<Arc<Vec<CompiledRule>>>,
  swap atomique), `replace_rules` retourne un `CompileReport`
  (compiled / failed_compile / skipped_expired).
- Hot reload automatique après chaque CUD via l'API + au boot dans
  `db::mod.rs`. Rules invalides loguées et skippées, ne bloquent
  pas le hot path d'ingestion.
- API REST :
  - `GET  /api/tc/suppression-rules?enabled_only={bool}`
  - `POST /api/tc/suppression-rules`
  - `GET  /api/tc/suppression-rules/{id}`
  - `DELETE /api/tc/suppression-rules/{id}` (soft disable)
  - `POST /api/tc/suppression-rules-preview` (14-day dry-run)
- Wizard UI `SuppressionWizard` lancé depuis le bouton « Ignorer ce
  pattern » de chaque incident. Pré-remplit le CEL depuis
  l'incident, preview automatique à l'ouverture, warning rouge si
  des incidents confirmés auraient été supprimés (pattern
  CrowdStrike Falcon « affected threats preview »), validation
  front-end stricte (reason ≥ 10, predicate non-vide).

### Added — CISA KEV time-to-alert telemetry (feature-roadmap §3.5)

- **Migration V45** — `cve_exposure_alerts` avec colonnes `GENERATED
  ALWAYS AS … STORED` pour `tta_ingest_sec` (publication CISA →
  ingestion TC) et `tta_alert_sec` (publication CISA → premier
  match asset). Unique sur `cve_id` = idempotence garantie.
- Vue `kev_tta_metrics_30d` : P50, P95, max, matched_count,
  observed_count sur les 30 derniers jours.
- Instrumentation `sync_kev` : `record_kev_observation` sur chaque
  nouvelle entrée catalog. `record_kev_first_match` appelé dès
  qu'une CVE KEV matche un de nos scanned assets (hook après
  `cisa_kev::is_exploited`).
- Endpoint `GET /api/tc/metrics/kev-tta` + widget home `KevTtaCard`
  (P50 vert / P95 orange / nb matched bleu).

### Added — Rapport mensuel RSSI (feature-roadmap §3.4)

- **Migration V46** — materialized view `monthly_rssi_summary`
  agrégée sur tous les incidents par mois : volumes
  (total/confirmed/fp/resolved/open), distribution severity,
  KPIs blast radius (count/avg/max), MTTR P50/P95. Unique index
  sur `month` → `REFRESH MATERIALIZED VIEW CONCURRENTLY` supporté.
- Fonction `top_incidents_by_blast(month_start, n)` pour la
  section « Top 3 risques du mois » du rapport.
- Template Typst `templates/monthly-rssi.typ` — 1 page A4 :
  header, 8 KPI cards, MTTR, blast radius, tableau top incidents,
  footer brandé client (via `company_profile`).
- API REST :
  - `GET  /api/tc/reports/monthly/{yyyy-mm}` (JSON)
  - `GET  /api/tc/reports/monthly/{yyyy-mm}/pdf` (PDF)
  - `POST /api/tc/reports/monthly/refresh` (refresh matview)
- Composant home `MonthlyRssiCard` avec téléchargement direct
  du PDF.

### Changed

- `get_incident()` retourne désormais les champs `evidence_citations`
  (V39, manquant), `blast_radius_snapshot`, `blast_radius_score`,
  `blast_radius_computed_at`.
- Database init loop (`src/db/mod.rs`) warm-up le cache graph et le
  moteur de suppression au boot Postgres.
- `SuppressionDecision` ajoute une variante `Downgrade { cap }` qui
  préserve l'event mais plafonne sa sévérité.

### Infrastructure

- **ADR-045** — Graph storage normalisé (Postgres + petgraph vs Neo4j/AGE)
- **ADR-046** — Rules engine (Cedar authz + CEL predicates vs Rego/DSL)
- **ADR-047** — Suppression rules TTL + audit + anti-overfit
- **ADR-048** — Blast radius auto-trigger + score déterministe

### Tests

- 45+ nouveaux tests unit (graph, suppression engine CEL, blast
  radius trigger, KEV TTA, CEL compile/eval errors, panic safety).
- 8 tests d'intégration live contre PostgreSQL réel : `#[ignore]`
  pour ne pas ralentir `cargo test`, à lancer avec
  `DATABASE_URL=… cargo test --features postgres --tests -- --ignored`.
- Fixtures reproductibles (préfixe de données `it-*` + cleanup
  systématique) pour tests idempotents et parallelizables.

### Community & Governance

Sprint de durcissement gouvernance open source pour hisser le projet
au niveau Django / HashiCorp / GitLab côté accueil des contributeurs
et des chercheurs en sécurité.

- **`CLA.md` v1.1** — Patent grant + retaliation (Apache 2.0 §3),
  moral rights clause compatible droit français (*droits moraux
  inaliénables*, art. L121-1 CPI), governing law France + Paris
  jurisdiction + exclusion UN CISG, versioning (protège les
  signataires des versions antérieures). Inspiré de Harmony
  Agreements outbound option 5 + Apache ICLA v2.2.
- **CLA Assistant bot** activé au niveau org `threatclaw` sur GitHub
  (gist public maintenu). Toute PR non-signée est bloquée avant merge.
- **`CODE_OF_CONDUCT.md`** — Contributor Covenant v3.0 (standard
  2026 adopté par Django, Linux, Swift, Go) avec 3 sections
  ThreatClaw-specific : weaponised disclosure, credential/PII
  leakage, offensive-security showcasing. Ladder enforcement 4
  niveaux.
- **`SECURITY.md`** refresh complet : versions supportées (1.0.x),
  scope in/out explicite, **safe harbor clause** pour good-faith
  security research, SLA chiffrés (ack 48h / triage 7j / patch
  critical 14j / high 30j), PGP workflow documenté.
- **PGP key ed25519** (`6A72 8106 4019 33B5 F772 9C64 9A23 EDB9 3FA6
  F355`, expire 2030-04-20) pour `security@threatclaw.io`. Publiée
  sur keys.openpgp.org et keyserver.ubuntu.com + téléchargeable
  depuis `https://threatclaw.io/.well-known/pgp-key.asc`.
- **`security.txt` RFC 9116 signé** disponible sur
  `https://threatclaw.io/.well-known/security.txt`. Pointe vers
  GitHub Private Vulnerability Reporting + email chiffré en
  alternative.
- **Migration emails produit vers `@threatclaw.io`** (cohérence
  domaine) : `security@`, `conduct@`, `admin@` — 11 occurrences
  mises à jour dans le repo. `contact@cyberconsulting.fr` reste le
  canal corporate.
- **`CONTRIBUTORS.md`** étendu avec 3 recognition levels
  (Contributor / Core Contributor / Core Team) et path clair
  Contributing → CoC → CLA → PR.
- **README badges** gouvernance : license dual, CLA assistant
  dynamique, Contributor Covenant 3.0, security policy, PRs welcome.

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

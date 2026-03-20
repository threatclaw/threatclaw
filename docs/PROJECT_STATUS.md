# THREATCLAW v0.2.0-beta — Statut Complet du Projet

> Dernière mise à jour : 20 mars 2026 — V2 multi-cibles + canaux + scanners + CI/CD
> Développeur : CyberConsulting.fr — RSSI à temps partagé
> Licence : Apache 2.0 | Base : Fork d'IronClaw

---

## 1. VUE D'ENSEMBLE

ThreatClaw est un **agent de cybersécurité autonome open source** pour PME sous directive NIS2.
Architecture **Zero Trust Agent** : 3 couches (réactive / corrélation IA / action sandboxée), 5 piliers de sécurité intouchables, 4 modes d'autonomie RSSI.

### Chiffres clés

| Métrique | Valeur |
|----------|--------|
| Fichiers Rust (.rs) | 345+ |
| Fichiers Python (skills) | 27 |
| Fichiers Dashboard (TSX/TS) | 40 |
| Migrations SQL | 18 (V01 → V18) |
| Lignes de code Rust | ~200 000 |
| Lignes module agent | ~26 000 |
| Lignes module scanners | ~600 (nouveau) |
| Lignes dashboard | ~7 500 |
| Tests Rust (agent+secrets+scanners) | 590 (0 failed) |
| Tests e2e Playwright | 5 (0 failed) |
| Tests Rust total | 3 500+ |
| Tables PostgreSQL | 32 |
| API endpoints ThreatClaw | 26 |
| Canaux WASM compilés | 4 (Slack, Telegram, Discord, WhatsApp) |
| Skills avec skill.json | 3 (vuln-scan, secrets-audit, cloud-posture) |

---

## 2. PHASES DE DÉVELOPPEMENT

### Phase 1 — Fork, rebrand, infrastructure — TERMINÉ
- Fork IronClaw → ThreatClaw (renommage complet)
- `docker-compose.dev.yml` (DB, Redis, Nuclei, Trivy)
- Structure skills Python

### Phase 2 — 5 skills core — TERMINÉ (82 tests Python)
- `skill-vuln-scan` — Scanner Nuclei + Nmap
- `skill-secrets-audit` — Détection secrets exposés
- `skill-email-audit` — SPF/DKIM/DMARC
- `skill-darkweb-monitor` — Surveillance dark web
- `skill-phishing-sim` — Simulation phishing

### Phase 3 — SOC Pipeline — TERMINÉ (194 tests)
- `skill-soc-monitor` — Moteur Sigma + corrélation (76 tests)
- `skill-cloud-posture` — Audit cloud AWS/Azure/GCP (66 tests)
- `src/anonymizer/` — Anonymisation LLM réversible (36 tests Rust)
- `src/agent/cyber_scheduler.rs` — 6 routines cyber (16 tests Rust)
- Migration V14 — logs, sigma_rules, sigma_alerts, cloud_findings

### Phase 4 — Rapports, compliance, dashboard — TERMINÉ (241 tests)
- `skill-report-gen` — Rapports PDF/HTML français (69 tests)
- `skill-compliance-nis2` — NIS2 Art.21 mapping (70 tests)
- `skill-compliance-iso27001` — 93 contrôles Annexe A (44 tests)
- `src/integrations/slack_hitl.rs` — HITL Slack Block Kit (26+32 tests)
- Dashboard Next.js 14 initial

### Phase 5 — Production Docker, installer, CI/CD — TERMINÉ
- `docker-compose.yml` — 13 services, 2 réseaux
- `installer/install.sh` — Installeur idempotent (618 lignes)
- Dockerfiles (core + dashboard) + nginx reverse proxy
- 3 workflows GitHub Actions (CI, release, security)
- Documentation (USER_GUIDE.md FR, ARCHITECTURE.md EN)

### Phase 6 — Mise en route réelle + API — TERMINÉ
- **Corrections backend Rust** :
  - Default LLM `nearai` → `ollama` (config/llm.rs, boot_screen.rs)
  - Doctor: skip nearai session check si backend != nearai
  - Webhook port 8080 → 18080
  - Migrations zero-padding (V1→V01 ... V9→V09)
- **Dashboard design system embossed** :
  - Light/Dark theme avec CSS variables (sable-pierre / brun-noir)
  - Éléments creusés (inset shadows), couleurs sémantiques
  - BottomNav (Board / Alertes / Agent / Skills / Config)
- **Dashboard dynamique** :
  - Widgets drag & drop (react-grid-layout)
  - Bouton [+ Widget] pour ajouter des widgets
  - Hover ⚙/📌/✕ sur chaque widget
  - Layout sauvegardé en localStorage
- **Onboarding wizard 6 étapes** :
  - LLM (Ollama/Mistral/Anthropic/Custom) avec test connexion
  - Communication (Slack/Telegram/Signal/WhatsApp/Email)
  - Niveau de sécurité (4 niveaux)
  - Planning des scans (6 routines, cron éditable)
  - Récap → CTA "Explorer le Marketplace"
- **Page Config** (après onboarding) :
  - Onglet Core : Général / LLM / Communication / Sécurité / Planning
  - Onglet Skills : config par skill installé
  - Bouton "Relancer l'assistant" + "Enregistrer"
- **Marketplace skills** :
  - 18 skills (10 officiels + 8 communautaires)
  - 7 catégories (Scanning, Conformité, Monitoring, etc.)
  - Filtres trust (Tous/Installés/Officiels/Vérifiés/Communauté)
  - Recherche instantanée + modale détail
  - Bouton "Proposer un skill"
- **Core API REST** (Rust/Axum) — 12 endpoints :
  - `/api/tc/health` — santé + version
  - `/api/tc/findings` — CRUD findings
  - `/api/tc/findings/counts` — compteurs par sévérité
  - `/api/tc/alerts` — CRUD alertes Sigma
  - `/api/tc/alerts/counts` — compteurs par niveau
  - `/api/tc/config/{skill}` — config par skill
  - `/api/tc/metrics` — métriques dashboard
- **Python SDK** (`sdk/python/threatclaw_sdk/`) :
  - `ThreatClawClient` — client HTTP pour les skills
  - `Finding`, `Alert`, `SkillConfig`, `Severity` — modèles
- **Next.js API proxy** (`/api/tc/*` → Core API)
- **Dashboard branché sur données réelles** (auto-refresh 15s)
- **Scan réel** Nmap + Nuclei sur la machine hôte → findings en DB → dashboard live
- **Migration V15** — tables findings, skill_configs, metrics_snapshots

### Phase 7 — Architecture ReAct Sécurisée (OWASP ASI 2026) — TERMINÉ

**Sprint 1 — 5 Piliers intouchables (74 tests) :**

| Pilier | Fichier | Tests | Description |
|--------|---------|-------|-------------|
| I — Soul immuable | `AGENT_SOUL.toml` + `soul.rs` + `build.rs` | 8 | Hash SHA-256 compilé dans le binaire, vérifié au démarrage et runtime |
| II — Whitelist remédiation | `remediation_whitelist.rs` | 20 | 12 commandes validées, anti-injection (`;|&\`$`), cibles interdites (root, PID 1, containers ThreatClaw), chemins interdits (/etc, /bin, /usr) |
| III — XML wrapper | `tool_output_wrapper.rs` | 17 | 25+ patterns cyber-spécifiques (mark as false positive, whitelist IP, disable security...), wrapping XML `trusted="false"` |
| IV — Mémoire HMAC | `memory.rs` + migration V17 | 15 | HMAC-SHA256 sur chaque entrée, vérification intégrité au démarrage, read-only depuis outils |
| V — Kill switch | `kill_switch.rs` | 14 | 8 triggers (soul tampering, whitelist violation, memory write, autonomy timeout, behavior anomaly, self-targeting, consecutive errors, manual), arrêt atomique |

**Sprint 2 — Boucle ReAct + composants (65 tests) :**

| Module | Fichier | Tests | Description |
|--------|---------|-------|-------------|
| Mode Manager | `mode_manager.rs` | 12 | 4 modes RSSI : Analyste (fixe) / Investigateur (read-only) / Répondeur (HITL) / Autonome Low |
| Observation Collector | `observation_collector.rs` | 12 | Agrège findings/alertes depuis DB, convertit en blocs XML wrappés |
| Prompt Builder | `prompt_builder.rs` | 9 | Construit le prompt sécurisé (soul + mode + observations + whitelist + schéma JSON) |
| LLM Router | `llm_router.rs` | 5 | Sélection modèle par tâche (chat/corrélation/rapport/triage), jamais hardcodé |
| Executor | `executor.rs` | 7 | Exécution native `std::process::Command`, jamais `shell=true`, split command strict |
| HITL Nonce | `hitl_nonce.rs` | 7 | Anti-replay SHA-256, TTL configurable, nonce usage unique |
| ReAct Cycle | `react_cycle.rs` | 13 | Orchestrateur complet : pre-checks → observations → prompt → LLM → JSON parse → whitelist validate → mode decision |

**Sprint 3 — Audit + API agent (migrations V16-V17) :**
- Migration V16 — `agent_audit_log` table immuable (trigger anti-UPDATE/DELETE)
- Migration V17 — `agent_memory` table avec HMAC + trigger immuabilité
- 6 nouveaux API endpoints agent

### Phase 8 — Boucle ReAct end-to-end — TERMINÉ

**Sprint 1 — Cycle ReAct automatique — TERMINÉ :**
- `react_runner.rs` — Module d'exécution qui connecte tous les piliers au monde réel
- `spawn_react_ticker()` — Cron ticker pour cycles automatiques (configurable, default 15min)
- API endpoint `POST /api/tc/agent/react-cycle` — déclenchement manuel
- **Testé end-to-end** : 3 findings réels (scan Nmap) → qwen3:14b → analyse JSON → audit log

**Sprint 2 — Corrélation IA réelle — TERMINÉ :**
- Scénario d'attaque : brute force SSH → connexion réussie → mouvement latéral RDP → CVE-2024-3094 → dark web
- LLM a identifié : 3 corrélations, sévérité CRITICAL, confiance 95%, 3 actions proposées (2 validées, 1 rejetée)
- Dashboard page Agent : bouton ReAct, analyse live, audit log, mode selector, kill switch

**Sprint 3 — HITL Slack live — TERMINÉ :**
- `hitl_bridge.rs` — Bridge ReAct → Slack → Executor → Audit (7 tests)
- API `POST /api/tc/agent/hitl-callback` — endpoint pour callbacks Slack
- Anti-replay vérifié : nonce invalide → rejet immédiat
- 490 tests agent, 0 failed

**Sprint 4 — Finitions — TERMINÉ :**
- `docs/openapi.json` — Spec OpenAPI 3.1.0 servie live sur `/api/tc/openapi.json` (16 paths, 6 tags)
- Tests e2e Playwright — 5 scénarios (dashboard, agent, marketplace, alertes, config) — 5/5 verts
- Docker compose prod — Ollama intégré, ports configurables, AGENT_SOUL.toml monté, Dockerfile.dashboard
- 490 tests + 5 e2e, 0 failed

### Phase 9 — Escalade 3 niveaux + Onboarding LLM — TERMINÉ

**Escalade IA 3 niveaux :**

```
Findings DB → Niveau 1 (IA locale rapide)
                  ↓ confiance < 70%
              Niveau 2 (IA locale enrichie, plus de contexte)
                  ↓ confiance < 50% ou CRITICAL
              Niveau 3 (IA cloud anonymisée)
                  ↓
              Résultat final → audit log → dashboard
```

- `llm_router.rs` — Refonte complète :
  - `PrimaryLlmConfig` — IA principale (ollama/mistral/anthropic/compatible)
  - `CloudLlmConfig` — IA cloud de secours (optionnel)
  - `CloudEscalation` — Politique : Never / Anonymized / Direct
  - `decide_escalation()` — Logique automatique basée sur confiance + sévérité + injection
  - `recommend_model()` — Auto-recommandation selon RAM (<8GB→4b, 8-16→8b, 16-32→14b, 32-64→32b, 64+→72b)
  - 12 tests
- `cloud_caller.rs` — Appels cloud anonymisés :
  - `AnonymizationMap` — Anonymise IPs, hostnames, emails, usernames avec tokens réversibles ([IP-001], [HOST-001]...)
  - `call_cloud_llm()` — Support Anthropic / Mistral / OpenAI Compatible
  - `deanonymize()` — Restaure les données originales dans la réponse cloud
  - Roundtrip vérifié : original → anonymisé → cloud → dé-anonymisé = original
  - 9 tests
- `react_runner.rs` — Refonte avec 3 niveaux :
  - L1 : IA locale → si confiance ≥ 70% → accepté
  - L2 : Retry local enrichi (réinjecte l'analyse L1 comme contexte) → si confiance ≥ 50% → accepté
  - L3 : Cloud anonymisé → analyse profonde → accepté
  - Fallback graceful : si cloud non configuré → AcceptDegraded (garde L1)
  - Si cloud échoue → fallback L1
  - `escalation_level` retourné dans l'API (1, 2 ou 3)
  - 3 tests

**Onboarding wizard 7 étapes :**

1. **Bienvenue**
2. **IA Principale** (obligatoire) — 4 choix :
   - Ollama local (ThreatClaw installe + télécharge le modèle recommandé)
   - Ollama distant (serveur existant, juste l'URL)
   - Mistral AI (souveraineté FR, clé API)
   - Anthropic (Claude, clé API)
   - Auto-détection RAM → recommandation de modèle
   - Test connexion + liste des modèles installés
3. **IA Cloud de secours** (optionnel) — 3 providers :
   - Anthropic / Mistral / OpenAI Compatible
   - Politique d'envoi : Anonymisé (recommandé) / Direct / Jamais
   - Toggle on/off avec message "100% local" quand désactivé
4. **Communication** (Slack/Telegram/Signal/WhatsApp/Email)
5. **Niveau de sécurité** (4 niveaux)
6. **Planning des scans** (6 routines, cron éditable)
7. **Récapitulatif** → Marketplace

**Tests de modèles LLM effectués :**

| Modèle | RAM poids | RAM totale | Résultat sur 30GB | Qualité corrélation |
|--------|-----------|-----------|-------------------|---------------------|
| qwen3:8b | 5GB | ~7GB | Stable | Bonne (3 corrélations, 95% confiance) |
| qwen3:14b | 9GB | ~11GB | Stable | Très bonne (recommandé pour cette machine) |
| qwen3:30b-a3b (MoE) | 18GB | >26GB | OOM crash | N/A |
| qwen3:32b | 20GB | >26GB | OOM crash | N/A |

**Recommandation** : qwen3:14b pour machines 16-32GB RAM. Pour 32B+ il faut 48GB+ de RAM.

**Nettoyage infrastructure :**
- 25 anciens containers supprimés (CyberBox, OpenClaw, Wazuh, DefectDojo, etc.)
- Ollama déplacé de `/var` (183GB, 87%) vers `/srv` (717GB, 17%) — 569GB disponibles pour les modèles
- Docker images purgées : 44GB → 4.8GB
- Build cache purgé : 8GB → 0
- `/var` libéré : 150GB → 70GB
- RAM libérée : 11GB → 1.8GB utilisés (27GB disponibles)

**508 tests agent Rust + 5 tests e2e Playwright, 0 failed.**

### Phase 10 — V2 : Multi-cibles, Canaux, Scanners, CI/CD — TERMINÉ

**V2a — Credential Vault :**
- `master_password.rs` — Argon2id (m=64MiB, t=3, p=1) pour mot de passe maître humain (7 tests)
- `credential_types.rs` — SshKey, ApiKey, WinrmBasic, WinrmCert, Token + TargetConfig (10 tests)
- Total : 70 tests secrets, 0 failed

**V2b — Infrastructure multi-cibles :**
- Migration V18 — Table `targets` (id, host, type, access, port, mode, credential, ssh_host_key, actions, tags)
- API `GET/POST /api/tc/targets` + `DELETE /api/tc/targets/{id}` — CRUD cibles
- Dashboard page `/infrastructure` — Ajout serveurs + firewalls, formulaire avec type/accès/mode/driver
- TopNav mis à jour avec "Infra"
- Testé : création + listage + suppression de cibles via API

**V2c — Canaux de communication (WASM) :**
- 4 canaux WASM compilés et installés :
  - `slack_channel.wasm` (196KB) — Bot Token + Signing Secret
  - `telegram_channel.wasm` (376KB) — Bot Token + Bot Username
  - `discord_channel.wasm` (292KB) — Bot Token + Public Key
  - `whatsapp_channel.wasm` (236KB) — Access Token + Phone Number ID
- Signal natif (déjà dans le core) — HTTP URL signal-cli + numéro
- Email — SMTP standard
- Wizard + Config mis à jour avec les vrais champs de chaque canal
- Chargement vérifié au démarrage : `WASM_CHANNELS_ENABLED=true` → 4 channels loaded

**V2d — Scanner abstraction layer :**
- `src/scanners/backend.rs` — Trait `ScannerBackend` + 3 modes :
  - `Docker` — ThreatClaw gère le container
  - `LocalBinary` — outil déjà installé, chemin vers le binaire
  - `RemoteApi` — outil sur un autre serveur, URL + API key
- `src/scanners/nuclei.rs` — Nuclei scanner (docker exec / local binary) — 5 tests
- `src/scanners/trivy.rs` — Trivy scanner (docker / local / API REST) — 4 tests
- 12 tests scanners, 0 failed

**V2e — Architecture skills refondée :**
- `docker/docker-compose.core.yml` — Stack léger 4 services (core, dashboard, DB, Redis)
- Chaque skill a :
  - `skill.json` — metadata, docker_deps, config_fields, timeout, memory
  - `docker-compose.skill.yml` — containers optionnels de l'outil
- 3 skills avec skill.json :
  - `skill-vuln-scan` : Nuclei + Trivy, 3 config fields
  - `skill-secrets-audit` : Gitleaks, 2 config fields
  - `skill-cloud-posture` : Prowler, 4 config fields

**V2f — CI/CD & Sécurité :**
- `UPSTREAM_VERSION` — tracking fork IronClaw v0.19.0
- `security.yml` renforcé :
  - Cargo audit strict sur wasmtime/ring/argon2 (nightly + push)
  - Check upstream IronClaw chaque lundi
  - Auto-label Dependabot PRs (security-critical / routine)
- `dependabot.yml` mis à jour :
  - Groupes security-critical (wasmtime, ring, argon2, axum, aes-gcm)
  - 5 ecosystems : cargo, pip, npm, docker, github-actions
- `SECURITY.md` — politique de sécurité, contact, fichiers prioritaires audit

**V2g — Design dashboard Chrome :**
- Composants Chrome : `ChromeButton` (rectangle, texte rouge gravé), `ChromeInsetCard` (enfoncée, blanc cassé), `ChromeEmbossedText`
- TopNav en haut au lieu de BottomNav
- 6 pages : Accueil, Alertes, Infrastructure, Skills, Agent, Config
- Fond beige sable `#e2dbd4`, cards `#ece5de`, texte gravé

**590 tests Rust (508 agent + 70 secrets + 12 scanners) + 5 tests e2e, 0 failed.**

### Phase 11 — Skills WASM officiels + Infrastructure logs — TERMINÉ

**10 skills officiels Rust/WASM compilés (total 14 WASM avec 4 channels) :**

| Skill | WASM | API externe | Clé requise |
|-------|------|-------------|-------------|
| skill-email-audit | 136KB | DNS-over-HTTPS | Non |
| skill-cti-crowdsec | 152KB | CrowdSec CTI | Gratuite |
| skill-abuseipdb | 128KB | AbuseIPDB | Gratuite |
| skill-darkweb-monitor | 132KB | HIBP v3 | Payante |
| skill-compliance-nis2 | 156KB | Interne | Non |
| skill-compliance-iso27001 | 124KB | Interne | Non |
| skill-report-gen | 136KB | Interne | Non |
| skill-wazuh | 136KB | Wazuh REST | Credentials |
| skill-virustotal | 132KB | VirusTotal v3 | Gratuite |
| skill-shodan | 136KB | Shodan | Payante |

**Infrastructure logs :** Fluent Bit ports 514/24224/9880, parsers pfSense/FortiGate/NXLog, migration V19 rétention.

**Documentation :** SKILLS_REFERENCE.md + SKILL_DEVELOPMENT_GUIDE.md (officiels Rust/WASM + communautaires Python/Docker).

---

## 3. ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────┐
│                    DASHBOARD (Next.js 14)                     │
│  Port 3001 · Embossed UI · Light/Dark · BottomNav            │
│  Pages: Board / Alertes / Agent / Marketplace / Config       │
│  Widgets drag & drop · Données réelles via API proxy         │
└──────────────────────────┬──────────────────────────────────┘
                           │ /api/tc/* (proxy)
┌──────────────────────────▼──────────────────────────────────┐
│                    CORE RUST (Axum)                           │
│  Port 3000 · Gateway + API · Auth Bearer token               │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │     BOUCLE REACT SÉCURISÉE + ESCALADE 3 NIVEAUX     │    │
│  │                                                       │    │
│  │  AGENT_SOUL.toml ──→ Pre-cycle checks                │    │
│  │       ↓           (Soul hash + Memory HMAC + Kill SW) │    │
│  │  Observation Collector ──→ Prompt Builder              │    │
│  │       ↓                                               │    │
│  │  ┌─ NIVEAU 1 : IA locale (qwen3:14b) ─────────┐     │    │
│  │  │  confiance ≥ 70% → ACCEPTÉ                   │     │    │
│  │  └──────────────────────────────────────────────┘     │    │
│  │       ↓ confiance < 70%                               │    │
│  │  ┌─ NIVEAU 2 : IA locale enrichie ─────────────┐     │    │
│  │  │  + contexte L1 réinjecté                      │     │    │
│  │  │  confiance ≥ 50% → ACCEPTÉ                   │     │    │
│  │  └──────────────────────────────────────────────┘     │    │
│  │       ↓ confiance < 50% ou CRITICAL                   │    │
│  │  ┌─ NIVEAU 3 : IA cloud anonymisée ────────────┐     │    │
│  │  │  Anonymizer → Cloud (Anthropic/Mistral)       │     │    │
│  │  │  → Dé-anonymizer → Analyse enrichie           │     │    │
│  │  └──────────────────────────────────────────────┘     │    │
│  │       ↓                                               │    │
│  │  JSON Parser → Whitelist → Mode Decision → HITL       │    │
│  │       ↓                                               │    │
│  │  Kill Switch ──→ Audit Log (immuable)                 │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  26 API Endpoints:                                           │
│  /api/tc/health          /api/tc/openapi.json                │
│  /api/tc/findings[/counts] /api/tc/alerts[/counts]           │
│  /api/tc/config/{skill}  /api/tc/metrics                     │
│  /api/tc/targets (CRUD)  /api/tc/agent/mode                  │
│  /api/tc/agent/kill-switch /api/tc/agent/soul                │
│  /api/tc/agent/audit     /api/tc/agent/react-cycle           │
│  /api/tc/agent/hitl-callback                                 │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                 SKILLS (Python/WASM) + SDK                    │
│  10 skills officiels · SDK Python (threatclaw-sdk)            │
│  WASM sandbox · Capabilities opt-in · LeakDetector           │
│                                                              │
│  API :  client.report_finding(Finding(...))                  │
│         client.list_alerts()                                 │
│         client.get_config("skill-id")                        │
│         client.record_metric("score", 72.0)                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    INFRASTRUCTURE                            │
│  PostgreSQL 16 (pgvector) · Redis 7 · Nuclei · Trivy        │
│  Ollama (qwen3:8b/14b) · Fluent Bit                          │
│  31 tables · 17 migrations (V01→V17)                         │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. CE QUI FONCTIONNE (RÉEL, TESTÉ)

| Composant | Status | Preuve |
|-----------|--------|--------|
| Core Rust binary | **Opérationnel** | Compile, démarre, sert l'API, 3400+ tests |
| PostgreSQL 16 | **Opérationnel** | 31 tables, 17 migrations, données réelles |
| Redis 7 | **Opérationnel** | Health check OK |
| Ollama (qwen3:8b/14b) | **Opérationnel** | LLM local, GPU AMD ROCm |
| Gateway web (port 3000) | **Opérationnel** | Chat LLM + API REST |
| API REST `/api/tc/*` | **Opérationnel** | 23 endpoints, données réelles, auth Bearer |
| Dashboard Next.js (port 3001) | **Opérationnel** | Branché sur API, auto-refresh 15s |
| Widgets dashboard | **Opérationnel** | Drag & drop, données réelles |
| Scan Nmap réel | **Opérationnel** | 3 ports détectés sur la machine hôte |
| Scan Nuclei réel | **Opérationnel** | Templates installés, 0 CVE sur la machine |
| Findings → DB → Dashboard | **Opérationnel** | Pipeline complet end-to-end |
| Soul hash vérifié | **Opérationnel** | SHA-256 compilé dans le binaire |
| Mode agent changeable | **Opérationnel** | Via API + dashboard |
| **Cycle ReAct end-to-end** | **Opérationnel** | findings DB → prompt → Ollama → JSON → whitelist → audit |
| **Escalade 3 niveaux** | **Opérationnel** | L1 local → L2 enrichi → L3 cloud anonymisé (testé end-to-end) |
| **Corrélation IA** | **Opérationnel** | 3 corrélations sur scénario d'attaque, CRITICAL, 95% confiance |
| **Anonymisation cloud** | **Opérationnel** | IPs/hostnames/emails/users anonymisés, roundtrip vérifié |
| **HITL bridge + nonce** | **Opérationnel** | Anti-replay vérifié, callback API, executor connecté |
| **Whitelist validation** | **Opérationnel** | 2/3 actions validées, 1 rejetée (paramètre mal formaté) |
| **Audit log** | **Opérationnel** | Entrées réelles visibles dans dashboard |
| **Kill switch** | **Opérationnel** | API + bouton dashboard avec double confirmation |
| **OpenAPI spec** | **Opérationnel** | `/api/tc/openapi.json` — 16 paths, 6 tags, OpenAPI 3.1.0 |
| **Canaux WASM** | **Opérationnel** | Slack, Telegram, Discord, WhatsApp compilés, installés, webhooks enregistrés |
| **Signal** | **Opérationnel** | Natif Rust, nécessite signal-cli daemon |
| **Scanner Nuclei** | **Opérationnel** | Trait ScannerBackend, 3 modes (docker/local/remote), testé end-to-end |
| **Scanner Trivy** | **Opérationnel** | Trait ScannerBackend, 3 modes, API REST server mode |
| **Targets API** | **Opérationnel** | GET/POST/DELETE `/api/tc/targets`, persistence DB |
| **Credential vault Argon2id** | **Opérationnel** | Master password, 7 tests, canary verification |
| **Credential types** | **Opérationnel** | SshKey, ApiKey, WinrmBasic, WinrmCert, Token, 10 tests |
| **Infrastructure page** | **Opérationnel** | Ajout serveurs + firewalls, mode par cible |
| **SECURITY.md** | **Opérationnel** | Politique sécurité, contact, fichiers prioritaires audit |
| **CI/CD sécurité** | **Opérationnel** | Upstream check, cargo audit strict, Dependabot labels |
| Setup wizard | **Opérationnel** | 7 étapes, 6 canaux avec vrais champs |
| Skills page | **Opérationnel** | Installés/Disponibles, recherche, metadata skill.json |
| Config page | **Opérationnel** | Design Chrome, 6 canaux, cron éditable |
| Tests e2e | **Opérationnel** | 5 scénarios Playwright, 5/5 verts |

## 5. CE QUI EST CODÉ MAIS PAS ENCORE BRANCHÉ AU RUNTIME

| Composant | Status | Ce qu'il manque |
|-----------|--------|-----------------|
| Ticker cron automatique | **Code prêt** (`spawn_react_ticker`) | Appeler au démarrage du core |
| Kill switch partagé | **Code prêt** | Instancier au démarrage, partager via Arc |
| Audit log SQL direct | **Table V16 créée** | Actuellement via settings (contournement) |
| Memory HMAC DB | **Table V17 créée** | API pour écrire/lire les entrées mémoire |
| Sigma engine live | **Code prêt** | Connecter Fluent Bit → sigma_engine → sigma_alerts |
| Config wizard → backend | **Frontend prêt** | Les choix du wizard doivent écrire dans settings DB |
| Canaux WASM → secrets | **Chargés** | Les bot tokens doivent être configurés via credential vault |
| Scanners → scheduler | **Code prêt** | Le scheduler doit appeler les scanners selon les routines cron |
| skill.json → dashboard | **JSON prêts** | Le dashboard doit lire skill.json au lieu de skills-data.ts |
| docker-compose.skill.yml | **Fichiers prêts** | `threatclaw skill install` doit `docker compose up` le skill |

## 6. CE QUI N'EST PAS ENCORE FAIT

| Composant | Priorité | Description |
|-----------|----------|-------------|
| `threatclaw skill install/remove` | **Haute** | CLI pour installer/désinstaller un skill + ses containers |
| Scanners intégrés au scheduler | **Haute** | Le core lance Nuclei/Trivy via ScannerBackend au cron |
| Wizard → credential vault | **Haute** | Les tokens saisis dans le wizard sont chiffrés dans le vault |
| SSH executor distant | **Haute** | executor_ssh.rs avec host key TOFU (V2 architecture) |
| pfSense driver | **Haute** | executor_api.rs premier driver firewall |
| Rate limiting API | **Haute** | tower-governor, 5/60 req/min, détection abuse |
| Binary integrity verify | **Haute** | SHA-256 + GPG + `threatclaw verify-binary` |
| Skills communautaires process | **Moyenne** | Docker isolé (network:none, mem 256MB), review avant pub |
| Auto-install Ollama + modèle | **Moyenne** | Le wizard détecte la RAM et installe le modèle recommandé |
| Dashboard responsive mobile | **Moyenne** | Layouts à adapter |
| Compliance live scoring | **Basse** | NIS2/ISO scores calculés depuis les findings réels |
| Export PDF rapports live | **Basse** | skill-report-gen → API |
| Multi-utilisateurs | **Basse** | RBAC + tenants, prévu V3 |

---

## 7. SÉCURITÉ — CONFORMITÉ OWASP ASI TOP 10 2026

| # | Risque | Mitigation | Status |
|---|--------|-----------|--------|
| ASI01 | Goal Hijack | Soul immuable + hash compilé + XML wrapper outputs (25+ patterns cyber) | **Implémenté + testé** |
| ASI02 | Tool Misuse | Whitelist 12 commandes + anti-injection (`;|&\`$(){}`) + cibles interdites | **Implémenté + testé** |
| ASI03 | Identity & Privilege | HITL obligatoire + nonce anti-replay + audit log immuable | **Implémenté + testé** |
| ASI04 | Supply Chain | WASM signé BLAKE3 (hérité IronClaw) | **Implémenté** |
| ASI05 | Code Execution | Sandbox WASM fuel-metered + ResourceLimiter 10MB (hérité IronClaw) | **Implémenté** |
| ASI06 | Memory Poisoning | Mémoire read-only + HMAC-SHA256 intégrité + trigger immuabilité DB | **Implémenté + testé** |
| ASI07 | Inter-Agent Comms | N/A — agent unique V1 | **N/A** |
| ASI08 | Cascading Failures | Kill switch 8 triggers + max iterations + timeout + autonomy timeout 8h | **Implémenté + testé** |
| ASI09 | Excessive Trust | Double confirmation High/Critical + mode Investigateur par défaut (lecture seule) | **Implémenté** |
| ASI10 | Rogue Agent | Kill switch multi-trigger + behavioral anomaly scoring + bouton d'urgence dashboard | **Implémenté + testé** |

**Score : 9/9 applicable (ASI07 non applicable en V1)**

---

## 8. STRUCTURE DES FICHIERS CLÉS

```
/srv/threatclaw/
├── AGENT_SOUL.toml                     # Identité + 8 règles immuables (hash SHA-256 compilé)
├── threatclaw.toml                     # Config client (LLM, scheduler, anonymizer, notifications)
├── build.rs                            # Compilation hash soul + WASM Telegram
├── Cargo.toml                          # Dépendances Rust (sha2 en build-deps)
│
├── src/agent/                          # Module agent (~24 500 lignes, 37 fichiers)
│   │
│   │   ── Piliers de sécurité (Phase 7) ──
│   ├── soul.rs                         # Pilier I — Soul immuable (8 tests)
│   ├── remediation_whitelist.rs        # Pilier II — Whitelist commandes (20 tests)
│   ├── tool_output_wrapper.rs          # Pilier III — XML wrapper cyber (17 tests)
│   ├── memory.rs                       # Pilier IV — Mémoire HMAC (15 tests)
│   ├── kill_switch.rs                  # Pilier V — Kill switch (14 tests)
│   │
│   │   ── Boucle ReAct + Escalade (Phase 7-9) ──
│   ├── mode_manager.rs                 # 4 modes RSSI (12 tests)
│   ├── observation_collector.rs        # Agrégation multi-sources (12 tests)
│   ├── prompt_builder.rs              # Prompts sécurisés (9 tests)
│   ├── llm_router.rs                  # Escalade 3 niveaux + config primary/cloud (12 tests)
│   ├── cloud_caller.rs               # Appels cloud anonymisés + AnonymizationMap (9 tests)
│   ├── executor.rs                    # Exécution native sans shell (7 tests)
│   ├── hitl_nonce.rs                  # Anti-replay HMAC (7 tests)
│   ├── hitl_bridge.rs                # Bridge ReAct→Slack→Executor (7 tests)
│   ├── react_cycle.rs                 # Orchestrateur ReAct (13 tests)
│   ├── react_runner.rs                # Runner 3 niveaux L1→L2→L3 (3 tests)
│   │
│   │   ── IronClaw hérité ──
│   ├── agentic_loop.rs                # Boucle agentique (LoopDelegate trait)
│   ├── cyber_scheduler.rs            # 6 routines cyber (16 tests)
│   ├── routine_engine.rs             # Moteur de routines (cron + events)
│   ├── dispatcher.rs                 # Dispatch messages
│   └── ...                           # 20 autres fichiers
│
├── src/channels/web/handlers/
│   └── threatclaw_api.rs              # 26 endpoints API ThreatClaw
│
├── src/scanners/                       # Scanner abstraction layer (NOUVEAU)
│   ├── backend.rs                     # Trait ScannerBackend + 3 modes (5 tests)
│   ├── nuclei.rs                      # Nuclei scanner docker/local (5 tests)
│   └── trivy.rs                       # Trivy scanner docker/local/remote (4 tests)
│
├── src/db/
│   ├── threatclaw_store.rs            # Trait ThreatClawStore
│   ├── pg_threatclaw.rs               # Implémentation PostgreSQL
│   └── libsql_threatclaw.rs           # Stub LibSQL
│
├── src/secrets/                        # Credential vault
│   ├── crypto.rs                      # AES-256-GCM + HKDF-SHA256
│   ├── master_password.rs             # Argon2id key derivation (NOUVEAU, 7 tests)
│   ├── credential_types.rs            # SshKey/ApiKey/WinRM/Token + TargetConfig (NOUVEAU, 10 tests)
│   ├── store.rs                       # PostgreSQL/LibSQL/InMemory backends
│   └── types.rs                       # Secret, DecryptedSecret, SecretError
│
├── src/anonymizer/                     # Anonymisation PII réversible
├── src/integrations/slack_hitl.rs      # HITL Slack Block Kit
├── crates/threatclaw_safety/           # Sanitizer + LeakDetector + Policy
│
├── channels-src/                       # Canaux WASM (compilés)
│   ├── slack/                         # Slack channel (196KB WASM)
│   ├── telegram/                      # Telegram channel (376KB WASM)
│   ├── discord/                       # Discord channel (292KB WASM)
│   ├── whatsapp/                      # WhatsApp channel (236KB WASM)
│   └── feishu/                        # Feishu/Lark channel
│
├── skills/                             # Skills avec metadata
│   ├── skill-vuln-scan/
│   │   ├── skill.json                 # docker_deps: nuclei+trivy, config_fields
│   │   ├── docker-compose.skill.yml   # Containers optionnels
│   │   └── src/main.py                # Logique Python (prototype)
│   ├── skill-secrets-audit/
│   │   └── skill.json                 # docker_deps: gitleaks
│   ├── skill-cloud-posture/
│   │   └── skill.json                 # docker_deps: prowler
│   └── ...                            # 7 autres skills (prototypes Python)
│
├── sdk/python/threatclaw_sdk/          # SDK Python pour skills
│   ├── client.py                      # ThreatClawClient (HTTP)
│   ├── models.py                      # Finding, Alert, Severity
│   └── setup.py                       # pip install
│
├── dashboard/                          # Next.js 14 App Router
│   ├── src/app/
│   │   ├── page.tsx                   # Dashboard widgets drag & drop
│   │   ├── agent/page.tsx             # Contrôle agent IA (mode, kill switch, analyse, audit)
│   │   ├── alertes/page.tsx           # Alertes live (findings + SOC)
│   │   ├── scans/page.tsx             # Scans & routines
│   │   ├── marketplace/page.tsx       # Marketplace 18 skills, 7 catégories
│   │   ├── setup/page.tsx             # Wizard onboarding / Config page
│   │   └── api/
│   │       ├── tc/[...path]/route.ts  # Proxy → Core API (avec token)
│   │       └── ollama/route.ts        # Proxy → Ollama (test connexion)
│   ├── src/components/
│   │   ├── Header.tsx                 # Embossed + health live + toggle theme
│   │   ├── BottomNav.tsx              # Navigation 5 items (Agent au centre)
│   │   ├── ScoreGauge.tsx             # Jauge SVG circulaire
│   │   ├── StatCard.tsx / BarItem.tsx / AlertItem.tsx
│   │   ├── widgets/
│   │   │   ├── LiveWidgets.tsx        # Widgets données réelles (auto-refresh)
│   │   │   ├── WidgetWrapper.tsx      # Conteneur avec ⚙/📌/✕
│   │   │   └── WidgetDrawer.tsx       # Drawer ajout widgets
│   │   ├── setup/
│   │   │   ├── SetupWizard.tsx        # Onboarding 6 étapes
│   │   │   └── ConfigPage.tsx         # Config Core (tabs) + Skills
│   │   └── marketplace/
│   │       ├── SkillCard.tsx          # Card embossed
│   │       └── SkillDetail.tsx        # Modale détail
│   ├── src/lib/
│   │   ├── tc-api.ts                  # Client findings/alerts/metrics
│   │   ├── tc-agent-api.ts            # Client agent control + ReAct
│   │   ├── use-tc-data.ts             # Hooks auto-refresh
│   │   └── skills-data.ts             # Données marketplace
│   └── src/context/ThemeContext.tsx    # Light/Dark theme
│
├── migrations/                         # 17 fichiers SQL
│   ├── V01__initial.sql ... V13__owner_scope.sql  # IronClaw
│   ├── V14__logs_pipeline.sql          # SOC (logs, sigma_rules, sigma_alerts, cloud_findings)
│   ├── V15__findings_api.sql           # Findings, skill_configs, metrics_snapshots
│   ├── V16__immutable_audit_log.sql    # agent_audit_log + trigger immuabilité
│   └── V17__memory_hmac.sql            # agent_memory + trigger immuabilité
│
├── docker/
│   ├── docker-compose.yml              # 9 services prod (core, dashboard, DB, Redis, Ollama, Nuclei, Trivy, Fluent Bit)
│   ├── docker-compose.dev.yml          # 4 services dev (DB, Redis, Nuclei, Trivy)
│   ├── Dockerfile                      # Multi-stage Rust build
│   ├── Dockerfile.dashboard            # Multi-stage Next.js build
│   └── nginx/nginx.conf               # Reverse proxy
│
├── installer/install.sh                # One-liner installer (618 lignes)
├── .github/workflows/                  # 15 workflows CI/CD
├── scripts/real_scan.py                # Scan réel Nmap + Nuclei → DB
│
└── docs/
    ├── USER_GUIDE.md                   # Guide utilisateur FR (1363 lignes)
    ├── ARCHITECTURE.md                 # Architecture EN (670 lignes)
    ├── THREATCLAW_REACT_ARCHITECTURE.md # Spec Phase 7 (982 lignes)
    ├── openapi.json                    # OpenAPI 3.1.0 spec (23 endpoints)
    └── PROJECT_STATUS.md               # Ce fichier
```

---

## 9. SERVICES EN PRODUCTION

| Service | Port | Status | Image/Binary |
|---------|------|--------|-------|
| ThreatClaw Core | 3000 | Running | Binary Rust natif (`target/debug/threatclaw`) |
| Dashboard Next.js | 3001 | Running | Next.js 14 dev server |
| PostgreSQL 16 | 5432 | Running (healthy) | pgvector/pgvector:pg16 |
| Redis 7 | 6379 | Running (healthy) | redis:7-alpine |
| Ollama | 11434 | Running | ollama (ROCm GPU AMD) |
| Nuclei | — | Running | projectdiscovery/nuclei:latest |
| Trivy | 4954 | Running | aquasec/trivy:latest |
| FileBrowser | 8090 | Running | Binaire standalone |

Machine hôte : 30GB RAM, 16 CPU, 717GB disk (/srv), Debian 13
Ollama stockage : /srv/ollama-data (569GB libres)

---

## 10. PROCHAINES ÉTAPES

### Immédiat (pré-beta)
1. **`threatclaw skill install/remove`** — CLI pour installer/désinstaller un skill + docker compose up/down
2. **Scanners → scheduler** — Le core lance Nuclei/Trivy via ScannerBackend au cron configuré
3. **Wizard → credential vault** — Les tokens (Slack, API keys) saisis dans le wizard sont chiffrés
4. **Rate limiting API** — tower-governor, 5/60 req/min, détection abuse token
5. **Binary integrity** — SHA-256 + GPG + `threatclaw verify-binary` CLI

### Court terme (beta)
6. **SSH executor distant** — executor_ssh.rs avec host key TOFU
7. **pfSense driver** — executor_api.rs premier driver firewall
8. **Skills Docker isolés** — Python skills en containers (network:none, mem 256MB)
9. **Auto-install Ollama** — Le wizard installe Ollama + modèle recommandé
10. **Dashboard responsive** — Adaptation mobile

### Moyen terme (post-beta)
11. **Compliance live scoring** — NIS2/ISO scores depuis les findings réels
12. **Skills connecteurs** — Wazuh, TheHive, Elastic, CrowdSec CTI
13. **Sigma engine live** — Fluent Bit → sigma_engine → sigma_alerts
14. **Skills communautaires** — Process soumission + review + Docker isolé

### V3
15. **Multi-utilisateurs** — RBAC + tenants
16. **mTLS containers** — Certificats entre services Docker
17. **Self-monitoring agent** — Watchdog ThreatClaw watching ThreatClaw
18. **Marketplace payant** — Skills premium

---

## 11. RÉSULTATS DE LA CORRÉLATION IA (PREUVE DE CONCEPT)

### Test 1 — Scan basique (3 findings Nmap)
```
Input:  SSH ouvert :22, HTTP :8080, PPP :3000
Output: severity=LOW, confidence=30%, 2 corrélations (même IP), 0 actions
Durée:  ~2 min (qwen3:14b)
```

### Test 2 — Scénario d'attaque (8 findings multi-sources)
```
Input:  Brute force SSH (150 tentatives) → connexion réussie → mouvement latéral RDP
        + CVE-2024-3094 xz-utils → credentials dark web
Output: severity=CRITICAL, confidence=95%, 3 corrélations :
        - "Brute force SSH → connexion réussie → mouvement latéral RDP vers srv-finance"
        - "CVE-2024-3094 + tentative d'accès → risque compromission serveur finance"
        - "Identifiants dark web + connexion SSH → risque comptes administrateurs"
        3 actions proposées :
        - net-001: Bloquer IP 10.0.0.42 (iptables) → VALIDÉ
        - net-002: Bannir via fail2ban → VALIDÉ
        - pkg-001: Mettre à jour xz-utils → REJETÉ (param mal formaté)
Durée:  ~2 min (qwen3:8b)
```

---

## 12. DIFFÉRENCIATION vs CONCURRENCE

| Feature | OpenClaw | Autres agents | ThreatClaw |
|---------|----------|--------------|------------|
| Soul immuable hash compilé | Non | Non | **Oui** |
| Whitelist commandes anti-injection | Non | Partiel | **12 commandes** |
| XML wrapper outputs cyber | Non | Non | **25+ patterns** |
| Mémoire HMAC anti-poisoning | Non | Non | **Oui** |
| Kill switch multi-trigger | Non | Non | **8 triggers** |
| 4 modes RSSI granulaires | Non | Non | **Oui** |
| Escalade IA 3 niveaux (local→cloud) | Non | Non | **L1→L2→L3 anonymisé** |
| Anonymisation cloud automatique | Non | Non | **IPs/hosts/emails/users** |
| OWASP ASI 2026 conformité | 0/10 | 2-3/10 | **9/9** |
| Corrélation IA multi-sources | Non | Basique | **End-to-end vérifié** |
| Open source sécurisé | Vulnérable | Closed | **Apache 2.0** |
| On-premise 100% | Cloud only | Cloud | **Local Ollama + cloud optionnel** |
| NIS2 natif | Non | Non | **Art.21 mapping** |
| Marketplace skills communautaires | Non | Non | **Architecture prête** |
| Skills optionnels (pas monolithique) | Non | Non | **skill.json + docker-compose.skill.yml** |
| Scanner 3 modes (docker/local/remote) | Non | Non | **ScannerBackend trait** |
| Canaux chat WASM sandboxés | Non | Natif | **Slack/Telegram/Discord/WhatsApp** |
| Infrastructure multi-cibles | Non | Partiel | **[[targets]] + mode par cible** |
| Credential vault Argon2id | Non | Partiel | **AES-256-GCM + HKDF + Argon2id** |
| CI/CD upstream monitoring | Non | Non | **IronClaw auto-check + Dependabot labels** |
| OpenAPI documentation | Non | Partiel | **26 endpoints, OpenAPI 3.1.0** |
| Tests automatisés | Non | Partiel | **590 Rust + 5 e2e Playwright** |

> *"Le seul agent cyber autonome open source qui a pensé sa propre sécurité avant d'implémenter son autonomie."*

# ThreatClaw — Roadmap

## v0.1.0 — Fork & Foundation (mars 2026) ✅

- [x] Fork IronClaw, rebranding complet
- [x] 10 skills Python (vuln-scan, secrets, email-audit, darkweb, phishing, soc-monitor, cloud-posture, report-gen, compliance-nis2, compliance-iso27001)
- [x] Docker composition (13 services)
- [x] 439 tests Python + 3275 tests Rust

## v0.2.0-beta — Architecture Sécurité (mars 2026) ✅

- [x] 5 piliers de sécurité compilés dans le binaire (Soul, Whitelist, XML wrapper, HMAC memory, Kill switch)
- [x] ReAct reasoning loop avec escalade 3 niveaux
- [x] 10 skills officielles en Rust/WASM (sandbox BLAKE3 signé)
- [x] 4 canaux de communication WASM (Slack, Telegram, Discord, WhatsApp)
- [x] Dashboard Next.js (Chrome embossed design)
- [x] Scanner abstraction (Nuclei, Trivy — Docker/local/remote API)
- [x] Multi-target infrastructure (per-server mode/permissions)
- [x] Credential vault (Argon2id + AES-256-GCM + HKDF)
- [x] HITL Slack avec nonce anti-replay
- [x] Fluent Bit syslog (port 514)
- [x] CI/CD (GitHub Actions)

## v0.2.1-beta — Sécurité & Anonymisation (mars 2026) ✅

- [x] 0 CVE dans le binaire (10 patchées : wasmtime 36, aws-lc-sys, serde_yaml_ng)
- [x] Anonymiseur international 17 catégories + custom RSSI rules API
- [x] Whitelist étendue : 12 → 35 commandes (scan, forensique, skill API lookups)
- [x] Dashboard connecté au vrai backend (plus de localStorage)
- [x] Tests connexion canaux (Slack auth.test, Telegram getMe, Discord users/@me)
- [x] Tests connexion skills (AbuseIPDB, Shodan, VirusTotal, CrowdSec, HIBP, Wazuh, DNS)
- [x] Multi-plateforme (Linux, macOS, Windows — installers)
- [x] FAQ 17 questions bilingues FR/EN
- [x] Page Skills vitrine
- [x] Threat Model MITRE ATLAS v2.0 (trust.threatclaw.io)
- [x] Skill Development Guide + template communautaire
- [x] GitHub Sponsors configuré

## v0.2.2-beta — LLM Cyber + Cycle ReAct fonctionnel (mars 2026) ✅

- [x] Stack LLM 3 niveaux : L1 (qwen3:8b SOC), L2 (Foundation-Sec Reasoning), L3 (Cloud)
- [x] Premier cycle ReAct end-to-end réussi (6 observations → CRITICAL 85%)
- [x] Foundation-Sec Reasoning validé pour forensique (MITRE ATT&CK mapping)
- [x] NVD CVE enrichment API (cve_lookup.rs)
- [x] Prompt builder compact (categories au lieu de 35 lignes)
- [x] Fix call_ollama (chat API, thinking mode fallback)
- [x] Docker compose avec Ollama intégré
- [x] Modelfiles custom (Modelfile.threatclaw-l1, Modelfile.threatclaw-l2)

---

## v0.3.0-beta — Config fonctionnelle & Telegram (mars 2026) ✅

### La config dashboard a un effet réel
- [x] **Bridge config DB → backend** : `LlmRouterConfig::from_db_settings()` lit la config LLM depuis la table `settings` à chaque cycle ReAct
- [x] **Bridge channels → env vars** : `config_set_handler` écrit les tokens canaux en env vars pour `inject_channel_credentials`
- [x] **Telegram API directe** : endpoints `/api/tc/telegram/send`, `/poll`, `/status` — lecture token depuis DB ou env var
- [x] **LLM config dynamique** : changer le modèle/URL dans le dashboard → change le modèle au prochain cycle ReAct (plus besoin de restart)
- [x] **NVD API key fonctionnel** : `NvdConfig::from_db()` lit depuis `tc_config_general.nvdApiKey` — 50 req/30s avec clé
- [x] **Tous les champs de config** lus par le backend via DB settings (priorité : env > DB > TOML > défaut)

### Dashboard redesign
- [x] **Dark glass theme** — fond #0a0a0f, glass cards avec backdrop-blur, rouge #d03020
- [x] **Tabs de config dédiés** — 5 onglets (Général, IA/LLM, Canaux, Sécurité, Anonymisation) au lieu d'accordéons
- [x] **Anonymizer UX** — liste scrollable avec maxHeight 400px pour 50+ règles
- [x] **Indicateur connectivité** dans le header (Full/Degraded/Offline) avec auto-refresh 30s
- [x] **Status des modèles LLM** — affichage L1/L2 avec taille, auto-détection dans le panneau IA
- [x] **Telegram intégré** — status bot, envoi message test, dans le panneau Canaux

## v0.4.0 — Enrichissement & Offline (mars 2026) ✅

- [x] Cache CVE PostgreSQL (7 jours TTL) — `lookup_cve_cached()` avec settings store
- [x] MITRE ATT&CK JSON sync — `sync_attack_techniques()` depuis STIX bundle GitHub
- [x] CERT-FR RSS (avis + alertes) — `sync_certfr_alerts()` avec extraction CVE IDs
- [x] Mode offline (Full/Degraded/Offline/AirGap) — indicateur dans TopNav + bundle metadata DB
- [x] Bundle offline script — `scripts/download-offline-bundle.sh` (NVD, CISA KEV, MITRE, Sigma, CrowdSec)
- [x] API enrichissement — `/api/tc/enrichment/{mitre,certfr,status}` endpoints
- [x] Migration V21 — tables cve_cache, mitre_techniques, certfr_alerts, offline_bundle

## v0.5.0 — Docker Plug-and-Play (mars 2026) ✅

- [x] `docker compose up` → tout démarre sans configuration
- [x] Auto-pull des modèles Ollama (L1 qwen3:8b + threatclaw-l1 Modelfile)
- [x] `entrypoint.sh` — attend PostgreSQL, génère/récupère auth token, pull models
- [x] Auth token transparent — généré auto, persisté en DB, partagé via volume `/shared`
- [x] Healthchecks sur tous les services (8/8 : core, dashboard, db, redis, ollama, nuclei, trivy, fluent-bit)
- [x] Docker-compose.yml documenté (commentaires, sections, ports, variables)

## v0.6.0 — Architecture 4 IA + HITL Instruct + Dashboard UX (mars 2026) ✅

### Architecture LLM 4 niveaux (nommage final)
- [x] **L1 — ThreatClaw AI 8B Triage** : qwen3:8b + system prompt SOC, pipeline auto permanent
- [x] **L2 — ThreatClaw AI 8B Reasoning** : Foundation-Sec Reasoning Q8_0, pipeline auto High/Critical
- [x] **L2.5 — ThreatClaw AI 8B Instruct** : Foundation-Sec Instruct Q4_K_M, enrichissement HITL + à la demande
- [x] **L3 — ThreatClaw AI Cloud** : Claude/Mistral API, escalade anonymisée
- [x] Modelfile.threatclaw-l3 (Instruct avec prompt SOC français)
- [x] InstructLlmConfig dans LlmRouterConfig (model, base_url, idle_timeout 5min)
- [x] Mutual exclusion L2/L3 (jamais chargés simultanément, RAM constraint)

### HITL enrichi par Instruct (L2.5)
- [x] `enrich_hitl_with_instruct()` — quand L2 Reasoning dit HITL=true, L2.5 enrichit le message
- [x] Résumé langage naturel + playbook suggéré (3-5 étapes) + impact NIS2
- [x] Timeout 30s — fallback message basique si Instruct indisponible
- [x] `send_hitl_to_telegram()` — HITL via Telegram (en plus de Slack)
- [x] Logs : `hitl_enriched_by: threatclaw_ai_8b_instruct`

### Instruct à la demande RSSI
- [x] `POST /api/tc/instruct/generate` — 4 types : playbook, report, sigma, threat_model
- [x] Audit trail dans settings DB pour chaque génération

### Dashboard UX amélioré
- [x] GlassSelect custom (remplace tous les `<select>` natifs du navigateur)
- [x] SVG logos canaux (Slack, Telegram, Discord) au lieu d'emojis
- [x] Skills catégorisées (5 catégories avec icônes) + config inline + bouton test
- [x] Tab IA : cartes compactes L1/L2/L2.5 avec bouton "Changer" + modèle affiché
- [x] Ollama model install depuis le dashboard + test par modèle
- [x] Cloud API key test (Mistral/Anthropic/OpenAI) avec liste modèles
- [x] Nettoyage Ollama : 4 modèles propres (L1, L2, L3, qwen3:8b base)

---

## v1.0.0 — Production Ready (mars 2026) ✅

### Implémenté
- [x] **Exécution SSH distante** — `executor_ssh.rs` : resolve target → SSH → execute whitelisted command → audit
- [x] **Lookup cible par nom** — `GET /api/tc/targets/resolve/{ref}` : resolve "srv-prod-01" → IP + port + credentials
- [x] **POST /api/tc/ssh/execute** — exécution distante avec validation whitelist + audit log
- [x] **Page Findings dans le dashboard** — filtres sévérité/status, recherche, détail expand, changement status
- [x] **Page Alertes Sigma dans le dashboard** — filtres level/status, matched_fields detail, auto-refresh 15s
- [x] **Navigation enrichie** — Findings + Alertes ajoutés au TopNav
- [x] **Binary integrity verification** — `GET /api/tc/security/verify-binary` : SHA-256 hash comparison
- [x] **Skill install from dashboard** — `POST /api/tc/skills/{id}/install` + bouton Installer

### Restant (post-v1.0 / contributions communautaires)
- [ ] Tests e2e automatisés du cycle complet
- [ ] Détection comportementale ML (compléter Sigma)
- [ ] mTLS entre containers Docker
- [ ] Audit de sécurité tiers (externe)
- [ ] CLI scaffolding (`threatclaw create-skill`)
- [ ] SDK Python sur PyPI (`threatclaw-sdk`)
- [ ] Whitelist dynamique (skills déclarent leurs actions dans skill.json)
- [ ] Planning par skill (au lieu du scheduler global)

## Post v1.0

- [ ] Marketplace/registry de skills (distribution OCI)
- [ ] Leaderboard contributeurs
- [ ] Skills premium (EDR, SIEM avancé, threat intel premium)
- [ ] Anonymiseur base64/hex (contournement encodage)
- [ ] Rate limiting API (tower-governor)

---

*Dernière mise à jour : 22 mars 2026*
*Version actuelle : 1.0.0-beta*

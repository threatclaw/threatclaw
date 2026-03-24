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

---

## v1.1.0 — Bot conversationnel + Canaux on-premise (mars 2026) ✅

### Bot conversationnel Telegram
- [x] **Command Interpreter** : parse langage naturel → action structurée via L1 LLM
- [x] **14 actions** : scan, lookup, block, playbook, report, sigma, react, status, findings, alerts...
- [x] **Fallback keyword** : si LLM indispo, parsing par mots-clés
- [x] **Mémoire conversationnelle** : historique 10 échanges par chat, contexte injecté dans L1
- [x] **Résolution de pronoms** : "bloque la" → "bloque 192.168.1.50" (depuis last_target)
- [x] **Suggestions follow-up** : après lookup → "Bloquer cette IP ?", après scan → "Générer un playbook ?"
- [x] **HITL confirmation** : actions de remédiation demandent oui/non avant exécution
- [x] **`POST /api/tc/command`** : API channel-agnostic (réutilisable pour Slack, Signal)

### Canaux on-premise (NIS2/souveraineté)
- [x] **Mattermost** : webhooks Slack-compatible + boutons interactifs Approve/Reject
- [x] **Ntfy** : push notifications ultra-léger (~3MB) + 3 boutons HTTP actions
- [x] **Gotify** : notifications push only (pas de HITL)
- [x] **HITL callback** : `POST /api/tc/hitl/callback` universel pour boutons Mattermost/Ntfy

## v1.2.0 — Intelligence Engine + Notification Router (mars 2026) ✅

### Intelligence Engine (le cerveau SOC)
- [x] **Cycle automatique 5 min** : collecte findings + alertes → groupe par asset → score → décide
- [x] **Score de situation global** (0-100) avec 4 niveaux : Silence / Digest / Alert / Critical
- [x] **Corrélation** : kill chain (finding + alert même asset), exploit connu, attaque active
- [x] **Scan logs pour IoCs** : extrait IPs/URLs/hashes des logs bruts PostgreSQL
- [x] **Cross-reference automatique** : OpenPhish, URLhaus, ThreatFox, MalwareBazaar
- [x] **Auto-création findings** quand menace détectée dans les logs
- [x] **Auto-start au boot** : démarre automatiquement au premier healthcheck

### Enrichissement (12 sources)
- [x] **NVD NIST** : CVE base + cache 7j (clé optionnelle 50 req/30s)
- [x] **CISA KEV** : CVEs activement exploitées → auto-escalade CRITICAL
- [x] **EPSS** : probabilité exploitation 30j → reprioritise les CVEs
- [x] **MITRE ATT&CK** : 700+ techniques, sync STIX mensuelle
- [x] **CERT-FR** : alertes ANSSI françaises, sync RSS quotidienne
- [x] **GreyNoise** : bruit vs attaque ciblée (réduit faux positifs)
- [x] **IPinfo** : géolocalisation + ASN des IPs source
- [x] **OpenPhish** : URLs de phishing (~500, sync 6h)
- [x] **ThreatFox** : IoCs C2/domaines malveillants (clé abuse.ch)
- [x] **MalwareBazaar** : hash malware (clé abuse.ch)
- [x] **URLhaus** : URLs malware (clé abuse.ch)
- [x] **CrowdSec CTI** : réputation IP communautaire (clé)
- [x] **OTX AlienVault** : IoCs communauté (clé gratuite)

### Priority Score Engine
- [x] **CVSS + KEV + EPSS + GreyNoise + ThreatFox** → score composite unique
- [x] CVSS 9.8 + pas KEV + EPSS 2% → High (pas Critical — pas exploité)
- [x] CVSS 5.5 + EPSS 94% → Critical (faible CVSS mais ciblé activement)

### Notification Router
- [x] **Matrice routing** : niveau × canal (digest→email, alert→telegram, critical→all)
- [x] **Cooldown** : Critical 15min, Alert 30min, Digest 12h (pas de spam)
- [x] **Dashboard Config > Notifications** : matrice cliquable, boutons test, situation live

### Dashboard Enrichissement
- [x] **Config > Enrichissement** : 12 sources avec toggle on/off, status, sync, aide contextuelle
- [x] **Champ clé API** pour les sources qui en ont besoin
- [x] **Badge "Clé optionnelle"** vs **"Clé requise"** vs **"Actif (à la demande)"**

## v1.3.0 — Production Safeguards + Pipeline réel (mars 2026) ✅

### Production Safeguards
- [x] **Déduplication findings** : même titre + asset + 24h → pas de doublon
- [x] **Notification cooldown** : escalade level always sends, même level = cooldown
- [x] **IoC cache 24h** : GreyNoise/IPinfo/EPSS cachés, pas re-querys à chaque cycle
- [x] **Rate limiter enrichissement** : max 15 lookups externes par cycle 5min
- [x] **Validation LLM robuste** : "LOW|MEDIUM|HIGH|CRITICAL" → picks CRITICAL, 85.0 → 0.85

### Parsing LLM robuste
- [x] **Two-phase parsing** : strict serde d'abord, flexible Value ensuite
- [x] **Coercion de types** : objets → strings, pourcentages → décimales, français → enum
- [x] **Cloud JSON instruction** : Mistral/Anthropic reçoivent "Réponds en JSON"

### Pipeline réel L1→L2→L3
- [x] **CRITICAL → L2 obligatoire** : chain-of-thought forensique sur tout incident critique
- [x] **L2 utilise le bon modèle** : threatclaw-l2 (Foundation-Sec Reasoning), pas L1
- [x] **Prompt forensique enrichi** : root cause, kill chain, MITRE, impact, actions immédiates
- [x] **L3 Cloud** : Mistral/Anthropic avec anonymisation 23 data points, instruction JSON

### Test Scenarios (6 scénarios réalistes)
- [x] **SSH Brute Force** : 13 auth logs depuis IP Tor réelle (185.220.101.42)
- [x] **Log4Shell** : 3 HTTP logs avec JNDI payloads + CVE-2021-44228
- [x] **Phishing** : 4 proxy/email logs avec URLs phishing
- [x] **Mouvement latéral** : SSH + sudo escalade + payload download
- [x] **C2 Communication** : 15 DNS/HTTP beacon pattern 60s
- [x] **Intrusion complète** : kill chain 6 phases (recon → exploit → shell → creds → lateral → exfil)
- [x] **Dashboard /test** : page dédiée, score live, pipeline réel (PAS de findings pré-écrits)
- [x] **Vrais logs en DB** : `INSERT INTO logs` direct (même format que Fluent Bit)
- [x] **Vrais alerts Sigma** : `INSERT INTO sigma_alerts` avec rule stubs

### Auto-start + Docker
- [x] **Intelligence Engine auto-start** au boot (premier healthcheck)
- [x] **Bot Telegram auto-start** si configuré
- [x] **Entrypoint pull les 3 modèles** : L1 (5.2GB) + L2 (8.5GB) + L3 (4.9GB)

---

## Restant (post-release / contributions communautaires)

### Technique
- [ ] Tests e2e automatisés du cycle complet (CI)
- [ ] Détection comportementale ML (compléter Sigma)
- [x] **mTLS** : script generate-certs.sh (CA + certs par service)
- [x] **Skill scheduler** : planning par skill avec cron configurable (API GET/POST /api/tc/scheduler)
- [ ] Barre d'avancement download modèles dans le wizard onboarding
- [x] **L1 upgradé** : qwen3:8b → qwen3.5:9b (256K context, meilleur instruction following)

### Skills V2 — Nouveaux outils (voir SKILLS_CATALOG.md)
- [ ] **Éphémères P1** : semgrep (SAST), checkov (IaC), trufflehog (secrets git), syft (SBOM), grype (container CVE), ZAP (DAST web), nmap (réseau)
- [ ] **Permanents** : suricata (IDS/IPS réseau), falco (runtime security containers)
- [ ] **Connecteurs** : defectdojo (vuln mgmt), dependency-track (SBOM lifecycle)
- [ ] **Éphémères P2** : httpx, subfinder, docker-bench-security
- [x] **Whitelist dynamique** : `CommandRegistry` (core + skill.json), `validate_remediation()` unifié, anti-injection sur dynamiques
- [ ] Système de modes d'exécution dans skill.json : `ephemeral` / `persistent` / `connector`
- [ ] Dashboard : badges mode, "Activer" simplifié, technique cachée par défaut
- [x] ~~Corriger `skill-appsec`~~ (pas de skill.json, déjà absent du catalog)
- [x] ~~Retirer `skill-secrets-audit`~~ (skill.json.disabled — doublon de skill-secrets)

### Fine-tuning L1 — ThreatClaw AI 8B Triage spécialisé

**Objectif** : Le L1 ne devient pas "meilleur en cyber" — il devient **expert ThreatClaw**.
Un modèle d'orchestration qui sait piloter parfaitement l'application.

**Ce que le fine-tuning enseigne au L1 :**
- [ ] Les 44 commandes whitelist exactes (net-001, usr-001, ssh-001...)
- [ ] Le format JSON ThreatClaw (severity enum, confidence float 0-1, action_ids valides)
- [ ] Les 12 sources d'enrichissement et comment les référencer
- [ ] Les modes RSSI et quand escalader vers L2
- [ ] Les skills disponibles et quand les suggérer
- [ ] Le champ `context_for_reasoning` structuré pour L2 Forensique
- [ ] Le nommage ThreatClaw (pas de termes génériques)

**Prérequis** : Les skills V2 doivent être implémentés d'abord (le modèle doit connaître les outils disponibles). Chaque ajout de skill = re-fine-tuning léger (LoRA incrémental).

**Pipeline de fine-tuning :**
1. Générer 500-1000 exemples synthétiques via Claude API
   - Input : alertes brutes variées (SSH, CVE, phishing, C2, lateral...)
   - Output : JSON ThreatClaw parfait avec context_for_reasoning
   - Couvrir tous les action_ids, sévérités, skills
2. Fine-tuning LoRA sur qwen3.5:9b
   - Hardware : Mac M3 Pro (MLX) ou GPU cloud ~50€
   - Durée : 4-8h
   - Résultat : adapter GGUF ~50-200 MB
3. Intégrer dans Ollama via Modelfile
   - `FROM qwen3.5:9b` + `ADAPTER threatclaw-lora.gguf`
   - Tester sur les 6 scénarios de test
   - Mesurer : % JSON valide, % action_ids corrects, temps de réponse
4. Distribuer via models.threatclaw.io (CloudFlare R2)

**Gain attendu :**
- JSON valide : 90% → 99%+ (moins de retries, pipeline plus stable)
- Actions whitelist correctes : ~70% → 95%+ (moins de rejets)
- Temps de réponse : -20% (moins de tokens perdus en formatting)
- Qualité L2 : meilleure car reçoit un contexte structuré parfait

**Collecte de données pour amélioration continue :**
- [x] **Table `llm_training_data`** : migration V22, prompt_hash, response_json, parsing_ok, severity, confidence, cycle_duration
- [x] **Logging automatique** de chaque appel L1 dans le ReAct runner (on-premise, jamais envoyé)
- [ ] Script `scripts/generate-training-data.py` (Claude API → JSONL)
- [ ] Re-fine-tuning après chaque ajout majeur de skill

**Timeline** : Après implémentation des skills V2 (les outils doivent exister pour que le modèle les connaisse).

### Graph Intelligence — Investigation déterministe (voir docs/GRAPH_INTELLIGENCE.md)

**Phase 1 — Fondation Graph (V2.0) ✅**
- [x] **Apache AGE** compilé et installé dans PostgreSQL 16 (Cypher queries actives)
- [x] **Schéma STIX 2.1** : 11 types de nœuds + 15 types d'arêtes dans `threat_graph`
- [x] **Cypher queries** : attack paths, kill chain, corrélation, investigation context
- [x] **Dockerfile.db** : image custom pgvector + AGE (build automatique Docker)
- [x] **Graph sync** : `sync_graph_from_db()` synchronise targets/alerts/findings → graph à chaque cycle
- [x] **API Graph** : `POST /api/tc/graph/query`, `GET /graph/context/{id}`, `GET /graph/attackers/{id}`

**Phase 2 — Investigation Graphs (V2.1) ✅**
- [x] **7 investigation graphs** prédéfinis (SSH brute, CVE, phishing, C2, lateral, malware, DNS exfil)
- [x] **Executor déterministe** : chaque étape (enrich → correlate → map MITRE → find paths → reason)
- [x] **13 mappings MITRE** automatiques (keyword → technique ID → nœud graph)
- [x] **Câblé dans Intelligence Engine** : chaque alerte match un graph → investigation auto
- [x] `GET /api/tc/graph/investigations` — liste les 7 templates

**Phase 3 — Graph Intelligence avancé ✅**
- [x] **Confidence Scoring dynamique** : score 0-100 STIX via 7 facteurs (GreyNoise, géo, historique graph, CVE/EPSS, KEV, heure, corroboration). API `/api/tc/graph/confidence/ip/{ip}` + `/confidence/cve/{cve_id}`. Câblé dans Intelligence Engine.
- [x] **Lateral Movement Detection** : 3 détecteurs (chaînes multi-sauts, fan-out, path vers critiques) + détection vulnérabilités partagées. API `/api/tc/graph/lateral`. Câblé dans Intelligence Engine.
- [x] **Note Graph / mémoire équipe** : STIX 2.1 Note + ANNOTATES edges. CRUD API (`/api/tc/graph/notes`). Notes injectées dans `build_investigation_context()` pour L2 Reasoning. Supprimer/lister/filtrer par IP/asset.
- [x] **Course of Action automatique** : 5 MITRE mitigations (M1036, M1035, M1051, M1049, M1037) + 12 technique mappings. `seed_default_mitigations()`, `find_coa_for_cve/asset()`. API `/api/tc/graph/coa/seed`, `/coa/cve/{id}`, `/coa/asset/{id}`.
- [ ] Dashboard : visualisation du graph d'attaque (D3.js ou Cytoscape.js)

**Phase 4 — Intelligence CTI ✅**
- [ ] Connecteur OpenCTI (ingestion STIX feeds via GraphQL)
- [ ] Connecteur TAXII pour feeds CTI communautaires
- [ ] Suggestions mitigation auto via MITRE D3FEND
- [x] **Campaign Detection** : groupement par pays/ASN, STIX Campaign nodes + PART_OF edges. Câblé dans Intelligence Engine. API `/api/tc/graph/campaigns`.
- [x] **Identity Graph (UBA)** : User/LOGGED_IN/ESCALATED nodes/edges, sync depuis auth logs, 3 détecteurs (fan-out, failed clusters, escalation chains). API `/api/tc/graph/identity`.

**Phase 5 — Proactif ✅**
- [x] **Blast Radius automatique** : 3 hops (shared IPs → shared CVEs → shared users), score d'impact pondéré par criticité. API `/api/tc/graph/blast-radius/{asset_id}`.
- [x] **Attack Path Prediction** : 3 patterns (external→pivot→critical, CVE chains, direct exposure), recommendations auto. API `/api/tc/graph/attack-paths`.
- [x] **Supply Chain Risk** : Vendor→Software→Asset→CVE model, rapport NIS2 Article 21. API `/api/tc/graph/supply-chain`, `/supply-chain/nis2`.
- [x] **Threat Actor Profiling** : clustering par pays/ASN, matching 7 APT connus (APT28, APT29, Lazarus, APT41, Sandworm, Turla, MuddyWater). API `/api/tc/graph/threat-actors`.

**Phase 6 — Collectif & GNN (V4)**
- [ ] **Sighting / mémoire incidents** : STIX Sighting, historique des IoCs sur le temps long
- [ ] **Opinion Graph collectif** : STIX Opinion, intelligence collective anonymisée (opt-in)
- [ ] **Federated Graph** : réseau d'instances ThreatClaw partageant IoCs via TAXII (NIS2 Article 26)
- [ ] Graph Neural Network pour classification flux réseau (Suricata/Zeek)
- [ ] Détection anomalies comportementales (complémente Sigma)

### Bot Cloud-Assisted — Intelligence conversationnelle souveraine

**Principe** : Le pipeline automatique (alertes, enrichissement, notifications) reste 100% local, toujours.
Le cloud intervient UNIQUEMENT quand le RSSI parle, pour comprendre et reformuler.

```
Pipeline auto 24/7  →  100% L1/L2 local (jamais de cloud)
RSSI parle          →  Cloud comprend → Local exécute → Cloud reformule (si activé)
```

- [ ] **Cloud Intent Parser** : message RSSI → Cloud API → plan JSON structuré (intent + steps)
- [ ] **Plan Executor** : exécute le plan localement (graph, enrichissement, logs, L2 Reasoning)
- [ ] **Anonymized Summary Builder** : résultats locaux → anonymiseur 17 catégories → Cloud reformule en français fluide
- [ ] **3 modes conversation** : `local` (air-gap) / `cloud_assisted` (hybride) / `cloud_direct` (existant L3)
- [ ] **Config dashboard toggle** : choix du mode conversation dans Config > IA/LLM
- [ ] **Zéro donnée réelle vers le cloud** : IPs, assets, credentials, logs, CVEs spécifiques = jamais envoyés

### Communauté / Outillage
- [ ] CLI scaffolding (`threatclaw create-skill`)
- [ ] SDK Python sur PyPI (`threatclaw-sdk`)
- [ ] Marketplace/registry de skills (distribution OCI)
- [ ] Mirror modèles IA sur CloudFlare R2 (`models.threatclaw.io`)
- [ ] Audit de sécurité tiers (externe)

---

*Dernière mise à jour : 24 mars 2026*
*Version actuelle : 1.4.0-beta (Graph Intelligence Phase 3-5)*
*Modèle business : prestation (CyberConsulting.fr installe chez les clients) — pas de freemium/SaaS*

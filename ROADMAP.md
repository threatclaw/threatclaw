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

## Architecture Skills Unifiée

**Tout est une Skill.** Le type est un champ dans `skill.json` :

```
type: "tool"         → ThreatClaw installe et lance l'outil (Docker)
type: "connector"    → ThreatClaw se branche sur un outil existant du client
type: "enrichment"   → API externe de threat intelligence (read-only)
```

**Dashboard** : une seule page "Skills" avec filtres [Tous] [Outils] [Connecteurs] [Enrichissement].
Skills, Cibles et Tests fusionnés dans Config. Lien direct "Skills" depuis le dashboard home.

**Skills actives par défaut (0 config)** : NVD, CISA KEV, EPSS, MITRE ATT&CK, CERT-FR, OpenPhish, Sigma Rules, Intelligence Engine, Graph STIX 2.1.

---

## Restant

### Asset Resolution Pipeline (prochaine priorité)

**Principe** : quand plusieurs sources découvrent le même asset, ThreatClaw fusionne intelligemment.
Résolution par priorité : **MAC > hostname > IP**. Jamais de doublon.

```
Nmap découvre IP → pfSense ajoute MAC+hostname → AD ajoute FQDN+OU+users → 1 seul nœud Asset
```

- [x] **`resolve_asset()`** : recherche par MAC, puis hostname, puis IP. Merge si trouvé, crée sinon. 7 tests.
- [x] **Gestion DHCP** : IP change → update via MAC (clé stable). Clear IP si >24h.
- [x] **Détection conflits** : même hostname + MAC différent → alerte "machine inconnue" + ResolutionAction::Conflict
- [x] **Score confiance asset** : monte avec chaque source (nmap=0.15, DHCP=0.25, AD=0.30, pfSense=0.25, proxmox=0.20)
- [x] **Modèle Asset enrichi** : id, mac, hostname, fqdn, ip, os, ou, vlan, vm_id, ports, sources[], confidence

### Skills V2 — Outils (type: "tool")

Les outils que ThreatClaw installe et lance dans Docker.

**P1 — Sécurité offensive/défensive :**
- [x] **nmap** : discovery réseau via tokio::process (local ou Docker), parse XML, MAC+hostname+IP+OS+ports → Asset Resolution Pipeline. Anti-injection sur les targets.
- [x] **semgrep** : SAST via Docker, parse JSON → findings. Parser teste.
- [x] **checkov** : IaC audit via Docker, parse failed_checks → findings.
- [x] **trufflehog** : secrets git via Docker, parse JSONL, verified=CRITICAL.
- [x] **syft** : SBOM via Docker, compte les packages, finding informatif.
- [x] **grype** : CVE container via Docker, parse matches, fixed_in. Parser teste.
- [x] **ZAP** : DAST scan web via Docker (parser pret, execution a valider)

**P2 — Réseau/monitoring :**
- [ ] **suricata** : IDS/IPS réseau (permanent)
- [ ] **falco** : runtime security containers (permanent)
- [x] **httpx** : probe HTTP rapide via Docker (projectdiscovery/httpx)
- [x] **subfinder** : enumeration sous-domaines via Docker (projectdiscovery/subfinder)
- [x] **docker-bench-security** : audit Docker CIS via Docker, parser [WARN], skill + API

### Skills V2 — Connecteurs (type: "connector")

Les outils du client auxquels ThreatClaw se branche.

**P1 — Discovery SI (comment ThreatClaw cartographie) :**
- [x] **Active Directory / LDAP** : real ldap3 crate, LDAPS, paged search, computers/users/groups/OUs/admins, userAccountControl bitmask, feeds Asset Resolution + Identity Graph
- [x] **pfSense / OPNsense API** : real REST API (pfSense v2 + OPNsense built-in), ARP/DHCP/interfaces/VLANs/rules, VLAN extraction from interface names, feeds Asset Resolution
- [x] **Proxmox API** : real REST API (PVEAPIToken auth), VMs/LXC/nodes, feeds Asset Resolution. API: POST /connectors/proxmox/sync
- [ ] **VMware / ESXi API** : VMs, vSwitches, datastores

**P2 — Outils existants du client :**
- [x] **Wazuh** : real REST API (JWT auth), import alertes level>=7, MITRE auto (le client a déjà un SIEM)
- [ ] **Elastic SIEM** : import alertes
- [x] **GLPI** : import assets depuis CMDB existant (le client a déjà un inventaire)
- [x] **DefectDojo** : export findings (vuln management)
- [ ] **Dependency-Track** : SBOM lifecycle
- [x] **Fortinet API** : firewall enterprise

**P3 — Actions (le client veut que ThreatClaw agisse) :**
- [x] **pfSense write** : bloquer IP via REST API v2 (POST /firewall/rule), regle auto ThreatClaw, reversible
- [x] **OPNsense write** : bloquer IP via API (POST /firewall/filter/addRule + apply), reversible
- [x] **AD write** : desactiver compte compromis via LDAP (set userAccountControl ACCOUNTDISABLE), reversible
- [x] **GLPI write** : créer ticket depuis finding

### Skills V2 — Enrichissement (type: "enrichment")

Sources de threat intelligence. Actives par défaut si gratuites.

**Actives par défaut (0 config) :**
- [x] NVD NIST, CISA KEV, EPSS, MITRE ATT&CK, CERT-FR, OpenPhish

**Activées si clé API fournie :**
- [x] GreyNoise, CrowdSec CTI, AbuseIPDB, OTX AlienVault, ThreatFox, MalwareBazaar, URLhaus
- [x] **Shodan** : exposition internet
- [x] **VirusTotal** : analyse fichiers/URLs
- [x] **HIBP** : comptes compromis

### Parcours client (onboarding)

```
Étape 1 — docker compose up (5 min)
  → 9 skills actives, 0 config. SOC fonctionnel.

Étape 2 — Discovery (10 min)
  → Wizard : "Votre range réseau ? Vous avez un AD ? Un pfSense ?"
  → Activation des skills connectors
  → Graphe peuplé automatiquement (Asset Resolution Pipeline)

Étape 3 — Choix du RSSI (5 min)
  → "Vous avez déjà un scanner ?" → Oui: skill-nessus connector / Non: skill-nuclei tool
  → "Vous avez déjà un SIEM ?" → Oui: skill-wazuh connector / Non: Sigma rules (actif par défaut)
  → "Vous avez un CMDB ?" → Oui: skill-glpi connector / Non: ThreatClaw = votre CMDB

Étape 4 — Automatique (continu)
  → Intelligence Engine cycle 5 min
  → Nouveaux assets détectés automatiquement
  → "Machine inconnue sur VLAN 30" → alerte
```

### Dashboard — Réorganisation menu

- [x] **Fusionner** Skills, Cibles et Tests dans Config (onglets) + Licence tab
- [x] **Lien direct** "Skills" depuis la page d'accueil dashboard
- [x] **Page Skills unifiée** : filtres [Tous] [Outils] [Connecteurs] [Enrichissement]
- [x] **Chaque skill** : logo + toggle ON/OFF + status + config inline
- [ ] Dashboard : visualisation du graph d'attaque (D3.js ou Cytoscape.js)

### Technique complété
- [x] **mTLS** : script generate-certs.sh (CA + certs par service)
- [x] **Skill scheduler** : planning par skill avec cron configurable
- [x] **L1 upgradé** : qwen3:8b → qwen3.5:9b (256K context)
- [x] **Whitelist dynamique** : `CommandRegistry` (core 44 + skill.json)
- [ ] Tests e2e automatisés du cycle complet (CI)
- [ ] Barre d'avancement download modèles dans le wizard onboarding

### Fine-tuning L1

**Objectif** : Le L1 devient **expert ThreatClaw** — pas juste meilleur en cyber.
**Timeline** : Après Skills V2 (le modèle doit connaître les outils disponibles).

- [ ] Générer 500-1000 exemples synthétiques (Claude API → JSONL)
- [ ] Fine-tuning LoRA sur qwen3.5:9b (~4-8h, Mac M3 Pro ou GPU cloud ~50€)
- [ ] Intégrer dans Ollama (`FROM qwen3.5:9b` + `ADAPTER threatclaw-lora.gguf`)
- [ ] Distribuer via models.threatclaw.io (CloudFlare R2)
- [x] Table `llm_training_data` + logging automatique chaque appel L1

### Graph Intelligence

**Phase 1-5 : ✅ COMPLÉTÉ** (voir sections ci-dessus)

### Analyse Comportementale — 3 couches de détection

Chaque couche attrape ce que les autres ratent :
```
Attaque connue (SSH brute force)     → Sigma ✅  Stats ✅  ML ✅
Michel à 2h du matin sur le backup   → Sigma ❌  Stats ✅  ML ✅
Nouveau malware jamais vu            → Sigma ❌  Stats ❌  ML ✅
```

**Couche 1 — Règles Sigma ✅ (déjà en place)**
- Détection déterministe des patterns connus
- 7 investigation graphs câblés dans l'Intelligence Engine

**Couche 2 — Baselines comportementales (prochaine priorité)**
Profil "normal" par utilisateur, calculé sur 30 jours glissants. Alerte quand déviation.

- [x] **`behavior_baseline.rs`** : calcul baseline 30j par User (heures, jours, IPs, assets, VLANs, volume réseau, DNS)
- [x] **`behavior_scorer.rs`** : score déviation 0-100 par événement vs baseline
- [ ] **7 détections** :
  - Horaire anormal (connexion hors heures habituelles)
  - Lieu/IP anormal (IP ou VLAN jamais utilisé)
  - Accès inhabituel (asset jamais accédé par ce user)
  - Volume réseau anormal (x10 la moyenne = exfiltration probable)
  - DNS suspect (volume, entropie, DGA pattern)
  - Escalade de privilèges (user standard fait action admin)
  - Kill chain multi-étapes (corrélation graph : 3+ anomalies sur même user en <2h)
- [x] **Période d'apprentissage** : 7 jours sans alertes pour un nouveau user (le profil se construit)
- [x] **Stockage baseline** sur le noeud User dans le graphe (usual_hours, usual_ips, usual_assets, avg_bytes...)
- [x] **API** : `GET /api/tc/graph/behavior/{username}` — profil comportemental d'un user
- [x] **Câblage** Intelligence Engine : scorer chaque login/événement vs baseline

~500 lignes Rust, pas de ML, pas de GPU. Juste des moyennes + écarts-types.
Les baselines générées servent aussi de données d'entraînement pour la couche 3.

**Couche 3 — Machine Learning (12+ mois, quand les données existent)**
Apprend des patterns invisibles aux règles et aux stats.

- [ ] **Prérequis** : 6 mois de baselines sur des clients en production
- [ ] Graph Neural Network pour classification flux réseau (Suricata/Zeek)
- [ ] Détection DGA (Domain Generation Algorithm) par analyse entropie
- [ ] Clustering comportemental (grouper les users par profil, détecter les outliers)
- [ ] Modèle : Python (scikit-learn ou PyTorch), entraîné offline, inférence locale

**Phase 6 — Collectif (V4)**
- [ ] **Sighting / mémoire incidents** : STIX Sighting, historique IoCs long terme
- [ ] **Opinion Graph collectif** : STIX Opinion, intelligence collective anonymisée (opt-in)
- [ ] **Federated Graph** : réseau d'instances ThreatClaw partageant IoCs via TAXII (NIS2 Article 26)

### Bot Cloud-Assisted — Intelligence conversationnelle souveraine

```
Pipeline auto 24/7  →  100% L1/L2 local (jamais de cloud)
RSSI parle          →  Cloud comprend → Local exécute → Cloud reformule (si activé)
```

- [x] **Cloud Intent Parser** : message RSSI → Cloud API → plan JSON structuré
- [x] **Plan Executor** : exécute localement (graph, enrichissement, logs, L2 Reasoning)
- [ ] **Anonymized Summary Builder** : anonymiseur → Cloud reformule en français fluide
- [ ] **3 modes conversation** : `local` / `cloud_assisted` / `cloud_direct`

### WinRM Executor — Support Windows natif (V2)

- [ ] **executor_winrm.rs** : connexion WinRM via container PowerShell Core
- [ ] **Cible Windows** : champ os=windows, protocol=winrm dans la config target
- [ ] **skill-windows-hardening** : script PowerShell audit (firewall, patches, comptes, services)
- [ ] **skill-ad-audit** (PowerShell) : comptes admin, delegations Kerberos, policies MDP, GPO

### ThreatClaw Agent — Surveillance temps reel (V2-V3)

**Binaire Rust read-only, ~5 MB, multiplateforme. Voir docs/AGENT_ARCHITECTURE.md**

- [ ] **Agent V1 Linux** : collecte metriques + connexions + auth logs, WebSocket TLS sortant
- [ ] **Enrolement par token** : certificat TLS mutuel, token 24h a usage unique
- [ ] **Format STIX 2.1** : events en Observed Data, batch 10s ou immediat si critique
- [ ] **Service systemd** : demarrage auto, reconnexion auto
- [ ] **Agent V1 Windows** : Windows Service, Event Log, Performance Monitor
- [ ] **Dashboard agents** : liste, status online/offline, metriques temps reel
- [ ] **Agent ARM64** (V3) : Raspberry Pi, serveurs ARM
- [ ] **Agent macOS** (V3) : Apple Silicon

**REGLE ABSOLUE : l'agent est READ-ONLY. Pas de remote execution. Jamais.**

### Communauté / Outillage
- [ ] CLI scaffolding (`threatclaw create-skill`)
- [ ] SDK Python sur PyPI (`threatclaw-sdk`)
- [ ] Marketplace/registry de skills (distribution OCI)
- [ ] Mirror modèles IA sur CloudFlare R2 (`models.threatclaw.io`)
- [ ] Audit de sécurité tiers (externe)

---

*Dernière mise à jour : 24 mars 2026*
*Version actuelle : 1.4.0-beta (Graph Intelligence Phase 3-5)*
*Licence : AGPL v3 + Commercial (dual-licence)*
*Modèle business : prestation (CyberConsulting.fr installe chez les clients)*

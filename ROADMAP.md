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

## v0.4.0 — Enrichissement & Offline

- [ ] Cache CVE pgvector (7 jours)
- [ ] MITRE ATT&CK JSON sync (mensuelle)
- [ ] CERT-FR RSS (quotidienne)
- [ ] Mode offline complet (Full/Degraded/Offline/AirGap)
- [ ] Bundle offline (CVEs CVSS≥7, ATT&CK, CrowdSec IPs, Sigma rules)
- [ ] Script download-offline-bundle.sh
- [ ] Dashboard indicateur offline + âge du bundle

## v0.5.0 — Docker Plug-and-Play

- [ ] `docker compose up` → tout démarre sans configuration
- [ ] Auto-pull des modèles Ollama au premier démarrage
- [ ] Migrations Refinery robustes (IF NOT EXISTS)
- [ ] Auth token transparent (généré et injecté automatiquement)
- [ ] Healthchecks sur tous les services
- [ ] Documentation docker-compose.yml commentée

## v1.0.0 — Production Ready

- [ ] Exécution SSH distante (executor_ssh.rs) — agir sur les cibles
- [ ] Lookup cible par nom dans le ReAct (resolve "srv-prod-01" → IP + credentials)
- [ ] Whitelist dynamique (skills déclarent leurs actions dans skill.json)
- [ ] Planning par skill (au lieu du scheduler global)
- [ ] Page alertes/findings (quand le scheduler produit des findings réels)
- [ ] Tests e2e automatisés du cycle complet
- [ ] Détection comportementale ML (compléter Sigma)
- [ ] mTLS entre containers Docker
- [ ] Audit de sécurité tiers
- [ ] CLI scaffolding (`threatclaw create-skill`)
- [ ] SDK Python sur PyPI (`threatclaw-sdk`)
- [ ] Binary integrity verification (`threatclaw verify-binary`)

## Post v1.0

- [ ] Marketplace/registry de skills (distribution OCI)
- [ ] Leaderboard contributeurs
- [ ] Skills premium (EDR, SIEM avancé, threat intel premium)
- [ ] Anonymiseur base64/hex (contournement encodage)
- [ ] Rate limiting API (tower-governor)

---

*Dernière mise à jour : 22 mars 2026*
*Version actuelle : 0.3.0-beta*

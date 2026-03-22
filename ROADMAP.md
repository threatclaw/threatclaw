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

## v0.3.0-beta — Config fonctionnelle & Telegram (À FAIRE — PRIO ABSOLUE)

### La config dashboard doit avoir un effet réel
- [ ] **Bridge config DB → backend** : le backend Rust lit les tokens canaux depuis la table `settings` (pas seulement le credential vault IronClaw)
- [ ] **Telegram interactif** : token configuré dans le dashboard → canal actif → commandes via chat ("scan 192.168.1.107") → résultats renvoyés
- [ ] **LLM config dynamique** : changer le modèle/URL dans le dashboard → change le modèle utilisé par le ReAct cycle (pas seulement les env vars)
- [ ] **NVD API key fonctionnel** : configuré dans dashboard → lu par cve_lookup.rs
- [ ] **Tous les champs de config** doivent être lus par le backend, pas juste sauvés en DB

### Dashboard redesign
- [ ] **Design identique au site vitrine** (dark, glass cards, rouge #d03020)
- [ ] **Pages de config dédiées** au lieu d'accordéons (bouton Configurer → page séparée)
- [ ] **Anonymizer UX** — page scrollable pour 50+ règles, pas d'ascenseur
- [ ] **Indicateur connectivité** dans le header (Full/Degraded/Offline)
- [ ] **Status des modèles LLM** (L1 chargé, L2 disponible, L3 config)

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
*Version actuelle : 0.2.2-beta*

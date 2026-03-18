# ThreatClaw — Roadmap

## Phase 1 — Fork & Setup

- [x] 1.1 Cloner IronClaw depuis GitHub
- [x] 1.2 Renommage branding (ironclaw → threatclaw)
- [x] 1.3 Mettre à jour Cargo.toml et fichiers de config
- [x] 1.4 Vérifier que `cargo check` compile (OK — 0 erreurs)
- [x] 1.5 Créer docker-compose.yml (core + db + tous services)
- [x] 1.6 Créer docker-compose.dev.yml (stack dev allégée)
- [x] 1.7 Créer la structure dossiers skills/ avec interface standard (10 skills)
- [x] 1.8 Créer le CLAUDE.md projet (copie depuis docs/)
- [x] 1.9 Créer README.md professionnel
- [x] 1.10 Initialiser le repo Git local
- [x] 1.11 Premier commit structuré (828 fichiers, 313K lignes)

## Phase 2 — Skills Core V1

- [x] 2.1 skill-vuln-scan (Nuclei + Grype + EPSS scoring) — 20 tests ✅
- [x] 2.2 skill-secrets (Gitleaks — Git history complet) — 21 tests ✅
- [x] 2.3 skill-email-audit (checkdmarc — DMARC/SPF/DKIM) — 12 tests ✅
- [x] 2.4 skill-darkweb (HIBP API + PasteHunter) — 15 tests ✅
- [x] 2.5 skill-phishing (GoPhish API + LLM templates) — 14 tests ✅
- [x] 2.6 Tests unitaires pour chaque skill — 82/82 ✅

## Phase 3 — SOC & Logs

- [x] 3.1 Pipeline logs : Fluent Bit → PostgreSQL (fluent-bit.conf + parsers.conf + V14 migration) ✅
- [x] 3.2 Intégration Sigma rules (sigma_engine.py — 32 tests) ✅
- [x] 3.3 skill-soc-monitor (collecte + Sigma + corrélation + triage LLM) — 76 tests ✅
- [x] 3.4 skill-cloud-posture (Prowler + NIS2 mapping + ISO27001) — 66 tests ✅
- [x] 3.5 Couche anonymisation src/anonymizer/ (patterns + transformer + dé-anonymisation) — 36 tests Rust ✅
- [x] 3.6 Cyber scheduler dans core Rust (6 routines par défaut) — 16 tests Rust ✅

## Phase 4 — IA & Rapports

- [x] 4.1 skill-report-gen (HTML/PDF NIS2 français, agrégation multi-sources, scoring pondéré) — 69 tests ✅
- [x] 4.2 skill-compliance-nis2 (mapping Art.21 §1-10, scoring, gap analysis, plan d'action) — 70 tests ✅
- [x] 4.3 skill-compliance-iso27001 (93 contrôles Annexe A, SoA, maturity assessment) — 44 tests ✅
- [x] 4.4 Dashboard RSSI Next.js v1 (score, NIS2 radar, alertes SOC, rapports, dark theme) — 18 fichiers ✅
- [x] 4.5 Human-in-the-loop Slack (Block Kit, approval workflows, urgency levels) — 26 Rust + 32 Python tests ✅

## Phase 5 — Docker & Release

- [x] 5.1 docker-compose.yml production (13 services, 2 réseaux, Redis, logging, resource limits) ✅
- [x] 5.2 installer/install.sh one-liner (Docker, .env, TLS, systemd, --update/--uninstall) ✅
- [x] 5.3 CI/CD GitHub Actions (ci.yml + release.yml + security.yml + dependabot) ✅
- [x] 5.4 Dockerfiles multi-stage (core Rust + dashboard Next.js + nginx reverse proxy) ✅
- [x] 5.5 Documentation utilisateur (USER_GUIDE.md fr + ARCHITECTURE.md en + CHANGELOG.md) ✅
- [x] 5.6 Tag v0.1.0 — Release prête ✅

---
*Dernière mise à jour : 2026-03-18*
*Version : 0.1.0*

## Statistiques finales

| Métrique | Valeur |
|----------|--------|
| Tests Python | 439 |
| Tests Rust | 3 275+ |
| Skills implémentés | 10/10 |
| Services Docker | 13 |
| Lignes de code ajoutées | ~25 000 |
| Commits | 5 |

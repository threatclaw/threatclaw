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

- [ ] 3.1 Pipeline logs : Fluent Bit → Vector → PostgreSQL
- [ ] 3.2 Intégration Sigma rules (3000+ règles communautaires)
- [ ] 3.3 skill-soc-monitor (collecte + triage LLM)
- [ ] 3.4 skill-cloud-posture (Prowler AWS/Azure/GCP)
- [ ] 3.5 Couche anonymisation src/anonymizer/
- [ ] 3.6 Modifications scheduler cyber dans core Rust

## Phase 4 — IA & Rapports

- [ ] 4.1 skill-report-gen (PDF NIS2 français via LLM)
- [ ] 4.2 skill-compliance-nis2 (mapping Art.21 §1-10)
- [ ] 4.3 skill-compliance-iso27001 (93 contrôles Annexe A)
- [ ] 4.4 Dashboard RSSI Next.js v1 (score + findings + rapport)
- [ ] 4.5 Human-in-the-loop validation Slack

## Phase 5 — Docker & Release

- [ ] 5.1 docker-compose.yml production complet
- [ ] 5.2 installer/install.sh one-liner (< 5 min)
- [ ] 5.3 CI/CD GitHub Actions (build + test + Docker build)
- [ ] 5.4 Tests sur VPS Debian vierge
- [ ] 5.5 Documentation utilisateur
- [ ] 5.6 Tag v0.1.0 — Release publique

---
*Dernière mise à jour : 2026-03-18*

# ThreatClaw — CLAUDE.md
# Agent Cybersécurité Autonome Open Source
# Fork d'ThreatClaw (github.com/nearai/threatclaw) — Licence Apache 2.0

## CONTEXTE PROJET

ThreatClaw est un fork d'ThreatClaw spécialisé cybersécurité, destiné aux PME françaises
sous NIS2. Il orchestre des outils open source via une architecture de skills WASM isolées,
un LLM configurable (local ou cloud), et produit des rapports de conformité en français.

**Repo base** : github.com/nearai/threatclaw
**Repo cible** : github.com/threatclaw/threatclaw
**Développeur** : CyberConsulting.fr — RSSI à temps partagé
**Environnement** : Debian 12 / MINISFORUM UM790 Pro / 32 GB RAM
**Licence** : Apache 2.0

---

## RÈGLES ABSOLUES — LIRE EN PREMIER

1. **Ne jamais modifier le sandbox WASM d'ThreatClaw** — c'est la couche de sécurité fondamentale
2. **Ne jamais contourner la couche d'anonymisation LLM** — données sensibles ne sortent pas
3. **Ne jamais créer de multi-tenant SaaS** — modèle B+ uniquement (1 instance par client)
4. **Ne jamais intégrer de code GPL dans le core** — Apache 2.0 pur uniquement
5. **Toujours valider les skills en isolation** avant intégration dans le docker-compose
6. **Human-in-the-loop obligatoire** sur toutes les actions write (réseau, firewall, comptes)

---

## ARCHITECTURE — LES 3 COUCHES

```
threatclaw-core/          ← Couche 1 : Core Rust (fork ThreatClaw)
  src/
    scheduler/            ← Scheduler cyber modifié
    anonymizer/           ← NOUVEAU : anonymisation avant LLM cloud
    permissions/          ← NOUVEAU : niveaux droits READ_ONLY/ALERT/REMEDIATE/AUTO
    
skills/                   ← Couche 2 : Skills WASM (Python → WASM)
  skill-vuln-scan/
  skill-phishing/
  skill-secrets/
  skill-email-audit/
  skill-darkweb/
  skill-soc-monitor/
  skill-cloud-posture/
  skill-report-gen/
  skill-compliance-nis2/
  skill-compliance-iso27001/

docker/                   ← Couche 3 : Services Docker
  docker-compose.yml      ← Stack complète
  docker-compose.dev.yml  ← Stack dev allégée
  
dashboard/                ← Interface RSSI (Next.js)
installer/                ← install.sh one-liner
docs/                     ← Documentation
```

---

## STACK TECHNIQUE

| Service | Image | Port | RAM | Licence |
|---------|-------|------|-----|---------|
| threatclaw-core | threatclaw/core | 18789 | ~200MB | Apache 2.0 |
| threatclaw-db | postgres:16 + pgvector | 5432 | ~512MB | PostgreSQL |
| threatclaw-dashboard | threatclaw/dashboard | 3000 | ~256MB | Apache 2.0 |
| gophish | gophish/gophish | 3333 | ~50MB | MIT |
| nuclei | projectdiscovery/nuclei | CLI | ~128MB | MIT |
| trivy | aquasec/trivy | 4954 | ~80MB | Apache 2.0 |
| grype | anchore/grype | CLI | ~80MB | Apache 2.0 |
| gitleaks | zricethezav/gitleaks | CLI | ~50MB | MIT |
| prowler | prowlercloud/prowler | CLI | ~128MB | Apache 2.0 |
| falco | falcosecurity/falco | 8765 | ~100MB | Apache 2.0 |
| fluent-bit | fluent/fluent-bit | 24224 | ~5MB | Apache 2.0 |
| **TOTAL** | | | **~1.6GB** | |

---

## SKILLS — INTERFACE STANDARD

Chaque skill WASM implémente cette interface :

```python
# Fichier : skills/skill-{nom}/src/main.py
# Compilé en WASM via componentize-py

from skill_interface import SkillInput, SkillOutput, SkillMetadata

METADATA = SkillMetadata(
    name="skill-vuln-scan",
    version="0.1.0",
    description="Scan de vulnérabilités réseau via Nuclei + Grype",
    permissions=["http:nuclei:8080", "http:grype:4954"],  # Endpoints autorisés UNIQUEMENT
    requires_approval=False,  # True pour les actions write
    data_classification="internal"  # internal | sensitive | public
)

def run(input: SkillInput) -> SkillOutput:
    # Logique de la skill
    pass
```

### Permissions disponibles pour les skills

```
# Read-only (pas d'approbation nécessaire)
http:nuclei:*       — Scanner Nuclei
http:trivy:4954     — Scanner Trivy
http:grype:*        — Scanner Grype
http:gophish:3333   — GoPhish (lecture uniquement)
http:falco:8765     — Falco (alertes)
api:hibp:*          — HaveIBeenPwned API
api:abusipdb:*      — AbuseIPDB API
api:nvd:*           — NVD NIST API
api:epss:*          — EPSS FIRST API

# Write (approbation RSSI obligatoire)
exec:firewall       — Modification règles firewall
exec:network        — Isolation réseau host
exec:accounts       — Gestion comptes (reset MFA, etc.)
exec:gophish:send   — Envoi campagne phishing (après validation)
```

---

## COUCHE ANONYMISATION LLM

**OBLIGATOIRE** avant tout envoi vers Claude API, Mistral cloud, ou tout LLM externe.

```python
# src/anonymizer/anonymizer.py
# Patterns à filtrer systématiquement :

PATTERNS = [
    r'\b(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01]))\.\d+\.\d+\b',  # IPs privées
    r'\b[A-Z][A-Z0-9\-]*\\[A-Z][A-Z0-9]*\b',  # Comptes Windows DOMAIN\user
    r'\b[0-9a-fA-F]{32,}\b',  # Hashes MD5/SHA
    r'password["\s:=]+["\']?[\w@#$%]+',  # Passwords
    r'api[_-]?key["\s:=]+["\']?[\w\-]+',  # API keys
    r'token["\s:=]+["\']?[\w\-\.]+',  # Tokens
]

# Remplacement par tokens réversibles en local
# IP_INTERNAL_001, ACCOUNT_001, HASH_001, etc.
```

---

## MODIFICATIONS CORE THREATCLAW

Seules ces modifications sont autorisées dans le core Rust :

### 1. Scheduler cyber (src/scheduler/cyber.rs)
```rust
// Ajouter ces types de tâches au scheduler ThreatClaw
pub enum CyberTaskType {
    VulnScanDaily,          // Scan réseau quotidien 02h00
    PhishingMonthly,        // Campagne phishing mensuelle
    DarkWebCheck6h,         // Vérification dark web toutes 6h
    CloudPostureWeekly,     // Audit cloud hebdomadaire
    LogAnalysisRealtime,    // Analyse logs en continu
    ReportGenWeekly,        // Rapport NIS2 hebdomadaire
}
```

### 2. Niveaux de droits (src/permissions/levels.rs)
```rust
pub enum PermissionLevel {
    ReadOnly,               // Scan + collecte uniquement
    AlertOnly,              // ReadOnly + notifications
    RemediateWithApproval,  // AlertOnly + actions après validation RSSI
    FullAuto,               // Actions réversibles simples (très limité)
}
```

### 3. Renommage branding
- Remplacer "threatclaw" → "threatclaw" dans tous les fichiers non-logique
- Garder les références ThreatClaw dans les credits/LICENSE
- Mettre à jour Cargo.toml : name = "threatclaw"

---

## MODÈLE DE DÉPLOIEMENT — B+ UNIQUEMENT

```
Client PME                    MSSP (toi)
─────────────────────         ─────────────────
ThreatClaw instance A  ←VPN→  Dashboard lecture
  └── Toutes données          seule à la demande
      restent ici
      
ThreatClaw instance B         Notification Slack
  └── Toutes données    ──→   "Alerte critique B"
      restent ici             (sans données brutes)
```

**Ce qui sort de l'infra client :**
- ✓ Notification d'alerte sans données (Slack/email)
- ✓ Résumés anonymisés vers LLM cloud (après anonymisation)
- ✗ JAMAIS : logs bruts, CVEs détaillées, findings, topologie réseau

---

## LLM — CONFIGURATION

```toml
# threatclaw.toml — configuration client

[llm]
# Option 1 : 100% local (recommandé pour données sensibles)
backend = "ollama"
model = "mistral:7b"
base_url = "http://localhost:11434"

# Option 2 : Souveraineté française
# backend = "mistral"
# api_key = "env:MISTRAL_API_KEY"
# endpoint = "https://francecentral.api.cognitive.microsoft.com"

# Option 3 : Meilleure qualité rapports
# backend = "anthropic"
# model = "claude-sonnet-4-20250514"
# api_key = "env:ANTHROPIC_API_KEY"

[llm.routing]
# Tâches toujours traitées en local (jamais vers cloud)
local_only = ["log_analysis", "alert_triage", "vuln_scoring"]
# Tâches pouvant aller vers cloud (après anonymisation)
cloud_allowed = ["report_generation", "compliance_analysis", "phishing_templates"]

[anonymizer]
enabled = true  # Non contournable
strip_internal_ips = true
strip_usernames = true
strip_credentials = true
strip_hostnames = true
```

---

## ROADMAP

### v0.1 → v1.9 — COMPLÉTÉ
- [x] Fork IronClaw → ThreatClaw, renommage branding
- [x] Docker 13 services (core, dashboard, ML, DB custom, Nginx, Fluent Bit, etc.)
- [x] 15 connecteurs (AD, pfSense, Proxmox, Wazuh, GLPI, Zeek, Suricata, Pi-hole, UniFi, etc.)
- [x] 15+ enrichissements (NVD, MITRE, CERT-FR, CISA KEV, EPSS, Shodan, VirusTotal, SSL Labs, etc.)
- [x] Asset Intelligence (MAC OUI 52K vendors, IP Classifier, Fingerprinting)
- [x] Graph Intelligence Apache AGE (STIX 2.1, Confidence, Lateral, Attack Paths, Blast Radius, Campaigns)
- [x] Anonymisation (14 catégories, constant-time, reversible placeholders)
- [x] NACE/NAF threat profiles (9 secteurs, MITRE ATT&CK mapping)
- [x] Dashboard Next.js 14 (Status, Assets, Alertes, Findings, Intelligence, Skills, Config, Exports)
- [x] Sécurité : 9/10 vulns fixées (SQL/Cypher injection, path traversal, timing attacks)
- [x] 3568+ tests Rust

### v2.0 — COMPLÉTÉ
- [x] ML Engine Python (Isolation Forest per asset, DGA Random Forest, DBSCAN clustering)
- [x] Intelligence Engine (cycle 5min, enrichment, scoring, notifications)
- [x] ML scores intégrés dans Intelligence Engine (downgrade normal / boost anomalies)
- [x] TimescaleDB (compression logs 90-95%, rétention 90j auto)
- [x] 4 images Docker fonctionnelles (core 173MB, dashboard 158MB, ML 493MB, DB 1.9GB)

### v2.0.1 — COMPLÉTÉ (session 26 mars 2026)
- [x] PDF reports via Typst (10 templates, zéro dépendance réseau)
  - [x] NIS2 Early Warning 24h (Art.23(4)(a) — 7 sections, checkboxes, champs légaux)
  - [x] NIS2 Intermédiaire 72h (Art.23(4)(b) — IOCs, évaluation, cause probable)
  - [x] NIS2 Final 1 mois (Art.23(4)(d-e) — timeline, root cause, leçons, cycle notif)
  - [x] NIS2 Article 21 (10 mesures obligatoires avec scores)
  - [x] RGPD Article 33 (notification CNIL — nature violation, DPO, conséquences)
  - [x] NIST SP 800-61r3 (CSF 2.0 — en anglais, format agences fédérales)
  - [x] ISO 27001:2022 (A.5.24-28 — classification, réponse, preuves, leçons)
  - [x] Rapport exécutif Direction/COMEX
  - [x] Rapport technique RSSI
  - [x] Journal d'audit
- [x] Graph AGE → TTPs MITRE injectés dans les rapports
- [x] ML scores → anomalies injectées dans rapport technique
- [x] Détection RGPD automatique (data_leak, PII findings, DB assets → gdpr_required)
- [x] Proxy Next.js corrigé pour binaires PDF (arrayBuffer)
- [x] Espace disque réel depuis `df` (plus hardcodé)
- [x] Statut DB réel depuis health check (plus hardcodé vert)
- [x] Statut ML réel depuis Intelligence Engine (plus hardcodé "Active")
- [x] Skills : 8 stubs grisés "En développement", 4 skills cachées rendues visibles
- [x] Skills : install/uninstall persisté côté backend (plus localStorage seul)
- [x] Skills : 3 enrichissements câblés (SecurityTrails, URLScan, Wordfence)
- [x] Anonymisation : bouton "Voir les règles par défaut" avec les 13 catégories
- [x] Document de référence multi-framework (docs/REPORT_FRAMEWORKS.md)
- [x] Document architecture auth (docs/AUTH_ARCHITECTURE.md)

### v2.1 — À FAIRE
- [ ] **Authentification dashboard** (login/mdp, argon2id, sessions cookie HttpOnly)
  - Voir docs/AUTH_ARCHITECTURE.md pour le design complet
  - Option A : auth intégrée (recommandé court terme)
  - Option C : OIDC optionnel en v2.5 (Keycloak/Azure AD en surcouche client)
- [ ] Câbler les 4 outils Docker stub (httpx, subfinder, trivy, ZAP) dans le skill executor
- [ ] Moteur Sigma Rules runtime (matching sur les logs)
- [ ] wasmtime migration v36→v43

### v2.5 — FUTUR
- [ ] OIDC optionnel (paramètre `oidc_issuer` dans config, validation JWKS)
- [ ] MFA TOTP (ajout sur l'auth intégrée)
- [ ] Federated Graph (multi-instance ThreatClaw, partage d'IOCs)
- [ ] Templates PDF supplémentaires (GDPR Art.34 communication personnes, NCSC UK CAF)
- [ ] Split sous-traits (db/threatclaw_store.rs refactoring)

---

## COMMANDES UTILES

```bash
# Compiler le core Rust
cargo build --release

# Lancer la stack de développement
docker compose -f docker/docker-compose.dev.yml up -d

# Lancer la stack complète
docker compose -f docker/docker-compose.yml up -d

# Tests Rust
cargo test

# Compiler une skill Python en WASM
cd skills/skill-vuln-scan
pip install componentize-py --break-system-packages
componentize-py --wit-path ../../wit/skill.wit componentize main -o skill-vuln-scan.wasm

# Lancer les logs en temps réel
docker compose logs -f threatclaw-core

# Accéder au dashboard
open http://localhost:3000
```

---

## STRUCTURE D'UNE SKILL — EXEMPLE COMPLET

```
skills/skill-vuln-scan/
├── SKILL.md              ← Documentation (format ThreatClaw)
├── Cargo.toml            ← Si Rust, ou pyproject.toml si Python
├── src/
│   └── main.py           ← Code principal
├── tests/
│   └── test_main.py      ← Tests unitaires
├── skill.wit             ← Interface WIT (WebAssembly Interface Types)
└── skill-vuln-scan.wasm  ← Compilé (gitignore — build artifact)
```

```markdown
<!-- SKILL.md -->
---
name: skill-vuln-scan
version: 0.1.0
description: Scan de vulnérabilités réseau via Nuclei et Grype avec scoring CVSS+EPSS
permissions:
  - http:nuclei:8080
  - http:grype:4954
  - api:nvd:*
  - api:epss:*
requires_approval: false
data_classification: internal
nis2_articles:
  - "Art.21 §2a — Politique de sécurité des systèmes d'information"
  - "Art.21 §2b — Gestion des incidents"
---
```

---

## TESTS DE SÉCURITÉ OBLIGATOIRES

Avant chaque merge dans main :

```bash
# 1. Analyse statique sécurité
semgrep --config=auto src/ skills/

# 2. Vérification des permissions skills
python scripts/check_skill_permissions.py skills/

# 3. Test d'isolation sandbox
cargo test --test sandbox_isolation

# 4. Vérification anonymisation
python scripts/test_anonymizer.py --strict
```

---

## CONTACTS ET RESSOURCES

- **ThreatClaw base** : https://github.com/nearai/threatclaw
- **ThreatClaw docs** : https://github.com/nearai/threatclaw-docs
- **Sigma rules** : https://github.com/SigmaHQ/sigma
- **NVD API** : https://nvd.nist.gov/developers/vulnerabilities
- **EPSS API** : https://www.first.org/epss/api
- **HIBP API** : https://haveibeenpwned.com/API/v3
- **GoPhish API** : https://docs.getgophish.com/api-documentation
- **Prowler docs** : https://docs.prowler.com
- **NIS2 texte officiel** : https://eur-lex.europa.eu/legal-content/FR/TXT/?uri=CELEX:32022L2555

---

*Dernière mise à jour : Mars 2026 — v1.0*
*Ce fichier est la référence unique pour Claude Code sur ce projet.*
*Toujours lire ce fichier avant toute action de développement.*

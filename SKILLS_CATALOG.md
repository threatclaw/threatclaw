# ThreatClaw — Skills Catalog

## Audit des skills existants (23 mars 2026)

### Skills WASM (Rust, sandbox BLAKE3) — 10/10 REAL ✅

| Skill | API externe | Config requise | Test handler | Status |
|-------|------------|----------------|--------------|--------|
| skill-abuseipdb | api.abuseipdb.com | api_key | Réel (check IP 8.8.8.8) | Production ✅ |
| skill-shodan | api.shodan.io | api_key | Réel (check credits) | Production ✅ |
| skill-virustotal | virustotal.com/api/v3 | api_key | Réel (check /users/me) | Production ✅ |
| skill-cti-crowdsec | cti.api.crowdsec.net | api_key | Réel (check /smoke/8.8.8.8) | Production ✅ |
| skill-darkweb-monitor | haveibeenpwned.com/api/v3 | api_key, emails | Réel (check subscription) | Production ✅ |
| skill-wazuh | wazuh:55000 | url, username, password | Réel (auth test) | Production ✅ |
| skill-email-audit | cloudflare-dns.com | domains | Réel (DNS SPF check) | Production ✅ |
| skill-report-gen | localhost:3000 (interne) | company_name, language | Local (pas d'API ext.) | Production ✅ |
| skill-compliance-nis2 | localhost:3000 (interne) | — | Local (mapping NIS2) | Production ✅ |
| skill-compliance-iso27001 | localhost:3000 (interne) | — | Local (93 contrôles) | Production ✅ |

### Skills Python (Docker) — 6/7 REAL, 1 STUB ⚠️

| Skill | Docker deps | Config | Status |
|-------|------------|--------|--------|
| skill-vuln-scan | Nuclei, Grype, Trivy | targets, severity | Production ✅ |
| skill-cloud-posture | Prowler | aws_profile, azure_tenant, gcp_project | Production ✅ |
| skill-soc-monitor | — (PostgreSQL direct) | — | Production ✅ |
| skill-secrets | Gitleaks | scan_path, scan_git | Production ✅ |
| skill-phishing | GoPhish | — (HITL required) | Production ✅ |
| skill-report-gen (Python) | — | company_name | Production ✅ |
| **skill-appsec** | Trivy, Semgrep | — | **STUB ✗** (45 lignes, TODO) |

### Skills FRONTEND ONLY — 1 VIDE ✗

| Skill | Problème |
|-------|----------|
| **skill-secrets-audit** | skill.json existe mais AUCUN code source |

---

## Nouveau catalogue — Skills à implémenter

### Mode éphémère (docker run --rm) — Scans à la demande

#### Priorité 1 — Implémenter maintenant

| Skill ID | Docker image | Commande | Taille | Licence | Config | Pertinence NIS2 |
|----------|-------------|----------|--------|---------|--------|-----------------|
| skill-sast | `semgrep/semgrep` | `docker run --rm -v "$PWD:/src" semgrep/semgrep semgrep scan --config auto --json` | 800 MB | LGPL-2.1 | chemin code | Art.21 dev sécurisé |
| skill-iac-security | `bridgecrew/checkov` | `docker run --rm -v "$PWD:/tf" bridgecrew/checkov -d /tf -o json` | 550 MB | Apache 2.0 | chemin IaC | Art.21 infra sécurisée |
| skill-git-secrets | `trufflesecurity/trufflehog` | `docker run --rm -v "$PWD:/pwd" trufflesecurity/trufflehog git file:///pwd --json` | 120 MB | AGPL-3.0 | repo path | #1 vecteur breach PME |
| skill-sbom | `anchore/syft` | `docker run --rm -v "$PWD:/src" anchore/syft /src -o spdx-json` | 75 MB | Apache 2.0 | path/image | Art.21 supply chain |
| skill-container-vuln | `anchore/grype` | `docker run --rm anchore/grype alpine:latest -o json` | 70 MB | Apache 2.0 | image name | CVE containers |
| skill-web-scanner | `zaproxy/zap-stable` | `docker run --rm zaproxy/zap-stable zap-baseline.py -t https://target -J report.json` | 1.5 GB | Apache 2.0 | URL cible | DAST web essentiel |
| skill-network-scan | `instrumentisto/nmap` | `docker run --rm instrumentisto/nmap -sV -oX - target` | 20 MB | NPSL (GPLv2-like) | IP/host | Inventaire réseau |

#### Priorité 2 — Après premiers clients

| Skill ID | Docker image | Commande | Taille | Licence | Config |
|----------|-------------|----------|--------|---------|--------|
| skill-http-probe | `projectdiscovery/httpx` | `echo "target" \| docker run --rm -i projectdiscovery/httpx -json` | 270 MB | MIT | domaines |
| skill-subdomain | `projectdiscovery/subfinder` | `docker run --rm projectdiscovery/subfinder -d target -json` | 50 MB | MIT | domaine |
| skill-docker-bench | `docker/docker-bench-security` | `docker run --rm ... docker-bench-security` | 15 MB | Apache 2.0 | Docker socket |

#### Rejetés (avec justification)

| Outil | Raison du rejet |
|-------|----------------|
| owasp/dependency-check | Trop lourd (1 GB Java), lent. Grype+Syft fait mieux |
| projectdiscovery/naabu | Doublon avec nmap |
| projectdiscovery/katana | ZAP fait déjà le crawl |
| checkmarx/kics | Doublon avec Checkov |
| wapiti-scanner/wapiti | Pas d'image Docker officielle, GPL, ZAP est meilleur |
| aquasec/kube-bench | PME n'utilisent pas K8s (V3+ si besoin) |
| cisecurity/cis-cat-lite | Pas de Docker, propriétaire, scope limité |
| clamav/clamav | MalwareBazaar couvre 95% des cas (V4 si air-gap) |

### Mode permanent (service continu)

| Skill ID | Docker image | Commande | Taille | Licence | RAM | Pertinence |
|----------|-------------|----------|--------|---------|-----|------------|
| skill-network-ids | `jasonish/suricata` | `docker run --net=host --cap-add=net_raw jasonish/suricata -i eth0` | 190 MB | GPL-2.0 | 512 MB | IDS/IPS NIS2 core |
| skill-runtime-security | `falcosecurity/falco` | `docker run --privileged falcosecurity/falco` | 200 MB | Apache 2.0 | 128 MB | Runtime threats |

#### Rejetés

| Outil | Raison |
|-------|--------|
| zeek/zeek | Complexe, Suricata couvre l'IDS. V2+ pour clients avancés |

### Mode connecteur (API externe)

| Skill ID | Plateforme | API | Config | Priorité | Pertinence |
|----------|-----------|-----|--------|----------|------------|
| skill-wazuh-siem | Wazuh Manager | REST `/security/user/authenticate` | url, user, pass | P2 | SIEM NIS2 |
| skill-defectdojo | DefectDojo | REST `/api/v2/import-scan/` | url, token | P2 | Agrégation vulns |
| skill-dependency-track | Dependency-Track | REST `/api/v1/bom` | url, api_key | P2 | SBOM lifecycle |

#### Rejetés

| Outil | Raison |
|-------|--------|
| SonarQube | Trop lourd, Semgrep couvre le SAST |
| MISP | Trop complexe pour PME self-hosted |
| TheHive | Licence propriétaire depuis v5 |
| Cortex | ThreatClaw enrichment le remplace |
| OpenCTI | 16 GB RAM, 8 containers, overkill PME |

---

## Architecture des modes d'exécution

```
skill.json → "mode": "ephemeral" | "persistent" | "connector"

Éphémère:
  docker run --rm {image} {args} → JSON stdout → findings DB
  Zéro RAM entre les scans

Permanent:
  docker compose -f skill-compose.yml up -d
  Container actif en continu
  ThreatClaw appelle son API

Connecteur:
  Pas de Docker
  URL + API key dans la config
  ThreatClaw interroge l'API existante
```

---

## Ce qui existe déjà et ne doit PAS être doublé

| Besoin | Déjà couvert par | Ne PAS ajouter |
|--------|------------------|----------------|
| Scan vulnérabilités réseau | skill-vuln-scan (Nuclei) | OpenVAS (trop lourd) |
| Scan containers | skill-vuln-scan (Trivy/Grype) | Doublon Grype standalone |
| Secrets Git | skill-secrets (Gitleaks) | TruffleHog (doublon partiel) |
| Compliance NIS2 | skill-compliance-nis2 | — |
| Compliance ISO 27001 | skill-compliance-iso27001 | — |
| Réputation IP | skill-abuseipdb + CrowdSec | — |
| Surface d'attaque | skill-shodan | — |
| Dark web monitoring | skill-darkweb-monitor (HIBP) | — |
| Email audit | skill-email-audit (SPF/DKIM/DMARC) | — |
| Cloud posture | skill-cloud-posture (Prowler) | — |
| Rapports | skill-report-gen | — |
| SOC monitoring | skill-soc-monitor (Sigma) | — |
| Phishing simulation | skill-phishing (GoPhish) | — |
| Wazuh | skill-wazuh (API) | — |

## Actions immédiates

1. ~~Retirer `skill-secrets-audit`~~ du dashboard (pas de code)
2. Compléter ou retirer `skill-appsec` (stub)
3. Implémenter le système de modes (ephemeral/persistent/connector)
4. Priorité V2 : semgrep, checkov, ZAP, suricata, falco, sonarqube connector

---

*Dernière mise à jour : 23 mars 2026*

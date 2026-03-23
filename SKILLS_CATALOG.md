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

| Skill ID | Outil Docker | Description | Taille image | Config min | Priorité |
|----------|-------------|-------------|--------------|------------|----------|
| skill-sast | returntocorp/semgrep | Analyse statique code (SAST multi-langage) | ~800 MB | chemin code | V2 |
| skill-iac-security | bridgecrew/checkov | Sécurité IaC (Terraform, CloudFormation, K8s) | ~500 MB | chemin IaC | V2 |
| skill-git-secrets | trufflesecurity/trufflehog | Secrets dans l'historique Git | ~200 MB | repo URL | V2 |
| skill-sbom | anchore/syft | Générateur SBOM (Software Bill of Materials) | ~100 MB | image/path | V2 |
| skill-sca | owasp/dependency-check | Analyse dépendances (SCA) | ~1.2 GB | chemin projet | V2 |
| skill-container-vuln | anchore/grype | Vulnérabilités containers/images | ~100 MB | image name | V2 |
| skill-web-scanner | zaproxy/zap-stable | Scanner DAST web (XSS, SQLi, etc.) | ~1.5 GB | URL cible | V2 |
| skill-iac-kics | checkmarx/kics | Sécurité IaC (alternative Checkov) | ~300 MB | chemin IaC | V3 |
| skill-dast-wapiti | wapiti-scanner/wapiti | Scanner DAST web (alternative ZAP) | ~200 MB | URL cible | V3 |
| skill-http-probe | projectdiscovery/httpx | HTTP probing rapide | ~50 MB | domaines | V3 |
| skill-subdomain | projectdiscovery/subfinder | Découverte sous-domaines | ~50 MB | domaine | V3 |
| skill-port-scan | projectdiscovery/naabu | Scanner de ports rapide | ~30 MB | IP/range | V3 |
| skill-web-crawl | projectdiscovery/katana | Web crawler | ~50 MB | URL | V3 |
| skill-k8s-bench | aquasec/kube-bench | CIS Kubernetes benchmark | ~50 MB | — (auto) | V3 |
| skill-docker-bench | docker/docker-bench-security | CIS Docker benchmark | ~20 MB | — (auto) | V3 |
| skill-antivirus | clamav/clamav | Antivirus fichiers (malware connu) | ~300 MB | chemin | V4 |

### Mode permanent (service continu)

| Skill ID | Outil Docker | Description | RAM | Priorité |
|----------|-------------|-------------|-----|----------|
| skill-network-ids | jasonish/suricata | IDS/IPS réseau temps réel | ~512 MB | V2 |
| skill-network-analysis | zeek/zeek | Analyse trafic réseau | ~256 MB | V3 |
| skill-runtime-security | falcosecurity/falco | Sécurité runtime containers | ~128 MB | V2 |

### Mode connecteur (API externe)

| Skill ID | Plateforme | Description | Config | Priorité |
|----------|-----------|-------------|--------|----------|
| skill-wazuh-siem | Wazuh Manager | SIEM/XDR complet | url, user, pass | V2 (déjà partiel) |
| skill-sonarqube | SonarQube | Qualité + sécurité code | url, token | V2 |
| skill-defectdojo | DefectDojo | Gestion des vulnérabilités | url, token | V3 |
| skill-misp | MISP | Threat Intelligence | url, api_key | V3 |
| skill-thehive | TheHive | Incident Response | url, api_key | V3 |
| skill-cortex | Cortex | Analyseur d'observables | url, api_key | V3 |
| skill-opencti | OpenCTI | Cyber Threat Intelligence | url, token | V4 |
| skill-dependency-track | Dependency-Track | SBOM + vulns management | url, api_key | V3 |

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

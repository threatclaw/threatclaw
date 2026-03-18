---
name: skill-vuln-scan
version: 0.1.0
description: Orchestre Nuclei + Grype pour scanner les vulnérabilités réseau et images. Scoring CVSS+EPSS. Priorise les findings par criticité réelle.
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
activation:
  keywords:
    - vulnerability scan
    - scan vulnérabilités
    - CVE scan
    - nuclei scan
    - grype scan
  patterns:
    - "scan.*vuln"
    - "CVE.*check"
---

# skill-vuln-scan

Scan de vulnérabilités réseau via Nuclei et images via Grype avec scoring CVSS+EPSS.

## Fonctionnement

1. Lance Nuclei sur les cibles réseau configurées
2. Lance Grype sur les images Docker du client
3. Récupère les scores CVSS depuis NVD API
4. Enrichit avec les scores EPSS (probabilité d'exploitation)
5. Priorise les findings par criticité réelle (CVSS * EPSS)
6. Stocke les résultats dans PostgreSQL
7. Génère un résumé pour le dashboard

## Inputs

- `targets`: Liste d'IPs/domaines à scanner
- `images`: Liste d'images Docker à auditer
- `scan_type`: "quick" | "full" | "custom"
- `templates`: Templates Nuclei spécifiques (optionnel)

## Outputs

- `findings[]`: Liste de vulnérabilités avec scores
- `summary`: Résumé exécutif
- `critical_count`: Nombre de findings critiques
- `high_count`: Nombre de findings élevés

---
name: skill-appsec
version: 0.1.0
description: Scan code + dépendances + images Docker via Trivy + Semgrep. Agrège les findings dans PostgreSQL.
permissions:
  - http:trivy:4954
requires_approval: false
data_classification: internal
nis2_articles:
  - "Art.21 §2a — Politique de sécurité des systèmes d'information"
  - "Art.21 §2e — Sécurité dans l'acquisition, le développement et la maintenance"
activation:
  keywords:
    - appsec scan
    - code scan
    - dependency scan
    - trivy scan
    - semgrep
  patterns:
    - "appsec.*scan"
    - "code.*security"
---

# skill-appsec

Application security scanning via Trivy (containers, dependencies) et Semgrep (SAST).

## Inputs

- `repositories`: Repos à scanner
- `images`: Images Docker à auditer
- `scan_code`: Activer Semgrep SAST

## Outputs

- `findings[]`: Vulnérabilités code + dépendances
- `summary`: Résumé

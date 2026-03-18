---
name: skill-cloud-posture
version: 0.1.0
description: Audit AWS/Azure/GCP via Prowler. 300+ checks CIS/NIS2/ISO 27001. Agentless, credentials read-only.
permissions:
  - http:prowler:*
requires_approval: false
data_classification: internal
nis2_articles:
  - "Art.21 §2a — Politique de sécurité des systèmes d'information"
  - "Art.21 §2e — Sécurité dans l'acquisition, le développement et la maintenance"
activation:
  keywords:
    - cloud security
    - cloud posture
    - prowler
    - CSPM
    - AWS audit
    - Azure audit
  patterns:
    - "cloud.*security"
    - "cloud.*audit"
    - "prowler"
---

# skill-cloud-posture

Audit de posture sécurité cloud via Prowler (AWS/Azure/GCP).

## Inputs

- `cloud_provider`: "aws" | "azure" | "gcp"
- `checks`: Liste de checks spécifiques (ou "all")
- `compliance_framework`: "cis" | "nis2" | "iso27001"

## Outputs

- `findings[]`: Résultats des checks
- `compliance_score`: Score de conformité
- `pass_count` / `fail_count`: Métriques

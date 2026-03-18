---
name: skill-secrets
version: 0.1.0
description: Détecte credentials exposés dans les dépôts Git (historique complet) via Gitleaks + surveillance paste sites.
permissions:
  - http:gitleaks:*
requires_approval: false
data_classification: sensitive
nis2_articles:
  - "Art.21 §2a — Politique de sécurité des systèmes d'information"
  - "Art.21 §2i — Sécurité des ressources humaines, contrôle d'accès"
activation:
  keywords:
    - secret detection
    - détection secrets
    - gitleaks
    - credential leak
  patterns:
    - "secret.*detect"
    - "credential.*leak"
    - "gitleaks"
---

# skill-secrets

Détection de secrets et credentials exposés dans les dépôts Git et paste sites.

## Fonctionnement

1. Clone le(s) repo(s) cibles en local (lecture seule)
2. Lance Gitleaks sur l'historique Git complet
3. Classifie les findings : API keys, passwords, tokens, certificates
4. Évalue la criticité selon le type de secret et son âge
5. Stocke les résultats dans PostgreSQL
6. Alerte si des secrets actifs sont détectés

## Inputs

- `repositories`: Liste d'URLs de repos Git
- `scan_history`: true/false (scan historique complet)
- `custom_rules`: Règles Gitleaks additionnelles (optionnel)

## Outputs

- `findings[]`: Liste de secrets détectés
- `summary`: Résumé exécutif
- `active_secrets_count`: Nombre de secrets potentiellement actifs

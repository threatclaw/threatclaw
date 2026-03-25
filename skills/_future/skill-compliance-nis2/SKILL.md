---
name: skill-compliance-nis2
version: 0.1.0
description: Mappe tous les findings vers les articles NIS2 (Art.21 §1-10). Score de conformité. GAP analysis.
permissions: []
requires_approval: false
data_classification: internal
nis2_articles:
  - "Art.21 §1 — Mesures de gestion des risques en matière de cybersécurité"
  - "Art.21 §2a — Politiques relatives à l'analyse des risques"
  - "Art.21 §2b — Gestion des incidents"
  - "Art.21 §2c — Continuité des activités"
  - "Art.21 §2d — Sécurité de la chaîne d'approvisionnement"
  - "Art.21 §2e — Sécurité dans l'acquisition et la maintenance"
  - "Art.21 §2f — Évaluation de l'efficacité des mesures"
  - "Art.21 §2g — Cyberhygiène et formation"
  - "Art.21 §2h — Cryptographie et chiffrement"
  - "Art.21 §2i — Ressources humaines et contrôle d'accès"
  - "Art.21 §2j — Authentification multi-facteur"
activation:
  keywords:
    - NIS2 compliance
    - conformité NIS2
    - NIS2 mapping
    - gap analysis NIS2
  patterns:
    - "NIS2.*compliance"
    - "conformité.*NIS2"
    - "NIS2.*gap"
---

# skill-compliance-nis2

Mapping des findings de sécurité vers les articles NIS2 (Directive EU 2022/2555).

## Fonctionnement

1. Collecte tous les findings depuis PostgreSQL (toutes skills)
2. Mappe chaque finding vers les articles NIS2 pertinents
3. Calcule un score de conformité par article (0-100)
4. Identifie les GAPs (articles non couverts)
5. Génère des recommandations d'actions correctives
6. Produit un rapport structuré pour skill-report-gen

## Inputs

- `findings_source`: "all" | "last_scan" | "period"
- `period`: Période d'analyse
- `include_recommendations`: Inclure les recommandations

## Outputs

- `compliance_report`: Rapport de conformité structuré
- `overall_score`: Score global NIS2 (0-100)
- `article_scores`: Score par article
- `gaps[]`: Articles non couverts
- `actions[]`: Actions correctives recommandées

---
name: skill-compliance-iso27001
version: 0.1.0
description: Mappe les findings vers les 93 controles ISO 27001:2022 Annexe A. Score de conformite par categorie. Statement of Applicability (SoA). Evaluation de maturite.
permissions: []
requires_approval: false
data_classification: internal
nis2_articles:
  - "Art.21 §2a — Politiques relatives a l'analyse des risques"
  - "Art.21 §2e — Securite dans l'acquisition et la maintenance"
  - "Art.21 §2f — Evaluation de l'efficacite des mesures"
activation:
  keywords:
    - ISO 27001 compliance
    - conformite ISO 27001
    - ISO 27001 mapping
    - Annexe A
    - Statement of Applicability
    - SoA ISO
    - controles ISO
    - gap analysis ISO 27001
    - audit ISO 27001
  patterns:
    - "ISO.?27001.*compliance"
    - "conformite.*ISO.?27001"
    - "ISO.?27001.*gap"
    - "ISO.?27001.*audit"
    - "SoA.*ISO"
    - "Annexe.*A.*controles"
---

# skill-compliance-iso27001

Mapping des findings de securite vers les 93 controles de l'Annexe A de la norme ISO 27001:2022.

## Fonctionnement

1. Collecte les findings depuis les autres skills (vuln-scan, secrets, cloud-posture, etc.)
2. Mappe chaque finding vers les controles ISO 27001 Annexe A pertinents
3. Evalue le statut de chaque controle (conforme, partiel, non conforme, non applicable)
4. Calcule un score de maturite par controle et par categorie
5. Genere le Statement of Applicability (SoA)
6. Produit un plan d'action et un rapport structure

## Inputs

- `scope`: "full" | "category" — portee de l'evaluation
- `category_filter`: Filtre par categorie (A.5, A.6, A.7, A.8)
- `include_soa`: Inclure le Statement of Applicability
- `include_recommendations`: Inclure les recommandations

## Outputs

- `overall_score`: Score global de conformite (0-100)
- `maturity_level`: Niveau de maturite global (INITIAL a OPTIMIZED)
- `category_scores[]`: Scores par categorie (organisationnel, personnel, physique, technologique)
- `soa[]`: Statement of Applicability complet
- `action_plan[]`: Plan d'action priorise
- `summary_fr`: Resume en francais

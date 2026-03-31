---
name: skill-report-gen
version: 0.1.0
description: Génère rapport PDF exécutif (COMEX) + technique (IT) en français. Templates NIS2/ISO 27001.
permissions:
  - api:llm:*
requires_approval: false
data_classification: internal
nis2_articles:
  - "Art.21 §1 — Mesures de gestion des risques"
  - "Art.23 — Obligations de notification"
activation:
  keywords:
    - report generation
    - rapport PDF
    - rapport NIS2
    - rapport sécurité
    - executive report
  patterns:
    - "rapport.*PDF"
    - "report.*gen"
    - "rapport.*NIS2"
---

# skill-report-gen

Génération de rapports PDF de sécurité en français (NIS2/ISO 27001).

## Inputs

- `report_type`: "executive" | "technical" | "compliance"
- `period`: Période couverte
- `framework`: "nis2" | "iso27001" | "both"
- `include_sections`: Sections à inclure

## Outputs

- `pdf_path`: Chemin du rapport PDF généré
- `summary`: Résumé du rapport
- `compliance_score`: Score global

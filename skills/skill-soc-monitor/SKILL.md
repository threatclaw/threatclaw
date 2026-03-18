---
name: skill-soc-monitor
version: 0.1.0
description: Collecte alertes Fluent Bit + Sigma rules. Triage LLM. Filtre faux positifs. Corrélation multi-sources.
permissions:
  - http:falco:8765
  - http:fluent-bit:24224
requires_approval: false
data_classification: internal
nis2_articles:
  - "Art.21 §2b — Gestion des incidents"
  - "Art.21 §2c — Continuité des activités et gestion de crise"
activation:
  keywords:
    - SOC monitoring
    - log analysis
    - analyse logs
    - sigma rules
    - alert triage
  patterns:
    - "SOC.*monitor"
    - "log.*analy"
    - "alert.*triage"
---

# skill-soc-monitor

Monitoring SOC léger avec collecte logs, Sigma rules, et triage LLM.

## Inputs

- `time_range`: Période d'analyse
- `sources`: Sources de logs à analyser
- `sigma_rulesets`: Sets de règles Sigma à appliquer

## Outputs

- `alerts[]`: Alertes détectées et triées
- `false_positive_rate`: Taux de faux positifs estimé
- `correlations[]`: Corrélations entre alertes

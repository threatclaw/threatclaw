---
name: skill-phishing
version: 0.1.0
description: Génère templates de phishing contextualisés via LLM. Orchestre GoPhish via API REST. Analyse résultats + rapport NIS2.
permissions:
  - http:gophish:3333
requires_approval: true
data_classification: internal
nis2_articles:
  - "Art.21 §2g — Pratiques de base en matière de cyberhygiène et formation"
activation:
  keywords:
    - phishing simulation
    - simulation phishing
    - gophish campaign
    - sensibilisation
  patterns:
    - "phishing.*simul"
    - "campagne.*phishing"
---

# skill-phishing

Simulation de phishing via GoPhish avec templates LLM contextualisés.

## Fonctionnement

1. Génère des templates d'emails de phishing via LLM (contexte secteur client)
2. Configure la campagne dans GoPhish via API REST
3. Envoie la campagne (APRÈS validation RSSI — requires_approval: true)
4. Collecte les résultats (ouvertures, clics, soumissions)
5. Génère un rapport de sensibilisation avec métriques
6. Mapping NIS2 Art.21 §2g

## Inputs

- `target_group`: Nom du groupe cible dans GoPhish
- `template_type`: "generic" | "spear" | "ceo_fraud"
- `sector`: Secteur d'activité du client (pour contextualisation LLM)
- `language`: "fr" | "en"

## Outputs

- `campaign_id`: ID de la campagne GoPhish
- `results`: Métriques (taux d'ouverture, clics, soumissions)
- `report`: Rapport de sensibilisation

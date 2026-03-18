---
name: skill-darkweb
version: 0.1.0
description: Surveille HIBP + LeakCheck pour emails/domaines exposés. Scrape paste sites via PasteHunter. Alerte sur leaks.
permissions:
  - api:hibp:*
  - api:leakcheck:*
requires_approval: false
data_classification: sensitive
nis2_articles:
  - "Art.21 §2b — Gestion des incidents"
  - "Art.21 §2i — Sécurité des ressources humaines"
activation:
  keywords:
    - dark web
    - darkweb monitoring
    - HIBP check
    - leak detection
    - breach check
  patterns:
    - "dark.*web"
    - "breach.*check"
    - "leak.*detect"
---

# skill-darkweb

Surveillance Dark Web et détection de fuites de données via HIBP API et PasteHunter.

## Fonctionnement

1. Vérifie les emails/domaines contre HaveIBeenPwned API
2. Cherche les credentials exposés sur paste sites
3. Classifie les fuites par ancienneté et criticité
4. Corrèle avec les comptes Active Directory du client
5. Alerte si des credentials actifs sont compromis

## Inputs

- `emails`: Liste d'emails à vérifier
- `domains`: Domaines à surveiller
- `check_pastes`: Activer la recherche sur paste sites

## Outputs

- `breaches[]`: Liste des fuites détectées
- `exposed_accounts`: Nombre de comptes exposés
- `recommendations[]`: Actions correctives

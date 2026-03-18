---
name: skill-email-audit
version: 0.1.0
description: Vérifie DMARC, SPF, DKIM des domaines clients via checkdmarc. Alerte si exposition au spoofing email.
permissions:
  - api:dns:*
requires_approval: false
data_classification: internal
nis2_articles:
  - "Art.21 §2a — Politique de sécurité des systèmes d'information"
  - "Art.21 §2e — Sécurité des réseaux et systèmes d'information"
activation:
  keywords:
    - email audit
    - audit email
    - DMARC check
    - SPF check
    - DKIM check
  patterns:
    - "email.*audit"
    - "DMARC.*check"
---

# skill-email-audit

Audit de la configuration email (DMARC/SPF/DKIM) des domaines clients.

## Fonctionnement

1. Récupère les enregistrements DNS (DMARC, SPF, DKIM) via checkdmarc
2. Analyse la conformité de chaque enregistrement
3. Détecte les faiblesses (SPF trop permissif, DMARC en mode none, etc.)
4. Score de maturité email security (0-100)
5. Recommandations d'amélioration

## Inputs

- `domains`: Liste de domaines à auditer
- `dkim_selectors`: Sélecteurs DKIM à vérifier (optionnel)

## Outputs

- `findings[]`: Résultats par domaine
- `score`: Score global de sécurité email
- `recommendations[]`: Actions correctives recommandées

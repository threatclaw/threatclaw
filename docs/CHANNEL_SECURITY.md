# ThreatClaw — Sécurité des canaux de communication

## DM Pairing (Vérification d'identité)

Quand un utilisateur inconnu envoie un message à ThreatClaw via Slack, Telegram ou Discord, le système de **DM Pairing** s'active :

1. L'utilisateur reçoit un **code de vérification** (6 caractères)
2. Le RSSI doit approuver ce code dans le dashboard ou la CLI
3. Tant que le code n'est pas approuvé, les messages sont **ignorés**
4. Les codes **expirent après 1 heure**
5. Maximum **3 demandes en attente** par canal

### Pourquoi c'est important

Sans pairing, n'importe qui peut envoyer des messages à l'agent et potentiellement :
- Extraire des informations de sécurité
- Manipuler l'agent via prompt injection
- Déclencher des actions non autorisées

### Configuration par canal

```toml
# Dans la config du canal (capabilities.json)
{
  "dm_policy": "pairing",    # open | allowlist | pairing (défaut)
  "owner_id": "U123456",     # ID Slack/Telegram du RSSI (optionnel)
  "allow_from": ["U123456"]  # Utilisateurs pré-approuvés
}
```

### Modes disponibles

| Mode | Description |
|------|-------------|
| `pairing` (défaut) | Code de vérification pour les inconnus |
| `allowlist` | Seuls les utilisateurs listés dans `allow_from` peuvent interagir |
| `open` | Tout le monde peut interagir (déconseillé en production) |

### Recommandation

- Telegram : mode `pairing` avec `owner_id` du RSSI
- Slack : mode `allowlist` avec les IDs des membres de l'équipe sécu
- Discord : mode `allowlist` dans les canaux publics

## Webhook Security

### Slack
- Vérification signature HMAC-SHA256 (`signing_secret`)
- Header : `X-Slack-Signature`

### Telegram
- Token secret dans le header `X-Telegram-Bot-Api-Secret-Token`

### Discord
- Vérification signature Ed25519 (`public_key`)

### WhatsApp
- Vérification HMAC-SHA256 (`X-Hub-Signature-256`)

## Bonnes pratiques

1. **Toujours configurer `owner_id`** pour chaque canal
2. **Ne jamais utiliser le mode `open`** en production
3. **Renouveler les tokens** tous les 6 mois
4. **Auditer les accès** via le journal d'audit ThreatClaw
5. **Tester le pairing** après chaque changement de config

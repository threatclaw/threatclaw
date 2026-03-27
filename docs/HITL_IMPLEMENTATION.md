# ThreatClaw — HITL & Bot Conversationnel — Plan d'implémentation

> Le game changer du produit. Implémentation en cours.

## Statut

### P0 — Fix pipeline cassé
- [x] NonceManager partagé dans GatewayState (plus de nonce temporaire par requête)
- [x] hitl_callback_handler utilise le NonceManager partagé
- [x] hitl_button_callback_handler vérifie nonce + exécute réellement
- [ ] Bot confirmation "oui" → exécute la remédiation (pas boucle infinie)

### P1 — Intelligence Engine → HITL automatique
- [ ] Quand Critical → extraire IPs attaquantes + assets affectés
- [ ] Proposer des actions concrètes (block_ip, lock_user, scan)
- [ ] Enrichir via L2.5 (playbook, NIS2 impact)
- [ ] Envoyer HITL avec boutons sur tous les canaux configurés

### P2 — Boutons inline sur tous les canaux
- [ ] Telegram InlineKeyboardMarkup + callback_query
- [ ] Mattermost (déjà câblé, juste connecter au NonceManager partagé)
- [ ] Ntfy (déjà câblé, juste connecter)
- [ ] Slack Block Kit (existant, connecter)
- [ ] Discord (webhook avec components)
- [ ] Signal / WhatsApp (texte + commandes, pas de boutons natifs)

### P3 — Bot conversationnel intelligent
- [ ] Fallback Cloud LLM quand commande non reconnue
- [ ] Réponses naturelles ("salut" → réponse humaine)
- [ ] Câbler conversation_mode.rs dans conversational_bot.rs
- [ ] Cloud: anonymiser → Cloud comprend → local exécute → Cloud reformule

## Architecture cible

```
RSSI écrit sur Telegram/Slack/Discord/...
    │
    ▼
POST /api/tc/command (channel-agnostic)
    │
    ▼
conversation_mode.rs → choisit Local/CloudAssisted/CloudDirect
    │
    ├── command_interpreter.rs (L1 LLM parse)
    │   ├── Commande reconnue → exécute
    │   └── Non reconnu → fallback
    │
    ├── cloud_intent.rs (Cloud LLM parse)
    │   └── Anonymise → Cloud comprend → plan structuré
    │
    └── Fallback → Cloud/Local LLM conversation libre
        └── "salut" → réponse naturelle
    │
    ▼
Si Remediation → HITL Flow :
    │
    ├── validate_remediation() (whitelist 25+ commandes)
    ├── enrich_hitl_with_instruct() (L2.5 playbook + NIS2)
    ├── NonceManager.generate() (anti-replay)
    ├── Envoyer boutons sur le canal du RSSI :
    │   ├── Telegram: InlineKeyboardMarkup [Approuver | Rejeter]
    │   ├── Mattermost: Interactive buttons
    │   ├── Ntfy: Action HTTP buttons
    │   ├── Slack: Block Kit buttons
    │   └── Autres: texte + commande /approve {nonce}
    │
    ▼
RSSI clique/approuve
    │
    ├── Telegram: callback_query → bot poll
    ├── Mattermost/Ntfy: HTTP POST → /api/tc/hitl/callback
    ├── Slack: webhook → /api/tc/hitl/callback
    │
    ▼
NonceManager.verify_and_consume() (anti-replay one-time)
    │
    ├── Rejeté → log + notify "Action rejetée"
    └── Approuvé → executor::execute_validated()
        │
        ▼
    Résultat → message retour sur le même canal
    + Audit log immutable
```

## Bugs critiques corrigés

| Bug | Fix |
|-----|-----|
| NonceManager temporaire par requête | Partagé dans GatewayState |
| hitl_button_callback ne fait rien | Appelle process_slack_callback |
| send_hitl_to_telegram jamais appelé | Sera câblé dans Intelligence Engine + Bot |
| Bot confirmation boucle infinie | Fix execute_command pour Remediation |
| conversation_mode.rs orphelin | Câblé dans conversational_bot.rs |
| cloud_intent ne call pas le cloud | Implémenté avec cloud_caller.rs |

---

*Document créé le 26/03/2026 — implémentation en cours*

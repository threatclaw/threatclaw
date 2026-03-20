# ThreatClaw — Heartbeat : Surveillance Proactive

## Instructions pour l'agent (exécutées automatiquement toutes les 30 minutes)

### Vérifications à effectuer

1. **Findings critiques non traités**
   - Chercher les findings avec severity=critical et status=open
   - Si trouvés → alerter le RSSI via le canal configuré
   - Format : "[HEARTBEAT] X findings critiques non traités depuis Y heures"

2. **Intégrité du soul**
   - Vérifier le hash SHA-256 de AGENT_SOUL.toml
   - Si mismatch → ALERTE CRITIQUE + kill switch

3. **Connectivité des cibles**
   - Pour chaque cible configurée dans [[targets]] :
     - Tester la connexion (ping/SSH/API selon le type)
     - Si une cible ne répond pas → alerter
   - Format : "[HEARTBEAT] Cible srv-prod-01 injoignable depuis 15min"

4. **Santé des services**
   - Vérifier que PostgreSQL répond
   - Vérifier que Redis répond
   - Vérifier que Ollama répond
   - Vérifier que Fluent Bit reçoit des logs
   - Si un service est down → alerter

5. **Volumétrie anormale**
   - Comparer le volume de logs des dernières 30min avec la moyenne
   - Si > 5x la moyenne → possible attaque ou incident
   - Si = 0 alors que des sources sont configurées → possible panne collecte

### Règles

- Ne JAMAIS exécuter d'actions correctives automatiquement
- Uniquement observer et alerter
- Si le mode agent est "Investigateur" → proposer des actions sans exécuter
- Si le mode agent est "Répondeur" → proposer et attendre approbation HITL
- Les vérifications ne doivent pas durer plus de 60 secondes
- Logger chaque vérification dans l'audit log

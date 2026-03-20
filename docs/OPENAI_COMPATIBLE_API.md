# ThreatClaw — API OpenAI-Compatible

ThreatClaw expose un endpoint compatible avec l'API OpenAI, permettant à tout client OpenAI-compatible d'interagir avec l'agent.

## Endpoints

### POST /v1/chat/completions

Envoie un message à l'agent et reçoit une réponse en streaming (SSE) ou en une fois.

```bash
curl -X POST http://threatclaw-ip:3000/v1/chat/completions \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "threatclaw",
    "messages": [
      {"role": "user", "content": "Quels sont les findings critiques ?"}
    ],
    "stream": false
  }'
```

### GET /v1/models

Liste les modèles disponibles.

```bash
curl http://threatclaw-ip:3000/v1/models \
  -H "Authorization: Bearer <token>"
```

## Cas d'usage

### SIEM → ThreatClaw
Un SIEM (Wazuh, Elastic, Splunk) peut envoyer des alertes à ThreatClaw via cet endpoint et recevoir une analyse IA en retour.

### IDE Plugin
Un plugin VS Code ou JetBrains peut utiliser ThreatClaw comme assistant de code sécurité.

### Script d'automatisation
```python
import openai

client = openai.OpenAI(
    base_url="http://threatclaw-ip:3000/v1",
    api_key="<token>"
)

response = client.chat.completions.create(
    model="threatclaw",
    messages=[{"role": "user", "content": "Analyse les 5 derniers findings critiques"}]
)
print(response.choices[0].message.content)
```

## Authentification

Bearer token identique au token du gateway web (affiché au démarrage).

## Limitations

- Le modèle est toujours l'agent ThreatClaw (pas de choix de modèle externe)
- Streaming SSE supporté avec `"stream": true`
- Max 1 message utilisateur par requête

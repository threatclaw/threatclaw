---
name: skill-shadow-ai-monitor
version: 0.1.0
description: Détecte et qualifie l'usage IA non-autorisé (Shadow AI). Corrèle alertes Sigma + graph AGE + policy. Produit findings AI_USAGE_POLICY pour auditabilité EU AI Act / NIS2 / ISO 42001.
permissions: []
requires_approval: false
data_classification: internal
nis2_articles:
  - "Art.21 §2d — Gestion de la chaîne d'approvisionnement (IA tierce)"
  - "Art.21 §2e — Acquisition, développement, maintenance des systèmes"
eu_ai_act_articles:
  - "Art.12 — Logging automatique des systèmes d'IA high-risk"
  - "Art.13-14 — Transparence et supervision humaine"
iso_42001_controls:
  - "A.5.2 — AI policy"
  - "A.6.2.2 — AI system impact assessment"
  - "A.10 — Third-party AI relationships"
activation:
  keywords:
    - shadow AI
    - shadow IA
    - unauthorized LLM
    - ChatGPT
    - Claude
    - Gemini
    - Mistral
    - Copilot
    - Ollama
    - vLLM
    - LLM usage
    - AI governance
    - AI policy
  patterns:
    - "(?i)shadow\\s*(ai|ia)"
    - "(?i)(unauthorized|undeclared)\\s+(llm|ai)"
    - "(?i)ai\\s+(governance|policy|inventory)"
  tags:
    - ai-governance
    - shadow-ai
    - compliance
---

# skill-shadow-ai-monitor

Détection et qualification de l'usage IA sortant non-autorisé (**Shadow AI**) à partir du trafic réseau observé passivement par Zeek, des alertes Sigma dédiées, et de la policy organisationnelle.

## Problème résolu

Les collaborateurs utilisent de plus en plus des LLM tiers (ChatGPT, Claude, Copilot…) ou déploient des runtimes locaux (Ollama, vLLM) **sans déclaration ni contrôle**. Conséquences :

- **Fuite de propriété intellectuelle** : code, contrats, données RH copiés dans des prompts tiers.
- **Non-conformité EU AI Act (Art. 12)** : obligation de logging pour les usages high-risk — impossible à produire si l'usage est caché.
- **Supply chain non cartographiée (NIS2 §2d-e)** : les LLM tiers sont des fournisseurs critiques non-inventoriés.
- **Violation ISO 42001 A.10** : pas de monitoring contractuel/technique des relations IA tierces.

Aucun outil FOSS SOC ne couvrait ce cas en avril 2026 — ThreatClaw est le premier.

## Modèle de détection

Passif, trois couches complémentaires :

1. **Réseau (Zeek)** — SNI TLS (`ssl.log`), requêtes DNS (`dns.log`), ports LAN (`conn.log`), paths OpenAI-compatible (`http.log`). Règles Sigma `shadow-ai-001..004` (migration V40).
2. **Endpoint (osquery/Sysmon)** — processus (`ollama`, `lms.exe`, `jan.exe`, `llama-run`), ports à l'écoute (11434/1234/8000…), fichiers `.gguf`/`.safetensors`. Pack osquery séparé (hors ce skill).
3. **Policy** — whitelist/blacklist par provider (ex: "Mistral on-prem OK, ChatGPT refusé") configurée dans `threatclaw.toml` section `[shadow_ai]`.

Ce skill orchestre l'étape **qualification** : à partir des alertes Sigma brutes, il enrichit avec l'identité (via `kerberos.log`), le graphe AGE (`:Asset → :IP → :Domain`), la policy, et produit un `finding` structuré.

## Inputs

- `time_range` *(str)* : `"1h"`, `"24h"`, `"7d"` (défaut `"24h"`).
- `alert_ids` *(list[int], optionnel)* : qualifier uniquement ces alertes.
- `policy_override` *(dict, optionnel)* : override de la policy `threatclaw.toml` pour tests.

## Outputs

- `findings[]` — chaque élément :
  - `category`: `"AI_USAGE_POLICY"`
  - `severity`: `critical` | `high` | `medium` | `low` | `informational`
  - `asset`: hostname ou IP source
  - `user`: identité Kerberos si disponible
  - `metadata`:
    - `llm_provider`: `"OpenAI"`, `"Anthropic"`, `"Ollama"`, …
    - `llm_category`: `commercial` | `self-hosted` | `coding-assistant` | `hub` | `hyperscaler`
    - `detection_type`: `fqdn` | `port` | `url_pattern`
    - `endpoint`: valeur exacte (ex `"api.openai.com"`, `11434`)
    - `policy_decision`: `allowed` | `denied` | `unreviewed`
    - `policy_reason`: explication (`"provider not in whitelist"`, `"tier 7 coding-assistant blocked"`…)
    - `first_seen_ts`, `last_seen_ts`, `connection_count`, `bytes_total`
    - `regulatory_flags`: `["eu_ai_act_art12", "nis2_art21_2d", "iso_42001_a10"]`
- `stats` — `alerts_processed`, `findings_created`, `policy_violations`, `per_provider_count`.

## Policy config (threatclaw.toml)

Section attendue — à ajouter au schéma de config :

```toml
[shadow_ai]
enabled = true
default_decision = "unreviewed"   # allowed | denied | unreviewed

# Whitelist par provider (matching exact, case-insensitive)
allowed_providers = ["Mistral"]   # ex: seule Mistral on-prem tolérée

# Blacklist explicite
denied_providers = ["DeepSeek"]   # pour raisons géopolitiques / compliance

# Blacklist par catégorie
denied_categories = ["coding-assistant"]  # refuse Copilot/Cursor/Codeium

# Severity mapping
severity_allowed      = "informational"
severity_unreviewed   = "medium"
severity_denied       = "high"
severity_self_hosted  = "high"  # self-hosted non déclaré = toujours high
```

## Pipeline interne

```
alerts (sigma_alerts WHERE rule_id LIKE 'shadow-ai-%')
    ↓
enrichment (join llm_endpoint_feed on value/port/pattern)
    ↓
identity resolution (kerberos.log window ±5min, asset → user)
    ↓
graph correlation (AGE: did this user access sensitive files recently?)
    ↓
policy evaluation (provider/category vs [shadow_ai] config)
    ↓
finding insertion (category=AI_USAGE_POLICY, metadata rich)
    ↓
[optional] propose remediation (notify RSSI, open ticket, block via pfSense)
```

## Règles Sigma consommées

| Rule ID | Source Zeek | Sévérité brute |
|---------|------------|----------------|
| `shadow-ai-001` | `ssl.log` SNI | medium |
| `shadow-ai-002` | `dns.log` query | low |
| `shadow-ai-003` | `conn.log` port | medium |
| `shadow-ai-004` | `http.log` URI | medium |

La sévérité finale du finding est **recalculée** par le skill selon la policy (un ChatGPT détecté contre une policy strict devient `high`, contre une policy `unreviewed` reste `medium`).

## Feed de référence

Table `llm_endpoint_feed` (migration V40) — 70+ entrées seed (tier 1-7). Mise à jour prévue via un futur `sync_llm_endpoint_feed()` dans `cti_feed.rs` tirant depuis `feeds.threatclaw.io/llm-endpoints.json` (fork maintenu de `abixb/llm-hosts-blocklist` MIT, GitHub Action hebdo).

## Limitations connues

- **ECH (RFC 9849) + DoH** : dégradation progressive de la détection SNI sur 12-18 mois. Fallback = endpoint osquery + IP ranges des AS providers.
- **JA4 non intégré v0.1** : champ prévu `ssl.log` → `ja4` ou `ja4s` ; à câbler dès que le parser Zeek expose ces colonnes.
- **Pas de détection de contenu** : on détecte l'usage, pas le prompt. Volontaire (RGPD + philosophie privacy-first ThreatClaw — zéro MITM).

## Roadmap

- v0.2 : intégration `ja4` fingerprint sur `ssl.log`, enrichissement UA sur `http.log`.
- v0.3 : corrélation `files.log` (transfert récent de fichiers sensibles avant la session LLM).
- v0.5 : module Python AgentPrint-inspired (arXiv 2510.07176) — fingerprint provider via timing SSE.
- v1.0 : publication pack Sigma `threatclaw/sigma-shadow-ai` + feed `feeds.threatclaw.io/llm-endpoints.json` en Apache-2.0.

## Références

- EU AI Act 2024/1689 — art. 12, 13-14, 53-55
- NIS2 Directive 2022/2555 — art. 21 §2(d-e)
- ISO/IEC 42001:2023 — A.5.2, A.6.2.2, A.10
- NIST AI RMF 2025 update — inventory control (shadow AI nommé)
- `abixb/llm-hosts-blocklist` (MIT) — liste communautaire amont
- arXiv 2510.07176 — AgentPrint (fingerprinting LLM agents via SSE)
- arXiv 2407.15847 — LLMmap (USENIX Security 2025)

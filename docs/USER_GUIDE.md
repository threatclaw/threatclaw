# Guide Utilisateur ThreatClaw v0.1.0

> *Every threat leaves a trace. We find it.*

---

## Table des matières

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [Configuration](#3-configuration)
4. [Skills — Référence](#4-skills--référence)
5. [Dashboard RSSI](#5-dashboard-rssi)
6. [Conformité NIS2](#6-conformité-nis2)
7. [Architecture](#7-architecture)
8. [Maintenance](#8-maintenance)
9. [Dépannage](#9-dépannage)

---

## 1. Introduction

### Qu'est-ce que ThreatClaw ?

ThreatClaw est un **agent cybersécurité autonome open source** conçu pour les **PME et ETI françaises** soumises à la directive NIS2. Fork d'[IronClaw](https://github.com/nearai/ironclaw) (Near AI), il orchestre intelligemment un ensemble d'outils open source via une architecture de skills WASM isolées, un LLM local ou cloud configurable, et produit des rapports de conformité NIS2/ISO 27001 en français.

**Le problème** : Les PME françaises sous NIS2 font face à une double contrainte — obligations de cybersécurité croissantes, mais pas d'équipe sécurité dédiée. Les solutions enterprise (Wiz, Tenable, CrowdStrike) sont inaccessibles. Les outils open source (Wazuh, OpenVAS) nécessitent une expertise technique élevée et restent des silos sans coordination.

**La solution** : ThreatClaw remplace une équipe SOC complète par un agent autonome qui :

- Scanne les vulnérabilités (réseau, images, code, cloud)
- Détecte les secrets exposés dans les dépôts Git
- Simule des campagnes de phishing pour la sensibilisation
- Surveille le dark web pour les fuites de données
- Analyse les logs en continu avec des règles Sigma
- Génère automatiquement des rapports NIS2 et ISO 27001 en français

| Capacité | Wazuh | Tenable/Wiz | **ThreatClaw** |
|---|---|---|---|
| Scan vulnérabilités | Partiel | Oui | **Oui** |
| SIEM / logs | Oui | Non | **Oui** |
| Détection IA | Non | Partiel | **Oui** |
| Dark web | Non | Non | **Oui** |
| Simulation phishing | Non | Non | **Oui** |
| Rapport NIS2 FR auto | Non | Non | **Oui** |
| 100% infra client | Oui | Non (SaaS) | **Oui** |
| < 2 GB RAM | Non (~6 GB) | Non (Cloud) | **Oui** |
| Open source | Oui (GPL) | Non | **Oui (Apache 2.0)** |

### Modèle B+ — Données on-premise

ThreatClaw fonctionne en modèle B+ : **une instance autonome par client, 100% dans l'infrastructure du client**. Aucune donnée brute ne quitte jamais le périmètre du client.

```
Client PME                     MSSP (vous)
─────────────────────          ──────────────────
ThreatClaw instance   <--VPN-->  Dashboard lecture
  └── Toutes données              seule à la demande
      restent ici
```

**Ce qui sort** (si configuré) :
- Notifications d'alerte sans données sensibles (Slack/email)
- Résumés anonymisés vers LLM cloud (après passage par l'anonymiseur)

**Ce qui ne sort JAMAIS** :
- Logs bruts
- CVEs détaillées avec contexte réseau
- Findings de sécurité
- Topologie réseau
- Credentials et secrets détectés

### Conformité NIS2 (Directive EU 2022/2555)

ThreatClaw est conçu dès l'origine pour aider les PME à se conformer à la **Directive NIS2** (Directive (UE) 2022/2555 du Parlement européen et du Conseil du 14 décembre 2022). Il couvre les 10 mesures de gestion des risques définies à l'Article 21 §2 (a-j) et génère automatiquement des rapports de conformité mappés sur chaque article.

---

## 2. Installation

### Prérequis

| Composant | Spécification minimum | Recommandé |
|---|---|---|
| **OS** | Debian 12+ / Ubuntu 22.04+ | Debian 12 |
| **RAM** | 4 GB | 8 GB |
| **CPU** | 2 vCPU | 4 vCPU |
| **Disque** | 20 GB SSD | 50 GB SSD |
| **Docker** | Docker Engine + Compose v2 | Dernière version stable |
| **Réseau** | Accès Internet pour pull des images | - |

> **Note** : Pour utiliser un LLM local (Ollama), prévoyez au minimum 8 GB de RAM supplémentaires et un GPU est fortement recommandé.

### Installation one-liner

```bash
curl -fsSL https://raw.githubusercontent.com/threatclaw/threatclaw/main/installer/install.sh | sudo bash
```

Cette commande :
1. Vérifie les prérequis système (OS, RAM, Docker)
2. Crée l'utilisateur et les répertoires système (`/opt/threatclaw/`)
3. Télécharge les fichiers de configuration
4. Pull toutes les images Docker (12 services)
5. Génère un mot de passe aléatoire pour PostgreSQL
6. Démarre la stack complète
7. Installe le service systemd `threatclaw.service`

### Installation manuelle

Si vous préférez une installation manuelle :

```bash
# 1. Cloner le dépôt
git clone https://github.com/threatclaw/threatclaw.git
cd threatclaw

# 2. Copier et éditer la configuration
cp threatclaw.toml threatclaw.local.toml
# Editez threatclaw.local.toml selon votre environnement

# 3. Définir le mot de passe PostgreSQL
export TC_DB_PASSWORD=$(openssl rand -base64 24)

# 4. Lancer la stack
docker compose -f docker/docker-compose.yml up -d
```

### Configuration post-installation

Après l'installation, éditez le fichier de configuration principal :

```bash
# Fichier de configuration principal
sudo nano /opt/threatclaw/threatclaw.toml

# Ou si installation manuelle
nano threatclaw.local.toml
```

Les paramètres essentiels à configurer :
1. **Nom de l'instance** : identifiant unique pour cette installation
2. **Niveau de permission** : voir section [Niveaux de permission](#niveaux-de-permission)
3. **Backend LLM** : Ollama local (recommandé) ou cloud
4. **Notifications** : Slack et/ou email

### Vérification de l'installation

```bash
# Vérifier que tous les services sont démarrés
docker compose -f docker/docker-compose.yml ps

# Résultat attendu : 12 services en état "running" ou "healthy"
# - threatclaw-core      (healthy)
# - threatclaw-db        (healthy)
# - threatclaw-dashboard (running)
# - redis                (healthy)
# - nuclei               (running)
# - trivy                (running)
# - grype                (running)
# - gitleaks             (running)
# - gophish              (running)
# - prowler              (running)
# - falco                (running)
# - fluent-bit           (running)

# Vérifier l'accès au dashboard
curl -s http://localhost:3000 | head -5

# Vérifier l'API core
curl -s http://localhost:18789/health
```

---

## 3. Configuration

### Fichier threatclaw.toml — Référence complète

Le fichier `threatclaw.toml` est le fichier de configuration principal de ThreatClaw. Voici toutes les options documentées :

```toml
# ══════════════════════════════════════════════════════════
# ThreatClaw — Configuration client
# Documentation : https://github.com/threatclaw/threatclaw
# ══════════════════════════════════════════════════════════

# ── Paramètres généraux ──────────────────────────────────
[general]
# Nom unique de cette instance (apparaît dans les rapports et alertes)
instance_name = "threatclaw-default"

# Niveau de permission de l'agent (voir détail ci-dessous)
# READ_ONLY | ALERT_ONLY | REMEDIATE_WITH_APPROVAL | FULL_AUTO
permission_level = "ALERT_ONLY"

# Langue des rapports et de l'interface
# "fr" | "en"
language = "fr"

# ── Configuration LLM ───────────────────────────────────
[llm]
# Option 1 : 100% local (recommandé pour données sensibles)
backend = "ollama"
model = "mistral:7b"
base_url = "http://localhost:11434"

# Option 2 : Souveraineté française (Mistral AI)
# backend = "mistral"
# api_key = "env:MISTRAL_API_KEY"

# Option 3 : Meilleure qualité rapports (Anthropic Claude)
# backend = "anthropic"
# model = "claude-sonnet-4-20250514"
# api_key = "env:ANTHROPIC_API_KEY"

# ── Routage intelligent LLM ─────────────────────────────
[llm.routing]
# Tâches TOUJOURS traitées en local (jamais envoyées vers cloud)
# Contiennent des données sensibles : logs, alertes, scores CVE
local_only = ["log_analysis", "alert_triage", "vuln_scoring"]

# Tâches pouvant aller vers cloud (après passage par l'anonymiseur)
cloud_allowed = ["report_generation", "compliance_analysis", "phishing_templates"]

# ── Anonymiseur ──────────────────────────────────────────
[anonymizer]
# Activer/désactiver l'anonymisation avant envoi au LLM cloud
enabled = true

# Remplacer les IPs internes (RFC 1918) par des placeholders [IP_1], [IP_2]...
strip_internal_ips = true

# Remplacer les noms d'utilisateurs par des placeholders [USER_1]...
strip_usernames = true

# Remplacer les credentials (password=xxx, token=xxx) par [CRED_1]...
strip_credentials = true

# Remplacer les hostnames internes (*.local, *.corp, *.lan) par [HOST_1]...
strip_hostnames = true

# ── Planification des scans ──────────────────────────────
[scheduler]
# Scan réseau quotidien à 02h00
vuln_scan_daily = "0 2 * * *"

# Campagne de phishing mensuelle le 1er du mois à 10h00
phishing_monthly = "0 10 1 * *"

# Vérification dark web toutes les 6 heures
darkweb_check = "0 */6 * * *"

# Audit posture cloud hebdomadaire le lundi à 03h00
cloud_posture_weekly = "0 3 * * 1"

# Analyse des logs toutes les 5 minutes
log_analysis = "*/5 * * * *"

# Rapport hebdomadaire le vendredi à 08h00
report_weekly = "0 8 * * 5"

# ── Notifications ────────────────────────────────────────
[notifications]
# Slack — webhook URL (stockée en variable d'environnement)
# slack_webhook = "env:SLACK_WEBHOOK_URL"
# slack_channel = "#threatclaw-alerts"

# Email — serveur SMTP
# smtp_host = "smtp.example.com"
# smtp_port = 587
# smtp_from = "threatclaw@example.com"
# smtp_to = ["rssi@example.com"]

# ── Base de données ──────────────────────────────────────
[database]
url = "postgres://threatclaw:threatclaw@localhost:5432/threatclaw"
```

### Niveaux de permission

ThreatClaw propose 4 niveaux de permission pour contrôler ce que l'agent peut faire de manière autonome :

| Niveau | Description | Actions autorisées | Cas d'usage |
|---|---|---|---|
| `READ_ONLY` | Scans et collecte uniquement | Scans, analyse de logs, collecte d'informations. Aucune notification, aucune action. | Phase de déploiement initial, test |
| `ALERT_ONLY` | + Notifications | Tout READ_ONLY + envoi d'alertes via Slack/email. Aucune action corrective. | **Niveau standard recommandé** |
| `REMEDIATE_WITH_APPROVAL` | + Actions après validation RSSI | Tout ALERT_ONLY + actions de remédiation (patch, blocage IP, etc.) uniquement après validation explicite du RSSI via Slack ou le dashboard. | **Niveau recommandé pour PME matures** |
| `FULL_AUTO` | Actions réversibles automatiques | Tout REMEDIATE_WITH_APPROVAL + actions réversibles simples sans validation. Les actions irréversibles nécessitent toujours une approbation. | Environnements très contrôlés uniquement |

> **Recommandation** : Commencez toujours par `ALERT_ONLY` pendant les 2 premières semaines, puis passez à `REMEDIATE_WITH_APPROVAL` une fois que vous avez confiance dans les alertes.

### Configuration LLM

ThreatClaw supporte 3 backends LLM :

#### Option 1 : Ollama local (recommandé)

Le LLM tourne entièrement sur votre serveur. Aucune donnée ne quitte l'infrastructure.

```toml
[llm]
backend = "ollama"
model = "mistral:7b"        # Bon compromis qualité/performance
base_url = "http://localhost:11434"
```

**Installation Ollama** :
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull mistral:7b
```

Modèles recommandés :
- `mistral:7b` — Modèle par défaut, bon pour le français, 4 GB RAM
- `llama3:8b` — Alternative, meilleur raisonnement, 5 GB RAM
- `codestral:22b` — Meilleur pour l'analyse de code, 13 GB RAM

#### Option 2 : Mistral Cloud (souveraineté française)

Mistral AI est une entreprise française. Les données passent par l'anonymiseur avant envoi.

```toml
[llm]
backend = "mistral"
api_key = "env:MISTRAL_API_KEY"
```

```bash
export MISTRAL_API_KEY="votre-clé-api-mistral"
```

#### Option 3 : Anthropic Claude (meilleure qualité)

Meilleure qualité pour la génération de rapports. Les données passent par l'anonymiseur.

```toml
[llm]
backend = "anthropic"
model = "claude-sonnet-4-20250514"
api_key = "env:ANTHROPIC_API_KEY"
```

```bash
export ANTHROPIC_API_KEY="votre-clé-api-anthropic"
```

### Configuration des notifications

#### Slack

1. Créez un webhook Slack entrant : [https://api.slack.com/messaging/webhooks](https://api.slack.com/messaging/webhooks)
2. Configurez dans `threatclaw.toml` :

```toml
[notifications]
slack_webhook = "env:SLACK_WEBHOOK_URL"
slack_channel = "#threatclaw-alerts"
```

3. Exportez la variable d'environnement :
```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../xxx"
```

Les alertes Slack incluent :
- Sévérité (critique, élevée, moyenne, faible)
- Résumé de l'alerte
- Actions recommandées
- Boutons d'approbation (si niveau `REMEDIATE_WITH_APPROVAL`)

#### Email

```toml
[notifications]
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_from = "threatclaw@example.com"
smtp_to = ["rssi@example.com", "dsi@example.com"]
```

### Planification des scans (syntaxe cron)

La planification utilise la syntaxe cron standard à 5 champs :

```
┌───────────── minute (0 - 59)
│ ┌───────────── heure (0 - 23)
│ │ ┌───────────── jour du mois (1 - 31)
│ │ │ ┌───────────── mois (1 - 12)
│ │ │ │ ┌───────────── jour de la semaine (0 - 6, 0 = dimanche)
│ │ │ │ │
* * * * *
```

| Scan | Cron par défaut | Fréquence | Description |
|---|---|---|---|
| `vuln_scan_daily` | `0 2 * * *` | Quotidien 02h00 | Scan de vulnérabilités réseau |
| `phishing_monthly` | `0 10 1 * *` | Mensuel, 1er à 10h00 | Campagne de phishing |
| `darkweb_check` | `0 */6 * * *` | Toutes les 6h | Vérification dark web |
| `cloud_posture_weekly` | `0 3 * * 1` | Lundi 03h00 | Audit cloud |
| `log_analysis` | `*/5 * * * *` | Toutes les 5 min | Analyse des logs |
| `report_weekly` | `0 8 * * 5` | Vendredi 08h00 | Rapport hebdomadaire |

### Anonymiseur — Données masquées avant envoi LLM

L'anonymiseur intercepte toutes les données envoyées vers un LLM cloud et remplace les informations sensibles par des placeholders réversibles. Cela permet au LLM de travailler avec le contexte structurel sans exposer les données réelles.

**Catégories de données masquées :**

| Catégorie | Pattern détecté | Placeholder | Exemple |
|---|---|---|---|
| IPs internes | `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x` | `[IP_1]`, `[IP_2]`... | `192.168.1.42` -> `[IP_1]` |
| IPv6 ULA | `fd00::/8` | `[IPV6_1]`... | `fd12:3456::1` -> `[IPV6_1]` |
| Emails | `user@domain.com` | `[EMAIL_1]`... | `jean@corp.fr` -> `[EMAIL_1]` |
| Hostnames internes | `*.internal`, `*.local`, `*.corp`, `*.lan` | `[HOST_1]`... | `srv01.corp` -> `[HOST_1]` |
| Credentials | `password=xxx`, `token=xxx`, `api_key=xxx` | `[CRED_1]`... | `password=S3cr3t` -> `[CRED_1]` |
| Clés SSH | `-----BEGIN RSA PRIVATE KEY-----` | `[SSH_KEY_1]`... | Clé complète masquée |
| Clés AWS | `AKIA...` | `[AWS_KEY_1]`... | `AKIAIOSFODNN7EXAMPLE` -> `[AWS_KEY_1]` |
| Clés GCP | `AIza...` | `[GCP_KEY_1]`... | Clé masquée |
| Connexions Azure | `AccountKey=...` | `[AZURE_1]`... | Chaîne masquée |
| SIRET/SIREN | Numéros d'identification | `[SIRET_1]`... | Numéro masqué |
| Adresses MAC | `XX:XX:XX:XX:XX:XX` | `[MAC_1]`... | Adresse masquée |
| Téléphones FR | `+33...`, `06...`, `07...` | `[PHONE_1]`... | Numéro masqué |

Le mapping inverse est conservé en mémoire pour dé-anonymiser les réponses du LLM avant affichage au RSSI.

---

## 4. Skills — Référence

ThreatClaw utilise un système de **skills** (compétences) modulaires, chacune spécialisée dans un domaine de la cybersécurité. Chaque skill est isolée dans un sandbox WASM et ne peut accéder qu'aux ressources explicitement autorisées.

### 4.1 skill-vuln-scan — Scan de vulnérabilités

**Description** : Orchestre Nuclei (scan réseau/web) et Grype (scan images Docker/dépendances) pour identifier les CVE et les prioriser par criticité réelle via scoring CVSS + EPSS.

**Inputs** :
| Paramètre | Type | Description |
|---|---|---|
| `targets` | `string[]` | IPs, domaines ou plages réseau à scanner |
| `scan_type` | `string` | `"quick"` (top vulns) ou `"full"` (toutes catégories) |
| `images` | `string[]` | Images Docker à analyser (optionnel) |
| `severity_filter` | `string` | Sévérités à inclure : `"critical,high,medium"` |

**Outputs** :
| Champ | Type | Description |
|---|---|---|
| `findings[]` | `array` | Liste des vulnérabilités trouvées |
| `summary` | `object` | Nombre par sévérité (critique, élevée, moyenne, faible) |
| `top_10` | `array` | Top 10 par score de priorité (CVSS * EPSS) |
| `nis2_mapping` | `object` | Mapping vers Art.21 §2a et §2b |

**Exemple de résultat** :
```
Résumé : 3 critiques, 7 élevées, 15 moyennes, 22 faibles

Top 3 :
1. CVE-2024-3094 (xz backdoor)  — CVSS 10.0, EPSS 0.97 -> Priorité 9.70
2. CVE-2024-21762 (FortiOS RCE) — CVSS 9.8,  EPSS 0.89 -> Priorité 8.72
3. CVE-2023-44487 (HTTP/2 Rapid Reset) — CVSS 7.5, EPSS 0.95 -> Priorité 7.12
```

**Configuration spécifique** :
```toml
[scheduler]
vuln_scan_daily = "0 2 * * *"    # Planification du scan
```

**Outils sous-jacents** : Nuclei (6000+ templates), Grype, API EPSS (first.org), API NVD (NIST)

---

### 4.2 skill-secrets — Détection de secrets

**Description** : Détecte les credentials exposés dans les dépôts Git (historique complet) via Gitleaks. Classifie par type et évalue la criticité.

**Inputs** :
| Paramètre | Type | Description |
|---|---|---|
| `repo_path` | `string` | Chemin du dépôt Git à scanner |
| `scan_mode` | `string` | `"full"` (historique complet) ou `"head"` (HEAD uniquement) |

**Outputs** :
| Champ | Type | Description |
|---|---|---|
| `secrets[]` | `array` | Secrets détectés (type, fichier, commit, criticité) |
| `summary` | `object` | Nombre par criticité |
| `actions` | `string[]` | Actions de remédiation recommandées |

**Exemple de résultat** :
```
3 secrets critiques détectés :
1. AWS Access Key dans config/deploy.py (commit abc1234, 2024-01-15) -> Rotation immédiate
2. GitHub Token dans .env.backup (commit def5678, 2024-02-20)       -> Révocation
3. Password BDD dans docker-compose.yml (commit ghi9012, 2024-03-01) -> Externaliser
```

**Types de secrets détectés** : AWS keys, GCP keys, Azure connection strings, GitHub tokens, mots de passe en clair, JWT, clés SSH, clés privées SSL/TLS, connection strings base de données, et 150+ autres patterns.

**Configuration spécifique** : Aucune configuration particulière. Le scan est déclenché manuellement ou via le scheduler.

**Outil sous-jacent** : Gitleaks

> **Important** : Les secrets ne sont **jamais** affichés en clair dans les résultats. Ils sont toujours masqués (redacted).

---

### 4.3 skill-email-audit — Audit sécurité email

**Description** : Vérifie les configurations DMARC, SPF et DKIM des domaines clients via checkdmarc. Alerte si exposition au spoofing email.

**Inputs** :
| Paramètre | Type | Description |
|---|---|---|
| `domains` | `string[]` | Domaines à auditer (ex: `["example.com"]`) |

**Outputs** :
| Champ | Type | Description |
|---|---|---|
| `score` | `number` | Score global de sécurité email (0-100) |
| `dmarc` | `object` | Politique, pourcentage, reporting |
| `spf` | `object` | Mécanisme terminal, lookups DNS |
| `dkim` | `object` | Sélecteurs trouvés, taille clé |
| `recommendations` | `string[]` | Recommandations priorisées |

**Exemple de résultat** :
```
Score global : 45/100

DMARC : Politique "none" (non protecteur) -> Passer à "quarantine" puis "reject"
SPF   : ~all (softfail) -> Passer à -all (hardfail)
DKIM  : Clé RSA 1024 bits -> Migrer vers 2048 bits
```

**Configuration spécifique** : Aucune. Utilise uniquement des requêtes DNS publiques (lecture seule).

**Outil sous-jacent** : checkdmarc

**Mapping NIS2** : Art.21 §2e (Sécurité des réseaux et systèmes d'information)

---

### 4.4 skill-darkweb — Surveillance dark web

**Description** : Surveille HaveIBeenPwned (HIBP) pour les emails et domaines exposés. Détecte les fuites de credentials et alerte le RSSI.

**Inputs** :
| Paramètre | Type | Description |
|---|---|---|
| `domains` | `string[]` | Domaines à surveiller |
| `emails` | `string[]` | Emails spécifiques à vérifier (optionnel) |

**Outputs** :
| Champ | Type | Description |
|---|---|---|
| `breaches[]` | `array` | Breaches détectées par email/domaine |
| `critical_count` | `number` | Nombre de comptes nécessitant une rotation immédiate |
| `actions` | `string[]` | Actions prioritaires |

**Exemple de résultat** :
```
12 comptes exposés sur le domaine example.com :
- 3 critiques (breach récente avec passwords) -> Reset MDP immédiat + MFA
- 5 élevés (breach ancienne avec passwords)   -> Reset MDP recommandé
- 4 moyens (breach sans passwords)            -> Sensibilisation
```

**Configuration spécifique** :
```bash
# Clé API HIBP (requise)
export HIBP_API_KEY="votre-clé-api-hibp"
```

```toml
[scheduler]
darkweb_check = "0 */6 * * *"    # Vérification toutes les 6h
```

**Outil sous-jacent** : API HaveIBeenPwned v3

> **Important** : Les emails sont anonymisés dans les résultats (`j***@company.com`). Rate limit : 10 requêtes/minute.

---

### 4.5 skill-phishing — Simulation de phishing

**Description** : Génère des templates de phishing contextualisés via LLM, orchestre GoPhish via API REST, analyse les résultats et produit un rapport NIS2 Art.21 §2g.

**Inputs** :
| Paramètre | Type | Description |
|---|---|---|
| `target_group` | `string` | Nom du groupe cible |
| `template_type` | `string` | `"generic"`, `"spear"`, ou `"ceo_fraud"` |
| `sector` | `string` | Secteur d'activité pour contextualisation |
| `language` | `string` | `"fr"` ou `"en"` |

**Outputs** :
| Champ | Type | Description |
|---|---|---|
| `campaign_id` | `string` | Identifiant GoPhish de la campagne |
| `results` | `object` | Taux d'ouverture, de clic, de soumission |
| `report` | `object` | Rapport de sensibilisation complet |
| `benchmarks` | `object` | Comparaison avec les benchmarks PME |

**Exemple de résultat** :
```
Campagne "Sensibilisation Q1 2026" — 150 utilisateurs
- Emails envoyés : 150
- Emails ouverts : 62 (41%) — benchmark PME : ~40%
- Liens cliqués : 23 (15%) — benchmark PME : ~15%
- Formulaires soumis : 8 (5%) — benchmark PME : ~5%

Recommandation : Formation ciblée pour les 8 utilisateurs ayant soumis le formulaire
```

**Configuration spécifique** :
```bash
# Clé API GoPhish (requise)
export GOPHISH_API_KEY="votre-clé-api-gophish"
```

```toml
[scheduler]
phishing_monthly = "0 10 1 * *"    # Campagne mensuelle
```

**Outil sous-jacent** : GoPhish (API REST)

> **Important** : Toute campagne nécessite une **validation RSSI explicite** avant envoi (`requires_approval: true`). Maximum 1 campagne par mois par groupe.

---

### 4.6 skill-soc-monitor — Monitoring SOC

**Description** : Collecte les alertes via Fluent Bit et les règles Sigma. Triage intelligent par LLM. Filtre les faux positifs. Corrélation multi-sources.

**Inputs** :
| Paramètre | Type | Description |
|---|---|---|
| `time_range` | `string` | Période d'analyse (ex: `"last_24h"`, `"last_7d"`) |
| `sources` | `string[]` | Sources de logs (`"syslog"`, `"docker"`, `"auth"`, `"falco"`) |
| `sigma_rulesets` | `string[]` | Sets de règles Sigma à appliquer |

**Outputs** :
| Champ | Type | Description |
|---|---|---|
| `alerts[]` | `array` | Alertes détectées et triées par criticité |
| `false_positive_rate` | `number` | Taux de faux positifs estimé par le LLM |
| `correlations[]` | `array` | Corrélations entre alertes de sources différentes |
| `timeline` | `array` | Chronologie des événements |

**Exemple de résultat** :
```
Période : dernières 24h — 3 alertes critiques, 8 élevées, 45 moyennes

Alerte #1 (CRITIQUE) : Brute force SSH détecté
  Source : auth.log — Sigma rule : win_brute_force_logon
  12 tentatives échouées depuis 185.x.x.x en 3 minutes
  Action : Bloquer l'IP source + vérifier les comptes ciblés

Corrélation : Alerte #1 + Alerte #3 (scan de ports depuis la même IP)
  -> Probable reconnaissance avant attaque
```

**Configuration spécifique** :
```toml
[scheduler]
log_analysis = "*/5 * * * *"    # Analyse toutes les 5 minutes
```

**Sources de logs collectées** :
- Syslog (UDP 5140)
- Docker container logs (TCP 24224)
- Auth logs (`/var/log/auth.log`)
- Alertes Falco (HTTP 8888)

**Outils sous-jacents** : Fluent Bit, Falco, moteur Sigma

**Mapping NIS2** : Art.21 §2b (Gestion des incidents), Art.21 §2c (Continuité des activités)

---

### 4.7 skill-cloud-posture — Audit cloud

**Description** : Audit de posture sécurité AWS/Azure/GCP via Prowler. 300+ checks CIS/NIS2/ISO 27001. Agentless, credentials read-only.

**Inputs** :
| Paramètre | Type | Description |
|---|---|---|
| `cloud_provider` | `string` | `"aws"`, `"azure"`, ou `"gcp"` |
| `checks` | `string[]` | Liste de checks spécifiques ou `["all"]` |
| `compliance_framework` | `string` | `"cis"`, `"nis2"`, ou `"iso27001"` |

**Outputs** :
| Champ | Type | Description |
|---|---|---|
| `findings[]` | `array` | Résultats des checks (pass/fail/warning) |
| `compliance_score` | `number` | Score de conformité (0-100) |
| `pass_count` | `number` | Nombre de checks réussis |
| `fail_count` | `number` | Nombre de checks échoués |

**Exemple de résultat** :
```
Audit AWS — Framework CIS — Score : 72/100
  - 216 checks passés
  - 84 checks échoués
  - 12 critiques : S3 buckets publics, MFA non activé sur root, etc.

Top 5 actions :
1. Activer MFA sur le compte root AWS
2. Fermer les S3 buckets publics (3 détectés)
3. Activer le chiffrement au repos sur RDS
4. Restreindre les security groups trop permissifs (0.0.0.0/0)
5. Activer CloudTrail sur toutes les régions
```

**Configuration spécifique** :
```toml
[scheduler]
cloud_posture_weekly = "0 3 * * 1"    # Audit hebdomadaire lundi 03h00
```

Les credentials cloud doivent être configurées en read-only. Exemple AWS :
```bash
export AWS_ACCESS_KEY_ID="votre-access-key"
export AWS_SECRET_ACCESS_KEY="votre-secret-key"
export AWS_DEFAULT_REGION="eu-west-3"    # Paris
```

**Outil sous-jacent** : Prowler

---

### 4.8 skill-report-gen — Génération de rapports

**Description** : Génère des rapports PDF en français — rapport exécutif (COMEX), rapport technique (IT), et rapport de conformité (NIS2/ISO 27001).

**Inputs** :
| Paramètre | Type | Description |
|---|---|---|
| `report_type` | `string` | `"executive"`, `"technical"`, ou `"compliance"` |
| `period` | `string` | Période couverte (ex: `"2026-03"`) |
| `framework` | `string` | `"nis2"`, `"iso27001"`, ou `"both"` |
| `include_sections` | `string[]` | Sections à inclure (optionnel, toutes par défaut) |

**Outputs** :
| Champ | Type | Description |
|---|---|---|
| `pdf_path` | `string` | Chemin du rapport PDF généré |
| `summary` | `string` | Résumé du rapport |
| `compliance_score` | `number` | Score global de conformité |

**Types de rapports** :

| Type | Audience | Contenu |
|---|---|---|
| `executive` | COMEX / Direction | Score global, tendances, risques majeurs, budget recommandé |
| `technical` | DSI / IT | CVEs détaillées, actions de remédiation, configurations |
| `compliance` | RSSI / Auditeurs | Mapping NIS2/ISO 27001, scores par article, gaps, plan d'action |

**Configuration spécifique** :
```toml
[scheduler]
report_weekly = "0 8 * * 5"    # Rapport hebdomadaire vendredi 08h00
```

**Mapping NIS2** : Art.21 §1 (Mesures de gestion des risques), Art.23 (Obligations de notification)

---

### 4.9 skill-compliance-nis2 — Conformité NIS2

**Description** : Mappe tous les findings vers les articles NIS2 (Art.21 §1-10). Calcule un score de conformité par article. Analyse des gaps.

**Inputs** :
| Paramètre | Type | Description |
|---|---|---|
| `findings_source` | `string` | `"all"`, `"last_scan"`, ou `"period"` |
| `period` | `string` | Période d'analyse (si `findings_source = "period"`) |
| `include_recommendations` | `bool` | Inclure les recommandations d'actions correctives |

**Outputs** :
| Champ | Type | Description |
|---|---|---|
| `overall_score` | `number` | Score global NIS2 (0-100) |
| `article_scores` | `object` | Score par article (§2a à §2j) |
| `gaps[]` | `array` | Articles non couverts ou insuffisants |
| `actions[]` | `array` | Actions correctives recommandées |
| `compliance_report` | `object` | Rapport structuré pour skill-report-gen |

**Exemple de résultat** :
```
Score global NIS2 : 68/100

Art.21 §2a (Analyse des risques)          : 75/100
Art.21 §2b (Gestion des incidents)        : 80/100
Art.21 §2c (Continuité des activités)     : 45/100  <- GAP
Art.21 §2d (Chaîne d'approvisionnement)   : 30/100  <- GAP
Art.21 §2e (Acquisition et maintenance)   : 70/100
Art.21 §2f (Évaluation efficacité)        : 65/100
Art.21 §2g (Cyberhygiène et formation)    : 85/100
Art.21 §2h (Cryptographie)               : 60/100
Art.21 §2i (RH et contrôle d'accès)      : 70/100
Art.21 §2j (Authentification MFA)        : 55/100  <- GAP
```

**Configuration spécifique** : Aucune configuration particulière. Utilise les findings de toutes les autres skills.

---

### 4.10 skill-compliance-iso27001 — Conformité ISO 27001

**Description** : Mappe les findings vers les 93 contrôles de l'Annexe A de la norme ISO 27001:2022. Score de conformité par catégorie. Statement of Applicability (SoA). Évaluation de maturité.

**Inputs** :
| Paramètre | Type | Description |
|---|---|---|
| `scope` | `string` | `"full"` ou `"category"` |
| `category_filter` | `string` | Filtre par catégorie : `"A.5"`, `"A.6"`, `"A.7"`, `"A.8"` |
| `include_soa` | `bool` | Inclure le Statement of Applicability |
| `include_recommendations` | `bool` | Inclure les recommandations |

**Outputs** :
| Champ | Type | Description |
|---|---|---|
| `overall_score` | `number` | Score global de conformité (0-100) |
| `maturity_level` | `string` | Niveau de maturité global (`INITIAL` à `OPTIMIZED`) |
| `category_scores[]` | `array` | Scores par catégorie |
| `soa[]` | `array` | Statement of Applicability complet |
| `action_plan[]` | `array` | Plan d'action priorisé |
| `summary_fr` | `string` | Résumé en français |

**Catégories ISO 27001:2022 Annexe A** :

| Catégorie | Nombre de contrôles | Description |
|---|---|---|
| A.5 | 37 contrôles | Contrôles organisationnels |
| A.6 | 8 contrôles | Contrôles liés aux personnes |
| A.7 | 14 contrôles | Contrôles physiques |
| A.8 | 34 contrôles | Contrôles technologiques |

**Niveaux de maturité** :

| Niveau | Score | Description |
|---|---|---|
| `INITIAL` | 0-20 | Processus ad hoc, non documentés |
| `MANAGED` | 21-40 | Processus de base en place |
| `DEFINED` | 41-60 | Processus documentés et standardisés |
| `MEASURED` | 61-80 | Processus mesurés et contrôlés |
| `OPTIMIZED` | 81-100 | Amélioration continue |

**Configuration spécifique** : Aucune configuration particulière.

---

## 5. Dashboard RSSI

### Accès

Le dashboard est accessible à l'adresse :

```
http://localhost:3000
```

> **Note** : En production, configurez un reverse proxy NGINX avec HTTPS et authentification.

### Page principale — Vue d'ensemble

La page principale affiche :

- **Score de sécurité global** : Indicateur agrégé (0-100) basé sur tous les findings actifs
- **Findings actifs** : Nombre total de findings par sévérité (critique, élevé, moyen, faible)
- **Alertes récentes** : Timeline des dernières alertes avec statut (nouveau, en cours, résolu)
- **Tendance** : Graphique d'évolution du score sur les 30 derniers jours
- **Prochains scans** : Liste des scans planifiés avec leur prochaine exécution

### Page conformité NIS2

Accessible via l'onglet **Conformité** :

- **Score global NIS2** : Jauge 0-100 avec code couleur
- **Scores par article** : Barres horizontales pour chaque article Art.21 §2a à §2j
- **Gaps identifiés** : Liste des articles en dessous du seuil acceptable (< 50)
- **Actions correctives** : Plan d'action priorisé pour combler les gaps
- **Historique** : Évolution des scores de conformité dans le temps

### Page alertes SOC

Accessible via l'onglet **Alertes** :

- **Timeline** : Chronologie des alertes avec sévérité et source
- **Filtres** : Par sévérité, source, période, statut (nouveau/en cours/résolu)
- **Corrélations** : Regroupement automatique des alertes liées
- **Détail d'alerte** : En cliquant sur une alerte — description, source, règle Sigma déclenchée, actions recommandées
- **Actions** : Boutons d'approbation/rejet pour les actions de remédiation (si `REMEDIATE_WITH_APPROVAL`)

### Page rapports

Accessible via l'onglet **Rapports** :

- **Génération** : Bouton pour générer un rapport à la demande (exécutif, technique, conformité)
- **Historique** : Liste des rapports générés avec date et type
- **Téléchargement** : Téléchargement direct en PDF
- **Planification** : Visualisation et modification de la planification des rapports automatiques

---

## 6. Conformité NIS2

### Mapping Article 21 §1-10

La Directive NIS2 (UE 2022/2555) impose aux entités essentielles et importantes de mettre en place des mesures de gestion des risques en matière de cybersécurité. L'Article 21 §2 définit 10 domaines spécifiques :

| Article | Domaine | Skills ThreatClaw | Couverture |
|---|---|---|---|
| §2a | Politiques d'analyse des risques et sécurité des SI | skill-vuln-scan, skill-cloud-posture, skill-compliance-nis2 | Scan de vulnérabilités, audit cloud, scoring de risque |
| §2b | Gestion des incidents | skill-soc-monitor, skill-report-gen | Détection, triage, corrélation, notification |
| §2c | Continuité des activités et gestion de crise | skill-soc-monitor | Monitoring continu, alertes temps réel |
| §2d | Sécurité de la chaîne d'approvisionnement | skill-vuln-scan (Grype), skill-cloud-posture | Scan des dépendances, audit fournisseurs cloud |
| §2e | Sécurité dans l'acquisition, développement et maintenance | skill-vuln-scan, skill-email-audit | Scans CVE, audit configurations |
| §2f | Évaluation de l'efficacité des mesures | skill-compliance-nis2, skill-compliance-iso27001 | Scores de conformité, tendances, gap analysis |
| §2g | Pratiques de cyberhygiène et formation | skill-phishing | Campagnes de sensibilisation, métriques |
| §2h | Cryptographie et chiffrement | skill-secrets, skill-email-audit | Détection de clés exposées, audit DKIM |
| §2i | Sécurité des ressources humaines et contrôle d'accès | skill-secrets, skill-darkweb | Détection credentials, surveillance fuites |
| §2j | Authentification multi-facteur | skill-cloud-posture, skill-darkweb | Audit MFA, détection comptes compromis |

### Comment ThreatClaw couvre chaque article

#### Art.21 §2a — Politiques de sécurité des SI
- `skill-vuln-scan` scanne quotidiennement le réseau et les images Docker
- `skill-cloud-posture` audite la posture cloud avec 300+ checks CIS
- `skill-compliance-nis2` évalue le score de conformité et produit des recommandations

#### Art.21 §2b — Gestion des incidents
- `skill-soc-monitor` collecte et analyse les logs en continu (toutes les 5 min)
- Détection via règles Sigma + triage LLM
- Alertes Slack/email avec actions recommandées
- `skill-report-gen` documente les incidents pour le reporting réglementaire

#### Art.21 §2c — Continuité des activités
- `skill-soc-monitor` assure un monitoring 24/7
- Alertes en temps réel pour les événements critiques
- Corrélation multi-sources pour détection précoce

#### Art.21 §2d — Chaîne d'approvisionnement
- `skill-vuln-scan` (Grype) scanne les dépendances et images Docker
- `skill-cloud-posture` audite les configurations des fournisseurs cloud

#### Art.21 §2e — Acquisition, développement et maintenance
- `skill-vuln-scan` détecte les CVE dans les systèmes en production
- `skill-email-audit` vérifie les configurations de sécurité email

#### Art.21 §2f — Évaluation de l'efficacité
- `skill-compliance-nis2` produit des scores par article avec tendances
- `skill-compliance-iso27001` évalue la maturité organisationnelle
- Rapports automatiques avec évolution dans le temps

#### Art.21 §2g — Cyberhygiène et formation
- `skill-phishing` mène des campagnes de sensibilisation mensuelles
- Métriques de progression par département
- Recommandations de formation ciblées

#### Art.21 §2h — Cryptographie
- `skill-secrets` détecte les clés privées et credentials exposés
- `skill-email-audit` vérifie la taille des clés DKIM (>= 2048 bits)

#### Art.21 §2i — RH et contrôle d'accès
- `skill-secrets` détecte les credentials dans le code
- `skill-darkweb` identifie les comptes compromis

#### Art.21 §2j — Authentification multi-facteur
- `skill-cloud-posture` vérifie l'activation du MFA (AWS root, IAM users)
- `skill-darkweb` identifie les comptes nécessitant un MFA urgent

### Niveaux de maturité (1-5)

ThreatClaw évalue la maturité de chaque domaine sur une échelle de 1 à 5 :

| Niveau | Nom | Score | Description |
|---|---|---|---|
| 1 | Initial | 0-20 | Processus inexistants ou ad hoc. Aucune documentation. |
| 2 | Géré | 21-40 | Processus de base en place mais non systématiques. Documentation partielle. |
| 3 | Défini | 41-60 | Processus documentés et standardisés. Application systématique. |
| 4 | Mesuré | 61-80 | Processus mesurés et contrôlés. KPIs en place. |
| 5 | Optimisé | 81-100 | Amélioration continue. Processus automatisés et revus régulièrement. |

### Génération du rapport de conformité

```bash
# Via le dashboard : onglet Rapports -> Nouveau rapport -> Type "Conformité"

# Ou via l'API :
curl -X POST http://localhost:18789/api/reports/generate \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "compliance",
    "framework": "nis2",
    "period": "2026-03",
    "include_recommendations": true
  }'
```

Le rapport de conformité inclut :
- Page de garde avec score global
- Résumé exécutif (1 page)
- Score détaillé par article (Art.21 §2a à §2j)
- Gap analysis avec actions correctives priorisées
- Annexes : findings détaillés, métriques, tendances

---

## 7. Architecture

### Schéma des 3 couches

```
┌─────────────────────────────────────────────────────────────────────┐
│                        COUCHE 1 — Core Rust                        │
│                      (fork IronClaw / Near AI)                      │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐    │
│  │  Scheduler   │  │  Anonymizer  │  │     Permissions        │    │
│  │   Cyber      │  │  LLM Cloud   │  │ READ / ALERT / REMED   │    │
│  │  (cron)      │  │  (réversible)│  │ / FULL_AUTO            │    │
│  └──────────────┘  └──────────────┘  └────────────────────────┘    │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐    │
│  │  LLM Router  │  │  Sigma       │  │     API REST           │    │
│  │ local/cloud   │  │  Engine      │  │   :18789               │    │
│  └──────────────┘  └──────────────┘  └────────────────────────┘    │
├─────────────────────────────────────────────────────────────────────┤
│                    COUCHE 2 — Skills WASM                           │
│                   (sandbox isolées par skill)                       │
│                                                                     │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐      │
│  │ vuln-scan  │ │  secrets   │ │  phishing  │ │  darkweb   │      │
│  │ Nuclei     │ │  Gitleaks  │ │  GoPhish   │ │  HIBP API  │      │
│  │ + Grype    │ │            │ │  + LLM     │ │            │      │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘      │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐      │
│  │ email-aud  │ │ soc-monit  │ │ cloud-post │ │ report-gen │      │
│  │ checkdmarc │ │ Fluent Bit │ │  Prowler   │ │  LLM+PDF   │      │
│  │            │ │ + Sigma    │ │            │ │            │      │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘      │
│  ┌────────────┐ ┌────────────┐                                     │
│  │  nis2      │ │ iso27001   │                                     │
│  │ compliance │ │ compliance │                                     │
│  └────────────┘ └────────────┘                                     │
├─────────────────────────────────────────────────────────────────────┤
│                  COUCHE 3 — Services Docker                        │
│               (12 containers, réseau interne isolé)                 │
│                                                                     │
│  PostgreSQL+pgvector  Redis  Nuclei  Trivy  Grype  Gitleaks       │
│  GoPhish  Prowler  Falco  Fluent Bit  Dashboard (Next.js)          │
│  ThreatClaw Core (Rust)                                             │
└─────────────────────────────────────────────────────────────────────┘
```

### Flux de données

```
                                ┌──────────────┐
                                │  LLM Cloud   │
                                │ (Mistral /   │
                                │  Anthropic)  │
                                └──────┬───────┘
                                       │ Données anonymisées
                                       │ uniquement
                   ┌───────────────────┴───────────────────┐
                   │            ANONYMISEUR                 │
                   │  IPs -> [IP_1], Hosts -> [HOST_1]     │
                   │  Emails -> [EMAIL_1], etc.            │
                   └───────────────────┬───────────────────┘
                                       │
┌──────────┐    ┌──────────┐    ┌──────┴───────┐    ┌──────────────┐
│ Syslog   │───>│Fluent Bit│───>│ PostgreSQL   │───>│ Sigma Engine │
│ Auth.log │    │          │    │ + pgvector   │    │              │
│ Docker   │    └──────────┘    └──────┬───────┘    └──────┬───────┘
│ Falco    │                           │                    │
└──────────┘                           │                    │
                                       v                    v
                                ┌──────────────┐    ┌──────────────┐
                                │  Dashboard   │    │   Alertes    │
                                │  (Next.js)   │    │ Slack/Email  │
                                │  :3000       │    │              │
                                └──────────────┘    └──────────────┘
```

1. **Collecte** : Fluent Bit collecte les logs depuis syslog (UDP 5140), Docker (TCP 24224), auth.log (tail) et Falco (HTTP 8888)
2. **Stockage** : Tous les logs sont stockés dans PostgreSQL (avec pgvector pour les embeddings)
3. **Analyse** : Le moteur Sigma applique les règles de détection sur les logs stockés
4. **Triage** : Le LLM (local ou cloud via anonymiseur) trie et priorise les alertes
5. **Notification** : Les alertes sont envoyées via Slack et/ou email selon la configuration
6. **Dashboard** : Le dashboard Next.js lit les données depuis PostgreSQL et l'API core

### Anonymisation (flux LLM)

```
Données brutes                  Données anonymisées
──────────────                  ────────────────────
"Serveur srv01.corp             "Serveur [HOST_1]
 IP 192.168.1.42                 IP [IP_1]
 user jean.dupont                user [USER_1]
 password=S3cr3t!                [CRED_1]
 a un CVE critique"              a un CVE critique"

       │                                │
       └── JAMAIS envoyé au cloud       └── Envoyé au LLM cloud
                                             pour analyse
       ┌── Mapping conservé en RAM ─────┐
       │  [HOST_1] = srv01.corp         │
       │  [IP_1]   = 192.168.1.42      │
       │  [USER_1] = jean.dupont       │
       │  [CRED_1] = password=S3cr3t!  │
       └────────────────────────────────┘

Réponse LLM : "Le serveur [HOST_1] ([IP_1]) nécessite un patch urgent"
Dé-anonymisée : "Le serveur srv01.corp (192.168.1.42) nécessite un patch urgent"
```

### Sécurité

**Sandbox WASM** : Chaque skill s'exécute dans un sandbox WebAssembly (WASM) isolé. Les skills ne peuvent accéder qu'aux ressources explicitement déclarées dans leur manifeste (permissions HTTP, API, fichiers).

**Trust levels** : Les services Docker sont isolés dans deux réseaux :
- `threatclaw-internal` : Réseau interne isolé (pas d'accès Internet). Contient la base de données, les scanners et les collecteurs de logs.
- `threatclaw-frontend` : Réseau frontal. Contient uniquement le core, le dashboard et GoPhish (pour les campagnes de phishing).

**Credentials** : Toutes les clés API et mots de passe sont stockés en variables d'environnement (`env:NOM_VARIABLE`), jamais en clair dans les fichiers de configuration.

---

## 8. Maintenance

### Mise à jour

Pour mettre à jour ThreatClaw vers la dernière version :

```bash
# Via l'installer (recommandé)
curl -fsSL https://raw.githubusercontent.com/threatclaw/threatclaw/main/installer/install.sh | sudo bash -s -- --update

# Ou manuellement
cd /opt/threatclaw
git pull origin main
docker compose -f docker/docker-compose.yml pull
docker compose -f docker/docker-compose.yml up -d
```

La mise à jour :
1. Pull les nouvelles images Docker
2. Applique les migrations de base de données automatiquement
3. Redémarre les services modifiés (sans perdre les données)

### Sauvegarde de la base de données

```bash
# Sauvegarde manuelle
docker exec threatclaw-db pg_dump -U threatclaw -F c threatclaw > backup_$(date +%Y%m%d).dump

# Restauration
docker exec -i threatclaw-db pg_restore -U threatclaw -d threatclaw < backup_20260318.dump

# Sauvegarde automatique quotidienne (ajouter au crontab)
# 0 1 * * * docker exec threatclaw-db pg_dump -U threatclaw -F c threatclaw > /opt/threatclaw/backups/backup_$(date +\%Y\%m\%d).dump
```

> **Recommandation** : Sauvegardez quotidiennement et conservez au minimum 30 jours de sauvegardes (exigence NIS2 Art.21 §2c).

### Rotation des logs

Les logs Docker sont configurés avec une rotation automatique :
- **Taille maximale** : 10 MB par fichier log
- **Nombre de fichiers** : 3 fichiers maximum par service

```bash
# Vérifier l'espace disque utilisé par les logs
docker system df

# Nettoyer les logs manuellement si nécessaire
docker system prune --volumes
```

Pour les logs applicatifs dans PostgreSQL, configurez une politique de rétention :

```sql
-- Supprimer les logs de plus de 90 jours
DELETE FROM logs WHERE timestamp < NOW() - INTERVAL '90 days';
```

### Monitoring

**Health checks** : Chaque service dispose d'un health check intégré :

```bash
# Vérifier le statut de tous les services
docker compose -f docker/docker-compose.yml ps

# Vérifier un service spécifique
docker inspect --format='{{.State.Health.Status}}' threatclaw-core
```

**Endpoint /metrics** : Le core expose des métriques Prometheus sur :

```
http://localhost:18789/metrics
```

Métriques disponibles :
- `threatclaw_scans_total` : Nombre total de scans exécutés
- `threatclaw_findings_total` : Nombre total de findings
- `threatclaw_alerts_total` : Nombre total d'alertes
- `threatclaw_compliance_score` : Score de conformité actuel
- `threatclaw_llm_requests_total` : Nombre de requêtes LLM
- `threatclaw_anonymizer_replacements_total` : Nombre de remplacements anonymiseur

**Fluent Bit monitoring** :

```
http://localhost:2020/api/v1/metrics
```

---

## 9. Dépannage

### Problèmes fréquents et solutions

#### Le dashboard ne s'affiche pas

```bash
# Vérifier que le service dashboard tourne
docker compose -f docker/docker-compose.yml ps threatclaw-dashboard

# Vérifier les logs
docker compose -f docker/docker-compose.yml logs threatclaw-dashboard

# Redémarrer le dashboard
docker compose -f docker/docker-compose.yml restart threatclaw-dashboard
```

**Causes fréquentes** :
- Port 3000 déjà utilisé par un autre service
- Le core n'est pas encore démarré (dépendance)
- Problème de mémoire (le dashboard nécessite ~256 MB)

#### PostgreSQL ne démarre pas

```bash
# Vérifier les logs PostgreSQL
docker compose -f docker/docker-compose.yml logs threatclaw-db

# Vérifier l'espace disque
df -h

# Vérifier que le volume existe
docker volume ls | grep pgdata
```

**Causes fréquentes** :
- Espace disque insuffisant
- Port 5432 déjà utilisé
- Permissions sur le volume de données

#### Les scans ne se lancent pas

```bash
# Vérifier que le scheduler fonctionne
docker compose -f docker/docker-compose.yml logs threatclaw-core | grep scheduler

# Vérifier la configuration cron
grep -A 10 '\[scheduler\]' /opt/threatclaw/threatclaw.toml

# Lancer un scan manuellement
curl -X POST http://localhost:18789/api/scans/trigger \
  -H "Content-Type: application/json" \
  -d '{"skill": "skill-vuln-scan", "targets": ["localhost"]}'
```

#### Le LLM ne répond pas (Ollama)

```bash
# Vérifier que Ollama tourne
curl http://localhost:11434/api/tags

# Vérifier que le modèle est téléchargé
ollama list

# Retélécharger le modèle
ollama pull mistral:7b

# Vérifier la configuration
grep -A 5 '\[llm\]' /opt/threatclaw/threatclaw.toml
```

#### Les notifications Slack ne fonctionnent pas

```bash
# Vérifier la variable d'environnement
echo $SLACK_WEBHOOK_URL

# Tester le webhook manuellement
curl -X POST $SLACK_WEBHOOK_URL \
  -H "Content-Type: application/json" \
  -d '{"text": "Test ThreatClaw"}'

# Vérifier les logs core
docker compose -f docker/docker-compose.yml logs threatclaw-core | grep slack
```

#### Mémoire insuffisante

```bash
# Vérifier l'utilisation mémoire par container
docker stats --no-stream

# Réduire la mémoire si nécessaire en arrêtant les services non essentiels
docker compose -f docker/docker-compose.yml stop prowler  # Si pas de cloud
docker compose -f docker/docker-compose.yml stop gophish  # Si pas de phishing
```

### Logs

```bash
# Voir les logs de tous les services
docker compose -f docker/docker-compose.yml logs

# Logs d'un service spécifique
docker compose -f docker/docker-compose.yml logs threatclaw-core
docker compose -f docker/docker-compose.yml logs threatclaw-db
docker compose -f docker/docker-compose.yml logs fluent-bit

# Suivre les logs en temps réel
docker compose -f docker/docker-compose.yml logs -f threatclaw-core

# Logs depuis les dernières 2 heures
docker compose -f docker/docker-compose.yml logs --since 2h threatclaw-core
```

### Reset complet

En dernier recours, pour réinitialiser complètement l'installation :

```bash
# ATTENTION : Cette commande supprime toutes les données !
docker compose -f docker/docker-compose.yml down -v
docker compose -f docker/docker-compose.yml up -d
```

> **Avertissement** : Cette commande supprime toutes les données, y compris la base de données, les résultats de scans et les rapports. Effectuez une sauvegarde avant.

### Contact support

- **Documentation** : [https://github.com/threatclaw/threatclaw](https://github.com/threatclaw/threatclaw)
- **Issues GitHub** : [https://github.com/threatclaw/threatclaw/issues](https://github.com/threatclaw/threatclaw/issues)
- **Sécurité** : Pour les vulnérabilités de sécurité, utilisez les GitHub Security Advisories (responsible disclosure)
- **Email** : contact@cyberconsulting.fr

---

*ThreatClaw v0.1.0 — Développé par [CyberConsulting.fr](https://cyberconsulting.fr) — Licence Apache 2.0*

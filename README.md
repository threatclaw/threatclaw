# ThreatClaw

**Agent Cybersécurité Autonome Open Source**

*Every threat leaves a trace. We find it.*

---

ThreatClaw est un agent cybersécurité autonome open source, fork d'[IronClaw](https://github.com/nearai/ironclaw) (Near AI), spécialisé pour la cybersécurité des PME. Il orchestre intelligemment un ensemble d'outils open source via une architecture de skills WASM isolées, un LLM local ou cloud configurable, et produit des rapports de conformité NIS2/ISO 27001 en français.

## Le problème

Les PME françaises sous NIS2 font face à une double contrainte : obligations de cybersécurité croissantes, mais pas d'équipe sécurité dédiée. Les solutions enterprise (Wiz, Tenable, CrowdStrike) sont inaccessibles. Les outils open source (Wazuh, OpenVAS) nécessitent une expertise technique élevée et restent des silos sans coordination.

## La solution

| Capacité | Wazuh | Tenable/Wiz | **ThreatClaw** |
|---|---|---|---|
| Scan vulnérabilités | Partiel | ✓ | **✓** |
| SIEM / logs | ✓ | ✗ | **✓** |
| Détection IA | ✗ | Partiel | **✓** |
| Dark web | ✗ | ✗ | **✓** |
| Simulation phishing | ✗ | ✗ | **✓** |
| Rapport NIS2 FR auto | ✗ | ✗ | **✓** |
| 100% infra client | ✓ | ✗ SaaS | **✓** |
| < 2 GB RAM | ✗ ~6 GB | ✗ Cloud | **✓** |
| Open source | ✓ GPL | ✗ | **✓ Apache 2.0** |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ThreatClaw Core                       │
│              (Rust — fork IronClaw)                      │
│  ┌──────────┐ ┌──────────────┐ ┌──────────────────┐    │
│  │Scheduler │ │ Anonymizer   │ │   Permissions     │    │
│  │  Cyber   │ │ LLM Cloud    │ │ READ/ALERT/REMED  │    │
│  └──────────┘ └──────────────┘ └──────────────────┘    │
├─────────────────────────────────────────────────────────┤
│                   Skills WASM                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │vuln-scan │ │ secrets  │ │ phishing │ │ darkweb  │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │email-aud │ │soc-monit │ │cloud-post│ │report-gen│  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
│  ┌──────────┐ ┌──────────┐                              │
│  │nis2-comp │ │ appsec   │                              │
│  └──────────┘ └──────────┘                              │
├─────────────────────────────────────────────────────────┤
│                Services Docker                          │
│  Nuclei · Trivy · Grype · Gitleaks · GoPhish            │
│  Prowler · Falco · Fluent Bit · PostgreSQL+pgvector     │
└─────────────────────────────────────────────────────────┘
```

## Prérequis

| Configuration | Specs | Usage |
|---|---|---|
| **Minimum** | 4 GB RAM / 2 vCPU / 20 GB SSD | Stack V1 (~1.6 GB RAM) |
| **Recommandée** | 8 GB RAM / 4 vCPU / 50 GB SSD | Stack complète V1+V2 |
| **Optimale** | 16 GB RAM / 8 vCPU / 100 GB SSD | Stack + Wazuh optionnel |

- Docker Engine + Compose v2
- Debian 12 / Ubuntu 22.04+ (ou tout Linux avec Docker)

## Installation rapide

```bash
# Cloner le repo
git clone https://github.com/threatclaw/threatclaw.git
cd threatclaw

# Lancer la stack de développement
docker compose -f docker/docker-compose.dev.yml up -d

# Compiler le core
cargo build --release

# Lancer la stack complète
docker compose -f docker/docker-compose.yml up -d
```

## Configuration

Copiez et éditez le fichier de configuration :

```bash
cp threatclaw.toml threatclaw.local.toml
# Editez threatclaw.local.toml selon votre environnement
```

Configurez votre LLM provider dans `threatclaw.toml` :

```toml
[llm]
# 100% local (recommandé)
backend = "ollama"
model = "mistral:7b"
base_url = "http://localhost:11434"

# Ou Claude API (meilleure qualité rapports)
# backend = "anthropic"
# model = "claude-sonnet-4-20250514"
# api_key = "env:ANTHROPIC_API_KEY"
```

## Modèle de déploiement (B+)

ThreatClaw fonctionne en modèle B+ : **une instance autonome par client, 100% dans l'infra du client**. Aucune donnée ne quitte l'infrastructure cliente.

```
Client PME                     MSSP (vous)
─────────────────────          ──────────────────
ThreatClaw instance   ←VPN→   Dashboard lecture
  └── Toutes données           seule à la demande
      restent ici
```

**Ce qui sort** : notifications d'alerte sans données (Slack/email), résumés anonymisés vers LLM cloud.
**Ce qui ne sort JAMAIS** : logs bruts, CVEs détaillées, findings, topologie réseau.

## Skills cybersécurité

| Pilier | Skill | Description | Outil |
|---|---|---|---|
| AppSec | `skill-vuln-scan` | Scan CVE réseau + images | Nuclei, Grype |
| AppSec | `skill-appsec` | SAST + dépendances | Trivy, Semgrep |
| Secrets | `skill-secrets` | Détection credentials Git | Gitleaks |
| Phishing | `skill-phishing` | Simulation + templates LLM | GoPhish |
| Email | `skill-email-audit` | DMARC/SPF/DKIM | checkdmarc |
| Dark Web | `skill-darkweb` | Surveillance fuites | HIBP API |
| SOC | `skill-soc-monitor` | Logs + Sigma rules + triage | Fluent Bit, Falco |
| Cloud | `skill-cloud-posture` | Audit AWS/Azure/GCP | Prowler |
| Rapports | `skill-report-gen` | PDF NIS2/ISO 27001 FR | LLM + PDF |
| Conformité | `skill-compliance-nis2` | Mapping Art.21 + score | Règles internes |

## Niveaux de droits

| Niveau | Permissions | Cas d'usage |
|---|---|---|
| `READ_ONLY` | Scans + collecte uniquement | Déploiement initial |
| `ALERT_ONLY` | + notifications Slack/email | Standard |
| `REMEDIATE_WITH_APPROVAL` | + actions après validation RSSI | Recommandé |
| `FULL_AUTO` | Actions réversibles simples | Très limité |

## Contribuer

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les guidelines de contribution.

- **Skills** : PR + review code + test sandbox isolé
- **Core** : PR + tests CI automatiques + review mainteneur
- **Sécurité** : responsible disclosure via GitHub Security Advisories

## Licence

Apache 2.0 — voir [LICENSE-APACHE](LICENSE-APACHE).

Fork de [IronClaw](https://github.com/nearai/ironclaw) (Near AI) — Apache 2.0 / MIT.

## Crédits

- [IronClaw](https://github.com/nearai/ironclaw) par Near AI — base du projet
- [Nuclei](https://github.com/projectdiscovery/nuclei) — scanner CVE
- [GoPhish](https://github.com/gophish/gophish) — simulation phishing
- [Trivy](https://github.com/aquasecurity/trivy) — scanner containers
- [Prowler](https://github.com/prowlercloud/prowler) — audit cloud
- [Falco](https://github.com/falcosecurity/falco) — détection runtime
- [Gitleaks](https://github.com/gitleaks/gitleaks) — détection secrets

---

*Développé par [CyberConsulting.fr](https://cyberconsulting.fr) — RSSI à temps partagé pour PME*

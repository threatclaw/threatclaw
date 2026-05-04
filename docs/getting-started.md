# Getting Started

## Requirements

| Composant | Minimum | Recommandé |
|-----------|---------|------------|
| **OS** | Debian 12+ / Ubuntu 22.04+ | Debian 13, Ubuntu 24.04 |
| **Docker** | Docker Engine 24+ avec Compose plugin | Docker 27+ |
| **RAM** | 8 GB (sans IA locale) | 16 GB+ (modèles IA : ~8 GB VRAM) |
| **Disque** | 30 GB | 50 GB+ |
| **Réseau** | Accès Internet (premier démarrage) | — |

### Espace disque détaillé

| Composant | Taille |
|-----------|--------|
| Images Docker (core, dashboard, DB, ML, Fluent Bit...) | ~5 GB |
| Modèles IA Ollama (L1 triage + L2 forensic + L3 instruct) | ~18 GB |
| Base PostgreSQL + logs | ~2 GB (croît avec l'usage) |
| **Total premier boot** | **~25 GB** |

### Partitionnement

Docker stocke images et volumes dans `/var/lib/docker` par défaut. L'installeur détecte automatiquement les partitions disponibles, mais voici les recommandations :

**Partition unique** (cas simple) :
```
/  →  50 GB+    ← tout ici, rien à configurer
```

**Partitions LVM séparées** (serveurs durcis) :
```
/      →  10 GB    ← système
/var   →  50 GB+   ← Docker stocke ici par défaut
/opt   →  5 GB     ← fichiers de config ThreatClaw
/home  →  selon    ← non utilisé par ThreatClaw
/tmp   →  1 GB     ← non utilisé
```

Si `/var` est trop petit, deux options :

```bash
# Option 1 : agrandir /var (LVM)
lvextend -L +30G /dev/vg/var && resize2fs /dev/vg/var

# Option 2 : rediriger le stockage Docker à l'installation
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --docker-data /home/docker
```

L'installeur détecte automatiquement si `/var` manque de place et propose une relocalisation. Vous pouvez aussi configurer Docker manuellement via `/etc/docker/daemon.json` :

```json
{ "data-root": "/home/docker" }
```

## Installation

### One-liner (recommandé)

```bash
curl -fsSL https://get.threatclaw.io | sudo bash
```

Options courantes :

```bash
# Port personnalisé
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --port 8443

# Répertoire d'installation personnalisé
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --data /srv/threatclaw

# Rediriger le stockage Docker (petite partition /var)
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --docker-data /home/docker

# Combiné
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --data /srv/threatclaw --docker-data /home/docker --port 8443
```

L'installeur :
1. Installe Docker si absent
2. Analyse le partitionnement et adapte les chemins
3. Génère un mot de passe DB et un token d'auth sécurisés
4. Télécharge les images
5. Démarre les services
6. Télécharge les modèles IA en arrière-plan (~15-20 GB, 10-15 min)

### Docker Compose (manuel)

```bash
git clone https://github.com/threatclaw/threatclaw.git
cd threatclaw/docker
cp .env.example .env
# Edit .env to set your password and ports
docker compose up -d
```

### From source (developers only)

```bash
git clone https://github.com/threatclaw/threatclaw.git && cd threatclaw
cargo build --release
./target/release/threatclaw run
# Dashboard: cd dashboard && npm install && npm run build && npx next start -p 3001
```

Requires: Rust 1.90+, PostgreSQL 16 with graph extensions, local LLM runtime.

## First boot

On first boot, ThreatClaw will:
1. Create the database schema
2. Download the local AI models (~15-20 GB, 10-15 min on a typical link)
3. Start the Intelligence Engine
4. Start the dashboard on port 3001

**First access:** Open `http://your-server:3001` → Create your admin account → Follow the onboarding wizard.

## Configuration

### Ports

Edit `.env` before starting:
```bash
TC_DASHBOARD_PORT=3001    # Dashboard (default: 3001)
TC_CORE_PORT=3000         # API (default: 3000)
TC_SYSLOG_PORT=514        # Syslog receiver (default: 514)
```

### Database password

```bash
TC_DB_PASSWORD=your-secure-password
```

The installer generates a random password automatically.

### Cloud LLM (optional)

Add a cloud LLM for enhanced conversation quality:
```bash
ANTHROPIC_API_KEY=sk-ant-...    # Claude
MISTRAL_API_KEY=...              # Mistral AI
```

ThreatClaw works 100% locally without cloud. Cloud LLM is optional.

## Sending logs to ThreatClaw

ThreatClaw receives logs via Fluent Bit on port 514 (syslog).

| Source | Configuration |
|--------|--------------|
| **Linux** | Add `*.* @@threatclaw-ip:514` to `/etc/rsyslog.conf` |
| **Windows** | Install [NXLog CE](https://nxlog.co/products/nxlog-community-edition) |
| **pfSense** | Status > System Logs > Settings > Enable Remote Logging |
| **FortiGate** | `config log syslogd setting` → set server IP |
| **Docker** | `--log-driver=fluentd --log-opt fluentd-address=threatclaw-ip:24224` |

## Troubleshooting

### Espace disque insuffisant

```bash
# Vérifier l'espace par partition
df -h /var /opt /home

# Si /var est plein (Docker y stocke ses images par défaut)
# Option 1 : agrandir avec LVM
lvextend -L +30G /dev/mapper/vg-var && resize2fs /dev/mapper/vg-var

# Option 2 : déplacer le stockage Docker
sudo systemctl stop docker
echo '{"data-root": "/home/docker"}' | sudo tee /etc/docker/daemon.json
sudo rsync -a /var/lib/docker/ /home/docker/
sudo systemctl start docker
```

### Erreur containerd "blob not found"

Si vous avez supprimé manuellement des fichiers dans `/var/lib/containerd/` ou `/var/lib/docker/` :

```bash
sudo systemctl stop docker docker.socket containerd
sudo rm -rf /var/lib/containerd/*
sudo systemctl start containerd docker
```

### Changer de port

```bash
cd /opt/threatclaw
sed -i 's/TC_DASHBOARD_PORT=.*/TC_DASHBOARD_PORT=8443/' .env
docker compose down && docker compose up -d
```

### Gestion de l'installation

```bash
# Vérifier l'état des services
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --status

# Mettre à jour (pull dernières images, restart — garde les données)
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --update

# Réinstallation propre (wipe DB + config, garde le cache images Docker → ~2 min)
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --clean

# Désinstallation complète (supprime tout : données + images Docker)
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --uninstall
```

| Commande | Données | Images Docker | Réinstalle |
|----------|---------|---------------|------------|
| `--update` | conservées | mises à jour | oui (restart) |
| `--clean` | supprimées | conservées (cache) | oui (~2 min) |
| `--uninstall` | supprimées | supprimées | non |

### Voir les logs

```bash
cd /opt/threatclaw
docker compose ps                          # État des services
docker compose logs -f threatclaw-core     # Core (Rust)
docker compose logs -f threatclaw-dashboard # Dashboard (Next.js)
docker compose logs -f ollama              # Modèles IA
docker compose logs -f fluent-bit          # Ingestion de logs
```

### Modèles IA bloqués

Ollama a besoin d'un accès Internet. Les modèles (~18 GB) sont téléchargés au premier démarrage.

```bash
# Vérifier la progression
docker compose logs ollama | tail -20

# Relancer le téléchargement manuellement
docker compose exec ollama ollama pull <model-name>
```

## Endpoint Agents — inventory & CVE coverage

The ThreatClaw Endpoint Agent is a lightweight read-only collector that
reports each host's OS, software, listening ports, users, scheduled
tasks and SSH keys to ThreatClaw every 5 minutes. It does **not**
remediate anything on the machine — pure inventory.

### Generate a webhook token

In the dashboard, open **Setup → Endpoints**. The page shows the
server URL clients should use, the webhook token, and one-line
install commands for Linux/macOS and Windows. Both the URL and the
token are copy-paste-ready.

### Install on a Linux endpoint

```bash
curl -fsSL https://get.threatclaw.io/agent | sudo bash -s -- \
  --url https://your-tc-server --token <WEBHOOK_TOKEN>
```

Supported : Debian 12+, Ubuntu 22.04+, RHEL 9+, Fedora, macOS (Homebrew).

### Install on a Windows endpoint

PowerShell as Administrator:

```powershell
$env:TC_URL='https://your-tc-server'
$env:TC_TOKEN='<WEBHOOK_TOKEN>'
irm https://get.threatclaw.io/agent/windows | iex
```

The installer creates a Scheduled Task that syncs every 5 minutes as SYSTEM.

### Verify the agent registered

The **Setup → Endpoints** page lists every registered agent with its
hostname and last sync timestamp. Each agent's host then appears in
**Inventaire → Assets** with its software, OS and a CVE finding for
every package matched against public vulnerability feeds.

## Declare critical assets

Attack-path prediction only works once at least one asset is flagged
as `critical`. From the dashboard, open **Inventaire → Assets**, click
the asset (typically a domain controller, file server or production
database) and set its criticality to `critical`. The next prediction
cycle will compute paths from exposed entry points to that target.

## Next steps

- [Configuration options](configuration.md) — All settings
- [Available skills](skills.md) — Connectors, Intelligence, Actions
- [API documentation](api.md) — REST API endpoints
- [Skill Development Guide](SKILL_DEVELOPMENT_GUIDE.md) — Build custom skills

# Getting Started

This page walks you from a fresh server to a working ThreatClaw
deployment with at least one endpoint reporting in. It takes about
fifteen minutes of operator time; the local AI model download runs in
the background after that and finishes on its own.

## Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Debian 12+ / Ubuntu 22.04+ / RHEL 9+ | Debian 13, Ubuntu 24.04 |
| **Docker** | Docker Engine 24+ with the Compose plugin | Docker 27+ |
| **RAM** | 8 GB (without the local AI tier) | 16 GB+ (local AI ~8 GB resident) |
| **Disk** | 30 GB | 50 GB+ |
| **Network** | Internet access on first boot (model pull) | — |

### Disk usage breakdown

| Component | Size |
|-----------|------|
| Docker images (core, dashboard, DB, ML engine, Fluent Bit, ...) | ~5 GB |
| Local AI models (L1 triage + L2 forensic + L3 instruct) | ~18 GB |
| PostgreSQL data + logs | ~2 GB (grows with use) |
| **Total after first boot** | **~25 GB** |

### Partitioning

Docker stores images and volumes under `/var/lib/docker` by default.
The installer detects the available partitions and adapts, but for a
hardened LVM layout the safe choice is:

```
/      → 10 GB     ← system
/var   → 50 GB+    ← Docker stores here by default
/opt   → 5 GB      ← ThreatClaw config + data
/home  → as needed ← not used by ThreatClaw
/tmp   → 1 GB      ← not used by ThreatClaw
```

If `/var` is too small, either resize it or relocate the Docker data
root:

```bash
# Option 1 — grow /var (LVM)
lvextend -L +30G /dev/vg/var && resize2fs /dev/vg/var

# Option 2 — relocate the Docker data root at install time
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --docker-data /home/docker
```

The installer auto-detects when `/var` is short on space and offers
to relocate. You can also configure Docker manually via
`/etc/docker/daemon.json`:

```json
{ "data-root": "/home/docker" }
```

## Installation

### One-line install (recommended)

```bash
curl -fsSL https://get.threatclaw.io | sudo bash
```

No `curl`? The `wget` variant works the same way:

```bash
wget -qO- https://get.threatclaw.io | sudo bash
```

Common options:

```bash
# Custom port
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --port 8443

# Custom install directory
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --data /srv/threatclaw

# Relocate the Docker data root (small /var partition)
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --docker-data /home/docker

# Combined
curl -fsSL https://get.threatclaw.io | sudo bash -s -- \
  --data /srv/threatclaw --docker-data /home/docker --port 8443
```

What the installer does, in order:

1. Installs Docker if absent.
2. Inspects the partitioning and adapts the storage paths.
3. Generates a strong database password and an auth token.
4. Pulls the container images.
5. Starts the services.
6. Pulls the local AI models in the background (~15-20 GB, 10-15 min
   on a typical link).

### Docker Compose (manual)

```bash
git clone https://github.com/threatclaw/threatclaw.git
cd threatclaw/docker
cp .env.example .env
# Edit .env to set the password and ports
docker compose up -d
```

### From source (developers only)

```bash
git clone https://github.com/threatclaw/threatclaw.git && cd threatclaw
cargo build --release
./target/release/threatclaw run
# Dashboard:
cd dashboard && npm install && npm run build && npx next start -p 3001
```

Requires Rust 1.90+, PostgreSQL 16 with graph extensions, and a local
LLM runtime.

## First boot

On the first start ThreatClaw will:

1. Create the database schema.
2. Pull the local AI models (~15-20 GB, 10-15 min on a typical link).
3. Start the Intelligence Engine.
4. Start the dashboard on port 3001.

**First access**: open `http://your-server:3001`, create the admin
account, and follow the onboarding wizard.

## Configuration

### Ports

Edit `.env` before starting:

```bash
TC_DASHBOARD_PORT=3001   # Dashboard (default 3001)
TC_CORE_PORT=3000        # API (default 3000)
TC_SYSLOG_PORT=514       # Syslog receiver (default 514)
```

### Database password

```bash
TC_DB_PASSWORD=your-secure-password
```

The installer generates a random password automatically.

### Cloud LLM (optional)

Add a cloud LLM for enhanced conversation quality:

```bash
ANTHROPIC_API_KEY=sk-ant-...   # Claude
MISTRAL_API_KEY=...            # Mistral AI
```

ThreatClaw works 100% locally without any cloud LLM. The cloud tier
is optional.

## Sending logs to ThreatClaw

ThreatClaw receives logs via Fluent Bit on port 514 (syslog).

| Source | Configuration |
|--------|---------------|
| **Linux** | Add `*.* @@threatclaw-ip:514` to `/etc/rsyslog.conf` |
| **Windows** | Install [NXLog CE](https://nxlog.co/products/nxlog-community-edition) |
| **pfSense** | Status → System Logs → Settings → enable remote logging |
| **FortiGate** | `config log syslogd setting` → set server IP |
| **Docker** | `--log-driver=fluentd --log-opt fluentd-address=threatclaw-ip:24224` |

## Endpoint Agents — inventory & CVE coverage

The ThreatClaw Endpoint Agent is a lightweight read-only collector
that reports each host's OS, software, listening ports, users,
scheduled tasks and SSH keys to ThreatClaw every 5 minutes. It does
**not** remediate anything on the machine — pure inventory.

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

Supported: Debian 12+, Ubuntu 22.04+, RHEL 9+, Fedora, macOS
(Homebrew).

### Install on a Windows endpoint

PowerShell as Administrator:

```powershell
$env:TC_URL='https://your-tc-server'
$env:TC_TOKEN='<WEBHOOK_TOKEN>'
irm https://get.threatclaw.io/agent/windows | iex
```

The installer creates a scheduled task that syncs every 5 minutes as
SYSTEM.

> See the [Endpoint Agent guide](endpoint-agent.md) for what the
> agent actually collects, advanced install flags, day-to-day
> operations, and the clean uninstall procedure.

### Verify the agent is registered

The **Setup → Endpoints** page lists every registered agent with its
hostname and last sync timestamp. The agent's host then appears in
**Inventory → Assets** with its software, OS, and a CVE finding for
every package matched against public vulnerability feeds.

## Update, reinstall, uninstall

The same `get.threatclaw.io` one-liner that bootstraps the server
also drives every lifecycle operation. Pass a flag to pick the mode
(use `--yes` to skip the interactive confirmation):

```bash
# Pull the latest images and restart in place
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --update

# Reconnect orphaned data after a broken pre-1.0.58 update (config looks
# "reset"). Finds the data volume and reattaches the stack to it. Safe and
# non-destructive — the old volume is kept as a backup.
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --repair

# Wipe data and reinstall fresh — keeps the Docker image cache so
# the reinstall is fast. The "start over with the same OS" option.
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --clean --yes

# Full removal: stop and delete the containers, volumes and Docker
# images of the project, and remove `/opt/threatclaw`. Docker itself
# and the system packages stay installed.
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --uninstall --yes
```

`--update` and `--repair` locate the existing deployment automatically
(recorded at install in `/etc/threatclaw/install-dir`), so you no longer
need to re-pass `--data` for them — even if the install was redirected to
a larger partition. `--update` is safe to schedule from cron; `--clean`
and `--uninstall` are destructive and should be run interactively unless
you fully control the host. For `--clean`/`--uninstall` on a custom path,
pass the same `--data DIR` the original install used.

## Declare critical assets

Attack-path prediction only works once at least one asset is flagged
as `critical`. From the dashboard, open **Inventory → Assets**, click
the asset (typically a domain controller, file server, or production
database), and set its criticality to `critical`. The next prediction
cycle will compute paths from exposed entry points to that target.

## Troubleshooting

### Out of disk space

```bash
# Inspect free space per partition
df -h /var /opt /home

# If /var is full (Docker stores images there by default)
# Option 1 — grow /var with LVM
lvextend -L +30G /dev/mapper/vg-var && resize2fs /dev/mapper/vg-var

# Option 2 — move the Docker data root
sudo systemctl stop docker
echo '{"data-root": "/home/docker"}' | sudo tee /etc/docker/daemon.json
sudo rsync -a /var/lib/docker/ /home/docker/
sudo systemctl start docker
```

### containerd "blob not found"

If files were removed manually under `/var/lib/containerd/` or
`/var/lib/docker/`:

```bash
sudo systemctl stop docker docker.socket containerd
sudo rm -rf /var/lib/containerd/*
sudo systemctl start containerd docker
```

### Change a port

```bash
cd /opt/threatclaw
sed -i 's/TC_DASHBOARD_PORT=.*/TC_DASHBOARD_PORT=8443/' .env
docker compose down && docker compose up -d
```

### Install management

```bash
# Check service status
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --status

# Update (pull the latest images, restart — data preserved)
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --update

# Clean reinstall (wipe DB + config, keep Docker image cache → ~2 min)
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --clean

# Full uninstall (removes data and Docker images)
curl -fsSL https://get.threatclaw.io | sudo bash -s -- --uninstall
```

| Command | Data | Docker images | Reinstall |
|---------|------|---------------|-----------|
| `--update` | preserved | updated | yes (restart) |
| `--clean` | wiped | preserved (cache) | yes (~2 min) |
| `--uninstall` | wiped | wiped | no |

### View logs

```bash
cd /opt/threatclaw
docker compose ps                           # Service status
docker compose logs -f threatclaw-core      # Core (Rust)
docker compose logs -f threatclaw-dashboard # Dashboard (Next.js)
docker compose logs -f ollama               # Local AI models
docker compose logs -f fluent-bit           # Log ingestion
```

### Local AI models stuck

Ollama needs Internet access to pull the base models the first time
(~18 GB total). If the pull is interrupted, the model alias never
registers and the forensic engine reports a 404 every cycle.

```bash
# Check progress
docker compose logs ollama | tail -20

# Check what's actually loaded
docker exec threatclaw-ollama-1 ollama list

# Re-trigger the pull (the entrypoint retries automatically since
# v1.0.33-beta, otherwise run it manually)
docker compose restart threatclaw-core
```

If the network restricts Hugging Face, the models can be shipped as
an offline bundle on request — see `operator-handbook.md` for the
detail.

## Next steps

- [Operator handbook](operator-handbook.md) — the dashboard,
  incidents, the three-layer detection model
- [Configuration options](configuration.md) — every environment
  variable
- [Inventory gate](inventory-gate.md) — why scanner noise does not
  reach the operator queue
- [Attack prediction](attack-prediction.md) — predicted attack paths
- [Available skills](skills.md) — connectors, intelligence, actions
- [API reference](api.md) — REST endpoints
- [Skill development guide](SKILL_DEVELOPMENT_GUIDE.md) — building
  your own skill

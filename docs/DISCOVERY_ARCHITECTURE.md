# ThreatClaw — Architecture Discovery (inventaire assets)

> Stack de découverte réseau pour un inventaire fiable.
> Basé sur une recherche approfondie (mars 2026) comparant RustScan, Naabu, Masscan, ZMap, SX.

---

## Décision : Naabu + Nmap (pas RustScan)

### Pourquoi pas RustScan

RustScan a été évalué et **rejeté** pour les raisons suivantes :
- Le "65535 ports en 3 secondes" est du **marketing** — réalité : 8-16s, comparable à Nmap
- **66% de précision** sur réseaux instables (mesuré par des benchmarks indépendants)
- **Bug de perte de données** multi-target (Issue #775) — résultats qui s'écrasent
- **`cargo install` cassé** sur Debian 12 (Issue #824)
- **GPL-3.0** (pas MIT comme annoncé)
- Ouvre des milliers de connexions simultanées → peut crasher les switchs PME
- 34 open issues, maintenance = dependency bumps principalement

### Pourquoi Naabu

| Critère | Naabu | RustScan | Nmap seul |
|---------|-------|----------|-----------|
| Licence | **MIT** | GPL-3.0 | NPSL |
| Précision | **SYN scan fiable** | 66% (instable) | 100% |
| Vitesse /24 top-1000 | **~30s** | ~8s (ports only) | ~2-5min |
| Maintenance | **7 issues, v2.5.0 mars 2026** | 34 issues | 29 ans |
| Écosystème | **= Nuclei (déjà intégré)** | Isolé | Standard |
| JSON output | **Natif, JSON lines** | Basique | XML |
| Scan type | **SYN (discret)** | TCP connect (bruyant) | SYN/Connect/UDP |
| Rate-limit | **Natif** | Batch size | Timing templates |
| Service detection | Non (passe à Nmap) | Non | Oui |
| Risque réseau | **Contrôlable** | Élevé (flood) | Faible |

**Sources de la recherche :**
- Benchmark Nmap vs Masscan vs RustScan (medium.com/@2s1one)
- RustScan vs Naabu speed test (medium.com/fmisec)
- Port Scanner Shootout (s0cm0nkey.gitbook.io)
- GitHub Issues RustScan #775, #824, #689
- Naabu docs (docs.projectdiscovery.io)

---

## Architecture cible

```
Couche 1 — Découverte rapide (Naabu)
├── Phase 1 : naabu --top-ports 1000 --rate 1000   (30s pour /24)
├── Phase 2 : naabu -p - --rate 500                 (full port sur cibles critiques)
└── Output : liste IP + ports ouverts (JSON lines)

Couche 2 — Fingerprinting (Nmap, déjà intégré)
├── nmap -sV -O -p {ports} {ip}                     (services + OS)
└── Output : XML → parse → assets

Couche 3 — Vulnérabilités (déjà intégré)
├── Nuclei (web CVEs)
├── Trivy (container CVEs)
└── Gitleaks (secrets code)

         │
         ▼
  resolve_asset() → PostgreSQL → Graph AGE
```

---

## Intégration Naabu

### Installation

```dockerfile
# Dans Dockerfile core — stage builder
RUN apt-get update && apt-get install -y libpcap-dev
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Copier dans runtime
COPY --from=builder /root/go/bin/naabu /usr/local/bin/naabu
```

Ou via le binaire pré-compilé (pas besoin de Go sur la machine) :
```dockerfile
RUN curl -sSL https://github.com/projectdiscovery/naabu/releases/download/v2.5.0/naabu_2.5.0_linux_amd64.zip \
    -o /tmp/naabu.zip && unzip /tmp/naabu.zip -d /usr/local/bin/ && rm /tmp/naabu.zip
RUN apt-get install -y libpcap0.8  # runtime dependency
```

### Code Rust

```rust
// src/connectors/naabu_discovery.rs

use tokio::process::Command;
use std::process::Stdio;

pub struct NaabuConfig {
    pub targets: String,         // "192.168.1.0/24"
    pub top_ports: u16,          // 1000
    pub rate: u16,               // 1000 (packets/sec)
    pub full_port: bool,         // false (top-ports) or true (all 65535)
}

pub struct NaabuHost {
    pub ip: String,
    pub port: u16,
}

pub async fn run_naabu(config: &NaabuConfig) -> Result<Vec<NaabuHost>, String> {
    let mut cmd = Command::new("naabu");
    cmd.arg("-host").arg(&config.targets)
       .arg("-rate").arg(config.rate.to_string())
       .arg("-json")
       .arg("-silent")
       .stdout(Stdio::piped())
       .stderr(Stdio::piped());

    if config.full_port {
        cmd.arg("-p").arg("-");  // all ports
    } else {
        cmd.arg("-top-ports").arg(config.top_ports.to_string());
    }

    let output = cmd.output().await
        .map_err(|e| format!("naabu exec failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("naabu failed: {stderr}"));
    }

    // Parse JSON lines: {"host":"192.168.1.10","port":22}
    let stdout = String::from_utf8_lossy(&output.stdout);
    let hosts: Vec<NaabuHost> = stdout.lines()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            Some(NaabuHost {
                ip: v["host"].as_str()?.to_string(),
                port: v["port"].as_u64()? as u16,
            })
        })
        .collect();

    Ok(hosts)
}
```

### Workflow combiné Naabu → Nmap

```rust
// src/connectors/asset_discovery.rs

pub async fn run_full_discovery(store: &dyn Database, target: &str) -> DiscoveryResult {
    // Phase 1: Naabu fast port discovery
    let naabu_hosts = run_naabu(&NaabuConfig {
        targets: target.into(),
        top_ports: 1000,
        rate: 1000,
        full_port: false,
    }).await?;

    // Group by IP: {ip: [ports]}
    let mut ip_ports: HashMap<String, Vec<u16>> = HashMap::new();
    for h in &naabu_hosts {
        ip_ports.entry(h.ip.clone()).or_default().push(h.port);
    }

    // Phase 2: Nmap fingerprint on discovered ports only
    for (ip, ports) in &ip_ports {
        let port_list = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        let nmap_result = run_nmap_targeted(ip, &port_list).await;
        // Phase 3: resolve_asset() → PG + graph
        // ...
    }
}
```

---

## Cycle Discovery

**Fréquence : 1x par jour à 03h30** (configurable dans le dashboard)

```
03:30 — Naabu top-1000 sur le subnet (30s)
03:31 — Nmap ciblé sur les ports trouvés (2-5min)
03:36 — Nuclei sur les services web détectés
03:40 — resolve_asset() → PG + graph
~03:45 — Terminé
```

Pour un réseau PME de 50-200 hosts : **inventaire complet en < 15 minutes**.

Vs Nmap seul : 20-30 minutes pour la même couverture.

---

## Évolutions futures (optionnel)

| Outil | Usage | Quand |
|-------|-------|-------|
| **netdiscover** (passif) | Monitoring continu ARP silencieux | Si mode "surveillance passive" demandé |
| **snmp-check** | Enrichir switches/routeurs via SNMP | Si clients avec infra réseau complexe |
| **Naabu + Nuclei pipeline** | Naabu → Nuclei en pipe natif (même écosystème) | Quand Nuclei est mis à jour |

---

## Ce qu'on ne fait PAS

- **Pas de RustScan** — 66% précision, bugs, flood réseau
- **Pas de Masscan** — 390 issues, custom TCP/IP stack, trop agressif par défaut
- **Pas de ZMap** — architecture internet-scale, inadaptée au LAN
- **Pas de SX** — 1 développeur, 1500 stars, risque d'abandon
- **Pas de arp-scan séparé** — `nmap -sn -PR` fait la même chose
- **Pas de scan toutes les 5min** — 1x/jour suffit, les alertes temps réel c'est l'Intelligence Engine

---

*Document créé le 26/03/2026 — basé sur recherche approfondie*
*À implémenter en v2.5 — Naabu + Nmap ciblé*

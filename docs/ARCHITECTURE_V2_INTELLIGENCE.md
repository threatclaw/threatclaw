# ThreatClaw v2.0 — Architecture Intelligence

> Ce document definit l'architecture du coeur intelligent de ThreatClaw.
> Chaque couche a ete recherchee et validee (outils reels, open-source).
> Reference : docs/RESEARCH_ASSET_INTELLIGENCE.md (recherche brute)

---

## Vision

```
ThreatClaw aujourd'hui :
  Collecte → Correle → LLM analyse → Alerte

ThreatClaw v2.0 :
  Collecte → Apprend le "normal" (ML)
           → Detecte les anomalies AVANT les regles
           → S'adapte au contexte client
           → LLM explique ce que le ML a detecte
           → Alerte plus precise, moins de faux positifs
```

---

## Pipeline complet

```
COLLECTE (sources)
├── Agent ThreatClaw (postes clients, metriques temps reel)
├── Zeek (metadonnees reseau passives — port SPAN ou --network host)
├── Suricata (alertes IDS/IPS — signatures)
├── Connectors (pfSense, AD, Wazuh, Cloudflare, CrowdSec...)
├── Enrichment (Safe Browsing, SSL Labs, WPScan, Shodan...)
├── Syslog (logs bruts — auth, httpd, dns, firewall)
└── Nuclei/Trivy (CVEs et vulnerabilites)
        │
        ▼
STOCKAGE
├── PostgreSQL — findings, alerts, logs, metrics, configs
├── Apache AGE — graphe STIX 2.1 (assets, IPs, CVEs, techniques, campagnes)
└── pgvector (futur) — embeddings pour recherche semantique
        │
        ▼
ML ENGINE (conteneur Python isole)
├── Couche 1 : Isolation Forest par asset (comportement reseau)
├── Couche 2 : Time Series (Prophet) — detection pics anormaux
├── Couche 3 : DBSCAN clustering — grouper assets similaires
├── Contexte client — fiche entreprise parametrant les seuils
└── DGA detection — Random Forest sur les domaines DNS
        │
        ▼
CORRELATION (Apache AGE)
  "Cet asset a un score anomalie eleve
   ET une CVE critique ET une IP suspecte
   s'est connectee hier"
        │
        ▼
LLM (L1 local + L2 reasoning)
  Recoit : faits verifies + score ML + contexte
  Produit : analyse structuree + recommandations
  "Pattern coherent avec un C2 beacon
   sur un asset deja vulnerable"
        │
        ▼
RSSI — Alerte HITL avec contexte complet
```

---

## Taxonomie des Assets

### Categories de base (livrees avec ThreatClaw)

| ID | Categorie | Sous-types / Roles | Icone |
|----|-----------|-------------------|-------|
| server | Serveur | web, db, mail, dns, ad, file, backup, proxy, voip, app | Server |
| workstation | Poste client | desktop, laptop, tablette | Monitor |
| mobile | Mobile | smartphone, tablette | Smartphone |
| website | Site web / App | wordpress, prestashop, custom, saas | Globe |
| network | Equipement reseau | firewall, switch, routeur, wifi-ap, vpn, load-balancer | Network |
| printer | Imprimante / MFP | imprimante, scanner, copieur | Printer |
| iot | IoT | camera, badge, capteur, thermostat, tv | Cpu |
| ot | OT / Industriel | PLC, HMI, SCADA, capteur industriel | Factory |
| cloud | Cloud | VM, container, serverless, SaaS account | Cloud |
| unknown | Inconnu | auto-detecte, en attente de classification | HelpCircle |

### Attributs communs a tous les assets

```
Asset {
  id: UUID
  name: String              // "srv-web-01" ou "monsite.fr"
  category: String          // "server", "workstation", "website"...
  subcategory: String       // "web", "db", "wordpress"...
  role: Option<String>      // "Serveur de base de donnees production"
  criticality: Enum         // critical, high, medium, low

  // Identifiants reseau
  ip_addresses: Vec<String>
  mac_address: Option<String>
  hostname: Option<String>
  fqdn: Option<String>
  url: Option<String>       // pour les sites web

  // Fingerprint
  os: Option<String>        // "Linux Ubuntu 22.04" / "Windows Server 2022"
  os_confidence: f32        // 0.0-1.0
  mac_vendor: Option<String>// "Apple Inc." (via OUI lookup)
  services: Vec<Service>    // ports ouverts + service detecte

  // Provenance
  source: String            // "manual", "nmap", "pfsense", "dhcp", "alert-auto"
  first_seen: DateTime
  last_seen: DateTime

  // Contexte
  owner: Option<String>     // "Jean Dupont" ou "Equipe Dev"
  location: Option<String>  // "Bureau Paris" / "Datacenter OVH"
  tags: Vec<String>         // custom tags
  notes: Option<String>     // notes RSSI

  // Classification auto
  classification_method: String   // "manual", "fingerprint", "ml"
  classification_confidence: f32  // 0.0-1.0
}
```

### Categories custom (le client peut ajouter)

Le client peut creer ses propres categories dans Config > Assets.
Exemple : un hopital ajoute "medical" avec sous-types "pompe", "moniteur", "imagerie".
Les custom categories apparaissent dans les onglets et listes deroulantes.

---

## Classification automatique des IPs

### Prerequis : reseaux internes declares

A l'installation, le client declare ses plages :
```
internal_networks:
  - 192.168.1.0/24    # LAN principal
  - 10.0.0.0/16       # VPN
  - 172.16.0.0/12     # DMZ
```

### Logique de classification

```rust
fn classify_ip(ip: &str, internal_networks: &[IpNetwork]) -> IpClass {
    if is_in_networks(ip, internal_networks) {
        if asset_exists(ip) {
            IpClass::InternalKnown(asset_id)    // Asset connu du client
        } else {
            IpClass::InternalUnknown            // Device sur le reseau mais pas declare
        }
    } else if is_private_ip(ip) {
        IpClass::InternalUnknown                // IP privee hors plage declaree
    } else {
        IpClass::External                       // IP internet = attaquant potentiel
    }
}
```

### Traitement selon la classe

| Classe | Traitement | Exemple |
|--------|-----------|---------|
| InternalKnown | Rattacher alerte a l'asset, scorer | "Serveur web attaque" |
| InternalUnknown | Creer Asset "Inconnu", fingerprint, analyser | "PC du commercial sur le WiFi" |
| External | Noeud IP dans le graph, enrichir (AbuseIPDB, GreyNoise, Shodan) | "IP Tor qui scan" |

### Pas de milliards d'assets

- Les IPs EXTERNES ne sont PAS des assets — ce sont des noeuds IP dans le graph
- Seules les IPs INTERNES non reconnues deviennent des assets "Inconnu"
- En PME = 5-50 devices inconnus max (pas des milliards)

---

## Fingerprinting automatique (sans scanner)

### Tier 1 — Embedded (zero install)

| Methode | Donnee source | Ce qu'on apprend | Outil |
|---------|--------------|-----------------|-------|
| MAC OUI | ARP table (pfSense, Nmap) | Fabricant (Apple, Dell, Cisco...) | Crate Rust `mac_oui` |
| DHCP hostname | Logs syslog dhcpd | Nom machine (LAPTOP-JEAN, iPhone-de-Marie) | Parser regex |
| Ports ouverts | Nmap, logs firewall | Type probable (80+443+3306=web+db, 636+389=AD) | Regles simples |

### Tier 2 — Leger (optionnel)

| Methode | Donnee source | Ce qu'on apprend | Outil |
|---------|--------------|-----------------|-------|
| OS fingerprint passif | Trafic TCP/IP | OS exact (Windows 11, Ubuntu 22.04) | p0f v3 (<50MB RAM) |
| DHCP fingerprint | Option 55 DHCP | Type device (110K+ devices connus) | Fingerbank SQLite |
| User-Agent | Logs HTTP/proxy | Browser + OS + type device | Crate Rust `woothee` |
| JA4 TLS fingerprint | Zeek ssl.log | App/browser exact | JA4 (BSD, dans Zeek) |
| HASSH SSH fingerprint | Zeek ssh.log | Client SSH (PuTTY, OpenSSH, bot) | HASSH (BSD, dans Zeek) |

### Regles de classification probabiliste

```
ports 80+443+3306+22 ouverts           → server:web (70%)
ports 636+389+88+445                   → server:ad (90%)
que du 443 sortant, peu de volume      → workstation (60%)
MAC Apple + DHCP "iPhone-de-*"         → mobile:smartphone (95%)
MAC Hikvision + port 554 (RTSP)       → iot:camera (95%)
beaucoup de DNS + beacon regulier      → suspect C2 (80%)
MAC Siemens + ports Modbus/Profinet    → ot:plc (90%)
aucun pattern connu                    → unknown (0%)
```

---

## Couches ML

### Couche 1 — Isolation Forest (detection anomalies)

**Algorithme** : scikit-learn `IsolationForest`
**Donnees** : features par asset par heure (depuis logs + Zeek conn.log)
**Entrainement** : 7-14 jours sur le reseau du client
**Reentrainement** : nocturne
**CPU only** : oui, pas de GPU

Features par asset :
```
- connexions_par_heure (count)
- bytes_in, bytes_out (volume)
- destinations_uniques (count)
- ports_destination_uniques (count)
- ratio_in_out (ratio)
- dns_queries_par_heure (count)
- domaines_uniques (count)
- heure_activite (0-23)
- protocoles_utilises (bitmap)
- duree_connexion_moyenne (seconds)
```

Ce que ca detecte :
- "Ce serveur recoit 100-500 connexions/heure" → 5000 a 3h du matin = anomalie
- "Ce serveur ne parle jamais a l'exterieur" → connexion sortante vers Russie = anomalie
- "Ce compte se connecte de 9h a 18h depuis Paris" → connexion a 2h depuis Berlin = anomalie

**Precision reportee** : 93% accuracy, 95% precision, 90% recall (MDPI study)

### Couche 2 — Time Series (Prophet ou LSTM legere)

**But** : detecter les pics anormaux dans le temps
**Donnees** : metriques temporelles par asset (traffic/h, connexions/h, cpu, ram)
**Detecte** : "Le trafic est 10x superieur a la normale pour un mardi"

### Couche 3 — Clustering (DBSCAN)

**But** : grouper les assets par comportement similaire
**Detecte** : "Ces 5 serveurs se comportent pareil. Si l'un devie = anomalie."
**Utile pour** : decouvrir les groupes naturels dans l'infra du client

### DGA Detection — Random Forest

**But** : detecter les domaines DNS generes algorithmiquement (C2 malware)
**Features** : entropie, longueur, ratio consonnes/voyelles, n-grams
**Performance** : F1 > 99% avec deep learning, >95% avec Random Forest
**CPU only** : <1ms par domaine

### Deploiement ML

```yaml
# docker-compose.yml
services:
  ml-engine:
    image: threatclaw/ml-engine:latest
    volumes:
      - ml_models:/models
    environment:
      - DATABASE_URL=postgres://...
      - RETRAIN_SCHEDULE=0 3 * * *  # 3h du matin
    deploy:
      resources:
        limits:
          memory: 512M
    restart: unless-stopped
```

Conteneur Python isole :
- scikit-learn (Isolation Forest, DBSCAN, Random Forest)
- River (ML streaming temps reel)
- Prophet (time series)
- PyOD (40+ algos detection anomalies)
- Pas de GPU requis

---

## Contexte client — fiche entreprise

### Donnees collectees a l'installation

```
Secteur d'activite :
  NACE/NAF code ou selection manuelle
  industrie | sante | finance | commerce |
  collectivite | services | transport | energie

Taille :
  < 50 | 50-200 | 200-500 | 500+

Horaires d'activite :
  bureau (8h-18h) | 24/7 | par equipes | saisonnier

Zones geographiques autorisees :
  France uniquement | Europe | International

Assets critiques :
  ERP | base clients | paye | site web | production

Reseaux internes :
  192.168.1.0/24, 10.0.0.0/16...
```

### Impact sur le ML

| Parametre | Effet sur les seuils |
|-----------|---------------------|
| Industrie | Connexions PLC normales, connexion externe vers PLC = CRITICAL |
| Sante | IoMT attendu, ransomware = CRITICAL (vies en jeu) |
| Finance | Transactions la nuit = anormal, alertes PCI-DSS |
| Commerce | Pics le week-end = normal, pas d'activite = anormal |
| France uniquement | Connexion RU/CN = HIGH, autres pays = analyse fine |
| Horaires bureau | Activite nocturne = score anomalie x3 |
| < 50 personnes | Seuils plus sensibles, moins de bruit attendu |

### Mapping NACE → profil de menaces

Le code NACE/NAF du client determine automatiquement :
1. Quelles techniques MITRE ATT&CK sont les plus pertinentes
2. Quels types d'assets sont attendus
3. Quels frameworks de compliance s'appliquent
4. Quels seuils d'alerte utiliser

---

## Connecteurs reseau (sources de donnees)

### Zeek — l'analyseur reseau passif

**Deploiement** : Docker `--network host` ou port SPAN switch
**Produit** : JSON logs (conn, dns, http, ssl, ssh, files, dhcp...)
**Ressources** : ~1 CPU / 250 Mbps, 1-2 GB RAM
**Licence** : BSD
**Integration** : ThreatClaw lit les JSON logs toutes les 5 min

Ce que Zeek apporte que ThreatClaw n'a pas aujourd'hui :
- Vision de TOUT le trafic reseau
- Meme les equipements sans agent
- Donnees pour le ML (conn.log = features comportementales)
- JA4/HASSH fingerprints

### Suricata — IDS reseau

**Deploiement** : Docker `--network host`
**Produit** : eve.json (alertes + flow metadata)
**Ressources** : ~1 CPU / 200-500 Mbps, 2-4 GB RAM
**Licence** : GPL v2

### ntopng — monitoring reseau avec API

**Deploiement** : Docker ou natif
**Produit** : API REST (OpenAPI/Swagger) — hosts, flows, alerts
**Ressources** : 2-4 GB RAM
**Licence** : GPLv3 (Community Edition)
**Integration** : Query REST API pour inventaire temps reel

### Autres sources

| Source | Methode | Donnees |
|--------|---------|---------|
| Pi-hole / AdGuard | REST API | DNS queries par client |
| UniFi / Meraki | REST API | Clients WiFi (MAC, IP, SSID, trafic) |
| DHCP (ISC/Kea) | Syslog ou REST API (Kea) | MAC-IP-hostname mapping |
| SNMP | OID ipNetToMediaTable | ARP table switches manages |
| NetFlow/sFlow | nfcapd collector | Flow data des switches/routeurs |
| p0f | Socket API Unix | OS fingerprint passif |
| Fingerbank | SQLite local ou API | DHCP-based device classification |

---

## Plan d'implementation

### v1.6 — Assets + Classification (fondation)

- [ ] Refonte model Asset (categories, roles, criticite, attributs complets)
- [ ] Page Dashboard Assets avec onglets par categorie
- [ ] Config "reseaux internes" dans setup/config
- [ ] `classify_ip()` : interne connu / interne inconnu / externe
- [ ] Auto-creation Asset "Inconnu" pour IPs internes non reconnues
- [ ] MAC OUI lookup embarque (crate Rust `mac_oui`)
- [ ] Intelligence Engine analyse TOUT (meme les inconnus)
- [ ] Fiche entreprise dans le wizard onboarding (secteur, taille, horaires, zones)
- [ ] Fingerprint basique (MAC vendor + ports + DHCP hostname)
- [ ] Categories custom creables par le client

### v1.7 — Connectors reseau + Fingerprint enrichi

- [ ] Connector Pi-hole / AdGuard (DNS)
- [ ] Connector UniFi / Meraki (WiFi clients)
- [ ] Connector DHCP (ISC dhcpd syslog, Kea API)
- [ ] Fingerbank integration (SQLite local)
- [ ] p0f optionnel (OS fingerprint passif)
- [ ] NACE/NAF → profil de menaces auto
- [ ] User-Agent parsing (crate `woothee`)

### v1.8 — Zeek + Suricata connectors

- [ ] skill-zeek (persistent Docker, lit JSON logs)
- [ ] skill-suricata (persistent Docker, parse eve.json)
- [ ] ntopng connector (REST API)
- [ ] JA4/HASSH fingerprints depuis Zeek
- [ ] NetFlow/sFlow ingestion (via nfcapd)

### v2.0 — ML Engine

- [ ] Conteneur Python ML (Docker)
- [ ] Isolation Forest par asset (scikit-learn)
- [ ] Features extraction depuis conn.log + logs
- [ ] Entrainement 7-14 jours, reentrainement nocturne
- [ ] DGA detection (Random Forest sur DNS)
- [ ] Time Series anomaly (Prophet)
- [ ] Clustering DBSCAN
- [ ] Score anomalie integre dans l'Intelligence Engine
- [ ] LLM recoit le score ML + contexte (pas l'alerte brute)

### v2.1 — Agent + Advanced ML

- [ ] Agent ThreatClaw Linux (metriques temps reel)
- [ ] River (ML streaming temps reel sur les metriques agent)
- [ ] Behavioral baselines par type d'asset
- [ ] Peer group analysis (comparer un asset a ses similaires)
- [ ] Classification ML des devices inconnus (IoTDevID)

---

## References

### Outils confirmes (open-source, production-ready)

| Outil | Usage | Licence | Ressources |
|-------|-------|---------|------------|
| Zeek | Analyse reseau passive | BSD | 1 CPU / 250 Mbps |
| Suricata | IDS/IPS reseau | GPLv2 | 1 CPU / 200-500 Mbps |
| ntopng | Monitoring reseau + API | GPLv3 | 2-4 GB RAM |
| p0f | OS fingerprint passif | LGPL v2.1 | <50 MB RAM |
| Fingerbank | DHCP device classification | GPL | SQLite local |
| scikit-learn | ML anomaly detection | BSD | CPU only |
| River | ML streaming | BSD | CPU only |
| Prophet | Time series | MIT | CPU only |
| PyOD | 40+ algos anomalies | BSD | CPU only |
| CICFlowMeter | Feature extraction reseau | MIT | CPU only |
| mac_oui (Rust) | MAC vendor lookup | MIT | Embedded |
| woothee (Rust) | User-Agent parsing | MIT | Embedded |

### References recherche

- Kitsune (NDSS 2018) — autoencoder network anomaly detection
- IoTDevID — device fingerprinting from network behavior
- IoTSentinel — IoT classification from DHCP + first-minute traffic
- MITRE ATT&CK Enterprise + ICS matrices
- CISA 2025 OT Asset Inventory Guidance
- Darktrace / Armis / Forescout architecture analysis

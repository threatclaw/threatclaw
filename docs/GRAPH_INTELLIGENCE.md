# ThreatClaw — Graph Intelligence Architecture

## Vision

Transformer ThreatClaw d'un "agent IA qui analyse des alertes" en un **agent SOC déterministe avec IA** — inspiré de l'approche Qevlar AI (30M$ levés, 99.8% accuracy) mais en open source et on-premise.

**Principe fondamental** : Le graphe décide comment investiguer. Le LLM analyse seulement les faits collectés. Zéro hallucination possible car le LLM ne peut interpréter que ce qui a été vérifié par le graphe.

---

## Pourquoi le graph change tout

### Aujourd'hui (sans graph)

```
Alerte brute → L1 LLM → improvise son analyse → parfois hallucine
                         → ne sait pas quoi enrichir
                         → ne connaît pas l'historique
                         → résultat non reproductible
```

### Demain (avec graph)

```
Alerte → Investigation Graph (déterministe)
              ↓
         Étape 1: Enrichir IP (CrowdSec + GreyNoise + IPinfo) → fait vérifié
              ↓
         Étape 2: Historique 24h dans le graph (cette IP a déjà attaqué ?) → fait
              ↓
         Étape 3: Corréler alertes (même IP, même asset, même timeframe) → fait
              ↓
         Étape 4: Mapper MITRE ATT&CK (traversal du graph ATT&CK) → fait
              ↓
         Étape 5: Tous les faits → L2 Reasoning → analyse structurée
              ↓
         Résultat: reproductible, auditable, zéro hallucination
```

---

## Architecture technique

### Couche 1 — Apache AGE (Graph dans PostgreSQL)

ThreatClaw utilise déjà PostgreSQL. Apache AGE ajoute le support des requêtes graph (Cypher) directement dans la même base — zéro container supplémentaire.

**Installation** :
```sql
-- Migration V23
CREATE EXTENSION IF NOT EXISTS age;
LOAD 'age';
SET search_path = ag_catalog, "$user", public;
SELECT create_graph('threat_graph');
```

**Modèle de données STIX 2.1** (nœuds et arêtes) :

```
Nœuds (vertices) :
  (:IP {addr, country, asn, greynoise_class, first_seen, last_seen})
  (:Asset {id, hostname, type, os, criticality})
  (:CVE {id, cvss, epss, in_kev, description})
  (:Alert {id, level, title, rule_id, matched_at})
  (:Finding {id, severity, title, skill_id, detected_at})
  (:ThreatActor {name, aliases, country, motivation})
  (:Technique {mitre_id, name, tactic, platform})
  (:User {username, role, last_login})
  (:Domain {name, registrar, first_seen})
  (:Hash {value, type, malware_name})

Arêtes (edges) :
  (IP)-[:ATTACKS]->(Asset)
  (IP)-[:RESOLVES_TO]->(Domain)
  (Alert)-[:SOURCE_IP]->(IP)
  (Alert)-[:TARGET]->(Asset)
  (Alert)-[:MATCHES]->(Technique)
  (Finding)-[:AFFECTS]->(Asset)
  (Finding)-[:REFERENCES]->(CVE)
  (CVE)-[:EXPLOITED_BY]->(ThreatActor)
  (ThreatActor)-[:USES]->(Technique)
  (User)-[:LOGGED_INTO]->(Asset)
  (Asset)-[:RUNS]->(CVE)
  (Domain)-[:KNOWN_C2]->(ThreatActor)
  (Hash)-[:FOUND_ON]->(Asset)
```

**Exemples de requêtes Cypher** :

```cypher
-- Trouver tous les chemins d'attaque vers un asset critique
MATCH path = (ip:IP)-[:ATTACKS*1..3]->(asset:Asset {criticality: 'high'})
RETURN path

-- Corréler une IP avec des acteurs connus
MATCH (ip:IP {addr: '185.220.101.42'})-[:ATTACKS]->(a:Asset),
      (ip)-[:KNOWN_C2]->(actor:ThreatActor)-[:USES]->(tech:Technique)
RETURN ip, actor, tech

-- Kill chain : trouver les étapes d'une attaque en cours
MATCH (alert1:Alert)-[:SOURCE_IP]->(ip:IP),
      (alert2:Alert)-[:SOURCE_IP]->(ip),
      (alert1)-[:TARGET]->(asset:Asset),
      (alert2)-[:TARGET]->(asset)
WHERE alert1.matched_at > datetime() - duration('PT1H')
RETURN ip, asset, collect(alert1), collect(alert2)

-- Quelles CVEs exploitées affectent mes assets ?
MATCH (cve:CVE {in_kev: true})-[:AFFECTS]->(asset:Asset)
RETURN asset.hostname, collect(cve.id), count(cve) AS vuln_count
ORDER BY vuln_count DESC
```

### Couche 2 — Investigation Graphs (orchestration déterministe)

Inspiré de Qevlar AI. Chaque type d'alerte a un **chemin d'investigation prédéfini** — une liste d'étapes ordonnées et obligatoires.

```rust
// src/investigation/graphs.rs

pub enum InvestigationStep {
    // Enrichissement (appelle des APIs/skills)
    EnrichIp { ip: String, sources: Vec<EnrichSource> },
    EnrichDomain { domain: String },
    EnrichHash { hash: String },
    EnrichCve { cve_id: String },

    // Requêtes graph (Cypher dans AGE)
    QueryHistory { entity: String, window_hours: u64 },
    CorrelateAlerts { same_ip: bool, same_asset: bool, window_hours: u64 },
    MapMitreTechniques { alert_type: String },
    FindAttackPaths { from_ip: String, to_asset: String },

    // Analyse LLM (seulement après collecte des faits)
    SendToReasoning { context: InvestigationContext },

    // Actions
    CreateFinding { severity: String },
    NotifyRssi { level: NotificationLevel },
}

pub struct InvestigationGraph {
    pub name: String,
    pub trigger: AlertTrigger,
    pub steps: Vec<InvestigationStep>,
}
```

**Graphes d'investigation prédéfinis** :

| Type d'alerte | Étapes | Durée estimée |
|---------------|--------|---------------|
| SSH Brute Force | EnrichIP → History 24h → CorrelateAlerts → MapMITRE → Reasoning | ~30s |
| CVE Critique | EnrichCVE (NVD+KEV+EPSS) → FindAffectedAssets → MapMITRE → Reasoning | ~15s |
| Phishing URL | EnrichDomain → CheckOpenPhish+URLhaus → History → Reasoning | ~20s |
| C2 Communication | EnrichIP → EnrichDomain → QueryC2Graph → MapMITRE → Reasoning | ~25s |
| Mouvement latéral | CorrelateAlerts (multi-asset) → FindAttackPaths → MapMITRE → Reasoning | ~30s |
| Malware Hash | EnrichHash (MalwareBazaar) → FindAffectedAssets → MapMITRE → Reasoning | ~15s |
| Exfiltration DNS | EnrichDomain → QueryDNSHistory → CorrelateC2 → MapMITRE → Reasoning | ~20s |

**Avantage clé** : Même alerte = même investigation = même résultat. Reproductible et auditable. Le RSSI peut "rejouer" une investigation pour comprendre comment ThreatClaw est arrivé à sa conclusion.

### Couche 3 — MITRE ATT&CK comme graph navigable

Les 700+ techniques ATT&CK sont chargées dans AGE comme un graph :

```
(Tactic:initial-access)
    ├── (Technique:T1190 Exploit Public-Facing App)
    │       ├── (SubTechnique:T1190.001)
    │       └── uses_by → (ThreatActor:APT28)
    ├── (Technique:T1078 Valid Accounts)
    │       ├── mitigated_by → (Mitigation:M1032 Multi-factor Auth)
    │       └── detected_by → (DataSource:Authentication Logs)
    ...

(Tactic:lateral-movement)
    ├── (Technique:T1021 Remote Services)
    │       └── (SubTechnique:T1021.004 SSH)
    ...
```

Quand l'investigation identifie une technique (ex: T1078 Valid Accounts pour un brute force SSH), le graph permet de :
1. **Prédire les prochaines étapes** : quelles techniques suit T1078 dans les kill chains connues ?
2. **Suggérer des mitigations** : D3FEND suggère MFA, account lockout policy
3. **Identifier l'acteur** : quels threat actors utilisent cette technique + ciblent ce secteur ?

### Couche 4 — petgraph / rustworkx (algorithmes graph en mémoire)

Pour les calculs intensifs en temps réel dans le core Rust :

| Bibliothèque | Langage | Usage | Licence |
|--------------|---------|-------|---------|
| **petgraph** | Rust natif | Algorithmes graph dans le core (shortest path, connected components, topological sort) | Apache 2.0 / MIT |
| **rustworkx** | Rust + Python | Pour les skills Python qui ont besoin de graph analysis (3-100x plus rapide que NetworkX) | Apache 2.0 |
| **Raphtory** | Rust + Python | Analyse temporelle de graphes (corrélation d'attaques dans le temps) | Open source |

**Exemple** : Quand l'Intelligence Engine détecte 3 alertes sur le même asset en 10 minutes, petgraph calcule en mémoire les "connected components" pour identifier si c'est une campagne coordonnée ou des événements isolés.

---

## Intégration avec l'existant ThreatClaw

### Ce qui existe déjà et que le graph améliore

| Composant existant | Amélioration avec graph |
|-------------------|------------------------|
| Intelligence Engine (score par asset) | Le graph remplace le groupement naïf par de vraies relations typées |
| Enrichissement (GreyNoise, EPSS, etc.) | Les résultats d'enrichissement deviennent des propriétés de nœuds dans le graph |
| ReAct cycle (L1→L2) | L2 reçoit un sous-graph de l'investigation au lieu d'alertes brutes |
| MITRE ATT&CK (sync STIX) | Les techniques deviennent un graph navigable dans AGE |
| CERT-FR / CISA KEV | Les avis/CVEs deviennent des nœuds liés aux assets concernés |
| Notification Router | La notification inclut le chemin d'attaque visualisé du graph |
| Bot conversationnel | "Montre moi le graph de l'attaque sur srv-prod-01" |

### Ce qui est NOUVEAU

| Capacité | Description |
|----------|-------------|
| **Investigation déterministe** | Chaque type d'alerte suit un chemin fixe vérifié — zéro improvisation LLM |
| **Attack path discovery** | Cypher trouve les chemins entre l'attaquant et les assets critiques |
| **Prédiction d'étape suivante** | Le graph ATT&CK prédit la suite probable de l'attaque |
| **Corrélation temporelle** | Raphtory analyse les patterns temporels (beacon C2, scan progressif) |
| **Audit trail complet** | Chaque étape de l'investigation est un nœud dans le graph → reproductible |
| **Interopérabilité STIX** | Compatible nativement avec OpenCTI, MISP, et tout feed TAXII |

---

## Compatibilité et performance

### Taille des données estimée

| Données | Volume (PME 50 postes, 1 an) | Stockage AGE |
|---------|------------------------------|--------------|
| Nœuds IP | ~5 000 | ~5 MB |
| Nœuds Asset | ~100 | < 1 MB |
| Nœuds Alert | ~50 000 | ~50 MB |
| Nœuds CVE | ~2 000 | ~2 MB |
| Nœuds Technique | ~700 | < 1 MB |
| Arêtes (relations) | ~200 000 | ~200 MB |
| **Total** | | **~260 MB** |

PostgreSQL gère ça sans broncher. Pas besoin de Neo4j cluster.

### Performance requêtes

| Requête type | Complexité | Temps estimé (AGE) |
|-------------|------------|-------------------|
| Enrichir un nœud IP | O(1) lookup | < 1ms |
| Trouver les alertes d'un asset | O(degré) | < 5ms |
| Shortest path IP → Asset | O(V+E) BFS | < 50ms |
| Connected components (campagne) | O(V+E) | < 100ms |
| MITRE technique mapping | O(1) lookup | < 1ms |

Largement suffisant pour un cycle de 5 minutes.

---

## Références et inspirations

### Outils open source clés

| Outil | Ce qu'il fait | Comment l'utiliser |
|-------|-------------|-------------------|
| **Apache AGE** | Graph extension pour PostgreSQL (Cypher) | Fondation du threat graph |
| **petgraph** | Algorithmes graph en Rust | Calculs en mémoire dans le core |
| **CTINexus** | Construction de KG depuis CTI via LLM | Inspiration pour auto-construction du graph |
| **BloodHound CE** | Attack path analysis Active Directory | Ingestion des données AD dans le graph |
| **Cartography** (CNCF) | Maps cloud infra en graph (Neo4j) | Patterns de requêtes Cypher réutilisables |
| **MulVAL** | Générateur d'attack graphs logique | Algorithmes de génération de chemins d'attaque |

### Papers académiques

| Paper | Contribution |
|-------|-------------|
| Survey GNN for IDS (2024, Computers & Security) | 28 architectures GNN pour détection d'intrusion |
| FedGAT (2024, Nature Scientific Reports) | Détection d'attaque fédérée via Graph Attention Network |
| Graph-Based Alert Contextualisation (2025, Springer) | Agrégation d'alertes en sous-graphes + Graph Matching Networks |
| CTINexus (2025, Euro S&P) | Construction KG automatique depuis CTI, F1 87.65% |
| AttacKG+ (2025, ACM) | Construction de knowledge graphs d'attaque via LLM |

### Plateformes commerciales (positionnement)

| Plateforme | Approche | Prix | ThreatClaw vs. |
|-----------|----------|------|-----------------|
| Qevlar AI | Graph orchestration propriétaire | Enterprise (non communiqué) | ThreatClaw = open source, on-premise, PME |
| Wiz | Security Graph sur Amazon Neptune | SaaS cloud | ThreatClaw = on-premise, pas cloud-only |
| D3 Morpheus | Attack Path Discovery + playbooks | Enterprise | ThreatClaw = gratuit, NIS2 focused |

---

## Timeline d'implémentation

### Phase 1 — Fondation (V2.0)
- [ ] Apache AGE extension dans PostgreSQL (migration V23)
- [ ] Modèle STIX 2.1 dans AGE (nœuds IP, Asset, CVE, Alert, Technique)
- [ ] Chargement MITRE ATT&CK comme graph navigable
- [ ] Requêtes Cypher de base (corrélation, historique, attack path)
- [ ] petgraph dans le core Rust (connected components, shortest path)

### Phase 2 — Investigation graphs (V2.1)
- [ ] 7 graphes d'investigation prédéfinis par type d'alerte
- [ ] Orchestration déterministe (étapes fixes, pas d'improvisation LLM)
- [ ] L2 Reasoning reçoit le sous-graph de l'investigation (pas des alertes brutes)
- [ ] Audit trail : chaque investigation est un sous-graph dans AGE

### Phase 3 — Intelligence avancée (V2.2)
- [ ] Connecteur OpenCTI (ingestion STIX via GraphQL)
- [ ] Connecteur TAXII pour feeds CTI communautaires
- [ ] Prédiction d'étape suivante via traversal ATT&CK
- [ ] Suggestions de mitigation automatiques via D3FEND
- [ ] Dashboard : visualisation du graph d'attaque (D3.js ou Cytoscape.js)

### Phase 4 — GNN expérimental (V3.0)
- [ ] NF-GNN pour classification de flux réseau (Suricata/Zeek data)
- [ ] Entraînement sur données labélisées (CICIDS, CTU-13)
- [ ] Inférence via ONNX Runtime dans un Python skill
- [ ] Détection d'anomalies comportementales (complémente Sigma)

---

*Dernière mise à jour : 23 mars 2026*
*Basé sur recherche exhaustive : 15 sujets, 30+ sources, 50+ outils audités*

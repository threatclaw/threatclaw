# THREATCLAW — Référence complète des Skills

> Document technique : comment chaque skill fonctionne, ce qu'il faut pour l'activer, ce que le client doit configurer.
> Dernière mise à jour : 20 mars 2026

---

## LÉGENDE STATUT

| Statut | Signification |
|--------|---------------|
| ✅ FONCTIONNEL | Le skill peut être lancé et produit des résultats réels |
| ⚙️ PRÊT À BRANCHER | Le code existe, l'outil est dispo, il manque l'orchestration |
| 📝 PROTOTYPE | Le code Python existe mais n'est pas connecté |
| ❌ À DÉVELOPPER | Le skill n'existe pas encore |

---

## 1. skill-vuln-scan — Scanner de vulnérabilités

| | |
|---|---|
| **Statut** | ⚙️ PRÊT À BRANCHER |
| **Outils** | Nuclei + Nmap |
| **Gratuit** | Oui (100% open source) |
| **API key requise** | Non |
| **Docker image** | `projectdiscovery/nuclei:latest` |
| **Testé end-to-end** | Oui — `scripts/real_scan.py` a scanné cette machine |

### Comment ça marche
- **Nuclei** scanne les cibles réseau avec 8000+ templates de détection (CVE, misconfig, exposure)
- **Nmap** détecte les ports ouverts et les versions de services
- Résultats en JSONL → parsés → poussés en DB via `POST /api/tc/findings`

### Ce que le client configure
```
Cibles réseau : 192.168.1.0/24  (ou un hostname)
Sévérité minimum : medium
Templates : default / custom / all
Fréquence : cron (défaut: 0 2 * * * = tous les jours à 2h)
```

### Ce qui manque pour être ✅
- [ ] Le core Rust doit appeler `NucleiScanner::scan()` via le scheduler cron
- [ ] Supprimer `real_scan.py` au profit du scanner Rust
- [ ] Le scanner Rust (`src/scanners/nuclei.rs`) est écrit et testé

### Modes supportés
- **Docker** : `docker exec docker-nuclei-1 nuclei -target <ip> -json`
- **Local** : `/usr/local/bin/nuclei -target <ip> -json` (si le client a déjà Nuclei)

---

## 2. skill-secrets-audit — Détection de secrets exposés

| | |
|---|---|
| **Statut** | 📝 PROTOTYPE |
| **Outil** | Gitleaks |
| **Gratuit** | Oui (MIT) |
| **API key requise** | Non |
| **Docker image** | `zricethezav/gitleaks:latest` |

### Comment ça marche
- **Gitleaks** scanne les dépôts Git et le filesystem pour détecter les secrets exposés
- Détecte : clés AWS, tokens GitHub, mots de passe en dur, clés privées, etc.
- Résultat en JSON → parsé → poussé en DB

### Ce que le client configure
```
Chemin à scanner : /path/to/repo  (ou URL git)
Scanner l'historique Git : oui/non
Patterns personnalisés : (optionnel)
```

### Commande
```bash
# Docker
docker run -v /path/to/repo:/repo zricethezav/gitleaks:latest detect --source /repo --report-format json --report-path /dev/stdout

# Local
gitleaks detect --source /path/to/repo --report-format json
```

### Ce qui manque pour être ✅
- [ ] Scanner Rust `src/scanners/gitleaks.rs` (comme nuclei.rs)
- [ ] Intégration au scheduler
- [ ] `skill.json` existe déjà

---

## 3. skill-email-audit — Audit sécurité email

| | |
|---|---|
| **Statut** | ⚙️ PRÊT À BRANCHER |
| **Outil** | Requêtes DNS directes (pas d'outil externe) |
| **Gratuit** | Oui |
| **API key requise** | Non |
| **Docker** | Pas besoin — c'est du DNS lookup |

### Comment ça marche
- Vérifie les enregistrements **SPF** (TXT record du domaine)
- Vérifie les enregistrements **DKIM** (TXT record `_dmarc.<domain>`)
- Vérifie les enregistrements **DMARC** (politique anti-spoofing)
- Vérifie **BIMI** (logo email authentifié)
- Python : bibliothèque `checkdmarc` (`pip install checkdmarc`)

### Ce que le client configure
```
Domaines à auditer : example.com, corp.fr
```

### Commande
```bash
# Python
checkdmarc example.com  # → JSON avec SPF/DMARC status

# Programmatique
python3 -c "import checkdmarc; print(checkdmarc.check_domains(['example.com']))"
```

### Ce qui manque pour être ✅
- [ ] Module Rust qui appelle `checkdmarc` en subprocess ou fait les requêtes DNS directement
- [ ] Peut être implémenté en pur Rust avec `trust-dns-resolver` (pas besoin de Python)

---

## 4. skill-darkweb-monitor — Surveillance dark web / fuites

| | |
|---|---|
| **Statut** | 📝 PROTOTYPE |
| **Outil** | Have I Been Pwned (HIBP) API v3 |
| **Gratuit** | **PARTIELLEMENT** — Pwned Passwords gratuit, recherche email/domaine payant |
| **API key requise** | **Oui** — ~$3.50/mois |
| **Docker** | Non — API cloud uniquement |

### Comment ça marche
- Vérifie si les emails du client apparaissent dans des fuites de données connues
- API : `GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}`
- Header : `hibp-api-key: <key>`
- Rate limit : 10 req/min

### Ce que le client configure
```
Emails à surveiller : admin@corp.fr, ceo@corp.fr
Domaines à surveiller : corp.fr
Clé API HIBP : (payant ~$3.50/mois)
```

### ⚠️ Points importants
- **Le client doit acheter une clé API HIBP** (~$3.50/mois)
- L'API Pwned Passwords (vérification de mots de passe compromis) est **gratuite et sans clé**
- Rate limit : 10 req/min — respecter avec un délai entre les appels
- Les données transitent par le cloud HIBP — **pas d'anonymisation nécessaire** (l'email est la requête)

### Ce qui manque pour être ✅
- [ ] Module Rust HTTP client pour l'API HIBP
- [ ] Gestion de la clé API via credential vault
- [ ] Respect du rate limit (1.6s entre appels)
- [ ] Le skill doit être marqué "nécessite un abonnement" dans le marketplace

---

## 5. skill-phishing-sim — Simulation de phishing

| | |
|---|---|
| **Statut** | 📝 PROTOTYPE |
| **Outil** | GoPhish |
| **Gratuit** | Oui (MIT) |
| **API key requise** | Auto-générée dans GoPhish |
| **Docker image** | `gophish/gophish:latest` |

### Comment ça marche
- GoPhish a une **API REST complète** sur le port 3333
- ThreatClaw crée des campagnes, des templates, des groupes cibles via l'API
- GoPhish envoie les emails et track les clics/ouvertures/soumissions
- Résultats récupérés via `GET /api/campaigns/{id}/results`
- **HITL obligatoire** — jamais de lancement auto de campagne

### Ce que le client configure
```
Serveur SMTP : smtp.corp.fr:587
Groupes cibles : (liste d'emails)
Domaine expéditeur : phishing-test.corp.fr
API key GoPhish : (générée dans GoPhish > Settings)
```

### API GoPhish
```
POST /api/campaigns/       → créer une campagne
GET  /api/campaigns/{id}/results → résultats
POST /api/groups/           → créer un groupe cible
POST /api/templates/        → créer un template email
POST /api/smtp/             → configurer le profil SMTP
```

### Ce qui manque pour être ✅
- [ ] Client API GoPhish en Rust (ou appel via reqwest)
- [ ] Intégration HITL — le RSSI doit approuver avant tout envoi
- [ ] Template de campagne par défaut (CEO fraud, IT support, HR notice)

---

## 6. skill-soc-monitor — Monitoring SOC / Sigma

| | |
|---|---|
| **Statut** | 📝 PROTOTYPE (moteur Sigma Python fonctionnel en tests) |
| **Outil** | pySigma + Fluent Bit |
| **Gratuit** | Oui (LGPL) |
| **API key requise** | Non |
| **Docker** | Fluent Bit déjà dans le stack |

### Comment ça marche
1. **Le client envoie ses logs** à ThreatClaw via syslog/forward/HTTP
2. **Fluent Bit** reçoit et stocke en PostgreSQL (table `logs`)
3. **Le moteur Sigma** (Python) applique les règles sur les logs
4. Les alertes sont écrites dans `sigma_alerts`
5. Le dashboard affiche les alertes

### Comment le client envoie ses logs

| Source | Config client | Port ThreatClaw | Agent requis |
|--------|---------------|-----------------|--------------|
| **Linux** | 1 ligne dans `/etc/rsyslog.conf` : `*.* @@threatclaw-ip:5140` | 5140/tcp | Non (rsyslog intégré) |
| **Windows** | Installer NXLog CE (gratuit, 5MB), config 20 lignes | 5140/tcp | Oui — NXLog CE |
| **pfSense** | GUI > Status > System Logs > Remote Logging > IP + checkbox | 5140/udp | Non (intégré) |
| **FortiGate** | CLI : `config log syslogd setting` + IP + port | 5140/udp | Non (intégré) |
| **Docker** | `--log-driver=fluentd --log-opt fluentd-address=threatclaw-ip:24224` | 24224/tcp | Non (driver intégré) |
| **AWS CloudTrail** | Lambda function S3 → HTTP POST | 9880/tcp | Lambda function |
| **Azure** | Event Hub → Azure Function → HTTP POST | 9880/tcp | Azure Function |

### Règles Sigma
- 3000+ règles disponibles dans le repo SigmaHQ (LGPL)
- Format YAML standard
- ThreatClaw embarque les règles les plus courantes
- Le RSSI peut ajouter des règles custom

### Ce qui manque pour être ✅
- [ ] Connecter Fluent Bit → table `logs` (config déjà écrite dans `docker/fluent-bit/`)
- [ ] Le moteur Sigma Python doit tourner dans un container isolé
- [ ] Ou : réécrire le moteur en Rust (plus performant pour du temps réel)
- [ ] Le skill-soc-monitor Python a 76 tests qui passent

---

## 7. skill-cloud-posture — Audit cloud AWS/Azure/GCP

| | |
|---|---|
| **Statut** | 📝 PROTOTYPE |
| **Outil** | Prowler |
| **Gratuit** | Oui (Apache 2.0) |
| **API key requise** | **Credentials cloud obligatoires** (IAM) |
| **Docker image** | `prowlercloud/prowler:latest` |

### Comment ça marche
- Prowler scanne l'infrastructure cloud et vérifie les bonnes pratiques
- Mapping automatique NIS2 Art.21, ISO 27001, CIS Benchmarks
- Résultat en JSON-OCSF → parsé → poussé en DB

### Ce que le client configure
```
Provider : AWS / Azure / GCP
AWS : AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (read-only IAM policy suffit)
Azure : AZURE_CLIENT_ID + AZURE_TENANT_ID + AZURE_CLIENT_SECRET
GCP : Service Account JSON key
Régions : eu-west-1, eu-central-1 (optionnel, toutes par défaut)
```

### ⚠️ Points importants
- Le client doit créer un **IAM user/role read-only** dans son cloud
- Les credentials cloud sont **ultra-sensibles** → credential vault obligatoire
- Prowler fait des centaines d'appels API → attention aux **coûts AWS** si le client a un gros compte
- Recommander de scanner **une fois par semaine** (pas quotidien)

### Commande
```bash
docker run -e AWS_ACCESS_KEY_ID=... -e AWS_SECRET_ACCESS_KEY=... prowlercloud/prowler:latest aws --output-formats json-ocsf
```

### Ce qui manque pour être ✅
- [ ] Scanner Rust `src/scanners/prowler.rs`
- [ ] Stockage sécurisé des credentials cloud dans le vault
- [ ] Parsing du format JSON-OCSF

---

## 8. skill-report-gen — Génération de rapports

| | |
|---|---|
| **Statut** | 📝 PROTOTYPE (69 tests Python) |
| **Outil** | Aucun outil externe — génération HTML/PDF en Python |
| **Gratuit** | Oui |
| **API key requise** | Non |

### Comment ça marche
- Lit les findings, alertes, métriques depuis l'API ThreatClaw
- Génère un rapport HTML/PDF en français
- Templates : rapport mensuel, audit NIS2, brief exécutif

### Ce que le client configure
```
Nom de l'entreprise : Corp SAS
Logo : (URL ou upload)
Langue : fr / en
Format : PDF / HTML
Fréquence : cron (défaut: vendredi 8h)
```

### Ce qui manque pour être ✅
- [ ] Le script Python doit tourner dans un container isolé
- [ ] Lire les données réelles via le SDK (`ThreatClawClient`)
- [ ] Le PDF nécessite `weasyprint` ou `wkhtmltopdf` dans le container

---

## 9. skill-compliance-nis2 — Conformité NIS2

| | |
|---|---|
| **Statut** | 📝 PROTOTYPE (70 tests Python) |
| **Outil** | Aucun — mapping logique des findings vers Art.21 |
| **Gratuit** | Oui |
| **API key requise** | Non |

### Comment ça marche
- Lit les findings existants (scans, alertes, cloud) depuis l'API
- Mappe chaque finding vers les 10 articles de NIS2 Art.21
- Calcule un score de conformité par article
- Identifie les écarts et propose un plan de remédiation

### Ce que le client configure
```
Périmètre : Toute l'infrastructure / sélection
Référent conformité : rssi@corp.fr
Échéance : 2026-10-17
```

### Ce qui manque pour être ✅
- [ ] Lire les findings réels via le SDK
- [ ] Le mapping NIS2 Art.21 est codé en dur dans le Python (70 tests)
- [ ] Container isolé pour l'exécution

---

## 10. skill-compliance-iso27001 — Conformité ISO 27001

| | |
|---|---|
| **Statut** | 📝 PROTOTYPE (44 tests Python) |
| **Outil** | Aucun — mapping logique des findings vers 93 contrôles Annexe A |
| **Gratuit** | Oui |
| **API key requise** | Non |

### Identique au skill NIS2 mais pour ISO 27001:2022.
- 93 contrôles Annexe A répartis en 4 catégories
- Score de maturité par contrôle
- Matrice de correspondance NIS2 ↔ ISO 27001

---

## 11. skill-cti-crowdsec — Enrichissement IP (à développer)

| | |
|---|---|
| **Statut** | ❌ À DÉVELOPPER |
| **Outil** | CrowdSec CTI API |
| **Gratuit** | Oui (community tier : 50 req/jour) |
| **API key requise** | Oui (gratuite, inscription sur app.crowdsec.net) |

### Comment ça marcherait
- Quand l'agent IA détecte une IP suspecte dans un finding → enrichissement automatique
- `GET https://cti.api.crowdsec.net/v2/smoke/{ip}`
- Retourne : réputation, comportements, classifications, scores de menace
- Ajoute les infos au finding avant la corrélation IA

### Ce que le client configure
```
Clé API CrowdSec : (gratuite après inscription)
```

### ⚠️ Limite : 50 requêtes/jour sur le tier gratuit. Suffisant pour une PME (rarement plus de 50 IPs suspectes/jour).

---

## RÉSUMÉ GLOBAL

| Skill | Statut | Outil | Gratuit | API key | Effort restant |
|-------|--------|-------|---------|---------|----------------|
| **vuln-scan** | ⚙️ | Nuclei + Nmap | Oui | Non | Scanner Rust → scheduler |
| **secrets-audit** | 📝 | Gitleaks | Oui | Non | Scanner Rust |
| **email-audit** | ⚙️ | DNS (checkdmarc) | Oui | Non | Module Rust DNS |
| **darkweb-monitor** | 📝 | HIBP API | **Payant** (~$3.50/mois) | **Oui** | Client HTTP + vault |
| **phishing-sim** | 📝 | GoPhish | Oui | Auto-générée | Client API + HITL |
| **soc-monitor** | 📝 | Sigma + Fluent Bit | Oui | Non | Fluent Bit config + moteur |
| **cloud-posture** | 📝 | Prowler | Oui | **Credentials cloud** | Scanner + vault |
| **report-gen** | 📝 | Aucun | Oui | Non | Container + SDK |
| **compliance-nis2** | 📝 | Aucun | Oui | Non | Container + SDK |
| **compliance-iso27001** | 📝 | Aucun | Oui | Non | Container + SDK |
| **cti-crowdsec** | ❌ | CrowdSec CTI | Oui (50/jour) | Oui (gratuite) | Tout |

### Ce qui est VRAIMENT fonctionnel aujourd'hui
- **vuln-scan** : Nuclei + Nmap via `real_scan.py` → findings réels en DB → dashboard
- **soc-monitor** : Moteur Sigma Python testé (76 tests) mais pas connecté à Fluent Bit

### Ce qui peut être fonctionnel rapidement (1-2 jours chacun)
- **email-audit** : juste des requêtes DNS, pas d'outil externe
- **secrets-audit** : Gitleaks en Docker, JSON → DB
- **compliance-nis2/iso27001** : lire les findings existants + mapping (logique pure)
- **report-gen** : lire les données + générer HTML (pas d'outil externe)

### Ce qui nécessite une config client significative
- **darkweb-monitor** : le client doit acheter une clé HIBP ($3.50/mois)
- **cloud-posture** : le client doit créer des credentials IAM dans son cloud
- **phishing-sim** : le client doit configurer un SMTP + des groupes cibles
- **soc-monitor** : le client doit configurer l'envoi de logs (syslog/NXLog)

---

## COLLECTE DE LOGS — Guide client

### Linux (1 ligne)
```bash
echo "*.* @@threatclaw-ip:5140" >> /etc/rsyslog.conf && systemctl restart rsyslog
```

### Windows (NXLog CE gratuit)
Installer NXLog CE → configurer `nxlog.conf` avec l'IP ThreatClaw → redémarrer le service.

### pfSense
GUI > Status > System Logs > Settings > Enable Remote Logging > IP ThreatClaw + port 5140.

### FortiGate
```
config log syslogd setting
  set status enable
  set server "threatclaw-ip"
  set port 5140
end
```

### Docker
```bash
docker run --log-driver=fluentd --log-opt fluentd-address=threatclaw-ip:24224 myapp
```

### AWS CloudTrail
CloudTrail → S3 → Lambda → HTTP POST → `threatclaw-ip:9880`

### Azure
Monitor → Diagnostic Setting → Event Hub → Azure Function → HTTP POST → `threatclaw-ip:9880`

### Ports ThreatClaw à ouvrir
| Port | Protocole | Usage |
|------|-----------|-------|
| 5140/tcp | Syslog | Linux, Windows, firewalls |
| 24224/tcp | Forward | Docker containers |
| 9880/tcp | HTTP/JSON | Cloud (Lambda/Functions), scripts |

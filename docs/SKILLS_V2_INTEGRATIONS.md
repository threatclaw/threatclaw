# ThreatClaw Skills v2 — Integrations Reference

> Ce fichier est la source de verite pour chaque integration externe.
> Chaque skill a ete verifie : endpoint, auth, format, rate limits.
> NE PAS implementer sans suivre ce fichier.

---

## Architecture des 3 types d'integration

```
ENRICHMENT (ThreatClaw fait la requete, le client ne fait rien)
  Client ajoute "monsite.fr" dans assets
  → ThreatClaw appelle les APIs automatiquement
  → Cree des Findings si probleme detecte

CONNECTOR (le client a deja l'outil, il donne sa cle API)
  Client configure : URL + API key dans Config > Skills
  → ThreatClaw pull les donnees periodiquement
  → Cree des Alertes/Findings depuis les events

WEBHOOK RECEIVER (l'outil du client pousse vers nous)
  ThreatClaw expose /api/tc/webhook/ingest/{source}?token=xxx
  → L'outil envoie des events en POST JSON
  → ThreatClaw parse et cree des Findings/Alertes
  → Securise par : token HMAC par source, signature verification, rate limit 60/min
```

---

## TIER 1 — ENRICHISSEMENT AUTOMATIQUE

Le client rentre un domaine/URL dans ses assets. ThreatClaw fait les checks.
Pattern Rust : meme structure que `src/enrichment/shodan_lookup.rs`.

---

### 1. skill-google-safebrowsing

**But** : Verifier si une URL est blacklistee par Google (malware, phishing, social engineering)

**API** : Google Safe Browsing API v4
**Endpoint** : `POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=API_KEY`
**Auth** : API key en query param `?key=xxx` (cle gratuite depuis Google Cloud Console, activer "Safe Browsing API")
**Content-Type** : `application/json`

**Request** :
```json
{
  "client": {"clientId": "threatclaw", "clientVersion": "1.0"},
  "threatInfo": {
    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
    "platformTypes": ["ANY_PLATFORM"],
    "threatEntryTypes": ["URL"],
    "threatEntries": [{"url": "https://monsite.fr"}]
  }
}
```

**Response si blackliste** :
```json
{
  "matches": [{
    "threatType": "MALWARE",
    "platformType": "ANY_PLATFORM",
    "threat": {"url": "https://monsite.fr"},
    "cacheDuration": "300.000s"
  }]
}
```

**Response si clean** : `{}` (objet vide)

**Rate limits** : Pas de limite documentee, mais max 500 URLs par requete.

**Config skill.json** :
```json
{
  "id": "skill-google-safebrowsing",
  "name": "Google Safe Browsing",
  "type": "enrichment",
  "config_fields": [
    {"key": "GOOGLE_API_KEY", "label": "Google API Key", "type": "password", "required": true}
  ],
  "cache_ttl_hours": 24,
  "auto_trigger": "on_domain_asset"
}
```

**Implementation Rust** :
```rust
// POST avec reqwest, parse response
// Si "matches" non vide → Finding CRITICAL "URL blacklistee par Google Safe Browsing"
// Si {} → pas de finding, cache 24h
// Champ finding.source = "google-safebrowsing"
```

---

### 2. skill-ssl-labs

**But** : Audit SSL/TLS complet avec note (A+ a F)

**API** : Qualys SSL Labs API v4
**Base** : `https://api.ssllabs.com/api/v4/`
**Auth** : Header `email: votre@email.com` (inscription via `POST /api/v4/register` avec email)

**IMPORTANT** : C'est asynchrone. On soumet, puis on poll.

**Etape 1 — Soumettre** :
```
GET https://api.ssllabs.com/api/v4/analyze?host=monsite.fr&startNew=on
```

**Etape 2 — Poller** (toutes les 10s) :
```
GET https://api.ssllabs.com/api/v4/analyze?host=monsite.fr
```

**Response quand READY** :
```json
{
  "host": "monsite.fr",
  "status": "READY",
  "endpoints": [{
    "ipAddress": "1.2.3.4",
    "grade": "A+",
    "statusMessage": "Ready",
    "hasWarnings": false
  }]
}
```

**Status possibles** : `DNS` → `IN_PROGRESS` → `READY` ou `ERROR`
**Grades** : A+, A, A-, B, C, D, E, F, T (no trust), M (mismatch)

**Rate limits** :
- Headers `X-Max-Assessments` et `X-Current-Assessments`
- 429 = trop de scans simultanes
- 529 = service surcharge, attendre 15+ min
- Poll interval : 5s pendant DNS, 10s pendant IN_PROGRESS

**ATTENTION** : v4 necessite inscription email. Alternative : v3 (`/api/v3/analyze`) fonctionne encore sans auth mais risque deprecation.

**Config skill.json** :
```json
{
  "id": "skill-ssl-labs",
  "name": "SSL Labs Audit",
  "type": "enrichment",
  "config_fields": [
    {"key": "SSLLABS_EMAIL", "label": "Email (for API v4 registration)", "type": "text", "required": true}
  ],
  "cache_ttl_hours": 168,
  "auto_trigger": "on_domain_asset"
}
```

**Implementation Rust** :
```rust
// 1. POST /register si pas encore fait (une seule fois)
// 2. GET /analyze?host=xxx&startNew=on
// 3. Poll GET /analyze?host=xxx toutes les 10s (max 5 min timeout)
// 4. Quand READY : lire grade
//    Grade < B → Finding MEDIUM "SSL Grade {grade} — {details}"
//    Grade F/T → Finding HIGH
//    Grade A/A+ → pas de finding, cache 7 jours
```

---

### 3. skill-mozilla-observatory

**But** : Score securite des headers HTTP (CSP, HSTS, X-Frame-Options...)

**API** : Mozilla Observatory API v2 (v1 fermee octobre 2024)
**Endpoint** : `https://observatory-api.mdn.mozilla.net/api/v2/`
**Auth** : Aucune

**Soumettre un scan** :
```
POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host=monsite.fr
```

**Response** :
```json
{
  "id": 12345,
  "grade": "B+",
  "score": 70,
  "tests_failed": 3,
  "tests_passed": 8,
  "tests_quantity": 11,
  "scanned_at": "2025-01-15T10:30:00Z",
  "status_code": 200
}
```

**Grades** : A+, A, A-, B+, B, B-, C+, C, C-, D+, D, D-, F
**Score** : 0 a 135 (bonus possible au-dela de 100)

**Rate limits** : Cooldown ~60s entre deux scans du meme domaine. Pas de cle API.

**Config skill.json** :
```json
{
  "id": "skill-mozilla-observatory",
  "name": "Mozilla Observatory",
  "type": "enrichment",
  "config_fields": [],
  "cache_ttl_hours": 168,
  "auto_trigger": "on_domain_asset"
}
```

**Implementation Rust** :
```rust
// POST /scan?host=xxx
// Score < 50 → Finding MEDIUM "Headers securite insuffisants (score {score}/100)"
// Grade F/D → Finding HIGH avec details des tests echoues
// Grade A+ → pas de finding, cache 7 jours
```

---

### 4. skill-crt-sh

**But** : Surveiller les certificats emis pour un domaine (detecter rogue certs, sous-domaines)

**API** : crt.sh (Certificate Transparency logs)
**Endpoint** : `GET https://crt.sh/?q={domain}&output=json`
**Auth** : Aucune, pas de cle
**Wildcard** : `?q=%25.monsite.fr&output=json` (le `%25` est le `%` URL-encode)
**Deduplication** : ajouter `&deduplicate=Y`

**Response** (array) :
```json
[
  {
    "issuer_ca_id": 16418,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "monsite.fr",
    "name_value": "monsite.fr\nwww.monsite.fr",
    "id": 1234567890,
    "entry_timestamp": "2025-01-15T10:00:00.000",
    "not_before": "2025-01-15T00:00:00",
    "not_after": "2025-04-15T00:00:00"
  }
]
```

**ATTENTION** :
- Pas de doc officielle, endpoint non-documente mais stable et utilise massivement
- Peut etre lent (10-30s) pour les gros domaines
- `name_value` contient les SANs separes par `\n`
- Pas de rate limit officiel mais ne pas spammer

**Config skill.json** :
```json
{
  "id": "skill-crt-sh",
  "name": "Certificate Transparency Monitor",
  "type": "enrichment",
  "config_fields": [],
  "cache_ttl_hours": 24,
  "auto_trigger": "on_domain_asset"
}
```

**Implementation Rust** :
```rust
// GET https://crt.sh/?q=%25.{domain}&output=json&deduplicate=Y
// Parser le JSON array
// Detecter :
//   - Certificats emis par un CA inconnu/suspect → Finding HIGH "Rogue cert detecte"
//   - Sous-domaines inconnus dans name_value → enrichir la liste d'assets
//   - Certificats expires (not_after < now) → Finding LOW
// Stocker les sous-domaines decouverts comme nouveaux assets
```

---

### 5. skill-urlscan

**But** : Analyser une URL en sandbox (screenshot, scripts, redirections, malware)

**API** : URLScan.io
**Submit** : `POST https://urlscan.io/api/v1/scan/`
**Result** : `GET https://urlscan.io/api/v1/result/{uuid}/`
**Auth** : Header `API-Key: xxx` (cle gratuite sur urlscan.io)

**Submit request** :
```json
{"url": "https://monsite.fr", "visibility": "unlisted"}
```

**Submit response** :
```json
{
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "api": "https://urlscan.io/api/v1/result/UUID/"
}
```

**Result response** (poller jusqu'a HTTP 200, retourne 404 pendant le scan) :
```json
{
  "verdicts": {
    "overall": {
      "malicious": false,
      "score": 0
    }
  },
  "page": {
    "domain": "monsite.fr",
    "ip": "1.2.3.4",
    "url": "https://monsite.fr",
    "status": "200"
  },
  "stats": {
    "resourceStats": [...],
    "malicious": 0,
    "secureRequests": 42,
    "totalLinks": 15
  }
}
```

**Rate limits** : ~50-100 scans/jour sur le free tier. Headers `X-Rate-Limit-Remaining`.
**ATTENTION** : `visibility: "public"` = le scan est visible par tout le monde. Utiliser `"unlisted"`.

**Config skill.json** :
```json
{
  "id": "skill-urlscan",
  "name": "URLScan.io",
  "type": "enrichment",
  "config_fields": [
    {"key": "URLSCAN_API_KEY", "label": "URLScan.io API Key", "type": "password", "required": true}
  ],
  "cache_ttl_hours": 24,
  "auto_trigger": "on_domain_asset"
}
```

**Implementation Rust** :
```rust
// 1. POST /scan avec visibility: "unlisted"
// 2. Poll GET /result/{uuid} toutes les 5s (max 60s, retourne 404 pendant scan)
// 3. Si verdicts.overall.malicious == true → Finding CRITICAL
// 4. Si score > 50 → Finding HIGH
// 5. Sinon → pas de finding, cache 24h
```

---

### 6. skill-wpscan

**But** : Verifier les vulnerabilites WordPress (plugins, themes, core)

**API** : WPScan API v3
**Base** : `https://wpscan.com/api/v3/`
**Auth** : Header `Authorization: Token token=YOUR_API_TOKEN`
**Token gratuit** : 25 requetes/jour (inscription sur wpscan.com)

**Endpoints** :
- Plugin : `GET /plugins/{slug}` (ex: `contact-form-7`)
- Theme : `GET /themes/{slug}`
- Core : `GET /wordpresses/{version}` (ex: `663` pour 6.6.3, sans les points)

**Response plugin** :
```json
{
  "contact-form-7": {
    "friendly_name": "Contact Form 7",
    "latest_version": "5.9.3",
    "vulnerabilities": [
      {
        "id": "xxxx",
        "title": "Contact Form 7 < 5.3.2 - Unrestricted File Upload",
        "fixed_in": "5.3.2",
        "references": {"cve": ["2020-35489"]}
      }
    ]
  }
}
```

**ATTENTION** : Le `slug` est celui de WordPress.org, pas le nom affiche.
**Usage** : Le client entre la liste de ses plugins WP dans la config, ou on detecte automatiquement via headers HTTP.

**Config skill.json** :
```json
{
  "id": "skill-wpscan",
  "name": "WPScan Vulnerabilities",
  "type": "enrichment",
  "config_fields": [
    {"key": "WPSCAN_API_TOKEN", "label": "WPScan API Token", "type": "password", "required": true},
    {"key": "WP_PLUGINS", "label": "WordPress plugins (comma-separated slugs)", "type": "text", "required": false},
    {"key": "WP_THEMES", "label": "WordPress themes (comma-separated slugs)", "type": "text", "required": false},
    {"key": "WP_VERSION", "label": "WordPress version (e.g. 6.6.3)", "type": "text", "required": false}
  ],
  "cache_ttl_hours": 24,
  "auto_trigger": "on_wordpress_asset"
}
```

**Implementation Rust** :
```rust
// Pour chaque plugin/theme/version configure :
//   GET /plugins/{slug} ou /themes/{slug} ou /wordpresses/{version_sans_points}
//   Pour chaque vuln dans "vulnerabilities" :
//     Si la version du client est < fixed_in → Finding (severity selon CVE)
//     Enrichir avec NVD/EPSS si CVE present
// Attention : 25 req/jour max → grouper, cacher, prioriser
```

---

### 7. skill-wordfence-intel

**But** : Base de vulnerabilites WordPress temps reel (gratuit, sans cle API)

**API** : Wordfence Intelligence API v2
**Endpoint** : `GET https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production`
**Auth** : AUCUNE — completement gratuit et ouvert depuis decembre 2022

**Response** : JSON objet indexe par UUID (ATTENTION : fichier de plusieurs MB)
```json
{
  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx": {
    "id": "xxxxxxxx-...",
    "title": "Plugin Name <= 1.2.3 - SQL Injection",
    "software": [{
      "type": "plugin",
      "slug": "plugin-name",
      "affected_versions": {
        "1.2.3": {"from_version": "0", "to_version": "1.2.3"}
      }
    }],
    "references": {"cve": ["2024-12345"]},
    "published": "2024-01-15T00:00:00.000Z",
    "cwe": {"id": 89, "name": "SQL Injection"}
  }
}
```

**ATTENTION** :
- Le feed ENTIER est retourne en une requete (plusieurs MB)
- Pas de pagination ni filtrage cote serveur → filtrer cote client
- Production = vulns verifiees ; Scanner = inclut non-confirmees
- Obligation legale : afficher le copyright MITRE pour les CVE montres aux utilisateurs
- Cache local obligatoire, resync 1x/jour max

**Config skill.json** :
```json
{
  "id": "skill-wordfence-intel",
  "name": "Wordfence Intelligence Feed",
  "type": "enrichment",
  "config_fields": [],
  "cache_ttl_hours": 24,
  "auto_trigger": "on_wordpress_asset"
}
```

**Implementation Rust** :
```rust
// 1. GET /production → stocker en cache local (HashMap<slug, Vec<Vuln>>)
// 2. Resync 1x/jour (le feed entier)
// 3. Quand un asset WordPress est detecte :
//    - Matcher les plugins/themes du client contre le feed
//    - Creer un Finding par vuln matchee
// Difference avec WPScan : Wordfence est gratuit illimite mais necessite de gerer le cache local
// Les deux sont complementaires : Wordfence = feed bulk, WPScan = lookup par plugin
```

---

### 8. skill-phishtank

**But** : Verifier si une URL est connue comme phishing

**API** : PhishTank
**Endpoint** : `POST https://checkurl.phishtank.com/checkurl/`
**Auth** : Cle optionnelle mais recommandee (meilleurs rate limits)
**Content-Type** : `application/x-www-form-urlencoded` (PAS json !)

**Request** :
```
url=https://monsite.fr&format=json&app_key=YOUR_KEY
```

**Response** :
```json
{
  "results": {
    "url": "https://monsite.fr",
    "in_database": true,
    "phish_id": "1234567",
    "verified": true,
    "valid": true
  },
  "meta": {"status": "success"}
}
```

**ATTENTION** :
- Header `User-Agent` OBLIGATOIRE au format `phishtank/votre_username`
- HTTP 509 si rate limit depasse → IP bloquee si abus persistant
- Format par defaut = XML, il FAUT specifier `format=json`

**Config skill.json** :
```json
{
  "id": "skill-phishtank",
  "name": "PhishTank",
  "type": "enrichment",
  "config_fields": [
    {"key": "PHISHTANK_API_KEY", "label": "PhishTank App Key (optional)", "type": "password", "required": false}
  ],
  "cache_ttl_hours": 24,
  "auto_trigger": "on_domain_asset"
}
```

**Implementation Rust** :
```rust
// POST form-encoded (PAS json)
// Header User-Agent: "phishtank/threatclaw"
// Si in_database && verified && valid → Finding CRITICAL "URL phishing confirmee"
// Si in_database && !verified → Finding HIGH "URL signalee phishing (non verifiee)"
// Si !in_database → pas de finding, cache 24h
```

---

### 9. skill-spamhaus

**But** : Verifier si une IP est blacklistee (spam, botnet, hijacked)

**API** : Spamhaus DNSBL (ZEN = SBL + XBL + PBL combine)
**Methode** : DNS query (PAS HTTP)
**Auth** : Aucune (gratuit pour usage faible volume, resolveur DNS propre)

**Comment ca marche** :
Pour checker l'IP `1.2.3.4` → query DNS A pour `4.3.2.1.zen.spamhaus.org`

**Responses** :
- `NXDOMAIN` = clean, pas listee
- `127.0.0.2` = SBL (source de spam connue)
- `127.0.0.3` = SBL CSS (snowshoe spam)
- `127.0.0.4` = XBL CBL (machine exploitee/botnet)
- `127.0.0.9` = DROP/EDROP (espace IP hijacke)
- `127.0.0.10-11` = PBL (IP dynamique/residentielle)
- `127.255.255.254` = ERREUR : votre resolveur DNS est bloque

**ATTENTION CRITIQUE** :
- Les resolveurs publics (8.8.8.8, 1.1.1.1) sont BLOQUES par Spamhaus
- Il FAUT utiliser le resolveur DNS local du serveur ThreatClaw
- Gratuit uniquement pour < 300k requetes/jour et usage non-commercial
- Pour usage commercial → licence DQS (Data Query Service)

**Config skill.json** :
```json
{
  "id": "skill-spamhaus",
  "name": "Spamhaus Blacklist Check",
  "type": "enrichment",
  "config_fields": [],
  "cache_ttl_hours": 24,
  "auto_trigger": "on_ip_asset"
}
```

**Implementation Rust** :
```rust
// Utiliser trust-dns-resolver (pas reqwest, c'est du DNS pas HTTP)
// 1. Reverse l'IP : 1.2.3.4 → 4.3.2.1
// 2. Query A record pour {reversed}.zen.spamhaus.org
// 3. Si NXDOMAIN → clean
// 4. Si 127.0.0.2-4 → Finding HIGH "IP blacklistee Spamhaus ({raison})"
// 5. Si 127.0.0.9 → Finding CRITICAL "IP dans espace hijacke"
// 6. Si 127.0.0.10-11 → Finding LOW "IP dynamique/residentielle"
// 7. Si 127.255.255.x → log erreur, ne pas creer de finding
```

---

## TIER 2 — CONNECTORS (le client a deja l'outil)

Le client donne son URL + API key. ThreatClaw pull les donnees periodiquement.
Pattern Rust : meme structure que `src/connectors/pfsense.rs` ou `wazuh.rs`.

---

### 10. skill-cloudflare

**But** : Recuperer les events WAF, DDoS, bot scores depuis Cloudflare

**API** : Cloudflare GraphQL Analytics API
**Endpoint** : `POST https://api.cloudflare.com/client/v4/graphql`
**Auth** : Header `Authorization: Bearer {API_TOKEN}`
**Token** : Le client cree un API token dans Cloudflare avec permission `Analytics:Read`

**Query GraphQL pour WAF events** :
```json
{
  "query": "{ viewer { zones(filter: {zoneTag: \"ZONE_ID\"}) { firewallEventsAdaptive(filter: {datetime_geq: \"2025-01-15T00:00:00Z\"}, limit: 100, orderBy: [datetime_DESC]) { action clientIP clientCountryName clientRequestPath source userAgent datetime } } } }"
}
```

**Response** :
```json
{
  "data": {
    "viewer": {
      "zones": [{
        "firewallEventsAdaptive": [
          {
            "action": "block",
            "clientIP": "1.2.3.4",
            "clientRequestPath": "/wp-login.php",
            "source": "firewallRules",
            "datetime": "2025-01-15T12:00:00Z"
          }
        ]
      }]
    }
  }
}
```

**ATTENTION** :
- WAF events = GraphQL UNIQUEMENT, pas de REST endpoint pour ca
- Max 10 000 resultats par query
- Zone ID visible dans le dashboard Cloudflare > Overview > cote droit
- Filter supporte : action, clientIP, clientCountryName, source, ruleId, datetime_geq/leq

**Config skill.json** :
```json
{
  "id": "skill-cloudflare",
  "name": "Cloudflare WAF",
  "type": "connector",
  "config_fields": [
    {"key": "CF_API_TOKEN", "label": "Cloudflare API Token (Analytics:Read)", "type": "password", "required": true},
    {"key": "CF_ZONE_ID", "label": "Zone ID", "type": "text", "required": true}
  ],
  "sync_interval_minutes": 5,
  "default_active": false
}
```

**Implementation Rust** :
```rust
// POST GraphQL avec Bearer token
// Sync toutes les 5 min : datetime_geq = last_sync_time
// Pour chaque event "block" ou "challenge" :
//   → Creer une Alerte "Cloudflare WAF: {action} on {path} from {clientIP}"
//   → Enrichir l'IP avec AbuseIPDB/Shodan si deja configure
// Agreger : si > 50 blocks du meme IP en 5 min → Alerte HIGH "Brute force detecte via Cloudflare"
```

---

### 11. skill-crowdsec

**But** : Recuperer les decisions de ban IP et la reputation collaborative

**API** : CrowdSec Local API (LAPI)
**Base** : `http://{CROWDSEC_HOST}:8080/v1`
**Auth** : Header `X-Api-Key: {BOUNCER_KEY}`
**Bouncer key** : Le client genere avec `cscli bouncers add threatclaw`

**Endpoints** :
- Toutes les decisions : `GET /v1/decisions`
- Decisions pour une IP : `GET /v1/decisions?ip=1.2.3.4`
- Stream (temps reel) : `GET /v1/decisions/stream?startup=true`

**Response decisions** :
```json
[
  {
    "id": 42,
    "origin": "crowdsec",
    "type": "ban",
    "scope": "ip",
    "value": "1.2.3.4",
    "duration": "3h59m50s",
    "scenario": "crowdsecurity/http-bf"
  }
]
```

**Response si clean** : `null`

**Stream response** :
```json
{"new": [{...decisions...}], "deleted": [{...decisions...}]}
```

**ATTENTION** :
- C'est une API LOCALE — tourne sur la machine CrowdSec du client, pas un SaaS
- Bouncer keys ≠ watcher keys (permissions differentes)
- `duration` est un format Go (ex: "3h59m50.123456789s")
- Port par defaut 8080, configurable dans `/etc/crowdsec/config.yaml`
- Le stream endpoint avec `startup=true` renvoie tout au premier appel

**Config skill.json** :
```json
{
  "id": "skill-crowdsec",
  "name": "CrowdSec",
  "type": "connector",
  "config_fields": [
    {"key": "CROWDSEC_URL", "label": "CrowdSec LAPI URL (e.g. http://192.168.1.10:8080)", "type": "text", "required": true},
    {"key": "CROWDSEC_BOUNCER_KEY", "label": "Bouncer API Key", "type": "password", "required": true}
  ],
  "sync_interval_minutes": 5,
  "default_active": false
}
```

**Implementation Rust** :
```rust
// Premier sync : GET /v1/decisions/stream?startup=true
// Syncs suivants : GET /v1/decisions/stream (delta seulement)
// Pour chaque decision "new" de type "ban" :
//   → Creer une Alerte "CrowdSec ban: {value} ({scenario})"
//   → Correler avec nos assets : si l'IP bannie correspond a un asset → escalade
// Pour chaque decision "deleted" : marquer l'alerte comme resolue
```

---

### 12. skill-uptimerobot

**But** : Recuperer le statut uptime/down des monitors du client

**API** : UptimeRobot API v2
**Endpoint** : `POST https://api.uptimerobot.com/v2/getMonitors`
**Auth** : `api_key` dans le body POST (PAS un header)
**Content-Type** : `application/x-www-form-urlencoded`

**ATTENTION** : Tous les appels UptimeRobot sont en POST, meme les lectures.

**Request** :
```
api_key=YOUR_API_KEY&format=json
```

**Response** :
```json
{
  "stat": "ok",
  "monitors": [
    {
      "id": 123456,
      "friendly_name": "Mon Site",
      "url": "https://monsite.fr",
      "status": 2,
      "average_response_time": 350,
      "uptime_ratio": "99.980",
      "ssl": {
        "brand": "Let's Encrypt",
        "expires": 1735689600
      }
    }
  ]
}
```

**Status** : 0=paused, 1=not checked, 2=up, 8=seems down, 9=down

**Rate limits** : Free = 10 req/min. Free tier = 50 monitors, 5 min intervals.

**Config skill.json** :
```json
{
  "id": "skill-uptimerobot",
  "name": "UptimeRobot",
  "type": "connector",
  "config_fields": [
    {"key": "UPTIMEROBOT_API_KEY", "label": "UptimeRobot API Key (Read-Only)", "type": "password", "required": true}
  ],
  "sync_interval_minutes": 5,
  "default_active": false
}
```

**Implementation Rust** :
```rust
// POST form-encoded (PAS json)
// Body: api_key=xxx&format=json
// Pour chaque monitor :
//   status 8 ou 9 → Alerte HIGH "{friendly_name} DOWN"
//   ssl.expires < now + 14 jours → Finding MEDIUM "Cert expire dans X jours"
//   average_response_time > 2000ms → Finding LOW "Latence elevee"
//   status 2 → rien (silence)
// Quand un monitor passe de 9 → 2 : resoudre l'alerte
```

---

### 13. skill-uptime-kuma

**But** : Recuperer les monitors depuis une instance Uptime Kuma self-hosted

**API** : Uptime Kuma n'a PAS d'API REST native stable.
**Methode reelle** : Socket.IO (WebSocket)
**Alternative** : Il existe un wrapper REST non-officiel, mais la methode recommandee est Socket.IO.

**ATTENTION** : C'est plus complexe que les autres. Socket.IO necessite une lib specifique.

**Connexion Socket.IO** :
```
ws://{HOST}:3001/socket.io/?EIO=4&transport=websocket
```

**Authentification** :
```json
["login", {"username": "admin", "password": "xxx"}]
```

**Recevoir les monitors** :
```json
["monitorList", {
  "1": {"id": 1, "name": "Mon Site", "url": "https://monsite.fr", "type": "http", "active": true},
  "2": {"id": 2, "name": "API", "url": "https://api.monsite.fr", "type": "http", "active": true}
}]
```

**Recevoir les heartbeats** :
```json
["heartbeat", {"monitorID": 1, "status": 1, "time": "2025-01-15 12:00:00", "ping": 150, "msg": "200 - OK"}]
```

**Status heartbeat** : 0=down, 1=up, 2=pending, 3=maintenance

**Alternative simplifiee** : Uptime Kuma peut envoyer des webhooks (notification providers).
→ Le client configure un webhook vers ThreatClaw dans Uptime Kuma > Settings > Notifications.
→ On recoit les events en POST JSON sur notre webhook receiver.

**Config skill.json** :
```json
{
  "id": "skill-uptime-kuma",
  "name": "Uptime Kuma",
  "type": "connector",
  "config_fields": [
    {"key": "KUMA_URL", "label": "Uptime Kuma URL (e.g. http://192.168.1.10:3001)", "type": "text", "required": true},
    {"key": "KUMA_USERNAME", "label": "Username", "type": "text", "required": true},
    {"key": "KUMA_PASSWORD", "label": "Password", "type": "password", "required": true}
  ],
  "sync_interval_minutes": 0,
  "note": "Connexion WebSocket persistante OU webhook push"
}
```

**Implementation Rust** :
```rust
// OPTION A (recommandee) : Webhook push
//   → Le client configure dans Uptime Kuma : Notification > Webhook > URL = https://tc/api/tc/webhook/ingest/uptime-kuma?token=xxx
//   → On parse le JSON entrant (format Uptime Kuma webhook)
//
// OPTION B (complexe) : Socket.IO
//   → Utiliser rust-socketio ou tokio-tungstenite
//   → Se connecter, login, ecouter "heartbeat" events
//   → Plus complexe mais temps reel
//
// Recommandation : implementer OPTION A d'abord (webhook), OPTION B plus tard
```

---

### 14. skill-wordfence-plugin

**But** : Se connecter au plugin Wordfence installe sur le WordPress du client

**API** : WordPress REST API + Wordfence endpoints
**Base** : `https://{WP_SITE}/wp-json/wordfence/v1/`
**Auth** : Application Password WordPress (Basic Auth)

**ATTENTION** : Necessite que le client ait :
1. Wordfence installe et actif
2. WordPress REST API accessible
3. Un Application Password cree (WP > Users > Application Passwords)

**Endpoints disponibles** (selon version Wordfence) :
- Scan results, firewall events, brute force logs, file changes
- La doc API interne de Wordfence est limitee

**Alternative plus fiable** : Utiliser le Wordfence Intelligence Feed (skill-wordfence-intel, Tier 1) qui est public et ne necessite aucun acces au site du client.

**Recommandation** : Reporter cette skill. Le feed Wordfence Intelligence (Tier 1) couvre 90% du besoin sans acces au site.

---

### 15. skill-sucuri

**But** : Recuperer les events WAF et scans malware depuis Sucuri

**API** : Sucuri API
**Endpoint** : `https://waf.sucuri.net/api/v1/`
**Auth** : API key + secret dans les parametres

**ATTENTION** : L'API complete necessite un abonnement Sucuri payant (~199$/an).
Le scan gratuit (SiteCheck) n'a pas d'API stable documentee.

**Alternative** : On peut scraper SiteCheck (`https://sitecheck.sucuri.net/results/monsite.fr`) mais c'est fragile.

**Recommandation** : Implementer uniquement si le client a deja Sucuri. Sinon, nos enrichissements Tier 1 (Safe Browsing + VirusTotal + URLScan) couvrent le meme perimetre gratuitement.

**Config skill.json** :
```json
{
  "id": "skill-sucuri",
  "name": "Sucuri WAF",
  "type": "connector",
  "config_fields": [
    {"key": "SUCURI_API_KEY", "label": "Sucuri API Key", "type": "password", "required": true},
    {"key": "SUCURI_API_SECRET", "label": "Sucuri API Secret", "type": "password", "required": true}
  ],
  "sync_interval_minutes": 15,
  "default_active": false,
  "note": "Requires paid Sucuri subscription"
}
```

---

### 16. skill-securitytrails

**But** : Historique DNS, changements, detection de sous-domaines

**API** : SecurityTrails API
**Base** : `https://api.securitytrails.com/v1`
**Auth** : Header `APIKEY: xxx` (ATTENTION : nom de header en majuscules, pas de tiret)
**Free tier** : 50 requetes/mois

**Endpoints** :
- Infos domaine : `GET /v1/domain/{hostname}`
- Sous-domaines : `GET /v1/domain/{hostname}/subdomains`
- Historique DNS : `GET /v1/history/{hostname}/dns/{type}` (a, aaaa, mx, ns, soa, txt)
- WHOIS : `GET /v1/domain/{hostname}/whois`

**Response sous-domaines** :
```json
{
  "subdomains": ["www", "mail", "api", "blog", "cdn", "dev", "staging"]
}
```

**Response historique DNS A** :
```json
{
  "records": [
    {"values": [{"ip": "1.2.3.4"}], "first_seen": "2020-01-01", "last_seen": "2025-01-15", "organizations": ["OVH"]}
  ]
}
```

**ATTENTION** : 50 req/mois gratuit = tres limite. Utiliser uniquement pour les scans initiaux, pas le monitoring continu.

**Config skill.json** :
```json
{
  "id": "skill-securitytrails",
  "name": "SecurityTrails DNS Intelligence",
  "type": "enrichment",
  "config_fields": [
    {"key": "SECURITYTRAILS_API_KEY", "label": "SecurityTrails API Key", "type": "password", "required": true}
  ],
  "cache_ttl_hours": 720,
  "auto_trigger": "on_domain_asset",
  "note": "Free tier: 50 requests/month. Use sparingly."
}
```

**Implementation Rust** :
```rust
// GET /domain/{host}/subdomains → decouvrir sous-domaines → ajouter comme assets
// GET /history/{host}/dns/a → detecter changements DNS recents
//   Si IP a change recemment → Finding MEDIUM "Changement DNS detecte"
//   Si nouveau sous-domaine inconnu → Finding LOW "Nouveau sous-domaine decouvert"
// ATTENTION : 50 req/mois → cacher 30 jours, ne lancer que pour les assets "domaine"
```

---

## TIER 3 — WEBHOOK RECEIVER

Un seul endpoint generique, des parsers par source.

---

### 17. Webhook Ingest Endpoint

**Architecture** :
```
POST /api/tc/webhook/ingest/{source}?token={hmac_token}
Content-Type: application/json

{...payload specifique a la source...}
```

**Securite** :
1. Token HMAC unique par source, genere quand le client active le webhook
2. Si la source supporte la signature (Cloudflare, Shopify) → verifier en plus
3. Rate limit : 60/min/source, 1000/h/source
4. Drop silencieux (toujours 200 OK) pour ne rien leaker
5. Body max : 64 KB
6. Validation schema par source

**Sources webhook a supporter** :

| Source | Signature native | Format payload |
|--------|-----------------|----------------|
| `cloudflare` | Header `cf-webhook-auth` | Array d'events WAF |
| `crowdsec` | Aucune (token ThreatClaw) | Decision ban/unban |
| `fail2ban` | Aucune (token ThreatClaw) | `{"ip": "x.x.x.x", "action": "ban", "jail": "sshd"}` |
| `uptimerobot` | Aucune (token ThreatClaw) | `{"monitorFriendlyName": "...", "alertType": 1, "alertDetails": "..."}` |
| `uptime-kuma` | Aucune (token ThreatClaw) | `{"heartbeat": {"status": 0}, "monitor": {"name": "..."}}` |
| `wordfence` | Configurable shared secret | Vuln notification JSON |
| `modsecurity` | N/A (syslog, pas webhook) | Audit log JSON via syslog collector existant |
| `graylog` | Aucune (token ThreatClaw) | Alerte JSON configurable |
| `changedetection` | Aucune (token ThreatClaw) | `{"url": "...", "title": "...", "current_snapshot": "..."}` |

**Implementation Rust** :
```rust
// Route : POST /api/tc/webhook/ingest/{source}
// 1. Verifier token query param contre la DB (HMAC par source)
// 2. Verifier signature native si applicable (cf-webhook-auth, X-Shopify-Hmac-SHA256)
// 3. Rate limit check (compteur par source dans Redis ou memory)
// 4. Parser le body selon le schema de la source
// 5. Creer Finding ou Alerte selon le contenu
// 6. Retourner 200 OK (toujours, meme si erreur interne)

// Handler generique :
async fn webhook_ingest(source: &str, token: &str, body: &[u8]) -> StatusCode {
    if !verify_webhook_token(source, token).await { return StatusCode::OK; }
    if !check_rate_limit(source).await { return StatusCode::OK; }
    match source {
        "cloudflare" => parse_cloudflare_webhook(body).await,
        "crowdsec" => parse_crowdsec_webhook(body).await,
        "fail2ban" => parse_fail2ban_webhook(body).await,
        "uptimerobot" => parse_uptimerobot_webhook(body).await,
        "uptime-kuma" => parse_uptime_kuma_webhook(body).await,
        "wordfence" => parse_wordfence_webhook(body).await,
        "graylog" => parse_graylog_webhook(body).await,
        "changedetection" => parse_changedetection_webhook(body).await,
        _ => { /* source inconnue, drop silencieux */ }
    }
    StatusCode::OK
}
```

---

## RECAPITULATIF

### Deja implemente (ne pas refaire)
| Skill | Type | Status |
|-------|------|--------|
| VirusTotal | Enrichment | OK |
| Shodan | Enrichment | OK |
| AbuseIPDB | Enrichment | OK |
| HIBP | Enrichment | OK |
| GreyNoise | Enrichment | OK |
| NVD/EPSS/CISA KEV | Enrichment | OK |
| CERT-FR | Enrichment | OK |
| MITRE ATT&CK | Enrichment | OK |
| OpenPhish | Enrichment | OK |
| ThreatFox/MalwareBazaar/URLhaus | Enrichment | OK |
| OTX AlienVault | Enrichment | OK |
| CrowdSec (enrichment) | Enrichment | OK |
| Wazuh | Connector | OK |
| pfSense/OPNsense | Connector | OK |
| Fortinet | Connector | OK |
| Active Directory | Connector | OK |
| Proxmox | Connector | OK |
| GLPI | Connector | OK |
| DefectDojo | Connector | OK |
| Nmap | Tool | OK |
| Nuclei | Tool | OK |
| ZAP | Tool | OK |

### A implementer — Tier 1 (enrichissement, 0 config client)
| # | Skill | Effort | Cle API |
|---|-------|--------|---------|
| 1 | Google Safe Browsing | 1h | Oui (gratuite) |
| 2 | SSL Labs | 2h (async poll) | Email registration |
| 3 | Mozilla Observatory | 1h | Non |
| 4 | crt.sh | 1h | Non |
| 5 | URLScan.io | 1.5h (async poll) | Oui (gratuite) |
| 6 | WPScan | 1h | Oui (25/jour gratuit) |
| 7 | Wordfence Intelligence | 1.5h (gros feed) | Non |
| 8 | PhishTank | 30min | Optionnelle |
| 9 | Spamhaus DNSBL | 1h (DNS, pas HTTP) | Non |

### A implementer — Tier 2 (connector, client a deja l'outil)
| # | Skill | Effort | Note |
|---|-------|--------|------|
| 10 | Cloudflare WAF | 2h | GraphQL obligatoire |
| 11 | CrowdSec LAPI | 1.5h | Stream endpoint |
| 12 | UptimeRobot | 1h | POST body auth |
| 13 | Uptime Kuma | 1h webhook / 3h Socket.IO | Webhook d'abord |
| 14 | ~~Wordfence plugin~~ | Report | Feed Intel suffit |
| 15 | Sucuri WAF | 1h | Payant uniquement |
| 16 | SecurityTrails | 1h | 50 req/mois |

### A implementer — Tier 3 (webhook receiver)
| # | Composant | Effort |
|---|-----------|--------|
| 17 | Endpoint generique + parsers | 3h |

### Total estime : ~20h de dev pour 16 nouvelles integrations

---

## Notes pour l'implementation

1. **Pattern enrichissement** : Copier `src/enrichment/shodan_lookup.rs` comme template. Meme structure : `pub async fn enrich(target, config) -> Vec<EnrichmentResult>`.

2. **Pattern connector** : Copier `src/connectors/wazuh.rs`. Meme structure : `pub async fn sync(store, config) -> Result<SyncResult>`.

3. **Cache** : Tous les enrichissements doivent cacher les resultats. Utiliser `store.get_setting()` / `store.set_setting()` avec TTL.

4. **Auto-trigger** : Quand un asset de type "domain" ou "url" est ajoute, declencher automatiquement les enrichissements Tier 1.

5. **Findings** : Chaque enrichissement cree des Findings avec `source = "skill-{id}"`. Le finding contient le resultat brut dans `raw_data` et un texte lisible dans `description`.

6. **Pas de bullshit** : Chaque skill est soit implementee et testee, soit dans le catalogue avec "Bientot disponible" en grise. Jamais de skill qui ne marche pas.

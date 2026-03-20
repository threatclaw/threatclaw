# THREATCLAW V2 — Architecture Multi-Cibles & Credentials
## Surveillance continue · Remédiation distante · Credential Vault · Beta GitHub

---

## 0. PHILOSOPHIE V2

> "ThreatClaw surveille en continu. Les skills observent, l'agent corrèle, le RSSI décide."

La V1 tourne sur une machine et scanne le réseau depuis l'extérieur.
La V2 peut **agir** sur les machines du parc — si et seulement si le RSSI l'a autorisé, cible par cible, action par action.

**Trois principes :**
1. **Zéro droit par défaut** — ThreatClaw ne peut rien faire sans config explicite
2. **Granularité par cible** — chaque serveur/firewall a ses propres permissions
3. **Les credentials ne sortent jamais** — chiffrés au repos, déchiffrés en mémoire uniquement au moment de l'action, zeroed immédiatement après

---

## 1. LES 3 MODES AGENT (rappel)

| Mode | L'agent fait | Droits système | Cas d'usage |
|------|-------------|----------------|-------------|
| **Investigateur** | Scanne, corrèle, propose | **Aucun** — lecture réseau uniquement | Déploiement initial, environnement sensible |
| **Répondeur** | Propose + exécute APRÈS approbation RSSI | Droits sur les cibles configurées | Production avec RSSI disponible |
| **Autonome Low** | Exécute les Low risk seul, HITL pour le reste | Droits sur les cibles configurées | PME mature après 30j de validation |

**Chaque cible peut avoir son propre mode.** Le RSSI peut mettre srv-prod-01 en Répondeur mais garder srv-ad-01 en Investigateur.

---

## 2. INFRASTRUCTURE — LE MODÈLE `[[targets]]`

### 2.1. Structure d'une cible

```toml
# threatclaw.toml

[[targets]]
name = "srv-prod-01"               # Nom affiché dans le dashboard
host = "192.168.1.10"               # IP ou hostname
type = "linux"                      # linux | windows | firewall | network
access = "ssh"                      # ssh | winrm | api | local
port = 22                           # Port de connexion (défaut selon type)
mode = "responder"                  # investigator | responder | autonomous_low
credential = "srv-prod-01-ssh"      # Référence vers le credential vault
ssh_host_key = "sha256:ABC123..."   # Empreinte SSH vérifiée à chaque connexion (TOFU)

# Actions autorisées sur cette cible (subset de la whitelist globale)
allowed_actions = [
    "net-002",    # fail2ban ban IP
    "usr-001",    # verrouiller compte
    "pkg-001",    # mettre à jour package
]

# Tags pour le regroupement dans le dashboard
tags = ["production", "web"]

[[targets]]
name = "firewall-pfsense"
host = "192.168.1.1"
type = "firewall"
access = "api"
driver = "pfsense"                  # pfsense | stormshield | fortinet | sophos
credential = "pfsense-api-key"
mode = "responder"
allowed_actions = [
    "fw-block-ip",
    "fw-unblock-ip",
]
tags = ["réseau", "périmètre"]

[[targets]]
name = "srv-ad-01"
host = "192.168.1.20"
type = "windows"
access = "winrm"
port = 5985
credential = "srv-ad-01-winrm"
mode = "investigator"               # AD = trop critique pour auto-exécuter
allowed_actions = []                 # Vide = aucune action, propositions uniquement
tags = ["windows", "ad", "critique"]
```

### 2.2. Types de cibles supportés

| Type | Accès | Driver | Actions possibles |
|------|-------|--------|-------------------|
| `linux` | SSH (clé ed25519) | openssh natif | iptables, fail2ban, usermod, kill, chmod, apt |
| `windows` | WinRM (⚠️ NTLM ou ✓ Certificat) | `winrs` ou PSRemoting | netsh, Disable-LocalUser, Stop-Process |
| `firewall` | API REST | pfsense, stormshield, fortinet | fw-block-ip, fw-unblock-ip, fw-list-rules |
| `network` | SNMP/SSH | cisco, mikrotik | Lecture seule en V2 |
| `local` | sudoers | natif | Toutes les commandes whitelist (machine ThreatClaw) |

### 2.3. Cible locale (la machine ThreatClaw elle-même)

```toml
[[targets]]
name = "threatclaw-local"
host = "127.0.0.1"
type = "local"
access = "local"
mode = "responder"
allowed_actions = ["net-001", "net-002", "net-003", "usr-001", "proc-001", "file-001", "pkg-001"]
# Pas de credential nécessaire — sudoers configuré par install.sh
```

---

## 3. CREDENTIAL VAULT — SÉCURITÉ DES ACCÈS

### 3.1. Ce qui existe déjà (V1)

ThreatClaw a un module `src/secrets/` complet :
- **AES-256-GCM** chiffrement authentifié par secret
- **HKDF-SHA256** dérivation de clé unique par secret (salt aléatoire 32 bytes)
- **Master key** depuis variable d'environnement ou OS keychain
- **SecretString** (crate `secrecy`) — zeroed en mémoire à la destruction
- **Injection WASM** — les skills ne voient jamais le plaintext, injection au boundary HTTP
- **Contrôle d'accès** — allowlist par tool (patterns glob)

### 3.2. Ce qu'il faut ajouter (V2)

#### A. Master Password avec Argon2id

Au lieu d'une clé hex brute en variable d'env, le RSSI peut définir un **mot de passe maître** dans le wizard.

```
Mot de passe RSSI
    ↓
Argon2id (salt stocké en DB, m=64MiB, t=3, p=1)
    ↓
Master Key 256 bits (jamais stocké, jamais écrit sur disque)
    ↓
HKDF-SHA256 (salt unique par secret)     ← déjà implémenté
    ↓
Clé AES-256-GCM par secret               ← déjà implémenté
```

**Flow utilisateur :**
1. Premier lancement → le wizard demande un mot de passe maître
2. Le mot de passe dérive la master key via Argon2id (~1 seconde)
3. Un "canary" chiffré est stocké pour vérifier le bon mot de passe au prochain démarrage
4. Au redémarrage → le mot de passe est redemandé → dérive la clé → vérifie le canary → déverrouille le vault

**Jamais stocké :**
- Le mot de passe RSSI
- La master key dérivée
- Les clés par-secret

**Stocké (chiffré ou public) :**
- Le salt Argon2id (public, 16 bytes aléatoires)
- Les paramètres Argon2id (m, t, p)
- Le canary chiffré (pour vérification)
- Les secrets chiffrés + leur salt HKDF

#### B. Types de credentials

```rust
pub enum CredentialType {
    /// Clé privée SSH (ed25519 ou RSA).
    /// Stocké : contenu PEM chiffré AES-256-GCM.
    SshKey {
        key_type: SshKeyType,  // Ed25519 | Rsa
        username: String,
        passphrase: Option<SecretString>,  // Si la clé a un passphrase
    },

    /// Clé API REST (firewalls, services cloud).
    /// Stocké : chaîne API key chiffrée.
    ApiKey {
        provider: String,      // "pfsense", "stormshield", "wazuh"
        scopes: Vec<String>,   // permissions de la clé
    },

    /// Credentials WinRM (Windows).
    /// ⚠️ NTLM est vulnérable aux attaques pass-the-hash et relay.
    /// Le wizard recommande WinrmCert pour les environnements AD.
    /// Stocké : username + password chiffrés séparément.
    WinrmBasic {
        username: String,
        domain: Option<String>,  // Pour Kerberos : "CORP.LOCAL"
    },

    /// Certificat client WinRM — RECOMMANDÉ pour environnements AD.
    /// Plus sécurisé que WinrmBasic (pas de pass-the-hash possible).
    /// Stocké : PFX/PEM chiffré + password du certificat.
    WinrmCert {
        cert_password: Option<SecretString>,
    },

    /// Token bearer générique.
    Token {
        provider: String,
    },
}
```

#### C. Cycle de vie des credentials

```
1. CRÉATION (wizard ou CLI)
   RSSI saisit le credential → chiffré immédiatement → stocké en DB
   Le plaintext n'existe qu'en mémoire pendant la saisie

2. UTILISATION (exécution d'action)
   Action approuvée → déchiffrer credential de la cible → connexion → action → zeroed
   Durée en mémoire : quelques secondes maximum

3. TEST (dashboard)
   RSSI clique "Tester la connexion" → déchiffrer → test SSH/API/WinRM → résultat → zeroed
   Jamais de cache du credential déchiffré

4. ROTATION
   RSSI change le credential → nouveau chiffré → ancien conservé comme version N-1 (rollback)
   Historique des versions chiffré, purge automatique après 90 jours

5. RÉVOCATION
   RSSI supprime le credential → toutes les versions purgées → cible passe en Investigateur
   Commande CLI : threatclaw credentials revoke <nom>
```

#### D. Ce que le RSSI ne voit JAMAIS dans le dashboard

- Le contenu d'une clé SSH
- Le mot de passe WinRM en clair
- La clé API en clair

Il voit :
- Le **nom** du credential
- Le **type** (SSH key, API key, WinRM)
- La **cible** associée
- Le **statut** (valide / expiré / non testé)
- La **dernière utilisation** (date + skill qui l'a utilisé)
- Un bouton **"Tester"** et un bouton **"Modifier"** (qui demande re-authentification)

---

## 4. FLOW D'UNE ACTION DISTANTE

### Scénario complet : brute force détecté → blocage firewall

```
1. skill-soc-monitor (WASM sandbox, lecture seule)
   → Détecte 150 tentatives SSH depuis 185.220.101.47 sur srv-prod-01
   → Écrit un finding via SDK : POST /api/tc/findings

2. Cycle ReAct (automatique, toutes les 15 min)
   → Collecte les findings depuis DB
   → Construit le prompt (soul + observations XML wrapped)
   → Appelle qwen3:14b (local)
   → Réponse JSON : severity=CRITICAL, confidence=92%
   → Propose 2 actions :
     - fw-block-ip sur firewall-pfsense (IP: 185.220.101.47)
     - net-002 sur srv-prod-01 (fail2ban ban)

3. Validation whitelist
   → fw-block-ip : ✅ autorisé sur firewall-pfsense
   → net-002 : ✅ autorisé sur srv-prod-01
   → Paramètres validés (pas d'injection)

4. Vérification mode par cible
   → firewall-pfsense : mode=responder → HITL requis
   → srv-prod-01 : mode=responder → HITL requis

5. HITL Slack (message Block Kit)
   ┌──────────────────────────────────────────┐
   │ 🚨 CRITICAL — Kill chain SSH détectée    │
   │                                           │
   │ Brute force depuis 185.220.101.47        │
   │ 150 tentatives en 5 min sur srv-prod-01  │
   │                                           │
   │ Actions proposées :                       │
   │ 1. Bloquer IP sur firewall (tout réseau) │
   │ 2. Bannir IP via fail2ban (srv-prod-01)  │
   │                                           │
   │ [✅ Approuver tout] [1 seul] [2 seul] [❌]│
   │                                           │
   │ Nonce: a8f3c2d1 · Expire: 15 min         │
   └──────────────────────────────────────────┘

6. RSSI clique "Approuver tout"
   → Webhook callback → vérification nonce (anti-replay)
   → Action 1 : déchiffrer API key pfSense → POST /api/firewall/filter/rules
   → Action 2 : déchiffrer SSH key srv-prod-01 → ssh fail2ban-client set sshd banip
   → Credentials zeroed en mémoire immédiatement après

7. Audit log (immuable)
   → HITL_APPROVED by rssi@corp.com
   → EXECUTION_START fw-block-ip on firewall-pfsense
   → EXECUTION_COMPLETE success
   → EXECUTION_START net-002 on srv-prod-01
   → EXECUTION_COMPLETE success

8. Notification Slack
   ┌──────────────────────────────────────────┐
   │ ✅ Actions exécutées                      │
   │ 1. IP bloquée sur firewall — tout réseau │
   │ 2. IP bannie sur srv-prod-01             │
   │ Approuvé par : rssi@corp.com             │
   └──────────────────────────────────────────┘
```

---

## 5. EXÉCUTEURS PAR TYPE DE CIBLE

### 5.1. Exécuteur local (V1 — existe déjà)

```rust
// src/agent/executor.rs — std::process::Command, jamais shell=true
std::process::Command::new("iptables")
    .args(["-A", "INPUT", "-s", &ip, "-j", "DROP"])
    .output()
```

Droits : sudoers `/etc/sudoers.d/threatclaw` configuré par `install.sh`.

### 5.2. Exécuteur SSH distant (V2)

```rust
// src/agent/executor_ssh.rs
pub async fn execute_ssh(
    target: &Target,
    cmd: &ValidatedCommand,
    vault: &CredentialVault,
) -> Result<ExecutionResult, ExecutorError> {
    // 1. Déchiffrer la clé SSH
    let key = vault.decrypt(&target.credential).await?;

    // 2. Connexion SSH (library openssh ou russh)
    let session = SshSession::connect(
        &target.host,
        target.port,
        &key.username,
        &key.private_key,  // SecretString — zeroed à la destruction
    ).await?;

    // 3. Exécuter la commande (PAS de shell — commande directe)
    let output = session.exec(&cmd.rendered_cmd).await?;

    // 4. La clé est automatiquement zeroed quand `key` sort du scope

    Ok(ExecutionResult { ... })
}
```

**Sécurité SSH :**
- **Strict host key checking** (TOFU — Trust On First Use, fingerprint `ssh_host_key` stocké dans `[[targets]]`)
- À la première connexion, le fingerprint est enregistré. Toute modification ultérieure = **refus de connexion + alerte RSSI** (possible MITM)
- Pas de forwarding, pas de tunneling, pas de pseudo-TTY
- Commande directe, pas de shell interactif
- Timeout 30 secondes par commande

### 5.3. Exécuteur API REST (V2 — firewalls)

```rust
// src/agent/executor_api.rs
pub async fn execute_api(
    target: &Target,
    cmd: &ValidatedCommand,
    vault: &CredentialVault,
) -> Result<ExecutionResult, ExecutorError> {
    let api_key = vault.decrypt(&target.credential).await?;

    let driver = match target.driver.as_deref() {
        Some("pfsense") => PfSenseDriver::new(&target.host, &api_key),
        Some("stormshield") => StormshieldDriver::new(&target.host, &api_key),
        Some("fortinet") => FortinetDriver::new(&target.host, &api_key),
        _ => return Err(ExecutorError::UnknownDriver),
    };

    match cmd.id.as_str() {
        "fw-block-ip" => driver.block_ip(&cmd.params["IP"]).await,
        "fw-unblock-ip" => driver.unblock_ip(&cmd.params["IP"]).await,
        _ => Err(ExecutorError::UnsupportedAction),
    }
}
```

**Chaque driver firewall implémente un trait :**

```rust
#[async_trait]
pub trait FirewallDriver {
    async fn block_ip(&self, ip: &str) -> Result<ExecutionResult, ExecutorError>;
    async fn unblock_ip(&self, ip: &str) -> Result<ExecutionResult, ExecutorError>;
    async fn list_rules(&self) -> Result<Vec<FirewallRule>, ExecutorError>;
    async fn test_connection(&self) -> Result<bool, ExecutorError>;
}
```

### 5.4. Exécuteur WinRM (V2 — Windows)

```rust
// src/agent/executor_winrm.rs
// Utilise winrm-rs ou appelle winrs en sous-processus

pub async fn execute_winrm(
    target: &Target,
    cmd: &ValidatedCommand,
    vault: &CredentialVault,
) -> Result<ExecutionResult, ExecutorError> {
    let cred = vault.decrypt(&target.credential).await?;

    // PowerShell commande directe (pas de script, pas de pipeline)
    let ps_cmd = match cmd.id.as_str() {
        "win-usr-001" => format!("Disable-LocalUser -Name '{}'", cmd.params["USERNAME"]),
        "win-net-001" => format!(
            "netsh advfirewall firewall add rule name='TC-Block-{}' dir=in action=block remoteip={}",
            cmd.params["IP"], cmd.params["IP"]
        ),
        _ => return Err(ExecutorError::UnsupportedAction),
    };

    // Exécution via WinRM
    let output = winrm_exec(&target.host, target.port, &cred, &ps_cmd).await?;

    Ok(ExecutionResult { ... })
}
```

---

## 6. PERMISSIONS — INSTALL.SH ET SUDOERS

### 6.1. Ce que `install.sh` configure (V1 — machine locale)

```bash
# /etc/sudoers.d/threatclaw
# Généré par install.sh — exactement la whitelist, rien de plus

threatclaw ALL=(root) NOPASSWD: /sbin/iptables -A INPUT -s * -j DROP
threatclaw ALL=(root) NOPASSWD: /sbin/iptables -D INPUT -s * -j DROP
threatclaw ALL=(root) NOPASSWD: /usr/bin/fail2ban-client set sshd banip *
threatclaw ALL=(root) NOPASSWD: /usr/bin/fail2ban-client set sshd unbanip *
threatclaw ALL=(root) NOPASSWD: /usr/sbin/usermod -L *
threatclaw ALL=(root) NOPASSWD: /usr/sbin/usermod -U *
threatclaw ALL=(root) NOPASSWD: /usr/bin/passwd -l *
threatclaw ALL=(root) NOPASSWD: /usr/bin/passwd -u *
threatclaw ALL=(root) NOPASSWD: /bin/kill -9 *
threatclaw ALL=(root) NOPASSWD: /bin/chmod 000 *
threatclaw ALL=(root) NOPASSWD: /usr/bin/apt-get install --only-upgrade -y *
threatclaw ALL=(root) NOPASSWD: /usr/bin/docker stop *
```

### 6.2. CLI de gestion des permissions

```bash
# Voir les permissions actuelles
threatclaw permissions status
→ 12 commandes autorisées (sudoers)
→ Mode local : Répondeur
→ 3 cibles distantes configurées

# Révoquer tous les droits d'exécution (mode urgence)
threatclaw permissions revoke
→ /etc/sudoers.d/threatclaw supprimé
→ Mode automatiquement basculé en Investigateur
→ Toutes les cibles passent en lecture seule

# Restaurer les droits
threatclaw permissions grant
→ Mot de passe admin requis
→ /etc/sudoers.d/threatclaw recréé
```

### 6.3. Permissions pour cibles distantes (V2)

Les cibles distantes n'utilisent PAS sudoers. Elles utilisent :
- **SSH** : l'utilisateur `threatclaw-remote` sur la cible a son propre sudoers restreint
- **API** : la clé API a des scopes limités (configurés dans le firewall/service)
- **WinRM** : l'utilisateur de service a des GPO restrictives

**Le RSSI doit configurer les droits sur chaque cible manuellement.** ThreatClaw ne peut pas se donner des droits tout seul — c'est une feature de sécurité, pas une limitation.

---

## 7. UX — DASHBOARD V2

### 7.1. Parcours onboarding V2

```
Étape 1 : Bienvenue
Étape 2 : IA Principale (Ollama local / distant / cloud)
Étape 3 : IA Cloud de secours (optionnel, anonymisé)
Étape 4 : Communication (Slack / Telegram / etc.)
Étape 5 : Mot de passe maître (chiffrement credential vault)
Étape 6 : Infrastructure (ajouter les cibles — NOUVEAU)
Étape 7 : Mode agent par cible
Étape 8 : Planning des scans
Étape 9 : Récapitulatif → Dashboard
```

### 7.2. Étape "Infrastructure" dans le wizard

```
┌──────────────────────────────────────────────────────┐
│  INFRASTRUCTURE — Vos serveurs et équipements         │
│                                                       │
│  ThreatClaw peut surveiller et agir sur les machines  │
│  de votre parc. Ajoutez-les ici.                      │
│                                                       │
│  ┌──────────────────────────────────────────────┐    │
│  │  Machine locale (cette machine)       ✅      │    │
│  │  192.168.1.132 · Linux · sudoers configuré   │    │
│  └──────────────────────────────────────────────┘    │
│                                                       │
│  [+ Ajouter un serveur]                               │
│                                                       │
│  ┌──────────────────────────────────────────────┐    │
│  │  Nom : srv-prod-01                            │    │
│  │  IP  : [192.168.1.10        ]                │    │
│  │  Type: [Linux ▾]                              │    │
│  │  Accès: [SSH clé ▾]                           │    │
│  │                                                │    │
│  │  Clé SSH : [Parcourir...] ou [Coller la clé]  │    │
│  │  Utilisateur : [threatclaw-remote]            │    │
│  │                                                │    │
│  │  [Tester la connexion]  ● En attente           │    │
│  └──────────────────────────────────────────────┘    │
│                                                       │
│  [+ Ajouter un firewall]                              │
│                                                       │
│  ┌──────────────────────────────────────────────┐    │
│  │  Nom : firewall-pfsense                       │    │
│  │  IP  : [192.168.1.1         ]                │    │
│  │  Type: [Firewall ▾]                           │    │
│  │  Marque: [pfSense ▾]                          │    │
│  │                                                │    │
│  │  Clé API : [••••••••••••••••]                 │    │
│  │                                                │    │
│  │  [Tester la connexion]  ✅ Connecté            │    │
│  └──────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┘
```

### 7.3. Page "Infrastructure" dans le dashboard (après setup)

```
┌──────────────────────────────────────────────────────┐
│  INFRASTRUCTURE                              [+Ajouter]│
│                                                       │
│  ┌── Machine locale ────────────────────── ✅ ──────┐ │
│  │  192.168.1.132 · Linux · Mode: Répondeur         │ │
│  │  Dernier scan: il y a 2h · 3 findings            │ │
│  │  Actions autorisées: 7/12                         │ │
│  │  [Configurer] [Voir findings]                     │ │
│  └──────────────────────────────────────────────────┘ │
│                                                       │
│  ┌── srv-prod-01 ──────────────────────── ✅ ──────┐ │
│  │  192.168.1.10 · Linux · SSH · Mode: Répondeur    │ │
│  │  Dernier scan: il y a 15min · 1 finding           │ │
│  │  Actions autorisées: fail2ban, lock user, apt     │ │
│  │  [Configurer] [Tester connexion] [Voir findings]  │ │
│  └──────────────────────────────────────────────────┘ │
│                                                       │
│  ┌── firewall-pfsense ────────────────── ✅ ──────┐ │
│  │  192.168.1.1 · Firewall pfSense · API            │ │
│  │  Mode: Répondeur                                  │ │
│  │  Actions autorisées: block IP, unblock IP         │ │
│  │  [Configurer] [Tester connexion]                  │ │
│  └──────────────────────────────────────────────────┘ │
│                                                       │
│  ┌── srv-ad-01 ──────────────────────── ⚠️ ──────┐ │
│  │  192.168.1.20 · Windows · WinRM                   │ │
│  │  Mode: Investigateur (lecture seule)               │ │
│  │  Credentials non testés                            │ │
│  │  [Configurer] [Tester connexion]                  │ │
│  └──────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
```

### 7.4. Règles UX pour les credentials

| Action | Comportement |
|--------|-------------|
| Voir un credential | JAMAIS affiché. Indicateur "••••••" uniquement |
| Modifier un credential | Re-authentification mot de passe maître requise |
| Tester un credential | Déchiffre, teste, affiche résultat (OK/KO), zeroed |
| Supprimer un credential | Confirmation double + la cible passe en Investigateur |
| Copier un credential | INTERDIT — pas de bouton copier |
| Exporter les credentials | INTERDIT en V2. Possible en V3 avec format chiffré |

---

## 8. WHITELIST V2 — COMMANDES PAR TYPE DE CIBLE

### 8.1. Commandes Linux (existantes + distantes)

```rust
// Identiques en local et distant (seul l'exécuteur change)
"net-001"  : iptables -A INPUT -s {IP} -j DROP
"net-002"  : fail2ban-client set sshd banip {IP}
"net-003"  : ss -K dst {IP}
"usr-001"  : usermod -L {USERNAME}
"usr-002"  : passwd -l {USERNAME}
"usr-003"  : pkill -u {USERNAME}
"ssh-001"  : sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
"proc-001" : kill -9 {PID}
"file-001" : chmod 000 {FILEPATH}
"pkg-001"  : apt-get install --only-upgrade -y {PACKAGE}
"docker-001": docker stop {CONTAINER}
"cron-001" : crontab -l -u {USERNAME}          # Lecture seule — voir avant de supprimer
"cron-002" : crontab -u {USERNAME} -r          # Destructif — double confirmation HITL requise
```

### 8.2. Commandes Windows (V2)

```rust
"win-net-001" : netsh advfirewall firewall add rule name='TC-Block-{IP}' dir=in action=block remoteip={IP}
"win-net-002" : netsh advfirewall firewall delete rule name='TC-Block-{IP}'
"win-usr-001" : Disable-LocalUser -Name '{USERNAME}'
"win-usr-002" : Enable-LocalUser -Name '{USERNAME}'
"win-proc-001": Stop-Process -Id {PID} -Force
"win-svc-001" : Stop-Service -Name '{SERVICE}' -Force
```

### 8.3. Commandes Firewall (V2)

```rust
"fw-block-ip"   : Bloquer une IP (API du firewall)
"fw-unblock-ip" : Débloquer une IP
"fw-list-rules" : Lister les règles (lecture seule)
// Jamais : fw-delete-all-rules, fw-factory-reset, fw-disable-firewall
```

---

## 9. CHECKLIST PRÉ-BETA GITHUB

### Sécurité (bloquant)

- [ ] Credential vault avec Argon2id master password
- [ ] Audit log de chaque déchiffrement de credential
- [ ] Aucun credential en clair dans les logs (tracing redacted)
- [ ] Tests red team : injection dans les paramètres d'action
- [ ] Tests red team : tentative d'exécution hors whitelist
- [ ] Tests red team : replay d'un nonce HITL
- [ ] Tests red team : modification du soul en runtime
- [ ] Revue de code sécurité sur executor_ssh.rs et executor_api.rs
- [ ] AGENT_SOUL.toml hash vérifié au CI (pas de modification accidentelle)
- [ ] Aucune dépendance avec CVE connue (cargo audit clean)

### Fonctionnel (bloquant)

- [ ] Wizard onboarding complet (9 étapes)
- [ ] Config page fonctionnelle (targets, credentials, modes)
- [ ] Cycle ReAct end-to-end avec 3 niveaux d'escalade
- [ ] HITL Slack fonctionnel avec double confirmation pour High/Critical
- [ ] Au moins 1 driver firewall (pfSense)
- [ ] Exécuteur SSH distant testé sur 2 distributions Linux
- [ ] Docker compose démarre tout proprement (incluant Ollama)
- [ ] install.sh testé sur Debian 12/13 et Ubuntu 22.04/24.04
- [ ] 500+ tests Rust (0 failed)
- [ ] 5+ tests e2e Playwright (0 failed)

### Documentation (bloquant)

- [ ] README.md avec quick start (5 commandes max)
- [ ] Guide d'installation FR et EN
- [ ] Guide de sécurité (comment ThreatClaw protège vos données)
- [ ] OpenAPI spec à jour
- [ ] CHANGELOG.md à jour
- [ ] LICENSE Apache 2.0 vérifiée

### Qualité (non bloquant mais souhaitable)

- [ ] Dashboard responsive mobile
- [ ] Traduction EN du dashboard
- [ ] CI GitHub Actions vert sur chaque PR
- [ ] Dépendances à jour (dependabot configuré)
- [ ] Logo et branding cohérents

---

## 10. SÉCURITÉ V2 — IMPLÉMENTATION ET DOCUMENTATION

### 10.1. À implémenter (V2 — bloquant beta)

#### Point 1 — Vérification intégrité du binaire

**CI/CD (`.github/workflows/release.yml`) :**
```bash
# Après le build release
sha256sum target/release/threatclaw > threatclaw.sha256
gpg --detach-sign --armor target/release/threatclaw  # → threatclaw.asc

# Publier sur GitHub Releases : binaire + .sha256 + .asc
```

**Installer (`installer/install.sh`) :**
```bash
# Après téléchargement du binaire
echo "$EXPECTED_HASH  /usr/local/bin/threatclaw" | sha256sum -c -
if [ $? -ne 0 ]; then
    echo "ERREUR CRITIQUE : hash du binaire invalide — téléchargement corrompu ou compromis"
    rm -f /usr/local/bin/threatclaw
    exit 1
fi
```

**Systemd (`installer/threatclaw.service`) :**
```ini
[Service]
ExecStartPre=/usr/local/bin/threatclaw verify-binary
ExecStart=/usr/local/bin/threatclaw run
```

**Core Rust (`src/cli/verify.rs`) :**
```rust
/// Commande `threatclaw verify-binary`
/// Compare le hash du binaire en exécution avec le hash publié.
/// - Lit /proc/self/exe (Linux) pour obtenir le chemin du binaire
/// - Calcule SHA-256
/// - Compare avec le fichier .sha256 local ou le hash GitHub Releases
/// - Affiche OK ou ALERTE CRITIQUE
pub fn verify_binary() -> Result<(), Error> {
    let exe_path = std::fs::read_link("/proc/self/exe")?;
    let content = std::fs::read(&exe_path)?;
    let hash = sha256::digest(&content);

    let expected = std::fs::read_to_string("/etc/threatclaw/binary.sha256")
        .unwrap_or_default()
        .trim()
        .to_string();

    if hash == expected {
        println!("✓ Binary integrity OK — hash: {}...{}", &hash[..8], &hash[56..]);
        Ok(())
    } else {
        eprintln!("ALERTE CRITIQUE : hash du binaire ne correspond pas !");
        eprintln!("  Attendu : {}", expected);
        eprintln!("  Trouvé  : {}", hash);
        Err(Error::BinaryIntegrityFailed)
    }
}
```

**Tests :**
```bash
sha256sum /usr/local/bin/threatclaw          # doit correspondre au .sha256 GitHub
threatclaw verify-binary                     # doit afficher OK
# Simuler: remplacer le binaire → doit refuser de démarrer via systemd
```

#### Point 2 — SSH host key fingerprint (TOFU)

**Config (`threatclaw.toml`) :**
```toml
[[targets]]
name = "srv-prod-01"
host = "192.168.1.10"
ssh_host_key = "sha256:ABC123..."  # Récupéré au premier test de connexion
```

**Exécuteur (`src/agent/executor_ssh.rs`) :**
```rust
/// Avant toute connexion SSH :
/// 1. Récupérer le host key du serveur distant
/// 2. Comparer avec ssh_host_key stocké dans la config
/// 3. Si différent → REFUS + alerte critique + audit log
/// 4. Si premier accès (ssh_host_key vide) → stocker le fingerprint (TOFU)
fn verify_host_key(target: &Target, remote_key: &str) -> Result<(), SshError> {
    match &target.ssh_host_key {
        Some(stored) if stored != remote_key => {
            tracing::error!(
                "SECURITY: SSH host key mismatch for {} — possible MITM attack!",
                target.name
            );
            // Alerte RSSI + audit log
            Err(SshError::HostKeyMismatch {
                target: target.name.clone(),
                expected: stored.clone(),
                found: remote_key.to_string(),
            })
        }
        Some(_) => Ok(()),  // Fingerprint OK
        None => {
            tracing::info!("TOFU: Recording SSH host key for {}: {}", target.name, remote_key);
            // Stocker le fingerprint dans la config
            Ok(())
        }
    }
}
```

**Wizard onboarding (étape Infrastructure) :**
```
[Tester la connexion]

→ Connexion SSH réussie.
  Empreinte du serveur : sha256:ABC123DEF456...

  ⚠️ Vérifiez cette empreinte avec votre administrateur système.
  Est-ce correct ?

  [✓ Confirmer et enregistrer]  [✗ Annuler]
```

**Tests :**
```bash
# Simuler MITM: changer le fingerprint dans threatclaw.toml → doit refuser
# Vérifier dans l'audit log que la tentative est loguée
# Vérifier alerte RSSI envoyée
```

#### Point 3 — Rate limiting API Axum

**Middleware (`src/channels/web/server.rs`) :**
```rust
use tower_governor::{GovernorLayer, GovernorConfigBuilder};

// Rate limits par groupe d'endpoints
let critical_limiter = GovernorConfigBuilder::default()
    .per_second(5)           // 5 req/min pour kill-switch, mode
    .burst_size(5)
    .key_extractor(BearerTokenExtractor)
    .finish()
    .unwrap();

let default_limiter = GovernorConfigBuilder::default()
    .per_second(60)          // 60 req/min pour les endpoints data
    .burst_size(60)
    .key_extractor(BearerTokenExtractor)
    .finish()
    .unwrap();

// Appliquer aux routes
let critical_routes = Router::new()
    .route("/api/tc/agent/kill-switch", post(...))
    .route("/api/tc/agent/mode", post(...))
    .layer(GovernorLayer { config: critical_limiter });

let data_routes = Router::new()
    .route("/api/tc/findings", get(...))
    .route("/api/tc/alerts", get(...))
    // ...
    .layer(GovernorLayer { config: default_limiter });

// /api/tc/health → pas de rate limit (monitoring)
```

**Réponse si dépassé :**
```json
{
  "error": "Rate limit exceeded",
  "retry_after_seconds": 10
}
```
HTTP 429 Too Many Requests.

**Détection de token volé :**
```rust
/// Si 3 rate limits consécutifs en 1 minute → possible token volé
/// → Alerte audit log "RATE_LIMIT_ABUSE"
/// → Notification RSSI
static RATE_LIMIT_COUNTER: LazyLock<DashMap<String, (u32, Instant)>> = ...;

fn on_rate_limited(token_hash: &str) {
    let mut entry = RATE_LIMIT_COUNTER.entry(token_hash.to_string()).or_insert((0, Instant::now()));
    if entry.1.elapsed() > Duration::from_secs(60) {
        *entry = (1, Instant::now());
    } else {
        entry.0 += 1;
        if entry.0 >= 3 {
            tracing::error!("SECURITY: Rate limit abuse detected — possible stolen token");
            // Audit log + alerte RSSI
        }
    }
}
```

**Tests :**
```bash
# 100 requêtes en 1 minute sur /api/tc/agent/kill-switch → bloqué à la 6ème
# Vérifier HTTP 429 retourné
# Vérifier alerte dans l'audit log après 3 rate limits consécutifs
```

---

### 10.2. À documenter uniquement (V3 — pas d'implémentation)

#### Point 4 — Audit tiers

**Fichier : `SECURITY.md` (à créer)**

```markdown
## Audit de sécurité

Un audit de sécurité par un tiers indépendant est prévu avant la release
publique officielle (v1.0.0). L'audit couvrira les fichiers prioritaires :

1. `src/agent/executor.rs` — exécution de commandes système
2. `src/agent/executor_ssh.rs` — exécution distante SSH
3. `src/agent/soul.rs` — intégrité du system prompt
4. `src/secrets/crypto.rs` — chiffrement credential vault
5. `src/agent/react_runner.rs` — orchestration LLM
6. `src/agent/remediation_whitelist.rs` — whitelist anti-injection

Pour signaler une vulnérabilité : security@cyberconsulting.fr
(Ne pas ouvrir d'issue GitHub publique pour les vulnérabilités)
```

Ajouter dans le README : `[Politique de sécurité](SECURITY.md)`

#### Point 5 — mTLS entre containers Docker

**Fichier : `docs/ARCHITECTURE.md` — section "Roadmap sécurité"**

```markdown
### V3 — mTLS inter-containers

En V2, la communication entre containers Docker (core ↔ DB, core ↔ Redis)
passe par le réseau Docker interne (`threatclaw-internal`, mode `internal: true`).
C'est suffisant pour les déploiements PME standard.

En V3, mTLS (mutual TLS) sera implémenté entre tous les containers :
- Core ↔ PostgreSQL : certificats client/serveur
- Core ↔ Redis : TLS avec auth certificat
- Core ↔ Ollama : TLS si Ollama distant

Chaque container aura son propre certificat signé par une CA ThreatClaw
générée à l'installation. Rotation automatique des certificats tous les 90 jours.
```

#### Point 6 — Self-monitoring agent

**Fichier : `docs/ARCHITECTURE.md` — section "Roadmap sécurité"**

```markdown
### V3 — Self-monitoring ("ThreatClaw watching ThreatClaw")

Un second processus léger (`threatclaw-watchdog`) surveille le processus
principal de l'agent et déclenche le kill switch si anomalie détectée :

Métriques surveillées :
- Volume d'appels LLM par heure (seuil configurable)
- Fréquence des actions exécutées (détection d'emballement)
- Durée des cycles ReAct (détection de boucle infinie)
- Volume de données envoyées au cloud (détection d'exfiltration)
- Utilisation mémoire/CPU du processus principal

Seuils par défaut :
- > 100 appels LLM / heure → alerte
- > 20 actions exécutées / heure → kill switch
- Cycle ReAct > 30 minutes → kill switch
- > 10MB envoyés au cloud / heure → alerte

Le watchdog est un processus indépendant — si le processus principal est
compromis, le watchdog peut quand même l'arrêter via SIGKILL.
```

---

### 10.3. Ajouts à la checklist beta (section 9)

Les points 1-3 ci-dessus sont ajoutés comme bloquants :

- [ ] Vérification intégrité binaire (SHA-256 + GPG + `verify-binary`)
- [ ] SSH host key fingerprint TOFU avec refus si mismatch
- [ ] Rate limiting API (5/min critical, 60/min default, détection abuse)
- [ ] `SECURITY.md` créé avec contact et liste des fichiers prioritaires

---

### Phase V2a — Credential Vault (2 semaines)
1. Argon2id master password (`src/secrets/master_password.rs`)
2. Types de credentials (SSH, API, WinRM, Token)
3. CLI : `threatclaw credentials add/list/test/revoke`
4. Dashboard page Credentials (formulaires par type)
5. Tests unitaires + tests d'intégration

### Phase V2b — Infrastructure multi-cibles (2 semaines)
1. Structure `[[targets]]` dans `threatclaw.toml`
2. Page Infrastructure dans le dashboard
3. Wizard étape "Infrastructure" (ajout serveurs + firewalls)
4. Test de connexion par cible (SSH ping, API health, WinRM test)
5. Mode par cible (Investigateur/Répondeur/Autonome)

### Phase V2c — Exécuteurs distants + CTI (2 semaines)
1. `executor_ssh.rs` — exécution SSH distant (avec vérification `ssh_host_key`)
2. `executor_api.rs` — driver pfSense (premier firewall)
3. Whitelist Windows (`win-*` commandes)
4. Intégration dans le HITL (cible affichée dans le message Slack)
5. Audit log avec cible + credential utilisé
6. `skill-cti-crowdsec` — enrichissement IP via CrowdSec CTI (API GET, clé API par client)

### Phase V2d — Sécurité & Finitions Beta (2 semaines)
1. Vérification intégrité binaire (SHA-256 + GPG + `verify-binary` CLI)
2. Rate limiting API Axum (`tower-governor`, 5/60 req/min, détection abuse)
3. `SECURITY.md` avec contact et audit roadmap
4. install.sh mis à jour (sudoers, systemd, Ollama auto-install, SHA-256 check)
5. Tests red team complets (6 scénarios listés dans la checklist)
6. Dashboard simplifié (design Chrome, 5 pages, top nav)
7. Documentation complète (README FR/EN, guides, OpenAPI)
8. Tag GitHub v0.2.0-beta

---

## 11. CE QUE THREATCLAW NE FERA JAMAIS

Ces limitations sont des **choix architecturaux**, pas des TODO :

1. **Jamais de shell interactif** — commandes atomiques uniquement
2. **Jamais de credential en clair** dans les logs, la DB, ou les messages Slack
3. **Jamais d'auto-escalade de droits** — le RSSI configure manuellement
4. **Jamais de modification du sudoers** par l'agent — seul install.sh le fait
5. **Jamais de suppression de données** en masse (pas de rm -rf, pas de DROP TABLE)
6. **Jamais d'accès au credential vault** depuis les skills WASM
7. **Jamais de factory reset** sur un firewall
8. **Jamais de désactivation de l'antivirus/EDR** sur une cible
9. **Jamais de modification des GPO Active Directory**
10. **Jamais de transfert de credentials** entre cibles

> *"ThreatClaw est un agent de sécurité, pas un agent de déploiement. Il protège, il ne reconfigure pas."*

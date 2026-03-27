# ThreatClaw — Architecture d'authentification Dashboard

> Document de réflexion — pas encore implémenté.
> Décision à prendre avant mise en place.

---

## Situation actuelle

- Dashboard Next.js **ouvert** à quiconque sur le réseau
- API backend protégé par un **Bearer token partagé** (unique, généré au démarrage)
- Pas de comptes utilisateurs, pas de sessions, pas de login
- Single-tenant on-premise : 1 RSSI + 1-2 analystes max par instance

---

## Option A — Auth intégrée (recommandé pour v2.x)

### Principe

Login/mot de passe géré directement par ThreatClaw. Sessions cookie HttpOnly côté serveur (PostgreSQL). Pas de dépendance externe.

### Architecture

```
ML Engine / Connectors → Bearer token → backend (inchangé)
Navigateur → login → cookie tc_session → Next.js proxy → backend
```

**Dual-auth middleware** : le backend accepte soit un Bearer token (machine), soit un cookie session (humain).

### Points clés

| Aspect | Choix | Raison |
|--------|-------|--------|
| Hashing | argon2id | Standard OWASP 2024, déjà dans Cargo.toml |
| Sessions | Cookie HttpOnly + PostgreSQL | Pas de JWT en localStorage (XSS), pas de Redis (overkill) |
| Rôles | admin / analyst / viewer | 3 niveaux suffisent pour 1-3 users |
| Brute force | 5 échecs → lock 15min | + rate limit IP 10/5min |
| First-run | POST /api/auth/setup (usage unique) | Crée le premier admin à l'installation |
| Reset MdP | Admin reset manuellement | Pas de SMTP garanti en on-premise |

### Avantages

- **Zéro dépendance** — pas de service externe à installer/maintenir
- **Simple** — 5 fichiers Rust + 4 fichiers Next.js
- **Sécurisé** — argon2id, constant-time, anti-bruteforce, audit immutable
- **Rapide à implémenter** — ~2-3 jours
- **Le client n'a rien à configurer** — ça marche out-of-the-box

### Inconvénients

- Pas de SSO / SAML / OIDC
- Pas de fédération d'identité
- Gestion users manuelle (mais on a 3 users max)

### Fichiers à créer

```
migrations/V28__dashboard_auth.sql          ← users, sessions, auth_events
src/channels/web/password.rs                ← argon2id hash/verify
src/channels/web/session.rs                 ← dual_auth_middleware
src/channels/web/handlers/auth.rs           ← login, logout, setup, user CRUD
src/db/auth_store.rs                        ← queries PostgreSQL
dashboard/src/app/login/page.tsx            ← page login
dashboard/src/middleware.ts                  ← redirect /login si pas authentifié
```

---

## Option B — Keycloak en surcouche

### Principe

Keycloak (IAM open-source, Java) gère l'authentification. ThreatClaw valide les tokens OIDC.

### Comment ça marcherait

```
Navigateur → Keycloak login page → OIDC token
           → Dashboard → vérifie token OIDC → backend
```

### Avantages

- **SSO** — un seul login pour tous les outils du client
- **SAML / OIDC / LDAP** — fédération avec Active Directory, Azure AD, Google Workspace
- **MFA intégré** — TOTP, WebAuthn, push via Keycloak
- **Audit centralisé** — tous les événements auth dans Keycloak
- **Standard éprouvé** — utilisé par Red Hat, CERN, etc.

### Inconvénients

- **Dépendance lourde** — Keycloak = service Java qui tourne H24
  - Image Docker : ~500 MB
  - RAM : 512 MB - 1 GB minimum
  - BDD : PostgreSQL (séparée ou partagée)
- **Complexité** — realm, client, scopes, flows, policies...
  - Overkill pour 1-3 utilisateurs
  - Courbe d'apprentissage pour le RSSI client
- **Maintenance** — mises à jour Keycloak, CVEs Java, config à garder
- **Installation** — CyberConsulting.fr doit installer + configurer Keycloak chez chaque client
- **Point de défaillance** — si Keycloak down, plus personne n'accède au dashboard

### Analyse coût/bénéfice

| Critère | Auth intégrée | Keycloak |
|---------|---------------|----------|
| Temps d'implémentation | 2-3 jours | 5-7 jours + intégration OIDC |
| Dépendances | 0 | +1 service Java lourd |
| RAM supplémentaire | 0 | +512 MB - 1 GB |
| Complexité installation client | Zéro | Configuration realm/client |
| SSO / SAML / LDAP | Non | Oui |
| MFA | Non (ajout possible via TOTP plus tard) | Oui natif |
| Nombre d'users optimal | 1-10 | 10-10000 |

---

## Option C — Le client met Keycloak en surcouche

### Principe

ThreatClaw fournit l'auth intégrée (Option A). Si le client veut du SSO, IL installe Keycloak devant et ThreatClaw valide les tokens OIDC en plus des sessions locales.

### Comment

1. ThreatClaw a son auth intégrée (login/mdp) → fonctionne out-of-the-box
2. ThreatClaw expose un paramètre `oidc_issuer` dans la config
3. Si configuré, le dual_auth_middleware accepte aussi les tokens OIDC Bearer
4. Le client configure Keycloak/Azure AD/Okta de son côté

### Avantages

- **Best of both worlds** — marche sans rien, SSO si le client veut
- **Pas de dépendance** pour ThreatClaw
- **Le client garde le contrôle** de son IAM
- **Standard** — OIDC discovery + JWKS validation, quelques lignes de code

### Inconvénients

- 2 systèmes à maintenir pour le client (mais c'est son choix)
- Complexité côté ThreatClaw augmente légèrement (OIDC validation)

---

## Recommandation

### Décision validée

**v2.1 (après InCyber) : Option A — Auth intégrée + TOTP admin**

- Simple, sécurisé, zéro dépendance
- Suffisant pour 100% des clients CyberConsulting.fr actuels
- TOTP obligatoire pour le rôle admin dès le départ (pas en option)
- Un outil de sécurité sans 2FA sur son propre dashboard = mauvais signal

**v2.5 : Option C — OIDC optionnel**

- Paramètre `oidc_issuer` dans la config
- Le client branche Keycloak/Azure AD/Okta de son côté
- ThreatClaw reste léger

### En attendant v2.1 (beta)

Le dashboard est protégé par le Bearer token backend.
Pour la production avant v2.1 :
- Restreindre l'accès par firewall (IPs de confiance uniquement sur le port 3001)
- Utiliser un VPN si accès distant nécessaire

### TOTP 2FA — obligatoire admin

- Crate `totp-rs` — quelques lignes de Rust
- QR code à l'activation du compte admin
- Compatible Google Authenticator / Authy / tout client TOTP standard
- ~1 jour de dev supplémentaire
- Valeur perçue énorme pour un outil de sécurité

Sur le site : *"Authentification sécurisée : Cookie HttpOnly, argon2id, TOTP 2FA — zéro dépendance externe"*

### Perte du mot de passe admin

1. **Un autre admin** reset le mot de passe via le dashboard
2. **CyberConsulting.fr** (support) insère un nouvel admin en DB directement :
   ```sql
   INSERT INTO dashboard_users (email, display_name, password_hash, role)
   VALUES ('rssi@client.fr', 'Nouvel Admin', '$argon2id$...hash...', 'admin');
   ```
3. Même modèle que Grafana, Portainer, Gitea — standard pour l'on-premise

### Ce qu'on ne fait PAS

- **Pas de Keycloak embarqué** dans ThreatClaw (Option B) — trop lourd pour le use case
- **Pas de JWT en localStorage** — jamais (XSS = vol de token)
- **Pas d'OAuth2 password grant** — déprécié par l'IETF
- **Pas de multi-tenant** — une instance = un client
- **Pas de reset par email** — pas de SMTP garanti en on-premise

---

## Schéma de données prévu

```sql
-- V28__dashboard_auth.sql
CREATE TABLE dashboard_users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    password_hash   TEXT NOT NULL,       -- argon2id PHC string
    role            TEXT NOT NULL DEFAULT 'analyst'
                    CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    must_change_pwd BOOLEAN NOT NULL DEFAULT FALSE,
    totp_secret     TEXT,                -- TOTP base32 secret (NULL = 2FA pas encore activé)
    totp_enabled    BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE dashboard_sessions (
    id              TEXT PRIMARY KEY,    -- 32 bytes random hex (CSPRNG)
    user_id         UUID NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
    expires_at      TIMESTAMPTZ NOT NULL,
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address      INET,
    user_agent      TEXT,
    remember_me     BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,         -- NULL = active, set = révoquée
    revoked_reason  TEXT,                -- LOGOUT, ADMIN_REVOKE, PASSWORD_CHANGE, COMPROMISED
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth_events (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type      TEXT NOT NULL,       -- LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, ACCOUNT_LOCKED,
                                         -- PASSWORD_CHANGED, TOTP_ENABLED, SESSION_REVOKED
    email           TEXT NOT NULL,
    ip_address      INET,
    details         TEXT
);
```

---

*Document créé le 26/03/2026 — à valider avant implémentation.*
*Rédigé par CyberConsulting.fr pour ThreatClaw v2.x*

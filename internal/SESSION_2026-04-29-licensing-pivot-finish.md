# Session 2026-04-29 (suite) — finalisation du pivot licensing

**Durée** : après-midi du 2026-04-29.
**État final** : code complet du pivot pricing, livré sur les 3 repos
(`threatclaw`, `threatclaw-premium`). Reste deploy LIVE worker + Cloudflare
Pages côté opérateur (token CF requis).

> Ce fichier est la suite de [SESSION_2026-04-29.md](SESSION_2026-04-29.md)
> qui couvrait la matinée. Le contexte de la journée complète vit là-bas.
> Plan stratégique de référence : [LICENSING_PIPELINE_2026-04-29.md](LICENSING_PIPELINE_2026-04-29.md).
> Runbook go-live : [LICENSING_GO_LIVE_RUNBOOK.md](LICENSING_GO_LIVE_RUNBOOK.md).

---

## TL;DR

- Audit du worker LIVE → 70% du backend asset-tier était déjà en place (webhook `customer.subscription.updated`, tier resolution via lookup_key + product.metadata, magic_links table). Bug critique : le CHECK constraint D1 rejetait `starter`/`pro`/`business`, donc tous les nouveaux checkouts crashaient à l'INSERT.
- Migration D1 (`0002_pricing_pivot.sql` + `0003_portal_audit.sql`) qui rebuild la table licenses sans le CHECK obsolète, ajoute `assets_limit`, et provisionne les tables portal_audit + magic_link_rate_limit.
- Cert porte désormais `assets_limit` (LicenseCertJson v1 backward-compat).
- Endpoint worker `/api/portal-session` : génère URL Stripe billing portal pour le bouton "Manage subscription" du dashboard agent.
- 8 endpoints worker `/api/portal/*` pour le portail client : login-request (magic link rate-limité), login-redeem, logout, logout-everywhere, me, activations, deactivate (IDOR-safe + email d'alerte), billing-portal.
- JWT HS256 maison (~150 lignes, no lib) signé par `MAGIC_LINK_HMAC_SECRET`. Cookie HttpOnly+Secure+SameSite=Strict.
- Portail UI : ~600 lignes HTML+vanilla JS embarqué dans le worker, servi sur `account.threatclaw.io` via dispatch hostname. Strict CSP, no innerHTML interpolation.
- Côté agent : nouveau handler `/api/tc/licensing/portal-session` qui forward au worker. Manager exposed `LicenseManager::portal_session()`.
- Côté dashboard : nouvelle page `/license` (~940 lignes) qui fusionne `/licensing` (Action Pack 416 lignes) + `/setup?tab=about`. 6 sections : Cette installation, Plan actuel, Pas encore de licence, Air-gapped, Mon compte, Support. Sidebar simplifié.
- Anciennes URLs (`/licensing`, `/setup?tab=licenses`, `/setup?tab=about`) → 301 redirect vers `/license`.

---

## Commits

| Repo | Commit | Message |
|---|---|---|
| `threatclaw-premium` | `e043320` | feat(licensing): asset-tier pivot end-to-end + customer portal backend |
| `threatclaw-premium` | `1eba2a5` | feat(portal): account.threatclaw.io UI served from the same worker |
| `threatclaw` | `65f5234` | feat(licensing): unified /license page + portal-session endpoint |

Tous poussés sur Forgejo (origin) + GitHub mirror. Pre-push hooks (cargo fmt + clippy + leak check public docs) tous verts.

---

## Architecture finale

```
                    ┌────────────────────────────────────────────────┐
                    │           Cloudflare Worker (uniq)             │
                    │                                                │
   license.threatclaw.io ◄───── agent licensing API                  │
       /api/activate           + Stripe webhook                      │
       /api/heartbeat                                                │
       /api/deactivate                                               │
       /api/portal-session     (nouveau, agent → Stripe portal URL) │
       /api/check-revocation                                         │
       /webhook/stripe                                               │
                                                                     │
   account.threatclaw.io ◄──── portail client                        │
       /                       (HTML SPA, vanilla JS, 25KB)          │
       /auth                   (magic link redeem)                   │
       /api/portal/*           (8 endpoints, JWT cookie)             │
                                                                     │
                    │                  D1 (shared)                   │
                    │     licenses, activations, revocations,        │
                    │     magic_links, magic_link_rate_limit,        │
                    │     portal_audit, trial_attempts               │
                    └────────────────────────────────────────────────┘
```

Hostname dispatch dans `src/index.ts` : `c.req.header('host')` discrimine.

---

## Décisions techniques notables

- **Worker unique pour les 2 hostnames** plutôt que 2 workers séparés ou Cloudflare Pages : 1 deploy, 1 cookie domain, 0 CORS dance, 0 build pipeline en plus.
- **JWT maison HS256** (pas de lib) pour rester sous la taille de bundle Cloudflare et garder la surface d'attaque minimale (algorithme hardcodé, comparaison constante, pas de `alg=none` possible).
- **Logout-everywhere via watermark D1** plutôt qu'une session table : on regarde le `MAX(occurred_at)` des audit rows `action='logout_everywhere'` pour la licensee, et on refuse les JWT dont `iat < watermark`. Pas de table à GC, pas de session_id à tracker.
- **Email d'alerte sur chaque deactivate** depuis le portail : defence in depth contre une session volée — le client est notifié immédiatement par email même si son cookie a fuité.
- **Rate limit sliding-window via D1** plutôt que KV : un INSERT par requête + un DELETE WHERE older que window au début de chaque check. Cher en théorie mais vu les volumes (~10/h max par bucket), parfaitement OK.
- **Pas d'énumération d'emails** : login-request retourne toujours `{ok:true}`, qu'on envoie ou pas le mail. Différencier la réponse trahit qui a un compte chez nous.
- **Cert payload v1 reste compatible** : `assets_limit` ajouté en optional, l'agent tombe sur `LicenseTier::assets_limit()` runtime fallback si le champ est absent (cas d'un cert pré-pivot encore valide).

---

## Ce qu'il reste à faire (côté opérateur, ~30 min)

Détaillé dans `LICENSING_GO_LIVE_RUNBOOK.md` :

1. `npx wrangler@4 d1 migrations apply threatclaw-licenses --remote` (avec `CLOUDFLARE_API_TOKEN` exporté)
2. `npx wrangler@4 deploy` — provisionne `account.threatclaw.io` automatiquement (custom_domain = true)
3. 3 smoke tests : premier achat, upgrade plan, crash + deactivate-from-portal
4. Email aux clients existants

---

## Reprise dans 3 jours

Si tu rouvres une session "où on en est sur le portal/licensing" :

1. Lis ce fichier (5 min)
2. Lis `LICENSING_PIPELINE_2026-04-29.md` (la carte technique complète)
3. Lis `LICENSING_GO_LIVE_RUNBOOK.md` pour les commandes opérateur
4. `git log --oneline -10` sur `/srv/threatclaw` ET `/srv/threatclaw-premium`
5. Pour vérifier l'état LIVE : `npx wrangler@4 d1 execute threatclaw-licenses --remote --command "SELECT * FROM licenses LIMIT 5"` (montre si la migration a été appliquée et si les rows ont bien `assets_limit`)

---

## Hors scope, à faire dans une session ultérieure

- **CHANGELOG agent v1.0.16-beta** : pour graver publiquement la fin du pivot (page /license unifiée, portal customer self-service). Rédigé brand-level, comme d'habitude. Le passage par le `check-public-docs.sh` gate doit valider.
- **Tag v1.0.16-beta** + release GitHub.
- **Smoke test air-gap path** : valider que la textarea "Air-gapped" sur `/license` accepte bien un cert pré-issued. Endpoint `/api/tc/licensing/activate` actuel attend une `license_key`, pas un cert — il faut adapter le handler ou créer un endpoint `/api/tc/licensing/install-cert` séparé.
- **Page d'erreur friendly** sur le portail si le cookie session expire en plein milieu d'une action.
- **Rotation `MAGIC_LINK_HMAC_SECRET`** annuelle : doc à formaliser, mécanisme de re-keyage à valider (rotate signing_keys: à un instant T, accepter old + new pendant N jours).

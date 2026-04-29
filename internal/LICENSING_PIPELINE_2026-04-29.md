# Licensing Pipeline — état des lieux 2026-04-29 + plan asset-tier

Doc de reprise complète pour ne pas se perdre dans 3 jours / 3 mois.
Si tu rouvres ça en session fraîche, tu peux **partir de zéro** : tout
ce qu'il faut comprendre est ici, avec les pointeurs vers les fichiers
de code et les autres MDs.

> Ce doc supersède partiellement [PREMIUM_PIPELINE.md](PREMIUM_PIPELINE.md)
> qui décrit l'état Action Pack monolithique pré-pivot. Le pivot pricing
> du 28/04 (4 tiers asset-based) est documenté dans
> [PRICING_PIVOT_2026-04-28.md](PRICING_PIVOT_2026-04-28.md).

---

## 1. TL;DR

- Pipeline activate/heartbeat/deactivate déjà en place sur Cloudflare Worker, **plus sophistiqué qu'on ne le croyait** (anti-piratage, recycle stale, grace period).
- Produit a pivoté du modèle Action Pack monolithique (199 €/an unique) vers 4 tiers asset-based (Free/Starter/Pro/Business + Enterprise) le 28/04. HITL libre partout, paid lever = nb d'assets surveillés.
- **Le pipeline backend est encore en mode Action Pack côté Worker D1** (tier hardcodé, pas de `assets_limit`). L'agent côté TC a déjà l'enum + `assets_limit()` étendu (commit `cd7edb7`).
- L'UI dashboard `/licensing` est **toujours en copy Action Pack** (416 lignes pas mises à jour). C'est ce que le user voit sur staging et qui motive la suite.
- Portail client self-service **pas encore construit** (`/srv/threatclaw-premium/portal/` vide). Indispensable pour le scénario "serveur crashé, le client doit libérer sa licence pour réinstaller".

---

## 2. Le produit en deux phrases

**Avant pivot (jusqu'à v1.0.14)** : un SKU "Action Pack" 199 €/an qui débloque toutes les actions HITL destructrices ; tout le reste libre AGPL.

**Depuis pivot (v1.0.15-beta)** : tout le code est libre AGPL, **HITL inclus**. La paid lever est le **cap d'assets surveillés** par tier :

| Tier | Cap assets | Engagement |
|---|---|---|
| **Free** | 50 | self-hosted, AGPL, communauté |
| **Starter** | 200 | mensuel ou annuel |
| **Pro** | 500 | mensuel ou annuel |
| **Business** | 1500 | mensuel ou annuel |
| **Enterprise** | unlimited / MSP | sur devis |

Source de vérité tarifaire : `threatclaw.io/pricing` (refondu hier sur le repo `threatclaw-website` Forgejo).

---

## 3. Topologie complète du pipeline

```
   ┌──────────────────────┐
   │ threatclaw.io        │   site marketing Next.js
   │ /pricing (4 cards)   │   VPS 85.215.199.155
   └──────────┬───────────┘
              │ click "Starter / Pro / Business" (mensuel ou annuel)
              ▼
   ┌──────────────────────┐
   │ Stripe Payment Link  │   6 SKUs LIVE (3 plans × 2 cadences)
   │ buy.stripe.com/...   │   metadata.tier sur chaque produit
   └──────────┬───────────┘
              │ webhook checkout.session.completed
              ▼
   ┌──────────────────────┐
   │ Cloudflare Worker    │   license.threatclaw.io
   │ /webhook/stripe      │   handler dans handlers/stripe_webhook.ts
   └──────────┬───────────┘
              │ 1. valide signature webhook (STRIPE_WEBHOOK_SECRET)
              │ 2. lookup tier via price.lookup_key + product.metadata
              │ 3. INSERT D1.licenses ROW (license_key UUID, tier, expires_at)
              │ 4. EMAIL Brevo au client : "voici votre license_key XXXX"
              ▼
   ┌──────────────────────┐
   │ Client reçoit l'email│   contenu : license_key string (PAS le cert)
   │ Va sur /licensing    │
   │ dans son ThreatClaw  │
   └──────────┬───────────┘
              │ paste license_key, clic "Activer"
              ▼
   ┌──────────────────────┐
   │ TC core              │   src/licensing/manager.rs::activate()
   │ POST /api/tc/        │   lit ~/.threatclaw/licensing/install_id
   │   licensing/install  │   calcule site_fingerprint = sha256(install_id)
   └──────────┬───────────┘
              │ POST /api/activate
              │ { license_key, install_id, site_fingerprint }
              ▼
   ┌──────────────────────┐
   │ Worker /api/activate │
   │ handlers/activate.ts │
   └──────────┬───────────┘
              │ 1. SELECT D1.licenses → trouve la row
              │ 2. SELECT D1.revocations → check pas révoquée
              │ 3. SELECT D1.activations COUNT → si >= max_activations
              │      → recycle_stale (last_heartbeat > 30j) → retry
              │      → si toujours plein → 402 "activation_limit"
              │ 4. INSERT D1.activations (license_key, install_id, fp, host, ts)
              │ 5. cert_factory.ts::buildCertResponse :
              │     payload = { v:1, licensee, tier, skills, site_fingerprint,
              │                 issued_at, expires_at:now+30j, grace:90j }
              │     signature = Ed25519(SIGNING_PRIVKEY_HEX)
              │     return base64(payload + signature)
              ▼
   ┌──────────────────────┐
   │ TC core reçoit cert  │   storage::write_cert(cert)
   │ verify(cert, pubkey) │   PremiumGate::new(cert)
   │ allows_hitl()=true   │
   └──────────┬───────────┘
              │
              │ tâche background : LicenseManager::spawn_heartbeat()
              │ tous les 7 jours
              ▼
   ┌──────────────────────┐
   │ Worker /api/heartbeat│
   │ handlers/heartbeat.ts│
   └──────────┬───────────┘
              │ vérifie license active, refresh activation, ré-émet cert frais
              ▼
        cert renouvelé pour 30j de plus, allows_hitl reste true

```

**Certificats** : durée 30j, heartbeat tous les 7j → 4× safety margin. Si un heartbeat échoue, 3 autres tentatives avant expiry. Si tout est down 30j+90j de grace = 120j d'air-gap toléré sans contact serveur.

---

## 4. Composants — où ça vit

| Composant | Path | Hôte | Rôle |
|---|---|---|---|
| **Site marketing** | `/srv/threatclaw-website/app/src/app/[locale]/pricing/page.tsx` | VPS marketing 85.215.199.155 | 4 cartes + toggle mensuel/annuel + 6 Payment Links Stripe |
| **Worker licensing** | `/srv/threatclaw-premium/worker/src/` | Cloudflare (deploy via `npx wrangler@4 deploy`) | Endpoints `/api/activate /api/heartbeat /api/deactivate /api/trial /webhook/stripe` |
| **Worker handlers** | `worker/src/handlers/{activate,heartbeat,deactivate,stripe_webhook,trial}.ts` | Cloudflare | Logique métier par endpoint |
| **Worker cert factory** | `worker/src/cert_factory.ts` | Cloudflare | Construit + signe le cert Ed25519 |
| **Worker crypto** | `worker/src/crypto/{cert,license_key}.ts` | Cloudflare | Ed25519 sign + format license_key |
| **D1 (DB worker)** | `worker/src/db/{licenses,activations,revocations}.ts` | Cloudflare D1 | Tables : licenses, activations, revocations |
| **D1 schema** | `worker/schema/` | — | Migrations D1 |
| **Stripe** | dashboard.stripe.com | — | LIVE mode, account `cyberconsulting@…` |
| **Brevo** | api.brevo.com | — | Transac email avec template welcome |
| **Agent licensing** | `src/licensing/{manager,api_client,cert,gate,storage,fingerprint,trial,verify,grace}.rs` | Chez le client | LicenseManager, vérification cert, heartbeat client |
| **Agent install_id** | `~/.threatclaw/licensing/install_id` | FS du client | UUID local (généré à la 1ère install) |
| **Agent gate HITL** | `src/agent/tool_calling.rs::tool_requires_hitl` + `src/channels/hitl_bridge.rs` | TC core | Refuse 402 si `allows_hitl()=false`. **Note : depuis pivot, `allows_hitl()` retourne `true` partout — gate désactivée pour HITL, mais reste pour future features paid.** |
| **Dashboard licensing UI** | `dashboard/src/app/licensing/page.tsx` (416 l, ENCORE EN ACTION PACK) | Chez le client | À refaire : copy + tier display + assets gauge + portal link + textarea air-gap |
| **Dashboard billing UI** | `dashboard/src/app/billing/page.tsx` (créée hier) | Chez le client | Jauge tier + assets count + 60s refresh, **propre** |
| **Setup wizard licenses tab** | `dashboard/src/app/setup/page.tsx:371` | Chez le client | Lien vers `/licensing` qui pointe sur la vieille copy |
| **Lien Skills "Mes licences"** | `dashboard/src/app/skills/page.tsx:783` | Chez le client | À retirer (HITL libre, plus de raison) |
| **Portail client self-service** | `/srv/threatclaw-premium/portal/` | Cloudflare Pages (futur) | **Pas encore construit, juste un .gitkeep** |

---

## 5. Anti-piratage — ce qui est en place

| Scénario | Mécanisme |
|---|---|
| **Sharing license avec un pote** | `max_activations=1` par défaut. Worker refuse 402 quand slot pris. |
| **Install sur 1000 serveurs** | Idem `max_activations`. Chaque install a un `install_id` unique aléatoire généré par `storage::load_or_create_install_id`. |
| **Cert volé, fork sans vérif** | Possible légalement (AGPL) mais perd auto-renew, support, audit signé. Doctrine : on vend le workflow, pas la capacité. |
| **Air-gap (pas Internet)** | Cert valide 30j + grace 90j → 120j tolérance offline. |
| **Annulation Stripe** | Webhook `customer.subscription.deleted` → status='cancelled' → cert expire en fin de fenêtre 30j → HITL refusé. |
| **Crash serveur, slot bloquée** | Auto-recycle après 30j de heartbeat absent. Avant 30j : besoin du portail (à construire). |
| **Revocation manuelle (fraud, refund)** | Table D1 `revocations` consultée à chaque activate/heartbeat. Insertion manuelle via `wrangler d1 execute`. |

---

## 6. Reinstall flow — les deux scénarios

### Scénario A — Ancien serveur encore accessible
1. Login dashboard ancien install → `/licensing` → "Deactivate this install"
2. Appel `POST /api/deactivate` worker → slot D1 libérée immédiatement
3. Nouveau serveur active sans friction

**Couvert par le code actuel.**

### Scénario B — Ancien serveur mort
**Aujourd'hui (avant portail)** : deux options inconfortables :
- Attendre 30j que l'auto-recycle fasse son office (inacceptable en prod)
- Mailer `contact@cyberconsulting.fr` → `wrangler d1 execute` manuel

**Demain (avec portail)** : `account.threatclaw.io` permet au client de voir ses activations et deactivate à distance, sans contact support. **Indispensable pour le sprint pricing.**

---

## 7. Les clés et secrets — qui sert à quoi

### Paire Ed25519 (signature cert)
| Clé | Stockage | Rôle |
|---|---|---|
| `SIGNING_PRIVKEY_HEX` (privée) | Cloudflare Worker secret | Signe chaque cert. Si fuite : tout est cassé, faut tout révoquer + roll keys + re-émettre. |
| Clé publique correspondante | Compilée dans le binaire `threatclaw` (constante `PUBKEY_HEX` quelque part dans `src/licensing/verify.rs`) | Vérifie la signature de chaque cert. |

### Stripe
| Clé | Stockage | Rôle |
|---|---|---|
| `STRIPE_WEBHOOK_SECRET` | Worker secret | Vérifie signature des webhooks pour empêcher des appels forgés. |
| `STRIPE_API_KEY` | Worker secret | Appelle l'API Stripe (lookup, billing portal session, future API calls). |

### Email + Magic links
| Clé | Stockage | Rôle |
|---|---|---|
| `BREVO_API_KEY` | Worker secret | Envoi des emails transactionnels (welcome, magic link, etc.). |
| `MAGIC_LINK_HMAC_SECRET` | Worker secret | Signe les magic links pour login passwordless du portail. **Provisionné mais pas encore utilisé** — attend la construction du portail. |

### Variables non-secret (dans wrangler.toml [vars])
- `TRIAL_DURATION_SECS` (60j par défaut)
- `CERT_VALIDITY_SECS` (30j)
- `PAID_GRACE_DAYS` (90j) / `TRIAL_GRACE_DAYS` (0)
- `REVOCATION_URL` : URL de check révocation que le cert porte
- `EMAIL_FROM`, `EMAIL_REPLY_TO`
- `DEFAULT_TIER`, `DEFAULT_SKILL` (legacy "hitl")

---

## 8. Gap analysis — Action Pack → Asset tiers

### Côté Worker (Cloudflare)
- [ ] **Migration D1** : ajouter `'starter' | 'pro' | 'business'` à l'enum `tier` + colonne `assets_limit INTEGER` sur `licenses`. Backfill : Action Pack legacy → tier='starter', assets_limit=200.
- [x] **`stripe_webhook.ts`** : tier resolution via `price.lookup_key` + `product.metadata` — fait hier d'après mémoire `project_pricing_state.md`. À vérifier en LIVE.
- [ ] **`cert_factory.ts`** : ajouter `assets_limit` au payload `LicenseCertJson`.
- [ ] **`types.ts`** : ajouter `assets_limit` à `LicenseRow` + `LicenseCertJson`.
- [ ] **Webhook `customer.subscription.updated`** : nouveau handler pour les changements de plan via portail Stripe. UPDATE D1.licenses.tier + .assets_limit. **Cause directe du flow upgrade 200→250 sans friction.**
- [ ] **Endpoint `/api/portal-session`** : appelle Stripe `billing_portal.sessions.create`, retourne URL. Permet à TC core d'ouvrir le portail Stripe pour le client.

### Côté Agent (TC core Rust)
- [x] **`cert.rs`** : enum `LicenseTier` étendu avec Free/Starter/Pro/Business/Enterprise + `assets_limit()` (commit `cd7edb7` hier).
- [x] **`manager.rs`** : `allows_hitl()=true` partout (HITL libéré).
- [x] **`billing.rs`** + V66 : comptage `billable_assets` continu.
- [x] **`/api/tc/licensing/heartbeat`** : déjà présent dans `licensing_api.rs::heartbeat_handler`.
- [x] **`/api/tc/licensing/portal-session`** : ajouté dans `licensing_api.rs::portal_session_handler`, `LicenseManager::portal_session()`, `LicenseClient::portal_session()`.

### Côté Dashboard (Next.js)
- [x] **Réécrire `app/licensing/page.tsx`** : remplacé par `app/license/page.tsx` (~940 lignes, 6 sections) — voir §15.
- [x] **Retirer le lien `/setup?tab=licenses` de `app/skills/page.tsx`**.
- [x] **Aligner `app/setup/page.tsx`** : redirect 301 vers `/license`.

### Portail client (livré 2026-04-29 après-midi)
- [x] **`account.threatclaw.io`** : servi par le même worker que `license.threatclaw.io` (architecture single-worker hostname-dispatch, voir §13).
  - Login magic link (HMAC + JWT cookie, voir §14)
  - Page "Mes plans" : tier, cap assets, expires, statut, bouton Stripe billing portal
  - Page "Mes installations" : hostname, install_id, version, last_seen, bouton [Désactiver]
  - Logout + Logout-everywhere
- [x] **i18n FR/EN** : auto-détection navigator.language + toggle persisté (voir commit `5f418f3`).
- Stack effective : HTML+vanilla JS embarqué dans le worker (pas de Next.js séparé). Plus simple, single-deploy, pas de CORS dance, cookie same-origin par construction.

---

## 9. Plan de bataille — ordre d'attaque

> **Statut au 2026-04-29 fin de journée** : tâches 1 à 9 livrées, codé +
> déployé LIVE. Voir section 20 pour l'état final complet. Le tableau
> ci-dessous reste comme trace historique du planning initial.

| # | Tâche | Effort | Bloque | Statut |
|---|---|---|---|---|
| 1 | **Audit worker LIVE** : vérifier que `stripe_webhook.ts` reconnaît bien les 6 nouveaux SKUs Stripe et émet le tier correct. Test avec un webhook event. | 30-45 min | tout | ✅ |
| 2 | **Migration D1** : `tier` enum étendu + colonne `assets_limit` + backfill | 30 min | #3, #4 | ✅ |
| 3 | **Worker `cert_factory.ts` + types** : injecter `assets_limit` dans le cert | 30 min | agent | ✅ |
| 4 | **Worker webhook `customer.subscription.updated`** + tests | 1-2 h | upgrade flow | ✅ (déjà existant, enrichi) |
| 5 | **Worker `/api/portal-session`** : endpoint Stripe billing portal | 30 min | UI | ✅ |
| 6 | **TC core endpoints `/api/tc/licensing/{heartbeat,portal-session}`** | 1 h | UI | ✅ |
| 7 | **Dashboard refonte `/licensing`** | 2-3 h | UX visible | ✅ |
| 7bis | **Fusion `/licensing` + `/setup?tab=about` en `/license` unifiée** (voir §15) | inclus dans #7 | UX | ✅ |
| 8 | **Cleanup `/skills`** (retirer lien "Mes licences") + redirects 301 sur les anciennes URLs | 30 min | polish | ✅ |
| 9 | **Portail client `account.threatclaw.io`** (login magic link, list activations, deactivate, link Stripe portal) | 3-4 h | scénario reinstall sans support | ✅ |
| 9bis | **i18n FR/EN du portail** (toggle + auto-détection) | 30 min | UX EN | ✅ |
| 9ter | **Télémétrie anonyme + admin dashboard** (voir sections 17-19) | 6 h | visibilité installs | ✅ |
| 10 | **Test e2e LIVE** : carte réelle, upgrade Starter→Pro, vérif cert change, refund | 1 h + délais Stripe | sortir du beta | ⏳ à faire en condition réelle |
| 11 | **Communication client portail** : email aux clients existants + lien dans `/license` | 30 min | dépendance #9 | ⏳ à envoyer |

**Effort total : ~10-12 h** initialement estimé. Effort réel : ~12 h
de boulot étalé sur la journée (pivot complet + portail + télémétrie +
admin dashboard + i18n).

**Ordre recommandé** : 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11.

Possible split en 2 sprints :
- **Sprint A** (#1-#8) : refonte UI cohérente avec le nouveau pricing, upgrade flow Stripe portal opérationnel. ~7-8 h. Shippable et utile sans le portail.
- **Sprint B** (#9-#11) : portail client. ~5 h. Peut attendre 2-3 semaines sans bloquer les premiers vrais clients (workaround : on traite manuellement les rares cas crash + reinstall).

---

## 10. Stripe — référence rapide

### 6 Payment Links LIVE (pour mémoire)
Voir `project_pricing_state.md` pour les URLs exactes. Format :
- Starter mensuel / annuel
- Pro mensuel / annuel
- Business mensuel / annuel

Chaque produit Stripe a `metadata.tier` = `starter` | `pro` | `business`.
Chaque prix a un `lookup_key` = `tc_<tier>_<cadence>` (ex: `tc_starter_monthly`).

### Test mode vs Live
- TEST : ancien `Action Pack 199 €/an` archivé, garder pour régression
- LIVE : 6 nouveaux SKUs depuis 28/04, account `cyberconsulting@…`

### Diagnostic en cas de pépin paiement
1. Stripe Dashboard → Webhooks → endpoint `license.threatclaw.io/webhook/stripe` → "Recent attempts" : delivery OK ou signature rejected ?
2. Worker logs en live : `cd /srv/threatclaw-premium/worker && npx wrangler@4 tail`
3. D1 : `npx wrangler@4 d1 execute <DB> --command "SELECT * FROM licenses ORDER BY created_at DESC LIMIT 5"`
4. Brevo dashboard : transactional → email envoyé ?

---

## 11. Comment reprendre dans 3 jours / 3 mois

**Si tu rouvres une session à froid :**

1. **Lis la section 20 en premier** — c'est l'état définitif de ce qui est LIVE au 2026-04-29 fin de journée. Tableaux des composants, schéma D1, secrets, endpoints, runbook ops.
2. Lis ce fichier en intégralité si tu veux le contexte historique (pourquoi telle décision, alternatives écartées).
3. `cat ~/.claude/projects/-root/memory/project_pricing_state.md` pour l'état Stripe.
4. `cat ~/.claude/projects/-root/memory/project_hitl_doctrine.md` pour la doctrine HITL.
5. `git log --oneline | head -20` côté `/srv/threatclaw` ET `/srv/threatclaw-premium` pour voir les derniers commits.
6. `cat internal/SESSION_2026-04-29*.md` pour les récits chronologiques.

**Pour vérifier l'état LIVE D1 sans coder** :
```bash
cd /srv/threatclaw-premium/worker
export CLOUDFLARE_API_TOKEN=cfut_...   # voir infra_website.md memory
npx wrangler@4 d1 execute threatclaw-licenses --remote --command "
  SELECT 'licenses' as t, COUNT(*) FROM licenses
  UNION ALL SELECT 'activations', COUNT(*) FROM activations WHERE active=1
  UNION ALL SELECT 'anonymous_pings', COUNT(*) FROM anonymous_pings
  UNION ALL SELECT 'installer_downloads', COUNT(*) FROM installer_downloads
"
```

**Pour redéployer staging** :
```bash
cd /srv/threatclaw && bash deploy/deploy-staging.sh --core
```

**Pour redéployer le worker** :
```bash
cd /srv/threatclaw-premium/worker
export CLOUDFLARE_API_TOKEN=cfut_...
npx wrangler@4 d1 migrations apply threatclaw-licenses --remote   # si nouvelle migration
npx wrangler@4 deploy
```

**Pour ouvrir le dashboard admin** :
- https://account.threatclaw.io/
- Login avec `contact@cyberconsulting.fr` (whitelist `ADMIN_EMAILS`)
- Click `/admin`

---

## 12. Doctrine à respecter pendant la refonte

- **Le code reste AGPL.** On ne ferme rien. Le license check est juste un `if` qu'un fork peut retirer — on l'accepte.
- **La valeur vendue est le workflow** (cert auto-renew, support, audit signé, portail self-service, billing portal Stripe), pas la capacité technique.
- **Pas de jargon "premium skill" ou "Action Pack"** dans le copy nouveau. Tier name (Starter/Pro/Business) suffit.
- **Pas de friction inutile** : auto-sync 7j par défaut, refresh manuel sur demande, paste manuel seulement en air-gap.
- **Stripe billing portal pour tout ce qui touche au paiement** (upgrade, downgrade, cancel, payment method, factures). Pas de page custom = pas de surface d'erreur.

---

## 12bis. Identités — qui est qui dans le système

C'est la question la plus importante à comprendre pour ne pas tout mélanger.

| Identifiant | Stockage | Stabilité | Visibilité client | Rôle |
|---|---|---|---|---|
| **`licensee_id`** | D1 worker, colonne `licenses.licensee_id` | Immuable (UUID v4 généré à la 1ère license du client) | Pas affichée, c'est notre clé interne | Identifie **le client** (l'entité qui paie). Un client peut avoir N licenses (achats successifs). |
| **`email`** | D1 worker, colonne `licenses.email` | **Muable** (le client peut changer d'email) | Visible (client la connaît, c'est elle qui reçoit les emails) | Contact + lookup pour login portail. Pas une identité stable. |
| **`stripe_customer_id`** | D1 worker, colonne `licenses.stripe_customer_id` | Immuable côté Stripe | Pas affichée (technique) | Pivot vers Stripe billing portal + factures. |
| **`license_key`** | D1 worker, colonne `licenses.license_key` (PK) | Immuable, format UUID-like (vérifié par `isValidKeyShape`) | **Affichée dans l'email + dans `/licensing` après activation** | Identifie **un achat / un abonnement**. Un client peut avoir N license_keys s'il a acheté plusieurs fois. |
| **`install_id`** | Agent FS `~/.threatclaw/licensing/install_id`, jamais en DB worker autrement que via les activations | Persistant tant que le FS du client est intact ; régénéré sur réinstall propre | **Pas encore affichée** (gap, voir #15) | Identifie **une instance d'agent** chez le client. |
| **`site_fingerprint`** | Calculé localement = `sha256(install_id)` | Dérivé d'`install_id` | Pas affichée | Identifie l'install dans le cert (côté worker). Hash plutôt que UUID brut → un peu de privacy. |
| **Activation** = ligne dans `D1.activations` | Liée à un `(license_key, install_id)` unique | Vit tant que le couple est valide ; recyclée si `last_heartbeat > 30j` | Liste affichée dans le portail | Représente "cette licence est active sur cet install à cette date". |

**Concrètement** :
- 1 client = 1 `licensee_id` + 1+ `email` + 1+ `license_key` + 1+ `stripe_customer_id`
- 1 license = 1 `license_key` + N activations (cap = `max_activations`)
- 1 activation = 1 `install_id` chez le client

**Pour répondre à la question "le client a un UUID qu'on a déjà ?"** : oui, deux fois en fait — `licensee_id` (notre interne) et `stripe_customer_id` (Stripe). Le `install_id` est par **install**, pas par client : un client peut légitimement en avoir plusieurs (test + prod, multi-site MSP, etc.). C'est pour ça que le cap est sur `max_activations`, pas sur "1 install par client".

---

## 13. UX customer — comment ne pas le perdre

Le risque avec le pipeline cert/activate/heartbeat/portal : c'est puissant, mais pour un RSSI qui regarde ça la première fois c'est opaque. Quatre principes UX :

1. **Un seul lien de portail à retenir** : `account.threatclaw.io`. Tout part de là (login email magic link).
2. **Le portail interne ≠ le portail Stripe**. Mais le client ne doit pas le sentir :
   - Notre portail affiche : licenses, activations, info de base.
   - Bouton "Manage subscription / Update payment / View invoices" → ouvre Stripe billing portal dans un onglet → client revient sur notre portail après.
   - Pas d'instructions techniques "allez sur Stripe.com" — juste un bouton qui ouvre.
3. **Cohérence install_id end-to-end**. Le client doit pouvoir matcher visuellement "ce serveur dans mon parc" et "cette ligne dans mon portail" :
   - Sur l'agent : afficher l'`install_id` (ou ses 8 premiers chars) dans `/licensing` ET dans une page `/about`. **Cette page n'existe pas encore.**
   - Sur le portail : afficher le même `install_id` (idéalement, et le hostname rapporté + last_heartbeat humain "il y a 2 jours").
4. **Email transactionnels propres** :
   - Welcome → license_key + lien `account.threatclaw.io` (PAS le cert lui-même)
   - Heartbeat-failed-7-days → email d'alerte au client : "On n'a plus de news de votre install X depuis 7j"
   - Plan-changed → confirmation après upgrade Stripe : "Votre Pro est actif, vos installs ont été refresh"
   - Subscription-canceled → "Votre HITL ne sera plus disponible après date X (fin du cert + grace)"

### Parcours typiques sans se perdre

**Premier achat** :
1. Marketing pricing.tsx → click "Starter mensuel"
2. Stripe checkout → paie
3. Email Brevo → "Bienvenue, voici votre license_key XXX, activez-le ici"
4. RSSI ouvre son ThreatClaw → `/licensing` → paste license_key → activé
5. (En parallèle) Email Brevo bonus : "Voici votre espace client `account.threatclaw.io`"

**Crash serveur, reinstall** :
1. RSSI réinstalle TC sur nouveau serveur → demande à activer la même license_key
2. Worker refuse 402 (slot prise par l'install morte)
3. RSSI clique "Manage my activations" sur la page `/licensing` → ouvre `account.threatclaw.io` (préfilé `email=...`)
4. Login magic link
5. Voit l'ancien install (last_heartbeat il y a 3 jours, marqué "stale") → click [Deactivate]
6. Retour sur le nouveau TC, retry activation → OK
7. **Total < 3 minutes, zéro contact support**

**Upgrade 200→250 assets** :
1. RSSI voit warning à 90 % cap dans `/billing` ThreatClaw : "Vous êtes à 180/200, considérez Pro"
2. Click "Upgrade plan" → ouvre `account.threatclaw.io`
3. Click "Manage subscription" → ouvre Stripe billing portal → choisit Pro → confirme
4. Stripe portal redirect retour sur notre portail
5. Notre portail affiche déjà "Plan : Pro · 500 assets · Mis à jour à l'instant" (webhook traité)
6. Click "Refresh now" sur la dashboard ThreatClaw → cert mis à jour immédiatement
7. **Total < 2 minutes**

---

## 14. Sécurité du portail — décisions et garde-fous

Le portail manipule des actions sensibles : afficher les license_keys, déactiver des installs (qui peut bloquer la production HITL d'un client), proxy vers Stripe. Tout doit être verrouillé.

### Authentification
| Décision | Raison |
|---|---|
| **Login passwordless via magic link** (pas de mot de passe) | Pas de gestion mots de passe = pas de surface compromise + pas de reset password = surface anti-phishing. Standard 2026 (Linear, Notion, etc.) |
| **Magic link** : HMAC-SHA256 signé avec `MAGIC_LINK_HMAC_SECRET` (32 bytes random) | Évite les liens forgés. Secret jamais hors du worker. |
| **Validité link 30 min** | Compromis utilisabilité / fenêtre d'attaque. Conforme aux pratiques sectorielles (Stripe = 24h trop, Linear = 1h, Notion = 1h). On reste plus serré → 30 min. |
| **Single-use** : le link consomme un nonce stocké en KV / D1, refusé si réutilisé | Empêche le replay si le link fuit (capture proxy, log d'email server compromis, screenshot). |
| **Rate limit demande de magic link** : 3/h par email + 10/h par IP (KV avec TTL) | Empêche la énumération d'emails et le spam. |
| **Pas de réponse différenciée** "email existe / pas" → toujours "Si cette adresse est connue, un lien a été envoyé" | Empêche l'énumération de clients. |

### Session après login
| Décision | Raison |
|---|---|
| Cookie session : `HttpOnly; Secure; SameSite=Strict; Path=/` + JWT signé | HttpOnly bloque XSS read. SameSite=Strict bloque CSRF. Strict OK car portail n'est jamais incrusté en iframe. |
| TTL session : **30 min idle / 4 h max** | Compromis confort / fenêtre. Token re-issuable via heartbeat passif (pas via magic link à chaque fois). |
| Rotation token à chaque privileged action (deactivate, change plan) | Anti-fixation / détection clones. |
| Logout explicit + auto-logout sur fermeture browser | Standard. |

### Autorisation
| Décision | Raison |
|---|---|
| Le JWT porte `licensee_id` + `session_id` | Sert de scope : on ne peut voir/modifier QUE ce qui appartient à `licensee_id`. |
| Tous les endpoints du portail vérifient `where licensee_id = jwt.licensee_id` côté D1 | Multi-tenant strict. Pas d'IDOR. |
| Tout endpoint d'écriture (deactivate, etc.) **enregistre dans D1.activations_audit** : `(licensee_id, action, target_id, ip, ua, ts)` | Trace d'audit complète. Sert pour le support si fraude suspectée. |

### Surface API
| Décision | Raison |
|---|---|
| `/api/portal/*` séparé de `/api/activate /api/heartbeat /api/deactivate` | Auth différente : portail = JWT, agent = license_key + install_id. Le portail appelle ses propres endpoints. Pas de mélange. |
| Endpoint `/api/portal/deactivate` ne prend **pas** de license_key en input — il prend un `activation_id` interne | Empêche de deactivate une activation qui n'appartient pas au client (le serveur résout `activation_id → licensee_id` et compare au JWT). |
| Stripe billing portal : URL générée à la demande, valide 5 min, single-use (Stripe gère) | Pas d'URL longue durée stockée. Standard Stripe. |

### Secrets et rotation
| Décision | Raison |
|---|---|
| Rotation `MAGIC_LINK_HMAC_SECRET` annuelle ou en cas de fuite suspectée | Best practice. Les liens en cours sont invalidés (acceptable, le client redemande). |
| **`SIGNING_PRIVKEY_HEX` Ed25519 NE TOURNE JAMAIS** par défaut | La rotation forcerait à recompiler tous les agents avec une nouvelle pubkey. Réservé au cas critique (fuite avérée). Procédure documentée séparément. |
| Stockage : tout secret via `wrangler secret put`, jamais en `wrangler.toml` ou repo | Standard Cloudflare. |
| `STRIPE_API_KEY` : utiliser une **restricted key** (pas une secret key admin), scope minimal (`billing_portal:write`, `customer:read`) | Limit blast radius si fuite. |

### Anti-abus / anti-piraterie portail
| Décision | Raison |
|---|---|
| Limit deactivate : max 5/h par licensee_id | Empêche un attaquant qui a volé une session de "vider" toutes les activations en boucle pour racketter le client. |
| Email d'alerte au client à chaque deactivate **par le portail** : "Vous avez déactivé l'install X il y a 5 min. Si ce n'est pas vous, contactez-nous." | Detection / response sur compromise session. |
| Bouton "Sign out everywhere" dans le portail → invalide toutes les sessions du client | En cas de doute. |
| Audit log accessible au support pour investigation | Standard. |

### Privacy / RGPD
| Décision | Raison |
|---|---|
| `install_id` exposé dans le portail = UUID privé. Hostname et IP affichés dans le portail (utiles pour identifier les installs) → côté RGPD c'est du data du **client**, pas d'un tiers, donc pas de problème. | RSSI a le droit de voir ses propres installs. |
| Pas de tracking analytics tiers sur le portail (Google Analytics, Plausible, etc.) | Le portail manipule des secrets. Aucun tracker tiers. |
| Logs Cloudflare Workers : 30j max, jamais d'email ni de license_key dans les logs | Anti-leak. |
| RGPD article 33 / NIS2 art. 21 : si compromise du portail, on notifie sous 72h | Procédure incident à formaliser, mais le portail est conçu pour minimiser la surface. |

### Threat model résumé
| Threat | Mitigation |
|---|---|
| Vol de cookie session | HttpOnly + Secure + SameSite=Strict + TTL court + rotation sur action sensible |
| Phishing email magic link | Domain `threatclaw.io` strict, SPF/DKIM/DMARC `p=reject`, content email signé en visuel (CSS spécifique, signature visuelle) |
| Énumération emails | Pas de différenciation réponse + rate limit |
| Vol DB D1 (Cloudflare hack) | License keys hashées en D1 (à valider — actuellement stockées en clair) |
| Vol `SIGNING_PRIVKEY_HEX` | Si avéré : rotation nucléaire (recompile + push agent + révocation tous certs). Procédure à formaliser. |
| Compromise compte support manuel | Audit trail accessible, séparation : ops dev N'A PAS accès direct D1, passe par scripts auditables |
| Replay de magic link | Single-use via nonce KV |
| CSRF sur deactivate | SameSite=Strict + token CSRF dans le form |
| IDOR (lire les activations d'un autre client) | Filtrage `licensee_id = jwt.licensee_id` côté D1 sur tous les endpoints |
| DoS sur magic link request | Rate limit + KV throttling |

---

## 15. Décision UX : fusion `/licensing` + `/setup?tab=about`

**État actuel** (vu sur staging 2026-04-29) :
- `/setup?tab=about` (sous-tab Config → À propos) : Instance ID, Version, Licence cœur, "Licences premium → 1 active(s)" qui linke vers /licensing, Mon compte, Bouton support
- `/licensing` : 416 lignes Action Pack (essai 60j, Action Pack copy, etc.)

**Problème** : deux endroits qui parlent de la même chose (licence + instance), copy obsolète, friction RSSI.

**Décision** : **fusionner en une seule page canonique**, accessible depuis Config → "License & Instance" (ou "Compte & Licence", à arbitrer côté wording). `/licensing` redirige sur le nouvel emplacement, `tab=about` redirige aussi.

### Structure de la page unifiée

```
┌─────────────────────────────────────────────────────────────────────┐
│  License & Instance                                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ── CETTE INSTALLATION ───────────────────────────────────────────  │
│  Instance ID    tc-d49c18eb-a967-f0bc-b6cc4e16  [Copier]            │
│  Version        v1.0.15-beta · build abc123                          │
│  Hostname       case.threatclaw.local                                │
│  Dernier sync   il y a 2 min · auto-refresh 7j                       │
│                                                                      │
│  ── PLAN ACTUEL ──────────────────────────────────────────────────  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  STARTER                                                      │  │
│  │  ▓▓▓▓▓▓▓▓▓░░ 180 / 200 assets surveillés (90 %)               │  │
│  │  Renouvellement 2027-04-15 · mensuel                          │  │
│  │  License key : ABCD-EFGH-...-WXYZ  [Copier]                   │  │
│  │  [Refresh now]  [Manage subscription ↗]  [Manage activations ↗]│  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ⚠ Vous êtes à 90 % du cap. Considérez Pro (500 assets).           │
│                                                                      │
│  ── PAS ENCORE DE LICENCE ? (visible si aucune license active) ──   │
│  Achetez votre plan sur threatclaw.io/pricing puis collez la clé :  │
│  [____________________________________________________]  [Activer]  │
│                                                                      │
│  ── INSTALL AIR-GAPPED ? ────────────────────────────────  [▼]    │
│  (replié par défaut, pour les setups sans Internet sortant)         │
│  Collez votre certificat Ed25519 ici pour mise à jour manuelle :    │
│  [____________________________________________________]  [Apply]    │
│                                                                      │
│  ── MON COMPTE ────────────────────────────────────────────────────│
│  Email  rssi@example.com                                             │
│  Password [Change]                                                   │
│                                                                      │
│  ── SUPPORT ───────────────────────────────────────────────────────│
│  [Ouvrir un ticket support] (préfille Instance ID + License key)    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Avantages de la fusion
- Un seul endroit où tout converge (licence + instance + portail + support).
- Cohérence avec le portail web `account.threatclaw.io` qui montrera la même info côté server-side.
- Plus de copy obsolète "Action Pack / 60j d'essai" qui survit.
- L'info Instance ID est **directement à côté** de la jauge assets et des license keys → pas de chasse au trésor pour le RSSI.

### Mécanique
- Renommage côté URL : la nouvelle page vit à `/setup?tab=license` (singulier, pas "licenses") ou bien on en fait une **top-level page** `/license`. Mon vote : **`/license` top-level** parce que c'est consulté souvent et a sa place dans le menu sidebar principal.
- `/licensing` (legacy) → 301 redirect vers `/license`
- `/setup?tab=about` → redirect vers `/license`
- L'onglet "About" du sidebar config disparaît
- L'entrée "License" prend sa place dans le menu sidebar

### Côté tier-changement / upgrade flow
- "Refresh now" → POST `/api/tc/licensing/heartbeat`
- "Manage subscription" → POST `/api/tc/licensing/portal-session` → URL Stripe billing portal → ouvre dans nouvel onglet
- "Manage activations" → ouvre `account.threatclaw.io?email=<auto-fill>` dans nouvel onglet
- Les trois boutons sont visibles tant qu'il y a au moins une license active

### Côté portail web `account.threatclaw.io`
Même Instance ID affiché (`tc-d49c18eb...`), mêmes 8 premiers chars en mono → matching visuel "cette install" parfait.

---

## 15bis. Hors scope de ce sprint

Choses qu'on **ne fera pas** maintenant pour rester focused :

- Pricing Pro/MSP différent du Business ~990€ (PREMIUM_PIPELINE.md §8 ancien). Le tier Enterprise/MSP est sur devis pour l'instant.
- Implémenter les actions HITL en stub (`velociraptor_quarantine_endpoint`, `kill_process`, `isolate_host`, `opnsense_kill_states`, `quarantine_mac`, `fortinet_block_ip`, `fortinet_block_url`, `ad_reset_password`). Ne bloque pas le pricing — on a déjà `block_ip pf/opnsense`, `disable_account AD` qui couvrent les use cases de base.
- Filter-repo / force-push GitHub pour purger l'historique de la fuite des anciens docs (décidé option A le 29/04).

---

## 16. État au 2026-04-29 — milieu de journée

> Snapshot historique. Pour l'état final, voir section 20.

- v1.0.15-beta déployé sur CASE staging avec succès (post-fix `$HOME` du deploy-staging.sh).
- Pricing pivot LIVE côté Stripe + worker + site marketing.
- Pricing pivot **NOT YET LIVE** côté Dashboard `/licensing` UI (encore en Action Pack copy).
- Portail client `account.threatclaw.io` : **dans le scope du sprint, à construire**.
- Décision UX : fusion `/licensing` + `/setup?tab=about` en `/license` unifiée (voir §15).
- Sécurité portail : tous les garde-fous décidés et listés (magic link single-use, rate limit, audit log, IDOR-safe, restricted Stripe key, etc. — voir §14).
- Identités clarifiées : `licensee_id` (notre interne), `email` (contact), `stripe_customer_id` (Stripe), `license_key` (par achat), `install_id` (par install). Voir §12bis.
- Plan validé en 11 étapes ordonnées (§9), démarrage par #1 audit worker reco-only.

---

## 17. Télémétrie anonyme — visibilité sur les installs

Sprint 7 du 2026-04-29 (après-midi). Avant ça on ne voyait QUE les
installs payants (3 dans D1) parce que le heartbeat existant est gaté
sur un cert. Les installs free (50 assets, AGPL) étaient totalement
invisibles. Les téléchargements `get.threatclaw.io` ne disaient pas
si le script avait vraiment tourné ou si c'était un bot qui scrape.

### Ce qu'on collecte

| Champ | Exemple | Pourquoi |
|---|---|---|
| `install_id` | `abc123-…` | UUID local, déjà utilisé pour les activations licenses. Pas une PII. |
| `version` | `1.0.16-beta` | Distribution versions, qui doit upgrade. |
| `tier` | `free` / `starter` / `pro` / ... | Mix free vs payant. |
| `asset_count` | nombre exact, **bucketé serveur-side** en `0-50` / `51-200` / `201-500` / `501-1500` / `1500+` | Exact jamais persisté (privacy + utilité nulle pour la stat agrégée). |
| Country | ISO alpha-2 (`FR`) | Dérivé de `CF-IPCountry`, l'IP elle-même est jetée. |

### Ce qu'on ne collecte PAS

- Pas d'email, hostname, nom d'org, IP, path sur disque
- Pas de tracking comportemental (clics, features utilisées, alerts triées)
- Pas de contenu sécurité (alerts, findings, incidents, logs)
- Pas de license_key (channel séparé du licensing)

### Comment opt-out

Variable d'env dans le `.env` du client :

```
TC_TELEMETRY_DISABLED=1
```

Restart agent → plus aucun ping. Pas de retry, pas d'effet sur les
autres fonctionnalités (licensing, scan, alerts).

### Côté worker

- Endpoint : `POST /api/heartbeat-anonymous` (pas d'auth, c'est public)
- Validation : install_id en UUID v4, version 1-32 chars, tier dans la whitelist
- Bucketing serveur-side de l'asset_count
- UPSERT D1.anonymous_pings (install_id PK, version, tier, asset_bucket, country, first_seen, last_seen)
- Country résolu via `CF-IPCountry` au runtime, IP jetée

### Côté agent

- Module `src/licensing/telemetry.rs` (~140 lignes)
- Background tokio task spawné depuis `main.rs` à côté du heartbeat licensé
- Boot delay 180s (jitter anti-stampede), puis loop 7 jours
- Best-effort : erreurs réseau loguées en debug, jamais bubble up
- Asset count via `agent::billing::count_billable_assets`

### Doc publique

`docs/telemetry.md` — version brand-level pour audit RSSI / GDPR. Le
checker `scripts/check-public-docs.sh` allow-list `TC_TELEMETRY_DISABLED`
sur ce fichier (env var documenté volontairement publiquement).

---

## 18. Installer get.threatclaw.io — détection bot vs humain

Sprint 7b. La question "qui télécharge et qui est un bot" n'avait
aucune réponse propre. Cloudflare Analytics donne le total brut
(bots inclus) et perd les données après 30j.

### Solution

Le worker `get-threatclaw` legacy (proxy GitHub raw) a été supprimé et
sa route `get.threatclaw.io` migrée sur le worker `threatclaw-license`
(le même qui sert license + account). Donc :

- 1 worker = 3 hostnames
- Chaque hit sur `get.threatclaw.io/*` est loggé en D1 avec son UA
- L'admin dashboard lit directement de D1 (pas d'appel API à la sortie)

### Routes servies

| Path | Sert |
|---|---|
| `/` ou `/install` | `installer/install.sh` (Linux/macOS core) |
| `/agent` ou `/agent/linux` ou `/agent/macos` | `installer/install-agent.sh` |
| `/agent/windows` ou `/windows` | `installer/install-agent.ps1` |

Source : `raw.githubusercontent.com/threatclaw/threatclaw/main/installer/*`. Cache CF 5 min.

### D1 — `installer_downloads`

Une row par requête : `id, path, ua_class, ua_raw (200 chars max), country, occurred_at`.

### Classification UA (5 buckets)

| Bucket | Match | Verdict |
|---|---|---|
| `curl_or_wget` | `curl/*`, `wget/*`, `fetch/*` | install légitime Linux/macOS |
| `powershell` | `PowerShell/*`, `WindowsPowerShell/*` | install légitime Windows |
| `browser` | `Mozilla/*`, `Chrome/*`, `Firefox/*`, `Safari/*` | suspect (humain ne curl pas un .sh dans un browser) |
| `http_lib` | `python-requests/*`, `Go-http-client/*`, `Java/*`, `node-fetch/*`, `axios/*`, `aiohttp/*` | bot |
| `empty_or_other` | UA absente ou non reconnue | inconnu |

Les buckets sont calculés au moment du log (pas en query) → admin
dashboard fait du `GROUP BY ua_class`, pas de regex.

### Conversion bot vs humain

L'admin dashboard expose **3 chiffres juxtaposés** :

1. **Total downloads** (24h / 7d / 30d) — brut, tout UA confondu
2. **Real installs** (= `COUNT(*) FROM anonymous_pings WHERE first_seen >= cutoff`) — un bot scrape mais ne lance pas, donc n'apparaît jamais ici
3. **Ratio "real / total"** — direct bot-share signal

Si tu vois `5 downloads / 0 ping` un jour → tout bot. Si `120 / 38` →
~32% réels (industrie : 30-60% pour un one-liner sain).

---

## 19. Admin dashboard `account.threatclaw.io/admin`

Sprint 7c. La page opérateur qui agrège tout.

### Auth

- **Pas de login séparé** : reuse du magic-link customer portal
- Le user se logue normalement sur `/`, JWT cookie posé
- En allant sur `/admin`, le worker check : `email IN ADMIN_EMAILS` ?
  - Oui → admin view
  - Non (mais authentifié) → page "admin access required" + lien vers le portail
  - Pas de session → redirect login

### Whitelist d'admin

Secret worker `ADMIN_EMAILS` (CSV, lower-case à la comparaison).

État au 2026-04-29 fin de journée :
```
ADMIN_EMAILS = "contact@cyberconsulting.fr,yvann@outlook.fr"
```

Pour ajouter un admin :
```bash
cd /srv/threatclaw-premium/worker
export CLOUDFLARE_API_TOKEN=...
echo "contact@cyberconsulting.fr,yvann@outlook.fr,nouveau@example.com" | \
  npx wrangler@4 secret put ADMIN_EMAILS
```

(Pas de redéploiement nécessaire — la lecture est runtime.)

### Endpoints API admin

| Endpoint | Rôle |
|---|---|
| `GET /api/admin/me` | Renvoie `{email, is_admin: true}` ou 403 |
| `GET /api/admin/stats` | Payload complet du dashboard (anonymous + installer + licenses + recent_licenses) |
| `POST /api/admin/refresh-session` | Étend la session de 4h sans redo magic-link |

Tous gates sur `requireAdminSession()` qui vérifie cookie JWT + whitelist.

### Widgets affichés

1. **Active installs (14d)** : total / Free / Paid / Trial / nouveaux 7j / nouveaux 30j
2. **Licenses** : active / past_due / cancelled / activations payées
3. **Installer downloads — bot vs human** : 24h / 7d / 30d total + "real installs" first-seen + ratio "% real" + breakdown UA classes 7d
4. **Version distribution top 10** : barres horizontales
5. **Country distribution top 15** : barres horizontales
6. **Recent licenses** : 10 dernières (email, tier, status, created)

### Auto-refresh

60 secondes (frontend `setInterval`). Anti-rafraîchissement plus
agressif : si tu veux du temps réel, tu peux appeler manuellement
`/api/admin/stats` plus souvent — le D1 query est sub-50ms.

### Sécurité

- Cookie session `tc_portal_session` HS256 JWT, HttpOnly + Secure + SameSite=Strict
- IDOR-safe : tous les endpoints filtrent côté DB
- Pas d'analytics tiers (pas de Google Analytics / Plausible / etc. sur le portail)
- CSP strict : `default-src 'none'; script-src 'self' 'unsafe-inline'; ...`
- Frame-ancestors 'none' → pas d'embedding possible
- Logs Cloudflare 30j max, jamais d'email ni license_key dedans

---

## 20. État final 2026-04-29 (15h00)

> C'est le snapshot de référence. Si tu rouvres une session 3 mois plus
> tard, lis ça en premier.

### Ce qui est LIVE

| Composant | URL / endroit | Statut |
|---|---|---|
| **Marketing pricing** | https://threatclaw.io/fr/pricing | ✅ 4 cartes, 6 Stripe Payment Links, FR/EN/DE/ES |
| **Stripe LIVE** | dashboard.stripe.com | ✅ 6 SKUs (Starter/Pro/Business × monthly/yearly) |
| **Worker (1 deploy, 3 hostnames)** | Cloudflare | ✅ |
| ↳ `license.threatclaw.io` | API agent | activate, heartbeat, deactivate, portal-session, check-revocation, **heartbeat-anonymous**, /webhook/stripe |
| ↳ `account.threatclaw.io` | UI portail client + admin | `/`, `/auth`, `/admin`, `/api/portal/*`, `/api/admin/*` |
| ↳ `get.threatclaw.io` | One-liner installer + log | `/`, `/install`, `/agent`, `/agent/linux`, `/agent/macos`, `/agent/windows`, `/windows` |
| **D1 schema** | `threatclaw-licenses` | 5 migrations (0001-0005) appliquées |
| **TC core (agent)** | DEV + CASE staging | v1.0.15-beta + commits du 2026-04-29 |
| **Dashboard `/license`** | dans l'agent | ✅ page unifiée (instance + plan + activate + air-gap + account + support) |
| **Portail client** | account.threatclaw.io/ | ✅ login magic-link, FR/EN, list activations, deactivate, Stripe billing portal |
| **Admin dashboard** | account.threatclaw.io/admin | ✅ ADMIN_EMAILS whitelist, KPIs installs + licenses + downloads + UA breakdown |

### D1 — vue d'ensemble des tables

| Table | Migration | Rôle |
|---|---|---|
| `licenses` | 0001 + 0002 (pivot) | 1 row par achat Stripe (license_key, licensee_id, email, tier, expires, assets_limit, ...) |
| `activations` | 0001 | (license_key, install_id) avec last_seen, recyclé après 30j stale |
| `revocations` | 0001 | License keys révoquées manuellement |
| `trial_attempts` | 0001 | Anti-abuse essais |
| `magic_links` | 0001 + 0003 | Single-use 30 min pour le login portail |
| `magic_link_rate_limit` | 0003 | Sliding window pour bloquer le spam de magic links |
| `portal_audit` | 0003 | Log immuable de toutes les actions portail (login, deactivate, logout-everywhere) |
| `anonymous_pings` | 0004 | Telemetry installs (install_id, version, tier, asset_bucket, country, first_seen, last_seen) |
| `installer_downloads` | 0005 | 1 row par hit get.threatclaw.io (path, ua_class, ua_raw, country, occurred_at) |

### Secrets côté worker

Tous via `npx wrangler@4 secret put <name>` :

- `SIGNING_PRIVKEY_HEX` — Ed25519 privée pour signer les certs (jamais rotater sauf fuite avérée)
- `STRIPE_WEBHOOK_SECRET` — vérif signature webhooks Stripe
- `STRIPE_API_KEY` — appels API Stripe (billing portal, lookup price)
- `BREVO_API_KEY` — emails transactionnels
- `MAGIC_LINK_HMAC_SECRET` — signature magic links + JWT session portail
- `ADMIN_EMAILS` — CSV des admins autorisés sur `/admin` (lower-cased à la compare)

### Endpoints publiquement réachables

```
license.threatclaw.io/api/health             → {ok:true}
license.threatclaw.io/api/activate           → POST, agent activation
license.threatclaw.io/api/heartbeat          → POST, refresh cert 7j
license.threatclaw.io/api/deactivate         → POST, libère slot
license.threatclaw.io/api/portal-session     → POST, URL Stripe billing portal
license.threatclaw.io/api/heartbeat-anonymous → POST, télémétrie anonyme
license.threatclaw.io/api/check-revocation   → GET, check si license_key révoquée
license.threatclaw.io/webhook/stripe         → POST, webhook Stripe LIVE

account.threatclaw.io/                        → SPA portail client (login)
account.threatclaw.io/auth?token=…            → consume magic link
account.threatclaw.io/admin                   → SPA admin dashboard
account.threatclaw.io/api/portal/*            → 8 endpoints (login-request, login-redeem, logout, logout-everywhere, me, activations, deactivate, billing-portal)
account.threatclaw.io/api/admin/*             → 3 endpoints (me, stats, refresh-session)

get.threatclaw.io/                            → install.sh (Linux/macOS core)
get.threatclaw.io/install                     → idem
get.threatclaw.io/agent                       → install-agent.sh (Linux/macOS)
get.threatclaw.io/agent/linux                 → idem
get.threatclaw.io/agent/macos                 → idem
get.threatclaw.io/agent/windows               → install-agent.ps1
get.threatclaw.io/windows                     → idem
```

### Comment opérer

**Voir l'état des licenses** (admin dashboard ou direct D1) :
```bash
cd /srv/threatclaw-premium/worker
export CLOUDFLARE_API_TOKEN=cfut_...
npx wrangler@4 d1 execute threatclaw-licenses --remote \
  --command "SELECT email, tier, assets_limit, status FROM licenses"
```

**Voir les pings télémétrie** :
```bash
npx wrangler@4 d1 execute threatclaw-licenses --remote \
  --command "SELECT tier, COUNT(*) FROM anonymous_pings WHERE last_seen >= strftime('%s', 'now', '-14 days') GROUP BY tier"
```

**Voir les downloads installer** (avec bot/human breakdown) :
```bash
npx wrangler@4 d1 execute threatclaw-licenses --remote \
  --command "SELECT ua_class, COUNT(*) FROM installer_downloads WHERE occurred_at >= strftime('%s','now','-7 days') GROUP BY ua_class"
```

**Révoquer une license en cas de fraude** :
```bash
npx wrangler@4 d1 execute threatclaw-licenses --remote \
  --command "INSERT INTO revocations (license_key, revoked_at, reason) VALUES ('TC-XXXX-...', strftime('%s','now'), 'fraud refund')"
```

**Mettre à jour la whitelist admin** :
```bash
echo "contact@cyberconsulting.fr,yvann@outlook.fr,nouveau@example.com" | \
  npx wrangler@4 secret put ADMIN_EMAILS
```

**Diagnostic en cas de pépin paiement** : voir section 10.

**Diagnostic en cas de pépin portail** :
1. Cloudflare Workers logs : `cd /srv/threatclaw-premium/worker && npx wrangler@4 tail`
2. D1 portal_audit : `SELECT * FROM portal_audit ORDER BY occurred_at DESC LIMIT 20`
3. Brevo dashboard : transactional → magic link / portal-deactivation events

### Reste à faire (post-pivot)

- ⏳ **Test e2e LIVE** avec carte réelle (Starter→Pro→refund) pour valider Stripe portal end-to-end
- ⏳ **Email de communication** aux 3 clients legacy avec lien `account.threatclaw.io`
- ⏳ **CHANGELOG agent v1.0.16-beta + tag** pour graver le pivot complet (pivot pricing + portail + télémétrie + admin)
- ⏳ **Smoke test air-gap path** : valider que la textarea sur `/license` accepte un cert pré-issued (l'endpoint actuel attend une license_key, pas un cert ; à adapter ou créer `/api/tc/licensing/install-cert`)

### Fix bug bonus livré aujourd'hui

`deploy/deploy-staging.sh` avait un bug récurrent : `--force-recreate`
laissait des `docker-proxy` zombies qui squattent le port 514, ce qui
empêche fluent-bit de redémarrer. Fix : pre-kick `docker compose stop +
rm -f fluent-bit` + reap des PIDs sur 514 avant la recreate. Plus
jamais besoin de nettoyage manuel post-deploy.

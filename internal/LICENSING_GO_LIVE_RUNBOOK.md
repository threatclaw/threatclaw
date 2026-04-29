# Licensing pivot — runbook go-live

Étapes à dérouler pour basculer en production le code livré le
2026-04-29 (commit agent `65f5234`, commit worker `1eba2a5`).

Tout le code est commité et poussé. Il reste 4 étapes côté opérateur
parce qu'elles requièrent des credentials Cloudflare / Stripe que la
session Claude n'a pas en environnement.

---

## 1. Migration D1 (worker)

Deux migrations à appliquer sur le D1 LIVE :

```bash
cd /srv/threatclaw-premium/worker
export CLOUDFLARE_API_TOKEN=...   # ton token CF avec scope "Workers + D1"
npx wrangler@4 d1 migrations apply threatclaw-licenses --remote
```

Doit afficher :
```
✅ 0002_pricing_pivot.sql
✅ 0003_portal_audit.sql
```

**Vérification** :
```bash
npx wrangler@4 d1 execute threatclaw-licenses --remote \
  --command "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
```
Doit lister : `activations`, `licenses`, `magic_link_rate_limit`,
`magic_links`, `portal_audit`, `revocations`, `trial_attempts`.

Et :
```bash
npx wrangler@4 d1 execute threatclaw-licenses --remote \
  --command "SELECT license_key, tier, assets_limit FROM licenses ORDER BY created_at DESC LIMIT 5"
```
Doit montrer `assets_limit` rempli (200 pour Action Pack legacy).

---

## 2. Deploy worker

```bash
cd /srv/threatclaw-premium/worker
npx wrangler@4 deploy
```

La sortie doit lister :
- `license.threatclaw.io` (déjà existant)
- `account.threatclaw.io` (nouveau custom domain — Cloudflare provisionne le DNS + cert TLS automatiquement)

**Vérification post-deploy** :
```bash
# 1. Le worker répond bien sur les deux hostnames
curl -s https://license.threatclaw.io/api/health
# → {"ok":true,"t":...}

curl -sI https://account.threatclaw.io/
# → HTTP/2 200 / content-type: text/html
```

Ouvre `https://account.threatclaw.io/` dans un navigateur :
- Page de login s'affiche
- Entre ton email
- Vérifie que tu reçois le magic link sur Brevo (dashboard Brevo → Transactional → Activity)
- Click le lien, tu arrives sur le dashboard

---

## 3. Smoke test e2e Stripe

Trois scénarios à valider (tu peux tester en TEST mode si tu veux pas brûler du LIVE) :

### A. Premier achat
1. Va sur `https://threatclaw.io/fr/pricing`
2. Click "Starter mensuel" (ou n'importe quel tier)
3. Paie avec une carte (test : `4242 4242 4242 4242` en TEST mode)
4. Reçois l'email avec ta `license_key`
5. Sur ton instance ThreatClaw, va sur `/license`
6. Colle la `license_key`, clique "Activer"
7. Vérifie que le tier + cap assets correct s'affiche

### B. Upgrade plan
1. Sur ton ThreatClaw, va sur `/license`
2. Click "Manage subscription" → ouvre Stripe billing portal dans un nouvel onglet
3. Click "Update plan" → choisis Pro
4. Confirme, Stripe gère le prorata
5. Reviens sur `/license`, click "Refresh now"
6. Le tier passe à Pro, cap à 600 (ou whatever assets_limit fixé sur le produit Stripe)

### C. Crash + reinstall
1. Note ton `install_id` actuel (visible sur `/license` → Cette installation)
2. Va sur `https://account.threatclaw.io/`
3. Login via magic link
4. Vois ton install dans "Mes installations"
5. Click "Désactiver" sur cette ligne → email d'alerte arrive
6. Réinstalle ThreatClaw sur un nouveau serveur
7. Le nouveau serveur peut activer la même `license_key` immédiatement

---

## 4. Communication clients existants

À envoyer une fois les 3 smoke tests OK :

**Subject** : `ThreatClaw — Nouveau modèle tarifaire et espace client en self-service`

**Corps** :
> Bonjour,
>
> Nous avons fait évoluer ThreatClaw sur deux points :
>
> **Tarification** — la licence Action Pack (199 €/an) est remplacée par
> 4 paliers basés sur le nombre d'assets surveillés (Free 50, Starter 200,
> Pro 600, Business 1500), avec les actions HITL incluses partout. Votre
> licence existante a été automatiquement mappée sur Starter (200 assets,
> capacité plus large que ce que vous aviez avant). Aucune action requise
> de votre part.
>
> **Espace client** — vous pouvez désormais gérer votre abonnement et
> vos installations depuis `https://account.threatclaw.io/`. Connexion
> par email (lien magique, sans mot de passe). Vous y retrouvez :
> - vos plans + statut + facturation Stripe
> - la liste de vos installations actives + bouton "Désactiver" pour
>   libérer une slot après un crash de serveur
> - un bouton "Déconnecter partout" pour invalider toutes les sessions
>   actives en cas de doute sur une compromission
>
> La page `/license` de votre dashboard ThreatClaw a été simplifiée
> dans le même mouvement (fusion avec l'ancien onglet "À propos").
>
> Vos questions sur ces changements sont les bienvenues à
> contact@cyberconsulting.fr.
>
> — L'équipe ThreatClaw

Liste de destinataires à extraire :
```bash
cd /srv/threatclaw-premium/worker
export CLOUDFLARE_API_TOKEN=...
npx wrangler@4 d1 execute threatclaw-licenses --remote \
  --command "SELECT DISTINCT email FROM licenses WHERE status='active'"
```

---

## 5. Rollback (si quelque chose casse)

Si l'un des trois smoke tests rate :

**Côté worker** :
```bash
cd /srv/threatclaw-premium/worker
git log --oneline | head -5     # repère le commit avant 1eba2a5
git checkout <commit-précédent>
npx wrangler@4 deploy             # redéploie l'ancienne version
git checkout main                 # reviens au courant
```

**Côté D1** : les migrations ne se rollback pas trivialement. Si la
0002 a corrompu une row, restaurer depuis le backup automatique
Cloudflare D1 (point-in-time restore disponible 30 jours).

**Côté agent (CASE staging)** : si la nouvelle UI casse, redéploie
l'image précédente :
```bash
ssh claude@163.172.53.55 "sudo docker tag ghcr.io/threatclaw/dashboard:<ancienne-version> ghcr.io/threatclaw/dashboard:latest && cd /opt/threatclaw && sudo docker compose up -d threatclaw-dashboard"
```

---

## Checklist finale

- [ ] Migration D1 appliquée (étape 1)
- [ ] Worker déployé sur les deux hostnames (étape 2)
- [ ] DNS account.threatclaw.io résout vers Cloudflare
- [ ] Magic-link login fonctionne sur account.threatclaw.io
- [ ] Smoke test A (premier achat) OK
- [ ] Smoke test B (upgrade) OK
- [ ] Smoke test C (crash + deactivate via portail) OK
- [ ] Email comms envoyé aux clients existants
- [ ] CHANGELOG agent v1.0.16-beta créé pour graver le pivot complet

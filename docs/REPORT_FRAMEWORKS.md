# ThreatClaw — Référentiel des Rapports de Conformité

> Architecture multi-framework pour la génération automatique de rapports d'incident
> et de conformité. Mapping universel des champs obligatoires par framework.

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [NIS2 — Article 23 (Notification d'incidents)](#2-nis2--article-23)
3. [NIS2 — Article 21 (Mesures de gestion des risques)](#3-nis2--article-21)
4. [RGPD — Articles 33/34 (Violation de données)](#4-rgpd--articles-3334)
5. [NIST SP 800-61 Rev 3 (Incident Response)](#5-nist-sp-800-61-rev-3)
6. [ISO 27001:2022 — Annexe A.5.24-5.28](#6-iso-270012022)
7. [Mapping universel des champs](#7-mapping-universel)
8. [Schéma JSON universel ThreatClaw](#8-schéma-json-universel)
9. [Sources officielles](#9-sources-officielles)
10. [Stratégie d'implémentation](#10-stratégie-dimplémentation)

---

## 1. Vue d'ensemble

### Principe

ThreatClaw collecte les données d'incident en continu via ses sources (alertes, findings,
assets, IOCs, graph d'attaque). Ces données alimentent un **schéma JSON universel** qui
est ensuite projeté sur chaque framework réglementaire via les templates Typst.

```
PostgreSQL → JSON universel → Template Typst (par framework) → PDF
                                    ↑
                            Champs mappés par framework
```

### Frameworks couverts

| Framework | Juridiction | Obligatoire pour | Délais |
|-----------|-------------|------------------|--------|
| NIS2 Art. 23 | UE 27 États | Entités essentielles/importantes | 24h / 72h / 1 mois |
| NIS2 Art. 21 | UE 27 États | Entités essentielles/importantes | Continu |
| RGPD Art. 33/34 | UE + EEE | Tout responsable de traitement | 72h (CNIL/APD) |
| NIST CSF 2.0 / SP 800-61r3 | USA + international | Agences fédérales US, volontaire ailleurs | Variable |
| ISO 27001:2022 A.5.24-28 | International | Organisations certifiées | Selon politique interne |

### Transposition France (mars 2026)

- **Loi Résilience** : votée, promulgation Q1 2026
- **Décrets techniques ANSSI** : attendus Q2 2026
- **ReCyF** : publié par l'ANSSI le 17 mars 2026 — référentiel de conformité
- **MonEspaceNIS2** : plateforme de notification en ligne (monespacenis2.cyber.gouv.fr)
- **Pas de template PDF officiel ANSSI** à ce jour → opportunité pour ThreatClaw
- **Formulaire ANSSI OSE** (pré-NIS2) disponible : cyber.gouv.fr/sites/default/files/2022-10/formulaire-incidents-ose_anssi.pdf
- **Transmission chiffrée** requise (ACID cryptofiler ou Zed! recommandés par l'ANSSI)

### Double notification (NIS2 + RGPD)

Quand un incident implique **à la fois** une perturbation de service ET des données personnelles :
- **NIS2 → ANSSI/CERT-FR** : notification opérationnelle (24h/72h/1 mois)
- **RGPD → CNIL** : notification violation de données (72h)

Les deux sont obligatoires et indépendantes. ThreatClaw génère les deux rapports depuis le même JSON universel.

### Structure du formulaire ANSSI OSE (9 sections)

Le formulaire ANSSI pour les OSE (Opérateurs de Services Essentiels) donne la structure
la plus proche de ce que sera le formulaire NIS2 français :

| # | Section ANSSI | Correspondance NIS2 |
|---|--------------|---------------------|
| 1 | Identification de l'entité | Art.23 — entité notifiante |
| 2 | Description de l'incident | Art.23(4)(a) — nature |
| 3 | Systèmes affectés | Art.23(4)(d) — description |
| 4 | Évaluation de l'impact | Art.23(4)(b) — sévérité/impact |
| 5 | Type d'incident (taxonomie ANSSI) | Art.23(4)(a) — nature |
| 6 | Données techniques (IOCs, vecteurs) | Art.23(4)(b) — IoCs |
| 7 | Mesures prises | Art.23(4)(d) — atténuation |
| 8 | Chronologie | Art.23(4)(d) — description détaillée |
| 9 | Tiers impliqués | Art.23 — coordination |

---

## 2. NIS2 — Article 23

### Base légale

Directive (UE) 2022/2555, Article 23 — Obligations de notification aux CSIRT/autorités compétentes.

### Définition : "incident significatif" (Art. 23(3))

Un incident est significatif s'il :
- (a) a causé ou est susceptible de causer une **perturbation opérationnelle grave** des services ou une **perte financière** pour l'entité
- (b) a affecté ou est susceptible d'affecter d'autres personnes en causant un **dommage matériel ou moral considérable**

### 2.1 Early Warning — 24 heures (Art. 23(4)(a))

**Délai** : sans retard injustifié, au plus tard 24h après prise de connaissance.

| # | Champ | Obligatoire | Description |
|---|-------|-------------|-------------|
| 1 | Identification de l'entité | **OUI** | Dénomination, secteur NIS2, statut (essentielle/importante) |
| 2 | Contact sécurité | **OUI** | Nom, email, téléphone du point de contact |
| 3 | Date/heure de détection | **OUI** | Timestamp de première détection |
| 4 | Date/heure de notification | **OUI** | Timestamp de cette notification |
| 5 | Nature de l'incident | **OUI** | Type (ransomware, intrusion, DDoS, fuite, etc.) |
| 6 | Description initiale | **OUI** | Ce qui est connu à ce stade |
| 7 | Suspicion acte malveillant | **OUI** | Si l'incident est soupçonné d'être intentionnel |
| 8 | Impact transfrontalier | **OUI** | Si l'incident pourrait affecter d'autres États membres |
| 9 | Mesures immédiates | Recommandé | Actions de containment prises |

### 2.2 Rapport intermédiaire — 72 heures (Art. 23(4)(b))

**Délai** : au plus tard 72h après la notification initiale.

| # | Champ | Obligatoire | Description |
|---|-------|-------------|-------------|
| 1-9 | Champs Early Warning | **OUI** | Mis à jour si nécessaire |
| 10 | Évaluation initiale | **OUI** | Sévérité, périmètre, impact estimé |
| 11 | Cause probable | **OUI** | Vecteur d'attaque, hypothèses |
| 12 | IOCs identifiés | Recommandé | IPs, hashes, domaines, TTPs |
| 13 | Systèmes affectés | **OUI** | Liste détaillée des assets impactés |
| 14 | Services impactés | **OUI** | Services métier affectés |
| 15 | Statut actuel | **OUI** | En cours / contenu / résolu |
| 16 | Actions correctives | **OUI** | Mesures d'atténuation en cours |

### 2.3 Rapport final — 1 mois (Art. 23(4)(d-e))

**Délai** : au plus tard 1 mois après le rapport intermédiaire.

| # | Champ | Obligatoire | Description |
|---|-------|-------------|-------------|
| 1-16 | Champs précédents | **OUI** | Version finale |
| 17 | Description complète | **OUI** | Récit complet de l'incident |
| 18 | Timeline chronologique | **OUI** | Chronologie détaillée des événements |
| 19 | Cause racine (Root Cause) | **OUI** | Analyse forensique de la cause |
| 20 | TTPs MITRE ATT&CK | Recommandé | Tactiques/techniques identifiées |
| 21 | Impact total | **OUI** | Opérationnel, financier, données |
| 22 | Données exposées | **OUI** | Si données personnelles → lien RGPD Art.33 |
| 23 | Mesures correctives | **OUI** | Actions implémentées |
| 24 | Mesures préventives | **OUI** | Pour éviter la récurrence |
| 25 | Leçons apprises | Recommandé | Retour d'expérience |
| 26 | Conformité cycle notif. | **OUI** | Confirmation des 3 rapports envoyés dans les délais |
| 27 | Notification RGPD | Si applicable | Si données perso → Art.33 CNIL requis |

---

## 3. NIS2 — Article 21

### Base légale

Directive (UE) 2022/2555, Article 21 — Mesures de gestion des risques en matière de cybersécurité.

### Les 10 mesures obligatoires

| # | Mesure Art. 21 | Couverture ThreatClaw | Score |
|---|----------------|----------------------|-------|
| 1 | Politiques d'analyse des risques et de sécurité des SI | Engine + Config + Profils NACE | Variable |
| 2 | Gestion des incidents | Alertes + Intelligence Engine + Rapports NIS2 | Élevé |
| 3 | Continuité des activités et gestion de crise | Monitoring uptime + Backup | Partiel |
| 4 | Sécurité de la chaîne d'approvisionnement | Supply Chain Graph Analysis | Moyen |
| 5 | Sécurité dans l'acquisition, le développement et la maintenance des SI | Trivy + Semgrep scans | Partiel |
| 6 | Politiques et procédures d'évaluation de l'efficacité des mesures | Score sécurité + ML baselines | Élevé |
| 7 | Pratiques de base en matière d'hygiène cyber et formation | Lynis + Docker Bench audits | Moyen |
| 8 | Politiques et procédures relatives à l'utilisation de la cryptographie | SSL Labs + Observatory checks | Élevé |
| 9 | Sécurité des ressources humaines, politiques de contrôle d'accès | AD Audit + HIBP + Identity Graph | Partiel |
| 10 | Utilisation de solutions d'authentification multi-facteurs | Vérification MFA via AD | Variable |

### Référence ReCyF ANSSI (17 mars 2026)

Le ReCyF (Référentiel de Cybersécurité pour la France) publié par l'ANSSI le 17/03/2026
est le document de référence pour l'alignement des mesures Art. 21 en France.

---

## 4. RGPD — Articles 33/34

### Base légale

Règlement (UE) 2016/679, Articles 33 et 34.

### Article 33 — Notification à l'autorité de contrôle (CNIL)

**Délai** : 72h après prise de connaissance de la violation.
**Condition** : risque pour les droits et libertés des personnes.

| # | Champ | Obligatoire | Réf. Art.33(3) |
|---|-------|-------------|----------------|
| 1 | Nature de la violation | **OUI** | Art.33(3)(a) |
| 2 | Catégories de personnes | **OUI** | Art.33(3)(a) |
| 3 | Nombre approximatif de personnes | **OUI** | Art.33(3)(a) |
| 4 | Catégories de données | **OUI** | Art.33(3)(a) |
| 5 | Nombre approximatif d'enregistrements | **OUI** | Art.33(3)(a) |
| 6 | Nom et coordonnées du DPO | **OUI** | Art.33(3)(b) |
| 7 | Conséquences probables | **OUI** | Art.33(3)(c) |
| 8 | Mesures prises ou envisagées | **OUI** | Art.33(3)(d) |
| 9 | Mesures pour atténuer les effets | **OUI** | Art.33(3)(d) |

### Article 34 — Communication aux personnes concernées

**Condition** : risque élevé pour les droits et libertés.

| # | Champ | Obligatoire |
|---|-------|-------------|
| 1 | Description en termes clairs | **OUI** |
| 2 | Nom et coordonnées du DPO | **OUI** |
| 3 | Conséquences probables | **OUI** |
| 4 | Mesures prises ou envisagées | **OUI** |

### Formulaire officiel

- **France** : notifications.cnil.fr
- **UK** : ico.org.uk/for-organisations/report-a-breach
- **Belgique** : autoriteprotectiondonnees.be
- **Allemagne** : BfDI (par Land)

---

## 5. NIST SP 800-61 Rev 3

### Base légale

NIST Special Publication 800-61 Revision 3 (avril 2025) — *Incident Response Recommendations and Considerations for Cybersecurity Risk Management*.

Aligné sur le **NIST Cybersecurity Framework (CSF) 2.0** et ses 6 fonctions :
Govern / Identify / Protect / Detect / Respond / Recover.

### Champs de reporting recommandés

| # | Champ NIST | Fonction CSF 2.0 | Mapping NIS2 |
|---|-----------|------------------|--------------|
| 1 | Incident identifier | GV | Identifiant incident |
| 2 | Reporter/handler information | GV | Contact sécurité |
| 3 | Date/time reported | DE.AE-02 | Date détection |
| 4 | Date/time of incident | DE.AE-02 | Date détection |
| 5 | Current status | RS.MA-01 | Statut actuel |
| 6 | Incident category | DE.AE-04 | Nature incident |
| 7 | Source of the incident | DE.AE-03 | Vecteur attaque |
| 8 | Affected systems/assets | ID.AM-01 | Systèmes affectés |
| 9 | Actions taken | RS.MI-01 | Mesures immédiates |
| 10 | Impact assessment | RS.AN-02 | Impact estimé |
| 11 | Root cause | RS.AN-03 | Cause racine |
| 12 | Indicators of compromise | DE.AE-04 | IOCs |
| 13 | Evidence collected | RS.AN-04 | Preuves |
| 14 | Lessons learned | RC.RP-06 | Leçons apprises |
| 15 | Recommended actions | RC.RP-01 | Recommandations |

### Téléchargement

PDF gratuit : `nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf`

---

## 6. ISO 27001:2022

### Contrôles pertinents (Annexe A)

| Contrôle | Titre | Champs requis |
|----------|-------|---------------|
| A.5.24 | Information security incident management planning and preparation | Plan de réponse, rôles, procédures |
| A.5.25 | Assessment and decision on information security events | Critères de classification, sévérité, escalade |
| A.5.26 | Response to information security incidents | Actions de containment, éradication, recovery |
| A.5.27 | Learning from information security incidents | Post-mortem, cause racine, recommandations |
| A.5.28 | Collection of evidence | Préservation preuves, chaîne de custody, IOCs |
| A.6.8 | Information security event reporting | Procédure de signalement, canal, délai |

### Champs de reporting ISO

| # | Champ | Contrôle ISO | Mapping NIS2 |
|---|-------|-------------|--------------|
| 1 | Classification de l'événement | A.5.25 | Nature incident |
| 2 | Sévérité / priorité | A.5.25 | Sévérité |
| 3 | Timeline de l'incident | A.5.26 | Timeline |
| 4 | Actions de réponse | A.5.26 | Mesures correctives |
| 5 | Cause racine | A.5.27 | Cause racine |
| 6 | Améliorations identifiées | A.5.27 | Leçons apprises |
| 7 | Preuves collectées | A.5.28 | IOCs / forensique |
| 8 | Rapport d'incident | A.6.8 | Notification |

---

## 7. Mapping universel

### Matrice de correspondance des champs

Chaque champ universel ThreatClaw est mappé sur les références de chaque framework.

| Champ universel | NIS2 Art.23 | RGPD Art.33 | NIST 800-61 | ISO A.5.x |
|----------------|-------------|-------------|-------------|-----------|
| `org_name` | Identification entité | Responsable traitement | Reporter info | A.6.8 |
| `sector` | Secteur NIS2 | — | — | — |
| `security_contact` | Contact sécurité | DPO (Art.33(3)(b)) | Handler info | A.6.8 |
| `incident_id` | Référence interne | Référence CNIL | Incident ID | A.5.25 |
| `detected_at` | Date détection | Date prise connaissance | Date/time | A.5.25 |
| `notified_at` | Date notification | Date notification CNIL | Date reported | A.6.8 |
| `incident_type` | Nature (Art.23(4)(a)) | Nature violation (33(3)(a)) | Category | A.5.25 |
| `incident_description` | Description | Description | — | A.5.25 |
| `affected_assets` | Systèmes affectés | — | Affected systems | A.5.26 |
| `affected_services` | Services impactés | — | — | A.5.26 |
| `severity` | — | — | — | A.5.25 |
| `incident_status` | Statut | — | Current status | A.5.26 |
| `cross_border_impact` | Impact transfrontalier | — | — | — |
| `iocs` | — (recommandé) | — | Indicators | A.5.28 |
| `attack_vector` | Cause probable | — | Source | A.5.27 |
| `root_cause` | Cause racine (final) | — | Root cause | A.5.27 |
| `immediate_measures` | Mesures immédiates | Mesures prises (33(3)(d)) | Actions taken | A.5.26 |
| `corrective_measures` | Mesures correctives | — | — | A.5.26 |
| `lessons_learned` | Leçons apprises | — | Lessons learned | A.5.27 |
| `data_exposed` | — | Catégories données (33(3)(a)) | — | A.5.28 |
| `affected_persons_count` | — | Nombre personnes (33(3)(a)) | — | — |
| `dpo_contact` | — | Coordonnées DPO (33(3)(b)) | — | — |
| `consequences` | — | Conséquences (33(3)(c)) | Impact | — |
| `mitre_ttps` | — (recommandé) | — | — | A.5.28 |
| `timeline` | Timeline (final) | — | — | A.5.27 |
| `financial_impact` | Impact (final) | — | Impact | — |

### Légende

- **OUI** : champ explicitement requis par le texte légal
- **Recommandé** : recommandé par les guidelines (ENISA, ANSSI, etc.)
- **—** : non requis par ce framework

---

## 8. Schéma JSON universel

### Structure de données ThreatClaw

Toutes les données d'un incident sont stockées dans un seul JSON universel.
Le template Typst de chaque framework sélectionne les champs pertinents.

```json
{
  // ── Identification ──
  "org_name": "Acme Corp SAS",
  "sector": "Technologies de l'information",
  "sub_sector": "62.01 — Programmation informatique",
  "nis2_status": "Entité Essentielle",
  "security_contact": "Jean Dupont — RSSI",
  "contact_email": "rssi@acme.fr",
  "contact_phone": "+33 1 23 45 67 89",
  "dpo_contact": "Marie Martin — DPO",
  "dpo_email": "dpo@acme.fr",

  // ── Incident ──
  "notification_id": "TC-2026-0326-001",
  "incident_id": "TC-INC-20260326-001",
  "detected_at": "26/03/2026 02:17",
  "notified_at": "26/03/2026 14:32",
  "closure_date": "26/04/2026",
  "delay_hours": "12",
  "incident_type": "intrusion",
  "incident_type_label": "Accès non autorisé / Intrusion",
  "incident_description": "Tentatives de brute force SSH...",
  "incident_status": "contained",
  "severity": "high",

  // ── Impact ──
  "cross_border_impact": "no",
  "affected_assets": [
    {"name": "srv-web-01", "category": "Serveur", "criticality": "Critique", "ip": "192.168.1.10"}
  ],
  "affected_services": "Service web principal",
  "score": "51",
  "operational_impact": "Impact limité",
  "financial_impact": "Aucun",
  "data_exposed": "Aucune donnée personnelle",
  "affected_persons_count": "0",

  // ── Analyse technique ──
  "iocs": [
    {"type": "IPv4", "value": "185.220.101.34", "source": "ThreatClaw", "confidence": "High"}
  ],
  "attack_vector": "SSH brute force",
  "root_cause": "Mot de passe faible sur compte admin",
  "mitre_ttps": ["T1110 — Brute Force", "T1078 — Valid Accounts"],
  "probable_cause": "Exploitation de credentials faibles",

  // ── Actions ──
  "immediate_measures": ["IP bloquée", "Surveillance renforcée"],
  "corrective_measures": ["Rotation credentials", "MFA activé"],
  "lessons_learned": ["Renforcer politique MdP", "Activer MFA"],

  // ── Timeline ──
  "timeline": [
    {"time": "26/03 02:17", "phase": "Détection", "event": "Alertes SSH détectées"}
  ],

  // ── Conformité ──
  "notified_authority": "ANSSI / CSIRT-FR",
  "gdpr_notification_required": "no",
  "deadline_72h": "29/03/2026 14:32",
  "deadline_final": "26/04/2026",

  // ── Métadonnées rapport ──
  "generated_at_display": "26/03/2026 14:32",
  "alerts_count": "5",
  "findings_count": "3",
  "assets_count": "2"
}
```

---

## 9. Sources officielles

### Textes légaux (gratuits)

| Source | URL | Contenu |
|--------|-----|---------|
| NIS2 Directive complète | eur-lex.europa.eu/eli/dir/2022/2555 | Texte officiel complet |
| NIS2 Article 23 | nis-2-directive.com/NIS_2_Directive_Article_23 | Notification d'incidents |
| NIS2 Article 21 | nis-2-directive.com/NIS_2_Directive_Article_21 | Mesures de gestion risques |
| RGPD Article 33 | gdpr-info.eu/art-33-gdpr | Notification APD |
| RGPD Article 34 | gdpr-info.eu/art-34-gdpr | Communication personnes |
| NIST SP 800-61r3 | nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | Incident Response |
| NIST CSF 2.0 | nist.gov/cyberframework | Framework complet |

### Plateformes de notification

| Pays | Plateforme | URL |
|------|-----------|-----|
| France (NIS2) | MonEspaceNIS2 ANSSI | monespacenis2.cyber.gouv.fr |
| France (RGPD) | CNIL Notification | notifications.cnil.fr |
| UK (RGPD/UK GDPR) | ICO Breach Report | ico.org.uk/for-organisations/report-a-breach |
| Belgique | APD | autoriteprotectiondonnees.be |
| Allemagne | BfDI | bfdi.bund.de |

### Référentiels nationaux

| Pays | Référentiel | Date | Description |
|------|-------------|------|-------------|
| France | ReCyF ANSSI | 17/03/2026 | Référentiel de cybersécurité pour la France |
| UK | NCSC CAF | En cours | Cyber Assessment Framework — 14 principes |
| Australie | ASD Essential Eight | Actif | 8 stratégies d'atténuation, 4 niveaux maturité |

---

## 10. Stratégie d'implémentation

### Architecture actuelle (v2.0)

```
templates/
  common.typ                  ← Styles partagés (brand ThreatClaw)
  nis2-early-warning.typ      ← Art. 23(4)(a) — 24h
  nis2-intermediate.typ       ← Art. 23(4)(b) — 72h
  nis2-final.typ              ← Art. 23(4)(d-e) — 1 mois
  nis2-article21.typ          ← Art. 21 — 10 mesures
  executive-report.typ        ← Direction / COMEX
  technical-report.typ        ← RSSI détaillé
  audit-trail.typ             ← Journal d'audit
```

### Templates à ajouter (roadmap)

| Template | Framework | Priorité |
|----------|-----------|----------|
| `gdpr-article33.typ` | RGPD Art.33 | Haute — si données perso |
| `gdpr-article34.typ` | RGPD Art.34 | Haute — si risque élevé |
| `nist-incident.typ` | NIST SP 800-61r3 | Moyenne — marché US |
| `iso27001-incident.typ` | ISO 27001 A.5.24-28 | Moyenne — clients certifiés |

### Flux de génération

1. **Incident déclaré** → ThreatClaw Engine crée un incident dans PostgreSQL
2. **Données collectées** → alertes, findings, assets, IOCs enrichis automatiquement
3. **JSON universel construit** → le handler Rust agrège les données en un JSON unique
4. **Template sélectionné** → selon le type de rapport demandé
5. **Typst compile** → JSON → Typst → PDF (zéro réseau, zéro dépendance)
6. **PDF téléchargé** → via le dashboard, bouton dans la page Exports

### Argument commercial

> "Les rapports ThreatClaw sont alignés sur le texte légal de la Directive NIS2
> (UE 2022/2555), le ReCyF publié par l'ANSSI le 17 mars 2026, et le NIST
> SP 800-61 Rev 3. Chaque champ obligatoire est tracé jusqu'à sa référence
> légale. Le tout est généré automatiquement, sans intervention humaine,
> en moins de 2 secondes."

---

*Document généré le 26/03/2026 — ThreatClaw v2.0*
*Sources : Directive NIS2 (UE 2022/2555), RGPD (UE 2016/679), NIST SP 800-61r3, ISO 27001:2022*

// ThreatClaw — Rapport NIS2 Final (1 mois)
// Conforme Article 23(4)(d-e), Directive NIS2 (UE 2022/2555)
// Champs obligatoires : description complète, cause racine, mesures, impact, leçons

#import "common.typ": *

#let data = json("data.json")

#set page(paper: "a4", margin: (top: 18mm, bottom: 20mm, left: 15mm, right: 15mm))
#set text(font: "Noto Sans", size: 10pt)

// ── En-tête ──
#grid(
  columns: (1fr, auto),
  align: (left, right),
  [
    #text(size: 22pt, weight: "bold", fill: tc-red, tracking: 0.1em)[THREATCLAW]
    #v(2pt)
    #text(size: 8pt, fill: tc-gray)[Agent de cybersécurité autonome]
  ],
  [
    #text(size: 12pt, weight: "bold", fill: tc-dark)[#data.at("org_name", default: "Organisation")]
    #v(2pt)
    #text(size: 9pt, fill: tc-gray)[#data.at("generated_at_display", default: datetime.today().display("[day]/[month]/[year]"))]
  ],
)
#v(6pt)
#line(length: 100%, stroke: 2pt + tc-red)
#v(8pt)

#text(size: 16pt, weight: "bold", fill: tc-red)[RAPPORT FINAL D'INCIDENT]
#v(2pt)
#text(size: 10pt, fill: tc-gray)[Article 23(4)(d-e), Directive NIS2 (UE) 2022/2555]
#v(8pt)

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*N° de notification*], text(font: "Noto Sans Mono", size: 9pt)[#data.at("notification_id", default: "TC-2026-0001")],
  [*Réf. Early Warning*], text(font: "Noto Sans Mono", size: 9pt)[#data.at("early_warning_ref", default: "—")],
  [*Date de génération*], data.at("generated_at_display", default: "—"),
  [*Version*], [1.0 — Rapport final],
)

// ── 1. Synthèse de l'incident ──
#tc-section("1. Synthèse de l'incident")

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Organisation*], data.at("org_name", default: "—"),
  [*Secteur NIS2*], data.at("sector", default: "—"),
  [*Identifiant incident*], text(font: "Noto Sans Mono")[#data.at("incident_id", default: "—")],
  [*Type d'incident*], data.at("incident_type_label", default: "—"),
  [*Date de détection*], data.at("detected_at", default: "—"),
  [*Date de clôture*], data.at("closure_date", default: "—"),
  [*Durée totale*], data.at("incident_duration", default: "—"),
  [*Sévérité finale*], data.at("final_severity", default: "—"),
  [*Score sécurité final*], [#data.at("score", default: "100") / 100],
)

// ── 2. Description complète ──
#tc-section("2. Description complète de l'incident")

#data.at("full_description", default: "L'incident a été détecté par ThreatClaw Engine. L'analyse complète post-incident a été réalisée à partir des corrélations multi-sources, de la détection comportementale (ML) et du graph d'attaque.")

// ── 3. Timeline chronologique ──
#tc-section("3. Timeline de l'incident")

#let timeline = data.at("timeline", default: ())
#if timeline.len() == 0 [
  #table(
    columns: (120pt, 1fr),
    stroke: 0.5pt + rgb("#e0e0e0"),
    fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
    [#text(fill: white, weight: "bold", size: 8pt)[Date/Heure]],
    [#text(fill: white, weight: "bold", size: 8pt)[Événement]],
    [Détection], [Incident détecté par ThreatClaw Engine],
    [Early Warning], [Notification initiale envoyée (24h)],
    [Rapport 72h], [Rapport intermédiaire envoyé],
    [Analyse], [Analyse complète et remédiation],
    [Clôture], [Incident résolu — rapport final],
  )
] else [
  #table(
    columns: (120pt, auto, 1fr),
    stroke: 0.5pt + rgb("#e0e0e0"),
    fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
    [#text(fill: white, weight: "bold", size: 8pt)[Date/Heure]],
    [#text(fill: white, weight: "bold", size: 8pt)[Phase]],
    [#text(fill: white, weight: "bold", size: 8pt)[Événement]],
    ..timeline.map(t => (
      text(size: 8pt, font: "Noto Sans Mono")[#t.at("time", default: "—")],
      text(size: 8pt, weight: "bold")[#t.at("phase", default: "—")],
      text(size: 9pt)[#t.at("event", default: "—")],
    )).flatten()
  )
]

// ── 4. Cause racine ──
#tc-section("4. Cause racine identifiée (Root Cause)")

#data.at("root_cause", default: "Analyse des causes racines consolidée par ThreatClaw Engine à partir des corrélations multi-sources et du graph d'attaque.")

*Vecteur d'attaque initial :* #data.at("attack_vector", default: "—")

*TTPs MITRE ATT&CK identifiés :*
#let ttps = data.at("mitre_ttps", default: ())
#if ttps.len() == 0 [
  Aucun TTP identifié à ce stade.
] else [
  #for ttp in ttps [
    - #ttp
  ]
]

// ── 5. Impact constaté ──
#tc-section("5. Impact constaté")

#grid(
  columns: (1fr, 1fr, 1fr),
  gutter: 10pt,
  tc-kpi(data.at("alerts_count", default: "0"), "Alertes totales"),
  tc-kpi(data.at("findings_count", default: "0"), "Vulnérabilités"),
  tc-kpi(data.at("assets_count", default: "0"), "Assets impactés"),
)

#v(8pt)
*Impact opérationnel :* #data.at("operational_impact", default: "—")

*Impact financier estimé :* #data.at("financial_impact", default: "En cours d'évaluation")

*Données potentiellement exposées :* #data.at("data_exposed", default: "Aucune donnée personnelle identifiée comme exposée")

*Nombre d'utilisateurs affectés :* #data.at("affected_users", default: "—")

// ── 6. Assets affectés ──
#tc-section("6. Détail des assets affectés")

#let assets = data.at("affected_assets", default: ())
#if assets.len() > 0 [
  #table(
    columns: (1fr, auto, auto, auto),
    stroke: 0.5pt + rgb("#e0e0e0"),
    fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
    [#text(fill: white, weight: "bold", size: 8pt)[Asset]],
    [#text(fill: white, weight: "bold", size: 8pt)[Catégorie]],
    [#text(fill: white, weight: "bold", size: 8pt)[Criticité]],
    [#text(fill: white, weight: "bold", size: 8pt)[IP]],
    ..assets.map(a => (
      text(size: 9pt)[#a.at("name", default: "—")],
      text(size: 9pt)[#a.at("category", default: "—")],
      text(size: 9pt, weight: "bold")[#a.at("criticality", default: "—")],
      text(size: 9pt, font: "Noto Sans Mono")[#a.at("ip", default: "—")],
    )).flatten()
  )
]

// ── 7. Mesures correctives ──
#tc-section("7. Mesures correctives implémentées")

#let measures = data.at("corrective_measures", default: ())
#if measures.len() == 0 [
  + Isolation et remédiation des assets compromis
  + Mise à jour des signatures de détection
  + Renforcement des règles firewall et segmentation
  + Rotation des credentials exposés
  + Activation de la surveillance renforcée
] else [
  #for m in measures [
    + #m
  ]
]

// ── 8. Recommandations / Leçons apprises ──
#tc-section("8. Recommandations et leçons apprises")

#let lessons = data.at("lessons_learned", default: ())
#if lessons.len() == 0 [
  + Renforcer la politique de patching (délai max 48h pour les critiques)
  + Activer l'authentification multi-facteurs sur tous les accès
  + Mettre en place une segmentation réseau stricte
  + Planifier des tests d'intrusion réguliers
  + Maintenir la surveillance continue via ThreatClaw Engine
] else [
  #for l in lessons [
    + #l
  ]
]

// ── 9. Conformité NIS2 — Cycle de notification ──
#tc-section("9. Conformité NIS2 — Cycle de notification")

Ce rapport clôt le cycle de notification obligatoire prévu par l'Article 23 de la Directive NIS2 :

#table(
  columns: (1fr, auto, auto, auto),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
  [#text(fill: white, weight: "bold", size: 8pt)[Rapport]],
  [#text(fill: white, weight: "bold", size: 8pt)[Référence]],
  [#text(fill: white, weight: "bold", size: 8pt)[Délai]],
  [#text(fill: white, weight: "bold", size: 8pt)[Statut]],
  [Early Warning], [Art. 23(4)(a)], [24 heures], text(fill: tc-green, weight: "bold")[ENVOYÉ],
  [Intermédiaire], [Art. 23(4)(b)], [72 heures], text(fill: tc-green, weight: "bold")[ENVOYÉ],
  [Final (ce rapport)], [Art. 23(4)(d-e)], [1 mois], text(fill: tc-green, weight: "bold")[COMPLÉTÉ],
)

#v(6pt)
*Autorité notifiée :* #data.at("notified_authority", default: "ANSSI / CSIRT-FR")

*Notification CNIL requise (RGPD Art. 33) :*
#let gdpr_required = data.at("gdpr_notification_required", default: "unknown")
#if gdpr_required == "yes" [
  Oui — notification CNIL effectuée
] else if gdpr_required == "no" [
  Non — pas de données personnelles impliquées
] else [
  En cours d'évaluation
]

// ── Footer ──
#v(16pt)
#line(length: 100%, stroke: 0.5pt + rgb("#dddddd"))
#v(4pt)
#text(size: 7pt, fill: tc-gray)[
  Ce rapport est conforme à l'Article 23(4)(d-e) de la Directive NIS2 (UE 2022/2555) — rapport final.
  #linebreak()
  Généré automatiquement par ThreatClaw v2.0 — #datetime.today().display("[day]/[month]/[year]")
  #linebreak()
  Ce rapport final clôt le cycle de notification obligatoire.
  #linebreak()
  Document confidentiel — destiné uniquement à l'entité notifiante et à l'autorité compétente (ANSSI/CSIRT).
]

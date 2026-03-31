// ThreatClaw — Notification RGPD Article 33
// Notification de violation de données à l'autorité de contrôle (CNIL)
// Champs obligatoires : Art. 33(3)(a-d) du Règlement (UE) 2016/679

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

#text(size: 16pt, weight: "bold", fill: tc-red)[NOTIFICATION DE VIOLATION DE DONNÉES]
#v(2pt)
#text(size: 10pt, fill: tc-gray)[Article 33, Règlement (UE) 2016/679 (RGPD)]
#v(8pt)

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*N° de notification*], text(font: "Noto Sans Mono", size: 9pt)[#data.at("notification_id", default: "TC-RGPD-2026-0001")],
  [*Date de génération*], data.at("generated_at_display", default: "—"),
  [*Délai réglementaire*], [72 heures après prise de connaissance],
  [*Autorité destinataire*], [CNIL — Commission Nationale de l'Informatique et des Libertés],
)

// ── 1. Responsable de traitement — Art. 33(3)(b) ──
#tc-section("1. Responsable de traitement")

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Dénomination*], data.at("org_name", default: "—"),
  [*Secteur d'activité*], data.at("sector", default: "—"),
  [*DPO / Contact*], data.at("dpo_contact", default: data.at("security_contact", default: "—")),
  [*Email DPO*], data.at("dpo_email", default: data.at("contact_email", default: "—")),
  [*Téléphone*], data.at("contact_phone", default: "—"),
)

// ── 2. Nature de la violation — Art. 33(3)(a) ──
#tc-section("2. Nature de la violation — Art. 33(3)(a)")

*Type de violation :*
#data.at("incident_type_label", default: "—")

#v(4pt)
*Description :*
#data.at("incident_description", default: "—")

#v(6pt)
#table(
  columns: (1fr, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: tc-light,
  [*Catégories de personnes concernées*],
  [*Nombre approximatif de personnes*],
  data.at("data_subject_categories", default: "En cours d'évaluation"),
  data.at("affected_persons_count", default: "En cours d'évaluation"),
)

#v(4pt)
#table(
  columns: (1fr, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: tc-light,
  [*Catégories de données concernées*],
  [*Nombre approximatif d'enregistrements*],
  data.at("data_categories", default: "En cours d'évaluation"),
  data.at("affected_records_count", default: "En cours d'évaluation"),
)

// ── 3. Conséquences probables — Art. 33(3)(c) ──
#tc-section("3. Conséquences probables — Art. 33(3)(c)")

#data.at("probable_consequences", default: "Les conséquences sont en cours d'évaluation par ThreatClaw Engine. L'analyse comportementale et l'enrichissement CTI permettront de préciser l'impact sur les droits et libertés des personnes concernées.")

#v(4pt)
*Risque pour les personnes :*
#let risk = data.at("risk_level", default: "medium")
#tc-badge(
  if risk == "high" { "RISQUE ÉLEVÉ" } else if risk == "medium" { "RISQUE MODÉRÉ" } else { "RISQUE FAIBLE" },
  if risk == "high" { "critical" } else if risk == "medium" { "medium" } else { "low" }
)

#v(4pt)
#if risk == "high" [
  #box(inset: (x: 8pt, y: 4pt), radius: 4pt, fill: rgb("#ffebee"), stroke: 1pt + tc-red)[
    #text(size: 9pt, weight: "bold", fill: tc-red)[Communication aux personnes concernées requise (Art. 34)]
  ]
]

// ── 4. Mesures prises — Art. 33(3)(d) ──
#tc-section("4. Mesures prises ou envisagées — Art. 33(3)(d)")

*Mesures pour remédier à la violation :*
#let measures = data.at("corrective_measures", default: ())
#if measures.len() == 0 [
  - Détection et containment par ThreatClaw Engine
  - Analyse forensique en cours
  - Surveillance renforcée des systèmes affectés
] else [
  #for m in measures [
    - #m
  ]
]

#v(6pt)
*Mesures pour atténuer les effets négatifs :*
#let mitigations = data.at("mitigation_measures", default: ())
#if mitigations.len() == 0 [
  - Vérification de l'intégrité des données
  - Évaluation de la nécessité de notifier les personnes (Art. 34)
  - Renforcement des contrôles d'accès
] else [
  #for m in mitigations [
    - #m
  ]
]

// ── 5. Systèmes impliqués ──
#tc-section("5. Systèmes impliqués")

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

// ── 6. Lien NIS2 ──
#tc-section("6. Double notification NIS2")

#let nis2_notified = data.at("nis2_notification_sent", default: "unknown")
#if nis2_notified == "yes" [
  Cette violation fait également l'objet d'une notification NIS2 à l'ANSSI/CERT-FR (Article 23, Directive NIS2).
  #linebreak()
  Référence NIS2 : #data.at("notification_id", default: "—")
] else [
  Évaluation en cours de la nécessité d'une notification NIS2 complémentaire.
]

// ── Footer ──
#v(16pt)
#line(length: 100%, stroke: 0.5pt + rgb("#dddddd"))
#v(4pt)
#text(size: 7pt, fill: tc-gray)[
  Ce rapport est conforme à l'Article 33 du Règlement (UE) 2016/679 (RGPD).
  #linebreak()
  À transmettre à la CNIL dans les 72 heures suivant la prise de connaissance de la violation.
  #linebreak()
  Plateforme officielle : notifications.cnil.fr
  #linebreak()
  Généré automatiquement par ThreatClaw v2.0 — #datetime.today().display("[day]/[month]/[year]")
  #linebreak()
  Document confidentiel.
]

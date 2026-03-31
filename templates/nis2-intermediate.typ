// ThreatClaw — Rapport NIS2 Intermédiaire (72h)
// Conforme Article 23(4)(b), Directive NIS2 (UE 2022/2555)
// Champs obligatoires : évaluation initiale, IOCs, cause probable, statut

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

#text(size: 16pt, weight: "bold", fill: tc-red)[RAPPORT INTERMÉDIAIRE — 72h]
#v(2pt)
#text(size: 10pt, fill: tc-gray)[Article 23(4)(b), Directive NIS2 (UE) 2022/2555]
#v(8pt)

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*N° de notification*], text(font: "Noto Sans Mono", size: 9pt)[#data.at("notification_id", default: "TC-2026-0001")],
  [*Réf. Early Warning*], text(font: "Noto Sans Mono", size: 9pt)[#data.at("early_warning_ref", default: "—")],
  [*Date de génération*], data.at("generated_at_display", default: "—"),
  [*Version*], [1.0],
)

// ── 1. Rappel de l'incident ──
#tc-section("1. Rappel de l'incident")

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Organisation*], data.at("org_name", default: "—"),
  [*Secteur NIS2*], data.at("sector", default: "—"),
  [*Identifiant incident*], text(font: "Noto Sans Mono")[#data.at("incident_id", default: "—")],
  [*Date de détection*], data.at("detected_at", default: "—"),
  [*Type d'incident*], data.at("incident_type_label", default: "—"),
  [*Statut actuel*], data.at("incident_status_label", default: "En cours"),
)

// ── 2. Évaluation initiale ──
#tc-section("2. Évaluation initiale de l'incident")

#let score = data.at("score", default: "100")

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 10pt,
  tc-kpi(data.at("alerts_count", default: "0"), "Alertes"),
  tc-kpi(data.at("findings_count", default: "0"), "Findings"),
  tc-kpi(data.at("assets_count", default: "0"), "Assets affectés"),
  tc-kpi(score, "Score sécurité"),
)

#v(6pt)
*Sévérité estimée :*
#let severity = data.at("severity", default: "medium")
#tc-badge(
  upper(severity),
  if severity == "critical" { "critical" } else if severity == "high" { "high" } else if severity == "medium" { "medium" } else { "low" }
)

#v(6pt)
*Périmètre impacté :* #data.at("impact_scope", default: "En cours d'évaluation par ThreatClaw Engine.")

*Services affectés :* #data.at("affected_services", default: "En cours d'identification.")

// ── 3. Cause probable ──
#tc-section("3. Cause initiale probable")

#data.at("probable_cause", default: "L'analyse par ThreatClaw Engine est en cours. La corrélation multi-source et la détection comportementale (ML) sont activées pour identifier le vecteur d'attaque initial.")

*Vecteur d'attaque :* #data.at("attack_vector", default: "En cours d'identification")

// ── 4. Indicateurs de compromission ──
#tc-section("4. Indicateurs de compromission (IOCs)")

#let iocs = data.at("iocs", default: ())
#if iocs.len() == 0 [
  Aucun IOC confirmé à ce stade. L'enrichissement via les sources CTI est en cours.
] else [
  #table(
    columns: (auto, 1fr, auto, auto),
    stroke: 0.5pt + rgb("#e0e0e0"),
    fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
    [#text(fill: white, weight: "bold", size: 8pt)[Type]],
    [#text(fill: white, weight: "bold", size: 8pt)[Valeur]],
    [#text(fill: white, weight: "bold", size: 8pt)[Source]],
    [#text(fill: white, weight: "bold", size: 8pt)[Confiance]],
    ..iocs.map(ioc => (
      text(size: 8pt, weight: "bold")[#ioc.at("type", default: "—")],
      text(size: 8pt, font: "Noto Sans Mono")[#ioc.at("value", default: "—")],
      text(size: 8pt)[#ioc.at("source", default: "—")],
      text(size: 8pt)[#ioc.at("confidence", default: "—")],
    )).flatten()
  )
]

// ── 5. Systèmes affectés (mise à jour) ──
#tc-section("5. Systèmes affectés (mise à jour)")

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
] else [
  Aucun asset identifié dans le périmètre impacté à ce stade.
]

// ── 6. Impact transfrontalier ──
#tc-section("6. Impact transfrontalier (mise à jour)")

#let cross = data.at("cross_border_impact", default: "unknown")
#if cross == "yes" [
  *Oui* — impact confirmé sur d'autres États membres.
  #linebreak()
  Détails : #data.at("cross_border_detail", default: "—")
] else if cross == "no" [
  *Non* — pas d'impact transfrontalier identifié.
] else [
  *En cours d'évaluation.*
]

// ── 7. Actions correctives ──
#tc-section("7. Actions correctives en cours")

#let actions = data.at("corrective_actions", default: ())
#if actions.len() == 0 [
  - Surveillance renforcée par ThreatClaw Engine (cycle 5 minutes)
  - Analyse comportementale ML active sur tous les assets
  - Enrichissement IOCs via 26+ sources CTI
  - Corrélation multi-source via le graph d'attaque
  - Blocage préventif des IPs suspectes
] else [
  #for a in actions [
    - #a
  ]
]

// ── Prochaine étape ──
#v(12pt)
#box(width: 100%, inset: 10pt, radius: 4pt, fill: tc-light, stroke: 1pt + rgb("#e0e0e0"))[
  *Rapport final prévu avant :* #data.at("deadline_final", default: "—")
  #linebreak()
  Le rapport final contiendra l'analyse complète, la cause racine, les mesures correctives et les recommandations.
]

// ── Footer ──
#v(16pt)
#line(length: 100%, stroke: 0.5pt + rgb("#dddddd"))
#v(4pt)
#text(size: 7pt, fill: tc-gray)[
  Ce rapport est conforme à l'Article 23(4)(b) de la Directive NIS2 (UE 2022/2555) — rapport intermédiaire (72h).
  #linebreak()
  Généré automatiquement par ThreatClaw v2.0 — #datetime.today().display("[day]/[month]/[year]")
  #linebreak()
  Document confidentiel — destiné uniquement à l'entité notifiante et à l'autorité compétente (ANSSI/CSIRT).
]

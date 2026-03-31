// ThreatClaw — ISO 27001:2022 Incident Report
// Aligned with Annex A controls A.5.24 to A.5.28 + A.6.8
// Information Security Incident Management

#import "common.typ": *

#let data = json("data.json")

#set page(paper: "a4", margin: (top: 18mm, bottom: 20mm, left: 15mm, right: 15mm))
#set text(font: "Noto Sans", size: 10pt)

// ── Header ──
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

#text(size: 16pt, weight: "bold", fill: tc-red)[RAPPORT D'INCIDENT DE SÉCURITÉ]
#v(2pt)
#text(size: 10pt, fill: tc-gray)[ISO/IEC 27001:2022 — Annexe A.5.24 à A.5.28]
#v(8pt)

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Identifiant incident*], text(font: "Noto Sans Mono", size: 9pt)[#data.at("incident_id", default: "—")],
  [*Date du rapport*], data.at("generated_at_display", default: "—"),
  [*Classification*], [Confidentiel — Usage interne uniquement],
  [*Référence ISO*], [A.5.24 / A.5.25 / A.5.26 / A.5.27 / A.5.28],
)

// ── A.5.25 — Classification de l'événement ──
#tc-section("1. Classification de l'événement — A.5.25")

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Catégorie*], data.at("incident_type_label", default: "—"),
  [*Sévérité*], data.at("severity", default: "—"),
  [*Priorité*], data.at("severity", default: "—"),
  [*Date de détection*], data.at("detected_at", default: "—"),
  [*Statut*], data.at("incident_status_label", default: "—"),
  [*Escalade requise*], if data.at("severity", default: "low") == "critical" { "Oui — Direction générale" } else if data.at("severity", default: "low") == "high" { "Oui — RSSI" } else { "Non" },
)

#v(4pt)
*Description de l'événement :*
#data.at("incident_description", default: "—")

// ── A.5.26 — Réponse à l'incident ──
#tc-section("2. Réponse à l'incident — A.5.26")

*KPIs :*
#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 10pt,
  tc-kpi(data.at("alerts_count", default: "0"), "Alertes"),
  tc-kpi(data.at("findings_count", default: "0"), "Findings"),
  tc-kpi(data.at("assets_count", default: "0"), "Assets affectés"),
  tc-kpi(data.at("score", default: "100"), "Score sécurité"),
)

#v(8pt)
*Assets affectés :*
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

#v(6pt)
*Actions de containment :*
#let actions = data.at("corrective_measures", default: ())
#if actions.len() == 0 [
  - Détection automatique par ThreatClaw Engine
  - Analyse comportementale ML active
  - Enrichissement IOCs via sources CTI
  - Surveillance renforcée des assets critiques
] else [
  #for a in actions [
    - #a
  ]
]

// ── A.5.28 — Collecte de preuves ──
#tc-section("3. Collecte de preuves — A.5.28")

*Indicateurs de compromission (IOCs) :*
#let iocs = data.at("iocs", default: ())
#if iocs.len() > 0 [
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
] else [
  Aucun IOC confirmé. Enrichissement CTI en cours.
]

#v(6pt)
*Chaîne de custody :*
#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Logs collectés*], [ThreatClaw Engine — PostgreSQL + TimescaleDB],
  [*Intégrité*], [Horodatage UTC, hash SHA-256 des entrées d'audit],
  [*Rétention*], [90 jours (configurable)],
  [*Outil de collecte*], [ThreatClaw v2.0 — automatique],
)

// ── A.5.27 — Analyse post-incident ──
#tc-section("4. Analyse post-incident — A.5.27")

*Cause racine :*
#data.at("root_cause", default: "Analyse en cours par ThreatClaw Engine.")

#v(4pt)
*Vecteur d'attaque :*
#data.at("attack_vector", default: "En cours d'identification")

#v(4pt)
*TTPs MITRE ATT&CK :*
#let ttps = data.at("mitre_ttps", default: ())
#if ttps.len() == 0 [
  Aucun TTP identifié à ce stade.
] else [
  #for ttp in ttps [
    - #ttp
  ]
]

// ── A.5.27 — Leçons apprises ──
#tc-section("5. Leçons apprises et améliorations — A.5.27")

#let lessons = data.at("lessons_learned", default: ())
#if lessons.len() == 0 [
  + Renforcer la politique de patching
  + Activer l'authentification multi-facteurs
  + Améliorer la segmentation réseau
  + Planifier des tests d'intrusion réguliers
  + Mettre à jour les procédures de réponse aux incidents
] else [
  #for l in lessons [
    + #l
  ]
]

#v(8pt)
*Procédures à mettre à jour :*
- Plan de réponse aux incidents (A.5.24)
- Critères de classification (A.5.25)
- Procédures de collecte de preuves (A.5.28)

// ── A.6.8 — Communication ──
#tc-section("6. Communication — A.6.8")

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Communication interne*], [RSSI informé via ThreatClaw Engine],
  [*Communication externe*], data.at("notified_authority", default: "À évaluer selon obligations réglementaires"),
  [*Notification NIS2*], if data.at("nis2_notification_sent", default: "no") == "yes" { "Oui — notification envoyée" } else { "Non requise / En évaluation" },
  [*Notification RGPD*], if data.at("gdpr_notification_required", default: "no") == "yes" { "Oui — notification CNIL requise" } else if data.at("gdpr_notification_required", default: "no") == "likely" { "Probable — évaluation en cours" } else { "Non requise" },
)

// ── Footer ──
#v(16pt)
#line(length: 100%, stroke: 0.5pt + rgb("#dddddd"))
#v(4pt)
#text(size: 7pt, fill: tc-gray)[
  Ce rapport est conforme aux contrôles ISO/IEC 27001:2022 Annexe A.5.24 à A.5.28 et A.6.8.
  #linebreak()
  Référence complémentaire : ISO/IEC 27002:2022 pour les recommandations de mise en œuvre.
  #linebreak()
  Généré automatiquement par ThreatClaw v2.0 — #datetime.today().display("[day]/[month]/[year]")
  #linebreak()
  Document confidentiel.
]

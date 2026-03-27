// ThreatClaw — Notification NIS2 Early Warning (24h)
// Conforme Article 23(4)(a), Directive NIS2 (UE 2022/2555)
// Champs obligatoires extraits du texte légal

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

// ── Titre + métadonnées ──
#text(size: 16pt, weight: "bold", fill: tc-red)[NOTIFICATION D'INCIDENT — EARLY WARNING]
#v(2pt)
#text(size: 10pt, fill: tc-gray)[Article 23(4)(a), Directive NIS2 (UE) 2022/2555]
#v(8pt)

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*N° de notification*], text(font: "Noto Sans Mono", size: 9pt)[#data.at("notification_id", default: "TC-2026-0001")],
  [*Date de génération*], data.at("generated_at_display", default: "—"),
  [*Généré par*], [ThreatClaw v2.0 — Automatique],
  [*Version du document*], [1.0],
)

// ── 1. Entité notifiante ──
#tc-section("1. Entité notifiante")

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Dénomination*], data.at("org_name", default: "—"),
  [*Secteur NIS2*], data.at("sector", default: "—"),
  [*Sous-secteur*], data.at("sub_sector", default: "—"),
  [*Statut NIS2*], data.at("nis2_status", default: "Entité Essentielle / Importante"),
  [*Contact sécurité*], data.at("security_contact", default: "—"),
  [*Email*], data.at("contact_email", default: "—"),
  [*Téléphone*], data.at("contact_phone", default: "—"),
)

// ── 2. Identification de l'incident ──
#tc-section("2. Identification de l'incident")

#let detected = data.at("detected_at", default: "—")
#let notified = data.at("notified_at", default: "—")
#let delay = data.at("delay_hours", default: "—")

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Identifiant interne*], text(font: "Noto Sans Mono", size: 9pt)[#data.at("incident_id", default: "—")],
  [*Date/heure de détection*], detected,
  [*Date/heure de notification*], notified,
  [*Délai de notification*], [#delay h],
)

#v(4pt)
#let delay_ok = float(data.at("delay_hours", default: "0")) <= 24.0
#if delay_ok [
  #box(inset: (x: 8pt, y: 4pt), radius: 4pt, fill: rgb("#e8f5e9"), stroke: 1pt + tc-green)[
    #text(size: 9pt, weight: "bold", fill: tc-green)[Dans les 24h réglementaires]
  ]
] else [
  #box(inset: (x: 8pt, y: 4pt), radius: 4pt, fill: rgb("#ffebee"), stroke: 1pt + tc-red)[
    #text(size: 9pt, weight: "bold", fill: tc-red)[DÉPASSEMENT du délai de 24h]
  ]
]

// ── 3. Nature de l'incident ──
#tc-section("3. Nature de l'incident")

#let itype = data.at("incident_type", default: "other")

#let cbox(checked) = {
  if checked {
    box(width: 8pt, height: 8pt, stroke: 0.5pt + black, baseline: 1pt)[#align(center + horizon)[#text(size: 6pt, weight: "bold")[X]]]
  } else {
    box(width: 8pt, height: 8pt, stroke: 0.5pt + rgb("#cccccc"), baseline: 1pt)
  }
}

#let check(val, label) = {
  if itype == val {
    [#cbox(true) #text(size: 9pt)[#label]]
  } else {
    [#cbox(false) #text(size: 9pt, fill: tc-gray)[#label]]
  }
}

#grid(
  columns: (1fr, 1fr),
  gutter: 4pt,
  check("ransomware", "Ransomware / Chiffrement"),
  check("intrusion", "Accès non autorisé / Intrusion"),
  check("ddos", "DDoS / Déni de service"),
  check("data_leak", "Fuite de données"),
  check("account_compromise", "Compromission de compte"),
  check("supply_chain", "Compromission chaîne d'approvisionnement"),
  check("malware", "Malware / Code malveillant"),
  check("phishing", "Hameçonnage ciblé"),
)

#v(4pt)
#if itype == "other" or not (itype in ("ransomware", "intrusion", "ddos", "data_leak", "account_compromise", "supply_chain", "malware", "phishing")) [
  Autre : *#data.at("incident_type_detail", default: data.at("incident_description", default: "—"))*
]

#v(4pt)
*Description initiale :*
#data.at("incident_description", default: "Incident détecté par ThreatClaw Engine. Analyse en cours.")

#v(6pt)
*Suspicion d'acte malveillant (Art. 23(4)(a)) :*
#let malicious = data.at("suspected_malicious", default: "unknown")
#grid(
  columns: (auto, 1fr),
  gutter: 4pt,
  cbox(malicious == "yes"),
  text(size: 9pt)[Oui — acte illicite ou malveillant soupçonné],
  cbox(malicious == "no"),
  text(size: 9pt)[Non — cause accidentelle ou technique],
  cbox(malicious == "unknown"),
  text(size: 9pt)[En cours d'évaluation],
)

// ── 4. Systèmes affectés ──
#tc-section("4. Systèmes affectés")

#let assets = data.at("affected_assets", default: ())
#text(size: 9pt)[#assets.len() asset(s) dans le périmètre impacté.]

#if assets.len() > 0 [
  #v(4pt)
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

// ── 5. Impact transfrontalier ──
#tc-section("5. Impact transfrontalier")

#let cross = data.at("cross_border_impact", default: "unknown")

#grid(
  columns: (auto, 1fr),
  gutter: 4pt,
  cbox(cross == "yes"),
  text(size: 9pt)[Oui — impact possible sur d'autres États membres],
  cbox(cross == "no"),
  text(size: 9pt)[Non],
  cbox(cross == "unknown"),
  text(size: 9pt)[En cours d'évaluation],
)

#let cross_detail = data.at("cross_border_detail", default: none)
#if cross_detail != none [
  #v(2pt)
  Précisions : #cross_detail
]

// ── 6. Mesures immédiates prises ──
#tc-section("6. Mesures immédiates prises")

#let measures = data.at("immediate_measures", default: ())
#if measures.len() == 0 [
  - Détection automatique par ThreatClaw Engine (cycle toutes les 5 minutes)
  - Analyse comportementale en cours (ML)
  - Enrichissement IOCs via sources CTI
  - Surveillance renforcée des assets critiques
] else [
  #for m in measures [
    - #m
  ]
]

// ── 7. Statut actuel ──
#tc-section("7. Statut actuel")

#let status = data.at("incident_status", default: "ongoing")

#grid(
  columns: (auto, 1fr),
  gutter: 4pt,
  cbox(status == "ongoing"),
  text(size: 9pt)[Incident en cours],
  cbox(status == "contained"),
  text(size: 9pt)[Incident contenu],
  cbox(status == "resolved"),
  text(size: 9pt)[Incident résolu],
)

// ── Prochaine étape ──
#v(12pt)
#box(width: 100%, inset: 10pt, radius: 4pt, fill: tc-light, stroke: 1pt + rgb("#e0e0e0"))[
  *Rapport suivant (72h) prévu avant :* #data.at("deadline_72h", default: "—")
  #linebreak()
  Le rapport intermédiaire contiendra l'évaluation initiale, les IOCs identifiés et les actions correctives détaillées.
]

// ── Footer ──
#v(16pt)
#line(length: 100%, stroke: 0.5pt + rgb("#dddddd"))
#v(4pt)
#text(size: 7pt, fill: tc-gray)[
  Ce rapport est conforme à l'Article 23(4)(a) de la Directive NIS2 (UE 2022/2555) — notification initiale (Early Warning).
  #linebreak()
  Généré automatiquement par ThreatClaw v2.0 — #datetime.today().display("[day]/[month]/[year]")
  #linebreak()
  Les rapports intermédiaire (72h) et final (1 mois) seront générés automatiquement selon les délais réglementaires.
  #linebreak()
  Document confidentiel — destiné uniquement à l'entité notifiante et à l'autorité compétente (ANSSI/CSIRT).
]

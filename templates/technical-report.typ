// ThreatClaw — Rapport Technique RSSI
// Détail complet : findings, CVEs, TTPs MITRE, recommandations

#import "common.typ": *

#let data = json("data.json")

#set page(paper: "a4", margin: (top: 18mm, bottom: 20mm, left: 15mm, right: 15mm))
#set text(font: "Noto Sans", size: 10pt)

#tc-header(
  "RAPPORT TECHNIQUE — RSSI",
  data.at("company_name", default: "Organisation"),
  subtitle: "Période : " + data.at("period", default: "Mars 2026"),
)

// ── Score ──
#tc-section("Score de sécurité")

#let score = float(data.at("score", default: "100"))
#tc-score-box(score)

// ── KPIs ──
#v(8pt)
#let alerts_count = int(data.at("alerts_count", default: "0"))
#let findings_count = int(data.at("findings_count", default: "0"))
#let assets_count = int(data.at("assets_count", default: "0"))
#let critical_count = int(data.at("critical_count", default: "0"))

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 10pt,
  tc-kpi(str(alerts_count), "Alertes"),
  tc-kpi(str(critical_count), "Critiques"),
  tc-kpi(str(findings_count), "Findings"),
  tc-kpi(str(assets_count), "Assets"),
)

// ── Findings ──
#tc-section("Vulnérabilités détectées")

#let findings = data.at("findings", default: ())
#if findings.len() == 0 [
  Aucune vulnérabilité détectée sur la période.
] else [
  #table(
    columns: (auto, 1fr, auto, auto),
    stroke: 0.5pt + rgb("#e0e0e0"),
    fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
    [#text(fill: white, weight: "bold", size: 8pt)[Sévérité]],
    [#text(fill: white, weight: "bold", size: 8pt)[Description]],
    [#text(fill: white, weight: "bold", size: 8pt)[Asset]],
    [#text(fill: white, weight: "bold", size: 8pt)[Source]],
    ..findings.map(f => (
      text(size: 8pt, weight: "bold", fill: if f.at("severity", default: "") == "critical" { tc-red } else if f.at("severity", default: "") == "high" { rgb("#d07020") } else { tc-amber })[
        #upper(f.at("severity", default: "—"))
      ],
      text(size: 9pt)[#f.at("title", default: "—")],
      text(size: 9pt)[#f.at("asset", default: "—")],
      text(size: 8pt, font: "Noto Sans Mono")[#f.at("source", default: "—")],
    )).flatten()
  )
]

// ── Alertes ──
#tc-section("Alertes de sécurité")

#let alerts = data.at("alerts", default: ())
#if alerts.len() == 0 [
  Aucune alerte sur la période.
] else [
  #table(
    columns: (auto, 1fr, auto, auto),
    stroke: 0.5pt + rgb("#e0e0e0"),
    fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
    [#text(fill: white, weight: "bold", size: 8pt)[Niveau]],
    [#text(fill: white, weight: "bold", size: 8pt)[Description]],
    [#text(fill: white, weight: "bold", size: 8pt)[Source IP]],
    [#text(fill: white, weight: "bold", size: 8pt)[Date]],
    ..alerts.map(a => (
      text(size: 8pt, weight: "bold")[#a.at("level", default: "—")],
      text(size: 9pt)[#a.at("title", default: "—")],
      text(size: 9pt, font: "Noto Sans Mono")[#a.at("source_ip", default: "—")],
      text(size: 9pt)[#a.at("date", default: "—")],
    )).flatten()
  )
]

// ── Assets ──
#tc-section("Inventaire des assets")

#let assets = data.at("assets", default: ())
#if assets.len() == 0 [
  Aucun asset dans le périmètre.
] else [
  #table(
    columns: (1fr, auto, auto, auto),
    stroke: 0.5pt + rgb("#e0e0e0"),
    fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
    [#text(fill: white, weight: "bold", size: 8pt)[Nom]],
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

// ── Détection comportementale (ML) ──
#tc-section("Anomalies détectées (ML)")

#let ml_anomalies = data.at("ml_anomalies", default: ())
#if ml_anomalies.len() == 0 [
  Aucune anomalie comportementale détectée sur la période. Les baselines ML sont normales.
] else [
  #ml_anomalies.len() anomalie(s) détectée(s) par le moteur ML (Isolation Forest) :
  #v(4pt)
  #table(
    columns: (1fr, auto, auto, 1fr),
    stroke: 0.5pt + rgb("#e0e0e0"),
    fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
    [#text(fill: white, weight: "bold", size: 8pt)[Asset]],
    [#text(fill: white, weight: "bold", size: 8pt)[Catégorie]],
    [#text(fill: white, weight: "bold", size: 8pt)[Score ML]],
    [#text(fill: white, weight: "bold", size: 8pt)[Raison]],
    ..ml_anomalies.map(a => (
      text(size: 9pt)[#a.at("asset", default: "—")],
      text(size: 9pt)[#a.at("category", default: "—")],
      text(size: 9pt, weight: "bold", fill: tc-red)[#a.at("ml_score", default: "—")],
      text(size: 8pt)[#a.at("reason", default: "—")],
    )).flatten()
  )
]

// ── TTPs MITRE ATT&CK ──
#tc-section("TTPs MITRE ATT&CK identifiés")

#let ttps = data.at("mitre_ttps", default: ())
#if ttps.len() == 0 [
  Aucun TTP MITRE ATT&CK identifié dans le graph d'attaque sur la période.
] else [
  #for ttp in ttps [
    - #ttp
  ]
]

// ── Recommandations ──
#tc-section("Recommandations techniques")

#let recommendations = data.at("recommendations", default: ())
#if recommendations.len() == 0 [
  + Maintenir les scans de vulnérabilités automatiques
  + Appliquer les patches critiques dans les 48h
  + Renforcer la segmentation réseau
  + Activer l'authentification MFA sur tous les accès
] else [
  #for r in recommendations [
    + #r
  ]
]

#tc-footer(data.at("company_name", default: "Organisation"))

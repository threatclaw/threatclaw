// ThreatClaw — Rapport Exécutif (Direction / COMEX)
// Non-technique, factuel, concis — 1 à 2 pages max

#import "common.typ": *

// Data injected by backend as JSON
#let data = json("data.json")

#set page(paper: "a4", margin: (top: 18mm, bottom: 20mm, left: 15mm, right: 15mm))
#set text(font: "Noto Sans", size: 10pt)

#tc-header(
  "RAPPORT DE SÉCURITÉ",
  data.at("company_name", default: "Organisation"),
  subtitle: "Période : " + data.at("period", default: "Mars 2026"),
)

// ── Score ──
#tc-section("Score de sécurité global")

#let score = float(data.at("score", default: "100"))
#tc-score-box(score)

#v(6pt)
#if score >= 80 [
  Votre infrastructure est en bonne posture sécuritaire. ThreatClaw Engine surveille activement votre réseau sans détection d'incident majeur.
] else if score >= 50 [
  Des points d'attention ont été identifiés ce mois. Des actions correctives sont recommandées pour maintenir un niveau de sécurité optimal.
] else [
  *Situation dégradée.* Des menaces actives ou des vulnérabilités critiques nécessitent une attention immédiate.
]

// ── KPIs ──
#tc-section("Synthèse du mois")

#let alerts_count = int(data.at("alerts_count", default: "0"))
#let critical_count = int(data.at("critical_count", default: "0"))
#let assets_count = int(data.at("assets_count", default: "0"))

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 10pt,
  tc-kpi(str(alerts_count), "Alertes totales"),
  tc-kpi(str(critical_count), "Critiques"),
  tc-kpi(str(assets_count), "Assets surveillés"),
  tc-kpi("0", "Incidents majeurs"),
)

// ── Alertes ──
#tc-section("Alertes critiques")

#let alerts = data.at("alerts", default: ())
#if alerts.len() == 0 [
  Aucune alerte critique ce mois. ✓
] else [
  #table(
    columns: (auto, 1fr, auto),
    stroke: 0.5pt + rgb("#e0e0e0"),
    fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
    [#text(fill: white, weight: "bold")[Date]], [#text(fill: white, weight: "bold")[Description]], [#text(fill: white, weight: "bold")[Source]],
    ..alerts.map(a => (
      text(size: 9pt)[#a.at("date", default: "—")],
      text(size: 9pt)[#a.at("title", default: "—")],
      text(size: 9pt, font: "Noto Sans Mono")[#a.at("source", default: "—")],
    )).flatten()
  )
]

// ── Recommandations ──
#tc-section("Recommandations")

+ Maintenir la surveillance continue via ThreatClaw Engine
+ Vérifier les mises à jour de sécurité sur les assets critiques
+ Former les équipes aux bonnes pratiques (phishing, mots de passe)
+ Planifier un audit de conformité NIS2 Article 21

#tc-footer(data.at("company_name", default: "Organisation"))

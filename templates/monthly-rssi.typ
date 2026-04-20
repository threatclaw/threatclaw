// ThreatClaw — Rapport mensuel RSSI. See roadmap §3.4.
// 1 page A4, destinée à la direction / COMEX du client.

#import "common.typ": *

#let data = json("data.json")

#let format-duration(secs) = {
  if secs < 60 [
    #str(int(secs)) s
  ] else if secs < 3600 [
    #str(int(secs / 60)) min
  ] else if secs < 86400 [
    #str(int(secs / 3600)) h
  ] else [
    #str(int(secs / 86400)) j
  ]
}

#set page(paper: "a4", margin: (top: 16mm, bottom: 18mm, left: 15mm, right: 15mm))
#set text(font: "Noto Sans", size: 10pt)

#tc-header(
  "RAPPORT MENSUEL RSSI",
  data.at("company_name", default: "Organisation"),
  subtitle: "Période : " + data.at("period", default: ""),
)

// ── KPIs principaux ──
#tc-section("Activité du mois")

#let s = data.summary

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 8pt,
  tc-kpi(str(s.at("incidents_total", default: 0)), "Incidents"),
  tc-kpi(str(s.at("incidents_confirmed", default: 0)), "Confirmés"),
  tc-kpi(str(s.at("incidents_fp", default: 0)), "Faux positifs"),
  tc-kpi(str(s.at("incidents_resolved", default: 0)), "Résolus"),
)

#v(6pt)

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 8pt,
  tc-kpi(str(s.at("sev_critical", default: 0)), "Critiques"),
  tc-kpi(str(s.at("sev_high", default: 0)), "Hautes"),
  tc-kpi(str(s.at("sev_medium", default: 0)), "Moyennes"),
  tc-kpi(str(s.at("sev_low", default: 0)), "Faibles"),
)

// ── Temps de réponse ──
#v(10pt)
#tc-section("Temps de résolution (MTTR)")

#let mttr_p50 = s.at("mttr_p50_sec", default: none)
#let mttr_p95 = s.at("mttr_p95_sec", default: none)

#if mttr_p50 != none [
  - *Médiane* : #format-duration(float(mttr_p50))
] else [
  - *Médiane* : _données insuffisantes_
]
#if mttr_p95 != none [
  - *P95* : #format-duration(float(mttr_p95))
]

// ── Blast radius ──
#v(8pt)
#tc-section("Impact potentiel observé")

#let with_blast = s.at("incidents_with_blast", default: 0)
#let score_max = s.at("blast_score_max", default: 0)

- #with_blast incidents avec impact calculé (auto-trigger sur menaces latérales)
- Score d'impact maximum observé : *#score_max / 100*
- Score moyen : #s.at("blast_score_avg", default: "—")

// ── Top incidents ──
#v(8pt)
#tc-section("Incidents à plus fort impact")

#if data.top_incidents.len() == 0 [
  _Aucun incident à fort impact ce mois-ci._
] else [
  #table(
    columns: (auto, 1fr, auto, auto, auto),
    inset: 5pt,
    align: (left, left, center, center, right),
    stroke: 0.5pt + gray,
    [*No*], [*Titre*], [*Actif*], [*Sévérité*], [*Score*],
    ..data.top_incidents.map(i => (
      str(i.id),
      i.title,
      i.asset,
      i.at("severity", default: "—"),
      str(i.at("blast_radius_score", default: 0)),
    )).flatten()
  )
]

// ── Footer ──
#v(1fr)
#tc-footer(data.at("company_name", default: "Organisation"))

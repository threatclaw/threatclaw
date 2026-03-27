// ThreatClaw — Conformité NIS2 Article 21
// Checklist des 10 mesures de sécurité obligatoires

#import "common.typ": *

#let data = json("data.json")

#set page(paper: "a4", margin: (top: 18mm, bottom: 20mm, left: 15mm, right: 15mm))
#set text(font: "Noto Sans", size: 10pt)

#tc-header(
  "CONFORMITÉ NIS2 — ARTICLE 21",
  data.at("company_name", default: "Organisation"),
  subtitle: "Checklist des mesures de gestion des risques",
)

// ── Score global ──
#tc-section("Score global de conformité")

#let global_score = float(data.at("global_score", default: "62"))
#tc-score-box(global_score)

#v(6pt)
Basé sur les 10 mesures de l'Article 21 de la Directive NIS2 (UE 2022/2555).

// ── Détail ──
#tc-section("Détail par mesure")

#let measures = data.at("measures", default: ())

#table(
  columns: (30pt, 1fr, auto, 50pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
  [#text(fill: white, weight: "bold", size: 8pt)[\#]],
  [#text(fill: white, weight: "bold", size: 8pt)[Mesure Article 21]],
  [#text(fill: white, weight: "bold", size: 8pt)[Statut]],
  [#text(fill: white, weight: "bold", size: 8pt)[Score]],
  [#text(fill: white, weight: "bold", size: 8pt)[Couvert par]],
  ..measures.enumerate().map(((i, m)) => (
    text(size: 9pt, weight: "bold")[#str(i + 1)],
    text(size: 9pt)[#m.at("title", default: "—")],
    text(size: 8pt, weight: "bold", fill: if m.at("status", default: "") == "covered" { tc-green } else if m.at("status", default: "") == "partial" { tc-amber } else { tc-red })[
      #if m.at("status", default: "") == "covered" [COUVERT] else if m.at("status", default: "") == "partial" [PARTIEL] else [NON COUVERT]
    ],
    text(size: 9pt, weight: "bold")[#m.at("score", default: "0")%],
    text(size: 8pt, fill: tc-gray)[#m.at("covered_by", default: "—")],
  )).flatten()
)

// ── Actions prioritaires ──
#tc-section("Actions prioritaires")

#let low_measures = measures.filter(m => int(m.at("score", default: "100")) < 60)
#if low_measures.len() == 0 [
  Toutes les mesures sont au-dessus du seuil de 60%. ✓
] else [
  #for m in low_measures [
    + *#m.at("title", default: "—")* — Score actuel : #m.at("score", default: "0")%
  ]
]

// ── Légende ──
#tc-section("Légende")

#grid(
  columns: (auto, 1fr),
  gutter: 6pt,
  tc-badge("COUVERT", "low"), [La mesure est implémentée et surveillée par ThreatClaw],
  tc-badge("PARTIEL", "medium"), [La mesure est partiellement couverte — actions complémentaires recommandées],
  tc-badge("NON COUVERT", "critical"), [La mesure n'est pas dans le périmètre actuel de ThreatClaw],
)

#tc-footer(data.at("company_name", default: "Organisation"))

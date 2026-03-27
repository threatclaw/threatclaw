// ThreatClaw — Journal d'Audit
// Preuve légale horodatée — toutes les actions ThreatClaw

#import "common.typ": *

#let data = json("data.json")

#set page(paper: "a4", margin: (top: 18mm, bottom: 20mm, left: 15mm, right: 15mm))
#set text(font: "Noto Sans", size: 10pt)

#tc-header(
  "JOURNAL D'AUDIT",
  data.at("company_name", default: "Organisation"),
  subtitle: "Période : " + data.at("period", default: "Mars 2026"),
)

// ── Résumé ──
#tc-section("Résumé")

#let entries = data.at("entries", default: ())
#let total = entries.len()

#grid(
  columns: (1fr, 1fr, 1fr),
  gutter: 10pt,
  tc-kpi(str(total), "Actions enregistrées"),
  tc-kpi(data.at("period_start", default: "—"), "Début période"),
  tc-kpi(data.at("period_end", default: "—"), "Fin période"),
)

#v(6pt)
Ce journal contient l'intégralité des actions exécutées par ThreatClaw Engine sur la période. Chaque entrée est horodatée et associée à un acteur (système ou utilisateur).

// ── Entrées ──
#tc-section("Détail des actions")

#if entries.len() == 0 [
  Aucune action enregistrée sur la période.
] else [
  #table(
    columns: (100pt, auto, 1fr, auto),
    stroke: 0.5pt + rgb("#e0e0e0"),
    fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
    [#text(fill: white, weight: "bold", size: 8pt)[Date/Heure]],
    [#text(fill: white, weight: "bold", size: 8pt)[Acteur]],
    [#text(fill: white, weight: "bold", size: 8pt)[Action]],
    [#text(fill: white, weight: "bold", size: 8pt)[Résultat]],
    ..entries.map(e => (
      text(size: 8pt, font: "Noto Sans Mono")[#e.at("timestamp", default: "—")],
      text(size: 8pt, weight: "bold")[#e.at("actor", default: "system")],
      text(size: 9pt)[#e.at("action", default: "—")],
      text(size: 8pt, weight: "bold", fill: if e.at("result", default: "") == "success" { tc-green } else if e.at("result", default: "") == "error" { tc-red } else { tc-amber })[
        #upper(e.at("result", default: "—"))
      ],
    )).flatten()
  )
]

// ── Intégrité ──
#tc-section("Intégrité du journal")

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Nombre d'entrées*], str(total),
  [*Hash du journal*], text(font: "Noto Sans Mono", size: 8pt)[#data.at("journal_hash", default: "sha256:...")],
  [*Généré par*], [ThreatClaw Engine v2.0],
  [*Date de génération*], [#datetime.today().display("[day]/[month]/[year]")],
)

#v(6pt)
#text(size: 8pt, fill: tc-gray)[
  Ce journal est stocké dans PostgreSQL avec horodatage UTC. L'intégrité est vérifiable via le hash SHA-256 calculé sur l'ensemble des entrées ordonnées par timestamp.
]

#tc-footer(data.at("company_name", default: "Organisation"))

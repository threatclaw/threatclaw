// ThreatClaw — Common report styles and functions
// Brand: #d03020 (red), #3080d0 (blue), #30a050 (green), #d09020 (amber)

#let tc-red = rgb("#d03020")
#let tc-blue = rgb("#3080d0")
#let tc-green = rgb("#30a050")
#let tc-amber = rgb("#d09020")
#let tc-dark = rgb("#222222")
#let tc-gray = rgb("#888888")
#let tc-light = rgb("#f5f5f5")

#let tc-header(title, company, subtitle: none) = {
  grid(
    columns: (1fr, auto),
    align: (left, right),
    [
      #text(size: 22pt, weight: "bold", fill: tc-red, tracking: 0.1em)[THREATCLAW]
      #v(2pt)
      #text(size: 8pt, fill: tc-gray)[Agent de cybersécurité autonome]
    ],
    [
      #text(size: 12pt, weight: "bold", fill: tc-dark)[#company]
      #v(2pt)
      #text(size: 9pt, fill: tc-gray)[#datetime.today().display("[day]/[month]/[year]")]
      #if subtitle != none { v(2pt); text(size: 9pt, fill: tc-gray)[#subtitle] }
    ],
  )
  v(6pt)
  line(length: 100%, stroke: 2pt + tc-red)
  v(12pt)
  text(size: 18pt, weight: "bold", fill: tc-red)[#title]
  v(8pt)
}

#let tc-section(title) = {
  v(14pt)
  text(size: 14pt, weight: "bold", fill: tc-dark)[#title]
  v(2pt)
  line(length: 100%, stroke: 1.5pt + tc-red)
  v(6pt)
}

#let tc-kpi(value, label) = {
  box(
    width: 100%,
    inset: 8pt,
    radius: 4pt,
    stroke: 1pt + rgb("#e0e0e0"),
    [
      #align(center)[
        #text(size: 20pt, weight: "bold", fill: tc-dark)[#value]
        #v(2pt)
        #text(size: 7pt, fill: tc-gray, tracking: 0.05em)[#upper(label)]
      ]
    ]
  )
}

#let tc-badge(text-content, level) = {
  let color = if level == "critical" { tc-red } else if level == "high" { rgb("#d07020") } else if level == "medium" { tc-amber } else { tc-green }
  let bg = if level == "critical" { rgb("#ffebee") } else if level == "high" { rgb("#fff3e0") } else if level == "medium" { rgb("#fff8e1") } else { rgb("#e8f5e9") }
  box(inset: (x: 6pt, y: 2pt), radius: 3pt, fill: bg)[
    #text(size: 7pt, weight: "bold", fill: color)[#upper(text-content)]
  ]
}

#let tc-score-box(score) = {
  let color = if score >= 80 { tc-green } else if score >= 50 { tc-amber } else { tc-red }
  let bg = if score >= 80 { rgb("#e8f5e9") } else if score >= 50 { rgb("#fff8e1") } else { rgb("#ffebee") }
  box(inset: (x: 14pt, y: 8pt), radius: 6pt, fill: bg, stroke: 2pt + color)[
    #text(size: 24pt, weight: "bold", fill: color)[#calc.round(score) / 100]
  ]
}

#let tc-footer(company) = {
  v(20pt)
  line(length: 100%, stroke: 0.5pt + rgb("#dddddd"))
  v(4pt)
  text(size: 7pt, fill: tc-gray)[
    Rapport généré automatiquement par ThreatClaw v2.0 — #datetime.today().display("[day]/[month]/[year]")
    #linebreak()
    Ce document est confidentiel et destiné uniquement à #company.
  ]
}

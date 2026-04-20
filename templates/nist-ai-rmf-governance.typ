// ThreatClaw — NIST AI RMF 1.0 Governance Assessment
// 4 fonctions Govern / Map / Measure / Manage
// Révision 2025 : shadow AI explicitly named in inventory (MAP)

#import "common.typ": *

#let data = json("data.json")

#set page(paper: "a4", margin: (top: 18mm, bottom: 20mm, left: 15mm, right: 15mm))
#set text(font: "Noto Sans", size: 10pt)

#tc-header(
  "NIST AI RMF — GOVERNANCE ASSESSMENT",
  data.at("company_name", default: "Organisation"),
  subtitle: "AI 100-1 — 4 functions: Govern / Map / Measure / Manage",
)

// ── Overall score ──
#tc-section("Overall NIST AI RMF posture")

#let overall = int(data.at("overall_score", default: 50))
#tc-score-box(float(overall))

#v(6pt)

NIST AI Risk Management Framework provides a structured approach to managing AI risks
across four interdependent functions. The 2025 revision *explicitly names shadow AI*
as a mandatory inventory control (MAP function).

Maturity level: *#data.at("maturity_label", default: "Initial")*.

// ── Function-by-function breakdown ──
#tc-section("Scores by AI RMF function")

#let functions = data.at("articles", default: ())
#let cols = (ratio: (1fr, 1fr), gutter: 10pt)

#for func in functions [
  #let score = int(func.at("score", default: 50))
  #let color = if score >= 80 { tc-green } else if score >= 50 { tc-amber } else { tc-red }
  #let bg = if score >= 80 { rgb("#e8f5e9") } else if score >= 50 { rgb("#fff8e1") } else { rgb("#ffebee") }

  #block(
    fill: bg,
    inset: 12pt,
    radius: 5pt,
    width: 100%,
    stroke: (left: 4pt + color),
  )[
    #grid(
      columns: (1fr, auto),
      [
        #text(size: 13pt, weight: "bold", fill: tc-dark)[#func.id]
        #v(2pt)
        #text(weight: "bold")[#func.title]
        #v(3pt)
        #text(size: 8pt, fill: tc-gray)[#func.description]
      ],
      align(right)[
        #text(size: 20pt, weight: "bold", fill: color)[#score/100]
        #v(4pt)
        #text(size: 8pt, fill: tc-gray)[#func.at("relevant_findings", default: 0) findings]
      ]
    )

    #if func.at("top_recommendation", default: none) != none [
      #v(6pt)
      #block(
        fill: rgb("#ffffff"),
        inset: 8pt,
        radius: 3pt,
        text(size: 9pt, fill: tc-blue)[→ #func.top_recommendation]
      )
    ]
  ]
  #v(8pt)
]

// ── Shadow AI highlight (2025 revision) ──
#tc-section("Shadow AI — explicit inventory control (MAP)")

Since the *2025 revision*, NIST AI RMF explicitly states :

#block(
  fill: rgb("#f0f5fa"),
  inset: 10pt,
  radius: 3pt,
  stroke: (left: 3pt + tc-blue),
)[
  #text(style: "italic")[
    "Organizations should include formal ML models, third-party AI services, and *shadow
    AI* (employees using ChatGPT, Copilot, or similar tools for work) in their AI system
    inventory."
  ]
]

#v(6pt)

ThreatClaw implements this via the `ai_systems` inventory (V41) populated by :
- Manual declaration (RSSI dashboard)
- Automatic `shadow-ai-monitor` qualification (Sigma shadow-ai-001..004 + endpoint feed)

// ── Gaps ──
#tc-section("Gaps to close")

#let gaps = data.at("gaps", default: ())
#if gaps.len() == 0 [
  #text(fill: tc-green)[✓ No gap identified on the 4 core functions]
] else [
  #for g in gaps [
    - Function *#g* scored below 50 — remediation required
  ]
]

#v(8pt)

#text(size: 8pt, fill: tc-gray)[
  References: NIST AI 100-1 (Jan 2023) + Generative AI Profile AI 600-1 (2024) +
  2025 update explicitly covering shadow AI in inventory control.
]

#tc-footer(data.at("company_name", default: "Organisation"))

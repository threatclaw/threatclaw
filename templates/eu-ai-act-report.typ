// ThreatClaw — EU AI Act Compliance Report (Règlement UE 2024/1689)
// Mapping des obligations high-risk (Art.12 logging, Art.13-14 transparence)
// + inventaire IA + posture shadow AI

#import "common.typ": *

#let data = json("data.json")

#set page(paper: "a4", margin: (top: 18mm, bottom: 20mm, left: 15mm, right: 15mm))
#set text(font: "Noto Sans", size: 10pt)

#tc-header(
  "EU AI ACT — COMPLIANCE REPORT",
  data.at("company_name", default: "Organisation"),
  subtitle: "Règlement (UE) 2024/1689 — Obligations high-risk AI",
)

// ── Overall score ──
#tc-section("Score global de conformité EU AI Act")

#let overall = int(data.at("overall_score", default: 50))
#tc-score-box(float(overall))

#v(6pt)
Évaluation basée sur les findings et alertes en cours : politique IA (Art.9), logging
automatique (Art.12), transparence (Art.13-14), supervision humaine (Art.14), gestion
continue des risques IA (Art.9).

// ── Inventaire IA ──
#tc-section("Inventaire des systèmes IA")

#let ai_total = int(data.at("ai_systems_total", default: 0))
#let ai_declared = int(data.at("ai_systems_declared", default: 0))
#let ai_detected = int(data.at("ai_systems_detected", default: 0))
#let ai_high_risk = int(data.at("ai_systems_high_risk", default: 0))

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 8pt,
  tc-kpi(str(ai_total), "Total IA"),
  tc-kpi(str(ai_declared), "Déclarées"),
  tc-kpi(str(ai_detected), "Shadow (détectées)"),
  tc-kpi(str(ai_high_risk), "High-risk"),
)

#v(8pt)

Article 12 du règlement impose le logging automatique des systèmes high-risk (Annex III).
Chaque IA utilisée dans les domaines RH, crédit, éducation, police, santé doit disposer
d'un audit trail complet.

// ── Gaps ──
#tc-section("Contrôles non couverts (gaps)")

#let gaps = data.at("gaps", default: ())
#if gaps.len() == 0 [
  #text(fill: tc-green)[✓ Aucun gap identifié — posture EU AI Act conforme]
] else [
  #for gap in gaps [
    - *#gap.id* — #gap.title #tc-badge("GAP", "high")
  ]
]

// ── Détail par contrôle ──
#tc-section("Détail des contrôles EU AI Act")

#let articles = data.at("articles", default: ())
#for a in articles [
  #let score = int(a.at("score", default: 50))
  #grid(
    columns: (1fr, auto),
    [
      *#a.id — #a.title*
      #v(2pt)
      #text(size: 8pt, fill: tc-gray)[#a.description]
      #if a.at("top_recommendation", default: none) != none [
        #v(3pt)
        #text(size: 8pt, fill: tc-blue)[→ #a.top_recommendation]
      ]
    ],
    align(right)[
      #text(size: 12pt, weight: "bold",
        fill: if score >= 80 { tc-green } else if score >= 50 { tc-amber } else { tc-red })[#score/100]
      #v(2pt)
      #text(size: 7pt, fill: tc-gray)[#a.at("relevant_findings", default: 0) findings]
    ]
  )
  #v(8pt)
]

// ── Actions prioritaires ──
#tc-section("Plan d'actions prioritaires")

#let actions = data.at("priority_actions", default: ())
#if actions.len() == 0 [
  #text(fill: tc-gray)[Aucune action prioritaire identifiée.]
] else [
  #enum(
    ..for a in actions {
      ([#a],)
    }
  )
]

#v(8pt)

*Sanctions encourues* : jusqu'à 35 M€ ou 7% du chiffre d'affaires mondial (Art.99).
Entrée en vigueur des obligations high-risk : *2 août 2026*.

#tc-footer(data.at("company_name", default: "Organisation"))

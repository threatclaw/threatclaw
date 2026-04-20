// ThreatClaw — ISO/IEC 42001:2023 AI Management System Assessment
// Mapping des 8 contrôles Annex A retenus (A.2, A.4-A.10)

#import "common.typ": *

#let data = json("data.json")

#set page(paper: "a4", margin: (top: 18mm, bottom: 20mm, left: 15mm, right: 15mm))
#set text(font: "Noto Sans", size: 10pt)

#tc-header(
  "ISO/IEC 42001:2023 — ASSESSMENT",
  data.at("company_name", default: "Organisation"),
  subtitle: "AI Management System — Annex A controls",
)

// ── Overall score ──
#tc-section("Score global AI Management System")

#let overall = int(data.at("overall_score", default: 50))
#tc-score-box(float(overall))

#v(6pt)
Posture évaluée sur 8 contrôles Annex A (A.2, A.4-A.10), avec focus
third-party AI relationships (A.10) et AI usage policy (A.9) pour l'angle
shadow AI detection ThreatClaw.

Maturité : *#data.at("maturity_label", default: "Initial")*.

// ── Gaps ──
#tc-section("Contrôles en gap (score < 50)")

#let gaps = data.at("gaps", default: ())
#if gaps.len() == 0 [
  #text(fill: tc-green)[✓ Tous les contrôles au-dessus du seuil de gap]
] else [
  #for g in gaps [
    - *#g* — contrôle à adresser
  ]
]

// ── Control-by-control breakdown ──
#tc-section("Détail par contrôle Annex A")

#let controls = data.at("articles", default: ())
#for ctrl in controls [
  #let score = int(ctrl.at("score", default: 50))
  #let color = if score >= 80 { tc-green } else if score >= 50 { tc-amber } else { tc-red }

  #block(
    fill: rgb("#fafafa"),
    inset: 10pt,
    radius: 4pt,
    width: 100%,
  )[
    #grid(
      columns: (1fr, auto),
      [
        #text(weight: "bold")[#ctrl.id — #ctrl.title]
        #v(3pt)
        #text(size: 8pt, fill: tc-gray)[#ctrl.description]
      ],
      align(right)[
        #text(size: 14pt, weight: "bold", fill: color)[#score/100]
      ]
    )

    #v(4pt)

    #grid(
      columns: (auto, auto, auto, auto),
      gutter: 10pt,
      text(size: 8pt, fill: tc-gray)[Findings: #ctrl.at("relevant_findings", default: 0)],
      text(size: 8pt, fill: tc-red)[Critical: #ctrl.at("critical_hits", default: 0)],
      text(size: 8pt, fill: rgb("#d07020"))[High: #ctrl.at("high_hits", default: 0)],
      text(size: 8pt, fill: tc-amber)[Medium: #ctrl.at("medium_hits", default: 0)],
    )

    #if ctrl.at("top_recommendation", default: none) != none [
      #v(4pt)
      #text(size: 9pt, fill: tc-blue)[→ #ctrl.top_recommendation]
    ]
  ]
  #v(6pt)
]

// ── Evidence & roadmap ──
#tc-section("Traçabilité (A.6.2.6 evidence index)")

ThreatClaw matérialise l'exigence d'evidence index d'ISO 42001 A.6.2.6 via :
- Le log immuable *agent_audit_log* (trigger plpgsql, hash-chain, V16)
- Les *evidence_citations* dans chaque verdict LLM (Phase 4 grounding v1.1)
- La traçabilité Sigma → finding → reconciliation log (Phase 3)

#v(4pt)

Le bouton "Audit Trail" de l'onglet Rapports exporte le journal complet avec
hash-chain pour audit ISO 27001 + 42001.

#v(8pt)

#text(size: 8pt, fill: tc-gray)[
  Référence : ISO/IEC 42001:2023 — AI management systems — Requirements.
  Publication officielle ISO. Annex A controls, Annex B guidance.
]

#tc-footer(data.at("company_name", default: "Organisation"))

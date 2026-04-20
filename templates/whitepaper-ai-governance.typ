// ThreatClaw — AI Governance Whitepaper
// Document corporate 12-15 pages agrégeant toute la posture IA :
// shadow AI detection + inventaire + conformité multi-framework + roadmap

#import "common.typ": *

#let data = json("data.json")

#set page(paper: "a4", margin: (top: 20mm, bottom: 22mm, left: 18mm, right: 18mm))
#set text(font: "Noto Sans", size: 10pt)
#set par(justify: true, leading: 0.65em)

// ─────────────────────────────────────────────────────────
// COVER PAGE
// ─────────────────────────────────────────────────────────

#align(center)[
  #v(50pt)
  #text(size: 32pt, weight: "bold", fill: tc-red, tracking: 0.1em)[THREATCLAW]
  #v(4pt)
  #text(size: 10pt, fill: tc-gray)[#L.brand_tagline]
  #v(80pt)
  #text(size: 22pt, weight: "bold", fill: tc-dark)[AI GOVERNANCE]
  #v(8pt)
  #text(size: 22pt, weight: "bold", fill: tc-dark)[WHITEPAPER]
  #v(12pt)
  #text(size: 12pt, fill: tc-gray, style: "italic")[Livre blanc — posture IA & conformité réglementaire]
  #v(120pt)
  #text(size: 13pt, weight: "bold")[#data.at("company_name", default: "Organisation")]
  #v(6pt)
  #text(size: 10pt, fill: tc-gray)[
    #datetime.today().display("[day]/[month]/[year]")
  ]
  #v(60pt)
  #text(size: 8pt, fill: tc-gray)[
    Confidentiel — Usage interne
  ]
]

#pagebreak()

// ─────────────────────────────────────────────────────────
// 1 — EXECUTIVE SUMMARY
// ─────────────────────────────────────────────────────────

#tc-header(
  "1. Résumé exécutif",
  data.at("company_name", default: "Organisation"),
  subtitle: "Posture IA synthétique",
)

L'adoption massive de systèmes d'intelligence artificielle tiers
(ChatGPT, Claude, Gemini, Mistral, Copilot, GitHub Copilot, Cursor…)
et locaux (Ollama, vLLM, LM Studio) transforme la surface d'attaque
et le périmètre d'audit des organisations.

Ce document présente la *posture IA* de votre organisation telle que
mesurée automatiquement par ThreatClaw, couvrant quatre axes :

+ *Détection shadow AI* : usages IA non-autorisés observés via le
  trafic réseau Zeek (SNI/DNS/ports) et corrélés avec les politiques
  organisationnelles.

+ *Inventaire IA* : systèmes déclarés par le RSSI + systèmes détectés
  automatiquement par `skill-shadow-ai-monitor`.

+ *Conformité multi-framework* : NIS2 Art.21 §2, ISO 27001:2022,
  ISO/IEC 42001:2023, NIST AI RMF 1.0 (révision 2025 — shadow AI
  explicitly named), EU AI Act (Règlement UE 2024/1689).

+ *Traçabilité & evidence index* : log immuable V16 hash-chaîné,
  citations d'evidence Phase 4 grounding v1.1, reconciliation log.

#v(10pt)

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 8pt,
  tc-kpi(str(data.at("shadow_ai_findings", default: 0)), "Shadow AI ouverts"),
  tc-kpi(str(data.at("ai_systems_total", default: 0)), "Systèmes IA"),
  tc-kpi(str(int(data.at("compliance_avg", default: 50))) + "/100", "Conformité"),
  tc-kpi(str(data.at("critical_findings", default: 0)), "Findings critiques"),
)

#v(16pt)

== Recommandations top-3

#let top_recos = data.at("top_recommendations", default: ())
#if top_recos.len() == 0 [
  #text(fill: tc-gray)[Aucune recommandation prioritaire générée.]
] else [
  #enum(
    ..for r in top_recos {
      ([#r],)
    }
  )
]

#pagebreak()

// ─────────────────────────────────────────────────────────
// 2 — AI SYSTEM INVENTORY
// ─────────────────────────────────────────────────────────

#tc-header(
  "2. Inventaire IA",
  data.at("company_name", default: "Organisation"),
  subtitle: "Systèmes déclarés + détectés en shadow",
)

ThreatClaw maintient un inventaire unifié des IA utilisées dans
l'organisation. Chaque système passe par un cycle de vie :
*detected* → *declared* → *assessed* → *retired*.

#v(8pt)

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 8pt,
  tc-kpi(str(data.at("ai_systems_total", default: 0)), "Total"),
  tc-kpi(str(data.at("ai_systems_detected", default: 0)), "Détectés"),
  tc-kpi(str(data.at("ai_systems_declared", default: 0)), "Déclarés"),
  tc-kpi(str(data.at("ai_systems_assessed", default: 0)), "Évalués"),
)

#v(16pt)

=== Systèmes IA observés

#let systems = data.at("ai_systems", default: ())
#if systems.len() == 0 [
  #text(fill: tc-gray, style: "italic")[
    Aucun système IA détecté à ce jour. Activez le pipeline
    `skill-shadow-ai-monitor` via la cron 5min pour population
    automatique.
  ]
] else [
  #table(
    columns: (1fr, 1fr, auto, auto, auto),
    inset: 6pt,
    stroke: 0.5pt + rgb("#dddddd"),
    align: (left, left, center, center, left),
    [*Provider*], [*Endpoint*], [*Catégorie*], [*Statut*], [*Risk level*],
    ..for s in systems {
      (
        [#s.at("provider", default: "—")],
        text(size: 8pt)[#s.at("endpoint", default: "—")],
        [#s.at("category", default: "—")],
        [#s.at("status", default: "—")],
        [#s.at("risk_level", default: "—")],
      )
    }
  )
]

#pagebreak()

// ─────────────────────────────────────────────────────────
// 3 — COMPLIANCE POSTURE (4 frameworks)
// ─────────────────────────────────────────────────────────

#tc-header(
  "3. Posture de conformité",
  data.at("company_name", default: "Organisation"),
  subtitle: "NIS2 / ISO 27001 / ISO 42001 / NIST AI RMF",
)

Les scores sont calculés en temps réel à partir des findings et
alertes ouverts, via les modules natifs Rust `src/compliance/*`.

#v(10pt)

#let reports = data.at("compliance_reports", default: ())

#for report in reports [
  #let score = int(report.at("overall_score", default: 50))
  #let color = if score >= 80 { tc-green } else if score >= 50 { tc-amber } else { tc-red }

  === #report.framework_label

  #grid(
    columns: (auto, 1fr),
    gutter: 16pt,
    [
      #box(inset: (x: 16pt, y: 10pt), radius: 6pt,
        fill: if score >= 80 { rgb("#e8f5e9") } else if score >= 50 { rgb("#fff8e1") } else { rgb("#ffebee") },
        stroke: 2pt + color,
      )[
        #text(size: 20pt, weight: "bold", fill: color)[#score/100]
      ]
      #v(4pt)
      #text(size: 9pt, fill: tc-gray)[#report.maturity_label]
    ],
    [
      Total findings analysés : *#report.at("total_findings", default: 0)*.
      Dont critiques : *#report.at("critical_findings", default: 0)*.
      Gaps (score < 50) : *#report.at("gaps", default: ()).len()*.

      #v(6pt)

      #let items = report.at("articles", default: ())
      #if items.len() > 0 [
        Articles/contrôles couverts : #items.len().
      ]
    ]
  )

  #v(10pt)
]

#pagebreak()

// ─────────────────────────────────────────────────────────
// 4 — SHADOW AI DEEP DIVE
// ─────────────────────────────────────────────────────────

#tc-header(
  "4. Shadow AI — analyse détaillée",
  data.at("company_name", default: "Organisation"),
  subtitle: "Usages non-autorisés détectés",
)

Le module `skill-shadow-ai-monitor` observe passivement le trafic réseau
(Zeek ssl.log, dns.log, conn.log, http.log) et qualifie automatiquement
les hits Sigma `shadow-ai-001..004` en findings `AI_USAGE_POLICY`.

*Zéro MITM TLS, zéro agent endpoint* — la détection repose sur le SNI
(tant qu'ECH n'est pas généralisé), les résolutions DNS, et les ports
par défaut des runtimes self-hosted (Ollama 11434, vLLM 8000, LM Studio
1234/43411, Jan 1337, GPT4All 4891, TextGen 7860).

#v(8pt)

#grid(
  columns: (1fr, 1fr, 1fr),
  gutter: 8pt,
  tc-kpi(str(data.at("shadow_ai_findings", default: 0)), "Findings ouverts"),
  tc-kpi(str(data.at("shadow_ai_providers", default: 0)), "Providers distincts"),
  tc-kpi(str(data.at("shadow_ai_assets", default: 0)), "Assets concernés"),
)

#v(12pt)

=== Violations récentes

#let shadow_findings = data.at("shadow_ai_latest", default: ())
#if shadow_findings.len() == 0 [
  #text(fill: tc-green)[✓ Aucune violation shadow AI ouverte]
] else [
  #table(
    columns: (auto, 1fr, auto, auto),
    inset: 6pt,
    stroke: 0.5pt + rgb("#dddddd"),
    align: (left, left, center, center),
    [*Date*], [*Provider / Endpoint*], [*Asset*], [*Sévérité*],
    ..for f in shadow_findings {
      (
        text(size: 8pt)[#f.at("detected_at", default: "—")],
        [#f.at("title", default: "Shadow AI")],
        text(size: 8pt)[#f.at("asset", default: "—")],
        tc-badge(f.at("severity", default: "medium"), f.at("severity", default: "medium")),
      )
    }
  )
]

#pagebreak()

// ─────────────────────────────────────────────────────────
// 5 — REGULATORY MAPPING
// ─────────────────────────────────────────────────────────

#tc-header(
  "5. Alignement réglementaire",
  data.at("company_name", default: "Organisation"),
  subtitle: "EU AI Act / NIS2 / ISO / NIST",
)

== EU AI Act (Règlement UE 2024/1689)

- *Art. 9* — Gestion continue des risques IA
- *Art. 12* — Logging automatique obligatoire pour systèmes high-risk
  (RH, crédit, éducation, police, santé)
- *Art. 13-14* — Transparence et supervision humaine
- *Art. 99* — Sanctions : jusqu'à 35 M€ ou 7% du CA mondial

*Date clé* : 2 août 2026 — entrée en vigueur des obligations high-risk.

#v(6pt)

== NIS2 (Directive UE 2022/2555)

- *Art. 21 §2(d)* — Sécurité de la chaîne d'approvisionnement
  (inclut les IA tierces selon lecture ANSSI/ENISA 2025)
- *Art. 21 §2(e)* — Sécurité dans l'acquisition, développement et maintenance
- *Art. 23* — Notification d'incident : 24h / 72h / 1 mois

#v(6pt)

== ISO/IEC 42001:2023

Première norme dédiée à l'AI Management System. Contrôles Annex A
pertinents :
- *A.2* — AI policy
- *A.5* — Impact assessment (ISO 42005)
- *A.6.2.6* — Evidence index
- *A.9* — Use of AI systems
- *A.10* — Third-party AI relationships

#v(6pt)

== NIST AI RMF 1.0 (mise à jour 2025)

4 fonctions : *Govern*, *Map*, *Measure*, *Manage*. La révision
2025 ajoute explicitement shadow AI dans le contrôle d'inventaire
(MAP).

#pagebreak()

// ─────────────────────────────────────────────────────────
// 6 — ROADMAP DE REMÉDIATION
// ─────────────────────────────────────────────────────────

#tc-header(
  "6. Roadmap de remédiation",
  data.at("company_name", default: "Organisation"),
  subtitle: "Plan d'action 3-6-12 mois",
)

== Horizon 3 mois (quick wins)

- Déclarer les IA détectées en shadow via l'onglet Governance
- Documenter la politique d'usage IA (providers autorisés / interdits)
- Activer le blocage firewall/DNS des providers hors whitelist
- Former les équipes sensibles (R&D, RH, juridique)

== Horizon 6 mois (structurel)

- Impact assessment (ISO 42005) pour chaque IA classée high-risk
- Contractualisation avec les fournisseurs IA utilisés
- Intégration Langfuse pour audit trail complet (Phase 5 grounding)
- Mise en place DLP sortant sur les prompts (si tolérable)

== Horizon 12 mois (maturité)

- Certification ISO/IEC 42001:2023
- Red-teaming récurrent (Garak, MITRE ATLAS)
- AgentPrint-inspired fingerprinting (inter-token timing)
- Publication transparence annuelle

#v(12pt)

// ─────────────────────────────────────────────────────────
// 7 — ANNEXES
// ─────────────────────────────────────────────────────────

#tc-section("Annexe — Méthodologie ThreatClaw")

Les scores de conformité sont calculés par des fonctions Rust pures
`src/compliance/*.rs` — reproductibles, auditables, open source.

Pour chaque article/contrôle :
- Scan des findings avec mapping keywords (title, description, category, skill_id)
- Pondération par sévérité : critical × 15 + high × 8 + medium × 3
- Score final : `max(0, 100 - penalty)`
- Si aucune evidence : score = 50 (pas de confiance aveugle)

#v(8pt)

#text(size: 8pt, fill: tc-gray)[
  Ce document est généré automatiquement par ThreatClaw à partir des données
  de votre instance. La posture reflète l'état à l'instant
  #datetime.today().display("[day]/[month]/[year]"). Régénérez ce livre blanc
  après modifications significatives pour obtenir une vision à jour.
]

#tc-footer(data.at("company_name", default: "Organisation"))

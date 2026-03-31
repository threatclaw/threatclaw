// ThreatClaw — NIST SP 800-61 Rev 3 Incident Report
// Aligned with NIST CSF 2.0 (Detect / Respond / Recover)
// Data elements from SP 800-61r2 Appendix B + CSF 2.0 subcategories

#import "common.typ": *

#let data = json("data.json")

#set page(paper: "a4", margin: (top: 18mm, bottom: 20mm, left: 15mm, right: 15mm))
#set text(font: "Noto Sans", size: 10pt)

// ── Header ──
#grid(
  columns: (1fr, auto),
  align: (left, right),
  [
    #text(size: 22pt, weight: "bold", fill: tc-red, tracking: 0.1em)[THREATCLAW]
    #v(2pt)
    #text(size: 8pt, fill: tc-gray)[Autonomous Cybersecurity Agent]
  ],
  [
    #text(size: 12pt, weight: "bold", fill: tc-dark)[#data.at("org_name", default: "Organization")]
    #v(2pt)
    #text(size: 9pt, fill: tc-gray)[#data.at("generated_at_display", default: datetime.today().display("[day]/[month]/[year]"))]
  ],
)
#v(6pt)
#line(length: 100%, stroke: 2pt + tc-red)
#v(8pt)

#text(size: 16pt, weight: "bold", fill: tc-red)[INCIDENT RESPONSE REPORT]
#v(2pt)
#text(size: 10pt, fill: tc-gray)[NIST SP 800-61 Rev 3 — CSF 2.0 Aligned]
#v(8pt)

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Incident ID*], text(font: "Noto Sans Mono", size: 9pt)[#data.at("incident_id", default: "—")],
  [*Report Date*], data.at("generated_at_display", default: "—"),
  [*Classification*], [TLP:AMBER — Internal Use Only],
)

// ── 1. Reporter Information (GV) ──
#tc-section("1. Reporter Information")

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Organization*], data.at("org_name", default: "—"),
  [*Sector*], data.at("sector", default: "—"),
  [*Handler / Contact*], data.at("security_contact", default: "—"),
  [*Email*], data.at("contact_email", default: "—"),
  [*Phone*], data.at("contact_phone", default: "—"),
)

// ── 2. Incident Overview (DE.AE) ──
#tc-section("2. Incident Overview — Detect (DE.AE)")

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 10pt,
  tc-kpi(data.at("alerts_count", default: "0"), "ALERTS"),
  tc-kpi(data.at("findings_count", default: "0"), "FINDINGS"),
  tc-kpi(data.at("assets_count", default: "0"), "AFFECTED ASSETS"),
  tc-kpi(data.at("score", default: "100"), "SECURITY SCORE"),
)

#v(6pt)
#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Date/Time Detected (DE.AE-02)*], data.at("detected_at", default: "—"),
  [*Date/Time Reported*], data.at("notified_at", default: data.at("generated_at_display", default: "—")),
  [*Current Status (RS.MA-01)*], data.at("incident_status_label", default: "—"),
  [*Incident Category (DE.AE-04)*], data.at("incident_type_label", default: "—"),
  [*Severity*], data.at("severity", default: "—"),
  [*Source of Incident*], data.at("attack_vector", default: "Under investigation"),
)

#v(4pt)
*Description:*
#data.at("incident_description", default: "—")

// ── 3. Affected Resources (ID.AM) ──
#tc-section("3. Affected Resources — Identify (ID.AM)")

#let assets = data.at("affected_assets", default: ())
#if assets.len() > 0 [
  #table(
    columns: (1fr, auto, auto, auto),
    stroke: 0.5pt + rgb("#e0e0e0"),
    fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
    [#text(fill: white, weight: "bold", size: 8pt)[Asset]],
    [#text(fill: white, weight: "bold", size: 8pt)[Category]],
    [#text(fill: white, weight: "bold", size: 8pt)[Criticality]],
    [#text(fill: white, weight: "bold", size: 8pt)[IP Address]],
    ..assets.map(a => (
      text(size: 9pt)[#a.at("name", default: "—")],
      text(size: 9pt)[#a.at("category", default: "—")],
      text(size: 9pt, weight: "bold")[#a.at("criticality", default: "—")],
      text(size: 9pt, font: "Noto Sans Mono")[#a.at("ip", default: "—")],
    )).flatten()
  )
] else [
  No assets identified in the affected scope at this time.
]

// ── 4. Indicators of Compromise (DE.AE-04) ──
#tc-section("4. Indicators of Compromise — Detect (DE.AE-04)")

#let iocs = data.at("iocs", default: ())
#if iocs.len() > 0 [
  #table(
    columns: (auto, 1fr, auto, auto),
    stroke: 0.5pt + rgb("#e0e0e0"),
    fill: (_, row) => if row == 0 { tc-red } else if calc.rem(row, 2) == 0 { tc-light } else { white },
    [#text(fill: white, weight: "bold", size: 8pt)[Type]],
    [#text(fill: white, weight: "bold", size: 8pt)[Value]],
    [#text(fill: white, weight: "bold", size: 8pt)[Source]],
    [#text(fill: white, weight: "bold", size: 8pt)[Confidence]],
    ..iocs.map(ioc => (
      text(size: 8pt, weight: "bold")[#ioc.at("type", default: "—")],
      text(size: 8pt, font: "Noto Sans Mono")[#ioc.at("value", default: "—")],
      text(size: 8pt)[#ioc.at("source", default: "—")],
      text(size: 8pt)[#ioc.at("confidence", default: "—")],
    )).flatten()
  )
] else [
  No confirmed IoCs at this stage. CTI enrichment in progress.
]

// ── 5. Analysis (RS.AN) ──
#tc-section("5. Incident Analysis — Respond (RS.AN)")

*Root Cause (RS.AN-03):*
#data.at("root_cause", default: "Under investigation by ThreatClaw Engine.")

#v(4pt)
*Attack Vector:*
#data.at("attack_vector", default: "Under investigation")

#v(4pt)
*MITRE ATT&CK TTPs:*
#let ttps = data.at("mitre_ttps", default: ())
#if ttps.len() == 0 [
  No TTPs identified at this stage.
] else [
  #for ttp in ttps [
    - #ttp
  ]
]

// ── 6. Impact Assessment (RS.AN-02) ──
#tc-section("6. Impact Assessment — Respond (RS.AN-02)")

#table(
  columns: (180pt, 1fr),
  stroke: 0.5pt + rgb("#e0e0e0"),
  fill: (col, _) => if col == 0 { tc-light } else { white },
  [*Functional Impact*], data.at("operational_impact", default: "Under evaluation"),
  [*Information Impact*], data.at("data_exposed", default: "No data exposure identified"),
  [*Estimated Cost*], data.at("financial_impact", default: "Under evaluation"),
  [*Recoverability*], data.at("recoverability", default: "Recoverable"),
)

// ── 7. Actions Taken (RS.MI) ──
#tc-section("7. Mitigation Actions — Respond (RS.MI)")

#let actions = data.at("corrective_measures", default: ())
#if actions.len() == 0 [
  + Automated detection by ThreatClaw Engine (5-minute cycle)
  + Behavioral analysis (ML) active on all assets
  + IOC enrichment via CTI sources
  + Attack graph correlation (Apache AGE)
  + Preventive IP blocking
] else [
  #for a in actions [
    + #a
  ]
]

// ── 8. Recommendations (RC.RP) ──
#tc-section("8. Recommendations — Recover (RC.RP)")

#let recommendations = data.at("lessons_learned", default: ())
#if recommendations.len() == 0 [
  + Enforce critical patching within 48 hours
  + Enable multi-factor authentication on all access points
  + Implement strict network segmentation
  + Schedule regular penetration testing
  + Maintain continuous monitoring via ThreatClaw Engine
] else [
  #for r in recommendations [
    + #r
  ]
]

// ── Footer ──
#v(16pt)
#line(length: 100%, stroke: 0.5pt + rgb("#dddddd"))
#v(4pt)
#text(size: 7pt, fill: tc-gray)[
  This report is aligned with NIST SP 800-61 Revision 3 (April 2025) and NIST Cybersecurity Framework 2.0.
  #linebreak()
  CSF functions referenced: Govern (GV), Identify (ID), Detect (DE), Respond (RS), Recover (RC).
  #linebreak()
  Generated automatically by ThreatClaw v2.0 — #datetime.today().display("[day]/[month]/[year]")
  #linebreak()
  CONFIDENTIAL — For authorized recipients only.
]

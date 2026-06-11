/**
 * AttackTimeline — Phase 4 UI (refactor Phase 10b)
 *
 * Affiche les données factuelles d'enrichissement d'un incident :
 *  - lignes firewall cross-correlation (Suricata + pf logs OPNsense/Fortinet/etc.)
 *    récupérées par dossier_enrichment::enrich_firewall_logs
 *  - réputations IP source (Spamhaus, ThreatFox, GreyNoise)
 *  - détails CVE (CVSS, EPSS, KEV badges)
 *
 * Consomme `incident.enrichment` retourné par `GET /api/tc/incidents/:id`.
 * Le payload backend est sérialisé depuis le `EnrichmentBundle` de l'incident
 * (voir migration V71 et `roadmap-mai.md` Phase 4).
 *
 * Aucune donnée n'est inventée côté UI — on affiche uniquement ce que le
 * backend a peuplé (cohérent avec la doctrine anti-hallucination).
 *
 * Phase 10b — refactor pour utiliser les classes/variables CSS de la page
 * investigate (`.inv-card`, `var(--tc-*)`) au lieu des classes Tailwind.
 * Le titre "Chronologie d'attaque enrichie" était trompeur (ce bloc n'est
 * pas une vraie chronologie temporelle), il devient "Données factuelles".
 */

import React from "react";
import { t as tr, type Locale } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";

// ── Types miroirs des structs Rust ────────────────────────────────

export interface IpReputation {
  ip: string;
  is_malicious: boolean;
  classification: string;
  source: string;
  details: string;
}

export interface CveDetail {
  cve_id: string;
  cvss_score: number | null;
  epss_score: number | null;
  is_kev: boolean;
  description: string;
}

export interface ThreatIntelMatch {
  indicator: string;
  indicator_type: string;
  source: string;
  threat_type: string;
  malware: string | null;
  confidence: number;
}

export interface EnrichmentBundle {
  ip_reputations?: IpReputation[];
  cve_details?: CveDetail[];
  threat_intel?: ThreatIntelMatch[];
  enrichment_lines?: string[];
}

interface Props {
  enrichment: EnrichmentBundle | null | undefined;
  /**
   * Phase 9h — when set, the CVE block links to the asset's posture page
   * for the complete vulnerability inventory. Without it, the section
   * still renders but has no way to redirect the operator to the static
   * exposure view.
   */
  assetId?: string;
  /**
   * Phase 9h — `true` when the incident is driven by at least one
   * sigma alert (live attack signal). Used to render the "no CVE
   * directly tied to this attack" notice instead of an empty section,
   * since Phase 9e filters predictive software-vuln findings out of
   * `enrichment.cve_details` for sigma-driven incidents.
   */
  sigmaDriven?: boolean;
}

// ── Helpers couleurs (alignées sur la palette ThreatClaw) ─────────

function classificationColor(rep: IpReputation): {
  border: string;
  bg: string;
  fg: string;
} {
  if (rep.is_malicious || rep.classification === "malicious") {
    return { border: "#ff6030", bg: "rgba(255,96,48,0.08)", fg: "#ff6030" };
  }
  if (rep.classification === "benign") {
    return { border: "#30a050", bg: "rgba(48,160,80,0.08)", fg: "#30a050" };
  }
  if (rep.classification === "noise" || rep.classification === "scanner") {
    return { border: "#e0a020", bg: "rgba(224,160,32,0.08)", fg: "#e0a020" };
  }
  return {
    border: "var(--tc-border)",
    bg: "transparent",
    fg: "var(--tc-text-sec)",
  };
}

function cveSeverityColor(cvss: number | null): { bg: string; fg: string } {
  if (cvss === null) return { bg: "var(--tc-surface-alt)", fg: "var(--tc-text-muted)" };
  if (cvss >= 9) return { bg: "rgba(255,32,32,0.15)", fg: "#ff2020" };
  if (cvss >= 7) return { bg: "rgba(255,96,48,0.15)", fg: "#ff6030" };
  if (cvss >= 4) return { bg: "rgba(224,160,32,0.15)", fg: "#e0a020" };
  return { bg: "var(--tc-surface-alt)", fg: "var(--tc-text-muted)" };
}

function epssBadge(epss: number | null): React.ReactElement | null {
  if (epss === null) return null;
  const pct = (epss * 100).toFixed(1);
  const c =
    epss > 0.8
      ? { bg: "rgba(255,96,48,0.15)", fg: "#ff6030" }
      : epss > 0.5
        ? { bg: "rgba(224,160,32,0.15)", fg: "#e0a020" }
        : { bg: "var(--tc-surface-alt)", fg: "var(--tc-text-muted)" };
  return (
    <span style={badgeStyle(c.bg, c.fg)}>EPSS {pct}%</span>
  );
}

const sectionLabelStyle: React.CSSProperties = {
  fontSize: 9,
  fontWeight: 700,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  color: "var(--tc-text-muted)",
  fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
  padding: "10px 14px 6px",
};

const rowStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 10,
  padding: "8px 14px",
  fontSize: 12,
  fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
  borderTop: "1px dashed var(--tc-border)",
};

function badgeStyle(bg: string, fg: string): React.CSSProperties {
  return {
    fontSize: 10,
    fontWeight: 700,
    fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
    padding: "1px 6px",
    background: bg,
    color: fg,
    border: `1px solid ${fg === "#ff2020" || fg === "#ff6030" || fg === "#e0a020" || fg === "#30a050" ? fg + "44" : "var(--tc-border)"}`,
    textTransform: "uppercase",
    letterSpacing: "0.05em",
  };
}

// ── Composant ─────────────────────────────────────────────────────

export function AttackTimeline({
  enrichment,
  assetId,
  sigmaDriven,
}: Props): React.ReactElement | null {
  const locale = useLocale();
  if (!enrichment) return null;

  const ipReps = enrichment.ip_reputations ?? [];
  const cves = enrichment.cve_details ?? [];
  const threatIntel = enrichment.threat_intel ?? [];
  const lines = enrichment.enrichment_lines ?? [];

  // Phase 9h — render the attack-vs-posture notice on a sigma-driven
  // incident even when every other section is empty, so the operator
  // never sees a silent "no CVE here" without context.
  const showCveSection = cves.length > 0 || sigmaDriven === true;

  if (
    ipReps.length === 0 &&
    !showCveSection &&
    threatIntel.length === 0 &&
    lines.length === 0
  ) {
    return null;
  }

  return (
    <div className="inv-card">
      <div className="inv-card-head">
        <div className="inv-card-head-left">
          <strong>{tr("attackTimeline_factualData", locale)}</strong>{" "}
          {tr("attackTimeline_externalEnrichmentSuffix", locale)}
        </div>
        <div className="inv-card-head-right">
          {tr("attackTimeline_externalSourcesConnectedSkills", locale)}
        </div>
      </div>

      {ipReps.length > 0 && (
        <>
          <div style={sectionLabelStyle}>{tr("attackTimeline_ipSourceReputations", locale)}</div>
          {ipReps.map((rep, i) => {
            const c = classificationColor(rep);
            return (
              <div
                key={`${rep.ip}-${rep.source}-${i}`}
                style={{
                  ...rowStyle,
                  background: c.bg,
                  color: c.fg,
                  borderLeft: `2px solid ${c.border}`,
                }}
              >
                <span style={{ fontWeight: 600 }}>{rep.ip}</span>
                <span
                  style={{
                    fontSize: 10,
                    color: "var(--tc-text-muted)",
                    textTransform: "uppercase",
                    letterSpacing: "0.05em",
                  }}
                >
                  {rep.source}
                </span>
                <span style={{ marginLeft: "auto", fontSize: 11 }}>
                  {rep.classification}
                  {rep.details ? ` — ${rep.details}` : ""}
                </span>
              </div>
            );
          })}
        </>
      )}

      {showCveSection && (
        <>
          <div style={sectionLabelStyle}>{tr("attackTimeline_vulnsTiedToAttack", locale)}</div>
          {cves.length > 0 ? (
            cves.map((cve, i) => {
              const sev = cveSeverityColor(cve.cvss_score);
              return (
                <div
                  key={`${cve.cve_id}-${i}`}
                  style={{
                    ...rowStyle,
                    flexWrap: "wrap",
                    color: "var(--tc-text-sec)",
                  }}
                >
                  <span style={{ color: "var(--tc-text)", fontWeight: 600 }}>
                    {cve.cve_id}
                  </span>
                  {cve.cvss_score !== null && (
                    <span style={badgeStyle(sev.bg, sev.fg)}>
                      CVSS {cve.cvss_score.toFixed(1)}
                    </span>
                  )}
                  {epssBadge(cve.epss_score)}
                  {cve.is_kev && (
                    <span style={badgeStyle("rgba(255,32,32,0.15)", "#ff2020")}>
                      CISA KEV
                    </span>
                  )}
                  {cve.description && (
                    <span
                      style={{
                        fontSize: 11,
                        color: "var(--tc-text-muted)",
                        marginLeft: 4,
                        flex: 1,
                      }}
                    >
                      {cve.description}
                    </span>
                  )}
                </div>
              );
            })
          ) : (
            // Phase 9h — sigma-driven incident with no CVE pinned to the
            // attack. Make it explicit so the operator doesn't think we
            // missed something. The asset's full vuln posture is one click
            // away on the asset page.
            <div
              style={{
                padding: "10px 14px",
                fontSize: 12,
                fontStyle: "italic",
                color: "var(--tc-text-muted)",
                borderTop: "1px dashed var(--tc-border)",
              }}
            >
              {tr("attackTimeline_noCveTiedToAttack", locale)}
            </div>
          )}
          {assetId && (
            <div
              style={{
                padding: "6px 14px 10px",
                fontSize: 11,
                fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
              }}
            >
              <a
                href={`/assets/${encodeURIComponent(assetId)}`}
                style={{
                  color: "var(--tc-red)",
                  textDecoration: "none",
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLAnchorElement).style.textDecoration =
                    "underline";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLAnchorElement).style.textDecoration =
                    "none";
                }}
              >
                {tr("attackTimeline_viewAssetVulnPosture", locale)}
              </a>
            </div>
          )}
        </>
      )}

      {threatIntel.length > 0 && (
        <>
          <div style={sectionLabelStyle}>Threat intel</div>
          {threatIntel.map((ti, i) => (
            <div
              key={`${ti.indicator}-${ti.source}-${i}`}
              style={{
                ...rowStyle,
                background: "rgba(224,160,32,0.05)",
                borderLeft: "2px solid #e0a020",
                color: "#e0a020",
              }}
            >
              <span style={{ fontWeight: 600 }}>{ti.indicator}</span>
              <span
                style={{
                  fontSize: 10,
                  color: "var(--tc-text-muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                {ti.indicator_type}
              </span>
              <span
                style={{ fontSize: 10, color: "var(--tc-text-muted)" }}
              >
                {ti.source}
              </span>
              <span
                style={{
                  marginLeft: "auto",
                  fontSize: 11,
                  color: "var(--tc-text-sec)",
                }}
              >
                {ti.threat_type}
                {ti.malware ? ` · ${ti.malware}` : ""}
              </span>
            </div>
          ))}
        </>
      )}

      {lines.length > 0 && (
        <>
          <div style={sectionLabelStyle}>
            {tr("attackTimeline_crossCorrelationConnectedSkills", locale)}
          </div>
          {lines.map((line, i) => (
            <div
              key={i}
              style={{
                ...rowStyle,
                color: "var(--tc-text-sec)",
                wordBreak: "break-all",
                fontSize: 11,
              }}
            >
              {line}
            </div>
          ))}
        </>
      )}
    </div>
  );
}

export default AttackTimeline;

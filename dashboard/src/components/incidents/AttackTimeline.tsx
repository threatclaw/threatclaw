/**
 * AttackTimeline — Phase 4 UI
 *
 * Affiche la chronologie d'attaque enrichie d'un incident :
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
 */

import React from "react";

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
}

// ── Helpers ───────────────────────────────────────────────────────

function classificationColor(rep: IpReputation): string {
  if (rep.is_malicious || rep.classification === "malicious") {
    return "bg-red-900/40 border-red-700 text-red-200";
  }
  if (rep.classification === "benign") {
    return "bg-emerald-900/40 border-emerald-700 text-emerald-200";
  }
  if (rep.classification === "noise" || rep.classification === "scanner") {
    return "bg-amber-900/40 border-amber-700 text-amber-200";
  }
  return "bg-slate-800/40 border-slate-700 text-slate-300";
}

function cveSeverityColor(cvss: number | null): string {
  if (cvss === null) return "bg-slate-700 text-slate-300";
  if (cvss >= 9) return "bg-red-900/60 text-red-200";
  if (cvss >= 7) return "bg-orange-900/60 text-orange-200";
  if (cvss >= 4) return "bg-amber-900/60 text-amber-200";
  return "bg-slate-700 text-slate-300";
}

function epssBadge(epss: number | null): React.ReactElement | null {
  if (epss === null) return null;
  const pct = (epss * 100).toFixed(1);
  const color =
    epss > 0.8
      ? "bg-red-900/60 text-red-200"
      : epss > 0.5
        ? "bg-orange-900/60 text-orange-200"
        : "bg-slate-700 text-slate-300";
  return (
    <span className={`px-2 py-0.5 text-[11px] rounded ${color}`}>
      EPSS {pct}%
    </span>
  );
}

// ── Composant ─────────────────────────────────────────────────────

export function AttackTimeline({ enrichment }: Props): React.ReactElement | null {
  if (!enrichment) return null;

  const ipReps = enrichment.ip_reputations ?? [];
  const cves = enrichment.cve_details ?? [];
  const threatIntel = enrichment.threat_intel ?? [];
  const lines = enrichment.enrichment_lines ?? [];

  if (
    ipReps.length === 0 &&
    cves.length === 0 &&
    threatIntel.length === 0 &&
    lines.length === 0
  ) {
    return null;
  }

  return (
    <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4 space-y-4">
      <header className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-200">
          Chronologie d&apos;attaque enrichie
        </h3>
        <span className="text-[11px] text-slate-500">
          Données factuelles · sources externes + skills connectés
        </span>
      </header>

      {ipReps.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-[12px] uppercase tracking-wider text-slate-400">
            Réputations IP source
          </h4>
          <ul className="space-y-1.5">
            {ipReps.map((rep, i) => (
              <li
                key={`${rep.ip}-${rep.source}-${i}`}
                className={`flex items-center gap-3 px-3 py-2 rounded border text-sm ${classificationColor(
                  rep,
                )}`}
              >
                <span className="font-mono">{rep.ip}</span>
                <span className="text-[11px] uppercase opacity-70">
                  {rep.source}
                </span>
                <span className="ml-auto text-[12px]">
                  {rep.classification}
                  {rep.details ? ` — ${rep.details}` : ""}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {cves.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-[12px] uppercase tracking-wider text-slate-400">
            Vulnérabilités exploitées ou exploitables
          </h4>
          <ul className="space-y-1.5">
            {cves.map((cve, i) => (
              <li
                key={`${cve.cve_id}-${i}`}
                className="flex flex-wrap items-center gap-2 px-3 py-2 rounded border border-slate-700 bg-slate-900/40 text-sm"
              >
                <span className="font-mono text-slate-200">{cve.cve_id}</span>
                {cve.cvss_score !== null && (
                  <span
                    className={`px-2 py-0.5 text-[11px] rounded ${cveSeverityColor(
                      cve.cvss_score,
                    )}`}
                  >
                    CVSS {cve.cvss_score.toFixed(1)}
                  </span>
                )}
                {epssBadge(cve.epss_score)}
                {cve.is_kev && (
                  <span className="px-2 py-0.5 text-[11px] rounded bg-red-900/60 text-red-200">
                    CISA KEV
                  </span>
                )}
                {cve.description && (
                  <span className="text-[12px] text-slate-400 ml-1">
                    {cve.description}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {threatIntel.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-[12px] uppercase tracking-wider text-slate-400">
            Threat intel
          </h4>
          <ul className="space-y-1.5">
            {threatIntel.map((ti, i) => (
              <li
                key={`${ti.indicator}-${ti.source}-${i}`}
                className="flex items-center gap-3 px-3 py-2 rounded border border-amber-700 bg-amber-900/20 text-sm"
              >
                <span className="font-mono text-amber-200">{ti.indicator}</span>
                <span className="text-[11px] uppercase opacity-70">
                  {ti.indicator_type}
                </span>
                <span className="text-[11px] text-slate-400">{ti.source}</span>
                <span className="ml-auto text-[12px] text-slate-300">
                  {ti.threat_type}
                  {ti.malware ? ` · ${ti.malware}` : ""}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {lines.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-[12px] uppercase tracking-wider text-slate-400">
            Cross-correlation skills connectés
          </h4>
          <ul className="space-y-1 font-mono text-[12px] text-slate-300">
            {lines.map((line, i) => (
              <li
                key={i}
                className="px-3 py-1.5 rounded bg-slate-950/60 border border-slate-800 break-all"
              >
                {line}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

export default AttackTimeline;

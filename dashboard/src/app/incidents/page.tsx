"use client";
// Unified Incidents page — Incidents (confirmed) + Findings (vulns) + Alerts (sigma)
import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { t as tr, localizeFinding, type Locale } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import BlastRadiusCard from "@/components/incidents/BlastRadiusCard";
import SuppressionWizard from "@/components/incidents/SuppressionWizard";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { PageShell } from "@/components/chrome/PageShell";
import {
  AlertTriangle, Shield, Bell, ChevronDown, RefreshCw, CheckCircle2, XCircle,
  Clock, Search, X, FileText, Eye, Zap, Ban, Ticket, UserX, Brain, Filter,
} from "lucide-react";
import { fetchFindings, fetchFindingsCounts, updateFindingStatus, type Finding, type CountEntry } from "@/lib/tc-api";
import { fetchAlerts, fetchAlertsCounts, type Alert } from "@/lib/tc-api";
import type { IncidentAction } from "@/types/incident_action";
import { displayAsset, displayAssetVerbose } from "@/types/asset_display";
import { OperatorDecisionMenu } from "@/components/incidents/OperatorDecisionMenu";

// ═══════════════════════════════════════════════
// INCIDENTS TAB
// ═══════════════════════════════════════════════

// Phase 9a — `IncidentAction` is now imported from `@/types/incident_action`,
// the shared TS mirror of the Rust struct in `src/agent/incident_action.rs`.

interface IncidentNote {
  text: string;
  author: string;
  at: string;
}

/**
 * Phase 4 (v1.1.0-beta): evidence citation attached to a Confirmed verdict.
 * Optional to preserve backward compatibility with incidents created before
 * the phase-4 migration.
 */
export interface EvidenceCitation {
  claim: string;
  evidence_type: "alert" | "finding" | "log" | "graph_node";
  evidence_id: string;
  excerpt?: string;
}

export interface ReachableAsset {
  id: string;
  hops: number;
  total_weight: number;
  criticality: number;
}

export interface BlastRadiusSnapshot {
  origin: string;
  score: number;
  max_hops: number;
  reachable_count: number;
  reachable: ReachableAsset[];
}

// ─────────────────────────────────────────────────────────────────────
// ScanInProgressBadge — small pill on the incident card that lights up
// when scan_queue has a queued/running row for the incident's asset.
// Auto-refreshes every 5s so the badge disappears when the scan
// finishes without forcing the operator to F5.
// ─────────────────────────────────────────────────────────────────────
function ScanInProgressBadge({ assetId, locale }: { assetId: string; locale: Locale }) {
  const [running, setRunning] = React.useState(false);
  React.useEffect(() => {
    let cancel = false;
    const fetchOnce = async () => {
      try {
        const r = await fetch(`/api/tc/scans/asset/${encodeURIComponent(assetId)}`);
        if (!r.ok) return;
        const d = await r.json();
        if (!cancel) setRunning(!!d.running);
      } catch {}
    };
    fetchOnce();
    const id = setInterval(fetchOnce, 5000);
    return () => {
      cancel = true;
      clearInterval(id);
    };
  }, [assetId]);
  if (!running) return null;
  return (
    <span style={{
      padding: "2px 8px",
      background: "rgba(48,128,208,0.12)", color: "#3080d0",
      fontWeight: 700, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.04em",
      whiteSpace: "nowrap",
      display: "inline-flex", alignItems: "center", gap: 4,
      fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
      border: "1px solid rgba(48,128,208,0.2)",
    }}>
      <RefreshCw size={9} className="tc-spin" />
      {tr("incidents_scanInProgress", locale)}
    </span>
  );
}

interface Incident {
  id: number;
  asset: string;
  // Phase 9f — backend hydrates these from the assets table. Optional
  // because legacy incidents and assets removed from inventory don't have
  // them.
  asset_name?: string | null;
  asset_hostname?: string | null;
  asset_ips?: string[] | null;
  title: string;
  summary: string | null;
  verdict: string;
  /** Sprint 1 #2 — 'graph' | 'react' | 'manual'. NULL on legacy rows. */
  verdict_source?: "graph" | "react" | "manual" | null;
  confidence: number | null;
  severity: string | null;
  alert_count: number | null;
  status: string;
  hitl_status: string | null;
  hitl_response: string | null;
  // proposed_actions is now {actions: IncidentAction[], iocs: string[]}
  proposed_actions: { actions?: IncidentAction[]; iocs?: string[] } | null | any;
  mitre_techniques: string[] | null;
  notes: IncidentNote[] | null;
  /** Phase 4: evidence citations. Empty array / undefined for legacy incidents. */
  evidence_citations?: EvidenceCitation[];
  /** v1.0.8: auto-computed blast radius snapshot. See ADR-048. */
  blast_radius_snapshot?: BlastRadiusSnapshot | null;
  blast_radius_score?: number | null;
  blast_radius_computed_at?: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
}

const severityColor: Record<string, string> = {
  CRITICAL: "#ff2020", HIGH: "#ff6030", MEDIUM: "#e0a020", LOW: "#30a050",
};

// Sépare un titre dense ("X — Y") en {title, description}. Permet
// d'afficher juste la portion factuelle dans le header collapsed et
// d'exposer la description riche dans le body. Supporte "—" (em dash)
// et "-" (hyphen) comme séparateurs.
function splitTitle(raw: string | null): { title: string; description: string | null } {
  if (!raw) return { title: "", description: null };
  const sep = raw.indexOf(" — ") >= 0 ? " — " : (raw.indexOf(" - ") >= 0 ? " - " : null);
  if (!sep) return { title: raw, description: null };
  const idx = raw.indexOf(sep);
  const desc = raw.substring(idx + sep.length).trim();
  return {
    title: raw.substring(0, idx).trim(),
    description: desc || null,
  };
}

// Identifie la source du verdict pour distinguer une décision graph
// déterministe (rapide, traçable) d'une investigation ReAct (LLM, plus
// lente). Sprint 1 #2 : on lit la colonne `verdict_source` en DB. Pour les
// 88 incidents legacy (NULL), fallback sur le parsing du préfixe `[graph] `
// du titre (ancienne convention) puis sinon ReAct par défaut.
function getVerdictSource(inc: Incident, locale: Locale): {
  kind: "graph" | "react" | "manual";
  label: string;
  color: string;
  detail: string;
} {
  const t = inc.title || "";
  const explicit = inc.verdict_source ?? null;

  const graphName = (() => {
    const m = t.match(/^\[graph\]\s+([^\s—-]+)/);
    return m ? m[1] : null;
  })();

  const kind: "graph" | "react" | "manual" =
    explicit ?? (t.startsWith("[graph]") ? "graph" : "react");

  if (kind === "graph") {
    return {
      kind: "graph",
      label: tr("incidents_deterministicGraph", locale),
      color: "#4090ff",
      detail: graphName ? `'${graphName}'` : "",
    };
  }
  if (kind === "manual") {
    return {
      kind: "manual",
      label: tr("incidents_manualDecision", locale),
      color: "#888",
      detail: "",
    };
  }
  return {
    kind: "react",
    label: tr("incidents_aiInvestigationReact", locale),
    color: "#a060c0",
    detail: "",
  };
}

const verdictBadge: Record<string, { color: string; labelKey: string }> = {
  pending: { color: "#888", labelKey: "incidents_verdictPending" },
  confirmed: { color: "#ff4040", labelKey: "incidents_verdictConfirmed" },
  false_positive: { color: "#30a050", labelKey: "incidents_verdictFalsePositive" },
  inconclusive: { color: "#e0a020", labelKey: "incidents_verdictInconclusive" },
  investigating: { color: "#4090ff", labelKey: "incidents_verdictInvestigating" },
};

function IncidentsTab({ locale }: { locale: Locale }) {
  const router = useRouter();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [confirmAction, setConfirmAction] = useState<{ incident: Incident; action: IncidentAction } | null>(null);
  const [suppressingIncident, setSuppressingIncident] = useState<Incident | null>(null);
  // Dialog de confirmation pour les décisions RSSI irréversibles (FP).
  // Le bouton "Ignorer ce pattern" passe par SuppressionWizard qui a son
  // propre flow de confirmation, donc pas besoin ici.
  const [confirmFp, setConfirmFp] = useState<Incident | null>(null);
  const [executing, setExecuting] = useState(false);
  const [showResolved, setShowResolved] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/tc/incidents");
      if (res.ok) { const data = await res.json(); setIncidents(data.incidents || []); }
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  const handleHitl = async (id: number, response: string) => {
    await fetch(`/api/tc/incidents/${id}/hitl`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ response, responded_by: "dashboard" }),
    });
    load();
  };

  const archiveResolved = async () => {
    const msg = tr("incidents_archiveConfirm", locale);
    if (!confirm(msg)) return;
    try {
      const res = await fetch("/api/tc/incidents/archive-resolved", { method: "POST" });
      const data = await res.json();
      alert(`${data.archived} ${tr("incidents_incidentsArchived", locale)}`);
      load();
    } catch (e: any) {
      alert(tr("incidents_error", locale) + ": " + e.message);
    }
  };

  const executeAction = async () => {
    if (!confirmAction) return;
    setExecuting(true);
    try {
      const res = await fetch(`/api/tc/incidents/${confirmAction.incident.id}/execute-action`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: confirmAction.action.kind }),
      });
      if (res.ok) {
        const data = await res.json();
        alert(tr("incidents_actionExecuted", locale) + (data.message || ""));
        setConfirmAction(null);
        load();
      } else {
        const err = await res.text();
        alert(tr("incidents_actionFailed", locale) + err);
      }
    } catch (e: any) {
      alert(tr("incidents_error", locale) + ": " + e.message);
    }
    setExecuting(false);
  };


  const markFalsePositive = async (id: number) => {
    try {
      await fetch(`/api/tc/incidents/${id}/hitl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ response: "false_positive", responded_by: "dashboard" }),
      });
      load();
    } catch (e: any) {
      alert(tr("incidents_error", locale) + ": " + e.message);
    }
  };

  const reinvestigate = async (id: number) => {
    try {
      const res = await fetch(`/api/tc/incidents/${id}/reinvestigate`, { method: "POST" });
      if (res.ok) {
        alert(tr("incidents_reinvestigateStarted", locale));
      } else {
        const err = await res.text();
        alert(tr("incidents_error", locale) + ": " + err);
      }
    } catch (e: any) {
      alert(tr("incidents_error", locale) + ": " + e.message);
    }
  };

  const actionIcon = (kind: string) => {
    switch (kind) {
      case "block_ip": return <Ban size={12} />;
      case "create_ticket": return <Ticket size={12} />;
      case "disable_account": return <UserX size={12} />;
      default: return <FileText size={12} />;
    }
  };

  // Only confirmed incidents on this page. V82 renamed the canonical
  // closed state from 'closed' to 'resolved'; by default we keep just
  // the open ones so the operator queue is not polluted by historical
  // rows. A toggle exposes the resolved confirmed incidents on demand
  // for operators who want to review their recent triage.
  const confirmedActive = incidents.filter(inc => {
    if (inc.verdict !== "confirmed") return false;
    if (inc.status === "open") return true;
    if (showResolved && inc.status === "resolved") return true;
    return false;
  });
  const filteredIncidents = search
    ? confirmedActive.filter(inc => {
        const q = search.toLowerCase();
        // Phase 9k — search across every operator-meaningful identifier so
        // typing "debian" or "10.77" both surface the same asset.
        return (
          inc.title.toLowerCase().includes(q) ||
          inc.asset.toLowerCase().includes(q) ||
          (inc.asset_name?.toLowerCase().includes(q) ?? false) ||
          (inc.asset_hostname?.toLowerCase().includes(q) ?? false) ||
          (inc.asset_ips?.some((ip) => ip.toLowerCase().includes(q)) ?? false)
        );
      })
    : confirmedActive;

  return (
    <div>
      <style>{`
        .inc-toolbar {
          display: flex;
          gap: 0;
          margin-bottom: 0;
          align-items: stretch;
          border-bottom: 1px solid var(--tc-border);
          flex-wrap: wrap;
        }
        .inc-filter-tab {
          padding: 8px 16px;
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.07em;
          text-transform: uppercase;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          border: none;
          border-bottom: 2px solid transparent;
          background: transparent;
          color: var(--tc-text-muted);
          cursor: pointer;
          margin-bottom: -1px;
          transition: color 0.12s, border-color 0.12s;
        }
        .inc-filter-tab:hover {
          color: var(--tc-text);
        }
        .inc-filter-tab.active {
          color: var(--tc-red);
          border-bottom-color: var(--tc-red);
        }
        .inc-toolbar-right {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-left: auto;
          padding: 6px 0;
        }
        .inc-search-wrap {
          display: flex;
          align-items: center;
          gap: 6px;
          background: var(--tc-input);
          border: 1px solid var(--tc-border);
          padding: 4px 10px;
          height: 28px;
        }
        .inc-search-wrap input {
          background: none;
          border: none;
          outline: none;
          color: var(--tc-text);
          font-size: 11px;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          width: 160px;
        }
        .inc-archive-btn {
          padding: 4px 12px;
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.06em;
          text-transform: uppercase;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          border: 1px solid var(--tc-border);
          background: var(--tc-surface-alt);
          color: var(--tc-text-muted);
          cursor: pointer;
          display: flex;
          align-items: center;
          gap: 5px;
          height: 28px;
        }
        .inc-archive-btn:hover {
          color: var(--tc-text);
          background: var(--tc-input);
        }
        .inc-table-head {
          display: grid;
          grid-template-columns: 70px 56px 1fr 130px 100px auto;
          padding: 7px 16px;
          border-bottom: 1px solid var(--tc-border);
          background: var(--tc-surface-alt);
          font-size: 9.5px;
          font-weight: 700;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          color: var(--tc-text-muted);
          gap: 12px;
          align-items: center;
          margin-top: 14px;
        }
        .inc-row {
          position: relative;
          border-bottom: 1px solid var(--tc-border);
          background: var(--tc-surface);
          transition: background 0.1s;
        }
        .inc-row:last-child {
          border-bottom: none;
        }
        .inc-row:hover {
          background: var(--tc-surface-alt);
        }
        .inc-row::before {
          content: '';
          position: absolute;
          left: 0;
          top: 0;
          bottom: 0;
          width: 3px;
          background: transparent;
        }
        .inc-row.sev-CRITICAL::before { background: #ff2020; }
        .inc-row.sev-HIGH::before { background: #ff6030; }
        .inc-row.sev-MEDIUM::before { background: #e0a020; }
        .inc-row.sev-LOW::before { background: #30a050; }
        .inc-grid {
          display: grid;
          grid-template-columns: 70px 56px 1fr 130px 100px auto;
          gap: 12px;
          align-items: center;
          padding: 11px 16px 11px 18px;
          cursor: pointer;
        }
        .inc-sev {
          display: inline-block;
          padding: 2px 6px;
          font-size: 9.5px;
          font-weight: 700;
          letter-spacing: 0.07em;
          text-transform: uppercase;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          border: 1px solid transparent;
        }
        .inc-id {
          font-size: 11px;
          font-weight: 700;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          color: var(--tc-text-muted);
        }
        .inc-signal-title {
          font-size: 13px;
          font-weight: 500;
          color: var(--tc-text);
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          margin-bottom: 2px;
        }
        .inc-sub {
          font-size: 10px;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          color: var(--tc-text-muted);
          display: flex;
          gap: 6px;
          align-items: center;
          flex-wrap: wrap;
        }
        .inc-sub .ip {
          color: var(--tc-red);
        }
        .inc-ai-cell {
          display: flex;
          align-items: center;
          gap: 5px;
        }
        .inc-ai-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          flex-shrink: 0;
        }
        .inc-ai-label {
          font-size: 10px;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          color: var(--tc-text-sec);
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .inc-when {
          font-size: 10px;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          color: var(--tc-text-muted);
          white-space: nowrap;
        }
        .inc-actions-row {
          display: flex;
          gap: 4px;
          align-items: center;
          flex-wrap: nowrap;
        }
        .inc-btn-sm {
          display: inline-flex;
          align-items: center;
          gap: 3px;
          padding: 3px 8px;
          font-size: 9.5px;
          font-weight: 700;
          letter-spacing: 0.04em;
          text-transform: uppercase;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          border: 1px solid var(--tc-border);
          background: var(--tc-surface-alt);
          color: var(--tc-text-muted);
          cursor: pointer;
          white-space: nowrap;
        }
        .inc-btn-sm:hover {
          color: var(--tc-text);
          background: var(--tc-input);
        }
        .inc-expanded {
          padding: 14px 18px 18px 18px;
          border-top: 1px solid var(--tc-border);
          background: var(--tc-surface-alt);
        }
        .inc-exp-section-head {
          font-size: 9.5px;
          font-weight: 700;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          color: var(--tc-text-muted);
          margin-bottom: 8px;
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .inc-decision-btn {
          padding: 6px 14px;
          font-size: 10.5px;
          font-weight: 600;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          text-transform: uppercase;
          letter-spacing: 0.04em;
          cursor: pointer;
          background: var(--tc-surface-alt);
          color: var(--tc-text-muted);
          border: 1px solid var(--tc-border);
          display: inline-flex;
          align-items: center;
          gap: 6px;
        }
        .inc-decision-btn:hover {
          color: var(--tc-text);
          background: var(--tc-input);
        }
        .inc-action-exec-btn {
          padding: 9px 16px;
          font-size: 12px;
          font-weight: 600;
          font-family: inherit;
          cursor: pointer;
          background: #d03020;
          color: #fff;
          border: 1px solid #b02818;
          display: inline-flex;
          align-items: center;
          gap: 8px;
          min-width: 160px;
        }
        .inc-action-exec-btn:hover {
          opacity: 0.9;
        }
        .inc-table-wrap {
          background: var(--tc-surface);
          border: 1px solid var(--tc-border);
          border-top: none;
        }
      `}</style>

      {suppressingIncident && (
        <SuppressionWizard
          incident={suppressingIncident}
          locale={locale}
          onClose={() => setSuppressingIncident(null)}
          onCreated={() => {
            setSuppressingIncident(null);
            load();
          }}
        />
      )}
      {confirmFp && (
        <div
          onClick={() => setConfirmFp(null)}
          style={{
            position: "fixed", inset: 0, zIndex: 100,
            background: "rgba(0,0,0,0.6)",
            display: "flex", alignItems: "center", justifyContent: "center",
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              maxWidth: 480, width: "90%",
              background: "var(--tc-surface)",
              border: "1px solid var(--tc-border)",
              padding: 24,
            }}
          >
            <h2 style={{ margin: "0 0 12px 0", fontSize: 15, fontWeight: 700, color: "var(--tc-text)", fontFamily: "ui-monospace, 'JetBrains Mono', monospace", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              {tr("incidents_markFalsePositiveQ", locale)}
            </h2>
            <p style={{ fontSize: 13, lineHeight: 1.6, color: "var(--tc-text-sec)", marginBottom: 8 }}>
              {tr("incidents_fpCloseIntro1", locale) + confirmFp.id + tr("incidents_fpCloseIntro2", locale)}
            </p>
            <ul style={{ fontSize: 12, lineHeight: 1.6, color: "var(--tc-text-muted)", paddingLeft: 18, marginBottom: 16 }}>
              <li>{tr("incidents_fpBulletMonitored", locale)}</li>
              <li>{tr("incidents_fpBulletNoRule", locale)}</li>
              <li>{tr("incidents_fpBulletReversible", locale)}</li>
            </ul>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button
                onClick={() => setConfirmFp(null)}
                className="inc-decision-btn"
              >
                {tr("incidents_cancel", locale)}
              </button>
              <button
                onClick={() => {
                  const id = confirmFp.id;
                  setConfirmFp(null);
                  markFalsePositive(id);
                }}
                style={{
                  padding: "8px 16px", fontSize: 11, fontWeight: 700, fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                  textTransform: "uppercase", letterSpacing: "0.04em",
                  cursor: "pointer", background: "#d03020", color: "#fff",
                  border: "1px solid #b02818",
                }}
              >
                {tr("incidents_confirmFalsePositive", locale)}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toolbar */}
      <div className="inc-toolbar">
        <div className="inc-toolbar-right">
          <div className="inc-search-wrap">
            <Search size={11} color="var(--tc-text-muted)" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder={tr("incidents_searchPlaceholder", locale)}
            />
            {search && (
              <button onClick={() => setSearch("")} style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
                <X size={11} color="var(--tc-text-muted)" />
              </button>
            )}
          </div>
          <button
            className="inc-archive-btn"
            onClick={() => setShowResolved(v => !v)}
            style={{
              borderColor: showResolved ? "rgba(48,160,80,0.4)" : "var(--tc-border)",
              background: showResolved ? "rgba(48,160,80,0.08)" : "var(--tc-surface-alt)",
              color: showResolved ? "#30a050" : "var(--tc-text-muted)",
            }}
            title={locale === "fr" ? "Inclure les incidents résolus dans la liste" : "Include resolved incidents in the list"}
          >
            {showResolved ? (locale === "fr" ? "+ Résolus" : "+ Resolved") : (locale === "fr" ? "Voir résolus" : "Show resolved")}
          </button>
          <button className="inc-archive-btn" onClick={archiveResolved}>
            <FileText size={11} />
            {tr("incidents_archiveResolved", locale)}
          </button>
        </div>
      </div>

      {loading && (
        <div style={{ color: "var(--tc-text-muted)", textAlign: "center", padding: 40, fontSize: 12 }}>
          {tr("incidents_loading", locale)}
        </div>
      )}

      {!loading && filteredIncidents.length === 0 && (
        <div style={{ textAlign: "center", padding: 48, background: "var(--tc-surface)", border: "1px solid var(--tc-border)" }}>
          <CheckCircle2 size={32} color="var(--tc-green)" style={{ marginBottom: 10 }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--tc-text)", marginBottom: 4 }}>
            {tr("incidents_noIncidents", locale)}
          </div>
          <div style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>
            {tr("incidents_underControl", locale)}
          </div>
        </div>
      )}

      {!loading && filteredIncidents.length > 0 && (
        <>
          {/* Table header */}
          <div className="inc-table-head">
            <span>{tr("incidents_colSeverity", locale)}</span>
            <span>{tr("incidents_colId", locale)}</span>
            <span>{tr("incidents_colSignal", locale)}</span>
            <span>{tr("incidents_colAiAgent", locale)}</span>
            <span>{tr("incidents_colDetected", locale)}</span>
            <span>{tr("incidents_colActions", locale)}</span>
          </div>

          <div className="inc-table-wrap">
            {filteredIncidents.map(inc => {
              const badge = verdictBadge[inc.verdict] || verdictBadge.pending;
              const sevColor = severityColor[inc.severity || "MEDIUM"] || "#888";
              const split = splitTitle(inc.title);
              const source = getVerdictSource(inc, locale);

              // AI dot color
              const aiDotColor = inc.verdict === "confirmed" ? "#ff4040"
                : inc.verdict === "false_positive" ? "#30a050"
                : inc.verdict === "investigating" ? "#4090ff"
                : "#e0a020";

              return (
                <div
                  key={inc.id}
                  className={`inc-row sev-${inc.severity || "MEDIUM"}`}
                >
                  {/* Main row grid */}
                  <div className="inc-grid" onClick={() => router.push(`/investigate/${inc.id}`)}>
                    {/* Col 1: severity */}
                    <div>
                      <span
                        className="inc-sev"
                        style={{
                          background: sevColor + "22",
                          color: sevColor,
                          borderColor: sevColor + "55",
                        }}
                      >
                        {inc.severity || "—"}
                      </span>
                    </div>

                    {/* Col 2: ID */}
                    <div className="inc-id">#{inc.id}</div>

                    {/* Col 3: signal info */}
                    <div style={{ minWidth: 0 }}>
                      <div className="inc-signal-title">{split.title}</div>
                      <div className="inc-sub">
                        <span className="ip" title={displayAssetVerbose(inc)}>{displayAsset(inc)}</span>
                        <span>·</span>
                        <span>{inc.alert_count || 0} {tr("incidents_alertsWord", locale)}</span>
                        <span>·</span>
                        <span>{getTimeAgo(inc.created_at, locale)}</span>
                        {inc.asset && <ScanInProgressBadge assetId={inc.asset} locale={locale} />}
                      </div>
                    </div>

                    {/* Col 4: AI state */}
                    <div className="inc-ai-cell">
                      <span className="inc-ai-dot" style={{ background: aiDotColor }} />
                      <span className="inc-ai-label">
                        {tr(badge.labelKey, locale)}
                        {inc.confidence ? ` ${Math.round(inc.confidence * 100)}%` : ""}
                      </span>
                    </div>

                    {/* Col 5: when */}
                    <div className="inc-when">{getTimeAgo(inc.created_at, locale)}</div>

                    {/* Col 6: actions */}
                    <div className="inc-actions-row" onClick={e => e.stopPropagation()}>
                      <button
                        className="inc-btn-sm"
                        onClick={() => reinvestigate(inc.id)}
                        title={tr("incidents_rerunAiTitle", locale)}
                      >
                        <Brain size={9} />
                        {tr("incidents_rerun", locale)}
                      </button>
                      <button
                        className="inc-btn-sm"
                        onClick={() => router.push(`/investigate/${inc.id}`)}
                        title={tr("incidents_openDossierTitle", locale)}
                      >
                        <FileText size={9} />
                        {tr("incidents_report", locale)}
                      </button>
                      <OperatorDecisionMenu
                        incidentId={inc.id}
                        ruleId={null}
                        assetHostname={inc.asset ?? null}
                        username={null}
                        sourceIp={null}
                        actor="dashboard:operator"
                        onDone={() => load()}
                      />
                    </div>
                  </div>

                </div>
              );
            })}
          </div>
        </>
      )}

      {/* Confirmation modal for action execution */}
      {confirmAction && (
        <div onClick={() => !executing && setConfirmAction(null)} style={{
          position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)",
          display: "flex", alignItems: "center", justifyContent: "center",
          zIndex: 1000, padding: 20,
        }}>
          <div onClick={e => e.stopPropagation()} style={{
            background: "var(--tc-surface)",
            border: "1px solid var(--tc-border)", padding: 24, maxWidth: 520, width: "100%",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
              {actionIcon(confirmAction.action.kind)}
              <h3 style={{ fontSize: 14, fontWeight: 700, color: "var(--tc-text)", margin: 0, fontFamily: "ui-monospace, 'JetBrains Mono', monospace", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                {tr("incidents_confirmAction", locale)}
              </h3>
            </div>

            <div style={{ fontSize: 13, color: "var(--tc-text)", marginBottom: 16, lineHeight: 1.6 }}>
              {tr("incidents_aboutToExecute1", locale) + confirmAction.incident.id + tr("incidents_aboutToExecute2", locale)}
            </div>

            <div style={{ padding: "10px 12px", background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)", marginBottom: 14 }}>
              <div style={{ fontSize: 12, color: "var(--tc-text)", fontWeight: 600, marginBottom: 4 }}>
                {confirmAction.action.description}
              </div>
              <div style={{ fontSize: 10, color: "var(--tc-text-muted)", fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>
                kind: {confirmAction.action.kind}  ·  asset: {displayAsset(confirmAction.incident)}
              </div>
            </div>

            <div style={{ padding: "9px 11px", background: "rgba(208,48,32,0.08)", border: "1px solid rgba(208,48,32,0.2)", marginBottom: 18 }}>
              <div style={{ fontSize: 11, color: "#d03020", lineHeight: 1.5, fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>
                {tr("incidents_remediationNote", locale)}
              </div>
            </div>

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button
                onClick={() => setConfirmAction(null)}
                disabled={executing}
                className="inc-decision-btn"
              >
                {tr("incidents_cancel", locale)}
              </button>
              <button
                onClick={executeAction}
                disabled={executing}
                style={{
                  padding: "8px 16px", fontSize: 11, fontWeight: 700, fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                  textTransform: "uppercase", letterSpacing: "0.04em",
                  cursor: executing ? "not-allowed" : "pointer",
                  background: "#d03020", color: "#fff", border: "none",
                  display: "flex", alignItems: "center", gap: 6,
                  opacity: executing ? 0.6 : 1,
                }}
              >
                <Zap size={11} />
                {executing ? tr("incidents_executing", locale) : tr("incidents_confirmAndExecute", locale)}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════
// FINDINGS TAB (embedded)
// ═══════════════════════════════════════════════

const SEVERITY_COLORS: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "#e84040", bg: "rgba(232,64,64,0.08)", border: "rgba(232,64,64,0.2)" },
  high: { color: "#d07020", bg: "rgba(208,112,32,0.08)", border: "rgba(208,112,32,0.2)" },
  medium: { color: "var(--tc-amber)", bg: "rgba(208,144,32,0.08)", border: "rgba(208,144,32,0.2)" },
  low: { color: "var(--tc-blue)", bg: "rgba(48,128,208,0.08)", border: "rgba(48,128,208,0.2)" },
  info: { color: "var(--tc-text-muted)", bg: "var(--tc-input)", border: "var(--tc-input)" },
};

function FindingsTab({ locale }: { locale: Locale }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [counts, setCounts] = useState<CountEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterStatus, setFilterStatus] = useState("open");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [f, c] = await Promise.all([
        fetchFindings({ severity: filterSeverity || undefined, status: filterStatus || undefined, limit: 200 }),
        fetchFindingsCounts(),
      ]);
      setFindings(f.findings); setCounts(c); setError(null);
    } catch { setError(tr("incidents_loadError", locale)); }
    setLoading(false);
  }, [filterSeverity, filterStatus, locale]);

  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t); }, [load]);

  const changeStatus = async (id: number, status: string) => {
    try { await updateFindingStatus(id, status, "rssi"); await load(); } catch {}
  };

  const filtered = search
    ? findings.filter(f => f.title.toLowerCase().includes(search.toLowerCase()) || f.asset?.toLowerCase().includes(search.toLowerCase()))
    : findings;

  const total = counts.reduce((s, c) => s + c.count, 0);

  return (
    <div>
      {error && <ErrorBanner message={error} onRetry={load} />}

      {/* Severity counts */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap" }}>
        {["critical", "high", "medium", "low"].map(sev => {
          const c = counts.find(c => c.label.toLowerCase() === sev)?.count || 0;
          const s = SEVERITY_COLORS[sev];
          const active = filterSeverity === sev;
          return (
            <button key={sev} onClick={() => setFilterSeverity(active ? "" : sev)} style={{
              padding: "8px 14px", border: `1px solid ${active ? s.border : "var(--tc-border)"}`,
              background: active ? s.bg : "var(--tc-surface-alt)", cursor: "pointer", fontFamily: "inherit",
              display: "flex", alignItems: "center", gap: "6px", color: s.color, fontSize: "13px", fontWeight: 600,
            }}>
              <span style={{ fontSize: "16px", fontWeight: 800 }}>{c}</span>
              {sev.charAt(0).toUpperCase() + sev.slice(1)}
            </button>
          );
        })}
      </div>

      {/* Search + status filters */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", alignItems: "center" }}>
        <div style={{ flex: 1, display: "flex", alignItems: "center", gap: "8px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", padding: "8px 12px" }}>
          <Search size={14} color="var(--tc-text-muted)" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder={tr("incidents_searchPlaceholder", locale)}
            style={{ flex: 1, background: "none", border: "none", outline: "none", color: "var(--tc-text)", fontSize: "13px", fontFamily: "inherit" }} />
          {search && <button onClick={() => setSearch("")} style={{ background: "none", border: "none", cursor: "pointer" }}><X size={14} color="var(--tc-text-muted)" /></button>}
        </div>
        {["open", "in_progress", "resolved"].map(st => {
          const active = filterStatus === st;
          return (
            <button key={st} onClick={() => setFilterStatus(active ? "" : st)} style={{
              padding: "8px 12px", fontSize: "11px", fontWeight: 600,
              border: `1px solid ${active ? "rgba(208,48,32,0.2)" : "var(--tc-border)"}`,
              background: active ? "rgba(208,48,32,0.06)" : "var(--tc-surface-alt)",
              color: active ? "#d03020" : "var(--tc-text-muted)", cursor: "pointer", fontFamily: "inherit",
            }}>
              {st === "open" ? tr("incidents_statusOpen", locale) : st === "in_progress" ? tr("incidents_statusInProgress", locale) : tr("incidents_statusResolved", locale)}
            </button>
          );
        })}
        <ChromeButton onClick={load} variant="glass"><RefreshCw size={14} /></ChromeButton>
      </div>

      {/* Findings list */}
      {loading ? (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{tr("incidents_loading", locale)}</div></NeuCard>
      ) : filtered.length === 0 ? (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{tr("incidents_noFindings", locale)}</div></NeuCard>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          {filtered.map(f => {
            const sev = SEVERITY_COLORS[f.severity.toLowerCase()] || SEVERITY_COLORS.info;
            const isExpanded = expandedId === f.id;
            return (
              <NeuCard key={f.id} style={{ padding: "14px 16px", borderRadius: "var(--tc-radius-card)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={() => setExpandedId(isExpanded ? null : f.id)}>
                  <span style={{ fontSize: "10px", fontWeight: 700, padding: "3px 8px", background: sev.bg, color: sev.color, border: `1px solid ${sev.border}`, textTransform: "uppercase", flexShrink: 0, fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>{f.severity.toUpperCase()}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--tc-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{localizeFinding(f, locale).title}</div>
                    <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", display: "flex", gap: "12px", marginTop: "2px" }}>
                      {f.asset && <span style={{ color: "var(--tc-blue)" }}>{f.asset}</span>}
                      <span>{f.source || f.skill_id}</span>
                      <span>{new Date(f.detected_at).toLocaleDateString(locale === "fr" ? "fr-FR" : "en-US")}</span>
                    </div>
                  </div>
                  <ChevronDown size={14} color="var(--tc-text-muted)" style={{ transform: isExpanded ? "rotate(180deg)" : "none", transition: "0.2s" }} />
                </div>
                {isExpanded && (
                  <div style={{ marginTop: "14px", borderTop: "1px solid var(--tc-border)", paddingTop: "14px" }}>
                    {(() => { const d = localizeFinding(f, locale).description; return d ? <div style={{ fontSize: "12px", color: "var(--tc-text-sec)", lineHeight: 1.6, marginBottom: "12px", whiteSpace: "pre-line" }}>{d}</div> : null; })()}
                    {f.metadata && (
                      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "10px" }}>
                        {f.metadata.src_ip && <span style={{ fontSize: "10px", padding: "3px 8px", background: "rgba(232,64,64,0.08)", color: "var(--tc-red)", border: "1px solid rgba(232,64,64,0.15)", fontFamily: "monospace" }}>src: {String(f.metadata.src_ip)}</span>}
                        {f.metadata.cve && <span style={{ fontSize: "10px", padding: "3px 8px", background: "rgba(208,48,32,0.08)", color: "var(--tc-red)", border: "1px solid rgba(208,48,32,0.15)", fontFamily: "monospace" }}>{String(f.metadata.cve)}</span>}
                        {f.metadata.mitre && Array.isArray(f.metadata.mitre) && <span style={{ fontSize: "10px", padding: "3px 8px", background: "rgba(128,64,208,0.08)", color: "#8040d0", border: "1px solid rgba(128,64,208,0.15)", fontFamily: "monospace" }}>MITRE: {(f.metadata.mitre as string[]).join(", ")}</span>}
                      </div>
                    )}
                    <div style={{ display: "flex", gap: "6px" }}>
                      {f.status !== "resolved" && <ChromeButton onClick={() => changeStatus(f.id, "resolved")} variant="glass"><CheckCircle2 size={12} /> {tr("incidents_statusResolved", locale)}</ChromeButton>}
                      {f.status !== "false_positive" && <ChromeButton onClick={() => changeStatus(f.id, "false_positive")} variant="glass"><XCircle size={12} /> {tr("incidents_verdictFalsePositive", locale)}</ChromeButton>}
                      <ChromeButton onClick={async () => {
                        try {
                          const res = await fetch("/api/tc/connectors/glpi/ticket", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ finding_id: f.id }) });
                          const data = await res.json();
                          if (data.ticket_id) alert(`Ticket GLPI #${data.ticket_id}`);
                          else if (data.error) alert(data.error);
                        } catch { alert(tr("incidents_glpiNotConfigured", locale)); }
                      }} variant="glass"><FileText size={12} /> Ticket GLPI</ChromeButton>
                    </div>
                  </div>
                )}
              </NeuCard>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════
// ALERTS TAB (embedded)
// ═══════════════════════════════════════════════

const LEVEL_COLORS: Record<string, string> = {
  critical: "#e84040", high: "#d07020", medium: "var(--tc-amber)", low: "var(--tc-blue)", informational: "var(--tc-text-muted)",
};

function AlertsTab({ locale }: { locale: Locale }) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterLevel, setFilterLevel] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await fetchAlerts({ level: filterLevel || undefined, limit: 200 });
      setAlerts(data.alerts || []); setError(null);
    } catch { setError(tr("incidents_loadError", locale)); }
    setLoading(false);
  }, [filterLevel, locale]);

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  const archiveResolvedAlerts = async () => {
    const msg = tr("incidents_archiveAlertsConfirm", locale);
    if (!confirm(msg)) return;
    try {
      const res = await fetch("/api/tc/alerts/archive-resolved", { method: "POST" });
      const data = await res.json();
      alert(`${data.archived} ${tr("incidents_alertsArchived", locale)}`);
      load();
    } catch (e: any) {
      alert(tr("incidents_error", locale) + ": " + e.message);
    }
  };

  return (
    <div>
      {error && <ErrorBanner message={error} onRetry={load} />}

      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap", alignItems: "center" }}>
        {["critical", "high", "medium", "low"].map(level => {
          const active = filterLevel === level;
          const color = LEVEL_COLORS[level] || "var(--tc-text-muted)";
          return (
            <button key={level} onClick={() => setFilterLevel(active ? "" : level)} style={{
              padding: "6px 14px", fontSize: 11, fontWeight: 600,
              border: `1px solid ${active ? color : "var(--tc-border)"}`,
              background: active ? `${color}15` : "var(--tc-surface-alt)",
              color: active ? color : "var(--tc-text-muted)", cursor: "pointer",
              fontFamily: "ui-monospace, 'JetBrains Mono', monospace", textTransform: "uppercase",
            }}>{level}</button>
          );
        })}
        <div style={{ flex: 1 }} />
        <button onClick={archiveResolvedAlerts} style={{
          padding: "6px 14px", fontSize: 11, fontWeight: 600,
          border: "1px solid var(--tc-border)", background: "var(--tc-surface-alt)",
          color: "var(--tc-text-muted)", cursor: "pointer", fontFamily: "inherit",
          display: "flex", alignItems: "center", gap: 6,
        }}>
          <FileText size={12} />
          {tr("incidents_archiveResolved", locale)}
        </button>
        <ChromeButton onClick={load} variant="glass"><RefreshCw size={14} /></ChromeButton>
      </div>

      {loading ? (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{tr("incidents_loading", locale)}</div></NeuCard>
      ) : alerts.length === 0 ? (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{tr("incidents_noAlerts", locale)}</div></NeuCard>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          {alerts.map((a, i) => {
            const color = LEVEL_COLORS[a.level?.toLowerCase()] || "var(--tc-text-muted)";
            return (
              <NeuCard key={a.id || i} style={{ padding: "12px 16px", borderRadius: "var(--tc-radius-card)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  <span style={{ fontSize: "10px", fontWeight: 700, padding: "3px 8px", background: `${color}15`, color, border: `1px solid ${color}30`, textTransform: "uppercase", flexShrink: 0, fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>{a.level}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--tc-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.title}</div>
                    <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", display: "flex", gap: "12px", marginTop: "2px" }}>
                      {a.hostname && <span>{a.hostname}</span>}
                      {a.source_ip && <span style={{ fontFamily: "monospace", color: "var(--tc-red)" }}>{a.source_ip}</span>}
                      {a.username && <span>{a.username}</span>}
                      <span>{a.rule_id}</span>
                      {a.matched_at && <span>{new Date(a.matched_at).toLocaleTimeString(locale === "fr" ? "fr-FR" : "en-US")}</span>}
                    </div>
                  </div>
                </div>
              </NeuCard>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════
// MAIN PAGE — Tab switcher
// ═══════════════════════════════════════════════

export default function IncidentsPage() {
  const locale = useLocale();
  // Navigation between Incidents / Findings / Alertes is handled by the
  // root layout's left sidebar (see sections.ts → incidents). This page
  // stays focused on the incident triage view; /findings and /alerts
  // render their own content.
  return (
    <PageShell
      title={tr("incidents_title", locale)}
      subtitle={tr("incidents_subtitle", locale)}
    >
      <IncidentsTab locale={locale} />
    </PageShell>
  );
}

function getTimeAgo(iso: string, locale: Locale): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return tr("incidents_justNow", locale);
  if (mins < 60) return tr("incidents_agoPrefix", locale) + mins + tr("incidents_minSuffix", locale);
  const hours = Math.floor(mins / 60);
  if (hours < 24) return tr("incidents_agoPrefix", locale) + hours + tr("incidents_hourSuffix", locale);
  const days = Math.floor(hours / 24);
  return tr("incidents_agoPrefix", locale) + days + tr("incidents_daySuffix", locale);
}

"use client";
// Unified Incidents page — Incidents (confirmed) + Findings (vulns) + Alerts (sigma)
import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import BlastRadiusCard from "@/components/incidents/BlastRadiusCard";
import SuppressionWizard from "@/components/incidents/SuppressionWizard";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { PageShell } from "@/components/chrome/PageShell";
import {
  AlertTriangle, Shield, Bell, ChevronDown, RefreshCw, CheckCircle2, XCircle,
  Clock, Search, X, FileText, Eye, Zap, Ban, MessageSquare, Ticket, UserX, Send, Brain, Filter,
} from "lucide-react";
import { fetchFindings, fetchFindingsCounts, updateFindingStatus, type Finding, type CountEntry } from "@/lib/tc-api";
import { fetchAlerts, fetchAlertsCounts, type Alert } from "@/lib/tc-api";

// ═══════════════════════════════════════════════
// INCIDENTS TAB
// ═══════════════════════════════════════════════

interface IncidentAction {
  kind: string;       // "block_ip" | "create_ticket" | "disable_account" | "manual"
  description: string;
}

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
function ScanInProgressBadge({ assetId, locale }: { assetId: string; locale: string }) {
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
      {locale === "fr" ? "scan en cours" : "scan in progress"}
    </span>
  );
}

interface Incident {
  id: number;
  asset: string;
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

// Recommandations rules-based pour un incident dont l'IA n'a pas
// proposé d'action HITL automatisable. Distingue deux choses :
//
//  - `actions` : recommandations qui correspondent à un skill actionnable
//    (ex. opnsense_block_ip). Elles passent par le MÊME chemin HITL que
//    les actions produites par l'IA — boutons rouge dans "Que faire
//    maintenant", confirmation dialog, license check, audit. Si le skill
//    n'est pas installé, le backend rejette l'exec avec un message clair.
//
//  - `manual` : recommandations purement humaines (reviewer findings,
//    documenter décision). Pas de bouton — juste une checklist.
//
// Pas de LLM call — c'est rules-based.
function generateRecommendedActions(inc: Incident, locale: string): {
  actions: IncidentAction[];
  manual: string[];
} {
  const actions: IncidentAction[] = [];
  const manual: string[] = [];
  const sev = inc.severity || "MEDIUM";
  const asset = inc.asset || "";
  const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(asset);
  const isRfc1918 = isIp && (
    asset.startsWith("10.") ||
    asset.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(asset) ||
    asset.startsWith("127.")
  );
  const isPublicIp = isIp && !isRfc1918;
  const isHigh = sev === "CRITICAL" || sev === "HIGH";
  const fr = locale === "fr";

  if (isHigh && isPublicIp) {
    actions.push({
      kind: "opnsense_block_ip",
      description: fr ? `Bloquer ${asset} au firewall OPNsense` : `Block ${asset} at OPNsense firewall`,
    });
    actions.push({
      kind: "fortinet_block_ip",
      description: fr ? `Bloquer ${asset} au firewall Fortinet` : `Block ${asset} at Fortinet firewall`,
    });
    manual.push(fr
      ? "Vérifier la réputation IP via les enrichissements (urlscan, greynoise, spamhaus)"
      : "Check IP reputation via enrichments (urlscan, greynoise, spamhaus)");
  } else if (isHigh && isIp) {
    actions.push({
      kind: "velociraptor_isolate_host",
      description: fr ? `Isoler ${asset} du réseau via Velociraptor` : `Isolate ${asset} from network via Velociraptor`,
    });
    actions.push({
      kind: "velociraptor_collect_artifacts",
      description: fr ? `Collecter les artefacts forensiques de ${asset}` : `Collect forensic artifacts from ${asset}`,
    });
  } else if (isHigh) {
    // Asset par hostname — on a souvent un user dans les findings, mais
    // sans nom certain on suggère les actions sans cible précise. Le
    // backend résoudra le username depuis le contexte de l'incident.
    actions.push({
      kind: "velociraptor_isolate_host",
      description: fr ? `Isoler ${asset} (Velociraptor)` : `Isolate ${asset} (Velociraptor)`,
    });
    actions.push({
      kind: "ad_disable_account",
      description: fr ? "Désactiver le compte AD compromis" : "Disable compromised AD account",
    });
    actions.push({
      kind: "ad_reset_password",
      description: fr ? "Forcer le reset password du compte" : "Force account password reset",
    });
    manual.push(fr
      ? "Vérifier les logs d'authentification récents sur cet asset"
      : "Review recent authentication logs on this asset");
  }

  manual.push(fr
    ? "Reviewer les findings et alertes liés (contexte ci-dessus)"
    : "Review related findings and alerts (context above)");
  manual.push(fr
    ? "Documenter la décision RSSI dans une note pour traçabilité"
    : "Document the CISO decision in a note for traceability");

  return { actions, manual };
}

// Identifie la source du verdict pour distinguer une décision graph
// déterministe (rapide, traçable) d'une investigation ReAct (LLM, plus
// lente). Sprint 1 #2 : on lit la colonne `verdict_source` en DB. Pour les
// 88 incidents legacy (NULL), fallback sur le parsing du préfixe `[graph] `
// du titre (ancienne convention) puis sinon ReAct par défaut.
function getVerdictSource(inc: Incident, locale: string): {
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
      label: locale === "fr" ? "Graph déterministe" : "Deterministic graph",
      color: "#4090ff",
      detail: graphName ? `'${graphName}'` : "",
    };
  }
  if (kind === "manual") {
    return {
      kind: "manual",
      label: locale === "fr" ? "Décision RSSI" : "Manual decision",
      color: "#888",
      detail: "",
    };
  }
  return {
    kind: "react",
    label: locale === "fr" ? "Investigation IA (ReAct)" : "AI investigation (ReAct)",
    color: "#a060c0",
    detail: "",
  };
}

const verdictBadge: Record<string, { color: string; labelFr: string; labelEn: string }> = {
  pending: { color: "#888", labelFr: "En cours...", labelEn: "Pending..." },
  confirmed: { color: "#ff4040", labelFr: "Confirme", labelEn: "Confirmed" },
  false_positive: { color: "#30a050", labelFr: "Faux positif", labelEn: "False positive" },
  inconclusive: { color: "#e0a020", labelFr: "Inconclusif", labelEn: "Inconclusive" },
  investigating: { color: "#4090ff", labelFr: "Investigation", labelEn: "Investigating" },
};

function IncidentsTab({ locale }: { locale: string }) {
  const router = useRouter();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [confirmAction, setConfirmAction] = useState<{ incident: Incident; action: IncidentAction } | null>(null);
  const [suppressingIncident, setSuppressingIncident] = useState<Incident | null>(null);
  // Dialog de confirmation pour les décisions RSSI irréversibles (FP).
  // Le bouton "Ignorer ce pattern" passe par SuppressionWizard qui a son
  // propre flow de confirmation, donc pas besoin ici.
  const [confirmFp, setConfirmFp] = useState<Incident | null>(null);
  const [executing, setExecuting] = useState(false);
  const [noteInput, setNoteInput] = useState<Record<number, string>>({});

  const load = useCallback(async () => {
    try {
      const url = filter === "all" ? "/api/tc/incidents" : `/api/tc/incidents?status=${filter}`;
      const res = await fetch(url);
      if (res.ok) { const data = await res.json(); setIncidents(data.incidents || []); }
    } catch {}
    setLoading(false);
  }, [filter]);

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  const handleHitl = async (id: number, response: string) => {
    await fetch(`/api/tc/incidents/${id}/hitl`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ response, responded_by: "dashboard" }),
    });
    load();
  };

  const filters = [
    { key: "all", label: locale === "fr" ? "Tous" : "All" },
    { key: "open", label: locale === "fr" ? "Ouverts" : "Open" },
    { key: "investigating", label: locale === "fr" ? "En cours" : "Investigating" },
    { key: "resolved", label: locale === "fr" ? "Resolus" : "Resolved" },
    { key: "closed", label: locale === "fr" ? "Fermes" : "Closed" },
    { key: "archived", label: locale === "fr" ? "Archives" : "Archived" },
  ];

  const archiveResolved = async () => {
    const msg = locale === "fr"
      ? "Archiver tous les incidents resolus/fermes/faux positifs ? (reversible — purge definitive apres 60 jours)"
      : "Archive all resolved/closed/false-positive incidents? (reversible — permanent purge after 60 days)";
    if (!confirm(msg)) return;
    try {
      const res = await fetch("/api/tc/incidents/archive-resolved", { method: "POST" });
      const data = await res.json();
      alert(locale === "fr" ? `${data.archived} incidents archives` : `${data.archived} incidents archived`);
      load();
    } catch (e: any) {
      alert("Erreur: " + e.message);
    }
  };

  const archiveOne = async (id: number) => {
    try {
      await fetch(`/api/tc/incidents/${id}/archive`, { method: "POST" });
      load();
    } catch (e: any) {
      alert("Erreur: " + e.message);
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
        alert((locale === "fr" ? "Action exécutée : " : "Action executed: ") + (data.message || ""));
        setConfirmAction(null);
        load();
      } else {
        const err = await res.text();
        alert((locale === "fr" ? "Échec : " : "Failed: ") + err);
      }
    } catch (e: any) {
      alert("Erreur: " + e.message);
    }
    setExecuting(false);
  };

  const addNote = async (id: number) => {
    const text = (noteInput[id] || "").trim();
    if (!text) return;
    try {
      await fetch(`/api/tc/incidents/${id}/note`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, author: "dashboard" }),
      });
      setNoteInput(prev => ({ ...prev, [id]: "" }));
      load();
    } catch (e: any) {
      alert("Erreur: " + e.message);
    }
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
      alert("Erreur: " + e.message);
    }
  };

  const reinvestigate = async (id: number) => {
    try {
      const res = await fetch(`/api/tc/incidents/${id}/reinvestigate`, { method: "POST" });
      if (res.ok) {
        alert(locale === "fr"
          ? "Investigation relancée. Le résultat apparaîtra dans 10-30 secondes (rafraîchissement auto)."
          : "Investigation restarted. Results will appear in 10-30 seconds (auto-refresh).");
      } else {
        const err = await res.text();
        alert("Erreur: " + err);
      }
    } catch (e: any) {
      alert("Erreur: " + e.message);
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

  // Filter incidents by search
  const filteredIncidents = search
    ? incidents.filter(inc =>
        inc.title.toLowerCase().includes(search.toLowerCase()) ||
        inc.asset.toLowerCase().includes(search.toLowerCase())
      )
    : incidents;

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
              {locale === "fr" ? "Marquer comme faux positif ?" : "Mark as false positive?"}
            </h2>
            <p style={{ fontSize: 13, lineHeight: 1.6, color: "var(--tc-text-sec)", marginBottom: 8 }}>
              {locale === "fr"
                ? "Tu vas fermer l'incident #" + confirmFp.id + " et le classer en faux positif."
                : "You'll close incident #" + confirmFp.id + " and classify it as false positive."}
            </p>
            <ul style={{ fontSize: 12, lineHeight: 1.6, color: "var(--tc-text-muted)", paddingLeft: 18, marginBottom: 16 }}>
              <li>{locale === "fr"
                ? "L'asset reste surveillé — les futurs signaux seront analysés normalement."
                : "The asset stays monitored — future signals are analyzed normally."}</li>
              <li>{locale === "fr"
                ? "Aucune règle de suppression n'est créée. Pour ça, utilise plutôt \"Ignorer ce pattern\"."
                : "No suppression rule is created. For that, use \"Ignore this pattern\" instead."}</li>
              <li>{locale === "fr"
                ? "Décision réversible — l'incident reste consultable dans les archives."
                : "Reversible — the incident stays viewable in archives."}</li>
            </ul>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button
                onClick={() => setConfirmFp(null)}
                className="inc-decision-btn"
              >
                {locale === "fr" ? "Annuler" : "Cancel"}
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
                {locale === "fr" ? "Confirmer faux positif" : "Confirm false positive"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Filter toolbar */}
      <div className="inc-toolbar">
        {filters.map(f => (
          <button
            key={f.key}
            onClick={() => setFilter(f.key)}
            className={`inc-filter-tab${filter === f.key ? " active" : ""}`}
          >
            {f.label}
          </button>
        ))}
        <div className="inc-toolbar-right">
          <div className="inc-search-wrap">
            <Search size={11} color="var(--tc-text-muted)" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder={locale === "fr" ? "Rechercher..." : "Search..."}
            />
            {search && (
              <button onClick={() => setSearch("")} style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
                <X size={11} color="var(--tc-text-muted)" />
              </button>
            )}
          </div>
          <button className="inc-archive-btn" onClick={archiveResolved}>
            <FileText size={11} />
            {locale === "fr" ? "Archiver le resolu" : "Archive resolved"}
          </button>
        </div>
      </div>

      {loading && (
        <div style={{ color: "var(--tc-text-muted)", textAlign: "center", padding: 40, fontSize: 12 }}>
          {locale === "fr" ? "Chargement..." : "Loading..."}
        </div>
      )}

      {!loading && filteredIncidents.length === 0 && (
        <div style={{ textAlign: "center", padding: 48, background: "var(--tc-surface)", border: "1px solid var(--tc-border)" }}>
          <CheckCircle2 size={32} color="var(--tc-green)" style={{ marginBottom: 10 }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--tc-text)", marginBottom: 4 }}>
            {locale === "fr" ? "Aucun incident" : "No incidents"}
          </div>
          <div style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>
            {locale === "fr" ? "Tout est sous controle" : "Everything is under control"}
          </div>
        </div>
      )}

      {!loading && filteredIncidents.length > 0 && (
        <>
          {/* Table header */}
          <div className="inc-table-head">
            <span>Severite</span>
            <span>ID</span>
            <span>Signal</span>
            <span>Agent IA</span>
            <span>Detecte</span>
            <span>Actions</span>
          </div>

          <div className="inc-table-wrap">
            {filteredIncidents.map(inc => {
              const isExpanded = expanded === inc.id;
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
                  <div className="inc-grid" onClick={() => setExpanded(isExpanded ? null : inc.id)}>
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
                        <span className="ip">{inc.asset}</span>
                        <span>·</span>
                        <span>{inc.alert_count || 0} alerts</span>
                        <span>·</span>
                        <span>{getTimeAgo(inc.created_at, locale)}</span>
                        {inc.asset && <ScanInProgressBadge assetId={inc.asset} locale={locale} />}
                      </div>
                    </div>

                    {/* Col 4: AI state */}
                    <div className="inc-ai-cell">
                      <span className="inc-ai-dot" style={{ background: aiDotColor }} />
                      <span className="inc-ai-label">
                        {locale === "fr" ? badge.labelFr : badge.labelEn}
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
                        title={locale === "fr" ? "Relancer l'investigation IA" : "Re-run AI investigation"}
                      >
                        <Brain size={9} />
                        Relancer
                      </button>
                      <button
                        className="inc-btn-sm"
                        onClick={() => router.push(`/investigate/${inc.id}`)}
                        title={locale === "fr" ? "Ouvrir le dossier d'investigation" : "Open investigation dossier"}
                      >
                        <FileText size={9} />
                        Rapport
                      </button>
                      <button
                        className="inc-btn-sm"
                        onClick={() => setConfirmFp(inc)}
                        title={locale === "fr" ? "Marquer comme faux positif" : "Mark as false positive"}
                      >
                        FP
                      </button>
                    </div>
                  </div>

                  {/* Expanded detail panel */}
                  {isExpanded && (() => {
                    const actions: IncidentAction[] = (inc.proposed_actions?.actions || []) as IncidentAction[];
                    const iocs: string[] = (inc.proposed_actions?.iocs || []) as string[];
                    const isOpen = inc.status !== "resolved" && inc.status !== "closed" && inc.status !== "archived";
                    const aiActions = actions.filter(a => a.kind !== "manual");
                    const recoBundle = aiActions.length === 0
                      ? generateRecommendedActions(inc, locale)
                      : { actions: [] as IncidentAction[], manual: [] as string[] };
                    const executableActions = [...aiActions, ...recoBundle.actions];
                    const recoSource: "ai" | "rules" = aiActions.length > 0 ? "ai" : "rules";
                    return (
                      <div className="inc-expanded">
                        {/* Summary */}
                        {(split.description || inc.summary) && (
                          <div style={{ marginBottom: 14 }}>
                            {split.description && (
                              <div style={{
                                fontSize: 13, lineHeight: 1.5, color: "var(--tc-text)",
                                marginBottom: inc.summary ? 8 : 0, fontWeight: 500,
                              }}>
                                {split.description}
                              </div>
                            )}
                            {inc.summary && (
                              <div style={{
                                fontSize: 12, lineHeight: 1.6, color: "var(--tc-text-sec)",
                                whiteSpace: "pre-wrap",
                              }}>
                                {inc.summary}
                              </div>
                            )}
                          </div>
                        )}
                        {!split.description && !inc.summary && (
                          <div style={{
                            marginBottom: 14, fontSize: 12,
                            color: "var(--tc-text-muted)", fontStyle: "italic",
                          }}>
                            {locale === "fr"
                              ? "Investigation en cours — pas encore de résumé disponible."
                              : "Investigation in progress — no summary yet."}
                          </div>
                        )}

                        {/* Executable actions */}
                        {isOpen && executableActions.length > 0 && (
                          <div style={{
                            marginBottom: 16,
                            padding: "12px 14px",
                            background: "rgba(208,48,32,0.06)",
                            border: "1px solid rgba(208,48,32,0.2)",
                          }}>
                            <div className="inc-exp-section-head" style={{ color: "#d03020" }}>
                              <Zap size={11} />
                              {locale === "fr" ? "Que faire maintenant" : "What to do now"}
                            </div>
                            {recoSource === "rules" && (
                              <div style={{ fontSize: 10, color: "var(--tc-text-muted)", marginBottom: 10, fontStyle: "italic", fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>
                                {locale === "fr"
                                  ? "Actions suggérées automatiquement. Chaque exécution passe par confirmation + license check."
                                  : "Auto-suggested actions. Each execution goes through confirmation + license check."}
                              </div>
                            )}
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: recoSource === "ai" ? 6 : 0 }}>
                              {executableActions.map((act, i) => (
                                <button
                                  key={i}
                                  onClick={() => setConfirmAction({ incident: inc, action: act })}
                                  className="inc-action-exec-btn"
                                  title={act.description}
                                >
                                  {actionIcon(act.kind)}
                                  <span style={{ flex: 1, textAlign: "left" }}>{act.description}</span>
                                </button>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Manual checklist */}
                        {isOpen && recoBundle.manual.length > 0 && (
                          <div style={{
                            marginBottom: 14, padding: "10px 12px",
                            background: "var(--tc-surface)",
                            border: "1px solid var(--tc-border)",
                          }}>
                            <div className="inc-exp-section-head">
                              <CheckCircle2 size={10} />
                              {locale === "fr" ? "À faire à la main" : "Manual checklist"}
                            </div>
                            <ul style={{ margin: 0, paddingLeft: 16, fontSize: 12, color: "var(--tc-text-sec)", lineHeight: 1.6 }}>
                              {recoBundle.manual.map((r, i) => (
                                <li key={i} style={{ marginBottom: 3 }}>{r}</li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* Blast Radius */}
                        <BlastRadiusCard
                          incidentId={inc.id}
                          snapshot={inc.blast_radius_snapshot}
                          score={inc.blast_radius_score}
                          computedAt={inc.blast_radius_computed_at}
                          locale={locale}
                          onRecomputed={(fresh) => {
                            setIncidents((prev) =>
                              prev.map((p) =>
                                p.id === inc.id
                                  ? {
                                      ...p,
                                      blast_radius_snapshot: fresh,
                                      blast_radius_score: fresh.score,
                                      blast_radius_computed_at: new Date().toISOString(),
                                    }
                                  : p,
                              ),
                            );
                          }}
                        />

                        {/* Context: IOCs + MITRE */}
                        {(iocs.length > 0 || (inc.mitre_techniques && inc.mitre_techniques.length > 0)) && (
                          <div style={{ marginBottom: 14, padding: "10px 12px", background: "var(--tc-surface)", border: "1px solid var(--tc-border)" }}>
                            <div className="inc-exp-section-head">
                              <Search size={10} />
                              {locale === "fr" ? "Contexte" : "Context"}
                            </div>
                            {iocs.length > 0 && (
                              <div style={{ marginBottom: 6, fontSize: 11 }}>
                                <span style={{ color: "var(--tc-text-muted)", marginRight: 6, fontFamily: "ui-monospace, 'JetBrains Mono', monospace", fontSize: 10 }}>IOCs :</span>
                                {iocs.map((ioc, i) => (
                                  <span key={i} style={{ fontSize: 10, padding: "2px 6px", background: "rgba(208,48,32,0.12)", color: "#d03020", marginRight: 4, fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>{ioc}</span>
                                ))}
                              </div>
                            )}
                            {inc.mitre_techniques && inc.mitre_techniques.length > 0 && (
                              <div style={{ fontSize: 11 }}>
                                <span style={{ color: "var(--tc-text-muted)", marginRight: 6, fontFamily: "ui-monospace, 'JetBrains Mono', monospace", fontSize: 10 }}>MITRE :</span>
                                {inc.mitre_techniques.map(t => (
                                  <span key={t} style={{ fontSize: 10, padding: "2px 6px", background: "rgba(64,144,255,0.15)", color: "#4090ff", marginRight: 4, fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>{t}</span>
                                ))}
                              </div>
                            )}
                          </div>
                        )}

                        {/* Manual/informational actions */}
                        {isOpen && actions.length > executableActions.length && (
                          <div style={{ marginBottom: 14 }}>
                            <div className="inc-exp-section-head">
                              <Search size={10} />
                              {locale === "fr" ? "Actions manuelles suggérées" : "Suggested manual actions"}
                            </div>
                            <ul style={{ margin: 0, paddingLeft: 16, fontSize: 12, color: "var(--tc-text-muted)" }}>
                              {actions.filter(a => a.kind === "manual").map((act, i) => (
                                <li key={i} style={{ marginBottom: 4 }}>{act.description}</li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* RSSI decisions */}
                        {isOpen && (
                          <div style={{ marginBottom: 14 }}>
                            <div className="inc-exp-section-head">
                              <CheckCircle2 size={10} />
                              {locale === "fr" ? "Décision RSSI" : "CISO decision"}
                            </div>
                            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                              <button
                                className="inc-decision-btn"
                                onClick={() => setConfirmFp(inc)}
                                title={locale === "fr"
                                  ? "Ferme l'incident et le classe en faux positif."
                                  : "Closes the incident and classifies it as false positive."}
                              >
                                <XCircle size={11} />
                                {locale === "fr" ? "Marquer faux positif" : "Mark false positive"}
                              </button>
                              <button
                                className="inc-decision-btn"
                                onClick={() => reinvestigate(inc.id)}
                                title={locale === "fr"
                                  ? "Relance l'investigation IA avec les données fraîches."
                                  : "Re-runs AI investigation with fresh data."}
                              >
                                <Brain size={11} />
                                {locale === "fr" ? "Relancer l'investigation" : "Re-investigate"}
                              </button>
                              <button
                                className="inc-decision-btn"
                                onClick={() => router.push(`/investigate/${inc.id}`)}
                                style={{ color: "#4a9eff", borderColor: "rgba(74,158,255,0.35)", background: "rgba(74,158,255,0.1)" }}
                                title={locale === "fr"
                                  ? "Ouvre le dossier d'investigation complet."
                                  : "Opens the full investigation dossier."}
                              >
                                <FileText size={11} />
                                {locale === "fr" ? "Ouvrir le rapport" : "Open report"}
                              </button>
                              <button
                                className="inc-decision-btn"
                                onClick={() => setSuppressingIncident(inc)}
                                title={locale === "fr"
                                  ? "Crée une règle de suppression pour ce pattern."
                                  : "Creates a suppression rule for this pattern."}
                              >
                                <Filter size={11} />
                                {locale === "fr" ? "Ignorer ce pattern" : "Ignore this pattern"}
                              </button>
                            </div>
                          </div>
                        )}

                        {/* Archive when resolved */}
                        {!isOpen && inc.status !== "archived" && (
                          <div style={{ marginBottom: 14 }}>
                            <button className="inc-decision-btn" onClick={() => archiveOne(inc.id)}>
                              <FileText size={11} />
                              {locale === "fr" ? "Archiver" : "Archive"}
                            </button>
                          </div>
                        )}

                        {/* Notes */}
                        <div style={{ marginBottom: 8 }}>
                          <div className="inc-exp-section-head">
                            <MessageSquare size={10} />
                            {locale === "fr" ? "Notes & historique" : "Notes & history"}
                          </div>
                          {inc.notes && inc.notes.length > 0 && (
                            <div style={{ display: "flex", flexDirection: "column", gap: 4, marginBottom: 8, maxHeight: 200, overflowY: "auto" }}>
                              {inc.notes.map((n, i) => (
                                <div key={i} style={{ padding: "6px 10px", background: "var(--tc-surface)", border: "1px solid var(--tc-border)", fontSize: 11 }}>
                                  <div style={{ color: "var(--tc-text)", marginBottom: 2 }}>{n.text}</div>
                                  <div style={{ color: "var(--tc-text-muted)", fontSize: 9, fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>
                                    {n.author} · {new Date(n.at).toLocaleString(locale === "fr" ? "fr-FR" : "en-US", { dateStyle: "short", timeStyle: "short" })}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                          <div style={{ display: "flex", gap: 6 }}>
                            <input
                              type="text"
                              value={noteInput[inc.id] || ""}
                              onChange={e => setNoteInput(prev => ({ ...prev, [inc.id]: e.target.value }))}
                              onKeyDown={e => { if (e.key === "Enter") addNote(inc.id); }}
                              placeholder={locale === "fr" ? "Ajouter une note..." : "Add a note..."}
                              style={{
                                flex: 1, padding: "6px 10px", fontSize: 11, fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                                background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                                color: "var(--tc-text)",
                              }}
                            />
                            <button
                              onClick={() => addNote(inc.id)}
                              disabled={!(noteInput[inc.id] || "").trim()}
                              style={{
                                padding: "6px 12px", fontSize: 11, fontWeight: 700, fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                                cursor: (noteInput[inc.id] || "").trim() ? "pointer" : "not-allowed",
                                background: "var(--tc-red)", color: "#fff", border: "none",
                                display: "flex", alignItems: "center", gap: 4,
                                opacity: (noteInput[inc.id] || "").trim() ? 1 : 0.5,
                              }}
                            >
                              <Send size={11} />
                            </button>
                          </div>
                        </div>

                        {/* Legacy HITL response badge */}
                        {inc.hitl_response && (
                          <div style={{ marginTop: 8, fontSize: 10, color: "var(--tc-text-muted)", fontStyle: "italic", fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>
                            HITL: {inc.hitl_response} (via {inc.hitl_status})
                          </div>
                        )}
                      </div>
                    );
                  })()}
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
                {locale === "fr" ? "Confirmer l'action" : "Confirm action"}
              </h3>
            </div>

            <div style={{ fontSize: 13, color: "var(--tc-text)", marginBottom: 16, lineHeight: 1.6 }}>
              {locale === "fr"
                ? `Vous êtes sur le point d'exécuter cette action sur l'incident #${confirmAction.incident.id} :`
                : `You are about to execute this action on incident #${confirmAction.incident.id}:`}
            </div>

            <div style={{ padding: "10px 12px", background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)", marginBottom: 14 }}>
              <div style={{ fontSize: 12, color: "var(--tc-text)", fontWeight: 600, marginBottom: 4 }}>
                {confirmAction.action.description}
              </div>
              <div style={{ fontSize: 10, color: "var(--tc-text-muted)", fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>
                kind: {confirmAction.action.kind}  ·  asset: {confirmAction.incident.asset}
              </div>
            </div>

            <div style={{ padding: "9px 11px", background: "rgba(208,48,32,0.08)", border: "1px solid rgba(208,48,32,0.2)", marginBottom: 18 }}>
              <div style={{ fontSize: 11, color: "#d03020", lineHeight: 1.5, fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>
                {locale === "fr"
                  ? "Cette action passe par remediation_engine et remediation_guard. Elle sera loggée dans l'audit trail et notifiée au canal HITL."
                  : "This goes through remediation_engine and remediation_guard. It will be logged in the audit trail and notified to the HITL channel."}
              </div>
            </div>

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button
                onClick={() => setConfirmAction(null)}
                disabled={executing}
                className="inc-decision-btn"
              >
                {locale === "fr" ? "Annuler" : "Cancel"}
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
                {executing ? (locale === "fr" ? "Exécution..." : "Executing...") : (locale === "fr" ? "Confirmer et exécuter" : "Confirm and execute")}
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

function FindingsTab({ locale }: { locale: string }) {
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
    } catch { setError(locale === "fr" ? "Erreur chargement" : "Load error"); }
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
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder={locale === "fr" ? "Rechercher..." : "Search..."}
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
              {st === "open" ? (locale === "fr" ? "Ouvert" : "Open") : st === "in_progress" ? (locale === "fr" ? "En cours" : "In progress") : (locale === "fr" ? "Resolu" : "Resolved")}
            </button>
          );
        })}
        <ChromeButton onClick={load} variant="glass"><RefreshCw size={14} /></ChromeButton>
      </div>

      {/* Findings list */}
      {loading ? (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{locale === "fr" ? "Chargement..." : "Loading..."}</div></NeuCard>
      ) : filtered.length === 0 ? (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{locale === "fr" ? "Aucun finding" : "No findings"}</div></NeuCard>
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
                    <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--tc-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</div>
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
                    {f.description && <div style={{ fontSize: "12px", color: "var(--tc-text-sec)", lineHeight: 1.6, marginBottom: "12px", whiteSpace: "pre-line" }}>{f.description}</div>}
                    {f.metadata && (
                      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "10px" }}>
                        {f.metadata.src_ip && <span style={{ fontSize: "10px", padding: "3px 8px", background: "rgba(232,64,64,0.08)", color: "var(--tc-red)", border: "1px solid rgba(232,64,64,0.15)", fontFamily: "monospace" }}>src: {String(f.metadata.src_ip)}</span>}
                        {f.metadata.cve && <span style={{ fontSize: "10px", padding: "3px 8px", background: "rgba(208,48,32,0.08)", color: "var(--tc-red)", border: "1px solid rgba(208,48,32,0.15)", fontFamily: "monospace" }}>{String(f.metadata.cve)}</span>}
                        {f.metadata.mitre && Array.isArray(f.metadata.mitre) && <span style={{ fontSize: "10px", padding: "3px 8px", background: "rgba(128,64,208,0.08)", color: "#8040d0", border: "1px solid rgba(128,64,208,0.15)", fontFamily: "monospace" }}>MITRE: {(f.metadata.mitre as string[]).join(", ")}</span>}
                      </div>
                    )}
                    <div style={{ display: "flex", gap: "6px" }}>
                      {f.status !== "resolved" && <ChromeButton onClick={() => changeStatus(f.id, "resolved")} variant="glass"><CheckCircle2 size={12} /> {locale === "fr" ? "Resolu" : "Resolved"}</ChromeButton>}
                      {f.status !== "false_positive" && <ChromeButton onClick={() => changeStatus(f.id, "false_positive")} variant="glass"><XCircle size={12} /> {locale === "fr" ? "Faux positif" : "False positive"}</ChromeButton>}
                      <ChromeButton onClick={async () => {
                        try {
                          const res = await fetch("/api/tc/connectors/glpi/ticket", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ finding_id: f.id }) });
                          const data = await res.json();
                          if (data.ticket_id) alert(`Ticket GLPI #${data.ticket_id}`);
                          else if (data.error) alert(data.error);
                        } catch { alert("GLPI non configure"); }
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

function AlertsTab({ locale }: { locale: string }) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterLevel, setFilterLevel] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await fetchAlerts({ level: filterLevel || undefined, limit: 200 });
      setAlerts(data.alerts || []); setError(null);
    } catch { setError(locale === "fr" ? "Erreur chargement" : "Load error"); }
    setLoading(false);
  }, [filterLevel, locale]);

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  const archiveResolvedAlerts = async () => {
    const msg = locale === "fr"
      ? "Archiver toutes les alertes traitees/resolues ? (reversible — purge definitive apres 60 jours)"
      : "Archive all acknowledged/resolved alerts? (reversible — permanent purge after 60 days)";
    if (!confirm(msg)) return;
    try {
      const res = await fetch("/api/tc/alerts/archive-resolved", { method: "POST" });
      const data = await res.json();
      alert(locale === "fr" ? `${data.archived} alertes archivees` : `${data.archived} alerts archived`);
      load();
    } catch (e: any) {
      alert("Erreur: " + e.message);
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
              color: active ? color : "var(--tc-text-muted)", cursor: "pointer", fontFamily: "inherit", textTransform: "uppercase",
              fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
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
          {locale === "fr" ? "Archiver le resolu" : "Archive resolved"}
        </button>
        <ChromeButton onClick={load} variant="glass"><RefreshCw size={14} /></ChromeButton>
      </div>

      {loading ? (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{locale === "fr" ? "Chargement..." : "Loading..."}</div></NeuCard>
      ) : alerts.length === 0 ? (
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{locale === "fr" ? "Aucune alerte" : "No alerts"}</div></NeuCard>
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
      title={locale === "fr" ? "Incidents" : "Incidents"}
      subtitle={
        locale === "fr"
          ? "Incidents confirmés par l'Intelligence Engine, à trier par le RSSI."
          : "IE-confirmed incidents awaiting RSSI triage."
      }
    >
      <IncidentsTab locale={locale} />
    </PageShell>
  );
}

function getTimeAgo(iso: string, locale: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return locale === "fr" ? "a l'instant" : "just now";
  if (mins < 60) return locale === "fr" ? `il y a ${mins}min` : `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return locale === "fr" ? `il y a ${hours}h` : `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return locale === "fr" ? `il y a ${days}j` : `${days}d ago`;
}

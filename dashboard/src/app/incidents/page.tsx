"use client";
// Unified Incidents page — Incidents (confirmed) + Findings (vulns) + Alerts (sigma)
import React, { useState, useEffect, useCallback } from "react";
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
  Clock, Search, X, FileText, Eye, Zap, Ban, MessageSquare, Ticket, UserX, Send, Brain,
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
      padding: "2px 8px", borderRadius: 4,
      background: "rgba(48,128,208,0.12)", color: "#3080d0",
      fontWeight: 700, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.04em",
      whiteSpace: "nowrap",
    }}>
      🔄 {locale === "fr" ? "scan en cours" : "scan in progress"}
    </span>
  );
}

interface Incident {
  id: number;
  asset: string;
  title: string;
  summary: string | null;
  verdict: string;
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

const verdictBadge: Record<string, { color: string; labelFr: string; labelEn: string }> = {
  pending: { color: "#888", labelFr: "En cours...", labelEn: "Pending..." },
  confirmed: { color: "#ff4040", labelFr: "Confirme", labelEn: "Confirmed" },
  false_positive: { color: "#30a050", labelFr: "Faux positif", labelEn: "False positive" },
  inconclusive: { color: "#e0a020", labelFr: "Inconclusif", labelEn: "Inconclusive" },
  investigating: { color: "#4090ff", labelFr: "Investigation", labelEn: "Investigating" },
};

function IncidentsTab({ locale }: { locale: string }) {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [filter, setFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [confirmAction, setConfirmAction] = useState<{ incident: Incident; action: IncidentAction } | null>(null);
  const [suppressingIncident, setSuppressingIncident] = useState<Incident | null>(null);
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
        alert((locale === "fr" ? "✅ Action exécutée : " : "✅ Action executed: ") + (data.message || ""));
        setConfirmAction(null);
        load();
      } else {
        const err = await res.text();
        alert((locale === "fr" ? "❌ Échec : " : "❌ Failed: ") + err);
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
          ? "✅ Investigation relancée. Le résultat apparaîtra dans 10-30 secondes (rafraîchissement auto)."
          : "✅ Investigation restarted. Results will appear in 10-30 seconds (auto-refresh).");
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

  return (
    <div>
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
      <div style={{ display: "flex", gap: 6, marginBottom: 16, alignItems: "center", flexWrap: "wrap" }}>
        {filters.map(f => (
          <button key={f.key} onClick={() => setFilter(f.key)} style={{
            padding: "6px 14px", borderRadius: "var(--tc-radius-sm)", fontSize: 11, fontWeight: 600,
            border: filter === f.key ? "1px solid #d03020" : "1px solid var(--tc-border)",
            background: filter === f.key ? "rgba(208,48,32,0.15)" : "var(--tc-surface-alt)",
            color: filter === f.key ? "#d03020" : "var(--tc-text-muted)", cursor: "pointer", fontFamily: "inherit",
          }}>{f.label}</button>
        ))}
        <div style={{ flex: 1 }} />
        <button onClick={archiveResolved} style={{
          padding: "6px 14px", borderRadius: "var(--tc-radius-sm)", fontSize: 11, fontWeight: 600,
          border: "1px solid var(--tc-border)", background: "var(--tc-surface-alt)",
          color: "var(--tc-text-muted)", cursor: "pointer", fontFamily: "inherit",
          display: "flex", alignItems: "center", gap: 6,
        }}>
          <FileText size={12} />
          {locale === "fr" ? "Archiver le resolu" : "Archive resolved"}
        </button>
      </div>

      {loading && <div style={{ color: "var(--tc-text-muted)", textAlign: "center", padding: 40 }}>{locale === "fr" ? "Chargement..." : "Loading..."}</div>}

      {!loading && incidents.length === 0 && (
        <NeuCard style={{ textAlign: "center", padding: 40 }}>
          <CheckCircle2 size={40} color="var(--tc-green)" style={{ marginBottom: 12 }} />
          <div style={{ fontSize: 16, fontWeight: 600, color: "var(--tc-text)" }}>{locale === "fr" ? "Aucun incident" : "No incidents"}</div>
          <div style={{ fontSize: 12, marginTop: 6, color: "var(--tc-text-muted)" }}>{locale === "fr" ? "Tout est sous controle" : "Everything is under control"}</div>
        </NeuCard>
      )}

      {incidents.map(inc => {
        const isExpanded = expanded === inc.id;
        const badge = verdictBadge[inc.verdict] || verdictBadge.pending;
        const sevColor = severityColor[inc.severity || "MEDIUM"] || "#888";

        return (
          <NeuCard key={inc.id} style={{ padding: 0, marginBottom: 8, borderRadius: "var(--tc-radius-card)", overflow: "hidden" }}>
            <div onClick={() => setExpanded(isExpanded ? null : inc.id)} style={{
              padding: "16px 18px", cursor: "pointer",
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                    <span style={{ fontSize: 14, fontWeight: 700, color: "var(--tc-text)" }}>#{inc.id}</span>
                    <span style={{ fontSize: 14, fontWeight: 600, color: "var(--tc-text)" }}>{inc.title}</span>
                  </div>
                  <div style={{ display: "flex", gap: 8, fontSize: 11, flexWrap: "wrap" }}>
                    <span style={{ padding: "2px 8px", borderRadius: 4, background: `${sevColor}22`, color: sevColor, fontWeight: 600 }}>{inc.severity}</span>
                    <span style={{ padding: "2px 8px", borderRadius: 4, background: `${badge.color}22`, color: badge.color, fontWeight: 600 }}>
                      {locale === "fr" ? badge.labelFr : badge.labelEn}{inc.confidence ? ` ${Math.round(inc.confidence * 100)}%` : ""}
                    </span>
                    <span style={{ color: "var(--tc-text-muted)" }}>
                      {inc.asset} &middot; {inc.alert_count || 0} {locale === "fr" ? "alertes" : "alerts"} &middot; {getTimeAgo(inc.created_at, locale)}
                    </span>
                    {inc.asset && <ScanInProgressBadge assetId={inc.asset} locale={locale} />}
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 10, padding: "3px 8px", borderRadius: 6, background: inc.status === "open" ? "rgba(255,64,64,0.15)" : "rgba(48,160,80,0.15)", color: inc.status === "open" ? "#ff4040" : "#30a050", fontWeight: 700, textTransform: "uppercase" }}>{inc.status}</span>
                  <ChevronDown size={14} color="var(--tc-text-muted)" style={{ transform: isExpanded ? "rotate(180deg)" : "none", transition: "0.2s" }} />
                </div>
              </div>
            </div>

            {isExpanded && (() => {
              const actions: IncidentAction[] = (inc.proposed_actions?.actions || []) as IncidentAction[];
              const iocs: string[] = (inc.proposed_actions?.iocs || []) as string[];
              const isOpen = inc.status !== "resolved" && inc.status !== "closed" && inc.status !== "archived";
              const executableActions = actions.filter(a => a.kind !== "manual");
              return (
              <div style={{ padding: "16px 18px", borderTop: "1px solid var(--tc-border-light)" }}>
                {/* Phase D — action-first layout. The RSSI must see what
                    to do BEFORE the technical context. Hero block at the
                    top with prominent HITL buttons; everything else (blast
                    radius, IOCs, MITRE, summary, triage) is moved down. */}

                {/* Hero — summary + primary actions */}
                {inc.summary && (
                  <div style={{ fontSize: 13, lineHeight: 1.6, color: "var(--tc-text)", marginBottom: 14, whiteSpace: "pre-wrap" }}>
                    {inc.summary}
                  </div>
                )}

                {isOpen && executableActions.length > 0 && (
                  <div style={{
                    marginBottom: 16,
                    padding: "14px 16px",
                    background: "linear-gradient(180deg, rgba(208,48,32,0.08) 0%, rgba(208,48,32,0.02) 100%)",
                    border: "1px solid rgba(208,48,32,0.25)",
                    borderRadius: "var(--tc-radius-sm)",
                  }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: "#d03020", textTransform: "uppercase", marginBottom: 10, display: "flex", alignItems: "center", gap: 6, letterSpacing: 0.5 }}>
                      <Zap size={13} /> {locale === "fr" ? "Que faire maintenant" : "What to do now"}
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                      {executableActions.map((act, i) => (
                        <button key={i} onClick={() => setConfirmAction({ incident: inc, action: act })} style={{
                          padding: "10px 16px", fontSize: 13, fontWeight: 600, fontFamily: "inherit",
                          cursor: "pointer", background: "#d03020", color: "#fff",
                          border: "1px solid #b02818", borderRadius: "var(--tc-radius-sm)",
                          display: "flex", alignItems: "center", gap: 8, minWidth: 160,
                          boxShadow: "0 1px 3px rgba(208,48,32,0.3)",
                        }} title={act.description}>
                          {actionIcon(act.kind)}
                          <span style={{ flex: 1, textAlign: "left" }}>{act.description}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {isOpen && executableActions.length === 0 && (
                  <div style={{ marginBottom: 14, padding: "10px 14px", fontSize: 12, color: "var(--tc-text-muted)", background: "var(--tc-surface-alt)", borderRadius: "var(--tc-radius-sm)", border: "1px dashed var(--tc-border)" }}>
                    {locale === "fr"
                      ? "Aucune action HITL automatisée n'est proposée pour cet incident. Utilise les boutons de décision RSSI ci-dessous ou ajoute une note."
                      : "No automated HITL action proposed for this incident. Use the CISO decision buttons below or add a note."}
                  </div>
                )}

                {/* Blast Radius (ADR-048) — kept but moved below the hero */}
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
                  <div style={{ marginBottom: 16, padding: "12px 14px", background: "var(--tc-surface-alt)", borderRadius: "var(--tc-radius-sm)", border: "1px solid var(--tc-border-light)" }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
                      <Search size={11} /> {locale === "fr" ? "Contexte" : "Context"}
                    </div>
                    {iocs.length > 0 && (
                      <div style={{ marginBottom: 6, fontSize: 11 }}>
                        <span style={{ color: "var(--tc-text-muted)", marginRight: 6 }}>IOCs :</span>
                        {iocs.map((ioc, i) => (
                          <span key={i} style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: "rgba(208,48,32,0.12)", color: "#d03020", marginRight: 4, fontFamily: "monospace" }}>{ioc}</span>
                        ))}
                      </div>
                    )}
                    {inc.mitre_techniques && inc.mitre_techniques.length > 0 && (
                      <div style={{ fontSize: 11 }}>
                        <span style={{ color: "var(--tc-text-muted)", marginRight: 6 }}>MITRE :</span>
                        {inc.mitre_techniques.map(t => (
                          <span key={t} style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: "rgba(64,144,255,0.15)", color: "#4090ff", marginRight: 4 }}>{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Manual / informational actions list (proposed but not
                    auto-executable — operator follows them out of band). */}
                {isOpen && actions.length > executableActions.length && (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
                      <Search size={11} /> {locale === "fr" ? "Actions manuelles suggérées" : "Suggested manual actions"}
                    </div>
                    <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: "var(--tc-text-muted)" }}>
                      {actions.filter(a => a.kind === "manual").map((act, i) => (
                        <li key={i} style={{ marginBottom: 4 }}>{act.description}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* RSSI decision buttons */}
                {isOpen && (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
                      <CheckCircle2 size={11} /> {locale === "fr" ? "Décision RSSI" : "CISO decision"}
                    </div>
                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                      <button onClick={() => markFalsePositive(inc.id)} style={{
                        padding: "6px 14px", fontSize: 11, fontWeight: 600, fontFamily: "inherit", cursor: "pointer",
                        background: "var(--tc-surface-alt)", color: "var(--tc-text-muted)",
                        border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
                        display: "flex", alignItems: "center", gap: 6,
                      }}>
                        <XCircle size={12} />
                        {locale === "fr" ? "Marquer faux positif" : "Mark false positive"}
                      </button>
                      <button onClick={() => reinvestigate(inc.id)} style={{
                        padding: "6px 14px", fontSize: 11, fontWeight: 600, fontFamily: "inherit", cursor: "pointer",
                        background: "var(--tc-surface-alt)", color: "var(--tc-text-muted)",
                        border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
                        display: "flex", alignItems: "center", gap: 6,
                      }}>
                        <Brain size={12} />
                        {locale === "fr" ? "Relancer l'investigation" : "Re-investigate"}
                      </button>
                      <button onClick={() => setSuppressingIncident(inc)} style={{
                        padding: "6px 14px", fontSize: 11, fontWeight: 600, fontFamily: "inherit", cursor: "pointer",
                        background: "var(--tc-surface-alt)", color: "var(--tc-text-muted)",
                        border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
                        display: "flex", alignItems: "center", gap: 6,
                      }} title={locale === "fr" ? "Créer une règle de suppression pour ce pattern récurrent" : "Create a suppression rule for this recurring pattern"}>
                        ⚙️
                        {locale === "fr" ? "Ignorer ce pattern" : "Ignore this pattern"}
                      </button>
                    </div>
                  </div>
                )}

                {/* Archive button when resolved */}
                {!isOpen && inc.status !== "archived" && (
                  <div style={{ marginBottom: 16 }}>
                    <button onClick={() => archiveOne(inc.id)} style={{
                      padding: "6px 14px", fontSize: 11, fontWeight: 600, fontFamily: "inherit", cursor: "pointer",
                      background: "var(--tc-surface-alt)", color: "var(--tc-text-muted)",
                      border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
                      display: "flex", alignItems: "center", gap: 6,
                    }}>
                      <FileText size={12} />
                      {locale === "fr" ? "Archiver" : "Archive"}
                    </button>
                  </div>
                )}

                {/* RSSI note input + history */}
                <div style={{ marginBottom: 8 }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
                    <MessageSquare size={11} /> {locale === "fr" ? "Notes & historique" : "Notes & history"}
                  </div>
                  {/* Existing notes */}
                  {inc.notes && inc.notes.length > 0 && (
                    <div style={{ display: "flex", flexDirection: "column", gap: 4, marginBottom: 8, maxHeight: 200, overflowY: "auto" }}>
                      {inc.notes.map((n, i) => (
                        <div key={i} style={{ padding: "6px 10px", background: "var(--tc-surface-alt)", borderRadius: "var(--tc-radius-sm)", fontSize: 11 }}>
                          <div style={{ color: "var(--tc-text)", marginBottom: 2 }}>{n.text}</div>
                          <div style={{ color: "var(--tc-text-muted)", fontSize: 9 }}>
                            {n.author}{new Date(n.at).toLocaleString(locale === "fr" ? "fr-FR" : "en-US", { dateStyle: "short", timeStyle: "short" })}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  {/* Add note */}
                  <div style={{ display: "flex", gap: 6 }}>
                    <input type="text" value={noteInput[inc.id] || ""}
                      onChange={e => setNoteInput(prev => ({ ...prev, [inc.id]: e.target.value }))}
                      onKeyDown={e => { if (e.key === "Enter") addNote(inc.id); }}
                      placeholder={locale === "fr" ? "Ajouter une note..." : "Add a note..."}
                      style={{
                        flex: 1, padding: "6px 10px", fontSize: 11, fontFamily: "inherit",
                        background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                        borderRadius: "var(--tc-radius-sm)", color: "var(--tc-text)",
                      }} />
                    <button onClick={() => addNote(inc.id)} disabled={!(noteInput[inc.id] || "").trim()} style={{
                      padding: "6px 12px", fontSize: 11, fontWeight: 600, fontFamily: "inherit",
                      cursor: (noteInput[inc.id] || "").trim() ? "pointer" : "not-allowed",
                      background: "var(--tc-red)", color: "#fff", border: "none",
                      borderRadius: "var(--tc-radius-sm)", display: "flex", alignItems: "center", gap: 4,
                      opacity: (noteInput[inc.id] || "").trim() ? 1 : 0.5,
                    }}>
                      <Send size={11} />
                    </button>
                  </div>
                </div>

                {/* Legacy HITL response badge (from Telegram) */}
                {inc.hitl_response && (
                  <div style={{ marginTop: 8, fontSize: 10, color: "var(--tc-text-muted)", fontStyle: "italic" }}>
                    HITL: {inc.hitl_response} (via {inc.hitl_status})
                  </div>
                )}
              </div>
              );
            })()}
          </NeuCard>
        );
      })}

      {/* Confirmation modal for action execution */}
      {confirmAction && (
        <div onClick={() => !executing && setConfirmAction(null)} style={{
          position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)",
          display: "flex", alignItems: "center", justifyContent: "center",
          zIndex: 1000, padding: 20,
        }}>
          <div onClick={e => e.stopPropagation()} style={{
            background: "var(--tc-bg)", borderRadius: "var(--tc-radius-card)",
            border: "1px solid var(--tc-border)", padding: 24, maxWidth: 520, width: "100%",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
              {actionIcon(confirmAction.action.kind)}
              <h3 style={{ fontSize: 16, fontWeight: 700, color: "var(--tc-text)", margin: 0 }}>
                {locale === "fr" ? "Confirmer l'action" : "Confirm action"}
              </h3>
            </div>

            <div style={{ fontSize: 13, color: "var(--tc-text)", marginBottom: 16, lineHeight: 1.6 }}>
              {locale === "fr"
                ? `Vous êtes sur le point d'exécuter cette action sur l'incident #${confirmAction.incident.id} :`
                : `You are about to execute this action on incident #${confirmAction.incident.id}:`}
            </div>

            <div style={{ padding: "12px 14px", background: "var(--tc-surface-alt)", borderRadius: "var(--tc-radius-sm)", border: "1px solid var(--tc-border-light)", marginBottom: 16 }}>
              <div style={{ fontSize: 12, color: "var(--tc-text)", fontWeight: 600, marginBottom: 4 }}>
                {confirmAction.action.description}
              </div>
              <div style={{ fontSize: 10, color: "var(--tc-text-muted)", fontFamily: "monospace" }}>
                kind: {confirmAction.action.kind}  ·  asset: {confirmAction.incident.asset}
              </div>
            </div>

            <div style={{ padding: "10px 12px", background: "rgba(208,48,32,0.08)", borderRadius: "var(--tc-radius-sm)", border: "1px solid rgba(208,48,32,0.2)", marginBottom: 20 }}>
              <div style={{ fontSize: 11, color: "#d03020", lineHeight: 1.5 }}>
                ⚠️ {locale === "fr"
                  ? "Cette action passe par remediation_engine et remediation_guard. Elle sera loggée dans l'audit trail et notifiée au canal HITL."
                  : "This goes through remediation_engine and remediation_guard. It will be logged in the audit trail and notified to the HITL channel."}
              </div>
            </div>

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button onClick={() => setConfirmAction(null)} disabled={executing} style={{
                padding: "8px 16px", fontSize: 12, fontWeight: 600, fontFamily: "inherit", cursor: "pointer",
                background: "var(--tc-surface-alt)", color: "var(--tc-text-muted)",
                border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
              }}>
                {locale === "fr" ? "Annuler" : "Cancel"}
              </button>
              <button onClick={executeAction} disabled={executing} style={{
                padding: "8px 16px", fontSize: 12, fontWeight: 600, fontFamily: "inherit",
                cursor: executing ? "not-allowed" : "pointer",
                background: "#d03020", color: "#fff", border: "none",
                borderRadius: "var(--tc-radius-sm)", display: "flex", alignItems: "center", gap: 6,
                opacity: executing ? 0.6 : 1,
              }}>
                <Zap size={12} />
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
              padding: "8px 14px", borderRadius: "var(--tc-radius-md)", border: `1px solid ${active ? s.border : "var(--tc-border)"}`,
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
        <div style={{ flex: 1, display: "flex", alignItems: "center", gap: "8px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-md)", padding: "8px 12px" }}>
          <Search size={14} color="var(--tc-text-muted)" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder={locale === "fr" ? "Rechercher..." : "Search..."}
            style={{ flex: 1, background: "none", border: "none", outline: "none", color: "var(--tc-text)", fontSize: "13px", fontFamily: "inherit" }} />
          {search && <button onClick={() => setSearch("")} style={{ background: "none", border: "none", cursor: "pointer" }}><X size={14} color="var(--tc-text-muted)" /></button>}
        </div>
        {["open", "in_progress", "resolved"].map(st => {
          const active = filterStatus === st;
          return (
            <button key={st} onClick={() => setFilterStatus(active ? "" : st)} style={{
              padding: "8px 12px", borderRadius: "var(--tc-radius-md)", fontSize: "11px", fontWeight: 600,
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
                  <span style={{ fontSize: "10px", fontWeight: 700, padding: "3px 8px", borderRadius: "var(--tc-radius-sm)", background: sev.bg, color: sev.color, border: `1px solid ${sev.border}`, textTransform: "uppercase", flexShrink: 0 }}>{f.severity.toUpperCase()}</span>
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
                  <div style={{ marginTop: "14px", borderTop: "1px solid var(--tc-border-light)", paddingTop: "14px" }}>
                    {f.description && <div style={{ fontSize: "12px", color: "var(--tc-text-sec)", lineHeight: 1.6, marginBottom: "12px", whiteSpace: "pre-line" }}>{f.description}</div>}
                    {f.metadata && (
                      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "10px" }}>
                        {f.metadata.src_ip && <span style={{ fontSize: "10px", padding: "3px 8px", borderRadius: "var(--tc-radius-sm)", background: "rgba(232,64,64,0.08)", color: "var(--tc-red)", border: "1px solid rgba(232,64,64,0.15)", fontFamily: "monospace" }}>src: {String(f.metadata.src_ip)}</span>}
                        {f.metadata.cve && <span style={{ fontSize: "10px", padding: "3px 8px", borderRadius: "var(--tc-radius-sm)", background: "rgba(208,48,32,0.08)", color: "var(--tc-red)", border: "1px solid rgba(208,48,32,0.15)", fontFamily: "monospace" }}>{String(f.metadata.cve)}</span>}
                        {f.metadata.mitre && Array.isArray(f.metadata.mitre) && <span style={{ fontSize: "10px", padding: "3px 8px", borderRadius: "var(--tc-radius-sm)", background: "rgba(128,64,208,0.08)", color: "#8040d0", border: "1px solid rgba(128,64,208,0.15)", fontFamily: "monospace" }}>MITRE: {(f.metadata.mitre as string[]).join(", ")}</span>}
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
              padding: "6px 14px", borderRadius: "var(--tc-radius-sm)", fontSize: 11, fontWeight: 600,
              border: `1px solid ${active ? color : "var(--tc-border)"}`,
              background: active ? `${color}15` : "var(--tc-surface-alt)",
              color: active ? color : "var(--tc-text-muted)", cursor: "pointer", fontFamily: "inherit", textTransform: "uppercase",
            }}>{level}</button>
          );
        })}
        <div style={{ flex: 1 }} />
        <button onClick={archiveResolvedAlerts} style={{
          padding: "6px 14px", borderRadius: "var(--tc-radius-sm)", fontSize: 11, fontWeight: 600,
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
                  <span style={{ fontSize: "10px", fontWeight: 700, padding: "3px 8px", borderRadius: "var(--tc-radius-sm)", background: `${color}15`, color, border: `1px solid ${color}30`, textTransform: "uppercase", flexShrink: 0 }}>{a.level}</span>
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

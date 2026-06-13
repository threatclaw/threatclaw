"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useLocale } from "@/lib/useLocale";
import { t as tr, type Locale } from "@/lib/i18n";
import { PageShell } from "@/components/chrome/PageShell";
import {
  AlertTriangle, CheckCircle2, Clock, Download,
  Globe, RefreshCw, Shield, Target, Zap, Link2, BarChart2,
  FileText, Siren, Lock, X, Loader2, ArrowRight,
  MessageSquare, Send, Filter, XCircle, Archive, ArrowLeft, Brain, Search,
} from "lucide-react";
import SuppressionWizard from "@/components/incidents/SuppressionWizard";
import AttackTimeline from "@/components/incidents/AttackTimeline";
import InvestigationTimeline from "@/components/incidents/InvestigationTimeline";
import type { InvestigationStep } from "@/components/incidents/InvestigationTimeline";
import type { IncidentAction } from "@/types/incident_action";
import { kindShortLabel } from "@/types/incident_action";
import { displayAsset, displayAssetVerbose } from "@/types/asset_display";

// ─────────────────────────── types ───────────────────────────

// Phase 9a — `IncidentAction` is now imported from the shared TS module
// `@/types/incident_action`, which mirrors `src/agent/incident_action.rs`.
// The wire shape on `incidents.proposed_actions` is the canonical
// `{actions: IncidentAction[], iocs: string[]}` wrapper.

interface EvidenceCitation {
  claim: string;
  evidence_type: "alert" | "finding" | "log" | "graph_node";
  evidence_id: string;
  excerpt?: string;
}

interface AiAnalysis {
  id: number;
  incident_id: number;
  source: "react_l1" | "react_l2" | "manual";
  confidence: number | null;
  summary: string;
  skills_used: string[];
  mitre_added: string[];
  raw_output: Record<string, unknown> | null;
  created_at: string;
}

interface GraphExecution {
  id: number;
  graph_name: string;
  status: string;
  outcome: string | null;
  archive_reason: string | null;
  incident_id: number | null;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
}

interface IpEnrichment {
  ip: string;
  is_malicious: boolean;
  classification: string;
  noise: boolean;
  riot: boolean;
  greynoise_name: string | null;
  spamhaus_listed: boolean;
  spamhaus_lists: string[];
  country: string | null;
  asn: string | null;
}

interface AttackPath {
  id: number;
  src_asset: string;
  dst_asset: string;
  path_assets: string[];
  risk_score: number;
  hop_count: number;
}

interface IncidentNote {
  text: string;
  author: string;
  at: string;
}

interface Incident {
  id: number;
  asset: string;
  // Phase 9f — backend hydrates these from the assets table so the UI never
  // has to render the raw canonical id. Stay nullable: legacy incidents and
  // assets removed from inventory will not have them.
  asset_name?: string | null;
  asset_hostname?: string | null;
  asset_ips?: string[] | null;
  title: string;
  severity: string;
  status: string;
  verdict: string | null;
  verdict_source: string | null;
  confidence: number | null;
  summary: string | null;
  forensic_enriched_at: string | null;
  mitre_techniques: string[];
  proposed_actions: { actions?: IncidentAction[]; iocs?: string[] } | null;
  evidence_citations: EvidenceCitation[];
  hitl_status: string | null;
  hitl_responded_at: string | null;
  created_at: string;
  resolved_at: string | null;
  notes: IncidentNote[];
  // Phase 4 — bundle d'enrichment persisté à la création de l'incident
  // (cve_details, ip_reputations, threat_intel, enrichment_lines firewall).
  enrichment?: import("@/components/incidents/AttackTimeline").EnrichmentBundle;
}

interface AttackEvent {
  kind: "alert" | "finding";
  id: number;
  title: string;
  level: string;
  hostname: string | null;
  username: string | null;
  source_ip: string | null;
  ts: string;
  matched_fields: Record<string, unknown>;
}

interface FullData {
  incident: Incident;
  graph_executions: GraphExecution[];
  ai_analyses: AiAnalysis[];
  ip_enrichment: IpEnrichment | null;
  attack_paths: AttackPath[];
  choke_points: unknown[];
  attack_events: AttackEvent[];
  /** Phase 9o — investigation timeline (skill calls, LLM, derive, …). */
  investigation_steps?: InvestigationStep[];
}

interface RelatedIncident {
  id: number;
  title: string;
  severity: string;
  asset: string;
  status: string;
  created_at: string;
}

// ─────────────── helpers ────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#ff2020", HIGH: "#ff6030", MEDIUM: "#e0a020", LOW: "#30a050",
};
const STATUS_COLOR: Record<string, string> = {
  open: "#e0a020", resolved: "#30a050", closed: "#888", archived: "#888",
};

function fmtTime(iso: string, locale: Locale): string {
  return new Date(iso).toLocaleTimeString(locale === "fr" ? "fr-FR" : "en-US", { hour: "2-digit", minute: "2-digit" });
}
function fmtDate(iso: string, locale: Locale): string {
  return new Date(iso).toLocaleDateString(locale === "fr" ? "fr-FR" : "en-US", { day: "2-digit", month: "short", year: "numeric" });
}
function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}min`;
}
function pct(v: number | null): string {
  return v != null ? `${Math.round(v * 100)}%` : "—";
}
function timeAgo(iso: string, locale: Locale): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return tr("investigate_justNow", locale);
  if (mins < 60) return locale === "fr" ? `il y a ${mins}min` : `${mins}min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return locale === "fr" ? `il y a ${hours}h` : `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return locale === "fr" ? `il y a ${days}j` : `${days}d ago`;
}

// ─────────────── report modal ──────────────────────────────

const REPORT_ITEMS = [
  {
    id: "nis2-early",
    label: "NIS2 Early Warning (24h)",
    endpoint: "/api/tc/exports/nis2-early-warning",
    color: "#e04040",
    icon: Siren,
    formats: ["PDF", "JSON"],
  },
  {
    id: "nis2-intermediate",
    label: "NIS2 — 72h",
    endpoint: "/api/tc/exports/nis2-intermediate",
    color: "#e04040",
    icon: FileText,
    formats: ["PDF", "JSON"],
  },
  {
    id: "nist-incident",
    label: "NIST SP 800-61",
    endpoint: "/api/tc/exports/nist-incident",
    color: "#d06020",
    icon: Globe,
    formats: ["PDF", "JSON"],
  },
  {
    id: "iso27001",
    label: "ISO 27001",
    endpoint: "/api/tc/exports/iso27001-incident",
    color: "#d06020",
    icon: Lock,
    formats: ["PDF", "JSON"],
  },
];

function ReportModal({ incidentId, locale, onClose }: { incidentId: number; locale: Locale; onClose: () => void }) {
  const [generating, setGenerating] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const run = async (item: typeof REPORT_ITEMS[0], fmt: string) => {
    const key = `${item.id}-${fmt}`;
    setGenerating(key);
    try {
      const res = await fetch(item.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format: fmt.toLowerCase(), locale, incident_id: String(incidentId) }),
        signal: AbortSignal.timeout(30000),
      });
      if (!res.ok) throw new Error(await res.text());
      const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
      let blob: Blob;
      let filename: string;
      if (fmt === "PDF") {
        const bytes = await res.arrayBuffer();
        blob = new Blob([bytes], { type: "application/pdf" });
        filename = `incident-${incidentId}-${item.id}_${date}.pdf`;
      } else {
        const data = await res.json();
        blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        filename = `incident-${incidentId}-${item.id}_${date}.json`;
      }
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = filename; a.click();
      URL.revokeObjectURL(url);
      setDone(key);
      setTimeout(() => setDone(null), 3000);
    } catch (e: unknown) {
      alert((locale === "fr" ? "Erreur : " : "Error: ") + (e instanceof Error ? e.message : "timeout"));
    } finally {
      setGenerating(null);
    }
  };

  return (
    <div
      style={{
        position: "fixed", inset: 0, background: "rgba(0,0,0,0.65)", zIndex: 200,
        display: "flex", alignItems: "center", justifyContent: "center", padding: 20,
      }}
      onClick={onClose}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: "var(--tc-surface)", border: "1px solid var(--tc-border)",
          padding: 24, width: "100%", maxWidth: 520, borderRadius: 0,
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 18 }}>
          <div>
            <div style={{
              fontSize: 11, fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
              fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em",
              color: "var(--tc-text-muted)", marginBottom: 4,
            }}>
              {tr("investigate_incidentReport", locale)}
            </div>
            <div style={{ fontSize: 15, fontWeight: 700, color: "var(--tc-text)" }}>
              #{incidentId}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "transparent", border: "1px solid var(--tc-border)",
              padding: "4px 6px", cursor: "pointer", color: "var(--tc-text-muted)",
              display: "flex", alignItems: "center",
            }}
          >
            <X size={14} />
          </button>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {REPORT_ITEMS.map(item => {
            const Icon = item.icon;
            return (
              <div
                key={item.id}
                style={{
                  display: "grid", gridTemplateColumns: "28px 1fr auto",
                  alignItems: "center", gap: 10, padding: "10px 12px",
                  border: "1px solid var(--tc-border)", background: "var(--tc-surface-alt)",
                }}
              >
                <div style={{
                  width: 28, height: 28, display: "flex", alignItems: "center", justifyContent: "center",
                  border: `1px solid ${item.color}44`, background: item.color + "11",
                }}>
                  <Icon size={13} color={item.color} />
                </div>
                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--tc-text)" }}>
                  {item.label}
                </span>
                <div style={{ display: "flex", gap: 4 }}>
                  {item.formats.map(fmt => {
                    const key = `${item.id}-${fmt}`;
                    const isGen = generating === key;
                    const isDone = done === key;
                    return (
                      <button
                        key={fmt}
                        onClick={() => run(item, fmt)}
                        disabled={!!generating}
                        style={{
                          padding: "3px 9px", fontSize: 10, fontWeight: 700,
                          cursor: generating ? "default" : "pointer",
                          background: isDone ? "rgba(48,160,80,0.1)" : "var(--tc-input)",
                          color: isDone ? "#30a050" : "var(--tc-text-sec)",
                          border: isDone ? "1px solid rgba(48,160,80,0.2)" : "1px solid var(--tc-border)",
                          display: "flex", alignItems: "center", gap: 3,
                          textTransform: "uppercase", letterSpacing: "0.05em",
                          fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                        }}
                      >
                        {isGen ? <Loader2 size={9} className="inv-spin" />
                          : isDone ? <CheckCircle2 size={9} />
                          : <Download size={9} />}
                        {fmt}
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        <div style={{ marginTop: 12, fontSize: 10, color: "var(--tc-text-muted)", fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>
          {locale === "fr"
            ? "Rapport complet disponible dans Rapports & Exports → Réponse à incident."
            : "Full report catalog available in Reports & Exports → Incident Response."}
        </div>
      </div>
    </div>
  );
}

// ─────────────── related incidents ──────────────────────────

function RelatedCard({ incidentId, locale }: { incidentId: number; locale: Locale }) {
  const [related, setRelated] = useState<RelatedIncident[] | null>(null);
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/tc/incidents/${incidentId}/related`);
      if (res.ok) {
        const d = await res.json();
        setRelated(d.related || []);
      }
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => { load(); }, [load]);

  return (
    <div>
      {related === null || loading ? (
        <div style={{ padding: "12px 14px", fontSize: 12, color: "var(--tc-text-muted)", display: "flex", alignItems: "center", gap: 6, fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>
          <RefreshCw size={11} className="inv-spin" />
          {locale === "fr" ? "Recherche de corrélations..." : "Looking for correlations..."}
        </div>
      ) : related.length === 0 ? (
        <div style={{ padding: "12px 14px", fontSize: 12, color: "var(--tc-text-muted)" }}>
          {locale === "fr" ? "Aucune corrélation trouvée." : "No correlation found."}
        </div>
      ) : (
        <div className="inv-related">
          {related.map(r => {
            const sevColor = SEV_COLOR[r.severity] || "#888";
            return (
              <div
                key={r.id}
                className="inv-rel"
                onClick={() => router.push(`/investigate/${r.id}`)}
                style={{ cursor: "pointer" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: "1px 6px",
                    fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                    background: sevColor + "22", color: sevColor, border: `1px solid ${sevColor}44`,
                    textTransform: "uppercase",
                  }}>{r.severity}</span>
                  <span style={{
                    fontSize: 10, fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                    color: "var(--tc-text-muted)",
                  }}>#{r.id}</span>
                </div>
                <div style={{ fontSize: 12, fontWeight: 500, color: "var(--tc-text)", marginBottom: 2, lineHeight: 1.3 }}>
                  {r.title.length > 50 ? r.title.slice(0, 50) + "…" : r.title}
                </div>
                <div style={{ fontSize: 10, color: "var(--tc-text-muted)", fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>
                  {r.asset} · {fmtDate(r.created_at, locale)}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─────────────────────── page ────────────────────────────────

export default function InvestigatePage() {
  const params = useParams();
  const router = useRouter();
  const locale = useLocale();
  const incidentId = Number(params.incidentId);

  const [data, setData] = useState<FullData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [showReport, setShowReport] = useState(false);
  const [reinvestigating, setReinvestigating] = useState(false);
  const [hitlExecuting, setHitlExecuting] = useState(false);
  const [noteInput, setNoteInput] = useState("");
  const [notePosting, setNotePosting] = useState(false);
  const [confirmFp, setConfirmFp] = useState(false);
  const [suppressingIncident, setSuppressingIncident] = useState(false);
  const refreshTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch(`/api/tc/incidents/${incidentId}/full`);
      if (!res.ok) {
        setError(`API ${res.status}: ${await res.text()}`);
        return;
      }
      setData(await res.json());
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : tr("investigate_networkError", locale));
    } finally {
      setLoading(false);
    }
  }, [incidentId, locale]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (data?.incident.status === "open") {
      refreshTimer.current = setInterval(load, 15000);
    } else {
      if (refreshTimer.current) clearInterval(refreshTimer.current);
    }
    return () => { if (refreshTimer.current) clearInterval(refreshTimer.current); };
  }, [data?.incident.status, load]);

  const handleHitl = async (response: "approve" | "reject") => {
    if (!inc) return;
    setHitlExecuting(true);
    try {
      await fetch(`/api/tc/incidents/${incidentId}/hitl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ response, responded_by: "dashboard" }),
      });
      await load();
    } finally {
      setHitlExecuting(false);
    }
  };

  // Phase 9i — granular HITL: approve/reject a single action by `cmd_id`.
  // The backend marks only that action executed and keeps the incident open
  // so the operator can decide on the remaining proposals.
  const handleHitlAction = async (
    response: "approve" | "reject",
    cmdId: string,
  ) => {
    if (!inc) return;
    setHitlExecuting(true);
    try {
      await fetch(`/api/tc/incidents/${incidentId}/hitl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          response,
          responded_by: "dashboard",
          cmd_id: cmdId,
        }),
      });
      await load();
    } finally {
      setHitlExecuting(false);
    }
  };

  const addNote = async (text: string) => {
    if (!text.trim()) return;
    setNotePosting(true);
    try {
      await fetch(`/api/tc/incidents/${incidentId}/note`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: text.trim(), author: "dashboard" }),
      });
      setNoteInput("");
      await load();
    } catch {}
    setNotePosting(false);
  };

  const markFalsePositive = async () => {
    await fetch(`/api/tc/incidents/${incidentId}/hitl`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ response: "false_positive", responded_by: "dashboard" }),
    });
    setConfirmFp(false);
    await load();
  };

  const archiveIncident = async () => {
    await fetch(`/api/tc/incidents/${incidentId}/archive`, { method: "POST" });
    router.push("/incidents");
  };

  const reinvestigateInv = async () => {
    setReinvestigating(true);
    try {
      const res = await fetch(`/api/tc/incidents/${incidentId}/reinvestigate`, { method: "POST" });
      if (res.ok) await load();
    } finally {
      setReinvestigating(false);
    }
  };

  const inc = data?.incident;
  const statusColor = inc ? STATUS_COLOR[inc.status] || "#888" : "#888";
  const sevColor = inc ? SEV_COLOR[inc.severity] || "#888" : "#888";

  // Phase 10b — `latestL1` reste calculé pour alimenter la strip "Confiance L1"
  // (haut de page). Les anciens blocs "Analyse · agent L1 · ReAct" et
  // "Chronologie d'analyse · ai_analyses" ont été retirés au profit de
  // l'InvestigationTimeline (Phase 9o) qui agrège skill / llm_call / decision.
  const latestL1 = data?.ai_analyses
    .filter(a => a.source === "react_l1")
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())[0] || null;

  const allMitre = inc
    ? [
        ...(inc.mitre_techniques || []),
        ...(data?.ai_analyses.flatMap(a => a.mitre_added) || []),
      ].filter((v, i, arr) => arr.indexOf(v) === i)
    : [];

  const enrichData = data?.ip_enrichment;
  const isKnownScanner = enrichData?.noise && enrichData?.classification === "benign";

  return (
    <PageShell title={inc ? `#${inc.id} — ${displayAsset(inc)}` : "Investigation"}>
      <style>{`
        .inv-wrap {
          max-width: 1280px;
          margin: 0 auto;
          padding: 0 0 40px;
        }
        .inv-crumbs {
          display: flex;
          align-items: center;
          gap: 6px;
          margin-bottom: 14px;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          font-size: 11px;
          color: var(--tc-text-muted);
        }
        .inv-crumbs a {
          color: var(--tc-text-muted);
          text-decoration: none;
        }
        .inv-crumbs a:hover {
          color: var(--tc-text);
        }
        .inv-crumbs .inv-crumb-current {
          color: var(--tc-text);
        }
        .inv-crumbs .inv-crumb-ip {
          color: var(--tc-red);
          font-weight: 600;
        }
        .inv-topbar {
          display: flex;
          justify-content: flex-end;
          gap: 10px;
          margin-bottom: 18px;
          align-items: center;
          flex-wrap: wrap;
        }
        .inv-loading {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 60px 20px;
          color: var(--tc-text-muted);
          gap: 12px;
          font-size: 12px;
          background: var(--tc-surface);
          border: 1px solid var(--tc-border);
        }
        .inv-error {
          padding: 14px 16px;
          border: 1px solid #ff4040;
          background: rgba(255,64,64,0.06);
          color: #ff4040;
          font-size: 13px;
          margin-bottom: 14px;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .inv-det-grid {
          display: grid;
          grid-template-columns: 1fr 340px;
          gap: 24px;
          align-items: start;
        }
        @media (max-width: 900px) {
          .inv-det-grid {
            grid-template-columns: 1fr;
          }
        }
        .inv-hero {
          background: var(--tc-surface);
          border: 1px solid var(--tc-border);
          border-left: 3px solid var(--tc-red);
          padding: 20px 20px 20px 18px;
          position: relative;
          margin-bottom: 14px;
        }
        .inv-hero.sev-critical { border-left-color: #ff2020; }
        .inv-hero.sev-high { border-left-color: #ff6030; }
        .inv-hero.sev-medium { border-left-color: #e0a020; }
        .inv-hero.sev-low { border-left-color: #30a050; }
        .inv-stamp {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 10px;
          flex-wrap: wrap;
        }
        .inv-sev-badge {
          display: inline-block;
          padding: 2px 8px;
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.07em;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          text-transform: uppercase;
          border: 1px solid transparent;
        }
        .inv-strip {
          display: grid;
          grid-template-columns: repeat(5, 1fr);
          border-top: 1px solid var(--tc-border);
          margin-top: 16px;
        }
        .inv-strip-cell {
          padding: 10px 0;
          border-right: 1px solid var(--tc-border);
        }
        .inv-strip-cell:last-child {
          border-right: none;
        }
        .inv-strip-label {
          font-size: 9px;
          font-weight: 700;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          color: var(--tc-text-muted);
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          margin-bottom: 3px;
        }
        .inv-strip-val {
          font-size: 11px;
          color: var(--tc-text);
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          font-weight: 600;
        }
        .inv-sec {
          margin-bottom: 14px;
        }
        .inv-card {
          background: var(--tc-surface);
          border: 1px solid var(--tc-border);
        }
        .inv-card-head {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 10px 14px;
          border-bottom: 1px solid var(--tc-border);
          background: var(--tc-surface-alt);
        }
        .inv-card-head-left {
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          color: var(--tc-text-muted);
        }
        .inv-card-head-left strong {
          color: var(--tc-text);
        }
        .inv-card-head-right {
          font-size: 10px;
          color: var(--tc-text-muted);
          font-family: ui-monospace, 'JetBrains Mono', monospace;
        }
        .inv-ai-body {
          padding: 18px 20px;
        }
        .inv-ai-head {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 10px;
        }
        .inv-verdict {
          font-size: 13px;
          color: var(--tc-text-sec);
          line-height: 1.6;
          margin-bottom: 14px;
        }
        .inv-ai-foot {
          display: grid;
          grid-template-columns: 1fr 1fr 1fr;
          gap: 12px;
          border-top: 1px dashed var(--tc-border);
          padding-top: 10px;
          margin-top: 10px;
        }
        .inv-ai-foot-cell label {
          display: block;
          font-size: 9px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.08em;
          color: var(--tc-text-muted);
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          margin-bottom: 2px;
        }
        .inv-ai-foot-cell span {
          font-size: 11px;
          color: var(--tc-text);
          font-family: ui-monospace, 'JetBrains Mono', monospace;
        }
        .inv-signals {
          display: flex;
          flex-direction: column;
        }
        .inv-signal-row {
          display: grid;
          grid-template-columns: 80px 1fr;
          gap: 12px;
          padding: 12px 14px;
          border-bottom: 1px dashed var(--tc-border);
        }
        .inv-signal-row:last-child {
          border-bottom: none;
        }
        .inv-signal-ts {
          font-size: 10px;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          color: var(--tc-red);
          font-weight: 600;
          padding-top: 2px;
          line-height: 1.4;
        }
        .inv-signal-content-title {
          font-size: 12px;
          font-weight: 600;
          color: var(--tc-text);
          margin-bottom: 3px;
        }
        .inv-signal-content-body {
          font-size: 11px;
          color: var(--tc-text-sec);
          line-height: 1.5;
          margin-bottom: 4px;
        }
        .inv-signal-source {
          font-size: 10px;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          color: var(--tc-text-muted);
          margin-bottom: 4px;
        }
        .inv-tag {
          display: inline-block;
          padding: 1px 5px;
          font-size: 9px;
          font-weight: 700;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          background: #4a9eff22;
          color: #4a9eff;
          margin-right: 3px;
          margin-bottom: 2px;
        }
        .inv-right {
          position: sticky;
          top: 72px;
          display: flex;
          flex-direction: column;
          gap: 12px;
        }
        .inv-actions {
          background: var(--tc-surface);
          border: 1px solid var(--tc-border);
        }
        .inv-actions-head {
          padding: 10px 14px;
          border-bottom: 1px solid var(--tc-border);
          background: var(--tc-surface-alt);
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          color: var(--tc-text-muted);
        }
        .inv-actions-body {
          padding: 10px;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }
        .inv-act-btn {
          display: grid;
          grid-template-columns: 18px 1fr auto;
          align-items: center;
          gap: 8px;
          padding: 9px 12px;
          border: 1px solid var(--tc-border);
          background: var(--tc-surface-alt);
          color: var(--tc-text);
          font-size: 12px;
          font-weight: 600;
          cursor: pointer;
          font-family: inherit;
          text-align: left;
          transition: background 0.12s;
          width: 100%;
        }
        .inv-act-btn:hover {
          background: var(--tc-input);
        }
        .inv-act-btn.primary {
          background: var(--tc-red);
          color: #fff;
          border-color: var(--tc-red);
        }
        .inv-act-btn.primary:hover {
          opacity: 0.9;
        }
        .inv-act-btn .act-arrow {
          color: var(--tc-text-muted);
          font-size: 11px;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
        }
        .inv-enrich {
          background: var(--tc-surface);
          border: 1px solid var(--tc-border);
        }
        .inv-enrich-body {
          padding: 12px 14px;
        }
        .inv-enrich-kv {
          display: flex;
          justify-content: space-between;
          align-items: baseline;
          padding: 5px 0;
          border-bottom: 1px dashed var(--tc-border);
          font-size: 11px;
        }
        .inv-enrich-kv:last-child {
          border-bottom: none;
        }
        .inv-enrich-key {
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          font-size: 10px;
          font-weight: 700;
          text-transform: uppercase;
          color: var(--tc-text-muted);
          letter-spacing: 0.05em;
        }
        .inv-enrich-val {
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          font-size: 11px;
          color: var(--tc-text);
          font-weight: 500;
        }
        .inv-notice {
          padding: 8px 10px;
          font-size: 11px;
          line-height: 1.5;
          margin-bottom: 10px;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
        }
        .inv-notice.green {
          border-left: 3px solid #30a050;
          background: rgba(48,160,80,0.06);
          color: #30a050;
        }
        .inv-notice.red {
          border-left: 3px solid #ff4040;
          background: rgba(255,64,64,0.06);
          color: #ff4040;
        }
        .inv-audit {
          padding: 10px 12px;
          border: 1px dashed var(--tc-border);
          font-size: 9.5px;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          color: var(--tc-text-muted);
          text-align: center;
          letter-spacing: 0.04em;
          line-height: 1.6;
        }
        .inv-related {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 8px;
          padding: 12px 14px;
        }
        .inv-rel {
          background: var(--tc-surface-alt);
          border: 1px solid var(--tc-border);
          padding: 10px 10px;
          transition: border-color 0.12s;
        }
        .inv-rel:hover {
          border-color: var(--tc-text-muted);
        }
        .inv-foot {
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-top: 1px dashed var(--tc-border);
          padding-top: 14px;
          margin-top: 6px;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          font-size: 10px;
          color: var(--tc-text-muted);
          flex-wrap: wrap;
          gap: 8px;
        }
        .inv-foot a {
          color: var(--tc-text-muted);
          text-decoration: none;
        }
        .inv-foot a:hover {
          color: var(--tc-text);
        }
        .inv-live-dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          display: inline-block;
          animation: inv-pulse 2s infinite;
        }
        .inv-blink {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          display: inline-block;
          animation: inv-pulse 1.5s infinite;
        }
        @keyframes inv-pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.3; }
        }
        @keyframes inv-spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .inv-spin {
          animation: inv-spin 1s linear infinite;
        }
        .inv-ghost-btn {
          display: inline-flex;
          align-items: center;
          gap: 5px;
          padding: 6px 12px;
          font-size: 11px;
          font-weight: 600;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          cursor: pointer;
          background: var(--tc-surface-alt);
          color: var(--tc-text-muted);
          border: 1px solid var(--tc-border);
        }
        .inv-ghost-btn:hover {
          color: var(--tc-text);
          background: var(--tc-input);
        }
        .inv-ghost-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
        .inv-primary-btn {
          display: inline-flex;
          align-items: center;
          gap: 5px;
          padding: 6px 14px;
          font-size: 11px;
          font-weight: 700;
          font-family: ui-monospace, 'JetBrains Mono', monospace;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          cursor: pointer;
          background: var(--tc-red);
          color: #fff;
          border: 1px solid var(--tc-red);
        }
        .inv-primary-btn:hover {
          opacity: 0.9;
        }
      `}</style>

      <div className="inv-wrap">
        {/* Breadcrumbs */}
        <div className="inv-crumbs">
          <a href="/">Console</a>
          <span>/</span>
          <a href="/incidents">Incidents</a>
          <span>/</span>
          <span className="inv-crumb-current">#{incidentId}</span>
          {inc && (
            <>
              <span>/</span>
              <span className="inv-crumb-ip" title={displayAssetVerbose(inc)}>{displayAsset(inc)}</span>
            </>
          )}
        </div>

        {/* Top action bar */}
        <div className="inv-topbar">
          <button className="inv-ghost-btn" onClick={() => router.push("/incidents")} style={{ marginRight: "auto" }}>
            <ArrowLeft size={11} />
            Incidents
          </button>
          {inc?.status === "open" && (
            <span style={{ fontSize: 10, color: statusColor, fontWeight: 600, display: "flex", alignItems: "center", gap: 5, fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>
              <span className="inv-live-dot" style={{ background: statusColor }} />
              Auto-refresh 15s
            </span>
          )}
          <button className="inv-ghost-btn" onClick={load}>
            <RefreshCw size={11} />
            {tr("investigate_refresh", locale)}
          </button>
          <button
            className="inv-ghost-btn"
            disabled={!inc}
            onClick={() => {
              if (!inc) return;
              const events = data?.attack_events ?? [];
              const tsList = events
                .map(ev => new Date(ev.ts).getTime())
                .filter(n => Number.isFinite(n));
              const refMs = tsList.length > 0
                ? { min: Math.min(...tsList), max: Math.max(...tsList) }
                : { min: new Date(inc.created_at).getTime(), max: new Date(inc.created_at).getTime() };
              const PAD = 10 * 60_000;
              const from = new Date(refMs.min - PAD).toISOString();
              const to   = new Date(refMs.max + PAD).toISOString();
              const qs = new URLSearchParams({ from, to });
              const host = inc.asset_hostname || inc.asset_name;
              if (host) qs.set("hostname", host);
              router.push(`/hunt?${qs.toString()}`);
            }}
            title={tr("investigate_pivotHuntTooltip", locale)}
          >
            <Search size={11} />
            {tr("investigate_pivotHunt", locale)}
          </button>
          <button className="inv-ghost-btn" onClick={() => setShowReport(true)}>
            <Download size={11} />
            Export
          </button>
        </div>

        {/* Loading */}
        {loading && (
          <div className="inv-loading">
            <RefreshCw size={22} className="inv-spin" />
            <span>{tr("investigate_loading", locale)}</span>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="inv-error">
            <AlertTriangle size={14} /> {error}
          </div>
        )}

        {inc && data && (
          <div className="inv-det-grid">
            {/* LEFT COLUMN */}
            <div>
              {/* Hero card */}
              <div className={`inv-hero sev-${inc.severity.toLowerCase()}`}>
                <div className="inv-stamp">
                  <span
                    className="inv-sev-badge"
                    style={{
                      background: sevColor + "22",
                      color: sevColor,
                      borderColor: sevColor + "55",
                    }}
                  >
                    {inc.severity}
                  </span>
                  <span
                    className="inv-sev-badge"
                    style={{
                      background: statusColor + "22",
                      color: statusColor,
                      borderColor: statusColor + "44",
                    }}
                  >
                    {inc.status}
                  </span>
                  {inc.verdict && (
                    <span
                      className="inv-sev-badge"
                      style={{
                        background: "var(--tc-surface-alt)",
                        color: "var(--tc-text-muted)",
                        borderColor: "var(--tc-border)",
                      }}
                    >
                      {inc.verdict}{inc.confidence != null ? ` · ${pct(inc.confidence)}` : ""}
                    </span>
                  )}
                  <span style={{
                    fontSize: 10, fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                    color: "var(--tc-text-muted)",
                  }}>
                    #{inc.id} · {displayAsset(inc)} · {timeAgo(inc.created_at, locale)}
                  </span>
                </div>
                <h1 style={{ margin: "0 0 0 0", fontSize: 20, fontWeight: 600, color: "var(--tc-text)", lineHeight: 1.3 }}>
                  {inc.title}
                </h1>

                {/* Strip */}
                <div className="inv-strip">
                  <div className="inv-strip-cell" style={{ paddingLeft: 0 }}>
                    <div className="inv-strip-label">Asset</div>
                    <div className="inv-strip-val" style={{ color: "var(--tc-red)" }} title={displayAssetVerbose(inc)}>{displayAsset(inc)}</div>
                  </div>
                  <div className="inv-strip-cell" style={{ paddingLeft: 12 }}>
                    <div className="inv-strip-label">MITRE</div>
                    <div className="inv-strip-val">
                      {allMitre.length > 0
                        ? allMitre.slice(0, 2).join(", ") + (allMitre.length > 2 ? " …" : "")
                        : "—"}
                    </div>
                  </div>
                  <div className="inv-strip-cell" style={{ paddingLeft: 12 }}>
                    <div className="inv-strip-label">{tr("investigate_l1Confidence", locale)}</div>
                    <div className="inv-strip-val">
                      {latestL1?.confidence != null ? pct(latestL1.confidence) : "—"}
                    </div>
                  </div>
                  <div className="inv-strip-cell" style={{ paddingLeft: 12 }}>
                    <div className="inv-strip-label">{tr("investigate_status", locale)}</div>
                    <div className="inv-strip-val" style={{ color: statusColor }}>{inc.status}</div>
                  </div>
                  <div className="inv-strip-cell" style={{ paddingLeft: 12 }}>
                    <div className="inv-strip-label">{tr("investigate_detected", locale)}</div>
                    <div className="inv-strip-val">{fmtDate(inc.created_at, locale)}</div>
                  </div>
                </div>

              </div>

              {/* Phase 10b — bloc "Analyse · agent L1 · ReAct" retiré.
                  Il rendait toujours soit "Aucune analyse" soit le dernier
                  cycle de polling react_l1 sans valeur opérateur. La trace
                  L1/L2 vit désormais dans InvestigationTimeline (Phase 9o)
                  où chaque step est typé skill/llm_call/decision/action. */}

              {/* Phase 4 — chronologie d'attaque enrichie (firewall logs cross-correlation,
                  IP reputations, CVE details). Nourri par EnrichmentBundle persisté
                  par l'IE au moment de la création de l'incident (V71 + dossier_enrichment).
                  Phase 9h — passer l'asset id et le flag sigma-driven pour que la
                  section CVE puisse afficher un message clair quand l'attaque n'est
                  pas tied à un CVE (brute force, scan...) et linker vers la posture
                  vuln complète sur la page asset. */}
              <section className="inv-sec">
                <AttackTimeline
                  enrichment={inc.enrichment}
                  assetId={inc.asset}
                  sigmaDriven={
                    data?.attack_events?.some((e) => e.kind === "alert") ?? false
                  }
                />
              </section>

              {/* Phase 9o — chronologie d'analyse pliable. Sous l'AttackTimeline
                  pour rester secondaire à la chronologie d'attaque (qui est ce
                  que le RSSI veut voir d'abord). Collapsed par défaut. */}
              <section className="inv-sec">
                <InvestigationTimeline steps={data?.investigation_steps} />
              </section>

              {/* Forensic L2 enrichment section */}
              <section className="inv-sec">
                <div className="inv-card">
                  <div className="inv-card-head">
                    <div className="inv-card-head-left">
                      <strong>{tr("investigate_forensicEnrichment", locale)}</strong> · L2
                    </div>
                    <div className="inv-card-head-right">
                      {inc.forensic_enriched_at
                        ? `${fmtDate(inc.forensic_enriched_at, locale)} ${fmtTime(inc.forensic_enriched_at, locale)}`
                        : tr("investigate_pending", locale)}
                    </div>
                  </div>
                  <div className="inv-ai-body">
                    {!inc.forensic_enriched_at ? (
                      <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12, color: "var(--tc-text-muted)" }}>
                        <RefreshCw size={11} className="inv-spin" />
                        {tr("investigate_forensicQueued", locale)}
                      </div>
                    ) : inc.summary?.startsWith("Données insuffisantes") ? (
                      <div style={{
                        padding: "8px 10px", fontSize: 12, lineHeight: 1.5,
                        background: "rgba(224,160,32,0.08)", border: "1px solid rgba(224,160,32,0.3)",
                        color: "#c08820", fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                      }}>
                        {inc.summary}
                      </div>
                    ) : (
                      <>
                        <div className="inv-verdict" style={{ whiteSpace: "pre-wrap" }}>{inc.summary}</div>
                        {inc.mitre_techniques?.length > 0 && (
                          <div style={{ marginBottom: 12 }}>
                            {inc.mitre_techniques.map(t => (
                              <span key={t} className="inv-tag">{t}</span>
                            ))}
                          </div>
                        )}
                        {inc.evidence_citations?.length > 0 && (
                          <div style={{ borderTop: "1px dashed var(--tc-border)", paddingTop: 10 }}>
                            <div style={{
                              fontSize: 9, fontWeight: 700, textTransform: "uppercase",
                              letterSpacing: "0.08em", color: "var(--tc-text-muted)",
                              fontFamily: "ui-monospace, 'JetBrains Mono', monospace", marginBottom: 6,
                            }}>
                              {tr("investigate_evidence", locale)} ({inc.evidence_citations.length})
                            </div>
                            {inc.evidence_citations.map((c, i) => (
                              <div key={i} style={{
                                padding: "6px 0", borderBottom: "1px dashed var(--tc-border)",
                                display: "grid", gridTemplateColumns: "80px 1fr", gap: 8,
                              }}>
                                <span style={{
                                  fontSize: 9, fontWeight: 700,
                                  fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                                  color: "var(--tc-text-muted)", textTransform: "uppercase",
                                  paddingTop: 2,
                                }}>{c.evidence_type}</span>
                                <div>
                                  <div style={{ fontSize: 11, color: "var(--tc-text)", lineHeight: 1.4 }}>{c.claim}</div>
                                  {c.excerpt && (
                                    <div style={{
                                      fontSize: 10, color: "var(--tc-text-muted)",
                                      fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                                      marginTop: 2, lineHeight: 1.4,
                                    }}>{c.excerpt}</div>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                </div>
              </section>

              {/* Attack timeline */}
              <section className="inv-sec">
                <div className="inv-card">
                  <div className="inv-card-head">
                    <div className="inv-card-head-left">
                      <strong>{tr("investigate_attackTimeline", locale)}</strong> · {data.attack_events.length} signal{data.attack_events.length !== 1 ? "s" : ""}
                    </div>
                    {data.attack_events.length > 0 && (
                      <div className="inv-card-head-right">
                        {fmtDate(data.attack_events[0].ts, locale)} — {fmtDate(data.attack_events[data.attack_events.length - 1].ts, locale)}
                      </div>
                    )}
                  </div>
                  <div className="inv-signals">
                    {data.attack_events.length === 0 ? (
                      <div style={{ padding: "16px 14px", fontSize: 12, color: "var(--tc-text-muted)" }}>
                        {tr("investigate_noRawSignal", locale)}
                      </div>
                    ) : (
                      data.attack_events.map((ev, idx) => {
                        const lvlColor = ev.level === "critical" ? "#ff2020"
                          : ev.level === "high" ? "#ff6030"
                          : ev.level === "medium" ? "#e0a020"
                          : "#30a050";
                        const context = [ev.source_ip, ev.hostname, ev.username].filter(Boolean).join(" · ");
                        return (
                          <div key={`ev-${idx}`} className="inv-signal-row">
                            <div className="inv-signal-ts">
                              {fmtTime(ev.ts, locale)}<br />
                              <span style={{ color: "var(--tc-text-muted)", fontWeight: 400, fontSize: 9 }}>{fmtDate(ev.ts, locale)}</span>
                            </div>
                            <div>
                              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}>
                                <span style={{
                                  fontSize: 9, fontWeight: 700, padding: "1px 5px",
                                  fontFamily: "ui-monospace,'JetBrains Mono',monospace",
                                  background: lvlColor + "22", color: lvlColor,
                                  border: `1px solid ${lvlColor}44`, textTransform: "uppercase",
                                }}>{ev.level}</span>
                                <span style={{
                                  fontSize: 9, fontFamily: "ui-monospace,'JetBrains Mono',monospace",
                                  color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em",
                                }}>{ev.kind}</span>
                              </div>
                              <div className="inv-signal-content-title">{ev.title}</div>
                              {context && (
                                <div className="inv-signal-source">{context}</div>
                              )}
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              </section>

              {/* Phase 10b — bloc "Chronologie d'analyse · ai_analyses" retiré.
                  Il rendait essentiellement le polling react_l1 toutes les
                  ~15 min ("Aucun résumé produit · 50%"), pas une vraie trace
                  d'investigation. Remplacé par <InvestigationTimeline> ci-dessus
                  (Phase 9o) qui agrège skill / llm_call / decision / action sur
                  la table append-only `incident_investigation_steps` (V72). */}

              {/* Related incidents */}
              <section className="inv-sec">
                <div className="inv-card">
                  <div className="inv-card-head">
                    <div className="inv-card-head-left">
                      <strong>{tr("investigate_relatedIncidents", locale)}</strong>
                    </div>
                  </div>
                  <RelatedCard incidentId={inc.id} locale={locale} />
                </div>
              </section>
            </div>

            {/* RIGHT COLUMN */}
            <aside className="inv-right">
              {/* RSSI decisions */}
              {inc && inc.status !== "archived" && (
                <div className="inv-actions">
                  <div className="inv-actions-head">{tr("investigate_operatorDecisions", locale)}</div>
                  <div className="inv-actions-body">
                    <button className="inv-act-btn" onClick={() => setConfirmFp(true)}>
                      <XCircle size={14} />
                      <span>{tr("investigate_markFalsePositive", locale)}</span>
                      <ArrowRight size={11} className="act-arrow" />
                    </button>
                    <button className="inv-act-btn" onClick={reinvestigateInv} disabled={reinvestigating}>
                      {reinvestigating ? <RefreshCw size={14} className="inv-spin" /> : <Brain size={14} />}
                      <span>{reinvestigating ? tr("investigate_inProgress", locale) : tr("investigate_relaunchInvestigation", locale)}</span>
                      {!reinvestigating && <ArrowRight size={11} className="act-arrow" />}
                    </button>
                    <button className="inv-act-btn" onClick={() => setSuppressingIncident(true)}>
                      <Filter size={14} />
                      <span>{tr("investigate_ignorePattern", locale)}</span>
                      <ArrowRight size={11} className="act-arrow" />
                    </button>
                    <button className="inv-act-btn" onClick={archiveIncident}>
                      <Archive size={14} />
                      <span>{tr("investigate_archive", locale)}</span>
                      <ArrowRight size={11} className="act-arrow" />
                    </button>
                  </div>
                </div>
              )}

              {/* IP Enrichment card */}
              {enrichData && (
                <div className="inv-enrich">
                  <div className="inv-card-head">
                    <div className="inv-card-head-left">
                      <strong>{tr("investigate_enrichment", locale)}</strong> · IP
                    </div>
                  </div>
                  <div className="inv-enrich-body">
                    {isKnownScanner && (
                      <div className="inv-notice green">
                        {tr("investigate_knownScanner", locale)}
                      </div>
                    )}
                    {enrichData.is_malicious && (
                      <div className="inv-notice red">
                        {tr("investigate_maliciousIp", locale)}
                      </div>
                    )}
                    {[
                      ["IP", enrichData.ip],
                      ["GreyNoise", enrichData.greynoise_name || (enrichData.noise ? tr("investigate_noise", locale) : "—")],
                      ["RIOT", enrichData.riot ? tr("investigate_riotYes", locale) : tr("investigate_no", locale)],
                      ["Spamhaus", enrichData.spamhaus_listed ? (enrichData.spamhaus_lists.join(", ") || tr("investigate_listed", locale)) : tr("investigate_notListed", locale)],
                      [tr("investigate_country", locale), enrichData.country || "—"],
                      ["ASN", enrichData.asn || "—"],
                    ].map(([k, v]) => (
                      <div key={k} className="inv-enrich-kv">
                        <span className="inv-enrich-key">{k}</span>
                        <span className="inv-enrich-val">{v}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Attack paths */}
              {data.attack_paths.length > 0 && (
                <div className="inv-card">
                  <div className="inv-card-head">
                    <div className="inv-card-head-left">
                      <strong>{tr("investigate_attackPaths", locale)}</strong> · {data.attack_paths.length}
                    </div>
                  </div>
                  <div style={{ padding: "10px 12px", display: "flex", flexDirection: "column", gap: 6 }}>
                    {data.attack_paths.map(p => (
                      <div key={p.id} style={{
                        background: "var(--tc-surface-alt)",
                        border: "1px solid var(--tc-border)",
                        padding: "7px 10px",
                        display: "flex", alignItems: "center", gap: 8,
                      }}>
                        <span style={{
                          fontSize: 11, fontWeight: 700, color: "#ff6030",
                          background: "#ff603022", padding: "1px 6px",
                          fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                        }}>
                          {Math.round(p.risk_score)}
                        </span>
                        <span style={{ fontSize: 11, color: "var(--tc-text)", fontFamily: "ui-monospace, 'JetBrains Mono', monospace", flex: 1 }}>
                          {p.src_asset} → {p.dst_asset}
                        </span>
                        <span style={{ fontSize: 10, color: "var(--tc-text-muted)", fontFamily: "ui-monospace, 'JetBrains Mono', monospace" }}>
                          {p.hop_count}h
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* HITL proposed actions — always visible */}
              {(() => {
                const hitlActions = inc.proposed_actions?.actions?.filter(a => a.kind !== "manual") || [];
                const alreadyActed = !!inc.hitl_responded_at;
                return (
                  <div className="inv-card">
                    <div className="inv-card-head" style={{ borderLeft: "3px solid #ff6030" }}>
                      <div className="inv-card-head-left" style={{ color: "#ff6030" }}>
                        <strong>{tr("investigate_proposedActions", locale)}</strong>
                        {inc.hitl_status && (
                          <span style={{
                            marginLeft: 6, fontSize: 9, padding: "1px 5px",
                            background: alreadyActed ? "rgba(48,160,80,0.15)" : "rgba(255,96,48,0.12)",
                            color: alreadyActed ? "#30a050" : "#ff6030",
                            border: `1px solid ${alreadyActed ? "rgba(48,160,80,0.3)" : "rgba(255,96,48,0.3)"}`,
                            fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                          }}>{inc.hitl_status}</span>
                        )}
                      </div>
                    </div>
                    <div style={{ padding: "10px 12px", display: "flex", flexDirection: "column", gap: 6 }}>
                      {hitlActions.length === 0 ? (
                        <div style={{
                          fontSize: 11, color: "var(--tc-text-muted)", fontStyle: "italic",
                          padding: "4px 0",
                        }}>
                          {tr("investigate_noProposedAction", locale)}
                        </div>
                      ) : (
                        hitlActions.map((act, i) => {
                          // Phase 9c — `act` is the canonical IncidentAction with
                          // kind / cmd_id / description / params / rationale /
                          // skill_id / origin. Older incidents persisted before
                          // Phase 9 may be missing some fields; we render what
                          // we have rather than crash.
                          const params = act.params ?? {};
                          const paramEntries = Object.entries(params);
                          return (
                            <div key={i} style={{
                              padding: "8px 10px",
                              background: "var(--tc-surface-alt)",
                              border: "1px solid var(--tc-border)",
                            }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4, flexWrap: "wrap" }}>
                                <span style={{
                                  fontSize: 9, fontWeight: 700, padding: "1px 5px",
                                  fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                                  background: "rgba(255,96,48,0.1)", color: "#ff6030",
                                  border: "1px solid rgba(255,96,48,0.25)", textTransform: "uppercase",
                                }}>{kindShortLabel(act.kind, locale)}</span>
                                {act.skill_id && (
                                  <span style={{
                                    fontSize: 9, padding: "1px 5px",
                                    fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                                    background: "var(--tc-surface)", color: "var(--tc-text-muted)",
                                    border: "1px solid var(--tc-border)",
                                  }}>{act.skill_id}</span>
                                )}
                                {act.cmd_id && (
                                  <span style={{
                                    fontSize: 9, color: "var(--tc-text-muted)",
                                    fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                                    marginLeft: "auto",
                                  }}>{act.cmd_id}</span>
                                )}
                              </div>
                              <div style={{ fontSize: 11, color: "var(--tc-text-sec)", lineHeight: 1.4, marginBottom: 6 }}>
                                {act.description || act.cmd_id || "—"}
                              </div>
                              {paramEntries.length > 0 && (
                                <div style={{
                                  fontSize: 10, color: "var(--tc-text-muted)",
                                  fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                                  marginBottom: 4, lineHeight: 1.5,
                                }}>
                                  {paramEntries.map(([k, v]) => (
                                    <span key={k} style={{ marginRight: 10 }}>
                                      <span style={{ color: "var(--tc-text-muted)" }}>{k}=</span>
                                      <span style={{ color: "var(--tc-text-sec)" }}>{String(v)}</span>
                                    </span>
                                  ))}
                                </div>
                              )}
                              {act.rationale && (
                                <div style={{
                                  fontSize: 10, color: "var(--tc-text-muted)",
                                  fontStyle: "italic", lineHeight: 1.4,
                                }}>
                                  {act.rationale}
                                </div>
                              )}
                              {/* Phase 9i — granular per-action HITL buttons.
                                  Skipped on `manual` actions (nothing to execute)
                                  and on already-acted incidents. */}
                              {!alreadyActed && act.kind !== "manual" && act.cmd_id && (
                                <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
                                  <button
                                    onClick={() => handleHitlAction("approve", act.cmd_id!)}
                                    disabled={hitlExecuting}
                                    style={{
                                      padding: "5px 10px", fontSize: 10, fontWeight: 700,
                                      fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                                      textTransform: "uppercase", letterSpacing: "0.05em",
                                      cursor: hitlExecuting ? "default" : "pointer",
                                      background: "rgba(208,48,32,0.15)", color: "#d03020",
                                      border: "1px solid rgba(208,48,32,0.4)",
                                      display: "inline-flex", alignItems: "center", gap: 4,
                                    }}
                                  >
                                    <Zap size={9} />
                                    {tr("investigate_approveThisAction", locale)}
                                  </button>
                                  <button
                                    onClick={() => handleHitlAction("reject", act.cmd_id!)}
                                    disabled={hitlExecuting}
                                    style={{
                                      padding: "5px 10px", fontSize: 10,
                                      fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                                      textTransform: "uppercase", letterSpacing: "0.05em",
                                      cursor: hitlExecuting ? "default" : "pointer",
                                      background: "var(--tc-surface)", color: "var(--tc-text-muted)",
                                      border: "1px solid var(--tc-border)",
                                      display: "inline-flex", alignItems: "center", gap: 4,
                                    }}
                                  >
                                    {tr("investigate_reject", locale)}
                                  </button>
                                </div>
                              )}
                            </div>
                          );
                        })
                      )}
                      {hitlActions.length > 0 && !alreadyActed && (
                        <div style={{
                          display: "flex", gap: 6, marginTop: 4,
                          paddingTop: 8, borderTop: "1px dashed var(--tc-border)",
                        }}>
                          <button
                            onClick={() => handleHitl("approve")}
                            disabled={hitlExecuting}
                            title={tr("investigate_approveAllTitle", locale)}
                            style={{
                              flex: 1, padding: "7px 0", fontSize: 11, fontWeight: 700,
                              fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                              textTransform: "uppercase", letterSpacing: "0.05em",
                              cursor: hitlExecuting ? "default" : "pointer",
                              background: "#d03020", color: "#fff", border: "1px solid #d03020",
                              display: "flex", alignItems: "center", justifyContent: "center", gap: 4,
                            }}
                          >
                            {hitlExecuting ? <RefreshCw size={10} className="inv-spin" /> : <Zap size={10} />}
                            {tr("investigate_approveAll", locale)}
                          </button>
                          <button
                            onClick={() => handleHitl("reject")}
                            disabled={hitlExecuting}
                            style={{
                              flex: 1, padding: "7px 0", fontSize: 11, fontWeight: 700,
                              fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                              textTransform: "uppercase", letterSpacing: "0.05em",
                              cursor: hitlExecuting ? "default" : "pointer",
                              background: "var(--tc-surface-alt)", color: "var(--tc-text-muted)",
                              border: "1px solid var(--tc-border)",
                              display: "flex", alignItems: "center", justifyContent: "center", gap: 4,
                            }}
                          >
                            {tr("investigate_reject", locale)}
                          </button>
                        </div>
                      )}
                      {alreadyActed && (
                        <div style={{
                          fontSize: 10, textAlign: "center", color: "#30a050",
                          fontFamily: "ui-monospace, 'JetBrains Mono', monospace",
                          padding: "4px 0",
                        }}>
                          {tr("investigate_decisionSaved", locale)} · {fmtDate(inc.hitl_responded_at!, locale)}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })()}

              {/* Notes & historique */}
              <div className="inv-actions">
                <div className="inv-actions-head">
                  <MessageSquare size={11} style={{ display: "inline", marginRight: 5 }} />
                  {tr("investigate_notesHistory", locale)}
                </div>
                <div style={{ padding: "10px 12px", display: "flex", flexDirection: "column", gap: 6 }}>
                  {inc && inc.notes && inc.notes.length > 0 ? (
                    <div style={{ display: "flex", flexDirection: "column", gap: 4, marginBottom: 8, maxHeight: 220, overflowY: "auto" }}>
                      {inc.notes.map((n, i) => (
                        <div key={i} style={{ padding: "6px 8px", background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)", fontSize: 11 }}>
                          <div style={{ color: "var(--tc-text)", marginBottom: 2, lineHeight: 1.5 }}>{n.text}</div>
                          <div style={{ color: "var(--tc-text-muted)", fontSize: 9, fontFamily: "ui-monospace,'JetBrains Mono',monospace" }}>
                            {n.author} · {new Date(n.at).toLocaleString(locale === "fr" ? "fr-FR" : "en-US", { dateStyle: "short", timeStyle: "short" })}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ fontSize: 11, color: "var(--tc-text-muted)", fontStyle: "italic", marginBottom: 8 }}>{tr("investigate_noNote", locale)}</div>
                  )}
                  <div style={{ display: "flex", gap: 6 }}>
                    <input
                      type="text"
                      value={noteInput}
                      onChange={e => setNoteInput(e.target.value)}
                      onKeyDown={e => { if (e.key === "Enter") addNote(noteInput); }}
                      placeholder={tr("investigate_addNote", locale)}
                      style={{
                        flex: 1, padding: "6px 8px", fontSize: 11,
                        fontFamily: "ui-monospace,'JetBrains Mono',monospace",
                        background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                        color: "var(--tc-text)", outline: "none",
                      }}
                    />
                    <button
                      onClick={() => addNote(noteInput)}
                      disabled={notePosting || !noteInput.trim()}
                      style={{
                        padding: "6px 10px", background: "var(--tc-red)", color: "#fff",
                        border: "none", cursor: noteInput.trim() ? "pointer" : "not-allowed",
                        opacity: noteInput.trim() ? 1 : 0.5,
                        display: "flex", alignItems: "center",
                      }}
                    >
                      {notePosting ? <RefreshCw size={11} className="inv-spin" /> : <Send size={11} />}
                    </button>
                  </div>
                </div>
              </div>

              {/* Audit note */}
              <div className="inv-audit">
                {tr("investigate_auditTrail", locale)} · ISO 27001 A.16 · NIS2 Art.23
              </div>
            </aside>
          </div>
        )}

        {/* Footer */}
        {inc && (
          <div className="inv-foot">
            <span>incident://INC-{inc.id}</span>
            <span>{tr("investigate_lastUpdate", locale)} {timeAgo(inc.created_at, locale)}</span>
            <a href="/incidents">{tr("investigate_backToIncidents", locale)}</a>
          </div>
        )}
      </div>

      {suppressingIncident && inc && (
        <SuppressionWizard
          incident={{ id: inc.id, asset: inc.asset, title: inc.title, severity: inc.severity, mitre_techniques: inc.mitre_techniques, evidence_citations: inc.evidence_citations }}
          locale={locale}
          onClose={() => setSuppressingIncident(false)}
          onCreated={() => { setSuppressingIncident(false); load(); }}
        />
      )}

      {confirmFp && inc && (
        <div onClick={() => setConfirmFp(false)} style={{ position: "fixed", inset: 0, zIndex: 200, background: "rgba(0,0,0,0.65)", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div onClick={e => e.stopPropagation()} style={{ maxWidth: 460, width: "90%", background: "var(--tc-surface)", border: "1px solid var(--tc-border)", padding: 24 }}>
            <div style={{ fontSize: 13, fontWeight: 700, fontFamily: "ui-monospace,'JetBrains Mono',monospace", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 12 }}>
              {tr("investigate_markFalsePositiveQ", locale)}
            </div>
            <p style={{ fontSize: 12, color: "var(--tc-text-sec)", lineHeight: 1.6, marginBottom: 16 }}>
              {locale === "fr"
                ? <>Cela classe l&apos;incident #{inc.id} en faux positif et le déplace dans les archives. L&apos;asset reste surveillé.</>
                : <>This classifies incident #{inc.id} as a false positive and moves it to the archives. The asset remains monitored.</>}
            </p>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button onClick={() => setConfirmFp(false)} className="inv-ghost-btn">{tr("investigate_cancel", locale)}</button>
              <button onClick={markFalsePositive} className="inv-primary-btn">
                <XCircle size={12} />
                {tr("investigate_confirmFalsePositive", locale)}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Report modal */}
      {showReport && inc && (
        <ReportModal incidentId={inc.id} locale={locale} onClose={() => setShowReport(false)} />
      )}
    </PageShell>
  );
}

"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useLocale } from "@/lib/useLocale";
import { PageShell } from "@/components/chrome/PageShell";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  AlertTriangle, ArrowLeft, Brain, CheckCircle2, Clock, Download,
  Globe, RefreshCw, Shield, Target, Zap, Link2, BarChart2,
} from "lucide-react";

// ─────────────────────────── types ───────────────────────────

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

interface Incident {
  id: number;
  asset: string;
  title: string;
  severity: string;
  status: string;
  verdict: string | null;
  verdict_source: string | null;
  confidence: number | null;
  summary: string | null;
  mitre_techniques: string[];
  proposed_actions: unknown[];
  created_at: string;
  resolved_at: string | null;
}

interface FullData {
  incident: Incident;
  graph_executions: GraphExecution[];
  ai_analyses: AiAnalysis[];
  ip_enrichment: IpEnrichment | null;
  attack_paths: AttackPath[];
  choke_points: unknown[];
}

interface RelatedIncident {
  id: number;
  title: string;
  severity: string;
  asset: string;
  status: string;
  created_at: string;
}

// ─────────────────────── helpers ────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#ff2020", HIGH: "#ff6030", MEDIUM: "#e0a020", LOW: "#30a050",
};

const STATUS_COLOR: Record<string, string> = {
  open: "#e0a020", resolved: "#30a050", closed: "#888", archived: "#888",
};

function fmtTime(iso: string): string {
  return new Date(iso).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
}
function fmtDate(iso: string): string {
  return new Date(iso).toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" });
}
function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}min`;
}
function pct(v: number | null): string {
  return v != null ? `${Math.round(v * 100)}%` : "—";
}

function SeverityBadge({ sev }: { sev: string }) {
  const color = SEV_COLOR[sev] || "#888";
  return (
    <span style={{
      display: "inline-block", padding: "2px 8px", borderRadius: 4,
      fontSize: 11, fontWeight: 700, letterSpacing: "0.05em",
      background: color + "22", color, border: `1px solid ${color}55`,
    }}>{sev}</span>
  );
}

function SourceBadge({ source }: { source: string }) {
  const cfg: Record<string, { color: string; label: string }> = {
    react_l1: { color: "#4a9eff", label: "L1 ReAct" },
    react_l2: { color: "#9b59ff", label: "L2 Forensic" },
    manual: { color: "#888", label: "Manuel" },
    graph: { color: "#f59e0b", label: "Graph" },
  };
  const c = cfg[source] || { color: "#888", label: source };
  return (
    <span style={{
      padding: "2px 7px", borderRadius: 4, fontSize: 10, fontWeight: 700,
      background: c.color + "22", color: c.color, border: `1px solid ${c.color}44`,
    }}>{c.label}</span>
  );
}

function ConfidencePip({ value }: { value: number | null }) {
  if (value == null) return null;
  const color = value >= 0.8 ? "#30a050" : value >= 0.5 ? "#e0a020" : "#ff6030";
  return (
    <span style={{ fontSize: 11, color, fontWeight: 600 }}>
      {pct(value)} confiance
    </span>
  );
}

// ─────────────────── sub-cards ───────────────────────────────

function IpEnrichmentCard({ data }: { data: IpEnrichment }) {
  const malColor = data.is_malicious ? "#ff4040" : data.classification === "benign" ? "#30a050" : "#888";
  return (
    <NeuCard style={{ padding: "16px 18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <Globe size={15} color="#4a9eff" />
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)" }}>
          Enrichissement IP
        </span>
        <span style={{
          padding: "2px 7px", borderRadius: 4, fontSize: 10, fontWeight: 700,
          background: malColor + "22", color: malColor, border: `1px solid ${malColor}44`,
        }}>
          {data.classification}
        </span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))", gap: "8px 16px" }}>
        {[
          ["IP", data.ip],
          ["Pays", data.country || "—"],
          ["ASN", data.asn || "—"],
          ["GreyNoise", data.greynoise_name || (data.noise ? "Noise" : "—")],
          ["RIOT", data.riot ? "Oui (infra tierce)" : "Non"],
          ["Spamhaus", data.spamhaus_listed ? data.spamhaus_lists.join(", ") || "Listé" : "Non listé"],
        ].map(([k, v]) => (
          <div key={k}>
            <div style={{ fontSize: 10, color: "var(--tc-text-muted)", marginBottom: 1 }}>{k}</div>
            <div style={{ fontSize: 12, color: "var(--tc-text)", fontWeight: 500 }}>{v}</div>
          </div>
        ))}
      </div>
    </NeuCard>
  );
}

function AnalysisTimelineCard({
  graphExecs, aiAnalyses,
}: {
  graphExecs: GraphExecution[];
  aiAnalyses: AiAnalysis[];
}) {
  type TimelineEntry =
    | { kind: "graph"; data: GraphExecution; ts: string }
    | { kind: "ai"; data: AiAnalysis; ts: string };

  const entries: TimelineEntry[] = [
    ...graphExecs.map((g) => ({ kind: "graph" as const, data: g, ts: g.started_at })),
    ...aiAnalyses.map((a) => ({ kind: "ai" as const, data: a, ts: a.created_at })),
  ].sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());

  if (entries.length === 0) {
    return (
      <NeuCard style={{ padding: "16px 18px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
          <Brain size={15} color="var(--tc-text-muted)" />
          <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)" }}>Analyse IA</span>
        </div>
        <div style={{ fontSize: 12, color: "var(--tc-text-muted)", padding: "8px 0" }}>
          Aucune analyse disponible — cliquez sur "Analyser" pour lancer L1.
        </div>
      </NeuCard>
    );
  }

  return (
    <NeuCard style={{ padding: "16px 18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
        <Brain size={15} color="#4a9eff" />
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)" }}>
          Analyse IA ({entries.length})
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {entries.map((entry, i) => {
          if (entry.kind === "graph") {
            const g = entry.data;
            const outcomeColor = g.outcome === "Incident" ? "#ff6030"
              : g.outcome === "Archive" ? "#30a050"
              : g.outcome === "Inconclusive" ? "#888" : "#4a9eff";
            return (
              <div key={`g-${g.id}`} style={{
                borderLeft: "2px solid #f59e0b44",
                paddingLeft: 12,
                position: "relative",
              }}>
                <div style={{ position: "absolute", left: -5, top: 6, width: 8, height: 8, borderRadius: "50%", background: "#f59e0b" }} />
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}>
                  <SourceBadge source="graph" />
                  <span style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>
                    {fmtDate(g.started_at)} {fmtTime(g.started_at)}
                    {g.duration_ms != null && ` · ${fmtDuration(g.duration_ms)}`}
                  </span>
                </div>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--tc-text)", marginBottom: 2 }}>
                  {g.graph_name}
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  {g.outcome && (
                    <span style={{ fontSize: 11, fontWeight: 700, color: outcomeColor }}>
                      → {g.outcome}
                    </span>
                  )}
                  {g.archive_reason && (
                    <span style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>
                      ({g.archive_reason})
                    </span>
                  )}
                </div>
              </div>
            );
          }
          const a = entry.data;
          const borderColor = a.source === "react_l2" ? "#9b59ff44"
            : a.source === "react_l1" ? "#4a9eff44" : "#88888844";
          const dotColor = a.source === "react_l2" ? "#9b59ff"
            : a.source === "react_l1" ? "#4a9eff" : "#888";
          return (
            <div key={`a-${a.id}`} style={{
              borderLeft: `2px solid ${borderColor}`,
              paddingLeft: 12,
              position: "relative",
            }}>
              <div style={{ position: "absolute", left: -5, top: 6, width: 8, height: 8, borderRadius: "50%", background: dotColor }} />
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}>
                <SourceBadge source={a.source} />
                <ConfidencePip value={a.confidence} />
                <span style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>
                  {fmtDate(a.created_at)} {fmtTime(a.created_at)}
                </span>
              </div>
              <div style={{ fontSize: 12, color: "var(--tc-text)", lineHeight: 1.6, marginBottom: 4 }}>
                {a.summary}
              </div>
              {a.mitre_added.length > 0 && (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                  {a.mitre_added.map((t) => (
                    <span key={t} style={{
                      padding: "1px 5px", borderRadius: 3, fontSize: 10, fontWeight: 600,
                      background: "#4a9eff22", color: "#4a9eff",
                    }}>{t}</span>
                  ))}
                </div>
              )}
              {a.skills_used.length > 0 && (
                <div style={{ fontSize: 10, color: "var(--tc-text-muted)", marginTop: 3 }}>
                  Skills: {a.skills_used.join(", ")}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </NeuCard>
  );
}

function MitreCard({ techniques }: { techniques: string[] }) {
  if (techniques.length === 0) return null;
  return (
    <NeuCard style={{ padding: "16px 18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <Target size={15} color="#f59e0b" />
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)" }}>
          MITRE ATT&CK ({techniques.length})
        </span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        {techniques.map((t) => (
          <span key={t} style={{
            padding: "3px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600,
            background: "#f59e0b22", color: "#f59e0b", border: "1px solid #f59e0b44",
          }}>{t}</span>
        ))}
      </div>
    </NeuCard>
  );
}

function AttackPathsCard({ paths }: { paths: AttackPath[] }) {
  if (paths.length === 0) return null;
  return (
    <NeuCard style={{ padding: "16px 18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <BarChart2 size={15} color="#ff6030" />
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)" }}>
          Chemins d'attaque ({paths.length})
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {paths.map((p) => (
          <div key={p.id} style={{
            background: "var(--tc-surface-alt)", borderRadius: 6, padding: "8px 10px",
            display: "flex", alignItems: "center", gap: 10,
          }}>
            <span style={{
              fontSize: 11, fontWeight: 700, color: "#ff6030",
              background: "#ff603022", padding: "1px 6px", borderRadius: 3,
            }}>
              {Math.round(p.risk_score)}
            </span>
            <span style={{ fontSize: 12, color: "var(--tc-text)", fontFamily: "monospace" }}>
              {p.src_asset} → {p.dst_asset}
            </span>
            <span style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>
              {p.hop_count} hop(s)
            </span>
          </div>
        ))}
      </div>
    </NeuCard>
  );
}

function RelatedCard({ incidentId, locale }: { incidentId: number; locale: string }) {
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

  if (related === null) {
    return (
      <NeuCard style={{ padding: "16px 18px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <Link2 size={15} color="var(--tc-text-muted)" />
          <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)" }}>
            {locale === "fr" ? "Incidents liés" : "Related incidents"}
          </span>
        </div>
        <ChromeButton onClick={load} variant="glass" disabled={loading}>
          {loading ? <RefreshCw size={12} className="spin" /> : <Link2 size={12} />}
          {locale === "fr" ? "Rechercher des corrélations" : "Find correlations"}
        </ChromeButton>
      </NeuCard>
    );
  }

  return (
    <NeuCard style={{ padding: "16px 18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <Link2 size={15} color="#4a9eff" />
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)" }}>
          {locale === "fr" ? "Incidents liés" : "Related incidents"} ({related.length})
        </span>
        <ChromeButton onClick={load} variant="glass" disabled={loading} style={{ marginLeft: "auto" }}>
          <RefreshCw size={11} />
        </ChromeButton>
      </div>
      {related.length === 0 ? (
        <div style={{ fontSize: 12, color: "var(--tc-text-muted)" }}>
          {locale === "fr" ? "Aucune corrélation trouvée." : "No correlation found."}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {related.map((r) => (
            <div
              key={r.id}
              onClick={() => router.push(`/investigate/${r.id}`)}
              style={{
                background: "var(--tc-surface-alt)", borderRadius: 6, padding: "8px 10px",
                cursor: "pointer", display: "flex", alignItems: "center", gap: 10,
              }}
            >
              <SeverityBadge sev={r.severity} />
              <span style={{ fontSize: 12, color: "var(--tc-text)", flex: 1 }}>
                #{r.id} — {r.title}
              </span>
              <span style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>
                {fmtDate(r.created_at)}
              </span>
            </div>
          ))}
        </div>
      )}
    </NeuCard>
  );
}

function ReportButtons({ incidentId, locale }: { incidentId: number; locale: string }) {
  const [loading, setLoading] = useState<string | null>(null);

  const download = async (type: string) => {
    setLoading(type);
    try {
      const res = await fetch(`/api/tc/incidents/${incidentId}/report/${type}`, { method: "POST" });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `incident-${incidentId}-${type}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      alert("Erreur: " + e.message);
    } finally {
      setLoading(null);
    }
  };

  return (
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
      <ChromeButton onClick={() => download("ir")} variant="glass" disabled={loading === "ir"}>
        {loading === "ir" ? <RefreshCw size={12} className="spin" /> : <Download size={12} />}
        {locale === "fr" ? "Rapport IR" : "IR Report"}
      </ChromeButton>
      <ChromeButton onClick={() => download("nis2")} variant="glass" disabled={loading === "nis2"}>
        {loading === "nis2" ? <RefreshCw size={12} className="spin" /> : <Download size={12} />}
        NIS2
      </ChromeButton>
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
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeMsg, setAnalyzeMsg] = useState<string | null>(null);
  const refreshTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch(`/api/tc/incidents/${incidentId}/full`);
      if (!res.ok) {
        const text = await res.text();
        setError(`API ${res.status}: ${text}`);
        return;
      }
      const d: FullData = await res.json();
      setData(d);
      setError(null);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => {
    load();
  }, [load]);

  // Auto-refresh every 15s while incident is open
  useEffect(() => {
    if (data?.incident.status === "open") {
      refreshTimer.current = setInterval(load, 15000);
    } else {
      if (refreshTimer.current) clearInterval(refreshTimer.current);
    }
    return () => {
      if (refreshTimer.current) clearInterval(refreshTimer.current);
    };
  }, [data?.incident.status, load]);

  const triggerL1 = async () => {
    setAnalyzing(true);
    setAnalyzeMsg(null);
    try {
      const res = await fetch(`/api/tc/incidents/${incidentId}/investigate`, { method: "POST" });
      const d = await res.json();
      setAnalyzeMsg(d.message || "Analyse démarrée");
      // Refresh after ~35s
      setTimeout(load, 35000);
    } catch (e: any) {
      setAnalyzeMsg("Erreur: " + e.message);
    } finally {
      setAnalyzing(false);
    }
  };

  // Build merged MITRE (incident + all analyses)
  const allMitre = data
    ? [
        ...(data.incident.mitre_techniques || []),
        ...data.ai_analyses.flatMap((a) => a.mitre_added),
      ].filter((v, i, arr) => arr.indexOf(v) === i)
    : [];

  const inc = data?.incident;
  const statusColor = inc ? STATUS_COLOR[inc.status] || "#888" : "#888";

  return (
    <PageShell title={inc ? `#${inc.id} — ${inc.asset}` : locale === "fr" ? "Investigation" : "Investigation"}>
      <div style={{ maxWidth: 900, margin: "0 auto", padding: "0 0 24px 0" }}>

        {/* Back + header */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
          <ChromeButton onClick={() => router.push("/incidents")} variant="glass">
            <ArrowLeft size={14} />
            {locale === "fr" ? "Incidents" : "Incidents"}
          </ChromeButton>
          {inc && (
            <span style={{ fontSize: 12, color: "var(--tc-text-muted)" }}>
              / #{inc.id} — {inc.asset}
            </span>
          )}
          {inc?.status === "open" && (
            <span style={{
              marginLeft: "auto", fontSize: 10, color: statusColor, fontWeight: 600,
              display: "flex", alignItems: "center", gap: 4,
            }}>
              <span style={{
                width: 6, height: 6, borderRadius: "50%", background: statusColor,
                animation: "pulse 2s infinite",
              }} />
              Live — rafraîchissement auto 15s
            </span>
          )}
        </div>

        {/* Loading state */}
        {loading && (
          <NeuCard style={{ padding: 40, textAlign: "center" }}>
            <RefreshCw size={24} className="spin" color="var(--tc-text-muted)" />
            <div style={{ marginTop: 10, color: "var(--tc-text-muted)", fontSize: 13 }}>
              {locale === "fr" ? "Chargement..." : "Loading..."}
            </div>
          </NeuCard>
        )}

        {/* Error state */}
        {error && (
          <NeuCard style={{ padding: "16px 18px", borderColor: "#ff4040" }}>
            <div style={{ color: "#ff4040", fontSize: 13 }}>
              <AlertTriangle size={14} style={{ marginRight: 6, verticalAlign: "middle" }} />
              {error}
            </div>
          </NeuCard>
        )}

        {inc && (
          <>
            {/* Incident header card */}
            <NeuCard style={{ padding: "18px 20px", marginBottom: 14 }}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: 12, flexWrap: "wrap" }}>
                <div style={{ flex: 1, minWidth: 240 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
                    <SeverityBadge sev={inc.severity} />
                    <span style={{
                      padding: "2px 7px", borderRadius: 4, fontSize: 10, fontWeight: 700,
                      background: statusColor + "22", color: statusColor, border: `1px solid ${statusColor}44`,
                    }}>{inc.status}</span>
                    {inc.verdict && (
                      <span style={{
                        padding: "2px 7px", borderRadius: 4, fontSize: 10, fontWeight: 700,
                        background: "#ffffff11", color: "var(--tc-text-muted)", border: "1px solid var(--tc-border)",
                      }}>{inc.verdict} {inc.confidence != null ? `(${pct(inc.confidence)})` : ""}</span>
                    )}
                  </div>
                  <h1 style={{ margin: "0 0 4px 0", fontSize: 16, fontWeight: 700, color: "var(--tc-text)", lineHeight: 1.4 }}>
                    {inc.title}
                  </h1>
                  <div style={{ fontSize: 12, color: "var(--tc-text-muted)" }}>
                    <Shield size={11} style={{ marginRight: 4, verticalAlign: "middle" }} />
                    {inc.asset}
                    <span style={{ margin: "0 8px" }}>·</span>
                    <Clock size={11} style={{ marginRight: 4, verticalAlign: "middle" }} />
                    {fmtDate(inc.created_at)} {fmtTime(inc.created_at)}
                  </div>
                  {inc.summary && (
                    <div style={{ marginTop: 8, fontSize: 12, color: "var(--tc-text-sec)", lineHeight: 1.6 }}>
                      {inc.summary}
                    </div>
                  )}
                </div>
                {/* Action buttons */}
                <div style={{ display: "flex", flexDirection: "column", gap: 8, alignItems: "flex-end" }}>
                  <ChromeButton
                    onClick={triggerL1}
                    variant="primary"
                    disabled={analyzing}
                    style={{ whiteSpace: "nowrap" }}
                  >
                    {analyzing
                      ? <><RefreshCw size={13} className="spin" /> Analyse en cours...</>
                      : <><Brain size={13} /> Analyser (L1)</>
                    }
                  </ChromeButton>
                  <ChromeButton
                    onClick={load}
                    variant="glass"
                  >
                    <RefreshCw size={12} />
                    {locale === "fr" ? "Rafraîchir" : "Refresh"}
                  </ChromeButton>
                  <ReportButtons incidentId={inc.id} locale={locale} />
                </div>
              </div>
              {analyzeMsg && (
                <div style={{
                  marginTop: 10, padding: "8px 12px", borderRadius: 6,
                  background: "#4a9eff22", border: "1px solid #4a9eff44",
                  fontSize: 12, color: "#4a9eff",
                }}>
                  {analyzeMsg}
                </div>
              )}
            </NeuCard>

            {/* IP enrichment */}
            {data?.ip_enrichment && (
              <div style={{ marginBottom: 14 }}>
                <IpEnrichmentCard data={data.ip_enrichment} />
              </div>
            )}

            {/* Analysis timeline */}
            <div style={{ marginBottom: 14 }}>
              <AnalysisTimelineCard
                graphExecs={data?.graph_executions || []}
                aiAnalyses={data?.ai_analyses || []}
              />
            </div>

            {/* MITRE */}
            {allMitre.length > 0 && (
              <div style={{ marginBottom: 14 }}>
                <MitreCard techniques={allMitre} />
              </div>
            )}

            {/* Attack paths */}
            {(data?.attack_paths?.length ?? 0) > 0 && (
              <div style={{ marginBottom: 14 }}>
                <AttackPathsCard paths={data!.attack_paths} />
              </div>
            )}

            {/* Related incidents */}
            <div style={{ marginBottom: 14 }}>
              <RelatedCard incidentId={inc.id} locale={locale} />
            </div>
          </>
        )}
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
        .spin {
          animation: spin 1s linear infinite;
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </PageShell>
  );
}

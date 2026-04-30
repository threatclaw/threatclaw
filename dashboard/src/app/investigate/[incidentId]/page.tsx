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
  FileText, Siren, Lock, X, Loader2,
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
      display: "inline-block", padding: "2px 8px",
      fontSize: 11, fontWeight: 700, letterSpacing: "0.05em",
      background: color + "22", color, border: `1px solid ${color}55`,
    }}>{sev}</span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const color = STATUS_COLOR[status] || "#888";
  return (
    <span style={{
      padding: "2px 7px", fontSize: 10, fontWeight: 700,
      background: color + "22", color, border: `1px solid ${color}44`,
    }}>{status}</span>
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
      padding: "2px 7px", fontSize: 10, fontWeight: 700,
      background: c.color + "22", color: c.color, border: `1px solid ${c.color}44`,
    }}>{c.label}</span>
  );
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

function ReportModal({ incidentId, locale, onClose }: { incidentId: number; locale: string; onClose: () => void }) {
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
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)", zIndex: 200,
      display: "flex", alignItems: "center", justifyContent: "center", padding: 20,
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: "var(--tc-surface)", border: "1px solid var(--tc-border)",
        padding: 20, width: "100%", maxWidth: 520,
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: "var(--tc-text)" }}>
              {locale === "fr" ? "Rapport d'incident" : "Incident report"} — #{incidentId}
            </div>
            <div style={{ fontSize: 11, color: "var(--tc-text-muted)", marginTop: 2 }}>
              {locale === "fr" ? "Choisissez un format réglementaire" : "Select a compliance format"}
            </div>
          </div>
          <button onClick={onClose} style={{
            background: "transparent", border: "1px solid var(--tc-border)",
            padding: 4, cursor: "pointer", color: "var(--tc-text-muted)",
          }}><X size={14} /></button>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {REPORT_ITEMS.map(item => {
            const Icon = item.icon;
            return (
              <div key={item.id} style={{
                display: "flex", alignItems: "center", gap: 10, padding: "10px 12px",
                border: "1px solid var(--tc-border)", background: "var(--tc-surface-alt)",
              }}>
                <div style={{
                  width: 28, height: 28, display: "flex", alignItems: "center", justifyContent: "center",
                  border: `1px solid ${item.color}44`, background: item.color + "11",
                }}>
                  <Icon size={13} color={item.color} />
                </div>
                <span style={{ flex: 1, fontSize: 12, fontWeight: 600, color: "var(--tc-text)" }}>
                  {item.label}
                </span>
                <div style={{ display: "flex", gap: 4 }}>
                  {item.formats.map(fmt => {
                    const key = `${item.id}-${fmt}`;
                    const isGen = generating === key;
                    const isDone = done === key;
                    return (
                      <button key={fmt} onClick={() => run(item, fmt)} disabled={!!generating} style={{
                        padding: "3px 9px", fontSize: 10, fontWeight: 700, cursor: generating ? "default" : "pointer",
                        background: isDone ? "rgba(48,160,80,0.1)" : "var(--tc-input)",
                        color: isDone ? "#30a050" : "var(--tc-text-sec)",
                        border: isDone ? "1px solid rgba(48,160,80,0.2)" : "1px solid var(--tc-border)",
                        display: "flex", alignItems: "center", gap: 3,
                        textTransform: "uppercase", letterSpacing: "0.05em",
                      }}>
                        {isGen ? <Loader2 size={9} className="spin" />
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

        <div style={{ marginTop: 12, fontSize: 10, color: "var(--tc-text-muted)" }}>
          {locale === "fr"
            ? "Rapport complet disponible dans Rapports & Exports → Réponse à incident."
            : "Full report catalog available in Reports & Exports → Incident Response."}
        </div>
      </div>
    </div>
  );
}

// ─────────────── analysis timeline ──────────────────────────

function AnalysisTimelineCard({
  graphExecs, aiAnalyses, locale,
}: {
  graphExecs: GraphExecution[];
  aiAnalyses: AiAnalysis[];
  locale: string;
}) {
  type TimelineEntry =
    | { kind: "graph"; data: GraphExecution; ts: string }
    | { kind: "ai"; data: AiAnalysis; ts: string };

  const entries: TimelineEntry[] = [
    ...graphExecs.map((g) => ({ kind: "graph" as const, data: g, ts: g.started_at })),
    ...aiAnalyses.map((a) => ({ kind: "ai" as const, data: a, ts: a.created_at })),
  ].sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());

  return (
    <NeuCard style={{ padding: "16px 18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
        <Brain size={14} color="#4a9eff" />
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)" }}>
          {locale === "fr" ? "Analyse IA" : "AI Analysis"}
          {entries.length > 0 && <span style={{ color: "var(--tc-text-muted)", fontWeight: 400 }}> ({entries.length})</span>}
        </span>
      </div>

      {entries.length === 0 ? (
        <div style={{ fontSize: 12, color: "var(--tc-text-muted)", padding: "4px 0" }}>
          {locale === "fr"
            ? "Aucune analyse — cliquez sur « Analyser » pour lancer le moteur L1."
            : "No analysis yet — click \"Analyse\" to trigger the L1 engine."}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {entries.map((entry) => {
            if (entry.kind === "graph") {
              const g = entry.data;
              const outcomeColor = g.outcome === "Incident" ? "#ff6030"
                : g.outcome === "Archive" ? "#30a050"
                : "#888";
              return (
                <div key={`g-${g.id}`} style={{ borderLeft: "2px solid #f59e0b44", paddingLeft: 12, position: "relative" }}>
                  <div style={{ position: "absolute", left: -5, top: 5, width: 8, height: 8, borderRadius: "50%", background: "#f59e0b" }} />
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
                      <span style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>({g.archive_reason})</span>
                    )}
                  </div>
                </div>
              );
            }

            const a = entry.data;
            const dotColor = a.source === "react_l2" ? "#9b59ff" : a.source === "react_l1" ? "#4a9eff" : "#888";
            const borderColor = dotColor + "44";
            const verdict = (a.raw_output as Record<string, unknown> | null)?.parsed
              ? ((a.raw_output as { parsed?: { verdict?: string } }).parsed?.verdict ?? null)
              : null;
            const verdictColor = verdict === "false_positive" ? "#30a050"
              : verdict === "confirmed" ? "#ff6030" : "#888";
            return (
              <div key={`a-${a.id}`} style={{ borderLeft: `2px solid ${borderColor}`, paddingLeft: 12, position: "relative" }}>
                <div style={{ position: "absolute", left: -5, top: 5, width: 8, height: 8, borderRadius: "50%", background: dotColor }} />
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4, flexWrap: "wrap" }}>
                  <SourceBadge source={a.source} />
                  {a.confidence != null && (
                    <span style={{ fontSize: 11, fontWeight: 600, color: a.confidence >= 0.8 ? "#30a050" : a.confidence >= 0.5 ? "#e0a020" : "#ff6030" }}>
                      {pct(a.confidence)}
                    </span>
                  )}
                  {verdict && (
                    <span style={{ fontSize: 10, fontWeight: 700, color: verdictColor }}>
                      {verdict}
                    </span>
                  )}
                  <span style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>
                    {fmtDate(a.created_at)} {fmtTime(a.created_at)}
                  </span>
                </div>
                <div style={{ fontSize: 12, color: "var(--tc-text)", lineHeight: 1.6, marginBottom: a.mitre_added.length > 0 ? 6 : 0 }}>
                  {a.summary}
                </div>
                {a.mitre_added.length > 0 && (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 4 }}>
                    {a.mitre_added.map((t) => (
                      <span key={t} style={{
                        padding: "1px 5px", fontSize: 10, fontWeight: 600,
                        background: "#4a9eff22", color: "#4a9eff",
                      }}>{t}</span>
                    ))}
                  </div>
                )}
                {a.skills_used.length > 0 && (
                  <div style={{ fontSize: 10, color: "var(--tc-text-muted)" }}>
                    {locale === "fr" ? "Skills" : "Skills"}: {a.skills_used.join(", ")}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </NeuCard>
  );
}

// ─────────────── attack paths ───────────────────────────────

function AttackPathsCard({ paths, locale }: { paths: AttackPath[]; locale: string }) {
  return (
    <NeuCard style={{ padding: "16px 18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <BarChart2 size={14} color={paths.length > 0 ? "#ff6030" : "var(--tc-text-muted)"} />
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)" }}>
          {locale === "fr" ? "Chemins d'attaque" : "Attack paths"}
          {paths.length > 0 && <span style={{ color: "var(--tc-text-muted)", fontWeight: 400 }}> ({paths.length})</span>}
        </span>
      </div>
      {paths.length === 0 ? (
        <div style={{ fontSize: 12, color: "var(--tc-text-muted)" }}>
          {locale === "fr"
            ? "Aucun chemin d'attaque calculé pour cet incident. Le graphe de propagation est construit sur les actifs connectés à l'asset ciblé."
            : "No attack path computed for this incident. The propagation graph is built from assets connected to the targeted asset."}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {paths.map((p) => (
            <div key={p.id} style={{
              background: "var(--tc-surface-alt)", padding: "8px 10px",
              display: "flex", alignItems: "center", gap: 10,
            }}>
              <span style={{
                fontSize: 11, fontWeight: 700, color: "#ff6030",
                background: "#ff603022", padding: "1px 6px",
              }}>
                {Math.round(p.risk_score)}
              </span>
              <span style={{ fontSize: 12, color: "var(--tc-text)", fontFamily: "monospace", flex: 1 }}>
                {p.src_asset} → {p.dst_asset}
              </span>
              <span style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>
                {p.hop_count} hop(s)
              </span>
            </div>
          ))}
        </div>
      )}
    </NeuCard>
  );
}

// ─────────────── IP enrichment ──────────────────────────────

function IpEnrichmentCard({ data, locale }: { data: IpEnrichment; locale: string }) {
  const isKnownScanner = data.noise && data.classification === "benign";
  const isRiot = data.riot;
  const malColor = data.is_malicious ? "#ff4040" : isKnownScanner || isRiot ? "#30a050" : "#888";
  const classLabel = isRiot
    ? (locale === "fr" ? "Infrastructure tierce connue (RIOT)" : "Known third-party infra (RIOT)")
    : isKnownScanner
    ? (locale === "fr" ? "Scanner Internet légitime" : "Legitimate Internet scanner")
    : data.classification;

  return (
    <NeuCard style={{ padding: "16px 18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <Globe size={14} color="#4a9eff" />
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)" }}>
          {locale === "fr" ? "Enrichissement IP" : "IP enrichment"}
        </span>
        <span style={{
          padding: "2px 7px", fontSize: 10, fontWeight: 700,
          background: malColor + "22", color: malColor, border: `1px solid ${malColor}44`,
        }}>
          {classLabel}
        </span>
      </div>

      {(isKnownScanner || isRiot) && (
        <div style={{
          padding: "8px 10px", marginBottom: 10,
          borderLeft: "3px solid #30a050",
          background: "rgba(48,160,80,0.06)",
          fontSize: 11, color: "#30a050", lineHeight: 1.5,
        }}>
          {locale === "fr"
            ? `${data.greynoise_name || "Scanner"} — activité Internet de fond, non malveillante. Ce signal est probablement un faux positif.`
            : `${data.greynoise_name || "Scanner"} — background Internet activity, non-malicious. This signal is likely a false positive.`}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))", gap: "8px 16px" }}>
        {[
          ["IP", data.ip],
          [locale === "fr" ? "Pays" : "Country", data.country || "—"],
          ["ASN", data.asn || "—"],
          ["GreyNoise", data.greynoise_name || (data.noise ? (locale === "fr" ? "Bruit" : "Noise") : "—")],
          ["RIOT", data.riot ? (locale === "fr" ? "Oui (infra tierce)" : "Yes (third-party infra)") : "Non"],
          ["Spamhaus", data.spamhaus_listed ? data.spamhaus_lists.join(", ") || (locale === "fr" ? "Listé" : "Listed") : (locale === "fr" ? "Non listé" : "Not listed")],
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

// ─────────────── MITRE ──────────────────────────────────────

function MitreCard({ techniques, locale }: { techniques: string[]; locale: string }) {
  if (techniques.length === 0) return null;
  return (
    <NeuCard style={{ padding: "16px 18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <Target size={14} color="#f59e0b" />
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)" }}>
          MITRE ATT&CK <span style={{ color: "var(--tc-text-muted)", fontWeight: 400 }}>({techniques.length})</span>
        </span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        {techniques.map((t) => (
          <span key={t} style={{
            padding: "3px 8px", fontSize: 11, fontWeight: 600,
            background: "#f59e0b22", color: "#f59e0b", border: "1px solid #f59e0b44",
          }}>{t}</span>
        ))}
      </div>
    </NeuCard>
  );
}

// ─────────────── related incidents ──────────────────────────

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

  return (
    <NeuCard style={{ padding: "16px 18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <Link2 size={14} color="var(--tc-text-muted)" />
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)" }}>
          {locale === "fr" ? "Incidents liés" : "Related incidents"}
          {related !== null && <span style={{ color: "var(--tc-text-muted)", fontWeight: 400 }}> ({related.length})</span>}
        </span>
        {related !== null && (
          <ChromeButton onClick={load} variant="glass" disabled={loading} style={{ marginLeft: "auto", padding: "3px 8px" }}>
            <RefreshCw size={11} />
          </ChromeButton>
        )}
      </div>
      {related === null ? (
        <ChromeButton onClick={load} variant="glass" disabled={loading}>
          {loading ? <><RefreshCw size={12} className="spin" /> {locale === "fr" ? "Recherche..." : "Searching..."}</>
            : <><Link2 size={12} /> {locale === "fr" ? "Rechercher des corrélations" : "Find correlations"}</>}
        </ChromeButton>
      ) : related.length === 0 ? (
        <div style={{ fontSize: 12, color: "var(--tc-text-muted)" }}>
          {locale === "fr" ? "Aucune corrélation trouvée." : "No correlation found."}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {related.map((r) => (
            <div key={r.id} onClick={() => router.push(`/investigate/${r.id}`)} style={{
              background: "var(--tc-surface-alt)", padding: "8px 10px",
              cursor: "pointer", display: "flex", alignItems: "center", gap: 10,
            }}>
              <SeverityBadge sev={r.severity} />
              <span style={{ fontSize: 12, color: "var(--tc-text)", flex: 1 }}>
                #{r.id} — {r.title}
              </span>
              <span style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>{fmtDate(r.created_at)}</span>
            </div>
          ))}
        </div>
      )}
    </NeuCard>
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
  const [showReport, setShowReport] = useState(false);
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
      setError(e instanceof Error ? e.message : "Erreur réseau");
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (data?.incident.status === "open") {
      refreshTimer.current = setInterval(load, 15000);
    } else {
      if (refreshTimer.current) clearInterval(refreshTimer.current);
    }
    return () => { if (refreshTimer.current) clearInterval(refreshTimer.current); };
  }, [data?.incident.status, load]);

  const triggerL1 = async () => {
    setAnalyzing(true);
    setAnalyzeMsg(null);
    try {
      const res = await fetch(`/api/tc/incidents/${incidentId}/investigate`, { method: "POST" });
      const d = await res.json();
      setAnalyzeMsg(d.message || (locale === "fr" ? "Analyse démarrée" : "Analysis started"));
      setTimeout(load, 35000);
    } catch (e: unknown) {
      setAnalyzeMsg((locale === "fr" ? "Erreur : " : "Error: ") + (e instanceof Error ? e.message : "?"));
    } finally {
      setAnalyzing(false);
    }
  };

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
      <div style={{ maxWidth: 980, margin: "0 auto", padding: "0 0 32px 0" }}>

        {/* Top navigation bar */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 18, flexWrap: "wrap" }}>
          <ChromeButton onClick={() => router.push("/incidents")} variant="glass">
            <ArrowLeft size={13} />
            {locale === "fr" ? "Incidents" : "Incidents"}
          </ChromeButton>
          {inc && (
            <span style={{ fontSize: 12, color: "var(--tc-text-muted)" }}>
              #{inc.id} — {inc.title.length > 60 ? inc.title.slice(0, 60) + "…" : inc.title}
            </span>
          )}
          <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            {inc?.status === "open" && (
              <span style={{ fontSize: 10, color: statusColor, fontWeight: 600, display: "flex", alignItems: "center", gap: 4 }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: statusColor, animation: "pulse 2s infinite", display: "inline-block" }} />
                {locale === "fr" ? "Auto-refresh 15s" : "Auto-refresh 15s"}
              </span>
            )}
            <ChromeButton onClick={load} variant="glass">
              <RefreshCw size={12} />
              {locale === "fr" ? "Rafraîchir" : "Refresh"}
            </ChromeButton>
            <ChromeButton onClick={triggerL1} variant="glass" disabled={analyzing}>
              {analyzing
                ? <><RefreshCw size={12} className="spin" /> {locale === "fr" ? "Analyse..." : "Analysing..."}</>
                : <><Brain size={12} /> {locale === "fr" ? "Analyser (L1)" : "Analyse (L1)"}</>}
            </ChromeButton>
            <ChromeButton onClick={() => setShowReport(true)} variant="primary">
              <FileText size={13} />
              {locale === "fr" ? "Ouvrir le rapport" : "Open report"}
            </ChromeButton>
          </div>
        </div>

        {/* Loading */}
        {loading && (
          <NeuCard style={{ padding: 40, textAlign: "center" }}>
            <RefreshCw size={22} className="spin" color="var(--tc-text-muted)" />
            <div style={{ marginTop: 10, color: "var(--tc-text-muted)", fontSize: 13 }}>
              {locale === "fr" ? "Chargement..." : "Loading..."}
            </div>
          </NeuCard>
        )}

        {/* Error */}
        {error && (
          <NeuCard style={{ padding: "14px 16px", borderColor: "#ff4040", marginBottom: 14 }}>
            <div style={{ color: "#ff4040", fontSize: 13, display: "flex", gap: 8, alignItems: "center" }}>
              <AlertTriangle size={14} /> {error}
            </div>
          </NeuCard>
        )}

        {inc && (
          <>
            {/* Incident header */}
            <NeuCard style={{ padding: "18px 20px", marginBottom: 16 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
                <SeverityBadge sev={inc.severity} />
                <StatusBadge status={inc.status} />
                {inc.verdict && (
                  <span style={{
                    padding: "2px 7px", fontSize: 10, fontWeight: 700,
                    background: "#ffffff11", color: "var(--tc-text-muted)", border: "1px solid var(--tc-border)",
                  }}>
                    {inc.verdict}{inc.confidence != null ? ` (${pct(inc.confidence)})` : ""}
                  </span>
                )}
              </div>
              <h1 style={{ margin: "0 0 6px 0", fontSize: 17, fontWeight: 700, color: "var(--tc-text)", lineHeight: 1.3 }}>
                {inc.title}
              </h1>
              <div style={{ fontSize: 12, color: "var(--tc-text-muted)", display: "flex", gap: 12, flexWrap: "wrap" }}>
                <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <Shield size={11} /> {inc.asset}
                </span>
                <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <Clock size={11} /> {fmtDate(inc.created_at)} {fmtTime(inc.created_at)}
                </span>
                {inc.resolved_at && (
                  <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <CheckCircle2 size={11} color="#30a050" /> {locale === "fr" ? "Résolu" : "Resolved"} {fmtDate(inc.resolved_at)}
                  </span>
                )}
              </div>
              {inc.summary && (
                <div style={{ marginTop: 10, fontSize: 12, color: "var(--tc-text-sec)", lineHeight: 1.6, borderLeft: "2px solid var(--tc-border)", paddingLeft: 10 }}>
                  {inc.summary}
                </div>
              )}
              {analyzeMsg && (
                <div style={{
                  marginTop: 10, padding: "8px 12px",
                  background: "#4a9eff22", border: "1px solid #4a9eff44",
                  fontSize: 12, color: "#4a9eff",
                }}>
                  {analyzeMsg}
                </div>
              )}
            </NeuCard>

            {/* Two-column layout */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 14, alignItems: "start" }}>

              {/* Left column: AI analysis + attack paths */}
              <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                <AnalysisTimelineCard
                  graphExecs={data?.graph_executions || []}
                  aiAnalyses={data?.ai_analyses || []}
                  locale={locale}
                />
                <AttackPathsCard paths={data?.attack_paths || []} locale={locale} />
              </div>

              {/* Right column: enrichment + MITRE + related */}
              <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                {data?.ip_enrichment && (
                  <IpEnrichmentCard data={data.ip_enrichment} locale={locale} />
                )}
                {allMitre.length > 0 && (
                  <MitreCard techniques={allMitre} locale={locale} />
                )}
                <RelatedCard incidentId={inc.id} locale={locale} />
              </div>
            </div>
          </>
        )}
      </div>

      {showReport && inc && (
        <ReportModal incidentId={inc.id} locale={locale} onClose={() => setShowReport(false)} />
      )}

      <style>{`
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        .spin { animation: spin 1s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </PageShell>
  );
}

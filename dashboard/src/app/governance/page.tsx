"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import { PageShell } from "@/components/chrome/PageShell";
import {
  Shield, Brain, Gavel, FileCheck, AlertTriangle, RefreshCw, Loader2,
  CheckCircle2, XCircle, ChevronRight, Bot, Server, Globe,
} from "lucide-react";

// ── Types mirroring the Rust API ──────────────────────────

interface ArticleScore {
  id: string;
  title: string;
  description: string;
  score: number;
  relevant_findings: number;
  critical_hits: number;
  high_hits: number;
  medium_hits: number;
  top_recommendation: string | null;
}

interface ComplianceReport {
  framework: string;
  framework_label: string;
  overall_score: number;
  maturity_label: string;
  articles: ArticleScore[];
  gaps: string[];
  total_findings: number;
  critical_findings: number;
}

interface GovernanceSummary {
  generated_at: string;
  compliance: ComplianceReport[];
  ai_systems: {
    by_status: Record<string, number>;
    total: number;
  };
  shadow_ai: {
    findings_count: number;
  };
  findings_summary: {
    total: number;
    critical: number;
    high: number;
  };
}

interface AiSystem {
  id: number;
  name: string;
  category: string;
  provider: string | null;
  endpoint: string | null;
  status: string;
  risk_level: string | null;
  declared_at: string | null;
  first_seen: string;
  last_seen: string;
}

interface ShadowFinding {
  id: number;
  title: string;
  severity: string;
  category: string | null;
  asset: string | null;
  source: string | null;
  metadata: Record<string, unknown>;
  detected_at: string;
}

// ── Helpers ───────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 85) return "#30a050";
  if (score >= 70) return "#7ca030";
  if (score >= 55) return "#d0a820";
  if (score >= 35) return "#d06020";
  return "#e04040";
}

function severityColor(s: string): string {
  const k = s.toLowerCase();
  if (k === "critical") return "#e04040";
  if (k === "high") return "#d06020";
  if (k === "medium") return "#d0a820";
  return "#7ca030";
}

function statusColor(s: string): string {
  if (s === "detected") return "#d06020";
  if (s === "declared") return "#3080d0";
  if (s === "assessed") return "#30a050";
  if (s === "retired") return "#606060";
  return "#9060d0";
}

// ── Score bar (sub-component) ─────────────────────────────

function ScoreBar({ value, label }: { value: number; label?: string }) {
  const color = scoreColor(value);
  return (
    <div>
      {label && (
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "10px", marginBottom: "3px" }}>
          <span style={{ color: "var(--tc-text-sec)", fontWeight: 600 }}>{label}</span>
          <span style={{ color, fontWeight: 700 }}>{value}/100</span>
        </div>
      )}
      <div style={{ height: "6px", borderRadius: "3px", background: "var(--tc-surface-alt)", overflow: "hidden" }}>
        <div style={{ width: `${value}%`, height: "100%", background: color, transition: "width 0.3s" }} />
      </div>
    </div>
  );
}

// ── Card 1 — Shadow AI live ───────────────────────────────

function ShadowAiCard({ locale, summary, findings, loading, onRefresh }: {
  locale: string;
  summary: GovernanceSummary | null;
  findings: ShadowFinding[];
  loading: boolean;
  onRefresh: () => void;
}) {
  const count = summary?.shadow_ai.findings_count ?? 0;
  return (
    <NeuCard accent="red" style={{ padding: "18px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "12px" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
            <Brain size={16} color="#e04040" />
            <h2 style={{ fontSize: "13px", fontWeight: 800, color: "var(--tc-text)", margin: 0, textTransform: "uppercase", letterSpacing: "0.05em" }}>
              {locale === "fr" ? "Shadow AI en direct" : "Shadow AI live"}
            </h2>
          </div>
          <p style={{ fontSize: "11px", color: "var(--tc-text-muted)", margin: 0 }}>
            {locale === "fr"
              ? "Usages IA non-autorisés détectés par Zeek + règles Sigma shadow-ai-*"
              : "Unauthorized AI usage detected via Zeek + Sigma shadow-ai-* rules"}
          </p>
        </div>
        <button onClick={onRefresh} disabled={loading} style={refreshBtn}>
          {loading ? <Loader2 size={11} className="animate-spin" /> : <RefreshCw size={11} />}
        </button>
      </div>

      <div style={{ display: "flex", alignItems: "baseline", gap: "6px", marginBottom: "14px" }}>
        <span style={{ fontSize: "28px", fontWeight: 800, color: count > 0 ? "#e04040" : "#30a050" }}>{count}</span>
        <span style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>
          {locale === "fr" ? "findings AI_USAGE_POLICY ouverts" : "open AI_USAGE_POLICY findings"}
        </span>
      </div>

      {findings.length === 0 ? (
        <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", padding: "8px 0" }}>
          {locale === "fr" ? "Aucun usage shadow AI détecté" : "No shadow AI usage detected"}
        </div>
      ) : (
        <div style={{ maxHeight: "240px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "4px" }}>
          {findings.slice(0, 8).map(f => {
            const meta = f.metadata as Record<string, unknown>;
            const provider = (meta.llm_provider as string) || "—";
            const endpoint = (meta.endpoint as string) || "—";
            const decision = (meta.policy_decision as string) || "—";
            return (
              <div key={f.id} style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "6px 8px", borderRadius: "var(--tc-radius-sm)",
                background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
              }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-text)" }}>
                    {provider} — {endpoint}
                  </div>
                  <div style={{ fontSize: "9px", color: "var(--tc-text-muted)" }}>
                    {f.asset || "—"} · {new Date(f.detected_at).toLocaleString(locale)}
                  </div>
                </div>
                <div style={{ display: "flex", gap: "4px", alignItems: "center" }}>
                  <Badge color={severityColor(f.severity)} label={f.severity.toUpperCase()} />
                  <Badge color={statusColor(decision)} label={decision} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </NeuCard>
  );
}

// ── Card 2 — AI System Inventory ──────────────────────────

function AiInventoryCard({ locale, summary, systems, onDeclare }: {
  locale: string;
  summary: GovernanceSummary | null;
  systems: AiSystem[];
  onDeclare: (id: number) => void;
}) {
  const by = summary?.ai_systems.by_status ?? {};
  const detected = by["detected"] ?? 0;
  const declared = by["declared"] ?? 0;
  const assessed = by["assessed"] ?? 0;
  const total = summary?.ai_systems.total ?? 0;

  return (
    <NeuCard accent="purple" style={{ padding: "18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
        <Server size={16} color="#9060d0" />
        <h2 style={{ fontSize: "13px", fontWeight: 800, color: "var(--tc-text)", margin: 0, textTransform: "uppercase", letterSpacing: "0.05em" }}>
          {locale === "fr" ? "Inventaire IA" : "AI Inventory"}
        </h2>
      </div>
      <p style={{ fontSize: "11px", color: "var(--tc-text-muted)", margin: "0 0 12px" }}>
        {locale === "fr"
          ? "IA déclarées et détectées en shadow — requis EU AI Act Art.12, ISO 42001 A.10"
          : "Declared and shadow-detected AI systems — required by EU AI Act Art.12, ISO 42001 A.10"}
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "8px", marginBottom: "12px" }}>
        <Stat label={locale === "fr" ? "Total" : "Total"} value={total} color="#9060d0" />
        <Stat label={locale === "fr" ? "Détectés" : "Detected"} value={detected} color="#d06020" />
        <Stat label={locale === "fr" ? "Déclarés" : "Declared"} value={declared} color="#3080d0" />
        <Stat label={locale === "fr" ? "Évalués" : "Assessed"} value={assessed} color="#30a050" />
      </div>

      {systems.length === 0 ? (
        <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", padding: "8px 0" }}>
          {locale === "fr" ? "Aucun système IA enregistré" : "No AI system registered"}
        </div>
      ) : (
        <div style={{ maxHeight: "220px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "4px" }}>
          {systems.slice(0, 8).map(s => (
            <div key={s.id} style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              padding: "6px 8px", borderRadius: "var(--tc-radius-sm)",
              background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
            }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-text)" }}>
                  {s.provider || "Unknown"} — {s.endpoint || s.name}
                </div>
                <div style={{ fontSize: "9px", color: "var(--tc-text-muted)" }}>{s.category}</div>
              </div>
              <div style={{ display: "flex", gap: "4px", alignItems: "center" }}>
                <Badge color={statusColor(s.status)} label={s.status} />
                {s.risk_level && <Badge color={severityColor(s.risk_level)} label={s.risk_level} />}
                {s.status === "detected" && (
                  <button onClick={() => onDeclare(s.id)} style={miniBtn} title={locale === "fr" ? "Déclarer" : "Declare"}>
                    <CheckCircle2 size={10} />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </NeuCard>
  );
}

// ── Card 3 — Compliance posture (radar-like) ──────────────

function ComplianceCard({ locale, summary }: {
  locale: string;
  summary: GovernanceSummary | null;
}) {
  const reports = summary?.compliance ?? [];

  return (
    <NeuCard accent="blue" style={{ padding: "18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
        <Gavel size={16} color="#3080d0" />
        <h2 style={{ fontSize: "13px", fontWeight: 800, color: "var(--tc-text)", margin: 0, textTransform: "uppercase", letterSpacing: "0.05em" }}>
          {locale === "fr" ? "Conformité" : "Compliance posture"}
        </h2>
      </div>
      <p style={{ fontSize: "11px", color: "var(--tc-text-muted)", margin: "0 0 14px" }}>
        {locale === "fr"
          ? "Score calculé en temps réel depuis les findings + alertes (mapping keywords)"
          : "Score computed live from findings + alerts (keyword mapping)"}
      </p>

      {reports.length === 0 ? (
        <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>
          {locale === "fr" ? "Chargement…" : "Loading…"}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          {reports.map(r => (
            <FrameworkBlock key={r.framework} report={r} locale={locale} />
          ))}
        </div>
      )}
    </NeuCard>
  );
}

function FrameworkBlock({ report, locale }: { report: ComplianceReport; locale: string }) {
  const [expanded, setExpanded] = useState(false);
  const color = scoreColor(report.overall_score);
  return (
    <div>
      <button onClick={() => setExpanded(!expanded)} style={{
        width: "100%", background: "transparent", border: "none", padding: 0, cursor: "pointer",
        textAlign: "left", fontFamily: "inherit",
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <ChevronRight size={11} style={{ transform: expanded ? "rotate(90deg)" : "none", transition: "transform 0.15s", color: "var(--tc-text-muted)" }} />
            <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text)" }}>{report.framework_label}</span>
            <span style={{ fontSize: "9px", color: "var(--tc-text-muted)" }}>
              {report.gaps.length} {locale === "fr" ? "gaps" : "gaps"}
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <span style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>{report.maturity_label}</span>
            <span style={{ fontSize: "14px", fontWeight: 800, color }}>{report.overall_score}</span>
          </div>
        </div>
        <ScoreBar value={report.overall_score} />
      </button>

      {expanded && (
        <div style={{ marginTop: "10px", display: "flex", flexDirection: "column", gap: "6px", paddingLeft: "14px" }}>
          {report.articles.map(a => (
            <div key={a.id} style={{
              padding: "6px 8px", borderRadius: "var(--tc-radius-sm)",
              background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "3px" }}>
                <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-text)" }}>
                  {a.id} — {a.title}
                </div>
                <div style={{ fontSize: "11px", fontWeight: 700, color: scoreColor(a.score) }}>{a.score}</div>
              </div>
              <ScoreBar value={a.score} />
              {(a.critical_hits + a.high_hits + a.medium_hits) > 0 && (
                <div style={{ display: "flex", gap: "8px", marginTop: "5px", fontSize: "9px", color: "var(--tc-text-muted)" }}>
                  <span>{a.critical_hits} critical</span>
                  <span>{a.high_hits} high</span>
                  <span>{a.medium_hits} medium</span>
                </div>
              )}
              {a.top_recommendation && (
                <div style={{ fontSize: "9px", color: "var(--tc-text-sec)", marginTop: "4px", fontStyle: "italic" }}>
                  → {a.top_recommendation}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Card 4 — Evidence index (grounding v1.1 carry-over) ──

function EvidenceCard({ locale, summary }: { locale: string; summary: GovernanceSummary | null }) {
  return (
    <NeuCard accent="green" style={{ padding: "18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
        <FileCheck size={16} color="#30a050" />
        <h2 style={{ fontSize: "13px", fontWeight: 800, color: "var(--tc-text)", margin: 0, textTransform: "uppercase", letterSpacing: "0.05em" }}>
          {locale === "fr" ? "Traçabilité & audit" : "Evidence & audit"}
        </h2>
      </div>
      <p style={{ fontSize: "11px", color: "var(--tc-text-muted)", margin: "0 0 14px" }}>
        {locale === "fr"
          ? "Log immuable V16 + evidence citations (grounding v1.1) — ISO 42001 A.6.2.6"
          : "V16 immutable log + evidence citations (grounding v1.1) — ISO 42001 A.6.2.6"}
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "12px" }}>
        <Stat label={locale === "fr" ? "Findings totaux" : "Total findings"} value={summary?.findings_summary.total ?? 0} color="#30a050" />
        <Stat label={locale === "fr" ? "Critiques" : "Critical"} value={summary?.findings_summary.critical ?? 0} color="#e04040" />
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
        <a href="/api/tc/exports/audit-trail" style={evidenceLinkStyle}>
          <span style={{ fontSize: "10px", fontWeight: 700 }}>
            {locale === "fr" ? "Consulter l'audit trail immuable" : "Browse immutable audit trail"}
          </span>
          <ChevronRight size={11} />
        </a>
        <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", padding: "4px 8px" }}>
          {locale === "fr"
            ? "Export Audit Trail (onglet Rapports) pour récupérer le journal complet avec hash-chain."
            : "Use the Audit Trail export (Reports tab) to download the full hash-chained journal."}
        </div>
      </div>
    </NeuCard>
  );
}

// ── Tiny components ───────────────────────────────────────

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", padding: "1px 5px",
      fontSize: "8px", fontWeight: 700, borderRadius: "3px",
      background: `${color}18`, color, border: `1px solid ${color}30`,
      textTransform: "uppercase", letterSpacing: "0.05em",
    }}>{label}</span>
  );
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{
      padding: "8px 10px", borderRadius: "var(--tc-radius-sm)",
      background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
    }}>
      <div style={{ fontSize: "18px", fontWeight: 800, color, lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px", textTransform: "uppercase", letterSpacing: "0.05em" }}>{label}</div>
    </div>
  );
}

const refreshBtn: React.CSSProperties = {
  padding: "4px", background: "transparent", border: "1px solid var(--tc-border)",
  borderRadius: "var(--tc-radius-sm)", cursor: "pointer", color: "var(--tc-text-sec)",
};
const miniBtn: React.CSSProperties = {
  padding: "3px 5px", background: "var(--tc-surface)", border: "1px solid var(--tc-border)",
  borderRadius: "3px", cursor: "pointer", color: "#30a050", display: "flex", alignItems: "center",
};
const evidenceLinkStyle: React.CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "8px 10px", borderRadius: "var(--tc-radius-sm)",
  background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
  textDecoration: "none", color: "var(--tc-text-sec)",
};

// ── Main page ─────────────────────────────────────────────

export default function GovernancePage() {
  const locale = useLocale();
  const [summary, setSummary] = useState<GovernanceSummary | null>(null);
  const [systems, setSystems] = useState<AiSystem[]>([]);
  const [shadowFindings, setShadowFindings] = useState<ShadowFinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, a, f] = await Promise.all([
        fetch("/api/tc/governance/summary").then(r => r.ok ? r.json() : null),
        fetch("/api/tc/governance/ai-systems").then(r => r.ok ? r.json() : { data: [] }),
        fetch("/api/tc/governance/shadow-ai-findings").then(r => r.ok ? r.json() : { data: [] }),
      ]);
      setSummary(s);
      setSystems(Array.isArray(a.data) ? a.data : []);
      setShadowFindings(Array.isArray(f.data) ? f.data : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "fetch error");
    }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const declareSystem = async (id: number) => {
    await fetch(`/api/tc/governance/ai-systems/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "declared", declared_by: "dashboard" }),
    });
    load();
  };

  return (
    <PageShell
      title={locale === "fr" ? "Gouvernance IA & conformité" : "AI Governance & Compliance"}
      subtitle={
        locale === "fr"
          ? "Posture continue : shadow AI live · inventaire IA · score NIS2 / ISO 27001 · traçabilité"
          : "Continuous posture: shadow AI live · AI inventory · NIS2 / ISO 27001 score · audit trail"
      }
      right={
        <button
          onClick={load}
          disabled={loading}
          style={{
            padding: "6px 10px",
            fontSize: "10px",
            fontWeight: 600,
            borderRadius: "6px",
            cursor: loading ? "default" : "pointer",
            background: "var(--tc-surface-alt)",
            border: "1px solid var(--tc-border)",
            color: "var(--tc-text-sec)",
            display: "flex",
            alignItems: "center",
            gap: "4px",
          }}
        >
          {loading ? <Loader2 size={11} className="animate-spin" /> : <RefreshCw size={11} />}
          {locale === "fr" ? "Actualiser" : "Refresh"}
        </button>
      }
    >
      {error && (
        <div style={{
          padding: "10px 14px", background: "rgba(224,64,64,0.08)", borderLeft: "3px solid #e04040",
          borderRadius: "3px", fontSize: "11px", color: "#e04040", fontWeight: 600, marginBottom: "14px",
          display: "flex", gap: "6px", alignItems: "center",
        }}>
          <XCircle size={12} />
          {error}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
        <ShadowAiCard locale={locale} summary={summary} findings={shadowFindings} loading={loading} onRefresh={load} />
        <AiInventoryCard locale={locale} summary={summary} systems={systems} onDeclare={declareSystem} />
        <ComplianceCard locale={locale} summary={summary} />
        <EvidenceCard locale={locale} summary={summary} />
      </div>

      <div style={{
        marginTop: "20px", padding: "14px", borderRadius: "var(--tc-radius-sm)",
        background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
        display: "flex", alignItems: "flex-start", gap: "10px",
      }}>
        <AlertTriangle size={14} color="#d0a820" style={{ flexShrink: 0, marginTop: "2px" }} />
        <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", lineHeight: "1.5" }}>
          {locale === "fr" ? (
            <>
              <strong style={{ color: "var(--tc-text-sec)" }}>Alignement réglementaire :</strong> cette page matérialise
              l'auditabilité exigée par <strong>NIS2 Art.21 §2(d-e)</strong>, <strong>EU AI Act Art.12</strong>,
              <strong> ISO 42001 A.5.2 / A.6.2.2 / A.10</strong> et <strong>NIST AI RMF 2025</strong> (inventaire shadow AI).
              Les scores sont calculés à partir des findings et alertes en cours — ils reflètent la posture en temps réel.
            </>
          ) : (
            <>
              <strong style={{ color: "var(--tc-text-sec)" }}>Regulatory alignment:</strong> this page materializes the
              auditability required by <strong>NIS2 Art.21 §2(d-e)</strong>, <strong>EU AI Act Art.12</strong>,
              <strong> ISO 42001 A.5.2 / A.6.2.2 / A.10</strong> and <strong>NIST AI RMF 2025</strong> (shadow AI inventory).
              Scores are computed live from open findings and alerts — they reflect real-time posture.
            </>
          )}
        </div>
      </div>
    </PageShell>
  );
}

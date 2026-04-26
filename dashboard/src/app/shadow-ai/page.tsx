"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import { PageShell } from "@/components/chrome/PageShell";
import {
  Brain, Server, RefreshCw, Loader2, XCircle, CheckCircle2,
} from "lucide-react";

// ── Types mirroring the Rust API ──────────────────────────

interface ShadowSummary {
  shadow_ai: { findings_count: number };
  ai_systems: {
    by_status: Record<string, number>;
    total: number;
  };
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

// ── Helpers ───────────────────────────────────────────────

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

function policyDecisionColor(decision: string): string {
  switch (decision.toLowerCase()) {
    case "block":
    case "blocked":
    case "denied":
      return "#e04040";
    case "allow":
    case "allowed":
      return "#30a050";
    default:
      return "var(--tc-text-muted)";
  }
}

function Badge({ color, label }: { color: string; label: string }) {
  return (
    <span style={{
      fontSize: "9px", fontWeight: 700, padding: "1px 6px",
      borderRadius: "3px", background: color, color: "#fff",
      textTransform: "uppercase", letterSpacing: "0.04em",
    }}>
      {label}
    </span>
  );
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{
      padding: "8px", borderRadius: "var(--tc-radius-sm)",
      background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
      textAlign: "center",
    }}>
      <div style={{ fontSize: "18px", fontWeight: 800, color }}>{value}</div>
      <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
        {label}
      </div>
    </div>
  );
}

const miniBtn: React.CSSProperties = {
  padding: "2px 4px", border: "1px solid var(--tc-border)",
  borderRadius: "3px", background: "var(--tc-surface)",
  color: "var(--tc-text-sec)", cursor: "pointer",
  display: "flex", alignItems: "center",
};

// ── Card: Shadow AI live ──────────────────────────────────

function ShadowAiCard({ locale, summary, findings }: {
  locale: string;
  summary: ShadowSummary | null;
  findings: ShadowFinding[];
}) {
  const count = summary?.shadow_ai.findings_count ?? 0;
  return (
    <NeuCard accent="red" style={{ padding: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "12px" }}>
        <Brain size={18} color="var(--tc-red)" />
        <div>
          <h2 style={{ fontSize: "13px", fontWeight: 800, color: "var(--tc-text)", margin: 0, textTransform: "uppercase", letterSpacing: "0.05em" }}>
            {locale === "fr" ? "Shadow AI en direct" : "Shadow AI live"}
          </h2>
          <p style={{ fontSize: "11px", color: "var(--tc-text-muted)", margin: 0 }}>
            {locale === "fr"
              ? "ChatGPT, Claude, Gemini et autres usages non-déclarés"
              : "ChatGPT, Claude, Gemini and other undeclared usage"}
          </p>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "baseline", gap: "8px", marginBottom: "14px" }}>
        <span style={{ fontSize: "32px", fontWeight: 800, color: count > 0 ? "#e04040" : "#30a050" }}>{count}</span>
        <span style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>
          {locale === "fr" ? "findings AI_USAGE_POLICY ouverts" : "open AI_USAGE_POLICY findings"}
        </span>
      </div>

      {findings.length === 0 ? (
        <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", padding: "8px 0" }}>
          {locale === "fr"
            ? "Aucun usage shadow AI détecté. Le moteur Zeek + Sigma shadow-ai-* surveille en continu."
            : "No shadow AI usage detected. Zeek + shadow-ai-* Sigma rules monitor continuously."}
        </div>
      ) : (
        <div style={{ maxHeight: "280px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "4px" }}>
          {findings.slice(0, 12).map(f => {
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
                  <Badge color={policyDecisionColor(decision)} label={decision} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </NeuCard>
  );
}

// ── Card: AI System Inventory ─────────────────────────────

function AiInventoryCard({ locale, summary, systems, onDeclare }: {
  locale: string;
  summary: ShadowSummary | null;
  systems: AiSystem[];
  onDeclare: (id: number) => void;
}) {
  const by = summary?.ai_systems.by_status ?? {};
  const detected = by["detected"] ?? 0;
  const declared = by["declared"] ?? 0;
  const assessed = by["assessed"] ?? 0;
  const total = summary?.ai_systems.total ?? 0;

  return (
    <NeuCard accent="purple" style={{ padding: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "4px" }}>
        <Server size={18} color="var(--tc-text-sec)" />
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
        <div style={{ maxHeight: "260px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "4px" }}>
          {systems.slice(0, 12).map(s => (
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

// ── Page ──────────────────────────────────────────────────

export default function ShadowAiPage() {
  const locale = useLocale();
  const [summary, setSummary] = useState<ShadowSummary | null>(null);
  const [findings, setFindings] = useState<ShadowFinding[]>([]);
  const [systems, setSystems] = useState<AiSystem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, f, a] = await Promise.all([
        fetch("/api/tc/governance/summary").then(r => r.ok ? r.json() : null),
        fetch("/api/tc/governance/shadow-ai-findings").then(r => r.ok ? r.json() : { data: [] }),
        fetch("/api/tc/governance/ai-systems").then(r => r.ok ? r.json() : { data: [] }),
      ]);
      setSummary(s);
      setFindings(Array.isArray(f.data) ? f.data : []);
      setSystems(Array.isArray(a.data) ? a.data : []);
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
      title={locale === "fr" ? "IA — Shadow & Inventaire" : "AI — Shadow & Inventory"}
      subtitle={
        locale === "fr"
          ? "Détection en direct des usages IA non-autorisés + inventaire EU AI Act / ISO 42001"
          : "Live detection of unauthorized AI usage + EU AI Act / ISO 42001 inventory"
      }
      right={
        <button
          onClick={load}
          disabled={loading}
          style={{
            padding: "6px 10px", fontSize: "10px", fontWeight: 600,
            borderRadius: "6px", cursor: loading ? "default" : "pointer",
            background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
            color: "var(--tc-text-sec)",
            display: "flex", alignItems: "center", gap: "4px",
          }}
        >
          {loading ? <Loader2 size={11} className="animate-spin" /> : <RefreshCw size={11} />}
          {locale === "fr" ? "Actualiser" : "Refresh"}
        </button>
      }
    >
      {error && (
        <div style={{
          padding: "10px 14px", borderLeft: "3px solid var(--tc-red)",
          fontSize: "11px", color: "var(--tc-red)", fontWeight: 600, marginBottom: "14px",
          display: "flex", gap: "6px", alignItems: "center",
        }}>
          <XCircle size={12} />
          {error}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
        <ShadowAiCard locale={locale} summary={summary} findings={findings} />
        <AiInventoryCard locale={locale} summary={summary} systems={systems} onDeclare={declareSystem} />
      </div>
    </PageShell>
  );
}

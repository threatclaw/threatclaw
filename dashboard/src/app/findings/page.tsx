"use client";

import React, { useState, useEffect, useCallback } from "react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import { NeuCard as ChromeInsetCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  AlertTriangle, Shield, ChevronDown, RefreshCw, CheckCircle2, XCircle,
  Clock, Filter, Search, X, Eye,
} from "lucide-react";
import { fetchFindings, fetchFindingsCounts, updateFindingStatus, type Finding, type CountEntry } from "@/lib/tc-api";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";

const SEVERITY_COLORS: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "#e84040", bg: "rgba(232,64,64,0.08)", border: "rgba(232,64,64,0.2)" },
  high: { color: "#d07020", bg: "rgba(208,112,32,0.08)", border: "rgba(208,112,32,0.2)" },
  medium: { color: "var(--tc-amber)", bg: "rgba(208,144,32,0.08)", border: "rgba(208,144,32,0.2)" },
  low: { color: "var(--tc-blue)", bg: "rgba(48,128,208,0.08)", border: "rgba(48,128,208,0.2)" },
  info: { color: "var(--tc-text-muted)", bg: "var(--tc-input)", border: "var(--tc-input)" },
};

const STATUS_LABELS: Record<string, { labelKey: string; icon: React.ReactNode; color: string }> = {
  open: { labelKey: "open", icon: <AlertTriangle size={12} />, color: "var(--tc-red)" },
  in_progress: { labelKey: "inProgress", icon: <Clock size={12} />, color: "var(--tc-amber)" },
  resolved: { labelKey: "resolved", icon: <CheckCircle2 size={12} />, color: "var(--tc-green)" },
  false_positive: { labelKey: "falsePositive", icon: <XCircle size={12} />, color: "var(--tc-text-muted)" },
};

export default function FindingsPage() {
  const locale = useLocale();
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
      setFindings(f.findings);
      setCounts(c);
      setError(null);
    } catch {
      setError(tr("backendNotAccessible", locale));
    }
    setLoading(false);
  }, [filterSeverity, filterStatus]);

  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t); }, [load]);

  const changeStatus = async (id: number, status: string) => {
    try {
      await updateFindingStatus(id, status, "rssi");
      await load();
    } catch { /* */ }
  };

  const filtered = search
    ? findings.filter(f => f.title.toLowerCase().includes(search.toLowerCase()) || f.asset?.toLowerCase().includes(search.toLowerCase()))
    : findings;

  const total = counts.reduce((s, c) => s + c.count, 0);

  const [activeTab, setActiveTab] = useState<"findings" | "alerts">("findings");

  return (
    <div>
      <div style={{ marginBottom: "16px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 800, color: "var(--tc-text)", letterSpacing: "-0.02em", margin: 0 }}>Détections</h1>
        <p style={{ fontSize: "13px", color: "var(--tc-text-muted)", margin: "4px 0 0" }}>
          Vulnérabilités, alertes de sécurité et anomalies comportementales
        </p>
      </div>

      {/* Tabs: Vulnérabilités | Alertes de sécurité */}
      <div style={{ display: "flex", gap: "4px", marginBottom: "16px" }}>
        <button onClick={() => setActiveTab("findings")} style={{
          padding: "8px 16px", fontSize: "11px", fontWeight: 700, borderRadius: "var(--tc-radius-sm)",
          cursor: "pointer", fontFamily: "inherit", textTransform: "uppercase", letterSpacing: "0.04em",
          background: activeTab === "findings" ? "var(--tc-red)" : "var(--tc-input)",
          color: activeTab === "findings" ? "#fff" : "var(--tc-text-muted)",
          border: activeTab === "findings" ? "none" : "1px solid var(--tc-border)",
        }}>
          Vulnérabilités ({total})
        </button>
        <button onClick={() => { setActiveTab("alerts"); window.location.href = "/alerts"; }} style={{
          padding: "8px 16px", fontSize: "11px", fontWeight: 700, borderRadius: "var(--tc-radius-sm)",
          cursor: "pointer", fontFamily: "inherit", textTransform: "uppercase", letterSpacing: "0.04em",
          background: activeTab === "alerts" ? "var(--tc-red)" : "var(--tc-input)",
          color: activeTab === "alerts" ? "#fff" : "var(--tc-text-muted)",
          border: activeTab === "alerts" ? "none" : "1px solid var(--tc-border)",
        }}>
          Alertes de sécurité
        </button>
      </div>

      {error && <ErrorBanner message={error} onRetry={load} />}

      {/* Severity counts */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap" }}>
        {["critical", "high", "medium", "low", "info"].map(sev => {
          const c = counts.find(c => c.label === sev)?.count || 0;
          const s = SEVERITY_COLORS[sev];
          const active = filterSeverity === sev;
          return (
            <button key={sev} onClick={() => setFilterSeverity(active ? "" : sev)} style={{
              padding: "8px 14px", borderRadius: "var(--tc-radius-md)", border: `1px solid ${active ? s.border : "var(--tc-input)"}`,
              background: active ? s.bg : "var(--tc-surface-alt)", cursor: "pointer",
              display: "flex", alignItems: "center", gap: "6px", fontFamily: "inherit", color: s.color, fontSize: "13px", fontWeight: 600,
            }}>
              <span style={{ fontSize: "16px", fontWeight: 800 }}>{c}</span>
              {sev.charAt(0).toUpperCase() + sev.slice(1)}
            </button>
          );
        })}
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", alignItems: "center" }}>
        <div style={{ flex: 1, display: "flex", alignItems: "center", gap: "8px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-md)", padding: "8px 12px" }}>
          <Search size={14} color="var(--tc-text-muted)" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Rechercher..."
            style={{ flex: 1, background: "none", border: "none", outline: "none", color: "var(--tc-text)", fontSize: "13px", fontFamily: "inherit" }} />
          {search && <button onClick={() => setSearch("")} style={{ background: "none", border: "none", cursor: "pointer" }}><X size={14} color="var(--tc-text-muted)" /></button>}
        </div>
        {["open", "in_progress", "resolved"].map(st => {
          const active = filterStatus === st;
          return (
            <button key={st} onClick={() => setFilterStatus(active ? "" : st)} style={{
              padding: "8px 12px", borderRadius: "var(--tc-radius-md)", fontSize: "11px", fontWeight: 600,
              border: `1px solid ${active ? "rgba(208,48,32,0.2)" : "var(--tc-input)"}`,
              background: active ? "rgba(208,48,32,0.06)" : "var(--tc-surface-alt)",
              color: active ? "#d03020" : "var(--tc-text-muted)", cursor: "pointer", fontFamily: "inherit",
            }}>
              {STATUS_LABELS[st] ? tr(STATUS_LABELS[st].labelKey, locale) : st}
            </button>
          );
        })}
        <ChromeButton onClick={load} variant="glass"><RefreshCw size={14} /></ChromeButton>
      </div>

      {/* Findings list */}
      {loading ? (
        <ChromeInsetCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>Chargement...</div></ChromeInsetCard>
      ) : filtered.length === 0 ? (
        <ChromeInsetCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{tr("noFinding", locale)}{filterSeverity || filterStatus ? ` ${tr("withFilters", locale)}` : ""}</div></ChromeInsetCard>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          {filtered.map(f => {
            const sev = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.info;
            const st = STATUS_LABELS[f.status] || STATUS_LABELS.open;
            const isExpanded = expandedId === f.id;
            return (
              <ChromeInsetCard key={f.id} style={{ padding: "14px 16px", borderRadius: "var(--tc-radius-card)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={() => setExpandedId(isExpanded ? null : f.id)}>
                  <span style={{ fontSize: "10px", fontWeight: 700, padding: "3px 8px", borderRadius: "var(--tc-radius-sm)", background: sev.bg, color: sev.color, border: `1px solid ${sev.border}`, textTransform: "uppercase", flexShrink: 0 }}>
                    {f.severity}
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--tc-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</div>
                    <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", display: "flex", gap: "12px", marginTop: "2px" }}>
                      {f.asset && <a href={`/assets?search=${encodeURIComponent(f.asset)}`} style={{ color: "var(--tc-blue)", textDecoration: "none" }}>{f.asset}</a>}
                      <span>{f.skill_id}</span>
                      <span>{new Date(f.detected_at).toLocaleDateString("fr-FR")}</span>
                    </div>
                  </div>
                  <span style={{ fontSize: "10px", color: st.color, display: "flex", alignItems: "center", gap: "4px" }}>
                    {st.icon} {tr(st.labelKey, locale)}
                  </span>
                  <ChevronDown size={14} color="var(--tc-text-muted)" style={{ transform: isExpanded ? "rotate(180deg)" : "none", transition: "0.2s" }} />
                </div>

                {isExpanded && (
                  <div style={{ marginTop: "14px", borderTop: "1px solid var(--tc-border-light)", paddingTop: "14px" }}>
                    {f.description && <div style={{ fontSize: "12px", color: "var(--tc-text-sec)", lineHeight: 1.6, marginBottom: "12px" }}>{f.description}</div>}
                    <div style={{ display: "flex", gap: "16px", fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "12px", flexWrap: "wrap" }}>
                      {f.source && <span>Source : <strong style={{ color: "var(--tc-text)" }}>{f.source}</strong></span>}
                      {f.category && <span>Catégorie : <strong style={{ color: "var(--tc-text)" }}>{f.category}</strong></span>}
                      <span>Détecté : <strong style={{ color: "var(--tc-text)" }}>{new Date(f.detected_at).toLocaleString("fr-FR")}</strong></span>
                      {f.resolved_at && <span>Résolu : <strong style={{ color: "var(--tc-green)" }}>{new Date(f.resolved_at).toLocaleString("fr-FR")}</strong></span>}
                    </div>
                    <div style={{ display: "flex", gap: "6px" }}>
                      {f.status !== "resolved" && (
                        <ChromeButton onClick={() => changeStatus(f.id, "resolved")} variant="glass">
                          <CheckCircle2 size={12} /> Résolu
                        </ChromeButton>
                      )}
                      {f.status !== "in_progress" && f.status !== "resolved" && (
                        <ChromeButton onClick={() => changeStatus(f.id, "in_progress")} variant="glass">
                          <Clock size={12} /> En cours
                        </ChromeButton>
                      )}
                      {f.status !== "false_positive" && (
                        <ChromeButton onClick={() => changeStatus(f.id, "false_positive")} variant="glass">
                          <XCircle size={12} /> Faux positif
                        </ChromeButton>
                      )}
                    </div>
                  </div>
                )}
              </ChromeInsetCard>
            );
          })}
        </div>
      )}
    </div>
  );
}

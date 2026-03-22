"use client";

import React, { useState, useEffect, useCallback } from "react";
import { ChromeInsetCard } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  AlertTriangle, Shield, ChevronDown, RefreshCw, CheckCircle2, XCircle,
  Clock, Filter, Search, X, Eye,
} from "lucide-react";
import { fetchFindings, fetchFindingsCounts, updateFindingStatus, type Finding, type CountEntry } from "@/lib/tc-api";

const SEVERITY_COLORS: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "#e84040", bg: "rgba(232,64,64,0.08)", border: "rgba(232,64,64,0.2)" },
  high: { color: "#d07020", bg: "rgba(208,112,32,0.08)", border: "rgba(208,112,32,0.2)" },
  medium: { color: "#d09020", bg: "rgba(208,144,32,0.08)", border: "rgba(208,144,32,0.2)" },
  low: { color: "#3080d0", bg: "rgba(48,128,208,0.08)", border: "rgba(48,128,208,0.2)" },
  info: { color: "#5a534e", bg: "rgba(255,255,255,0.03)", border: "rgba(255,255,255,0.06)" },
};

const STATUS_LABELS: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  open: { label: "Ouvert", icon: <AlertTriangle size={12} />, color: "#d03020" },
  in_progress: { label: "En cours", icon: <Clock size={12} />, color: "#d09020" },
  resolved: { label: "Résolu", icon: <CheckCircle2 size={12} />, color: "#30a050" },
  false_positive: { label: "Faux positif", icon: <XCircle size={12} />, color: "#5a534e" },
};

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [counts, setCounts] = useState<CountEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      const [f, c] = await Promise.all([
        fetchFindings({ severity: filterSeverity || undefined, status: filterStatus || undefined, limit: 200 }),
        fetchFindingsCounts(),
      ]);
      setFindings(f.findings);
      setCounts(c);
    } catch { /* */ }
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

  return (
    <div>
      <div style={{ marginBottom: "24px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 800, color: "#e8e4e0", letterSpacing: "-0.02em", margin: 0 }}>Findings</h1>
        <p style={{ fontSize: "13px", color: "#5a534e", margin: "4px 0 0" }}>
          {total} finding{total !== 1 ? "s" : ""} détecté{total !== 1 ? "s" : ""} par les skills
        </p>
      </div>

      {/* Severity counts */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap" }}>
        {["critical", "high", "medium", "low", "info"].map(sev => {
          const c = counts.find(c => c.label === sev)?.count || 0;
          const s = SEVERITY_COLORS[sev];
          const active = filterSeverity === sev;
          return (
            <button key={sev} onClick={() => setFilterSeverity(active ? "" : sev)} style={{
              padding: "8px 14px", borderRadius: "10px", border: `1px solid ${active ? s.border : "rgba(255,255,255,0.04)"}`,
              background: active ? s.bg : "rgba(255,255,255,0.02)", cursor: "pointer",
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
        <div style={{ flex: 1, display: "flex", alignItems: "center", gap: "8px", background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: "10px", padding: "8px 12px" }}>
          <Search size={14} color="#5a534e" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Rechercher..."
            style={{ flex: 1, background: "none", border: "none", outline: "none", color: "#e8e4e0", fontSize: "13px", fontFamily: "inherit" }} />
          {search && <button onClick={() => setSearch("")} style={{ background: "none", border: "none", cursor: "pointer" }}><X size={14} color="#5a534e" /></button>}
        </div>
        {["open", "in_progress", "resolved"].map(st => {
          const active = filterStatus === st;
          return (
            <button key={st} onClick={() => setFilterStatus(active ? "" : st)} style={{
              padding: "8px 12px", borderRadius: "10px", fontSize: "11px", fontWeight: 600,
              border: `1px solid ${active ? "rgba(208,48,32,0.2)" : "rgba(255,255,255,0.04)"}`,
              background: active ? "rgba(208,48,32,0.06)" : "rgba(255,255,255,0.02)",
              color: active ? "#d03020" : "#5a534e", cursor: "pointer", fontFamily: "inherit",
            }}>
              {STATUS_LABELS[st]?.label || st}
            </button>
          );
        })}
        <ChromeButton onClick={load} variant="glass"><RefreshCw size={14} /></ChromeButton>
      </div>

      {/* Findings list */}
      {loading ? (
        <ChromeInsetCard><div style={{ textAlign: "center", padding: "32px", color: "#5a534e" }}>Chargement...</div></ChromeInsetCard>
      ) : filtered.length === 0 ? (
        <ChromeInsetCard><div style={{ textAlign: "center", padding: "32px", color: "#5a534e" }}>Aucun finding{filterSeverity || filterStatus ? " avec ces filtres" : ""}</div></ChromeInsetCard>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          {filtered.map(f => {
            const sev = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.info;
            const st = STATUS_LABELS[f.status] || STATUS_LABELS.open;
            const isExpanded = expandedId === f.id;
            return (
              <ChromeInsetCard key={f.id} style={{ borderLeft: `3px solid ${sev.color}`, padding: "14px 16px", borderRadius: "12px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={() => setExpandedId(isExpanded ? null : f.id)}>
                  <span style={{ fontSize: "10px", fontWeight: 700, padding: "3px 8px", borderRadius: "6px", background: sev.bg, color: sev.color, border: `1px solid ${sev.border}`, textTransform: "uppercase", flexShrink: 0 }}>
                    {f.severity}
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: "13px", fontWeight: 600, color: "#e8e4e0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</div>
                    <div style={{ fontSize: "11px", color: "#5a534e", display: "flex", gap: "12px", marginTop: "2px" }}>
                      {f.asset && <span>{f.asset}</span>}
                      <span>{f.skill_id}</span>
                      <span>{new Date(f.detected_at).toLocaleDateString("fr-FR")}</span>
                    </div>
                  </div>
                  <span style={{ fontSize: "10px", color: st.color, display: "flex", alignItems: "center", gap: "4px" }}>
                    {st.icon} {st.label}
                  </span>
                  <ChevronDown size={14} color="#5a534e" style={{ transform: isExpanded ? "rotate(180deg)" : "none", transition: "0.2s" }} />
                </div>

                {isExpanded && (
                  <div style={{ marginTop: "14px", borderTop: "1px solid rgba(255,255,255,0.04)", paddingTop: "14px" }}>
                    {f.description && <div style={{ fontSize: "12px", color: "#9a918a", lineHeight: 1.6, marginBottom: "12px" }}>{f.description}</div>}
                    <div style={{ display: "flex", gap: "16px", fontSize: "11px", color: "#5a534e", marginBottom: "12px", flexWrap: "wrap" }}>
                      {f.source && <span>Source : <strong style={{ color: "#e8e4e0" }}>{f.source}</strong></span>}
                      {f.category && <span>Catégorie : <strong style={{ color: "#e8e4e0" }}>{f.category}</strong></span>}
                      <span>Détecté : <strong style={{ color: "#e8e4e0" }}>{new Date(f.detected_at).toLocaleString("fr-FR")}</strong></span>
                      {f.resolved_at && <span>Résolu : <strong style={{ color: "#30a050" }}>{new Date(f.resolved_at).toLocaleString("fr-FR")}</strong></span>}
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

"use client";

import React, { useState, useEffect, useCallback } from "react";
import { ChromeInsetCard } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  Bell, ChevronDown, RefreshCw, CheckCircle2, XCircle,
  Clock, Search, X, AlertTriangle, Shield,
} from "lucide-react";
import { fetchAlerts, fetchAlertsCounts, type Alert, type CountEntry } from "@/lib/tc-api";

const LEVEL_COLORS: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "#e84040", bg: "rgba(232,64,64,0.08)", border: "rgba(232,64,64,0.2)" },
  high: { color: "#d07020", bg: "rgba(208,112,32,0.08)", border: "rgba(208,112,32,0.2)" },
  medium: { color: "#d09020", bg: "rgba(208,144,32,0.08)", border: "rgba(208,144,32,0.2)" },
  low: { color: "#3080d0", bg: "rgba(48,128,208,0.08)", border: "rgba(48,128,208,0.2)" },
  informational: { color: "#5a534e", bg: "rgba(255,255,255,0.03)", border: "rgba(255,255,255,0.06)" },
};

const STATUS_LABELS: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  new: { label: "Nouveau", icon: <Bell size={12} />, color: "#d03020" },
  investigating: { label: "Investigation", icon: <Clock size={12} />, color: "#d09020" },
  resolved: { label: "Résolu", icon: <CheckCircle2 size={12} />, color: "#30a050" },
  false_positive: { label: "Faux positif", icon: <XCircle size={12} />, color: "#5a534e" },
};

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [counts, setCounts] = useState<CountEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterLevel, setFilterLevel] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      const [a, c] = await Promise.all([
        fetchAlerts({ level: filterLevel || undefined, status: filterStatus || undefined, limit: 200 }),
        fetchAlertsCounts(),
      ]);
      setAlerts(a.alerts);
      setCounts(c);
    } catch { /* */ }
    setLoading(false);
  }, [filterLevel, filterStatus]);

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  const total = counts.reduce((s, c) => s + c.count, 0);

  const filtered = search
    ? alerts.filter(a => a.title.toLowerCase().includes(search.toLowerCase()) || a.hostname?.toLowerCase().includes(search.toLowerCase()) || a.source_ip?.toLowerCase().includes(search.toLowerCase()))
    : alerts;

  return (
    <div>
      <div style={{ marginBottom: "24px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 800, color: "#e8e4e0", letterSpacing: "-0.02em", margin: 0 }}>Alertes Sigma</h1>
        <p style={{ fontSize: "13px", color: "#5a534e", margin: "4px 0 0" }}>
          {total} alerte{total !== 1 ? "s" : ""} détectée{total !== 1 ? "s" : ""} par le moteur Sigma
        </p>
      </div>

      {/* Level counts */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap" }}>
        {["critical", "high", "medium", "low", "informational"].map(lev => {
          const c = counts.find(c => c.label === lev)?.count || 0;
          const s = LEVEL_COLORS[lev];
          const active = filterLevel === lev;
          return (
            <button key={lev} onClick={() => setFilterLevel(active ? "" : lev)} style={{
              padding: "8px 14px", borderRadius: "10px", border: `1px solid ${active ? s.border : "rgba(255,255,255,0.04)"}`,
              background: active ? s.bg : "rgba(255,255,255,0.02)", cursor: "pointer",
              display: "flex", alignItems: "center", gap: "6px", fontFamily: "inherit", color: s.color, fontSize: "13px", fontWeight: 600,
            }}>
              <span style={{ fontSize: "16px", fontWeight: 800 }}>{c}</span>
              {lev === "informational" ? "Info" : lev.charAt(0).toUpperCase() + lev.slice(1)}
            </button>
          );
        })}
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", alignItems: "center" }}>
        <div style={{ flex: 1, display: "flex", alignItems: "center", gap: "8px", background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: "10px", padding: "8px 12px" }}>
          <Search size={14} color="#5a534e" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Rechercher par titre, hostname, IP..."
            style={{ flex: 1, background: "none", border: "none", outline: "none", color: "#e8e4e0", fontSize: "13px", fontFamily: "inherit" }} />
          {search && <button onClick={() => setSearch("")} style={{ background: "none", border: "none", cursor: "pointer" }}><X size={14} color="#5a534e" /></button>}
        </div>
        {["new", "investigating", "resolved"].map(st => {
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

      {/* Alerts list */}
      {loading ? (
        <ChromeInsetCard><div style={{ textAlign: "center", padding: "32px", color: "#5a534e" }}>Chargement...</div></ChromeInsetCard>
      ) : filtered.length === 0 ? (
        <ChromeInsetCard>
          <div style={{ textAlign: "center", padding: "32px" }}>
            <Shield size={24} color="#30a050" style={{ margin: "0 auto 8px" }} />
            <div style={{ fontSize: "14px", fontWeight: 600, color: "#30a050" }}>
              {filterLevel || filterStatus ? "Aucune alerte avec ces filtres" : "Aucune alerte — tout est calme"}
            </div>
          </div>
        </ChromeInsetCard>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          {filtered.map(a => {
            const lev = LEVEL_COLORS[a.level] || LEVEL_COLORS.informational;
            const st = STATUS_LABELS[a.status] || STATUS_LABELS.new;
            const isExpanded = expandedId === a.id;
            return (
              <ChromeInsetCard key={a.id} style={{ borderLeft: `3px solid ${lev.color}`, padding: "14px 16px", borderRadius: "12px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={() => setExpandedId(isExpanded ? null : a.id)}>
                  <span style={{ fontSize: "10px", fontWeight: 700, padding: "3px 8px", borderRadius: "6px", background: lev.bg, color: lev.color, border: `1px solid ${lev.border}`, textTransform: "uppercase", flexShrink: 0 }}>
                    {a.level === "informational" ? "info" : a.level}
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: "13px", fontWeight: 600, color: "#e8e4e0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.title}</div>
                    <div style={{ fontSize: "11px", color: "#5a534e", display: "flex", gap: "12px", marginTop: "2px" }}>
                      {a.hostname && <span>{a.hostname}</span>}
                      {a.source_ip && <span>{a.source_ip}</span>}
                      {a.username && <span>{a.username}</span>}
                      <span>{new Date(a.matched_at).toLocaleString("fr-FR")}</span>
                    </div>
                  </div>
                  <span style={{ fontSize: "10px", color: st.color, display: "flex", alignItems: "center", gap: "4px" }}>
                    {st.icon} {st.label}
                  </span>
                  <ChevronDown size={14} color="#5a534e" style={{ transform: isExpanded ? "rotate(180deg)" : "none", transition: "0.2s" }} />
                </div>

                {isExpanded && (
                  <div style={{ marginTop: "14px", borderTop: "1px solid rgba(255,255,255,0.04)", paddingTop: "14px" }}>
                    <div style={{ display: "flex", gap: "16px", fontSize: "11px", color: "#5a534e", marginBottom: "12px", flexWrap: "wrap" }}>
                      <span>Règle : <strong style={{ color: "#e8e4e0", fontFamily: "monospace" }}>{a.rule_id}</strong></span>
                      <span>Détecté : <strong style={{ color: "#e8e4e0" }}>{new Date(a.matched_at).toLocaleString("fr-FR")}</strong></span>
                    </div>
                    {a.matched_fields && Object.keys(a.matched_fields).length > 0 && (
                      <div style={{ marginBottom: "12px", padding: "10px 12px", borderRadius: "8px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.04)", fontSize: "11px", fontFamily: "monospace", color: "#9a918a" }}>
                        {Object.entries(a.matched_fields).map(([k, v]) => (
                          <div key={k}><span style={{ color: "#5a534e" }}>{k}:</span> {String(v)}</div>
                        ))}
                      </div>
                    )}
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

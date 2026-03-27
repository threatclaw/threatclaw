"use client";

import React, { useState, useEffect, useCallback } from "react";
import { NeuCard as ChromeInsetCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  Bell, ChevronDown, RefreshCw, CheckCircle2, XCircle,
  Clock, Search, X, AlertTriangle, Shield,
} from "lucide-react";
import { fetchAlerts, fetchAlertsCounts, type Alert, type CountEntry } from "@/lib/tc-api";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";

const LEVEL_COLORS: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "#e84040", bg: "rgba(232,64,64,0.08)", border: "rgba(232,64,64,0.2)" },
  high: { color: "#d07020", bg: "rgba(208,112,32,0.08)", border: "rgba(208,112,32,0.2)" },
  medium: { color: "var(--tc-amber)", bg: "rgba(208,144,32,0.08)", border: "rgba(208,144,32,0.2)" },
  low: { color: "var(--tc-blue)", bg: "rgba(48,128,208,0.08)", border: "rgba(48,128,208,0.2)" },
  informational: { color: "var(--tc-text-muted)", bg: "var(--tc-input)", border: "var(--tc-input)" },
};

const STATUS_LABELS: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  new: { label: "Nouveau", icon: <Bell size={12} />, color: "var(--tc-red)" },
  investigating: { label: "Investigation", icon: <Clock size={12} />, color: "var(--tc-amber)" },
  resolved: { label: "Résolu", icon: <CheckCircle2 size={12} />, color: "var(--tc-green)" },
  false_positive: { label: "Faux positif", icon: <XCircle size={12} />, color: "var(--tc-text-muted)" },
};

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [counts, setCounts] = useState<CountEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterLevel, setFilterLevel] = useState("");
  const [filterStatus, setFilterStatus] = useState("new");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [a, c] = await Promise.all([
        fetchAlerts({ level: filterLevel || undefined, status: filterStatus || undefined, limit: 200 }),
        fetchAlertsCounts(),
      ]);
      setAlerts(a.alerts);
      setCounts(c);
      setError(null);
    } catch {
      setError("Backend non accessible — verifiez que le service tourne");
    }
    setLoading(false);
  }, [filterLevel, filterStatus]);

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  const total = counts.reduce((s, c) => s + c.count, 0);

  const filtered = search
    ? alerts.filter(a => a.title.toLowerCase().includes(search.toLowerCase()) || a.hostname?.toLowerCase().includes(search.toLowerCase()) || a.source_ip?.toLowerCase().includes(search.toLowerCase()))
    : alerts;

  return (
    <div>
      <div style={{ marginBottom: "16px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 800, color: "var(--tc-text)", letterSpacing: "-0.02em", margin: 0 }}>Détections</h1>
        <p style={{ fontSize: "13px", color: "var(--tc-text-muted)", margin: "4px 0 0" }}>
          Vulnérabilités, alertes de sécurité et anomalies comportementales
        </p>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: "4px", marginBottom: "16px" }}>
        <button onClick={() => window.location.href = "/findings"} style={{
          padding: "8px 16px", fontSize: "11px", fontWeight: 700, borderRadius: "var(--tc-radius-sm)",
          cursor: "pointer", fontFamily: "inherit", textTransform: "uppercase", letterSpacing: "0.04em",
          background: "var(--tc-input)", color: "var(--tc-text-muted)", border: "1px solid var(--tc-border)",
        }}>
          Vulnérabilités
        </button>
        <button style={{
          padding: "8px 16px", fontSize: "11px", fontWeight: 700, borderRadius: "var(--tc-radius-sm)",
          cursor: "pointer", fontFamily: "inherit", textTransform: "uppercase", letterSpacing: "0.04em",
          background: "var(--tc-red)", color: "#fff", border: "none",
        }}>
          Alertes de sécurité ({total})
        </button>
      </div>

      {error && <ErrorBanner message={error} onRetry={load} />}

      {/* Level counts */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap" }}>
        {["critical", "high", "medium", "low", "informational"].map(lev => {
          const c = counts.find(c => c.label === lev)?.count || 0;
          const s = LEVEL_COLORS[lev];
          const active = filterLevel === lev;
          return (
            <button key={lev} onClick={() => setFilterLevel(active ? "" : lev)} style={{
              padding: "8px 14px", borderRadius: "var(--tc-radius-md)", border: `1px solid ${active ? s.border : "var(--tc-input)"}`,
              background: active ? s.bg : "var(--tc-surface-alt)", cursor: "pointer",
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
        <div style={{ flex: 1, display: "flex", alignItems: "center", gap: "8px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-md)", padding: "8px 12px" }}>
          <Search size={14} color="var(--tc-text-muted)" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Rechercher par titre, hostname, IP..."
            style={{ flex: 1, background: "none", border: "none", outline: "none", color: "var(--tc-text)", fontSize: "13px", fontFamily: "inherit" }} />
          {search && <button onClick={() => setSearch("")} style={{ background: "none", border: "none", cursor: "pointer" }}><X size={14} color="var(--tc-text-muted)" /></button>}
        </div>
        {["new", "investigating", "resolved"].map(st => {
          const active = filterStatus === st;
          return (
            <button key={st} onClick={() => setFilterStatus(active ? "" : st)} style={{
              padding: "8px 12px", borderRadius: "var(--tc-radius-md)", fontSize: "11px", fontWeight: 600,
              border: `1px solid ${active ? "rgba(208,48,32,0.2)" : "var(--tc-input)"}`,
              background: active ? "rgba(208,48,32,0.06)" : "var(--tc-surface-alt)",
              color: active ? "#d03020" : "var(--tc-text-muted)", cursor: "pointer", fontFamily: "inherit",
            }}>
              {STATUS_LABELS[st]?.label || st}
            </button>
          );
        })}
        <ChromeButton onClick={load} variant="glass"><RefreshCw size={14} /></ChromeButton>
      </div>

      {/* Alerts list */}
      {loading ? (
        <ChromeInsetCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>Chargement...</div></ChromeInsetCard>
      ) : filtered.length === 0 ? (
        <ChromeInsetCard>
          <div style={{ textAlign: "center", padding: "32px" }}>
            <Shield size={24} color="#30a050" style={{ margin: "0 auto 8px" }} />
            <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--tc-green)" }}>
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
              <ChromeInsetCard key={a.id} style={{ padding: "14px 16px", borderRadius: "var(--tc-radius-card)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={() => setExpandedId(isExpanded ? null : a.id)}>
                  <span style={{ fontSize: "10px", fontWeight: 700, padding: "3px 8px", borderRadius: "var(--tc-radius-sm)", background: lev.bg, color: lev.color, border: `1px solid ${lev.border}`, textTransform: "uppercase", flexShrink: 0 }}>
                    {a.level === "informational" ? "info" : a.level}
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--tc-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.title}</div>
                    <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", display: "flex", gap: "12px", marginTop: "2px" }}>
                      {a.hostname && <span>{a.hostname}</span>}
                      {a.source_ip && <span>{a.source_ip}</span>}
                      {a.username && <span>{a.username}</span>}
                      <span>{new Date(a.matched_at).toLocaleString("fr-FR")}</span>
                    </div>
                  </div>
                  <span style={{ fontSize: "10px", color: st.color, display: "flex", alignItems: "center", gap: "4px" }}>
                    {st.icon} {st.label}
                  </span>
                  <ChevronDown size={14} color="var(--tc-text-muted)" style={{ transform: isExpanded ? "rotate(180deg)" : "none", transition: "0.2s" }} />
                </div>

                {isExpanded && (
                  <div style={{ marginTop: "14px", borderTop: "1px solid var(--tc-border-light)", paddingTop: "14px" }}>
                    <div style={{ display: "flex", gap: "16px", fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "12px", flexWrap: "wrap" }}>
                      <span>Règle : <strong style={{ color: "var(--tc-text)", fontFamily: "monospace" }}>{a.rule_id}</strong></span>
                      <span>Détecté : <strong style={{ color: "var(--tc-text)" }}>{new Date(a.matched_at).toLocaleString("fr-FR")}</strong></span>
                    </div>
                    {a.matched_fields && Object.keys(a.matched_fields).length > 0 && (
                      <div style={{ marginBottom: "12px", padding: "10px 12px", borderRadius: "var(--tc-radius-input)", background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)", fontSize: "11px", fontFamily: "monospace", color: "var(--tc-text-sec)" }}>
                        {Object.entries(a.matched_fields).map(([k, v]) => (
                          <div key={k}><span style={{ color: "var(--tc-text-muted)" }}>{k}:</span> {String(v)}</div>
                        ))}
                      </div>
                    )}
                    <div style={{ display: "flex", gap: "6px" }}>
                      {a.status !== "resolved" && (
                        <button className="tc-btn-embossed" onClick={async () => {
                          await fetch(`/api/tc/alerts/${a.id}/status`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: "resolved" }) });
                          load();
                        }} style={{ fontSize: "10px", padding: "6px 12px" }}>
                          <CheckCircle2 size={11} /> Résolu
                        </button>
                      )}
                      {a.status !== "investigating" && a.status !== "resolved" && (
                        <button className="tc-btn-embossed" onClick={async () => {
                          await fetch(`/api/tc/alerts/${a.id}/status`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: "investigating" }) });
                          load();
                        }} style={{ fontSize: "10px", padding: "6px 12px" }}>
                          <Clock size={11} /> En cours
                        </button>
                      )}
                      {a.status !== "false_positive" && (
                        <button className="tc-btn-embossed" onClick={async () => {
                          await fetch(`/api/tc/alerts/${a.id}/status`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: "false_positive" }) });
                          load();
                        }} style={{ fontSize: "10px", padding: "6px 12px" }}>
                          <X size={11} /> Faux positif
                        </button>
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

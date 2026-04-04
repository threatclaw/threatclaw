"use client";
// See ADR-043: Incidents page — synthesized view for RSSI
import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";

const API = "/api/tc/incidents";

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
  proposed_actions: any[];
  mitre_techniques: string[] | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
}

const severityColor: Record<string, string> = {
  CRITICAL: "#ff2020",
  HIGH: "#ff6030",
  MEDIUM: "#e0a020",
  LOW: "#30a050",
  Alert: "#ff6030",
  Digest: "#e0a020",
};

const verdictBadge: Record<string, { color: string; label: string }> = {
  pending: { color: "#888", label: "En cours..." },
  confirmed: { color: "#ff4040", label: "Confirme" },
  false_positive: { color: "#30a050", label: "Faux positif" },
  inconclusive: { color: "#e0a020", label: "Inconclusif" },
  investigating: { color: "#4090ff", label: "Investigation" },
};

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [filter, setFilter] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<number | null>(null);

  const fetchIncidents = useCallback(async () => {
    try {
      const url = filter === "all" ? API : `${API}?status=${filter}`;
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setIncidents(data.incidents || []);
      }
    } catch { /* silent */ }
    setLoading(false);
  }, [filter]);

  useEffect(() => { fetchIncidents(); const t = setInterval(fetchIncidents, 15000); return () => clearInterval(t); }, [fetchIncidents]);

  const handleHitl = async (id: number, response: string) => {
    await fetch(`${API}/${id}/hitl`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ response, responded_by: "dashboard" }),
    });
    fetchIncidents();
  };

  const filters = [
    { key: "all", label: "Tous" },
    { key: "open", label: "Ouverts" },
    { key: "investigating", label: "En cours" },
    { key: "resolved", label: "Resolus" },
    { key: "closed", label: "Fermes" },
  ];

  const cardStyle: React.CSSProperties = {
    background: "var(--tc-surface, #12121a)",
    border: "1px solid var(--tc-border, #2a2a3a)",
    borderRadius: 12,
    padding: "16px 20px",
    marginBottom: 12,
    cursor: "pointer",
    transition: "border-color 0.2s",
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800, letterSpacing: "-0.5px" }}>Incidents</h1>
        <div style={{ display: "flex", gap: 6 }}>
          {filters.map(f => (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              style={{
                padding: "6px 14px", borderRadius: 8, fontSize: 11, fontWeight: 600,
                border: filter === f.key ? "1px solid #d03020" : "1px solid var(--tc-border)",
                background: filter === f.key ? "rgba(208,48,32,0.15)" : "var(--tc-surface)",
                color: filter === f.key ? "#d03020" : "var(--tc-text-sec)",
                cursor: "pointer",
              }}
            >{f.label}</button>
          ))}
        </div>
      </div>

      {loading && <div style={{ color: "var(--tc-text-muted)", textAlign: "center", padding: 40 }}>Chargement...</div>}

      {!loading && incidents.length === 0 && (
        <div style={{ ...cardStyle, textAlign: "center", padding: 40, color: "var(--tc-text-muted)" }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>&#x2714;</div>
          <div style={{ fontSize: 16, fontWeight: 600 }}>Aucun incident</div>
          <div style={{ fontSize: 12, marginTop: 6 }}>Tout est sous controle</div>
        </div>
      )}

      {incidents.map(inc => {
        const isExpanded = expanded === inc.id;
        const badge = verdictBadge[inc.verdict] || verdictBadge.pending;
        const sevColor = severityColor[inc.severity || "MEDIUM"] || "#888";
        const timeAgo = getTimeAgo(inc.created_at);

        return (
          <div
            key={inc.id}
            style={{ ...cardStyle, borderLeftWidth: 3, borderLeftColor: sevColor }}
            onClick={() => setExpanded(isExpanded ? null : inc.id)}
          >
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                  <span style={{ fontSize: 14, fontWeight: 700 }}>#{inc.id}</span>
                  <span style={{ fontSize: 14, fontWeight: 600 }}>{inc.title}</span>
                </div>
                <div style={{ display: "flex", gap: 8, fontSize: 11 }}>
                  <span style={{ padding: "2px 8px", borderRadius: 4, background: `${sevColor}22`, color: sevColor, fontWeight: 600 }}>
                    {inc.severity}
                  </span>
                  <span style={{ padding: "2px 8px", borderRadius: 4, background: `${badge.color}22`, color: badge.color, fontWeight: 600 }}>
                    {badge.label}{inc.confidence ? ` ${Math.round(inc.confidence * 100)}%` : ""}
                  </span>
                  <span style={{ color: "var(--tc-text-muted)" }}>
                    {inc.asset} &middot; {inc.alert_count || 0} alertes &middot; {timeAgo}
                  </span>
                </div>
              </div>
              <div style={{ fontSize: 10, padding: "3px 8px", borderRadius: 6, background: inc.status === "open" ? "rgba(255,64,64,0.15)" : "rgba(48,160,80,0.15)", color: inc.status === "open" ? "#ff4040" : "#30a050", fontWeight: 700, textTransform: "uppercase" }}>
                {inc.status}
              </div>
            </div>

            {/* Expanded detail */}
            {isExpanded && (
              <div style={{ marginTop: 16, paddingTop: 12, borderTop: "1px solid var(--tc-border)" }}>
                {inc.summary && (
                  <div style={{ fontSize: 13, lineHeight: 1.6, color: "var(--tc-text)", marginBottom: 12, whiteSpace: "pre-wrap" }}>
                    {inc.summary}
                  </div>
                )}

                {inc.mitre_techniques && inc.mitre_techniques.length > 0 && (
                  <div style={{ marginBottom: 12 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase" }}>MITRE ATT&CK: </span>
                    {inc.mitre_techniques.map(t => (
                      <span key={t} style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: "rgba(64,144,255,0.15)", color: "#4090ff", marginRight: 4 }}>{t}</span>
                    ))}
                  </div>
                )}

                {/* HITL Actions */}
                {inc.status !== "resolved" && inc.status !== "closed" && (
                  <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleHitl(inc.id, "approve_remediate"); }}
                      style={{ padding: "8px 16px", borderRadius: 8, background: "rgba(208,48,32,0.15)", border: "1px solid rgba(208,48,32,0.3)", color: "#d03020", fontSize: 12, fontWeight: 700, cursor: "pointer" }}
                    >Remedier</button>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleHitl(inc.id, "false_positive"); }}
                      style={{ padding: "8px 16px", borderRadius: 8, background: "rgba(48,160,80,0.15)", border: "1px solid rgba(48,160,80,0.3)", color: "#30a050", fontSize: 12, fontWeight: 700, cursor: "pointer" }}
                    >Faux positif</button>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleHitl(inc.id, "investigate_more"); }}
                      style={{ padding: "8px 16px", borderRadius: 8, background: "rgba(64,144,255,0.15)", border: "1px solid rgba(64,144,255,0.3)", color: "#4090ff", fontSize: 12, fontWeight: 700, cursor: "pointer" }}
                    >Investiguer</button>
                  </div>
                )}

                {inc.hitl_response && (
                  <div style={{ marginTop: 8, fontSize: 11, color: "var(--tc-text-muted)" }}>
                    HITL: {inc.hitl_response} (via {inc.hitl_status})
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function getTimeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "a l'instant";
  if (mins < 60) return `il y a ${mins}min`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `il y a ${hours}h`;
  const days = Math.floor(hours / 24);
  return `il y a ${days}j`;
}

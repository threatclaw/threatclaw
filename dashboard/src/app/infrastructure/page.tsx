"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Network, Search, RefreshCw, Shield, Monitor, Server, Wifi,
  AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, Eye,
  Target, Plus, Trash2,
} from "lucide-react";

// ── Types ──

interface GraphAsset {
  "a.id"?: string;
  "a.mac"?: string;
  "a.hostname"?: string;
  "a.fqdn"?: string;
  "a.ip"?: string;
  "a.os"?: string;
  "a.ou"?: string;
  "a.vlan"?: number;
  "a.criticality"?: string;
  "a.confidence"?: number;
  "a.sources"?: string;
  "a.first_seen"?: string;
  "a.last_seen"?: string;
}

interface AssetStats {
  total_assets: number;
  with_mac: number;
  with_hostname: number;
  coverage: number;
}

interface ManualTarget {
  id: string;
  host: string;
  target_type: string;
  port: number;
}

// ── Main Page ──

export default function AssetsPage() {
  const [assets, setAssets] = useState<GraphAsset[]>([]);
  const [stats, setStats] = useState<AssetStats | null>(null);
  const [targets, setTargets] = useState<ManualTarget[]>([]);
  const [search, setSearch] = useState("");
  const [expandedAsset, setExpandedAsset] = useState<string | null>(null);
  const [tab, setTab] = useState<"discovered" | "manual">("discovered");
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [assetsRes, statsRes, targetsRes] = await Promise.all([
        fetch("/api/tc/graph/assets?limit=200"),
        fetch("/api/tc/graph/assets/stats"),
        fetch("/api/tc/config?key=_targets"),
      ]);
      if (assetsRes.ok) {
        const data = await assetsRes.json();
        setAssets(data.assets || []);
      }
      if (statsRes.ok) setStats(await statsRes.json());
      if (targetsRes.ok) {
        const data = await targetsRes.json();
        // Parse targets from settings
        const tgts = (data.settings || []).map((s: any) => s.value).filter(Boolean);
        setTargets(tgts);
      }
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Filter assets
  const filtered = assets.filter(a => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (a["a.hostname"] || "").toLowerCase().includes(q)
      || (a["a.ip"] || "").toLowerCase().includes(q)
      || (a["a.mac"] || "").toLowerCase().includes(q)
      || (a["a.os"] || "").toLowerCase().includes(q)
      || (a["a.ou"] || "").toLowerCase().includes(q);
  });

  const critColor = (c: string | undefined) => {
    switch (c) {
      case "critical": return "#d03020";
      case "high": return "#d06020";
      case "medium": return "#d09020";
      case "low": return "#30a050";
      default: return "#6a625c";
    }
  };

  const confColor = (c: number | undefined) => {
    if (!c) return "#6a625c";
    if (c >= 0.8) return "#30a050";
    if (c >= 0.5) return "#d09020";
    return "#d03020";
  };

  return (
    <div style={{ padding: "0 24px 40px" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>Assets</h1>
          <p style={{ fontSize: "12px", color: "var(--tc-text-muted)", margin: "4px 0 0" }}>
            {stats ? `${stats.total_assets} assets decouverts · ${stats.with_mac} avec MAC · couverture ${Math.round(stats.coverage * 100)}%` : "Chargement..."}
          </p>
        </div>
        <div style={{ display: "flex", gap: "8px" }}>
          <button onClick={refresh} disabled={loading} style={{
            display: "flex", alignItems: "center", gap: "6px", padding: "8px 16px",
            borderRadius: "var(--tc-radius-input)", border: "1px solid var(--tc-border)",
            background: "var(--tc-surface-alt)", color: "var(--tc-text-muted)",
            fontSize: "11px", fontWeight: 600, cursor: "pointer",
          }}>
            <RefreshCw size={12} /> Actualiser
          </button>
        </div>
      </div>

      {/* Stats bar */}
      {stats && stats.total_assets > 0 && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "10px", marginBottom: "20px" }}>
          {[
            { value: stats.total_assets, label: "Total", color: "#30a0d0" },
            { value: stats.with_mac, label: "Avec MAC", color: "var(--tc-green)" },
            { value: stats.with_hostname, label: "Avec hostname", color: "var(--tc-amber)" },
            { value: `${Math.round(stats.coverage * 100)}%`, label: "Couverture", color: stats.coverage >= 0.7 ? "#30a050" : "#d09020" },
          ].map((s, i) => (
            <div key={i} style={{
              textAlign: "center", padding: "14px",
              background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
              borderRadius: "var(--tc-radius-md)",
            }}>
              <div style={{ fontSize: "24px", fontWeight: 800, color: s.color }}>{s.value}</div>
              <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", textTransform: "uppercase" }}>{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: "flex", gap: "2px", marginBottom: "16px" }}>
        {[
          { key: "discovered" as const, label: `Decouverts (${assets.length})`, icon: Network },
          { key: "manual" as const, label: `Manuels (${targets.length})`, icon: Plus },
        ].map(t => (
          <button key={t.key} onClick={() => setTab(t.key)} style={{
            display: "flex", alignItems: "center", gap: "6px",
            padding: "8px 16px", borderRadius: "var(--tc-radius-input)", fontSize: "11px", fontWeight: 600,
            border: tab === t.key ? "1px solid rgba(208,48,32,0.3)" : "1px solid rgba(255,255,255,0.08)",
            background: tab === t.key ? "rgba(208,48,32,0.08)" : "rgba(255,255,255,0.03)",
            color: tab === t.key ? "var(--tc-red)" : "var(--tc-text-muted)",
            cursor: "pointer",
          }}>
            <t.icon size={12} /> {t.label}
          </button>
        ))}
      </div>

      {/* Search */}
      <div style={{ position: "relative", marginBottom: "16px" }}>
        <Search size={14} style={{ position: "absolute", left: "10px", top: "9px", color: "var(--tc-text-muted)" }} />
        <input
          type="text" value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Rechercher par hostname, IP, MAC, OS..."
          style={{
            width: "100%", padding: "8px 10px 8px 32px", borderRadius: "var(--tc-radius-input)", fontSize: "12px",
            background: "var(--tc-input)", border: "1px solid var(--tc-border)",
            color: "var(--tc-text)", outline: "none",
          }}
        />
      </div>

      {/* Discovered assets */}
      {tab === "discovered" && (
        <div>
          {filtered.length === 0 && !loading && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-muted)" }}>
              <Network size={40} style={{ margin: "0 auto 12px", opacity: 0.3 }} />
              <p>Aucun asset decouvert</p>
              <p style={{ fontSize: "11px" }}>Activez un scan nmap, un connecteur AD ou pfSense dans Skills</p>
            </div>
          )}

          {filtered.map((a, i) => {
            const id = a["a.id"] || a["a.hostname"] || a["a.ip"] || `asset-${i}`;
            const isExpanded = expandedAsset === id;
            const conf = typeof a["a.confidence"] === "number" ? a["a.confidence"] : 0;
            const sources: string[] = (() => {
              try { return JSON.parse(a["a.sources"] || "[]"); } catch { return []; }
            })();

            return (
              <div key={id} style={{
                background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
                borderRadius: "var(--tc-radius-md)", marginBottom: "8px",
                borderLeft: `3px solid ${critColor(a["a.criticality"])}`,
              }}>
                <div
                  onClick={() => setExpandedAsset(isExpanded ? null : id)}
                  style={{
                    display: "flex", alignItems: "center", gap: "12px", padding: "12px 14px",
                    cursor: "pointer", userSelect: "none",
                  }}
                >
                  {isExpanded ? <ChevronDown size={14} color="#6a625c" /> : <ChevronRight size={14} color="#6a625c" />}

                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)" }}>
                        {a["a.hostname"] || a["a.id"] || "unknown"}
                      </span>
                      {a["a.ip"] && (
                        <span style={{ fontSize: "11px", color: "var(--tc-text-muted)", fontFamily: "monospace" }}>
                          {a["a.ip"]}
                        </span>
                      )}
                      <span style={{
                        fontSize: "8px", fontWeight: 700, padding: "2px 6px", borderRadius: "3px",
                        background: `${critColor(a["a.criticality"])}15`,
                        color: critColor(a["a.criticality"]),
                        textTransform: "uppercase",
                      }}>
                        {a["a.criticality"] || "medium"}
                      </span>
                    </div>
                    <div style={{ display: "flex", gap: "8px", marginTop: "3px", fontSize: "10px", color: "var(--tc-text-muted)" }}>
                      {a["a.os"] && <span>{a["a.os"]}</span>}
                      {a["a.ou"] && <span>OU: {a["a.ou"]}</span>}
                      {sources.length > 0 && <span>Sources: {sources.join(", ")}</span>}
                    </div>
                  </div>

                  {/* Confidence bar */}
                  <div style={{ width: "80px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                      <div style={{ flex: 1, height: "4px", borderRadius: "2px", background: "rgba(255,255,255,0.06)" }}>
                        <div style={{ width: `${conf * 100}%`, height: "100%", borderRadius: "2px", background: confColor(conf) }} />
                      </div>
                      <span style={{ fontSize: "10px", color: confColor(conf), fontWeight: 600 }}>
                        {Math.round(conf * 100)}%
                      </span>
                    </div>
                  </div>
                </div>

                {/* Expanded detail */}
                {isExpanded && (
                  <div style={{ padding: "0 14px 14px", borderTop: "1px solid var(--tc-border-light)" }}>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginTop: "10px", fontSize: "11px" }}>
                      {[
                        ["ID", a["a.id"]],
                        ["Hostname", a["a.hostname"]],
                        ["FQDN", a["a.fqdn"]],
                        ["IP", a["a.ip"]],
                        ["MAC", a["a.mac"]],
                        ["OS", a["a.os"]],
                        ["OU", a["a.ou"]],
                        ["VLAN", a["a.vlan"]?.toString()],
                        ["Criticite", a["a.criticality"]],
                        ["Confiance", `${Math.round(conf * 100)}%`],
                        ["Sources", sources.join(", ")],
                        ["Premier vu", a["a.first_seen"]?.split("T")[0]],
                        ["Dernier vu", a["a.last_seen"]?.split("T")[0]],
                      ].filter(([, v]) => v).map(([label, value], j) => (
                        <div key={j}>
                          <span style={{ color: "var(--tc-text-muted)" }}>{label}: </span>
                          <span style={{ color: "var(--tc-text)", fontFamily: label === "MAC" || label === "IP" ? "monospace" : "inherit" }}>
                            {value}
                          </span>
                        </div>
                      ))}
                    </div>

                    {conf < 0.5 && (
                      <div style={{
                        marginTop: "10px", padding: "8px", borderRadius: "var(--tc-radius-sm)",
                        background: "rgba(208,144,32,0.08)", border: "1px solid rgba(208,144,32,0.15)",
                        fontSize: "10px", color: "var(--tc-amber)",
                      }}>
                        <AlertTriangle size={11} style={{ display: "inline", verticalAlign: "middle", marginRight: "4px" }} />
                        Confiance faible — activez des sources supplementaires (AD, pfSense) dans Skills pour enrichir cet asset.
                      </div>
                    )}

                    <div style={{ display: "flex", gap: "8px", marginTop: "10px" }}>
                      <a href={`/intelligence`} style={{
                        display: "flex", alignItems: "center", gap: "4px",
                        padding: "6px 12px", borderRadius: "var(--tc-radius-sm)", fontSize: "10px", fontWeight: 600,
                        background: "var(--tc-red-soft)", border: "1px solid rgba(208,48,32,0.2)",
                        color: "var(--tc-red)", textDecoration: "none",
                      }}>
                        <Target size={11} /> Blast Radius
                      </a>
                      <a href={`/intelligence`} style={{
                        display: "flex", alignItems: "center", gap: "4px",
                        padding: "6px 12px", borderRadius: "var(--tc-radius-sm)", fontSize: "10px", fontWeight: 600,
                        background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
                        color: "var(--tc-text-muted)", textDecoration: "none",
                      }}>
                        <Eye size={11} /> Voir dans le graphe
                      </a>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Manual targets tab */}
      {tab === "manual" && (
        <div>
          {targets.length === 0 && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-muted)" }}>
              Aucune cible manuelle configuree
            </div>
          )}
          {targets.map((t, i) => (
            <div key={i} style={{
              display: "flex", alignItems: "center", gap: "12px",
              padding: "12px 14px", marginBottom: "6px", borderRadius: "var(--tc-radius-md)",
              background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
            }}>
              <Server size={16} color="#6a625c" />
              <div style={{ flex: 1 }}>
                <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)" }}>{t.id || t.host}</span>
                <span style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginLeft: "8px" }}>{t.host}:{t.port}</span>
              </div>
              <span style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>{t.target_type}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

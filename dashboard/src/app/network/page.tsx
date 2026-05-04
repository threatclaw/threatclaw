"use client";

// /network — single pane of glass for the firewall layer.
// Aggregates data already collected by the pf/OPNsense/FortiGate connectors
// (top blocked sources, recent IDS alerts, control-plane events, identity
// anomalies including impossible-travel) — so the data we ingest stops
// being orphaned in the DB.

import React, { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { PageShell } from "@/components/chrome/PageShell";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import {
  Shield,
  AlertTriangle,
  Network as NetworkIcon,
  Activity,
  Eye,
  RefreshCw,
  ChevronRight,
} from "lucide-react";

interface NetworkOverview {
  firewalls: Array<{
    skill_id: string;
    url: string;
    enabled: boolean;
    auto_sync: boolean;
  }>;
  top_blocked_sources: Array<{
    src_ip: string;
    block_count: number;
    distinct_dst: number;
    distinct_ports: number;
    ssh_brute_count: number;
    rdp_brute_count: number;
    smb_brute_count: number;
  }>;
  recent_ids_alerts: Array<{
    tag: string;
    time: string;
    hostname: string;
    snippet: string;
  }>;
  admin_events: Array<{
    tag: string;
    time: string;
    hostname: string;
    snippet: string;
  }>;
  identity_anomalies: Array<{
    anomaly_type: string;
    username: string;
    detail: string;
    severity: string;
    confidence: number;
  }>;
  users_tracked: number;
  since_24h: string;
  since_60m: string;
}

const FW_LABELS: Record<string, string> = {
  "skill-pfsense": "pfSense",
  "skill-opnsense": "OPNsense",
  "skill-fortinet": "FortiGate",
};

function fmtTime(iso: string): string {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toLocaleString("fr-FR", {
      hour: "2-digit",
      minute: "2-digit",
      day: "2-digit",
      month: "2-digit",
    });
  } catch {
    return iso;
  }
}

export default function NetworkPage() {
  const [data, setData] = useState<NetworkOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/api/tc/network/overview", { cache: "no-store" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setData(j);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 60_000);
    return () => clearInterval(id);
  }, [load]);

  // Empty state — no firewall configured at all
  if (!loading && data && data.firewalls.length === 0) {
    return (
      <PageShell title="Réseau" subtitle="Vue unifiée pare-feu">
        <div style={{ padding: "1rem 0" }}>
          <NeuCard>
            <div style={{ padding: "2rem", textAlign: "center" }}>
              <NetworkIcon size={48} style={{ opacity: 0.4, margin: "0 auto 1rem" }} />
              <h3 style={{ marginBottom: "0.5rem" }}>Aucun pare-feu configuré</h3>
              <p style={{ opacity: 0.7, marginBottom: "1.5rem" }}>
                Connecte un pare-feu (pfSense, OPNsense, FortiGate) pour voir
                les sessions VPN, les blocages, les événements admin et les
                anomalies d&apos;identité dans une seule vue.
              </p>
              <Link href="/skills?cat=network">
                <ChromeButton>
                  Aller au catalogue de skills <ChevronRight size={16} />
                </ChromeButton>
              </Link>
            </div>
          </NeuCard>
        </div>
      </PageShell>
    );
  }

  return (
    <PageShell
      title="Réseau"
      subtitle="Vue unifiée pare-feu — sessions VPN, blocages, audit, anomalies"
      right={
        <ChromeButton onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? "tc-spin" : ""} /> Rafraîchir
        </ChromeButton>
      }
    >
      <div style={{ padding: "1rem 0" }}>

        {error && <ErrorBanner message={error} />}

        {/* Card 1 — Pare-feu connectés */}
        <NeuCard>
          <div style={{ padding: "1rem" }}>
            <h2 style={{ fontSize: "1rem", marginBottom: "0.75rem", display: "flex", gap: 6, alignItems: "center" }}>
              <Shield size={16} /> Pare-feu connectés
            </h2>
            {data?.firewalls.map((fw) => (
              <div
                key={fw.skill_id}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  padding: "0.5rem 0",
                  borderBottom: "1px solid rgba(255,255,255,0.05)",
                }}
              >
                <span>
                  <strong>{FW_LABELS[fw.skill_id] || fw.skill_id}</strong>
                  <span style={{ opacity: 0.6, marginLeft: "0.5rem", fontSize: "0.85rem" }}>
                    {fw.url}
                  </span>
                </span>
                <span style={{ fontSize: "0.85rem" }}>
                  {fw.enabled ? "✓ actif" : "○ désactivé"}
                  {fw.auto_sync && <span style={{ marginLeft: "0.5rem", opacity: 0.6 }}>auto-sync</span>}
                </span>
              </div>
            ))}
          </div>
        </NeuCard>

        <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)", gap: "1rem", marginTop: "1rem" }}>
          {/* Card 2 — Top sources bloquées */}
          <NeuCard>
            <div style={{ padding: "1rem" }}>
              <h2 style={{ fontSize: "1rem", marginBottom: "0.75rem", display: "flex", gap: 6, alignItems: "center" }}>
                <AlertTriangle size={16} /> Top sources bloquées (24 h)
              </h2>
              {(data?.top_blocked_sources || []).length === 0 && (
                <p style={{ opacity: 0.6, fontSize: "0.9rem" }}>Aucun blocage détecté ces dernières 24 h.</p>
              )}
              {(data?.top_blocked_sources || []).map((b) => (
                <div
                  key={b.src_ip}
                  style={{
                    padding: "0.5rem 0",
                    borderBottom: "1px solid rgba(255,255,255,0.05)",
                    fontSize: "0.85rem",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ fontFamily: "monospace" }}>{b.src_ip}</span>
                    <span><strong>{b.block_count}</strong> blocs</span>
                  </div>
                  <div style={{ opacity: 0.65, fontSize: "0.78rem", marginTop: "0.2rem" }}>
                    {b.distinct_dst} dst · {b.distinct_ports} ports
                    {b.ssh_brute_count > 0 && ` · SSH ${b.ssh_brute_count}`}
                    {b.rdp_brute_count > 0 && ` · RDP ${b.rdp_brute_count}`}
                    {b.smb_brute_count > 0 && ` · SMB ${b.smb_brute_count}`}
                  </div>
                </div>
              ))}
            </div>
          </NeuCard>

          {/* Card 3 — Anomalies d'identité */}
          <NeuCard>
            <div style={{ padding: "1rem" }}>
              <h2 style={{ fontSize: "1rem", marginBottom: "0.75rem", display: "flex", gap: 6, alignItems: "center" }}>
                <Activity size={16} /> Anomalies d&apos;identité
                <span style={{ marginLeft: "auto", fontSize: "0.78rem", opacity: 0.55 }}>
                  {data?.users_tracked ?? 0} users suivis
                </span>
              </h2>
              {(data?.identity_anomalies || []).length === 0 && (
                <p style={{ opacity: 0.6, fontSize: "0.9rem" }}>Aucune anomalie détectée.</p>
              )}
              {(data?.identity_anomalies || []).map((a, i) => (
                <div
                  key={i}
                  style={{
                    padding: "0.5rem 0",
                    borderBottom: "1px solid rgba(255,255,255,0.05)",
                    fontSize: "0.85rem",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <strong>{a.username}</strong>
                    <span
                      style={{
                        fontSize: "0.7rem",
                        padding: "0.1rem 0.45rem",
                        borderRadius: 4,
                        background:
                          a.severity === "high" || a.severity === "critical"
                            ? "rgba(220,80,80,0.2)"
                            : "rgba(220,180,80,0.2)",
                      }}
                    >
                      {a.severity}
                    </span>
                  </div>
                  <div style={{ opacity: 0.7, fontSize: "0.78rem", marginTop: "0.2rem" }}>
                    {a.anomaly_type.replace(/_/g, " ")} — {a.detail}
                  </div>
                </div>
              ))}
            </div>
          </NeuCard>

          {/* Card 4 — IDS alerts récents */}
          <NeuCard>
            <div style={{ padding: "1rem" }}>
              <h2 style={{ fontSize: "1rem", marginBottom: "0.75rem", display: "flex", gap: 6, alignItems: "center" }}>
                <Eye size={16} /> IDS / IPS récent (60 min)
              </h2>
              {(data?.recent_ids_alerts || []).length === 0 && (
                <p style={{ opacity: 0.6, fontSize: "0.9rem" }}>Aucune alerte IDS dans la dernière heure.</p>
              )}
              {(data?.recent_ids_alerts || []).slice(0, 5).map((a, i) => (
                <div
                  key={i}
                  style={{
                    padding: "0.4rem 0",
                    borderBottom: "1px solid rgba(255,255,255,0.05)",
                    fontSize: "0.78rem",
                    minWidth: 0,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", opacity: 0.7 }}>
                    <span>{a.tag}</span>
                    <span>{fmtTime(a.time)}</span>
                  </div>
                  <div
                    style={{
                      marginTop: "0.15rem",
                      fontSize: "0.72rem",
                      opacity: 0.78,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      minWidth: 0,
                    }}
                    title={a.snippet}
                  >
                    {a.snippet}
                  </div>
                </div>
              ))}
              {(data?.recent_ids_alerts || []).length > 5 && (
                <div style={{ opacity: 0.55, fontSize: "0.72rem", marginTop: "0.4rem" }}>
                  + {(data?.recent_ids_alerts || []).length - 5} autres alertes
                </div>
              )}
            </div>
          </NeuCard>

          {/* Card 5 — Audit firewall récent */}
          <NeuCard>
            <div style={{ padding: "1rem" }}>
              <h2 style={{ fontSize: "1rem", marginBottom: "0.75rem", display: "flex", gap: 6, alignItems: "center" }}>
                <Shield size={16} /> Audit pare-feu récent (60 min)
              </h2>
              {(data?.admin_events || []).length === 0 && (
                <p style={{ opacity: 0.6, fontSize: "0.9rem" }}>Aucun événement admin.</p>
              )}
              {(data?.admin_events || []).slice(0, 5).map((a, i) => (
                <div
                  key={i}
                  style={{
                    padding: "0.4rem 0",
                    borderBottom: "1px solid rgba(255,255,255,0.05)",
                    fontSize: "0.78rem",
                    minWidth: 0,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", opacity: 0.7 }}>
                    <span>{a.tag}</span>
                    <span>{fmtTime(a.time)}</span>
                  </div>
                  <div
                    style={{
                      marginTop: "0.15rem",
                      fontSize: "0.72rem",
                      opacity: 0.78,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      minWidth: 0,
                    }}
                    title={a.snippet}
                  >
                    {a.snippet}
                  </div>
                </div>
              ))}
              {(data?.admin_events || []).length > 5 && (
                <div style={{ opacity: 0.55, fontSize: "0.72rem", marginTop: "0.4rem" }}>
                  + {(data?.admin_events || []).length - 5} autres événements
                </div>
              )}
            </div>
          </NeuCard>
        </div>
      </div>
    </PageShell>
  );
}

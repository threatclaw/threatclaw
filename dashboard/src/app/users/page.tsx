"use client";

import React, { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import { Users, Shield, AlertTriangle, Search, RefreshCw, ChevronRight, Server } from "lucide-react";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { PageShell } from "@/components/chrome/PageShell";

interface UserSummary {
  username: string;
  is_admin: boolean;
  is_service_account: boolean;
  department: string | null;
  last_seen: string | null;
  login_count: number;
  failed_login_count: number;
  linked_assets: number;
}

interface Anomaly {
  anomaly_type: string;
  username: string;
  detail: string;
  severity: string;
  confidence: number;
}

interface UsersResponse {
  users: UserSummary[];
  total: number;
  anomalies: Anomaly[];
}

const SEV_COLORS: Record<string, string> = {
  critical: "var(--tc-red)",
  high: "var(--tc-red)",
  medium: "var(--tc-amber)",
  low: "var(--tc-text-sec)",
};

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("fr-FR", {
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit",
    });
  } catch { return iso; }
}

function SeverityPill({ severity }: { severity: string }) {
  const c = SEV_COLORS[severity.toLowerCase()] ?? "var(--tc-text-muted)";
  return (
    <span style={{
      display: "inline-block", padding: "2px 6px", fontSize: "9px",
      fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em",
      color: c, border: `1px solid ${c}`, borderRadius: "3px",
    }}>{severity}</span>
  );
}

function Tag({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: "inline-block", padding: "2px 6px", fontSize: "9px",
      fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em",
      color, background: "var(--tc-input)", borderRadius: "3px",
    }}>{label}</span>
  );
}

export default function UsersPage() {
  const [data, setData] = useState<UsersResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [filterType, setFilterType] = useState<"all" | "admin" | "service" | "with_anomaly">("all");

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const r = await fetch("/api/tc/users", { signal: AbortSignal.timeout(15000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d: UsersResponse = await r.json();
      setData(d);
    } catch (e: any) {
      setError(e?.message ?? "fetch failed");
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  // Index anomalies by username → max severity + count
  const anomalyByUser = useMemo(() => {
    const m = new Map<string, { count: number; max: string }>();
    const rank = (s: string) => ({ critical: 4, high: 3, medium: 2, low: 1 }[s.toLowerCase()] ?? 0);
    for (const a of data?.anomalies ?? []) {
      const cur = m.get(a.username);
      if (!cur) m.set(a.username, { count: 1, max: a.severity });
      else {
        cur.count += 1;
        if (rank(a.severity) > rank(cur.max)) cur.max = a.severity;
      }
    }
    return m;
  }, [data]);

  const filtered = useMemo(() => {
    const users = data?.users ?? [];
    const qlc = q.toLowerCase();
    return users.filter((u) => {
      if (filterType === "admin" && !u.is_admin) return false;
      if (filterType === "service" && !u.is_service_account) return false;
      if (filterType === "with_anomaly" && !anomalyByUser.has(u.username)) return false;
      if (!qlc) return true;
      return (
        u.username.toLowerCase().includes(qlc) ||
        (u.department ?? "").toLowerCase().includes(qlc)
      );
    });
  }, [data, q, filterType, anomalyByUser]);

  const stats = useMemo(() => {
    const users = data?.users ?? [];
    return {
      total: users.length,
      admins: users.filter((u) => u.is_admin).length,
      service: users.filter((u) => u.is_service_account).length,
      withAnomaly: users.filter((u) => anomalyByUser.has(u.username)).length,
    };
  }, [data, anomalyByUser]);

  const refreshBtn = (
    <button
      onClick={load}
      disabled={loading}
      style={{
        background: "var(--tc-input)", color: "var(--tc-text-sec)", border: "1px solid var(--tc-border)",
        borderRadius: "var(--tc-radius-md)", padding: "6px 12px", fontSize: "10px", fontWeight: 600,
        cursor: loading ? "wait" : "pointer", display: "inline-flex", alignItems: "center", gap: "6px",
        fontFamily: "inherit",
      }}
    >
      <RefreshCw size={11} className={loading ? "spin" : ""} />
      Rafraîchir
    </button>
  );

  return (
    <PageShell
      title={`Utilisateurs · ${stats.total}`}
      subtitle="Comptes observés dans les logs, sur le graphe d'identité et via les connecteurs (M365, AD). Croisement asset × user et anomalies UBA."
      right={refreshBtn}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

        {error && <ErrorBanner message={error} />}

        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px" }}>
          <StatCard label="Total" value={stats.total} />
          <StatCard label="Admins" value={stats.admins} color="var(--tc-red)" />
          <StatCard label="Comptes de service" value={stats.service} />
          <StatCard label="Anomalies UBA" value={stats.withAnomaly} color={stats.withAnomaly ? "var(--tc-red)" : undefined} />
        </div>

        <NeuCard style={{ padding: "12px" }}>
          <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
            <div style={{ position: "relative", flex: "1 1 240px" }}>
              <Search size={11} style={{ position: "absolute", left: "8px", top: "50%", transform: "translateY(-50%)", color: "var(--tc-text-muted)" }} />
              <input
                type="text"
                placeholder="Chercher un utilisateur ou département…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                style={{
                  width: "100%", padding: "6px 8px 6px 24px", fontSize: "11px",
                  background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                  borderRadius: "var(--tc-radius-sm)", color: "var(--tc-text)",
                  fontFamily: "inherit", outline: "none",
                }}
              />
            </div>
            {(["all", "admin", "service", "with_anomaly"] as const).map((k) => (
              <button
                key={k}
                onClick={() => setFilterType(k)}
                style={{
                  padding: "6px 10px", fontSize: "10px", fontWeight: 600, fontFamily: "inherit",
                  background: filterType === k ? "var(--tc-text-sec)" : "var(--tc-input)",
                  color: filterType === k ? "var(--tc-surface)" : "var(--tc-text-sec)",
                  border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
                  cursor: "pointer", textTransform: "uppercase", letterSpacing: "0.08em",
                }}
              >
                {k === "all" ? "Tous" : k === "admin" ? "Admins" : k === "service" ? "Services" : "Anomalies"}
              </button>
            ))}
          </div>
        </NeuCard>

        <NeuCard style={{ padding: 0, overflow: "hidden" }}>
          {loading && !data ? (
            <div style={{ padding: "40px", textAlign: "center", color: "var(--tc-text-muted)", fontSize: "11px" }}>
              Chargement des utilisateurs…
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: "40px", textAlign: "center", color: "var(--tc-text-muted)", fontSize: "11px" }}>
              Aucun utilisateur correspondant.
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
              <thead>
                <tr style={{ background: "var(--tc-input)" }}>
                  <Th>Utilisateur</Th>
                  <Th>Département</Th>
                  <Th>Type</Th>
                  <Th align="right">Logins</Th>
                  <Th align="right">Échecs</Th>
                  <Th align="right">Assets</Th>
                  <Th>Anomalie</Th>
                  <Th>Dernière activité</Th>
                  <Th></Th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((u) => {
                  const anom = anomalyByUser.get(u.username);
                  return (
                    <tr
                      key={u.username}
                      style={{ borderTop: "1px solid var(--tc-border)", cursor: "pointer" }}
                      onClick={() => { window.location.href = `/users/${encodeURIComponent(u.username)}`; }}
                    >
                      <Td>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                          {u.is_admin && <Shield size={10} color="var(--tc-red)" />}
                          <span style={{ fontWeight: 600, color: "var(--tc-text)" }}>{u.username}</span>
                        </div>
                      </Td>
                      <Td>{u.department ?? "—"}</Td>
                      <Td>
                        <div style={{ display: "flex", gap: "4px" }}>
                          {u.is_admin && <Tag label="Admin" color="var(--tc-red)" />}
                          {u.is_service_account && <Tag label="Service" color="var(--tc-text-sec)" />}
                          {!u.is_admin && !u.is_service_account && <Tag label="Humain" color="var(--tc-text-muted)" />}
                        </div>
                      </Td>
                      <Td align="right"><span style={{ fontVariantNumeric: "tabular-nums" }}>{u.login_count}</span></Td>
                      <Td align="right">
                        <span style={{
                          fontVariantNumeric: "tabular-nums",
                          color: u.failed_login_count > 0 ? "var(--tc-red)" : "var(--tc-text-muted)",
                        }}>{u.failed_login_count}</span>
                      </Td>
                      <Td align="right">
                        <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontVariantNumeric: "tabular-nums" }}>
                          <Server size={9} color="var(--tc-text-muted)" />
                          {u.linked_assets}
                        </span>
                      </Td>
                      <Td>
                        {anom ? (
                          <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                            <AlertTriangle size={10} color={SEV_COLORS[anom.max.toLowerCase()] ?? "var(--tc-text-muted)"} />
                            <SeverityPill severity={anom.max} />
                            <span style={{ color: "var(--tc-text-muted)", fontSize: "9px" }}>×{anom.count}</span>
                          </div>
                        ) : "—"}
                      </Td>
                      <Td>{fmtDate(u.last_seen)}</Td>
                      <Td><ChevronRight size={11} color="var(--tc-text-muted)" /></Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </NeuCard>
      </div>
      <style jsx>{`
        .spin { animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </PageShell>
  );
}

function Th({ children, align }: { children?: React.ReactNode; align?: "left" | "right" }) {
  return (
    <th style={{
      padding: "8px 10px", textAlign: align ?? "left",
      fontSize: "9px", fontWeight: 700, textTransform: "uppercase",
      letterSpacing: "0.12em", color: "var(--tc-text-muted)",
    }}>{children}</th>
  );
}

function Td({ children, align }: { children?: React.ReactNode; align?: "left" | "right" }) {
  return (
    <td style={{
      padding: "10px", textAlign: align ?? "left",
      color: "var(--tc-text-sec)", verticalAlign: "middle",
    }}>{children}</td>
  );
}

function StatCard({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <NeuCard style={{ padding: "14px" }}>
      <div style={{ fontSize: "9px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.14em", marginBottom: "6px" }}>
        {label}
      </div>
      <div style={{
        fontSize: "22px", fontWeight: 800, color: color ?? "var(--tc-text)",
        fontVariantNumeric: "tabular-nums",
      }}>{value}</div>
    </NeuCard>
  );
}

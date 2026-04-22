"use client";

// Experimental dashboard home — playground only.
// Reach by typing /dash-test in the URL.
//
// Wiring rule: this page re-uses the real /api/tc/* endpoints so the
// data is the same as the production dashboard. No mocks, no parallel
// backend. What differs is only the UX layout.

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Shield,
  Bell,
  MessageSquare,
  Radio,
  BrainCircuit,
  Gavel,
  Activity,
  Settings,
  AlertTriangle,
  Clock,
  ShieldCheck,
  Target,
  ArrowLeft,
} from "lucide-react";

type Incident = {
  id: number;
  severity: string | null;
  verdict: string;
  status: string;
  title?: string;
  asset?: string;
  created_at?: string;
};

type AssetScore = { asset: string; score: number };
type Situation = { global_score?: number; assets?: AssetScore[] };

function isSevere(s: string | null | undefined) {
  const x = (s ?? "").toUpperCase();
  return x === "HIGH" || x === "CRITICAL";
}

export default function DashTest() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [situation, setSituation] = useState<Situation | null>(null);
  const [alertsTotal, setAlertsTotal] = useState<number>(0);

  useEffect(() => {
    let mounted = true;
    void (async () => {
      try {
        const r = await fetch("/api/tc/incidents?limit=500");
        const d = await r.json();
        if (mounted) setIncidents(d?.incidents ?? []);
      } catch {
        /* */
      }
    })();
    void (async () => {
      try {
        const r = await fetch("/api/tc/intelligence/situation");
        const d = await r.json();
        if (mounted) setSituation(d);
      } catch {
        /* */
      }
    })();
    void (async () => {
      try {
        const r = await fetch("/api/tc/alerts/counts");
        const d = await r.json();
        const total = (d?.counts ?? []).reduce((a: number, c: { count: number }) => a + c.count, 0);
        if (mounted) setAlertsTotal(total);
      } catch {
        /* */
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  // Derive the same signals we show on the real home — pending triage,
  // confirmed HIGH+, top risk asset, noise ratio.
  const pending = incidents.filter((i) => i.verdict === "pending");
  const pendingHigh = pending.filter((i) => isSevere(i.severity));
  const confirmed = incidents.filter((i) => i.verdict === "confirmed");
  const confirmedHigh = confirmed.filter((i) => isSevere(i.severity));
  const triaged = pending.length + confirmed.length;
  const noisePct = alertsTotal > 0 ? (1 - triaged / alertsTotal) * 100 : null;
  const topAsset = (situation?.assets ?? []).slice().sort((a, b) => (b.score ?? 0) - (a.score ?? 0))[0];

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "220px 1fr",
        minHeight: "calc(100vh - 44px)",
      }}
    >
      {/* ═══ SIDEBAR ═══ */}
      <aside
        style={{
          borderRight: "1px solid var(--tc-border)",
          background: "var(--tc-surface-alt, var(--tc-surface))",
          padding: "20px 14px",
          display: "flex",
          flexDirection: "column",
          gap: "6px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px", padding: "6px 8px 20px" }}>
          <img src="/logo.png" alt="ThreatClaw" width={28} height={28} style={{ borderRadius: "5px" }} />
          <span style={{ fontSize: "14px", fontWeight: 800, letterSpacing: "0.12em" }}>
            <span style={{ color: "var(--tc-text)" }}>THREAT</span>
            <span style={{ color: "#d03020" }}>CLAW</span>
          </span>
        </div>

        <SideLink href="/dash-test" icon={Shield} label="Overview" active />
        <SideLink href="/incidents" icon={Bell} label="Incidents" />
        <SideLink href="/chat" icon={MessageSquare} label="Chat" />
        <SideLink href="/sources" icon={Radio} label="Sources" />

        <SideSection label="Analytics" />
        <SideLink href="/intelligence" icon={BrainCircuit} label="Intelligence" />
        <SideLink href="/governance" icon={Gavel} label="Governance" />
        <SideLink href="/exports" icon={Activity} label="Reports" />

        <SideSection label="System" />
        <SideLink href="/setup" icon={Settings} label="Config" />

        <div style={{ marginTop: "auto", paddingTop: "20px" }}>
          <Link
            href="/"
            style={{
              fontSize: "10px",
              color: "var(--tc-text-muted)",
              textDecoration: "none",
              display: "flex",
              alignItems: "center",
              gap: "6px",
            }}
          >
            <ArrowLeft size={11} /> back to current dashboard
          </Link>
        </div>
      </aside>

      {/* ═══ MAIN ═══ */}
      <main style={{ padding: "24px 32px", overflow: "auto" }}>
        {/* Top banner — make it obvious this is the sandbox */}
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "6px",
            padding: "4px 10px",
            background: "rgba(208,144,32,0.15)",
            border: "0.5px solid rgba(208,144,32,0.4)",
            borderRadius: "20px",
            fontSize: "10px",
            fontWeight: 700,
            color: "#d09020",
            textTransform: "uppercase",
            letterSpacing: "0.05em",
            marginBottom: "24px",
          }}
        >
          Experimental UI · /dash-test
        </div>

        <h1 style={{ fontSize: "24px", fontWeight: 700, margin: "0 0 4px 0", color: "var(--tc-text)" }}>
          Bonjour RSSI
        </h1>
        <div style={{ fontSize: "13px", color: "var(--tc-text-muted)", marginBottom: "28px" }}>
          {triaged > 0
            ? `${pending.length} incidents à trier · ${confirmedHigh.length} menaces confirmées HIGH+ · ${noisePct?.toFixed(2)}% de bruit filtré`
            : "Aucun incident pour l'instant — la prochaine cycle IE arrive dans < 5 min"}
        </div>

        {/* Row of KPI cards — more spacious than the current home */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
            gap: "12px",
            marginBottom: "32px",
          }}
        >
          <KpiCard
            icon={<Clock size={16} color="#d09020" />}
            label="À trier"
            value={pending.length}
            accent={pendingHigh.length > 0 ? "#d03020" : "#d09020"}
            hint={pendingHigh.length > 0 ? `dont ${pendingHigh.length} HIGH+` : "rien d'urgent"}
          />
          <KpiCard
            icon={<AlertTriangle size={16} color="#d03020" />}
            label="Menaces confirmées HIGH+"
            value={confirmedHigh.length}
            accent="#d03020"
            hint={`sur ${confirmed.length} confirmés`}
          />
          <KpiCard
            icon={<Target size={16} color="#9060d0" />}
            label="Asset le plus à risque"
            value={topAsset ? topAsset.asset : "—"}
            hint={topAsset ? `score ${Math.max(0, 100 - Math.round(topAsset.score))}/100` : "aucun"}
          />
          <KpiCard
            icon={<ShieldCheck size={16} color="#30a050" />}
            label="Bruit écarté"
            value={noisePct === null ? "—" : noisePct >= 99.99 ? ">99.99%" : `${noisePct.toFixed(2)}%`}
            accent="#30a050"
            hint={`${triaged} incidents · ${alertsTotal.toLocaleString("fr")} alertes brutes`}
          />
        </div>

        {/* Recent incidents — compact table */}
        <h2 style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", margin: "0 0 12px 0", textTransform: "uppercase", letterSpacing: "0.05em" }}>
          Incidents récents
        </h2>
        <div style={{ border: "1px solid var(--tc-border)", borderRadius: "10px", overflow: "hidden", background: "var(--tc-surface)" }}>
          {incidents.length === 0 ? (
            <div style={{ padding: "40px", textAlign: "center", color: "var(--tc-text-muted)", fontSize: "12px" }}>
              Aucun incident — le cycle IE tourne toutes les 5 minutes
            </div>
          ) : (
            incidents.slice(0, 10).map((i, idx) => (
              <div
                key={i.id}
                style={{
                  display: "grid",
                  gridTemplateColumns: "auto 1fr auto auto auto",
                  gap: "12px",
                  alignItems: "center",
                  padding: "10px 16px",
                  borderTop: idx === 0 ? "none" : "0.5px solid var(--tc-border)",
                  fontSize: "12px",
                }}
              >
                <SeverityDot severity={i.severity} />
                <div style={{ color: "var(--tc-text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {i.title || i.asset || `Incident #${i.id}`}
                </div>
                <VerdictChip verdict={i.verdict} />
                <span style={{ color: "var(--tc-text-muted)", fontSize: "10px" }}>
                  {i.created_at ? new Date(i.created_at).toLocaleString("fr") : ""}
                </span>
                <Link
                  href={`/incidents?id=${i.id}`}
                  style={{ color: "var(--tc-red)", fontSize: "10px", textDecoration: "none", fontWeight: 600 }}
                >
                  ouvrir →
                </Link>
              </div>
            ))
          )}
        </div>
      </main>
    </div>
  );
}

// ─── Shared mini-components (local to the experimental layout) ───────────

function SideLink({
  href,
  icon: Icon,
  label,
  active,
}: {
  href: string;
  icon: typeof Shield;
  label: string;
  active?: boolean;
}) {
  return (
    <Link
      href={href}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "10px",
        padding: "8px 10px",
        borderRadius: "8px",
        textDecoration: "none",
        color: active ? "var(--tc-red)" : "var(--tc-text-sec)",
        background: active ? "var(--tc-red-soft)" : "transparent",
        fontSize: "12px",
        fontWeight: active ? 700 : 500,
        transition: "background 120ms",
      }}
    >
      <Icon size={14} />
      {label}
    </Link>
  );
}

function SideSection({ label }: { label: string }) {
  return (
    <div
      style={{
        fontSize: "9px",
        fontWeight: 700,
        color: "var(--tc-text-muted)",
        textTransform: "uppercase",
        letterSpacing: "0.08em",
        padding: "16px 10px 4px",
      }}
    >
      {label}
    </div>
  );
}

function KpiCard({
  icon,
  label,
  value,
  accent,
  hint,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  accent?: string;
  hint?: string;
}) {
  return (
    <div
      style={{
        padding: "14px 16px",
        borderRadius: "10px",
        border: "1px solid var(--tc-border)",
        background: "var(--tc-surface)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "10px", color: "var(--tc-text-sec)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>
        {icon}
        {label}
      </div>
      <div style={{ fontSize: "24px", fontWeight: 800, color: accent ?? "var(--tc-text)", lineHeight: 1 }}>
        {value}
      </div>
      {hint && <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "6px" }}>{hint}</div>}
    </div>
  );
}

function SeverityDot({ severity }: { severity: string | null }) {
  const sev = (severity ?? "").toUpperCase();
  const color =
    sev === "CRITICAL" ? "#d03020" : sev === "HIGH" ? "#d09020" : sev === "MEDIUM" ? "#3080d0" : "#30a050";
  return (
    <div
      style={{ width: "8px", height: "8px", borderRadius: "50%", background: color, flexShrink: 0 }}
      title={sev || "UNKNOWN"}
    />
  );
}

function VerdictChip({ verdict }: { verdict: string }) {
  const map: Record<string, { bg: string; fg: string; label: string }> = {
    pending: { bg: "rgba(208,144,32,0.15)", fg: "#d09020", label: "à trier" },
    confirmed: { bg: "rgba(208,48,32,0.15)", fg: "#d03020", label: "confirmé" },
    false_positive: { bg: "rgba(48,160,80,0.15)", fg: "#30a050", label: "FP" },
    inconclusive: { bg: "rgba(255,255,255,0.06)", fg: "var(--tc-text-muted)", label: "incertain" },
  };
  const v = map[verdict] ?? map.pending;
  return (
    <span
      style={{
        padding: "2px 8px",
        borderRadius: "10px",
        background: v.bg,
        color: v.fg,
        fontSize: "10px",
        fontWeight: 700,
        letterSpacing: "0.02em",
      }}
    >
      {v.label}
    </span>
  );
}

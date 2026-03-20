"use client";

import React from "react";
import { useMetrics, useFindings, useAlerts, useFindingsCounts, useHealth } from "@/lib/use-tc-data";
import ScoreGauge from "@/components/ScoreGauge";
import BarItem from "@/components/BarItem";
import StatCard from "@/components/StatCard";
import AlertItem from "@/components/AlertItem";

function severityToColor(s: string): string {
  switch (s) {
    case "critical": return "var(--accent-danger)";
    case "high": return "var(--accent-warning)";
    case "medium": return "var(--text-secondary)";
    default: return "var(--text-muted)";
  }
}

function levelToSeverity(l: string): "critical" | "high" | "medium" | "info" {
  switch (l) {
    case "critical": return "critical";
    case "high": return "high";
    case "medium": return "medium";
    default: return "info";
  }
}

function timeAgo(dateStr: string): string {
  try {
    const d = new Date(dateStr);
    const now = new Date();
    const diff = Math.floor((now.getTime() - d.getTime()) / 1000);
    if (diff < 60) return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff / 60)}min`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
    return `${Math.floor(diff / 86400)}j`;
  } catch {
    return dateStr;
  }
}

export function ScoreWidget() {
  const { data: m } = useMetrics();
  const score = Math.round(m.security_score) || calcScore(m);
  return <ScoreGauge score={score} trend={score > 0 ? `${m.findings_critical} critique(s)` : "Aucune donnée"} />;
}

function calcScore(m: { findings_critical: number; findings_high: number; findings_medium: number }): number {
  // Simple score: start at 100, subtract per finding
  const penalty = m.findings_critical * 10 + m.findings_high * 5 + m.findings_medium * 2;
  return Math.max(0, Math.min(100, 100 - penalty));
}

export function PillarsWidget() {
  const { data: m } = useMetrics();
  const vulnScore = Math.max(0, 100 - (m.findings_critical * 15 + m.findings_high * 8 + m.findings_medium * 3));
  const cloudScore = Math.round(m.cloud_score) || 0;
  const darkwebScore = m.darkweb_leaks === 0 ? 100 : Math.max(0, 100 - m.darkweb_leaks * 20);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px" }}>
      <BarItem label="Vuln." value={vulnScore} color={vulnScore < 50 ? "var(--accent-danger)" : vulnScore < 75 ? "var(--accent-warning)" : "var(--accent-ok)"} />
      <BarItem label="Cloud" value={cloudScore} color={cloudScore < 50 ? "var(--accent-danger)" : cloudScore < 75 ? "var(--accent-warning)" : "var(--accent-ok)"} />
      <BarItem label="Alertes" value={Math.max(0, 100 - m.alerts_new * 5)} color={m.alerts_new > 5 ? "var(--accent-danger)" : "var(--accent-ok)"} />
      <BarItem label="Dark web" value={darkwebScore} color={darkwebScore < 50 ? "var(--accent-danger)" : "var(--accent-ok)"} />
    </div>
  );
}

export function StatsWidget() {
  const { data: m } = useMetrics();
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px" }}>
      <StatCard value={m.findings_critical} label="Critiques" deltaColor={m.findings_critical > 0 ? "danger" : "ok"} />
      <StatCard value={m.alerts_new} label="Alertes" delta={`${m.alerts_total} total`} deltaColor={m.alerts_new > 0 ? "danger" : "ok"} />
      <StatCard value={m.cloud_score > 0 ? `${Math.round(m.cloud_score)}%` : "—"} label="Cloud" deltaColor="ok" />
      <StatCard value={m.darkweb_leaks} label="Dark web" delta={m.darkweb_leaks === 0 ? "Aucun leak" : ""} deltaColor={m.darkweb_leaks === 0 ? "ok" : "danger"} />
    </div>
  );
}

export function AlertsWidget() {
  const { data: alerts } = useAlerts({ limit: 5 });

  if (alerts.length === 0) {
    return (
      <div style={{ textAlign: "center", padding: "12px" }}>
        <div className="status-dot" style={{ width: 10, height: 10, margin: "0 auto 6px" }} />
        <div style={{ fontSize: "10px", color: "var(--accent-ok)", fontWeight: 700 }}>Aucune alerte</div>
        <div style={{ fontSize: "8px", color: "var(--text-muted)", marginTop: "2px" }}>Système opérationnel</div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
      {alerts.map((a) => (
        <AlertItem
          key={a.id}
          severity={levelToSeverity(a.level)}
          title={a.title}
          meta={[a.hostname, a.source_ip, timeAgo(a.matched_at)].filter(Boolean).join(" · ")}
          actionLabel="Voir"
          onAction={() => {}}
        />
      ))}
    </div>
  );
}

export function VulnsWidget() {
  const { data: counts } = useFindingsCounts();

  if (counts.length === 0) {
    return (
      <div style={{ textAlign: "center", padding: "12px" }}>
        <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>Aucune vulnérabilité détectée</div>
        <div style={{ fontSize: "8px", color: "var(--text-muted)", marginTop: "4px" }}>Lancez un scan pour commencer</div>
      </div>
    );
  }

  const max = Math.max(...counts.map((c) => c.count), 1);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
      {counts.map((c) => (
        <div key={c.label}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span className="label-caps">{c.label}</span>
            <span style={{ fontSize: "14px", fontWeight: 800, color: severityToColor(c.label) }}>{c.count}</span>
          </div>
          <div className="bar-track">
            <div className="bar-fill" style={{ width: `${(c.count / max) * 100}%`, background: severityToColor(c.label) }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export function FindingsWidget() {
  const { data: findings } = useFindings({ limit: 5 });

  if (findings.length === 0) {
    return (
      <div style={{ textAlign: "center", padding: "12px" }}>
        <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>Aucun finding</div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
      {findings.map((f) => (
        <AlertItem
          key={f.id}
          severity={levelToSeverity(f.severity)}
          title={f.title}
          meta={[f.asset, f.source, f.skill_id].filter(Boolean).join(" · ")}
        />
      ))}
    </div>
  );
}

export function HealthWidget() {
  const { data: h } = useHealth();
  return (
    <div style={{ textAlign: "center" }}>
      <div className={`status-dot ${h.database ? "" : "danger"}`} style={{ width: 12, height: 12, margin: "0 auto 6px", background: h.database ? "var(--accent-ok)" : "var(--accent-danger)" }} />
      <div style={{ fontSize: "11px", fontWeight: 700, color: h.database ? "var(--accent-ok)" : "var(--accent-danger)" }}>
        {h.status === "ok" ? "Opérationnel" : "Dégradé"}
      </div>
      <div style={{ fontSize: "8px", color: "var(--text-muted)", marginTop: "2px" }}>
        v{h.version} · {h.llm}
      </div>
    </div>
  );
}

export function CloudWidget() {
  const { data: m } = useMetrics();
  const score = Math.round(m.cloud_score);
  return (
    <div style={{ textAlign: "center" }}>
      <div className="metric-val">{score > 0 ? `${score}%` : "—"}</div>
      <div className="label-caps" style={{ marginTop: "2px" }}>Posture Cloud</div>
      <div style={{ fontSize: "9px", color: score > 0 ? "var(--accent-ok)" : "var(--text-muted)", marginTop: "4px" }}>
        {score > 0 ? "Dernier audit actif" : "Pas encore audité"}
      </div>
    </div>
  );
}

export function DarkwebWidget() {
  const { data: m } = useMetrics();
  return (
    <div style={{ textAlign: "center" }}>
      <div className="status-dot" style={{ width: 12, height: 12, margin: "0 auto 6px", background: m.darkweb_leaks === 0 ? "var(--accent-ok)" : "var(--accent-danger)" }} />
      <div style={{ fontSize: "11px", fontWeight: 700, color: m.darkweb_leaks === 0 ? "var(--accent-ok)" : "var(--accent-danger)" }}>
        {m.darkweb_leaks === 0 ? "Aucun leak" : `${m.darkweb_leaks} leak(s)`}
      </div>
      <div style={{ fontSize: "8px", color: "var(--text-muted)", marginTop: "2px" }}>Surveillance active</div>
    </div>
  );
}

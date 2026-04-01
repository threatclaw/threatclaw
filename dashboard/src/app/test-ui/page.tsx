"use client";

import React, { useEffect, useState } from "react";
import { Shield, Brain, Database, AlertTriangle, Radio, Cpu, Eye, Clock, ChevronRight, BarChart3 } from "lucide-react";

// ── Types ──
interface HealthData {
  status: string; version: string; database: boolean; llm: string; disk_free: string;
  ml?: { alive: boolean; model_trained: boolean; data_days: number; timestamp?: string };
}
interface Finding { id: number; title: string; severity: string; status: string; asset?: string; source?: string; detected_at: string; }

// ── Card ──
function Card({ children, style, gradient }: { children: React.ReactNode; style?: React.CSSProperties; gradient?: string }) {
  return (
    <div style={{
      background: gradient || "linear-gradient(145deg, #1e1e24 0%, #18181e 100%)",
      border: "1px solid rgba(255,255,255,0.08)",
      borderRadius: 16, padding: "20px", position: "relative", overflow: "hidden", ...style,
    }}>{children}</div>
  );
}

function Label({ children, icon }: { children: React.ReactNode; icon?: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
      {icon}
      <span style={{ fontSize: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.1em", color: "#6B7280" }}>{children}</span>
    </div>
  );
}

function StatusDot({ ok }: { ok: boolean }) {
  const c = ok ? "#30a050" : "#d03020";
  return <span style={{ width: 7, height: 7, borderRadius: "50%", background: c, display: "inline-block", boxShadow: `0 0 6px ${c}` }} />;
}

// ── KPI Card ──
function KpiCard({ label, value, unit, icon, trend, color }: { label: string; value: string; unit?: string; icon: React.ReactNode; trend?: string; color?: string }) {
  return (
    <Card>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <Label icon={icon}>{label}</Label>
        {trend && <span style={{ fontSize: 10, fontWeight: 600, color: trend.startsWith("+") ? "#d03020" : "#30a050", background: trend.startsWith("+") ? "rgba(208,48,32,0.1)" : "rgba(48,160,80,0.1)", padding: "2px 8px", borderRadius: 6 }}>{trend}</span>}
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 4, marginTop: 10 }}>
        <span style={{ fontSize: 36, fontWeight: 900, color: color || "#e8e4e0", letterSpacing: -1 }}>{value}</span>
        {unit && <span style={{ fontSize: 13, color: "#6B7280" }}>{unit}</span>}
      </div>
    </Card>
  );
}

// ── Pipeline Flow ──
function PipelineFlow({ engineOk, aiOk, findings }: { engineOk: boolean; aiOk: boolean; findings: number }) {
  const stages = [
    { label: "Wazuh", active: true },
    { label: "Suricata", active: true },
    { label: "Fluent-Bit", active: true },
    { label: "Nuclei", active: false },
    { label: "Connectors", active: true },
  ];
  const startX = 80; const ieX = 250; const reactX = 400; const verdictX = 540; const centerY = 130;

  return (
    <svg width="100%" height="260" viewBox="0 0 600 260" style={{ overflow: "visible" }}>
      <defs>
        <linearGradient id="pA" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="#d03020" stopOpacity="0.7" /><stop offset="100%" stopColor="#d03020" stopOpacity="0.2" /></linearGradient>
        <linearGradient id="pI" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="#3a3a3a" stopOpacity="0.3" /><stop offset="100%" stopColor="#2a2a2a" stopOpacity="0.1" /></linearGradient>
      </defs>
      {stages.map((s, i) => {
        const y = 40 + i * 45;
        return (
          <g key={i}>
            <path d={`M${startX},${y} C${startX + 60},${y} ${ieX - 60},${centerY} ${ieX},${centerY}`} fill="none" stroke={s.active ? "url(#pA)" : "url(#pI)"} strokeWidth={s.active ? 3 : 1.5} strokeLinecap="round" opacity={s.active ? 1 : 0.3} />
            {s.active && <circle r={2.5} fill="#d03020" opacity={0.8}><animateMotion dur="2s" repeatCount="indefinite" path={`M${startX},${y} C${startX + 60},${y} ${ieX - 60},${centerY} ${ieX},${centerY}`} /></circle>}
            <text x={startX - 8} y={y + 4} fill={s.active ? "#d03020" : "#3a3a3a"} fontSize="9" fontWeight="600" textAnchor="end">{s.label}</text>
          </g>
        );
      })}
      <path d={`M${ieX + 30},${centerY} L${reactX - 30},${centerY}`} fill="none" stroke={engineOk ? "#d03020" : "#3a3a3a"} strokeWidth={3} strokeLinecap="round" opacity={0.6} />
      {engineOk && <circle r={3} fill="#d03020" opacity={0.9}><animateMotion dur="1.5s" repeatCount="indefinite" path={`M${ieX + 30},${centerY} L${reactX - 30},${centerY}`} /></circle>}
      <path d={`M${reactX + 30},${centerY} L${verdictX - 30},${centerY}`} fill="none" stroke={aiOk ? "#d03020" : "#3a3a3a"} strokeWidth={3} strokeLinecap="round" opacity={0.6} />
      {aiOk && <circle r={3} fill="#30a050" opacity={0.9}><animateMotion dur="1.8s" repeatCount="indefinite" path={`M${reactX + 30},${centerY} L${verdictX - 30},${centerY}`} /></circle>}
      {[{ x: ieX, l: "IE", s: "Intelligence", a: engineOk, c: "#d03020" }, { x: reactX, l: "AI", s: "Investigation", a: aiOk, c: "#d03020" }, { x: verdictX, l: "OUT", s: "Verdict", a: engineOk, c: "#30a050" }].map(n => (
        <g key={n.l}>
          <circle cx={n.x} cy={centerY} r={26} fill="#1a1a20" stroke={n.a ? n.c : "#3a3a3a"} strokeWidth={2} />
          {n.a && <circle cx={n.x} cy={centerY} r={34} fill="none" stroke={n.c} strokeWidth={0.5} opacity={0.3} />}
          <text x={n.x} y={centerY + 1} fill={n.a ? "#fff" : "#4a4a4a"} fontSize="11" fontWeight="800" textAnchor="middle" dominantBaseline="middle">{n.l}</text>
          <text x={n.x} y={centerY + 42} fill="#6B7280" fontSize="9" fontWeight="600" textAnchor="middle">{n.s}</text>
        </g>
      ))}
      <rect x={verdictX - 20} y={centerY - 55} width={40} height={20} rx={6} fill="rgba(208,48,32,0.12)" stroke="rgba(208,48,32,0.3)" strokeWidth={0.5} />
      <text x={verdictX} y={centerY - 41} fill="#d03020" fontSize="11" fontWeight="800" textAnchor="middle">{findings}</text>
    </svg>
  );
}

// ── Service Hub ──
function ServiceHub({ services }: { services: { id: string; label: string; ok: boolean; detail: string; angle: number }[] }) {
  const size = 280; const center = size / 2; const nodeR = 110;
  return (
    <div style={{ position: "relative", width: size, height: size, margin: "0 auto" }}>
      <svg width={size} height={size}>
        <defs><radialGradient id="hG"><stop offset="0%" stopColor="#d03020" stopOpacity="0.15" /><stop offset="100%" stopColor="#d03020" stopOpacity="0" /></radialGradient></defs>
        {services.map(s => { const rad = (s.angle * Math.PI) / 180; const x = center + nodeR * Math.cos(rad); const y = center + nodeR * Math.sin(rad); const c = s.ok ? "#30a050" : "#d03020"; return (
          <g key={s.id}><line x1={center} y1={center} x2={x} y2={y} stroke={c} strokeWidth={1.5} opacity={0.5} strokeDasharray={s.ok ? "none" : "3,3"} />{s.ok && <circle r={2} fill={c} opacity={0.8}><animateMotion dur="2.5s" repeatCount="indefinite" path={`M${center},${center} L${x},${y}`} /></circle>}</g>
        ); })}
        <circle cx={center} cy={center} r={28} fill="url(#hG)" /><circle cx={center} cy={center} r={24} fill="#1a1a20" stroke="#d03020" strokeWidth={2} />
        <text x={center} y={center + 1} fill="#d03020" fontSize="12" fontWeight="900" textAnchor="middle" dominantBaseline="middle">TC</text>
      </svg>
      {services.map(s => { const rad = (s.angle * Math.PI) / 180; const x = center + nodeR * Math.cos(rad) - 36; const y = center + nodeR * Math.sin(rad) - 16; const c = s.ok ? "#30a050" : "#d03020"; return (
        <div key={s.id} style={{ position: "absolute", left: x, top: y, width: 72, padding: "4px 6px", background: s.ok ? "rgba(48,160,80,0.06)" : "rgba(208,48,32,0.06)", border: `1px solid ${c}22`, borderRadius: 8, textAlign: "center" }}>
          <div style={{ fontSize: 8, fontWeight: 700, color: c, textTransform: "uppercase" }}>{s.label}</div>
          <div style={{ fontSize: 7, color: "#6B7280", marginTop: 1 }}>{s.detail}</div>
        </div>
      ); })}
    </div>
  );
}

// ── Severity Bars ──
function SeverityBars({ counts }: { counts: { critical: number; high: number; medium: number; low: number } }) {
  const max = Math.max(counts.critical, counts.high, counts.medium, counts.low, 1);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {[{ l: "CRITICAL", c: counts.critical, color: "#d03020" }, { l: "HIGH", c: counts.high, color: "#e06030" }, { l: "MEDIUM", c: counts.medium, color: "#d09020" }, { l: "LOW", c: counts.low, color: "#6B7280" }].map(b => (
        <div key={b.l}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
            <span style={{ fontSize: 9, fontWeight: 700, color: b.color, letterSpacing: "0.05em" }}>{b.l}</span>
            <span style={{ fontSize: 12, fontWeight: 800, color: "#fff" }}>{b.c}</span>
          </div>
          <div style={{ height: 6, background: "rgba(255,255,255,0.04)", borderRadius: 3, overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${(b.c / max) * 100}%`, background: `linear-gradient(90deg, ${b.color}, ${b.color}88)`, borderRadius: 3, transition: "width 0.8s ease" }} />
          </div>
        </div>
      ))}
    </div>
  );
}

// ── ML Gauge ──
function MlGauge({ days, trained }: { days: number; trained: boolean }) {
  const target = 14; const pct = Math.min(100, (days / target) * 100);
  const radius = 60; const circ = Math.PI * radius; const prog = (pct / 100) * circ;
  const color = trained ? "#30a050" : "#d09020";
  return (
    <div style={{ position: "relative", width: 160, height: 100, margin: "0 auto" }}>
      <svg width="160" height="100" viewBox="0 0 160 100">
        <defs><linearGradient id="mG" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="#3a3a3a" /><stop offset="60%" stopColor={color} /><stop offset="100%" stopColor={color} /></linearGradient></defs>
        <path d={`M ${80 - radius} 90 A ${radius} ${radius} 0 0 1 ${80 + radius} 90`} fill="none" stroke="#1a1a1e" strokeWidth={8} strokeLinecap="round" />
        <path d={`M ${80 - radius} 90 A ${radius} ${radius} 0 0 1 ${80 + radius} 90`} fill="none" stroke="url(#mG)" strokeWidth={8} strokeLinecap="round" strokeDasharray={`${prog} ${circ}`} />
      </svg>
      <div style={{ position: "absolute", bottom: 8, left: "50%", transform: "translateX(-50%)", textAlign: "center" }}>
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff" }}>{days}<span style={{ fontSize: 12, color: "#6B7280" }}>/{target}j</span></div>
      </div>
    </div>
  );
}

// ── Main ──
export default function TestUIPage() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [models, setModels] = useState<string[]>([]);
  const [counts, setCounts] = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [recentFindings, setRecentFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch("/api/tc/health").then(r => r.json()).catch(() => null),
      fetch("/api/ollama").then(r => r.json()).catch(() => ({ models: [] })),
      fetch("/api/tc/findings/counts").then(r => r.json()).catch(() => ({})),
      fetch("/api/tc/findings?limit=6&status=open").then(r => r.json()).catch(() => []),
    ]).then(([h, o, c, f]) => {
      setHealth(h); setModels((o?.models || []).map((m: any) => m.name));
      setCounts({ critical: c?.CRITICAL || 0, high: c?.HIGH || 0, medium: c?.MEDIUM || 0, low: c?.LOW || 0 });
      if (Array.isArray(f)) setRecentFindings(f.slice(0, 6));
      else if (f?.findings) setRecentFindings(f.findings.slice(0, 6));
      setLoading(false);
    });
  }, []);

  const engineOk = health?.status === "ok" || health?.status === "healthy";
  const dbOk = health?.database === true;
  const aiOk = models.length > 0;
  const mlOk = health?.ml?.alive === true;
  const mlTrained = health?.ml?.model_trained === true;
  const mlDays = health?.ml?.data_days || 0;
  const totalFindings = counts.critical + counts.high + counts.medium + counts.low;
  const sevColor = (s: string) => { switch (s) { case "CRITICAL": return "#d03020"; case "HIGH": return "#e06030"; case "MEDIUM": return "#d09020"; default: return "#6B7280"; } };

  const hubServices = [
    { id: "db", label: "PostgreSQL", ok: dbOk, detail: "PG16+AGE", angle: -90 },
    { id: "ollama", label: "Ollama", ok: aiOk, detail: `${models.length} models`, angle: -30 },
    { id: "ml", label: "ML Engine", ok: mlOk, detail: mlTrained ? "Trained" : `${mlDays}d`, angle: 30 },
    { id: "graph", label: "Graph", ok: dbOk, detail: "STIX 2.1", angle: 90 },
    { id: "telegram", label: "Telegram", ok: engineOk, detail: "HITL", angle: 150 },
    { id: "syslog", label: "Syslog", ok: true, detail: "Port 514", angle: 210 },
  ];

  return (
    <div style={{ minHeight: "100vh", background: "#111114", color: "#e8e4e0", fontFamily: "-apple-system, BlinkMacSystemFont, 'Inter', sans-serif" }}>
      <nav style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 32px", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 30, height: 30, borderRadius: 8, background: "linear-gradient(135deg, #d03020, #a01810)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <Shield size={14} color="#fff" />
          </div>
          <span style={{ fontSize: 15, fontWeight: 800, letterSpacing: "0.12em" }}>
            <span style={{ color: "#e8e4e0" }}>THREAT</span><span style={{ color: "#d03020" }}>CLAW</span>
          </span>
          <span style={{ fontSize: 9, color: "#6B7280", marginLeft: 8, background: "rgba(208,48,32,0.1)", padding: "2px 8px", borderRadius: 4, fontWeight: 600 }}>v{health?.version || "..."}</span>
        </div>
        <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
          {["Status", "Detections", "Intelligence", "Config"].map((item, i) => (
            <span key={item} style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: i === 0 ? "#d03020" : "#6B7280", cursor: "pointer", borderBottom: i === 0 ? "2px solid #d03020" : "none", paddingBottom: 2 }}>{item}</span>
          ))}
        </div>
      </nav>

      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "24px 32px" }}>
        {/* KPIs */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 16, marginBottom: 20 }}>
          <KpiCard label="Score Securite" value={loading ? "..." : engineOk ? "100" : "--"} icon={<Shield size={12} color="#d03020" />} color={engineOk ? "#30a050" : "#6B7280"} />
          <KpiCard label="Findings Actifs" value={loading ? "..." : String(totalFindings)} icon={<AlertTriangle size={12} color="#d03020" />} trend={counts.critical > 0 ? `${counts.critical} crit` : undefined} />
          <KpiCard label="Sources Actives" value="26" unit="feeds" icon={<Radio size={12} color="#6B7280" />} />
          <KpiCard label="Disque" value={health?.disk_free?.replace(" libre", "") || "..."} icon={<Database size={12} color="#6B7280" />} />
        </div>

        {/* Pipeline + Hub */}
        <div style={{ display: "grid", gridTemplateColumns: "3fr 2fr", gap: 16, marginBottom: 20 }}>
          <Card gradient="linear-gradient(145deg, #1a1a22 0%, #14141c 100%)" style={{ padding: "24px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <div>
                <h2 style={{ fontSize: 22, fontWeight: 900, margin: 0, letterSpacing: -0.5 }}>PIPELINE</h2>
                <span style={{ fontSize: 10, color: "#6B7280" }}>Sources &rarr; IE &rarr; AI Investigation &rarr; Verdict</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <StatusDot ok={engineOk} />
                <span style={{ fontSize: 10, color: engineOk ? "#30a050" : "#d03020", fontWeight: 600 }}>{engineOk ? "ACTIF" : "ARRETE"}</span>
              </div>
            </div>
            <PipelineFlow engineOk={engineOk} aiOk={aiOk} findings={totalFindings} />
          </Card>

          <Card gradient="linear-gradient(180deg, #1a1a22 0%, #14141c 100%)" style={{ padding: "20px", display: "flex", flexDirection: "column", alignItems: "center" }}>
            <Label icon={<Cpu size={12} color="#d03020" />}>Connexions Services</Label>
            <div style={{ marginTop: 8, flex: 1, display: "flex", alignItems: "center" }}><ServiceHub services={hubServices} /></div>
            <div style={{ fontSize: 10, color: "#6B7280", marginTop: 4 }}>{hubServices.filter(s => s.ok).length}/{hubServices.length} connectes</div>
          </Card>
        </div>

        {/* Bottom row */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr 1fr", gap: 16 }}>
          <Card><Label icon={<BarChart3 size={12} color="#d03020" />}>Repartition Severite</Label><div style={{ marginTop: 12 }}><SeverityBars counts={counts} /></div></Card>

          <Card style={{ padding: "16px 20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <Label icon={<Eye size={12} color="#d03020" />}>Findings Recents</Label>
              <span style={{ fontSize: 9, color: "#d03020", fontWeight: 600, cursor: "pointer", display: "flex", alignItems: "center", gap: 2 }}>Voir tout <ChevronRight size={10} /></span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {recentFindings.length === 0 && <div style={{ fontSize: 11, color: "#6B7280", padding: "16px 0", textAlign: "center" }}>Aucun finding actif</div>}
              {recentFindings.map(f => (
                <div key={f.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", background: "rgba(255,255,255,0.02)", borderRadius: 8, border: "1px solid rgba(255,255,255,0.04)" }}>
                  <span style={{ width: 6, height: 6, borderRadius: 2, background: sevColor(f.severity), flexShrink: 0 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: "#e8e4e0", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{f.title}</div>
                    <div style={{ fontSize: 9, color: "#6B7280", marginTop: 2 }}>{f.asset || "\u2014"} &middot; {f.source || "\u2014"}</div>
                  </div>
                  <span style={{ fontSize: 8, fontWeight: 700, color: sevColor(f.severity), textTransform: "uppercase", flexShrink: 0 }}>{f.severity}</span>
                </div>
              ))}
            </div>
          </Card>

          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <Card gradient="linear-gradient(145deg, #1a1a22 0%, #16161e 100%)">
              <Label icon={<Brain size={12} color="#d09020" />}>ML Training</Label>
              <MlGauge days={mlDays} trained={mlTrained} />
              <div style={{ textAlign: "center", fontSize: 9, color: "#6B7280", marginTop: 4 }}>{mlTrained ? "Scoring actif" : `${14 - mlDays}j avant scoring`}</div>
            </Card>
            <Card>
              <Label icon={<Clock size={12} color="#6B7280" />}>Engine</Label>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 8 }}><StatusDot ok={engineOk} /><span style={{ fontSize: 12, fontWeight: 600, color: "#e8e4e0" }}>Cycle 5 min</span></div>
              <div style={{ fontSize: 9, color: "#6B7280", marginTop: 6 }}>{health?.ml?.timestamp ? `Dernier: ${new Date(health.ml.timestamp).toLocaleTimeString("fr-FR")}` : "En attente..."}</div>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}

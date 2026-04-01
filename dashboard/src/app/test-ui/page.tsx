"use client";

import React, { useEffect, useState } from "react";
import { Shield, Brain, AlertTriangle, Database, Radio, Cpu, Eye, Clock, Activity } from "lucide-react";

// ── Types ──
interface HealthData { status: string; version: string; database: boolean; llm: string; disk_free: string; ml?: { alive: boolean; model_trained: boolean; data_days: number; timestamp?: string }; }
interface Finding { id: number; title: string; severity: string; status: string; asset?: string; source?: string; detected_at: string; }

// ══════════════════════════════════════════════════════════
//  TUILE 1 — Score Sécurité (Radial Gauge + arc glow)
// ══════════════════════════════════════════════════════════
function Tuile1_ScoreRadial({ score, engineOk }: { score: number; engineOk: boolean }) {
  const radius = 70;
  const stroke = 8;
  const circ = 2 * Math.PI * radius;
  const pct = score / 100;
  const dashLen = circ * pct;
  const color = score >= 80 ? "#30a050" : score >= 50 ? "#d09020" : "#d03020";

  return (
    <div style={{ background: "linear-gradient(160deg, #1c1c24 0%, #141418 50%, #1a1420 100%)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 20, padding: "28px 24px", textAlign: "center", position: "relative", overflow: "hidden" }}>
      {/* Subtle radial glow behind gauge */}
      <div style={{ position: "absolute", top: "30%", left: "50%", transform: "translate(-50%, -50%)", width: 200, height: 200, background: `radial-gradient(circle, ${color}15 0%, transparent 70%)`, pointerEvents: "none" }} />

      <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 16 }}>Score Securite</div>

      <div style={{ position: "relative", width: 170, height: 170, margin: "0 auto" }}>
        <svg width="170" height="170" viewBox="0 0 170 170">
          {/* Background ring */}
          <circle cx="85" cy="85" r={radius} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={stroke} />
          {/* Track ring (subtle) */}
          <circle cx="85" cy="85" r={radius} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={stroke} strokeDasharray={`${circ * 0.75} ${circ * 0.25}`} strokeDashoffset={circ * 0.25} strokeLinecap="round" transform="rotate(-225 85 85)" />
          {/* Value arc */}
          <circle cx="85" cy="85" r={radius} fill="none" stroke={color} strokeWidth={stroke} strokeDasharray={`${dashLen * 0.75} ${circ}`} strokeDashoffset={circ * 0.25} strokeLinecap="round" transform="rotate(-225 85 85)" style={{ filter: `drop-shadow(0 0 8px ${color}60)`, transition: "stroke-dasharray 1s ease" }} />
          {/* Tick marks */}
          {Array.from({ length: 24 }).map((_, i) => {
            const a = (-225 + i * (270 / 24)) * (Math.PI / 180);
            const r1 = radius + 10; const r2 = radius + 14;
            return <line key={i} x1={85 + r1 * Math.cos(a)} y1={85 + r1 * Math.sin(a)} x2={85 + r2 * Math.cos(a)} y2={85 + r2 * Math.sin(a)} stroke="rgba(255,255,255,0.1)" strokeWidth={1} />;
          })}
        </svg>
        <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <span style={{ fontSize: 42, fontWeight: 900, color, letterSpacing: -2, lineHeight: 1 }}>{score}</span>
          <span style={{ fontSize: 10, color: "#6B7280", fontWeight: 600, marginTop: 4 }}>{score >= 80 ? "Situation stable" : score >= 50 ? "Vigilance" : "Critique"}</span>
        </div>
      </div>

      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 6, marginTop: 12 }}>
        <span style={{ width: 6, height: 6, borderRadius: "50%", background: engineOk ? "#30a050" : "#d03020", boxShadow: `0 0 6px ${engineOk ? "#30a050" : "#d03020"}` }} />
        <span style={{ fontSize: 10, color: engineOk ? "#30a050" : "#d03020", fontWeight: 600 }}>{engineOk ? "Engine actif" : "Engine arrete"}</span>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════
//  TUILE 2 — Threat Severity (Donut + breakdown)
// ══════════════════════════════════════════════════════════
function Tuile2_ThreatDonut({ counts }: { counts: { critical: number; high: number; medium: number; low: number } }) {
  const total = counts.critical + counts.high + counts.medium + counts.low || 1;
  const data = [
    { label: "CRITICAL", value: counts.critical, color: "#d03020" },
    { label: "HIGH", value: counts.high, color: "#e06030" },
    { label: "MEDIUM", value: counts.medium, color: "#d09020" },
    { label: "LOW", value: counts.low, color: "#4a5568" },
  ];
  const radius = 52; const stroke = 14; const circ = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div style={{ background: "linear-gradient(160deg, #1a1a24 0%, #16161e 100%)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 20, padding: "24px" }}>
      <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 16, display: "flex", alignItems: "center", gap: 6 }}>
        <AlertTriangle size={12} color="#d03020" /> Menaces par Severite
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
        {/* Donut */}
        <div style={{ position: "relative", width: 130, height: 130, flexShrink: 0 }}>
          <svg width="130" height="130" viewBox="0 0 130 130">
            <circle cx="65" cy="65" r={radius} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={stroke} />
            {data.map((d, i) => {
              const dashLen = (d.value / total) * circ;
              const currentOffset = offset;
              offset += dashLen;
              return dashLen > 0 ? (
                <circle key={i} cx="65" cy="65" r={radius} fill="none" stroke={d.color} strokeWidth={stroke}
                  strokeDasharray={`${dashLen} ${circ - dashLen}`} strokeDashoffset={-currentOffset}
                  transform="rotate(-90 65 65)" strokeLinecap="round"
                  style={{ filter: i === 0 ? `drop-shadow(0 0 6px ${d.color}50)` : "none", transition: "stroke-dasharray 0.8s ease" }} />
              ) : null;
            })}
          </svg>
          <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
            <span style={{ fontSize: 28, fontWeight: 900, color: "#fff", lineHeight: 1 }}>{total}</span>
            <span style={{ fontSize: 9, color: "#6B7280", fontWeight: 600 }}>findings</span>
          </div>
        </div>

        {/* Breakdown */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 8 }}>
          {data.map(d => (
            <div key={d.label} style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ width: 10, height: 10, borderRadius: 3, background: d.color, flexShrink: 0 }} />
              <span style={{ fontSize: 10, color: "#6B7280", flex: 1 }}>{d.label}</span>
              <span style={{ fontSize: 14, fontWeight: 800, color: "#fff" }}>{d.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════
//  TUILE 3 — Pipeline Flow (animated Sankey)
// ══════════════════════════════════════════════════════════
function Tuile3_Pipeline({ engineOk, aiOk, findings }: { engineOk: boolean; aiOk: boolean; findings: number }) {
  const sources = [
    { label: "Wazuh", active: true }, { label: "Suricata", active: true },
    { label: "Fluent-Bit", active: true }, { label: "Nuclei", active: false },
    { label: "Connectors", active: true },
  ];

  return (
    <div style={{ background: "linear-gradient(160deg, #181820 0%, #12121a 100%)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 20, padding: "24px", position: "relative", overflow: "hidden" }}>
      {/* Grid pattern */}
      <div style={{ position: "absolute", inset: 0, backgroundImage: "linear-gradient(rgba(208,48,32,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(208,48,32,0.03) 1px, transparent 1px)", backgroundSize: "40px 40px", pointerEvents: "none" }} />

      <div style={{ position: "relative", zIndex: 1 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <div>
            <span style={{ fontSize: 18, fontWeight: 900, letterSpacing: -0.5 }}>PIPELINE</span>
            <span style={{ fontSize: 10, color: "#6B7280", display: "block", marginTop: 2 }}>Sources → IE → Investigation → Verdict</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, background: engineOk ? "rgba(48,160,80,0.1)" : "rgba(208,48,32,0.1)", padding: "4px 10px", borderRadius: 8, border: `1px solid ${engineOk ? "rgba(48,160,80,0.2)" : "rgba(208,48,32,0.2)"}` }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: engineOk ? "#30a050" : "#d03020" }} />
            <span style={{ fontSize: 9, fontWeight: 700, color: engineOk ? "#30a050" : "#d03020" }}>{engineOk ? "ACTIF" : "ARRETE"}</span>
          </div>
        </div>

        <svg width="100%" height="220" viewBox="0 0 600 220" style={{ overflow: "visible" }}>
          <defs>
            <linearGradient id="fA"><stop offset="0%" stopColor="#d03020" stopOpacity="0.6" /><stop offset="100%" stopColor="#d03020" stopOpacity="0.15" /></linearGradient>
            <linearGradient id="fI"><stop offset="0%" stopColor="#333" stopOpacity="0.3" /><stop offset="100%" stopColor="#222" stopOpacity="0.1" /></linearGradient>
            <filter id="glow"><feGaussianBlur stdDeviation="3" /><feComposite in="SourceGraphic" /></filter>
          </defs>

          {sources.map((s, i) => {
            const y = 25 + i * 42;
            const active = s.active;
            return (
              <g key={i}>
                <path d={`M80,${y} C160,${y} 190,110 250,110`} fill="none" stroke={active ? "url(#fA)" : "url(#fI)"} strokeWidth={active ? 2.5 : 1} strokeLinecap="round" opacity={active ? 1 : 0.3} />
                {active && <circle r={2} fill="#d03020" opacity={0.9}><animateMotion dur="2.5s" repeatCount="indefinite" path={`M80,${y} C160,${y} 190,110 250,110`} /></circle>}
                {/* Source pill */}
                <rect x={4} y={y - 10} width={72} height={20} rx={6} fill={active ? "rgba(208,48,32,0.08)" : "rgba(255,255,255,0.02)"} stroke={active ? "rgba(208,48,32,0.15)" : "rgba(255,255,255,0.04)"} strokeWidth={0.5} />
                <text x={40} y={y + 3} fill={active ? "#d03020" : "#3a3a3a"} fontSize="8" fontWeight="700" textAnchor="middle" letterSpacing="0.03em">{s.label}</text>
              </g>
            );
          })}

          {/* IE → AI → Verdict */}
          <line x1="280" y1="110" x2="370" y2="110" stroke={engineOk ? "#d03020" : "#333"} strokeWidth={2} opacity={0.5} />
          <line x1="420" y1="110" x2="500" y2="110" stroke={aiOk ? "#30a050" : "#333"} strokeWidth={2} opacity={0.5} />
          {engineOk && <circle r={2.5} fill="#d03020"><animateMotion dur="1.2s" repeatCount="indefinite" path="M280,110 L370,110" /></circle>}
          {aiOk && <circle r={2.5} fill="#30a050"><animateMotion dur="1.5s" repeatCount="indefinite" path="M420,110 L500,110" /></circle>}

          {/* Nodes */}
          {[
            { x: 265, label: "IE", sub: "Intelligence\nEngine", ok: engineOk, c: "#d03020" },
            { x: 395, label: "AI", sub: "ReAct\nInvestigation", ok: aiOk, c: "#d03020" },
            { x: 525, label: "✓", sub: "Verdict\nHITL", ok: engineOk, c: "#30a050" },
          ].map(n => (
            <g key={n.label}>
              {n.ok && <circle cx={n.x} cy={110} r={30} fill="none" stroke={n.c} strokeWidth={0.5} opacity={0.2} />}
              <circle cx={n.x} cy={110} r={22} fill="#1a1a22" stroke={n.ok ? n.c : "#333"} strokeWidth={1.5} />
              <text x={n.x} y={113} fill={n.ok ? "#fff" : "#4a4a4a"} fontSize={n.label === "✓" ? "14" : "10"} fontWeight="900" textAnchor="middle" dominantBaseline="middle">{n.label}</text>
              {n.sub.split("\n").map((line, li) => (
                <text key={li} x={n.x} y={145 + li * 11} fill="#6B7280" fontSize="8" fontWeight="600" textAnchor="middle">{line}</text>
              ))}
            </g>
          ))}

          {/* Findings badge */}
          <rect x={505} y={65} width={40} height={22} rx={8} fill="rgba(208,48,32,0.12)" stroke="rgba(208,48,32,0.25)" strokeWidth={0.5} />
          <text x={525} y={79} fill="#d03020" fontSize="11" fontWeight="900" textAnchor="middle">{findings}</text>
        </svg>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════
//  TUILE 4 — Service Hub (processor style)
// ══════════════════════════════════════════════════════════
function Tuile4_ServiceHub({ services }: { services: { id: string; label: string; ok: boolean; detail: string; icon: React.ReactNode; angle: number }[] }) {
  const size = 300; const center = size / 2; const nodeR = 120;

  return (
    <div style={{ background: "linear-gradient(160deg, #1a1a24 0%, #141420 100%)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 20, padding: "24px", textAlign: "center" }}>
      <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 8, display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
        <Cpu size={12} color="#d03020" /> Connexions Services
      </div>

      <div style={{ position: "relative", width: size, height: size, margin: "0 auto" }}>
        <svg width={size} height={size}>
          <defs>
            <radialGradient id="hGlow"><stop offset="0%" stopColor="#d03020" stopOpacity="0.12" /><stop offset="100%" stopColor="#d03020" stopOpacity="0" /></radialGradient>
          </defs>

          {/* Concentric rings */}
          <circle cx={center} cy={center} r={60} fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth={0.5} />
          <circle cx={center} cy={center} r={90} fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth={0.5} strokeDasharray="4,4" />

          {/* Connections */}
          {services.map(s => {
            const rad = (s.angle * Math.PI) / 180;
            const x = center + nodeR * Math.cos(rad);
            const y = center + nodeR * Math.sin(rad);
            const c = s.ok ? "#30a050" : "#d03020";
            return (
              <g key={s.id}>
                <line x1={center} y1={center} x2={x} y2={y} stroke={c} strokeWidth={1.5} opacity={0.4} strokeDasharray={s.ok ? "none" : "3,3"} />
                {s.ok && (
                  <>
                    <circle r={2} fill={c} opacity={0.7}><animateMotion dur="3s" repeatCount="indefinite" path={`M${center},${center} L${x},${y}`} /></circle>
                    <circle cx={x} cy={y} r={8} fill="none" stroke={c} strokeWidth={0.5} opacity={0.2}>
                      <animate attributeName="r" values="8;14;8" dur="2s" repeatCount="indefinite" />
                      <animate attributeName="opacity" values="0.2;0;0.2" dur="2s" repeatCount="indefinite" />
                    </circle>
                  </>
                )}
              </g>
            );
          })}

          {/* Hub */}
          <circle cx={center} cy={center} r={34} fill="url(#hGlow)" />
          <circle cx={center} cy={center} r={28} fill="#16161e" stroke="#d03020" strokeWidth={2} />
          <circle cx={center} cy={center} r={20} fill="none" stroke="rgba(208,48,32,0.2)" strokeWidth={0.5} strokeDasharray="2,3" />
          <text x={center} y={center - 2} fill="#d03020" fontSize="10" fontWeight="900" textAnchor="middle" dominantBaseline="middle">THREAT</text>
          <text x={center} y={center + 10} fill="#d03020" fontSize="10" fontWeight="900" textAnchor="middle">CLAW</text>
        </svg>

        {/* Service nodes */}
        {services.map(s => {
          const rad = (s.angle * Math.PI) / 180;
          const x = center + nodeR * Math.cos(rad) - 40;
          const y = center + nodeR * Math.sin(rad) - 20;
          const c = s.ok ? "#30a050" : "#d03020";
          return (
            <div key={s.id} style={{ position: "absolute", left: x, top: y, width: 80, padding: "6px 8px", background: "rgba(20,20,28,0.9)", border: `1px solid ${c}33`, borderRadius: 10, textAlign: "center", backdropFilter: "blur(4px)" }}>
              <div style={{ fontSize: 8, fontWeight: 700, color: c, textTransform: "uppercase", display: "flex", alignItems: "center", justifyContent: "center", gap: 3 }}>
                <span style={{ width: 5, height: 5, borderRadius: "50%", background: c }} />
                {s.label}
              </div>
              <div style={{ fontSize: 7, color: "#6B7280", marginTop: 2 }}>{s.detail}</div>
            </div>
          );
        })}
      </div>

      <div style={{ fontSize: 10, color: "#6B7280", marginTop: 4 }}>
        {services.filter(s => s.ok).length}/{services.length} services connectes
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════
//  TUILE 5 — Findings récents (glass list)
// ══════════════════════════════════════════════════════════
function Tuile5_RecentFindings({ findings }: { findings: Finding[] }) {
  const sevColor = (s: string) => { switch (s) { case "CRITICAL": return "#d03020"; case "HIGH": return "#e06030"; case "MEDIUM": return "#d09020"; default: return "#6B7280"; } };
  const sevBg = (s: string) => { switch (s) { case "CRITICAL": return "rgba(208,48,32,0.08)"; case "HIGH": return "rgba(224,96,48,0.06)"; default: return "rgba(255,255,255,0.02)"; } };

  return (
    <div style={{ background: "linear-gradient(160deg, #1a1a24 0%, #16161e 100%)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 20, padding: "20px 16px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, padding: "0 4px" }}>
        <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", display: "flex", alignItems: "center", gap: 6 }}>
          <Eye size={12} color="#d03020" /> Findings Recents
        </div>
        <span style={{ fontSize: 9, color: "#d03020", fontWeight: 600, cursor: "pointer" }}>Voir tout →</span>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {findings.length === 0 && <div style={{ fontSize: 11, color: "#6B7280", padding: "20px 0", textAlign: "center" }}>Aucun finding</div>}
        {findings.map((f, i) => (
          <div key={f.id} style={{
            display: "flex", alignItems: "center", gap: 10, padding: "10px 12px",
            background: sevBg(f.severity), borderRadius: 10,
            border: `1px solid ${sevColor(f.severity)}15`,
            borderLeft: `3px solid ${sevColor(f.severity)}`,
            transition: "background 0.2s",
          }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: "#e8e4e0", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{f.title}</div>
              <div style={{ fontSize: 9, color: "#6B7280", marginTop: 3, display: "flex", gap: 8 }}>
                <span>{f.asset || "—"}</span>
                <span>•</span>
                <span>{f.source || "—"}</span>
              </div>
            </div>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4, flexShrink: 0 }}>
              <span style={{ fontSize: 8, fontWeight: 800, color: sevColor(f.severity), background: `${sevColor(f.severity)}15`, padding: "2px 6px", borderRadius: 4, textTransform: "uppercase" }}>{f.severity}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════
//  TUILE 6 — ML + Quick Stats (mini cards grid)
// ══════════════════════════════════════════════════════════
function Tuile6_QuickStats({ mlDays, mlTrained, disk, models, engineOk }: { mlDays: number; mlTrained: boolean; disk: string; models: number; engineOk: boolean }) {
  const target = 14; const pct = Math.min(100, (mlDays / target) * 100);
  const items = [
    { label: "ML Training", value: `${mlDays}/${target}j`, sub: mlTrained ? "Scoring actif" : `${target - mlDays}j restants`, color: mlTrained ? "#30a050" : "#d09020", pct },
    { label: "IA Models", value: String(models), sub: "charges en memoire", color: models > 0 ? "#30a050" : "#d03020", pct: models > 0 ? 100 : 0 },
    { label: "Disque", value: disk, sub: "disponible", color: "#6B7280", pct: 60 },
    { label: "Enrichissement", value: "26", sub: "sources actives", color: "#d03020", pct: 100 },
  ];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
      {items.map(item => (
        <div key={item.label} style={{ background: "linear-gradient(160deg, #1c1c24 0%, #16161e 100%)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 16, padding: "16px" }}>
          <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.1em", color: "#6B7280", marginBottom: 8 }}>{item.label}</div>
          <div style={{ fontSize: 22, fontWeight: 900, color: item.color, lineHeight: 1 }}>{item.value}</div>
          <div style={{ fontSize: 9, color: "#6B7280", marginTop: 4 }}>{item.sub}</div>
          {/* Mini progress bar */}
          <div style={{ height: 3, background: "rgba(255,255,255,0.04)", borderRadius: 2, marginTop: 8, overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${item.pct}%`, background: item.color, borderRadius: 2, transition: "width 1s ease" }} />
          </div>
        </div>
      ))}
    </div>
  );
}

// ══════════════════════════════════════════════════════════
//  MAIN PAGE
// ══════════════════════════════════════════════════════════
export default function TestUIPage() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [models, setModels] = useState<string[]>([]);
  const [counts, setCounts] = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [recentFindings, setRecentFindings] = useState<Finding[]>([]);

  useEffect(() => {
    Promise.all([
      fetch("/api/tc/health").then(r => r.json()).catch(() => null),
      fetch("/api/ollama").then(r => r.json()).catch(() => ({ models: [] })),
      fetch("/api/tc/findings/counts").then(r => r.json()).catch(() => ({})),
      fetch("/api/tc/findings?limit=5&status=open").then(r => r.json()).catch(() => []),
    ]).then(([h, o, c, f]) => {
      setHealth(h); setModels((o?.models || []).map((m: any) => m.name));
      setCounts({ critical: c?.CRITICAL || 0, high: c?.HIGH || 0, medium: c?.MEDIUM || 0, low: c?.LOW || 0 });
      if (Array.isArray(f)) setRecentFindings(f.slice(0, 5));
      else if (f?.findings) setRecentFindings(f.findings.slice(0, 5));
    });
  }, []);

  const engineOk = health?.status === "ok" || health?.status === "healthy";
  const dbOk = health?.database === true;
  const aiOk = models.length > 0;
  const mlOk = health?.ml?.alive === true;
  const mlDays = health?.ml?.data_days || 0;
  const totalFindings = counts.critical + counts.high + counts.medium + counts.low;

  const hubServices = [
    { id: "db", label: "PostgreSQL", ok: dbOk, detail: "PG16 + AGE", icon: <Database size={10} />, angle: -90 },
    { id: "ollama", label: "Ollama", ok: aiOk, detail: `${models.length} models`, icon: <Brain size={10} />, angle: -30 },
    { id: "ml", label: "ML Engine", ok: mlOk, detail: mlOk ? `${mlDays}j data` : "Down", icon: <Activity size={10} />, angle: 30 },
    { id: "graph", label: "Graph", ok: dbOk, detail: "STIX 2.1", icon: <Radio size={10} />, angle: 90 },
    { id: "telegram", label: "Telegram", ok: engineOk, detail: "HITL", icon: <Radio size={10} />, angle: 150 },
    { id: "syslog", label: "Syslog", ok: true, detail: "Port 514", icon: <Radio size={10} />, angle: 210 },
  ];

  return (
    <div style={{ minHeight: "100vh", background: "#0f0f13", color: "#e8e4e0", fontFamily: "-apple-system, BlinkMacSystemFont, 'Inter', sans-serif" }}>
      {/* Nav */}
      <nav style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 32px", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 30, height: 30, borderRadius: 8, background: "linear-gradient(135deg, #d03020, #a01810)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <Shield size={14} color="#fff" />
          </div>
          <span style={{ fontSize: 15, fontWeight: 800, letterSpacing: "0.12em" }}>
            <span style={{ color: "#e8e4e0" }}>THREAT</span><span style={{ color: "#d03020" }}>CLAW</span>
          </span>
          <span style={{ fontSize: 9, color: "#6B7280", marginLeft: 8, background: "rgba(208,48,32,0.1)", padding: "2px 8px", borderRadius: 4, fontWeight: 600 }}>TEST UI</span>
        </div>
        <span style={{ fontSize: 9, color: "#6B7280" }}>v{health?.version || "..."}</span>
      </nav>

      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "24px 32px" }}>
        {/* Tuile labels */}
        <div style={{ fontSize: 9, color: "#6B7280", marginBottom: 8, fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase" }}>Dashboard SOC — Propositions de tuiles</div>

        {/* Row 1 — Tuile 1 + Tuile 2 + Tuile 6 */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.2fr 1fr", gap: 16, marginBottom: 16 }}>
          <Tuile1_ScoreRadial score={engineOk ? 100 : 0} engineOk={engineOk} />
          <Tuile2_ThreatDonut counts={counts} />
          <Tuile6_QuickStats mlDays={mlDays} mlTrained={health?.ml?.model_trained === true} disk={health?.disk_free?.replace(" libre", "") || "..."} models={models.length} engineOk={engineOk} />
        </div>

        {/* Row 2 — Tuile 3 (pipeline) */}
        <div style={{ marginBottom: 16 }}>
          <Tuile3_Pipeline engineOk={engineOk} aiOk={aiOk} findings={totalFindings} />
        </div>

        {/* Row 3 — Tuile 4 + Tuile 5 */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.5fr", gap: 16 }}>
          <Tuile4_ServiceHub services={hubServices} />
          <Tuile5_RecentFindings findings={recentFindings} />
        </div>
      </div>
    </div>
  );
}

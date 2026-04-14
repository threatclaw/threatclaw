"use client";

import React, { useEffect, useState } from "react";
import { CpuCard } from "@/components/chrome/CpuCard";

// ═══════════════════════════════════════════════════════════════
//  TYPES
// ═══════════════════════════════════════════════════════════════

interface HealthData {
  status: string; version: string; database: boolean;
  llm: string; disk_free: string;
  ml?: { alive: boolean; model_trained: boolean; data_days: number };
}

interface FindingCounts { critical: number; high: number; medium: number; low: number; info: number; }

interface ScoreProps { score: number; engineRunning: boolean; lastCycle?: string; }
interface PipelineProps { ie: boolean; llm: boolean; db: boolean; lastCycle?: string; findingsCount: number; }
interface HubService { name: string; connected: boolean; detail?: string; }
interface HubProps { services: HubService[]; }
interface FindingsProps extends FindingCounts { total: number; }

// ═══════════════════════════════════════════════════════════════
//  CSS ANIMATIONS (injected once)
// ═══════════════════════════════════════════════════════════════

const cssAnimations = `
  @keyframes tc-sweep { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  @keyframes tc-pulse { 0%,100% { opacity: 0.3; } 50% { opacity: 1; } }
  @keyframes tc-pulse-soft { 0%,100% { opacity: 0.6; } 50% { opacity: 1; } }
  @keyframes tc-scan { from { top: -4px; } to { top: 100%; } }
  @keyframes tc-glow-ring { 0%,100% { box-shadow: 0 0 4px currentColor, 0 0 8px currentColor; } 50% { box-shadow: 0 0 6px currentColor, 0 0 14px currentColor; } }
  @keyframes tc-flow { from { stroke-dashoffset: 20; } to { stroke-dashoffset: 0; } }
  @keyframes tc-blink { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
  @keyframes tc-float { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-3px); } }
`;

// ═══════════════════════════════════════════════════════════════
//  SHARED COMPONENTS
// ═══════════════════════════════════════════════════════════════

function TileLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      fontSize: 16, fontWeight: 700, textTransform: "uppercase",
      letterSpacing: "0.14em", color: "#bbb", marginBottom: 16,
      display: "flex", alignItems: "center", gap: 8,
    }}>
      <span style={{ width: 12, height: 1, background: "rgba(208,48,32,0.3)", display: "inline-block" }} />
      {children}
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      fontSize: 15, fontWeight: 800, textTransform: "uppercase",
      letterSpacing: "0.18em", color: "#d03020",
      margin: "40px 0 18px", paddingBottom: 10,
      borderBottom: "1px solid rgba(208,48,32,0.12)",
      display: "flex", alignItems: "center", gap: 10,
    }}>
      <span style={{ width: 3, height: 14, background: "#d03020", borderRadius: 1, display: "inline-block" }} />
      {children}
    </div>
  );
}

function Led({ color, size = 6, pulse = false }: { color: string; size?: number; pulse?: boolean }) {
  return (
    <span style={{
      display: "inline-block", width: size, height: size, borderRadius: "50%",
      background: color,
      boxShadow: `0 0 ${size}px ${color}80, 0 0 ${size * 2}px ${color}30`,
      animation: pulse ? "tc-pulse 2s ease-in-out infinite" : undefined,
    }} />
  );
}

function MiniLabel({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return <span style={{ fontSize: 15, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.1em", color: "#bbb", ...style }}>{children}</span>;
}

// ═══════════════════════════════════════════════════════════════
//  TILE WRAPPER — Phoenix-inspired inset panel
// ═══════════════════════════════════════════════════════════════

function Tile({ children, mesh, pattern, accentGlow, style }: {
  children: React.ReactNode;
  mesh: string;
  pattern?: React.CSSProperties;
  accentGlow?: string;
  style?: React.CSSProperties;
}) {
  const [h, setH] = useState(false);
  return (
    <div
      onMouseEnter={() => setH(true)}
      onMouseLeave={() => setH(false)}
      style={{
        position: "relative" as const,
        background: `${mesh}, linear-gradient(165deg, #151520 0%, #0d0d15 60%, #111118 100%)`,
        border: `1px solid rgba(255,255,255,${h ? "0.10" : "0.05"})`,
        borderRadius: 14,
        padding: "28px 30px",
        overflow: "hidden",
        boxShadow: [
          "inset 0 2px 12px rgba(0,0,0,0.7)",
          "inset 0 1px 3px rgba(0,0,0,0.5)",
          "inset 0 -1px 1px rgba(255,255,255,0.025)",
          accentGlow ? `inset 0 0 40px ${accentGlow}` : "",
          "0 1px 0 rgba(255,255,255,0.04)",
          "0 4px 20px rgba(0,0,0,0.6)",
          h ? "inset 0 0 50px rgba(255,255,255,0.015)" : "",
        ].filter(Boolean).join(", "),
        transition: "box-shadow 0.4s ease, border-color 0.4s ease, transform 0.3s ease",
        transform: h ? "translateY(-1px)" : "translateY(0)",
        ...style,
      }}
    >
      {pattern && <div style={{ position: "absolute" as const, inset: 0, pointerEvents: "none" as const, ...pattern }} />}
      {/* Noise texture overlay */}
      <div style={{
        position: "absolute" as const, inset: 0,
        backgroundImage: "url('/textures/random-grey-variations.png')",
        backgroundSize: "200px", opacity: 0.025,
        mixBlendMode: "overlay" as const,
        pointerEvents: "none" as const, borderRadius: "inherit",
      }} />
      {/* Bottom depth fog */}
      <div style={{
        position: "absolute" as const, bottom: 0, left: 0, right: 0, height: "40%",
        background: "linear-gradient(to top, rgba(0,0,0,0.15), transparent)",
        pointerEvents: "none" as const, borderRadius: "inherit",
      }} />
      <div style={{ position: "relative", zIndex: 1 }}>{children}</div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  SCORE — 3 variantes
// ═══════════════════════════════════════════════════════════════

function ScoreGauge({ score, engineRunning, lastCycle }: ScoreProps) {
  const color = score >= 80 ? "#30a050" : score >= 50 ? "#d09020" : "#d03020";
  const status = score >= 80 ? "Situation stable" : score >= 50 ? "Sous surveillance" : "Situation critique";
  const r = 58, circ = 2 * Math.PI * r, arc = (score / 100) * circ * 0.75;

  return (
    <Tile
      mesh="radial-gradient(ellipse at 25% 20%, rgba(208,48,32,0.06) 0%, transparent 55%), radial-gradient(ellipse at 80% 75%, rgba(30,30,60,0.25) 0%, transparent 55%)"
      pattern={{ backgroundImage: "radial-gradient(circle, rgba(255,255,255,0.03) 1px, transparent 1px)", backgroundSize: "18px 18px" }}
      accentGlow={`${color}05`}
    >
      <TileLabel>1 — Command Gauge</TileLabel>
      <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
        <div style={{ position: "relative", width: 180, height: 180, flexShrink: 0 }}>
          <svg width="180" height="180" viewBox="0 0 150 150">
            {/* Outer tick marks */}
            {Array.from({ length: 36 }).map((_, i) => {
              const a = (-225 + i * (270 / 36)) * (Math.PI / 180);
              const major = i % 4 === 0;
              const inner = r + 5, outer = inner + (major ? 10 : 5);
              const filled = i < (score / 100) * 36;
              return <line key={i} x1={75 + inner * Math.cos(a)} y1={75 + inner * Math.sin(a)} x2={75 + outer * Math.cos(a)} y2={75 + outer * Math.sin(a)} stroke={filled ? `${color}50` : "rgba(255,255,255,0.05)"} strokeWidth={major ? 1.5 : 0.7} />;
            })}
            {/* Background track */}
            <circle cx="75" cy="75" r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={7} strokeDasharray={`${circ * 0.75} ${circ * 0.25}`} strokeDashoffset={circ * 0.125} transform="rotate(-225 75 75)" strokeLinecap="round" />
            {/* Score arc */}
            <circle cx="75" cy="75" r={r} fill="none" stroke={color} strokeWidth={7} strokeDasharray={`${arc} ${circ}`} strokeDashoffset={circ * 0.125} transform="rotate(-225 75 75)" strokeLinecap="round" style={{ filter: `drop-shadow(0 0 6px ${color}60)`, transition: "stroke-dasharray 1.2s ease" }} />
            {/* Inner decorative rings */}
            <circle cx="75" cy="75" r="30" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5" />
            <circle cx="75" cy="75" r="22" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="0.5" strokeDasharray="2 4" />
            {/* Center glow */}
            <circle cx="75" cy="75" r="18" fill={`${color}08`} />
          </svg>
          <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
            <span style={{ fontSize: 48, fontWeight: 900, color, letterSpacing: -2, textShadow: `0 0 20px ${color}30`, lineHeight: 1 }}>{score}</span>
            <MiniLabel style={{ marginTop: 3, color: "#bbb" }}>/ 100</MiniLabel>
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 12, minWidth: 0 }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: "#f0ece8" }}>{status}</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Led color={engineRunning ? "#30a050" : "#d03020"} pulse={engineRunning} />
            <span style={{ fontSize: 14, color: "#e0e0e0" }}>{engineRunning ? "Agent autonome actif" : "Agent arrêté"}</span>
          </div>
          {lastCycle && <div style={{ fontSize: 16, color: "#bbb" }}>Dernier cycle : {lastCycle}</div>}
          <div style={{ display: "flex", gap: 12, marginTop: 4 }}>
            {[
              { label: "Réseau", ok: true },
              { label: "Endpoints", ok: true },
              { label: "Identité", ok: score > 30 },
            ].map(d => (
              <div key={d.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                <Led color={d.ok ? "#30a050" : "#d03020"} size={4} />
                <span style={{ fontSize: 15, color: "#ccc" }}>{d.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Tile>
  );
}

function ScoreGrid({ score, engineRunning, lastCycle }: ScoreProps) {
  const color = score >= 80 ? "#30a050" : score >= 50 ? "#d09020" : "#d03020";
  const status = score >= 80 ? "Défense optimale" : score >= 50 ? "Brèches détectées" : "Périmètre compromis";
  // Generate hex grid
  const hexes: { cx: number; cy: number; idx: number }[] = [];
  const cols = 9, rows = 5, hexR = 10, gapX = 22, gapY = 19;
  for (let row = 0; row < rows; row++) {
    for (let col = 0; col < cols; col++) {
      hexes.push({ cx: 14 + col * gapX + (row % 2 ? gapX / 2 : 0), cy: 14 + row * gapY, idx: row * cols + col });
    }
  }
  const filledCount = Math.round((score / 100) * hexes.length);
  const hexPath = (cx: number, cy: number) => {
    const pts = Array.from({ length: 6 }, (_, i) => {
      const a = (Math.PI / 3) * i - Math.PI / 6;
      return `${cx + hexR * Math.cos(a)},${cy + hexR * Math.sin(a)}`;
    });
    return `M${pts.join("L")}Z`;
  };

  return (
    <Tile
      mesh="radial-gradient(ellipse at 50% 40%, rgba(48,128,208,0.06) 0%, transparent 55%), radial-gradient(ellipse at 20% 80%, rgba(99,102,241,0.04) 0%, transparent 50%)"
      pattern={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)", backgroundSize: "28px 28px" }}
      accentGlow="rgba(48,128,208,0.04)"
    >
      <TileLabel>2 — Defense Grid</TileLabel>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 20 }}>
        <svg width="210" height="110" viewBox="0 0 210 110" style={{ flexShrink: 0 }}>
          {hexes.map((h, i) => {
            const filled = i < filledCount;
            const nearEdge = i >= filledCount - 3 && i < filledCount;
            const fillColor = filled ? (i < filledCount * 0.3 ? "#d03020" : i < filledCount * 0.6 ? "#d09020" : "#30a050") : "transparent";
            return (
              <g key={i}>
                <path d={hexPath(h.cx, h.cy)}
                  fill={filled ? `${fillColor}15` : "transparent"}
                  stroke={filled ? `${fillColor}40` : "rgba(255,255,255,0.04)"}
                  strokeWidth={filled ? 0.8 : 0.4}
                  style={nearEdge ? { filter: `drop-shadow(0 0 4px ${fillColor}40)` } : undefined}
                />
                {nearEdge && (
                  <path d={hexPath(h.cx, h.cy)} fill="none" stroke={fillColor} strokeWidth={0.5} opacity={0.6}>
                    <animate attributeName="opacity" values="0.3;0.8;0.3" dur="2s" repeatCount="indefinite" />
                  </path>
                )}
              </g>
            );
          })}
        </svg>
        <div style={{ display: "flex", flexDirection: "column", gap: 10, paddingTop: 4 }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
            <span style={{ fontSize: 44, fontWeight: 900, color, letterSpacing: -2, lineHeight: 1, textShadow: `0 0 15px ${color}25` }}>{score}</span>
            <MiniLabel style={{ color: "#bbb" }}>/ 100</MiniLabel>
          </div>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#ccc" }}>{status}</div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 4 }}>
            <Led color={engineRunning ? "#30a050" : "#d03020"} size={5} />
            <span style={{ fontSize: 16, color: "#ccc" }}>{engineRunning ? "Monitoring actif" : "Monitoring inactif"}</span>
          </div>
          <div style={{ fontSize: 15, color: "#e0e0e0", marginTop: 2 }}>
            {filledCount}/{hexes.length} zones couvertes
          </div>
        </div>
      </div>
    </Tile>
  );
}

function ScoreTerminal({ score, engineRunning, lastCycle }: ScoreProps) {
  const color = score >= 80 ? "#30a050" : score >= 50 ? "#d09020" : "#d03020";
  const level = score >= 80 ? "GREEN" : score >= 50 ? "AMBER" : "RED";
  const trend = score >= 80 ? "▲ STABLE" : score >= 50 ? "► WATCH" : "▼ DEGRAD";

  return (
    <Tile
      mesh="radial-gradient(ellipse at 70% 30%, rgba(48,160,80,0.05) 0%, transparent 50%), radial-gradient(ellipse at 20% 70%, rgba(48,128,208,0.03) 0%, transparent 50%)"
      pattern={{
        backgroundImage: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.08) 2px, rgba(0,0,0,0.08) 4px)",
      }}
      accentGlow={`${color}04`}
    >
      <TileLabel>3 — Status Terminal</TileLabel>
      <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "6px 20px", alignItems: "center" }}>
        {/* Score block */}
        <div style={{ gridRow: "1 / 4", display: "flex", flexDirection: "column", alignItems: "center", padding: "8px 16px", borderRight: "1px solid rgba(255,255,255,0.04)" }}>
          <span style={{ fontSize: 48, fontWeight: 900, color, letterSpacing: -3, lineHeight: 1, textShadow: `0 0 25px ${color}25`, fontFamily: "'JetBrains Mono', monospace" }}>{score}</span>
          <div style={{
            fontSize: 15, fontWeight: 800, letterSpacing: "0.15em",
            color, marginTop: 6,
            padding: "2px 8px", borderRadius: 3,
            background: `${color}12`, border: `1px solid ${color}20`,
          }}>{level}</div>
        </div>

        {/* Data rows */}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <MiniLabel>Tendance</MiniLabel>
          <span style={{ fontSize: 14, fontWeight: 700, color: color, fontFamily: "monospace" }}>{trend}</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <MiniLabel>Engine</MiniLabel>
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <Led color={engineRunning ? "#30a050" : "#d03020"} size={5} pulse={engineRunning} />
            <span style={{ fontSize: 14, color: "#e0e0e0", fontFamily: "monospace" }}>{engineRunning ? "RUNNING" : "STOPPED"}</span>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <MiniLabel>Cycle</MiniLabel>
          <span style={{ fontSize: 14, color: "#ccc", fontFamily: "monospace" }}>{lastCycle || "—"}</span>
        </div>
      </div>
      {/* Scan line */}
      <div style={{
        position: "absolute", left: 0, right: 0, height: 1,
        background: `linear-gradient(90deg, transparent, ${color}15, transparent)`,
        animation: "tc-scan 5s linear infinite", pointerEvents: "none",
      }} />
    </Tile>
  );
}

// ═══════════════════════════════════════════════════════════════
//  PIPELINE — 3 variantes
// ═══════════════════════════════════════════════════════════════

const pipelineStages = [
  { key: "collect", label: "Collecte", icon: "◉" },
  { key: "analyze", label: "Analyse IE", icon: "◈" },
  { key: "investigate", label: "Investigation", icon: "◇" },
  { key: "notify", label: "Notification", icon: "◆" },
];

function PipelineFlow({ ie, llm, db, lastCycle, findingsCount }: PipelineProps) {
  const stages = [
    { ...pipelineStages[0], active: db },
    { ...pipelineStages[1], active: ie },
    { ...pipelineStages[2], active: llm },
    { ...pipelineStages[3], active: ie },
  ];

  return (
    <Tile
      mesh="radial-gradient(ellipse at 30% 30%, rgba(208,48,32,0.06) 0%, transparent 55%), radial-gradient(ellipse at 80% 70%, rgba(48,80,160,0.05) 0%, transparent 50%)"
      pattern={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)", backgroundSize: "40px 40px" }}
      accentGlow="rgba(208,48,32,0.03)"
    >
      <TileLabel>1 — Signal Flow</TileLabel>
      <svg width="100%" height="140" viewBox="0 0 400 100" style={{ overflow: "visible" }}>
        {/* Connection lines */}
        {stages.slice(0, -1).map((s, i) => {
          const x1 = 50 + i * 105, x2 = 50 + (i + 1) * 105;
          const active = s.active && stages[i + 1].active;
          return (
            <g key={`line-${i}`}>
              <line x1={x1 + 28} y1={42} x2={x2 - 28} y2={42} stroke={active ? "rgba(208,48,32,0.2)" : "rgba(255,255,255,0.04)"} strokeWidth={2} />
              {active && (
                <line x1={x1 + 28} y1={42} x2={x2 - 28} y2={42} stroke="#d03020" strokeWidth={2} strokeDasharray="6 14" style={{ animation: "tc-flow 1s linear infinite" }} />
              )}
              {active && (
                <circle r="2.5" fill="#d03020" opacity={0.8}>
                  <animateMotion dur="2s" repeatCount="indefinite" path={`M${x1 + 28},42 L${x2 - 28},42`} />
                  <animate attributeName="opacity" values="0.4;1;0.4" dur="2s" repeatCount="indefinite" />
                </circle>
              )}
            </g>
          );
        })}
        {/* Stage nodes */}
        {stages.map((s, i) => {
          const cx = 50 + i * 105;
          return (
            <g key={s.key}>
              {/* Outer glow ring */}
              {s.active && <circle cx={cx} cy={42} r={28} fill="none" stroke={i === 3 ? "rgba(48,160,80,0.1)" : "rgba(208,48,32,0.08)"} strokeWidth={0.5}>
                <animate attributeName="r" values="26;30;26" dur="3s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.5;1;0.5" dur="3s" repeatCount="indefinite" />
              </circle>}
              {/* Node */}
              <circle cx={cx} cy={42} r={22} fill="rgba(14,14,22,0.9)" stroke={s.active ? (i === 3 ? "#30a05040" : "#d0302040") : "rgba(255,255,255,0.05)"} strokeWidth={1.5} />
              <circle cx={cx} cy={42} r={18} fill="none" stroke={s.active ? (i === 3 ? "#30a05015" : "#d0302015") : "transparent"} strokeWidth={0.5} />
              {/* Icon */}
              <text x={cx} y={38} fill={s.active ? (i === 3 ? "#30a050" : "#d03020") : "#666"} fontSize="14" textAnchor="middle" dominantBaseline="middle">{s.icon}</text>
              {/* Label */}
              <text x={cx} y={60} fill={s.active ? "#888" : "#666"} fontSize="7.5" fontWeight="600" textAnchor="middle" letterSpacing="0.05em">{s.label.toUpperCase()}</text>
              {/* Status dot */}
              <circle cx={cx + 16} cy={25} r={3} fill={s.active ? "#30a050" : "#d03020"} opacity={0.8}>
                {s.active && <animate attributeName="opacity" values="0.5;1;0.5" dur="2s" repeatCount="indefinite" />}
              </circle>
            </g>
          );
        })}
        {/* Findings processed badge */}
        <text x="365" y={90} fill="#ccc" fontSize="8" textAnchor="middle">
          {findingsCount} findings traités
        </text>
      </svg>
      {lastCycle && <div style={{ fontSize: 16, color: "#e0e0e0", marginTop: 6, textAlign: "right" }}>Cycle : {lastCycle}</div>}
    </Tile>
  );
}

function PipelineRack({ ie, llm, db, lastCycle, findingsCount }: PipelineProps) {
  const stages = [
    { label: "Collecte de données", active: db, detail: "Wazuh · Syslog · FluentBit", color: "#3080d0" },
    { label: "Intelligence Engine", active: ie, detail: "Corrélation · Scoring · IoC", color: "#d03020" },
    { label: "Investigation ReAct", active: llm, detail: "L1 Triage · L2 Forensic", color: "#9060d0" },
    { label: "Notification", active: ie, detail: "Telegram · Verdict · HITL", color: "#30a050" },
  ];

  return (
    <Tile
      mesh="radial-gradient(ellipse at 60% 35%, rgba(48,128,208,0.05) 0%, transparent 55%)"
      pattern={{ backgroundImage: "repeating-linear-gradient(0deg, transparent, transparent 29px, rgba(255,255,255,0.015) 29px, rgba(255,255,255,0.015) 30px)" }}
      accentGlow="rgba(48,128,208,0.03)"
    >
      <TileLabel>2 — Control Rack</TileLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {stages.map((s, i) => (
          <div key={i} style={{
            display: "flex", alignItems: "center", gap: 12,
            padding: "12px 16px", borderRadius: 8,
            background: s.active ? `${s.color}06` : "rgba(255,255,255,0.01)",
            border: `1px solid ${s.active ? `${s.color}15` : "rgba(255,255,255,0.03)"}`,
            transition: "all 0.3s",
          }}>
            <Led color={s.active ? s.color : "#666"} size={7} pulse={s.active} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 15, fontWeight: 700, color: s.active ? "#c8c0b8" : "#444" }}>{s.label}</div>
              <div style={{ fontSize: 15, color: s.active ? "#555" : "#666", marginTop: 1 }}>{s.detail}</div>
            </div>
            <span style={{
              fontSize: 15, fontWeight: 700, letterSpacing: "0.1em",
              padding: "2px 6px", borderRadius: 3,
              background: s.active ? `${s.color}15` : "rgba(255,255,255,0.02)",
              color: s.active ? s.color : "#666",
            }}>{s.active ? "ON" : "OFF"}</span>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 10, fontSize: 16, color: "#e0e0e0" }}>
        <span>{findingsCount} findings</span>
        <span>{lastCycle || "—"}</span>
      </div>
    </Tile>
  );
}

function PipelineCircuit({ ie, llm, db, lastCycle, findingsCount }: PipelineProps) {
  const allUp = ie && llm && db;
  const traceColor = allUp ? "#30a050" : ie ? "#d09020" : "#d03020";

  return (
    <Tile
      mesh="radial-gradient(ellipse at 30% 60%, rgba(48,160,80,0.05) 0%, transparent 50%), radial-gradient(ellipse at 75% 25%, rgba(208,144,32,0.04) 0%, transparent 50%)"
      pattern={{ backgroundImage: "radial-gradient(circle, rgba(255,255,255,0.025) 1px, transparent 1px)", backgroundSize: "14px 14px" }}
      accentGlow={`${traceColor}04`}
    >
      <TileLabel>3 — Circuit Trace</TileLabel>
      <svg width="100%" height="180" viewBox="0 0 480 160" style={{ overflow: "visible" }}>
        {/* PCB trace background */}
        <path d="M30,110 L100,110 L100,45 L200,45 L200,110 L300,110 L300,45 L400,45 L400,110 L460,110" fill="none" stroke="rgba(0,0,0,0.06)" strokeWidth={4} strokeLinecap="round" strokeLinejoin="round" />
        {/* Animated trace */}
        <path d="M30,110 L100,110 L100,45 L200,45 L200,110 L300,110 L300,45 L400,45 L400,110 L460,110" fill="none" stroke={traceColor} strokeWidth={4} strokeLinecap="round" strokeLinejoin="round" strokeDasharray="20 580" strokeDashoffset="0">
          <animate attributeName="stroke-dashoffset" from="0" to="-600" dur="4s" repeatCount="indefinite" />
        </path>
        {/* Glow trace */}
        <path d="M30,110 L100,110 L100,45 L200,45 L200,110 L300,110 L300,45 L400,45 L400,110 L460,110" fill="none" stroke={traceColor} strokeWidth={10} strokeLinecap="round" strokeLinejoin="round" strokeDasharray="12 588" strokeDashoffset="0" opacity={0.15} style={{ filter: "blur(4px)" }}>
          <animate attributeName="stroke-dashoffset" from="0" to="-600" dur="4s" repeatCount="indefinite" />
        </path>

        {/* Stage nodes */}
        {[
          { cx: 30, label: "IN", sub: "Data", active: db },
          { cx: 150, label: "IE", sub: "Engine", active: ie },
          { cx: 250, label: "ReAct", sub: "Invest.", active: llm },
          { cx: 350, label: "L1/L2", sub: "LLM", active: llm },
          { cx: 460, label: "OUT", sub: "Notify", active: ie },
        ].map((n, i) => {
          const y = i % 2 === 0 ? 95 : 28;
          return (
            <g key={i}>
              <rect x={n.cx - 26} y={y} width={52} height={36} rx={6} fill="rgba(14,14,22,0.95)" stroke={n.active ? `${traceColor}50` : "rgba(0,0,0,0.08)"} strokeWidth={1.5} style={n.active ? { filter: `drop-shadow(0 2px 6px ${traceColor}20)` } : undefined} />
              <text x={n.cx} y={y + 16} fill={n.active ? traceColor : "#888"} fontSize="11" fontWeight="800" textAnchor="middle" letterSpacing="0.04em">{n.label}</text>
              <text x={n.cx} y={y + 28} fill={n.active ? "#666" : "#aaa"} fontSize="8" fontWeight="600" textAnchor="middle">{n.sub}</text>
              <circle cx={n.cx + 20} cy={y + 6} r={3.5} fill={n.active ? "#30a050" : "#d03020"} />
            </g>
          );
        })}
      </svg>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 8, alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Led color={traceColor} size={7} />
          <span style={{ fontSize: 14, fontWeight: 600, color: "#e0e0e0" }}>{allUp ? "Pipeline nominal" : "Pipeline dégradé"}</span>
        </div>
        <span style={{ fontSize: 14, color: "#bbb" }}>{findingsCount} findings traités</span>
      </div>
    </Tile>
  );
}

// ═══════════════════════════════════════════════════════════════
//  HUB SERVICES — 3 variantes
// ═══════════════════════════════════════════════════════════════

function HubBoard({ services }: HubProps) {
  const connectedCount = services.filter(s => s.connected).length;
  return (
    <Tile
      mesh="radial-gradient(ellipse at 40% 30%, rgba(48,160,80,0.05) 0%, transparent 55%), radial-gradient(ellipse at 70% 80%, rgba(48,128,208,0.04) 0%, transparent 50%)"
      pattern={{ backgroundImage: "radial-gradient(circle, rgba(255,255,255,0.02) 1px, transparent 1px)", backgroundSize: "22px 22px" }}
      accentGlow="rgba(48,160,80,0.03)"
    >
      <TileLabel>1 — Status Board</TileLabel>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <span style={{ fontSize: 14, color: "#e0e0e0" }}>{connectedCount}/{services.length} services connectés</span>
        <Led color={connectedCount === services.length ? "#30a050" : connectedCount > 0 ? "#d09020" : "#d03020"} size={7} pulse />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
        {services.map((s, i) => (
          <div key={i} style={{
            padding: "14px 16px", borderRadius: 8,
            background: s.connected ? "rgba(48,160,80,0.04)" : "rgba(255,255,255,0.01)",
            border: `1px solid ${s.connected ? "rgba(48,160,80,0.12)" : "rgba(255,255,255,0.03)"}`,
            display: "flex", alignItems: "center", gap: 10,
          }}>
            <div style={{
              width: 28, height: 28, borderRadius: 6,
              background: s.connected ? "rgba(48,160,80,0.08)" : "rgba(255,255,255,0.02)",
              display: "flex", alignItems: "center", justifyContent: "center",
              border: `1px solid ${s.connected ? "rgba(48,160,80,0.15)" : "rgba(255,255,255,0.04)"}`,
            }}>
              <Led color={s.connected ? "#30a050" : "#d03020"} size={6} pulse={s.connected} />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: s.connected ? "#c0b8b0" : "#444", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{s.name}</div>
              {s.detail && <div style={{ fontSize: 15, color: "#bbb", marginTop: 1, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{s.detail}</div>}
            </div>
          </div>
        ))}
      </div>
    </Tile>
  );
}

function HubConstellation({ services }: HubProps) {
  const positions = [
    { x: 55, y: 25 }, { x: 155, y: 20 }, { x: 105, y: 65 }, { x: 35, y: 100 }, { x: 175, y: 95 },
  ];
  const links: [number, number][] = [[0, 2], [1, 2], [2, 3], [2, 4], [0, 1]];
  const connectedCount = services.filter(s => s.connected).length;

  return (
    <Tile
      mesh="radial-gradient(ellipse at 55% 45%, rgba(99,102,241,0.06) 0%, transparent 55%), radial-gradient(ellipse at 20% 20%, rgba(48,128,208,0.03) 0%, transparent 40%)"
      accentGlow="rgba(99,102,241,0.03)"
    >
      <TileLabel>2 — Constellation</TileLabel>
      <div style={{ display: "flex", gap: 16 }}>
        <svg width="210" height="125" viewBox="0 0 210 125" style={{ flexShrink: 0, overflow: "visible" }}>
          {/* Background stars */}
          {Array.from({ length: 25 }).map((_, i) => (
            <circle key={`star-${i}`} cx={10 + (i * 37) % 200} cy={5 + (i * 23) % 120} r={0.5 + (i % 3) * 0.3} fill="rgba(255,255,255,0.08)">
              {i % 4 === 0 && <animate attributeName="opacity" values="0.04;0.15;0.04" dur={`${3 + i % 4}s`} repeatCount="indefinite" />}
            </circle>
          ))}
          {/* Connection lines */}
          {links.map(([a, b], i) => {
            const pa = positions[Math.min(a, services.length - 1)];
            const pb = positions[Math.min(b, services.length - 1)];
            const sa = services[Math.min(a, services.length - 1)];
            const sb = services[Math.min(b, services.length - 1)];
            if (!pa || !pb) return null;
            const active = sa?.connected && sb?.connected;
            return (
              <g key={`link-${i}`}>
                <line x1={pa.x} y1={pa.y} x2={pb.x} y2={pb.y} stroke={active ? "rgba(99,102,241,0.15)" : "rgba(255,255,255,0.03)"} strokeWidth={active ? 1 : 0.5} />
                {active && <line x1={pa.x} y1={pa.y} x2={pb.x} y2={pb.y} stroke="rgba(99,102,241,0.08)" strokeWidth={3} style={{ filter: "blur(2px)" }} />}
              </g>
            );
          })}
          {/* Service nodes */}
          {services.slice(0, 5).map((s, i) => {
            const p = positions[i];
            if (!p) return null;
            return (
              <g key={i}>
                {s.connected && <circle cx={p.x} cy={p.y} r={12} fill="none" stroke="rgba(99,102,241,0.1)" strokeWidth={0.5}>
                  <animate attributeName="r" values="10;14;10" dur="4s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.3;0.8;0.3" dur="4s" repeatCount="indefinite" />
                </circle>}
                <circle cx={p.x} cy={p.y} r={s.connected ? 4 : 2.5} fill={s.connected ? "#6366f1" : "#666"} style={s.connected ? { filter: "drop-shadow(0 0 4px rgba(99,102,241,0.5))" } : undefined}>
                  {s.connected && <animate attributeName="opacity" values="0.7;1;0.7" dur={`${2 + i * 0.5}s`} repeatCount="indefinite" />}
                </circle>
                <text x={p.x} y={p.y + (p.y < 60 ? -10 : 14)} fill={s.connected ? "#888" : "#3a3a3a"} fontSize="7" fontWeight="600" textAnchor="middle">{s.name}</text>
              </g>
            );
          })}
        </svg>
        <div style={{ display: "flex", flexDirection: "column", gap: 6, paddingTop: 8 }}>
          <span style={{ fontSize: 22, fontWeight: 800, color: connectedCount === services.length ? "#30a050" : "#d09020", lineHeight: 1 }}>{connectedCount}<span style={{ fontSize: 12, color: "#ccc" }}>/{services.length}</span></span>
          <MiniLabel>Services actifs</MiniLabel>
          <div style={{ marginTop: 8 }}>
            {services.map((s, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 3 }}>
                <Led color={s.connected ? "#30a050" : "#d03020"} size={4} />
                <span style={{ fontSize: 15, color: s.connected ? "#666" : "#3a3a3a" }}>{s.name}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Tile>
  );
}

function HubModules({ services }: HubProps) {
  const connectedCount = services.filter(s => s.connected).length;
  const serviceColors = ["#d03020", "#3080d0", "#9060d0", "#30a050", "#d09020"];

  return (
    <Tile
      mesh="radial-gradient(ellipse at 65% 35%, rgba(208,144,32,0.05) 0%, transparent 55%), radial-gradient(ellipse at 25% 75%, rgba(48,128,208,0.03) 0%, transparent 50%)"
      pattern={{ backgroundImage: "repeating-linear-gradient(0deg, transparent, transparent 34px, rgba(255,255,255,0.015) 34px, rgba(255,255,255,0.015) 35px)" }}
      accentGlow="rgba(208,144,32,0.03)"
    >
      <TileLabel>3 — Module Rack</TileLabel>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {services.map((s, i) => {
          const accent = serviceColors[i % serviceColors.length];
          return (
            <div key={i} style={{
              display: "flex", alignItems: "center", gap: 10,
              padding: "7px 10px", borderRadius: 6,
              background: "rgba(255,255,255,0.01)",
              borderLeft: `3px solid ${s.connected ? accent : "rgba(255,255,255,0.03)"}`,
              transition: "all 0.3s",
            }}>
              {/* Status indicator block */}
              <div style={{
                width: 8, height: 22, borderRadius: 2,
                background: s.connected ? `linear-gradient(to bottom, ${accent}40, ${accent}15)` : "rgba(255,255,255,0.02)",
                position: "relative",
              }}>
                {s.connected && <div style={{
                  position: "absolute", top: 2, left: 2, width: 4, height: 4, borderRadius: "50%",
                  background: accent,
                  boxShadow: `0 0 4px ${accent}`,
                  animation: "tc-pulse-soft 2s ease-in-out infinite",
                }} />}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: s.connected ? "#b8b0a8" : "#444" }}>{s.name}</div>
                {s.detail && <div style={{ fontSize: 15, color: "#bbb" }}>{s.detail}</div>}
              </div>
              <span style={{
                fontSize: 14, fontWeight: 800, letterSpacing: "0.12em",
                color: s.connected ? "#30a050" : "#555",
              }}>{s.connected ? "LINK" : "DOWN"}</span>
            </div>
          );
        })}
      </div>
      <div style={{ marginTop: 10, fontSize: 16, color: "#bbb", textAlign: "right" }}>
        Uptime: {connectedCount}/{services.length} modules
      </div>
    </Tile>
  );
}

// ═══════════════════════════════════════════════════════════════
//  FINDINGS — 3 variantes
// ═══════════════════════════════════════════════════════════════

const severityConfig = [
  { key: "critical", label: "Critical", color: "#d03020" },
  { key: "high", label: "High", color: "#d06020" },
  { key: "medium", label: "Medium", color: "#d09020" },
  { key: "low", label: "Low", color: "#3080d0" },
  { key: "info", label: "Info", color: "#ccc" },
];

function FindingsSpectrum({ critical, high, medium, low, info, total }: FindingsProps) {
  const counts = [critical, high, medium, low, info];
  const max = Math.max(...counts, 1);

  return (
    <Tile
      mesh="radial-gradient(ellipse at 25% 30%, rgba(208,48,32,0.07) 0%, transparent 55%), radial-gradient(ellipse at 75% 70%, rgba(208,144,32,0.04) 0%, transparent 50%)"
      accentGlow="rgba(208,48,32,0.04)"
    >
      <TileLabel>1 — Threat Spectrum</TileLabel>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 14 }}>
        <span style={{ fontSize: 36, fontWeight: 900, color: "#f0ece8", letterSpacing: -1 }}>{total}</span>
        <MiniLabel>findings actifs</MiniLabel>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {severityConfig.map((sev, i) => {
          const count = counts[i];
          const pct = (count / max) * 100;
          return (
            <div key={sev.key} style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ fontSize: 15, fontWeight: 700, width: 42, textAlign: "right", color: sev.color, letterSpacing: "0.05em" }}>{sev.label.toUpperCase()}</span>
              <div style={{ flex: 1, height: 10, borderRadius: 5, background: "rgba(255,255,255,0.03)", overflow: "hidden", position: "relative" }}>
                <div style={{
                  height: "100%", borderRadius: 3,
                  width: `${Math.max(pct, count > 0 ? 3 : 0)}%`,
                  background: `linear-gradient(90deg, ${sev.color}30, ${sev.color})`,
                  boxShadow: count > 0 ? `0 0 8px ${sev.color}30, inset 0 0 4px ${sev.color}20` : "none",
                  transition: "width 0.8s ease",
                }} />
              </div>
              <span style={{ fontSize: 12, fontWeight: 800, width: 28, color: count > 0 ? sev.color : "#666", textAlign: "right", fontFamily: "monospace" }}>{count}</span>
            </div>
          );
        })}
      </div>
    </Tile>
  );
}

function FindingsRadar({ critical, high, medium, low, info, total }: FindingsProps) {
  const radarR = 62;
  const blips: { angle: number; dist: number; color: string; count: number; label: string }[] = [
    { angle: -30, dist: 0.2, color: "#d03020", count: critical, label: "CRIT" },
    { angle: 45, dist: 0.4, color: "#d06020", count: high, label: "HIGH" },
    { angle: 150, dist: 0.6, color: "#d09020", count: medium, label: "MED" },
    { angle: -120, dist: 0.8, color: "#3080d0", count: low, label: "LOW" },
    { angle: 90, dist: 0.95, color: "#ccc", count: info, label: "INFO" },
  ];

  return (
    <Tile
      mesh="radial-gradient(ellipse at 50% 50%, rgba(48,160,80,0.06) 0%, transparent 55%)"
      accentGlow="rgba(48,160,80,0.03)"
    >
      <TileLabel>2 — Threat Radar</TileLabel>
      <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
        <div style={{ position: "relative", width: 180, height: 180, flexShrink: 0 }}>
          <svg width="180" height="180" viewBox="0 0 150 150">
            <defs>
              <radialGradient id="fr-sweep-grad">
                <stop offset="0%" stopColor="#30a050" stopOpacity="0.15" />
                <stop offset="100%" stopColor="#30a050" stopOpacity="0" />
              </radialGradient>
            </defs>
            {/* Concentric rings */}
            {[0.25, 0.5, 0.75, 1].map(f => (
              <circle key={f} cx="75" cy="75" r={radarR * f} fill="none" stroke="rgba(48,160,80,0.08)" strokeWidth={0.5} />
            ))}
            {/* Cross hairs */}
            <line x1="75" y1={75 - radarR} x2="75" y2={75 + radarR} stroke="rgba(48,160,80,0.06)" strokeWidth={0.5} />
            <line x1={75 - radarR} y1="75" x2={75 + radarR} y2="75" stroke="rgba(48,160,80,0.06)" strokeWidth={0.5} />
            {/* Sweep arm */}
            <g style={{ transformOrigin: "75px 75px", animation: "tc-sweep 4s linear infinite" }}>
              <line x1="75" y1="75" x2="75" y2={75 - radarR} stroke="#30a050" strokeWidth={1} opacity={0.7} />
              <path d={`M75,75 L75,${75 - radarR} A${radarR},${radarR} 0 0,1 ${75 + radarR * 0.5},${75 - radarR * 0.866} Z`} fill="url(#fr-sweep-grad)" />
            </g>
            {/* Blips */}
            {blips.filter(b => b.count > 0).map((b, i) => {
              const rad = (b.angle * Math.PI) / 180;
              const cx = 75 + radarR * b.dist * Math.cos(rad);
              const cy = 75 + radarR * b.dist * Math.sin(rad);
              return (
                <g key={i}>
                  <circle cx={cx} cy={cy} r={Math.min(4 + b.count * 0.3, 8)} fill={`${b.color}20`} />
                  <circle cx={cx} cy={cy} r={3} fill={b.color} opacity={0.9}>
                    <animate attributeName="opacity" values="0.4;1;0.4" dur={`${1.5 + i * 0.3}s`} repeatCount="indefinite" />
                  </circle>
                  <text x={cx} y={cy - 7} fill={b.color} fontSize="6" fontWeight="800" textAnchor="middle" opacity={0.8}>{b.count}</text>
                </g>
              );
            })}
            {/* Center */}
            <circle cx="75" cy="75" r="3" fill="#30a050" opacity={0.5} />
          </svg>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontSize: 24, fontWeight: 900, color: "#f0ece8", lineHeight: 1 }}>{total}</div>
          <MiniLabel>Détections</MiniLabel>
          <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
            {blips.map(b => (
              <div key={b.label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <div style={{ width: 8, height: 8, borderRadius: 2, background: b.count > 0 ? `${b.color}30` : "rgba(255,255,255,0.02)", border: `1px solid ${b.count > 0 ? `${b.color}40` : "rgba(255,255,255,0.04)"}` }} />
                <span style={{ fontSize: 15, color: b.count > 0 ? "#777" : "#666", width: 28 }}>{b.label}</span>
                <span style={{ fontSize: 14, fontWeight: 800, color: b.count > 0 ? b.color : "#666", fontFamily: "monospace" }}>{b.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Tile>
  );
}

function FindingsConsole({ critical, high, medium, low, info, total }: FindingsProps) {
  const items = [
    { label: "Critical", count: critical, color: "#d03020", bg: "rgba(208,48,32,0.06)" },
    { label: "High", count: high, color: "#d06020", bg: "rgba(208,96,32,0.05)" },
    { label: "Medium", count: medium, color: "#d09020", bg: "rgba(208,144,32,0.05)" },
    { label: "Low", count: low, color: "#3080d0", bg: "rgba(48,128,208,0.05)" },
    { label: "Info", count: info, color: "#ccc", bg: "rgba(255,255,255,0.02)" },
  ];

  return (
    <Tile
      mesh="radial-gradient(ellipse at 40% 40%, rgba(48,128,208,0.05) 0%, transparent 55%), radial-gradient(ellipse at 70% 70%, rgba(99,102,241,0.03) 0%, transparent 50%)"
      pattern={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px)", backgroundSize: "32px 32px" }}
      accentGlow="rgba(48,128,208,0.03)"
    >
      <TileLabel>3 — Signal Console</TileLabel>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 12 }}>
        <span style={{ fontSize: 36, fontWeight: 900, color: "#f0ece8", letterSpacing: -1, fontFamily: "monospace" }}>{total}</span>
        <MiniLabel>total actifs</MiniLabel>
        {critical > 0 && (
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 4 }}>
            <Led color="#d03020" size={5} pulse />
            <span style={{ fontSize: 16, fontWeight: 700, color: "#d03020" }}>{critical} CRIT</span>
          </div>
        )}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 6 }}>
        {items.map(item => (
          <div key={item.label} style={{
            padding: "16px 10px", borderRadius: 8, textAlign: "center",
            background: item.bg,
            border: `1px solid ${item.count > 0 ? `${item.color}15` : "rgba(255,255,255,0.02)"}`,
            position: "relative", overflow: "hidden",
          }}>
            {/* Bottom accent bar */}
            <div style={{
              position: "absolute", bottom: 0, left: "15%", right: "15%", height: 2,
              background: item.count > 0 ? item.color : "transparent",
              borderRadius: "2px 2px 0 0",
              boxShadow: item.count > 0 ? `0 0 6px ${item.color}40` : "none",
            }} />
            <div style={{ fontSize: 30, fontWeight: 900, color: item.count > 0 ? item.color : "#2a2a2a", lineHeight: 1, fontFamily: "monospace", textShadow: item.count > 0 ? `0 0 10px ${item.color}20` : "none" }}>{item.count}</div>
            <div style={{ fontSize: 14, fontWeight: 700, color: "#bbb", marginTop: 6, letterSpacing: "0.08em" }}>{item.label.toUpperCase()}</div>
          </div>
        ))}
      </div>
    </Tile>
  );
}

// ═══════════════════════════════════════════════════════════════
//  PAGE
// ═══════════════════════════════════════════════════════════════

export default function TestUI() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [findings, setFindings] = useState<FindingCounts>({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  const [situation, setSituation] = useState<{ score: number }>({ score: 0 });

  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = cssAnimations;
    document.head.appendChild(style);
    return () => { document.head.removeChild(style); };
  }, []);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem("tc_token") || "";
        const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
        const [hRes, fRes, sRes] = await Promise.all([
          fetch("/api/tc/health", { headers }).catch(() => null),
          fetch("/api/tc/findings/counts", { headers }).catch(() => null),
          fetch("/api/tc/intelligence/situation", { headers }).catch(() => null),
        ]);
        if (hRes?.ok) setHealth(await hRes.json());
        if (fRes?.ok) {
          const data = await fRes.json();
          setFindings(data);
        }
        if (sRes?.ok) {
          const data = await sRes.json();
          setSituation({ score: data.score ?? data.situation_score ?? 0 });
        }
      } catch { /* fallback to defaults */ }
    };
    fetchData();
    const iv = setInterval(fetchData, 15000);
    return () => clearInterval(iv);
  }, []);

  // Derived data
  const score = situation.score;
  const engineRunning = health?.status === "running";
  const dbConnected = health?.database === true;
  const aiConnected = !!health?.llm && health.llm !== "none" && health.llm !== "";
  const mlAlive = health?.ml?.alive === true;
  const findingsTotal = findings.critical + findings.high + findings.medium + findings.low + findings.info;

  const services: HubService[] = [
    { name: "ThreatClaw", connected: engineRunning, detail: health?.version || "—" },
    { name: "PostgreSQL", connected: dbConnected, detail: "Base de données" },
    { name: "AI / Ollama", connected: aiConnected, detail: health?.llm || "Non configuré" },
    { name: "ML Engine", connected: mlAlive, detail: mlAlive ? `${health?.ml?.data_days ?? 0}j données` : "Inactif" },
    { name: "Disque", connected: true, detail: health?.disk_free || "—" },
  ];

  return (
    <div style={{ maxWidth: 1100, margin: "0 auto", padding: "24px 24px 60px", color: "#f0ece8" }}>
      <div style={{ marginBottom: 8 }}>
        <h1 style={{ fontSize: 20, fontWeight: 800, color: "#f0ece8", letterSpacing: "-0.02em" }}>Dashboard — Test Tuiles V2</h1>
        <p style={{ fontSize: 15, color: "#ccc", marginTop: 4 }}>Sélectionne tes préférées : Score X + Pipeline X + Hub X + Findings X</p>
      </div>

      {/* ─── CPU CARD ─── */}
      <SectionTitle>Processeur Central</SectionTitle>
      <Tile
        mesh="radial-gradient(ellipse at 50% 45%, rgba(208,48,32,0.05) 0%, transparent 60%), radial-gradient(ellipse at 20% 20%, rgba(48,128,208,0.03) 0%, transparent 40%), radial-gradient(ellipse at 80% 80%, rgba(48,160,80,0.03) 0%, transparent 40%)"
        accentGlow="rgba(208,48,32,0.03)"
      >
        <CpuCard
          version={health?.version ? `v${health.version}` : "v1.0.0-beta"}
          services={[
            { name: "PostgreSQL", connected: dbConnected, color: "#3080d0" },
            { name: "AI / Ollama", connected: aiConnected, color: "#9060d0" },
            { name: "Intel. Engine", connected: engineRunning, color: "#d03020" },
            { name: "ML Engine", connected: services.find(s => s.name === "ML Engine")?.connected ?? false, color: "#d09020" },
            { name: "Skills", connected: engineRunning, color: "#06b6d4" },
            { name: "Channels", connected: engineRunning, color: "#30a050" },
            { name: "Wazuh / Logs", connected: dbConnected, color: "#f97316" },
            { name: "Dashboard", connected: true, color: "#b0a8a0" },
          ]}
        />
      </Tile>

      {/* ─── SCORE ─── */}
      <SectionTitle>Score Sécurité</SectionTitle>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <ScoreGauge score={score} engineRunning={engineRunning} lastCycle="il y a 3 min" />
        <ScoreGrid score={score} engineRunning={engineRunning} lastCycle="il y a 3 min" />
      </div>
      <div style={{ marginTop: 16 }}>
        <ScoreTerminal score={score} engineRunning={engineRunning} lastCycle="il y a 3 min" />
      </div>

      {/* ─── PIPELINE ─── */}
      <SectionTitle>Pipeline SOC</SectionTitle>
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <PipelineFlow ie={engineRunning} llm={aiConnected} db={dbConnected} lastCycle="il y a 3 min" findingsCount={findingsTotal} />
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <PipelineRack ie={engineRunning} llm={aiConnected} db={dbConnected} lastCycle="il y a 3 min" findingsCount={findingsTotal} />
          <PipelineCircuit ie={engineRunning} llm={aiConnected} db={dbConnected} lastCycle="il y a 3 min" findingsCount={findingsTotal} />
        </div>
      </div>

      {/* ─── HUB SERVICES ─── */}
      <SectionTitle>Services connectés</SectionTitle>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <HubBoard services={services} />
        <HubConstellation services={services} />
      </div>
      <div style={{ marginTop: 16 }}>
        <HubModules services={services} />
      </div>

      {/* ─── FINDINGS ─── */}
      <SectionTitle>Findings</SectionTitle>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <FindingsSpectrum {...findings} total={findingsTotal} />
        <FindingsRadar {...findings} total={findingsTotal} />
      </div>
      <div style={{ marginTop: 16 }}>
        <FindingsConsole {...findings} total={findingsTotal} />
      </div>
    </div>
  );
}

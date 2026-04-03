"use client";

import React, { useState, useCallback } from "react";

export interface CpuService {
  name: string;
  connected: boolean;
  color: string;
  detail?: string;
  restartable?: boolean;
}

interface CpuCardProps {
  services?: CpuService[];
  version?: string;
  score?: number | null;
  scoreLabel?: string;
  onRestart?: (serviceName: string) => void;
}

/*
  ViewBox: 200x96 — chip 32x32 centered at (100, 48)
  Chip rect: x=84 y=32 w=32 h=32 → center (100, 48)

  4 labels LEFT (textAnchor end, x=17)
  4 labels RIGHT (textAnchor start, x=183)
  Each path exits the chip from a unique edge point
*/

// LEFT column services (top→bottom)
// RIGHT column services (top→bottom)
const defaultServices: CpuService[] = [
  // Left column
  { name: "PostgreSQL",    connected: true,  color: "#3080d0", detail: "Base de données" },
  { name: "Intel. Engine", connected: true,  color: "#d03020", detail: "Corrélation & scoring" },
  { name: "Channels",      connected: true,  color: "#30a050", detail: "Telegram" },
  { name: "Logs",           connected: true,  color: "#f97316", detail: "Syslog + FluentBit" },
  // Right column
  { name: "AI",             connected: true,  color: "#9060d0", detail: "LLM local", restartable: true },
  { name: "ML Engine",     connected: false, color: "#d09020", detail: "Anomaly detection", restartable: true },
  { name: "Skills",        connected: true,  color: "#06b6d4", detail: "49 skills actives" },
  { name: "Dashboard",     connected: true,  color: "#b0a8a0", detail: "Next.js frontend" },
];

// Label Y positions — enough vertical distance for proper double right-angle bends
const LY = [16, 32, 62, 80];

// Endpoint positions
// Top/bottom labels: x=30/170 (cable arrives at block inner edge)
// Middle labels: x=50/150 (closer to chip, shorter horizontal cable)
const endpoints = [
  // Left column — cable arrives at right edge of block
  { x: 30, y: LY[0], ta: "end" as const },
  { x: 50, y: LY[1], ta: "end" as const },
  { x: 50, y: LY[2], ta: "end" as const },
  { x: 30, y: LY[3], ta: "end" as const },
  // Right column — cable arrives at left edge of block
  { x: 170, y: LY[0], ta: "start" as const },
  { x: 150, y: LY[1], ta: "start" as const },
  { x: 150, y: LY[2], ta: "start" as const },
  { x: 170, y: LY[3], ta: "start" as const },
];

// Paths: top labels exit from chip top, bottom from chip bottom, mid from sides
// This ensures NO crossing. Vertical order is preserved.
// Chip edges: left=84, right=116, top=32, bottom=64
// All paths use PCB-style right-angle bends with q 0 R R R radius
// R=4 for all curves — consistent look
// Right angles with small radius (R=2) on every corner
const R = 2;
const pathData = [
  // LEFT column
  `M 91 32 v -${16-R} q 0 -${R} -${R} -${R} h -${61-R}`,
  `M 84 42 h -${17-R} q -${R} 0 -${R} -${R} v -${10-2*R} q 0 -${R} -${R} -${R} h -${17-R}`,
  `M 84 54 h -${17-R} q -${R} 0 -${R} ${R} v ${8-2*R} q 0 ${R} -${R} ${R} h -${17-R}`,
  `M 91 64 v ${16-R} q 0 ${R} -${R} ${R} h -${61-R}`,
  // RIGHT column — mirror
  `M 109 32 v -${16-R} q 0 -${R} ${R} -${R} h ${61-R}`,
  `M 116 42 h ${17-R} q ${R} 0 ${R} -${R} v -${10-2*R} q 0 -${R} ${R} -${R} h ${17-R}`,
  `M 116 54 h ${17-R} q ${R} 0 ${R} ${R} v ${8-2*R} q 0 ${R} ${R} ${R} h ${17-R}`,
  `M 109 64 v ${16-R} q 0 ${R} ${R} ${R} h ${61-R}`,
];

// Gradient colors
const gradIds = [
  "cpu-blue-grad", "cpu-rose-grad", "cpu-green-grad", "cpu-orange-grad",
  "cpu-yellow-grad", "cpu-white-grad", "cpu-cyan-grad", "cpu-pinkish-grad",
];

// Animation config
const anim = [
  { delay: 0,  rev: false },
  { delay: 4,  rev: true },
  { delay: 7,  rev: false },
  { delay: 2,  rev: true },
  { delay: 5,  rev: false },
  { delay: 9,  rev: true },
  { delay: 3,  rev: false },
  { delay: 6,  rev: true },
];

const CYCLE = 11;
const TF = 4 / CYCLE;

// Pin positions — each pin centered on its cable's exit point
// Paths exit at: top (91,32)(109,32), left (84,42)(84,54), right (116,42)(116,54), bottom (91,64)(109,64)
const pins = [
  // Left edge pins (horizontal, cable exits at x=84)
  { x: 80, y: 40.5, w: 4, h: 3 },   // cable 1: y=42, pin center y=42 ✓
  { x: 80, y: 52.5, w: 4, h: 3 },   // cable 2: y=54, pin center y=54 ✓
  // Right edge pins
  { x: 116, y: 40.5, w: 4, h: 3 },  // cable 5: y=42 ✓
  { x: 116, y: 52.5, w: 4, h: 3 },  // cable 6: y=54 ✓
  // Top edge pins (vertical, cable exits at y=32)
  { x: 89.5, y: 28, w: 3, h: 4 },   // cable 0: x=91, pin center x=91 ✓
  { x: 107.5, y: 28, w: 3, h: 4 },  // cable 4: x=109 ✓
  // Bottom edge pins
  { x: 89.5, y: 64, w: 3, h: 4 },   // cable 3: x=91 ✓
  { x: 107.5, y: 64, w: 3, h: 4 },  // cable 7: x=109 ✓
];

export function CpuCard({ services = defaultServices, version, score, scoreLabel, onRestart }: CpuCardProps) {
  const scoreColor = score == null ? "#555" : score >= 80 ? "#30a050" : score >= 50 ? "#d09020" : "#d03020";
  const [sel, setSel] = useState<number | null>(null);
  const click = useCallback((i: number) => setSel(p => p === i ? null : i), []);
  const close = useCallback(() => setSel(null), []);

  const ep = sel !== null ? endpoints[sel] : null;
  const ps = sel !== null ? services[sel] : null;
  let px = 0, py = 0;
  if (ep) {
    px = ep.ta === "end" ? ep.x + 3 : ep.x - 58;
    py = ep.y - 18;
    px = Math.max(2, Math.min(px, 143));
    py = Math.max(2, Math.min(py, 60));
  }

  return (
    <div>
      <svg viewBox="0 0 200 96" style={{ width: "100%", display: "block", color: "var(--tc-text-muted, #7a726c)" }}>
        <defs>
          {/* Path refs for animateMotion */}
          {pathData.map((d, i) => <path key={i} id={`cp${i}`} d={d} fill="none" />)}
          {/* Masks */}
          {pathData.map((d, i) => <mask key={`m${i}`} id={`cm${i}`}><path d={d} strokeWidth="0.6" stroke="white" fill="none" /></mask>)}
          {/* Light gradients */}
          <radialGradient id="cpu-blue-grad" fx="1"><stop offset="0%" stopColor="#00E8ED" /><stop offset="50%" stopColor="#08F" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-yellow-grad" fx="1"><stop offset="0%" stopColor="#FFD800" /><stop offset="50%" stopColor="#FFD800" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-pinkish-grad" fx="1"><stop offset="0%" stopColor="#830CD1" /><stop offset="50%" stopColor="#FF008B" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-white-grad" fx="1"><stop offset="0%" stopColor="white" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-green-grad" fx="1"><stop offset="0%" stopColor="#22c55e" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-orange-grad" fx="1"><stop offset="0%" stopColor="#f97316" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-cyan-grad" fx="1"><stop offset="0%" stopColor="#06b6d4" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-rose-grad" fx="1"><stop offset="0%" stopColor="#f43f5e" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          {/* Reversed gradients (fx=0) for return flux */}
          <radialGradient id="cpu-blue-grad-r" fx="0"><stop offset="0%" stopColor="#00E8ED" /><stop offset="50%" stopColor="#08F" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-yellow-grad-r" fx="0"><stop offset="0%" stopColor="#FFD800" /><stop offset="50%" stopColor="#FFD800" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-pinkish-grad-r" fx="0"><stop offset="0%" stopColor="#830CD1" /><stop offset="50%" stopColor="#FF008B" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-white-grad-r" fx="0"><stop offset="0%" stopColor="white" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-green-grad-r" fx="0"><stop offset="0%" stopColor="#22c55e" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-orange-grad-r" fx="0"><stop offset="0%" stopColor="#f97316" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-cyan-grad-r" fx="0"><stop offset="0%" stopColor="#06b6d4" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          <radialGradient id="cpu-rose-grad-r" fx="0"><stop offset="0%" stopColor="#f43f5e" /><stop offset="100%" stopColor="transparent" /></radialGradient>
          {/* Chip glow */}
          <linearGradient id="chip-glow" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#d03020" /><stop offset="33%" stopColor="#3080d0" /><stop offset="66%" stopColor="#9060d0" /><stop offset="100%" stopColor="#30a050" />
          </linearGradient>
          <filter id="chip-blur" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3" /></filter>
          {/* LED inset filter — shadow for the "creusé" look */}
          <filter id="led-inset" x="-30%" y="-30%" width="160%" height="160%">
            <feDropShadow dx="0" dy="0.4" stdDeviation="0.3" floodColor="black" floodOpacity="0.6" />
            <feDropShadow dx="0" dy="-0.2" stdDeviation="0.15" floodColor="white" floodOpacity="0.06" />
          </filter>
          {/* LED radial gradients — Uiverse style */}
          <radialGradient id="led-green">
            <stop offset="0%" stopColor="hsla(118,100%,90%,1)" />
            <stop offset="15%" stopColor="hsla(118,100%,70%,1)" />
            <stop offset="28%" stopColor="hsla(118,100%,60%,0.3)" />
            <stop offset="70%" stopColor="hsla(118,100%,30%,0)" />
          </radialGradient>
          <radialGradient id="led-red">
            <stop offset="0%" stopColor="hsla(0,100%,90%,1)" />
            <stop offset="15%" stopColor="hsla(0,100%,70%,1)" />
            <stop offset="28%" stopColor="hsla(0,100%,60%,0.3)" />
            <stop offset="70%" stopColor="hsla(0,100%,30%,0)" />
          </radialGradient>
          {/* Engraved/embossed text filter — dark shadow above + light highlight below */}
          <filter id="engrave" x="-15%" y="-15%" width="130%" height="130%">
            {/* Inner shadow (top) — creates the "pressed in" look */}
            <feOffset in="SourceAlpha" dx="0" dy="-0.5" result="shadow-top" />
            <feGaussianBlur in="shadow-top" stdDeviation="0.3" result="shadow-top-blur" />
            <feFlood floodColor="black" floodOpacity="0.7" result="shadow-top-color" />
            <feComposite in="shadow-top-color" in2="shadow-top-blur" operator="in" result="shadow-top-final" />
            {/* Bottom highlight — light catching the edge */}
            <feOffset in="SourceAlpha" dx="0" dy="0.5" result="highlight" />
            <feGaussianBlur in="highlight" stdDeviation="0.2" result="highlight-blur" />
            <feFlood floodColor="white" floodOpacity="0.12" result="highlight-color" />
            <feComposite in="highlight-color" in2="highlight-blur" operator="in" result="highlight-final" />
            {/* Merge: shadow + highlight + original */}
            <feMerge>
              <feMergeNode in="shadow-top-final" />
              <feMergeNode in="highlight-final" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          {/* Pin gradient */}
          <linearGradient id="pin-grad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#4F4F4F" /><stop offset="60%" stopColor="#121214" /></linearGradient>
          {/* Endpoint marker */}
          <marker id="ep-dot" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="14" markerHeight="14">
            <circle cx="5" cy="5" r="2" fill="black" stroke="#232323" strokeWidth="0.5">
              <animate attributeName="r" values="0;3;2" dur="0.5s" />
            </circle>
          </marker>
        </defs>

        {/* ── Traces ── */}
        <g fill="none" strokeWidth="0.3" markerStart="url(#ep-dot)">
          {pathData.map((d, i) => {
            const s = services[i];
            return <path key={i} d={d} stroke={s?.connected ? "currentColor" : "rgba(208,48,32,0.35)"} strokeWidth={s?.connected ? 0.3 : 0.4} />;
          })}
        </g>

        {/* ── Traveling lights ── */}
        {pathData.map((d, i) => {
          const s = services[i];
          if (!s?.connected) return null;
          const a = anim[i];
          const isLeft = i < 4;
          const gradSuffix = isLeft ? (a.rev ? "" : "-r") : (a.rev ? "-r" : "");
          return (
            <g key={`l${i}`} mask={`url(#cm${i})`}>
              <circle r="8" fill={`url(#${gradIds[i]}${gradSuffix})`}>
                <animateMotion dur={`${CYCLE}s`} repeatCount="indefinite" begin={`${a.delay}s`}
                  keyPoints={a.rev ? "1;0;0" : "0;1;1"} keyTimes={`0;${TF.toFixed(3)};1`} calcMode="linear" fill="freeze">
                  <mpath href={`#cp${i}`} />
                </animateMotion>
                <animate attributeName="opacity" dur={`${CYCLE}s`} repeatCount="indefinite" begin={`${a.delay}s`}
                  values="0;0.9;0.9;0;0" keyTimes={`0;0.04;${(TF-0.04).toFixed(3)};${TF.toFixed(3)};1`} fill="freeze" />
              </circle>
            </g>
          );
        })}
        {/* Skills (index 6) — 2nd flux in reverse direction, delayed */}
        {services[6]?.connected && (
          <g mask="url(#cm6)">
            <circle r="8" fill={`url(#${gradIds[6]}-r)`}>
              <animateMotion dur={`${CYCLE}s`} repeatCount="indefinite" begin="8s"
                keyPoints="1;0;0" keyTimes={`0;${TF.toFixed(3)};1`} calcMode="linear" fill="freeze">
                <mpath href="#cp6" />
              </animateMotion>
              <animate attributeName="opacity" dur={`${CYCLE}s`} repeatCount="indefinite" begin="8s"
                values={`0;0.9;0.9;0;0`} keyTimes={`0;0.04;${(TF-0.04).toFixed(3)};${TF.toFixed(3)};1`} fill="freeze" />
            </circle>
          </g>
        )}

        {/* ── Label blocks + LED ── */}
        {endpoints.map((ep, i) => {
          const s = services[i];
          if (!s) return null;
          const dn = !s.connected;
          const isLeft = ep.ta === "end";
          const bw = 28, bh = 8, br = 1.5;
          const bx = isLeft ? ep.x - bw : ep.x;
          const by = ep.y - bh / 2;
          // LED verte = côté mini-card (connexion OK)
          // LED rouge = côté processeur (connexion coupée)
          // Chip exit points per index: 0,3=top/bottom x=91, 1,2=left x=84, 4,7=top/bottom x=109, 5,6=right x=116
          // All red LEDs at exactly 8px from chip edge, on the cable
          const D = 8;
          const chipLedPositions = [
            { x: 91, y: 32 - D },  { x: 84 - D, y: 42 }, { x: 84 - D, y: 54 }, { x: 91, y: 64 + D },
            { x: 109, y: 32 - D }, { x: 116 + D, y: 42 }, { x: 116 + D, y: 54 }, { x: 109, y: 64 + D },
          ];
          const greenLedX = isLeft ? bx + bw + 2.5 : bx - 2.5;
          const ledId = dn ? "led-red" : "led-green";
          return (
            <g key={`e${i}`} onClick={() => click(i)} style={{ cursor: "pointer" }}>
              {/* Bloc uni */}
              <rect x={bx} y={by} width={bw} height={bh} rx={br} fill="#141418" stroke="rgba(255,255,255,0.06)" strokeWidth="0.3" />
              <text x={bx + bw / 2} y={ep.y + 1.2} fill={dn ? "#888" : "#ccc"} fontSize="2.8" fontWeight="600" textAnchor="middle">{s.name}</text>
              {/* LED à 8px du chip, sur le câble */}
              <circle cx={chipLedPositions[i].x} cy={chipLedPositions[i].y} r="2" fill={`url(#${ledId})`} filter="url(#led-inset)" />
            </g>
          );
        })}

        {/* ── Pins with fine border ── */}
        {pins.map((p, i) => (
          <g key={i}>
            <rect x={p.x - 0.3} y={p.y - 0.3} width={p.w + 0.6} height={p.h + 0.6} rx={0.8} fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="0.2" />
            <rect x={p.x} y={p.y} width={p.w} height={p.h} rx={0.5} fill="url(#pin-grad)" />
          </g>
        ))}

        {/* ── Chip (pure SVG, centered at 100,48) ── */}
        <rect x="81" y="29" width="38" height="38" rx="4" fill="none" stroke="url(#chip-glow)" strokeWidth="2" filter="url(#chip-blur)" opacity="0.45" />
        <rect x="83" y="31" width="34" height="34" rx="3" fill="none" stroke="url(#chip-glow)" strokeWidth="0.5" opacity="0.3" />
        <rect x="84" y="32" width="32" height="32" rx="2" fill="#0a0a0f" />
        {/* Brushed aluminium texture */}
        <clipPath id="chip-clip"><rect x="84" y="32" width="32" height="32" rx="2" /></clipPath>
        <image href="/textures/brushed-alum.png" x="84" y="32" width="32" height="32" clipPath="url(#chip-clip)" opacity="0.06" style={{ mixBlendMode: "overlay" }} preserveAspectRatio="none" />
        <rect x="85.5" y="33.5" width="29" height="29" rx="1.5" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="0.3" />
        {/* "SCORE SÉCURITÉ" title */}
        <text x="100" y="38" fontSize="2.8" fill="#888" fontWeight="700" textAnchor="middle" letterSpacing="0.1em">SCORE SÉCURITÉ</text>
        {/* Score engraved */}
        <text x="100" y="52" fontSize="11" fill={scoreColor} fontWeight="900" textAnchor="middle" dominantBaseline="middle" filter="url(#engrave)">{score != null ? Math.round(score) : "—"}</text>
        {scoreLabel && <text x="100" y="60" fontSize="2.2" fill={scoreColor} fontWeight="600" textAnchor="middle" opacity="0.7">{scoreLabel}</text>}

        {/* ── Popup ── */}
        {sel !== null && ps && ep && (
          <foreignObject x={px} y={py} width="55" height="36" style={{ overflow: "visible" }}>
            <div style={{
              background: "linear-gradient(165deg, #1a1a24, #111118)",
              border: `1px solid ${ps.connected ? ps.color + "40" : "rgba(208,48,32,0.3)"}`,
              borderRadius: 3, padding: "3px 4px",
              boxShadow: "0 4px 12px rgba(0,0,0,0.6)",
              color: "#e0e0e0",
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 2 }}>
                <span style={{ fontWeight: 700, fontSize: 3, color: ps.connected ? "#f0ece8" : "#d03020" }}>{ps.name}</span>
                <span onClick={close} style={{ cursor: "pointer", color: "#666", fontSize: 4, lineHeight: 1 }}>✕</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 1.5, marginBottom: 1.5 }}>
                <div style={{ width: 2, height: 2, borderRadius: "50%", background: ps.connected ? "#30a050" : "#d03020" }} />
                <span style={{ fontSize: 2.5, color: ps.connected ? "#30a050" : "#d03020", fontWeight: 600 }}>{ps.connected ? "Opérationnel" : "Hors ligne"}</span>
              </div>
              {ps.detail && <div style={{ fontSize: 2.5, color: "#999", marginBottom: 2 }}>{ps.detail}</div>}
              {ps.restartable && onRestart && (
                <button onClick={(e) => { e.stopPropagation(); onRestart(ps.name); }} style={{
                  width: "100%", padding: "1px 0", borderRadius: 2, border: "none", cursor: "pointer",
                  background: ps.connected ? "rgba(255,255,255,0.05)" : "rgba(208,48,32,0.15)",
                  color: ps.connected ? "#bbb" : "#d03020", fontSize: 2.5, fontWeight: 700, fontFamily: "inherit",
                }}>{ps.connected ? "⟳ Redémarrer" : "▶ Démarrer"}</button>
              )}
            </div>
          </foreignObject>
        )}
      </svg>
    </div>
  );
}

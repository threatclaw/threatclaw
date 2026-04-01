"use client";

import React from "react";
import { Zap, Clock, Thermometer, Activity, Settings, Wifi, Battery, ChevronRight, Grid3X3, Bell } from "lucide-react";

// ── Sankey Flow Component ──
function SankeyFlow() {
  const ports = [
    { label: "Main AC", value: 30, unit: "KWH", active: true },
    { label: "Sec AC", value: 0, unit: "KWH", active: false },
    { label: "USB-C", value: 0, unit: "KWH", active: false },
    { label: "USB-C", value: 8, unit: "KWH", active: true },
    { label: "USB-A", value: 0, unit: "KWH", active: false },
  ];

  const startX = 180;
  const startY = 160;
  const endX = 520;
  const spacing = 50;
  const startOffset = -(ports.length - 1) * spacing / 2;

  return (
    <svg width="100%" height="320" viewBox="0 0 600 320" style={{ overflow: "visible" }}>
      <defs>
        <linearGradient id="flowGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#F97316" stopOpacity="0.8" />
          <stop offset="100%" stopColor="#F97316" stopOpacity="0.3" />
        </linearGradient>
        <linearGradient id="flowGradInactive" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#3a3a3a" stopOpacity="0.5" />
          <stop offset="100%" stopColor="#2a2a2a" stopOpacity="0.2" />
        </linearGradient>
      </defs>

      {/* Flow paths */}
      {ports.map((port, i) => {
        const endY = startOffset + startY + i * spacing;
        const color = port.active ? "url(#flowGrad)" : "url(#flowGradInactive)";
        const strokeW = port.active ? Math.max(3, port.value / 5) : 2;
        const midX1 = startX + 100;
        const midX2 = endX - 80;

        return (
          <g key={i}>
            <path
              d={`M${startX},${startY} C${midX1},${startY} ${midX2},${endY} ${endX},${endY}`}
              fill="none" stroke={color} strokeWidth={strokeW}
              strokeLinecap="round" opacity={port.active ? 1 : 0.4}
            >
              {port.active && (
                <animate attributeName="stroke-dashoffset" from="40" to="0" dur="1.5s" repeatCount="indefinite" />
              )}
            </path>
            {port.active && (
              <path
                d={`M${startX},${startY} C${midX1},${startY} ${midX2},${endY} ${endX},${endY}`}
                fill="none" stroke="#F97316" strokeWidth={strokeW}
                strokeDasharray="8 32" strokeLinecap="round" opacity={0.6}
              >
                <animate attributeName="stroke-dashoffset" from="40" to="0" dur="1.5s" repeatCount="indefinite" />
              </path>
            )}

            {/* Port label */}
            <text x={endX + 12} y={endY + 4} fill={port.active ? "#F97316" : "#4a4a4a"} fontSize="11" fontWeight="600">
              {port.label}
            </text>
            <text x={endX + 12} y={endY + 18} fill={port.active ? "#fff" : "#3a3a3a"} fontSize="10" fontWeight="400">
              {port.value} {port.unit}
            </text>
          </g>
        );
      })}

      {/* Center hub */}
      <circle cx={startX} cy={startY} r="28" fill="#1a1a1e" stroke="#F97316" strokeWidth="2.5" />
      <circle cx={startX} cy={startY} r="20" fill="rgba(249,115,22,0.15)" />
      <Zap x={startX - 8} y={startY - 8} width={16} height={16} color="#F97316" />
      {/* Zap icon approximation */}
      <polygon points={`${startX - 5},${startY - 8} ${startX + 2},${startY - 1} ${startX - 1},${startY + 1} ${startX + 5},${startY + 8} ${startX - 2},${startY + 1} ${startX + 1},${startY - 1}`} fill="#F97316" />

      {/* Output label */}
      <rect x="40" y={startY - 16} width="110" height="32" rx="8" fill="rgba(249,115,22,0.12)" stroke="rgba(249,115,22,0.3)" strokeWidth="1" />
      <text x="56" y={startY - 1} fill="#F97316" fontSize="10" fontWeight="700" textAnchor="start">OUTPUT</text>
      <text x="56" y={startY + 12} fill="#fff" fontSize="11" fontWeight="800" textAnchor="start">38 KWH</text>
      <polygon points={`${150 + 4},${startY} ${150 - 4},${startY - 5} ${150 - 4},${startY + 5}`} fill="#F97316" />
    </svg>
  );
}

// ── Gauge Component ──
function Gauge({ value }: { value: number }) {
  const radius = 80;
  const strokeWidth = 10;
  const circumference = Math.PI * radius;
  const progress = (value / 100) * circumference;

  return (
    <div style={{ position: "relative", width: 200, height: 120, margin: "0 auto" }}>
      <svg width="200" height="120" viewBox="0 0 200 120">
        <defs>
          <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#3a3a3a" />
            <stop offset="50%" stopColor="#F97316" />
            <stop offset="100%" stopColor="#EA580C" />
          </linearGradient>
        </defs>
        {/* Background arc */}
        <path
          d={`M ${100 - radius} 105 A ${radius} ${radius} 0 0 1 ${100 + radius} 105`}
          fill="none" stroke="#1a1a1e" strokeWidth={strokeWidth} strokeLinecap="round"
        />
        {/* Value arc */}
        <path
          d={`M ${100 - radius} 105 A ${radius} ${radius} 0 0 1 ${100 + radius} 105`}
          fill="none" stroke="url(#gaugeGrad)" strokeWidth={strokeWidth} strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference}`}
        />
        {/* Tick marks */}
        {[0, 25, 50, 75, 100].map((tick) => {
          const angle = Math.PI - (tick / 100) * Math.PI;
          const x1 = 100 + (radius + 8) * Math.cos(angle);
          const y1 = 105 - (radius + 8) * Math.sin(angle);
          const x2 = 100 + (radius + 14) * Math.cos(angle);
          const y2 = 105 - (radius + 14) * Math.sin(angle);
          return <line key={tick} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#4a4a4a" strokeWidth="1.5" />;
        })}
      </svg>
      <div style={{ position: "absolute", bottom: 10, left: "50%", transform: "translateX(-50%)", textAlign: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, justifyContent: "center" }}>
          <Battery size={16} color="#F97316" />
          <span style={{ fontSize: 36, fontWeight: 900, color: "#fff", letterSpacing: -2 }}>{value}%</span>
        </div>
      </div>
    </div>
  );
}

// ── Volt Display Grid ──
function VoltGrid() {
  const dots: { x: number; y: number; active: boolean }[] = [];
  for (let row = 0; row < 6; row++) {
    for (let col = 0; col < 8; col++) {
      const active = Math.random() > 0.6;
      dots.push({ x: 20 + col * 28, y: 16 + row * 22, active });
    }
  }

  return (
    <svg width="100%" height="140" viewBox="0 0 240 140">
      {dots.map((d, i) => (
        <circle key={i} cx={d.x} cy={d.y} r={d.active ? 3 : 1.5}
          fill={d.active ? "#F97316" : "#2a2a2a"}
          opacity={d.active ? 0.8 : 0.4}
        >
          {d.active && (
            <animate attributeName="opacity" values="0.4;0.9;0.4" dur={`${2 + Math.random() * 2}s`} repeatCount="indefinite" />
          )}
        </circle>
      ))}
    </svg>
  );
}

// ── Knob Component ──
function Knob() {
  return (
    <svg width="60" height="60" viewBox="0 0 60 60">
      <defs>
        <radialGradient id="knobGrad">
          <stop offset="0%" stopColor="#2a2a2e" />
          <stop offset="100%" stopColor="#1a1a1e" />
        </radialGradient>
      </defs>
      <circle cx="30" cy="30" r="28" fill="url(#knobGrad)" stroke="#3a3a3a" strokeWidth="1.5" />
      <circle cx="30" cy="30" r="22" fill="none" stroke="#2a2a2a" strokeWidth="1" />
      {/* Notches */}
      {Array.from({ length: 12 }).map((_, i) => {
        const angle = (i * 30 * Math.PI) / 180;
        const x1 = 30 + 24 * Math.cos(angle);
        const y1 = 30 + 24 * Math.sin(angle);
        const x2 = 30 + 27 * Math.cos(angle);
        const y2 = 30 + 27 * Math.sin(angle);
        return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#4a4a4a" strokeWidth="1" />;
      })}
      {/* Indicator */}
      <line x1="30" y1="30" x2="30" y2="12" stroke="#F97316" strokeWidth="2" strokeLinecap="round" />
      <circle cx="30" cy="30" r="4" fill="#F97316" />
    </svg>
  );
}

// ── Toggle Component ──
function Toggle({ on }: { on: boolean }) {
  return (
    <div style={{
      width: 44, height: 24, borderRadius: 12,
      background: on ? "#F97316" : "#2a2a2e",
      border: `1px solid ${on ? "#EA580C" : "#3a3a3a"}`,
      position: "relative", cursor: "pointer", transition: "all 0.2s",
    }}>
      <div style={{
        width: 18, height: 18, borderRadius: "50%",
        background: "#fff",
        position: "absolute", top: 2,
        left: on ? 22 : 2,
        transition: "left 0.2s",
        boxShadow: "0 1px 3px rgba(0,0,0,0.3)",
      }} />
    </div>
  );
}

// ── Main Page ──
export default function TestUIPage() {
  return (
    <div style={{
      minHeight: "100vh",
      background: "#0D0D0F",
      color: "#fff",
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Inter', sans-serif",
    }}>
      {/* ── Navbar ── */}
      <nav style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "14px 32px",
        borderBottom: "1px solid rgba(255,255,255,0.06)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{
              width: 28, height: 28, borderRadius: 6,
              background: "linear-gradient(135deg, #F97316, #EA580C)",
              display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <Zap size={14} color="#fff" />
            </div>
            <span style={{ fontSize: 14, fontWeight: 800, letterSpacing: "0.15em", textTransform: "uppercase" }}>Phoenix</span>
          </div>
          <div style={{ display: "flex", gap: 24 }}>
            {["Dashboard", "Statistics", "Support", "Settings"].map((item, i) => (
              <span key={item} style={{
                fontSize: 11, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase",
                color: i === 0 ? "#F97316" : "#6B7280", cursor: "pointer",
                borderBottom: i === 0 ? "2px solid #F97316" : "none", paddingBottom: 2,
              }}>{item}</span>
            ))}
          </div>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <Grid3X3 size={16} color="#6B7280" style={{ cursor: "pointer" }} />
          <Bell size={16} color="#6B7280" style={{ cursor: "pointer" }} />
        </div>
      </nav>

      {/* ── Content ── */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16, padding: "24px 32px", maxWidth: 1200, margin: "0 auto" }}>

        {/* ═══ CARD 1 — ENERGY FLOW ═══ */}
        <div style={{
          background: "#141418", border: "1px solid rgba(255,255,255,0.06)",
          borderRadius: 16, padding: "28px 24px", position: "relative", gridRow: "1",
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
            <div>
              <h1 style={{ fontSize: 32, fontWeight: 900, letterSpacing: -1, margin: 0, lineHeight: 1 }}>ENERGY</h1>
              <h1 style={{ fontSize: 32, fontWeight: 900, letterSpacing: -1, margin: 0, lineHeight: 1 }}>FLOW</h1>
            </div>
            <button style={{
              background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 8, padding: "6px 14px", color: "#6B7280", fontSize: 11, fontWeight: 600,
              cursor: "pointer", letterSpacing: "0.05em",
            }}>ADD PORT +</button>
          </div>

          <SankeyFlow />

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 16 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 28, fontWeight: 900, color: "#fff" }}>12</span>
              <span style={{ fontSize: 11, color: "#6B7280", fontWeight: 600 }}>HR</span>
              <span style={{ fontSize: 11, color: "#6B7280", lineHeight: 1.2 }}>BATTERY<br />LIFE</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <svg width="60" height="20" viewBox="0 0 60 20">
                <path d="M0,10 Q15,2 30,10 Q45,18 60,10" fill="none" stroke="#F97316" strokeWidth="2" />
                <circle cx="45" cy="12" r="3" fill="#F97316" />
              </svg>
              <span style={{ fontSize: 11, color: "#6B7280", fontWeight: 600, textTransform: "uppercase" }}>Medium Load</span>
            </div>
          </div>
        </div>

        {/* ═══ CARD 2 — ZEUS-X ═══ */}
        <div style={{
          background: "linear-gradient(180deg, #1a1a22 0%, #141418 40%, #0a0a0f 100%)",
          border: "1px solid rgba(255,255,255,0.06)",
          borderRadius: 16, padding: "28px 24px", position: "relative",
          overflow: "hidden", gridRow: "1",
        }}>
          {/* Dramatic gradient overlay */}
          <div style={{
            position: "absolute", top: 0, left: 0, right: 0, height: "60%",
            background: "radial-gradient(ellipse at 50% 20%, rgba(249,115,22,0.08) 0%, transparent 60%)",
          }} />

          <div style={{ position: "relative", zIndex: 1 }}>
            <h2 style={{ fontSize: 36, fontWeight: 900, letterSpacing: 2, margin: "0 0 8px" }}>ZEUS-X</h2>
            <span style={{
              background: "rgba(249,115,22,0.15)", border: "1px solid rgba(249,115,22,0.3)",
              borderRadius: 20, padding: "4px 12px", fontSize: 10, fontWeight: 600, color: "#F97316",
            }}>X-boost mode</span>
          </div>

          {/* Device silhouette area */}
          <div style={{
            height: 140, display: "flex", alignItems: "center", justifyContent: "center",
            position: "relative", margin: "24px 0",
          }}>
            <div style={{
              width: 100, height: 100, borderRadius: "50%",
              background: "radial-gradient(circle, rgba(249,115,22,0.06) 0%, transparent 70%)",
              border: "1px solid rgba(249,115,22,0.1)",
              display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <Zap size={32} color="#F97316" />
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", position: "relative", zIndex: 1 }}>
            <div>
              <span style={{ fontSize: 10, color: "#6B7280", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.1em" }}>POWER</span>
              <div style={{ marginTop: 8 }}>
                <Knob />
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <Toggle on={true} />
              <span style={{ fontSize: 12, fontWeight: 700, color: "#F97316" }}>ON</span>
            </div>
          </div>
        </div>

        {/* ═══ ROW 2 — DETAILS + CABLE + VOLT + CHARGING ═══ */}

        {/* CARD 3 — DETAILS */}
        <div style={{
          background: "#1C1C20", border: "1px solid rgba(255,255,255,0.06)",
          borderRadius: 16, padding: "20px 24px", gridColumn: "1",
        }}>
          <h3 style={{ fontSize: 14, fontWeight: 800, letterSpacing: "0.1em", textAlign: "center", margin: "0 0 16px", textTransform: "uppercase", color: "#6B7280" }}>Details</h3>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            {[
              { icon: <Zap size={14} color="#F97316" />, label: "Mode", value: "X-BOOST" },
              { icon: <Clock size={14} color="#6B7280" />, label: "Time", value: "3H 15M" },
              { icon: <Activity size={14} color="#6B7280" />, label: "Frequency", value: "50 HZ" },
              { icon: <Thermometer size={14} color="#6B7280" />, label: "Temp", value: "30°C" },
              { icon: <Activity size={14} color="#6B7280" />, label: "Ampere", value: "600A" },
              { icon: <Settings size={14} color="#6B7280" />, label: "Current", value: "10A" },
            ].map((m, i) => (
              <div key={i} style={{
                background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: "12px",
                border: "1px solid rgba(255,255,255,0.04)",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                  {m.icon}
                  <span style={{ fontSize: 9, color: "#6B7280", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em" }}>{m.label}</span>
                </div>
                <span style={{ fontSize: 16, fontWeight: 800, color: "#fff" }}>{m.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Right column row 2 — CHARGING MODE */}
        <div style={{
          background: "#141418", border: "1px solid rgba(255,255,255,0.06)",
          borderRadius: 16, padding: "24px", gridColumn: "2",
        }}>
          <h3 style={{ fontSize: 12, fontWeight: 800, letterSpacing: "0.1em", textTransform: "uppercase", color: "#6B7280", margin: "0 0 16px" }}>Charging Mode</h3>
          <Gauge value={74} />
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 16, padding: "0 8px" }}>
            <div>
              <span style={{ fontSize: 9, color: "#6B7280", fontWeight: 600, display: "block" }}>Power</span>
              <span style={{ fontSize: 13, fontWeight: 700, color: "#fff" }}>5A / 220V</span>
            </div>
            <div style={{ textAlign: "right" }}>
              <span style={{ fontSize: 9, color: "#6B7280", fontWeight: 600, display: "block" }}>Input</span>
              <span style={{ fontSize: 13, fontWeight: 700, color: "#fff" }}>200 KWH</span>
            </div>
          </div>
        </div>

        {/* ═══ ROW 3 — CABLE + VOLT ═══ */}

        {/* CARD 4 — CABLE */}
        <div style={{
          display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, gridColumn: "1",
        }}>
          <div style={{
            background: "#141418", border: "1px solid rgba(249,115,22,0.15)",
            borderRadius: 16, padding: "20px", textAlign: "center",
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
              <span style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>&Omega; 15</span>
              <span style={{ fontSize: 11, color: "#6B7280" }}>1w</span>
            </div>
            <div style={{
              width: 80, height: 80, margin: "0 auto 16px",
              borderRadius: "50%", border: "2px solid rgba(249,115,22,0.3)",
              display: "flex", alignItems: "center", justifyContent: "center",
              background: "radial-gradient(circle, rgba(249,115,22,0.08) 0%, transparent 70%)",
            }}>
              <Wifi size={24} color="#F97316" />
            </div>
            <div style={{ fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>
              Flash Mode Cabel
            </div>
            <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 8 }}>
              <Toggle on={true} />
              <span style={{ fontSize: 11, fontWeight: 700, color: "#F97316" }}>ON</span>
            </div>
          </div>

          {/* CARD 5 — VOLT DISPLAY */}
          <div style={{
            background: "#0e0e12", border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: 16, padding: "20px", position: "relative", overflow: "hidden",
          }}>
            <div style={{ position: "absolute", inset: 0, opacity: 0.4 }}>
              <VoltGrid />
            </div>
            <div style={{ position: "relative", zIndex: 1, textAlign: "center", paddingTop: 30 }}>
              <div style={{ fontSize: 48, fontWeight: 900, color: "#fff", letterSpacing: -2, lineHeight: 1 }}>23.8</div>
              <div style={{ fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase", letterSpacing: "0.15em", marginTop: 8 }}>
                Volt Display
              </div>
              <div style={{
                display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 20,
                fontSize: 10, color: "#6B7280",
              }}>
                <span>AC 23.8V / DC 14V</span>
                <span style={{ display: "flex", alignItems: "center", gap: 2, color: "#F97316", cursor: "pointer", fontWeight: 600 }}>
                  Details <ChevronRight size={12} />
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

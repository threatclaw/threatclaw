"use client";

import React, { useEffect, useState } from "react";

// ── Types ──
interface HealthData {
  status: string;
  version: string;
  database: boolean;
  llm: string;
  disk_free: string;
  ml?: { alive: boolean; model_trained: boolean; data_days: number };
}

interface ServiceNode {
  id: string;
  label: string;
  status: "online" | "offline" | "degraded";
  detail: string;
  angle: number; // position around the hub
}

// ── Card Component (Phoenix style) ──
function Card({ children, style, gradient }: { children: React.ReactNode; style?: React.CSSProperties; gradient?: string }) {
  return (
    <div style={{
      background: gradient || "#141418",
      border: "1px solid rgba(255,255,255,0.06)",
      borderRadius: 16,
      padding: "20px",
      position: "relative",
      overflow: "hidden",
      ...style,
    }}>
      {children}
    </div>
  );
}

// ── Label ──
function Label({ children }: { children: React.ReactNode }) {
  return (
    <span style={{ fontSize: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.1em", color: "rgba(255,255,255,0.35)" }}>
      {children}
    </span>
  );
}

// ── Metric ──
function Metric({ value, unit, color }: { value: string; unit?: string; color?: string }) {
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: 4, marginTop: 8 }}>
      <span style={{ fontSize: 32, fontWeight: 800, color: color || "#e8e4e0", letterSpacing: -1 }}>{value}</span>
      {unit && <span style={{ fontSize: 13, color: "rgba(255,255,255,0.4)" }}>{unit}</span>}
    </div>
  );
}

// ── Status Dot ──
function StatusDot({ status }: { status: "online" | "offline" | "degraded" }) {
  const color = status === "online" ? "#30a050" : status === "degraded" ? "#d09020" : "#d03020";
  return (
    <span style={{
      width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block",
      boxShadow: `0 0 6px ${color}`,
      animation: status === "online" ? "pulse 2s ease-in-out infinite" : undefined,
    }} />
  );
}

// ── Hub Processor Visualization ──
function HubProcessor({ services }: { services: ServiceNode[] }) {
  const size = 320;
  const center = size / 2;
  const hubRadius = 32;
  const nodeRadius = 140;

  return (
    <div style={{ position: "relative", width: size, height: size, margin: "0 auto" }}>
      <svg width={size} height={size} style={{ position: "absolute", top: 0, left: 0 }}>
        {/* Connection lines */}
        {services.map((s) => {
          const rad = (s.angle * Math.PI) / 180;
          const x = center + nodeRadius * Math.cos(rad);
          const y = center + nodeRadius * Math.sin(rad);
          const color = s.status === "online" ? "#30a050" : s.status === "degraded" ? "#d09020" : "#d03020";
          return (
            <g key={s.id}>
              {/* Line from hub to node */}
              <line
                x1={center} y1={center} x2={x} y2={y}
                stroke={color} strokeWidth={2} opacity={0.6}
                strokeDasharray={s.status === "offline" ? "4,4" : "none"}
              />
              {/* Animated pulse on line */}
              {s.status === "online" && (
                <circle r={3} fill={color} opacity={0.8}>
                  <animateMotion dur="2s" repeatCount="indefinite"
                    path={`M${center},${center} L${x},${y}`} />
                </circle>
              )}
            </g>
          );
        })}

        {/* Hub center glow */}
        <defs>
          <radialGradient id="hubGlow">
            <stop offset="0%" stopColor="#d03020" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#d03020" stopOpacity="0" />
          </radialGradient>
        </defs>
        <circle cx={center} cy={center} r={hubRadius + 20} fill="url(#hubGlow)" />

        {/* Hub center */}
        <circle cx={center} cy={center} r={hubRadius} fill="#1a1a20" stroke="#d03020" strokeWidth={2} />
        <circle cx={center} cy={center} r={hubRadius - 6} fill="none" stroke="rgba(208,48,32,0.3)" strokeWidth={1} />

        {/* TC text in hub */}
        <text x={center} y={center + 1} textAnchor="middle" dominantBaseline="middle"
          fill="#d03020" fontSize={14} fontWeight={800} letterSpacing="0.1em">TC</text>
      </svg>

      {/* Service nodes */}
      {services.map((s) => {
        const rad = (s.angle * Math.PI) / 180;
        const x = center + nodeRadius * Math.cos(rad) - 44;
        const y = center + nodeRadius * Math.sin(rad) - 22;
        const color = s.status === "online" ? "#30a050" : s.status === "degraded" ? "#d09020" : "#d03020";
        const bgColor = s.status === "online" ? "rgba(48,160,80,0.08)" : s.status === "degraded" ? "rgba(208,144,32,0.08)" : "rgba(208,48,32,0.08)";

        return (
          <div key={s.id} style={{
            position: "absolute", left: x, top: y,
            width: 88, padding: "6px 8px",
            background: bgColor,
            border: `1px solid ${color}33`,
            borderRadius: 10,
            textAlign: "center",
          }}>
            <div style={{ fontSize: 9, fontWeight: 700, color, textTransform: "uppercase", letterSpacing: "0.05em" }}>
              {s.label}
            </div>
            <div style={{ fontSize: 8, color: "rgba(255,255,255,0.4)", marginTop: 2 }}>
              {s.detail}
            </div>
          </div>
        );
      })}

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 0.6; }
          50% { opacity: 1; }
        }
      `}</style>
    </div>
  );
}

// ── Main Page ──
export default function TestUIPage() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [ollamaModels, setOllamaModels] = useState<string[]>([]);
  const [score, setScore] = useState<number | null>(null);
  const [findings, setFindings] = useState<{ critical: number; high: number; medium: number; low: number }>({ critical: 0, high: 0, medium: 0, low: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch("/api/tc/health").then(r => r.json()).catch(() => null),
      fetch("/api/ollama").then(r => r.json()).catch(() => ({ models: [] })),
      fetch("/api/tc/findings/counts").then(r => r.json()).catch(() => ({})),
    ]).then(([h, o, f]) => {
      setHealth(h);
      setOllamaModels((o?.models || []).map((m: any) => m.name));
      if (f) setFindings({ critical: f.CRITICAL || 0, high: f.HIGH || 0, medium: f.MEDIUM || 0, low: f.LOW || 0 });
      if (h?.ml?.alive) setScore(100);
      setLoading(false);
    });
  }, []);

  const dbOk = health?.database === true;
  const aiOk = ollamaModels.length > 0;
  const engineOk = health?.status === "ok" || health?.status === "healthy";
  const mlOk = health?.ml?.alive === true;
  const mlTrained = health?.ml?.model_trained === true;

  const services: ServiceNode[] = [
    { id: "db", label: "Database", status: dbOk ? "online" : "offline", detail: dbOk ? "PG16 + AGE" : "Down", angle: -90 },
    { id: "ai", label: "AI Models", status: aiOk ? "online" : "offline", detail: aiOk ? `${ollamaModels.length} models` : "No models", angle: -30 },
    { id: "engine", label: "Engine", status: engineOk ? "online" : "offline", detail: engineOk ? "Cycle 5min" : "Stopped", angle: 30 },
    { id: "ml", label: "ML", status: mlOk ? (mlTrained ? "online" : "degraded") : "offline", detail: mlOk ? (mlTrained ? "Trained" : `${health?.ml?.data_days || 0}d data`) : "Down", angle: 90 },
    { id: "graph", label: "Graph", status: dbOk ? "online" : "offline", detail: "STIX 2.1", angle: 150 },
    { id: "notif", label: "Telegram", status: engineOk ? "online" : "offline", detail: "HITL", angle: 210 },
  ];

  const totalFindings = findings.critical + findings.high + findings.medium + findings.low;

  return (
    <div style={{
      minHeight: "100vh",
      background: "#0e0e12",
      color: "#e8e4e0",
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Inter', sans-serif",
      padding: "0",
    }}>
      {/* Header */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "16px 32px",
        borderBottom: "1px solid rgba(255,255,255,0.06)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: "linear-gradient(135deg, #d03020, #a01810)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 14, fontWeight: 900, color: "#fff",
          }}>TC</div>
          <span style={{ fontSize: 15, fontWeight: 800, letterSpacing: "0.12em" }}>
            <span style={{ color: "#e8e4e0" }}>THREAT</span>
            <span style={{ color: "#d03020" }}>CLAW</span>
          </span>
        </div>
        <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", letterSpacing: "0.05em" }}>
          TEST UI — {health?.version || "..."}
        </div>
      </div>

      {/* Content */}
      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "24px 32px" }}>

        {/* Top row — Score + Status cards */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 16, marginBottom: 24 }}>

          {/* Score */}
          <Card gradient="linear-gradient(135deg, #141418 0%, #1a1018 100%)">
            <Label>Score securite</Label>
            <Metric
              value={loading ? "..." : engineOk ? "100" : "--"}
              color={engineOk ? "#30a050" : "#7a726c"}
            />
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", marginTop: 4 }}>
              {engineOk ? "Situation stable" : "En attente"}
            </div>
          </Card>

          {/* Engine */}
          <Card>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <Label>Engine</Label>
              <StatusDot status={engineOk ? "online" : "offline"} />
            </div>
            <div style={{ fontSize: 18, fontWeight: 700, marginTop: 10, color: engineOk ? "#30a050" : "#d03020" }}>
              {engineOk ? "Operationnel" : "Arrete"}
            </div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", marginTop: 4 }}>
              v{health?.version || "..."} — Cycle 5 min
            </div>
          </Card>

          {/* AI */}
          <Card>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <Label>IA Models</Label>
              <StatusDot status={aiOk ? "online" : "offline"} />
            </div>
            <div style={{ fontSize: 18, fontWeight: 700, marginTop: 10, color: aiOk ? "#30a050" : "#d03020" }}>
              {aiOk ? `${ollamaModels.length} charges` : "Non accessible"}
            </div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", marginTop: 4 }}>
              {ollamaModels.filter(m => m.includes("l1") || m.includes("l2")).length > 0 ? "L1 + L2 ready" : "..."}
            </div>
          </Card>

          {/* Database */}
          <Card>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <Label>Base de donnees</Label>
              <StatusDot status={dbOk ? "online" : "offline"} />
            </div>
            <div style={{ fontSize: 18, fontWeight: 700, marginTop: 10, color: dbOk ? "#30a050" : "#d03020" }}>
              {dbOk ? "Connectee" : "Deconnectee"}
            </div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", marginTop: 4 }}>
              PG16 + AGE + TimescaleDB
            </div>
          </Card>
        </div>

        {/* Middle row — Hub + Findings */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>

          {/* Hub Processor */}
          <Card style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "24px 16px" }}
                gradient="linear-gradient(180deg, #141418 0%, #10101a 100%)">
            <Label>Connexions services</Label>
            <div style={{ marginTop: 16 }}>
              <HubProcessor services={services} />
            </div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.25)", marginTop: 8 }}>
              {services.filter(s => s.status === "online").length}/{services.length} services connectes
            </div>
          </Card>

          {/* Findings */}
          <div style={{ display: "grid", gridTemplateRows: "1fr 1fr", gap: 16 }}>

            <Card gradient="linear-gradient(135deg, #141418 0%, #181418 100%)">
              <Label>Detections</Label>
              <Metric value={loading ? "..." : String(totalFindings)} />
              <div style={{ display: "flex", gap: 12, marginTop: 12 }}>
                {[
                  { label: "CRITICAL", count: findings.critical, color: "#d03020" },
                  { label: "HIGH", count: findings.high, color: "#d09020" },
                  { label: "MEDIUM", count: findings.medium, color: "#3080d0" },
                  { label: "LOW", count: findings.low, color: "#7a726c" },
                ].map(f => (
                  <div key={f.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <span style={{ width: 6, height: 6, borderRadius: 2, background: f.color }} />
                    <span style={{ fontSize: 10, color: "rgba(255,255,255,0.5)" }}>{f.count}</span>
                  </div>
                ))}
              </div>
            </Card>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {/* ML */}
              <Card>
                <Label>ML Engine</Label>
                <div style={{ fontSize: 16, fontWeight: 700, marginTop: 8, color: mlOk ? (mlTrained ? "#30a050" : "#d09020") : "#d03020" }}>
                  {mlOk ? (mlTrained ? "Entraine" : "Apprentissage") : "Inactif"}
                </div>
                <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", marginTop: 4 }}>
                  {health?.ml?.data_days || 0}j de donnees
                </div>
              </Card>

              {/* Disk */}
              <Card>
                <Label>Disque</Label>
                <div style={{ fontSize: 16, fontWeight: 700, marginTop: 8, color: "#e8e4e0" }}>
                  {health?.disk_free || "..."}
                </div>
                <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", marginTop: 4 }}>
                  disponible
                </div>
              </Card>
            </div>

          </div>
        </div>

        {/* Bottom row — quick info */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16 }}>
          <Card>
            <Label>Intelligence Engine</Label>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 8 }}>
              <StatusDot status={engineOk ? "online" : "offline"} />
              <span style={{ fontSize: 12, color: "rgba(255,255,255,0.6)" }}>
                Agent autonome — Cycle toutes les 5 min
              </span>
            </div>
          </Card>

          <Card>
            <Label>Enrichissement</Label>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 8 }}>
              <span style={{ fontSize: 22, fontWeight: 800, color: "#d03020" }}>26</span>
              <span style={{ fontSize: 12, color: "rgba(255,255,255,0.4)" }}>sources actives</span>
            </div>
          </Card>

          <Card>
            <Label>Graph Intelligence</Label>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 8 }}>
              <span style={{ fontSize: 12, color: "rgba(255,255,255,0.6)" }}>
                STIX 2.1 — Apache AGE
              </span>
            </div>
          </Card>
        </div>

      </div>
    </div>
  );
}

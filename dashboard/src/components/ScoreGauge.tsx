"use client";

import React from "react";

interface ScoreGaugeProps {
  score: number;
  label?: string;
  trend?: string;
  size?: number;
}

export default function ScoreGauge({ score, label = "Score global", trend, size = 82 }: ScoreGaugeProps) {
  const r = size / 2 - 7;
  const circ = 2 * Math.PI * r;
  const filled = (score / 100) * circ * 0.75;

  const color =
    score >= 80 ? "var(--accent-ok)" :
    score >= 60 ? "var(--accent-warning)" :
    "var(--accent-danger)";

  return (
    <div className="pit" style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "4px" }}>
      <div style={{ position: "relative", width: size, height: size }}>
        <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size}
          style={{ transform: "rotate(-225deg)" }}>
          <circle
            cx={size / 2} cy={size / 2} r={r}
            fill="none"
            stroke="var(--border-subtle)"
            strokeWidth={6}
          />
          <circle
            cx={size / 2} cy={size / 2} r={r}
            fill="none"
            stroke={color}
            strokeWidth={6}
            strokeLinecap="round"
            strokeDasharray={`${filled} ${circ}`}
            style={{ transition: "stroke-dasharray 0.8s cubic-bezier(0.4,0,0.2,1)" }}
          />
        </svg>
        <div style={{
          position: "absolute",
          top: "50%",
          left: "50%",
          transform: "translate(-50%, -50%)",
          fontSize: "20px",
          fontWeight: 800,
          color: color,
          letterSpacing: "-0.02em",
        }}>
          {score}
        </div>
      </div>
      <span className="label-caps">{label}</span>
      {trend && (
        <span style={{ fontSize: "9px", color: "var(--accent-ok)" }}>{trend}</span>
      )}
    </div>
  );
}

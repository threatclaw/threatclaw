"use client";

import React from "react";

interface BarItemProps {
  label: string;
  value: number;
  color?: string;
}

export default function BarItem({ label, value, color }: BarItemProps) {
  const barColor = color ?? "var(--accent-danger)";

  return (
    <div className="pit-xs">
      <div className="label-caps" style={{ marginBottom: "4px" }}>{label}</div>
      <div className="bar-track">
        <div className="bar-fill" style={{ width: `${value}%`, background: barColor }} />
      </div>
      <div style={{ fontSize: "11px", fontWeight: 700, marginTop: "4px", color: barColor }}>
        {value}
      </div>
    </div>
  );
}

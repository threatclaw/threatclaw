"use client";

import React from "react";

interface StatCardProps {
  value: string | number;
  label: string;
  delta?: string;
  deltaColor?: "ok" | "danger" | "warning";
}

const deltaColors = {
  ok: "var(--accent-ok)",
  danger: "var(--accent-danger)",
  warning: "var(--accent-warning)",
};

export default function StatCard({ value, label, delta, deltaColor = "ok" }: StatCardProps) {
  return (
    <div className="pit" style={{ borderRadius: "12px", padding: "10px", textAlign: "center" }}>
      <div className="metric-val">{value}</div>
      <div className="label-caps" style={{ marginTop: "2px" }}>{label}</div>
      {delta && (
        <div style={{ fontSize: "8px", marginTop: "3px", color: deltaColors[deltaColor] }}>
          {delta}
        </div>
      )}
    </div>
  );
}

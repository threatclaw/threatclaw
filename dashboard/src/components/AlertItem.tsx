"use client";

import React from "react";

type Severity = "critical" | "high" | "medium" | "info";

interface AlertItemProps {
  severity: Severity;
  title: string;
  meta?: string;
  onAction?: () => void;
  actionLabel?: string;
}

const severityDot: Record<Severity, string> = {
  critical: "alert-dot danger",
  high: "alert-dot warning",
  medium: "alert-dot warning",
  info: "alert-dot ok",
};

export default function AlertItem({ severity, title, meta, onAction, actionLabel = "Voir" }: AlertItemProps) {
  return (
    <div className="pit" style={{
      borderRadius: "10px",
      padding: "9px 12px",
      display: "flex",
      alignItems: "center",
      gap: "9px",
    }}>
      <span className={severityDot[severity]} />
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: "10px", color: "var(--text-primary)", fontWeight: 500, lineHeight: 1.3 }}>
          {title}
        </div>
        {meta && (
          <div style={{ fontSize: "8px", color: "var(--text-secondary)", marginTop: "2px" }}>
            {meta}
          </div>
        )}
      </div>
      {onAction && (
        <button className="btn-raised" onClick={onAction}>{actionLabel}</button>
      )}
    </div>
  );
}

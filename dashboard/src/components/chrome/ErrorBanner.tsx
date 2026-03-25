"use client";
import React from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div style={{
      background: "rgba(208,48,32,0.08)", border: "1px solid rgba(208,48,32,0.2)",
      borderRadius: "var(--tc-radius-md)", padding: "14px 16px",
      display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px",
    }}>
      <AlertTriangle size={16} color="#d03020" />
      <span style={{ fontSize: "12px", color: "var(--tc-text)", flex: 1 }}>{message}</span>
      {onRetry && (
        <button onClick={onRetry} style={{
          background: "none", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
          padding: "4px 10px", cursor: "pointer", fontSize: "10px", color: "var(--tc-text-sec)",
          fontFamily: "inherit", display: "flex", alignItems: "center", gap: "4px",
        }}>
          <RefreshCw size={10} /> Reessayer
        </button>
      )}
    </div>
  );
}

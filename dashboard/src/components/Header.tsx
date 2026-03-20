"use client";

import React from "react";
import { useTheme } from "@/context/ThemeContext";
import { useHealth } from "@/lib/use-tc-data";

interface HeaderProps {
  subtitle?: string;
}

export default function Header({ subtitle }: HeaderProps) {
  const { theme, toggleTheme } = useTheme();
  const { data: health } = useHealth();
  const isOk = health.status === "ok";

  return (
    <header style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      marginBottom: "16px",
    }}>
      <div>
        <h1 style={{
          fontSize: "11px",
          fontWeight: 800,
          letterSpacing: "0.18em",
          color: "var(--text-logo)",
          textTransform: "uppercase",
          margin: 0,
        }}>
          THREATCLAW
        </h1>
        {subtitle && (
          <p style={{ fontSize: "9px", color: "var(--text-secondary)", marginTop: "2px", margin: 0 }}>
            {subtitle}
          </p>
        )}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <span className="pill-ok" style={!isOk ? { color: "var(--accent-danger)", background: "rgba(200,64,48,0.1)", borderColor: "rgba(200,64,48,0.25)" } : {}}>
          <span className="status-dot" style={!isOk ? { background: "var(--accent-danger)" } : {}} />
          {isOk ? `v${health.version}` : "Déconnecté"}
        </span>

        <button
          onClick={toggleTheme}
          aria-label="Basculer thème"
          className="toggle-track"
          style={{ border: "none" }}
        >
          <span
            className="toggle-thumb"
            style={{
              transform: theme === "dark" ? "translateX(16px)" : "translateX(0)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: "8px",
            }}
          >
            {theme === "dark" ? "\u{1F319}" : "\u{2600}"}
          </span>
        </button>

        <div style={{
          width: "28px",
          height: "28px",
          borderRadius: "50%",
          background: "var(--bg-pit)",
          boxShadow: "var(--shadow-pit-xs)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: "9px",
          fontWeight: 800,
          color: "var(--text-secondary)",
          letterSpacing: "0.04em",
        }}>
          RS
        </div>
      </div>
    </header>
  );
}

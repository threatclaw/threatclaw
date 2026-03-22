"use client";

import React from "react";

interface ChromeButtonProps {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  className?: string;
  variant?: "primary" | "glass" | "danger";
}

export function ChromeButton({ children, onClick, disabled, className = "", variant = "glass" }: ChromeButtonProps) {
  const styles: Record<string, React.CSSProperties> = {
    primary: {
      background: "linear-gradient(135deg, #d03020 0%, #a02018 100%)",
      border: "1px solid rgba(255,255,255,0.1)",
      color: "#fff",
      boxShadow: "0 2px 8px rgba(208,48,32,0.25), 0 1px 2px rgba(0,0,0,0.3)",
    },
    glass: {
      background: "rgba(255,255,255,0.04)",
      border: "1px solid rgba(255,255,255,0.06)",
      color: "#9a918a",
      boxShadow: "none",
    },
    danger: {
      background: "rgba(208,48,32,0.08)",
      border: "1px solid rgba(208,48,32,0.2)",
      color: "#d03020",
      boxShadow: "none",
    },
  };

  return (
    <button
      className={className}
      onClick={onClick}
      disabled={disabled}
      style={{
        ...styles[variant],
        borderRadius: "10px",
        padding: "8px 16px",
        fontSize: "12px",
        fontWeight: 600,
        fontFamily: "inherit",
        letterSpacing: "0.02em",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
        transition: "all 0.2s ease",
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
      }}
    >
      {children}
    </button>
  );
}

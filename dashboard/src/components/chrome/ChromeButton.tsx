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
  if (variant === "primary") {
    return (
      <button className={`tc-btn-embossed ${className}`} onClick={onClick} disabled={disabled}>
        {children}
      </button>
    );
  }

  // Glass + danger variants use simple inline styles
  const styles: Record<string, React.CSSProperties> = {
    glass: {
      background: "var(--tc-input)",
      border: "1px solid var(--tc-border)",
      color: "var(--tc-text-sec)",
    },
    danger: {
      background: "var(--tc-red-soft)",
      border: "1px solid var(--tc-red-border)",
      color: "var(--tc-red)",
    },
  };

  return (
    <button
      className={className}
      onClick={onClick}
      disabled={disabled}
      style={{
        ...styles[variant],
        borderRadius: "var(--tc-radius-md)",
        padding: "8px 16px",
        fontSize: "12px",
        fontWeight: 600,
        fontFamily: "inherit",
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

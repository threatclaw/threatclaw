"use client";

import React from "react";

interface ChromeInsetCardProps {
  children: React.ReactNode;
  className?: string;
  glow?: boolean;
  style?: React.CSSProperties;
}

export function ChromeInsetCard({ children, className = "", glow = false, style }: ChromeInsetCardProps) {
  return (
    <div
      className={`${className}`}
      style={{
        background: "rgba(18, 18, 26, 0.7)",
        backdropFilter: "blur(12px)",
        WebkitBackdropFilter: "blur(12px)",
        border: "1px solid var(--tc-input)",
        borderRadius: "var(--tc-radius-lg)",
        boxShadow: glow
          ? "0 4px 24px rgba(0,0,0,0.4), 0 1px 2px rgba(0,0,0,0.3), inset 0 1px 0 var(--tc-surface-alt), 0 0 30px rgba(208,48,32,0.05)"
          : "0 4px 24px rgba(0,0,0,0.4), 0 1px 2px rgba(0,0,0,0.3), inset 0 1px 0 var(--tc-surface-alt)",
        padding: "20px",
        transition: "box-shadow 0.25s ease, border-color 0.25s ease",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

interface ChromeEmbossedTextProps {
  children: React.ReactNode;
  as?: "p" | "span" | "h1" | "h2" | "h3" | "div";
  className?: string;
  style?: React.CSSProperties;
}

export function ChromeEmbossedText({ children, as: Tag = "span", className = "", style }: ChromeEmbossedTextProps) {
  return (
    <Tag
      className={className}
      style={{
        color: "var(--tc-text)",
        ...style,
      }}
    >
      {children}
    </Tag>
  );
}

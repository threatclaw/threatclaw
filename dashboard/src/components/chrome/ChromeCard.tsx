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
        background: "var(--tc-surface-alt)",
        border: glow ? "1px solid var(--tc-border-accent)" : "1px solid var(--tc-border)",
        borderRadius: "var(--tc-radius-md)",
        padding: "20px",
        transition: "border-color 0.25s ease",
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

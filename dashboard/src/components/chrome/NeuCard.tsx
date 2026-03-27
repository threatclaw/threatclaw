"use client";

import React from "react";

interface NeuCardProps {
  variant?: "raised" | "inset" | "flat";
  children: React.ReactNode;
  style?: React.CSSProperties;
  className?: string;
  glow?: boolean;
  [key: string]: any;
}

export function NeuCard({ variant = "inset", children, style, className }: NeuCardProps) {
  if (variant === "inset") {
    // Extract padding from style to apply on inner div, rest on outer
    const { padding, ...outerStyle } = style || {};
    return (
      <div
        className={className}
        style={{
          padding: "2px",
          borderRadius: "var(--tc-radius-md)",
          overflow: "visible",
          position: "relative",
          backgroundColor: "var(--tc-neu-outer)",
          boxShadow: `
            inset 0 2px 6px rgba(0,0,0,0.3),
            inset 0 1px 2px rgba(0,0,0,0.2),
            inset 0 -1px 1px rgba(255,255,255,0.06),
            0 1px 0 rgba(255,255,255,0.1)
          `,
          ...outerStyle,
        }}
      >
        <div style={{
          borderRadius: "calc(var(--tc-radius-md) - 2px)",
          padding: padding ?? "20px",
          position: "relative",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          backgroundColor: "var(--tc-neu-inner)",
          boxShadow: `
            inset 0 2px 6px rgba(0,0,0,0.2),
            inset 0 1px 3px rgba(0,0,0,0.15),
            inset 0 -1px 2px rgba(255,255,255,0.05)
          `,
          color: "var(--tc-neu-text)",
        }}>
          {children}
        </div>
      </div>
    );
  }

  // flat fallback
  return (
    <div className={className} style={{
      background: "var(--tc-surface-alt)",
      border: "1px solid var(--tc-border)",
      borderRadius: "var(--tc-radius-md)",
      padding: "20px",
      ...style,
    }}>
      {children}
    </div>
  );
}

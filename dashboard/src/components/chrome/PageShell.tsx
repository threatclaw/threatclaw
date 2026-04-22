"use client";

// Shared wrapper for every "content" page that is NOT the SOC console home.
// Gives every route the same gutters, maxWidth, font stack, and header
// pattern so the whole app reads as one product.
//
// The console home (/) has its own full-viewport layout and bypasses this
// shell on purpose.

import React from "react";

export function PageShell({
  title,
  subtitle,
  right,
  children,
}: {
  title: string;
  subtitle?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div
      style={{
        padding: "24px 28px 40px",
        fontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace",
        color: "var(--tc-text)",
        maxWidth: "1600px",
        margin: "0 auto",
      }}
    >
      <div
        style={{
          marginBottom: "24px",
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: "18px",
        }}
      >
        <div>
          <div
            style={{
              fontSize: "9px",
              letterSpacing: "0.22em",
              color: "var(--tc-text-muted)",
              textTransform: "uppercase",
            }}
          >
            {title}
          </div>
          {subtitle && (
            <div
              style={{
                fontSize: "13px",
                color: "var(--tc-text-sec)",
                marginTop: "6px",
                maxWidth: "700px",
                lineHeight: 1.5,
              }}
            >
              {subtitle}
            </div>
          )}
        </div>
        {right}
      </div>
      {children}
    </div>
  );
}

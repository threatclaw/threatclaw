"use client";

import React from "react";

interface ChromeInsetCardProps {
  children: React.ReactNode;
  className?: string;
}

export function ChromeInsetCard({ children, className = "" }: ChromeInsetCardProps) {
  return (
    <div
      className={`rounded-xl overflow-visible relative ${className}`}
      style={{
        padding: "2px",
        backgroundColor: "#c8c0b8",
        boxShadow: `
          inset 0 3px 8px rgba(0,0,0,0.5),
          inset 0 1px 3px rgba(0,0,0,0.4),
          inset 0 -1px 1px rgba(255,255,255,0.08),
          0 1px 0 rgba(255,255,255,0.15)
        `,
      }}
    >
      <div
        className="rounded-[10px] h-full flex flex-col"
        style={{
          backgroundColor: "#ece5de",
          boxShadow: `
            inset 0 4px 10px rgba(0,0,0,0.45),
            inset 0 2px 4px rgba(0,0,0,0.35),
            inset 0 -2px 4px rgba(255,255,255,0.05)
          `,
        }}
      >
        <div style={{ position: "relative", padding: "16px", flex: 1, display: "flex", flexDirection: "column" }}>
          {children}
        </div>
      </div>
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
        color: "#1a1a22",
        textShadow: "0 1px 1px rgba(255,255,255,0.4), 0 -1px 1px rgba(0,0,0,0.15)",
        ...style,
      }}
    >
      {children}
    </Tag>
  );
}

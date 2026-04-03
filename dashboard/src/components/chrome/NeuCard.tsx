"use client";

import React from "react";

// ── Accent presets: each gives a unique mesh gradient + optional pattern ──
const accents: Record<string, { mesh: string; pat?: string; patSize?: string; glow?: string }> = {
  red:   { mesh: "radial-gradient(ellipse at 25% 20%, rgba(208,48,32,0.06) 0%, transparent 55%)", glow: "inset 0 0 35px rgba(208,48,32,0.03)" },
  blue:  { mesh: "radial-gradient(ellipse at 70% 30%, rgba(48,128,208,0.05) 0%, transparent 55%)", glow: "inset 0 0 35px rgba(48,128,208,0.025)" },
  green: { mesh: "radial-gradient(ellipse at 40% 70%, rgba(48,160,80,0.05) 0%, transparent 55%)", glow: "inset 0 0 35px rgba(48,160,80,0.025)" },
  purple:{ mesh: "radial-gradient(ellipse at 60% 40%, rgba(144,96,208,0.05) 0%, transparent 55%)", glow: "inset 0 0 35px rgba(144,96,208,0.025)" },
  amber: { mesh: "radial-gradient(ellipse at 50% 30%, rgba(208,144,32,0.05) 0%, transparent 55%)", glow: "inset 0 0 35px rgba(208,144,32,0.025)" },
  dots:  { mesh: "radial-gradient(ellipse at 30% 60%, rgba(48,128,208,0.04) 0%, transparent 50%)", pat: "radial-gradient(circle, rgba(255,255,255,0.035) 1px, transparent 1px)", patSize: "16px 16px", glow: "inset 0 0 30px rgba(48,128,208,0.02)" },
  hex:   { mesh: "radial-gradient(ellipse at 50% 50%, rgba(48,160,80,0.04) 0%, transparent 55%)", pat: "linear-gradient(30deg, rgba(255,255,255,0.02) 12%, transparent 12.5%, transparent 87%, rgba(255,255,255,0.02) 87.5%), linear-gradient(150deg, rgba(255,255,255,0.02) 12%, transparent 12.5%, transparent 87%, rgba(255,255,255,0.02) 87.5%), linear-gradient(60deg, rgba(255,255,255,0.015) 25%, transparent 25.5%, transparent 75%, rgba(255,255,255,0.015) 75%)", patSize: "28px 49px", glow: "inset 0 0 30px rgba(48,160,80,0.02)" },
  grid:  { mesh: "radial-gradient(ellipse at 70% 70%, rgba(208,48,32,0.04) 0%, transparent 55%)", pat: "linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)", patSize: "20px 20px", glow: "inset 0 0 30px rgba(208,48,32,0.02)" },
  scan:  { mesh: "radial-gradient(ellipse at 30% 30%, rgba(48,160,80,0.04) 0%, transparent 50%)", pat: "repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(255,255,255,0.012) 3px, rgba(255,255,255,0.012) 4px)", patSize: "100% 4px", glow: "inset 0 0 30px rgba(48,160,80,0.015)" },
  rings: { mesh: "radial-gradient(ellipse at 50% 50%, rgba(99,102,241,0.05) 0%, transparent 55%)", pat: "repeating-radial-gradient(circle at center, transparent, transparent 16px, rgba(255,255,255,0.015) 16px, rgba(255,255,255,0.015) 17px)", patSize: "100% 100%", glow: "inset 0 0 30px rgba(99,102,241,0.02)" },
};

interface NeuCardProps {
  variant?: "raised" | "inset" | "flat";
  children: React.ReactNode;
  style?: React.CSSProperties;
  className?: string;
  glow?: boolean;
  accent?: keyof typeof accents;
  [key: string]: any;
}

export function NeuCard({ variant = "inset", children, style, className, accent }: NeuCardProps) {
  if (variant === "inset") {
    const { padding, ...outerStyle } = style || {};
    const pad = padding ?? "20px";
    const a = accent ? accents[accent] : undefined;

    return (
      <>
        {/* ── DARK MODE ── */}
        <div
          className={`neu-dark ${className || ""}`}
          style={{
            borderRadius: "var(--tc-radius-card)",
            overflow: "hidden",
            position: "relative" as const,
            padding: pad,
            background: a
              ? `${a.mesh}, linear-gradient(165deg, #151520 0%, #0d0d15 60%, #111118 100%)`
              : "linear-gradient(165deg, #151520 0%, #0d0d15 60%, #111118 100%)",
            border: "1px solid rgba(255,255,255,0.05)",
            boxShadow: [
              "inset 0 2px 12px rgba(0,0,0,0.7)",
              "inset 0 1px 3px rgba(0,0,0,0.5)",
              "inset 0 -1px 1px rgba(255,255,255,0.025)",
              a?.glow || "",
              "0 1px 0 rgba(255,255,255,0.04)",
              "0 4px 20px rgba(0,0,0,0.6)",
            ].filter(Boolean).join(", "),
            color: "var(--tc-neu-text)",
            transition: "box-shadow 0.4s ease, border-color 0.4s ease, transform 0.3s ease",
            ...outerStyle,
          }}
        >
          {/* Pattern overlay */}
          {a?.pat && <div style={{
            position: "absolute", inset: 0,
            backgroundImage: a.pat, backgroundSize: a.patSize || "20px 20px",
            pointerEvents: "none" as any, borderRadius: "inherit",
          }} />}
          {/* Noise texture */}
          <div style={{
            position: "absolute", inset: 0,
            backgroundImage: "url('/textures/random-grey-variations.png')",
            backgroundSize: "200px", opacity: 0.025,
            mixBlendMode: "overlay" as any,
            pointerEvents: "none" as any, borderRadius: "inherit",
          }} />
          {/* Bottom depth fog */}
          <div style={{
            position: "absolute", bottom: 0, left: 0, right: 0, height: "40%",
            background: "linear-gradient(to top, rgba(0,0,0,0.15), transparent)",
            pointerEvents: "none" as any, borderRadius: "inherit",
          }} />
          <div style={{ position: "relative", zIndex: 1 }}>{children}</div>
        </div>

        {/* ── LIGHT MODE: original — untouched ── */}
        <div
          className={`neu-light ${className || ""}`}
          style={{
            padding: "2px",
            borderRadius: "var(--tc-radius-md)",
            overflow: "visible",
            position: "relative" as const,
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
            padding: pad,
            position: "relative",
            height: "100%",
            display: "flex", flexDirection: "column",
            backgroundColor: "var(--tc-neu-inner)",
            boxShadow: `
              inset 0 2px 6px rgba(0,0,0,0.2),
              inset 0 1px 3px rgba(0,0,0,0.15),
              inset 0 -1px 2px rgba(255,255,255,0.05)
            `,
            color: "var(--tc-neu-text)",
          }}>{children}</div>
        </div>
      </>
    );
  }

  return (
    <div className={className} style={{
      background: "var(--tc-surface-alt)",
      border: "1px solid var(--tc-border)",
      borderRadius: "var(--tc-radius-md)",
      padding: "20px",
      ...style,
    }}>{children}</div>
  );
}

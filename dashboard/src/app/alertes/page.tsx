"use client";

import React, { useState, useEffect } from "react";
import { ChromeInsetCard, ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";

interface Finding {
  id: number;
  title: string;
  severity: string;
  status: string;
  asset: string | null;
  source: string | null;
  skill_id: string;
  detected_at: string;
}

const SEV_COLORS: Record<string, string> = {
  critical: "#903020",
  high: "#906020",
  medium: "#5a6a4a",
  low: "#5a7a8a",
  info: "#907060",
};

export default function AlertesPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filter, setFilter] = useState<string>("all");

  useEffect(() => {
    fetch("/api/tc/findings?limit=50")
      .then(r => r.json())
      .then(d => setFindings(d.findings || []))
      .catch(() => {});
    const interval = setInterval(() => {
      fetch("/api/tc/findings?limit=50")
        .then(r => r.json())
        .then(d => setFindings(d.findings || []))
        .catch(() => {});
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  const filtered = filter === "all" ? findings : findings.filter(f => f.severity === filter);

  return (
    <div>
      {/* Filters */}
      <div style={{ display: "flex", gap: "6px", marginBottom: "16px" }}>
        {["all", "critical", "high", "medium", "low"].map(f => (
          <ChromeButton key={f} onClick={() => setFilter(f)}>
            <span style={{
              fontSize: "10px",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              color: filter === f ? "#903020" : undefined,
              opacity: filter === f ? 1 : 0.6,
            }}>
              {f === "all" ? `Tous (${findings.length})` : f}
            </span>
          </ChromeButton>
        ))}
      </div>

      {/* Findings list */}
      {filtered.length === 0 ? (
        <ChromeInsetCard>
          <div style={{ textAlign: "center", padding: "20px" }}>
            <ChromeEmbossedText as="div" style={{ fontSize: "12px", fontWeight: 700 }}>
              {findings.length === 0 ? "Aucun finding" : "Aucun finding pour ce filtre"}
            </ChromeEmbossedText>
            <ChromeEmbossedText as="div" style={{ fontSize: "9px", opacity: 0.5, marginTop: "4px" }}>
              Les findings apparaîtront après un scan
            </ChromeEmbossedText>
          </div>
        </ChromeInsetCard>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          {filtered.map(f => (
            <ChromeInsetCard key={f.id}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <div style={{
                  width: "8px", height: "8px", borderRadius: "50%", flexShrink: 0,
                  background: SEV_COLORS[f.severity] || "#907060",
                  boxShadow: `0 0 4px ${SEV_COLORS[f.severity] || "#907060"}`,
                }} />
                <div style={{ flex: 1 }}>
                  <ChromeEmbossedText as="div" style={{ fontSize: "11px", fontWeight: 600 }}>
                    {f.title}
                  </ChromeEmbossedText>
                  <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.45, marginTop: "2px" }}>
                    {[f.asset, f.source, f.skill_id].filter(Boolean).join(" · ")}
                  </ChromeEmbossedText>
                </div>
                <ChromeEmbossedText as="span" style={{
                  fontSize: "8px", fontWeight: 800, textTransform: "uppercase",
                  letterSpacing: "0.08em", color: SEV_COLORS[f.severity],
                }}>
                  {f.severity}
                </ChromeEmbossedText>
              </div>
            </ChromeInsetCard>
          ))}
        </div>
      )}
    </div>
  );
}

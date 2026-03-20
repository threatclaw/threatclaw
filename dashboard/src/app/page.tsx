"use client";

import React, { useState, useEffect } from "react";
import { ChromeInsetCard, ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { CheckCircle2, AlertTriangle, Shield, Activity } from "lucide-react";

interface Metrics {
  security_score: number;
  findings_critical: number;
  findings_high: number;
  findings_medium: number;
  findings_low: number;
  alerts_total: number;
  alerts_new: number;
}

interface Health {
  status: string;
  version: string;
  database: boolean;
  llm: string;
}

export default function HomePage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [health, setHealth] = useState<Health | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [m, h] = await Promise.all([
          fetch("/api/tc/metrics").then(r => r.json()).then(d => d.metrics),
          fetch("/api/tc/health").then(r => r.json()),
        ]);
        setMetrics(m);
        setHealth(h);
      } catch { /* API not ready */ }
    };
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  const isOk = health?.status === "ok";
  const hasCritical = (metrics?.findings_critical || 0) > 0;

  return (
    <div>
      {/* Status bar */}
      <ChromeInsetCard className="mb-4">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            {isOk ? (
              <CheckCircle2 size={18} color={hasCritical ? "#903020" : "#5a7a4a"} />
            ) : (
              <AlertTriangle size={18} color="#903020" />
            )}
            <div>
              <ChromeEmbossedText as="div" style={{ fontSize: "16px", fontWeight: 800 }}>
                {!health ? "Connexion..." : isOk ? (hasCritical ? "Alertes actives" : "Tout est nominal") : "Agent déconnecté"}
              </ChromeEmbossedText>
              <ChromeEmbossedText as="div" style={{ fontSize: "9px", opacity: 0.5, marginTop: "2px" }}>
                {health ? `v${health.version} · ${health.llm} · ${health.database ? "DB connectée" : "DB hors ligne"}` : ""}
              </ChromeEmbossedText>
            </div>
          </div>
          <div style={{
            width: "10px", height: "10px", borderRadius: "50%",
            background: !health ? "#907060" : isOk ? (hasCritical ? "#903020" : "#5a7a4a") : "#903020",
            boxShadow: `0 0 6px ${!health ? "#907060" : isOk ? (hasCritical ? "#903020" : "#5a7a4a") : "#903020"}`,
          }} />
        </div>
      </ChromeInsetCard>

      {/* Metrics grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px", marginBottom: "16px" }}>
        {[
          { label: "Critiques", value: metrics?.findings_critical ?? "—", color: "#903020" },
          { label: "Hautes", value: metrics?.findings_high ?? "—", color: "#906020" },
          { label: "Moyennes", value: metrics?.findings_medium ?? "—", color: "#5a6a4a" },
          { label: "Alertes", value: metrics?.alerts_new ?? "—", color: metrics?.alerts_new ? "#903020" : "#5a7a4a" },
        ].map((m) => (
          <ChromeInsetCard key={m.label}>
            <div style={{ textAlign: "center" }}>
              <ChromeEmbossedText as="div" style={{ fontSize: "26px", fontWeight: 800, color: m.color }}>{m.value}</ChromeEmbossedText>
              <ChromeEmbossedText as="div" style={{ fontSize: "8px", fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", opacity: 0.5, marginTop: "2px" }}>{m.label}</ChromeEmbossedText>
            </div>
          </ChromeInsetCard>
        ))}
      </div>

      {/* Quick actions */}
      <ChromeInsetCard>
        <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 800, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: "12px" }}>
          Accès rapide
        </ChromeEmbossedText>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
          <ChromeButton onClick={() => window.location.href = "/alertes"}>
            <span style={{ display: "flex", alignItems: "center", gap: "5px", fontSize: "10px" }}>
              <AlertTriangle size={12} /> Voir les alertes
            </span>
          </ChromeButton>
          <ChromeButton onClick={() => window.location.href = "/skills"}>
            <span style={{ display: "flex", alignItems: "center", gap: "5px", fontSize: "10px" }}>
              <Shield size={12} /> Gérer les skills
            </span>
          </ChromeButton>
          <ChromeButton onClick={() => window.location.href = "/agent"}>
            <span style={{ display: "flex", alignItems: "center", gap: "5px", fontSize: "10px" }}>
              <Activity size={12} /> Contrôle agent
            </span>
          </ChromeButton>
        </div>
      </ChromeInsetCard>
    </div>
  );
}

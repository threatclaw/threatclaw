"use client";

import React from "react";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { ChromeInsetCard, ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { Shield, AlertTriangle, CheckCircle2, Wifi, Settings, Bell } from "lucide-react";

export default function DesignTestPage() {
  return (
    <div style={{
      minHeight: "100vh",
      background: "#e2dbd4",
      padding: "24px",
      fontFamily: "'Inter', sans-serif",
    }}>
      {/* Title */}
      <div style={{ textAlign: "center", marginBottom: "32px" }}>
        <h1 style={{
          fontSize: "11px",
          fontWeight: 800,
          letterSpacing: "0.25em",
          textTransform: "uppercase",
          color: "#5a3a2a",
          marginBottom: "4px",
        }}>
          THREATCLAW
        </h1>
        <p style={{ fontSize: "9px", color: "#907060" }}>Design System — Embossed Terracotta</p>
      </div>

      {/* Buttons row */}
      <div style={{ display: "flex", gap: "12px", justifyContent: "center", flexWrap: "wrap", marginBottom: "32px" }}>
        <ChromeButton>
          <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <Shield size={14} />
            <span style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.08em" }}>
              Dashboard
            </span>
          </span>
        </ChromeButton>

        <ChromeButton>
          <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <Bell size={14} />
            <span style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.08em" }}>
              3 Alertes
            </span>
          </span>
        </ChromeButton>

        <ChromeButton>
          <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <Settings size={12} />
            <span style={{ fontSize: "11px" }}>Config</span>
          </span>
        </ChromeButton>

        <ChromeButton disabled>
          <span style={{ fontSize: "11px" }}>Désactivé</span>
        </ChromeButton>
      </div>

      {/* Cards grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "16px", maxWidth: "800px", margin: "0 auto 32px" }}>
        {/* Status card */}
        <ChromeInsetCard>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
            <CheckCircle2 size={16} color="#5a7a4a" />
            <ChromeEmbossedText as="span" style={{ fontSize: "10px", fontWeight: 800, letterSpacing: "0.12em", textTransform: "uppercase" }}>
              Statut Agent
            </ChromeEmbossedText>
          </div>
          <ChromeEmbossedText as="div" style={{ fontSize: "22px", fontWeight: 800 }}>
            Opérationnel
          </ChromeEmbossedText>
          <ChromeEmbossedText as="p" style={{ fontSize: "9px", marginTop: "4px", opacity: 0.5 }}>
            Mode Investigateur · v0.1.0
          </ChromeEmbossedText>
        </ChromeInsetCard>

        {/* Findings card */}
        <ChromeInsetCard>
          <ChromeEmbossedText as="span" className="block" style={{ fontSize: "10px", fontWeight: 800, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: "12px" }}>
            Findings
          </ChromeEmbossedText>
          <div style={{ display: "flex", gap: "16px" }}>
            <div>
              <ChromeEmbossedText as="div" style={{ fontSize: "28px", fontWeight: 800, color: "#903020" }}>3</ChromeEmbossedText>
              <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.5 }}>CRITIQUES</ChromeEmbossedText>
            </div>
            <div>
              <ChromeEmbossedText as="div" style={{ fontSize: "28px", fontWeight: 800, color: "#906020" }}>7</ChromeEmbossedText>
              <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.5 }}>HAUTES</ChromeEmbossedText>
            </div>
            <div>
              <ChromeEmbossedText as="div" style={{ fontSize: "28px", fontWeight: 800 }}>12</ChromeEmbossedText>
              <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.5 }}>TOTAL</ChromeEmbossedText>
            </div>
          </div>
        </ChromeInsetCard>

        {/* Alert card */}
        <ChromeInsetCard>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
            <AlertTriangle size={16} color="#903020" />
            <ChromeEmbossedText as="span" style={{ fontSize: "10px", fontWeight: 800, letterSpacing: "0.12em", textTransform: "uppercase" }}>
              Dernière alerte
            </ChromeEmbossedText>
          </div>
          <ChromeEmbossedText as="div" style={{ fontSize: "11px", fontWeight: 600, lineHeight: 1.4 }}>
            Brute force SSH détecté
          </ChromeEmbossedText>
          <ChromeEmbossedText as="p" style={{ fontSize: "9px", marginTop: "4px", opacity: 0.45 }}>
            185.220.101.47 · srv-prod-01 · il y a 3min
          </ChromeEmbossedText>
        </ChromeInsetCard>

        {/* Infrastructure card */}
        <ChromeInsetCard>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
            <Wifi size={16} color="#5a6a8a" />
            <ChromeEmbossedText as="span" style={{ fontSize: "10px", fontWeight: 800, letterSpacing: "0.12em", textTransform: "uppercase" }}>
              Infrastructure
            </ChromeEmbossedText>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            {[
              { name: "srv-prod-01", status: "ok" },
              { name: "firewall-pfsense", status: "ok" },
              { name: "srv-ad-01", status: "warning" },
            ].map((s) => (
              <div key={s.name} style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <div style={{
                  width: "6px", height: "6px", borderRadius: "50%",
                  background: s.status === "ok" ? "#5a7a4a" : "#906020",
                  boxShadow: `0 0 4px ${s.status === "ok" ? "#5a7a4a" : "#906020"}`,
                }} />
                <ChromeEmbossedText as="span" style={{ fontSize: "10px", fontWeight: 500 }}>
                  {s.name}
                </ChromeEmbossedText>
              </div>
            ))}
          </div>
        </ChromeInsetCard>
      </div>

      {/* Large card */}
      <div style={{ maxWidth: "800px", margin: "0 auto" }}>
        <ChromeInsetCard>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
            <ChromeEmbossedText as="span" style={{ fontSize: "10px", fontWeight: 800, letterSpacing: "0.12em", textTransform: "uppercase" }}>
              Dernière analyse IA
            </ChromeEmbossedText>
            <ChromeEmbossedText as="span" style={{ fontSize: "9px", opacity: 0.4 }}>
              Il y a 15 min · L1 · qwen3:14b
            </ChromeEmbossedText>
          </div>
          <ChromeEmbossedText as="p" style={{ fontSize: "11px", lineHeight: 1.6, marginBottom: "12px" }}>
            3 ports ouverts sur 192.168.1.132. Aucune vulnérabilité critique. Sévérité LOW.
          </ChromeEmbossedText>
          <div style={{ display: "flex", gap: "8px" }}>
            <ChromeButton>
              <span style={{ fontSize: "10px" }}>Voir détails</span>
            </ChromeButton>
            <ChromeButton>
              <span style={{ fontSize: "10px" }}>Relancer</span>
            </ChromeButton>
          </div>
        </ChromeInsetCard>
      </div>
    </div>
  );
}

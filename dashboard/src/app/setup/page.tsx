"use client";

import React, { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import SetupWizard from "@/components/setup/SetupWizard";
import EmbossedButton from "@/components/chrome/EmbossedButton";
import ConfigPage from "@/components/setup/ConfigPage";
import { Settings, Puzzle, Network, Play, Key } from "lucide-react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";

// Lazy load the sub-pages to avoid circular imports
const SkillsContent = dynamic(() => import("../skills/page"), { ssr: false });
const AssetsContent = dynamic(() => import("../assets/page"), { ssr: false });
const TestsContent = dynamic(() => import("../test/page"), { ssr: false });
const LicenseContent = dynamic(() => Promise.resolve({ default: LicensePage }), { ssr: false });

const TABS = [
  { key: "config", i18n: "general", icon: Settings },
  { key: "skills", i18n: "skills", icon: Puzzle },
  { key: "assets", i18n: "assets", icon: Network },
  { key: "tests", i18n: "tests", icon: Play },
  { key: "about", i18n: "about", icon: Key },
] as const;

// ── About Tab Component ──
function LicensePage() {
  const [info, setInfo] = React.useState<any>(null);

  React.useEffect(() => {
    fetch("/api/tc/license").then(r => r.json()).then(setInfo).catch(() => {});
  }, []);

  return (
    <div style={{ padding: "20px 24px" }}>
      <h2 style={{ fontSize: "18px", fontWeight: 800, color: "var(--tc-text)", margin: "0 0 16px" }}>ThreatClaw</h2>

      <div className="tc-card" style={{ padding: "20px", marginBottom: "16px" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "11px", color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.5px" }}>Instance</span>
            <span style={{ fontSize: "13px", fontWeight: 700, fontFamily: "monospace", color: "var(--tc-text)" }}>
              {info?.instance_id || "..."}
            </span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "11px", color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.5px" }}>Assets</span>
            <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)" }}>
              {info?.asset_count || 0} <span style={{ fontSize: "10px", color: "var(--tc-text-muted)", fontWeight: 400 }}>aucune limite</span>
            </span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "11px", color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.5px" }}>Licence</span>
            <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-green)" }}>
              Community — Gratuit et illimité
            </span>
          </div>
        </div>
      </div>

      <div className="tc-card" style={{ padding: "20px" }}>
        <p style={{ fontSize: "12px", color: "var(--tc-text-muted)", lineHeight: "1.6", margin: 0 }}>
          ThreatClaw est un agent cybersécurité autonome pour PME.
          <br />Développé par <a href="https://cyberconsulting.fr" target="_blank" rel="noopener noreferrer" style={{ color: "var(--tc-red)", textDecoration: "none" }}>CyberConsulting.fr</a>
          <br />Licence AGPL v3 — <a href="https://threatclaw.io" target="_blank" rel="noopener noreferrer" style={{ color: "var(--tc-red)", textDecoration: "none" }}>threatclaw.io</a>
        </p>
      </div>
    </div>
  );
}

type TabKey = typeof TABS[number]["key"];

export default function SetupPage() {
  const locale = useLocale();
  const [onboarded, setOnboarded] = useState<boolean | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("config");

  useEffect(() => {
    setOnboarded(localStorage.getItem("threatclaw_onboarded") === "true");
    // Check URL hash for direct tab navigation
    const hash = window.location.hash.replace("#", "");
    if (hash && TABS.some(t => t.key === hash)) {
      setActiveTab(hash as TabKey);
    }
  }, []);

  if (onboarded === null) return null;

  if (!onboarded) {
    return (
      <div style={{ margin: "-0 -20px" }}>
        <SetupWizard />
      </div>
    );
  }

  return (
    <div>
      {/* Tab bar — sliding indicator */}
      <div style={{
        position: "relative", display: "flex", padding: "3px",
        margin: "0 24px 8px", borderRadius: "11px",
        background: "var(--tc-input)",
      }}>
        {/* Sliding indicator */}
        <div style={{
          position: "absolute", top: "3px", height: "calc(100% - 6px)",
          width: `calc(${100 / TABS.length}% - 2px)`,
          left: `calc(${(TABS.findIndex(t => t.key === activeTab)) * (100 / TABS.length)}% + 1px)`,
          background: "var(--tc-surface-alt)",
          borderRadius: "8px",
          border: "0.5px solid var(--tc-border)",
          boxShadow: "0 3px 8px rgba(0,0,0,0.12), 0 3px 1px rgba(0,0,0,0.04)",
          transition: "left 0.25s ease-out",
          zIndex: 0,
        }} />
        {TABS.map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => {
                setActiveTab(tab.key);
                window.history.replaceState(null, "", `#${tab.key}`);
              }}
              style={{
                flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
                gap: "6px", padding: "8px 0", fontSize: "11px", fontWeight: 600,
                color: isActive ? "var(--tc-text)" : "var(--tc-text-muted)",
                background: "transparent", border: "none",
                cursor: "pointer", transition: "color 200ms, opacity 200ms",
                position: "relative", zIndex: 1,
                opacity: isActive ? 1 : 0.5,
              }}
            >
              <Icon size={13} />
              {tr(tab.i18n, locale)}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      {activeTab === "config" && (
        <ConfigPage onResetWizard={() => {
          localStorage.removeItem("threatclaw_onboarded");
          setOnboarded(false);
        }} />
      )}
      {activeTab === "skills" && <SkillsContent />}
      {activeTab === "assets" && <AssetsContent />}
      {activeTab === "tests" && <TestsContent />}
      {activeTab === "about" && <LicenseContent />}
    </div>
  );
}

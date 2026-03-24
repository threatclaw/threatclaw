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
const AssetsContent = dynamic(() => import("../infrastructure/page"), { ssr: false });
const TestsContent = dynamic(() => import("../test/page"), { ssr: false });
const LicenseContent = dynamic(() => Promise.resolve({ default: LicensePage }), { ssr: false });

const TABS = [
  { key: "config", i18n: "general", icon: Settings },
  { key: "skills", i18n: "skills", icon: Puzzle },
  { key: "assets", i18n: "assets", icon: Network },
  { key: "tests", i18n: "tests", icon: Play },
  { key: "license", i18n: "license", icon: Key },
] as const;

// ── License Tab Component ──
function LicensePage() {
  const [license, setLicense] = React.useState<any>(null);
  const [serial, setSerial] = React.useState("");
  const [activating, setActivating] = React.useState(false);
  const [message, setMessage] = React.useState("");

  React.useEffect(() => {
    fetch("/api/tc/license").then(r => r.json()).then(setLicense).catch(() => {});
  }, []);

  const activate = async () => {
    setActivating(true);
    setMessage("");
    try {
      const res = await fetch("/api/tc/license/activate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ serial }),
      });
      const data = await res.json();
      setMessage(data.message || "");
      // Refresh license status
      const lic = await fetch("/api/tc/license").then(r => r.json());
      setLicense(lic);
    } catch (e: any) {
      setMessage("Erreur: " + e.message);
    }
    setActivating(false);
  };

  const tierColor = license?.tier === "community" ? "var(--tc-text-muted)" : "var(--tc-green)";
  const usagePct = license?.usage_percent || 0;
  const barColor = usagePct >= 100 ? "var(--tc-red)" : usagePct >= 80 ? "var(--tc-amber)" : "var(--tc-green)";

  return (
    <div style={{ padding: "20px 24px" }}>
      <h2 style={{ fontSize: "18px", fontWeight: 800, color: "var(--tc-text)", margin: "0 0 16px" }}>Licence ThreatClaw</h2>

      {/* Current status */}
      <div className="tc-card" style={{ padding: "20px", marginBottom: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
          <div>
            <span style={{ fontSize: "14px", fontWeight: 700, color: tierColor, textTransform: "uppercase" }}>
              {license?.tier || "Community"}
            </span>
            {license?.client_name && (
              <span style={{ fontSize: "12px", color: "var(--tc-text-muted)", marginLeft: "8px" }}>
                — {license.client_name}
              </span>
            )}
          </div>
          {license?.expires && (
            <span style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>
              Expire: {license.expires}
              {license.days_remaining !== null && license.days_remaining < 30 && (
                <span style={{ color: "var(--tc-amber)", marginLeft: "6px" }}>
                  ({license.days_remaining}j restants)
                </span>
              )}
            </span>
          )}
        </div>

        {/* Asset usage bar */}
        <div style={{ marginBottom: "8px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
            <span style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>Assets utilises</span>
            <span style={{ fontSize: "11px", fontWeight: 700, color: barColor }}>
              {license?.asset_count || 0} / {license?.max_assets || 150}
            </span>
          </div>
          <div style={{ height: "8px", borderRadius: "4px", background: "var(--tc-input)" }}>
            <div style={{
              width: `${Math.min(usagePct, 100)}%`, height: "100%", borderRadius: "4px",
              background: barColor, transition: "width 500ms",
            }} />
          </div>
        </div>

        {license?.status_message && (
          <p style={{ fontSize: "11px", color: usagePct >= 80 ? "var(--tc-amber)" : "var(--tc-text-muted)", margin: "8px 0 0" }}>
            {license.status_message}
          </p>
        )}
      </div>

      {/* Serial input */}
      <div className="tc-card" style={{ padding: "20px" }}>
        <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", margin: "0 0 12px" }}>
          {license?.tier === "community" ? "Activer une licence" : "Changer de licence"}
        </h3>
        <div style={{ display: "flex", gap: "8px", marginBottom: "8px" }}>
          <input
            type="text" value={serial}
            onChange={e => setSerial(e.target.value)}
            onKeyDown={e => e.key === "Enter" && activate()}
            placeholder="TC-PRO-XXXX...XXXX"
            style={{
              flex: 1, padding: "10px 14px", borderRadius: "var(--tc-radius-input)", fontSize: "13px",
              fontFamily: "monospace", background: "var(--tc-input)", border: "1px solid var(--tc-border)",
              color: "var(--tc-text)", outline: "none", letterSpacing: "0.05em",
            }}
          />
          <EmbossedButton onClick={activate} disabled={activating || !serial.trim()}>
            {activating ? "..." : "Activer"}
          </EmbossedButton>
        </div>

        {message && (
          <p style={{
            fontSize: "12px", padding: "8px 12px", borderRadius: "var(--tc-radius-sm)",
            background: message.includes("activee") ? "var(--tc-green-soft)" : "var(--tc-red-soft)",
            color: message.includes("activee") ? "var(--tc-green)" : "var(--tc-red)",
            margin: "8px 0 0",
          }}>
            {message}
          </p>
        )}

        <p style={{ fontSize: "11px", color: "var(--tc-text-faint)", margin: "12px 0 0" }}>
          Obtenez une licence sur <a href="https://threatclaw.io/pricing" target="_blank" rel="noopener noreferrer"
            style={{ color: "var(--tc-red)", textDecoration: "none" }}>threatclaw.io/pricing</a>
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
      {activeTab === "license" && <LicenseContent />}
    </div>
  );
}

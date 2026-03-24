"use client";

import React, { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import SetupWizard from "@/components/setup/SetupWizard";
import ConfigPage from "@/components/setup/ConfigPage";
import { Settings, Puzzle, Network, Play } from "lucide-react";

// Lazy load the sub-pages to avoid circular imports
const SkillsContent = dynamic(() => import("../skills/page"), { ssr: false });
const AssetsContent = dynamic(() => import("../infrastructure/page"), { ssr: false });
const TestsContent = dynamic(() => import("../test/page"), { ssr: false });

const TABS = [
  { key: "config", label: "General", icon: Settings },
  { key: "skills", label: "Skills", icon: Puzzle },
  { key: "assets", label: "Assets", icon: Network },
  { key: "tests", label: "Tests", icon: Play },
] as const;

type TabKey = typeof TABS[number]["key"];

export default function SetupPage() {
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
      {/* Tab bar */}
      <div style={{
        display: "flex", gap: "2px", padding: "0 24px", marginBottom: "4px",
        borderBottom: "1px solid var(--tc-input)",
      }}>
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
                display: "flex", alignItems: "center", gap: "6px",
                padding: "10px 18px", fontSize: "12px", fontWeight: 600,
                color: isActive ? "#d03020" : "var(--tc-text-muted)",
                borderBottom: isActive ? "2px solid #d03020" : "2px solid transparent",
                background: "transparent", border: "none", borderBottomStyle: "solid",
                cursor: "pointer", transition: "all 150ms",
              }}
            >
              <Icon size={14} />
              {tab.label}
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
    </div>
  );
}

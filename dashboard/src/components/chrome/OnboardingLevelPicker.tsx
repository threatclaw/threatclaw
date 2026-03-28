"use client";

import React from "react";
import { Compass, BookOpen, Zap } from "lucide-react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import { OnboardingLevel } from "@/lib/useOnboarding";

interface Props {
  onSelect: (level: OnboardingLevel) => void;
}

const LEVELS: { id: OnboardingLevel; icon: typeof Compass; labelKey: string; descKey: string; color: string; bg: string; border: string }[] = [
  { id: "discovery", icon: Compass, labelKey: "onboardingDiscovery", descKey: "onboardingDiscoveryDesc", color: "var(--tc-red)", bg: "rgba(208,48,32,0.08)", border: "rgba(208,48,32,0.2)" },
  { id: "standard", icon: BookOpen, labelKey: "onboardingStandard", descKey: "onboardingStandardDesc", color: "var(--tc-blue)", bg: "rgba(48,128,208,0.08)", border: "rgba(48,128,208,0.2)" },
  { id: "expert", icon: Zap, labelKey: "onboardingExpert", descKey: "onboardingExpertDesc", color: "var(--tc-green)", bg: "rgba(48,160,80,0.08)", border: "rgba(48,160,80,0.2)" },
];

export default function OnboardingLevelPicker({ onSelect }: Props) {
  const locale = useLocale();

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9999,
      background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center",
      backdropFilter: "blur(4px)", WebkitBackdropFilter: "blur(4px)",
    }}>
      <div style={{
        background: "var(--tc-bg)", border: "1px solid var(--tc-border)",
        borderRadius: "var(--tc-radius-md)", padding: "32px", maxWidth: "480px", width: "100%",
      }}>
        <h2 style={{ fontSize: "16px", fontWeight: 800, color: "var(--tc-text)", marginBottom: "6px", textAlign: "center" }}>
          {tr("onboardingChooseLevel", locale)}
        </h2>
        <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "20px" }}>
          {LEVELS.map(level => {
            const Icon = level.icon;
            return (
              <button key={level.id} onClick={() => onSelect(level.id)} style={{
                display: "flex", alignItems: "center", gap: "14px",
                padding: "16px 18px", borderRadius: "var(--tc-radius-card)",
                background: level.bg, border: `1px solid ${level.border}`,
                cursor: "pointer", textAlign: "left", fontFamily: "inherit",
                transition: "all 0.2s ease", color: "inherit",
              }}>
                <div style={{
                  width: "40px", height: "40px", borderRadius: "50%", flexShrink: 0,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  background: level.bg, border: `1px solid ${level.border}`,
                }}>
                  <Icon size={18} color={level.color} />
                </div>
                <div>
                  <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)" }}>
                    {tr(level.labelKey, locale)}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginTop: "2px" }}>
                    {tr(level.descKey, locale)}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

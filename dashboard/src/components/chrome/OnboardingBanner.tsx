"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { X, Check, ChevronRight, Rocket } from "lucide-react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import { OnboardingStep } from "@/lib/useOnboarding";

interface Props {
  steps: OnboardingStep[];
  completed: number;
  total: number;
  onDismiss: () => void;
  onStepClick?: (step: OnboardingStep) => void;
}

export default function OnboardingBanner({ steps, completed, total, onDismiss, onStepClick }: Props) {
  const locale = useLocale();
  const router = useRouter();
  const [showConfirm, setShowConfirm] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const pct = Math.round((completed / total) * 100);

  // All done — show completion message briefly, then hide
  if (completed >= total) {
    return (
      <div style={{
        padding: "10px 20px", display: "flex", alignItems: "center", gap: "10px",
        background: "rgba(48,160,80,0.06)", border: "1px solid rgba(48,160,80,0.15)",
        borderRadius: "var(--tc-radius-md)", marginBottom: "16px",
      }}>
        <Check size={14} color="#30a050" />
        <span style={{ fontSize: "12px", fontWeight: 700, color: "#30a050", flex: 1 }}>
          {tr("onboardingComplete", locale)}
        </span>
      </div>
    );
  }

  const handleStepClick = (step: OnboardingStep) => {
    if (step.done) return;
    if (onStepClick) onStepClick(step);
    if (step.href) {
      const url = step.configTab ? `${step.href}?configTab=${step.configTab}` : step.href;
      // Use window.location for hash+query combo to work properly
      window.location.href = url;
    }
  };

  const nextStep = steps.find(s => !s.done);

  return (
    <>
      <div style={{
        padding: "10px 16px", display: "flex", alignItems: "center", gap: "12px",
        background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
        borderRadius: "var(--tc-radius-md)", marginBottom: "16px",
        cursor: "pointer",
      }}
        onClick={() => setExpanded(!expanded)}>
        <Rocket size={14} color="var(--tc-red)" />

        {/* Progress bar */}
        <div style={{ flex: 1, display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{ flex: 1, height: "4px", borderRadius: "2px", background: "var(--tc-input)", overflow: "hidden" }}>
            <div style={{
              height: "100%", borderRadius: "2px", background: pct >= 100 ? "#30a050" : "var(--tc-red)",
              width: `${pct}%`, transition: "width 0.5s ease",
            }} />
          </div>
          <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text)", whiteSpace: "nowrap" }}>
            {completed}/{total}
          </span>
        </div>

        {/* Next step hint */}
        {nextStep && (
          <span style={{ fontSize: "10px", color: "var(--tc-text-muted)", whiteSpace: "nowrap", display: "flex", alignItems: "center", gap: "4px" }}>
            {tr("next", locale)}: {tr(nextStep.labelKey, locale)}
            <ChevronRight size={10} />
          </span>
        )}

        {/* Title */}
        <span style={{ fontSize: "10px", fontWeight: 600, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", whiteSpace: "nowrap" }}>
          {tr("onboardingTitle", locale)}
        </span>

        {/* Dismiss */}
        <button onClick={e => { e.stopPropagation(); setShowConfirm(true); }} style={{
          background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)",
          padding: "2px", display: "flex", alignItems: "center",
        }}>
          <X size={12} />
        </button>
      </div>

      {/* Expanded steps */}
      {expanded && (
        <div style={{
          display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: "6px",
          marginTop: "-10px", marginBottom: "16px",
        }}>
          {steps.map(step => (
            <button key={step.id} onClick={() => handleStepClick(step)} style={{
              display: "flex", alignItems: "center", gap: "6px",
              padding: "8px 10px", borderRadius: "var(--tc-radius-sm)",
              background: step.done ? "rgba(48,160,80,0.06)" : "var(--tc-surface-alt)",
              border: step.done ? "1px solid rgba(48,160,80,0.15)" : "1px solid var(--tc-border)",
              cursor: step.done ? "default" : "pointer",
              fontSize: "10px", fontWeight: 600, fontFamily: "inherit",
              color: step.done ? "#30a050" : "var(--tc-text-sec)",
              opacity: step.done ? 0.7 : 1,
              transition: "all 0.2s",
              textAlign: "left",
            }}>
              <div style={{
                width: "16px", height: "16px", borderRadius: "50%", flexShrink: 0,
                display: "flex", alignItems: "center", justifyContent: "center",
                background: step.done ? "#30a050" : "var(--tc-input)",
                border: step.done ? "none" : "1px solid var(--tc-border)",
              }}>
                {step.done && <Check size={9} color="#fff" />}
              </div>
              {tr(step.labelKey, locale)}
            </button>
          ))}
        </div>
      )}

      {/* Dismiss confirmation modal */}
      {showConfirm && (
        <div style={{
          position: "fixed", inset: 0, zIndex: 9999,
          background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center",
        }} onClick={() => setShowConfirm(false)}>
          <div onClick={e => e.stopPropagation()} style={{
            background: "var(--tc-bg)", border: "1px solid var(--tc-border)",
            borderRadius: "var(--tc-radius-md)", padding: "24px", maxWidth: "380px",
          }}>
            <p style={{ fontSize: "13px", color: "var(--tc-text)", marginBottom: "16px", lineHeight: 1.6 }}>
              {tr("onboardingDismissConfirm", locale)}
            </p>
            <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end" }}>
              <button onClick={() => setShowConfirm(false)} style={{
                padding: "8px 16px", fontSize: "12px", fontWeight: 600, fontFamily: "inherit",
                background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                borderRadius: "var(--tc-radius-md)", color: "var(--tc-text-sec)", cursor: "pointer",
              }}>
                {tr("onboardingDismissNo", locale)}
              </button>
              <button onClick={() => { setShowConfirm(false); onDismiss(); }} style={{
                padding: "8px 16px", fontSize: "12px", fontWeight: 600, fontFamily: "inherit",
                background: "var(--tc-red)", border: "none",
                borderRadius: "var(--tc-radius-md)", color: "#fff", cursor: "pointer",
              }}>
                {tr("onboardingDismissYes", locale)}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

"use client";

import { useEffect, useRef } from "react";
import { driver, DriveStep } from "driver.js";
import "driver.js/dist/driver.css";
import { t as tr, Locale } from "@/lib/i18n";

interface Props {
  tourId: string;
  locale: Locale;
  level: "discovery" | "standard" | "expert";
  toursCompleted: string[];
  onComplete: (tourId: string) => void;
  steps: { element: string; titleKey?: string; descKey: string; side?: "top" | "bottom" | "left" | "right" }[];
  autoStart?: boolean;
}

export default function OnboardingTour({ tourId, locale, level, toursCompleted, onComplete, steps, autoStart }: Props) {
  const started = useRef(false);

  useEffect(() => {
    // Don't run in expert mode
    if (level === "expert") return;
    // Already completed this tour
    if (toursCompleted.includes(tourId)) return;
    // In standard mode, only run if autoStart is explicitly true (manual trigger)
    if (level === "standard" && !autoStart) return;
    // Prevent double-start in strict mode
    if (started.current) return;
    started.current = true;

    // Small delay to ensure DOM is ready
    const timer = setTimeout(() => {
      const driverSteps: DriveStep[] = steps
        .filter(s => document.querySelector(s.element))
        .map(s => ({
          element: s.element,
          popover: {
            title: s.titleKey ? tr(s.titleKey, locale) : undefined,
            description: tr(s.descKey, locale),
            side: s.side || "bottom",
          },
        }));

      if (driverSteps.length === 0) return;

      const d = driver({
        showProgress: true,
        showButtons: ["next", "previous", "close"],
        nextBtnText: locale === "fr" ? "Suivant" : "Next",
        prevBtnText: locale === "fr" ? "Précédent" : "Previous",
        doneBtnText: locale === "fr" ? "Terminé" : "Done",
        progressText: locale === "fr" ? "{{current}} sur {{total}}" : "{{current}} of {{total}}",
        popoverClass: "tc-driver-popover",
        overlayColor: "rgba(0, 0, 0, 0.6)",
        stagePadding: 8,
        stageRadius: 8,
        steps: driverSteps,
        onDestroyed: () => {
          onComplete(tourId);
        },
      });

      d.drive();
    }, 800);

    return () => clearTimeout(timer);
  }, [tourId, locale, level, toursCompleted, autoStart]); // eslint-disable-line react-hooks/exhaustive-deps

  return null;
}

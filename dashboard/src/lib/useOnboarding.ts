"use client";

import { useState, useEffect, useCallback } from "react";

export type OnboardingLevel = "discovery" | "standard" | "expert";

export interface OnboardingStep {
  id: string;
  labelKey: string;
  done: boolean;
  href?: string;
  configTab?: string;
}

export interface OnboardingState {
  level: OnboardingLevel;
  dismissed: boolean;
  steps: OnboardingStep[];
  toursCompleted: string[];
  completed: number;
  total: number;
  loading: boolean;
}

const STEP_DEFS: { id: string; labelKey: string; href?: string; configTab?: string }[] = [
  { id: "admin", labelKey: "obStepAdmin" },
  { id: "company", labelKey: "obStepCompany", href: "/setup#config", configTab: "company" },
  { id: "ai", labelKey: "obStepAi", href: "/setup#config", configTab: "llm" },
  { id: "channel", labelKey: "obStepChannel", href: "/setup#config", configTab: "channels" },
  { id: "networks", labelKey: "obStepNetworks", href: "/setup#config", configTab: "company" },
  { id: "skill", labelKey: "obStepSkill", href: "/skills?search=nmap" },
  { id: "logs", labelKey: "obStepLogs", href: "/setup#config", configTab: "sources" },
  { id: "scan", labelKey: "obStepScan", href: "/skills" },
];

/** Client-side aggregation of onboarding status from existing APIs */
async function checkSteps(): Promise<Record<string, boolean>> {
  const checks: Record<string, boolean> = { admin: true }; // always true if logged in

  try {
    // Fetch config, health, networks, logs stats, assets, company in parallel
    const [configRes, healthRes, networksRes, logsRes, assetsRes, companyRes] = await Promise.allSettled([
      fetch("/api/tc/config").then(r => r.json()),
      fetch("/api/tc/health").then(r => r.json()),
      fetch("/api/tc/networks").then(r => r.json()),
      fetch("/api/tc/logs/stats").then(r => r.json()),
      fetch("/api/tc/assets").then(r => r.json()),
      fetch("/api/tc/company").then(r => r.json()),
    ]);

    const config = configRes.status === "fulfilled" ? configRes.value : {};
    const health = healthRes.status === "fulfilled" ? healthRes.value : {};
    const networks = networksRes.status === "fulfilled" ? networksRes.value : {};
    const logs = logsRes.status === "fulfilled" ? logsRes.value : {};
    const assets = assetsRes.status === "fulfilled" ? assetsRes.value : {};
    const company = companyRes.status === "fulfilled" ? companyRes.value : {};

    // Company profile — company_name non-empty
    checks.company = !!(company.company_name && company.company_name.trim());

    // AI configured — LLM connected
    checks.ai = !!(health.llm || (health.ml && health.ml.alive) || config.llm?.model);

    // Channel connected — at least 1 enabled with token
    const channels = config.channels || {};
    checks.channel = Object.values(channels).some((ch: any) => ch.enabled && (ch.botToken || ch.accessToken || ch.webhookUrl || ch.host || ch.appToken));

    // Networks declared
    checks.networks = ((networks.networks || []).length > 0);

    // Skill configured — at least 1 skill has custom config (target, api_key, etc.)
    // Check if any skill has been run by looking at installed skills with config
    const skills = config.skills || {};
    checks.skill = Object.values(skills).some((s: any) => s.target || s.api_key || s.configured);

    // Logs received
    checks.logs = ((logs.today || 0) > 0);

    // First scan — at least 1 asset or finding
    const assetList = assets.assets || assets || [];
    checks.scan = (Array.isArray(assetList) ? assetList.length > 0 : false);
  } catch {
    // On error, keep admin=true, rest=false
  }

  return checks;
}

export function useOnboarding() {
  const [state, setState] = useState<OnboardingState>({
    level: "standard",
    dismissed: false,
    steps: STEP_DEFS.map(s => ({ ...s, done: false })),
    toursCompleted: [],
    completed: 0,
    total: STEP_DEFS.length,
    loading: true,
  });

  const refresh = useCallback(async () => {
    // Load onboarding preferences from config
    let level: OnboardingLevel = "standard";
    let dismissed = false;
    let toursCompleted: string[] = [];

    try {
      const configRes = await fetch("/api/tc/config");
      const config = await configRes.json();
      level = config.onboarding_level || "standard";
      dismissed = config.onboarding_dismissed ?? false;
      toursCompleted = config.tours_completed || [];
    } catch { /* defaults */ }

    // Check step completion from real APIs
    const checks = await checkSteps();

    const steps = STEP_DEFS.map(def => ({
      ...def,
      done: checks[def.id] ?? false,
    }));
    const completed = steps.filter(s => s.done).length;

    setState({
      level,
      dismissed,
      steps,
      toursCompleted,
      completed,
      total: STEP_DEFS.length,
      loading: false,
    });
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const setLevel = useCallback(async (level: OnboardingLevel) => {
    setState(prev => ({ ...prev, level }));
    try {
      await fetch("/api/tc/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ onboarding_level: level }),
      });
    } catch { /* */ }
  }, []);

  const dismiss = useCallback(async () => {
    setState(prev => ({ ...prev, dismissed: true }));
    try {
      await fetch("/api/tc/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ onboarding_dismissed: true }),
      });
    } catch { /* */ }
  }, []);

  const undismiss = useCallback(async () => {
    setState(prev => ({ ...prev, dismissed: false }));
    try {
      await fetch("/api/tc/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ onboarding_dismissed: false }),
      });
    } catch { /* */ }
  }, []);

  const markTourCompleted = useCallback(async (tourId: string) => {
    setState(prev => {
      const updated = prev.toursCompleted.includes(tourId) ? prev.toursCompleted : [...prev.toursCompleted, tourId];
      // Persist
      fetch("/api/tc/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tours_completed: updated }),
      }).catch(() => {});
      return { ...prev, toursCompleted: updated };
    });
  }, []);

  return { ...state, refresh, setLevel, dismiss, undismiss, markTourCompleted };
}

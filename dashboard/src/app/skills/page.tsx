"use client";

import React, { useState, useEffect, useCallback } from "react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import {
  Search, Settings, Shield, Network, Database, Code, Monitor,
  FileText, Eye, Crosshair, RefreshCw, CheckCircle2,
  Key, Clock, Zap, Power, Play, X, Trash2, Plus, Server,
  ChevronDown, ChevronRight, Download, Wifi, Loader2,
  Plug, AlertTriangle, Lock,
} from "lucide-react";
import { NeuCard } from "@/components/chrome/NeuCard";

interface SkillManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  type: string;
  category: string;
  trust?: string;
  premium?: boolean;
  remediation?: boolean;
  execution: any;
  config: Record<string, any> | null;
  default_active: boolean;
  requires_config: boolean;
  api_key_required: boolean;
  icon: string;
  price?: number;
}

// ── Type definitions for UI ──
const TYPE_UI_BASE: Record<string, { labelKey: string; descKey: string; icon: React.ElementType; color: string }> = {
  "connector": { labelKey: "connectors", descKey: "collectData", icon: Plug, color: "var(--tc-blue)" },
  "enrichment": { labelKey: "intelligenceSkills", descKey: "ctiEnrichment", icon: Search, color: "var(--tc-green)" },
  "tool": { labelKey: "actions", descKey: "remediationResponse", icon: Zap, color: "var(--tc-amber)" },
};

// ── Trust level badges ──
const TRUST_UI: Record<string, { labelKey: string; shortLabel: string; color: string; bg: string; border: string }> = {
  "official": { labelKey: "official", shortLabel: "TC", color: "#d03020", bg: "rgba(208,48,32,0.12)", border: "rgba(208,48,32,0.25)" },
  "verified": { labelKey: "verified", shortLabel: "✓", color: "#30a050", bg: "rgba(48,160,80,0.12)", border: "rgba(48,160,80,0.25)" },
  "community": { labelKey: "communautaire", shortLabel: "!", color: "#d09020", bg: "rgba(208,144,32,0.12)", border: "rgba(208,144,32,0.25)" },
};

const RUNNABLE: Record<string, string> = {
  "skill-semgrep": "/api/tc/skills/run/skill-semgrep",
  "skill-checkov": "/api/tc/skills/run/skill-checkov",
  "skill-trufflehog": "/api/tc/skills/run/skill-trufflehog",
  "skill-grype": "/api/tc/skills/run/skill-grype",
  "skill-syft": "/api/tc/skills/run/skill-syft",
  "skill-lynis": "/api/tc/skills/run/skill-lynis",
  "skill-docker-bench": "/api/tc/skills/run/skill-docker-bench",
  "skill-nmap-discovery": "/api/tc/connectors/nmap/scan",
  "skill-active-directory": "/api/tc/connectors/ad/sync",
  "skill-pfsense": "/api/tc/connectors/firewall/sync",
  "skill-proxmox": "/api/tc/connectors/proxmox/sync",
  "skill-fortinet": "/api/tc/connectors/fortinet/sync",
  "skill-wazuh-connector": "/api/tc/connectors/wazuh/sync",
  "skill-glpi": "/api/tc/connectors/glpi/sync",
  "skill-freebox": "/api/tc/connectors/freebox/sync",
};

const NOT_FUNCTIONAL: Set<string> = new Set([
  "skill-ad-audit", "skill-cloud-posture", "skill-vuln-scan",
  "skill-httpx", "skill-subfinder", "skill-trivy", "skill-zap", "skill-sigma-rules",
]);

// Skills with code written but not yet validated in production
const BETA_SKILLS: Set<string> = new Set([
  "skill-active-directory", "skill-pfsense", "skill-proxmox", "skill-fortinet",
  "skill-wazuh", "skill-wazuh-connector", "skill-glpi", "skill-defectdojo",
  "skill-pihole", "skill-unifi", "skill-zeek", "skill-suricata",
  "skill-crowdsec-connector", "skill-cloudflare", "skill-uptimerobot",
  "skill-semgrep", "skill-checkov", "skill-trufflehog", "skill-grype",
  "skill-syft", "skill-docker-bench", "skill-lynis",
  "skill-darkweb-monitor", "skill-email-audit", "skill-report-gen",
  "skill-compliance-nis2", "skill-compliance-iso27001",
]);

function TrustBadge({ trust, locale }: { trust: string; locale: "fr" | "en" }) {
  const t = TRUST_UI[trust] || TRUST_UI["community"];
  return (
    <span style={{
      fontSize: "8px", fontWeight: 800, padding: "2px 6px", borderRadius: "4px",
      background: t.bg, color: t.color, border: `1px solid ${t.border}`,
      textTransform: "uppercase", letterSpacing: "0.03em", whiteSpace: "nowrap",
    }}>
      {t.shortLabel === "✓" ? "✓ " : ""}{tr(t.labelKey, locale)}
    </span>
  );
}

function TypeBadge({ type }: { type: string }) {
  const base = TYPE_UI_BASE[type];
  const t = base ? { label: base.labelKey, color: base.color } : { label: type, color: "var(--tc-text-muted)" };
  return (
    <span style={{
      fontSize: "8px", fontWeight: 700, padding: "1px 5px", borderRadius: "3px",
      background: `${t.color}15`, color: t.color, textTransform: "uppercase",
    }}>
      {t.label}
    </span>
  );
}

export default function SkillsPage() {
  const locale = useLocale();
  const [allSkills, setAllSkills] = useState<SkillManifest[]>([]);
  const [enabled, setEnabled] = useState<Set<string>>(new Set());
  const [tab, setTab] = useState<"installed" | "catalog">("installed");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [trustFilter, setTrustFilter] = useState<string>("all");
  const [modalSkill, setModalSkill] = useState<SkillManifest | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, Record<string, string>>>({});
  const [running, setRunning] = useState<string | null>(null);
  const [runResult, setRunResult] = useState<any>(null);
  const [installing, setInstalling] = useState<SkillManifest | null>(null);
  const [installDone, setInstallDone] = useState(false);
  const [installMsg, setInstallMsg] = useState("");
  const [expandedCatalog, setExpandedCatalog] = useState<string | null>(null);
  const [disabledSkills, setDisabledSkills] = useState<Set<string>>(new Set());

  const refresh = useCallback(async () => {
    try {
      const res = await fetch("/api/tc/catalog");
      if (res.ok) {
        const data = await res.json();
        setAllSkills(data.skills || []);
        const active = new Set<string>();
        (data.skills || []).forEach((s: SkillManifest) => { if (s.default_active) active.add(s.id); });
        const saved = localStorage.getItem("tc_installed_skills");
        if (saved) { try { JSON.parse(saved).forEach((id: string) => active.add(id)); } catch {} }
        const savedDisabled = localStorage.getItem("tc_disabled_skills");
        if (savedDisabled) { try { setDisabledSkills(new Set(JSON.parse(savedDisabled))); } catch {} }
        setEnabled(active);
      }
    } catch {}
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Load from backend on mount
  useEffect(() => {
    fetch("/api/tc/config?key=_skills_state", { signal: AbortSignal.timeout(3000) })
      .then(r => r.json())
      .then(d => {
        if (d._skills_state?.installed) {
          const backendInstalled = new Set<string>(d._skills_state.installed);
          const backendDisabled = new Set<string>(d._skills_state.disabled || []);
          setEnabled(prev => { const m = new Set(prev); backendInstalled.forEach(id => m.add(id)); return m; });
          setDisabledSkills(backendDisabled);
          localStorage.setItem("tc_installed_skills", JSON.stringify(d._skills_state.installed));
          localStorage.setItem("tc_disabled_skills", JSON.stringify(d._skills_state.disabled || []));
        }
      })
      .catch(() => {});
  }, []);

  const mySkills = allSkills.filter(s => enabled.has(s.id));
  const catalogSkills = allSkills.filter(s => !enabled.has(s.id));

  // Group installed skills by type
  const groupByType = (skills: SkillManifest[]) => {
    const groups: Record<string, SkillManifest[]> = { connector: [], enrichment: [], tool: [] };
    for (const s of skills) {
      const type = s.type || "enrichment";
      if (!groups[type]) groups[type] = [];
      groups[type].push(s);
    }
    return groups;
  };

  // Filter catalog
  const filteredCatalog = catalogSkills
    .filter(s => typeFilter === "all" || s.type === typeFilter)
    .filter(s => trustFilter === "all" || (s.trust || "official") === trustFilter)
    .filter(s => !search.trim() || s.name.toLowerCase().includes(search.toLowerCase()) || s.description.toLowerCase().includes(search.toLowerCase()));

  const persistSkills = (enabledSet: Set<string>, disabledSet: Set<string>) => {
    const enabledArr = Array.from(enabledSet);
    const disabledArr = Array.from(disabledSet);
    localStorage.setItem("tc_installed_skills", JSON.stringify(enabledArr));
    localStorage.setItem("tc_disabled_skills", JSON.stringify(disabledArr));
    fetch("/api/tc/config", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: "_skills_state", value: { installed: enabledArr, disabled: disabledArr } }),
    }).catch(() => {});
  };

  const install = (skill: SkillManifest) => {
    // Block community remediation skills
    if ((skill.trust === "community") && (skill.type === "tool" || skill.remediation)) {
      return; // Blocked by UI — should never reach here
    }
    setInstalling(skill);
    setInstallDone(false);
    setInstallMsg(tr("installing", locale));
    fetch(`/api/tc/skills/${skill.id}/config`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: true, ...(configValues[skill.id] || {}) }),
    }).catch(() => {});
    setTimeout(() => {
      setEnabled(prev => { const n = new Set(prev).add(skill.id); persistSkills(n, disabledSkills); return n; });
      setDisabledSkills(prev => { const n = new Set(prev); n.delete(skill.id); return n; });
      setInstallDone(true);
      setInstallMsg(`${skill.name} ${tr('installed', locale)}`);
      setTimeout(() => { setInstalling(null); setInstallDone(false); }, 2000);
    }, 1500);
  };

  const uninstall = (id: string) => {
    setModalSkill(null);
    const skill = allSkills.find(s => s.id === id);
    setInstalling(skill || null);
    setInstallDone(false);
    setInstallMsg(tr("uninstalling", locale));
    fetch(`/api/tc/skills/${id}/config`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: false }),
    }).catch(() => {});
    setTimeout(() => {
      setEnabled(prev => { const n = new Set(prev); n.delete(id); persistSkills(n, disabledSkills); return n; });
      setDisabledSkills(prev => { const n = new Set(prev); n.delete(id); return n; });
      setInstallDone(true);
      setInstallMsg(`${skill?.name || 'Skill'} ${tr('uninstalled', locale)}`);
      setTimeout(() => { setInstalling(null); setInstallDone(false); }, 1500);
    }, 1000);
  };

  const toggleActive = (id: string) => {
    setDisabledSkills(prev => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id); else n.add(id);
      persistSkills(enabled, n);
      return n;
    });
  };

  const setConfig = (sid: string, key: string, val: string) => {
    setConfigValues(prev => ({ ...prev, [sid]: { ...prev[sid], [key]: val } }));
  };

  const handleRun = async (skill: SkillManifest) => {
    const url = RUNNABLE[skill.id]; if (!url) return;
    setRunning(skill.id); setRunResult(null);
    try {
      const body: any = { ...(configValues[skill.id] || {}) };
      if (skill.id === "skill-nmap-discovery") body.targets = body.target_subnets || "192.168.1.0/24";
      const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      setRunResult(await res.json());
    } catch (e: any) { setRunResult({ error: e.message }); }
    setRunning(null);
  };

  const installedGroups = groupByType(mySkills);

  return (
    <div style={{ padding: "0 24px 40px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>Skills</h1>
        <button className="tc-btn-embossed" onClick={refresh}><RefreshCw size={12} /> Actualiser</button>
      </div>

      {/* ── Sliding tabs ── */}
      <div style={{ position: "relative", display: "flex", padding: "3px", marginBottom: "16px", borderRadius: "11px", background: "var(--tc-input)" }}>
        <div style={{ position: "absolute", top: "3px", height: "calc(100% - 6px)", width: "calc(50% - 2px)",
          left: tab === "installed" ? "1px" : "calc(50% + 1px)",
          background: "var(--tc-surface-alt)", borderRadius: "8px", border: "0.5px solid var(--tc-border)",
          boxShadow: "0 3px 8px rgba(0,0,0,0.12)", transition: "left 0.25s ease-out", zIndex: 0 }} />
        {([
          ["installed", `${tr("installed2", locale)} (${mySkills.length})`],
          ["catalog", `${tr("catalogue", locale)} (${catalogSkills.length})`],
        ] as const).map(([k, l]) => (
          <button key={k} onClick={() => setTab(k as any)} style={{ flex: 1, padding: "8px 0", fontSize: "12px", fontWeight: 600,
            color: tab === k ? "var(--tc-text)" : "var(--tc-text-muted)", background: "transparent", border: "none",
            cursor: "pointer", position: "relative", zIndex: 1, opacity: tab === k ? 1 : 0.5, transition: "all 200ms" }}>{l}</button>
        ))}
      </div>

      {/* ═══ INSTALLED — grouped by type ═══ */}
      {tab === "installed" && (
        <div>
          {mySkills.length === 0 && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-faint)" }}>
              {tr("noSkillsActive", locale)}
            </div>
          )}

          {(["connector", "enrichment", "tool"] as const).map(type => {
            const skills = installedGroups[type] || [];
            if (skills.length === 0) return null;
            const ui = TYPE_UI_BASE[type];
            const Icon = ui.icon;
            return (
              <div key={type} style={{ marginBottom: "20px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px", paddingBottom: "6px", borderBottom: `2px solid ${ui.color}20` }}>
                  <Icon size={15} color={ui.color} />
                  <span style={{ fontSize: "12px", fontWeight: 800, color: ui.color, textTransform: "uppercase", letterSpacing: "0.05em" }}>{tr(ui.labelKey, locale)}</span>
                  <span style={{ fontSize: "10px", color: "var(--tc-text-faint)" }}>({skills.length})</span>
                  <span style={{ fontSize: "9px", color: "var(--tc-text-muted)", fontStyle: "italic", marginLeft: "auto" }}>{tr(ui.descKey, locale)}</span>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: "8px" }}>
                  {skills.map(skill => {
                    const isRunning = running === skill.id;
                    const isDisabled = disabledSkills.has(skill.id);
                    const trust = skill.trust || "official";
                    return (
                      <div key={skill.id} style={{
                        display: "flex", alignItems: "center", gap: "10px", padding: "10px 12px",
                        borderRadius: "var(--tc-radius-md)", background: "var(--tc-neu-inner)",
                        border: isRunning ? "1px solid var(--tc-red-border)" : "1px solid transparent",
                        boxShadow: "inset 0 2px 6px rgba(0,0,0,0.25), inset 0 1px 2px rgba(0,0,0,0.2), 0 1px 0 rgba(255,255,255,0.08)",
                        opacity: isDisabled ? 0.5 : 1, transition: "all 200ms",
                      }}>
                        <input type="checkbox" className="tc-toggle" checked={!isDisabled} onChange={() => toggleActive(skill.id)} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                            <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{skill.name}</span>
                            {isRunning && <div className="tc-spin-loader" />}
                          </div>
                          <div style={{ display: "flex", alignItems: "center", gap: "4px", marginTop: "2px" }}>
                            <TrustBadge trust={trust} locale={locale} />
                            {BETA_SKILLS.has(skill.id) && (
                              <span style={{ fontSize: "7px", fontWeight: 800, padding: "1px 5px", borderRadius: "3px", background: "rgba(208,144,32,0.12)", color: "var(--tc-amber)", textTransform: "uppercase" }} title={tr("betaSkillHint", locale)}>{tr("beta", locale)}</span>
                            )}
                            {skill.api_key_required && <Key size={9} color="var(--tc-amber)" />}
                          </div>
                        </div>
                        <button onClick={() => { setRunResult(null); setModalSkill(skill); }}
                          style={{ padding: "6px", borderRadius: "6px", background: "transparent", border: "none", color: "var(--tc-text-muted)", cursor: "pointer" }}>
                          <Settings size={14} />
                        </button>
                      </div>
                    );
                  })}
                </div>

                {/* Lock notice for Actions section */}
                {type === "tool" && (
                  <div style={{
                    display: "flex", alignItems: "center", gap: "8px", marginTop: "8px",
                    padding: "8px 12px", borderRadius: "var(--tc-radius-sm)",
                    background: "rgba(208,144,32,0.05)", border: "1px dashed rgba(208,144,32,0.2)",
                    fontSize: "9px", color: "var(--tc-text-muted)",
                  }}>
                    <Lock size={10} color="var(--tc-amber)" />
                    {tr("onlyVerified", locale)}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ═══ CATALOGUE ═══ */}
      {tab === "catalog" && (
        <div>
          {/* Search + filters */}
          <div style={{ display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap" }}>
            <div style={{ position: "relative", flex: 1, minWidth: "200px" }}>
              <Search size={14} style={{ position: "absolute", left: "10px", top: "9px", color: "var(--tc-text-muted)" }} />
              <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder={tr("search", locale)}
                style={{ width: "100%", padding: "8px 10px 8px 32px", borderRadius: "var(--tc-radius-input)", fontSize: "12px",
                  background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", outline: "none" }} />
            </div>
            {/* Type filter pills */}
            <div style={{ display: "flex", gap: "4px" }}>
              {[
                { key: "all", label: tr("allTypes", locale) },
                { key: "connector", label: tr("connectors", locale) },
                { key: "enrichment", label: tr("intelligenceSkills", locale) },
                { key: "tool", label: tr("actions", locale) },
              ].map(f => (
                <button key={f.key} onClick={() => setTypeFilter(f.key)} style={{
                  padding: "6px 10px", fontSize: "10px", fontWeight: 600, borderRadius: "6px", cursor: "pointer",
                  background: typeFilter === f.key ? "var(--tc-surface-alt)" : "transparent",
                  border: typeFilter === f.key ? "1px solid var(--tc-border)" : "1px solid transparent",
                  color: typeFilter === f.key ? "var(--tc-text)" : "var(--tc-text-muted)",
                }}>{f.label}</button>
              ))}
            </div>
            {/* Trust filter pills */}
            <div style={{ display: "flex", gap: "4px" }}>
              {[
                { key: "all", label: tr("allTypes", locale), color: "var(--tc-text-muted)" },
                { key: "official", label: "TC", color: "#d03020" },
                { key: "verified", label: `✓ ${tr("verified", locale)}`, color: "#30a050" },
                { key: "community", label: tr("communautaire", locale), color: "#d09020" },
              ].map(f => (
                <button key={f.key} onClick={() => setTrustFilter(f.key)} style={{
                  padding: "6px 10px", fontSize: "10px", fontWeight: 600, borderRadius: "6px", cursor: "pointer",
                  background: trustFilter === f.key ? "var(--tc-surface-alt)" : "transparent",
                  border: trustFilter === f.key ? "1px solid var(--tc-border)" : "1px solid transparent",
                  color: trustFilter === f.key ? f.color : "var(--tc-text-muted)",
                }}>{f.label}</button>
              ))}
            </div>
          </div>

          {filteredCatalog.length === 0 && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-faint)" }}>
              {search ? tr("noSkillFound", locale) : tr("allInstalled", locale)}
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: "8px" }}>
            {filteredCatalog.map(skill => {
              const trust = skill.trust || "official";
              const trustUi = TRUST_UI[trust] || TRUST_UI["community"];
              const typeUi = TYPE_UI_BASE[skill.type] || TYPE_UI_BASE["enrichment"];
              const notReady = NOT_FUNCTIONAL.has(skill.id);
              const isCommunityAction = trust === "community" && (skill.type === "tool" || skill.remediation);
              const isExp = expandedCatalog === skill.id;

              return (
                <div key={skill.id} style={{
                  borderRadius: "var(--tc-radius-md)", background: "var(--tc-neu-inner)", overflow: "hidden",
                  boxShadow: "inset 0 2px 6px rgba(0,0,0,0.25), inset 0 1px 2px rgba(0,0,0,0.2), 0 1px 0 rgba(255,255,255,0.08)",
                  opacity: notReady ? 0.45 : 1, border: "1px solid transparent",
                }}>
                  <div onClick={() => setExpandedCatalog(isExp ? null : skill.id)} style={{
                    display: "flex", alignItems: "center", gap: "10px", padding: "10px 12px", cursor: "pointer",
                  }}>
                    {isExp ? <ChevronDown size={14} color="var(--tc-text-muted)" /> : <ChevronRight size={14} color="var(--tc-text-muted)" />}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
                        <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{skill.name}</span>
                        <TypeBadge type={skill.type} />
                        <TrustBadge trust={trust} locale={locale} />
                        {skill.api_key_required && <Key size={10} color="var(--tc-amber)" />}
                        {BETA_SKILLS.has(skill.id) && (
                          <span style={{ fontSize: "7px", fontWeight: 800, padding: "1px 5px", borderRadius: "3px", background: "rgba(208,144,32,0.12)", color: "var(--tc-amber)", textTransform: "uppercase" }} title={tr("betaSkillHint", locale)}>{tr("beta", locale)}</span>
                        )}
                        {skill.premium && <span style={{ fontSize: "8px", fontWeight: 800, padding: "2px 5px", borderRadius: "3px", background: "rgba(208,168,32,0.15)", color: "#d0a820" }}>PREMIUM</span>}
                      </div>
                    </div>
                  </div>

                  {isExp && (
                    <div style={{ padding: "0 12px 12px", borderTop: "1px solid var(--tc-border)" }}>
                      <p style={{ fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: "1.6", margin: "10px 0" }}>
                        {skill.description}
                      </p>
                      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "10px", fontSize: "9px", color: "var(--tc-text-muted)" }}>
                        {skill.version && <span>v{skill.version}</span>}
                        <span>{tr("by", locale)} : {skill.author || "ThreatClaw"}</span>
                        {skill.execution?.mode && <span>{skill.execution.mode === "ephemeral" ? "Docker" : skill.execution.mode === "persistent" ? "Sync continue" : "API"}</span>}
                      </div>

                      {isCommunityAction ? (
                        <div style={{
                          display: "flex", alignItems: "center", gap: "8px", padding: "10px 12px",
                          borderRadius: "var(--tc-radius-sm)", background: "rgba(208,48,32,0.06)",
                          border: "1px solid rgba(208,48,32,0.15)", fontSize: "10px",
                        }}>
                          <Lock size={12} color="#d03020" />
                          <div>
                            <div style={{ fontWeight: 700, color: "#d03020", marginBottom: "2px" }}>{tr("verificationRequired", locale)}</div>
                            <div style={{ color: "var(--tc-text-muted)" }}>{tr("communityReadOnly", locale)}</div>
                          </div>
                        </div>
                      ) : notReady ? (
                        <span style={{ fontSize: "8px", fontWeight: 700, padding: "2px 8px", borderRadius: "4px", background: "rgba(208,144,32,0.12)", color: "var(--tc-amber)", textTransform: "uppercase", letterSpacing: "0.05em" }}>{tr("inDevelopment", locale)}</span>
                      ) : skill.premium ? (
                        <button className="tc-btn-embossed" style={{ fontSize: "11px", padding: "6px 16px" }}>
                          Acheter {skill.price ? `${skill.price}€` : ""}
                        </button>
                      ) : (
                        <button className="tc-btn-embossed" onClick={() => install(skill)} style={{ fontSize: "11px", padding: "6px 16px" }}>
                          <Download size={12} /> Installer
                        </button>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ═══ INSTALL POPUP ═══ */}
      {installing && (
        <div style={{ position: "fixed", inset: 0, zIndex: 1001, background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)",
          display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div style={{ width: "320px", background: "var(--tc-bg)", border: "1px solid var(--tc-border)",
            borderRadius: "var(--tc-radius-card)", padding: "32px", textAlign: "center",
            boxShadow: "0 20px 60px rgba(0,0,0,0.4)" }}>
            {!installDone ? (
              <>
                <div style={{ display: "flex", justifyContent: "center", marginBottom: "24px", height: "20px" }}>
                  <div className="tc-ball-loader" />
                </div>
                <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "8px" }}>{installMsg}</div>
                <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{installing.name}</div>
              </>
            ) : (
              <>
                <div style={{ marginBottom: "12px" }}><CheckCircle2 size={36} color="var(--tc-green)" /></div>
                <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "8px" }}>{installMsg}</div>
              </>
            )}
          </div>
        </div>
      )}

      {/* ═══ CONFIG MODAL ═══ */}
      {modalSkill && (
        <div style={{ position: "fixed", inset: 0, zIndex: 1000, background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)",
          display: "flex", alignItems: "center", justifyContent: "center" }} onClick={() => setModalSkill(null)}>
          <div onClick={e => e.stopPropagation()} style={{ width: "100%", maxWidth: "500px", maxHeight: "80vh", overflow: "auto",
            background: "var(--tc-bg)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-card)", padding: "24px",
            boxShadow: "0 20px 60px rgba(0,0,0,0.4)" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <h2 style={{ fontSize: "16px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>{modalSkill.name}</h2>
                  <TrustBadge trust={modalSkill.trust || "official"} locale={locale} />
                  <TypeBadge type={modalSkill.type} />
                </div>
                <span style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>v{modalSkill.version} · {modalSkill.author || "ThreatClaw"}</span>
              </div>
              <button onClick={() => setModalSkill(null)} style={{ padding: "4px", background: "transparent", border: "none", color: "var(--tc-text-muted)", cursor: "pointer" }}><X size={18} /></button>
            </div>
            <p style={{ fontSize: "12px", color: "var(--tc-text-sec)", lineHeight: "1.6", marginBottom: "16px" }}>{modalSkill.description}</p>
            <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginBottom: "16px", fontSize: "10px", color: "var(--tc-text-muted)" }}>
              {modalSkill.execution?.mode && <span>Mode: {modalSkill.execution.mode}</span>}
              {modalSkill.execution?.docker_image && <span style={{ fontFamily: "monospace", color: "var(--tc-blue)" }}>{modalSkill.execution.docker_image}</span>}
              {modalSkill.execution?.sync_interval_minutes && <span><Clock size={9} style={{ display: "inline", verticalAlign: "middle" }} /> {modalSkill.execution.sync_interval_minutes}min</span>}
            </div>
            {modalSkill.config && Object.keys(modalSkill.config).length > 0 && (
              <div style={{ marginBottom: "16px" }}>
                <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: "8px" }}>Configuration</div>
                {Object.entries(modalSkill.config).map(([key, field]: [string, any]) => {
                  if (!field) return null;
                  const val = configValues[modalSkill.id]?.[key] || "";
                  return (
                    <div key={key} style={{ marginBottom: "10px" }}>
                      <label style={{ fontSize: "11px", color: "var(--tc-text-sec)", display: "block", marginBottom: "4px" }}>
                        {field.description || key}{field.required && <span style={{ color: "var(--tc-red)" }}> *</span>}
                      </label>
                      {field.options ? (
                        <select value={val || field.default || ""} onChange={e => setConfig(modalSkill.id, key, e.target.value)}
                          style={{ width: "100%", padding: "8px 10px", borderRadius: "var(--tc-radius-input)", fontSize: "12px",
                            background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", outline: "none" }}>
                          <option value="">Choisir...</option>
                          {field.options.map((o: string) => <option key={o} value={o}>{o}</option>)}
                        </select>
                      ) : field.type === "boolean" ? (
                        <label style={{ fontSize: "11px", color: "var(--tc-text)", display: "flex", alignItems: "center", gap: "8px" }}>
                          <input type="checkbox" className="tc-toggle" checked={val === "true" || (!val && field.default === true)}
                            onChange={e => setConfig(modalSkill.id, key, e.target.checked ? "true" : "false")} />
                          {field.default ? tr("activeByDefault", locale) : tr("inactiveByDefault", locale)}
                        </label>
                      ) : (
                        <input type={field.type === "password" ? "password" : "text"} value={val}
                          onChange={e => setConfig(modalSkill.id, key, e.target.value)} placeholder={field.default?.toString() || ""}
                          style={{ width: "100%", padding: "8px 10px", borderRadius: "var(--tc-radius-input)", fontSize: "12px",
                            background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", outline: "none" }} />
                      )}
                    </div>
                  );
                })}
              </div>
            )}
            {modalSkill.id === "skill-freebox" && <FreeboxPairingFlow url={configValues["skill-freebox"]?.freebox_url || "http://mafreebox.freebox.fr"} />}

            {runResult && (
              <div style={{ marginBottom: "16px", padding: "10px", borderRadius: "var(--tc-radius-sm)", background: "var(--tc-surface-alt)",
                border: "1px solid var(--tc-border)", fontSize: "10px", fontFamily: "monospace", color: "var(--tc-text-sec)", maxHeight: "120px", overflow: "auto" }}>
                <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(runResult, null, 2)}</pre>
              </div>
            )}
            <div style={{ display: "flex", gap: "8px", justifyContent: "space-between", paddingTop: "12px", borderTop: "1px solid var(--tc-border)" }}>
              <button onClick={() => uninstall(modalSkill.id)} style={{ display: "flex", alignItems: "center", gap: "5px",
                padding: "8px 14px", borderRadius: "var(--tc-radius-btn)", background: "var(--tc-red-soft)", border: "1px solid var(--tc-red-border)",
                color: "var(--tc-red)", fontSize: "11px", fontWeight: 600, cursor: "pointer" }}><Trash2 size={12} /> {tr("uninstall", locale)}</button>
              <div style={{ display: "flex", gap: "8px" }}>
                {RUNNABLE[modalSkill.id] && (
                  <button className="tc-btn-embossed" onClick={() => handleRun(modalSkill)} disabled={running === modalSkill.id}
                    style={{ fontSize: "11px", padding: "8px 14px" }}>
                    <Play size={12} /> {running === modalSkill.id ? "..." : modalSkill.type === "connector" ? "Sync" : "Lancer"}
                  </button>
                )}
                <button className="tc-btn-embossed" onClick={() => {
                  if (modalSkill && configValues[modalSkill.id]) {
                    fetch(`/api/tc/skills/${modalSkill.id}/config`, {
                      method: "POST", headers: { "Content-Type": "application/json" },
                      body: JSON.stringify(configValues[modalSkill.id]),
                    }).catch(() => {});
                  }
                  setModalSkill(null);
                }} style={{ fontSize: "11px", padding: "8px 14px" }}>{tr("save", locale)}</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Freebox Pairing Flow ──
function FreeboxPairingFlow({ url }: { url: string }) {
  const locale = useLocale();
  const [status, setStatus] = useState<"idle" | "requesting" | "pending" | "granted" | "denied" | "error">("idle");
  const [message, setMessage] = useState("");
  const [polling, setPolling] = useState(false);

  useEffect(() => {
    fetch("/api/tc/connectors/freebox/pair/status").then(r => r.json()).then(d => {
      if (d.status === "granted") { setStatus("granted"); setMessage(tr("freeboxPaired", locale)); }
      else if (d.status === "pending") { setStatus("pending"); setMessage(tr("freeboxWaitButton", locale)); setPolling(true); }
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!polling) return;
    const interval = setInterval(async () => {
      try {
        const res = await fetch("/api/tc/connectors/freebox/pair/status");
        const d = await res.json();
        if (d.status === "granted") { setStatus("granted"); setMessage(tr("freeboxPairedSuccess", locale)); setPolling(false); }
        else if (d.status === "denied" || d.status === "timeout") { setStatus("denied"); setMessage(tr("freeboxDenied", locale)); setPolling(false); }
      } catch {}
    }, 2000);
    return () => clearInterval(interval);
  }, [polling]);

  const requestPairing = async () => {
    setStatus("requesting"); setMessage("");
    try {
      const res = await fetch("/api/tc/connectors/freebox/pair", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) });
      const d = await res.json();
      if (d.error) { setStatus("error"); setMessage(d.error); }
      else { setStatus("pending"); setMessage(tr("freeboxPressButton", locale)); setPolling(true); }
    } catch (e: any) { setStatus("error"); setMessage(e.message || tr("networkError", locale)); }
  };

  return (
    <div style={{ padding: "14px", borderRadius: "var(--tc-radius-sm)", background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)", marginBottom: "16px" }}>
      <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
        <Wifi size={13} color="var(--tc-blue)" /> {tr("freeboxPairing", locale)}
      </div>
      {status === "granted" ? (
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
            <CheckCircle2 size={14} color="#30a050" />
            <span style={{ fontSize: "12px", fontWeight: 600, color: "#30a050" }}>{message}</span>
          </div>
          <button onClick={() => { setStatus("idle"); setMessage(""); }} style={{
            padding: "6px 12px", fontSize: "10px", fontWeight: 600, fontFamily: "inherit",
            borderRadius: "var(--tc-radius-sm)", cursor: "pointer",
            background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text-muted)",
            display: "flex", alignItems: "center", gap: "4px",
          }}><RefreshCw size={10} /> {tr("repairFreebox", locale)}</button>
        </div>
      ) : (
        <>
          <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "10px", lineHeight: 1.5 }}>
            ThreatClaw doit s{"'"}appairer avec votre Freebox une seule fois.
          </div>
          <button onClick={requestPairing} disabled={status === "requesting" || status === "pending"}
            style={{
              padding: "8px 16px", fontSize: "11px", fontWeight: 700, fontFamily: "inherit",
              borderRadius: "var(--tc-radius-sm)", cursor: status === "requesting" || status === "pending" ? "default" : "pointer",
              background: status === "pending" ? "var(--tc-amber-soft)" : "var(--tc-blue-soft)",
              color: status === "pending" ? "var(--tc-amber)" : "var(--tc-blue)",
              border: status === "pending" ? "1px solid rgba(208,144,32,0.3)" : "1px solid rgba(48,128,208,0.3)",
              display: "flex", alignItems: "center", gap: "6px", width: "100%", justifyContent: "center",
            }}>
            {status === "requesting" ? <><Loader2 size={12} className="animate-spin" /> {tr("requestInProgress", locale)}</>
              : status === "pending" ? <><Clock size={12} /> {tr("waitingFreeboxButton", locale)}</>
              : <><Wifi size={12} /> {tr("pairFreebox", locale)}</>}
          </button>
        </>
      )}
      {message && status !== "granted" && (
        <div style={{ marginTop: "8px", fontSize: "10px", color: status === "pending" ? "var(--tc-amber)" : "#d03020", display: "flex", alignItems: "center", gap: "6px" }}>
          {status === "pending" && <Loader2 size={10} className="animate-spin" />}
          {(status === "error" || status === "denied") && <X size={10} />}
          {message}
        </div>
      )}
    </div>
  );
}

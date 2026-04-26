"use client";

import React, { useState, useEffect, useCallback } from "react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import {
  Search, Settings, Shield, Network, Database, Monitor,
  Eye, Crosshair, RefreshCw, CheckCircle2,
  Key, Clock, Zap, Play, X, Trash2,
  Download, Wifi, Loader2,
  Plug, Lock, HelpCircle, Info, Globe,
} from "lucide-react";

interface HitlAction {
  name: string;
  label?: string;
  description?: string;
}

interface HitlActionsManifest {
  enabled?: boolean;
  implemented?: boolean;
  requires_separate_creds?: boolean;
  credential_fields?: Record<string, any>;
  actions?: HitlAction[];
}

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
  help?: string;
  tier?: string;
  depends_on?: string;
  advanced?: boolean;
  hitl_actions?: HitlActionsManifest;
}

// ── Type definitions for UI ──
const TYPE_UI_BASE: Record<string, { labelKey: string; icon: React.ElementType; color: string }> = {
  "connector":  { labelKey: "connectors",         icon: Plug,   color: "var(--tc-blue)" },
  "enrichment": { labelKey: "intelligenceSkills", icon: Search, color: "var(--tc-green)" },
  "tool":       { labelKey: "actions",            icon: Zap,    color: "var(--tc-amber)" },
};

// ── Category definitions for UI ──
const CATEGORY_UI: Record<string, { label: string; labelEn: string; icon: React.ElementType; color: string }> = {
  "network":      { label: "Réseau",       labelEn: "Network",      icon: Network,   color: "#d03020" },
  "endpoints":    { label: "Endpoints",    labelEn: "Endpoints",    icon: Monitor,   color: "#9060d0" },
  "inventory":    { label: "Inventaire",   labelEn: "Inventory",    icon: Database,  color: "#3080d0" },
  "scan":         { label: "Scan",         labelEn: "Scan",         icon: Crosshair, color: "#d09020" },
  "threat-intel": { label: "Threat Intel", labelEn: "Threat Intel", icon: Eye,       color: "#06b6d4" },
  "web":          { label: "Web",          labelEn: "Web",          icon: Globe,     color: "#30a050" },
};
const CATEGORY_ORDER = ["network", "endpoints", "inventory", "scan", "threat-intel", "web"];

// ── Trust level badges ──
const TRUST_UI: Record<string, { label: string; color: string; bg: string; border: string }> = {
  "official":  { label: "TC",          color: "#d03020", bg: "rgba(208,48,32,0.12)",  border: "rgba(208,48,32,0.25)" },
  "verified":  { label: "✓ Vérifié",   color: "#30a050", bg: "rgba(48,160,80,0.12)",  border: "rgba(48,160,80,0.25)" },
  "community": { label: "Communauté",  color: "#d09020", bg: "rgba(208,144,32,0.12)", border: "rgba(208,144,32,0.25)" },
};

const RUNNABLE: Record<string, string> = {
  "skill-semgrep": "/api/tc/skills/run/skill-semgrep",
  "skill-checkov": "/api/tc/skills/run/skill-checkov",
  "skill-trufflehog": "/api/tc/skills/run/skill-trufflehog",
  "skill-syft": "/api/tc/skills/run/skill-syft",
  "skill-lynis": "/api/tc/skills/run/skill-lynis",
  "skill-docker-bench": "/api/tc/skills/run/skill-docker-bench",
  "skill-nmap-discovery": "/api/tc/connectors/nmap/scan",
  // skill-grype removed in C2 — duplicate of skill-trivy. Keeping a
  // single CVE scanner reduces image-pull churn and simplifies the
  // catalog.
  "skill-active-directory": "/api/tc/connectors/ad/sync",
  "skill-pfsense": "/api/tc/connectors/pfsense/sync",
  "skill-opnsense": "/api/tc/connectors/opnsense/sync",
  "skill-proxmox": "/api/tc/connectors/proxmox/sync",
  "skill-fortinet": "/api/tc/connectors/fortinet/sync",
  "skill-wazuh": "/api/tc/connectors/wazuh/sync",
  "skill-wazuh-connector": "/api/tc/connectors/wazuh/sync",
  "skill-microsoft-graph": "/api/tc/connectors/microsoft-graph/sync",
  "skill-glpi": "/api/tc/connectors/glpi/sync",
  "skill-freebox": "/api/tc/connectors/freebox/sync",
  "skill-nuclei": "/api/tc/skills/run/skill-nuclei",
  "skill-trivy": "/api/tc/skills/run/skill-trivy",
  "skill-zap": "/api/tc/skills/run/skill-zap",
  "skill-subfinder": "/api/tc/skills/run/skill-subfinder",
  "skill-httpx": "/api/tc/skills/run/skill-httpx",
  "skill-elastic-siem": "/api/tc/connectors/elastic-siem/sync",
  "skill-graylog": "/api/tc/connectors/graylog/sync",
  "skill-thehive": "/api/tc/connectors/thehive/sync",
  "skill-dfir-iris": "/api/tc/connectors/dfir-iris/sync",
  "skill-shuffle": "/api/tc/connectors/shuffle/sync",
  "skill-keycloak": "/api/tc/connectors/keycloak/sync",
  "skill-authentik": "/api/tc/connectors/authentik/sync",
  "skill-proxmox-backup": "/api/tc/connectors/proxmox-backup/sync",
  "skill-veeam": "/api/tc/connectors/veeam/sync",
  "skill-mikrotik": "/api/tc/connectors/mikrotik/sync",
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
  "skill-semgrep", "skill-checkov", "skill-trufflehog",
  "skill-syft", "skill-docker-bench", "skill-lynis",
  "skill-darkweb-monitor", "skill-email-audit", "skill-report-gen",
  "skill-compliance-nis2", "skill-compliance-iso27001",
  "skill-microsoft-graph",
]);

// Doctrine pivot 2026-04-26: skills no longer carry a "premium" flag.
// HITL destructive actions are gated by a single global Action Pack
// license, surfaced via the per-skill HitlActionsPanel. Kept the
// helper as a no-op pass-through to minimise the diff in render code
// — every call site now reads `false`, so the premium-gated install
// branch is dead code that the next cleanup pass can prune.
const isPremium = (_s: SkillManifest) => false;

function TrustBadge({ trust }: { trust: string }) {
  // "official" is the implicit default — surfacing a "TC" badge on every
  // first-party skill is noise. Only show the badge when it signals
  // something the user should actually pay attention to.
  if (!trust || trust === "official") return null;
  const t = TRUST_UI[trust] || TRUST_UI["community"];
  return (
    <span style={{
      fontSize: "8px", fontWeight: 800, padding: "2px 6px", borderRadius: "4px",
      background: t.bg, color: t.color, border: `1px solid ${t.border}`,
      textTransform: "uppercase", letterSpacing: "0.03em", whiteSpace: "nowrap",
    }}>
      {t.label}
    </span>
  );
}

function TypeBadge({ type, locale }: { type: string; locale: "fr" | "en" }) {
  const base = TYPE_UI_BASE[type];
  if (!base) {
    return (
      <span style={{
        fontSize: "8px", fontWeight: 700, padding: "1px 5px", borderRadius: "3px",
        background: "rgba(140,140,140,0.15)", color: "var(--tc-text-muted)", textTransform: "uppercase",
      }}>{type}</span>
    );
  }
  return (
    <span style={{
      fontSize: "8px", fontWeight: 700, padding: "1px 5px", borderRadius: "3px",
      background: `${base.color}15`, color: base.color, textTransform: "uppercase",
    }}>
      {tr(base.labelKey, locale)}
    </span>
  );
}

export default function SkillsPage() {
  const locale = useLocale();
  const [allSkills, setAllSkills] = useState<SkillManifest[]>([]);
  const [enabled, setEnabled] = useState<Set<string>>(new Set());
  const [disabledSkills, setDisabledSkills] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);

  const initialQuery = (() => {
    if (typeof window === "undefined") return new URLSearchParams("");
    return new URLSearchParams(window.location.search);
  })();
  const [search, setSearch] = useState<string>(initialQuery.get("search") || "");
  const [catFilter, setCatFilter] = useState<string>(initialQuery.get("cat") || "");
  const [installedOnly, setInstalledOnly] = useState<boolean>(initialQuery.get("installed") === "1");

  const [modalSkill, setModalSkill] = useState<SkillManifest | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, Record<string, string>>>({});
  const [running, setRunning] = useState<string | null>(null);
  const [runResult, setRunResult] = useState<any>(null);
  const [activeHint, setActiveHint] = useState<string | null>(null);

  // Install/uninstall feedback overlay state.
  const [busySkill, setBusySkill] = useState<SkillManifest | null>(null);
  const [busyDone, setBusyDone] = useState(false);
  const [busyError, setBusyError] = useState(false);
  const [busyMsg, setBusyMsg] = useState("");

  // ── Mount: backend is single source of truth ──
  // We deliberately don't seed from localStorage and don't write
  // localStorage from the GET response. The previous implementation did
  // both, which created a race: a slow POST could be clobbered by a
  // stale read on the next mount, making freshly-installed skills
  // "disappear" after a refresh.
  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [catRes, skillsRes] = await Promise.all([
        fetch("/api/tc/catalog"),
        fetch("/api/tc/config/_skills"),
      ]);
      const catData = catRes.ok ? await catRes.json() : { skills: [] };
      const skillsData = skillsRes.ok ? await skillsRes.json() : { config: [] };
      // Tool-type skills (Nmap, Trivy, Lynis, ...) live on /scans now —
      // filter them out of the /skills catalogue so this page only shows
      // connectors (= sources of data the operator wires once).
      const rawList: SkillManifest[] = catData.skills || [];
      const allList: SkillManifest[] = rawList.filter((s) => s.type !== "tool");
      const validIds = new Set(allList.map((s) => s.id));

      const active = new Set<string>();
      allList.forEach((s) => { if (s.default_active) active.add(s.id); });

      const map: Record<string, string> = {};
      for (const c of (skillsData.config || [])) map[c.key] = c.value;
      if (map.installed) {
        try {
          const ids: string[] = JSON.parse(map.installed);
          // Filter zombies — only ids still present in current catalog.
          ids.filter((id) => validIds.has(id)).forEach((id) => active.add(id));
        } catch {}
      }
      let nextDisabled = new Set<string>();
      if (map.disabled) {
        try {
          const ids: string[] = JSON.parse(map.disabled);
          nextDisabled = new Set(ids.filter((id) => validIds.has(id)));
        } catch {}
      }
      setAllSkills(allList);
      setEnabled(active);
      setDisabledSkills(nextDisabled);
    } catch (e) {
      console.error("Failed to load skills:", e);
    }
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // URL → state sync. Sidebar Link clicks patch history.pushState and
  // broadcast `tc:history`; bare back/forward emits popstate.
  useEffect(() => {
    const sync = () => {
      const p = new URLSearchParams(window.location.search);
      setCatFilter(p.get("cat") || "");
      setInstalledOnly(p.get("installed") === "1");
      const s = p.get("search");
      if (s !== null) setSearch(s);
    };
    sync();
    window.addEventListener("popstate", sync);
    window.addEventListener("tc:history", sync);
    return () => {
      window.removeEventListener("popstate", sync);
      window.removeEventListener("tc:history", sync);
    };
  }, []);

  // Load skill config when modal opens. Layers, lowest priority first:
  // (1) defaults from the skill manifest, (2) values stored in DB,
  // (3) values the user just typed in this session. The merge below
  // preserves that order so a user's in-session typing always wins.
  useEffect(() => {
    if (!modalSkill) return;
    const seedDefaults: Record<string, string> = {};
    if (modalSkill.config) {
      for (const [key, field] of Object.entries(modalSkill.config)) {
        if (field && field.default !== undefined && field.default !== null) {
          seedDefaults[key] = String(field.default);
        }
      }
    }
    fetch(`/api/tc/config/${modalSkill.id}`, { signal: AbortSignal.timeout(3000) })
      .then((r) => r.json())
      .then((d: any) => {
        const fromDb: Record<string, string> = {};
        if (d.config && Array.isArray(d.config)) {
          for (const c of d.config) fromDb[c.key] = c.value;
        }
        setConfigValues((prev) => ({
          ...prev,
          [modalSkill.id]: { ...seedDefaults, ...fromDb, ...prev[modalSkill.id] },
        }));
      })
      .catch(() => {
        setConfigValues((prev) => ({
          ...prev,
          [modalSkill.id]: { ...seedDefaults, ...prev[modalSkill.id] },
        }));
      });
  }, [modalSkill]);

  // ── Persistence helpers ──
  // Aggregate `_skills.installed` / `_skills.disabled` rows are still the
  // wire format the dashboard reads on mount. We compute them via the
  // functional setEnabled/setDisabledSkills updaters so we always read
  // the latest state — no stale closure.
  const persistAggregate = async (
    nextEnabled: Set<string>,
    nextDisabled: Set<string>,
  ) => {
    const writeRow = async (key: string, value: string) => {
      const r = await fetch("/api/tc/config/_skills", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, value }),
      });
      if (!r.ok) throw new Error(`POST _skills/${key} HTTP ${r.status}`);
    };
    await Promise.all([
      writeRow("installed", JSON.stringify(Array.from(nextEnabled))),
      writeRow("disabled", JSON.stringify(Array.from(nextDisabled))),
    ]);
  };

  const install = async (skill: SkillManifest) => {
    if ((skill.trust === "community") && (skill.type === "tool" || skill.remediation)) return;
    setBusySkill(skill);
    setBusyDone(false);
    setBusyError(false);
    setBusyMsg(tr("installing", locale));
    try {
      const vals: Record<string, string> = { enabled: "true" };
      const cfg = configValues[skill.id];
      if (cfg) for (const [k, v] of Object.entries(cfg)) vals[k] = String(v);
      await Promise.all(Object.entries(vals).map(async ([key, value]) => {
        const r = await fetch(`/api/tc/config/${skill.id}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key, value }),
        });
        if (!r.ok) throw new Error(`POST ${skill.id}/${key} HTTP ${r.status}`);
      }));

      // Snapshot current state, compute next, push to React + backend
      // synchronously. Avoids any reliance on functional-updater timing.
      const nextEnabled = new Set(enabled);
      nextEnabled.add(skill.id);
      const nextDisabled = new Set(disabledSkills);
      nextDisabled.delete(skill.id);
      setEnabled(nextEnabled);
      setDisabledSkills(nextDisabled);
      await persistAggregate(nextEnabled, nextDisabled);

      setBusyDone(true);
      setBusyMsg(`${skill.name} ${locale === "fr" ? "installé" : "installed"}`);
      window.setTimeout(() => { setBusySkill(null); setBusyDone(false); }, 900);
    } catch (e: any) {
      setBusyError(true);
      setBusyMsg(`${locale === "fr" ? "Erreur" : "Error"}: ${e?.message || String(e)}`);
      window.setTimeout(() => { setBusySkill(null); setBusyError(false); }, 3500);
    }
  };

  const uninstall = async (id: string) => {
    setModalSkill(null);
    const skill = allSkills.find((s) => s.id === id) || null;
    setBusySkill(skill);
    setBusyDone(false);
    setBusyError(false);
    setBusyMsg(tr("uninstalling", locale));
    try {
      const r = await fetch(`/api/tc/config/${id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: "enabled", value: "false" }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);

      const nextEnabled = new Set(enabled);
      nextEnabled.delete(id);
      const nextDisabled = new Set(disabledSkills);
      nextDisabled.delete(id);
      setEnabled(nextEnabled);
      setDisabledSkills(nextDisabled);
      await persistAggregate(nextEnabled, nextDisabled);

      setBusyDone(true);
      setBusyMsg(`${skill?.name || "Skill"} ${tr("uninstalled", locale)}`);
      window.setTimeout(() => { setBusySkill(null); setBusyDone(false); }, 800);
    } catch (e: any) {
      setBusyError(true);
      setBusyMsg(`${locale === "fr" ? "Erreur" : "Error"}: ${e?.message || String(e)}`);
      window.setTimeout(() => { setBusySkill(null); setBusyError(false); }, 3500);
    }
  };

  const toggleActive = async (id: string) => {
    const nextDisabled = new Set(disabledSkills);
    if (nextDisabled.has(id)) nextDisabled.delete(id); else nextDisabled.add(id);
    setDisabledSkills(nextDisabled);
    try {
      await persistAggregate(enabled, nextDisabled);
    } catch (e) {
      console.error("Toggle persist failed", e);
    }
  };

  const setConfig = (sid: string, key: string, val: string) => {
    setConfigValues((prev) => ({ ...prev, [sid]: { ...prev[sid], [key]: val } }));
  };

  const handleRun = async (skill: SkillManifest) => {
    const url = RUNNABLE[skill.id]; if (!url) return;
    setRunning(skill.id); setRunResult(null);
    try {
      const raw: any = { ...(configValues[skill.id] || {}) };
      const body: any = {};
      for (const [k, v] of Object.entries(raw)) {
        const fieldDef = skill.config?.[k];
        if (fieldDef?.type === "boolean") body[k] = v === "true" || v === true;
        else if (fieldDef?.type === "number") body[k] = Number(v) || fieldDef.default || 0;
        else body[k] = v;
      }
      if (skill.id === "skill-nmap-discovery") body.targets = body.target_subnets || raw.target_subnets || "192.168.1.0/24";
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const ct = res.headers.get("content-type") || "";
      let data: any;
      if (ct.includes("json")) {
        try { data = await res.json(); } catch { data = { error: `HTTP ${res.status}` }; }
      } else {
        const text = await res.text();
        data = res.ok ? { message: text } : { error: text || `HTTP ${res.status}` };
      }
      if (!res.ok && !data.error) {
        data = { error: data.message || data.error || `HTTP ${res.status}`, raw: data };
      }
      setRunResult(data);
    } catch (e: any) {
      setRunResult({ error: e.message });
    }
    setRunning(null);
  };

  // ── Filtering / grouping ──
  const matchesSearch = (s: SkillManifest) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return s.name.toLowerCase().includes(q) ||
      (s.description || "").toLowerCase().includes(q);
  };

  const visibleSkills = allSkills.filter((s) => {
    if (catFilter && s.category !== catFilter) return false;
    if (installedOnly && !enabled.has(s.id)) return false;
    if (!matchesSearch(s)) return false;
    return true;
  });

  const groupedByCategory: Record<string, SkillManifest[]> = {};
  for (const cat of CATEGORY_ORDER) groupedByCategory[cat] = [];
  for (const s of visibleSkills) {
    const cat = (s.category && groupedByCategory[s.category] !== undefined) ? s.category : "scan";
    groupedByCategory[cat].push(s);
  }
  // Within each category: installed first, then alphabetical. Lets the
  // user see what they have configured at a glance when they land on a
  // category.
  for (const cat of CATEGORY_ORDER) {
    groupedByCategory[cat].sort((a, b) => {
      const aInstalled = enabled.has(a.id) ? 0 : 1;
      const bInstalled = enabled.has(b.id) ? 0 : 1;
      if (aInstalled !== bInstalled) return aInstalled - bInstalled;
      return a.name.localeCompare(b.name);
    });
  }

  const installedCount = allSkills.filter((s) => enabled.has(s.id)).length;
  const visibleCount = visibleSkills.length;
  const totalCount = allSkills.length;
  const catLabel = catFilter && CATEGORY_UI[catFilter]
    ? (locale === "fr" ? CATEGORY_UI[catFilter].label : CATEGORY_UI[catFilter].labelEn)
    : null;

  return (
    <div style={{ padding: "0 24px 40px" }}>
      {/* ─── Header ─── */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px", flexWrap: "wrap", gap: "12px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>
          {tr("skills", locale)}
          <span style={{ fontSize: "12px", fontWeight: 500, color: "var(--tc-text-muted)", marginLeft: "10px" }}>
            {installedOnly
              ? `${installedCount} ${tr("installed2", locale).toLowerCase()}`
              : `${visibleCount} / ${totalCount} · ${installedCount} ${tr("installed2", locale).toLowerCase()}`}
            {catLabel && ` · ${catLabel}`}
          </span>
        </h1>
        <button className="tc-btn-embossed" onClick={refresh}>
          <RefreshCw size={12} /> {tr("refresh", locale)}
        </button>
      </div>

      {/* ─── Search bar (the only filter UI now) ─── */}
      <div style={{ position: "relative", marginBottom: "20px" }}>
        <Search size={14} style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: "var(--tc-text-muted)" }} />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={tr("search", locale)}
          style={{
            width: "100%", padding: "10px 12px 10px 34px", borderRadius: "var(--tc-radius-input)",
            fontSize: "12px", background: "var(--tc-input)", border: "1px solid var(--tc-border)",
            color: "var(--tc-text)", outline: "none",
          }}
        />
      </div>

      {/* ─── Loading / empty ─── */}
      {loading && (
        <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-faint)", fontSize: "12px" }}>
          {tr("loading", locale)}
        </div>
      )}
      {!loading && visibleSkills.length === 0 && (
        <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-faint)", fontSize: "12px" }}>
          {search
            ? tr("noSkillFound", locale)
            : installedOnly
              ? (locale === "fr" ? "Aucun skill installé pour le moment." : "No installed skills yet.")
              : tr("noSkillFound", locale)}
        </div>
      )}

      {/* ─── Skills grouped by category ─── */}
      {!loading && CATEGORY_ORDER.map((cat) => {
        const skills = groupedByCategory[cat] || [];
        if (skills.length === 0) return null;
        const ui = CATEGORY_UI[cat];
        const Icon = ui.icon;
        return (
          <section key={cat} id={cat} style={{ marginBottom: "28px" }}>
            <div style={{
              display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px",
              paddingBottom: "6px", borderBottom: `2px solid ${ui.color}20`,
            }}>
              <Icon size={15} color={ui.color} />
              <span style={{
                fontSize: "12px", fontWeight: 800, color: ui.color,
                textTransform: "uppercase", letterSpacing: "0.05em",
              }}>
                {locale === "fr" ? ui.label : ui.labelEn}
              </span>
              <span style={{ fontSize: "10px", color: "var(--tc-text-faint)" }}>({skills.length})</span>
            </div>
            <div style={{
              display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: "8px",
            }}>
              {skills.map((skill) => (
                <SkillCard
                  key={skill.id}
                  skill={skill}
                  installed={enabled.has(skill.id)}
                  disabled={disabledSkills.has(skill.id)}
                  locale={locale}
                  onToggleActive={() => toggleActive(skill.id)}
                  onInstall={() => install(skill)}
                  onOpenConfig={() => { setRunResult(null); setActiveHint(null); setModalSkill(skill); }}
                />
              ))}
            </div>
          </section>
        );
      })}

      {/* ─── Install/uninstall feedback overlay ─── */}
      {busySkill && (
        <div style={{
          position: "fixed", inset: 0, zIndex: 1001, background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)",
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <div style={{
            width: "320px", background: "var(--tc-bg)", border: "1px solid var(--tc-border)",
            borderRadius: "var(--tc-radius-card)", padding: "32px", textAlign: "center",
            boxShadow: "0 20px 60px rgba(0,0,0,0.4)",
          }}>
            {busyError ? (
              <>
                <div style={{ marginBottom: "12px" }}><X size={36} color="var(--tc-red)" /></div>
                <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-red)", marginBottom: "8px" }}>{busyMsg}</div>
                <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{busySkill.name}</div>
              </>
            ) : !busyDone ? (
              <>
                <div style={{ display: "flex", justifyContent: "center", marginBottom: "24px", height: "20px" }}>
                  <div className="tc-ball-loader" />
                </div>
                <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "8px" }}>{busyMsg}</div>
                <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>{busySkill.name}</div>
              </>
            ) : (
              <>
                <div style={{ marginBottom: "12px" }}><CheckCircle2 size={36} color="var(--tc-green)" /></div>
                <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "8px" }}>{busyMsg}</div>
              </>
            )}
          </div>
        </div>
      )}

      {/* ─── Config modal ─── */}
      {modalSkill && (
        <ConfigModal
          skill={modalSkill}
          locale={locale}
          configValues={configValues}
          activeHint={activeHint}
          running={running}
          runResult={runResult}
          allSkills={allSkills}
          setActiveHint={setActiveHint}
          setConfig={setConfig}
          setConfigValues={setConfigValues}
          onOpenSkill={(s) => { setRunResult(null); setActiveHint(null); setModalSkill(s); }}
          onClose={() => setModalSkill(null)}
          onRun={() => handleRun(modalSkill)}
          onUninstall={() => uninstall(modalSkill.id)}
        />
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// SkillCard — single card in the catalog. Always-expanded WordPress-style:
// description, meta and the action row are visible at a glance, no
// expand/collapse interaction. The action row morphs based on install
// state (Installer / Configurer + active toggle / Licence requise).
// ─────────────────────────────────────────────────────────────────────
function SkillCard({
  skill, installed, disabled, locale,
  onToggleActive, onInstall, onOpenConfig,
}: {
  skill: SkillManifest;
  installed: boolean;
  disabled: boolean;
  locale: "fr" | "en";
  onToggleActive: () => void;
  onInstall: () => void;
  onOpenConfig: () => void;
}) {
  const trust = skill.trust || "official";
  const notReady = NOT_FUNCTIONAL.has(skill.id);
  const isCommunityAction = trust === "community" && (skill.type === "tool" || skill.remediation);
  const premium = isPremium(skill);

  return (
    <div style={{
      display: "flex", flexDirection: "column",
      borderRadius: "var(--tc-radius-md)",
      background: "var(--tc-neu-inner)",
      overflow: "hidden",
      boxShadow: "inset 0 2px 6px rgba(0,0,0,0.25), inset 0 1px 2px rgba(0,0,0,0.2), 0 1px 0 rgba(255,255,255,0.08)",
      opacity: notReady ? 0.45 : (installed && disabled ? 0.65 : 1),
      border: installed ? "1px solid rgba(48,160,80,0.28)" : "1px solid transparent",
      padding: "12px",
      gap: "8px",
    }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", gap: "8px" }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
            <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{skill.name}</span>
            <TypeBadge type={skill.type} locale={locale} />
            <TrustBadge trust={trust} />
            {skill.api_key_required && <Key size={10} color="var(--tc-amber)" />}
            {BETA_SKILLS.has(skill.id) && (
              <span style={{
                fontSize: "7px", fontWeight: 800, padding: "1px 5px", borderRadius: "3px",
                background: "rgba(208,144,32,0.12)", color: "var(--tc-amber)", textTransform: "uppercase",
              }} title={tr("betaSkillHint", locale)}>{tr("beta", locale)}</span>
            )}
            {premium && (
              <span style={{
                fontSize: "8px", fontWeight: 800, padding: "2px 5px", borderRadius: "3px",
                background: "rgba(208,168,32,0.15)", color: "#d0a820",
              }}>PREMIUM</span>
            )}
          </div>
        </div>
        {installed && (
          <span style={{
            display: "flex", alignItems: "center", gap: "4px",
            fontSize: "9px", fontWeight: 800, color: "#30a050",
            background: "rgba(48,160,80,0.10)", border: "1px solid rgba(48,160,80,0.25)",
            padding: "3px 8px", borderRadius: "4px",
            textTransform: "uppercase", letterSpacing: "0.05em",
            flexShrink: 0, whiteSpace: "nowrap",
          }}>
            <CheckCircle2 size={10} /> {locale === "fr" ? "Installé" : "Installed"}
          </span>
        )}
      </div>

      {/* Description */}
      <p style={{
        fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: "1.55",
        margin: 0, flex: 1,
      }}>
        {skill.description}
      </p>

      {/* Meta */}
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", fontSize: "9px", color: "var(--tc-text-muted)" }}>
        {skill.version && <span>v{skill.version}</span>}
        <span>{tr("by", locale)} : {skill.author || "ThreatClaw"}</span>
        {skill.execution?.mode && (
          <span>
            {skill.execution.mode === "ephemeral" ? "Docker"
              : skill.execution.mode === "persistent" ? (locale === "fr" ? "Sync continue" : "Continuous sync")
              : "API"}
          </span>
        )}
      </div>

      {/* Action row */}
      <div style={{ marginTop: "4px" }}>
        {isCommunityAction ? (
          <div style={{
            display: "flex", alignItems: "center", gap: "8px", padding: "8px 10px",
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
          <span style={{
            fontSize: "8px", fontWeight: 700, padding: "2px 8px", borderRadius: "4px",
            background: "rgba(208,144,32,0.12)", color: "var(--tc-amber)",
            textTransform: "uppercase", letterSpacing: "0.05em",
          }}>{tr("inDevelopment", locale)}</span>
        ) : installed ? (
          <div style={{ display: "flex", gap: "8px", alignItems: "center", justifyContent: "space-between" }}>
            <label style={{
              display: "flex", alignItems: "center", gap: "8px",
              fontSize: "10px", color: "var(--tc-text-muted)", cursor: "pointer",
            }}>
              <input
                type="checkbox"
                className="tc-toggle"
                checked={!disabled}
                onChange={onToggleActive}
              />
              {disabled ? (locale === "fr" ? "Désactivé" : "Disabled") : (locale === "fr" ? "Actif" : "Active")}
            </label>
            <button
              onClick={onOpenConfig}
              className="tc-btn-embossed"
              style={{ fontSize: "11px", padding: "6px 14px" }}
            >
              <Settings size={12} /> {locale === "fr" ? "Configurer" : "Configure"}
            </button>
          </div>
        ) : premium ? (
          <div style={{ display: "flex", gap: "10px", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap" }}>
            <a
              href="/setup?tab=licenses"
              style={{
                fontSize: "10px", color: "var(--tc-red)", textDecoration: "none",
                display: "inline-flex", alignItems: "center", gap: "3px",
              }}
            >
              <Lock size={10} /> {locale === "fr" ? "Licence requise pour exécuter" : "License required to run"}
            </a>
            <button
              onClick={onInstall}
              className="tc-btn-embossed"
              style={{ fontSize: "11px", padding: "6px 16px" }}
            >
              <Download size={12} /> {locale === "fr" ? "Installer" : "Install"}
            </button>
          </div>
        ) : (
          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <button
              onClick={onInstall}
              className="tc-btn-embossed"
              style={{ fontSize: "11px", padding: "6px 16px" }}
            >
              <Download size={12} /> {locale === "fr" ? "Installer" : "Install"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// ConfigModal — opened from the "Configurer" button on an installed
// card. Identical behaviour to the previous in-page modal: shows the
// help blurb, the per-skill config fields (with type-aware widgets),
// the wazuh extra panel and the freebox pairing flow as inline
// addendums, plus Save / Run / Uninstall.
// ─────────────────────────────────────────────────────────────────────
function ConfigModal({
  skill, locale, configValues, activeHint, running, runResult, allSkills,
  setActiveHint, setConfig, setConfigValues, onOpenSkill,
  onClose, onRun, onUninstall,
}: {
  skill: SkillManifest;
  locale: "fr" | "en";
  configValues: Record<string, Record<string, string>>;
  activeHint: string | null;
  running: string | null;
  runResult: any;
  allSkills: SkillManifest[];
  setActiveHint: (s: string | null) => void;
  setConfig: (sid: string, key: string, val: string) => void;
  setConfigValues: React.Dispatch<React.SetStateAction<Record<string, Record<string, string>>>>;
  onOpenSkill: (s: SkillManifest) => void;
  onClose: () => void;
  onRun: () => void;
  onUninstall: () => void;
}) {
  const parentSkill = skill.depends_on
    ? allSkills.find((s) => s.id === skill.depends_on)
    : null;
  const sortedConfig: [string, any][] = skill.config
    ? Object.entries(skill.config).sort(([, a]: [string, any], [, b]: [string, any]) => {
        const reqA = a?.required ? 0 : 1;
        const reqB = b?.required ? 0 : 1;
        if (reqA !== reqB) return reqA - reqB;
        const typeOrder: Record<string, number> = { string: 0, password: 1, boolean: 2, number: 3 };
        return (typeOrder[a?.type] ?? 4) - (typeOrder[b?.type] ?? 4);
      })
    : [];

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 1000, background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)",
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "100%", maxWidth: "500px", maxHeight: "80vh", overflow: "auto",
          background: "var(--tc-bg)", border: "1px solid var(--tc-border)",
          borderRadius: "var(--tc-radius-card)", padding: "24px",
          boxShadow: "0 20px 60px rgba(0,0,0,0.4)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <h2 style={{ fontSize: "16px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>{skill.name}</h2>
              <TrustBadge trust={skill.trust || "official"} />
              <TypeBadge type={skill.type} locale={locale} />
            </div>
            <span style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
              v{skill.version} · {skill.author || "ThreatClaw"}
            </span>
          </div>
          <button
            onClick={onClose}
            style={{ padding: "4px", background: "transparent", border: "none", color: "var(--tc-text-muted)", cursor: "pointer" }}
          >
            <X size={18} />
          </button>
        </div>
        <p style={{ fontSize: "12px", color: "var(--tc-text-sec)", lineHeight: "1.6", marginBottom: "12px" }}>{skill.description}</p>

        {parentSkill && (
          <div style={{
            display: "flex", alignItems: "flex-start", gap: "8px",
            padding: "10px 12px", marginBottom: "16px",
            background: "rgba(48,128,208,0.08)", border: "1px solid rgba(48,128,208,0.22)",
            borderRadius: "var(--tc-radius-sm)",
          }}>
            <Info size={13} color="var(--tc-blue)" style={{ flexShrink: 0, marginTop: "2px" }} />
            <div style={{ flex: 1, fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: 1.55 }}>
              <div style={{ fontWeight: 700, color: "var(--tc-blue)", marginBottom: "3px" }}>
                {locale === "fr" ? "Configuration partagée" : "Shared configuration"}
              </div>
              {locale === "fr" ? (
                <>Ce skill utilise la connexion configurée dans <strong>{parentSkill.name}</strong>. Pas de paramètres à régler ici.</>
              ) : (
                <>This skill uses the connection configured in <strong>{parentSkill.name}</strong>. No settings to tune here.</>
              )}
              <div style={{ marginTop: "6px" }}>
                <button
                  onClick={() => onOpenSkill(parentSkill)}
                  style={{
                    fontSize: "10px", fontWeight: 600, padding: "4px 10px",
                    borderRadius: "var(--tc-radius-sm)", cursor: "pointer",
                    background: "var(--tc-blue-soft)", color: "var(--tc-blue)",
                    border: "1px solid rgba(48,128,208,0.3)", fontFamily: "inherit",
                    display: "inline-flex", alignItems: "center", gap: "4px",
                  }}
                >
                  <Settings size={10} /> {locale === "fr" ? `Configurer ${parentSkill.name}` : `Configure ${parentSkill.name}`}
                </button>
              </div>
            </div>
          </div>
        )}

        {skill.help && (
          <details style={{
            marginBottom: "16px", background: "rgba(48,128,208,0.06)",
            border: "1px solid rgba(48,128,208,0.15)", borderRadius: "var(--tc-radius-md)", padding: "0",
          }}>
            <summary style={{
              fontSize: "11px", fontWeight: 600, color: "var(--tc-blue)", cursor: "pointer",
              padding: "10px 14px", display: "flex", alignItems: "center", gap: "6px", listStyle: "none",
            }}>
              <HelpCircle size={13} /> {tr("whatIsThis", locale)}
            </summary>
            <div style={{
              fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: "1.7",
              padding: "0 14px 12px", whiteSpace: "pre-line",
            }}>
              {skill.help}
            </div>
          </details>
        )}

        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginBottom: "16px", fontSize: "10px", color: "var(--tc-text-muted)" }}>
          {skill.execution?.mode && <span>Mode: {skill.execution.mode}</span>}
          {skill.execution?.docker_image && (
            <span style={{ fontFamily: "monospace", color: "var(--tc-blue)" }}>{skill.execution.docker_image}</span>
          )}
          {skill.execution?.sync_interval_minutes && (
            <span><Clock size={9} style={{ display: "inline", verticalAlign: "middle" }} /> {skill.execution.sync_interval_minutes}min</span>
          )}
        </div>

        {sortedConfig.length > 0 && (
          <div style={{ marginBottom: "16px" }}>
            <div style={{
              fontSize: "10px", fontWeight: 700, color: "var(--tc-text-muted)",
              textTransform: "uppercase", marginBottom: "8px",
            }}>
              Configuration
            </div>
            {sortedConfig.map(([key, field]: [string, any]) => {
              if (!field) return null;
              const val = configValues[skill.id]?.[key] || "";
              return (
                <div key={key} style={{ marginBottom: "10px" }}>
                  <label style={{
                    fontSize: "11px", color: "var(--tc-text-sec)",
                    display: "flex", alignItems: "center", gap: "4px", marginBottom: "4px",
                  }}>
                    {field.description || key}
                    {field.required && <span style={{ color: "var(--tc-red)" }}> *</span>}
                    {field.hint && (
                      <span
                        onClick={(e) => { e.preventDefault(); setActiveHint(activeHint === key ? null : key); }}
                        style={{
                          cursor: "pointer", display: "inline-flex", padding: "2px", borderRadius: "50%",
                          background: activeHint === key ? "rgba(48,128,208,0.15)" : "transparent",
                        }}
                      >
                        <Info size={11} color={activeHint === key ? "var(--tc-blue)" : "var(--tc-text-muted)"} />
                      </span>
                    )}
                  </label>
                  {field.hint && activeHint === key && (
                    <div style={{
                      fontSize: "10px", color: "var(--tc-blue)",
                      background: "rgba(48,128,208,0.06)", border: "1px solid rgba(48,128,208,0.12)",
                      borderRadius: "var(--tc-radius-sm)", padding: "6px 10px",
                      marginBottom: "4px", lineHeight: "1.5",
                    }}>
                      {field.hint}
                    </div>
                  )}
                  {field.options ? (
                    <select
                      value={val || field.default || ""}
                      onChange={(e) => setConfig(skill.id, key, e.target.value)}
                      style={{
                        width: "100%", padding: "8px 10px", borderRadius: "var(--tc-radius-input)", fontSize: "12px",
                        background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", outline: "none",
                      }}
                    >
                      <option value="">{locale === "fr" ? "Choisir..." : "Select..."}</option>
                      {field.options.map((o: string) => <option key={o} value={o}>{o}</option>)}
                    </select>
                  ) : field.type === "boolean" ? (
                    <label style={{
                      fontSize: "11px", color: "var(--tc-text)",
                      display: "flex", alignItems: "center", gap: "8px",
                    }}>
                      <input
                        type="checkbox"
                        className="tc-toggle"
                        checked={val === "true" || (!val && field.default === true)}
                        onChange={(e) => setConfig(skill.id, key, e.target.checked ? "true" : "false")}
                      />
                      {field.default ? tr("activeByDefault", locale) : tr("inactiveByDefault", locale)}
                    </label>
                  ) : (
                    <input
                      type={field.type === "password" ? "password" : "text"}
                      value={val}
                      onChange={(e) => setConfig(skill.id, key, e.target.value)}
                      placeholder={field.placeholder || field.default?.toString() || ""}
                      style={{
                        width: "100%", padding: "8px 10px", borderRadius: "var(--tc-radius-input)", fontSize: "12px",
                        background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", outline: "none",
                      }}
                    />
                  )}
                </div>
              );
            })}
          </div>
        )}

        {skill.hitl_actions?.enabled && (
          <HitlActionsPanel
            skillId={skill.id}
            hitl={skill.hitl_actions}
            configValues={configValues}
            setConfig={setConfig}
            locale={locale}
          />
        )}
        {skill.id === "skill-velociraptor" && (
          <VelociraptorPastePanel
            onParsed={(fields) => {
              const sid = "skill-velociraptor";
              Object.entries(fields).forEach(([k, v]) => {
                if (v) setConfig(sid, k, v);
              });
            }}
          />
        )}
        {skill.id === "skill-wazuh-connector" && (
          <WazuhExtraPanel
            cursor={configValues["skill-wazuh-connector"]?.cursor_last_timestamp || ""}
            onCursorReset={() => {
              fetch(`/api/tc/config/skill-wazuh-connector`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ key: "cursor_last_timestamp", value: "" }),
              })
                .then(() => {
                  setConfigValues((v) => ({
                    ...v,
                    "skill-wazuh-connector": {
                      ...(v["skill-wazuh-connector"] || {}),
                      cursor_last_timestamp: "",
                    },
                  }));
                })
                .catch(() => {});
            }}
          />
        )}
        {skill.id === "skill-freebox" && (
          <FreeboxPairingFlow url={configValues["skill-freebox"]?.freebox_url || "http://mafreebox.freebox.fr"} />
        )}

        {runResult && <TestResultBox result={runResult} skillType={skill.type} locale={locale} />}

        <div style={{
          display: "flex", gap: "8px", justifyContent: "space-between",
          paddingTop: "12px", borderTop: "1px solid var(--tc-border)",
        }}>
          <button
            onClick={onUninstall}
            style={{
              display: "flex", alignItems: "center", gap: "5px",
              padding: "8px 14px", borderRadius: "var(--tc-radius-btn)",
              background: "var(--tc-red-soft)", border: "1px solid var(--tc-red-border)",
              color: "var(--tc-red)", fontSize: "11px", fontWeight: 600, cursor: "pointer",
            }}
          >
            <Trash2 size={12} /> {tr("uninstall", locale)}
          </button>
          <div style={{ display: "flex", gap: "8px" }}>
            {RUNNABLE[skill.id] && (
              <button
                className="tc-btn-embossed"
                onClick={onRun}
                disabled={running === skill.id}
                style={{ fontSize: "11px", padding: "8px 14px" }}
              >
                <Play size={12} />{" "}
                {running === skill.id
                  ? "..."
                  : skill.type === "connector"
                    ? (locale === "fr" ? "Tester la connexion" : "Test connection")
                    : (locale === "fr" ? "Lancer" : "Run")}
              </button>
            )}
            <button
              className="tc-btn-embossed"
              onClick={() => {
                const vals = configValues[skill.id];
                if (vals) {
                  Promise.all(Object.entries(vals).map(([key, value]) =>
                    fetch(`/api/tc/config/${skill.id}`, {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ key, value }),
                    })
                  )).catch(() => {});
                }
                onClose();
              }}
              style={{ fontSize: "11px", padding: "8px 14px" }}
            >
              {tr("save", locale)}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// TestResultBox — pretty-print the response from a "Tester la connexion"
// (or run-tool) call. Recognises the common shapes our connector sync
// handlers return (clients_imported, hunts_fetched, errors[],
// findings_created, etc.) and renders them as a green success block
// with a one-line summary. Falls back to a red error block when the
// response carries an `error` key, and to JSON for unrecognised shapes.
// ─────────────────────────────────────────────────────────────────────
function TestResultBox({
  result, skillType, locale,
}: {
  result: any;
  skillType: string;
  locale: "fr" | "en";
}) {
  const isError = !!(result && (result.error || result.errors?.length > 0));
  const isConnector = skillType === "connector";

  // Build a compact summary out of the well-known counter keys our
  // connectors emit. Anything that isn't a counter (or that is zero)
  // just gets dropped — we only want to surface useful signal.
  const counters: Array<[string, number, string]> = [];
  const labelize = (k: string): string => {
    if (locale !== "fr") return k.replace(/_/g, " ");
    const map: Record<string, string> = {
      clients_imported: "clients importés",
      hunts_fetched: "hunts récupérés",
      findings_created: "findings créés",
      insert_errors: "erreurs d'insertion",
      assets_imported: "assets importés",
      users_imported: "utilisateurs importés",
      events_ingested: "événements ingérés",
      rules_imported: "règles importées",
      arp_imported: "entrées ARP",
      dhcp_leases: "baux DHCP",
      interfaces: "interfaces",
      vlans: "VLANs",
      sign_ins: "connexions",
      audit_logs: "events d'audit",
    };
    return map[k] || k.replace(/_/g, " ");
  };
  if (result && typeof result === "object" && !isError) {
    for (const [k, v] of Object.entries(result)) {
      if (typeof v === "number" && k !== "cursor" && !k.endsWith("_at")) {
        counters.push([k, v, labelize(k)]);
      }
    }
  }

  if (isError) {
    const msg = result.error || (Array.isArray(result.errors) ? result.errors.join("; ") : null) || "Erreur inconnue";
    return (
      <div style={{
        marginBottom: "16px", padding: "12px 14px",
        borderRadius: "var(--tc-radius-sm)",
        background: "rgba(208,48,32,0.06)",
        border: "1px solid rgba(208,48,32,0.22)",
      }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: "8px" }}>
          <X size={14} color="#d03020" style={{ flexShrink: 0, marginTop: "1px" }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: "12px", fontWeight: 700, color: "#d03020", marginBottom: "4px" }}>
              {locale === "fr" ? "Échec de la connexion" : "Connection failed"}
            </div>
            <div style={{
              fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: 1.5,
              fontFamily: "'JetBrains Mono', ui-monospace, monospace",
              whiteSpace: "pre-wrap", wordBreak: "break-word",
              maxHeight: "140px", overflow: "auto",
            }}>
              {String(msg)}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{
      marginBottom: "16px", padding: "12px 14px",
      borderRadius: "var(--tc-radius-sm)",
      background: "rgba(48,160,80,0.06)",
      border: "1px solid rgba(48,160,80,0.22)",
    }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: "8px" }}>
        <CheckCircle2 size={14} color="#30a050" style={{ flexShrink: 0, marginTop: "1px" }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "#30a050", marginBottom: "4px" }}>
            {isConnector
              ? (locale === "fr" ? "Connexion établie" : "Connection successful")
              : (locale === "fr" ? "Exécution réussie" : "Run successful")}
          </div>
          {counters.length > 0 ? (
            <div style={{ display: "flex", flexWrap: "wrap", gap: "10px 14px", fontSize: "11px", color: "var(--tc-text-sec)" }}>
              {counters.map(([k, v, label]) => (
                <span key={k}>
                  <strong style={{ color: "var(--tc-text)" }}>{v}</strong> {label}
                </span>
              ))}
            </div>
          ) : (
            <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", fontFamily: "'JetBrains Mono', ui-monospace, monospace", maxHeight: "120px", overflow: "auto" }}>
              <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(result, null, 2)}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// HitlActionsPanel — collapsible section in the Configure modal that
// surfaces destructive HITL actions declared by the skill manifest.
// Shows: list of actions + their description, implementation status,
// optional privileged credential slots, and a license indicator.
//
// License pivot 2026-04-26: instead of selling a separate
// "skill-velociraptor-actions" SKU, ThreatClaw now sells a single
// "Action Pack" license that unlocks every HITL flow across all skills.
// This panel reads /api/tc/licensing/status to know if the operator
// currently has Action Pack and renders a clear message either way.
// ─────────────────────────────────────────────────────────────────────
function HitlActionsPanel({
  skillId,
  hitl,
  configValues,
  setConfig,
  locale,
}: {
  skillId: string;
  hitl: HitlActionsManifest;
  configValues: Record<string, Record<string, string>>;
  setConfig: (sid: string, key: string, val: string) => void;
  locale: "fr" | "en";
}) {
  const [open, setOpen] = useState(false);
  const [allowsHitl, setAllowsHitl] = useState<boolean | null>(null);

  useEffect(() => {
    fetch("/api/tc/licensing/status", { signal: AbortSignal.timeout(3000) })
      .then((r) => r.json())
      .then((d: any) => {
        const ok = (d.licenses || []).some((l: any) => l.active && l.allows_hitl);
        setAllowsHitl(ok);
      })
      .catch(() => setAllowsHitl(false));
  }, []);

  const actions = hitl.actions || [];
  const credFields = hitl.credential_fields || {};
  const credKeys = Object.keys(credFields);
  const hasCreds = credKeys.every(
    (k) => (configValues[skillId]?.[k] || "").length > 0,
  );

  return (
    <div style={{
      marginBottom: "16px",
      background: "rgba(208,168,32,0.06)",
      border: "1px solid rgba(208,168,32,0.22)",
      borderRadius: "var(--tc-radius-sm)",
    }}>
      <div
        onClick={() => setOpen(!open)}
        style={{
          padding: "10px 14px", cursor: "pointer",
          display: "flex", alignItems: "center", gap: "10px",
        }}
      >
        <Lock size={13} color="#d0a820" />
        <div style={{ flex: 1, fontSize: "12px", fontWeight: 700, color: "#d0a820" }}>
          {locale === "fr" ? "Actions HITL" : "HITL Actions"}{" "}
          <span style={{ fontWeight: 400, color: "var(--tc-text-muted)", fontSize: "11px" }}>
            ({actions.length}{" "}
            {hitl.implemented === false
              ? (locale === "fr" ? "à venir" : "coming soon")
              : ""})
          </span>
        </div>
        <span style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
          {open ? "▾" : "▸"}
        </span>
      </div>

      {open && (
        <div style={{ padding: "0 14px 14px", fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: 1.55 }}>
          {/* License status */}
          <div style={{
            display: "flex", alignItems: "center", gap: "8px",
            padding: "8px 10px", marginBottom: "12px",
            borderRadius: "var(--tc-radius-sm)",
            background: allowsHitl
              ? "rgba(48,160,80,0.08)"
              : "rgba(208,48,32,0.06)",
            border: `1px solid ${allowsHitl ? "rgba(48,160,80,0.22)" : "rgba(208,48,32,0.22)"}`,
          }}>
            {allowsHitl ? (
              <>
                <CheckCircle2 size={12} color="#30a050" />
                <span style={{ color: "#30a050", fontWeight: 600 }}>
                  {locale === "fr" ? "Action Pack actif" : "Action Pack active"}
                </span>
              </>
            ) : (
              <>
                <X size={12} color="#d03020" />
                <span style={{ color: "var(--tc-text-sec)" }}>
                  {locale === "fr"
                    ? "Action Pack non activé — les actions sont visibles mais non exécutables. "
                    : "Action Pack not active — actions are visible but not executable. "}
                  <a href="/setup?tab=licenses" style={{ color: "var(--tc-blue)" }}>
                    {locale === "fr" ? "Activer" : "Activate"}
                  </a>
                </span>
              </>
            )}
          </div>

          {/* List of declared actions */}
          <div style={{ marginBottom: credKeys.length > 0 ? "12px" : 0 }}>
            <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "6px" }}>
              {locale === "fr" ? "Outils" : "Tools"}
            </div>
            {actions.map((a) => (
              <div key={a.name} style={{ marginBottom: "6px" }}>
                <code style={{ background: "var(--tc-input)", padding: "1px 5px", fontSize: "10px" }}>
                  {a.name}
                </code>
                {a.label && (
                  <span style={{ marginLeft: "8px", fontWeight: 600, color: "var(--tc-text)" }}>
                    {a.label}
                  </span>
                )}
                {a.description && (
                  <div style={{ marginTop: "2px", fontSize: "10px", color: "var(--tc-text-muted)" }}>
                    {a.description}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Privileged credentials (optional) */}
          {credKeys.length > 0 && (
            <div>
              <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "6px" }}>
                {locale === "fr" ? "Credentials privilégiés" : "Privileged credentials"}
                {hitl.requires_separate_creds && (
                  <span style={{ fontWeight: 400, marginLeft: "6px", textTransform: "none" }}>
                    {locale === "fr" ? "(obligatoires si tu veux exécuter les actions)" : "(required to run actions)"}
                  </span>
                )}
              </div>
              {!hasCreds && hitl.requires_separate_creds && (
                <div style={{ fontSize: "10px", color: "var(--tc-amber)", marginBottom: "8px" }}>
                  {locale === "fr"
                    ? "⚠️ Champs vides : les actions ne peuvent pas s'exécuter, même avec une licence active."
                    : "⚠️ Fields empty: actions cannot execute even with an active license."}
                </div>
              )}
              {credKeys.map((k) => {
                const field = credFields[k];
                const val = configValues[skillId]?.[k] || "";
                return (
                  <div key={k} style={{ marginBottom: "8px" }}>
                    <label style={{ fontSize: "10px", color: "var(--tc-text-sec)", display: "block", marginBottom: "3px" }}>
                      {field.description || k}
                    </label>
                    {field.hint && (
                      <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginBottom: "3px", lineHeight: 1.4 }}>
                        {field.hint}
                      </div>
                    )}
                    <input
                      type={field.type === "password" ? "password" : "text"}
                      value={val}
                      onChange={(e) => setConfig(skillId, k, e.target.value)}
                      placeholder={field.placeholder || ""}
                      style={{
                        width: "100%", padding: "6px 9px", fontSize: "11px",
                        background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                        borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none",
                        fontFamily: field.type === "password" ? "inherit" : "'JetBrains Mono', monospace",
                      }}
                    />
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Velociraptor — paste-once helper ──
// The api_client subcommand on the Velociraptor server emits a YAML
// file with one URL line and three indented PEM blocks (CA, client
// cert, client key). Asking the operator to copy-paste each one into
// a separate text field is a 4-paste, error-prone exercise. This panel
// takes the whole file in a single textarea, parses it client-side,
// and pre-fills the underlying form fields. They can still verify or
// override the individual fields before saving.
function VelociraptorPastePanel({ onParsed }: { onParsed: (fields: Record<string, string>) => void }) {
  const locale = useLocale();
  const [yaml, setYaml] = useState("");
  const [status, setStatus] = useState<"idle" | "ok" | "error">("idle");
  const [message, setMessage] = useState("");

  const parse = () => {
    try {
      const text = yaml;
      // api_connection_string: <url>
      const apiMatch = text.match(/^api_connection_string:\s*(.+)$/m);
      let apiUrl = apiMatch ? apiMatch[1].trim() : "";
      if (apiUrl && !apiUrl.startsWith("http")) apiUrl = "https://" + apiUrl;

      // PEM blocks — extract all, strip leading whitespace from each line
      const pemRe = /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g;
      const pems = (text.match(pemRe) || []).map((p) => p.replace(/^[ \t]+/gm, ""));

      // Velociraptor's api_client output has 3 PEMs in order:
      // 1. ca_certificate (CERTIFICATE)
      // 2. client_cert (CERTIFICATE)
      // 3. client_private_key (RSA PRIVATE KEY / PRIVATE KEY)
      const ca = pems[0] || "";
      const cert = pems[1] || "";
      const key = pems.find((p) => p.includes("PRIVATE KEY")) || pems[2] || "";

      // username comes from `name: <value>` (the --name arg passed to api_client)
      const nameMatch = text.match(/^name:\s*(\S+)/m);
      const username = nameMatch ? nameMatch[1].trim() : "threatclaw";

      const filled: string[] = [];
      const out: Record<string, string> = {};
      if (apiUrl) { out.api_url = apiUrl; filled.push("api_url"); }
      if (username) { out.username = username; filled.push("username"); }
      if (ca) { out.ca_pem = ca; filled.push("ca_pem"); }
      if (cert) { out.client_cert_pem = cert; filled.push("client_cert_pem"); }
      if (key) { out.client_key_pem = key; filled.push("client_key_pem"); }

      if (filled.length === 0) {
        setStatus("error");
        setMessage(locale === "fr"
          ? "Impossible d'extraire des champs — vérifie que tu as collé le contenu complet de threatclaw.config.yaml."
          : "Could not extract any fields — make sure you pasted the full content of threatclaw.config.yaml.");
        return;
      }
      onParsed(out);
      setStatus("ok");
      setMessage(locale === "fr"
        ? `${filled.length} champs remplis automatiquement. Vérifie ci-dessous puis clique sur Enregistrer.`
        : `${filled.length} fields auto-filled. Verify below and click Save.`);
    } catch (e: any) {
      setStatus("error");
      setMessage(`${locale === "fr" ? "Erreur" : "Error"}: ${e?.message || String(e)}`);
    }
  };

  return (
    <div style={{
      marginBottom: "16px", padding: "12px 14px",
      background: "rgba(48,128,208,0.06)", border: "1px solid rgba(48,128,208,0.18)",
      borderRadius: "var(--tc-radius-sm)",
    }}>
      <div style={{
        fontSize: "11px", fontWeight: 700, color: "var(--tc-blue)", marginBottom: "6px",
        display: "flex", alignItems: "center", gap: "6px",
      }}>
        <Info size={13} /> {locale === "fr" ? "Coller le YAML en une fois (recommandé)" : "Paste YAML once (recommended)"}
      </div>
      <div style={{ fontSize: "10px", color: "var(--tc-text-sec)", marginBottom: "8px", lineHeight: 1.5 }}>
        {locale === "fr" ? (
          <>
            Sur le serveur Velociraptor, lance{" "}
            <code style={{ background: "var(--tc-input)", padding: "0 4px", fontSize: "10px" }}>
              velociraptor --config /etc/velociraptor/server.config.yaml config api_client --name threatclaw --role investigator,api threatclaw.config.yaml
            </code>
            , puis colle le contenu intégral de <code style={{ background: "var(--tc-input)", padding: "0 4px" }}>threatclaw.config.yaml</code> ci-dessous. Les 4 champs en bas se rempliront tout seuls.
          </>
        ) : (
          <>
            On the Velociraptor server, run{" "}
            <code style={{ background: "var(--tc-input)", padding: "0 4px", fontSize: "10px" }}>
              velociraptor --config /etc/velociraptor/server.config.yaml config api_client --name threatclaw --role investigator,api threatclaw.config.yaml
            </code>
            , then paste the full content of <code style={{ background: "var(--tc-input)", padding: "0 4px" }}>threatclaw.config.yaml</code> below. The 4 fields underneath will fill automatically.
          </>
        )}
      </div>
      <textarea
        value={yaml}
        onChange={(e) => setYaml(e.target.value)}
        placeholder={"ca_certificate: |\n  -----BEGIN CERTIFICATE-----\n  ...\n  -----END CERTIFICATE-----\nclient_cert: |\n  ...\nclient_private_key: |\n  ...\napi_connection_string: 10.77.0.136:8001\nname: threatclaw"}
        style={{
          width: "100%", minHeight: "100px", maxHeight: "180px",
          padding: "8px 10px", borderRadius: "var(--tc-radius-input)", fontSize: "10px",
          fontFamily: "'JetBrains Mono', ui-monospace, monospace",
          background: "var(--tc-input)", border: "1px solid var(--tc-border)",
          color: "var(--tc-text)", outline: "none", resize: "vertical",
        }}
      />
      <div style={{ display: "flex", gap: "8px", marginTop: "8px", alignItems: "center" }}>
        <button
          onClick={parse}
          disabled={!yaml.trim()}
          className="tc-btn-embossed"
          style={{ fontSize: "11px", padding: "6px 14px" }}
        >
          {locale === "fr" ? "Extraire les champs" : "Extract fields"}
        </button>
        {status === "ok" && (
          <span style={{ fontSize: "10px", color: "#30a050", display: "flex", alignItems: "center", gap: "4px" }}>
            <CheckCircle2 size={11} /> {message}
          </span>
        )}
        {status === "error" && (
          <span style={{ fontSize: "10px", color: "#d03020", display: "flex", alignItems: "center", gap: "4px" }}>
            <X size={11} /> {message}
          </span>
        )}
      </div>
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
    fetch("/api/tc/connectors/freebox/pair/status").then((r) => r.json()).then((d) => {
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
      const res = await fetch("/api/tc/connectors/freebox/pair", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const d = await res.json();
      if (d.error) { setStatus("error"); setMessage(d.error); }
      else { setStatus("pending"); setMessage(tr("freeboxPressButton", locale)); setPolling(true); }
    } catch (e: any) {
      setStatus("error"); setMessage(e.message || tr("networkError", locale));
    }
  };

  return (
    <div style={{
      padding: "14px", borderRadius: "var(--tc-radius-sm)",
      background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)", marginBottom: "16px",
    }}>
      <div style={{
        fontSize: "11px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "8px",
        display: "flex", alignItems: "center", gap: "6px",
      }}>
        <Wifi size={13} color="var(--tc-blue)" /> {tr("freeboxPairing", locale)}
      </div>
      {status === "granted" ? (
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
            <CheckCircle2 size={14} color="#30a050" />
            <span style={{ fontSize: "12px", fontWeight: 600, color: "#30a050" }}>{message}</span>
          </div>
          <button
            onClick={() => { setStatus("idle"); setMessage(""); }}
            style={{
              padding: "6px 12px", fontSize: "10px", fontWeight: 600, fontFamily: "inherit",
              borderRadius: "var(--tc-radius-sm)", cursor: "pointer",
              background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text-muted)",
              display: "flex", alignItems: "center", gap: "4px",
            }}
          >
            <RefreshCw size={10} /> {tr("repairFreebox", locale)}
          </button>
        </div>
      ) : (
        <>
          <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "10px", lineHeight: 1.5 }}>
            ThreatClaw doit s{"'"}appairer avec votre Freebox une seule fois.
          </div>
          <button
            onClick={requestPairing}
            disabled={status === "requesting" || status === "pending"}
            style={{
              padding: "8px 16px", fontSize: "11px", fontWeight: 700, fontFamily: "inherit",
              borderRadius: "var(--tc-radius-sm)",
              cursor: status === "requesting" || status === "pending" ? "default" : "pointer",
              background: status === "pending" ? "var(--tc-amber-soft)" : "var(--tc-blue-soft)",
              color: status === "pending" ? "var(--tc-amber)" : "var(--tc-blue)",
              border: status === "pending" ? "1px solid rgba(208,144,32,0.3)" : "1px solid rgba(48,128,208,0.3)",
              display: "flex", alignItems: "center", gap: "6px", width: "100%", justifyContent: "center",
            }}
          >
            {status === "requesting" ? <><Loader2 size={12} className="animate-spin" /> {tr("requestInProgress", locale)}</>
              : status === "pending" ? <><Clock size={12} /> {tr("waitingFreeboxButton", locale)}</>
              : <><Wifi size={12} /> {tr("pairFreebox", locale)}</>}
          </button>
        </>
      )}
      {message && status !== "granted" && (
        <div style={{
          marginTop: "8px", fontSize: "10px",
          color: status === "pending" ? "var(--tc-amber)" : "#d03020",
          display: "flex", alignItems: "center", gap: "6px",
        }}>
          {status === "pending" && <Loader2 size={10} className="animate-spin" />}
          {(status === "error" || status === "denied") && <X size={10} />}
          {message}
        </div>
      )}
    </div>
  );
}

// ── Wazuh-specific config addendum ──
// Surfaces two things the generic skill form can't: (1) the built-in noise
// filter defaults so the operator knows what's already silenced without
// having to read source code, (2) the cursor state + a reset button for
// the rare case the operator needs to replay the last hour (e.g. after
// fixing an indexer corruption, or during a training exercise).
function WazuhExtraPanel({
  cursor,
  onCursorReset,
}: {
  cursor: string;
  onCursorReset: () => void;
}) {
  const locale = useLocale();
  const [confirmReset, setConfirmReset] = useState(false);
  return (
    <div
      style={{
        marginTop: "16px",
        marginBottom: "16px",
        padding: "12px 14px",
        background: "var(--tc-surface-alt)",
        border: "1px solid var(--tc-border)",
        borderRadius: "var(--tc-radius-sm)",
      }}
    >
      <div
        style={{
          fontSize: "10px",
          fontWeight: 700,
          color: "var(--tc-text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.14em",
          marginBottom: "10px",
          display: "flex",
          alignItems: "center",
          gap: "6px",
        }}
      >
        <Shield size={11} /> {locale === "fr" ? "Filtre de bruit intégré" : "Built-in noise filter"}
      </div>
      <div style={{ fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: 1.55, marginBottom: "10px" }}>
        {locale === "fr" ? (
          <>
            Les règles suivantes sont silencieuses par défaut — elles génèrent
            ~40-80 événements/minute sur tout hôte Docker et noieraient le
            signal. Ajoute tes propres règles bruit via les champs{" "}
            <code style={{ background: "var(--tc-input)", padding: "0 4px" }}>skip_rule_ids</code> et{" "}
            <code style={{ background: "var(--tc-input)", padding: "0 4px" }}>skip_if_log_contains</code> ci-dessus.
          </>
        ) : (
          <>
            The rules below are silenced by default — they emit ~40-80 events/min
            on any Docker host and would drown the real signal. Add your own
            noise rules via the <code style={{ background: "var(--tc-input)", padding: "0 4px" }}>skip_rule_ids</code> and{" "}
            <code style={{ background: "var(--tc-input)", padding: "0 4px" }}>skip_if_log_contains</code> fields above.
          </>
        )}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginBottom: "14px", fontFamily: "'JetBrains Mono', ui-monospace, monospace", fontSize: "10px" }}>
        <div style={{ color: "var(--tc-text-muted)" }}>
          <span style={{ color: "var(--tc-red)", marginRight: "8px" }}>skip</span>
          rule 5104 when full_log contains <code style={{ color: "var(--tc-text)" }}>veth</code>
          <span style={{ color: "var(--tc-text-muted)", marginLeft: "6px" }}>— Docker veth promiscuous noise</span>
        </div>
        <div style={{ color: "var(--tc-text-muted)" }}>
          <span style={{ color: "var(--tc-red)", marginRight: "8px" }}>skip</span>
          rule 80710 when full_log contains <code style={{ color: "var(--tc-text)" }}>dev=veth</code>
          <span style={{ color: "var(--tc-text-muted)", marginLeft: "6px" }}>— auditd veth promiscuous noise</span>
        </div>
        <div style={{ color: "var(--tc-text-muted)" }}>
          <span style={{ color: "var(--tc-red)", marginRight: "8px" }}>skip</span>
          all rules 80700-80799
          <span style={{ color: "var(--tc-text-muted)", marginLeft: "6px" }}>— Linux audit inventory events</span>
        </div>
      </div>

      <div style={{ borderTop: "1px solid var(--tc-border)", paddingTop: "10px" }}>
        <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.14em", marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" }}>
          <Clock size={11} /> {locale === "fr" ? "Curseur de synchronisation" : "Sync cursor"}
        </div>
        <div style={{ fontSize: "11px", color: "var(--tc-text-sec)", marginBottom: "8px" }}>
          {cursor ? (
            <>
              {locale === "fr" ? "Dernier événement ingéré :" : "Last ingested event:"}{" "}
              <code style={{ color: "var(--tc-text)", fontFamily: "'JetBrains Mono', monospace" }}>{cursor}</code>
            </>
          ) : (
            <span style={{ color: "var(--tc-text-muted)" }}>
              {locale === "fr"
                ? "Pas encore de curseur — le prochain cycle récupérera la dernière heure."
                : "No cursor yet — next cycle will fetch the last hour."}
            </span>
          )}
        </div>
        {cursor && !confirmReset && (
          <button
            type="button"
            onClick={() => setConfirmReset(true)}
            style={{
              padding: "5px 10px",
              fontSize: "10px",
              letterSpacing: "0.14em",
              textTransform: "uppercase",
              background: "transparent",
              color: "var(--tc-text-sec)",
              border: "1px solid var(--tc-border)",
              cursor: "pointer",
              fontFamily: "inherit",
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
            }}
          >
            <RefreshCw size={10} /> {locale === "fr" ? "Réinitialiser" : "Reset cursor"}
          </button>
        )}
        {confirmReset && (
          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            <span style={{ fontSize: "10px", color: "var(--tc-amber)" }}>
              {locale === "fr" ? "Re-ingérer la dernière heure ?" : "Replay the last hour?"}
            </span>
            <button
              type="button"
              onClick={() => {
                onCursorReset();
                setConfirmReset(false);
              }}
              style={{
                padding: "4px 10px",
                fontSize: "10px",
                letterSpacing: "0.14em",
                textTransform: "uppercase",
                background: "var(--tc-red)",
                color: "#fff",
                border: "none",
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              {locale === "fr" ? "Confirmer" : "Confirm"}
            </button>
            <button
              type="button"
              onClick={() => setConfirmReset(false)}
              style={{
                padding: "4px 10px",
                fontSize: "10px",
                letterSpacing: "0.14em",
                textTransform: "uppercase",
                background: "transparent",
                color: "var(--tc-text-muted)",
                border: "1px solid var(--tc-border)",
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              {locale === "fr" ? "Annuler" : "Cancel"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

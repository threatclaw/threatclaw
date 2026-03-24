"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Search, ChevronDown, ChevronRight, Play, Shield, Network,
  Database, Code, Monitor, FileText, Radio, Globe, Server, Users,
  Eye, Crosshair, RefreshCw, CheckCircle2, XCircle,
  Key, Clock, Zap, Power, Settings,
} from "lucide-react";

// ── Types (matching real API response) ──

interface SkillManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  type: string; // "tool" | "connector" | "enrichment"
  category: string;
  execution: any;
  config: Record<string, any> | null;
  default_active: boolean;
  requires_config: boolean;
  api_key_required: boolean;
  icon: string;
}

interface CatalogResponse {
  skills: SkillManifest[];
  total: number;
  tools: number;
  connectors: number;
  enrichment: number;
}

const CATEGORIES: Record<string, { label: string; icon: React.ElementType; color: string }> = {
  "discovery": { label: "Discovery", icon: Network, color: "#30a0d0" },
  "threat-intel": { label: "Threat Intel", icon: Shield, color: "var(--tc-red)" },
  "appsec": { label: "AppSec", icon: Code, color: "var(--tc-amber)" },
  "containers": { label: "Containers", icon: Server, color: "var(--tc-blue)" },
  "monitoring": { label: "Monitoring", icon: Eye, color: "var(--tc-green)" },
  "scanning": { label: "Scanning", icon: Crosshair, color: "var(--tc-purple)" },
  "compliance": { label: "Compliance", icon: FileText, color: "var(--tc-blue)" },
  "rapports": { label: "Rapports", icon: FileText, color: "var(--tc-text-muted)" },
};

const TYPE_INFO: Record<string, { label: string; color: string }> = {
  "tool": { label: "OUTIL", color: "var(--tc-amber)" },
  "connector": { label: "CONNECTEUR", color: "var(--tc-blue)" },
  "enrichment": { label: "ENRICHISSEMENT", color: "var(--tc-green)" },
};

// Skills that have real run endpoints
const RUNNABLE_TOOLS: Record<string, string> = {
  "skill-semgrep": "/api/tc/skills/run/skill-semgrep",
  "skill-checkov": "/api/tc/skills/run/skill-checkov",
  "skill-trufflehog": "/api/tc/skills/run/skill-trufflehog",
  "skill-grype": "/api/tc/skills/run/skill-grype",
  "skill-syft": "/api/tc/skills/run/skill-syft",
};

const RUNNABLE_CONNECTORS: Record<string, string> = {
  "skill-nmap-discovery": "/api/tc/connectors/nmap/scan",
  "skill-active-directory": "/api/tc/connectors/ad/sync",
  "skill-pfsense": "/api/tc/connectors/firewall/sync",
  "skill-proxmox": "/api/tc/connectors/proxmox/sync",
};

function isRunnable(skill: SkillManifest): boolean {
  return skill.id in RUNNABLE_TOOLS || skill.id in RUNNABLE_CONNECTORS;
}

function getRunUrl(skill: SkillManifest): string | null {
  return RUNNABLE_TOOLS[skill.id] || RUNNABLE_CONNECTORS[skill.id] || null;
}

function getRunLabel(skill: SkillManifest): string {
  if (skill.type === "connector") return "Synchroniser";
  if (skill.type === "tool") return "Lancer le scan";
  return "";
}

export default function SkillsPage() {
  const [catalog, setCatalog] = useState<CatalogResponse | null>(null);
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState<string>("all");
  const [filterCat, setFilterCat] = useState<string>("all");
  const [showOnlyActive, setShowOnlyActive] = useState(false);
  const [expandedSkill, setExpandedSkill] = useState<string | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, Record<string, string>>>({});
  const [enabledSkills, setEnabledSkills] = useState<Set<string>>(new Set());
  const [running, setRunning] = useState<string | null>(null);
  const [runResult, setRunResult] = useState<any>(null);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch("/api/tc/catalog");
      if (res.ok) {
        const data: CatalogResponse = await res.json();
        setCatalog(data);
        // Init enabled from default_active
        const active = new Set<string>();
        data.skills.forEach(s => { if (s.default_active) active.add(s.id); });
        setEnabledSkills(prev => {
          const merged = new Set(prev);
          active.forEach(id => merged.add(id));
          return merged;
        });
      }
    } catch {}
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  if (!catalog) return <div style={{ padding: "40px", textAlign: "center", color: "var(--tc-text-muted)" }}>Chargement du catalogue...</div>;

  // Filter
  let filtered = catalog.skills;
  if (filterType !== "all") filtered = filtered.filter(s => s.type === filterType);
  if (filterCat !== "all") filtered = filtered.filter(s => s.category === filterCat);
  if (showOnlyActive) filtered = filtered.filter(s => enabledSkills.has(s.id));
  if (search.trim()) {
    const q = search.toLowerCase();
    filtered = filtered.filter(s =>
      s.name.toLowerCase().includes(q) || s.description.toLowerCase().includes(q) ||
      s.id.toLowerCase().includes(q) || s.category.toLowerCase().includes(q)
    );
  }

  // Group by category
  const grouped: Record<string, SkillManifest[]> = {};
  for (const s of filtered) {
    const cat = s.category || "autre";
    if (!grouped[cat]) grouped[cat] = [];
    grouped[cat].push(s);
  }

  const availableCats = Array.from(new Set(catalog.skills.map(s => s.category))).filter(Boolean).sort();

  const toggleSkill = (id: string) => {
    setEnabledSkills(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const handleRun = async (skill: SkillManifest) => {
    const url = getRunUrl(skill);
    if (!url) return;
    setRunning(skill.id);
    setRunResult(null);
    try {
      const body: any = {};
      if (configValues[skill.id]) Object.assign(body, configValues[skill.id]);
      // Map specific fields for connectors
      if (skill.id === "skill-nmap-discovery") {
        body.targets = body.target_subnets || "192.168.1.0/24";
        body.top_ports = parseInt(body.top_ports) || 1000;
      }
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      setRunResult(await res.json());
    } catch (e: any) {
      setRunResult({ error: e.message });
    }
    setRunning(null);
  };

  const setConfig = (skillId: string, key: string, value: string) => {
    setConfigValues(prev => ({ ...prev, [skillId]: { ...prev[skillId], [key]: value } }));
  };

  const activeCount = filtered.filter(s => enabledSkills.has(s.id)).length;

  return (
    <div style={{ padding: "0 24px 40px" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>Skills</h1>
          <p style={{ fontSize: "12px", color: "var(--tc-text-muted)", margin: "4px 0 0" }}>
            {catalog.total} skills &middot; {catalog.tools} outils &middot; {catalog.connectors} connecteurs &middot; {catalog.enrichment} enrichissement
            &middot; <span style={{ color: "var(--tc-green)" }}>{activeCount} actives</span>
          </p>
        </div>
        <button onClick={refresh} style={{
          display: "flex", alignItems: "center", gap: "6px", padding: "8px 16px", borderRadius: "var(--tc-radius-input)",
          border: "1px solid var(--tc-border)", background: "var(--tc-surface-alt)",
          color: "var(--tc-text-muted)", fontSize: "11px", fontWeight: 600, cursor: "pointer",
        }}><RefreshCw size={12} /> Actualiser</button>
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap", alignItems: "center" }}>
        <div style={{ flex: 1, minWidth: "180px", position: "relative" }}>
          <Search size={14} style={{ position: "absolute", left: "10px", top: "9px", color: "var(--tc-text-muted)" }} />
          <input type="text" value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Rechercher..." style={{
              width: "100%", padding: "8px 10px 8px 32px", borderRadius: "var(--tc-radius-input)", fontSize: "12px",
              background: "var(--tc-input)", border: "1px solid var(--tc-border)",
              color: "var(--tc-text)", outline: "none",
            }} />
        </div>
        {[
          { key: "all", label: `Tous (${catalog.total})` },
          { key: "tool", label: `Outils (${catalog.tools})` },
          { key: "connector", label: `Connecteurs (${catalog.connectors})` },
          { key: "enrichment", label: `Enrichissement (${catalog.enrichment})` },
        ].map(f => (
          <button key={f.key} onClick={() => setFilterType(f.key)} style={{
            padding: "7px 12px", borderRadius: "var(--tc-radius-input)", fontSize: "10px", fontWeight: 600,
            border: filterType === f.key ? "1px solid rgba(208,48,32,0.3)" : "1px solid rgba(255,255,255,0.08)",
            background: filterType === f.key ? "rgba(208,48,32,0.1)" : "transparent",
            color: filterType === f.key ? "var(--tc-red)" : "var(--tc-text-muted)", cursor: "pointer",
          }}>{f.label}</button>
        ))}
        <select value={filterCat} onChange={e => setFilterCat(e.target.value)} style={{
          padding: "7px 10px", borderRadius: "var(--tc-radius-input)", fontSize: "10px",
          background: "var(--tc-input)", border: "1px solid var(--tc-border)",
          color: "var(--tc-text)", outline: "none",
        }}>
          <option value="all">Categorie</option>
          {availableCats.map(c => <option key={c} value={c}>{CATEGORIES[c]?.label || c}</option>)}
        </select>
        <button onClick={() => setShowOnlyActive(!showOnlyActive)} style={{
          padding: "7px 12px", borderRadius: "var(--tc-radius-input)", fontSize: "10px", fontWeight: 600,
          border: showOnlyActive ? "1px solid rgba(48,160,80,0.3)" : "1px solid rgba(255,255,255,0.08)",
          background: showOnlyActive ? "rgba(48,160,80,0.1)" : "transparent",
          color: showOnlyActive ? "var(--tc-green)" : "var(--tc-text-muted)", cursor: "pointer",
        }}><Power size={10} style={{ display: "inline", verticalAlign: "middle", marginRight: "4px" }} />Actives</button>
      </div>

      {/* Skills by category */}
      {Object.entries(grouped).map(([cat, skills]) => {
        const ci = CATEGORIES[cat] || { label: cat, icon: Zap, color: "var(--tc-text-muted)" };
        const CatIcon = ci.icon;
        return (
          <div key={cat} style={{ marginBottom: "20px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px" }}>
              <CatIcon size={15} color={ci.color} />
              <span style={{ fontSize: "12px", fontWeight: 700, color: ci.color, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                {ci.label}
              </span>
              <span style={{ fontSize: "10px", color: "var(--tc-text-faint)" }}>({skills.length})</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: "8px" }}>
              {skills.map(skill => {
                const expanded = expandedSkill === skill.id;
                const ti = TYPE_INFO[skill.type] || { label: skill.type, color: "var(--tc-text-muted)" };
                const enabled = enabledSkills.has(skill.id);
                const configKeys = skill.config ? Object.keys(skill.config) : [];
                const canRun = isRunnable(skill);

                return (
                  <div key={skill.id} style={{
                    background: "var(--tc-surface-alt)", border: `1px solid ${enabled ? "var(--tc-green-soft)" : "var(--tc-border)"}`,
                    borderRadius: "var(--tc-radius-md)", borderLeft: `3px solid ${enabled ? "var(--tc-green)" : "var(--tc-border-light)"}`,
                  }}>
                    {/* Header */}
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", padding: "10px 12px" }}>
                      {/* Toggle */}
                      <button onClick={() => toggleSkill(skill.id)} style={{
                        width: "34px", height: "18px", borderRadius: "9px", border: "none", cursor: "pointer",
                        background: enabled ? "var(--tc-green)" : "var(--tc-input)",
                        position: "relative", flexShrink: 0,
                      }}>
                        <div style={{
                          width: "14px", height: "14px", borderRadius: "7px", background: "#fff",
                          position: "absolute", top: "2px", transition: "left 150ms",
                          left: enabled ? "18px" : "2px",
                        }} />
                      </button>

                      {/* Name + badges */}
                      <div style={{ flex: 1, cursor: "pointer" }} onClick={() => setExpandedSkill(expanded ? null : skill.id)}>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                          <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{skill.name}</span>
                          <span style={{
                            fontSize: "7px", fontWeight: 700, padding: "1px 5px", borderRadius: "3px",
                            background: `${ti.color}15`, color: ti.color, textTransform: "uppercase",
                          }}>{ti.label}</span>
                          {skill.api_key_required && <Key size={10} color="#d09020" />}
                        </div>
                        <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "2px" }}>
                          {skill.description.substring(0, 70)}{skill.description.length > 70 ? "..." : ""}
                        </div>
                      </div>

                      {/* Expand arrow */}
                      <div onClick={() => setExpandedSkill(expanded ? null : skill.id)} style={{ cursor: "pointer", padding: "4px" }}>
                        {expanded ? <ChevronDown size={14} color="#6a625c" /> : <ChevronRight size={14} color="#6a625c" />}
                      </div>
                    </div>

                    {/* Expanded */}
                    {expanded && (
                      <div style={{ padding: "0 12px 12px", borderTop: "1px solid var(--tc-border-light)" }}>
                        <p style={{ fontSize: "11px", color: "var(--tc-text-sec)", margin: "10px 0", lineHeight: "1.5" }}>
                          {skill.description}
                        </p>

                        {/* Metadata */}
                        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginBottom: "10px", fontSize: "9px", color: "var(--tc-text-muted)" }}>
                          {skill.version && <span>v{skill.version}</span>}
                          {skill.author && <span>{skill.author}</span>}
                          {skill.execution?.mode === "ephemeral" && <span>Docker ephemere</span>}
                          {skill.execution?.mode === "persistent" && <span>Sync continue</span>}
                          {skill.execution?.mode === "api" && <span>API externe</span>}
                          {skill.execution?.docker_image && (
                            <span style={{ color: "var(--tc-blue)", fontFamily: "monospace" }}>{skill.execution.docker_image}</span>
                          )}
                          {skill.execution?.sync_interval_minutes && (
                            <span><Clock size={8} style={{ display: "inline", verticalAlign: "middle" }} /> {skill.execution.sync_interval_minutes}min</span>
                          )}
                          {skill.execution?.base_url && (
                            <span style={{ fontFamily: "monospace", color: "var(--tc-text-muted)" }}>{skill.execution.base_url.substring(0, 40)}...</span>
                          )}
                        </div>

                        {/* Config fields — only if skill HAS config */}
                        {configKeys.length > 0 && (
                          <div style={{ marginBottom: "10px" }}>
                            <div style={{ fontSize: "9px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: "6px" }}>
                              <Settings size={9} style={{ display: "inline", verticalAlign: "middle", marginRight: "4px" }} />
                              Configuration
                            </div>
                            {configKeys.map(key => {
                              const field = skill.config![key];
                              if (!field) return null;
                              const val = configValues[skill.id]?.[key] || "";
                              return (
                                <div key={key} style={{ marginBottom: "6px" }}>
                                  <label style={{ fontSize: "9px", color: "var(--tc-text-sec)", display: "block", marginBottom: "2px" }}>
                                    {field.description || key}
                                    {field.required && <span style={{ color: "var(--tc-red)" }}> *</span>}
                                  </label>
                                  {field.options ? (
                                    <select value={val || field.default || ""} onChange={e => setConfig(skill.id, key, e.target.value)}
                                      style={{ width: "100%", padding: "5px 8px", borderRadius: "var(--tc-radius-sm)", fontSize: "11px",
                                        background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                                        color: "var(--tc-text)", outline: "none" }}>
                                      <option value="">Choisir...</option>
                                      {field.options.map((o: string) => <option key={o} value={o}>{o}</option>)}
                                    </select>
                                  ) : field.type === "boolean" ? (
                                    <label style={{ fontSize: "10px", color: "var(--tc-text)", display: "flex", alignItems: "center", gap: "6px" }}>
                                      <input type="checkbox" checked={val === "true" || (!val && field.default === true)}
                                        onChange={e => setConfig(skill.id, key, e.target.checked ? "true" : "false")} />
                                      {field.default ? "Oui" : "Non"} par defaut
                                    </label>
                                  ) : (
                                    <input type={field.type === "password" ? "password" : "text"} value={val}
                                      onChange={e => setConfig(skill.id, key, e.target.value)}
                                      placeholder={field.default?.toString() || ""}
                                      style={{ width: "100%", padding: "5px 8px", borderRadius: "var(--tc-radius-sm)", fontSize: "11px",
                                        background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                                        color: "var(--tc-text)", outline: "none" }} />
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        )}

                        {/* Actions — only for runnable skills */}
                        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                          {canRun && (
                            <button onClick={() => handleRun(skill)} disabled={running === skill.id}
                              style={{
                                display: "flex", alignItems: "center", gap: "5px",
                                padding: "6px 12px", borderRadius: "var(--tc-radius-sm)", fontSize: "10px", fontWeight: 600,
                                background: "var(--tc-red-soft)", border: "1px solid var(--tc-red-border)",
                                color: "var(--tc-red)", cursor: running === skill.id ? "wait" : "pointer",
                                opacity: running === skill.id ? 0.5 : 1,
                              }}>
                              <Play size={11} />
                              {running === skill.id ? "En cours..." : getRunLabel(skill)}
                            </button>
                          )}
                          {skill.type === "enrichment" && !canRun && (
                            <span style={{ fontSize: "10px", color: "var(--tc-text-muted)", fontStyle: "italic" }}>
                              {skill.default_active ? "Actif automatiquement dans le pipeline" : "Activez le toggle pour inclure dans le pipeline"}
                            </span>
                          )}
                          {skill.default_active && (
                            <span style={{ fontSize: "9px", color: "var(--tc-green)", display: "flex", alignItems: "center", gap: "3px" }}>
                              <CheckCircle2 size={10} /> Actif par defaut
                            </span>
                          )}
                        </div>

                        {/* Run result */}
                        {runResult && expandedSkill === skill.id && (
                          <div style={{
                            marginTop: "8px", padding: "8px", borderRadius: "var(--tc-radius-sm)",
                            background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
                            fontSize: "9px", fontFamily: "monospace", color: "var(--tc-text-sec)",
                            maxHeight: "120px", overflow: "auto",
                          }}>
                            <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(runResult, null, 2)}</pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {filtered.length === 0 && (
        <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-muted)" }}>
          Aucune skill ne correspond aux filtres
        </div>
      )}
    </div>
  );
}

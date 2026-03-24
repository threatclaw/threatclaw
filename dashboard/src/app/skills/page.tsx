"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Search, ChevronDown, ChevronRight, Play, Settings, Shield, Network,
  Database, Code, Monitor, FileText, Radio, Globe, Server, Users,
  Eye, Crosshair, AlertTriangle, RefreshCw, CheckCircle2, XCircle,
  Key, Clock, Zap,
} from "lucide-react";

// ── Types ──

interface SkillManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  skill_type: string; // "tool" | "connector" | "enrichment"
  category: string;
  execution: any;
  config: Record<string, { type: string; description: string; required?: boolean; default?: any; options?: string[] }>;
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

// ── Category config ──

const CATEGORIES: Record<string, { label: string; icon: React.ElementType; color: string }> = {
  "discovery": { label: "Discovery", icon: Network, color: "#30a0d0" },
  "threat-intel": { label: "Threat Intel", icon: Shield, color: "#d03020" },
  "appsec": { label: "AppSec", icon: Code, color: "#d09020" },
  "containers": { label: "Containers", icon: Server, color: "#3080d0" },
  "monitoring": { label: "Monitoring", icon: Eye, color: "#30a050" },
  "scanning": { label: "Scanning", icon: Crosshair, color: "#9060d0" },
  "compliance": { label: "Compliance", icon: FileText, color: "#3080d0" },
  "rapports": { label: "Rapports", icon: FileText, color: "#6a625c" },
};

const TYPE_LABELS: Record<string, { label: string; color: string }> = {
  "tool": { label: "OUTIL", color: "#d09020" },
  "connector": { label: "CONNECTEUR", color: "#3080d0" },
  "enrichment": { label: "ENRICHISSEMENT", color: "#30a050" },
};

// ── Main Page ──

export default function SkillsPage() {
  const [catalog, setCatalog] = useState<CatalogResponse | null>(null);
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState<string>("all");
  const [filterCat, setFilterCat] = useState<string>("all");
  const [expandedSkill, setExpandedSkill] = useState<string | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, Record<string, string>>>({});
  const [running, setRunning] = useState<string | null>(null);
  const [runResult, setRunResult] = useState<any>(null);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch("/api/tc/catalog");
      if (res.ok) setCatalog(await res.json());
    } catch {}
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  if (!catalog) return <div style={{ padding: "40px", textAlign: "center", color: "#6a625c" }}>Chargement du catalogue...</div>;

  // Filter + search
  let filtered = catalog.skills;
  if (filterType !== "all") filtered = filtered.filter(s => s.skill_type === filterType);
  if (filterCat !== "all") filtered = filtered.filter(s => s.category === filterCat);
  if (search.trim()) {
    const q = search.toLowerCase();
    filtered = filtered.filter(s =>
      s.name.toLowerCase().includes(q) ||
      s.description.toLowerCase().includes(q) ||
      s.id.toLowerCase().includes(q) ||
      s.category.toLowerCase().includes(q)
    );
  }

  // Group by category
  const grouped: Record<string, SkillManifest[]> = {};
  for (const s of filtered) {
    const cat = s.category || "autre";
    if (!grouped[cat]) grouped[cat] = [];
    grouped[cat].push(s);
  }

  // Available categories from current filter
  const availableCats = Array.from(new Set(catalog.skills.map(s => s.category))).sort();

  const handleRun = async (skill: SkillManifest) => {
    setRunning(skill.id);
    setRunResult(null);
    try {
      const body: any = { target: configValues[skill.id]?.target_subnets || configValues[skill.id]?.target_path || configValues[skill.id]?.target_image || "." };
      // Add all config values
      if (configValues[skill.id]) {
        Object.assign(body, configValues[skill.id]);
      }

      let url = "";
      if (skill.id === "skill-nmap-discovery") {
        url = "/api/tc/connectors/nmap/scan";
        body.targets = configValues[skill.id]?.target_subnets || "192.168.1.0/24";
      } else if (skill.id === "skill-active-directory") {
        url = "/api/tc/connectors/ad/sync";
      } else if (skill.id === "skill-pfsense") {
        url = "/api/tc/connectors/firewall/sync";
      } else if (skill.id === "skill-proxmox") {
        url = "/api/tc/connectors/proxmox/sync";
      } else {
        url = `/api/tc/skills/run/${skill.id}`;
      }

      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      setRunResult(data);
    } catch (e: any) {
      setRunResult({ error: e.message });
    }
    setRunning(null);
  };

  const setConfig = (skillId: string, key: string, value: string) => {
    setConfigValues(prev => ({
      ...prev,
      [skillId]: { ...prev[skillId], [key]: value },
    }));
  };

  return (
    <div style={{ padding: "0 24px 40px" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: 800, color: "#e8e4e0", margin: 0 }}>Skills</h1>
          <p style={{ fontSize: "12px", color: "#6a625c", margin: "4px 0 0" }}>
            {catalog.total} skills &middot; {catalog.tools} outils &middot; {catalog.connectors} connecteurs &middot; {catalog.enrichment} enrichissement
          </p>
        </div>
        <button onClick={refresh} style={{
          display: "flex", alignItems: "center", gap: "6px", padding: "8px 16px",
          borderRadius: "8px", border: "1px solid rgba(255,255,255,0.08)",
          background: "rgba(255,255,255,0.03)", color: "#6a625c",
          fontSize: "11px", fontWeight: 600, cursor: "pointer",
        }}>
          <RefreshCw size={12} /> Actualiser
        </button>
      </div>

      {/* Search + filters */}
      <div style={{ display: "flex", gap: "10px", marginBottom: "20px", flexWrap: "wrap" }}>
        <div style={{ flex: 1, minWidth: "200px", position: "relative" }}>
          <Search size={14} style={{ position: "absolute", left: "10px", top: "9px", color: "#6a625c" }} />
          <input
            type="text" value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Rechercher une skill..."
            style={{
              width: "100%", padding: "8px 10px 8px 32px", borderRadius: "8px", fontSize: "12px",
              background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
              color: "#e8e4e0", outline: "none",
            }}
          />
        </div>
        {/* Type filter */}
        {[
          { key: "all", label: "Tous" },
          { key: "tool", label: "Outils" },
          { key: "connector", label: "Connecteurs" },
          { key: "enrichment", label: "Enrichissement" },
        ].map(f => (
          <button key={f.key} onClick={() => setFilterType(f.key)} style={{
            padding: "8px 14px", borderRadius: "8px", fontSize: "11px", fontWeight: 600,
            border: filterType === f.key ? "1px solid rgba(208,48,32,0.3)" : "1px solid rgba(255,255,255,0.08)",
            background: filterType === f.key ? "rgba(208,48,32,0.1)" : "rgba(255,255,255,0.03)",
            color: filterType === f.key ? "#d03020" : "#6a625c",
            cursor: "pointer",
          }}>{f.label}</button>
        ))}
        {/* Category filter */}
        <select
          value={filterCat} onChange={e => setFilterCat(e.target.value)}
          style={{
            padding: "8px 12px", borderRadius: "8px", fontSize: "11px",
            background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
            color: "#e8e4e0", outline: "none",
          }}
        >
          <option value="all">Toutes categories</option>
          {availableCats.map(c => (
            <option key={c} value={c}>{CATEGORIES[c]?.label || c}</option>
          ))}
        </select>
      </div>

      {/* Skills grouped by category */}
      {Object.entries(grouped).map(([cat, skills]) => {
        const catInfo = CATEGORIES[cat] || { label: cat, icon: Zap, color: "#6a625c" };
        const CatIcon = catInfo.icon;
        return (
          <div key={cat} style={{ marginBottom: "24px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
              <CatIcon size={16} color={catInfo.color} />
              <span style={{ fontSize: "13px", fontWeight: 700, color: catInfo.color, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                {catInfo.label}
              </span>
              <span style={{ fontSize: "11px", color: "#6a625c" }}>({skills.length})</span>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: "10px" }}>
              {skills.map(skill => {
                const isExpanded = expandedSkill === skill.id;
                const typeInfo = TYPE_LABELS[skill.skill_type] || { label: skill.skill_type, color: "#6a625c" };
                const configKeys = Object.keys(skill.config || {});
                const hasConfig = configKeys.length > 0;

                return (
                  <div key={skill.id} style={{
                    background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
                    borderRadius: "10px", overflow: "hidden",
                    borderLeft: skill.default_active ? `3px solid ${typeInfo.color}` : "3px solid transparent",
                  }}>
                    {/* Header — always visible */}
                    <div
                      onClick={() => setExpandedSkill(isExpanded ? null : skill.id)}
                      style={{
                        display: "flex", alignItems: "center", gap: "10px", padding: "12px 14px",
                        cursor: "pointer", userSelect: "none",
                      }}
                    >
                      {isExpanded ? <ChevronDown size={14} color="#6a625c" /> : <ChevronRight size={14} color="#6a625c" />}
                      <div style={{ flex: 1 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={{ fontSize: "13px", fontWeight: 700, color: "#e8e4e0" }}>{skill.name}</span>
                          <span style={{
                            fontSize: "8px", fontWeight: 700, padding: "2px 6px", borderRadius: "3px",
                            background: `${typeInfo.color}15`, color: typeInfo.color, border: `1px solid ${typeInfo.color}30`,
                            textTransform: "uppercase", letterSpacing: "0.05em",
                          }}>{typeInfo.label}</span>
                          {skill.default_active && (
                            <CheckCircle2 size={12} color="#30a050" />
                          )}
                          {skill.api_key_required && (
                            <Key size={11} color="#d09020" />
                          )}
                        </div>
                        <div style={{ fontSize: "10px", color: "#6a625c", marginTop: "2px" }}>
                          {skill.description.substring(0, 80)}{skill.description.length > 80 ? "..." : ""}
                        </div>
                      </div>
                    </div>

                    {/* Expanded detail */}
                    {isExpanded && (
                      <div style={{ padding: "0 14px 14px", borderTop: "1px solid rgba(255,255,255,0.04)" }}>
                        {/* Full description */}
                        <p style={{ fontSize: "11px", color: "#a09080", margin: "10px 0", lineHeight: "1.6" }}>
                          {skill.description}
                        </p>

                        {/* Metadata */}
                        <div style={{ display: "flex", gap: "12px", marginBottom: "12px", flexWrap: "wrap" }}>
                          <span style={{ fontSize: "10px", color: "#6a625c" }}>v{skill.version || "1.0.0"}</span>
                          <span style={{ fontSize: "10px", color: "#6a625c" }}>par {skill.author || "ThreatClaw"}</span>
                          {skill.execution?.mode && (
                            <span style={{ fontSize: "10px", color: "#6a625c" }}>
                              {skill.execution.mode === "ephemeral" ? "Docker ephemere" :
                               skill.execution.mode === "persistent" ? "Synchronisation continue" :
                               skill.execution.mode === "api" ? "API externe" : skill.execution.mode}
                            </span>
                          )}
                          {skill.execution?.docker_image && (
                            <span style={{ fontSize: "10px", color: "#3080d0", fontFamily: "monospace" }}>
                              {skill.execution.docker_image}
                            </span>
                          )}
                          {skill.execution?.sync_interval_minutes && (
                            <span style={{ fontSize: "10px", color: "#6a625c" }}>
                              <Clock size={9} style={{ display: "inline", verticalAlign: "middle" }} /> sync {skill.execution.sync_interval_minutes}min
                            </span>
                          )}
                        </div>

                        {/* Config fields */}
                        {hasConfig && (
                          <div style={{ marginBottom: "12px" }}>
                            <div style={{ fontSize: "10px", fontWeight: 700, color: "#6a625c", textTransform: "uppercase", marginBottom: "6px" }}>
                              Configuration
                            </div>
                            {configKeys.map(key => {
                              const field = (skill.config as any)[key];
                              const val = configValues[skill.id]?.[key] || "";
                              return (
                                <div key={key} style={{ marginBottom: "8px" }}>
                                  <label style={{ fontSize: "10px", color: "#a09080", display: "block", marginBottom: "3px" }}>
                                    {field.description || key}
                                    {field.required && <span style={{ color: "#d03020" }}> *</span>}
                                  </label>
                                  {field.type === "select" && field.options ? (
                                    <select
                                      value={val || field.default || ""}
                                      onChange={e => setConfig(skill.id, key, e.target.value)}
                                      style={{
                                        width: "100%", padding: "6px 8px", borderRadius: "6px", fontSize: "11px",
                                        background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
                                        color: "#e8e4e0", outline: "none",
                                      }}
                                    >
                                      <option value="">Choisir...</option>
                                      {field.options.map((o: string) => <option key={o} value={o}>{o}</option>)}
                                    </select>
                                  ) : field.type === "boolean" ? (
                                    <label style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px", color: "#e8e4e0" }}>
                                      <input
                                        type="checkbox"
                                        checked={val === "true" || (!val && field.default === true)}
                                        onChange={e => setConfig(skill.id, key, e.target.checked ? "true" : "false")}
                                      />
                                      {field.default === true ? "Actif par defaut" : "Desactive par defaut"}
                                    </label>
                                  ) : (
                                    <input
                                      type={field.type === "password" ? "password" : "text"}
                                      value={val}
                                      onChange={e => setConfig(skill.id, key, e.target.value)}
                                      placeholder={field.default?.toString() || ""}
                                      style={{
                                        width: "100%", padding: "6px 8px", borderRadius: "6px", fontSize: "11px",
                                        background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
                                        color: "#e8e4e0", outline: "none",
                                      }}
                                    />
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        )}

                        {/* Action buttons */}
                        <div style={{ display: "flex", gap: "8px" }}>
                          {skill.skill_type !== "enrichment" && (
                            <button
                              onClick={() => handleRun(skill)}
                              disabled={running === skill.id}
                              style={{
                                display: "flex", alignItems: "center", gap: "6px",
                                padding: "7px 14px", borderRadius: "6px", fontSize: "11px", fontWeight: 600,
                                background: "rgba(208,48,32,0.1)", border: "1px solid rgba(208,48,32,0.3)",
                                color: "#d03020", cursor: running === skill.id ? "wait" : "pointer",
                                opacity: running === skill.id ? 0.5 : 1,
                              }}
                            >
                              <Play size={12} />
                              {running === skill.id ? "En cours..." :
                               skill.skill_type === "connector" ? "Synchroniser" : "Lancer le scan"}
                            </button>
                          )}
                          {skill.default_active && (
                            <span style={{
                              display: "flex", alignItems: "center", gap: "4px",
                              padding: "7px 12px", fontSize: "10px", color: "#30a050",
                            }}>
                              <CheckCircle2 size={12} /> Actif par defaut
                            </span>
                          )}
                        </div>

                        {/* Run result */}
                        {runResult && expandedSkill === skill.id && (
                          <div style={{
                            marginTop: "10px", padding: "10px", borderRadius: "6px",
                            background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)",
                            fontSize: "10px", fontFamily: "monospace", color: "#a09080",
                            maxHeight: "150px", overflow: "auto",
                          }}>
                            <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>
                              {JSON.stringify(runResult, null, 2)}
                            </pre>
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
        <div style={{ textAlign: "center", padding: "40px", color: "#6a625c" }}>
          Aucune skill ne correspond a votre recherche
        </div>
      )}
    </div>
  );
}

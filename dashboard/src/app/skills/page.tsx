"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Search, Settings, Shield, Network, Database, Code, Monitor,
  FileText, Eye, Crosshair, RefreshCw, CheckCircle2,
  Key, Clock, Zap, Power, Play, X, Trash2, Plus, Server,
  ChevronDown, ChevronRight, Download,
} from "lucide-react";

interface SkillManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  type: string;
  category: string;
  execution: any;
  config: Record<string, any> | null;
  default_active: boolean;
  requires_config: boolean;
  api_key_required: boolean;
  icon: string;
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
};

// Skills with no real backend code yet — shown grayed out in catalog
const NOT_FUNCTIONAL: Set<string> = new Set([
  "skill-ad-audit",       // PowerShell scripts not written
  "skill-cloud-posture",  // No cloud API integration
  "skill-darkweb-monitor",// No darkweb scraping code
  "skill-report-gen",     // Report generation is manual
  "skill-vuln-scan",      // Use skill-nmap-discovery instead
]);

export default function SkillsPage() {
  const [allSkills, setAllSkills] = useState<SkillManifest[]>([]);
  const [enabled, setEnabled] = useState<Set<string>>(new Set());
  const [tab, setTab] = useState<"my" | "catalog">("my");
  const [search, setSearch] = useState("");
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
        setEnabled(prev => { const m = new Set(prev); active.forEach(id => m.add(id)); return m; });
      }
    } catch {}
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const mySkills = allSkills.filter(s => enabled.has(s.id));
  const catalogSkills = allSkills.filter(s => !enabled.has(s.id));
  const filteredCatalog = search.trim()
    ? catalogSkills.filter(s => s.name.toLowerCase().includes(search.toLowerCase()) || s.description.toLowerCase().includes(search.toLowerCase()))
    : catalogSkills;

  const catalogGrouped: Record<string, SkillManifest[]> = {};
  for (const s of filteredCatalog) { const c = s.category || "autre"; if (!catalogGrouped[c]) catalogGrouped[c] = []; catalogGrouped[c].push(s); }

  const install = (skill: SkillManifest) => {
    setInstalling(skill);
    setInstallDone(false);
    setInstallMsg("Installation en cours...");
    setTimeout(() => {
      setEnabled(prev => new Set(prev).add(skill.id));
      setDisabledSkills(prev => { const n = new Set(prev); n.delete(skill.id); return n; });
      setInstallDone(true);
      setInstallMsg(`${skill.name} installe ! Configurez-le dans My Skills`);
      setTimeout(() => { setInstalling(null); setInstallDone(false); }, 2000);
    }, 3000);
  };
  const uninstall = (id: string) => {
    setModalSkill(null);
    const skill = allSkills.find(s => s.id === id);
    setInstalling(skill || null);
    setInstallDone(false);
    setInstallMsg("Desinstallation en cours...");
    setTimeout(() => {
      setEnabled(prev => { const n = new Set(prev); n.delete(id); return n; });
      setDisabledSkills(prev => { const n = new Set(prev); n.delete(id); return n; });
      setInstallDone(true);
      setInstallMsg(`${skill?.name || "Skill"} desinstallee`);
      setTimeout(() => { setInstalling(null); setInstallDone(false); }, 2000);
    }, 2000);
  };
  // Toggle = enable/disable, NOT uninstall (stays in My Skills)
  const toggleActive = (id: string) => {
    setDisabledSkills(prev => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id); else n.add(id);
      return n;
    });
  };
  const setConfig = (sid: string, key: string, val: string) => { setConfigValues(prev => ({ ...prev, [sid]: { ...prev[sid], [key]: val } })); };

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

  return (
    <div style={{ padding: "0 24px 40px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>Skills</h1>
        <button className="tc-btn-embossed" onClick={refresh}><RefreshCw size={12} /> Actualiser</button>
      </div>

      {/* Sliding tabs */}
      <div style={{ position: "relative", display: "flex", padding: "3px", marginBottom: "16px", borderRadius: "11px", background: "var(--tc-input)" }}>
        <div style={{ position: "absolute", top: "3px", height: "calc(100% - 6px)", width: "calc(50% - 2px)",
          left: tab === "my" ? "1px" : "calc(50% + 1px)",
          background: "var(--tc-surface-alt)", borderRadius: "8px", border: "0.5px solid var(--tc-border)",
          boxShadow: "0 3px 8px rgba(0,0,0,0.12)", transition: "left 0.25s ease-out", zIndex: 0 }} />
        {([["my", `My Skills (${mySkills.length})`], ["catalog", `Catalog (${catalogSkills.length})`]] as const).map(([k, l]) => (
          <button key={k} onClick={() => setTab(k)} style={{ flex: 1, padding: "8px 0", fontSize: "12px", fontWeight: 600,
            color: tab === k ? "var(--tc-text)" : "var(--tc-text-muted)", background: "transparent", border: "none",
            cursor: "pointer", position: "relative", zIndex: 1, opacity: tab === k ? 1 : 0.5, transition: "all 200ms" }}>{l}</button>
        ))}
      </div>

      {/* ═══ MY SKILLS ═══ */}
      {tab === "my" && (
        <div>
          {mySkills.length === 0 && <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-faint)" }}>Aucune skill activee. Allez dans le Catalog pour en ajouter.</div>}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "8px" }}>
            {mySkills.map(skill => {
              const ti = TYPE_INFO[skill.type] || { label: skill.type, color: "var(--tc-text-muted)" };
              return (
                <div key={skill.id} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "10px 12px",
                  borderRadius: "var(--tc-radius-md)", background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)" }}>
                  <input type="checkbox" className="tc-toggle" checked={!disabledSkills.has(skill.id)} onChange={() => toggleActive(skill.id)} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{skill.name}</div>
                    <span style={{ fontSize: "8px", fontWeight: 700, padding: "1px 5px", borderRadius: "3px", background: `${ti.color}15`, color: ti.color, textTransform: "uppercase" }}>{ti.label}</span>
                  </div>
                  <button onClick={() => { setRunResult(null); setModalSkill(skill); }} style={{ padding: "6px", borderRadius: "6px", background: "transparent", border: "none", color: "var(--tc-text-muted)", cursor: "pointer" }}>
                    <Settings size={14} />
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ═══ CATALOG ═══ */}
      {tab === "catalog" && (
        <div>
          <div style={{ position: "relative", marginBottom: "16px" }}>
            <Search size={14} style={{ position: "absolute", left: "10px", top: "9px", color: "var(--tc-text-muted)" }} />
            <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder="Rechercher..."
              style={{ width: "100%", padding: "8px 10px 8px 32px", borderRadius: "var(--tc-radius-input)", fontSize: "12px",
                background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", outline: "none" }} />
          </div>
          {Object.keys(catalogGrouped).length === 0 && <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-faint)" }}>{search ? "Aucune skill trouvee" : "Toutes les skills sont installees"}</div>}
          {Object.entries(catalogGrouped).map(([cat, skills]) => {
            const ci = CATEGORIES[cat] || { label: cat, icon: Zap, color: "var(--tc-text-muted)" };
            const CatIcon = ci.icon;
            return (
              <div key={cat} style={{ marginBottom: "20px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
                  <CatIcon size={14} color={ci.color} />
                  <span style={{ fontSize: "11px", fontWeight: 700, color: ci.color, textTransform: "uppercase", letterSpacing: "0.05em" }}>{ci.label}</span>
                  <span style={{ fontSize: "10px", color: "var(--tc-text-faint)" }}>({skills.length})</span>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "8px" }}>
                  {skills.map(skill => {
                    const ti = TYPE_INFO[skill.type] || { label: skill.type, color: "var(--tc-text-muted)" };
                    const isExp = expandedCatalog === skill.id;
                    const notReady = NOT_FUNCTIONAL.has(skill.id);
                    return (
                      <div key={skill.id} style={{
                        borderRadius: "var(--tc-radius-md)", background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)", overflow: "hidden",
                        opacity: notReady ? 0.45 : 1,
                      }}>
                        {/* Header — click to expand */}
                        <div onClick={() => setExpandedCatalog(isExp ? null : skill.id)} style={{
                          display: "flex", alignItems: "center", gap: "10px", padding: "10px 12px", cursor: "pointer",
                        }}>
                          {isExp ? <ChevronDown size={14} color="var(--tc-text-muted)" /> : <ChevronRight size={14} color="var(--tc-text-muted)" />}
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                              <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{skill.name}</span>
                              <span style={{ fontSize: "8px", fontWeight: 700, padding: "1px 5px", borderRadius: "3px", background: `${ti.color}15`, color: ti.color, textTransform: "uppercase" }}>{ti.label}</span>
                              {skill.api_key_required && <Key size={10} color="var(--tc-amber)" />}
                            </div>
                          </div>
                        </div>
                        {/* Expanded detail */}
                        {isExp && (
                          <div style={{ padding: "0 12px 12px", borderTop: "1px solid var(--tc-border)" }}>
                            <p style={{ fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: "1.6", margin: "10px 0" }}>
                              {skill.description}
                            </p>
                            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "10px", fontSize: "9px", color: "var(--tc-text-muted)" }}>
                              {skill.version && <span>v{skill.version}</span>}
                              {skill.author && <span>{skill.author}</span>}
                              {skill.execution?.mode && <span>{skill.execution.mode === "ephemeral" ? "Docker" : skill.execution.mode === "persistent" ? "Sync continue" : "API"}</span>}
                              {skill.execution?.docker_image && <span style={{ fontFamily: "monospace", color: "var(--tc-blue)" }}>{skill.execution.docker_image}</span>}
                            </div>
                            {notReady ? (
                              <span style={{ fontSize: "10px", color: "var(--tc-text-faint)", fontStyle: "italic" }}>Bientot disponible</span>
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
            );
          })}
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
                <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "8px" }}>
                  {installMsg}
                </div>
                <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>
                  {installing.name}
                </div>
              </>
            ) : (
              <>
                <div style={{ marginBottom: "12px" }}>
                  <CheckCircle2 size={36} color="var(--tc-green)" />
                </div>
                <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "8px" }}>
                  {installMsg}
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* ═══ MODAL ═══ */}
      {modalSkill && (
        <div style={{ position: "fixed", inset: 0, zIndex: 1000, background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)",
          display: "flex", alignItems: "center", justifyContent: "center" }} onClick={() => setModalSkill(null)}>
          <div onClick={e => e.stopPropagation()} style={{ width: "100%", maxWidth: "500px", maxHeight: "80vh", overflow: "auto",
            background: "var(--tc-bg)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-card)", padding: "24px",
            boxShadow: "0 20px 60px rgba(0,0,0,0.4)" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
              <div>
                <h2 style={{ fontSize: "16px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>{modalSkill.name}</h2>
                <span style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>{modalSkill.version} · {modalSkill.author || "ThreatClaw"}</span>
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
                          {field.default ? "Actif" : "Inactif"} par defaut
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
            {runResult && (
              <div style={{ marginBottom: "16px", padding: "10px", borderRadius: "var(--tc-radius-sm)", background: "var(--tc-surface-alt)",
                border: "1px solid var(--tc-border)", fontSize: "10px", fontFamily: "monospace", color: "var(--tc-text-sec)", maxHeight: "120px", overflow: "auto" }}>
                <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(runResult, null, 2)}</pre>
              </div>
            )}
            <div style={{ display: "flex", gap: "8px", justifyContent: "space-between", paddingTop: "12px", borderTop: "1px solid var(--tc-border)" }}>
              <button onClick={() => uninstall(modalSkill.id)} style={{ display: "flex", alignItems: "center", gap: "5px",
                padding: "8px 14px", borderRadius: "var(--tc-radius-btn)", background: "var(--tc-red-soft)", border: "1px solid var(--tc-red-border)",
                color: "var(--tc-red)", fontSize: "11px", fontWeight: 600, cursor: "pointer" }}><Trash2 size={12} /> Desinstaller</button>
              <div style={{ display: "flex", gap: "8px" }}>
                {RUNNABLE[modalSkill.id] && (
                  <button className="tc-btn-embossed" onClick={() => handleRun(modalSkill)} disabled={running === modalSkill.id}
                    style={{ fontSize: "11px", padding: "8px 14px" }}>
                    <Play size={12} /> {running === modalSkill.id ? "..." : modalSkill.type === "connector" ? "Sync" : "Lancer"}
                  </button>
                )}
                <button className="tc-btn-embossed" onClick={() => setModalSkill(null)} style={{ fontSize: "11px", padding: "8px 14px" }}>Fermer</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

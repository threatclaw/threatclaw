"use client";

import React, { useState, useEffect } from "react";
import { ChromeInsetCard, ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  CheckCircle2, Search, Settings, Save, X, Loader2, Key, Wifi, XCircle,
  Shield, Scan, BarChart3, FileText, Server, Eye, Play, ChevronDown, ChevronRight,
} from "lucide-react";

interface Skill {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  trust: string;
  category: string;
  runtime: string;
  installed: boolean;
  api_key_required?: boolean;
  requires_network?: boolean;
  secrets?: string[];
  config_fields?: { key: string; label: string; type: string; default?: string; placeholder?: string; options?: string[] }[];
}

interface SkillConfig {
  skill_id: string;
  config: { key: string; value: string }[];
}

// ── Categories with icons ──
const CATEGORIES = [
  { id: "scanning", label: "Scanning & Reconnaissance", icon: Scan, color: "#d03020" },
  { id: "monitoring", label: "Monitoring & Threat Intel", icon: Eye, color: "#3080d0" },
  { id: "compliance", label: "Conformité & Audit", icon: Shield, color: "#30a050" },
  { id: "infrastructure", label: "Infrastructure & Cloud", icon: Server, color: "#d09020" },
  { id: "rapports", label: "Rapports", icon: FileText, color: "#a040d0" },
];

// ── Config fields per skill (merge with config_fields from skill.json) ──
const SKILL_CONFIG_FIELDS: Record<string, { key: string; label: string; placeholder: string; secret?: boolean; type?: string; options?: string[] }[]> = {
  "skill-abuseipdb": [{ key: "api_key", label: "AbuseIPDB API Key", placeholder: "Clé depuis abuseipdb.com/account/api", secret: true }],
  "skill-shodan": [{ key: "api_key", label: "Shodan API Key", placeholder: "Clé depuis account.shodan.io", secret: true }],
  "skill-virustotal": [{ key: "api_key", label: "VirusTotal API Key", placeholder: "Clé depuis virustotal.com/gui/my-apikey", secret: true }],
  "skill-cti-crowdsec": [{ key: "api_key", label: "CrowdSec CTI Key", placeholder: "Clé depuis app.crowdsec.net", secret: true }],
  "skill-darkweb-monitor": [
    { key: "api_key", label: "HIBP API Key", placeholder: "Clé depuis haveibeenpwned.com/API/Key", secret: true },
    { key: "emails", label: "Emails à surveiller", placeholder: "admin@example.com, ceo@example.com" },
  ],
  "skill-wazuh": [
    { key: "url", label: "URL Wazuh API", placeholder: "https://wazuh.local:55000" },
    { key: "username", label: "Utilisateur API", placeholder: "wazuh-wui" },
    { key: "password", label: "Mot de passe", placeholder: "Mot de passe Wazuh API", secret: true },
  ],
  "skill-email-audit": [{ key: "domains", label: "Domaines à auditer", placeholder: "example.com, corp.fr" }],
  "skill-report-gen": [
    { key: "company_name", label: "Nom de l'entreprise", placeholder: "Acme Corp" },
    { key: "language", label: "Langue du rapport", placeholder: "fr" },
  ],
  "skill-vuln-scan": [
    { key: "targets", label: "Cibles réseau", placeholder: "192.168.1.0/24" },
    { key: "severity_filter", label: "Sévérité minimum", placeholder: "medium", type: "select", options: ["critical", "high", "medium", "low"] },
    { key: "templates", label: "Templates Nuclei", placeholder: "default", type: "select", options: ["default", "custom", "all"] },
  ],
  "skill-secrets-audit": [
    { key: "scan_path", label: "Chemin à scanner", placeholder: "/app/data" },
  ],
  "skill-cloud-posture": [
    { key: "provider", label: "Cloud Provider", placeholder: "aws", type: "select", options: ["aws", "azure", "gcp", "all"] },
    { key: "aws_profile", label: "AWS Profile", placeholder: "default" },
    { key: "azure_tenant", label: "Azure Tenant ID", placeholder: "" },
    { key: "gcp_project", label: "GCP Project", placeholder: "" },
  ],
};

const inputStyle: React.CSSProperties = {
  width: "100%", border: "1px solid rgba(255,255,255,0.06)", borderRadius: "10px",
  padding: "10px 14px", fontSize: "13px", color: "#e8e4e0", fontFamily: "inherit",
  background: "rgba(255,255,255,0.04)", outline: "none",
  boxShadow: "inset 0 2px 4px rgba(0,0,0,0.3)",
};

const labelStyle: React.CSSProperties = {
  fontSize: "11px", fontWeight: 600, color: "#5a534e",
  textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "6px",
};

export default function SkillsPage() {
  const [skills, setSkills] = useState<Skill[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [configOpen, setConfigOpen] = useState<string | null>(null);
  const [configData, setConfigData] = useState<Record<string, string>>({});
  const [configSaving, setConfigSaving] = useState(false);
  const [configSaved, setConfigSaved] = useState(false);
  const [expandedCats, setExpandedCats] = useState<Set<string>>(new Set(CATEGORIES.map(c => c.id)));

  useEffect(() => {
    fetch("/api/tc/skills/catalog")
      .then(r => r.json())
      .then(d => { setSkills(d.skills || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const loadSkillConfig = async (skillId: string) => {
    try {
      const res = await fetch(`/api/tc/config/${skillId}`);
      const data: SkillConfig = await res.json();
      const configMap: Record<string, string> = {};
      (data.config || []).forEach(c => { configMap[c.key] = c.value; });
      setConfigData(configMap);
    } catch {
      setConfigData({});
    }
    setConfigOpen(configOpen === skillId ? null : skillId);
    setConfigSaved(false);
  };

  const saveSkillConfig = async (skillId: string) => {
    setConfigSaving(true);
    const fields = getConfigFields(skillId);
    try {
      for (const field of fields) {
        const value = configData[field.key] || "";
        if (value) {
          await fetch(`/api/tc/config/${skillId}`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ key: field.key, value }),
          });
        }
      }
      setConfigSaved(true);
      setTimeout(() => setConfigSaved(false), 3000);
    } catch { /* */ }
    setConfigSaving(false);
  };

  const getConfigFields = (skillId: string) => {
    // Use hardcoded fields first, fall back to skill.json config_fields
    if (SKILL_CONFIG_FIELDS[skillId]) return SKILL_CONFIG_FIELDS[skillId];
    const skill = skills.find(s => s.id === skillId);
    if (skill?.config_fields) {
      return skill.config_fields.map(f => ({
        key: f.key, label: f.label, placeholder: f.placeholder || f.default || "",
        secret: false, type: f.type, options: f.options,
      }));
    }
    return [];
  };

  const filtered = search
    ? skills.filter(s => s.name?.toLowerCase().includes(search.toLowerCase()) || s.description?.toLowerCase().includes(search.toLowerCase()) || s.category?.toLowerCase().includes(search.toLowerCase()))
    : skills;

  const toggleCat = (catId: string) => {
    setExpandedCats(p => {
      const next = new Set(p);
      next.has(catId) ? next.delete(catId) : next.add(catId);
      return next;
    });
  };

  if (loading) return (
    <ChromeInsetCard>
      <div style={{ textAlign: "center", padding: "32px" }}>
        <Loader2 size={20} className="animate-spin" style={{ margin: "0 auto 12px", color: "#d03020" }} />
        <div style={{ fontSize: "13px", color: "#5a534e" }}>Chargement des skills...</div>
      </div>
    </ChromeInsetCard>
  );

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: "24px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 800, color: "#e8e4e0", letterSpacing: "-0.02em", margin: 0 }}>Skills</h1>
        <p style={{ fontSize: "13px", color: "#5a534e", margin: "4px 0 0" }}>
          {skills.length} skills disponibles — {skills.filter(s => s.installed).length} installées
        </p>
      </div>

      {/* Search */}
      <ChromeInsetCard style={{ marginBottom: "20px", padding: "12px 16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <Search size={16} color="#5a534e" />
          <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder="Rechercher par nom, description ou catégorie..."
            style={{ ...inputStyle, border: "none", boxShadow: "none", padding: 0, background: "transparent", fontSize: "14px" }} />
          {search && (
            <button onClick={() => setSearch("")} style={{ background: "none", border: "none", cursor: "pointer", padding: "2px" }}>
              <X size={14} color="#5a534e" />
            </button>
          )}
        </div>
      </ChromeInsetCard>

      {/* Skills by category */}
      {CATEGORIES.map(cat => {
        const catSkills = filtered.filter(s => s.category === cat.id);
        if (catSkills.length === 0) return null;
        const CatIcon = cat.icon;
        const isExpanded = expandedCats.has(cat.id);
        const installedCount = catSkills.filter(s => s.installed).length;

        return (
          <div key={cat.id} style={{ marginBottom: "16px" }}>
            {/* Category header */}
            <button onClick={() => toggleCat(cat.id)} style={{
              display: "flex", alignItems: "center", gap: "10px", width: "100%",
              background: "none", border: "none", cursor: "pointer", padding: "8px 0",
              fontFamily: "inherit", textAlign: "left", color: "inherit",
            }}>
              <CatIcon size={16} color={cat.color} />
              <span style={{ fontSize: "13px", fontWeight: 700, color: "#e8e4e0", flex: 1 }}>
                {cat.label}
              </span>
              <span style={{ fontSize: "11px", color: "#5a534e" }}>
                {installedCount}/{catSkills.length} actives
              </span>
              {isExpanded ? <ChevronDown size={14} color="#5a534e" /> : <ChevronRight size={14} color="#5a534e" />}
            </button>

            {/* Skills in category */}
            {isExpanded && (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px", paddingLeft: "0" }}>
                {catSkills.map(skill => (
                  <React.Fragment key={skill.id}>
                    <SkillCard
                      skill={skill}
                      isConfigOpen={configOpen === skill.id}
                      hasConfig={getConfigFields(skill.id).length > 0}
                      onToggleConfig={() => loadSkillConfig(skill.id)}
                      catColor={cat.color}
                    />
                    {configOpen === skill.id && (
                      <SkillConfigPanel
                        skillId={skill.id}
                        skillName={skill.name}
                        fields={getConfigFields(skill.id)}
                        configData={configData}
                        setConfigData={setConfigData}
                        onSave={() => saveSkillConfig(skill.id)}
                        onClose={() => setConfigOpen(null)}
                        saving={configSaving}
                        saved={configSaved}
                      />
                    )}
                  </React.Fragment>
                ))}
              </div>
            )}
          </div>
        );
      })}

      {/* Uncategorized skills */}
      {filtered.filter(s => !CATEGORIES.some(c => c.id === s.category)).length > 0 && (
        <div style={{ marginBottom: "16px" }}>
          <div style={{ fontSize: "13px", fontWeight: 700, color: "#e8e4e0", padding: "8px 0", display: "flex", alignItems: "center", gap: "10px" }}>
            <BarChart3 size={16} color="#5a534e" /> Autres
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {filtered.filter(s => !CATEGORIES.some(c => c.id === s.category)).map(skill => (
              <React.Fragment key={skill.id}>
                <SkillCard skill={skill} isConfigOpen={configOpen === skill.id} hasConfig={getConfigFields(skill.id).length > 0}
                  onToggleConfig={() => loadSkillConfig(skill.id)} catColor="#5a534e" />
                {configOpen === skill.id && (
                  <SkillConfigPanel skillId={skill.id} skillName={skill.name} fields={getConfigFields(skill.id)}
                    configData={configData} setConfigData={setConfigData} onSave={() => saveSkillConfig(skill.id)}
                    onClose={() => setConfigOpen(null)} saving={configSaving} saved={configSaved} />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════
// SKILL CARD
// ═══════════════════════════════════════

function SkillCard({ skill, isConfigOpen, hasConfig, onToggleConfig, catColor }: {
  skill: Skill; isConfigOpen: boolean; hasConfig: boolean; onToggleConfig: () => void; catColor: string;
}) {
  const needsApiKey = skill.api_key_required || (SKILL_CONFIG_FIELDS[skill.id] || []).some(f => f.secret);

  return (
    <ChromeInsetCard style={{
      borderLeft: `3px solid ${skill.installed ? catColor : "rgba(255,255,255,0.04)"}`,
      borderRadius: "12px",
      padding: "16px",
    }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: "14px" }}>
        {/* Status indicator */}
        <div style={{
          width: "36px", height: "36px", borderRadius: "10px", flexShrink: 0,
          background: skill.installed ? `${catColor}12` : "rgba(255,255,255,0.02)",
          border: `1px solid ${skill.installed ? `${catColor}30` : "rgba(255,255,255,0.04)"}`,
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          {skill.installed ? <CheckCircle2 size={16} color={catColor} /> : <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#3a3a3a" }} />}
        </div>

        {/* Info */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap", marginBottom: "4px" }}>
            <span style={{ fontSize: "14px", fontWeight: 700, color: "#e8e4e0" }}>{skill.name || skill.id}</span>
            <span style={{ fontSize: "10px", color: "#5a534e", fontFamily: "monospace" }}>v{skill.version || "1.0.0"}</span>
            {skill.runtime && (
              <span style={{
                fontSize: "9px", fontWeight: 600, padding: "2px 6px", borderRadius: "4px",
                background: skill.runtime === "wasm" ? "rgba(48,128,208,0.08)" : "rgba(208,144,32,0.08)",
                color: skill.runtime === "wasm" ? "#3080d0" : "#d09020",
                border: `1px solid ${skill.runtime === "wasm" ? "rgba(48,128,208,0.15)" : "rgba(208,144,32,0.15)"}`,
              }}>
                {skill.runtime === "wasm" ? "WASM" : "Docker"}
              </span>
            )}
            {needsApiKey && (
              <span style={{ fontSize: "9px", color: "#d09020", display: "flex", alignItems: "center", gap: "3px" }}>
                <Key size={10} /> API Key
              </span>
            )}
          </div>
          <div style={{ fontSize: "12px", color: "#7a7470", lineHeight: 1.4 }}>{skill.description}</div>
        </div>

        {/* Actions */}
        <div style={{ display: "flex", gap: "6px", flexShrink: 0 }}>
          {skill.installed && hasConfig && (
            <ChromeButton onClick={onToggleConfig} variant={isConfigOpen ? "danger" : "glass"}>
              {isConfigOpen ? <X size={14} /> : <Settings size={14} />}
              {isConfigOpen ? "Fermer" : "Configurer"}
            </ChromeButton>
          )}
          {skill.installed && !hasConfig && (
            <span style={{ fontSize: "11px", color: "#30a050", display: "flex", alignItems: "center", gap: "4px", padding: "6px 10px" }}>
              <CheckCircle2 size={14} /> Actif
            </span>
          )}
          {!skill.installed && (
            <span style={{
              fontSize: "11px", color: "#5a534e", padding: "6px 12px", borderRadius: "8px",
              background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.04)",
            }}>
              Non installé
            </span>
          )}
        </div>
      </div>
    </ChromeInsetCard>
  );
}

// ═══════════════════════════════════════
// SKILL CONFIG PANEL
// ═══════════════════════════════════════

function SkillConfigPanel({ skillId, skillName, fields, configData, setConfigData, onSave, onClose, saving, saved }: {
  skillId: string; skillName: string;
  fields: { key: string; label: string; placeholder: string; secret?: boolean; type?: string; options?: string[] }[];
  configData: Record<string, string>;
  setConfigData: React.Dispatch<React.SetStateAction<Record<string, string>>>;
  onSave: () => void; onClose: () => void;
  saving: boolean; saved: boolean;
}) {
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; detail?: string; error?: string } | null>(null);

  const testSkill = async () => {
    // Save first, then test
    setTesting(true);
    setTestResult(null);
    try {
      // Save config before testing
      for (const field of fields) {
        const value = configData[field.key] || "";
        if (value) {
          await fetch(`/api/tc/config/${skillId}`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ key: field.key, value }),
          });
        }
      }
      // Now test
      const res = await fetch(`/api/tc/skills/${skillId}/test`, { method: "POST" });
      const data = await res.json();
      setTestResult(data);
    } catch {
      setTestResult({ ok: false, error: "Impossible de contacter le backend" });
    }
    setTesting(false);
  };

  if (fields.length === 0) {
    return (
      <ChromeInsetCard style={{ borderLeft: "3px solid rgba(48,160,80,0.3)", padding: "14px 16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <CheckCircle2 size={14} color="#30a050" />
          <span style={{ fontSize: "12px", color: "#30a050" }}>Analyse locale — aucune configuration requise</span>
        </div>
      </ChromeInsetCard>
    );
  }

  return (
    <ChromeInsetCard style={{ borderLeft: "3px solid rgba(208,48,32,0.3)", padding: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
        <div style={{ fontSize: "14px", fontWeight: 700, color: "#e8e4e0" }}>
          Configuration — {skillName}
        </div>
        <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", padding: "4px" }}>
          <X size={16} color="#5a534e" />
        </button>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
        {fields.map(field => (
          <div key={field.key}>
            <div style={labelStyle}>{field.label}</div>
            {field.type === "select" && field.options ? (
              <select style={inputStyle} value={configData[field.key] || ""} onChange={e => setConfigData(p => ({ ...p, [field.key]: e.target.value }))}>
                <option value="">— Sélectionner —</option>
                {field.options.map(o => <option key={o} value={o}>{o}</option>)}
              </select>
            ) : (
              <input
                type={field.secret ? "password" : "text"}
                style={inputStyle}
                value={configData[field.key] || ""}
                onChange={e => setConfigData(p => ({ ...p, [field.key]: e.target.value }))}
                placeholder={field.placeholder}
              />
            )}
          </div>
        ))}
      </div>

      {/* Test result */}
      {testResult && (
        <div style={{
          marginTop: "14px", padding: "12px 14px", borderRadius: "10px", fontSize: "12px",
          background: testResult.ok ? "rgba(48,160,80,0.06)" : "rgba(208,48,32,0.06)",
          border: `1px solid ${testResult.ok ? "rgba(48,160,80,0.15)" : "rgba(208,48,32,0.15)"}`,
          color: testResult.ok ? "#30a050" : "#d03020",
          display: "flex", alignItems: "center", gap: "8px",
        }}>
          {testResult.ok ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
          {testResult.ok ? testResult.detail : testResult.error}
        </div>
      )}

      {/* Actions */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "16px" }}>
        <ChromeButton onClick={testSkill} disabled={testing} variant="glass">
          {testing ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
          {testing ? "Test en cours..." : "Sauvegarder et tester"}
        </ChromeButton>
        <ChromeButton onClick={onSave} disabled={saving} variant="primary">
          {saving ? <Loader2 size={14} className="animate-spin" /> : saved ? <CheckCircle2 size={14} /> : <Save size={14} />}
          {saved ? "Sauvegardé" : "Enregistrer"}
        </ChromeButton>
      </div>
    </ChromeInsetCard>
  );
}

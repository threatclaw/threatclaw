"use client";

import React, { useState, useEffect } from "react";
import { ChromeInsetCard, ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { CheckCircle2, Search, AlertTriangle, Settings, Save, X, Loader2, Key } from "lucide-react";

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
}

interface SkillConfig {
  skill_id: string;
  config: { key: string; value: string }[];
}

const CATEGORY_LABELS: Record<string, string> = {
  scanning: "Scanning", compliance: "Conformité", monitoring: "Monitoring",
  rapports: "Rapports", infrastructure: "Infrastructure", intel: "Threat Intel",
  recon: "Reconnaissance", ops: "Opérationnel",
};

// Known API key fields per skill
const SKILL_CONFIG_FIELDS: Record<string, { key: string; label: string; placeholder: string; secret?: boolean }[]> = {
  "skill-abuseipdb": [{ key: "api_key", label: "AbuseIPDB API Key", placeholder: "Clé depuis abuseipdb.com/account/api", secret: true }],
  "skill-shodan": [{ key: "api_key", label: "Shodan API Key", placeholder: "Clé depuis account.shodan.io", secret: true }],
  "skill-virustotal": [{ key: "api_key", label: "VirusTotal API Key", placeholder: "Clé depuis virustotal.com/gui/my-apikey", secret: true }],
  "skill-cti-crowdsec": [{ key: "api_key", label: "CrowdSec CTI Key", placeholder: "Clé depuis app.crowdsec.net", secret: true }],
  "skill-darkweb-monitor": [
    { key: "api_key", label: "HIBP API Key", placeholder: "Clé depuis haveibeenpwned.com/API/Key", secret: true },
    { key: "emails", label: "Emails à surveiller", placeholder: "admin@example.com, ceo@example.com" },
  ],
  "skill-wazuh": [
    { key: "url", label: "URL Wazuh", placeholder: "https://wazuh.example.com:55000" },
    { key: "username", label: "Utilisateur", placeholder: "wazuh-wui" },
    { key: "password", label: "Mot de passe", placeholder: "Mot de passe Wazuh API", secret: true },
  ],
  "skill-email-audit": [
    { key: "domains", label: "Domaines à auditer", placeholder: "example.com, example.fr" },
  ],
  "skill-compliance-nis2": [],
  "skill-compliance-iso27001": [],
  "skill-report-gen": [
    { key: "company_name", label: "Nom de l'entreprise", placeholder: "Acme Corp" },
    { key: "language", label: "Langue du rapport", placeholder: "fr" },
  ],
};

export default function SkillsPage() {
  const [skills, setSkills] = useState<Skill[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [configOpen, setConfigOpen] = useState<string | null>(null);
  const [configData, setConfigData] = useState<Record<string, string>>({});
  const [configSaving, setConfigSaving] = useState(false);
  const [configSaved, setConfigSaved] = useState(false);

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
    setConfigOpen(skillId);
    setConfigSaved(false);
  };

  const saveSkillConfig = async (skillId: string) => {
    setConfigSaving(true);
    const fields = SKILL_CONFIG_FIELDS[skillId] || [];
    try {
      for (const field of fields) {
        const value = configData[field.key] || "";
        if (value) {
          await fetch(`/api/tc/config/${skillId}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ key: field.key, value }),
          });
        }
      }
      setConfigSaving(false);
      setConfigSaved(true);
      setTimeout(() => setConfigSaved(false), 2000);
    } catch {
      setConfigSaving(false);
    }
  };

  const filtered = search
    ? skills.filter(s => s.name?.toLowerCase().includes(search.toLowerCase()) || s.description?.toLowerCase().includes(search.toLowerCase()))
    : skills;

  const installed = filtered.filter(s => s.installed);
  const available = filtered.filter(s => !s.installed);

  if (loading) return (
    <ChromeInsetCard>
      <div style={{ textAlign: "center", padding: "24px" }}>
        <Loader2 size={16} className="animate-spin" style={{ margin: "0 auto 8px", color: "#907060" }} />
        <ChromeEmbossedText as="div" style={{ fontSize: "11px" }}>Chargement des skills...</ChromeEmbossedText>
      </div>
    </ChromeInsetCard>
  );

  return (
    <div>
      {/* Search */}
      <ChromeInsetCard className="mb-4">
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <Search size={14} color="#907060" />
          <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder="Rechercher un skill..."
            style={{ flex: 1, border: "none", background: "transparent", outline: "none", fontSize: "11px", color: "var(--text-primary)", fontFamily: "Inter, sans-serif" }} />
          <ChromeEmbossedText as="span" style={{ fontSize: "9px", opacity: 0.4 }}>{skills.length} skills</ChromeEmbossedText>
        </div>
      </ChromeInsetCard>

      {/* Installed */}
      {installed.length > 0 && (
        <>
          <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "8px", opacity: 0.5 }}>
            Installés ({installed.length})
          </ChromeEmbossedText>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginBottom: "20px" }}>
            {installed.map(skill => (
              <React.Fragment key={skill.id}>
                <SkillRow skill={skill} onConfigure={() => loadSkillConfig(skill.id)} />
                {configOpen === skill.id && (
                  <SkillConfigPanel
                    skillId={skill.id}
                    fields={SKILL_CONFIG_FIELDS[skill.id] || []}
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
        </>
      )}

      {/* Available */}
      {available.length > 0 && (
        <>
          <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "8px", opacity: 0.5 }}>
            Disponibles ({available.length})
          </ChromeEmbossedText>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {available.map(skill => (
              <SkillRow key={skill.id} skill={skill} />
            ))}
          </div>
        </>
      )}

      {skills.length === 0 && (
        <ChromeInsetCard>
          <div style={{ textAlign: "center", padding: "24px" }}>
            <ChromeEmbossedText as="div" style={{ fontSize: "12px", fontWeight: 700 }}>Aucun skill trouvé</ChromeEmbossedText>
            <ChromeEmbossedText as="div" style={{ fontSize: "9px", opacity: 0.5, marginTop: "4px" }}>
              Vérifiez que le core ThreatClaw est démarré et que les skills WASM sont dans ~/.threatclaw/tools/
            </ChromeEmbossedText>
          </div>
        </ChromeInsetCard>
      )}
    </div>
  );
}

function SkillRow({ skill, onConfigure }: { skill: Skill; onConfigure?: () => void }) {
  const hasConfig = SKILL_CONFIG_FIELDS[skill.id] && SKILL_CONFIG_FIELDS[skill.id].length > 0;
  const needsApiKey = skill.api_key_required || (SKILL_CONFIG_FIELDS[skill.id] || []).some(f => f.secret);

  return (
    <ChromeInsetCard>
      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "3px", flexWrap: "wrap" }}>
            <ChromeEmbossedText as="span" style={{ fontSize: "12px", fontWeight: 700 }}>
              {skill.name || skill.id}
            </ChromeEmbossedText>
            <ChromeEmbossedText as="span" style={{ fontSize: "8px", opacity: 0.35, fontFamily: "monospace" }}>
              v{skill.version || "1.0.0"}
            </ChromeEmbossedText>
            {skill.installed && <CheckCircle2 size={12} color="#2d6a40" />}
            {skill.runtime === "wasm" && (
              <ChromeEmbossedText as="span" style={{ fontSize: "7px", fontWeight: 700, color: "#5a6a8a", background: "rgba(90,106,138,0.1)", padding: "1px 4px", borderRadius: "3px" }}>
                WASM
              </ChromeEmbossedText>
            )}
            {needsApiKey && (
              <ChromeEmbossedText as="span" style={{ fontSize: "7px", color: "#906020", display: "flex", alignItems: "center", gap: "2px" }}>
                <Key size={8} /> Clé API
              </ChromeEmbossedText>
            )}
          </div>
          <ChromeEmbossedText as="div" style={{ fontSize: "9px", opacity: 0.5, lineHeight: 1.3 }}>
            {skill.description}
          </ChromeEmbossedText>
          <div style={{ display: "flex", gap: "6px", marginTop: "4px", alignItems: "center" }}>
            {skill.category && (
              <ChromeEmbossedText as="span" style={{ fontSize: "7px", fontWeight: 700, textTransform: "uppercase", opacity: 0.35, background: "rgba(0,0,0,0.04)", padding: "1px 4px", borderRadius: "3px" }}>
                {CATEGORY_LABELS[skill.category] || skill.category}
              </ChromeEmbossedText>
            )}
            <ChromeEmbossedText as="span" style={{ fontSize: "7px", opacity: 0.3 }}>
              {skill.trust === "official" ? "Officiel" : skill.trust === "verified" ? "Vérifié" : "Communauté"}
            </ChromeEmbossedText>
          </div>
        </div>
        <div>
          {skill.installed && hasConfig && onConfigure ? (
            <ChromeButton onClick={onConfigure}>
              <span style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "9px" }}>
                <Settings size={10} /> Configurer
              </span>
            </ChromeButton>
          ) : skill.installed ? (
            <ChromeEmbossedText as="span" style={{ fontSize: "8px", color: "#2d6a40", display: "flex", alignItems: "center", gap: "3px" }}>
              <CheckCircle2 size={10} /> Actif
            </ChromeEmbossedText>
          ) : (
            <ChromeEmbossedText as="span" style={{ fontSize: "8px", opacity: 0.4 }}>
              CLI: threatclaw skill install {skill.id}
            </ChromeEmbossedText>
          )}
        </div>
      </div>
    </ChromeInsetCard>
  );
}

function SkillConfigPanel({ skillId, fields, configData, setConfigData, onSave, onClose, saving, saved }: {
  skillId: string;
  fields: { key: string; label: string; placeholder: string; secret?: boolean }[];
  configData: Record<string, string>;
  setConfigData: React.Dispatch<React.SetStateAction<Record<string, string>>>;
  onSave: () => void;
  onClose: () => void;
  saving: boolean;
  saved: boolean;
}) {
  const inputStyle: React.CSSProperties = {
    width: "100%", border: "none", borderRadius: "6px", padding: "8px 10px",
    fontSize: "11px", color: "var(--text-primary)", fontFamily: "Inter, sans-serif",
    background: "var(--bg-pit)", outline: "none",
    boxShadow: "inset 0 2px 4px rgba(60,30,15,0.15), inset 0 1px 2px rgba(60,30,15,0.1)",
  };

  if (fields.length === 0) {
    return (
      <ChromeInsetCard>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <ChromeEmbossedText as="span" style={{ fontSize: "9px", opacity: 0.5 }}>
            Ce skill ne nécessite aucune configuration.
          </ChromeEmbossedText>
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", padding: "2px" }}>
            <X size={12} color="#907060" />
          </button>
        </div>
      </ChromeInsetCard>
    );
  }

  return (
    <ChromeInsetCard>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
        <ChromeEmbossedText as="span" style={{ fontSize: "10px", fontWeight: 700 }}>
          Configuration — {skillId}
        </ChromeEmbossedText>
        <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", padding: "2px" }}>
          <X size={12} color="#907060" />
        </button>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {fields.map(field => (
          <div key={field.key}>
            <ChromeEmbossedText as="div" style={{ fontSize: "9px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px", opacity: 0.5 }}>
              {field.label}
            </ChromeEmbossedText>
            <input
              type={field.secret ? "password" : "text"}
              style={inputStyle}
              value={configData[field.key] || ""}
              onChange={e => setConfigData(p => ({ ...p, [field.key]: e.target.value }))}
              placeholder={field.placeholder}
            />
          </div>
        ))}
      </div>

      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "12px" }}>
        <ChromeButton onClick={onSave} disabled={saving}>
          <span style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "9px" }}>
            {saving ? <><Loader2 size={10} className="animate-spin" /> Sauvegarde...</>
              : saved ? <><CheckCircle2 size={10} color="#2d6a40" /> Sauvegardé</>
              : <><Save size={10} /> Enregistrer</>}
          </span>
        </ChromeButton>
      </div>
    </ChromeInsetCard>
  );
}

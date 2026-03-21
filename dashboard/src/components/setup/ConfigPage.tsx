"use client";

import React, { useState, useEffect } from "react";
import {
  Cpu, MessageSquare, ShieldAlert, Calendar, ChevronDown, ChevronRight,
  Check, Save, RotateCcw, Wifi, Loader2, CheckCircle2, Eye, Bell,
  ShieldCheck, Zap, AlertTriangle, Globe,
} from "lucide-react";
import { ChromeInsetCard, ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";

const PERM_LEVELS = [
  { id: "READ_ONLY", icon: Eye, label: "Observation", desc: "Observation uniquement", color: "#5a6a8a" },
  { id: "ALERT_ONLY", icon: Bell, label: "Alertes", desc: "Alertes sans action corrective", color: "#5a7a4a", recommended: true },
  { id: "REMEDIATE_WITH_APPROVAL", icon: ShieldCheck, label: "Remédiation supervisée", desc: "Avec approbation humaine", color: "#906020" },
  { id: "FULL_AUTO", icon: Zap, label: "Automatisation complète", desc: "Environnement maîtrisé uniquement", color: "#903020", warning: true },
];

interface ConfigPageProps { onResetWizard: () => void; }

export default function ConfigPage({ onResetWizard }: ConfigPageProps) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const [llm, setLlm] = useState({ backend: "ollama", url: "http://localhost:11434", model: "", apiKey: "", connected: false, testing: false, models: [] as string[] });
  const [channels, setChannels] = useState<Record<string, { enabled: boolean; [k: string]: string | boolean }>>({
    slack: { enabled: false, botToken: "", signingSecret: "" },
    telegram: { enabled: false, botToken: "", botUsername: "" },
    discord: { enabled: false, botToken: "", publicKey: "" },
    whatsapp: { enabled: false, accessToken: "", phoneNumberId: "" },
    signal: { enabled: false, httpUrl: "http://localhost:8080", account: "" },
    email: { enabled: false, host: "", port: "587", from: "", to: "" },
  });
  const [permLevel, setPermLevel] = useState("ALERT_ONLY");
  const [schedules, setSchedules] = useState<Record<string, { enabled: boolean; label: string; default: string; cron: string }>>({
    vuln_scan: { enabled: true, label: "Scan vulnérabilités", default: "Tous les jours à 2h", cron: "0 2 * * *" },
    log_analysis: { enabled: true, label: "Analyse logs SOC", default: "Toutes les 5 min", cron: "*/5 * * * *" },
    darkweb: { enabled: true, label: "Surveillance dark web", default: "Toutes les 6h", cron: "0 */6 * * *" },
    cloud_posture: { enabled: true, label: "Audit cloud", default: "Lundi 3h", cron: "0 3 * * 1" },
    phishing: { enabled: false, label: "Campagne phishing", default: "1er du mois", cron: "0 9 1 * *" },
    report: { enabled: true, label: "Rapport hebdomadaire", default: "Vendredi 8h", cron: "0 8 * * 5" },
  });
  const [general, setGeneral] = useState({ instanceName: "threatclaw-dev", language: "fr" });

  // Load config from backend on mount
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch("/api/tc/config");
        const cfg = await res.json();
        if (cfg.llm) setLlm(p => ({ ...p, ...cfg.llm }));
        if (cfg.channels) setChannels(p => {
          const merged = { ...p };
          Object.keys(cfg.channels).forEach(k => {
            if (merged[k]) merged[k] = { ...merged[k], ...cfg.channels[k] };
          });
          return merged;
        });
        if (cfg.permissions) setPermLevel(cfg.permissions);
        if (cfg.general) setGeneral(p => ({ ...p, ...cfg.general }));
      } catch {
        // Fallback to localStorage
        try {
          const raw = localStorage.getItem("threatclaw_config");
          if (raw) {
            const cfg = JSON.parse(raw);
            if (cfg.llm) setLlm(p => ({ ...p, ...cfg.llm }));
            if (cfg.channels) setChannels(p => {
              const merged = { ...p };
              Object.keys(cfg.channels).forEach(k => {
                if (merged[k]) merged[k] = { ...merged[k], ...cfg.channels[k] };
              });
              return merged;
            });
            if (cfg.permLevel) setPermLevel(cfg.permLevel);
            if (cfg.general) setGeneral(p => ({ ...p, ...cfg.general }));
          }
        } catch { /* */ }
      }
    })();
  }, []);

  const handleSave = async () => {
    const config = {
      llm: { backend: llm.backend, url: llm.url, model: llm.model, apiKey: llm.apiKey },
      channels,
      permissions: permLevel,
      general,
    };
    try {
      const res = await fetch("/api/tc/config", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(config) });
      const data = await res.json();
      if (data.status === "saved") {
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
      }
    } catch {
      // Fallback localStorage
      localStorage.setItem("threatclaw_config", JSON.stringify(config));
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    }
  };

  const testOllama = async () => {
    setLlm(p => ({ ...p, testing: true, connected: false, models: [] }));
    try {
      const res = await fetch(`/api/ollama?url=${encodeURIComponent(llm.url)}`);
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      const models = (data.models || []).map((m: { name: string }) => m.name);
      setLlm(p => ({ ...p, testing: false, connected: true, models, model: p.model || models[0] || "" }));
    } catch { setLlm(p => ({ ...p, testing: false, connected: false })); }
  };

  const toggle = (id: string) => setExpanded(expanded === id ? null : id);

  const inputStyle: React.CSSProperties = {
    width: "100%", border: "none", borderRadius: "6px", padding: "8px 10px",
    fontSize: "11px", color: "#4a3028", fontFamily: "Inter, sans-serif",
    background: "#e2dbd4", outline: "none",
    boxShadow: "inset 0 2px 4px rgba(60,30,15,0.15), inset 0 1px 2px rgba(60,30,15,0.1)",
  };

  const sections = [
    { id: "general", label: "Général", icon: Globe, summary: `${general.instanceName} · ${general.language === "fr" ? "Français" : "English"}` },
    { id: "llm", label: "IA Principale", icon: Cpu, summary: `${llm.backend} · ${llm.model || "non configuré"}` },
    { id: "communication", label: "Communication", icon: MessageSquare, summary: `${Object.values(channels).filter(c => c.enabled).length} canal(aux) actif(s)` },
    { id: "security", label: "Niveau de sécurité", icon: ShieldAlert, summary: PERM_LEVELS.find(l => l.id === permLevel)?.label || permLevel },
    // Planning retiré — sera configurable par skill
  ];

  const channelDefs = [
    { key: "slack", label: "Slack", fields: [{ id: "botToken", label: "Bot Token (xoxb-...)" }, { id: "signingSecret", label: "Signing Secret" }] },
    { key: "telegram", label: "Telegram", fields: [{ id: "botToken", label: "Bot Token" }, { id: "botUsername", label: "Nom du bot" }] },
    { key: "discord", label: "Discord", fields: [{ id: "botToken", label: "Bot Token" }, { id: "publicKey", label: "Public Key (hex)" }] },
    { key: "whatsapp", label: "WhatsApp", fields: [{ id: "accessToken", label: "Access Token" }, { id: "phoneNumberId", label: "Phone Number ID" }] },
    { key: "signal", label: "Signal", fields: [{ id: "httpUrl", label: "URL signal-cli" }, { id: "account", label: "Numéro (+33...)" }] },
    { key: "email", label: "Email", fields: [{ id: "host", label: "SMTP" }, { id: "port", label: "Port" }, { id: "from", label: "De" }, { id: "to", label: "À" }] },
  ];

  return (
    <div>
      {/* Sections */}
      <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginBottom: "16px" }}>
        {sections.map(section => {
          const Icon = section.icon;
          const isOpen = expanded === section.id;
          return (
            <ChromeInsetCard key={section.id}>
              <button onClick={() => toggle(section.id)} style={{ display: "flex", width: "100%", alignItems: "center", gap: "10px", background: "none", border: "none", cursor: "pointer", padding: 0 }}>
                <Icon size={15} color="#903020" />
                <div style={{ flex: 1, textAlign: "left" }}>
                  <ChromeEmbossedText as="div" style={{ fontSize: "11px", fontWeight: 700 }}>{section.label}</ChromeEmbossedText>
                  <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.45, marginTop: "1px" }}>{section.summary}</ChromeEmbossedText>
                </div>
                {isOpen ? <ChevronDown size={14} color="#907060" /> : <ChevronRight size={14} color="#907060" />}
              </button>

              {isOpen && (
                <div style={{ marginTop: "12px", borderTop: "1px solid rgba(0,0,0,0.06)", paddingTop: "12px", display: "flex", flexDirection: "column", gap: "8px" }}>

                  {section.id === "general" && (<>
                    <div>
                      <ChromeEmbossedText as="div" style={{ fontSize: "9px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px", opacity: 0.5 }}>Nom de l{"'"}instance</ChromeEmbossedText>
                      <input style={inputStyle} value={general.instanceName} onChange={e => setGeneral(p => ({ ...p, instanceName: e.target.value }))} />
                    </div>
                    <div>
                      <ChromeEmbossedText as="div" style={{ fontSize: "9px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px", opacity: 0.5 }}>Langue</ChromeEmbossedText>
                      <select style={inputStyle} value={general.language} onChange={e => setGeneral(p => ({ ...p, language: e.target.value }))}>
                        <option value="fr">Français</option><option value="en">English</option>
                      </select>
                    </div>
                  </>)}

                  {section.id === "llm" && (<>
                    <div>
                      <ChromeEmbossedText as="div" style={{ fontSize: "9px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px", opacity: 0.5 }}>Backend</ChromeEmbossedText>
                      <select style={inputStyle} value={llm.backend} onChange={e => setLlm(p => ({ ...p, backend: e.target.value, connected: false, models: [] }))}>
                        <option value="ollama">Ollama (local)</option><option value="ollama_remote">Ollama distant</option>
                        <option value="mistral">Mistral AI</option><option value="anthropic">Anthropic</option>
                      </select>
                    </div>
                    {(llm.backend === "ollama" || llm.backend === "ollama_remote") && (<>
                      <div>
                        <ChromeEmbossedText as="div" style={{ fontSize: "9px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px", opacity: 0.5 }}>URL</ChromeEmbossedText>
                        <div style={{ display: "flex", gap: "6px" }}>
                          <input style={{ ...inputStyle, flex: 1 }} value={llm.url} onChange={e => setLlm(p => ({ ...p, url: e.target.value }))} />
                          <ChromeButton onClick={testOllama} disabled={llm.testing}>
                            <span style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "9px" }}>
                              {llm.testing ? <Loader2 size={10} className="animate-spin" /> : llm.connected ? <CheckCircle2 size={10} color="#5a7a4a" /> : <Wifi size={10} />}
                              Tester
                            </span>
                          </ChromeButton>
                        </div>
                      </div>
                      {llm.connected && llm.models.length > 0 && (
                        <div>
                          <ChromeEmbossedText as="div" style={{ fontSize: "9px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px", opacity: 0.5 }}>Modèle</ChromeEmbossedText>
                          <select style={inputStyle} value={llm.model} onChange={e => setLlm(p => ({ ...p, model: e.target.value }))}>
                            {llm.models.map(m => <option key={m} value={m}>{m}</option>)}
                          </select>
                          <ChromeEmbossedText as="div" style={{ fontSize: "9px", color: "#5a7a4a", marginTop: "4px", display: "flex", alignItems: "center", gap: "4px" }}>
                            <CheckCircle2 size={10} /> Connecté — {llm.models.length} modèle(s)
                          </ChromeEmbossedText>
                        </div>
                      )}
                    </>)}
                    {(llm.backend === "mistral" || llm.backend === "anthropic") && (<>
                      <div>
                        <ChromeEmbossedText as="div" style={{ fontSize: "9px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px", opacity: 0.5 }}>Clé API</ChromeEmbossedText>
                        <input style={inputStyle} type="password" value={llm.apiKey} onChange={e => setLlm(p => ({ ...p, apiKey: e.target.value }))} />
                      </div>
                      <div>
                        <ChromeEmbossedText as="div" style={{ fontSize: "9px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px", opacity: 0.5 }}>Modèle</ChromeEmbossedText>
                        <input style={inputStyle} value={llm.model} onChange={e => setLlm(p => ({ ...p, model: e.target.value }))} placeholder={llm.backend === "mistral" ? "mistral-large-latest" : "claude-sonnet-4-20250514"} />
                      </div>
                    </>)}
                  </>)}

                  {section.id === "communication" && (
                    channelDefs.map(ch => (
                      <div key={ch.key}>
                        <button onClick={() => setChannels(p => ({ ...p, [ch.key]: { ...p[ch.key], enabled: !p[ch.key].enabled } }))}
                          style={{ display: "flex", width: "100%", alignItems: "center", gap: "8px", background: "none", border: "none", cursor: "pointer", padding: "4px 0" }}>
                          <div style={{ width: "28px", height: "16px", borderRadius: "8px", background: channels[ch.key].enabled ? "#5a7a4a" : "#c8c0b8", transition: "background 200ms", position: "relative", boxShadow: "inset 0 1px 3px rgba(0,0,0,0.2)" }}>
                            <div style={{ width: "12px", height: "12px", borderRadius: "50%", background: "#f0ebe6", position: "absolute", top: "2px", left: channels[ch.key].enabled ? "14px" : "2px", transition: "left 200ms", boxShadow: "0 1px 2px rgba(0,0,0,0.2)" }} />
                          </div>
                          <ChromeEmbossedText as="span" style={{ fontSize: "10px", fontWeight: 600 }}>{ch.label}</ChromeEmbossedText>
                        </button>
                        {channels[ch.key].enabled && (
                          <div style={{ display: "flex", flexDirection: "column", gap: "4px", marginTop: "4px", paddingLeft: "36px" }}>
                            {ch.fields.map(f => (
                              <div key={f.id}>
                                <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.4, marginBottom: "2px" }}>{f.label}</ChromeEmbossedText>
                                <input style={{ ...inputStyle, fontSize: "10px", padding: "6px 8px" }}
                                  type={f.id.toLowerCase().includes("token") ? "password" : "text"}
                                  value={(channels[ch.key][f.id] as string) || ""}
                                  onChange={e => setChannels(p => ({ ...p, [ch.key]: { ...p[ch.key], [f.id]: e.target.value } }))} />
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))
                  )}

                  {section.id === "security" && (
                    PERM_LEVELS.map(level => {
                      const LIcon = level.icon;
                      const sel = permLevel === level.id;
                      return (
                        <button key={level.id} onClick={() => setPermLevel(level.id)}
                          style={{ display: "flex", alignItems: "center", gap: "8px", background: "none", border: "none", cursor: "pointer", padding: "4px 0", textAlign: "left", opacity: sel ? 1 : 0.6 }}>
                          <LIcon size={14} color={level.color} />
                          <div style={{ flex: 1 }}>
                            <ChromeEmbossedText as="span" style={{ fontSize: "10px", fontWeight: 700 }}>{level.label}</ChromeEmbossedText>
                            {level.recommended && <ChromeEmbossedText as="span" style={{ fontSize: "7px", color: "#5a7a4a", marginLeft: "6px" }}>RECOMMANDÉ</ChromeEmbossedText>}
                            {level.warning && <ChromeEmbossedText as="span" style={{ fontSize: "7px", color: "#903020", marginLeft: "6px", display: "inline-flex", alignItems: "center", gap: "2px" }}><AlertTriangle size={8} />AVANCÉ</ChromeEmbossedText>}
                            <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.4 }}>{level.desc}</ChromeEmbossedText>
                          </div>
                          {sel && <Check size={12} color={level.color} />}
                        </button>
                      );
                    })
                  )}

                  {section.id === "schedule" && (
                    Object.entries(schedules).map(([key, sched]) => (
                      <div key={key}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <button onClick={() => setSchedules(p => ({ ...p, [key]: { ...p[key], enabled: !p[key].enabled } }))}
                            style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
                            <div style={{ width: "28px", height: "16px", borderRadius: "8px", background: sched.enabled ? "#5a7a4a" : "#c8c0b8", transition: "background 200ms", position: "relative", boxShadow: "inset 0 1px 3px rgba(0,0,0,0.2)" }}>
                              <div style={{ width: "12px", height: "12px", borderRadius: "50%", background: "#f0ebe6", position: "absolute", top: "2px", left: sched.enabled ? "14px" : "2px", transition: "left 200ms", boxShadow: "0 1px 2px rgba(0,0,0,0.2)" }} />
                            </div>
                          </button>
                          <div style={{ flex: 1 }}>
                            <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 600 }}>{sched.label}</ChromeEmbossedText>
                            <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.35 }}>{sched.default}</ChromeEmbossedText>
                          </div>
                        </div>
                        {sched.enabled && (
                          <div style={{ marginTop: "4px", paddingLeft: "36px" }}>
                            <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.4, marginBottom: "2px" }}>Cron</ChromeEmbossedText>
                            <input style={{ ...inputStyle, fontSize: "10px", padding: "6px 8px", fontFamily: "monospace" }}
                              value={sched.cron} onChange={e => setSchedules(p => ({ ...p, [key]: { ...p[key], cron: e.target.value } }))} />
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}
            </ChromeInsetCard>
          );
        })}
      </div>

      {/* Actions */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <ChromeButton onClick={onResetWizard}>
          <span style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "9px", opacity: 0.6 }}>
            <RotateCcw size={10} /> Relancer l{"'"}assistant
          </span>
        </ChromeButton>
        <ChromeButton onClick={handleSave}>
          <span style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "10px" }}>
            {saved ? <><CheckCircle2 size={11} color="#5a7a4a" /> Sauvegardé</> : <><Save size={11} /> Enregistrer</>}
          </span>
        </ChromeButton>
      </div>
    </div>
  );
}

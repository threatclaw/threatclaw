"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Cpu, MessageSquare, ShieldAlert, Check, Save, RotateCcw, Wifi, Loader2,
  CheckCircle2, Eye, Bell, ShieldCheck, Zap, AlertTriangle, Globe, Shield,
  Plus, Trash2, Send, Bot, ArrowRight, Database, Key, Radio, Mail,
  Download, Play, XCircle, Cloud,
} from "lucide-react";

// ── Channel SVG icons (no emojis) ──
function SlackIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zm1.271 0a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313z" fill="#E01E5A"/>
      <path d="M8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zm0 1.271a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312z" fill="#36C5F0"/>
      <path d="M18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zm-1.27 0a2.528 2.528 0 0 1-2.522 2.521 2.528 2.528 0 0 1-2.52-2.521V2.522A2.528 2.528 0 0 1 15.165 0a2.528 2.528 0 0 1 2.521 2.522v6.312z" fill="#2EB67D"/>
      <path d="M15.165 18.956a2.528 2.528 0 0 1 2.521 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zm0-1.27a2.527 2.527 0 0 1-2.52-2.522 2.527 2.527 0 0 1 2.52-2.52h6.313A2.528 2.528 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.521h-6.313z" fill="#ECB22E"/>
    </svg>
  );
}

function TelegramIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path d="M12 0C5.374 0 0 5.374 0 12s5.374 12 12 12 12-5.374 12-12S18.626 0 12 0zm5.568 8.16l-1.848 8.712c-.136.612-.504.764-.996.476l-2.76-2.04-1.332 1.284c-.144.144-.268.268-.552.268l.192-2.784 5.1-4.608c.22-.196-.048-.308-.344-.112l-6.3 3.972-2.724-.852c-.588-.18-.6-.588.132-.876l10.62-4.092c.492-.18.924.12.764.876l-.004-.004z" fill="#229ED9"/>
    </svg>
  );
}

function DiscordIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.947 2.418-2.157 2.418z" fill="#5865F2"/>
    </svg>
  );
}
import { ChromeInsetCard, ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";

const PERM_LEVELS = [
  { id: "READ_ONLY", icon: Eye, label: "Observation", desc: "Observation uniquement", color: "#5a6a8a" },
  { id: "ALERT_ONLY", icon: Bell, label: "Alertes", desc: "Alertes sans action corrective", color: "#30a050", recommended: true },
  { id: "REMEDIATE_WITH_APPROVAL", icon: ShieldCheck, label: "Remédiation supervisée", desc: "Avec approbation humaine", color: "#d09020" },
  { id: "FULL_AUTO", icon: Zap, label: "Automatisation complète", desc: "Environnement maîtrisé uniquement", color: "#d03020", warning: true },
];

interface ConfigPageProps { onResetWizard: () => void; }

export default function ConfigPage({ onResetWizard }: ConfigPageProps) {
  const [activeTab, setActiveTab] = useState("general");
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  const [llm, setLlm] = useState({ backend: "ollama", url: "http://ollama:11434", model: "", apiKey: "", connected: false, testing: false, models: [] as string[] });
  const [forensic, setForensic] = useState({ model: "threatclaw-l2", url: "" });
  const [cloud, setCloud] = useState({ enabled: false, backend: "anthropic", model: "", apiKey: "", escalation: "anonymized" });
  const [channels, setChannels] = useState<Record<string, { enabled: boolean; [k: string]: string | boolean }>>({
    slack: { enabled: false, botToken: "", signingSecret: "" },
    telegram: { enabled: false, botToken: "", botUsername: "", chatId: "" },
    discord: { enabled: false, botToken: "", publicKey: "" },
    whatsapp: { enabled: false, accessToken: "", phoneNumberId: "" },
    signal: { enabled: false, httpUrl: "http://localhost:8080", account: "" },
    email: { enabled: false, host: "", port: "587", from: "", to: "" },
  });
  const [permLevel, setPermLevel] = useState("ALERT_ONLY");
  const [general, setGeneral] = useState({ instanceName: "threatclaw-dev", language: "fr", nvdApiKey: "" });

  // Telegram status
  const [telegramStatus, setTelegramStatus] = useState<{ ok: boolean; username?: string; error?: string } | null>(null);
  const [telegramTestMsg, setTelegramTestMsg] = useState("");
  const [telegramSending, setTelegramSending] = useState(false);
  const [telegramSent, setTelegramSent] = useState(false);

  // LLM model details
  const [llmModels, setLlmModels] = useState<{ name: string; size: string }[]>([]);

  // Load config
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch("/api/tc/config");
        const cfg = await res.json();
        if (cfg.llm) setLlm(p => ({ ...p, ...cfg.llm }));
        if (cfg.forensic) setForensic(p => ({ ...p, ...cfg.forensic }));
        if (cfg.cloud) setCloud(p => ({ ...p, enabled: true, ...cfg.cloud }));
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
        try {
          const raw = localStorage.getItem("threatclaw_config");
          if (raw) {
            const cfg = JSON.parse(raw);
            if (cfg.llm) setLlm(p => ({ ...p, ...cfg.llm }));
            if (cfg.forensic) setForensic(p => ({ ...p, ...cfg.forensic }));
            if (cfg.cloud) setCloud(p => ({ ...p, enabled: true, ...cfg.cloud }));
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

  // Check Telegram status when tab switches
  const checkTelegram = useCallback(async () => {
    try {
      const res = await fetch("/api/tc/telegram/status");
      const data = await res.json();
      setTelegramStatus(data);
    } catch {
      setTelegramStatus(null);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "channels") {
      checkTelegram();
    }
  }, [activeTab, checkTelegram]);

  // Load LLM models
  useEffect(() => {
    if (activeTab === "llm") {
      (async () => {
        try {
          const res = await fetch(`/api/ollama?url=${encodeURIComponent(llm.url)}`);
          const data = await res.json();
          if (data.models) {
            setLlmModels(data.models.map((m: { name: string; size: number }) => ({
              name: m.name,
              size: m.size ? `${(m.size / 1e9).toFixed(1)}GB` : "",
            })));
            setLlm(p => ({ ...p, connected: true, models: data.models.map((m: { name: string }) => m.name) }));
          }
        } catch {
          setLlmModels([]);
        }
      })();
    }
  }, [activeTab, llm.url]);

  const handleSave = async () => {
    setSaving(true);
    const config: Record<string, unknown> = {
      llm: { backend: llm.backend, url: llm.url, model: llm.model, apiKey: llm.apiKey },
      forensic: { model: forensic.model, url: forensic.url || llm.url },
      channels,
      permissions: permLevel,
      general,
    };
    if (cloud.enabled && cloud.apiKey) {
      config.cloud = { backend: cloud.backend, model: cloud.model, apiKey: cloud.apiKey, escalation: cloud.escalation };
    }
    try {
      const res = await fetch("/api/tc/config", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(config) });
      const data = await res.json();
      if (data.status === "saved") {
        setSaved(true);
        setTimeout(() => setSaved(false), 2500);
      }
    } catch {
      localStorage.setItem("threatclaw_config", JSON.stringify(config));
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    }
    setSaving(false);
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

  const testChannel = async (channel: string, token: string) => {
    try {
      const res = await fetch("/api/tc/config/test-channel", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel, token }),
      });
      return await res.json();
    } catch { return { ok: false, error: "Connexion échouée" }; }
  };

  const sendTelegramTest = async () => {
    const chatId = channels.telegram.chatId as string;
    if (!chatId || !telegramTestMsg) return;
    setTelegramSending(true);
    try {
      const res = await fetch("/api/tc/telegram/send", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: chatId, text: telegramTestMsg, parse_mode: "Markdown" }),
      });
      const data = await res.json();
      if (data.ok) {
        setTelegramSent(true);
        setTelegramTestMsg("");
        setTimeout(() => setTelegramSent(false), 3000);
      }
    } catch { /* */ }
    setTelegramSending(false);
  };

  const inputStyle: React.CSSProperties = {
    width: "100%", border: "1px solid rgba(255,255,255,0.06)", borderRadius: "10px",
    padding: "10px 14px", fontSize: "13px", color: "#e8e4e0", fontFamily: "inherit",
    background: "rgba(255,255,255,0.04)", outline: "none",
    boxShadow: "inset 0 2px 4px rgba(0,0,0,0.3), inset 0 0 0 1px rgba(255,255,255,0.04)",
    transition: "border-color 0.2s ease",
  };

  const labelStyle: React.CSSProperties = {
    fontSize: "11px", fontWeight: 600, color: "#5a534e",
    textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "6px",
  };

  const tabs = [
    { id: "general", label: "Général", icon: Globe },
    { id: "llm", label: "IA / LLM", icon: Cpu },
    { id: "channels", label: "Canaux", icon: MessageSquare },
    { id: "security", label: "Sécurité", icon: ShieldAlert },
    { id: "anonymizer", label: "Anonymisation", icon: Shield },
  ];

  const channelDefs = [
    { key: "slack", label: "Slack", icon: <SlackIcon />, fields: [{ id: "botToken", label: "Bot Token (xoxb-...)", secret: true }, { id: "signingSecret", label: "Signing Secret", secret: true }] },
    { key: "telegram", label: "Telegram", icon: <TelegramIcon />, fields: [{ id: "botToken", label: "Bot Token", secret: true }, { id: "botUsername", label: "Nom du bot (@...)", secret: false }, { id: "chatId", label: "Chat ID (pour notifications)", secret: false }] },
    { key: "discord", label: "Discord", icon: <DiscordIcon />, fields: [{ id: "botToken", label: "Bot Token", secret: true }, { id: "publicKey", label: "Public Key", secret: false }] },
    { key: "whatsapp", label: "WhatsApp", icon: <MessageSquare size={18} color="#30a050" />, fields: [{ id: "accessToken", label: "Access Token", secret: true }, { id: "phoneNumberId", label: "Phone Number ID", secret: false }] },
    { key: "signal", label: "Signal", icon: <Shield size={18} color="#3080d0" />, fields: [{ id: "httpUrl", label: "URL signal-cli", secret: false }, { id: "account", label: "Numéro (+33...)", secret: false }] },
    { key: "email", label: "Email", icon: <Mail size={18} color="#9a918a" />, fields: [{ id: "host", label: "SMTP", secret: false }, { id: "port", label: "Port", secret: false }, { id: "from", label: "De", secret: false }, { id: "to", label: "À", secret: false }] },
  ];

  return (
    <div>
      {/* Tab nav */}
      <div style={{ display: "flex", gap: "4px", marginBottom: "20px", flexWrap: "wrap" }}>
        {tabs.map(tab => {
          const Icon = tab.icon;
          const active = activeTab === tab.id;
          return (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)} style={{
              display: "flex", alignItems: "center", gap: "6px",
              padding: "8px 16px", borderRadius: "10px", border: "none",
              fontSize: "12px", fontWeight: 600, fontFamily: "inherit",
              cursor: "pointer", transition: "all 0.2s ease",
              background: active ? "rgba(208,48,32,0.08)" : "rgba(255,255,255,0.02)",
              color: active ? "#d03020" : "#5a534e",
              borderColor: active ? "rgba(208,48,32,0.15)" : "transparent",
              borderWidth: "1px", borderStyle: "solid",
            }}>
              <Icon size={14} /> {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      <div style={{ display: "flex", flexDirection: "column", gap: "16px", marginBottom: "24px" }}>

        {/* ═══ GENERAL ═══ */}
        {activeTab === "general" && (
          <ChromeInsetCard>
            <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 700, marginBottom: "20px", display: "flex", alignItems: "center", gap: "10px" }}>
              <Globe size={18} color="#d03020" /> Configuration Générale
            </ChromeEmbossedText>
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              <div>
                <div style={labelStyle}>{"Nom de l'instance"}</div>
                <input style={inputStyle} value={general.instanceName} onChange={e => setGeneral(p => ({ ...p, instanceName: e.target.value }))} />
              </div>
              <div>
                <div style={labelStyle}>Langue</div>
                <select style={inputStyle} value={general.language} onChange={e => setGeneral(p => ({ ...p, language: e.target.value }))}>
                  <option value="fr">Français</option><option value="en">English</option>
                </select>
              </div>
              <div style={{ borderTop: "1px solid rgba(255,255,255,0.04)", paddingTop: "16px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                  <Key size={14} color="#d09020" />
                  <div style={labelStyle}>Clé API NVD (optionnel)</div>
                </div>
                <input style={inputStyle} type="password" value={general.nvdApiKey}
                  onChange={e => setGeneral(p => ({ ...p, nvdApiKey: e.target.value }))}
                  placeholder="Gratuit sur nvd.nist.gov — améliore la vitesse d'enrichissement CVE" />
                <div style={{ fontSize: "11px", color: "#5a534e", marginTop: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                  <Database size={12} />
                  {general.nvdApiKey
                    ? <span style={{ color: "#30a050" }}>Clé configurée — 50 req/30s</span>
                    : <span>Sans clé : 5 req/30s. Avec clé : 50 req/30s.</span>}
                </div>
              </div>
            </div>
          </ChromeInsetCard>
        )}

        {/* ═══ LLM — 3 niveaux ═══ */}
        {activeTab === "llm" && (<LlmTab
          llm={llm} setLlm={setLlm} forensic={forensic} setForensic={setForensic}
          cloud={cloud} setCloud={setCloud} llmModels={llmModels} setLlmModels={setLlmModels}
          testOllama={testOllama} inputStyle={inputStyle} labelStyle={labelStyle}
        />)}

        {/* ═══ CHANNELS ═══ */}
        {activeTab === "channels" && (<>
          {channelDefs.map(ch => {
            const chState = channels[ch.key] || { enabled: false };
            const isEnabled = chState.enabled as boolean;
            return (
              <ChromeInsetCard key={ch.key} glow={isEnabled && ch.key === "telegram"}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: isEnabled ? "16px" : 0 }}>
                  {ch.icon}
                  <div style={{ flex: 1 }}>
                    <ChromeEmbossedText as="div" style={{ fontSize: "14px", fontWeight: 700 }}>{ch.label}</ChromeEmbossedText>
                  </div>
                  {/* Toggle */}
                  <button onClick={() => setChannels(p => ({ ...p, [ch.key]: { ...p[ch.key], enabled: !isEnabled } }))}
                    style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
                    <div style={{
                      width: "44px", height: "24px", borderRadius: "12px", position: "relative",
                      background: isEnabled ? "rgba(208,48,32,0.15)" : "rgba(255,255,255,0.06)",
                      border: isEnabled ? "1px solid rgba(208,48,32,0.3)" : "1px solid rgba(255,255,255,0.06)",
                      transition: "all 0.25s ease",
                    }}>
                      <div style={{
                        width: "18px", height: "18px", borderRadius: "50%", position: "absolute", top: "2px",
                        left: isEnabled ? "23px" : "2px",
                        background: isEnabled ? "#d03020" : "#5a534e",
                        boxShadow: isEnabled ? "0 0 8px rgba(208,48,32,0.3)" : "none",
                        transition: "all 0.25s ease",
                      }} />
                    </div>
                  </button>
                </div>

                {isEnabled && (
                  <div style={{ display: "flex", flexDirection: "column", gap: "12px", borderTop: "1px solid rgba(255,255,255,0.04)", paddingTop: "16px" }}>
                    {ch.fields.map(f => (
                      <div key={f.id}>
                        <div style={labelStyle}>{f.label}</div>
                        <input style={inputStyle}
                          type={f.secret ? "password" : "text"}
                          value={(chState[f.id] as string) || ""}
                          onChange={e => setChannels(p => ({ ...p, [ch.key]: { ...p[ch.key], [f.id]: e.target.value } }))} />
                      </div>
                    ))}

                    {/* Telegram special: status + test message */}
                    {ch.key === "telegram" && (
                      <div style={{ borderTop: "1px solid rgba(255,255,255,0.04)", paddingTop: "16px" }}>
                        {/* Bot status */}
                        {telegramStatus && (
                          <div style={{
                            display: "flex", alignItems: "center", gap: "8px", marginBottom: "16px",
                            padding: "10px 14px", borderRadius: "10px",
                            background: telegramStatus.ok ? "rgba(48,160,80,0.06)" : "rgba(208,48,32,0.06)",
                            border: `1px solid ${telegramStatus.ok ? "rgba(48,160,80,0.15)" : "rgba(208,48,32,0.15)"}`,
                          }}>
                            <Bot size={16} color={telegramStatus.ok ? "#30a050" : "#d03020"} />
                            <div style={{ flex: 1 }}>
                              <div style={{ fontSize: "13px", fontWeight: 600, color: telegramStatus.ok ? "#30a050" : "#d03020" }}>
                                {telegramStatus.ok ? `@${telegramStatus.username} — Connecté` : "Bot non connecté"}
                              </div>
                              {telegramStatus.error && <div style={{ fontSize: "11px", color: "#5a534e" }}>{String(telegramStatus.error)}</div>}
                            </div>
                            <ChromeButton onClick={checkTelegram} variant="glass">
                              <RotateCcw size={12} />
                            </ChromeButton>
                          </div>
                        )}

                        {/* Send test message */}
                        <div style={labelStyle}>Envoyer un message test</div>
                        <div style={{ display: "flex", gap: "8px" }}>
                          <input style={{ ...inputStyle, flex: 1 }} value={telegramTestMsg}
                            onChange={e => setTelegramTestMsg(e.target.value)}
                            placeholder="Tapez un message à envoyer via Telegram..."
                            onKeyDown={e => e.key === "Enter" && sendTelegramTest()} />
                          <ChromeButton onClick={sendTelegramTest} disabled={telegramSending || !telegramTestMsg} variant="primary">
                            {telegramSending ? <Loader2 size={14} className="animate-spin" /> : telegramSent ? <CheckCircle2 size={14} /> : <Send size={14} />}
                            {telegramSent ? "Envoyé!" : "Envoyer"}
                          </ChromeButton>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </ChromeInsetCard>
            );
          })}
        </>)}

        {/* ═══ SECURITY ═══ */}
        {activeTab === "security" && (
          <ChromeInsetCard>
            <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 700, marginBottom: "20px", display: "flex", alignItems: "center", gap: "10px" }}>
              <ShieldAlert size={18} color="#d03020" /> Niveau de sécurité
            </ChromeEmbossedText>
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {PERM_LEVELS.map(level => {
                const LIcon = level.icon;
                const sel = permLevel === level.id;
                return (
                  <button key={level.id} onClick={() => setPermLevel(level.id)} style={{
                    display: "flex", alignItems: "center", gap: "14px",
                    background: sel ? "rgba(208,48,32,0.06)" : "rgba(255,255,255,0.01)",
                    border: sel ? "1px solid rgba(208,48,32,0.15)" : "1px solid rgba(255,255,255,0.04)",
                    borderRadius: "12px", cursor: "pointer", padding: "14px 16px",
                    textAlign: "left", transition: "all 0.2s ease", fontFamily: "inherit",
                    color: "inherit",
                  }}>
                    <LIcon size={20} color={level.color} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: "14px", fontWeight: 700, color: "#e8e4e0", display: "flex", alignItems: "center", gap: "8px" }}>
                        {level.label}
                        {level.recommended && <span style={{ fontSize: "9px", color: "#30a050", fontWeight: 600, padding: "2px 6px", background: "rgba(48,160,80,0.1)", borderRadius: "4px" }}>RECOMMANDÉ</span>}
                        {level.warning && <span style={{ fontSize: "9px", color: "#d03020", fontWeight: 600, padding: "2px 6px", background: "rgba(208,48,32,0.1)", borderRadius: "4px", display: "inline-flex", alignItems: "center", gap: "3px" }}><AlertTriangle size={9} />AVANCÉ</span>}
                      </div>
                      <div style={{ fontSize: "12px", color: "#5a534e", marginTop: "2px" }}>{level.desc}</div>
                    </div>
                    {sel && <Check size={18} color="#d03020" />}
                  </button>
                );
              })}
            </div>
          </ChromeInsetCard>
        )}

        {/* ═══ ANONYMIZER ═══ */}
        {activeTab === "anonymizer" && (
          <AnonymizerSection inputStyle={inputStyle} labelStyle={labelStyle} />
        )}
      </div>

      {/* Actions bar */}
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        padding: "16px 20px", borderRadius: "14px",
        background: "rgba(18,18,26,0.5)", border: "1px solid rgba(255,255,255,0.04)",
        position: "sticky", bottom: "20px",
        backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
      }}>
        <ChromeButton onClick={onResetWizard} variant="glass">
          <RotateCcw size={14} /> Relancer assistant
        </ChromeButton>
        <ChromeButton onClick={handleSave} disabled={saving} variant="primary">
          {saving ? <Loader2 size={14} className="animate-spin" /> : saved ? <CheckCircle2 size={14} /> : <Save size={14} />}
          {saved ? "Sauvegardé" : "Enregistrer la configuration"}
          {!saved && <ArrowRight size={14} />}
        </ChromeButton>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════
// LLM TAB — 3 levels with model management
// ═══════════════════════════════════════

interface LlmTabProps {
  llm: { backend: string; url: string; model: string; apiKey: string; connected: boolean; testing: boolean; models: string[] };
  setLlm: React.Dispatch<React.SetStateAction<LlmTabProps["llm"]>>;
  forensic: { model: string; url: string };
  setForensic: React.Dispatch<React.SetStateAction<LlmTabProps["forensic"]>>;
  cloud: { enabled: boolean; backend: string; model: string; apiKey: string; escalation: string };
  setCloud: React.Dispatch<React.SetStateAction<LlmTabProps["cloud"]>>;
  llmModels: { name: string; size: string }[];
  setLlmModels: React.Dispatch<React.SetStateAction<LlmTabProps["llmModels"]>>;
  testOllama: () => Promise<void>;
  inputStyle: React.CSSProperties;
  labelStyle: React.CSSProperties;
}

function LlmTab({ llm, setLlm, forensic, setForensic, cloud, setCloud, llmModels, setLlmModels, testOllama, inputStyle, labelStyle }: LlmTabProps) {
  const [pullModel, setPullModel] = useState("");
  const [pulling, setPulling] = useState(false);
  const [pullStatus, setPullStatus] = useState<string | null>(null);
  const [testingModel, setTestingModel] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<Record<string, { ok: boolean; msg: string }>>({});
  const [cloudTesting, setCloudTesting] = useState(false);
  const [cloudTestResult, setCloudTestResult] = useState<{ ok: boolean; models?: string[]; error?: string } | null>(null);

  const pullOllamaModel = async () => {
    if (!pullModel) return;
    setPulling(true);
    setPullStatus(`Téléchargement de ${pullModel}...`);
    try {
      const res = await fetch("/api/ollama", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "pull", model: pullModel, url: llm.url }),
      });
      const data = await res.json();
      if (data.ok) {
        setPullStatus(`${pullModel} installé`);
        setPullModel("");
        // Refresh model list
        const listRes = await fetch(`/api/ollama?url=${encodeURIComponent(llm.url)}`);
        const listData = await listRes.json();
        if (listData.models) {
          const models = listData.models.map((m: { name: string }) => m.name);
          setLlm(p => ({ ...p, models, connected: true }));
          setLlmModels(listData.models.map((m: { name: string; size: number }) => ({
            name: m.name, size: m.size ? `${(m.size / 1e9).toFixed(1)}GB` : "",
          })));
        }
      } else {
        setPullStatus(`Erreur: ${data.error}`);
      }
    } catch (e) {
      setPullStatus(`Erreur: ${e instanceof Error ? e.message : "inconnu"}`);
    }
    setPulling(false);
    setTimeout(() => setPullStatus(null), 5000);
  };

  const testModel = async (model: string) => {
    setTestingModel(model);
    try {
      const res = await fetch("/api/ollama", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "test", model, url: llm.url }),
      });
      const data = await res.json();
      setTestResult(p => ({ ...p, [model]: { ok: data.ok, msg: data.ok ? data.response : data.error } }));
    } catch {
      setTestResult(p => ({ ...p, [model]: { ok: false, msg: "Erreur réseau" } }));
    }
    setTestingModel(null);
  };

  const testCloudApi = async () => {
    setCloudTesting(true);
    setCloudTestResult(null);
    try {
      const res = await fetch("/api/ollama", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "test_cloud", backend: cloud.backend, apiKey: cloud.apiKey }),
      });
      const data = await res.json();
      setCloudTestResult(data);
    } catch {
      setCloudTestResult({ ok: false, error: "Erreur réseau" });
    }
    setCloudTesting(false);
  };

  const LevelBadge = ({ level, color, bg, border }: { level: string; color: string; bg: string; border: string }) => (
    <div style={{ width: "32px", height: "32px", borderRadius: "8px", background: bg, border: `1px solid ${border}`,
      display: "flex", alignItems: "center", justifyContent: "center", fontSize: "13px", fontWeight: 800, color, flexShrink: 0 }}>
      {level}
    </div>
  );

  return (
    <>
      {/* Architecture overview */}
      <ChromeInsetCard>
        <div style={{ fontSize: "13px", color: "#9a918a", lineHeight: 1.7 }}>
          <strong style={{ color: "#e8e4e0" }}>Architecture 3 niveaux</strong> — Le routeur décide automatiquement :
        </div>
        <div style={{ display: "flex", gap: "10px", marginTop: "14px" }}>
          {[
            { level: "L1", label: "Triage", desc: "Alertes courantes, confiance ≥70%", color: "#3080d0", bg: "rgba(48,128,208,0.08)", border: "rgba(48,128,208,0.2)" },
            { level: "L2", label: "Forensique", desc: "Critical/High, chain-of-thought", color: "#d09020", bg: "rgba(208,144,32,0.08)", border: "rgba(208,144,32,0.2)" },
            { level: "L3", label: "Cloud", desc: "Rapports, escalade anonymisée", color: "#a040d0", bg: "rgba(160,64,208,0.08)", border: "rgba(160,64,208,0.2)" },
          ].map(l => (
            <div key={l.level} style={{ flex: 1, padding: "10px 12px", borderRadius: "10px", background: l.bg, border: `1px solid ${l.border}`, textAlign: "center" }}>
              <div style={{ fontSize: "18px", fontWeight: 800, color: l.color }}>{l.level}</div>
              <div style={{ fontSize: "12px", fontWeight: 600, color: "#e8e4e0", marginTop: "2px" }}>{l.label}</div>
              <div style={{ fontSize: "10px", color: "#5a534e", marginTop: "2px" }}>{l.desc}</div>
            </div>
          ))}
        </div>
      </ChromeInsetCard>

      {/* ── Connexion Ollama ── */}
      <ChromeInsetCard>
        <ChromeEmbossedText as="h2" style={{ fontSize: "15px", fontWeight: 700, marginBottom: "16px", display: "flex", alignItems: "center", gap: "10px" }}>
          <Cpu size={18} color="#d03020" /> Connexion Ollama
        </ChromeEmbossedText>
        <div style={{ display: "flex", gap: "8px", marginBottom: "16px" }}>
          <input style={{ ...inputStyle, flex: 1 }} value={llm.url} onChange={e => setLlm(p => ({ ...p, url: e.target.value }))}
            placeholder="http://ollama:11434" />
          <ChromeButton onClick={testOllama} disabled={llm.testing} variant={llm.connected ? "glass" : "primary"}>
            {llm.testing ? <Loader2 size={14} className="animate-spin" /> : llm.connected ? <CheckCircle2 size={14} color="#30a050" /> : <Wifi size={14} />}
            {llm.connected ? "Connecté" : "Connecter"}
          </ChromeButton>
        </div>

        {/* Models installed */}
        {llmModels.length > 0 && (
          <div style={{ marginBottom: "16px" }}>
            <div style={labelStyle}>Modèles installés ({llmModels.length})</div>
            <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "8px" }}>
              {llmModels.map(m => {
                const isL1 = m.name === llm.model;
                const isL2 = m.name === forensic.model;
                const tr = testResult[m.name];
                return (
                  <div key={m.name} style={{
                    display: "flex", alignItems: "center", gap: "10px",
                    padding: "8px 12px", borderRadius: "10px",
                    background: (isL1 || isL2) ? "rgba(48,128,208,0.04)" : "rgba(255,255,255,0.02)",
                    border: `1px solid ${(isL1 || isL2) ? "rgba(48,128,208,0.12)" : "rgba(255,255,255,0.04)"}`,
                  }}>
                    <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#30a050", boxShadow: "0 0 6px rgba(48,160,80,0.3)", flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: "13px", fontWeight: 600, color: "#e8e4e0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{m.name}</div>
                      {m.size && <span style={{ fontSize: "10px", color: "#5a534e" }}>{m.size}</span>}
                    </div>
                    {isL1 && <span style={{ fontSize: "10px", fontWeight: 700, padding: "2px 6px", borderRadius: "4px", background: "rgba(48,128,208,0.1)", color: "#3080d0", border: "1px solid rgba(48,128,208,0.2)" }}>L1</span>}
                    {isL2 && <span style={{ fontSize: "10px", fontWeight: 700, padding: "2px 6px", borderRadius: "4px", background: "rgba(208,144,32,0.1)", color: "#d09020", border: "1px solid rgba(208,144,32,0.2)" }}>L2</span>}
                    {tr && (
                      <span style={{ fontSize: "10px", color: tr.ok ? "#30a050" : "#d03020" }}>
                        {tr.ok ? "OK" : "Erreur"}
                      </span>
                    )}
                    <ChromeButton onClick={() => testModel(m.name)} disabled={testingModel === m.name} variant="glass">
                      {testingModel === m.name ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
                    </ChromeButton>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Pull new model */}
        {llm.connected && (
          <div>
            <div style={labelStyle}>Installer un modèle</div>
            <div style={{ display: "flex", gap: "8px", marginTop: "6px" }}>
              <input style={{ ...inputStyle, flex: 1 }} value={pullModel} onChange={e => setPullModel(e.target.value)}
                placeholder="Ex: qwen3:8b, llama3.1:8b, mistral:7b..."
                onKeyDown={e => e.key === "Enter" && pullOllamaModel()} />
              <ChromeButton onClick={pullOllamaModel} disabled={pulling || !pullModel} variant="primary">
                {pulling ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
                {pulling ? "Installation..." : "Installer"}
              </ChromeButton>
            </div>
            {pullStatus && (
              <div style={{ fontSize: "12px", marginTop: "8px", color: pullStatus.includes("Erreur") ? "#d03020" : "#30a050", display: "flex", alignItems: "center", gap: "6px" }}>
                {pullStatus.includes("Erreur") ? <XCircle size={12} /> : pullStatus.includes("...") ? <Loader2 size={12} className="animate-spin" /> : <CheckCircle2 size={12} />}
                {pullStatus}
              </div>
            )}
          </div>
        )}
      </ChromeInsetCard>

      {/* ── L1 — Triage ── */}
      <ChromeInsetCard>
        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px" }}>
          <LevelBadge level="L1" color="#3080d0" bg="rgba(48,128,208,0.12)" border="rgba(48,128,208,0.25)" />
          <div>
            <ChromeEmbossedText as="div" style={{ fontSize: "15px", fontWeight: 700 }}>Triage — IA locale rapide</ChromeEmbossedText>
            <div style={{ fontSize: "11px", color: "#5a534e" }}>Corrélation, scoring CVSS, JSON structuré</div>
          </div>
        </div>
        <div>
          <div style={labelStyle}>Modèle L1</div>
          {llm.connected && llm.models.length > 0 ? (
            <select style={inputStyle} value={llm.model} onChange={e => setLlm(p => ({ ...p, model: e.target.value }))}>
              <option value="">— Sélectionner un modèle —</option>
              {llm.models.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
          ) : (
            <input style={inputStyle} value={llm.model} onChange={e => setLlm(p => ({ ...p, model: e.target.value }))}
              placeholder="Connectez Ollama pour voir les modèles disponibles" />
          )}
          <div style={{ fontSize: "11px", color: "#5a534e", marginTop: "6px" }}>
            Recommandé : <strong style={{ color: "#3080d0" }}>threatclaw-l1</strong> (qwen3:8b + system prompt SOC français)
          </div>
        </div>
      </ChromeInsetCard>

      {/* ── L2 — Forensique ── */}
      <ChromeInsetCard>
        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px" }}>
          <LevelBadge level="L2" color="#d09020" bg="rgba(208,144,32,0.12)" border="rgba(208,144,32,0.25)" />
          <div>
            <ChromeEmbossedText as="div" style={{ fontSize: "15px", fontWeight: 700 }}>Forensique — Analyse approfondie</ChromeEmbossedText>
            <div style={{ fontSize: "11px", color: "#5a534e" }}>Chain-of-thought, root cause, MITRE ATT&CK</div>
          </div>
        </div>
        <div>
          <div style={labelStyle}>Modèle L2</div>
          {llm.connected && llm.models.length > 0 ? (
            <select style={inputStyle} value={forensic.model} onChange={e => setForensic(p => ({ ...p, model: e.target.value }))}>
              <option value="">— Sélectionner un modèle —</option>
              {llm.models.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
          ) : (
            <input style={inputStyle} value={forensic.model} onChange={e => setForensic(p => ({ ...p, model: e.target.value }))}
              placeholder="threatclaw-l2" />
          )}
          <div style={{ fontSize: "11px", color: "#5a534e", marginTop: "6px" }}>
            Recommandé : <strong style={{ color: "#d09020" }}>threatclaw-l2</strong> (Foundation-Sec Reasoning Q8_0)
          </div>
        </div>
      </ChromeInsetCard>

      {/* ── L3 — Cloud ── */}
      <ChromeInsetCard glow={cloud.enabled}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: cloud.enabled ? "16px" : 0 }}>
          <LevelBadge level="L3" color="#a040d0" bg="rgba(160,64,208,0.12)" border="rgba(160,64,208,0.25)" />
          <div style={{ flex: 1 }}>
            <ChromeEmbossedText as="div" style={{ fontSize: "15px", fontWeight: 700 }}>Cloud — Escalade anonymisée</ChromeEmbossedText>
            <div style={{ fontSize: "11px", color: "#5a534e" }}>Rapports NIS2, incidents critiques, confiance insuffisante</div>
          </div>
          <button onClick={() => setCloud(p => ({ ...p, enabled: !p.enabled }))}
            style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
            <div style={{
              width: "44px", height: "24px", borderRadius: "12px", position: "relative",
              background: cloud.enabled ? "rgba(160,64,208,0.15)" : "rgba(255,255,255,0.06)",
              border: cloud.enabled ? "1px solid rgba(160,64,208,0.3)" : "1px solid rgba(255,255,255,0.06)",
              transition: "all 0.25s ease",
            }}>
              <div style={{
                width: "18px", height: "18px", borderRadius: "50%", position: "absolute", top: "2px",
                left: cloud.enabled ? "23px" : "2px",
                background: cloud.enabled ? "#a040d0" : "#5a534e",
                transition: "all 0.25s ease",
              }} />
            </div>
          </button>
        </div>

        {cloud.enabled && (
          <div style={{ display: "flex", flexDirection: "column", gap: "14px", borderTop: "1px solid rgba(255,255,255,0.04)", paddingTop: "16px" }}>
            <div>
              <div style={labelStyle}>Provider</div>
              <select style={inputStyle} value={cloud.backend} onChange={e => setCloud(p => ({ ...p, backend: e.target.value }))}>
                <option value="anthropic">Anthropic Claude</option>
                <option value="mistral">Mistral AI (souverain FR)</option>
                <option value="openai_compatible">OpenAI / Compatible</option>
              </select>
            </div>
            <div>
              <div style={labelStyle}>Clé API</div>
              <div style={{ display: "flex", gap: "8px" }}>
                <input style={{ ...inputStyle, flex: 1 }} type="password" value={cloud.apiKey}
                  onChange={e => setCloud(p => ({ ...p, apiKey: e.target.value }))}
                  placeholder={cloud.backend === "anthropic" ? "sk-ant-..." : cloud.backend === "mistral" ? "..." : "sk-..."} />
                <ChromeButton onClick={testCloudApi} disabled={cloudTesting || !cloud.apiKey} variant={cloudTestResult?.ok ? "glass" : "primary"}>
                  {cloudTesting ? <Loader2 size={14} className="animate-spin" /> : cloudTestResult?.ok ? <CheckCircle2 size={14} color="#30a050" /> : <Cloud size={14} />}
                  Tester
                </ChromeButton>
              </div>
              {cloudTestResult && (
                <div style={{ fontSize: "12px", marginTop: "8px", color: cloudTestResult.ok ? "#30a050" : "#d03020", display: "flex", alignItems: "center", gap: "6px" }}>
                  {cloudTestResult.ok ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                  {cloudTestResult.ok
                    ? `Connecté — ${cloudTestResult.models?.length || 0} modèle(s) disponible(s)`
                    : cloudTestResult.error}
                </div>
              )}
            </div>
            <div>
              <div style={labelStyle}>Modèle</div>
              {cloudTestResult?.ok && cloudTestResult.models && cloudTestResult.models.length > 0 ? (
                <select style={inputStyle} value={cloud.model} onChange={e => setCloud(p => ({ ...p, model: e.target.value }))}>
                  <option value="">— Sélectionner —</option>
                  {cloudTestResult.models.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              ) : (
                <input style={inputStyle} value={cloud.model} onChange={e => setCloud(p => ({ ...p, model: e.target.value }))}
                  placeholder={cloud.backend === "anthropic" ? "claude-sonnet-4-20250514" : cloud.backend === "mistral" ? "mistral-large-latest" : "gpt-4o"} />
              )}
            </div>
            <div>
              <div style={labelStyle}>Anonymisation</div>
              <select style={inputStyle} value={cloud.escalation} onChange={e => setCloud(p => ({ ...p, escalation: e.target.value }))}>
                <option value="anonymized">Anonymisé — IPs, hostnames, users remplacés avant envoi</option>
                <option value="direct">Direct — données brutes (déconseillé)</option>
                <option value="never">Désactivé — jamais d{"'"}escalade cloud</option>
              </select>
            </div>
          </div>
        )}
      </ChromeInsetCard>
    </>
  );
}

// ═══════════════════════════════════════
// ANONYMIZER SECTION (scrollable)
// ═══════════════════════════════════════

function AnonymizerSection({ inputStyle, labelStyle }: { inputStyle: React.CSSProperties; labelStyle: React.CSSProperties }) {
  const [rules, setRules] = useState<{ id: string; label: string; pattern: string; token_prefix: string }[]>([]);
  const [newLabel, setNewLabel] = useState("");
  const [newPattern, setNewPattern] = useState("");
  const [newPrefix, setNewPrefix] = useState("CUSTOM");
  const [adding, setAdding] = useState(false);

  const loadRules = async () => {
    try {
      const res = await fetch("/api/tc/anonymizer/rules");
      const data = await res.json();
      setRules(data.rules || []);
    } catch { /* */ }
  };

  useEffect(() => { loadRules(); }, []);

  const addRule = async () => {
    if (!newLabel || !newPattern) return;
    setAdding(true);
    try {
      await fetch("/api/tc/anonymizer/rules", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label: newLabel, pattern: newPattern, token_prefix: newPrefix }),
      });
      setNewLabel(""); setNewPattern(""); setNewPrefix("CUSTOM");
      await loadRules();
    } catch { /* */ }
    setAdding(false);
  };

  const deleteRule = async (id: string) => {
    try {
      await fetch(`/api/tc/anonymizer/rules/${id}`, { method: "DELETE" });
      await loadRules();
    } catch { /* */ }
  };

  return (
    <>
      <ChromeInsetCard>
        <ChromeEmbossedText as="h2" style={{ fontSize: "16px", fontWeight: 700, marginBottom: "8px", display: "flex", alignItems: "center", gap: "10px" }}>
          <Shield size={18} color="#d03020" /> Anonymisation
        </ChromeEmbossedText>
        <div style={{ fontSize: "13px", color: "#5a534e", marginBottom: "20px", lineHeight: 1.6 }}>
          <strong style={{ color: "#9a918a" }}>17 catégories automatiques</strong> : IPs, MAC, emails, téléphones, clés API, IBAN, SIRET, chemins fichiers, Active Directory, etc.
        </div>

        {/* Rules list - scrollable */}
        <div style={{ maxHeight: "400px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "8px" }}
          className="scrollbar-thin">
          {rules.length === 0 && (
            <div style={{ textAlign: "center", padding: "24px", color: "#5a534e", fontSize: "13px" }}>
              Aucune règle personnalisée. Les 17 catégories automatiques protègent déjà vos données.
            </div>
          )}
          {rules.map(rule => (
            <div key={rule.id} style={{
              display: "flex", alignItems: "center", gap: "12px",
              padding: "12px 14px", borderRadius: "10px",
              background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.04)",
            }}>
              <Shield size={14} color="#30a050" />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: "13px", fontWeight: 600, color: "#e8e4e0" }}>{rule.label}</div>
                <div style={{ fontSize: "11px", fontFamily: "monospace", color: "#5a534e" }}>
                  {rule.pattern} → [{rule.token_prefix}-001]
                </div>
              </div>
              <button onClick={() => deleteRule(rule.id)} style={{
                background: "rgba(208,48,32,0.06)", border: "1px solid rgba(208,48,32,0.15)",
                borderRadius: "8px", cursor: "pointer", padding: "6px 8px", transition: "all 0.2s ease",
              }}>
                <Trash2 size={14} color="#d03020" />
              </button>
            </div>
          ))}
        </div>
      </ChromeInsetCard>

      {/* Add new rule */}
      <ChromeInsetCard>
        <ChromeEmbossedText as="h3" style={{ fontSize: "14px", fontWeight: 700, marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
          <Plus size={16} color="#d03020" /> Ajouter une règle
        </ChromeEmbossedText>
        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          <div>
            <div style={labelStyle}>Nom de la règle</div>
            <input style={inputStyle} value={newLabel} onChange={e => setNewLabel(e.target.value)}
              placeholder="Ex: Nom du projet confidentiel" />
          </div>
          <div>
            <div style={labelStyle}>Mot ou pattern à anonymiser</div>
            <input style={{ ...inputStyle, fontFamily: "monospace" }} value={newPattern}
              onChange={e => setNewPattern(e.target.value)}
              placeholder="Ex: Projet-Neptune ou SRV-\d+" />
            <div style={{ fontSize: "11px", color: "#5a534e", marginTop: "6px", lineHeight: 1.5 }}>
              Exemples : mot exact (Projet-Neptune), insensible casse {"((?i)confidentiel)"}, pattern {"(SRV-\\d+ pour SRV-001, SRV-042...)"}
            </div>
          </div>
          <div style={{ display: "flex", gap: "12px", alignItems: "flex-end" }}>
            <div style={{ width: "140px" }}>
              <div style={labelStyle}>Préfixe</div>
              <input style={{ ...inputStyle, textTransform: "uppercase" }} value={newPrefix}
                onChange={e => setNewPrefix(e.target.value.toUpperCase())} />
            </div>
            <div style={{ flex: 1, fontSize: "12px", color: "#5a534e", paddingBottom: "12px" }}>
              → Le LLM verra [{newPrefix || "CUSTOM"}-001]
            </div>
            <ChromeButton onClick={addRule} disabled={adding || !newLabel || !newPattern} variant="primary">
              {adding ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
              Ajouter
            </ChromeButton>
          </div>
        </div>
      </ChromeInsetCard>
    </>
  );
}
